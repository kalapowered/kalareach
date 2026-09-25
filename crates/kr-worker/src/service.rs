//! The worker's private endpoint.
//!
//! Everything that reaches a session goes through here: the `kr` command line attaching directly,
//! and the control daemon proxying a paired device. Both are authenticated by the operating system
//! before a frame is read, and both have to prove what they claim to be:
//!
//! * A client challenges the worker. The worker signs the challenge with the per-session key it
//!   generated at startup, so a descriptor that points somewhere else cannot pass as this session.
//! * A controller answers the worker's challenge with a generation token. Accepting one fences the
//!   previous connection of that generation, so a controller that lost the singleton lock cannot
//!   keep acting through an old connection.
//!
//! # Mutations and the raw input stream
//!
//! A mutation arrives as a mutation envelope and receives a receipt: the intent is committed, the
//! dispatch marker is written before anything external happens, and the outcome is recorded.
//! `input.write` is not one of those. Section 9 makes raw input a separate ordered stream keyed by
//! connection, lease epoch and sequence, with no durable de-duplication and nothing replayed on
//! reconnection, so it arrives as an ordinary request and is ordered by its own sequence.

use std::sync::{Arc, Mutex};

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::Endpoint;
use kr_ipc::peer::PeerIdentity;
use kr_ipc::verify::{GenerationAcceptance, WorkerIdentity, check_generation_token};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{
    AttachmentCapability, AttachmentConfigureParams, AttachmentViewportParams,
    AttachmentViewportResult, GeometryResult, SessionAttachParams, SessionDetachParams,
    TerminalGeometryTransferParams, TerminalResizeParams,
};
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION};
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{
    ActorId, AttachmentId, BootEpoch, ConnectionId, ControllerGeneration, EnvironmentId, RequestId,
    SessionId, StreamId,
};
use kr_protocol::input::{
    InputAcquireParams, InputInterruptParams, InputLeaseResult, InputReleaseParams,
    InputWriteParams, InputWriteResult, InterruptAction,
};
use kr_protocol::local::{
    ControllerConnectionRole, LocalClientKind, LocalHello, LocalHelloAck, LocalRole,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{
    EventsSnapshotParams, EventsSubscribeParams, EventsSubscribeResult, HistoryPageParams,
    OutputEvent,
};
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, Nonce256, Nullable, U64};
use kr_protocol::session::{
    ClosureReason, SessionCloseResult, SessionReadParams, SessionReadResult,
};
use kr_protocol::worker::GenerationChallenge;
use kr_transport::clock::{ContinuousClock, ContinuousInstant, SystemContinuousClock};
use kr_transport::window::{AcceptedDeadline, ActionWindowIssuer, MAX_WINDOW_VALIDITY};

use crate::broker::MAX_SNAPSHOT_RESOURCES;
use crate::error::{Result, WorkerError};
use kr_protocol::projection::ProjectionEvent;

use crate::output::OutputDelivery;
use crate::runtime::SessionRuntime;
use crate::session::DETACH_HINT;
use crate::session::Session;

/// How often the worker replaces a live connection's action window.
///
/// Half the window's validity, which is the schedule the transport uses: an attached terminal that
/// stays open for hours never has to ask for a window, and never holds one that expired while its
/// replacement was in flight.
pub const WINDOW_RENEWAL: std::time::Duration =
    std::time::Duration::from_millis(MAX_WINDOW_VALIDITY.as_millis() as u64 / 2);

/// How often a local connection sends a keepalive.
///
/// Section 23 puts it at ten seconds while the connection is active. A Unix socket or a named pipe
/// has no keepalive underneath it, so the control stream carries one itself.
pub const LOCAL_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the host looks at its own clocks while it is idle.
///
/// Nothing depends on the cadence being fast: every mutation looks at the clocks on its own way
/// through, so a discontinuity that matters to a caller is found by that caller rather than by
/// this. What this is for is the host with nobody asking it anything - a machine that slept for a
/// week, or one whose clock was corrected overnight - where retention and an unresolved clock
/// would otherwise wait for the next request.
pub const HOST_MAINTENANCE: std::time::Duration = std::time::Duration::from_secs(60);

/// The event stream name output notifications carry.
pub const OUTPUT_STREAM: &str = "session.output";

/// How many connections one session serves at once.
///
/// Every attachment needs one, and a client that is between attachments needs one more, so the
/// bound is the attachment limit with room to reconnect rather than the attachment limit exactly.
pub const MAX_CONNECTIONS: usize = kr_protocol::limits::MAX_CONCURRENT_ATTACHMENTS * 2;

/// The largest replay page one notification carries.
///
/// A control frame is bounded at 1 MiB including its metadata, so a replay page stays well inside
/// that rather than filling it exactly.
pub const MAX_REPLAY_PAGE_BYTES: u64 = 512 * 1024;

/// What the worker currently accepts as controller authority.
///
/// The generation and the connection that speaks for it are one value under one lock, so a token
/// can never install a generation without also installing the connection it arrived on. A request
/// from a controller connection that is not the bound one is refused, which is what makes fencing
/// something the dispatch path enforces rather than something the handshake merely records.
///
/// A daemon also opens a connection for each caller it is proxying, because the worker's
/// attachments, subscriptions and input lane all belong to the connection that created them, and a
/// device's own attachment cannot share a connection with the daemon's housekeeping. Those
/// connections declare themselves proxies before they present a token, so they never take the
/// authority binding and never fence the connection that holds it. A token for a *higher*
/// generation fences every one of them along with the authority itself.
#[derive(Clone, Debug)]
struct Authority {
    /// The highest generation this worker has accepted.
    accepted_generation: Option<ControllerGeneration>,
    /// The connection that presented it.
    bound_connection: Option<ConnectionId>,
    /// The proxy connections of that same generation.
    proxy_connections: std::collections::BTreeSet<ConnectionId>,
    /// The connection the control daemon reads this session's attention sources over.
    ///
    /// There is one: a newer one replaces it, and a replacement generation fences it with the
    /// rest.
    attention_connection: Option<ConnectionId>,
    /// The authority revision the controller last announced and this worker acknowledged.
    acknowledged_revision: Option<kr_protocol::ids::AuthorityRevision>,
    /// A revision this worker was told about while it was inside a dispatch transition.
    ///
    /// The announcement was refused, because a fence cannot interleave with a dispatch and waiting
    /// for the boundary would hold a connection the dispatch may need. What must not depend on the
    /// daemon announcing again is the *fence*, so the revision is recorded here and the host's own
    /// maintenance runs it.
    owed_revision: Option<kr_protocol::ids::AuthorityRevision>,
}

/// The worker's endpoint server.
pub struct WorkerService {
    runtime: Arc<SessionRuntime>,
    identity: Arc<WorkerIdentity>,
    endpoint: Endpoint,
    environment_id: EnvironmentId,
    boot_identity: BootIdentity,
    /// The compact form of the boot above, which is what an action window is bound to.
    boot_epoch: BootEpoch,
    /// The suspend-aware continuous clock every deadline this worker decides is measured on.
    clock: Arc<SystemContinuousClock>,
    /// The machine's own continuous clock, which is the one a forwarded deadline arrives on.
    shared_clock: Arc<dyn kr_ipc::clock::SharedClock>,
    /// The session's time contract, which reads UTC through the host's clock floor.
    time: Arc<crate::action::time::TimeContract>,
    /// The action windows of every connection this worker serves.
    windows: ActionWindowIssuer,
    controller_public_key: AuthorisationKey,
    authority: Mutex<Authority>,
    /// The serial boundary every mutation and every authority change passes through.
    ///
    /// Checking authority and then acting on it are two operations, and between them a replacement
    /// controller can install a newer generation. Holding this for the whole sequence — the
    /// authority check, the admission, the revalidation, the dispatch marker and the effect — is
    /// what makes the check mean something by the time the effect happens. Authority changes take
    /// it too, so one cannot slip between the two halves of the other.
    dispatch: Mutex<()>,
    /// How many connections this session is serving.
    connections: Arc<std::sync::atomic::AtomicUsize>,
    /// Every connection this worker has admitted, and how to withdraw it.
    ///
    /// The transport's contract names this as the host's to keep: the final validation of the
    /// caller's record and the registration of the connection are one step, and the registration
    /// stays revocable for the life of the session. Section 9's dispatch barrier covers a
    /// mutation; it does not cover a read or a subscription already running on a connection that
    /// was authorised a moment before its authority was withdrawn. This is what covers those.
    admitted: Mutex<std::collections::BTreeMap<ConnectionId, Registration>>,
    /// The attachments a forwarded caller made, whose authority is a grant rather than this user.
    ///
    /// An authority revision fences what those attachments were admitted to do, and an attachment
    /// identifier is the only thing the input lease records about who holds it. A local
    /// attachment is not in here, because its authority is the operating-system identity the
    /// socket authenticated and no revision replaces that.
    remote_attachments: Mutex<std::collections::BTreeSet<AttachmentId>>,
    /// The session's questions, and the sources bound to them.
    questions: Arc<crate::questions::Questions>,
    /// The session's journal file, which the attention sources are read from.
    journal_path: Option<std::path::PathBuf>,
    /// A reading connection of its own to that file, for the control daemon's attention link.
    ///
    /// The link reads beside the session rather than through it, so a page being read or held
    /// never waits for the session's lock and the session never waits for the link. It is opened
    /// on first use and again after a read fails.
    attention_reader: Mutex<Option<crate::journal::Journal>>,
    /// Woken when the session's journal commits a host event or a privacy transition.
    journal_changes: Option<Arc<tokio::sync::Notify>>,
    /// The session's side of the privacy fence around its attention text: the transition in
    /// progress, the statements that tell the control daemon about it, and the leases of the text
    /// this worker has answered with.
    attention_fence: Arc<crate::attention_fence::AttentionFence>,
    /// The trusted broker: the agent processes, their gateway and the resources it arbitrates.
    broker: Arc<crate::broker::Broker>,
    /// The frozen copies the connections of this worker are reading their recoveries out of.
    recoveries: crate::recovery::RecoveryCopies,
    build_id: kr_protocol::ids::BuildId,
    /// A pause between a durable receipt acceptance and the broker's admission of the same
    /// mutation, which this host's own tests arm to stand inside that interval. It is compiled
    /// away in every shipped build.
    #[cfg(feature = "testing")]
    admission_pause: Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
    /// A pause before a connection replaces a delivery that is still running, which this host's
    /// own tests arm to make that replacement meet a frame part way to its peer. It is compiled
    /// away in every shipped build.
    #[cfg(feature = "testing")]
    replacement_pause: Mutex<Option<ArmedReplacement>>,
}

impl WorkerService {
    /// Returns the build this worker reports.
    #[must_use]
    pub const fn build_id(&self) -> &kr_protocol::ids::BuildId {
        &self.build_id
    }

    /// Returns the worker's private endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns how many action windows this service currently holds.
    ///
    /// A connection's windows are retired when the connection ends, so this is what a reader has
    /// to watch to know that a window is gone rather than merely unused.
    #[must_use]
    pub fn outstanding_windows(&self) -> usize {
        self.windows.outstanding()
    }

    /// Returns the boot every action window this service issues is bound to.
    #[must_use]
    pub const fn boot_epoch(&self) -> BootEpoch {
        self.boot_epoch
    }

    /// Returns the session this service serves.
    #[must_use]
    pub fn runtime(&self) -> &Arc<SessionRuntime> {
        &self.runtime
    }

    /// Returns this session's question ledger.
    #[must_use]
    pub fn questions(&self) -> &Arc<crate::questions::Questions> {
        &self.questions
    }

    /// Returns this session's trusted broker.
    #[must_use]
    pub fn broker(&self) -> &Arc<crate::broker::Broker> {
        &self.broker
    }

    /// Sets up the backends an integrated invocation is given before it runs, on this session's
    /// broker, and hands them to the session; on Unix it also starts the watch that adopts a
    /// program those backends did not launch.
    ///
    /// Returns them, so the installation's connectors can be handed over to their sources. It must
    /// be called from inside the runtime the backends serve their endpoints on.
    pub fn install_command_backends(
        &self,
        config: crate::broker::commands::CommandBackendsConfig,
    ) -> Arc<crate::broker::commands::CommandBackends> {
        // A program the integrated route did not launch is adopted from the same connectors, by
        // a watch of the terminal's foreground, and its adoption ends with the backends when the
        // session closes.
        #[cfg(unix)]
        let adoptions = Arc::new(
            crate::broker::adoption::Adoptions::new(
                Arc::clone(&self.broker),
                Arc::clone(&config.sources),
                config.environment_id,
            )
            .with_views(Arc::downgrade(&self.runtime)),
        );
        let backends = crate::broker::commands::CommandBackends::new(
            Arc::clone(&self.broker),
            config,
            tokio::runtime::Handle::current(),
        )
        .with_views(Arc::downgrade(&self.runtime));
        #[cfg(unix)]
        let backends = backends.with_adoptions(Arc::clone(&adoptions));
        let backends = Arc::new(backends);
        self.runtime
            .session()
            .set_command_backends(Arc::clone(&backends));
        #[cfg(unix)]
        tokio::spawn(crate::broker::adoption::watch(
            adoptions,
            Arc::downgrade(&self.runtime),
        ));
        backends
    }
}

impl std::fmt::Debug for WorkerService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerService")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl WorkerService {
    /// Builds a service for one session.
    ///
    /// # Errors
    ///
    /// Returns an error when the host's boot identity cannot be reduced to a boot epoch.
    pub fn new(
        runtime: Arc<SessionRuntime>,
        identity: Arc<WorkerIdentity>,
        endpoint: Endpoint,
        binding: ServiceBinding,
    ) -> Result<Self> {
        let boot_epoch = kr_ipc::identity::boot_epoch(&binding.boot_identity)?;
        let (session_id, session_epoch, health) = {
            let session = runtime.session();
            (session.id(), session.epoch(), Arc::clone(session.health()))
        };
        // The broker's records live in the same journal file, beside the receipts and the
        // questions, with their own version row. It reads the session's own journal condition, and
        // reports its own store's failures there: one fence for the receipt path and the broker.
        let broker = Arc::new(crate::broker::Broker::open(
            binding.journal_path.as_deref(),
            session_id,
            health,
        )?);
        // The broker is the bridge that says which launched agent a question's source belongs to
        // and the binding it asks under, so a switch it detects invalidates what was asked under
        // the binding it left.
        let questions = Arc::new(
            crate::questions::Questions::open(
                binding.journal_path.as_deref(),
                session_id,
                session_epoch,
            )?
            .with_agents(Arc::clone(&broker) as Arc<dyn crate::questions::AgentBindings>),
        );
        let clock = Arc::new(SystemContinuousClock::new());
        // The session's own, not a second one: the check this service makes before a batch is
        // accepted and the fence the writer applies before it is written have to be reading the
        // same clock for the second to be a continuation of the first.
        let shared_clock = runtime.shared_clock();
        let time = Arc::clone(runtime.session().time());
        let journal_changes = runtime
            .session()
            .journal()
            .map(crate::journal::Journal::attention_changes);
        let attention_fence = Arc::new(crate::attention_fence::AttentionFence::new(Arc::clone(
            &shared_clock,
        )));
        Ok(Self {
            runtime,
            identity,
            endpoint,
            environment_id: binding.environment_id,
            boot_identity: binding.boot_identity,
            boot_epoch,
            windows: ActionWindowIssuer::with_default_validity(Arc::clone(&clock) as Arc<_>),
            clock,
            shared_clock,
            time,
            controller_public_key: binding.controller_public_key,
            authority: Mutex::new(Authority {
                accepted_generation: Some(binding.controller_generation),
                bound_connection: None,
                proxy_connections: std::collections::BTreeSet::new(),
                attention_connection: None,
                acknowledged_revision: None,
                owed_revision: None,
            }),
            dispatch: Mutex::new(()),
            connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            admitted: Mutex::new(std::collections::BTreeMap::new()),
            remote_attachments: Mutex::new(std::collections::BTreeSet::new()),
            questions,
            journal_path: binding.journal_path,
            attention_reader: Mutex::new(None),
            journal_changes,
            attention_fence,
            broker,
            recoveries: crate::recovery::RecoveryCopies::new(),
            build_id: binding.build_id,
            #[cfg(feature = "testing")]
            admission_pause: Mutex::new(None),
            #[cfg(feature = "testing")]
            replacement_pause: Mutex::new(None),
        })
    }

    /// Stops the next approval immediately before the broker admits it, for this host's own tests.
    ///
    /// The receipt has been accepted durably by then and the dispatch marker has not been written,
    /// which is the interval section 24 divides. Every other seam a test controls inside that
    /// interval runs under the broker's own lock, so a test that wanted to resolve the resource or
    /// replace its evidence from one would deadlock rather than race.
    ///
    /// Returns the end that says the service has arrived, and the end that lets it go. The pause
    /// fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_admission(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (arrived, watch) = std::sync::mpsc::sync_channel(1);
        let (release, go) = std::sync::mpsc::sync_channel(1);
        *self
            .admission_pause
            .lock()
            .expect("the pause is not poisoned") = Some((arrived, go));
        (watch, release)
    }

    /// Waits at the pause above, where one is armed. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    fn wait_before_admission(&self) {
        let armed = self
            .admission_pause
            .lock()
            .expect("the pause is not poisoned")
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.recv();
        }
    }

    /// The same, without the feature: there is no pause.
    #[cfg(not(feature = "testing"))]
    #[expect(
        clippy::unused_self,
        reason = "it is the shipped form of a method that reads this service's own pause"
    )]
    const fn wait_before_admission(&self) {}

    /// Takes the turn to write on the current attention connection and holds it until the
    /// returned guard is dropped, for this host's own tests.
    ///
    /// Every frame the connection carries waits for its turn, so a statement then waits exactly as
    /// it waits behind a frame the daemon is not reading. A test cannot make that wait through the
    /// socket alone, because how much a socket takes before it refuses more differs between
    /// platforms. Nothing when there is no attention connection.
    #[cfg(feature = "testing")]
    pub async fn hold_attention_turn(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let connection_id = self.attention_fence.current_connection()?;
        let turn = self
            .admitted
            .lock()
            .expect("the connection registry is not poisoned")
            .get(&connection_id)
            .map(|registration| Arc::clone(&registration.writable.turn))?;
        Some(turn.lock_owned().await)
    }

    /// Returns whether a privacy transition is raised, for this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn attention_transition_raised(&self) -> bool {
        self.attention_fence.is_raised()
    }

    /// Stops the next connection that replaces a running delivery immediately before it does, for
    /// this host's own tests.
    ///
    /// The answer to the subscription that replaces it has been written by then, and the delivery
    /// being replaced goes on writing what it was sent before, so a test can let it begin a frame
    /// its peer does not take and replace it part way through that frame.
    ///
    /// The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_before_replacing_delivery(&self) -> ReplacementPause {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (release, go) = tokio::sync::oneshot::channel();
        let (replaced, replacement) = tokio::sync::oneshot::channel();
        *self
            .replacement_pause
            .lock()
            .expect("the pause is not poisoned") = Some(ArmedReplacement {
            arrived,
            go,
            replaced,
        });
        ReplacementPause {
            arrived: arrival,
            release,
            replaced: replacement,
        }
    }

    /// Waits at the pause above, where one is armed, and returns what says the replacement has
    /// happened. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    async fn wait_before_replacing_delivery(&self) -> Option<tokio::sync::oneshot::Sender<()>> {
        let armed = self
            .replacement_pause
            .lock()
            .expect("the pause is not poisoned")
            .take()?;
        let _ = armed.arrived.send(());
        let _ = armed.go.await;
        Some(armed.replaced)
    }

    /// Returns whether the connection that owns `attachment_id` has sent its peer part of a frame
    /// and not the rest, for this host's own tests.
    ///
    /// That is where a delivery waits when its peer has stopped reading part way through a frame,
    /// and it is the state a replacement must not cut: the frame is finished before anything else is
    /// written, or the connection ends.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn part_way_through_a_frame(&self, attachment_id: AttachmentId) -> bool {
        let writer = self
            .admitted
            .lock()
            .expect("the connection registry is not poisoned")
            .values()
            .find(|registration| {
                registration
                    .attachments
                    .lock()
                    .expect("the attachment list is not poisoned")
                    .contains(&attachment_id)
            })
            .map(|registration| Arc::clone(&registration.writer));
        writer.is_some_and(|writer| {
            let writer = writer
                .lock()
                .expect("the connection writer is not poisoned");
            writer.is_mid_frame() && writer.has_sent_any()
        })
    }

    /// Returns the generation this worker currently accepts.
    #[must_use]
    pub fn accepted_generation(&self) -> Option<ControllerGeneration> {
        self.authority
            .lock()
            .expect("the authority lock is not poisoned")
            .accepted_generation
    }

    /// Returns the authority revision this worker has acknowledged.
    ///
    /// Revocation is reported as pending for a worker until the revision it names has been
    /// acknowledged here or the worker is confirmed ended. The remote dispatch lease that consumes
    /// this arrives with the transport; this is the worker half of that interface.
    #[must_use]
    pub fn acknowledged_revision(&self) -> Option<kr_protocol::ids::AuthorityRevision> {
        self.authority
            .lock()
            .expect("the authority lock is not poisoned")
            .acknowledged_revision
    }

    /// Serves the endpoint until the session has closed.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails for a reason other than a peer going away.
    pub async fn serve(self: Arc<Self>, listener: Listener) -> Result<()> {
        // The host's own cadence, started before the first connection is accepted. Retention and
        // the clocks are the host's business rather than a caller's, and a session that is never
        // asked anything still has records to collect and a clock that can move.
        let maintenance = Arc::clone(&self);
        tokio::spawn(async move { maintenance.maintain().await });
        // The copies a recovery is read out of have a deadline of their own, shorter than that
        // cadence, and a client that stops paging makes no call to notice it in. This waits for
        // the next one rather than looking on a cadence, so the memory goes back when the copy
        // ends and not at some later pass.
        let reclaiming = Arc::clone(&self);
        tokio::spawn(async move { reclaiming.reclaim_recoveries().await });
        loop {
            let (connection, peer) = listener.accept().await?;
            // One session serves a bounded number of connections at once. Without a bound a caller
            // that opened connections and never spoke would take this worker's memory a frame
            // buffer at a time.
            let held = Arc::clone(&self.connections);
            if held.load(std::sync::atomic::Ordering::Acquire) >= MAX_CONNECTIONS {
                drop(connection);
                continue;
            }
            held.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let service = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = service.run_connection(connection, peer).await;
                held.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            });
        }
    }

    /// Gives back the memory of every recovery copy that has reached its deadline.
    ///
    /// It waits for the earliest deadline this host is holding, and for a copy being kept, so a
    /// copy taken a moment after this went to sleep is still reclaimed at its own deadline rather
    /// than at the next one after it.
    async fn reclaim_recoveries(self: Arc<Self>) {
        loop {
            self.recoveries.until_a_deadline(self.clock.now()).await;
            self.recoveries.expire(self.clock.now());
        }
    }

    /// Runs the host's own maintenance until the session closes.
    ///
    /// Two things happen on every tick, in this order. The clocks are looked at, because what they
    /// say decides the second thing: a wake, a reboot or a step of the wall clock revalidates the
    /// freshness resources this host issued, and a clock that cannot be proved stops collection
    /// outright. Then the records past the retention period are collected, on the schedule the
    /// journal itself keeps rather than on this one.
    async fn maintain(self: Arc<Self>) {
        let mut tick = tokio::time::interval(HOST_MAINTENANCE);
        // The first pass happens at once, so a host that has just come up collects, looks at its
        // clocks before it waits a minute to do either.
        tick.tick().await;
        loop {
            let closed = {
                // Maintenance passes through the same serial boundary a mutation does. Section 9
                // puts the revalidation a discontinuity owes *before* the host serves a mutation,
                // and this barrier is what "before" means here: a mutation either sees the
                // revalidation completed or waits for it.
                let _barrier = self
                    .dispatch
                    .lock()
                    .expect("the dispatch barrier is not poisoned");
                self.revalidate_time();
                // A revocation this worker was told about while it was dispatching something. The
                // announcement was refused rather than queued, and this is what makes the fence
                // happen anyway: the daemon's next announcement finds it done.
                self.fence_what_is_owed();
                // One look at the session, and the lock released before anything else asks for
                // it. Collection records its own failure, so nothing here needs the lock a second
                // time to say that it failed.
                let state = {
                    let mut session = self.runtime.session();
                    // A store that has started answering again is a store this host may call
                    // durable, and the interval it could not is written down before it says so.
                    // The broker's half follows, once this lock and the barrier are released.
                    session.recover_journal();
                    session.collect_expired();
                    // Output retention is separate from receipt retention and runs on the same
                    // tick: section 20 budgets the two stores apart, so history pressure never
                    // reaches a dispatch barrier or a de-duplication record.
                    session.collect_output();
                    session.state()
                };
                state == kr_protocol::session::SessionState::Closed
            };
            // The broker's half of the same recovery, off the session's lock and the dispatch
            // barrier. It writes its gap while native work goes on, and nothing that serves the
            // terminal or a mutation waits on that write.
            self.recover_broker();
            // Questions whose time ran out, whose source went or whose agent binding moved on end
            // here even when nobody is reading them, so the feed the daemon's attention store reads
            // and every client that follows it hear of it on this tick rather than at the next read.
            let _ = self.questions.sweep(self.question_clock());
            if closed {
                break;
            }
            tick.tick().await;
        }
    }

    /// Runs the storage half of one maintenance pass now: the journal first, then the broker.
    ///
    /// Maintenance does this on its own cadence, once a minute. This exists so that this host's
    /// own tests can reach the end of a storage fault without waiting for that pass, through the
    /// same barrier, the same locks and the same order. It is compiled away in every shipped
    /// build.
    #[cfg(feature = "testing")]
    pub fn recover_storage_now(&self) {
        {
            let _barrier = self
                .dispatch
                .lock()
                .expect("the dispatch barrier is not poisoned");
            self.runtime.session().recover_journal();
        }
        self.recover_broker();
    }

    /// Takes the broker through its half of a recovery the journal has finished.
    ///
    /// It commits the broker's gap and owes each upstream with an unresolved resource a
    /// reconciliation, then reconciles every one whose connection is open. A fault the journal
    /// recovered from before the broker decided anything is still the broker's to recover from:
    /// reading the mode applies it. A store that fails again has already raised the fence where it
    /// failed, and the next pass starts again.
    ///
    /// It runs after the journal has written its own gap, and it holds neither the session's lock
    /// nor the dispatch barrier, because the broker's gap is written while native work goes on.
    /// Nothing rich is decided in between on the strength of that: until this recovery and its
    /// reconciliations finish, the broker refuses rich work itself.
    fn recover_broker(&self) {
        let now = kr_ipc::now_ms();
        let mode = self.broker.mode();
        if mode == kr_protocol::gateway::GatewayMode::Normal {
            return;
        }
        if mode == kr_protocol::gateway::GatewayMode::NativeOnlyVolatile
            && self.broker.recover(now).is_err()
        {
            return;
        }
        // Whether this pass finished the recovery or left upstreams still owed, the next pass
        // looks again; there is nothing further to do with the answer here.
        let _finished = self.broker.reconcile_connected(now);
    }

    /// Looks at the host's clocks, and revalidates what a discontinuity invalidated.
    ///
    /// Section 9: a wake, a reboot or a discontinuity revalidates the leases before the host
    /// serves an expiry-dependent read or mutation. The freshness resources this host issues are
    /// the action windows, and revalidating one means establishing that it is still live on the
    /// suspend-aware continuous clock its deadline was set on. A window that is not is retired
    /// here, so the next request presenting it finds it gone rather than being decided against a
    /// clock that moved.
    fn revalidate_time(&self) {
        let found = self.runtime.session().observe_time();
        if !found.any() {
            return;
        }
        self.windows.revalidate();
        // Recorded only once the windows have actually been rechecked. The flag is what refuses an
        // expiry-dependent answer in the meantime, so setting it before the work would be a claim
        // rather than a record.
        self.runtime.session().note_leases_revalidated();
    }

    async fn run_connection(
        self: Arc<Self>,
        connection: Connection,
        peer: PeerIdentity,
    ) -> Result<()> {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let (mut reader, writer) = split(connection, StreamKind::Control);
        // The lock is an ordinary one, because nothing is ever awaited while it is held: what
        // happens inside it is the authority check, one attempt that refuses to wait, and the
        // accounting for what that attempt sent. Waiting for the peer happens outside it, on the
        // readiness handle beside it, which is what lets a withdrawal take the same lock and know
        // that no write can begin after it.
        let writable = Writing {
            turn: Arc::new(tokio::sync::Mutex::new(())),
            readiness: writer.writable(),
        };
        let writer = Arc::new(Mutex::new(writer));
        let mut state =
            ConnectionState::new(connection_id, &peer, Arc::new(Mutex::new(Vec::new())));
        // The caller's record is validated and the connection registered in one step. The
        // listener checked the peer when it accepted the connection; this is the final check, and
        // it happens where the registration is written, so nothing can be admitted in between.
        if peer.authorise(kr_ipc::paths::current_uid()).is_err() {
            return Ok(());
        }
        let registration = self.admit(connection_id, &writer, &writable);
        let withdrawn = Arc::clone(&registration.withdrawn);
        state.attachments = Arc::clone(&registration.attachments);
        state.withdrawn = Arc::clone(&registration.withdrawn);
        // Both timers fire once immediately; that first tick is consumed here so a connection is
        // not handed a replacement window before it has read the one in its acknowledgement.
        let mut renewal = tokio::time::interval(WINDOW_RENEWAL);
        renewal.tick().await;
        let mut keepalive = tokio::time::interval(LOCAL_KEEPALIVE);
        keepalive.tick().await;
        // The withdrawal is a latch rather than a single permit, so this loop acts on it once and
        // then stops watching it: the connection stays open to refuse the next request.
        let mut fenced = false;
        loop {
            let message: ControlFrame = tokio::select! {
                message = reader.read_message::<ControlFrame>() => match message {
                    Ok(message) => message,
                    Err(_) => break,
                },
                // The authority this connection was admitted under has been withdrawn. Whatever
                // it had already subscribed to stops here: refusing its *next* request would leave
                // a delivery task streaming this session's output down a connection that no longer
                // holds authority. The connection itself stays open, so the caller is told why its
                // next request is refused rather than finding a socket that closed.
                () = withdrawn.wait(), if !fenced => {
                    fenced = true;
                    // The delivery task and the attachments went with the withdrawal itself. What
                    // is left is this connection's own handle on the task it started.
                    state.delivery = None;
                    // The daemon's attention link has no caller to tell why. A withdrawn one is
                    // closed instead, so the daemon opens the next at once rather than waiting out
                    // a request this connection will never answer.
                    if state.controller
                        && state.controller_role == ControllerConnectionRole::Attention
                    {
                        break;
                    }
                    continue;
                }
                // The window is replaced on the live authorised connection, at half its
                // validity, so an attachment that stays open for hours never has to renew before a
                // mutation. A connection whose registration has been withdrawn is no longer that:
                // a replacement window for it would be a freshness resource issued to authority
                // that has gone, so the renewal stops with the registration.
                _ = renewal.tick(), if state.negotiated => {
                    if self.check_authority(&state).is_err() {
                        continue;
                    }
                    let Ok(window) = self.issue_window(connection_id) else {
                        break;
                    };
                    let renewed = ControlFrame::Event(ControlEvent::ActionWindowRenewed(window));
                    // A window is this host's own offer and carries nothing of the session, so it
                    // is written or it is not; what it must not do is wait for a peer that has
                    // stopped reading while this connection still holds anything.
                    if !write_frame(&writable, &writer, &renewed, &withdrawn, !fenced).await {
                        break;
                    }
                    continue;
                }
                _ = keepalive.tick(), if state.negotiated => {
                    let beat = ControlFrame::Event(ControlEvent::Keepalive);
                    if !write_frame(&writable, &writer, &beat, &withdrawn, !fenced).await {
                        break;
                    }
                    continue;
                }
            };
            // Whether this connection still held its registration when the answer was *produced*
            // is what decides how the answer may be written. One produced while it held it carries
            // what that authority gave it, and a withdrawal that lands before it reaches the peer
            // must stop it. One produced afterwards is a refusal, and the caller is owed that
            // refusal rather than a socket that closed.
            let protected = !withdrawn.is_set();
            let reply = self.handle(&mut state, &peer, message).await;
            // A page the control daemon asked for is read, and held while there is nothing to
            // answer with, on its own task too: the same connection carries the text requests the
            // daemon serves its readers from meanwhile. A newer request replaces a held one: the
            // one it replaces stops waiting and writes nothing, and one already writing its page
            // finishes it, because a frame cut part way would end the connection. The daemon tells
            // the two answers apart by their request identifiers.
            if let Some(pending) = state.pending_page.take() {
                {
                    // The replacement is signalled under the writer, where the answer it replaces
                    // decides whether to write its first byte: so that answer either sees the
                    // replacement and writes nothing, or has already begun and finishes.
                    let _boundary = writer
                        .lock()
                        .expect("the connection writer is not poisoned");
                    drop(state.page_cancel.take());
                }
                let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
                let service = Arc::clone(&self);
                let sender = Arc::clone(&writer);
                let answering_writable = writable.clone();
                let answering_withdrawn = Arc::clone(&withdrawn);
                state.page_cancel = Some(cancel);
                state.page_task = Some(tokio::spawn(async move {
                    if let Some(answer) = service.finish_page(pending, &mut cancelled).await {
                        write_frame_unless(
                            &answering_writable,
                            &sender,
                            &answer,
                            &answering_withdrawn,
                            true,
                            Some(&mut cancelled),
                        )
                        .await;
                    }
                }));
            }
            // A launch the reader is still deciding is answered on its own task, so this loop goes
            // on serving the same client: its next keystroke, its interrupt and its detach do not
            // wait behind a transaction the reader has not finished.
            if let Some(pending) = state.pending_launch.take() {
                let service = Arc::clone(&self);
                let sender = Arc::clone(&writer);
                let answering_writable = writable.clone();
                let answering_withdrawn = Arc::clone(&withdrawn);
                tokio::spawn(async move {
                    let answer = service.finish_launch(pending).await;
                    write_frame(
                        &answering_writable,
                        &sender,
                        &answer,
                        &answering_withdrawn,
                        true,
                    )
                    .await
                });
            }
            // An admitted operation the upstream has not answered is answered on its own task for
            // the same reason: the transport work is the upstream's, and this loop owes the same
            // client its input, its interrupt and its keepalive while that work is happening.
            if let Some(pending) = state.pending_upstream.take() {
                let service = Arc::clone(&self);
                let sender = Arc::clone(&writer);
                let answering_writable = writable.clone();
                let answering_withdrawn = Arc::clone(&withdrawn);
                tokio::spawn(async move {
                    let answer = service.finish_upstream(pending).await;
                    write_frame(
                        &answering_writable,
                        &sender,
                        &answer,
                        &answering_withdrawn,
                        true,
                    )
                    .await
                });
            }
            if let Some(reply) = reply {
                // A close that was admitted happens, whether or not its acceptance can be written.
                // What the two bounds here separate is the write and the delivery: the write gets
                // its own bound, because a peer that has stopped reading must not hold a session
                // closing for as long as it stays away; the wait for a *proxy* to pass the
                // acceptance on starts after the write succeeded, so it cannot run out while the
                // acceptance is still on its way.
                let closing = state.close_gate.take();
                // A write this bound abandons part way through leaves the connection carrying
                // nothing more, which `false` is read as below. The close still happens: it was
                // admitted.
                let written = tokio::time::timeout(
                    crate::runtime::ACCEPTANCE_WRITE_TIMEOUT,
                    write_frame(&writable, &writer, &reply, &withdrawn, protected),
                )
                .await
                .unwrap_or_default();
                if let Some((action_id, gate)) = closing {
                    if written && state.client_kind == LocalClientKind::Controller {
                        // The requester is not the peer that was just written to: the daemon still
                        // has to pass the acceptance on. Termination waits for it to say so, or for
                        // the bound this owner holds from here.
                        state.pending_delivery = Some((
                            action_id,
                            gate.release_on_delivery(crate::runtime::ACCEPTANCE_DELIVERY_TIMEOUT),
                        ));
                    } else {
                        // Either the acceptance reached its own requester, or it reached nobody and
                        // never will. Both release the gate now.
                        gate.release();
                    }
                }
                if !written {
                    break;
                }
                // A controller announces itself in its hello; the worker answers with a challenge
                // it will only accept once.
                if let Some(challenge) = state.pending_challenge.take()
                    && !write_frame(&writable, &writer, &challenge, &withdrawn, protected).await
                {
                    break;
                }
                // A newly accepted attention connection states the privacy fence before anything
                // else it carries. One whose statement cannot be written whole, or cannot name the
                // journal's generation, is ended, and the next connection states the fence instead.
                if let Some(statement) = state.pending_statement.take() {
                    let deadline = tokio::time::Instant::now()
                        + crate::attention_fence::ATTENTION_BARRIER_WAIT;
                    let stated = match self.state_fence(connection_id, statement, deadline) {
                        Some(stating) => stating.await.unwrap_or(false),
                        None => false,
                    };
                    if !stated {
                        break;
                    }
                }
            }
            if state.subscribed.is_none() {
                continue;
            }
            if let Some((attachment_id, mut stream)) = state.subscribed.take() {
                // A connection has one delivery writing at a time. The one this subscription
                // replaces stops between two frames: a frame it has begun is finished, because one
                // cut part way would end the connection, and it begins no other, except the
                // keepalive that completes a closure notice it has already written. The new one
                // begins its first frame only once the old one has stopped, so the peer is sent
                // the old stream's last frame whole and then the new stream.
                #[cfg(feature = "testing")]
                let watched = if state.delivery.is_some() {
                    self.wait_before_replacing_delivery().await
                } else {
                    None
                };
                let previous = state
                    .delivery
                    .take()
                    .map(|previous| previous.replace(&writer));
                #[cfg(feature = "testing")]
                if let Some(replaced) = watched {
                    let _ = replaced.send(());
                }
                let (replacement, replaced) = tokio::sync::oneshot::channel::<()>();
                // And a withdrawn connection starts none at all. The task is created holding a
                // permit it has to be given before it does anything, and the permit is only sent
                // once its abort handle is installed in a registration that still stands. The two
                // are therefore one step: nothing can start delivering between the check and the
                // moment a withdrawal could stop it.
                let (start, started) = tokio::sync::oneshot::channel::<()>();
                // The latch the connection's own writes watch. This task watches it too, because
                // aborting the task only takes effect where it yields, and a task with every chunk
                // ready to go does not yield between them.
                let mut outlet = Outlet {
                    writable: registration.writable.clone(),
                    writer: Arc::clone(&writer),
                    withdrawn: Arc::clone(&registration.withdrawn),
                    replaced,
                };
                let stream_id = state.stream_id.clone();
                let restoration = state.restoration.take();
                let task = tokio::spawn(async move {
                    // Nothing before this line touches the connection. A permit that never arrives
                    // means the registration was withdrawn while this task was being created.
                    if started.await.is_err() {
                        return;
                    }
                    // The delivery this one replaced finishes the frame it had begun first.
                    if let Some(previous) = previous {
                        previous.stopped().await;
                    }
                    let mut sequence = 0_u64;
                    // The screen this attachment joins on is the canonical screen as it is now,
                    // drawn from the terminal engine's own state. It is not the raw history.
                    // Replaying that would replay whatever it contained — a clipboard write, a
                    // bell, a query whose answer would arrive at the wrong moment — into a terminal
                    // that was not there when any of it happened.
                    let live_from = restoration.as_ref().map_or(0, |joined| joined.cursor);
                    if let Some(joined) = restoration {
                        if let Some(gap) = joined.gap.as_ref()
                            && let Some(notification) =
                                notification(&stream_id, sequence, "session.gap", gap)
                        {
                            sequence += 1;
                            if !outlet.write(&notification).await {
                                return;
                            }
                        }
                        if !send_screen(
                            &mut outlet,
                            &stream_id,
                            &mut sequence,
                            joined.cursor,
                            &joined.bytes,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    loop {
                        // Waiting for the next delivery is between two frames too, and a replaced
                        // delivery stops there rather than keeping its successor waiting.
                        let delivery = tokio::select! {
                            biased;
                            _ = &mut outlet.replaced => break,
                            delivery = stream.recv() => match delivery {
                                Some(delivery) => delivery,
                                None => break,
                            },
                        };
                        let delivered = delivery.len();
                        let written = match delivery {
                            OutputDelivery::Bytes { cursor, bytes } => {
                                // Anything the screen already covered is dropped here rather than
                                // sent again; a batch that straddles the boundary is trimmed to
                                // the part that follows it.
                                let end = cursor + bytes.len() as u64;
                                if end <= live_from {
                                    stream.written(delivered);
                                    continue;
                                }
                                let skip = usize::try_from(live_from.saturating_sub(cursor))
                                    .unwrap_or(0)
                                    .min(bytes.len());
                                send_stream(
                                    &mut outlet,
                                    &stream_id,
                                    &mut sequence,
                                    cursor + skip as u64,
                                    &bytes[skip..],
                                )
                                .await
                            }
                            // A rendering is one screen at one cursor, however many frames it
                            // takes: its cursor is the state it describes rather than an offset,
                            // so the parts do not carry advancing cursors of their own.
                            OutputDelivery::Screen { cursor, bytes } => {
                                send_screen(&mut outlet, &stream_id, &mut sequence, cursor, &bytes)
                                    .await
                            }
                            // A projection event is state, not a span of the stream: its cursor
                            // says which screen it describes and the client applies it to the one
                            // it holds. The event names the type it is published under, so there
                            // is one place that decides that rather than one per variant.
                            OutputDelivery::Projection { event, .. } => {
                                let event_type = event.event_type();
                                let frame = match event.as_ref() {
                                    ProjectionEvent::Reset(reset) => {
                                        notification(&stream_id, sequence, event_type, reset)
                                    }
                                    ProjectionEvent::Snapshot(header) => {
                                        notification(&stream_id, sequence, event_type, header)
                                    }
                                    ProjectionEvent::Rows(page) => {
                                        notification(&stream_id, sequence, event_type, page)
                                    }
                                    ProjectionEvent::Delta(delta) => {
                                        notification(&stream_id, sequence, event_type, delta)
                                    }
                                };
                                let Some(frame) = frame else {
                                    continue;
                                };
                                sequence += 1;
                                outlet.write(&frame).await
                            }
                            // An attachment event about this attachment's own input. It carries
                            // no output, so it neither advances the output stream nor waits behind
                            // one: the fence the client's keystrokes waited for is not a question
                            // about the screen.
                            // A resolution of this session's agent.
                            OutputDelivery::AgentResource { event, .. } => {
                                let Some(notification) = notification(
                                    &stream_id,
                                    sequence,
                                    kr_protocol::projection::AGENT_RESOURCE_EVENT,
                                    &*event,
                                ) else {
                                    continue;
                                };
                                sequence += 1;
                                outlet.write(&notification).await
                            }
                            // An announcement about one of this session's agent instances.
                            OutputDelivery::AgentInstance { event, .. } => {
                                let Some(notification) = notification(
                                    &stream_id,
                                    sequence,
                                    kr_protocol::projection::AGENT_INSTANCE_EVENT,
                                    &*event,
                                ) else {
                                    continue;
                                };
                                sequence += 1;
                                outlet.write(&notification).await
                            }
                            OutputDelivery::EditorBusy(event) => {
                                let Some(notification) = notification(
                                    &stream_id,
                                    sequence,
                                    kr_protocol::root::EDITOR_BUSY_EVENT,
                                    &*event,
                                ) else {
                                    continue;
                                };
                                sequence += 1;
                                outlet.write(&notification).await
                            }
                            OutputDelivery::Resync(marker) => {
                                let Some(notification) =
                                    notification(&stream_id, sequence, "session.resync", &marker)
                                else {
                                    continue;
                                };
                                sequence += 1;
                                outlet.write(&notification).await
                            }
                            OutputDelivery::Detached => {
                                // The attachment has ended. The client is told so it can put its
                                // terminal back, rather than waiting for output that is not coming.
                                if let Some(notification) = notification(
                                    &stream_id,
                                    sequence,
                                    "session.detached",
                                    &kr_protocol::attachment::SessionDetachParams {
                                        attachment_id: Nullable::some(attachment_id),
                                        line_token: Nullable::null(),
                                    },
                                ) {
                                    let _ = outlet.write(&notification).await;
                                }
                                return;
                            }
                            OutputDelivery::Closed(notice) => {
                                // The session has closed. How it ended is the last thing its
                                // attachment is sent, after every byte it was owed, so the client
                                // ends knowing why rather than finding a connection that stopped.
                                // The notice is released once the connection has it or never
                                // will, and that is what the worker waits for before it exits.
                                if let Some(notification) = notification(
                                    &stream_id,
                                    sequence,
                                    kr_protocol::session::SESSION_CLOSED_EVENT,
                                    notice.record(),
                                ) && outlet.write(&notification).await
                                {
                                    // A frame written is not always a frame the connection has
                                    // taken. A pipe finishes a write in the background, a process
                                    // that exits first loses it, and the pipe takes no further
                                    // frame until it has finished. So a keepalive, which every
                                    // client already ignores, follows the notice, and its being
                                    // taken is what shows the notice was. A socket takes a write
                                    // when it is made, and there this costs one small frame. It is
                                    // part of delivering the notice, so a replacement that arrives
                                    // in between does not stop it.
                                    let _ = outlet
                                        .write_even_if_replaced(&ControlFrame::Event(
                                            ControlEvent::Keepalive,
                                        ))
                                        .await;
                                }
                                drop(notice);
                                return;
                            }
                        };
                        if !written {
                            break;
                        }
                        // Released only now. Until the bytes have reached the peer they are still
                        // queued for it, which is what the bound is about.
                        stream.written(delivered);
                    }
                    let _ = attachment_id;
                });
                // The registry holds the handle too, so a withdrawal can stop the delivery without
                // waiting for this loop to come back round. Installing the handle and deciding
                // whether the task may start happen under the registration's own lock, so a
                // withdrawal either finds the handle and aborts the task, or arrives first and the
                // permit is never sent.
                let still_admitted = {
                    let mut held = registration
                        .delivery
                        .lock()
                        .expect("the delivery slot is not poisoned");
                    let admitted = self
                        .admitted
                        .lock()
                        .expect("the connection registry is not poisoned")
                        .contains_key(&connection_id);
                    if admitted {
                        *held = Some(task.abort_handle());
                    }
                    admitted
                };
                if still_admitted && start.send(()).is_ok() {
                    state.delivery = Some(Delivery { task, replacement });
                } else {
                    task.abort();
                }
            }
        }
        // A close whose acceptance was never confirmed delivered still happens. The connection is
        // gone, so nothing is going to confirm it.
        if let Some((_, gate)) = state.close_gate.take() {
            gate.release();
        }
        if let Some((_, delivery)) = state.pending_delivery.take() {
            delivery.confirm();
        }
        // A connection that goes away takes its delivery task and its attachments with it.
        // Undelivered input from them is discarded rather than replayed.
        if let Some(delivery) = state.delivery.take() {
            delivery.abort();
        }
        // And a page it was holding, which nobody is left to read.
        drop(state.page_cancel.take());
        if let Some(task) = state.page_task.take() {
            task.abort();
        }
        for attachment_id in state.take_attachments() {
            let mut session = self.runtime.session();
            let _ = session.detach(attachment_id);
            // The fence this detach moved, and any terminator it produced, reach the writer here.
            self.runtime.flush_locked(&mut session);
            self.forget_remote_attachment(attachment_id);
        }
        // A window that outlived its connection could first-admit a request through a connection
        // that no longer exists, so the connection's windows go when it does, and so does its
        // registration.
        self.windows.retire_connection(connection_id);
        self.deregister(connection_id);
        Ok(())
    }

    /// Returns the refusal a session owes while its managed integration has never qualified.
    ///
    /// A session with no managed editor is never unqualified: it claims none of this contract, and
    /// whether it started is its own launch's answer.
    fn unqualified(&self) -> Option<kr_protocol::error::ProtocolError> {
        let session = self.runtime.session();
        let driver = session.fence()?;
        if driver.phase().ever_qualified() {
            return None;
        }
        Some(kr_protocol::error::ProtocolError::new(
            kr_protocol::error::ErrorCode::ResourceUnavailable,
            "this session's root integration has not qualified yet, so this worker proves nothing \
             for it",
        ))
    }

    async fn handle(
        &self,
        state: &mut ConnectionState,
        peer: &PeerIdentity,
        message: ControlFrame,
    ) -> Option<ControlFrame> {
        // The attention connection carries the attention requests and nothing else once it speaks
        // for a generation. It holds no authority to act and forwards no caller, so anything else
        // on it is refused rather than served.
        if state.controller_role == ControllerConnectionRole::Attention
            && state.controller
            && !matches!(
                message,
                ControlFrame::AttentionSources(_)
                    | ControlFrame::AttentionText(_)
                    | ControlFrame::AttentionBarrierAcknowledged(_)
            )
        {
            return Some(failure(
                request_id_of(&message),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "the attention connection carries attention requests and nothing else",
                ),
            ));
        }
        match message {
            ControlFrame::Hello(hello) => Some(self.hello(state, peer, &hello)),
            ControlFrame::VerifyChallenge(challenge) => {
                // A managed session that has never qualified proves nothing. The endpoint is open
                // before the integration is live so that a session still being created is
                // reachable, and a daemon that restarted in that moment would otherwise take this
                // proof, publish the worker and answer the create as a live session before the
                // reader's hooks ever came up. A session that qualified and then degraded still
                // proves itself: it is a session somebody is using.
                if let Some(error) = self.unqualified() {
                    return Some(failure(state.next_request_id(), &error));
                }
                match self.identity.answer(&challenge, &self.endpoint.as_text()) {
                    Ok(proof) => Some(ControlFrame::VerifyProof(proof)),
                    Err(error) => Some(failure(
                        state.next_request_id(),
                        &WorkerError::from(error).to_protocol_error(),
                    )),
                }
            }
            ControlFrame::ControllerRole(role) => Some(Self::declare_role(state, role)),
            ControlFrame::GenerationToken(token) => Some(self.accept_generation(state, &token)),
            ControlFrame::AcceptanceDelivered(action_id) => {
                // The proxy has passed the acceptance on. Whatever it names, only the close this
                // connection is holding can be released by it.
                if let Some((held, delivery)) = state.pending_delivery.take() {
                    if held == action_id {
                        delivery.confirm();
                    } else {
                        state.pending_delivery = Some((held, delivery));
                    }
                }
                None
            }
            ControlFrame::AuthorityRevision(notice) => {
                Some(self.acknowledge_revision(state, &notice))
            }
            ControlFrame::Request(request) => {
                // A source that asked to wait waits here: outside the session lock, outside the
                // dispatch barrier and outside any transaction. Section 11 makes a long poll an
                // asynchronous subscription, renewed in bounded steps, that returns the same
                // durable question when it times out and notifies nobody a second time.
                self.wait_for_answer(state, &request).await;
                let caller = Caller::local(state.actor_id.clone());
                Some(self.request(state, &request, &caller))
            }
            ControlFrame::Mutation(mutation) => {
                let caller = Caller::local(state.actor_id.clone());
                let reply = self
                    .mutation(
                        state,
                        &mutation,
                        &caller,
                        Freshness::Window(self.clock.now()),
                        false,
                    )
                    .await;
                // A launch the reader is deciding and an operation the upstream has not answered
                // both have no answer yet, and this request is written when one of them does.
                (state.pending_launch.is_none() && state.pending_upstream.is_none())
                    .then_some(reply)
            }
            ControlFrame::Forwarded(forwarded) => {
                let reply = self.forwarded(state, &forwarded).await;
                (state.pending_launch.is_none() && state.pending_upstream.is_none())
                    .then_some(reply)
            }
            ControlFrame::ForwardedRead(forwarded) => Some(self.forwarded_read(state, &forwarded)),
            ControlFrame::AttentionSources(request) => self.attention_sources(state, request),
            ControlFrame::AttentionText(request) => Some(self.attention_text(state, &request)),
            ControlFrame::AttentionBarrierAcknowledged(acknowledgement) => {
                // Only the daemon's current attention connection speaks for the daemon this worker
                // answers to now; an acknowledgement anywhere else is answered with nothing.
                if self.check_attention_link(state).is_ok() {
                    self.attention_fence
                        .acknowledged(state.connection_id, acknowledgement.sequence.get());
                }
                None
            }
            _ => Some(failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "a worker endpoint does not accept this message",
                ),
            )),
        }
    }

    /// Waits for a source's own question to move, when the request asked to wait.
    ///
    /// The caller's binding and its token are checked first, so a wait tells an unauthorised
    /// caller nothing about somebody else's question; anything that fails here simply does not
    /// wait, and the read that follows returns the failure. The wait is renewed in bounded steps
    /// rather than held as one long sleep, so an expiry that falls due while nobody is asking is
    /// still noticed, and the read that follows is the ordinary one.
    async fn wait_for_answer(&self, state: &ConnectionState, request: &Request) {
        if request.method.method() != Some(Method::QuestionReadOwn) {
            return;
        }
        let Ok(params) = request
            .params
            .to_typed::<kr_protocol::question::QuestionReadOwnParams>()
        else {
            return;
        };
        let Some(wait) = params.wait_ms.as_ref().copied() else {
            return;
        };
        let Ok(source) = self.bind_source(state) else {
            return;
        };
        // The token is checked before anything waits. A caller that cannot read this question
        // cannot learn when it was answered by timing a wait either.
        if self
            .questions
            .read_own(
                &source,
                &kr_protocol::question::QuestionReadOwnParams {
                    wait_ms: kr_protocol::scalars::Nullable::null(),
                    ..params.clone()
                },
                self.question_clock(),
            )
            .is_err()
        {
            return;
        }
        let bounded =
            kr_protocol::question::bounded_wait(Some(wait), kr_protocol::question::MAX_WAIT);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(bounded.get());
        let step = std::time::Duration::from_millis(kr_protocol::question::WAIT_RENEWAL.get());
        while tokio::time::Instant::now() < deadline {
            // The subscription is taken before the state is read. Registering afterwards would
            // leave a window in which an answer arrives between the read and the wait, and the
            // caller would sleep through its own answer until the next renewal.
            let waiting = self.questions.subscribe();
            let _ = self.questions.sweep(self.question_clock());
            match self.questions.question(params.question_id) {
                Ok(question) if question.state.is_resolved() => return,
                Err(_) => return,
                Ok(_) => {}
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let _ = tokio::time::timeout(remaining.min(step), waiting).await;
        }
    }

    fn hello(
        &self,
        state: &mut ConnectionState,
        peer: &PeerIdentity,
        hello: &LocalHello,
    ) -> ControlFrame {
        if state.negotiated {
            // One connection, one identity. Sending a second hello would otherwise let a fenced
            // controller reintroduce itself as a local caller and skip the authority check.
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::UnsupportedSchema,
                    "this connection has already negotiated; open another one to change client",
                ),
            );
        }
        if !hello
            .offered_versions
            .iter()
            .any(|offered| offered.major == PROTOCOL_VERSION.major)
        {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::UnsupportedSchema,
                    format!(
                        "this host speaks protocol {PROTOCOL_VERSION}; the client offered none of it"
                    ),
                ),
            );
        }
        // A peer that says it can hold no outstanding mutation at all is refused rather than
        // quietly read as one. Section 23's negotiated floor is the smallest connection this host
        // serves, and a connection that admits nothing is not a connection: reading nought as one
        // would let a client negotiate a limit this host then ignores.
        if hello.max_receive.max_outstanding_mutations.get() == 0 {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "a connection holds at least one outstanding mutation; offering none is not a \
                     limit this host serves",
                ),
            );
        }
        state.negotiated = true;
        state.client_kind = hello.client;
        // The peer's offered limits bound what this worker sends it, and never raise this host's
        // own: a client that offers more than this host will accept does not get more.
        state.peer_limits = kr_protocol::hello::ReceiveLimits {
            max_control_frame_len: kr_protocol::scalars::U64::new(
                hello
                    .max_receive
                    .max_control_frame_len
                    .get()
                    .min(kr_protocol::limits::MAX_CONTROL_FRAME_LEN as u64),
            ),
            max_input_frame_len: kr_protocol::scalars::U64::new(
                hello
                    .max_receive
                    .max_input_frame_len
                    .get()
                    .min(kr_protocol::limits::MAX_INPUT_FRAME_LEN as u64),
            ),
            max_attachment_frame_len: hello.max_receive.max_attachment_frame_len,
            max_outstanding_mutations: hello.max_receive.max_outstanding_mutations,
            max_send_queue_bytes: kr_protocol::scalars::U64::new(
                hello
                    .max_receive
                    .max_send_queue_bytes
                    .get()
                    .min(kr_protocol::limits::MAX_SEND_QUEUE_BYTES as u64),
            ),
        };
        if hello.client == LocalClientKind::Controller {
            // A controller has to prove which generation it speaks for before it acts. The
            // challenge is issued here, bound to this connection, and consumed exactly once.
            state.pending_challenge = Self::generation_challenge(state);
        }
        // The window is issued when the connection is authenticated, not when it was accepted, so
        // its deadline starts from the handshake the client will quote it against.
        let Ok(action_window) = self.issue_window(state.connection_id) else {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    "this host could not issue an action window for the connection",
                ),
            );
        };
        ControlFrame::HelloAck(Box::new(LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Worker,
            connection_id: state.connection_id,
            environment_id: self.environment_id,
            boot_identity: self.boot_identity.clone(),
            peer: peer.to_wire(),
            action_window,
            capabilities: self.stated_capabilities(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
        }))
    }

    /// What this worker states about itself in its answer to a hello.
    ///
    /// The clock floor it maps, by the floor's identity, so a control daemon can tell whether this
    /// worker decides UTC deadlines from the same floor as it does. A worker that maps none states
    /// none.
    fn stated_capabilities(&self) -> CanonicalSet<kr_protocol::ids::CapabilityId> {
        self.time
            .floor_identity()
            .map(|identity| kr_protocol::local::utc_floor_capability(identity.as_bytes()))
            .into_iter()
            .collect()
    }

    /// Issues an action window for one authenticated connection.
    fn issue_window(&self, connection_id: ConnectionId) -> Result<ActionWindow> {
        self.windows
            .issue(connection_id, self.boot_epoch)
            .map_err(|error| WorkerError::ResourceUnavailable {
                detail: error.to_string(),
            })
    }

    /// Issues a challenge a controller must answer before it speaks for a generation.
    #[must_use]
    pub fn generation_challenge(state: &mut ConnectionState) -> Option<ControlFrame> {
        let nonce = kr_ipc::verify::fresh_challenge().ok()?.nonce;
        state.generation_nonce = Some(nonce);
        Some(ControlFrame::GenerationChallenge(GenerationChallenge {
            nonce,
        }))
    }

    /// Takes the control daemon's request for this session's attention source records.
    ///
    /// Only on the daemon's attention connection, bound to the generation this worker accepts.
    /// The page is read and, when there is nothing to answer with yet, held on a task of its own,
    /// so the connection goes on serving text requests while it waits.
    fn attention_sources(
        &self,
        state: &mut ConnectionState,
        request: kr_protocol::attention::AttentionSourcesRequest,
    ) -> Option<ControlFrame> {
        if let Err(error) = self.check_attention_link(state) {
            return Some(failure(request.request_id, &error.to_protocol_error()));
        }
        self.attention_fence.named(
            state.connection_id,
            request.recorded_generation.0.map(U64::get),
        );
        state.pending_page = Some(PendingPage {
            request,
            max_bytes: Self::frame_bytes(state),
        });
        None
    }

    /// Answers the control daemon's request for the text of records its attention store names.
    ///
    /// The answer is decided under the privacy fence ([`crate::attention_fence`]). Where the
    /// transitions stand is noted before the records are read, and the answer keeps its text only
    /// when no transition is raised and none was raised or settled meanwhile, and the daemon's
    /// recorded generation is not behind the one the answer was decided under. Its lease is then
    /// registered, under the daemon generation of this connection, before it leaves.
    fn attention_text(
        &self,
        state: &ConnectionState,
        request: &kr_protocol::attention::AttentionTextRequest,
    ) -> ControlFrame {
        if let Err(error) = self.check_attention_link(state) {
            return failure(request.request_id, &error.to_protocol_error());
        }
        let recorded = request.recorded_generation.0.map(U64::get);
        self.attention_fence.named(state.connection_id, recorded);
        let noted = self.attention_fence.note();
        let mut answer =
            match self.read_attention(|journal| crate::attention_source::texts(journal, request)) {
                Ok(answer) => answer,
                Err(error) => return failure(request.request_id, &error.to_protocol_error()),
            };
        if answer.texts.iter().any(|text| text.text.0.is_some()) {
            let leased = self.attention_fence.lease(
                noted,
                state.generation.map_or(0, ControllerGeneration::get),
                answer.privacy_generation.0.map(U64::get),
                recorded,
            );
            match leased {
                Some(until) => answer.release_until_boot_ms = U64::new(until),
                None => {
                    for text in &mut answer.texts {
                        text.text = Nullable::null();
                    }
                    answer.release_until_boot_ms = U64::ZERO;
                }
            }
        }
        let answer = ControlFrame::AttentionTextAnswer(Box::new(answer));
        let measured = crate::attention_source::measure(&answer);
        let frame = Self::frame_bytes(state);
        if measured > frame {
            return failure(
                request.request_id,
                &WorkerError::InvalidArgument(format!(
                    "the text of these records is {measured} bytes and this connection said it \
                     can receive {frame}: ask for fewer records"
                ))
                .to_protocol_error(),
            );
        }
        answer
    }

    /// Refuses an attention request anywhere but on the daemon's current attention connection.
    fn check_attention_link(&self, state: &ConnectionState) -> Result<()> {
        if state.client_kind != LocalClientKind::Controller
            || state.controller_role != ControllerConnectionRole::Attention
        {
            return Err(WorkerError::PermissionDenied {
                detail: "attention records are read only over the control daemon's attention \
                         connection"
                    .to_owned(),
            });
        }
        self.check_authority(state)
    }

    /// Reads the session's journal through the attention link's own reading connection.
    ///
    /// A read that fails drops the connection, so the next request opens it again rather than
    /// reading through a connection that has gone bad.
    fn read_attention<T>(
        &self,
        read: impl FnOnce(&crate::journal::Journal) -> Result<T>,
    ) -> Result<T> {
        let mut reader =
            self.attention_reader
                .lock()
                .map_err(|_| WorkerError::JournalUnavailable {
                    detail: "the attention reader's lock is poisoned".to_owned(),
                })?;
        if reader.is_none() {
            let Some(path) = self.journal_path.as_ref() else {
                return Err(WorkerError::JournalUnavailable {
                    detail: "this session keeps no journal, so it has no attention records to read"
                        .to_owned(),
                });
            };
            *reader = Some(crate::journal::Journal::open_read_only(path)?);
        }
        let journal = reader.as_ref().expect("the reader was opened a moment ago");
        let answer = read(journal);
        if answer.is_err() {
            *reader = None;
        }
        answer
    }

    /// Returns the privacy generation the session's journal holds, read through the attention
    /// link's own reading connection: none when it holds no privacy record, and unreadable when the
    /// journal cannot be read.
    fn journal_generation(&self) -> crate::attention_fence::JournalGeneration {
        match self.read_attention(crate::journal::Journal::read_privacy) {
            Ok(record) => crate::attention_fence::JournalGeneration::Read(
                record.map(|privacy| privacy.generation),
            ),
            Err(_) => crate::attention_fence::JournalGeneration::Unreadable,
        }
    }

    /// Returns this session's attention subsystem for privacy mode, over the worker's fence.
    ///
    /// It is one of the subsystems the caller that enables privacy mode drives, and it reports the
    /// control daemon's record of the new generation as outstanding until the daemon names it.
    #[must_use]
    pub fn attention_privacy(&self) -> crate::attention_fence::AttentionPrivacy {
        crate::attention_fence::AttentionPrivacy::new(Arc::clone(&self.attention_fence))
    }

    /// Raises a privacy transition before a generation that enables privacy mode is committed, and
    /// returns once the commit may proceed.
    ///
    /// The transition is raised in the worker's fence first, so from then on no text answer
    /// carries text, and a statement saying so goes to the control daemon on the current attention
    /// connection. Within [`crate::attention_fence::ATTENTION_BARRIER_WAIT`], for the write and the
    /// answer together, the daemon acknowledging that statement or a later one on the connection
    /// current then means it has stopped releasing this session's text; the commit then waits only
    /// for leases issued under other daemon generations. Without that acknowledgement it waits for
    /// every lease this worker has issued, so no text decided before the commit can be released
    /// after it, whatever any daemon holds. Either way it never waits on the daemon for longer
    /// than one lease after the raise.
    ///
    /// One transition is raised at a time; a second raise waits until the first is settled. The
    /// caller settles the one returned once it has tried to commit, whether the commit succeeded
    /// or failed, and a transition dropped without that, the future of this call included, is
    /// settled then.
    pub async fn raise_privacy_transition(self: &Arc<Self>) -> PrivacyTransition {
        let turn = self.attention_fence.turn().await;
        let deadline = tokio::time::Instant::now() + crate::attention_fence::ATTENTION_BARRIER_WAIT;
        let raised = self.attention_fence.raise(|| self.journal_generation());
        let transition = PrivacyTransition {
            service: Arc::clone(self),
            turn: Some(turn),
        };
        let sequence = raised.frame.sequence.get();
        if let Some(connection_id) = raised.connection_id
            && let Some(stating) = self.state_fence(connection_id, raised, deadline)
        {
            let _ = stating.await;
        }
        let acknowledged = self
            .attention_fence
            .until_acknowledged(sequence, deadline)
            .await;
        self.attention_fence.until_leases_end(acknowledged).await;
        transition
    }

    /// Sends a statement of the privacy fence on an attention connection before `deadline`, on a
    /// task of its own, and returns that task; nothing when there is no runtime to run it on, and
    /// the connection is ended then instead.
    ///
    /// The task is the statement's owner, so a caller that stops waiting for it does not stop it.
    /// A statement that cannot be written whole ends the connection, a frame none of which went
    /// being taken back first, and so does one made without being able to read the journal: the
    /// daemon then opens the next connection, and the first frame on it states the fence as it is
    /// by then. The task answers whether the statement was written whole and the journal read.
    fn state_fence(
        self: &Arc<Self>,
        connection_id: ConnectionId,
        statement: crate::attention_fence::Statement,
        deadline: tokio::time::Instant,
    ) -> Option<tokio::task::JoinHandle<bool>> {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.withdraw(connection_id);
            return None;
        };
        let service = Arc::clone(self);
        let crate::attention_fence::Statement {
            frame, unreadable, ..
        } = statement;
        Some(runtime.spawn(async move {
            let named = !unreadable;
            let registration = service
                .admitted
                .lock()
                .expect("the connection registry is not poisoned")
                .get(&connection_id)
                .cloned();
            let Some(registration) = registration else {
                return false;
            };
            let written = write_within(
                &registration.writable,
                &registration.writer,
                &ControlFrame::AttentionBarrier(frame),
                &registration.withdrawn,
                deadline,
            )
            .await;
            if !written || !named {
                service.withdraw(connection_id);
            }
            written && named
        }))
    }

    /// Reads one page, holding the request while there is nothing to answer with.
    ///
    /// It answers at once when either source has a record past its cursor, when the session's
    /// privacy generation has moved since the request arrived or is past the generation the
    /// request says the daemon has recorded, and when the request's bound runs out. Both
    /// subscriptions are taken before each read, so a commit between the read and the wait wakes
    /// the wait rather than falling between them. A request a newer one replaced
    /// answers nothing: the replacement is checked before every read and before the answer is
    /// handed over, and it wins a wait that something else ends at the same moment.
    async fn finish_page(
        &self,
        pending: PendingPage,
        cancelled: &mut tokio::sync::oneshot::Receiver<()>,
    ) -> Option<ControlFrame> {
        let request = pending.request;
        let bound = request
            .wait_ms
            .get()
            .min(kr_protocol::attention::MAX_ATTENTION_SOURCE_WAIT_MS);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(bound);
        let recorded = request.recorded_generation.0.map(U64::get);
        let mut generation: Option<Option<U64>> = None;
        loop {
            if replaced(cancelled) {
                return None;
            }
            let questions_moved = self.questions.subscribe();
            let journal_moved = self
                .journal_changes
                .as_ref()
                .map(|changes| changes.notified());
            let built_at = self.shared_clock.boot_elapsed_ms();
            let mut page = match self.read_attention(|journal| {
                crate::attention_source::page(journal, &request, built_at, pending.max_bytes)
            }) {
                Ok(page) => page,
                Err(error) => return Some(failure(request.request_id, &error.to_protocol_error())),
            };
            page.output_floor =
                Nullable::some(U64::new(self.runtime.session().oldest_retained_cursor()));
            let started = *generation.get_or_insert(page.privacy_generation.0);
            let answer = !page.questions.records.is_empty()
                || !page.host_events.records.is_empty()
                || page.privacy_generation.0 != started
                || crate::attention_fence::behind(
                    recorded,
                    page.privacy_generation.0.map(U64::get),
                )
                || tokio::time::Instant::now() >= deadline;
            if answer {
                if replaced(cancelled) {
                    return None;
                }
                // What does not fit the frame is left for the next page; only a page that cannot
                // carry even one record is refused.
                if !crate::attention_source::fit(&mut page, pending.max_bytes) {
                    return Some(failure(
                        request.request_id,
                        &WorkerError::InvalidArgument(format!(
                            "one attention record makes a page larger than the {} bytes this \
                             connection said it can receive",
                            pending.max_bytes
                        ))
                        .to_protocol_error(),
                    ));
                }
                return Some(ControlFrame::AttentionSourcePage(Box::new(page)));
            }
            tokio::select! {
                biased;
                _ = &mut *cancelled => return None,
                () = questions_moved => {}
                () = async {
                    match journal_moved {
                        Some(moved) => moved.await,
                        None => std::future::pending().await,
                    }
                } => {}
                () = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    /// Records what a controller connection is for, before it presents a token.
    ///
    /// It is declared once and only before the token: a connection that could relabel itself
    /// afterwards could take the authority binding away from the connection that holds it, or give
    /// its own proxy the authority to announce a revocation.
    fn declare_role(state: &mut ConnectionState, role: ControllerConnectionRole) -> ControlFrame {
        if state.client_kind != LocalClientKind::Controller {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "only a control-daemon connection has a role to declare",
                ),
            );
        }
        if state.controller {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this connection has already presented a generation; open another one to \
                     change what it is for",
                ),
            );
        }
        state.controller_role = role;
        ControlFrame::ControllerRole(role)
    }

    fn accept_generation(
        &self,
        state: &mut ConnectionState,
        token: &kr_protocol::worker::ControllerGenerationToken,
    ) -> ControlFrame {
        let Some(nonce) = state.generation_nonce.take() else {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "a generation token answers a challenge this worker issued",
                ),
            );
        };
        // Taken before the authority lock, and held for the whole decision. A generation that
        // arrives while a mutation is between its authority check and its effect waits here, so no
        // request is ever fenced half way through.
        let _barrier = self
            .dispatch
            .lock()
            .expect("the dispatch barrier is not poisoned");
        // One lock for the whole decision. Reading the accepted generation, checking the token
        // against it and installing the new generation with the connection that presented it
        // happen without a window in between, so two tokens cannot interleave and leave the
        // generation behind the connection that is bound to it.
        let mut authority = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned");
        let acceptance = GenerationAcceptance {
            controller_public_key: self.controller_public_key,
            environment_id: self.environment_id,
            boot_identity: self.boot_identity.clone(),
            accepted_generation: authority.accepted_generation,
        };
        match check_generation_token(&acceptance, &nonce, token) {
            Ok(()) => {
                // A token for a higher generation replaces the authority, so the connection that
                // held it and every proxy of it are fenced together. Anything a previous generation
                // opened stops being served, whatever it was for.
                let superseded = authority
                    .accepted_generation
                    .is_none_or(|accepted| token.generation.get() > accepted.get());
                let mut fenced = Vec::new();
                if superseded {
                    fenced.extend(authority.bound_connection.take());
                    fenced.extend(std::mem::take(&mut authority.proxy_connections));
                    fenced.extend(authority.attention_connection.take());
                }
                authority.accepted_generation = Some(token.generation);
                match state.controller_role {
                    // Installing this connection fences whatever held the authority before it,
                    // including an earlier connection of the same generation.
                    ControllerConnectionRole::Authority => {
                        if let Some(previous) =
                            authority.bound_connection.replace(state.connection_id)
                            && previous != state.connection_id
                            && !fenced.contains(&previous)
                        {
                            fenced.push(previous);
                        }
                    }
                    // A proxy takes no authority binding, so it displaces nothing: it serves one
                    // caller the daemon authenticated, and the daemon's own connection goes on
                    // holding the authority.
                    ControllerConnectionRole::Proxy => {
                        authority.proxy_connections.insert(state.connection_id);
                    }
                    // The daemon reads this session's attention sources over one connection, so
                    // a newer one replaces the one before it, whose held request goes with it.
                    // It becomes the privacy fence's current connection in the same step, and
                    // the statement of the fence it carries first goes out after the acceptance.
                    ControllerConnectionRole::Attention => {
                        if let Some(previous) =
                            authority.attention_connection.replace(state.connection_id)
                            && previous != state.connection_id
                            && !fenced.contains(&previous)
                        {
                            fenced.push(previous);
                        }
                        state.pending_statement = Some(self.attention_fence.began(
                            state.connection_id,
                            token.generation.get(),
                            || self.journal_generation(),
                        ));
                    }
                }
                drop(authority);
                // Refusing a fenced connection's next request is not enough on its own: a
                // subscription it already started would keep delivering this session's output down
                // a connection whose authority has been withdrawn. Withdrawing the registration
                // ends that connection, which takes its delivery task and its attachments with it.
                for previous in &fenced {
                    self.withdraw(*previous);
                }
                state.controller = true;
                state.generation = Some(token.generation);
                ControlFrame::GenerationAccepted(kr_protocol::worker::GenerationAccepted {
                    generation: token.generation,
                    fenced_previous: !fenced.is_empty(),
                })
            }
            Err(error) => {
                drop(authority);
                failure(
                    RequestId::new(0),
                    &ProtocolError::new(ErrorCode::PermissionDenied, error.to_string()),
                )
            }
        }
    }

    /// Installs the authority revision the controller now holds, and fences what it removes.
    ///
    /// A revision is not a number to store. Section 9 makes a revocation complete only once every
    /// worker that could still act under the removed authority has stopped being able to, so
    /// installing one rejects every intent this worker has admitted and not yet dispatched. An
    /// intent past its dispatch marker cannot be taken back from here, and is not claimed to be.
    ///
    /// The whole sequence runs inside the dispatch barrier, so a mutation cannot be admitted under
    /// the old revision after this has begun and before it finishes. That is also what makes the
    /// fence's two answers two answers: it reads an action either before its dispatch marker, and
    /// rejects it, or after, and names it, never between the acceptance and the marker.
    ///
    /// The boundary is taken without waiting. A fence that queued for it would hold this
    /// connection, and on a host with few threads it would hold one the dispatch it is waiting for
    /// may need. Section 9 says what to do instead: a revocation a worker has not acknowledged is
    /// `pending`, and the daemon announces again. So a dispatch in flight is answered with a
    /// refusal that says to come back, which is exactly what `pending` means.
    fn acknowledge_revision(
        &self,
        state: &ConnectionState,
        notice: &kr_protocol::worker::AuthorityRevisionNotice,
    ) -> ControlFrame {
        // Who is asking, before anything at all is recorded or read. A revocation is what this
        // answers, so a caller the revocation might be *about* must not be able to satisfy it, and
        // must not be able to leave this worker holding a revision to fence on its own either. A
        // proxy connection is not that caller: it carries a device's requests and holds none of
        // this environment's authority.
        if state.client_kind != LocalClientKind::Controller
            || state.controller_role != ControllerConnectionRole::Authority
        {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "only the control daemon's authority connection announces an authority \
                     revision",
                ),
            );
        }
        if let Err(error) = self.check_authority(state) {
            return failure(RequestId::new(0), &error.to_protocol_error());
        }
        if notice.environment_id != self.environment_id {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this worker belongs to another environment",
                ),
            );
        }
        let Ok(_barrier) = self.dispatch.try_lock() else {
            // Recorded so the fence happens whether or not the daemon ever announces again: the
            // host's own maintenance runs it inside the same boundary, and the next announcement
            // then finds it done. A refusal that left nothing behind would make progress depend on
            // a caller.
            //
            // The binding is checked again as part of recording it, under one lock. This is the
            // path where a replacement can overtake the caller: it is here because the dispatch
            // boundary is *not* held, and installing a generation takes that boundary before it
            // changes the binding. So the check above can have been true and stopped being true,
            // and work recorded after that would be work left behind by a connection this worker
            // has stopped answering to.
            if let Err(error) = self.owe_fence(state, notice.revision) {
                return failure(RequestId::new(0), &error.to_protocol_error());
            }
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    "this worker is inside a dispatch transition, so the revocation is pending \
                     for it until the announcement is made again",
                ),
            );
        };
        // The boundary is held now, and a replacement cannot arrive while it is: installing a
        // generation takes this same boundary before it changes the binding. The binding is looked
        // at again anyway, so that what follows depends on a check made here rather than on that
        // ordering holding somewhere else.
        if let Err(error) = self.check_authority(state) {
            return failure(RequestId::new(0), &error.to_protocol_error());
        }
        // How many names of this revision's evidence the daemon already has. A first announcement
        // asks for the first page; a later one asks for what the previous answer said remained.
        let page_from = usize::try_from(notice.evidence_from).unwrap_or(usize::MAX);
        let held = {
            let authority = self
                .authority
                .lock()
                .expect("the authority lock is not poisoned");
            authority.acknowledged_revision
        };
        // Revisions are ordered and only the host issues them, so an older one never replaces a
        // newer one that has already been acknowledged.
        if held.is_some_and(|held| held.get() >= notice.revision.get()) {
            // The fence for this revision has already run, and its names are in the journal. This
            // answer is a page of them: an acknowledgement lost on the way back is the ordinary
            // case, section 9 requires the actions the fence could not take back to be named in
            // the *result*, and a page that carried nothing would lose them for good.
            // The revision the *request* names, not whatever this worker has installed since: a
            // continuation offset belongs to the list it was issued against, and applying it to a
            // newer revision's list would skip that list's beginning.
            return self.evidence_reply(state, notice.revision, page_from);
        }
        if let Err(error) = self.fence(notice.revision) {
            // The acknowledgement is what the daemon waits on before it calls a revocation
            // complete. Reporting success while the fence did not finish would answer it wrongly;
            // what the pass did name is in the journal under this revision, so the next
            // announcement names it as well as whatever the next pass reaches.
            return failure(RequestId::new(0), &error.to_protocol_error());
        }
        self.evidence_reply(state, notice.revision, page_from)
    }

    /// Fences this session for one revision, and records that it ran.
    ///
    /// The caller holds the dispatch boundary. Both callers do: the announcement, which answers
    /// with a page of what this produced, and the host's own maintenance, which runs a fence the
    /// announcement could not.
    ///
    /// The session is held from the pass until the revision is installed, because the two fences
    /// and the installation are one step: input that got past the fence and into the queue while
    /// the revision was going in would otherwise still be written to the application after the
    /// revocation had been called complete.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the pass could not finish. What it did
    /// name is in the journal, and the boundary it started from is not moved, so the next pass
    /// looks at everything this one was looking at.
    fn fence(&self, revision: kr_protocol::ids::AuthorityRevision) -> Result<()> {
        let ran_at = kr_ipc::now_ms();
        // Which controller this host answers to, because what a *previous* one collected is not
        // something the current one holds: a revocation's names are finished with when the daemon
        // that has to name them has taken them.
        let generation = {
            let authority = self
                .authority
                .lock()
                .expect("the authority lock is not poisoned");
            authority
                .accepted_generation
                .map_or(0, kr_protocol::ids::ControllerGeneration::get)
        };
        let mut session = self.runtime.session();
        let outcome = match session.journal_mut() {
            // Where the previous fence got to is the journal's own record rather than this
            // process's memory: a restarted worker that started from nothing would name the
            // session's whole history.
            Some(journal) => {
                let since = journal.fence_boundary()?;
                journal
                    .fence_for_revocation(
                        revision.get(),
                        Some(ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            format!(
                                "the authority this action was admitted under was revoked at \
                                 revision {revision}"
                            ),
                        )),
                        ran_at,
                        since,
                        generation,
                    )
                    .1
            }
            // Without a journal there is no admitted intent to fence, because no ordinary
            // mutation is admitted at all, and no event order to have a position in.
            None => Ok(0),
        };
        outcome?;
        self.fence_remote_input(&mut session, None);
        let mut authority = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned");
        authority.acknowledged_revision = Some(revision);
        // Only work this fence covered. A newer announcement can have arrived while this pass ran,
        // and clearing that would leave the maintenance with nothing to do and the newer
        // revocation waiting on a caller.
        if authority
            .owed_revision
            .is_some_and(|owed| owed.get() <= revision.get())
        {
            authority.owed_revision = None;
        }
        Ok(())
    }

    /// Runs a fence this worker was told about while it was dispatching something.
    ///
    /// The caller holds the dispatch boundary. A failure is left recorded rather than reported: the
    /// revision stays owed, and the next tick tries again.
    fn fence_what_is_owed(&self) {
        let owed = {
            let authority = self
                .authority
                .lock()
                .expect("the authority lock is not poisoned");
            let held = authority.acknowledged_revision;
            authority
                .owed_revision
                .filter(|owed| held.is_none_or(|held| held.get() < owed.get()))
        };
        if let Some(revision) = owed {
            let _ = self.fence(revision);
        }
    }

    /// Answers an announcement with one page of a revocation's fence evidence.
    ///
    /// A journal this host cannot read has no evidence to page through, and says so by carrying
    /// none: absent evidence is not empty evidence, and the daemon reads the difference.
    ///
    /// Where the announcement asks from is also what it says it already holds, and that is written
    /// down before the page is read, against the generation that said it: a revocation's names are
    /// kept until the daemon has taken them, and this is the only thing that tells this worker it
    /// has. A replacement controller holds none of what its predecessor took, and the record says
    /// so, because it belongs to a generation rather than to the environment.
    fn evidence_reply(
        &self,
        state: &ConnectionState,
        revision: kr_protocol::ids::AuthorityRevision,
        from: usize,
    ) -> ControlFrame {
        let session_id = self.runtime.session().id();
        let generation = state
            .generation
            .map_or(0, kr_protocol::ids::ControllerGeneration::get);
        let page = {
            let session = self.runtime.session();
            session.journal().map(|journal| {
                // Whether this journal can answer for the revocation at all, before anything
                // about this announcement is written down: recording what the daemon holds would
                // create the very record whose absence is the answer. Absent evidence and empty
                // evidence are different statements, and only the second may read as a fence that
                // named nothing.
                if !journal.evidence_answerable(revision.get())? {
                    return Ok(None);
                }
                journal.note_evidence_delivered(revision.get(), from as u64, generation)?;
                journal.evidence_page(revision.get(), from as u64).map(Some)
            })
        };
        let fence = match page {
            Some(Ok(page)) => page.map(|page| page.evidence()),
            Some(Err(error)) => {
                return failure(RequestId::new(0), &error.to_protocol_error());
            }
            None => None,
        };
        ControlFrame::AuthorityRevisionAck(kr_protocol::worker::AuthorityRevisionAck {
            session_id,
            revision,
            fence,
        })
    }

    /// Forgets an attachment that has gone, so the set holds only attachments that exist.
    ///
    /// Every way an attachment ends comes through here: its own detach, its connection going, and
    /// a withdrawal taking it back. A set that only grew would keep one entry per remote
    /// attachment for as long as this worker ran.
    fn forget_remote_attachment(&self, attachment_id: AttachmentId) {
        self.remote_attachments
            .lock()
            .expect("the remote attachment set is not poisoned")
            .remove(&attachment_id);
    }

    /// Takes the input lease away from a forwarded caller, with whatever it had not delivered.
    ///
    /// Section 10's input fence is what a revocation needs here. Input the worker accepted can sit
    /// in the lease's queue while the application is not taking bytes, so an acknowledgement that
    /// only fenced *admitted intents* would let keystrokes admitted under the replaced authority
    /// reach the application afterwards. Releasing the lease discards them on the same boundary
    /// the writer takes, which is the step a takeover already uses.
    ///
    /// `only` names the attachment whose authority ended, when one is known. A revision
    /// acknowledgement knows no attachment: which device the revision was about is not something
    /// this worker is told, so every forwarded lease is fenced. A grant that ran out knows exactly
    /// which attachment it belonged to, and fences nothing else: another device may hold the lease
    /// by then, and its authority is its own.
    ///
    /// Either way the device acquires the lease again on its next request, under the authority
    /// now in force; a local lease is untouched, because no revision and no grant replaces the
    /// operating-system identity behind it.
    fn fence_remote_input(&self, session: &mut Session, only: Option<AttachmentId>) {
        let lease = session.lease();
        let Some(holder) = lease.holder.0 else {
            return;
        };
        if only.is_some_and(|named| named != holder) {
            return;
        }
        let remote = self
            .remote_attachments
            .lock()
            .expect("the remote attachment set is not poisoned")
            .contains(&holder);
        if !remote {
            return;
        }
        let _ = session.release_input(holder, lease.epoch.get());
        // The fence moved, so what the writer holds has to be published with it rather than left
        // for the next caller to flush.
        self.runtime.flush_locked(session);
    }

    /// Registers one admitted connection, and returns how it learns that it has been withdrawn.
    ///
    /// The registration is written under the authority lock, in the same critical section as the
    /// check that admitted the connection, so nothing can be admitted against authority that has
    /// already been replaced.
    fn admit(
        &self,
        connection_id: ConnectionId,
        writer: &Arc<Mutex<kr_ipc::framed::FrameWriter>>,
        writable: &Writing,
    ) -> Registration {
        let registration = Registration {
            withdrawn: Arc::new(Withdrawal::default()),
            delivery: Arc::new(Mutex::new(None)),
            attachments: Arc::new(Mutex::new(Vec::new())),
            writer: Arc::clone(writer),
            writable: writable.clone(),
        };
        let _authority = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned");
        self.admitted
            .lock()
            .expect("the connection registry is not poisoned")
            .insert(connection_id, registration.clone());
        registration
    }

    /// Withdraws one connection's registration.
    ///
    /// Everything the withdrawal has to end is ended **here**, not left for the connection's own
    /// loop to notice. That loop may be blocked writing to a socket nobody is reading, and waiting
    /// for it would leave this session's authority in the hands of a peer that has stopped
    /// listening, for as long as it cares to:
    ///
    /// * the delivery task is aborted, so no more of this session's output is written;
    /// * the latch is set, so a write already waiting for the peer abandons what it was writing;
    /// * the attachments are detached, so the connection owns nothing of the session;
    /// * the frozen copy of any recovery it was reading is ended, so its memory goes back.
    fn withdraw(&self, connection_id: ConnectionId) {
        // The authority binding goes with the registration. A connection whose registration has
        // been withdrawn must not still be one a generation speaks through.
        self.unbind(connection_id);
        let held = self
            .admitted
            .lock()
            .expect("the connection registry is not poisoned")
            .remove(&connection_id);
        let Some(registration) = held else {
            return;
        };
        if let Some(task) = registration
            .delivery
            .lock()
            .expect("the delivery slot is not poisoned")
            .take()
        {
            task.abort();
        }
        {
            // The latch goes out with the writer held, which is what makes this and a write one
            // order rather than two races: a write either finished before this line or finds the
            // latch set when it takes the lock. Nothing waits for the peer while that lock is
            // held, so a peer that has stopped reading cannot hold a withdrawal up.
            let _sender = registration
                .writer
                .lock()
                .expect("the connection writer is not poisoned");
            registration.withdrawn.set();
        }
        let held = std::mem::take(
            &mut *registration
                .attachments
                .lock()
                .expect("the attachment list is not poisoned"),
        );
        for attachment_id in held {
            let mut session = self.runtime.session();
            let _ = session.detach(attachment_id);
            // The fence this detach moved, and any terminator it produced, reach the writer here.
            self.runtime.flush_locked(&mut session);
            self.forget_remote_attachment(attachment_id);
        }
        // Last, and never before the latch above. Nobody is left to read the recovery this
        // connection was paging, and a first page still being cut for it finds the latch set and
        // keeps nothing, so this cannot run before the copy it is meant to end exists.
        self.recoveries.forget(connection_id);
    }

    /// Removes one connection from whatever the accepted generation speaks through.
    fn unbind(&self, connection_id: ConnectionId) {
        {
            let mut authority = self
                .authority
                .lock()
                .expect("the authority lock is not poisoned");
            if authority.bound_connection == Some(connection_id) {
                authority.bound_connection = None;
            }
            authority.proxy_connections.remove(&connection_id);
            if authority.attention_connection == Some(connection_id) {
                authority.attention_connection = None;
            }
        }
        // And from the privacy fence, when it was the connection the fence speaks through: an
        // acknowledgement or a named generation from it no longer counts.
        self.attention_fence.ended(connection_id);
    }

    /// Removes a connection that has ended of its own accord.
    fn deregister(&self, connection_id: ConnectionId) {
        self.unbind(connection_id);
        let held = self
            .admitted
            .lock()
            .expect("the connection registry is not poisoned")
            .remove(&connection_id);
        if let Some(registration) = held {
            // The same order a withdrawal uses: the latch first, so a first page still being cut
            // for this connection keeps nothing, and the sweep after it.
            registration.withdrawn.set();
        }
        self.recoveries.forget(connection_id);
    }

    /// Refuses a request from a controller connection that does not hold current authority.
    ///
    /// A worker serves two kinds of caller. A local caller is authenticated by peer credentials and
    /// acts under the worker's own authority over its session. A controller acts for a generation,
    /// and a generation that has been superseded is exactly what fencing is for: the request is
    /// refused here, on the dispatch path, before anything reads its parameters.
    fn check_authority(&self, state: &ConnectionState) -> Result<()> {
        if state.client_kind != LocalClientKind::Controller {
            return Ok(());
        }
        let authority = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned");
        Self::check_bound(state, &authority)
    }

    /// Records the fence a refused announcement leaves behind, for a caller checked with it.
    ///
    /// The check and the record are one operation under one lock, which is what binds the deferred
    /// work to the authority that was validated. A caller that checked first and recorded
    /// afterwards could be replaced in between, and would leave this worker holding a revision to
    /// fence on behalf of a connection it no longer answers to.
    ///
    /// The highest revision wins, because an older announcement arriving late is not news. The
    /// record carries no generation of its own: a revision is the host's own, the fence it asks
    /// for is this host's own work, and a replacement controller inherits it rather than starting
    /// again.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::GenerationFenced`] when this connection no longer holds authority,
    /// in which case nothing is recorded.
    fn owe_fence(
        &self,
        state: &ConnectionState,
        revision: kr_protocol::ids::AuthorityRevision,
    ) -> Result<()> {
        let mut authority = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned");
        Self::check_bound(state, &authority)?;
        if authority
            .owed_revision
            .is_none_or(|owed| owed.get() < revision.get())
        {
            authority.owed_revision = Some(revision);
        }
        Ok(())
    }

    /// The same refusal, against an authority the caller already holds the lock on.
    ///
    /// Reading the binding and acting on it under one lock is what closes the window between them.
    fn check_bound(state: &ConnectionState, authority: &Authority) -> Result<()> {
        if !state.controller {
            return Err(WorkerError::GenerationFenced {
                detail: "this connection has not proved which controller generation it speaks for"
                    .to_owned(),
            });
        }
        let bound = match state.controller_role {
            ControllerConnectionRole::Authority => {
                authority.bound_connection == Some(state.connection_id)
            }
            ControllerConnectionRole::Proxy => {
                authority.proxy_connections.contains(&state.connection_id)
            }
            ControllerConnectionRole::Attention => {
                authority.attention_connection == Some(state.connection_id)
            }
        };
        if !bound {
            return Err(WorkerError::GenerationFenced {
                detail: "a later controller connection holds this environment's authority"
                    .to_owned(),
            });
        }
        if authority.accepted_generation != state.generation {
            return Err(WorkerError::GenerationFenced {
                detail: format!(
                    "this worker accepts generation {}",
                    authority
                        .accepted_generation
                        .map_or_else(|| "none".to_owned(), |generation| generation.to_string())
                ),
            });
        }
        Ok(())
    }

    fn request(
        &self,
        state: &mut ConnectionState,
        request: &Request,
        caller: &Caller,
    ) -> ControlFrame {
        if !state.negotiated {
            return failure(request.request_id, &not_negotiated());
        }
        if let Err(error) = self.check_authority(state) {
            return failure(request.request_id, &error.to_protocol_error());
        }
        // A read the daemon admitted under an authority revision this worker has installed past is
        // a read whose authority has been withdrawn. It matters most for raw input, which is a
        // write that travels as a request: bytes forwarded under the old revision can still be on
        // the socket when the new one is acknowledged.
        if let Err(error) = self.check_validated_revision(caller) {
            return failure(request.request_id, &error.to_protocol_error());
        }
        let Some(method) = request.method.method() else {
            return failure(request.request_id, &unlisted());
        };
        if Self::entry(method, request.method_version, caller.ingress).is_none() {
            return failure(request.request_id, &unlisted());
        }
        let outcome = match method {
            Method::SessionRead => self.session_read(&request.params),
            Method::EventsSnapshot => self.events_snapshot(state, &request.params),
            Method::HistoryPage => self.history_page(state, &request.params),
            Method::EventsSubscribe => self.events_subscribe(state, &request.params),
            Method::ActionRead => self.action_read(&caller.actor_id, &request.params),
            Method::InputWrite => self.input_write(state, &request.params, caller),
            Method::QuestionReadOwn => self.question_read_own(state, &request.params),
            Method::QuestionRead => self.question_read(&request.params),
            Method::AgentCapabilities => self.agent_capabilities(&request.params),
            Method::AgentSnapshot => self.agent_snapshot(&request.params, caller),
            Method::AgentCommands => self.agent_commands(&request.params),
            Method::AgentApprovalInspect => {
                self.agent_approval_inspect(state, &request.params, caller)
            }
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a read this worker serves",
                method.as_str()
            ))),
        };
        // Checked again, now that the read has finished. A read that passed its check and then
        // waited for the session lock can complete after the authority behind it was withdrawn,
        // and what the contract forbids is *serving* that state rather than reading it. A
        // subscription this read started is ended with the connection it belongs to.
        if let Err(error) = self.check_authority(state) {
            state.subscribed = None;
            state.restoration = None;
            return failure(request.request_id, &error.to_protocol_error());
        }
        respond(request.request_id, outcome)
    }

    /// Runs one mutation through the receipt contract.
    ///
    /// The order is the one section 9 fixes, and every step of it matters:
    ///
    /// 1. The intent is committed before the caller is told it was accepted, so a crash does not
    ///    lose an action the caller believes the host has.
    /// 2. An exact duplicate returns the retained receipt and the retained *result*. A retried
    ///    `session.attach` therefore returns the attachment the first request allocated rather than
    ///    allocating a second one, and an identifier reused with a different payload is
    ///    `ID_CONFLICT`.
    /// 3. Authority and preconditions are revalidated inside the serial path, immediately before
    ///    the dispatch marker. Durable acceptance does not preserve authority that has since gone.
    /// 4. The dispatch marker is committed **before** the effect. A failure after it is `unknown`,
    ///    never `rejected`: nothing here can prove the effect did not happen.
    ///
    /// `forwarded` says whether the answer goes to a proxy rather than to the actor whose action
    /// it is. A proxy is told when the answer came from a retained action instead of from this
    /// worker performing one, because passing a retained result on is a read of a receipt and the
    /// daemon has an authority check to make before it does that.
    async fn mutation(
        &self,
        state: &mut ConnectionState,
        mutation: &MutationRequest,
        caller: &Caller,
        freshness: Freshness,
        forwarded: bool,
    ) -> ControlFrame {
        if !state.negotiated {
            return failure(mutation.request_id, &not_negotiated());
        }
        if let Err(error) = self.check_authority(state) {
            return failure(mutation.request_id, &error.to_protocol_error());
        }
        let Some(method) = mutation.method.method() else {
            return failure(mutation.request_id, &unlisted());
        };
        let Some(entry) = Self::entry(method, mutation.method_version, caller.ingress) else {
            return failure(mutation.request_id, &unlisted());
        };
        let dispatched = self.receipted(state, mutation, method, entry, caller, freshness);
        let answered = match dispatched {
            Ok(Answered::Launch {
                transaction,
                receiver,
            }) => {
                // The answer is the reader's, and it arrives later. Waiting for it on this task
                // would stop the connection reading anything else: the same client's next
                // keystroke, its interrupt, its detach and its keepalive all travel on this socket.
                // So the wait, the receipt and the response leave the read loop and happen on their
                // own task, and this request is answered when the reader answers it.
                state.pending_launch = Some(PendingLaunch {
                    request_id: mutation.request_id,
                    action_id: mutation.action_id,
                    actor_id: caller.actor_id.clone(),
                    transaction,
                    receiver,
                });
                // Nothing is written now. The connection's loop finds the pending launch, hands it
                // to a task of its own and writes nothing for this request until the reader speaks.
                return ControlFrame::Event(ControlEvent::Keepalive);
            }
            // The admission is committed and the boundary is over. The transport work is the
            // upstream's, and waiting for it on this task would stop the connection reading
            // anything else: the same client's next keystroke, its interrupt, its detach and its
            // keepalive all travel on this socket. So the wait, the receipt and the response leave
            // the read loop, exactly as a launch's do.
            Ok(Answered::Upstream {
                handoff,
                action_id,
                actor_id,
            }) => {
                state.pending_upstream = Some(PendingUpstream {
                    request_id: mutation.request_id,
                    action_id,
                    actor_id,
                    handoff,
                });
                // Nothing is written now. The connection's loop finds the pending operation, hands
                // it to a task of its own and writes nothing for this request until the transport
                // has said what the upstream did.
                return ControlFrame::Event(ControlEvent::Keepalive);
            }
            other => other,
        };
        match answered {
            Ok(Answered::Performed(value)) => ControlFrame::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(value),
            }),
            Ok(Answered::Retained(value)) => {
                let response = Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Ok(value),
                };
                if forwarded {
                    ControlFrame::RetainedResponse(Box::new(response))
                } else {
                    ControlFrame::Response(response)
                }
            }
            // An upstream operation and a launch are both answered above.
            Ok(Answered::Upstream { .. } | Answered::Launch { .. }) => failure(
                mutation.request_id,
                &ProtocolError::new(
                    ErrorCode::ResourceUnavailable,
                    "the launch transaction was not resolved",
                ),
            ),
            Err(error) => failure(mutation.request_id, &error.to_protocol_error()),
        }
    }

    /// Waits for a launch the reader is deciding, records its outcome and answers the caller.
    ///
    /// It runs on its own task. The dispatch marker was committed before the request reached the
    /// reader, so a crash in between leaves the receipt `unknown`, which is exactly what a command
    /// that may be in the editor is. A receiver that ends without an answer means the session went,
    /// and the caller is owed the outcome nothing can establish rather than a claim that nothing
    /// happened.
    async fn finish_launch(&self, pending: PendingLaunch) -> ControlFrame {
        let answer = pending
            .receiver
            .await
            .unwrap_or(crate::fence::driver::LaunchAnswer::Refused {
            reason:
                kr_shell_integration::contract::requests::LaunchRejectionReason::ConfirmationLost,
            code: ErrorCode::OutcomeUnknown,
        });
        self.runtime.forget_launch(pending.transaction);
        let outcome = match answer {
            crate::fence::driver::LaunchAnswer::Installed(result) => encode(&result),
            crate::fence::driver::LaunchAnswer::Refused { reason, code } => {
                Err(WorkerError::LaunchRefused {
                    reason: reason.as_str(),
                    code,
                })
            }
        };
        self.settle(&pending.actor_id, pending.action_id, outcome.as_ref());
        respond(pending.request_id, outcome)
    }

    /// Waits for one admitted operation's upstream, records its receipt and answers the caller.
    ///
    /// It runs on its own task. The dispatch marker was committed before this was handed over, so
    /// a crash in between leaves the receipt `unknown`, which is exactly what an operation that
    /// may have reached the upstream is. The bound is this worker's own: an upstream that has not
    /// answered by then leaves an outcome nobody can establish, which section 9 records as unknown
    /// rather than as a refusal the caller would read as "nothing happened".
    async fn finish_upstream(&self, pending: PendingUpstream) -> ControlFrame {
        // Everything the broker settles happens on this task, and the resource an answer resolves
        // is settled before the receipt is recorded and before the caller hears: at the deadline,
        // what `carry` was waiting for is dropped here, and an answer's claim goes with it.
        let deadline = tokio::time::Instant::now() + UPSTREAM_SUBMIT_DEADLINE;
        let outcome = pending.handoff.carry(deadline).await;
        self.settle_upstream(&pending.actor_id, pending.action_id, outcome.as_ref());
        match outcome {
            Ok(value) => ControlFrame::Response(Response {
                request_id: pending.request_id,
                outcome: Outcome::Ok(value),
            }),
            Err(error) => failure(pending.request_id, &error.to_protocol_error()),
        }
    }

    /// Records the outcome of an admitted operation that was transmitted outside the boundary.
    ///
    /// The admission is committed before the bytes go, so a failure after it is an outcome nobody
    /// can establish rather than a refusal: the frame may have reached the upstream and the answer
    /// may have been lost. Section 9 records exactly that.
    fn settle_upstream(
        &self,
        actor_id: &ActorId,
        action_id: kr_protocol::ids::ActionId,
        outcome: std::result::Result<&ParamsValue, &WorkerError>,
    ) {
        let now = kr_ipc::now_ms();
        let mut session = self.runtime.session();
        let Some(journal) = session.journal_mut() else {
            return;
        };
        let settled = match outcome {
            // The upstream answered and this is what it said. Nothing earlier than its own
            // acknowledgement reaches here: a queue that took the bytes and a socket that wrote
            // them are two facts about this host, and neither of them is the upstream acting.
            Ok(value) => {
                let bytes = kr_cbor::encode(value.as_value());
                journal.settle(
                    actor_id.clone(),
                    action_id,
                    kr_protocol::receipt::ReceiptState::Applied,
                    Some(&bytes),
                    None,
                    now,
                )
            }
            // An upstream that answered and refused has *proved* the refusal, and section 9 keeps
            // that apart from an outcome nobody can establish. Everything else past the admission
            // is unknown: a frame that went in part, a reply that never came, a connection that
            // ended. The caller reads the two differently, so they are recorded differently.
            Err(error) => journal.settle(
                actor_id.clone(),
                action_id,
                if matches!(
                    error,
                    WorkerError::Broker(crate::broker::BrokerError::UpstreamRefused { .. })
                ) {
                    kr_protocol::receipt::ReceiptState::Refused
                } else {
                    kr_protocol::receipt::ReceiptState::Unknown
                },
                None,
                Some(error.to_protocol_error()),
                now,
            ),
        };
        if let Err(failure) = settled {
            session.note_journal_failure(&failure);
        }
    }

    /// Records the outcome of a mutation that was settled outside the session boundary.
    fn settle(
        &self,
        actor_id: &ActorId,
        action_id: kr_protocol::ids::ActionId,
        outcome: std::result::Result<&ParamsValue, &WorkerError>,
    ) {
        let now = kr_ipc::now_ms();
        let mut session = self.runtime.session();
        let Some(journal) = session.journal_mut() else {
            return;
        };
        let settled = match outcome {
            Ok(value) => {
                let bytes = kr_cbor::encode(value.as_value());
                journal.settle(
                    actor_id.clone(),
                    action_id,
                    kr_protocol::receipt::ReceiptState::Applied,
                    Some(&bytes),
                    None,
                    now,
                )
            }
            // The reader is the authoritative interface for a launch. When it says the buffer had
            // moved or the transaction was revoked before it installed anything, it has *proved*
            // the refusal, which is `refused` rather than `unknown`. Only an answer nothing can
            // give any more leaves the outcome unknown.
            Err(error) => journal.settle(
                actor_id.clone(),
                action_id,
                if error.code() == ErrorCode::OutcomeUnknown {
                    kr_protocol::receipt::ReceiptState::Unknown
                } else {
                    kr_protocol::receipt::ReceiptState::Refused
                },
                None,
                Some(error.to_protocol_error()),
                now,
            ),
        };
        if let Err(failure) = settled {
            session.note_journal_failure(&failure);
        }
    }

    /// Performs a mutation the control daemon admitted for somebody else.
    ///
    /// The mutation arrives unchanged, so its digest is the caller's, and it is recorded under the
    /// caller's own principal rather than the daemon's: a retry that reaches this worker by either
    /// route finds the same action. What the daemon vouches for is the part the worker cannot
    /// check — who the caller was, and the deadline the daemon accepted.
    async fn forwarded(
        &self,
        state: &mut ConnectionState,
        forwarded: &kr_protocol::local::ForwardedMutation,
    ) -> ControlFrame {
        if state.client_kind != LocalClientKind::Controller {
            return failure(
                forwarded.mutation.request_id,
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "only the control daemon forwards an admitted mutation",
                ),
            );
        }
        // The daemon vouches for where the caller entered the host, and the registry decides which
        // ingress may reach which method. A paired device is the one remote ingress a worker
        // serves, because the daemon is the only thing that can authenticate one: an unpaired peer
        // reaches the pairing surface and nothing else, and a plugin, a workflow or a service
        // credential is not something this endpoint admits at all.
        if !matches!(
            forwarded.actor.ingress,
            ActorIngress::LocalIpc | ActorIngress::PairedDevice
        ) {
            return failure(
                forwarded.mutation.request_id,
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this endpoint serves the local and paired-device ingresses",
                ),
            );
        }
        // A device envelope names the device, which is what makes the receipt attributable. One
        // that does not is malformed rather than merely unusual.
        if forwarded.actor.ingress == ActorIngress::PairedDevice
            && !forwarded.actor.device_id.is_present()
        {
            return failure(
                forwarded.mutation.request_id,
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "a paired-device envelope names the device it acts for",
                ),
            );
        }
        // The daemon's deadline is on the machine's own continuous clock, which this worker reads
        // too, so what is left of it is a subtraction rather than a guess: the journey cost
        // whatever it cost, and the deadline does not restart on arrival. It is anchored here,
        // before the dispatch barrier and before anything else this worker waits for.
        //
        // A deadline that has already passed is carried through as absent rather than refused
        // here. Section 9 keeps an existing receipt readable after its freshness is gone, and a
        // retry is how a caller whose answer never arrived finds out what its action did; only a
        // *first* admission needs the deadline, and `receipted` is where that distinction lives.
        let deadline = vouched_deadline(
            &*self.clock,
            &*self.shared_clock,
            forwarded.accepted_deadline_boot_ms.get(),
        );
        // The marker travels to a proxy and nowhere else. A proxy forwards for somebody whose
        // receipts are not its own, which is what makes passing a retained result on a read. The
        // daemon's authority connection carries a local caller's own action, and that caller is
        // answered the way it always was.
        let proxied = state.controller_role == ControllerConnectionRole::Proxy;
        self.mutation(
            state,
            &forwarded.mutation,
            &Caller::forwarded(&forwarded.actor, &forwarded.grant_rights),
            Freshness::Vouched(deadline),
            proxied,
        )
        .await
    }

    /// Serves a read the control daemon admitted for somebody else.
    ///
    /// A read has no deadline to honour and no receipt to write, so what forwarding adds is the
    /// attribution: the request is served as the caller rather than as the daemon, and the method
    /// is checked against the ingress the daemon vouched for. Without that, a read that asks about
    /// an action would ask about the daemon's own actions, and a method the registry keeps to
    /// private IPC would be reachable from the network through the proxy.
    fn forwarded_read(
        &self,
        state: &mut ConnectionState,
        forwarded: &kr_protocol::local::ForwardedRequest,
    ) -> ControlFrame {
        if state.client_kind != LocalClientKind::Controller {
            return failure(
                forwarded.request.request_id,
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "only the control daemon forwards an admitted read",
                ),
            );
        }
        if !matches!(
            forwarded.actor.ingress,
            ActorIngress::LocalIpc | ActorIngress::PairedDevice
        ) {
            return failure(
                forwarded.request.request_id,
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this endpoint serves the local and paired-device ingresses",
                ),
            );
        }
        if forwarded.actor.ingress == ActorIngress::PairedDevice
            && !forwarded.actor.device_id.is_present()
        {
            return failure(
                forwarded.request.request_id,
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "a paired-device envelope names the device it acts for",
                ),
            );
        }
        self.request(
            state,
            &forwarded.request,
            // A forwarded read carries no rights, because nothing a read decides is decided from
            // them: an attachment's capabilities are fixed where the attachment is admitted, which
            // is a mutation, and every later operation is checked against what that admission
            // granted rather than against the grant again.
            &Caller::forwarded(&forwarded.actor, &CanonicalSet::new())
                .until(forwarded.authority_deadline_boot_ms.0.map(U64::get)),
        )
    }

    fn receipted(
        &self,
        state: &mut ConnectionState,
        mutation: &MutationRequest,
        method: Method,
        entry: &'static kr_protocol::authority::MethodEntry,
        caller: &Caller,
        freshness: Freshness,
    ) -> Result<Answered> {
        let actor_id = caller.actor_id.clone();
        // Everything from here to the recorded outcome happens inside the barrier. The authority
        // this request was admitted under cannot change underneath it, and two mutations cannot
        // interleave their checks with each other's effects.
        let _barrier = self
            .dispatch
            .lock()
            .expect("the dispatch barrier is not poisoned");
        // Section 9's time contract, before anything whose answer depends on an expiry. A wake, a
        // reboot or a step of the wall clock is revalidated here, on this mutation's own way
        // through, rather than left for a maintenance tick that may be a minute away.
        self.revalidate_time();
        self.check_authority(state)?;
        // Inside the barrier, and before anything durable: an action the daemon validated under an
        // authority revision this worker has since installed past is an action whose authority has
        // been withdrawn. The daemon takes its lease before it forwards, but a request can arrive
        // after the revision it was validated under was replaced, and the barrier is where that has
        // to be caught: a revocation is complete for a worker when the worker has stopped being
        // able to act under what it removed.
        self.check_validated_revision(caller)?;
        let digest = kr_protocol::digest::mutation_digest(mutation, &actor_id)
            .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?;

        // A retained action is answered before anything about a first admission is considered.
        // Current authority decides whether the caller may see it, which is checked above; the
        // freshness window and the subject preconditions decide whether a *new* action is
        // admitted, and applying them here would refuse a caller its own completed result because
        // its own effect moved the subject on.
        let work = work_class(method);
        let volatile_permitted = work.survives_a_journal_fault();
        match self.retained(&actor_id, mutation, digest) {
            Ok(Some(retained)) => return Ok(Answered::Retained(retained)),
            Ok(None) => {}
            // A journal this host cannot read has no retained action to give back. For an ordinary
            // mutation that is a storage failure and the request stops here; for an authorised stop
            // it is the same condition section 7 names, so the close proceeds and says volatile.
            //
            // A conflict is not that condition. The journal answered, and what it said is that this
            // identifier already belongs to a different payload: section 9 makes that `ID_CONFLICT`
            // for every method, and there is no stop to admit because the action the caller named
            // is not this one. Reading it as a storage failure would also mark durability lost over
            // a journal that is working perfectly.
            Err(error) if volatile_permitted && is_storage_failure(&error) => {
                self.runtime
                    .session()
                    .note_journal_failure(error.to_string());
            }
            Err(error) => return Err(error),
        }

        // The envelope is checked before anything durable happens: the target this worker will
        // act on, the grant the caller claims, the preconditions the subject must still satisfy
        // and the freshness window that admits a first request.
        self.check_envelope(mutation, entry, caller)?;
        // What this mutation asks for, as distinct from the identifier it asks under. It is what
        // decides whether a fresh identifier would be taking an uncertain outcome's place.
        let subject = kr_protocol::action::subject_digest(mutation)
            .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?;
        self.check_admission_limits(&actor_id, state, mutation, method, subject)?;
        // The deadline lives on the continuous clock. That is what admission, revalidation and
        // expiry all read, so a wall clock that moves cannot lengthen or shorten an action's life.
        let now = self.clock.now();
        let deadline = match freshness {
            Freshness::Window(received_at) => {
                self.check_window(state, mutation, received_at)?.deadline
            }
            // The daemon derived this deadline at first admission and the worker anchored what was
            // left of it on its own clock the moment the frame arrived, before it waited for
            // anything. Anchoring it here instead would hand back every millisecond the dispatch
            // barrier had already spent.
            Freshness::Vouched(Some(deadline)) => deadline,
            // A retained action was answered above. A first admission with no lifetime left is
            // refused here, after the de-duplication lookup rather than before it.
            Freshness::Vouched(None) => {
                return Err(WorkerError::WindowExpired {
                    detail: "the accepted deadline for this action had passed before it reached \
                             this worker, so it cannot be admitted for the first time"
                        .to_owned(),
                });
            }
        };
        // The receipt carries a wall-clock deadline, because that is what a person and a wire
        // format read. Nothing expires against it.
        let accepted_deadline =
            crate::action::window::receipt_stamp(now, deadline, kr_ipc::now_ms());
        let intent = Self::intent_of(mutation, method)?;
        let submission = crate::journal::Submission {
            actor_id: actor_id.clone(),
            action_id: mutation.action_id,
            method: mutation.method.clone(),
            method_version: mutation.method_version,
            payload_digest: digest,
            subject_digest: subject,
            intent,
            accepted_deadline_ms: Some(accepted_deadline),
            now_ms: kr_ipc::now_ms(),
        };

        // From here the session is locked and stays locked. Admission, the final revalidation, the
        // dispatch marker, the effect and the recorded outcome are one serial boundary: nothing
        // the mutation was validated against — the geometry, the lease, the output cursor, the
        // lifecycle state — can move between the check and the effect.
        let mut session = self.runtime.session();

        // The condition the journal publishes, asked inside the boundary and before anything is
        // admitted. A write that fails is refused where it fails, which is what the arms below
        // do; this is the other half, and section 24 needs both. A store that has already told
        // this host it cannot be trusted — a value nothing can decode, a device with no space —
        // does not have to refuse the *next* write for the work that write is part of to be work
        // this host must not start. So a fault fences rich work whether or not the journal
        // happens to answer the next statement.
        //
        // The two named exceptions pass: section 7's authorised stop and section 11's raw
        // terminal input, which does not travel this path at all.
        let posture = session.durability_posture();
        if !posture.admits(work) {
            let kind = posture
                .fault()
                .map_or(crate::persistence::fault::FaultKind::WriteFailed, |fault| {
                    fault.kind
                });
            let refusal = crate::persistence::capacity::StoreCapacity::refusal(kind);
            return Err(WorkerError::JournalUnavailable {
                detail: refusal.message,
            });
        }

        // Storage failure stops an ordinary typed mutation before dispatch. An authorised stop is
        // the named exception: section 7 requires `session.close` to proceed on the worker's
        // current in-memory authority and report `durability=volatile`. A journal that is *open
        // and failing* is the same condition as one that is absent — a full disk refusing a write
        // is exactly when a person most needs to be able to stop a session — so the exception
        // covers the write failing as well as the journal being missing.
        let admitted = match session.journal_mut() {
            Some(journal) => match journal.accept(&submission) {
                Ok(_) => true,
                Err(error) if volatile_permitted && is_storage_failure(&error) => {
                    session.note_journal_failure(error.to_string());
                    false
                }
                Err(error) => return Err(error),
            },
            None if volatile_permitted => false,
            None => {
                return Err(WorkerError::JournalUnavailable {
                    detail:
                        "the session journal is unavailable, so no durable mutation is accepted"
                            .to_owned(),
                });
            }
        };

        // Revalidate inside the boundary. Anything that was true at acceptance may not be now, and
        // this is the last moment at which checking it still means something.
        let revalidated = self
            .validate(&session, state, mutation, method)
            .and_then(|()| Self::check_preconditions(&session, mutation))
            .and_then(|()| {
                // The deadline the host derived is the deadline it keeps, measured on the
                // continuous clock so a wall clock that moves cannot extend it. This is also what
                // makes a zero requested lifetime mean what it says.
                if self.clock.now() >= deadline {
                    Err(WorkerError::WindowExpired {
                        detail: "the accepted deadline for this action has passed".to_owned(),
                    })
                } else {
                    Ok(())
                }
            })
            // And last, what the effect itself would have refused. Last, because that is where the
            // effect asked it: moving a refusal before the marker must not move it in front of a
            // precondition the caller stated or a deadline this host accepted. For a mutation the
            // broker owns, what comes back is the admission itself.
            .and_then(|()| self.decidable(&session, mutation, method, caller));
        let prepared = match revalidated {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Some(journal) = session.journal_mut() {
                    let reason = if matches!(error, WorkerError::WindowExpired { .. }) {
                        kr_protocol::receipt::RejectionReason::Expired
                    } else {
                        kr_protocol::receipt::RejectionReason::StalePreconditions
                    };
                    let _ = journal.reject(
                        actor_id,
                        mutation.action_id,
                        reason,
                        Some(error.to_protocol_error()),
                        kr_ipc::now_ms(),
                    );
                }
                return Err(error);
            }
        };
        if admitted && let Some(journal) = session.journal_mut() {
            // The dispatch marker is committed before the effect. A stop whose marker cannot be
            // written proceeds on the worker's current authority and reports volatile durability,
            // for the same reason its acceptance did; anything else is refused before it happens.
            if let Err(error) =
                journal.mark_dispatching(actor_id.clone(), mutation.action_id, kr_ipc::now_ms())
            {
                if !volatile_permitted {
                    // A marker that was not written leaves nothing executable behind it. The
                    // admission is abandoned here, so the operation it authorised cannot be
                    // transmitted by anything that still holds a reference to it.
                    if let Some(prepared) = prepared {
                        prepared.abandon();
                    }
                    return Err(error);
                }
                session.note_journal_failure(error.to_string());
            }
        }

        let outcome = self.apply(&mut session, state, mutation, method, caller, prepared);
        // A launch that reached the reader has no outcome yet, so none is recorded: it is settled
        // when the reader answers, outside this boundary. An admitted upstream operation is the
        // same shape for the same reason: its effect is the admission, and its outcome is what the
        // upstream says once this boundary has ended and the transport work has happened.
        let pending = matches!(
            outcome,
            Ok((_, AfterEffect::Launch { .. } | AfterEffect::Upstream(_)))
        );
        let settling = actor_id.clone();
        let now = kr_ipc::now_ms();
        match (&outcome, session.journal_mut()) {
            _ if pending => {}
            (Ok((value, _)), Some(journal)) => {
                // The result, the receipt revision and the event record are one commit. A crash
                // between them would leave a receipt that claims an outcome beside a result no
                // reader can retrieve.
                //
                // A created question is the exception, and it is deliberate. Its result carries
                // the caller token, and section 11 keeps that token out of every durable record
                // except the ledger's own sealed copy — a retained result is a durable record, and
                // one a backup would carry. So the receipt is written without it. Nothing is lost:
                // a question is de-duplicated by its source and its own request identifier, which
                // returns the same question and the same token, and a repeated action identifier
                // gets the receipt as it stands, which is what section 9 gives an action with no
                // retained result.
                let bytes = kr_cbor::encode(value.as_value());
                let retainable = method != Method::QuestionCreate;
                // A failure here cannot unwind the effect, which has already happened. It is
                // recorded against the session rather than turned into a refusal the caller would
                // read as "nothing happened".
                let settled = journal.settle(
                    actor_id,
                    mutation.action_id,
                    kr_protocol::receipt::ReceiptState::Applied,
                    retainable.then_some(bytes.as_slice()),
                    None,
                    now,
                );
                if let Err(error) = settled {
                    session.note_journal_failure(&error);
                }
            }
            (Err(error), Some(journal)) => {
                // Past the marker there is no rejection. Whether the effect happened cannot be
                // established from here, so the outcome is recorded as unknown — except where the
                // failure itself proves the effect did not happen, which a launch the machine
                // refused before it reached the reader does.
                let state = if matches!(error, WorkerError::LaunchRefused { code, .. }
                    if *code != ErrorCode::OutcomeUnknown)
                {
                    kr_protocol::receipt::ReceiptState::Refused
                } else {
                    kr_protocol::receipt::ReceiptState::Unknown
                };
                let settled = journal.settle(
                    actor_id,
                    mutation.action_id,
                    state,
                    None,
                    Some(error.to_protocol_error()),
                    now,
                );
                if let Err(failure) = settled {
                    session.note_journal_failure(&failure);
                }
            }
            (_, None) => {}
        }
        // Privacy mode is prospective, and this is where an action admitted under it settles. The
        // content its receipt carries goes here rather than on the next maintenance pass, which
        // narrows the window in which it is on the disk. It does not close it: this is a second
        // transaction after the one that wrote the outcome, so a crash between the two leaves the
        // content for the archive to serve, and the asynchronous launch settlement and the early
        // rejection path do not reach here at all. Closing it needs the content policy inside the
        // journal transition itself. A failure is recorded as cleanup this host still owes rather
        // than turned into a refusal of an effect that has already happened.
        if session.privacy().is_enabled() {
            session.redact_settled_action(&caller.actor_id, mutation.action_id);
        }
        drop(session);

        // The boundary is over. What the mutation left behind happens now: input reaches the
        // terminal, and a close that was admitted waits for its acceptance to be written before
        // anything is signalled.
        let (value, after) = outcome?;
        match after {
            AfterEffect::None => {}
            AfterEffect::Close(gate) => state.close_gate = Some((mutation.action_id, gate)),
            AfterEffect::Launch {
                transaction,
                receiver,
            } => {
                return Ok(Answered::Launch {
                    transaction,
                    receiver,
                });
            }
            // The session mutex and the dispatch barrier are both released by now, which is the
            // point: terminal ingestion needs the first and every other mutation needs the second,
            // and neither waits for an upstream.
            AfterEffect::Upstream(handoff) => {
                return Ok(Answered::Upstream {
                    handoff,
                    action_id: mutation.action_id,
                    actor_id: settling,
                });
            }
        }
        Ok(Answered::Performed(value))
    }

    /// Returns the bytes the journal keeps as this mutation's intent.
    ///
    /// Ordinarily that is the mutation exactly as it arrived, because the intent is what a
    /// recovering worker reads to know what the action was going to do. The two exceptions carry
    /// something a caller presents to prove it may ask, rather than a fact about the action, and
    /// section 11 keeps such a secret out of every durable record but the ledger's own sealed
    /// copy. The journal is such a record, and so is its write-ahead log.
    ///
    /// A cancellation from a question's source carries the caller token, and a detach carries the
    /// capability its line was given. Both are emptied before the intent is encoded. What remains
    /// says which question was to be cancelled and under whose authority, and which attachment a
    /// detach named, which is the whole of what it was going to do wherever it named one. A detach
    /// that named nothing keeps a null there: its subject is resolved from the capability when it
    /// runs, and the capability is exactly what this record must not hold. That costs a recovery
    /// nothing, because an intent that was never dispatched is not resumed.
    fn intent_of(mutation: &MutationRequest, method: Method) -> Result<Vec<u8>> {
        let redacted;
        let recorded = match method {
            Method::QuestionCancelOwn => {
                let params: kr_protocol::question::QuestionCancelOwnParams =
                    parse(&mutation.params)?;
                let params = kr_protocol::question::QuestionCancelOwnParams {
                    caller_token: kr_protocol::question::CallerToken::new(Vec::new()),
                    ..params
                };
                redacted = MutationRequest {
                    params: ParamsValue::from_typed(&params)
                        .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?,
                    ..mutation.clone()
                };
                &redacted
            }
            Method::SessionDetach => {
                let params: SessionDetachParams = parse(&mutation.params)?;
                let params = SessionDetachParams {
                    line_token: Nullable::null(),
                    ..params
                };
                redacted = MutationRequest {
                    params: ParamsValue::from_typed(&params)
                        .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?,
                    ..mutation.clone()
                };
                &redacted
            }
            _ => mutation,
        };
        kr_cbor::to_canonical_vec(recorded)
            .map_err(|error| WorkerError::InvalidArgument(error.to_string()))
    }

    /// Returns the answer a retained action is owed, when this caller has one.
    ///
    /// The de-duplication key is the actor and the action together, so this can only ever find the
    /// calling actor's own action. An identifier reused with a different payload is a conflict, not
    /// a second action.
    fn retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        digest: kr_protocol::scalars::Digest256,
    ) -> Result<Option<ParamsValue>> {
        let (receipt, result) = {
            let mut session = self.runtime.session();
            let Some(journal) = session.journal_mut() else {
                return Ok(None);
            };
            let Some(receipt) = journal.read(actor_id.clone(), mutation.action_id)? else {
                return Ok(None);
            };
            let result = journal.read_result(actor_id, mutation.action_id)?;
            (receipt, result)
        };
        if receipt.payload_digest != digest {
            return Err(WorkerError::IdConflict {
                action: mutation.action_id.to_string(),
            });
        }
        if let Some(bytes) = result {
            let value = kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)
                .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?;
            return Ok(Some(ParamsValue::new(value)));
        }
        // The action is known and it has no result to return. Section 9 answers that with the
        // receipt as it stands rather than performing the effect a second time or refusing as
        // though the request were malformed: the caller learns the action's real state and can
        // read it again when it settles.
        encode(&kr_protocol::receipt::ReceiptResponse {
            request_id: mutation.request_id,
            receipt,
        })
        .map(Some)
    }

    /// Checks the mutation envelope before anything durable happens.
    ///
    /// The envelope is not decoration. Its target names what the effect is for, its grant names
    /// the authority it is claimed under, and its preconditions name what the subject must still
    /// be. A host that parses only the parameters is acting on a request it has not read.
    fn check_envelope(
        &self,
        mutation: &MutationRequest,
        entry: &'static kr_protocol::authority::MethodEntry,
        caller: &Caller,
    ) -> Result<()> {
        use kr_protocol::authority::ResourceSelectorKind;

        mutation
            .target
            .validate()
            .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?;
        if mutation.target.environment_id != self.environment_id {
            return Err(WorkerError::StaleTarget {
                detail: format!("this worker belongs to environment {}", self.environment_id),
            });
        }
        let session = self.runtime.session();
        let owned = session.id();
        let epoch = session.epoch();
        drop(session);
        // The registry says which resources a method names. A method whose selectors include a
        // session must name one; a method that acts on a receipt need not.
        let names_session = entry
            .resource_selectors
            .contains(&ResourceSelectorKind::Session);
        match mutation.target.session_id.as_ref() {
            Some(named) if *named != owned => {
                return Err(WorkerError::StaleTarget {
                    detail: format!("this endpoint serves session {owned}, not {named}"),
                });
            }
            Some(_) => {}
            None if names_session => {
                return Err(WorkerError::InvalidArgument(format!(
                    "{} names the session it acts on",
                    entry.name
                )));
            }
            None => {}
        }
        if let Some(named) = mutation.target.session_epoch.as_ref()
            && *named != epoch
        {
            return Err(WorkerError::StaleTarget {
                detail: format!("session {owned} is at epoch {epoch}"),
            });
        }
        // Most methods act on the session itself, and naming an application instance in the
        // envelope is a request this endpoint cannot serve rather than a field to ignore. The
        // agent and plugin methods do act on one, and for those the envelope must agree with what
        // the parameters name: an envelope and a body that disagree are two requests.
        match mutation.target.application_instance_id.as_ref() {
            None => {}
            Some(named)
                if entry
                    .resource_selectors
                    .contains(&ResourceSelectorKind::ApplicationInstance) =>
            {
                let acted_on = Self::params_application_instance(entry.method, &mutation.params)?;
                if acted_on != *named {
                    return Err(WorkerError::InvalidArgument(
                        "this request names one application instance in its envelope and another \
                         in its parameters"
                            .to_owned(),
                    ));
                }
            }
            Some(_) => {
                return Err(WorkerError::InvalidArgument(
                    "this endpoint serves the session itself, not an application instance"
                        .to_owned(),
                ));
            }
        }
        // What a caller may say about its grant depends on how it reached the host. A local
        // caller's authority is the operating-system caller the listener authenticated, so section
        // 23 leaves its grant null and an identifier presented here would be a claim the worker
        // cannot check. A forwarded caller does act under a grant, and the daemon has already
        // checked which: the request may name it, and it may name no other.
        match mutation.grant_id.as_ref() {
            None => {}
            Some(_) if !caller.is_remote() => {
                return Err(WorkerError::InvalidArgument(
                    "a local caller acts under its authenticated operating-system identity, not a \
                     grant"
                        .to_owned(),
                ));
            }
            Some(named) if caller.grant_id.as_ref() != Some(named) => {
                return Err(WorkerError::InvalidArgument(
                    "this request names a grant the host did not check it against".to_owned(),
                ));
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Refuses an action validated under an authority revision this worker has installed past.
    ///
    /// A local caller has no revision to compare: its authority is the operating-system identity
    /// the socket authenticated, and nothing about an authority revision withdraws that. A
    /// forwarded caller's authority is a grant the daemon checked at a revision, and this worker
    /// installing a later one is exactly the event that withdraws it.
    fn check_validated_revision(&self, caller: &Caller) -> Result<()> {
        let Some(validated) = caller.validated_revision else {
            return Ok(());
        };
        let acknowledged = self
            .authority
            .lock()
            .expect("the authority lock is not poisoned")
            .acknowledged_revision;
        if acknowledged.is_some_and(|held| held.get() > validated.get()) {
            return Err(WorkerError::GenerationFenced {
                detail: format!(
                    "this action was admitted under authority revision {validated}, and this \
                     worker holds a later one"
                ),
            });
        }
        Ok(())
    }

    /// Refuses a request whose authority has run out, and fences what it was allowed to do.
    ///
    /// Read on the machine's own continuous clock, which is the clock the daemon expressed the
    /// deadline on. Called inside the boundary that decides what reaches the application, because
    /// that is the only place the answer cannot go stale: a batch that passed the daemon's check
    /// can wait here while the grant behind it ends.
    ///
    /// The refusal alone is not the fence. Input this caller has already handed over and the
    /// terminal has not taken goes with it, on the writer's own boundary, the same way a takeover
    /// discards the previous holder's bytes.
    fn check_authority_deadline(
        &self,
        caller: &Caller,
        session: &mut Session,
        attachment_id: AttachmentId,
    ) -> Result<()> {
        let Some(deadline) = caller.authority_deadline_boot_ms else {
            return Ok(());
        };
        if self.shared_clock.boot_elapsed_ms() < deadline {
            return Ok(());
        }
        // Only this request's own attachment. Another device may hold the lease by now, and its
        // authority has nothing to do with this one's having ended.
        self.fence_remote_input(session, Some(attachment_id));
        Err(WorkerError::GenerationFenced {
            detail: "the authority this request was admitted under has run out".to_owned(),
        })
    }

    /// Checks the subject preconditions the mutation requires.
    ///
    /// `expected` is a closed map of the subject facts the caller believes. Anything it names that
    /// is no longer true refuses the mutation before it is admitted, so a client acting on a stale
    /// screen cannot resize, take input or close on facts that have moved.
    fn check_preconditions(session: &Session, mutation: &MutationRequest) -> Result<()> {
        let expected = MutationPreconditions::parse(&mutation.expected)?;
        if let Some(state) = expected.session_state
            && state != session.state()
        {
            return Err(WorkerError::PreconditionFailed {
                detail: format!("the session is {}", session.state().as_str()),
            });
        }
        if let Some(epoch) = expected.geometry_epoch
            && epoch.get() != session.geometry().epoch.get()
        {
            return Err(WorkerError::PreconditionFailed {
                detail: format!("the geometry epoch is {}", session.geometry().epoch),
            });
        }
        if let Some(epoch) = expected.input_lease_epoch
            && epoch.get() != session.lease().epoch.get()
        {
            return Err(WorkerError::PreconditionFailed {
                detail: format!("the input lease is at epoch {}", session.lease().epoch),
            });
        }
        if let Some(cursor) = expected.output_cursor
            && cursor != session.output_cursor()
        {
            return Err(WorkerError::PreconditionFailed {
                detail: format!("the output cursor is {}", session.output_cursor()),
            });
        }
        Ok(())
    }

    /// Checks the action window a first admission is bound to and derives its deadline.
    ///
    /// The accepted deadline is the earliest of the window's expiry, receipt time plus the
    /// requested lifetime, and any applicable authority deadline, on the host's suspend-aware
    /// continuous clock. An expired or unknown window admits nothing: section 9 makes replacing a
    /// window a different request, never an automatic retry of this one.
    ///
    /// The third bound is `None` here, and that is a statement rather than an omission. A caller
    /// on this endpoint acts under the authenticated operating-system identity, whose authority
    /// over its own session does not expire; a caller acting under a grant reaches this worker
    /// through the control daemon, which applies that grant's deadline at first admission and
    /// forwards what is left of the result.
    fn check_window(
        &self,
        state: &ConnectionState,
        mutation: &MutationRequest,
        received_at: ContinuousInstant,
    ) -> Result<AcceptedDeadline> {
        crate::action::window::first_admission(
            &self.windows,
            &mutation.action_window_id,
            state.connection_id,
            self.boot_epoch,
            received_at,
            mutation.requested_ttl_ms,
            None,
        )
    }

    /// Refuses a first admission that section 9's de-duplication contract does not permit.
    ///
    /// Both checks are about admitting a *new* action, so a retained one has already been answered
    /// above and neither applies to it.
    ///
    /// * A subject that already carries an uncertain outcome admits a new identifier only when the
    ///   request names that outcome and the revision it was read at. That is what stops a service
    ///   from choosing a fresh identifier to evade de-duplication.
    /// * An actor holds at most eight admitted, unsettled mutations at once, lowered by whatever
    ///   the connection negotiated.
    fn check_admission_limits(
        &self,
        actor_id: &ActorId,
        state: &ConnectionState,
        mutation: &MutationRequest,
        method: Method,
        subject: kr_protocol::scalars::Digest256,
    ) -> Result<()> {
        let declared = MutationPreconditions::parse(&mutation.expected)?.supersedes;
        let mut session = self.runtime.session();
        let Some(journal) = session.journal_mut() else {
            return Ok(());
        };
        // These two reads are what stops a *new* rich action being admitted twice or past its
        // limit. An authorised stop and a native interrupt are neither, and a store that cannot
        // answer them is not a reason to take away the one way a person has of stopping a running
        // command. The failure is published as the fault it is, and the checks it feeds are
        // skipped rather than guessed at.
        let volatile_permitted = work_class(method).survives_a_journal_fault();
        let read = journal
            .uncertain_for_subject(actor_id, subject)
            .and_then(|uncertain| journal.outstanding(actor_id).map(|held| (uncertain, held)));
        let (uncertain, outstanding) = match read {
            Ok(pair) => pair,
            Err(error) if volatile_permitted && is_storage_failure(&error) => {
                session.note_journal_failure(error.to_string());
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let uncertain = uncertain.map(|(action_id, revision)| crate::action::dedup::Uncertain {
            action_id,
            revision,
        });
        drop(session);
        crate::action::dedup::check_supersession(uncertain, declared)?;
        if !crate::action::dedup::bounded_by_outstanding(method) {
            return Ok(());
        }
        crate::action::dedup::check_outstanding(
            outstanding,
            crate::action::dedup::outstanding_limit(
                state.peer_limits.max_outstanding_mutations.get(),
            ),
        )
    }

    /// Checks a mutation's target, authority and preconditions without acting on it.
    fn validate(
        &self,
        session: &Session,
        state: &ConnectionState,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<()> {
        match method {
            Method::SessionAttach => {
                let params: SessionAttachParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)
            }
            // An attachment of this session, not only one this connection made. Every attachment
            // of a local session belongs to the same operating-system user, whom the listener has
            // already authenticated, and `kr detach` from another window is the ordinary way to
            // end an attachment whose own terminal has gone. An identifier that names no
            // attachment of this session is still refused.
            Method::SessionDetach => {
                let params: SessionDetachParams = parse(&mutation.params)?;
                let attachment_id = Self::detach_subject(session, &params)?;
                if session.attachment_capabilities(attachment_id).is_some() {
                    Ok(())
                } else {
                    Err(WorkerError::UnknownAttachment {
                        attachment: attachment_id.to_string(),
                    })
                }
            }
            Method::SessionClose => {
                let params: kr_protocol::session::SessionCloseParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)
            }
            Method::AttachmentConfigure => {
                let params: AttachmentConfigureParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)?;
                if params.claim_geometry {
                    Self::check_capability(
                        session,
                        params.attachment_id,
                        AttachmentCapability::Geometry,
                    )?;
                }
                Ok(())
            }
            Method::TerminalResize => {
                let params: TerminalResizeParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)?;
                Self::check_capability(
                    session,
                    params.attachment_id,
                    AttachmentCapability::Geometry,
                )
            }
            Method::TerminalGeometryTransfer => {
                // The target is not checked against this connection, and that is the point of the
                // method. Section 8's phone-first, desk-later flow is one device selecting
                // another's terminal, so an actor with the transfer right names any eligible
                // attachment of this session. What it still cannot do is give the size to an
                // attachment the host never granted the geometry right.
                Self::check_capability(
                    session,
                    Self::params_attachment(&mutation.params)?,
                    AttachmentCapability::Geometry,
                )
            }
            Method::InputAcquire => {
                let params: InputAcquireParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                Self::check_attachment(state, params.attachment_id)?;
                Self::check_capability(session, params.attachment_id, AttachmentCapability::Input)
            }
            Method::InputRelease => {
                let params: InputReleaseParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                Self::check_attachment(state, params.attachment_id)
            }
            Method::InputInterrupt => {
                let params: InputInterruptParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                Self::check_attachment(state, params.attachment_id)?;
                Self::check_capability(session, params.attachment_id, AttachmentCapability::Input)
            }
            Method::ShellLaunch => {
                let params: kr_protocol::root::ShellLaunchParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                // Section 23's row for this method: the terminal-input right, the *current* input
                // lease, a qualified root editor, an empty prompt behind a fence, the recorded
                // working-directory revision and the session's launch profile. The first three are
                // here; the rest are the machine's, because they are facts about the reader.
                let attachment_id = Self::launching_attachment(session, state)?;
                Self::check_capability(session, attachment_id, AttachmentCapability::Input)?;
                if !session.config().shell_mode.claims_managed_editor() {
                    return Err(WorkerError::ShellIntegrationUnsupported {
                        detail:
                            "this session runs a stock shell, so a launch installs no command in \
                             its editor"
                                .to_owned(),
                    });
                }
                if !session.config().launch_profile.fenced_launch {
                    return Err(WorkerError::ShellIntegrationUnsupported {
                        detail: "this session's launch profile does not admit a fenced launch, so \
                                 no command is installed in its editor"
                            .to_owned(),
                    });
                }
                Ok(())
            }
            Method::AttachmentViewport => {
                let params: AttachmentViewportParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)
            }
            // Every question method names the session it acts in, and this endpoint serves one
            // session. Everything else a question can be refused for is checked here too, because
            // this runs *before* the dispatch marker: an unbound caller, a malformed form, a
            // reused request identifier and a question somebody else already answered are all
            // refusals, and a refusal recorded after the marker would say the effect might have
            // happened when nothing did.
            Method::QuestionCreate => {
                let params: kr_protocol::question::QuestionCreateParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                let source = self.bind_source_in(session, state)?;
                Ok(self.questions.check_create(&source, &params)?)
            }
            Method::QuestionCancelOwn => {
                let params: kr_protocol::question::QuestionCancelOwnParams =
                    parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                let source = self.bind_source_in(session, state)?;
                self.questions
                    .check_own(&source, params.question_id, &params.caller_token)?;
                let revision = self.questions.question(params.question_id)?.revision;
                Ok(self.questions.check_resolvable(
                    params.question_id,
                    revision,
                    None,
                    self.question_clock(),
                )?)
            }
            Method::AlertCreate => {
                let params: kr_protocol::question::AlertCreateParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                self.bind_source_in(session, state)?;
                Ok(())
            }
            Method::QuestionAnswer => {
                let params: kr_protocol::question::QuestionAnswerParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                Ok(self.questions.check_resolvable(
                    params.question_id,
                    params.expected_revision,
                    Some(&params.answer),
                    self.question_clock(),
                )?)
            }
            Method::QuestionCancel => {
                let params: kr_protocol::question::QuestionCancelParams = parse(&mutation.params)?;
                Self::check_session(session, params.session_id)?;
                Ok(self.questions.check_resolvable(
                    params.question_id,
                    params.expected_revision,
                    None,
                    self.question_clock(),
                )?)
            }
            // Every agent mutation names one subject, and the subject names this session. What
            // the broker checks is everything about the instance and the binding; this is the
            // envelope check the other methods make here, and nothing more.
            Method::AgentPromptSubmit | Method::AgentPromptQueue => {
                let params: kr_protocol::agent::AgentPromptParams = parse(&mutation.params)?;
                Self::check_session(session, params.target.subject.session_id)
            }
            Method::AgentTurnSteer => {
                let params: kr_protocol::agent::AgentSteerParams = parse(&mutation.params)?;
                Self::check_session(session, params.target.subject.session_id)
            }
            Method::AgentTurnCancel => {
                let params: kr_protocol::agent::AgentCancelParams = parse(&mutation.params)?;
                Self::check_session(session, params.target.subject.session_id)
            }
            Method::AgentApprovalRespond => {
                let params: kr_protocol::agent::AgentApprovalRespondParams =
                    parse(&mutation.params)?;
                Self::check_session(session, params.target.subject.session_id)
            }
            Method::PluginActionInvoke => {
                let params: kr_protocol::agent::PluginActionInvokeParams = parse(&mutation.params)?;
                Self::check_session(session, params.target.subject.session_id)
            }
            // An action belongs to the actor that submitted it, or to the host owner over anybody
            // else's, and the receipt itself is the subject: nothing else about the request decides
            // whether it may be cancelled. Whose it is, and whether there is one at all, are what
            // the cancellation itself answers.
            Method::ActionCancel => {
                let _: kr_protocol::receipt::ActionCancelParams = parse(&mutation.params)?;
                Ok(())
            }
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a mutation this worker serves",
                method.as_str()
            ))),
        }
    }

    /// Wraps one broker admission as the work that happens once the session boundary ends.
    fn handoff(
        &self,
        admitted: crate::broker::MutationAdmission,
        kind: UpstreamKind,
    ) -> UpstreamHandoff {
        UpstreamHandoff {
            broker: Arc::clone(&self.broker),
            admitted,
            kind,
        }
    }

    /// Refuses, before the dispatch marker, everything the effect itself would refuse.
    ///
    /// Section 9 makes a refusal this host can decide a rejection rather than an outcome nobody
    /// can establish, so these are asked here rather than inside the effect. Two rules keep that
    /// from changing what a caller is told. They run *after* the envelope, the ownership and the
    /// generic preconditions, which is where they ran when the effect made them; and inside each
    /// method they are asked in the order the effect asks them.
    fn decidable(
        &self,
        session: &Session,
        mutation: &MutationRequest,
        method: Method,
        caller: &Caller,
    ) -> Result<Option<UpstreamHandoff>> {
        // Whether this session is still running, for the methods that need it to be. Each of those
        // effects asks this first, so this does too.
        if matches!(
            method,
            Method::SessionAttach
                | Method::TerminalResize
                | Method::TerminalGeometryTransfer
                | Method::InputAcquire
        ) {
            session.require_live()?;
        }
        match method {
            Method::SessionAttach => {
                let params: SessionAttachParams = parse(&mutation.params)?;
                // Everything the attachment table would refuse: the session's attachment limit, a
                // semantic attachment claiming geometry, a terminal attachment with no dimensions,
                // and dimensions this host does not serve.
                session.attachable(&params).map(|()| None)
            }
            Method::AttachmentConfigure => {
                let params: AttachmentConfigureParams = parse(&mutation.params)?;
                // Whether this attachment can hold a claim at all, which a semantic one cannot.
                session
                    .configurable(params.attachment_id, params.claim_geometry)
                    .map(|()| None)
            }
            Method::TerminalResize => {
                let params: TerminalResizeParams = parse(&mutation.params)?;
                // The size, the ownership and the epoch, in the order the resize asks them: an
                // impossible size is an impossible size before it is anybody's to set.
                session
                    .resizable(
                        params.attachment_id,
                        params.dimensions,
                        params.expected_geometry_epoch.get(),
                    )
                    .map(|()| None)
            }
            Method::TerminalGeometryTransfer => {
                let params: kr_protocol::attachment::TerminalGeometryTransferParams =
                    parse(&mutation.params)?;
                // The epoch and then the claim, which is the order the transfer asks them.
                Self::check_geometry_epoch(session, params.expected_geometry_epoch)?;
                session.transferable(params.attachment_id).map(|()| None)
            }
            Method::InputAcquire => {
                let params: InputAcquireParams = parse(&mutation.params)?;
                // A takeover of a lease that has already moved is refused as a lost lease whatever
                // else is wrong with it, because that is what the lease itself answers first.
                if let Some(epoch) = params.expected_epoch.as_ref() {
                    Self::check_lease_epoch(session, *epoch)?;
                }
                session
                    .input_compatible(params.attachment_id)
                    .map(|()| None)
            }
            Method::InputRelease => {
                let params: InputReleaseParams = parse(&mutation.params)?;
                // Whether this attachment holds the lease at the epoch it names, which is what the
                // release itself answers.
                Self::check_lease_holder(session, params.attachment_id, params.epoch).map(|()| None)
            }
            Method::InputInterrupt => {
                let params: InputInterruptParams = parse(&mutation.params)?;
                Self::check_lease_holder(session, params.attachment_id, params.epoch).map(|()| None)
            }
            Method::AttachmentViewport => {
                let params: AttachmentViewportParams = parse(&mutation.params)?;
                // The size this window reports, whether this attachment is shown a terminal at
                // all, and whether it may put its window where the report asks. A semantic
                // attachment has no viewport to report.
                session
                    .viewportable(params.attachment_id, params.dimensions, params.position.0)
                    .map(|()| None)
            }
            // The agent mutations and the plugin action. The broker admits each one here,
            // before the dispatch marker: section 9 makes a refusal this host can decide a
            // rejection rather than an outcome nobody can establish, and everything the broker
            // decides is decidable without touching the upstream. What comes back is the
            // admission itself, and it crosses the marker with the mutation. What that buys is
            // not that nothing can change afterwards — the marker and the bytes still follow —
            // but that everything this host could refuse has been refused on *this* side of the
            // marker, and that an answer's one transmission is reserved from here, so a change
            // that lands later cannot turn into a second answer.
            Method::AgentPromptSubmit | Method::AgentPromptQueue => {
                let params: kr_protocol::agent::AgentPromptParams = parse(&mutation.params)?;
                let admitted = self.broker.admit_prompt(
                    &Self::broker_caller(caller),
                    &params,
                    method == Method::AgentPromptQueue,
                    kr_ipc::now_ms(),
                )?;
                Ok(Some(self.handoff(admitted, UpstreamKind::Mutation)))
            }
            Method::AgentTurnSteer => {
                let params: kr_protocol::agent::AgentSteerParams = parse(&mutation.params)?;
                let admitted = self.broker.admit_steer(
                    &Self::broker_caller(caller),
                    &params,
                    kr_ipc::now_ms(),
                )?;
                Ok(Some(self.handoff(admitted, UpstreamKind::Mutation)))
            }
            Method::AgentTurnCancel => {
                let params: kr_protocol::agent::AgentCancelParams = parse(&mutation.params)?;
                let admitted = self.broker.admit_cancel(
                    &Self::broker_caller(caller),
                    &params,
                    kr_ipc::now_ms(),
                )?;
                Ok(Some(self.handoff(admitted, UpstreamKind::Mutation)))
            }
            Method::AgentApprovalRespond => {
                let params: kr_protocol::agent::AgentApprovalRespondParams =
                    parse(&mutation.params)?;
                self.wait_before_admission();
                let admitted = self.broker.admit_approval(
                    &Self::broker_caller(caller),
                    &params,
                    kr_ipc::now_ms(),
                )?;
                Ok(Some(self.handoff(admitted, UpstreamKind::Approval)))
            }
            Method::PluginActionInvoke => {
                let params: kr_protocol::agent::PluginActionInvokeParams = parse(&mutation.params)?;
                let binding_id = self.broker.binding_for(
                    &params.plugin_id,
                    params.target.subject.application_instance_id,
                )?;
                let registered = self.broker.registered_action(binding_id, &params.action)?;
                // The rights this call intersects are the action's own: the ones its declared
                // class needs. A caller acting under a grant holds them, or the call is refused
                // here, before the marker. An action nobody registered is refused below for that.
                if let Some(registered) = registered.as_ref() {
                    Self::check_action_rights(caller, &params.action, &registered.rights)?;
                }
                // An action that answers a pending request through the connector table's decision
                // destination is admitted as that answer: the transaction an approval answer
                // makes, with the action's own checks inside it, and no component involved.
                let answers = registered.is_some_and(|registered| registered.decision.is_some());
                if answers {
                    self.wait_before_admission();
                    let admitted = self.broker.admit_plugin_answer(
                        &Self::broker_caller(caller),
                        binding_id,
                        &params,
                        kr_ipc::now_ms(),
                    )?;
                    return Ok(Some(self.handoff(
                        admitted,
                        UpstreamKind::PluginAnswer {
                            action: params.action,
                        },
                    )));
                }
                self.broker.check_invocable(
                    &Self::broker_caller(caller),
                    binding_id,
                    &params,
                    kr_ipc::now_ms(),
                )?;
                // An answer names the pending resource it resolves. The broker checks that
                // resource here with the checks its approval transaction makes: its owner, that
                // it is still open, its deadline, its interpretation and everything the claim
                // rechecks. A call naming a resource this instance cannot answer is then refused
                // for that resource's own reason before anything is marked.
                if let Some(resource_id) = params.resource_id.as_ref() {
                    self.broker.check_resource_answerable(
                        &params.target,
                        *resource_id,
                        kr_ipc::now_ms(),
                    )?;
                }
                // And the refusal this host makes whatever the caller does: the effect the
                // component prepares does not reach this broker yet, and the broker will not
                // transmit one nobody validated against the invocation it was prepared under. It
                // is decided here, before the marker, so it is a rejection rather than an outcome
                // nobody can establish.
                Err(crate::broker::BrokerError::UnsupportedCapability {
                    detail: format!(
                        "{} is admitted, and the effect its component prepares does not reach \
                         this broker yet, so nothing is transmitted for it",
                        params.action
                    ),
                }
                .into())
            }
            Method::ActionCancel => {
                let params: kr_protocol::receipt::ActionCancelParams = parse(&mutation.params)?;
                let Some(journal) = session.journal() else {
                    return Err(WorkerError::JournalUnavailable {
                        detail: "this session retains no receipts, so none can be cancelled"
                            .to_owned(),
                    });
                };
                let target = Self::cancellation_target(journal, caller, params.action_id)?;
                let receipt = journal.read(target, params.action_id)?.ok_or_else(|| {
                    WorkerError::InvalidArgument(format!(
                        "no receipt for action {}",
                        params.action_id
                    ))
                })?;
                // An intent this host has already settled is not a pending action. A receipt past
                // its dispatch marker cannot be taken back, and one already rejected or cancelled
                // has nothing left to cancel: both are refusals this host can decide, and deciding
                // the second inside the effect would turn a repeated cancellation into an
                // uncertain outcome rather than the plain refusal it is.
                if receipt.state != kr_protocol::receipt::ReceiptState::Accepted {
                    return Err(WorkerError::InvalidArgument(format!(
                        "action {} is already {} and cannot be cancelled here",
                        params.action_id, receipt.state
                    )));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Returns the registry entry that governs a request from this ingress.
    ///
    /// Anything unlisted, unreachable from this ingress or at an unsupported version has no entry,
    /// and the request is refused before a parameter is parsed. The ingress is the one the daemon
    /// vouched for rather than the socket this frame arrived on, so a method the registry keeps to
    /// private IPC is refused for a paired device even though the frame came over a Unix socket.
    fn entry(
        method: Method,
        version: MethodVersion,
        ingress: ActorIngress,
    ) -> Option<&'static kr_protocol::authority::MethodEntry> {
        match kr_protocol::method::decide(method.as_str(), version, ingress) {
            kr_protocol::authority::AuthorityDecision::Listed(entry) => Some(entry),
            kr_protocol::authority::AuthorityDecision::Denied(_) => None,
        }
    }

    /// Refuses a geometry change that quotes an epoch the session has moved past.
    ///
    /// The refusal is the one the session itself makes: a caller working from a view of the size
    /// that has already changed is not the owner of the size it is describing. Deciding it here
    /// rather than inside the effect is what makes it a rejection rather than an uncertain
    /// outcome, and moving the decision must not change what the caller is told.
    fn check_geometry_epoch(
        session: &Session,
        expected: kr_protocol::ids::GeometryEpoch,
    ) -> Result<()> {
        if expected == session.geometry().epoch {
            Ok(())
        } else {
            Err(WorkerError::NotGeometryOwner)
        }
    }

    /// Refuses an input mutation that quotes an epoch the lease has moved past.
    fn check_lease_epoch(
        session: &Session,
        expected: kr_protocol::ids::InputLeaseEpoch,
    ) -> Result<()> {
        if expected.get() == session.lease().epoch.get() {
            Ok(())
        } else {
            Err(WorkerError::LeaseLost)
        }
    }

    /// Refuses an input mutation from an attachment that does not hold the lease it quotes.
    fn check_lease_holder(
        session: &Session,
        attachment_id: AttachmentId,
        epoch: kr_protocol::ids::InputLeaseEpoch,
    ) -> Result<()> {
        let lease = session.lease();
        if lease.holder.as_ref() == Some(&attachment_id) && lease.epoch.get() == epoch.get() {
            Ok(())
        } else {
            Err(WorkerError::LeaseLost)
        }
    }

    /// Returns the actor whose action a cancellation may reach.
    ///
    /// The caller's own first: the de-duplication key is the actor and the action together, so
    /// that lookup can only ever find the caller's own action. Anything else is another actor's,
    /// which section 23's row permits only under host-owner authority.
    fn cancellation_target(
        journal: &crate::journal::Journal,
        caller: &Caller,
        action_id: kr_protocol::ids::ActionId,
    ) -> Result<ActorId> {
        if journal.read(caller.actor_id.clone(), action_id)?.is_some() {
            return Ok(caller.actor_id.clone());
        }
        let Some((actor_id, _)) = journal.find_any(action_id)? else {
            return Err(WorkerError::InvalidArgument(format!(
                "no receipt for action {action_id}"
            )));
        };
        crate::action::cancel::check(
            crate::action::cancel::Subject::OtherActor,
            caller.ingress,
            &caller.actor_id,
            action_id,
        )?;
        Ok(actor_id)
    }

    /// Refuses a request that names a session this worker does not own.
    ///
    /// A worker owns exactly one session. A request that arrives on this endpoint naming another
    /// session is not a request for this session with a typo in it; acting on it would let a
    /// caller close one session by addressing another.
    fn check_session(session: &Session, named: SessionId) -> Result<()> {
        let owned = session.id();
        if named == owned {
            Ok(())
        } else {
            Err(WorkerError::InvalidArgument(format!(
                "this endpoint serves session {owned}, not {named}"
            )))
        }
    }

    /// Refuses an operation on an attachment this connection does not own.
    ///
    /// An attachment identifier is not permission. A connection acts on the attachments it
    /// created, and nothing else.
    /// Returns the attachment a launch is attributed to.
    ///
    /// The current lease holder, and it has to be one of this connection's own. A line the reader
    /// accepts because of this launch belongs to the client that asked for it, so a caller that
    /// does not hold the keys cannot put one there under somebody else's name.
    fn launching_attachment(session: &Session, state: &ConnectionState) -> Result<AttachmentId> {
        let holder = session.lease().holder.0.ok_or(WorkerError::LeaseLost)?;
        if !state.holds_attachment(holder) {
            return Err(WorkerError::LeaseLost);
        }
        Ok(holder)
    }

    fn check_attachment(state: &ConnectionState, attachment_id: AttachmentId) -> Result<()> {
        if state.holds_attachment(attachment_id) {
            Ok(())
        } else {
            Err(WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            })
        }
    }

    /// Returns the attachment a transfer names, whether or not this connection created it.
    fn params_attachment(params: &ParamsValue) -> Result<AttachmentId> {
        let params: TerminalGeometryTransferParams = parse(params)?;
        Ok(params.attachment_id)
    }

    /// Refuses an operation the attachment was not granted.
    fn check_capability(
        session: &Session,
        attachment_id: AttachmentId,
        capability: AttachmentCapability,
    ) -> Result<()> {
        let granted = session
            .attachment_capabilities(attachment_id)
            .ok_or_else(|| WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            })?;
        if granted.contains(&capability) {
            Ok(())
        } else {
            Err(WorkerError::InvalidArgument(format!(
                "this attachment does not hold {}",
                capability.as_str()
            )))
        }
    }

    fn session_read(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionReadParams = parse(params)?;
        let session = self.runtime.session();
        Self::check_session(&session, params.session_id)?;
        let running = session.state().is_running();
        encode(&SessionReadResult {
            session: session.summary(),
            endpoint: Nullable(running.then(|| self.endpoint.as_text())),
            launch_profile: Nullable(running.then(|| session.config().launch_profile.clone())),
            last_command_block: Nullable(session.last_command_block()),
            outstanding_launches: Nullable(
                running
                    .then(|| session.outstanding_launches())
                    .flatten()
                    .map(U64::new),
            ),
        })
    }

    /// Serves `events.snapshot`: present state, and one page of the resources that go with it.
    ///
    /// The resources are paged because a host's arbitration is as large as its upstreams made it,
    /// and this is also where a paged recovery is continued. A first page copies the state and
    /// cuts the pages from that copy, so what the host does next cannot make two pages into two
    /// different states. A continuation names the copy it belongs to, and a copy that has ended -
    /// read to its end, outlived its deadline, or given up so another connection could recover -
    /// is refused, because the client can always start a new one.
    fn events_snapshot(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: EventsSnapshotParams = parse(params)?;
        let session = self.runtime.session();
        Self::check_session(&session, params.session_id)?;
        // What the answer costs before a single resource is in it, which is what the page has to
        // fit beside. The session and its attachments decide that, so it is measured and not
        // assumed, and a frame that cannot hold it and one resource is refused before this host
        // freezes anything for this connection.
        let bounds = Self::recovery_bounds(
            state,
            Self::answer_bytes(&session.snapshot(Self::no_resources())),
        )?;
        let page = match params.agent_resources_from.as_ref() {
            None => self.begin_recovery(state, bounds),
            Some(from) => self
                .recoveries
                .resume(
                    state.connection_id,
                    from.snapshot_id.get(),
                    from.after_resource_id,
                    self.clock.now(),
                    bounds,
                )
                .ok_or_else(|| WorkerError::ResyncRequired {
                    detail: "the snapshot this continues has ended, so the rest of it is no \
                             longer readable: take a fresh snapshot from its first page"
                        .to_owned(),
                })?,
        };
        let answer = session.snapshot(Self::agent_resource_snapshot(page));
        Self::within_the_frame(state, &answer)?;
        encode(&answer)
    }

    /// Returns how much of a recovery one page may carry, or refuses the peer outright.
    ///
    /// A page is cut to what is left of the frame once the rest of the answer is in it, so what a
    /// recovery needs is the answer's own size plus room for one resource. A resource is bounded
    /// ([`crate::recovery::MAX_RECOVERY_RESOURCE_BYTES`]), so a peer that cannot be served is
    /// known from its declared frame alone, before this host changes anything for it, and the same
    /// decision holds for every later call on that connection however large the state becomes.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when the frame cannot carry the answer and one
    /// resource.
    fn recovery_bounds(
        state: &ConnectionState,
        empty: usize,
    ) -> Result<crate::recovery::PageBounds> {
        let frame = Self::frame_bytes(state);
        if frame < empty.saturating_add(crate::recovery::MAX_RECOVERY_RESOURCE_BYTES) {
            return Err(WorkerError::InvalidArgument(format!(
                "this connection said it can receive {frame} bytes in a control frame, and this \
                 answer needs {empty} of them before one resource of this session's state, which \
                 takes up to {} more",
                crate::recovery::MAX_RECOVERY_RESOURCE_BYTES
            )));
        }
        Ok(crate::recovery::PageBounds {
            resources: MAX_SNAPSHOT_RESOURCES,
            bytes: frame.saturating_sub(empty),
        })
    }

    /// What a subscription answer costs before a single resource is in it.
    ///
    /// The session's agent instances are measured as they are, read under the lock that starts
    /// the subscription's queue. Every other part that varies is measured at its widest - the
    /// cursors, the gap this subscription may have to report, and the recovery's own counters and
    /// continuation - because none of them is known until the session has been read further, and
    /// a page cut against a narrower measurement would be cut too generously.
    fn subscription_answer_bytes(
        state: &ConnectionState,
        agent_instances: &kr_protocol::projection::AgentInstanceList,
    ) -> usize {
        Self::answer_bytes(&EventsSubscribeResult {
            stream_id: state.stream_id.clone(),
            from_cursor: U64::new(u64::MAX),
            oldest_retained_cursor: U64::new(u64::MAX),
            gap: Nullable::some(Self::widest_gap()),
            agent_resources: Self::no_resources(),
            agent_instances: agent_instances.clone(),
        })
    }

    /// Returns what one control frame may carry to this peer, beside its stream header.
    fn frame_bytes(state: &ConnectionState) -> usize {
        usize::try_from(state.peer_limits.max_control_frame_len.get())
            .unwrap_or(usize::MAX)
            .saturating_sub(kr_protocol::limits::MAX_STREAM_HEADER_LEN)
    }

    /// Refuses an answer the peer said it cannot receive.
    ///
    /// A page is cut to what is left of the frame once the rest of the answer is in it, and the
    /// first resource of a page is carried whatever it measures, because a page that refused it
    /// would never advance. Those two together leave one case: a peer whose frame cannot hold the
    /// answer and one resource. Sending it would be sending a frame that peer must discard, so it
    /// is refused here, and the refusal says what the frame would have to be.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when the answer exceeds what the peer declared.
    fn within_the_frame<T: serde::Serialize>(state: &ConnectionState, answer: &T) -> Result<()> {
        let measured = Self::answer_bytes(answer);
        let frame = Self::frame_bytes(state);
        if measured > frame {
            return Err(WorkerError::InvalidArgument(format!(
                "this answer is {measured} bytes and this connection said it can receive {frame}: \
                 one resource of this session's state does not fit a frame that size"
            )));
        }
        Ok(())
    }

    /// Copies what the broker holds for this connection and returns the first page of it.
    ///
    /// The copy and the cursor are taken in the same call, under the broker's own lock, which is
    /// what makes the pages that follow one state taken at one position.
    fn begin_recovery(
        &self,
        state: &ConnectionState,
        bounds: crate::recovery::PageBounds,
    ) -> crate::recovery::RecoveryPage {
        let snapshot = self.broker.resource_snapshot();
        self.recoveries.begin(
            state.connection_id,
            snapshot.cursor,
            snapshot.resources,
            self.clock.now(),
            bounds,
            &|| !state.withdrawn.is_set(),
        )
    }

    /// Measures an answer that carries no resource, which is what a page has to fit beside.
    fn answer_bytes<T: serde::Serialize>(answer: &T) -> usize {
        crate::snapshot::wire::measure(answer).map_or(usize::MAX, |cost| cost.bytes)
    }

    /// The page an answer is measured with: no resource in it, and every other field at its widest.
    ///
    /// What the counters and the continuation will be is not known when the room for a page is
    /// worked out, and a measurement taken with them at their narrowest would leave a page cut too
    /// generously: a snapshot that continues, or a run and a position with large numbers in them,
    /// would then push the answer past the frame after the page had been cut for it.
    fn no_resources() -> kr_protocol::projection::AgentResourceSnapshot {
        kr_protocol::projection::AgentResourceSnapshot {
            snapshot_id: U64::new(u64::MAX),
            stream_generation: U64::new(u64::MAX),
            cursor: U64::new(u64::MAX),
            resources: Vec::new(),
            continue_after: Nullable::some(kr_protocol::ids::PendingResourceId::new(
                kr_protocol::scalars::Uuid::from_bytes([0xff; 16]),
            )),
        }
    }

    /// The widest gap a subscription answer can carry, for the same reason.
    fn widest_gap() -> kr_protocol::recovery::HistoryGap {
        kr_protocol::recovery::HistoryGap {
            cause: Some(kr_protocol::recovery::HistoryGapCause::ArchiveIncomplete),
            from_cursor: U64::new(u64::MAX),
            to_cursor: U64::new(u64::MAX),
        }
    }

    /// Puts one page of a recovery on the wire.
    fn agent_resource_snapshot(
        page: crate::recovery::RecoveryPage,
    ) -> kr_protocol::projection::AgentResourceSnapshot {
        kr_protocol::projection::AgentResourceSnapshot {
            snapshot_id: U64::new(page.snapshot),
            stream_generation: U64::new(page.cursor.generation),
            cursor: U64::new(page.cursor.sequence),
            resources: page.resources,
            continue_after: Nullable(page.continue_after),
        }
    }

    fn history_page(&self, state: &ConnectionState, params: &ParamsValue) -> Result<ParamsValue> {
        let params: HistoryPageParams = parse(params)?;
        let session = self.runtime.session();
        Self::check_session(&session, params.session_id)?;
        // A page that filled the control frame exactly would not fit once its own metadata was
        // encoded around it, so the request is clamped to what the frame can actually carry, and
        // to what the peer said it can receive.
        let bound = state
            .peer_limits
            .max_control_frame_len
            .get()
            .saturating_sub(kr_protocol::limits::MAX_STREAM_HEADER_LEN as u64)
            .min(MAX_REPLAY_PAGE_BYTES);
        let page =
            session.history_page(params.from_cursor.get(), params.max_bytes.get().min(bound))?;
        encode(&page)
    }

    fn events_subscribe(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: EventsSubscribeParams = parse(params)?;
        Self::check_attachment(state, params.attachment_id)?;
        let mut session = self.runtime.session();
        Self::check_session(&session, params.session_id)?;
        // The session's agent instances, read under the lock that starts the queue below. The
        // session announces under this lock too, so an announcement is either in this list or
        // among the events that follow it, and the list's sequence says which.
        let agent_instances = session.agent_instances();
        // Before anything of this connection changes. A subscription replaces the stream the
        // attachment was being served through, and a refusal after that would leave a client with
        // neither the stream it had nor the one it asked for. What decides the refusal is this
        // peer's own frame against the answer's fixed parts, this session's instances and the room
        // one resource needs.
        let bounds = Self::recovery_bounds(
            state,
            Self::subscription_answer_bytes(state, &agent_instances),
        )?;
        let from = params
            .from_cursor
            .as_ref()
            .map_or_else(|| session.output_cursor(), |cursor| cursor.get());
        // The screen comes first, under the same lock that starts the live queue. The restoration
        // ends at the cursor it names and the live queue begins there, so the two meet exactly and
        // nothing arrives twice or goes missing at the handover. Its order matters for one more
        // reason: what that screen could not carry decides how this attachment is served, so the
        // queue is started in the presentation the screen it was actually given supports.
        let joined = session.join(params.attachment_id)?;
        let stream = session.subscribe(params.attachment_id)?;
        // A projected attachment's screen is queued now, through the subscription that has just
        // been created, so it is charged to that subscriber's own bound. It is the first thing in
        // the queue and therefore still the first thing the client receives.
        session.install_projection(params.attachment_id)?;
        // The broker's own state, taken while this session's lock is still held. Delivery to views
        // runs under that lock, so no transition can be published between the queue starting above
        // and this snapshot: a resolution is in the state described here or in the events that
        // follow it, and the cursor says which.
        // The page is cut to what is left of the frame once the rest of this answer is in it. The
        // screen this subscription is drawn is not in the same frame; the cursors and the stream
        // identifier are.
        let agent_resources = self.begin_recovery(state, bounds);
        let oldest = session.oldest_retained_cursor();
        // A client whose position has fallen out of the retained window is told so. The screen it
        // is about to be drawn is current either way; the gap says that what happened in between is
        // no longer readable through `history.page`.
        let gap = (from < oldest).then_some(kr_protocol::recovery::HistoryGap {
            cause: session.history_gap_cause(from),
            from_cursor: U64::new(from),
            to_cursor: U64::new(oldest),
        });
        drop(session);
        let cursor = joined.cursor;
        let answer = EventsSubscribeResult {
            stream_id: state.stream_id.clone(),
            from_cursor: U64::new(cursor),
            oldest_retained_cursor: U64::new(oldest),
            gap: Nullable(gap),
            agent_resources: Self::agent_resource_snapshot(agent_resources),
            agent_instances,
        };
        // Before the subscription is this connection's. A refused answer must leave the client
        // reading what it was reading before it asked: a stream started for an answer that was
        // never sent would deliver events to a view that has no snapshot and no cursor for them.
        Self::within_the_frame(state, &answer)?;
        state.subscribed = Some((params.attachment_id, stream));
        state.restoration = Some(JoinedScreen {
            cursor,
            bytes: joined.bytes,
            gap,
        });
        encode(&answer)
    }

    /// Returns a retained receipt and its result to the actor that owns it.
    ///
    /// The de-duplication key is the actor and the action together, so a lookup here can only ever
    /// find this caller's own action. An identifier belonging to somebody else simply is not
    /// present, which is what keeps an action identifier from being a way to read another actor's
    /// result.
    fn action_read(&self, actor_id: &ActorId, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::receipt::ActionReadParams = parse(params)?;
        let mut session = self.runtime.session();
        let journal = session
            .journal_mut()
            .ok_or_else(|| WorkerError::JournalUnavailable {
                detail: "this session retains no receipts, so none can be read".to_owned(),
            })?;
        let receipt = journal
            .read(actor_id.clone(), params.action_id)?
            .ok_or_else(|| {
                WorkerError::InvalidArgument(format!("no receipt for action {}", params.action_id))
            })?;
        let retained = journal.read_result(actor_id, params.action_id)?;
        drop(session);
        let result = retained
            .map(|bytes| {
                kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map(ParamsValue::new)
                    .map_err(|error| WorkerError::InvalidArgument(error.to_string()))
            })
            .transpose()?;
        encode(&kr_protocol::receipt::ActionReadResult {
            receipt,
            result: Nullable(result),
        })
    }

    /// Reads one question back to the source that created it.
    ///
    /// The source is bound again on every call, from what the kernel says about this connection.
    /// A token alone reaches nothing: it has to be presented by the application the question was
    /// created from.
    fn question_read_own(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::question::QuestionReadOwnParams = parse(params)?;
        {
            let session = self.runtime.session();
            Self::check_session(&session, params.session_id)?;
        }
        let source = self.bind_source(state)?;
        let (result, _) = self
            .questions
            .read_own(&source, &params, self.question_clock())?;
        encode(&result)
    }

    /// Reads the questions an answering actor may see.
    fn question_read(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::question::QuestionReadParams = parse(params)?;
        {
            let session = self.runtime.session();
            Self::check_session(&session, params.session_id)?;
        }
        let (result, _) = self.questions.read(&params, self.question_clock())?;
        encode(&result)
    }

    /// Returns the two clocks a question's deadlines are measured on.
    /// Answers `agent.capabilities`: what this installation can do, with its evidence.
    fn agent_capabilities(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::agent::AgentCapabilitiesParams = parse(params)?;
        encode(&self.broker.agent_capabilities(&params)?)
    }

    /// Answers `agent.snapshot`, through the actor's own history filter.
    ///
    /// The shared host-side filter is the one every subsystem reads through. What this passes is
    /// the lower bound a grant carries, which is the part this worker decides; the answer says how
    /// much was withheld, so a reader can tell a filtered answer from a complete one either way.
    fn agent_snapshot(&self, params: &ParamsValue, caller: &Caller) -> Result<ParamsValue> {
        let params: kr_protocol::agent::AgentSnapshotParams = parse(params)?;
        // A local caller is the operating-system user the listener authenticated, and section 10's
        // history rule narrows a *grant*; there is none to narrow, so it reads the whole retained
        // history, exactly as a local attachment is drawn the whole screen.
        //
        // A forwarded caller does act under a grant, and section 10 narrows a grant's history in
        // one place: the shared host-side filter. The retained agent history is not one of the
        // surfaces that filter admits, so a forwarded read is refused rather than answered with
        // more than the grant may cover; an unrestricted answer to a device is the failure this
        // refusal exists to avoid.
        if caller.is_remote() {
            return Err(WorkerError::Broker(
                crate::broker::BrokerError::UnsupportedCapability {
                    detail:
                        "a forwarded agent snapshot is narrowed by the shared host-side history \
                             filter, and the retained agent history is not one of the surfaces \
                             that filter admits; the terminal and the local reads are unaffected"
                            .to_owned(),
                },
            ));
        }
        let filter = crate::broker::GrantLowerBound {
            from: kr_protocol::ids::StreamCursor::new(0),
        };
        encode(&self.broker.agent_snapshot(&params, &filter)?)
    }

    /// Answers `agent.commands`: what the bound agent advertises.
    fn agent_commands(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::agent::AgentCommandsParams = parse(params)?;
        encode(&self.broker.agent_commands(&params)?)
    }

    /// Answers `agent.approval.inspect`: what an approval's decoder read and what it offered.
    ///
    /// A local caller reads the whole record, as it reads the whole retained agent history: its
    /// authority is the operating-system identity the listener authenticated, and section 10's
    /// history rule narrows a grant, of which there is none. A caller acting under a grant is
    /// refused with the reason instead, whichever socket the daemon heard it on: the grant's
    /// history scope does not reach this worker with a forwarded read, so nothing here can hold
    /// the record to it. A paired device does not get this far, because the method table serves
    /// the read on the local socket only.
    ///
    /// The original source travels whole with the answer, so the answer is held to what this
    /// connection said it can receive: a peer that declared a smaller control frame is refused
    /// with both sizes rather than sent a frame it would have to discard.
    fn agent_approval_inspect(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
        caller: &Caller,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::agent::AgentApprovalInspectParams = parse(params)?;
        if caller.acts_under_a_grant() {
            return Err(WorkerError::Broker(
                crate::broker::BrokerError::UnsupportedCapability {
                    detail: "an approval's record is narrowed to the history scope of the grant a \
                             caller acts under, and that scope does not reach this worker with a \
                             forwarded read; the local owner reads it"
                        .to_owned(),
                },
            ));
        }
        let record = self.broker.inspect_approval(&params)?;
        let measured = Self::answer_bytes(&record);
        if measured > Self::frame_bytes(state) {
            return Err(WorkerError::InvalidArgument(format!(
                "this approval's record is {measured} bytes with its original source, and this \
                 connection said it receives control frames of at most {} bytes",
                state.peer_limits.max_control_frame_len.get()
            )));
        }
        encode(&record)
    }

    /// Returns the application instance one of the agent or plugin methods acts on.
    ///
    /// It is read from the parameters, so the envelope's own selector can be compared with what
    /// the request actually does rather than trusted beside it.
    fn params_application_instance(
        method: Method,
        params: &ParamsValue,
    ) -> Result<kr_protocol::ids::ApplicationInstanceId> {
        Ok(match method {
            Method::AgentPromptSubmit | Method::AgentPromptQueue => {
                parse::<kr_protocol::agent::AgentPromptParams>(params)?
                    .target
                    .subject
                    .application_instance_id
            }
            Method::AgentTurnSteer => {
                parse::<kr_protocol::agent::AgentSteerParams>(params)?
                    .target
                    .subject
                    .application_instance_id
            }
            Method::AgentTurnCancel => {
                parse::<kr_protocol::agent::AgentCancelParams>(params)?
                    .target
                    .subject
                    .application_instance_id
            }
            Method::AgentApprovalRespond => {
                parse::<kr_protocol::agent::AgentApprovalRespondParams>(params)?
                    .target
                    .subject
                    .application_instance_id
            }
            Method::PluginActionInvoke => {
                parse::<kr_protocol::agent::PluginActionInvokeParams>(params)?
                    .target
                    .subject
                    .application_instance_id
            }
            other => {
                return Err(WorkerError::InvalidArgument(format!(
                    "{} names no application instance in its parameters",
                    other.as_str()
                )));
            }
        })
    }

    /// Returns the broker caller for one verified actor.
    /// Refuses a plugin action whose declared class needs a right the caller's grant does not
    /// carry.
    ///
    /// The one caller not held to a grant is the local owner, on this worker's own socket and
    /// naming no grant: its peer credentials proved it is this user, as they do for an
    /// attachment's capabilities. Every other caller holds exactly the rights its grant was
    /// checked against, a caller that reached the host some other way and named no grant
    /// included, which then holds none.
    fn check_action_rights(
        caller: &Caller,
        action: &kr_protocol::broker::ActionName,
        rights: &CanonicalSet<kr_protocol::rights::ActionRight>,
    ) -> Result<()> {
        if caller.ingress == ActorIngress::LocalIpc && !caller.grant_id.is_present() {
            return Ok(());
        }
        let missing: Vec<&str> = rights
            .iter()
            .filter(|right| !caller.grant_rights.contains(right))
            .map(|right| right.as_str())
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(WorkerError::PermissionDenied {
                detail: format!(
                    "{action} needs {}, which the grant this call was admitted under does not \
                     carry",
                    missing.join(" and ")
                ),
            })
        }
    }

    fn broker_caller(caller: &Caller) -> crate::broker::Caller {
        crate::broker::Caller {
            actor_id: caller.actor_id.clone(),
            // A local caller has none, and it stays none: its authority is the operating-system
            // identity the listener authenticated, and naming a grant nothing issued would be a
            // fact this host cannot check written into a token.
            grant_id: caller.grant_id.as_ref().copied(),
        }
    }

    fn question_clock(&self) -> crate::questions::Now {
        crate::questions::Now {
            utc_ms: kr_ipc::now_ms(),
            boot_ms: self.shared_clock.boot_elapsed_ms(),
        }
    }

    /// Returns the attachment a `session.detach` is about.
    ///
    /// A request that names nothing presents the capability the line it runs from was given. That
    /// capability is the whole answer: one line, one token, minted where the acceptance was
    /// recorded and exported by the integration for that command alone. Nothing about the caller's
    /// own process is read, because nothing about a process says which line it belongs to: it can
    /// be started by an earlier line, resumed from the background, or left over from one that has
    /// finished.
    ///
    /// The precondition and the effect resolve through this one function, on the same held
    /// session, so the attachment the check admitted is the attachment that goes.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::AmbiguousDetach`] when nothing is named and no capability of a live
    /// line is presented.
    fn detach_subject(session: &Session, params: &SessionDetachParams) -> Result<AttachmentId> {
        match params.attachment_id.0 {
            Some(named) => Ok(named),
            None => match params.line_token.0.as_deref() {
                Some(presented) => session.detach_for_token(presented),
                None => Err(WorkerError::AmbiguousDetach {
                    detail: format!(
                        "this caller presented no capability for a line this session accepted, so \
                         the attachment it would detach is not established; {DETACH_HINT}"
                    ),
                }),
            },
        }
    }

    /// Binds the caller on this connection to this session, for a source-side question method.
    fn bind_source(&self, state: &ConnectionState) -> Result<crate::questions::VerifiedSource> {
        let boundary = Self::session_boundary(&self.runtime.session());
        Ok(crate::questions::binding::verify(
            state.peer_pid,
            state.peer_process.as_ref(),
            state.connection_id,
            boundary.as_ref(),
            Some(self.broker.as_ref()),
        )?)
    }

    /// Binds the caller on this connection, with the session already held.
    fn bind_source_in(
        &self,
        session: &Session,
        state: &ConnectionState,
    ) -> Result<crate::questions::VerifiedSource> {
        let boundary = Self::session_boundary(session);
        Ok(crate::questions::binding::verify(
            state.peer_pid,
            state.peer_process.as_ref(),
            state.connection_id,
            boundary.as_ref(),
            Some(self.broker.as_ref()),
        )?)
    }

    /// Returns the process boundary this session owns, when its root shell is running.
    fn session_boundary(session: &Session) -> Option<crate::questions::SessionBoundary> {
        Some(crate::questions::SessionBoundary {
            boundary: session.owned()?.boundary().clone(),
            root: session.root_identity()?,
        })
    }

    fn input_write(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
        caller: &Caller,
    ) -> Result<ParamsValue> {
        let params: InputWriteParams = parse(params)?;
        Self::check_attachment(state, params.attachment_id)?;
        // Raw input is its own stream with its own bound. Travelling inside a control frame does
        // not give a keystroke batch the control frame's allowance.
        if params.bytes.len() > kr_protocol::limits::MAX_INPUT_FRAME_LEN {
            return Err(WorkerError::InvalidArgument(format!(
                "an input batch is at most {} bytes",
                kr_protocol::limits::MAX_INPUT_FRAME_LEN
            )));
        }
        let accepted = {
            let mut session = self.runtime.session();
            // Inside the session's own boundary, where the lease and the fence are: a forwarded
            // batch can wait here while the controller installs a newer authority revision or the
            // grant behind it runs out, and what the boundary decides is what actually reaches the
            // application.
            self.check_validated_revision(caller)?;
            self.check_authority_deadline(caller, &mut session, params.attachment_id)?;
            Self::check_session(&session, params.session_id)?;
            Self::check_capability(&session, params.attachment_id, AttachmentCapability::Input)?;
            let accepted = session.write_input(
                params.attachment_id,
                params.epoch.get(),
                params.sequence.get(),
                params.bytes.as_slice(),
                // The deadline travels with the bytes. This check is the host's, taken now; the
                // writer's is its own, taken when the terminal actually takes them.
                caller.authority_deadline_boot_ms,
                std::time::Instant::now(),
            )?;
            // Handed to the writer while the session is still held, so two writers cannot
            // interleave their batches after releasing the lock.
            self.runtime.flush_locked(&mut session);
            accepted
        };
        state.input_sequence = params.sequence.get();
        encode(&InputWriteResult {
            sequence: params.sequence,
            forwarded_bytes: U64::new(accepted.forwarded_bytes),
            held_prefix_bytes: U64::new(accepted.held_prefix_bytes),
        })
    }

    /// Performs one mutation on the session boundary the caller is already holding.
    ///
    /// Everything that happens here happens between the dispatch marker and the recorded outcome,
    /// with the session locked throughout, so nothing the mutation was validated against can move
    /// underneath it. What cannot be done under the lock — writing input to the terminal, starting
    /// a termination sequence — is handed back to the caller as an after-effect.
    fn apply(
        &self,
        session: &mut Session,
        state: &mut ConnectionState,
        mutation: &MutationRequest,
        method: Method,
        caller: &Caller,
        prepared: Option<UpstreamHandoff>,
    ) -> Result<(ParamsValue, AfterEffect)> {
        let params = &mutation.params;
        match method {
            Method::SessionAttach => {
                let params: SessionAttachParams = parse(params)?;
                let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
                // Section 8: what an attachment is granted is what it asked for intersected with
                // the actor's rights. A caller acting under a grant is narrowed to the rights the
                // host checked its request against, capability by capability, so an attachment
                // never records authority its grant never carried and the summary it is given says
                // what it actually holds.
                //
                // Exactly one caller is not narrowed: the local owner, on this worker's own socket
                // and holding no grant. Its peer credentials already proved it is this user and
                // the worker's own authority covers its session. Everything else is narrowed,
                // including a caller that reached the host some other way and named no grant,
                // which under this rule receives nothing rather than everything.
                let granted =
                    if caller.ingress == ActorIngress::LocalIpc && !caller.grant_id.is_present() {
                        params.requested.clone()
                    } else {
                        kr_protocol::rights::permitted_attachment_capabilities(
                            &params.requested,
                            &caller.grant_rights,
                        )
                    };
                // And it is drawn the whole screen, because it holds no grant to be narrowed by.
                // A forwarded caller is drawn the live screen alone: section 10's live-screen
                // exception never reaches the buffer that is not showing, and this build serves a
                // device no retained content beyond it.
                let result = session.attach(&params, granted, attachment_id)?;
                if caller.is_remote() {
                    // The one filter decides how much of the screen a caller is drawn. A forwarded
                    // caller's scope is section 10's live-screen exception, and asking the filter
                    // rather than naming the scope here is what keeps that decision in one place.
                    let filter = crate::history_filter::HistoryFilter::new(
                        crate::history_filter::ViewerScope::forwarded(kr_ipc::now_ms().get()),
                    );
                    session.narrow_content(attachment_id, filter.screen_scope());
                    self.remote_attachments
                        .lock()
                        .expect("the remote attachment set is not poisoned")
                        .insert(attachment_id);
                }
                state.add_attachment(attachment_id);
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::SessionDetach => {
                let params: SessionDetachParams = parse(params)?;
                // The same resolution the validation made, through the same function and on the
                // same held session: a request that named nothing is about the attachment its
                // line's own capability names, never about whatever the session has most recently
                // recorded.
                let attachment_id = Self::detach_subject(session, &params)?;
                // Whose attachment a caller may detach depends on how it reached the host. Every
                // local caller is the same authenticated operating-system user, and detaching from
                // another window is something a person does on purpose. A forwarded caller is a
                // different actor, and an attachment identifier is not permission: it detaches
                // what its own connection created and nothing else. The resolved attachment is
                // what that check is applied to, so naming nothing is not a way around it.
                if caller.is_remote() {
                    Self::check_attachment(state, attachment_id)?;
                }
                let outcome = session.detach(attachment_id);
                // Detaching releases the lease, which moves the input fence, and can produce the
                // terminator of a paste the attachment had open. Both are published here, *before*
                // the result is looked at: the lease has already moved whether or not the geometry
                // succession that follows it succeeded, and a fence that stayed in the session
                // would let bytes already handed to the writer reach the application after the
                // attachment that sent them had gone.
                self.runtime.flush_locked(session);
                let result = outcome?;
                state.remove_attachment(attachment_id);
                self.forget_remote_attachment(attachment_id);
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::SessionClose => {
                let params: kr_protocol::session::SessionCloseParams = parse(params)?;
                let (acceptance, gate) = self
                    .runtime
                    .close_locked(session, ClosureReason::CloseRequested);
                let reply = encode(&SessionCloseResult {
                    session_id: params.session_id,
                    state: acceptance.state,
                    durability: acceptance.durability,
                    closure: Nullable(acceptance.closure),
                })?;
                // The gate is held until the acceptance has been written. The requester is often a
                // command running inside the process group this closure is about to stop.
                Ok((reply, AfterEffect::Close(gate)))
            }
            Method::AttachmentConfigure => {
                let params: AttachmentConfigureParams = parse(params)?;
                let geometry = session.configure(params.attachment_id, params.claim_geometry)?;
                Ok((encode(&GeometryResult { geometry })?, AfterEffect::None))
            }
            Method::TerminalResize => {
                let params: TerminalResizeParams = parse(params)?;
                let geometry = session.resize(
                    params.attachment_id,
                    params.dimensions,
                    params.expected_geometry_epoch.get(),
                )?;
                Ok((encode(&GeometryResult { geometry })?, AfterEffect::None))
            }
            Method::TerminalGeometryTransfer => {
                let params: TerminalGeometryTransferParams = parse(params)?;
                let geometry = session.transfer_geometry(
                    params.attachment_id,
                    params.expected_geometry_epoch.get(),
                )?;
                Ok((encode(&GeometryResult { geometry })?, AfterEffect::None))
            }
            Method::InputAcquire => {
                let params: InputAcquireParams = parse(params)?;
                let result = session.acquire_input(
                    params.attachment_id,
                    state.connection_id,
                    params.expected_epoch.as_ref().map(|epoch| epoch.get()),
                )?;
                self.runtime.flush_locked(session);
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::InputRelease => {
                let params: InputReleaseParams = parse(params)?;
                let lease = session.release_input(params.attachment_id, params.epoch.get())?;
                self.runtime.flush_locked(session);
                Ok((encode(&InputLeaseResult { lease })?, AfterEffect::None))
            }
            Method::InputInterrupt => {
                let params: InputInterruptParams = parse(params)?;
                if params.action != InterruptAction::NativeInterrupt {
                    return Err(WorkerError::InvalidArgument(
                        "the interrupt method accepts only the configured native interrupt"
                            .to_owned(),
                    ));
                }
                // Every stimulus can sweep the machine's own deadlines, so a request from a client
                // can be what releases a hold that had already expired. The batches it released go
                // out on this boundary, whether or not the machine admitted the interrupt itself:
                // nothing else is due to run, and bytes the machine has let go of are the
                // application's.
                let interrupted = session.interrupt(params.attachment_id, params.epoch.get());
                self.runtime.flush_locked(session);
                interrupted?;
                Ok((
                    encode(&InputLeaseResult {
                        lease: session.lease(),
                    })?,
                    AfterEffect::None,
                ))
            }
            Method::ShellLaunch => {
                let params: kr_protocol::root::ShellLaunchParams = parse(params)?;
                let attachment_id = Self::launching_attachment(session, state)?;
                let transaction =
                    kr_shell_integration::contract::requests::LaunchTransactionId::new(
                        kr_ipc::new_uuid(),
                    );
                // Registered before the machine is asked, so an answer that arrives from the
                // bridge's own task the instant the reservation is sent has somewhere to go. It
                // goes on the session this call already holds: reaching for the lock again here
                // would be this thread waiting for itself.
                let receiver = session.register_launch(transaction);
                let driver = session.fence_mut().ok_or_else(|| {
                    WorkerError::ShellIntegrationUnsupported {
                        detail: "this session has no managed root editor to install into"
                            .to_owned(),
                    }
                })?;
                let effects = driver.launch_requested(params, attachment_id, transaction);
                let outcome = session.apply_fence_effects(effects);
                // The same sweep, and the same reason: a launch request can expire a hold that
                // arrived before it, and what the machine released belongs to the application now.
                self.runtime.flush_locked(session);
                // A refusal the machine could take on its own arrives here: nothing was sent to the
                // reader, so there is nothing to wait for.
                if let Some((_, answer)) = outcome.launch_answers.into_iter().next() {
                    session.forget_launch(transaction);
                    return match answer {
                        crate::fence::driver::LaunchAnswer::Installed(result) => {
                            Ok((encode(&result)?, AfterEffect::None))
                        }
                        crate::fence::driver::LaunchAnswer::Refused { reason, code } => {
                            Err(WorkerError::LaunchRefused {
                                reason: reason.as_str(),
                                code,
                            })
                        }
                    };
                }
                // The request is with the reader. The caller's answer is the reader's word, and it
                // is written when it arrives; this placeholder never reaches anybody.
                Ok((
                    ParamsValue::empty(),
                    AfterEffect::Launch {
                        transaction,
                        receiver,
                    },
                ))
            }
            Method::AttachmentViewport => {
                let params: AttachmentViewportParams = parse(params)?;
                let (presentation, top_row) =
                    session.viewport(params.attachment_id, params.dimensions, params.position.0)?;
                Ok((
                    encode(&AttachmentViewportResult {
                        geometry: session.geometry(),
                        presentation,
                        // Where the window actually landed, which is not always where it was
                        // asked to go: a row the session has given up becomes the oldest one it
                        // still holds, and a row inside the live page becomes the live page.
                        position: Nullable(top_row.map(|row| {
                            kr_protocol::attachment::ViewportPosition::Row(U64::new(
                                u64::try_from(row).unwrap_or_default(),
                            ))
                        })),
                    })?,
                    AfterEffect::None,
                ))
            }
            Method::QuestionCreate => {
                let params: kr_protocol::question::QuestionCreateParams = parse(params)?;
                let source = self.bind_source_in(session, state)?;
                let (result, _) = self
                    .questions
                    .create(&source, &params, self.question_clock())?;
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::QuestionCancelOwn => {
                let params: kr_protocol::question::QuestionCancelOwnParams = parse(params)?;
                let source = self.bind_source_in(session, state)?;
                let (result, _) =
                    self.questions
                        .cancel_own(&source, &params, self.question_clock())?;
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::AlertCreate => {
                let params: kr_protocol::question::AlertCreateParams = parse(params)?;
                let source = self.bind_source_in(session, state)?;
                let result = self
                    .questions
                    .alert(&source, &params, self.question_clock())?;
                Ok((encode(&result)?, AfterEffect::None))
            }
            // The answering surface. It needs no caller token: what admits it is the actor the
            // host verified and the rights that actor holds for this session, which is exactly why
            // a source cannot reach it and answer its own question.
            Method::QuestionAnswer => {
                let params: kr_protocol::question::QuestionAnswerParams = parse(params)?;
                let (result, _) = self.questions.answer(
                    &caller.actor_id,
                    caller.device(),
                    &params,
                    self.question_clock(),
                )?;
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::QuestionCancel => {
                let params: kr_protocol::question::QuestionCancelParams = parse(params)?;
                let (result, _) = self.questions.cancel(&params, self.question_clock())?;
                Ok((encode(&result)?, AfterEffect::None))
            }
            Method::ActionCancel => {
                let params: kr_protocol::receipt::ActionCancelParams = parse(params)?;
                let journal =
                    session
                        .journal_mut()
                        .ok_or_else(|| WorkerError::JournalUnavailable {
                            detail: "this session retains no receipts, so none can be cancelled"
                                .to_owned(),
                        })?;
                // Who the cancellation may reach was decided before the dispatch marker; this
                // resolves the same target again under the session lock, because the receipt it
                // acts on is what may have moved in between. A caller the daemon forwarded reaches
                // its own action and no other: the journal is keyed by the verified actor and the
                // action together, and host-management authority over somebody else's intent is
                // the local operating-system caller's alone.
                let target = Self::cancellation_target(journal, caller, params.action_id)?;
                let receipt = journal.cancel(target, params.action_id, kr_ipc::now_ms())?;
                Ok((
                    encode(&kr_protocol::receipt::ActionCancelResult { receipt })?,
                    AfterEffect::None,
                ))
            }
            // The five agent mutations and the plugin action call. The broker admitted each one
            // before the dispatch marker, and the admission it made is what arrives here: the
            // same permit crossed the marker, so nothing it was checked against could move in
            // between. What leaves this boundary is that permit, because the transport work
            // happens after the session mutex is released — terminal ingestion needs that mutex,
            // and an upstream that is slow to answer must not stop a person typing.
            Method::AgentPromptSubmit
            | Method::AgentPromptQueue
            | Method::AgentTurnSteer
            | Method::AgentTurnCancel
            | Method::AgentApprovalRespond => {
                let handoff = prepared.ok_or_else(|| {
                    WorkerError::InvalidArgument(format!(
                        "{} reached its effect without the admission that authorises it",
                        method.as_str()
                    ))
                })?;
                Ok((
                    ParamsValue::empty(),
                    AfterEffect::Upstream(Box::new(handoff)),
                ))
            }
            Method::PluginActionInvoke => {
                // An answer through the connector table's decision destination was admitted
                // before the marker, and its admission leaves this boundary as an approval
                // answer's does. Every other action was refused before the marker, so only a
                // component's prepared effect, which does not reach this broker, meets the refusal.
                if let Some(handoff) = prepared {
                    return Ok((
                        ParamsValue::empty(),
                        AfterEffect::Upstream(Box::new(handoff)),
                    ));
                }
                let params: kr_protocol::agent::PluginActionInvokeParams = parse(params)?;
                Err(crate::broker::BrokerError::UnsupportedCapability {
                    detail: format!(
                        "{} has no prepared effect this broker validated",
                        params.action
                    ),
                }
                .into())
            }
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a mutation this worker serves",
                method.as_str()
            ))),
        }
    }
}

/// The screen one subscription is drawn before its live output begins.
///
/// It is the canonical screen as the terminal engine holds it, rendered side-effect free, not the
/// bytes that produced it. A terminal that joins mid-session therefore sees what is on the screen
/// without anything that was an event when it happened happening again.
#[derive(Clone, Debug)]
pub struct JoinedScreen {
    /// The cursor the screen was taken at. Live output continues from here.
    pub cursor: u64,
    /// The bytes that draw it, for an attachment whose destination is a terminal of this size.
    ///
    /// Empty for a projected attachment: it holds the canonical grid as state and draws it itself,
    /// and its screen is queued through its own subscription so that it is charged to that
    /// subscriber's bound rather than written around it.
    pub bytes: Vec<u8>,
    /// The part of the stream that is no longer readable, when the client had fallen behind it.
    pub gap: Option<kr_protocol::recovery::HistoryGap>,
}

/// Who one request is served as.
///
/// A local caller is the operating-system identity the socket authenticated. A forwarded caller is
/// whoever the control daemon authenticated somewhere else, and the daemon vouches for four things
/// this worker cannot establish for itself: the principal, the ingress the request entered the host
/// Where a mutation's answer came from.
///
/// The value is the same either way. What differs is what producing it means: performing the
/// action, or handing back what an earlier submission of the same action produced. A proxy is told
/// which, because passing a retained result on is a read of somebody's receipt.
enum Answered {
    /// This worker performed the action now.
    Performed(ParamsValue),
    /// The journal already held this action's result.
    Retained(ParamsValue),
    /// An admitted upstream operation whose transport work has not happened yet.
    ///
    /// The admission is committed and the boundary is over. What is left is bytes reaching the
    /// upstream and the outcome being recorded, and neither of those holds anything this worker
    /// needs for something else.
    Upstream {
        /// The admitted operation and what recording it means.
        handoff: Box<UpstreamHandoff>,
        /// The action the outcome is recorded against.
        action_id: kr_protocol::ids::ActionId,
        /// The principal whose action it is.
        actor_id: ActorId,
    },
    /// A launch the reader is deciding.
    ///
    /// Every method but this one is finished when the boundary ends. A launch's effect is the
    /// reservation and the request in the reader's mailbox; its outcome is what the reader did,
    /// and only the reader knows that.
    Launch {
        /// The transaction.
        transaction: kr_shell_integration::contract::requests::LaunchTransactionId,
        /// Where the reader's word arrives.
        receiver: tokio::sync::oneshot::Receiver<crate::fence::driver::LaunchAnswer>,
    },
}
/// by, the grant it was checked against and the authority revision it was checked at.
#[derive(Clone, Debug)]
pub struct Caller {
    /// The principal the request is attributed to.
    pub actor_id: ActorId,
    /// Where the request entered the host.
    pub ingress: ActorIngress,
    /// The grant the daemon checked it against, when one applies.
    pub grant_id: Nullable<kr_protocol::ids::GrantId>,
    /// The paired device the request came from, when it came from one.
    ///
    /// An answer records it beside the principal, because section 25 returns the answering device
    /// as well as the actor to the agent that asked.
    pub device_id: Nullable<kr_protocol::ids::DeviceId>,
    /// The authority revision the daemon validated that grant at.
    ///
    /// A forwarded request carries one; a local caller does not, because its authority is the
    /// operating-system identity the socket authenticated rather than a grant.
    pub validated_revision: Option<kr_protocol::ids::AuthorityRevision>,
    /// When the authority behind the request runs out, on the machine's own continuous clock.
    ///
    /// A mutation carries its accepted deadline, but a read carries none of its own and raw input
    /// is a read. Without this, input admitted a moment before a grant expired could still be
    /// written to the application afterwards, because the queue it waits in is not the check that
    /// admitted it. Absent for a caller whose authority does not expire.
    pub authority_deadline_boot_ms: Option<u64>,
    /// The rights the grant this caller's *mutation* was checked against carries.
    ///
    /// Section 8's intersection of requested attachment capabilities with the actor's rights is
    /// made from this, because the worker holds no grants of its own and an attachment is admitted
    /// here. Empty for a caller whose authority is not a grant, and empty on a read: an
    /// attachment's capabilities are fixed where it is admitted, and every later operation is
    /// checked against what that admission granted rather than against the grant a second time.
    pub grant_rights: CanonicalSet<kr_protocol::rights::ActionRight>,
}

impl Caller {
    /// Returns the caller of a request that arrived on this connection's own socket.
    #[must_use]
    pub fn local(actor_id: ActorId) -> Self {
        Self {
            actor_id,
            ingress: ActorIngress::LocalIpc,
            grant_id: Nullable::null(),
            device_id: Nullable::null(),
            validated_revision: None,
            authority_deadline_boot_ms: None,
            grant_rights: CanonicalSet::new(),
        }
    }

    /// Returns the caller the control daemon vouched for, under the rights it checked.
    #[must_use]
    pub fn forwarded(
        actor: &ActorEnvelope,
        grant_rights: &CanonicalSet<kr_protocol::rights::ActionRight>,
    ) -> Self {
        Self {
            actor_id: actor.actor_id.clone(),
            ingress: actor.ingress,
            grant_id: actor.grant_id,
            device_id: actor.device_id,
            validated_revision: actor.grant_revision.as_ref().copied(),
            authority_deadline_boot_ms: None,
            grant_rights: grant_rights.clone(),
        }
    }

    /// Returns the same caller, with when the authority behind its request runs out.
    #[must_use]
    pub const fn until(mut self, authority_deadline_boot_ms: Option<u64>) -> Self {
        self.authority_deadline_boot_ms = authority_deadline_boot_ms;
        self
    }

    /// Returns true when this caller reached the host over a network transport.
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        self.ingress.is_remote()
    }

    /// Returns true when this caller's authority is a grant rather than the operating-system
    /// identity of a local caller.
    ///
    /// A grant is what section 10's history rule narrows. A caller that reached the host over a
    /// network transport acts under one whatever its envelope names.
    #[must_use]
    pub const fn acts_under_a_grant(&self) -> bool {
        self.grant_id.is_present() || self.is_remote()
    }

    /// Returns the paired device this caller is, when it is one.
    #[must_use]
    pub const fn device(&self) -> Option<kr_protocol::ids::DeviceId> {
        match self.device_id.as_ref() {
            Some(device_id) => Some(*device_id),
            None => None,
        }
    }
}

/// What decides whether a mutation may be admitted for the first time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// The action window this connection holds, and the instant the host read the request.
    ///
    /// Section 9 measures a requested lifetime from receipt time, and admission runs inside a
    /// serial boundary a request may have queued for, so the instant travels with the question
    /// rather than being sampled when the answer is worked out.
    Window(ContinuousInstant),
    /// The deadline the control daemon derived, anchored on this worker's clock as the frame
    /// arrived.
    ///
    /// The wire carries it as a reading of the machine's own boot clock, which both processes read
    /// the same, rather than as either process's continuous instant, which means nothing to the
    /// other. What this holds is what was left of it, anchored the moment the frame is read and
    /// before this worker waits for anything, so nothing the worker then waits for gives the
    /// action its time back.
    ///
    /// `None` is a deadline that had already passed when the frame arrived. A retained action is
    /// still answered under it, because a receipt outlives its freshness; a first admission is
    /// not, because there is no lifetime left to admit one under.
    Vouched(Option<ContinuousInstant>),
}

/// The subject facts a mutation requires to still be true.
///
/// A precondition map is not a closed object with nullable fields: a caller states what it depends
/// on, and states nothing about the rest. Absence therefore means "no precondition". An explicit
/// null is neither: it names a fact and then declines to say what it should be, so it is refused
/// rather than read as absence. The map itself is closed, so a precondition this host does not
/// implement is a refusal, not a field that quietly has no effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MutationPreconditions {
    /// The lifecycle state the session must be in.
    pub session_state: Option<kr_protocol::session::SessionState>,
    /// The geometry epoch the session must be at.
    pub geometry_epoch: Option<kr_protocol::ids::GeometryEpoch>,
    /// The input lease epoch the session must be at.
    pub input_lease_epoch: Option<kr_protocol::ids::InputLeaseEpoch>,
    /// The output cursor the session must be at.
    pub output_cursor: Option<u64>,
    /// The uncertain outcome this request supersedes, and the revision it was read at.
    ///
    /// Section 23 requires an explicit later request to *show* the earlier unknown result. The two
    /// keys are one precondition, because either alone proves nothing: an identifier without a
    /// revision does not say the result was read, and a revision without an identifier does not
    /// say which result.
    pub supersedes: Option<crate::action::dedup::Supersession>,
}

impl MutationPreconditions {
    /// The keys a precondition map may carry.
    pub const KEYS: [&'static str; 6] = [
        "geometry_epoch",
        "input_lease_epoch",
        "output_cursor",
        "session_state",
        kr_protocol::action::SUPERSEDES_ACTION_KEY,
        kr_protocol::action::SUPERSEDES_REVISION_KEY,
    ];

    /// Reads a precondition map out of a mutation's `expected` field.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument failure when the value is not a map, names a precondition this
    /// host does not implement, or carries an explicit null.
    pub fn parse(expected: &ParamsValue) -> Result<Self> {
        let kr_cbor::CanonicalValue::Map(map) = expected.as_value() else {
            return Err(WorkerError::InvalidArgument(
                "the subject preconditions are a map of the facts the caller depends on".to_owned(),
            ));
        };
        let mut preconditions = Self::default();
        let mut supersedes_action = None;
        let mut supersedes_revision = None;
        for (key, value) in map.entries() {
            if matches!(value, kr_cbor::CanonicalValue::Null) {
                return Err(WorkerError::InvalidArgument(format!(
                    "the precondition {key} names a fact and then says nothing about it"
                )));
            }
            match key.as_str() {
                "session_state" => {
                    preconditions.session_state = Some(decode_precondition(key, value)?);
                }
                "geometry_epoch" => {
                    preconditions.geometry_epoch = Some(decode_precondition(key, value)?);
                }
                "input_lease_epoch" => {
                    preconditions.input_lease_epoch = Some(decode_precondition(key, value)?);
                }
                "output_cursor" => {
                    preconditions.output_cursor = Some(decode_precondition(key, value)?);
                }
                kr_protocol::action::SUPERSEDES_ACTION_KEY => {
                    supersedes_action = Some(decode_precondition(key, value)?);
                }
                kr_protocol::action::SUPERSEDES_REVISION_KEY => {
                    supersedes_revision = Some(decode_precondition::<U64>(key, value)?.get());
                }
                other => {
                    return Err(WorkerError::InvalidArgument(format!(
                        "{other} is not a precondition this host evaluates"
                    )));
                }
            }
        }
        preconditions.supersedes = match (supersedes_action, supersedes_revision) {
            (None, None) => None,
            (Some(action_id), Some(revision)) => Some(crate::action::dedup::Supersession {
                action_id,
                revision,
            }),
            _ => {
                return Err(WorkerError::InvalidArgument(format!(
                    "{} and {} are one precondition and are given together",
                    kr_protocol::action::SUPERSEDES_ACTION_KEY,
                    kr_protocol::action::SUPERSEDES_REVISION_KEY
                )));
            }
        };
        Ok(preconditions)
    }
}

fn decode_precondition<T: kr_protocol::wire::WireMessage>(
    key: &str,
    value: &kr_cbor::CanonicalValue,
) -> Result<T> {
    kr_protocol::wire::from_value(value)
        .map_err(|error| WorkerError::InvalidArgument(format!("the precondition {key}: {error}")))
}

/// What a worker was told about the host it belongs to.
#[derive(Clone, Debug)]
pub struct ServiceBinding {
    /// The environment the session belongs to.
    pub environment_id: EnvironmentId,
    /// The boot the worker is running in.
    pub boot_identity: BootIdentity,
    /// The controller key recorded at spawn, which every generation token is checked against.
    pub controller_public_key: AuthorisationKey,
    /// The generation that spawned this worker.
    pub controller_generation: ControllerGeneration,
    /// The worker build.
    pub build_id: kr_protocol::ids::BuildId,
    /// The session's private journal, which is also where its questions are kept.
    ///
    /// `None` keeps them for the life of this process alone, which is what a session without a
    /// retained journal already does with its receipts.
    pub journal_path: Option<std::path::PathBuf>,
}

/// A privacy transition this worker has raised, which its caller settles once it has tried to
/// commit the new generation.
///
/// Settling it tells the control daemon the transition has ended, with the generation the journal
/// holds then, whether the commit succeeded or failed; the daemon releases none of the session's
/// text until it has. One that is dropped without being settled is settled then, by a statement
/// sent from a task of its own.
#[must_use = "a raised transition holds back the session's attention text until it is settled"]
pub struct PrivacyTransition {
    service: Arc<WorkerService>,
    /// The turn that keeps a second transition from being raised meanwhile.
    turn: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl std::fmt::Debug for PrivacyTransition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivacyTransition")
            .field("settled", &self.turn.is_none())
            .finish_non_exhaustive()
    }
}

impl PrivacyTransition {
    /// Settles the transition after the commit attempt, succeeded or failed.
    ///
    /// The statement is sent on a task of its own, so a caller that stops waiting for this does
    /// not stop the statement.
    pub async fn settle(mut self) {
        if let Some(stating) = self.settle_now() {
            let _ = stating.await;
        }
    }

    /// Settles the transition in the fence and starts the statement that says so.
    fn settle_now(&mut self) -> Option<tokio::task::JoinHandle<bool>> {
        let turn = self.turn.take()?;
        let settled = self
            .service
            .attention_fence
            .settle(|| self.service.journal_generation());
        drop(turn);
        let deadline = tokio::time::Instant::now() + crate::attention_fence::ATTENTION_BARRIER_WAIT;
        self.service
            .state_fence(settled.connection_id?, settled, deadline)
    }
}

impl Drop for PrivacyTransition {
    fn drop(&mut self) {
        // The statement's task outlives this; with no runtime to run it on, the connection is
        // ended instead, and the next one states the settled fence first.
        let _ = self.settle_now();
    }
}

/// What one connection knows about itself.
#[derive(Debug)]
pub struct ConnectionState {
    /// The connection identity the host assigned.
    pub connection_id: ConnectionId,
    /// True once version negotiation has succeeded.
    pub negotiated: bool,
    /// True once a controller generation has been accepted on this connection.
    pub controller: bool,
    /// Which kind of client opened this connection, as it declared in its hello.
    pub client_kind: LocalClientKind,
    /// What the peer said it can receive. Nothing this worker sends exceeds it.
    pub peer_limits: kr_protocol::hello::ReceiveLimits,
    /// The generation this connection proved, when it is a controller.
    pub generation: Option<ControllerGeneration>,
    /// What a controller connection is for, as it declared before presenting a token.
    pub controller_role: ControllerConnectionRole,
    /// The event stream identifier notifications carry.
    pub stream_id: StreamId,
    /// The challenge this connection issued to a controller, consumed once.
    pub generation_nonce: Option<Nonce256>,
    /// The latch this connection's registration is withdrawn by.
    ///
    /// Read where a recovery copy is installed, so a first page that was admitted before the
    /// withdrawal and finished after it keeps nothing: the latch is set before the copies are
    /// swept, and the sweep waits for the lock the installation holds, so an installation either
    /// sees the latch or is undone by the sweep.
    pub(crate) withdrawn: Arc<Withdrawal>,
    /// The attachments this connection owns.
    ///
    /// Shared with the connection's registration, so a withdrawal can take them back without
    /// waiting for this connection's own loop to come back round.
    pub attachments: Arc<Mutex<Vec<AttachmentId>>>,
    /// The output subscription waiting to be started.
    pub subscribed: Option<(AttachmentId, crate::output::OutputStream)>,
    /// The last input sequence accepted on this connection.
    pub input_sequence: u64,
    /// A close that has been admitted and whose acceptance has not yet been written.
    pub close_gate: Option<(kr_protocol::ids::ActionId, crate::runtime::CloseGate)>,
    /// A launch this connection asked for, whose answer the reader has not given yet.
    ///
    /// The connection's own loop takes it and hands it to a task of its own, so the read loop goes
    /// on serving this client while its launch is with the reader.
    pub pending_launch: Option<PendingLaunch>,
    /// A page the control daemon asked for, to be read and answered on its own task.
    pub pending_page: Option<PendingPage>,
    /// The task reading or holding that page, while it is.
    pub page_task: Option<tokio::task::JoinHandle<()>>,
    /// What tells that task a newer request has replaced it.
    pub page_cancel: Option<tokio::sync::oneshot::Sender<()>>,
    /// An admitted upstream operation whose transport work has not happened yet.
    ///
    /// The connection's own loop takes it and hands it to a task of its own. Section 12 has this
    /// socket carry the same client's next keystroke, its interrupt, its detach and its keepalive,
    /// and none of those waits behind an upstream that is slow to answer.
    pub pending_upstream: Option<PendingUpstream>,
    /// A close whose acceptance was written and whose delivery a proxy has not yet confirmed.
    pub pending_delivery: Option<(kr_protocol::ids::ActionId, crate::runtime::PendingDelivery)>,
    /// A generation challenge waiting to be sent after the current reply.
    pub pending_challenge: Option<ControlFrame>,
    /// The first statement of a newly accepted attention connection, sent after the acceptance.
    pub pending_statement: Option<crate::attention_fence::Statement>,
    /// The screen a new subscription is drawn before live output resumes.
    pub restoration: Option<JoinedScreen>,
    /// The delivery task this connection owns, cancelled when the connection goes.
    delivery: Option<Delivery>,
    /// The host-issued principal this connection acts under.
    ///
    /// It is built from the authenticated operating-system caller. A local caller never asserts
    /// its own provenance and never borrows a device identity.
    pub actor_id: ActorId,
    /// The calling process the kernel named, where the platform reports one.
    ///
    /// It is what a question's source binding is established from, and it comes from the socket
    /// rather than from anything the caller sent.
    pub peer_pid: Option<u32>,
    /// That process's start identity, read when the connection was accepted.
    ///
    /// Pinning it here is what stops a process identifier the kernel recycles while this
    /// connection is open from being answered as though it were the caller that opened it.
    pub peer_process: Option<kr_protocol::identity::ProcessStartIdentity>,
    next_request: u64,
}

impl ConnectionState {
    /// Builds the state for a fresh connection.
    ///
    /// `attachments` is the registration's own list, so what this connection takes and what a
    /// withdrawal gives back are one list rather than two that can disagree.
    #[must_use]
    pub fn new(
        connection_id: ConnectionId,
        peer: &PeerIdentity,
        attachments: Arc<Mutex<Vec<AttachmentId>>>,
    ) -> Self {
        Self {
            connection_id,
            negotiated: false,
            controller: false,
            client_kind: LocalClientKind::Cli,
            peer_limits: kr_protocol::hello::ReceiveLimits::default(),
            generation: None,
            controller_role: ControllerConnectionRole::Authority,
            stream_id: StreamId::new(OUTPUT_STREAM).expect("a valid stream name"),
            generation_nonce: None,
            withdrawn: Arc::new(Withdrawal::default()),
            attachments,
            subscribed: None,
            input_sequence: 0,
            close_gate: None,
            pending_launch: None,
            pending_page: None,
            page_task: None,
            page_cancel: None,
            pending_upstream: None,
            pending_delivery: None,
            pending_challenge: None,
            pending_statement: None,
            restoration: None,
            delivery: None,
            actor_id: ActorId::new(format!("local:{}", peer.uid))
                .unwrap_or_else(|_| ActorId::new("local").expect("a valid principal")),
            peer_pid: peer.pid,
            peer_process: peer
                .pid
                .and_then(|pid| kr_ipc::identity::process_start_identity(pid).ok()),
            next_request: 0,
        }
    }

    /// Records an attachment this connection now owns.
    fn add_attachment(&self, attachment_id: AttachmentId) {
        self.attachments
            .lock()
            .expect("the attachment list is not poisoned")
            .push(attachment_id);
    }

    /// Forgets an attachment this connection has given up.
    fn remove_attachment(&self, attachment_id: AttachmentId) {
        self.attachments
            .lock()
            .expect("the attachment list is not poisoned")
            .retain(|held| *held != attachment_id);
    }

    /// Returns whether this connection owns the attachment.
    fn holds_attachment(&self, attachment_id: AttachmentId) -> bool {
        self.attachments
            .lock()
            .expect("the attachment list is not poisoned")
            .contains(&attachment_id)
    }

    /// Takes every attachment this connection still owns.
    fn take_attachments(&self) -> Vec<AttachmentId> {
        std::mem::take(
            &mut *self
                .attachments
                .lock()
                .expect("the attachment list is not poisoned"),
        )
    }

    fn next_request_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }
}

/// The task delivering a connection's subscription, and how it is told a newer one replaced it.
#[derive(Debug)]
struct Delivery {
    task: tokio::task::JoinHandle<()>,
    /// Dropped when a newer subscription replaces this one.
    replacement: tokio::sync::oneshot::Sender<()>,
}

impl Delivery {
    /// Tells the task that a newer subscription has replaced it, and hands it over to be waited
    /// for.
    ///
    /// The word goes out under the connection's writer, which is where the task decides whether to
    /// begin its next frame: it either sees the replacement and begins nothing more, or had already
    /// begun and finishes that frame. A closure notice it has written is still followed by the
    /// keepalive that completes it.
    fn replace(self, writer: &Mutex<kr_ipc::framed::FrameWriter>) -> Predecessor {
        {
            let _boundary = writer
                .lock()
                .expect("the connection writer is not poisoned");
            drop(self.replacement);
        }
        Predecessor(self.task)
    }

    /// Stops the task where it stands, and the delivery it replaced if that one is still going.
    fn abort(&self) {
        self.task.abort();
    }
}

/// A delivery that a newer subscription replaced, finishing the frame it had begun.
///
/// The delivery that replaced it waits for it before writing anything, and owns it while it waits:
/// stopping the waiter stops this one too, so a connection that ends, or whose authority is
/// withdrawn, leaves no task behind that is still writing to it.
#[derive(Debug)]
struct Predecessor(tokio::task::JoinHandle<()>);

impl Predecessor {
    /// Waits until the replaced delivery has stopped.
    async fn stopped(mut self) {
        let _ = (&mut self.0).await;
    }
}

impl Drop for Predecessor {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A test's hold on the next connection that replaces a running delivery.
///
/// Returned by [`WorkerService::pause_before_replacing_delivery`], for this host's own tests.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct ReplacementPause {
    /// Says the connection has answered the replacing request and stands before the replacement.
    pub arrived: tokio::sync::oneshot::Receiver<()>,
    /// Lets the connection go on; dropping it does too.
    pub release: tokio::sync::oneshot::Sender<()>,
    /// Says the connection has told the running delivery that it was replaced.
    pub replaced: tokio::sync::oneshot::Receiver<()>,
}

/// The connection's ends of a [`ReplacementPause`].
#[cfg(feature = "testing")]
#[derive(Debug)]
struct ArmedReplacement {
    arrived: tokio::sync::oneshot::Sender<()>,
    go: tokio::sync::oneshot::Receiver<()>,
    replaced: tokio::sync::oneshot::Sender<()>,
}

/// One connection's registration in the worker's authority store.
///
/// It is what a withdrawal acts on, and it holds everything a withdrawal has to end without asking
/// the connection's own loop to do it: the latch that loop and its writes watch, the delivery task
/// it started, and the attachments it owns.
#[derive(Clone, Debug)]
struct Registration {
    withdrawn: Arc<Withdrawal>,
    delivery: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    /// The attachments this connection owns, shared so a withdrawal can take them back itself.
    attachments: Arc<Mutex<Vec<AttachmentId>>>,
    /// The connection's writer, so a withdrawal is decided on the same lock the writes are.
    writer: Arc<Mutex<kr_ipc::framed::FrameWriter>>,
    /// Whose turn it is to write, and where a write waits when the peer has stopped reading.
    writable: Writing,
}

/// A registration's withdrawal, as something every part of a connection can watch at once.
///
/// A stored notification permit is answered by exactly one waiter, and a connection has more than
/// one place that has to react: the loop waiting for the next frame, and a write that is waiting
/// for a peer which has stopped reading. This is a latch instead. It is set once, it is never
/// cleared, and every waiter, present and future, observes it.
#[derive(Debug, Default)]
pub(crate) struct Withdrawal {
    withdrawn: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Withdrawal {
    /// Sets the latch and wakes everything waiting on it.
    fn set(&self) {
        self.withdrawn
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Returns whether the registration has been withdrawn.
    fn is_set(&self) -> bool {
        self.withdrawn.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Waits until the registration is withdrawn, returning at once if it already has been.
    async fn wait(&self) {
        if self.is_set() {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        // Registered before the second look, so a withdrawal between the two is not missed.
        notified.as_mut().enable();
        if self.is_set() {
            return;
        }
        notified.await;
    }
}

/// The largest payload one output notification carries.
///
/// A control frame is bounded at 1 MiB including its metadata, so a payload stays well inside that
/// rather than filling it exactly. A rendering of a large screen is bigger than one frame, and a
/// restoration that was written as one frame would simply fail to be written at all.
pub const MAX_OUTPUT_EVENT_BYTES: usize = 256 * 1024;

/// Writes one frame, and stops a protected one from reaching a withdrawn connection.
///
/// Returns whether the frame reached the peer. `protected` says whether this frame was produced
/// while the connection still held its registration. Such a frame carries what that authority gave
/// it, so the withdrawal wins every race against it: a peer that has stopped reading would
/// otherwise hold it, and with it everything the connection still owns, for as long as it stayed
/// away, and a peer that starts reading again would be handed something the host no longer stands
/// behind.
///
/// An unprotected frame is one this host produced *after* the withdrawal: the refusal a fenced
/// caller is owed, or a keepalive. It is written ordinarily, so a fenced connection learns why its
/// next request failed rather than finding a socket that closed.
///
/// The authority and the writing are one step. The lock is taken, the latch is looked at, one
/// attempt is made that refuses to wait, and the lock is released; the waiting for a peer that has
/// no room happens outside it, against the latch. A withdrawal takes that same lock to set the
/// latch, so after it returns no frame of that connection's can begin, and one that had begun is
/// left half written and ends the connection rather than being finished later.
async fn write_frame(
    writable: &Writing,
    writer: &Arc<Mutex<kr_ipc::framed::FrameWriter>>,
    frame: &ControlFrame,
    withdrawn: &Withdrawal,
    protected: bool,
) -> bool {
    write_frame_unless(writable, writer, frame, withdrawn, protected, None).await
}

/// Writes one frame, as [`write_frame`], unless `abandoned` says so before its first byte is
/// written.
///
/// An answer a newer request has replaced is not written, however long it waited for its turn, and
/// nor is the next frame of a delivery a newer subscription has replaced. Once its first byte has
/// gone, it is finished rather than cut: a frame cut part way would end the connection.
async fn write_frame_unless(
    writable: &Writing,
    writer: &Arc<Mutex<kr_ipc::framed::FrameWriter>>,
    frame: &ControlFrame,
    withdrawn: &Withdrawal,
    protected: bool,
    mut abandoned: Option<&mut tokio::sync::oneshot::Receiver<()>>,
) -> bool {
    let Ok(bytes) = kr_ipc::framed::FrameWriter::encode(StreamKind::Control, frame) else {
        return false;
    };
    // One frame at a time on this connection. A frame the peer had no room for is retained by the
    // writer until it is finished, so a second writer starting one in between would interleave two
    // frames on a stream that carries them whole. This is where a writer waits for its turn, and a
    // withdrawal ends that wait rather than joining it, as does abandoning the frame.
    let abandon = async {
        match abandoned.as_deref_mut() {
            Some(abandoned) => {
                let _ = abandoned.await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    let _turn = if protected {
        tokio::select! {
            biased;
            () = withdrawn.wait() => return false,
            () = abandon => return false,
            turn = writable.turn.lock() => turn,
        }
    } else {
        tokio::select! {
            biased;
            () = abandon => return false,
            turn = writable.turn.lock() => turn,
        }
    };
    // Whether the frame is in the writer's hands, and whether any of it has reached the peer. The
    // two differ when the socket took none of it: such a frame is still this writer's to take
    // back, and a frame that has been abandoned is taken back then rather than sent later.
    let mut offered = false;
    let mut begun = false;
    loop {
        let attempt = {
            let mut sender = writer
                .lock()
                .expect("the connection writer is not poisoned");
            if protected && withdrawn.is_set() {
                return false;
            }
            // Asked under the writer, which is also where a replacement is signalled, so the
            // answer holds until the attempt below has written or not.
            if !begun && abandoned.as_deref_mut().is_some_and(replaced) {
                if offered {
                    sender.withdraw_unstarted();
                }
                return false;
            }
            // A frame that was cut in half left its beginning with the peer. Writing anything else
            // now would push the rest of it out first, so this connection is finished instead:
            // what the host stopped sending stays stopped.
            if !offered && sender.is_mid_frame() {
                return false;
            }
            let attempt = if offered {
                sender.resume_frame()
            } else {
                sender.begin_frame(&bytes)
            };
            offered = true;
            begun = sender.has_sent_any();
            attempt
        };
        match attempt {
            Ok(kr_ipc::framed::Wrote::Complete) => return true,
            Ok(kr_ipc::framed::Wrote::Blocked) => {}
            Err(_) => return false,
        }
        // The peer has no room. Waiting for it happens here, where the boundary is not held and a
        // withdrawal can both take that boundary and end this wait. While none of the frame has
        // gone, abandoning it ends the wait too, and the next look under the writer takes it back:
        // a frame that is not going to be sent does not hold the connection's turn until the peer
        // reads again.
        let abandon = async {
            match abandoned.as_deref_mut() {
                Some(abandoned) if !begun => {
                    let _ = abandoned.await;
                }
                _ => std::future::pending::<()>().await,
            }
        };
        if protected {
            tokio::select! {
                biased;
                () = withdrawn.wait() => return false,
                () = abandon => {}
                ready = writable.readiness.ready() => {
                    if ready.is_err() {
                        return false;
                    }
                }
            }
        } else {
            tokio::select! {
                biased;
                () = abandon => {}
                ready = writable.readiness.ready() => {
                    if ready.is_err() {
                        return false;
                    }
                }
            }
        }
    }
}

/// Writes one frame before `deadline`, as [`write_frame`] writes a protected one.
///
/// Returns whether the whole frame reached the peer in time. A frame none of whose bytes went is
/// taken back when the deadline passes, so the stream stays clean for the next frame; one the peer
/// has part of is left as it is, and the caller ends the connection.
async fn write_within(
    writable: &Writing,
    writer: &Arc<Mutex<kr_ipc::framed::FrameWriter>>,
    frame: &ControlFrame,
    withdrawn: &Withdrawal,
    deadline: tokio::time::Instant,
) -> bool {
    let Ok(bytes) = kr_ipc::framed::FrameWriter::encode(StreamKind::Control, frame) else {
        return false;
    };
    let _turn = tokio::select! {
        biased;
        () = withdrawn.wait() => return false,
        () = tokio::time::sleep_until(deadline) => return false,
        turn = writable.turn.lock() => turn,
    };
    let mut offered = false;
    loop {
        let attempt = {
            let mut sender = writer
                .lock()
                .expect("the connection writer is not poisoned");
            if withdrawn.is_set() || tokio::time::Instant::now() >= deadline {
                if offered {
                    sender.withdraw_unstarted();
                }
                return false;
            }
            if !offered && sender.is_mid_frame() {
                return false;
            }
            let attempt = if offered {
                sender.resume_frame()
            } else {
                sender.begin_frame(&bytes)
            };
            offered = true;
            attempt
        };
        match attempt {
            Ok(kr_ipc::framed::Wrote::Complete) => return true,
            Ok(kr_ipc::framed::Wrote::Blocked) => {}
            Err(_) => return false,
        }
        // Whichever ends the wait, the next look above decides: the deadline and the withdrawal
        // both stop the frame there, taking it back when none of it went.
        tokio::select! {
            biased;
            () = withdrawn.wait() => {}
            () = tokio::time::sleep_until(deadline) => {}
            ready = writable.readiness.ready() => {
                if ready.is_err() {
                    return false;
                }
            }
        }
    }
}

/// Whether a newer request or subscription has replaced the one this belongs to.
///
/// The replacement sends, or drops the sender; either one is a replacement.
fn replaced(cancelled: &mut tokio::sync::oneshot::Receiver<()>) -> bool {
    !matches!(
        cancelled.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    )
}

/// Returns the request identifier a frame carries, or nought for a frame that carries none.
fn request_id_of(frame: &ControlFrame) -> RequestId {
    match frame {
        ControlFrame::Request(request) => request.request_id,
        ControlFrame::Mutation(mutation) => mutation.request_id,
        ControlFrame::Forwarded(forwarded) => forwarded.mutation.request_id,
        ControlFrame::ForwardedRead(forwarded) => forwarded.request.request_id,
        ControlFrame::AttentionSources(request) => request.request_id,
        ControlFrame::AttentionText(request) => request.request_id,
        _ => RequestId::new(0),
    }
}

/// What a connection needs to write a frame without holding the boundary while it waits.
///
/// Two things, and they are different: whose turn it is to put a frame on this stream, and whether
/// the peer has room for more of it. The turn is held for a whole frame, because a stream carries
/// frames whole; the readiness is waited on inside that turn, and neither is the boundary that
/// decides whether the frame may be sent at all.
#[derive(Clone, Debug)]
struct Writing {
    turn: Arc<tokio::sync::Mutex<()>>,
    readiness: kr_ipc::framed::Writable,
}

/// Where one delivery writes its frames, and what stops it.
///
/// Every frame of a delivery goes through here. [`Outlet::write`] passes both checks: the
/// withdrawal, which stops a delivery wherever it stands, and the replacement, which stops it
/// between two frames. [`Outlet::write_even_if_replaced`] passes the withdrawal only, and carries
/// nothing but the keepalive that completes a closure notice.
#[derive(Debug)]
struct Outlet {
    writable: Writing,
    writer: Arc<Mutex<kr_ipc::framed::FrameWriter>>,
    withdrawn: Arc<Withdrawal>,
    /// Closed when a newer subscription replaces this delivery.
    replaced: tokio::sync::oneshot::Receiver<()>,
}

impl Outlet {
    /// Writes one frame of this delivery, unless the delivery has been withdrawn, or has been
    /// replaced before the frame began.
    async fn write(&mut self, frame: &ControlFrame) -> bool {
        write_frame_unless(
            &self.writable,
            &self.writer,
            frame,
            &self.withdrawn,
            true,
            Some(&mut self.replaced),
        )
        .await
    }

    /// Writes one frame that belongs with the frame this delivery wrote last, whether or not the
    /// delivery has been replaced since. A withdrawal still stops it.
    async fn write_even_if_replaced(&self, frame: &ControlFrame) -> bool {
        write_frame(&self.writable, &self.writer, frame, &self.withdrawn, true).await
    }
}

/// Writes a span of the output stream, in frames the control stream can carry.
///
/// Each frame carries the cursor its own bytes start at, because they are consecutive positions in
/// one stream. A span that a newer subscription replaces part way finishes the frame it has begun
/// and stops before the next; a withdrawal can stop the frame it has begun as well.
async fn send_stream(
    outlet: &mut Outlet,
    stream_id: &StreamId,
    sequence: &mut u64,
    cursor: u64,
    bytes: &[u8],
) -> bool {
    let mut at = cursor;
    for chunk in bytes.chunks(MAX_OUTPUT_EVENT_BYTES) {
        let event = OutputEvent {
            cursor: U64::new(at),
            bytes: kr_protocol::scalars::Bytes::new(chunk.to_vec()),
        };
        let Some(notification) = notification(stream_id, *sequence, "session.output", &event)
        else {
            return false;
        };
        *sequence += 1;
        // Every frame goes through the same boundary, so a span that takes several of them stops
        // at the first one after the withdrawal rather than finishing the span it had begun.
        // Stopping the task is not enough on its own: a task whose chunks are all ready writes
        // them without ever yielding to the abort.
        if !outlet.write(&notification).await {
            return false;
        }
        at += chunk.len() as u64;
    }
    true
}

/// Writes a rendering of the canonical screen, in frames the control stream can carry.
///
/// Every frame carries the same cursor: they are parts of one screen at one moment, not
/// consecutive positions in a stream, and a client draws them in the order they arrive. A screen
/// that a newer subscription replaces part way finishes the frame it has begun and stops before the
/// next: the new subscription is drawn a screen of its own.
async fn send_screen(
    outlet: &mut Outlet,
    stream_id: &StreamId,
    sequence: &mut u64,
    cursor: u64,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    for chunk in bytes.chunks(MAX_OUTPUT_EVENT_BYTES) {
        let event = OutputEvent {
            cursor: U64::new(cursor),
            bytes: kr_protocol::scalars::Bytes::new(chunk.to_vec()),
        };
        let Some(notification) = notification(stream_id, *sequence, "session.output", &event)
        else {
            return false;
        };
        *sequence += 1;
        if !outlet.write(&notification).await {
            return false;
        }
    }
    true
}

/// Returns whether a failure is the journal being unable to do its job.
///
/// Section 7's exception for an authorised stop is about storage: a full disk, a read-only tree, a
/// database that will not open. It is not about anything the journal *decided*, and a reused action
/// identifier is a decision.
/// Anchors a deadline the control daemon accepted on this worker's own clock.
///
/// The daemon measured it on the machine's own continuous clock, which this worker reads too. This
/// worker's own clock is read **first** and the machine's clock second, so a pause between the two
/// readings shortens the answer rather than lengthening it. The result is bounded by the protocol
/// maximum, so a daemon cannot hand a worker a longer life than the protocol allows, and `None`
/// Returns what a method is, for the purposes of a store that has failed.
///
/// What section 7 and section 11 keep available when the store has failed, and what they do not.
/// `session.close` is the authorised stop; `input.interrupt` is the interruption the live input
/// lease keeps, which is the one way a person has of stopping a running command on a host whose
/// journal has stopped answering. Everything else is rich work and is refused before dispatch.
/// Neither exception authorises a hidden rich retry: what they lose is the receipt, which is what
/// `durability=volatile` says for the close.
///
/// One answer serves every gate on the way in, so a method the posture admits is not then refused
/// by a read the same broken store could not answer.
const fn work_class(method: Method) -> crate::persistence::fault::WorkClass {
    match method {
        Method::SessionClose => crate::persistence::fault::WorkClass::AuthorisedStop,
        Method::InputInterrupt => crate::persistence::fault::WorkClass::NativeTerminal,
        _ => crate::persistence::fault::WorkClass::RichMutation,
    }
}

/// means the deadline has already passed.
fn vouched_deadline(
    clock: &dyn ContinuousClock,
    shared: &dyn kr_ipc::clock::SharedClock,
    accepted_deadline_boot_ms: u64,
) -> Option<ContinuousInstant> {
    let now = clock.now();
    let remaining =
        kr_ipc::clock::remaining_of(shared.boot_elapsed_ms(), accepted_deadline_boot_ms)?.min(
            std::time::Duration::from_millis(kr_protocol::limits::MAX_MUTATION_TTL.get()),
        );
    now.checked_add(remaining)
}

const fn is_storage_failure(error: &WorkerError) -> bool {
    matches!(
        error,
        WorkerError::Storage { .. } | WorkerError::JournalUnavailable { .. }
    )
}

fn parse<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| WorkerError::InvalidArgument(error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(value).map_err(|error| WorkerError::InvalidArgument(error.to_string()))
}

fn respond(request_id: RequestId, outcome: Result<ParamsValue>) -> ControlFrame {
    match outcome {
        Ok(value) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Err(error) => failure(request_id, &error.to_protocol_error()),
    }
}

fn failure(request_id: RequestId, error: &ProtocolError) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Error(error.clone()),
    })
}

/// A page of attention source records the control daemon asked for, read and answered off the
/// connection's read loop so that holding it holds nothing up.
#[derive(Debug)]
pub struct PendingPage {
    /// The request.
    pub request: kr_protocol::attention::AttentionSourcesRequest,
    /// What the page may carry, its text included, to fit one frame to the daemon.
    pub max_bytes: usize,
}

/// One launch whose answer the reader has not given yet.
///
/// Everything the answer needs, carried off the connection's read loop so the wait holds nothing up.
#[derive(Debug)]
pub struct PendingLaunch {
    /// The request the answer belongs to.
    request_id: RequestId,
    /// The action its receipt belongs to.
    action_id: kr_protocol::ids::ActionId,
    /// The principal that asked.
    actor_id: ActorId,
    /// The transaction.
    transaction: kr_shell_integration::contract::requests::LaunchTransactionId,
    /// Where the reader's word arrives.
    receiver: tokio::sync::oneshot::Receiver<crate::fence::driver::LaunchAnswer>,
}

/// One admitted operation the upstream has not answered yet.
///
/// Everything the answer needs, carried off the connection's read loop so the wait holds nothing
/// up.
#[derive(Debug)]
pub struct PendingUpstream {
    /// The request the answer belongs to.
    request_id: RequestId,
    /// The action its receipt belongs to.
    action_id: kr_protocol::ids::ActionId,
    /// The principal that asked.
    actor_id: ActorId,
    /// The admitted operation and what recording it means.
    handoff: Box<UpstreamHandoff>,
}

/// How long an admitted operation has to reach its upstream.
///
/// Section 11 makes a framing connection that cannot safely continue `UPSTREAM_UNAVAILABLE` rather
/// than a wait without an end. This is what turns "cannot continue" into a fact rather than a
/// hope: an upstream that has not answered by now leaves the outcome unknown, which is what it is.
pub const UPSTREAM_SUBMIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Which of the broker's recordings one admitted operation ends in.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UpstreamKind {
    /// A prompt, a steer or a cancellation.
    Mutation,
    /// An approval answer, which also resolves its pending resource.
    Approval,
    /// A package's action that answers a pending request through the connector table's decision
    /// destination: carried as an approval answer, and reported as the action that ran.
    PluginAnswer {
        /// The action.
        action: kr_protocol::broker::ActionName,
    },
}

/// One admitted operation, waiting for the session boundary to end before it is transmitted.
#[derive(Debug)]
pub struct UpstreamHandoff {
    broker: Arc<crate::broker::Broker>,
    admitted: crate::broker::MutationAdmission,
    kind: UpstreamKind,
}

impl UpstreamHandoff {
    /// Gives the admission up without transmitting.
    ///
    /// A dispatch marker this host could not write leaves no executable permit behind it: what
    /// the admission authorised is retired here rather than left for something else to send.
    fn abandon(self) {
        self.broker.abandon(&self.admitted);
    }

    /// Carries the admitted operation to its upstream and encodes what the upstream did, or stops
    /// waiting at `deadline`.
    ///
    /// Nothing of this worker's is held while this runs. The admission already carries everything
    /// the broker checked and the transport it checked against, so the transmission needs no lock
    /// of its own. What is awaited is the transport's own account of the operation: the bytes
    /// reaching the socket, and then, for a request, the upstream's own answer. A receipt says
    /// `applied` for this and for nothing earlier.
    ///
    /// The broker's own steps (the permit, the marker and an answer's settlement) happen on this
    /// task. Only the transport's call that takes the operation runs on a thread of its own, since
    /// a transport can block there and on this task the deadline could never fire. At the
    /// deadline this stops waiting for that call or for the upstream, and an answer's claim, which
    /// never left this task, leaves its resource uncertain before this returns; whatever the
    /// transport does afterwards settles nothing.
    async fn carry(self, deadline: tokio::time::Instant) -> Result<ParamsValue> {
        let now = kr_ipc::now_ms();
        match self.kind {
            UpstreamKind::Mutation => {
                let taken = self.broker.take_mutation(&self.admitted)?;
                let pending = submit_within(taken.transmission(), deadline).await?;
                let flight = taken.submitted(pending);
                encode(&within(deadline, flight.settled()).await??)
            }
            UpstreamKind::Approval => {
                let answered = answer_within(&self.broker, &self.admitted, now, deadline).await?;
                encode(&answered)
            }
            UpstreamKind::PluginAnswer { action } => {
                let answered = answer_within(&self.broker, &self.admitted, now, deadline).await?;
                encode(&kr_protocol::agent::PluginActionInvokeResult {
                    mutation: answered.mutation,
                    action,
                })
            }
        }
    }
}

/// Carries one admitted answer to its upstream, settling its resource with what the transport
/// says, or as uncertain when `deadline` passes first.
async fn answer_within(
    broker: &crate::broker::Broker,
    admitted: &crate::broker::MutationAdmission,
    now: kr_protocol::scalars::TimestampMs,
    deadline: tokio::time::Instant,
) -> Result<kr_protocol::agent::AgentApprovalRespondResult> {
    let marked = broker.mark_approval(admitted, now)?;
    // On a refusal or at the deadline `marked` is dropped here, which leaves the resource
    // uncertain before the caller is told anything.
    let pending = match submit_within(marked.transmission(), deadline).await {
        Ok(pending) => pending,
        Err(error) => {
            drop(marked);
            return Err(error);
        }
    };
    let flight = marked.submitted(pending);
    // At the deadline the answer in flight is dropped with the timeout, which settles it the
    // same way.
    Ok(within(deadline, flight.settled(now)).await??)
}

/// Makes the transport's own call that takes an operation on a thread of its own, and waits for
/// it until `deadline`.
///
/// A transport that blocks there holds that thread and nothing else. What it returns after the
/// deadline is dropped: the call's outcome is no longer anybody's to report.
async fn submit_within(
    (dispatch, request): (
        Arc<dyn crate::broker::UpstreamDispatch>,
        crate::broker::UpstreamRequest,
    ),
    deadline: tokio::time::Instant,
) -> Result<crate::broker::PendingTransmission> {
    let submitting = tokio::task::spawn_blocking(move || dispatch.submit(&request));
    match tokio::time::timeout_at(deadline, submitting).await {
        Ok(Ok(submitted)) => Ok(submitted?),
        Ok(Err(_)) => Err(WorkerError::Broker(
            crate::broker::BrokerError::UpstreamUnavailable {
                detail: "the transport's call ended without saying whether it took the operation"
                    .to_owned(),
            },
        )),
        Err(_) => Err(unanswered()),
    }
}

/// Waits for `waited` until `deadline`, and says the upstream did not answer when it passes.
async fn within<T>(
    deadline: tokio::time::Instant,
    waited: impl core::future::Future<Output = T>,
) -> Result<T> {
    tokio::time::timeout_at(deadline, waited)
        .await
        .map_err(|_| unanswered())
}

/// The failure an operation meets when its upstream does not answer within this worker's bound.
fn unanswered() -> WorkerError {
    WorkerError::Broker(crate::broker::BrokerError::UpstreamUnavailable {
        detail: format!(
            "the upstream did not answer within {} seconds, so whether the operation reached it \
             cannot be established",
            UPSTREAM_SUBMIT_DEADLINE.as_secs()
        ),
    })
}

/// What a mutation left for the caller to do once the session boundary is over.
#[derive(Debug)]
pub enum AfterEffect {
    /// Nothing.
    None,
    /// An admitted operation whose transport work happens outside the session boundary.
    ///
    /// Section 12 has terminal ingestion take the session mutex too, so an upstream that is slow
    /// to answer would stop a person typing if the transmission happened inside it. The admission
    /// is committed first, the mutex is released, the transport work happens, and the outcome is
    /// recorded afterwards.
    Upstream(Box<UpstreamHandoff>),
    /// A termination sequence to start once the acceptance has reached the requester.
    Close(crate::runtime::CloseGate),
    /// A launch the reader is deciding, whose answer the caller is owed.
    ///
    /// The mutation's effect is the reservation and the request in the reader's mailbox; its
    /// *outcome* is what the reader did, and only the reader knows that. So the boundary ends here
    /// and the answer is awaited outside it, which is also what keeps a 250 ms transaction from
    /// holding every other mutation on this worker behind it.
    Launch {
        /// The transaction.
        transaction: kr_shell_integration::contract::requests::LaunchTransactionId,
        /// Where the reader's word arrives.
        receiver: tokio::sync::oneshot::Receiver<crate::fence::driver::LaunchAnswer>,
    },
}
fn not_negotiated() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::UnsupportedSchema,
        "a local connection negotiates its version before anything else",
    )
}

fn unlisted() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        "the method is not reachable from a local caller",
    )
}

fn notification<T: serde::Serialize>(
    stream_id: &StreamId,
    sequence: u64,
    event: &str,
    payload: &T,
) -> Option<ControlFrame> {
    Some(ControlFrame::Notification(
        kr_protocol::envelope::Notification {
            stream_id: stream_id.clone(),
            sequence: kr_protocol::ids::EventSequence::new(sequence),
            event_type: kr_protocol::ids::EventType::new(event).ok()?,
            payload: ParamsValue::from_typed(payload).ok()?,
        },
    ))
}

/// Builds the actor envelope a local caller acts under.
///
/// Ingress is recorded as the local operating-system path, never as a paired device. A local
/// caller cannot relabel itself, because the host constructs this rather than accepting it.
#[must_use]
pub fn local_actor(
    actor_id: kr_protocol::ids::ActorId,
    connection_id: ConnectionId,
    generation: ControllerGeneration,
) -> ActorEnvelope {
    ActorEnvelope {
        actor_id,
        ingress: ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: generation,
        connection_id,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use kr_transport::clock::ManualClock;

    use super::{
        ContinuousClock, ContinuousInstant, MAX_OUTPUT_EVENT_BYTES, Outlet, StreamId, Withdrawal,
        Writing, notification, send_stream, vouched_deadline, write_frame, write_frame_unless,
        write_within,
    };

    /// Two clocks with one pause between the first reading and the second.
    ///
    /// Anchoring a forwarded deadline is two readings and a subtraction, and what decides whether
    /// the conversion can add time is which reading comes first. A pause between them is not
    /// something a test can arrange with the real clocks, so this arranges it: whichever side is
    /// read first, both clocks move on by `pause` before the other side is read.
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
    fn a_pause_between_the_two_readings_never_lengthens_an_arriving_deadline() {
        // The daemon's deadline is a hundred milliseconds away on the machine's own clock, and a
        // second passes between this worker's two clock readings. Nothing is left to admit.
        let pair = PausedPair::new(Duration::from_secs(1));
        let accepted = kr_ipc::clock::SharedClock::boot_elapsed_ms(&pair.shared) + 100;
        assert_eq!(
            vouched_deadline(
                &ProcessSide(Arc::clone(&pair)),
                &SharedSide(Arc::clone(&pair)),
                accepted,
            ),
            None,
            "a deadline whose remaining time was spent between the readings admits nothing"
        );
    }

    #[test]
    fn an_arriving_deadline_loses_the_pause_rather_than_gaining_it() {
        let pair = PausedPair::new(Duration::from_millis(10));
        let start = pair.process.now();
        let accepted = kr_ipc::clock::SharedClock::boot_elapsed_ms(&pair.shared) + 100;
        let anchored = vouched_deadline(
            &ProcessSide(Arc::clone(&pair)),
            &SharedSide(Arc::clone(&pair)),
            accepted,
        )
        .expect("some of the deadline is left");
        // This worker's clock read zero, and the deadline was a hundred milliseconds away. What is
        // anchored is ninety: the ten milliseconds spent between the readings are gone.
        assert_eq!(
            anchored.saturating_duration_since(start),
            Duration::from_millis(90)
        );
    }

    #[test]
    fn an_arriving_deadline_is_bounded_by_the_protocol_maximum() {
        let pair = PausedPair::new(Duration::ZERO);
        let start = pair.process.now();
        let accepted = kr_ipc::clock::SharedClock::boot_elapsed_ms(&pair.shared)
            + kr_protocol::limits::MAX_MUTATION_TTL.get()
            + 60_000;
        let anchored = vouched_deadline(
            &ProcessSide(Arc::clone(&pair)),
            &SharedSide(Arc::clone(&pair)),
            accepted,
        )
        .expect("some of the deadline is left");
        assert_eq!(
            anchored.saturating_duration_since(start),
            Duration::from_millis(kr_protocol::limits::MAX_MUTATION_TTL.get()),
            "a daemon cannot hand a worker a longer life than the protocol allows"
        );
    }

    /// A connected pair of frame halves, on an endpoint of this test's own.
    async fn connected() -> (
        kr_ipc::testing::TempHost,
        Writing,
        Arc<Mutex<kr_ipc::framed::FrameWriter>>,
        kr_ipc::framed::FrameReader,
    ) {
        let temp = kr_ipc::testing::TempHost::create();
        let endpoint = temp
            .environment()
            .worker_endpoint(kr_protocol::session::DisplayNumber::new(9))
            .expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds");
        let accepting = tokio::spawn(async move { listener.accept().await });
        let client = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects");
        let (server, _) = accepting
            .await
            .expect("the accept finishes")
            .expect("accepts");
        let (_, writer) = kr_ipc::framed::split(server, kr_protocol::frame::StreamKind::Control);
        let (reader, _) = kr_ipc::framed::split(client, kr_protocol::frame::StreamKind::Control);
        let writable = Writing {
            turn: Arc::new(tokio::sync::Mutex::new(())),
            readiness: writer.writable(),
        };
        (temp, writable, Arc::new(Mutex::new(writer)), reader)
    }

    /// One output notification of `bytes` bytes, which is what a delivery actually writes.
    fn output_frame(bytes: usize) -> kr_protocol::envelope::ControlFrame {
        let stream = StreamId::new("test".to_owned()).expect("a stream identifier");
        let event = kr_protocol::recovery::OutputEvent {
            cursor: kr_protocol::scalars::U64::new(0),
            bytes: kr_protocol::scalars::Bytes::new(vec![b'a'; bytes]),
        };
        notification(&stream, 0, "session.output", &event).expect("a notification")
    }

    /// The schedule a withdrawal has to win, and how it is arranged.
    ///
    /// This fills a peer's socket to put a writer mid-frame, which is a property of the socket
    /// rather than of the code under test. A Windows named pipe does not fill the way a Unix
    /// domain socket does - the same frame goes straight into it - so the arrangement never
    /// happens there and the test fails at its own setup rather than at what it is for. Whether
    /// what it checks holds on Windows is **not** established by skipping it; establishing that
    /// needs an arrangement this test does not have, and nobody has written one.
    #[cfg_attr(
        windows,
        ignore = "a Windows named pipe does not fill the way this test's own setup needs"
    )]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_protected_write_waiting_for_a_peer_ends_at_the_withdrawal() {
        let (_temp, writable, writer, _reader) = connected().await;
        let withdrawn = Arc::new(Withdrawal::default());
        let frame = output_frame(MAX_OUTPUT_EVENT_BYTES);
        let waiting = tokio::spawn({
            let writable = writable.clone();
            let writer = Arc::clone(&writer);
            let withdrawn = Arc::clone(&withdrawn);
            async move { write_frame(&writable, &writer, &frame, &withdrawn, true).await }
        });

        // The socket fills, and what could not go stays with the writer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if writer
                .lock()
                .expect("the connection writer is not poisoned")
                .is_mid_frame()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the peer's socket filled and the write is waiting for room"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The withdrawal, exactly as the service performs it: the latch set with the writer held.
        let withdrawal = tokio::time::timeout(Duration::from_secs(5), async {
            let _sender = writer
                .lock()
                .expect("the connection writer is not poisoned");
            withdrawn.set();
        })
        .await;
        assert!(
            withdrawal.is_ok(),
            "a peer that has stopped reading does not hold a withdrawal up"
        );
        assert!(
            !tokio::time::timeout(Duration::from_secs(5), waiting)
                .await
                .expect("the write answers the withdrawal")
                .expect("the write task"),
            "and the frame it was waiting to finish is not delivered"
        );
    }

    /// A frame none of whose bytes went is taken back as soon as it is abandoned, rather than
    /// holding the connection's turn until the peer reads again.
    ///
    /// On Linux and macOS a small frame goes to a local socket whole or not at all, so the socket
    /// fills at a frame boundary and the frame that finds it full has none of its bytes with the
    /// peer; the test watches for that state before relying on it. A Windows named pipe does not
    /// fill that way, so the arrangement does not arise there.
    #[cfg_attr(
        windows,
        ignore = "a Windows named pipe does not fill the way this test's own setup needs"
    )]
    #[tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_frame_none_of_which_went_gives_the_turn_back_at_once() {
        let (_temp, writable, writer, _reader) = connected().await;
        let withdrawn = Arc::new(Withdrawal::default());
        let (replacement, mut replaced) = tokio::sync::oneshot::channel::<()>();
        let filling = tokio::spawn({
            let writable = writable.clone();
            let writer = Arc::clone(&writer);
            async move {
                let frame = output_frame(16);
                while write_frame_unless(
                    &writable,
                    &writer,
                    &frame,
                    &withdrawn,
                    true,
                    Some(&mut replaced),
                )
                .await
                {}
            }
        });

        // The socket fills, and the frame that found it full waits whole for the peer.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            {
                let sender = writer
                    .lock()
                    .expect("the connection writer is not poisoned");
                if sender.is_mid_frame() && !sender.has_sent_any() {
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the peer's socket filled and a frame is waiting for room with none of it sent"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The replacement, exactly as a connection signals it: with the writer held.
        {
            let _boundary = writer
                .lock()
                .expect("the connection writer is not poisoned");
            drop(replacement);
        }
        tokio::time::timeout(Duration::from_secs(5), filling)
            .await
            .expect("the abandoned frame stops waiting for a peer that is not reading")
            .expect("the writing task");
        assert!(
            !writer
                .lock()
                .expect("the connection writer is not poisoned")
                .is_mid_frame(),
            "and it was taken back, so the stream is clean for the next frame"
        );
        assert!(
            writable.turn.try_lock().is_ok(),
            "and the connection's turn is free for whoever writes next"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nothing_protected_is_begun_after_a_withdrawal() {
        // With room in the socket and nothing in flight, a protected frame produced under an
        // authority that has ended is not written at all: the check and the write are one step, so
        // there is no moment between them for the withdrawal to land in.
        let (_temp, writable, writer, mut reader) = connected().await;
        let withdrawn = Arc::new(Withdrawal::default());
        {
            let _sender = writer
                .lock()
                .expect("the connection writer is not poisoned");
            withdrawn.set();
        }
        assert!(
            !write_frame(&writable, &writer, &output_frame(16), &withdrawn, true).await,
            "a withdrawn registration writes nothing"
        );
        assert!(
            !writer
                .lock()
                .expect("the connection writer is not poisoned")
                .is_mid_frame(),
            "and nothing of it reached the socket"
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                reader.read_message::<kr_protocol::envelope::ControlFrame>(),
            )
            .await
            .is_err(),
            "so the peer receives nothing"
        );
    }

    /// A statement's write is bounded whole: one that cannot get the connection's turn before its
    /// deadline is never offered, and, where a peer can hold part of a frame, one the peer has part
    /// of when the deadline passes is reported for the caller to end the connection over.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bounded_write_reports_what_it_could_not_finish() {
        let (_temp, writable, writer, mut reader) = connected().await;
        let withdrawn = Withdrawal::default();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        assert!(write_within(&writable, &writer, &output_frame(16), &withdrawn, deadline).await);
        let _ = reader
            .read_message::<kr_protocol::envelope::ControlFrame>()
            .await
            .expect("the frame arrives whole");

        {
            let _turn = writable.turn.lock().await;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
            assert!(
                !write_within(&writable, &writer, &output_frame(16), &withdrawn, deadline).await,
                "the turn never came"
            );
        }
        assert!(
            !writer
                .lock()
                .expect("the connection writer is not poisoned")
                .is_mid_frame(),
            "nothing of it went"
        );

        // Larger than the socket holds, with the peer no longer reading. A Unix socket takes what
        // fits and leaves the rest of the frame waiting; a Windows pipe takes each slice whole into
        // a buffer of its own, so there a peer that stops reading never holds part of a frame.
        #[cfg(unix)]
        {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
            assert!(
                !write_within(
                    &writable,
                    &writer,
                    &output_frame(900 * 1024),
                    &withdrawn,
                    deadline
                )
                .await
            );
            assert!(
                writer
                    .lock()
                    .expect("the connection writer is not poisoned")
                    .is_mid_frame(),
                "the peer has part of it, so the caller ends the connection"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_withdrawn_registration_stops_a_span_that_takes_several_frames() {
        // A span larger than one frame is written as several, and the authority behind it can be
        // withdrawn between any two of them. Stopping the task that writes them is not enough on
        // its own: a task whose frames are all ready writes them without ever yielding to the
        // abort. Each frame therefore passes the withdrawal itself.
        let (_temp, writable, writer, mut reader) = connected().await;
        let (_subscription, replaced) = tokio::sync::oneshot::channel();
        let mut outlet = Outlet {
            writable,
            writer: Arc::clone(&writer),
            withdrawn: Arc::new(Withdrawal::default()),
            replaced,
        };
        let stream_id = StreamId::new("test".to_owned()).expect("a stream identifier");
        let bytes = vec![b'a'; MAX_OUTPUT_EVENT_BYTES * 3];
        let mut sequence = 0_u64;

        outlet.withdrawn.set();
        // Bounded, because the failure this guards against is a writer that goes on writing into a
        // socket nobody is reading: without the boundary the call does not return at all.
        let sent = tokio::time::timeout(
            Duration::from_secs(5),
            send_stream(&mut outlet, &stream_id, &mut sequence, 0, &bytes),
        )
        .await
        .expect("a withdrawn registration stops rather than waiting for a peer");
        assert!(!sent, "a withdrawn registration is delivered nothing");
        assert!(
            !writer
                .lock()
                .expect("the connection writer is not poisoned")
                .is_mid_frame(),
            "and nothing was left half written"
        );
        let nothing = tokio::time::timeout(
            Duration::from_millis(200),
            reader.read_message::<kr_protocol::envelope::ControlFrame>(),
        )
        .await;
        assert!(
            nothing.is_err(),
            "the peer receives no frame of a span whose authority has gone"
        );
    }

    /// The journal keeps what a detach was going to do, never the capability that asked for it.
    ///
    /// A line's capability is the caller proving it may ask, like a question's caller token, and
    /// section 11 keeps such a secret out of every durable record. The intent is what a recovering
    /// worker reads, and it is written to the journal and its write-ahead log; a token left in it
    /// would outlive the line it was minted for by as long as the journal is kept.
    #[test]
    fn a_detachs_recorded_intent_carries_no_line_capability() {
        use kr_protocol::attachment::SessionDetachParams;
        use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
        use kr_protocol::ids::{
            ActionId, ActionWindowId, EnvironmentId, RequestId, SessionEpoch, SessionId,
        };
        use kr_protocol::method::{Method, MethodVersion};
        use kr_protocol::scalars::{DurationMs, Nullable, Uuid};

        let params = SessionDetachParams {
            attachment_id: Nullable::null(),
            line_token: Nullable::some("a-line-capability".to_owned()),
        };
        let mutation = MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionDetach.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(Uuid::from_bytes([0xAC; 16])),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: EnvironmentId::new(Uuid::from_bytes([0xE0; 16])),
                session_id: Nullable::some(SessionId::new(Uuid::from_bytes([0x5E; 16]))),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("host-issued-window-id".to_owned())
                .expect("a window name"),
            requested_ttl_ms: DurationMs::new(5_000),
            params: ParamsValue::from_typed(&params).expect("encodes"),
        };

        let intent = super::WorkerService::intent_of(&mutation, Method::SessionDetach)
            .expect("the intent is encoded");
        let recorded: MutationRequest =
            kr_cbor::from_canonical_slice(&intent, &kr_cbor::Limits::default())
                .expect("the intent reads back");
        let recorded: SessionDetachParams = recorded.params.to_typed().expect("decodes");
        assert!(
            !recorded.line_token.is_present(),
            "the capability is not in the durable record"
        );
        assert!(
            !intent
                .windows(b"a-line-capability".len())
                .any(|window| window == b"a-line-capability"),
            "and its bytes are nowhere in it"
        );
    }
}
