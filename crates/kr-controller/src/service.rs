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
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::peer::PeerIdentity;
use kr_ipc::verify::{ControllerIdentity, check_rendezvous};
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EnvironmentListResult, EnvironmentSummary, HostDoctorResult,
    HostInfoResult,
};
use kr_protocol::identity::{BootIdentity, WorkerProfile};
use kr_protocol::ids::{
    ActorId, BootEpoch, BuildId, ConnectionId, ControllerGeneration, EnvironmentId, RequestId,
    SessionEpoch, SessionId,
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
use kr_transport::lease::{LeaseIssuer, LeaseRefusal, RevocationStatus};
use kr_transport::window::{AcceptedDeadline, ActionWindowIssuer, MAX_WINDOW_VALIDITY};
use tokio::sync::{Mutex, oneshot};

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

/// How long the rendezvous waits for the launcher to report the worker's identity.
pub const LAUNCH_IDENTITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a create waits for its worker to report itself.
pub const RENDEZVOUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

/// The control daemon.
pub struct Controller {
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
    /// Every connection this daemon has admitted, and the authority revision it was admitted at.
    ///
    /// This is the daemon's authority store for live connections. A registration is written in the
    /// same critical section as the caller's final record validation, and withdrawn when the
    /// authority it was made under is revoked or the connection ends.
    admitted: Mutex<BTreeMap<ConnectionId, AdmittedConnection>>,
    identity: ControllerIdentity,
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
    /// renew a lease it did not issue.
    leases: LeaseIssuer,
    /// The network this daemon is on, when its environment selects one.
    /// The network host this daemon serves, once it is on a network.
    ///
    /// The host is what a revocation needs: withdrawing a registration stops the next request, and
    /// the connections holding those registrations have to lose their write boundary with it. It is
    /// recorded before the listener serves anything, so no connection can be admitted before the
    /// revocation path can reach it.
    network: std::sync::OnceLock<Arc<net::NetworkGuard>>,
    supervisor: Box<dyn WorkerSupervisor>,
    /// The environment's transfer service, whose methods this daemon admits and dispatches.
    transfer: Arc<crate::transfer::TransferModule>,
    /// The environment's project service, whose methods this daemon admits and dispatches.
    project: Arc<crate::project::ProjectModule>,
    worker_program: PathBuf,
    build_id: BuildId,
    release: String,
    started_at_ms: TimestampMs,
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
        let identity = (setup.identity)()?;
        let boot_epoch = kr_ipc::identity::boot_epoch(&setup.boot_identity)?;
        let clock = Arc::new(SystemContinuousClock::new());
        let authority_revision = registry.authority_revision()?;
        let transfer = Arc::new(crate::transfer::TransferModule::open(&setup.paths).await?);
        let project = Arc::new(crate::project::ProjectModule::open(&setup.paths).await?);
        let controller = Arc::new(Self {
            registry: Mutex::new(registry),
            directory: Mutex::new(Directory::default()),
            connections: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            admitted: Mutex::new(BTreeMap::new()),
            identity,
            generation,
            paths: setup.paths,
            boot_identity: setup.boot_identity,
            boot_epoch,
            windows: ActionWindowIssuer::with_default_validity(Arc::clone(&clock) as Arc<_>),
            shared_clock: Arc::new(kr_ipc::clock::SystemSharedClock),
            leases: LeaseIssuer::with_maximum_validity(generation, authority_revision),
            clock,
            network: std::sync::OnceLock::new(),
            supervisor: setup.supervisor,
            transfer,
            project,
            // The executable the daemon was told to start, resolved here rather than at the
            // launch: a worker runs in a directory of its own, so a relative name would be looked
            // for beneath that instead of beneath the directory this daemon was started in.
            worker_program: kr_ipc::paths::resolve_here(setup.worker_program)?,
            build_id: setup.build_id,
            release: setup.release,
            started_at_ms: kr_ipc::now_ms(),
            _lock: lock,
        });
        // Reconnecting is not only verifying. A replacement daemon has to present the generation it
        // advanced to, because that is what fences the daemon it replaced.
        let directory = {
            let registry = controller.registry.lock().await;
            Directory::rebuild(&controller.paths, &registry, &controller.reconnect()).await?
        };
        *controller.directory.lock().await = directory;
        controller.recover_reservations().await?;
        // Recovery has settled every reservation it can, so what is left under the workers
        // directory that no session claims is nothing's.
        controller.sweep_worker_dirs().await?;
        crate::transfer::serve(&controller)?;
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
            )
            .await?;
        }
        Ok(())
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
            let fenced = {
                let registry = self.registry.lock().await;
                registry
                    .reservation_for_session(row.session_id)?
                    .is_none_or(|reservation| reservation.phase == LaunchPhase::Fenced)
            };
            if fenced {
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
        let links: Vec<Arc<tokio::sync::Mutex<Option<LocalClient>>>> = self
            .connections
            .lock()
            .await
            .values()
            .map(Arc::clone)
            .collect();
        for link in links {
            let mut held = link.lock().await;
            if let Some(client) = held.as_mut()
                && client.confirm_delivery(action_id).await.is_err()
            {
                *held = None;
            }
        }
    }

    /// Announces the environment's current authority revision to every worker it knows about.
    ///
    /// A revocation is not complete when the daemon records it. It is complete for a worker when
    /// that worker has acknowledged the revision that removed the authority, or when the worker is
    /// confirmed ended. Anything else is pending, and this reports which.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or written.
    pub async fn announce_authority_revision(&self) -> Result<RevocationStatus> {
        let revision = {
            let registry = self.registry.lock().await;
            registry.authority_revision()?
        };
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            let session_id = worker.descriptor.session_id;
            // The binding is taken before the announcement travels, so an acknowledgement that
            // arrives over a control path this daemon has already given up on lifts nothing.
            let binding = self.leases.binding(session_id);
            let outcome = {
                match self.worker_client(&worker).await {
                    Ok(mut held) => {
                        let client = held.as_mut().expect("the connection is open");
                        let answered = client
                            .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
                                environment_id: self.paths.environment_id(),
                                revision,
                            })
                            .await;
                        if answered.is_err() {
                            *held = None;
                            self.leases.stop_renewal(session_id, binding);
                        }
                        answered.ok()
                    }
                    Err(_) => {
                        self.leases.stop_renewal(session_id, binding);
                        None
                    }
                }
            };
            match outcome {
                Some(ack) if ack.revision.get() >= revision.get() => {
                    let mut registry = self.registry.lock().await;
                    registry.record_acknowledged_revision(session_id, ack.revision)?;
                    drop(registry);
                    // Under the binding this announcement was made over, not whatever the binding
                    // is now: another exchange can lose the path and advance it while this one
                    // waits for the registry, and an acknowledgement from the path that was lost
                    // must not lift the fence that loss set on the one in force.
                    self.leases.acknowledge(session_id, binding, ack.revision);
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
        Ok(self.leases.status(revision))
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
    pub async fn revoke_authority(&self) -> Result<RevocationStatus> {
        // The store's lock order is the registry first, then the connections. Admission takes the
        // same two in the same order, so a connection cannot be registered against a revision this
        // has already replaced.
        let revision = {
            let mut registry = self.registry.lock().await;
            registry.advance_authority_revision()?;
            let revision = registry.authority_revision()?;
            let mut admitted = self.admitted.lock().await;
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
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<ControlFrame> {
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
        let mut admitted = self.admitted.lock().await;
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

    /// Refuses a request on a connection whose registration has been withdrawn.
    async fn authorised(&self, connection_id: ConnectionId) -> Result<ActorId> {
        let admitted = self.admitted.lock().await;
        match admitted.get(&connection_id) {
            Some(connection) => Ok(connection.actor_id.clone()),
            None => Err(ControllerError::PermissionDenied {
                detail: "the authority this connection was admitted under has been withdrawn; \
                         open a new connection"
                    .to_owned(),
            }),
        }
    }

    /// Withdraws one connection's registration.
    async fn deregister(&self, connection_id: ConnectionId) {
        self.admitted.lock().await.remove(&connection_id);
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
        let create: SessionCreateParams =
            kr_cbor::from_canonical_slice(recorded, &kr_cbor::Limits::DEFAULT).map_err(
                |error| {
                    ControllerError::registry(format!(
                        "the recorded create request cannot be read: {error}"
                    ))
                },
            )?;

        Ok(WorkerLaunchSpec {
            session_id: reservation.session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            create,
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
        let mut registry = self.registry.lock().await;
        let reservation = registry
            .reservation(reservation_id)?
            .ok_or_else(|| ControllerError::rendezvous("the reservation vanished"))?;
        let record = WorkerRecord {
            session_id: reservation.session_id,
            display_number: reservation.display_number,
            public_key: claim.worker_public_key,
            process_identity: claim.process_start_identity.clone(),
            endpoint: ready.endpoint.clone(),
            profile: WorkerProfile::HeadlessUser,
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
            worker_profile: WorkerProfile::HeadlessUser,
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
            _ if crate::transfer::TransferModule::serves(method) => {
                crate::transfer::TransferModule::check_subject(method, mutation)?;
            }
            _ if crate::project::ProjectModule::serves(method) => {
                crate::project::ProjectModule::check_subject(method, mutation)?;
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
            .accept(
                &mutation.action_window_id,
                connection_id,
                self.boot_epoch,
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
        self.deregister(connection_id).await;
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
        let actor_id = ActorId::new(format!("local:{}", peer.uid))
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
                    match self.authorised(connection_id).await {
                        Ok(_) => {
                            let answer = self.read_method(&actor_id, &request).await;
                            // Checked again now the read has finished. A read that passed its check
                            // and then waited for the registry can complete after the authority
                            // behind it was withdrawn, and what the contract forbids is *serving*
                            // that state rather than reading it.
                            match self.authorised(connection_id).await {
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
        if let Err(error) = self.authorised(connection_id).await {
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
        if let Some(retained) = self.retained(actor_id, &mutation, method).await {
            return retained;
        }
        if crate::transfer::TransferModule::serves(method)
            && let Some(retained) = self.transfer.retained(actor_id, &mutation, method).await
        {
            return retained;
        }
        if crate::project::ProjectModule::serves(method)
            && let Some(retained) = self.project.retained(actor_id, &mutation, method).await
        {
            return retained;
        }
        let accepted = match self.check_envelope(connection_id, &mutation, method) {
            Ok(accepted) => accepted,
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
                .write_method(&actor_id, &mutation, method, connection_id, accepted)
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
        let outcome = match method {
            Method::HostInfo => self.host_info().await,
            Method::EnvironmentList => self.environment_list().await,
            Method::HostDoctor => self.host_doctor().await,
            Method::SessionList => self.session_list(&request.params).await,
            Method::SessionRead => self.session_read(&request.params).await,
            Method::AgentToolsStatus => self.agent_tools_status(&request.params),
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
        accepted: AcceptedDeadline,
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
            if self.clock.now() >= accepted.deadline {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it                                  could run"
                            .to_owned(),
                    }),
                );
            }
            if let Err(error) = self.authorised(connection_id).await {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return self.transfer.write_frame(actor_id, mutation, method).await;
        }
        if crate::project::ProjectModule::serves(method) {
            // Everything between the envelope check and this point can wait: for this task to be
            // scheduled and for a blocking thread. An action whose accepted deadline passed while
            // it queued does not go on to write, and neither does one whose connection lost its
            // authority in the meantime.
            if self.clock.now() >= accepted.deadline {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it                                  could run"
                            .to_owned(),
                    }),
                );
            }
            if let Err(error) = self.authorised(connection_id).await {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return self.project.write_frame(actor_id, mutation, method).await;
        }
        let outcome = match method {
            Method::SessionCreate => {
                self.session_create(actor_id, mutation, connection_id, accepted)
                    .await
            }
            Method::SessionClose => {
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                self.session_close(mutation, &actor, accepted).await
            }
            Method::AgentToolsInstall | Method::AgentToolsRemove => {
                self.agent_tools_change(actor_id, mutation, method)
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation this daemon serves",
                method.as_str()
            ))),
        };
        respond(mutation.request_id, outcome)
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
    fn agent_tools_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::skill::AgentToolsParams = parse(&mutation.params)?;
        let installer = self.installer()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        if let Some(retained) = installer.retained(actor_id, mutation.action_id, &digest)? {
            return Ok(retained);
        }
        installer.check(&params)?;
        installer.mark_dispatching(actor_id, mutation.action_id, &digest)?;
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

    async fn host_info(&self) -> Result<ParamsValue> {
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
            default_worker_profile: WorkerProfile::HeadlessUser,
        })
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

    async fn host_doctor(&self) -> Result<ParamsValue> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            id: "runtime-directory".to_owned(),
            title: "The runtime directory is owner-only".to_owned(),
            status: DoctorStatus::Ok,
            detail: self.paths.runtime_dir().display().to_string(),
            remedy: Nullable::null(),
        });
        checks.push(DoctorCheck {
            id: "supervisor".to_owned(),
            title: "Workers outlive this daemon".to_owned(),
            status: DoctorStatus::Ok,
            detail: self.supervisor.describe(),
            remedy: Nullable::null(),
        });
        let directory = self.directory.lock().await;
        let quarantined = directory.quarantined.len();
        let verified = directory.verified.len();
        drop(directory);
        checks.push(DoctorCheck {
            id: "workers".to_owned(),
            title: "Every published descriptor answered its challenge".to_owned(),
            status: if quarantined == 0 {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            detail: format!("{verified} verified, {quarantined} quarantined"),
            remedy: Nullable(
                (quarantined > 0).then(|| {
                    "A quarantined descriptor is never used. Remove it once its session is known to be gone."
                        .to_owned()
                }),
            ),
        });
        let pending = self.revision_pending().await?;
        checks.push(DoctorCheck {
            id: "authority-revision".to_owned(),
            title: "Every worker holds this environment's authority revision".to_owned(),
            status: if pending.is_empty() {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            detail: format!("{} of {} pending", pending.len(), verified),
            remedy: Nullable((!pending.is_empty()).then(|| {
                "A revocation is complete for a worker once it acknowledges the revision or is \
                 confirmed ended."
                    .to_owned()
            })),
        });
        let healthy = checks.iter().all(|check| !check.status.is_failure());
        encode(&HostDoctorResult { checks, healthy })
    }

    async fn session_list(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionListParams = parse(params)?;
        // Any worker that has started answering since the last attempt rejoins the directory here,
        // so a list is the current picture rather than the picture at startup.
        let _ = self.recover_workers().await;
        let mut sessions = Vec::new();
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            match self.read_from_worker(&worker).await {
                Ok(summary) => sessions.push(summary),
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
            let _ = self.recover_workers().await;
        }
        let worker = self.directory.lock().await.get(params.session_id).cloned();
        if let Some(worker) = worker {
            match self.read_from_worker(&worker).await {
                Ok(summary) => {
                    return encode(&SessionReadResult {
                        session: summary,
                        endpoint: Nullable::some(worker.endpoint.as_text()),
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
                })
            }
            None => Err(ControllerError::UnknownSession {
                session: params.session_id.to_string(),
            }),
        }
    }

    /// Reserves a session and starts its worker.
    ///
    /// `connection_id` is the connection that asked, on whichever ingress. A create is the one
    /// mutation this daemon performs itself and the slowest thing it does: it writes the
    /// reservation, waits for a lock, starts a process and waits for that process to report
    /// itself. The connection identity travels with it so the registration behind it can be
    /// checked again at the moment the launch becomes possible, rather than only when the request
    /// arrived.
    async fn session_create(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        connection_id: ConnectionId,
        accepted: AcceptedDeadline,
    ) -> Result<ParamsValue> {
        let create: SessionCreateParams = parse(&mutation.params)?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The create request itself is recorded with the reservation, before anything is spawned.
        // A daemon that dies between the reservation and the launch then finds a request it can
        // resolve rather than an identifier with nothing behind it.
        let intent = kr_cbor::to_canonical_vec(&create)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The action identifier is the create token. One identifier, one session; a retry with the
        // same payload resolves to the same reservation rather than launching a second shell.
        let admission = {
            let mut registry = self.registry.lock().await;
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
            return self.replay_create(&reservation).await;
        }

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
            // The registration first, because reading it waits: the connection table is taken
            // under this guard, and a revocation can be part way through taking it. The deadline
            // is checked afterwards, so the last thing between this create and its launch is a
            // reading of the clock with nothing left to wait for.
            let refusal = match self.authorised(connection_id).await.err() {
                Some(withdrawn) => Some(withdrawn),
                None if self.clock.now() >= accepted.deadline => {
                    Some(ControllerError::WindowExpired {
                        detail: "the deadline this create was admitted under passed before it \
                                 could start"
                            .to_owned(),
                    })
                }
                None => None,
            };
            if let Some(refusal) = refusal {
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
        let summary = self.read_from_worker(&worker).await?;
        encode(&SessionCreateResult {
            session: summary,
            endpoint: Nullable::some(ready.endpoint),
            deduplicated: false,
            presentation_error: Nullable::null(),
        })
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
        let worker = self
            .directory
            .lock()
            .await
            .get(reservation.session_id)
            .cloned();
        if let Some(worker) = worker {
            let summary = self.read_from_worker(&worker).await?;
            return encode(&SessionCreateResult {
                session: summary,
                endpoint: Nullable::some(worker.endpoint.as_text()),
                deduplicated: true,
                presentation_error: Nullable::null(),
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
                deduplicated: true,
                presentation_error: Nullable::null(),
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
        accepted: AcceptedDeadline,
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
            // Remote dispatch additionally needs a live lease, taken at the moment the dispatch
            // runs rather than one that was valid when the request arrived. Its own remaining time
            // then bounds the deadline the worker is given.
            let lease_deadline = self.dispatch_lease(params.session_id, actor).await?;
            // What the worker is told is the accepted deadline itself, on the machine's own
            // continuous clock: the same clock the worker reads, so the deadline does not restart
            // on arrival and nothing has to guess at what the journey cost. A deadline already
            // spent is never forwarded as though it had time left.
            let accepted_deadline_boot_ms = remaining_deadline(
                &*self.shared_clock,
                &*self.clock,
                accepted.deadline,
                lease_deadline,
            )
            .ok_or_else(|| ControllerError::WindowExpired {
                detail: "the deadline this action was admitted under has passed".to_owned(),
            })?;
            let client = held.as_mut().expect("the connection is open");
            match tokio::time::timeout_at(
                budget,
                client.forward(mutation, actor, accepted_deadline_boot_ms),
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
                let reply: SessionCloseResult = value
                    .to_typed()
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                match reply.closure.as_ref() {
                    Some(record) => self.retire(record).await?,
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
                return;
            };
            match kr_ipc::identity::process_state(&identity) {
                kr_ipc::identity::ProcessState::Ended => {
                    let _ = self.record_final(session_id, reason, &identity).await;
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
        let identity = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .find(|record| record.session_id == session_id)
                .map(|record| record.process_identity)
        };
        let Some(identity) = identity else {
            return Ok(None);
        };
        match kr_ipc::identity::process_state(&identity) {
            kr_ipc::identity::ProcessState::Ended => self
                .record_final(session_id, ClosureReason::WorkerCrash, &identity)
                .await
                .map(Some),
            _ => Ok(None),
        }
    }

    async fn record_final(
        &self,
        session_id: SessionId,
        reason: ClosureReason,
        identity: &kr_protocol::identity::ProcessStartIdentity,
    ) -> Result<ClosureRecord> {
        if let Some(existing) = self.registry.lock().await.closure(session_id)? {
            return Ok(existing);
        }
        // The worker's own journal is the authority on how its session ended. It recorded the
        // root's exit status, what it stopped and how much of that it could account for; a record
        // written from outside knows none of those. This is read only after the worker is
        // confirmed gone, so nothing is still writing to it.
        if let Some(recovered) = self.recovered_closure(session_id) {
            self.retire(&recovered).await?;
            return Ok(recovered);
        }
        // Nothing authoritative survived. What is written instead says so: the coverage is
        // incomplete and the root's result is absent rather than invented.
        let record = ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: vec![kr_protocol::session::TerminatedProcess {
                identity: identity.clone(),
                name: Nullable::some("the session's worker".to_owned()),
                forced: false,
            }],
            surviving: Vec::new(),
            // The controller confirmed the worker process ended. It does not claim to have
            // discovered every application that worker may have started.
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        };
        self.retire(&record).await?;
        Ok(record)
    }

    /// Reads the closure a worker wrote for itself, when one survived it.
    fn recovered_closure(&self, session_id: SessionId) -> Option<ClosureRecord> {
        let path = self.paths.journal_database(session_id);
        let journal = kr_worker::journal::Journal::open_read_only(&path).ok()?;
        journal.read_closure(session_id).ok().flatten()
    }

    /// Reads the session a worker described, when its journal survived it.
    fn recovered_summary(&self, session_id: SessionId) -> Option<SessionSummary> {
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
        // geometry and the creation time a person sees after the session has closed.
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

    /// Records a closed session, removes its descriptor and forgets its key.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written.
    pub async fn retire(&self, record: &ClosureRecord) -> Result<()> {
        let mut registry = self.registry.lock().await;
        registry.record_closure(record)?;
        drop(registry);
        kr_ipc::descriptor::retire(&self.paths, record.session_id)?;
        self.directory.lock().await.remove(record.session_id);
        self.connections.lock().await.remove(&record.session_id);
        // The directory the worker ran in goes with the session. It holds nothing the closure
        // record needs, and one per session that nothing removes would outlive every session this
        // host has ever run. A worker still on its way out may be holding it; on the platforms
        // where that refuses the removal, the next start writes the directory again.
        let _ = std::fs::remove_dir_all(self.paths.worker_dir(record.session_id));
        Ok(())
    }

    async fn read_from_worker(&self, worker: &KnownWorker) -> Result<SessionSummary> {
        let mut held = self.worker_client(worker).await?;
        let client = held.as_mut().expect("the connection is open");
        let result = client
            .request(
                Method::SessionRead,
                &SessionReadParams {
                    session_id: worker.descriptor.session_id,
                },
            )
            .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                // A transport failure ends this connection. The next call opens a new one and
                // presents the generation again rather than writing into a socket that is gone.
                *held = None;
                return Err(error.into());
            }
        };
        match result {
            Ok(value) => {
                let read: SessionReadResult = value
                    .to_typed()
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                Ok(read.session)
            }
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

/// Returns the sentence a caller is given when a window cannot first-admit a request.
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
    use kr_protocol::session::{Presentation, SessionCreateParams, ShellMode};
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

        fn describe(&self) -> String {
            "a supervisor that records every launch and starts nothing".to_owned()
        }
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
    async fn daemon() -> (
        kr_ipc::testing::TempHost,
        Arc<Controller>,
        Arc<Mutex<Vec<WorkerLaunch>>>,
    ) {
        let temp = kr_ipc::testing::TempHost::create();
        let program = temp.root().join("kr-worker");
        let (controller, asked) = daemon_running(&temp, program).await;
        (temp, controller, asked)
    }

    /// Starts a daemon told to launch `program`, which may be a relative name.
    async fn daemon_running(
        temp: &kr_ipc::testing::TempHost,
        program: std::path::PathBuf,
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
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RecordingSupervisor {
                asked: Arc::clone(&asked),
            }),
            worker_program: program,
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
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
        let paused = controller.pending.lock().await;
        let create = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor_id = actor_id.clone();
            async move {
                controller
                    .session_create(&actor_id, &mutation, connection_id, accepted)
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
        drop(paused);

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
        let paused = controller.admitted.lock().await;
        let create = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor_id = actor_id.clone();
            async move {
                controller
                    .session_create(&actor_id, &mutation, connection_id, accepted)
                    .await
            }
        });
        // Long enough for the deadline to pass while the create is held here. The registry lock
        // is held by the create while it waits for the connection table, so nothing here asks the
        // registry what the create has reached: the deadline is absolute, and a create that has
        // not started yet still finds it spent by the time it looks.
        tokio::time::sleep(Duration::from_millis(600)).await;
        drop(paused);

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
                connection_id,
                accepted,
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
                connection_id,
                accepted,
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
        let paused = controller.admitted.lock().await;
        let create = tokio::spawn({
            let controller = Arc::clone(&controller);
            let actor_id = actor_id.clone();
            async move {
                controller
                    .session_create(&actor_id, &mutation, connection_id, accepted)
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(600)).await;
        drop(paused);
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
            daemon_running(&temp, std::path::PathBuf::from("kr-worker-relative")).await;
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
                connection_id,
                accepted,
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

        fn describe(&self) -> String {
            "a supervisor that starts nothing".to_owned()
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
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RefusingSupervisor),
            worker_program: temp.root().join("kr-worker"),
            build_id: BuildId::new("kr-test/0").expect("a build identifier"),
            release: "0".to_owned(),
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
        controller
            .leases
            .acknowledge(session_id, binding, controller.leases.authority_revision());
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
            .session_close(&close_request(environment_id, session_id), &actor, accepted)
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
            .session_close(&close_request(environment_id, session_id), &actor, accepted)
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
            async move { controller.session_close(&mutation, &actor, accepted).await }
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
