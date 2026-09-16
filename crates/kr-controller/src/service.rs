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
    network: std::sync::OnceLock<Arc<net::NetworkHost>>,
    supervisor: Box<dyn WorkerSupervisor>,
    /// The environment's transfer service, whose methods this daemon admits and dispatches.
    transfer: Arc<crate::transfer::TransferModule>,
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
            worker_program: setup.worker_program,
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
                registry.resolve_claim(reservation_id, LaunchPhase::Failed)?;
                drop(registry);
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
            _ if crate::transfer::TransferModule::serves(method) => {
                crate::transfer::TransferModule::check_subject(method, mutation)?;
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
        let outcome = match method {
            Method::HostInfo => self.host_info().await,
            Method::EnvironmentList => self.environment_list().await,
            Method::HostDoctor => self.host_doctor().await,
            Method::SessionList => self.session_list(&request.params).await,
            Method::SessionRead => self.session_read(&request.params).await,
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
        let outcome = match method {
            Method::SessionCreate => self.session_create(actor_id, mutation, accepted).await,
            Method::SessionClose => {
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                self.session_close(mutation, &actor, accepted).await
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation this daemon serves",
                method.as_str()
            ))),
        };
        respond(mutation.request_id, outcome)
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

    async fn session_create(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
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

        // The reservation moves to `spawned` before anything is started. A worker can reach the
        // rendezvous socket the instant the service manager starts it, which is sooner than the
        // launcher returns, and a reservation still recorded as merely reserved would fence its own
        // worker. The deadline the host accepted is checked in the same critical section, and after
        // the durable write rather than before it: everything from there to the launch runs without
        // waiting for anything, so an action whose life ran out queueing for this lock does not go
        // on to start a shell.
        {
            let mut registry = self.registry.lock().await;
            registry.set_phase(reservation.reservation_id, LaunchPhase::Spawned)?;
            if self.clock.now() >= accepted.deadline {
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                drop(registry);
                self.pending
                    .lock()
                    .await
                    .remove(&reservation.reservation_id);
                return Err(ControllerError::WindowExpired {
                    detail:
                        "the deadline this create was admitted under passed before it could start"
                            .to_owned(),
                });
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
        let result = {
            // The connection comes first. Waiting for it can take as long as whatever else is using
            // it, and a deadline computed before that wait would hand the worker time that had
            // already been spent queueing.
            let mut held = self.worker_client(&worker).await?;
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
            match client
                .forward(mutation, actor, accepted_deadline_boot_ms)
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    *held = None;
                    return Err(error.into());
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
