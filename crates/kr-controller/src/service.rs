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
use kr_ipc::freshness::FreshnessWindow;
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_ipc::peer::PeerIdentity;
use kr_ipc::verify::{ControllerIdentity, check_rendezvous};
use kr_protocol::envelope::{MutationRequest, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EnvironmentListResult, EnvironmentSummary, HostDoctorResult,
    HostInfoResult,
};
use kr_protocol::identity::{BootIdentity, WorkerProfile};
use kr_protocol::ids::{
    ActorId, BuildId, ConnectionId, ControllerGeneration, EnvironmentId, RequestId, SessionEpoch,
    SessionId,
};
use kr_protocol::local::{ControlMessage, LocalClientKind, LocalHelloAck, LocalPeer, LocalRole};
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
use tokio::sync::{Mutex, oneshot};

use crate::directory::{Directory, KnownWorker, Reconnect};
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, Registry, WorkerRecord};
use crate::singleton::SingletonLock;
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

/// How long a closing worker is watched before the controller stops waiting for it to end.
pub const CLOSURE_WATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long the rendezvous waits for the launcher to report the worker's identity.
pub const LAUNCH_IDENTITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a create waits for its worker to report itself.
pub const RENDEZVOUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a local connection's freshness window lasts.
pub const ACTION_WINDOW_MS: u64 = 5 * 60 * 1000;

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
    identity: ControllerIdentity,
    generation: ControllerGeneration,
    paths: EnvironmentPaths,
    boot_identity: BootIdentity,
    supervisor: Box<dyn WorkerSupervisor>,
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
        let controller = Arc::new(Self {
            registry: Mutex::new(registry),
            directory: Mutex::new(Directory::default()),
            connections: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            identity,
            generation,
            paths: setup.paths,
            boot_identity: setup.boot_identity,
            supervisor: setup.supervisor,
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
                LaunchPhase::Spawned => {
                    if reservation
                        .launcher_identity
                        .as_ref()
                        .is_some_and(|identity| {
                            matches!(
                                kr_ipc::identity::process_state(identity),
                                kr_ipc::identity::ProcessState::Ended
                            )
                        })
                    {
                        let mut registry = self.registry.lock().await;
                        registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                    }
                }
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
    pub async fn announce_authority_revision(&self) -> Result<RevisionProgress> {
        let revision = {
            let registry = self.registry.lock().await;
            registry.authority_revision()?
        };
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        let mut progress = RevisionProgress {
            revision,
            acknowledged: Vec::new(),
            pending: Vec::new(),
        };
        for worker in workers {
            let session_id = worker.descriptor.session_id;
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
                        }
                        answered.ok()
                    }
                    Err(_) => None,
                }
            };
            match outcome {
                Some(ack) if ack.revision.get() >= revision.get() => {
                    let mut registry = self.registry.lock().await;
                    registry.record_acknowledged_revision(session_id, ack.revision)?;
                    drop(registry);
                    progress.acknowledged.push(session_id);
                }
                // A worker that is confirmed gone answers the question a different way: it can no
                // longer act under anything.
                _ => {
                    if self.reconcile(session_id).await?.is_some() {
                        progress.acknowledged.push(session_id);
                    } else {
                        progress.pending.push(session_id);
                    }
                }
            }
        }
        Ok(progress)
    }

    /// Advances the environment's authority revision and announces it.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be written.
    pub async fn revoke_authority(&self) -> Result<RevisionProgress> {
        {
            let mut registry = self.registry.lock().await;
            registry.advance_authority_revision()?;
        }
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
                let _ = controller.client(connection, peer).await;
            });
        }
    }

    async fn rendezvous(&self, connection: Connection, peer: PeerIdentity) -> Result<()> {
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let hello: ControlMessage = reader.read_message().await?;
        let ControlMessage::Hello(hello) = hello else {
            return Err(ControllerError::rendezvous("the worker did not say hello"));
        };
        if hello.client != LocalClientKind::Worker {
            return Err(ControllerError::rendezvous(
                "only a worker's startup claim is accepted here",
            ));
        }
        writer
            .write_message(&ControlMessage::HelloAck(self.acknowledgement(
                LocalRole::Rendezvous,
                &self.window(connection_id),
                &peer,
            )))
            .await?;

        let claim: ControlMessage = reader.read_message().await?;
        let ControlMessage::Rendezvous(claim) = claim else {
            return Err(ControllerError::rendezvous(
                "the worker did not present a startup claim",
            ));
        };
        let specification = self.admit_rendezvous(&claim, &peer).await?;
        writer
            .write_message(&ControlMessage::LaunchSpec(Box::new(specification)))
            .await?;

        let report: ControlMessage = reader.read_message().await?;
        let reservation_id = claim.reservation_id;
        match report {
            ControlMessage::WorkerReady(ready) => {
                self.record_ready(reservation_id, &claim, &ready).await?;
                self.resolve(reservation_id, Ok(ready)).await;
                Ok(())
            }
            ControlMessage::WorkerFailed(error) => {
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
        window: &FreshnessWindow,
        peer: &PeerIdentity,
    ) -> LocalHelloAck {
        LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role,
            connection_id: window.connection_id(),
            environment_id: self.paths.environment_id(),
            boot_identity: self.boot_identity.clone(),
            peer: LocalPeer {
                uid: U64::new(u64::from(peer.uid)),
                gid: U64::new(u64::from(peer.gid)),
                pid: Nullable(peer.pid.map(|pid| U64::new(u64::from(pid)))),
            },
            action_window_id: window.id().clone(),
            action_window_expires_at_ms: window.expires_at_ms(),
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
        }
    }

    /// Stamps a freshness window for one authenticated connection.
    fn window(&self, connection_id: ConnectionId) -> FreshnessWindow {
        FreshnessWindow::issue(
            connection_id,
            self.boot_identity.clone(),
            kr_ipc::now_ms().get(),
            ACTION_WINDOW_MS,
        )
    }

    /// Checks the envelope of a mutation this daemon is asked to perform.
    ///
    /// The target says which environment the effect belongs to, and the window says whether this
    /// is a first admission the host will accept at all. Both are checked before the create token
    /// reaches the registry, so an expired window never reserves a session.
    fn check_envelope(
        &self,
        window: &FreshnessWindow,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<TimestampMs> {
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
        let remaining = window
            .admit(
                &mutation.action_window_id,
                &self.boot_identity,
                kr_ipc::now_ms().get(),
            )
            .map_err(|refusal| ControllerError::WindowExpired {
                detail: refusal.detail().to_owned(),
            })?;
        // The accepted deadline is the earliest of what the window has left, the requested
        // lifetime and the protocol maximum. The caller never supplies an authoritative deadline,
        // and nothing downstream lengthens this one.
        let accepted = mutation
            .requested_ttl_ms
            .get()
            .min(kr_protocol::limits::MAX_MUTATION_TTL.get())
            .min(remaining);
        Ok(TimestampMs::new(
            kr_ipc::now_ms().get().saturating_add(accepted),
        ))
    }

    async fn client(self: &Arc<Self>, connection: Connection, peer: PeerIdentity) -> Result<()> {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let actor_id = ActorId::new(format!("local:{}", peer.uid))
            .unwrap_or_else(|_| ActorId::new("local").expect("a valid principal"));
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        let mut negotiated = false;
        let mut window = self.window(connection_id);
        loop {
            let message: ControlMessage = match reader.read_message().await {
                Ok(message) => message,
                Err(_) => break,
            };
            let reply = match message {
                ControlMessage::Hello(hello) => {
                    if hello
                        .offered_versions
                        .iter()
                        .any(|offered| offered.major == PROTOCOL_VERSION.major)
                    {
                        negotiated = true;
                        // The window is stamped when the connection is authenticated, so its
                        // deadline starts from the handshake the client will quote it against.
                        window = self.window(connection_id);
                        ControlMessage::HelloAck(self.acknowledgement(
                            LocalRole::Controller,
                            &window,
                            &peer,
                        ))
                    } else {
                        error_reply(
                            RequestId::new(0),
                            ErrorCode::UnsupportedSchema,
                            format!("this host speaks protocol {PROTOCOL_VERSION}"),
                        )
                    }
                }
                ControlMessage::ActionWindowRenew(_) if negotiated => {
                    window = window.renew(kr_ipc::now_ms().get());
                    ControlMessage::ActionWindow(kr_protocol::local::ActionWindowGrant {
                        connection_id,
                        action_window_id: window.id().clone(),
                        action_window_expires_at_ms: window.expires_at_ms(),
                    })
                }
                ControlMessage::Request(request) if negotiated => self.read_method(&request).await,
                ControlMessage::Mutation(mutation) if negotiated => {
                    let confirm = mutation.action_id;
                    let reply = match mutation.method.method() {
                        Some(method) => match self.check_envelope(&window, &mutation, method) {
                            Ok(deadline) => {
                                self.write_method(
                                    &actor_id,
                                    &mutation,
                                    method,
                                    connection_id,
                                    deadline,
                                )
                                .await
                            }
                            Err(error) => ControlMessage::Response(Response {
                                request_id: mutation.request_id,
                                outcome: Outcome::Error(error.to_protocol_error()),
                            }),
                        },
                        None => error_reply(
                            mutation.request_id,
                            ErrorCode::PermissionDenied,
                            "the method is not in the registry",
                        ),
                    };
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

    async fn read_method(self: &Arc<Self>, request: &Request) -> ControlMessage {
        let Some(method) = request.method.method() else {
            return error_reply(
                request.request_id,
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            );
        };
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
        accepted_deadline_ms: TimestampMs,
    ) -> ControlMessage {
        let outcome = match method {
            Method::SessionCreate => self.session_create(actor_id, mutation).await,
            Method::SessionClose => {
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                self.session_close(mutation, &actor, accepted_deadline_ms)
                    .await
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
        // launcher returns, and a reservation still recorded as merely reserved would fence its
        // own worker.
        {
            let mut registry = self.registry.lock().await;
            registry.set_phase(reservation.reservation_id, LaunchPhase::Spawned)?;
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
        accepted_deadline_ms: TimestampMs,
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
            let mut held = self.worker_client(&worker).await?;
            let client = held.as_mut().expect("the connection is open");
            match client.forward(mutation, actor, accepted_deadline_ms).await {
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

/// How far an authority revision has reached the workers it applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionProgress {
    /// The revision being announced.
    pub revision: kr_protocol::ids::AuthorityRevision,
    /// The sessions that have installed it, or that are confirmed ended.
    pub acknowledged: Vec<SessionId>,
    /// The sessions it has not reached, where the revocation is still pending.
    pub pending: Vec<SessionId>,
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

fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn respond(request_id: RequestId, outcome: Result<ParamsValue>) -> ControlMessage {
    match outcome {
        Ok(value) => ControlMessage::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Err(error) => ControlMessage::Response(Response {
            request_id,
            outcome: Outcome::Error(error.to_protocol_error()),
        }),
    }
}

fn error_reply(
    request_id: RequestId,
    code: ErrorCode,
    message: impl Into<String>,
) -> ControlMessage {
    ControlMessage::Response(Response {
        request_id,
        outcome: Outcome::Error(ProtocolError::new(code, message)),
    })
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| format!("uid {}", kr_ipc::paths::current_uid()))
}
