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
    ActionTarget, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EnvironmentListResult, EnvironmentSummary, HostDoctorResult,
    HostInfoResult,
};
use kr_protocol::identity::{BootIdentity, WorkerProfile};
use kr_protocol::ids::{
    ActionWindowId, ActorId, BuildId, ConnectionId, ControllerGeneration, EnvironmentId, RequestId,
    SessionEpoch, SessionId,
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
use crate::supervision::{WorkerLaunch, WorkerSupervisor};

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
        let mut registry = Registry::open(setup.paths.registry_database(), setup.environment_id)?;
        // The lock comes before everything the environment owns: the persistent identity, the
        // generation and the directory. Two daemons starting together would otherwise both find an
        // empty key store, both create an identity, and the loser would overwrite the key every
        // live worker recorded at spawn.
        let lock = SingletonLock::acquire(&setup.paths.singleton_lock(), &mut registry)?;
        let generation = lock.generation();
        let identity = (setup.identity)()?;
        let controller = Arc::new(Self {
            registry: Mutex::new(registry),
            directory: Mutex::new(Directory::default()),
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
            let resolution = match (reservation.phase, reservation.launcher_identity.as_ref()) {
                // Nothing was ever handed to the service manager: the phase moves to `spawned`
                // before the call and this one never got there.
                (LaunchPhase::Reserved, _) => Some(LaunchPhase::Failed),
                // The launcher never reported an identity, so there is nothing to ask about. The
                // execution stays unresolved and keeps its slot rather than being guessed at.
                (_, None) => None,
                (_, Some(identity)) => match kr_ipc::identity::process_state(identity) {
                    // The process the launcher started is gone and it never became live, so no
                    // worker came of it. This is a confirmed failure.
                    kr_ipc::identity::ProcessState::Ended => Some(LaunchPhase::Failed),
                    kr_ipc::identity::ProcessState::Running
                    | kr_ipc::identity::ProcessState::Unknown { .. } => None,
                },
            };
            if let Some(phase) = resolution {
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation.reservation_id, phase)?;
            }
        }
        // A worker row whose process has ended is reconciled whether or not its descriptor
        // answered, so a session that died while no daemon was running is recorded rather than
        // silently omitted from every later list.
        let sessions: Vec<SessionId> = {
            let registry = self.registry.lock().await;
            registry
                .workers()?
                .into_iter()
                .map(|worker| worker.session_id)
                .collect()
        };
        for session_id in sessions {
            let _ = self.reconcile(session_id).await;
        }
        Ok(())
    }

    /// Returns the generation this daemon speaks for.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.generation
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
                connection_id,
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
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation_id, LaunchPhase::Closed)?;
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
        let create: SessionCreateParams =
            kr_cbor::from_canonical_slice(&reservation.create_intent, &kr_cbor::Limits::DEFAULT)
                .map_err(|error| {
                    ControllerError::registry(format!(
                        "the recorded create request cannot be read: {error}"
                    ))
                })?;

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
        connection_id: ConnectionId,
        peer: &PeerIdentity,
    ) -> LocalHelloAck {
        let now = kr_ipc::now_ms();
        LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role,
            connection_id,
            environment_id: self.paths.environment_id(),
            boot_identity: self.boot_identity.clone(),
            peer: LocalPeer {
                uid: U64::new(u64::from(peer.uid)),
                gid: U64::new(u64::from(peer.gid)),
                pid: Nullable(peer.pid.map(|pid| U64::new(u64::from(pid)))),
            },
            action_window_id: ActionWindowId::new(format!("local:{connection_id}"))
                .unwrap_or_else(|_| ActionWindowId::new("local").expect("a valid window")),
            action_window_expires_at_ms: TimestampMs::new(
                now.get().saturating_add(ACTION_WINDOW_MS),
            ),
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
        }
    }

    async fn client(self: &Arc<Self>, connection: Connection, peer: PeerIdentity) -> Result<()> {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let actor_id = ActorId::new(format!("local:{}", peer.uid))
            .unwrap_or_else(|_| ActorId::new("local").expect("a valid principal"));
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        let mut negotiated = false;
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
                        ControlMessage::HelloAck(self.acknowledgement(
                            LocalRole::Controller,
                            connection_id,
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
                ControlMessage::Request(request) if negotiated => self.read_method(&request).await,
                ControlMessage::Mutation(mutation) if negotiated => {
                    self.write_method(&actor_id, &mutation).await
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
    ) -> ControlMessage {
        let Some(method) = mutation.method.method() else {
            return error_reply(
                mutation.request_id,
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            );
        };
        let outcome = match method {
            Method::SessionCreate => self.session_create(actor_id, mutation).await,
            Method::SessionClose => self.session_close(&mutation.params).await,
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
        let healthy = checks.iter().all(|check| !check.status.is_failure());
        encode(&HostDoctorResult { checks, healthy })
    }

    async fn session_list(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionListParams = parse(params)?;
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
            let registry = self.registry.lock().await;
            for reservation in registry.closed_reservations()? {
                if let Some(closure) = registry.closure(reservation.session_id)? {
                    sessions.push(closed_summary(
                        &closure,
                        self.paths.environment_id(),
                        reservation.display_number,
                    ));
                }
            }
        }
        sessions.sort_by_key(|session| session.display_number.get());
        encode(&SessionListResult { sessions })
    }

    async fn session_read(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionReadParams = parse(params)?;
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
                    session: closed_summary(&closure, self.paths.environment_id(), display),
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
            Ok(identity) => identity,
            Err(error) => {
                // The service manager refused. Nothing started, so the reservation is resolved as
                // a confirmed failure and stops occupying the environment; it is never resumed.
                self.pending
                    .lock()
                    .await
                    .remove(&reservation.reservation_id);
                let mut registry = self.registry.lock().await;
                registry.set_phase(reservation.reservation_id, LaunchPhase::Failed)?;
                return Err(error);
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
                session: closed_summary(
                    &closure,
                    self.paths.environment_id(),
                    reservation.display_number,
                ),
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

    async fn session_close(self: &Arc<Self>, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionCloseParams = parse(params)?;
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
        let mut client = self.open_worker(&worker).await?;
        let result = client
            .mutate(
                Method::SessionClose,
                kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                session_target(self.paths.environment_id(), params.session_id),
                &params,
            )
            .await?;
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
        let record = ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason,
            root_exit_code: Nullable::null(),
            root_signal: Nullable::null(),
            terminated: vec![kr_protocol::session::TerminatedProcess {
                identity: identity.clone(),
                name: Nullable::some("kr-worker".to_owned()),
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
        Ok(())
    }

    async fn read_from_worker(&self, worker: &KnownWorker) -> Result<SessionSummary> {
        let mut client = self.open_worker(worker).await?;
        let result = client
            .request(
                Method::SessionRead,
                &SessionReadParams {
                    session_id: worker.descriptor.session_id,
                },
            )
            .await?;
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

fn session_target(environment_id: EnvironmentId, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
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
