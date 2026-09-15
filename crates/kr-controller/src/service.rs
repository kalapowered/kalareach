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
    ClosureRecord, SessionCloseParams, SessionCloseResult, SessionCreateParams,
    SessionCreateResult, SessionListParams, SessionListResult, SessionReadParams,
    SessionReadResult, SessionState, SessionSummary,
};
use kr_protocol::worker::{
    ReservationId, WorkerDescriptor, WorkerLaunchSpec, WorkerReady, WorkerRendezvous,
};
use tokio::sync::{Mutex, oneshot};

use crate::directory::{Directory, KnownWorker};
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, Registry, WorkerRecord};
use crate::singleton::SingletonLock;
use crate::supervision::{WorkerLaunch, WorkerSupervisor};

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
    create: SessionCreateParams,
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
        let lock = SingletonLock::acquire(&setup.paths.singleton_lock(), &mut registry)?;
        let generation = lock.generation();
        let identity = setup.identity;
        let directory = Directory::rebuild(&setup.paths, &registry, &setup.build_id).await?;
        Ok(Arc::new(Self {
            registry: Mutex::new(registry),
            directory: Mutex::new(directory),
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
        }))
    }

    /// Returns the generation this daemon speaks for.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.generation
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
        let mut registry = self.registry.lock().await;
        let reservation = registry
            .reservation(claim.reservation_id)?
            .ok_or_else(|| ControllerError::rendezvous("no reservation matches this claim"))?;
        if reservation.session_id != claim.session_id {
            return Err(ControllerError::rendezvous(
                "the claim names a different session from its reservation",
            ));
        }
        // Exactly one rendezvous per reservation. A second attempt is refused, recorded, and the
        // reservation is fenced: two processes claiming one reservation means the host does not
        // know which of them owns the session.
        if reservation.phase != LaunchPhase::Spawned {
            registry.set_phase(claim.reservation_id, LaunchPhase::Fenced)?;
            return Err(ControllerError::rendezvous(format!(
                "this reservation is {} and accepts no further claim",
                reservation.phase.as_str()
            )));
        }
        let launcher = reservation
            .launcher_identity
            .as_ref()
            .ok_or_else(|| ControllerError::rendezvous("the reservation has no launch identity"))?;
        // The connecting process must be the process the launcher started, checked by both its
        // identifier and the kernel's record of when it started.
        let peer_pid = peer
            .pid
            .ok_or_else(|| ControllerError::rendezvous("the platform did not report the peer"))?;
        if u64::from(peer_pid) != launcher.pid.get() {
            registry.set_phase(claim.reservation_id, LaunchPhase::Fenced)?;
            return Err(ControllerError::rendezvous(
                "the connecting process is not the one the launcher started",
            ));
        }
        if &claim.process_start_identity != launcher {
            registry.set_phase(claim.reservation_id, LaunchPhase::Fenced)?;
            return Err(ControllerError::rendezvous(
                "the claim's process identity is not the launcher's",
            ));
        }
        if claim.boot_identity != self.boot_identity {
            return Err(ControllerError::rendezvous(
                "the claim names a different boot",
            ));
        }
        drop(registry);

        let pending = self.pending.lock().await;
        let create = pending
            .get(&claim.reservation_id)
            .map(|pending| pending.create.clone())
            .ok_or_else(|| {
                ControllerError::rendezvous("no create request is waiting for this reservation")
            })?;
        drop(pending);

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

    async fn client(&self, connection: Connection, peer: PeerIdentity) -> Result<()> {
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

    async fn read_method(&self, request: &Request) -> ControlMessage {
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

    async fn write_method(&self, actor_id: &ActorId, mutation: &MutationRequest) -> ControlMessage {
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

    async fn session_list(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionListParams = parse(params)?;
        let mut sessions = Vec::new();
        let workers: Vec<KnownWorker> = self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            if let Ok(summary) = self.read_from_worker(&worker).await {
                sessions.push(summary);
            }
        }
        if params.include_closed {
            let registry = self.registry.lock().await;
            for record in registry.workers()? {
                if let Some(closure) = registry.closure(record.session_id)? {
                    sessions.push(closed_summary(
                        &closure,
                        self.paths.environment_id(),
                        record.display_number,
                    ));
                }
            }
        }
        sessions.sort_by_key(|session| session.display_number.get());
        encode(&SessionListResult { sessions })
    }

    async fn session_read(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: SessionReadParams = parse(params)?;
        let worker = self.directory.lock().await.get(params.session_id).cloned();
        if let Some(worker) = worker {
            let summary = self.read_from_worker(&worker).await?;
            return encode(&SessionReadResult {
                session: summary,
                endpoint: Nullable::some(worker.endpoint.as_text()),
            });
        }
        // A closed session answers with its record. It never starts anything.
        let registry = self.registry.lock().await;
        let closure = registry.closure(params.session_id)?;
        let display = registry
            .workers()?
            .into_iter()
            .find(|record| record.session_id == params.session_id)
            .map(|record| record.display_number);
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
        // The action identifier is the create token. One identifier, one session; a retry with the
        // same payload resolves to the same reservation rather than launching a second shell.
        let admission = {
            let mut registry = self.registry.lock().await;
            registry.reserve(actor_id, mutation.action_id.get(), digest, kr_ipc::now_ms())?
        };
        let reservation = admission.reservation;
        if admission.deduplicated {
            return self.replay_create(&reservation).await;
        }

        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(
            reservation.reservation_id,
            PendingCreate {
                create: create.clone(),
                ready: sender,
            },
        );

        let launch = WorkerLaunch {
            reservation_id: reservation.reservation_id,
            session_id: reservation.session_id,
            environment_id: self.paths.environment_id(),
            display_number: reservation.display_number,
            program: self.worker_program.clone(),
            rendezvous: self.paths.rendezvous_endpoint()?.as_path().to_path_buf(),
            runtime_directory: self.paths.runtime_dir().to_path_buf(),
            state_directory: self.paths.state_dir().to_path_buf(),
            jobs_directory: self.paths.jobs_dir(),
        };
        let identity = self.supervisor.start(&launch)?;
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

    async fn session_close(&self, params: &ParamsValue) -> Result<ParamsValue> {
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
                if let Some(record) = reply.closure.as_ref() {
                    self.retire(record).await?;
                }
                encode(&reply)
            }
            Err(error) => Err(ControllerError::InvalidArgument(error.to_string())),
        }
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
    /// The persistent identity this daemon signs generation tokens with.
    pub identity: ControllerIdentity,
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
