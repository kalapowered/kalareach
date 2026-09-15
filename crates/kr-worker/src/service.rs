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
    AttachmentConfigureParams, AttachmentViewportParams, AttachmentViewportResult, GeometryResult,
    SessionAttachParams, SessionDetachParams, TerminalGeometryTransferParams, TerminalResizeParams,
};
use kr_protocol::envelope::{MutationRequest, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{
    ActionWindowId, AttachmentId, ConnectionId, ControllerGeneration, EnvironmentId, RequestId,
    StreamId,
};
use kr_protocol::input::{
    InputAcquireParams, InputInterruptParams, InputLeaseResult, InputReleaseParams,
    InputWriteParams, InputWriteResult, InterruptAction,
};
use kr_protocol::local::{ControlMessage, LocalHello, LocalHelloAck, LocalRole};
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

use crate::error::{Result, WorkerError};
use crate::output::OutputDelivery;
use crate::runtime::SessionRuntime;

/// How long a local connection's freshness window lasts.
pub const ACTION_WINDOW_MS: u64 = 5 * 60 * 1000;

/// The event stream name output notifications carry.
pub const OUTPUT_STREAM: &str = "session.output";

/// The worker's endpoint server.
pub struct WorkerService {
    runtime: Arc<SessionRuntime>,
    identity: Arc<WorkerIdentity>,
    endpoint: Endpoint,
    environment_id: EnvironmentId,
    boot_identity: BootIdentity,
    controller_public_key: AuthorisationKey,
    accepted_generation: Mutex<Option<ControllerGeneration>>,
    generation_connection: Mutex<Option<ConnectionId>>,
    build_id: kr_protocol::ids::BuildId,
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

    /// Returns the session this service serves.
    #[must_use]
    pub fn runtime(&self) -> &Arc<SessionRuntime> {
        &self.runtime
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
    #[must_use]
    pub fn new(
        runtime: Arc<SessionRuntime>,
        identity: Arc<WorkerIdentity>,
        endpoint: Endpoint,
        binding: ServiceBinding,
    ) -> Self {
        Self {
            runtime,
            identity,
            endpoint,
            environment_id: binding.environment_id,
            boot_identity: binding.boot_identity,
            controller_public_key: binding.controller_public_key,
            accepted_generation: Mutex::new(Some(binding.controller_generation)),
            generation_connection: Mutex::new(None),
            build_id: binding.build_id,
        }
    }

    /// Serves the endpoint until the session has closed.
    ///
    /// # Errors
    ///
    /// Returns an error when accepting fails for a reason other than a peer going away.
    pub async fn serve(self: Arc<Self>, listener: Listener) -> Result<()> {
        loop {
            let (connection, peer) = listener.accept().await?;
            let service = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = service.run_connection(connection, peer).await;
            });
        }
    }

    async fn run_connection(
        self: Arc<Self>,
        connection: Connection,
        peer: PeerIdentity,
    ) -> Result<()> {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let (mut reader, writer) = split(connection, StreamKind::Control);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let mut state = ConnectionState::new(connection_id);
        loop {
            let message: ControlMessage = match reader.read_message().await {
                Ok(message) => message,
                Err(_) => break,
            };
            let reply = self.handle(&mut state, &peer, message).await;
            if let Some(reply) = reply {
                let mut writer = writer.lock().await;
                if writer.write_message(&reply).await.is_err() {
                    break;
                }
            }
            if state.subscribed.is_none() {
                continue;
            }
            if let Some((attachment_id, mut stream)) = state.subscribed.take() {
                let sender = Arc::clone(&writer);
                let stream_id = state.stream_id.clone();
                tokio::spawn(async move {
                    let mut sequence = 0_u64;
                    while let Some(delivery) = stream.recv().await {
                        let notification = match delivery {
                            OutputDelivery::Bytes { cursor, bytes } => notification(
                                &stream_id,
                                sequence,
                                "session.output",
                                &OutputEvent {
                                    cursor: U64::new(cursor),
                                    bytes: kr_protocol::scalars::Bytes::new(bytes.to_vec()),
                                },
                            ),
                            OutputDelivery::Resync(marker) => {
                                notification(&stream_id, sequence, "session.resync", &marker)
                            }
                        };
                        let Some(notification) = notification else {
                            continue;
                        };
                        sequence += 1;
                        let mut sender = sender.lock().await;
                        if sender.write_message(&notification).await.is_err() {
                            break;
                        }
                    }
                    let _ = attachment_id;
                });
            }
        }
        // A connection that goes away takes its attachments with it. Undelivered input from them
        // is discarded rather than replayed.
        for attachment_id in state.attachments.drain(..) {
            let mut session = self.runtime.session();
            let _ = session.detach(attachment_id);
        }
        Ok(())
    }

    async fn handle(
        &self,
        state: &mut ConnectionState,
        peer: &PeerIdentity,
        message: ControlMessage,
    ) -> Option<ControlMessage> {
        match message {
            ControlMessage::Hello(hello) => Some(self.hello(state, peer, &hello)),
            ControlMessage::VerifyChallenge(challenge) => {
                match self.identity.answer(&challenge, &self.endpoint.as_text()) {
                    Ok(proof) => Some(ControlMessage::VerifyProof(proof)),
                    Err(error) => Some(failure(
                        state.next_request_id(),
                        &WorkerError::from(error).to_protocol_error(),
                    )),
                }
            }
            ControlMessage::GenerationToken(token) => Some(self.accept_generation(state, &token)),
            ControlMessage::Request(request) => Some(self.request(state, &request)),
            ControlMessage::Mutation(mutation) => Some(self.mutation(state, &mutation)),
            _ => Some(failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "a worker endpoint does not accept this message",
                ),
            )),
        }
    }

    fn hello(
        &self,
        state: &mut ConnectionState,
        peer: &PeerIdentity,
        hello: &LocalHello,
    ) -> ControlMessage {
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
        state.negotiated = true;
        let now = kr_ipc::now_ms();
        ControlMessage::HelloAck(LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Worker,
            connection_id: state.connection_id,
            environment_id: self.environment_id,
            boot_identity: self.boot_identity.clone(),
            peer: peer.to_wire(),
            action_window_id: state.action_window.clone(),
            action_window_expires_at_ms: kr_protocol::scalars::TimestampMs::new(
                now.get().saturating_add(ACTION_WINDOW_MS),
            ),
            capabilities: CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
        })
    }

    /// Issues a challenge a controller must answer before it speaks for a generation.
    #[must_use]
    pub fn generation_challenge(state: &mut ConnectionState) -> Option<ControlMessage> {
        let nonce = kr_ipc::verify::fresh_challenge().ok()?.nonce;
        state.generation_nonce = Some(nonce);
        Some(ControlMessage::GenerationChallenge(GenerationChallenge {
            nonce,
        }))
    }

    fn accept_generation(
        &self,
        state: &mut ConnectionState,
        token: &kr_protocol::worker::ControllerGenerationToken,
    ) -> ControlMessage {
        let Some(nonce) = state.generation_nonce.take() else {
            return failure(
                RequestId::new(0),
                &ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "a generation token answers a challenge this worker issued",
                ),
            );
        };
        let accepted = *self
            .accepted_generation
            .lock()
            .expect("the generation lock is not poisoned");
        let acceptance = GenerationAcceptance {
            controller_public_key: self.controller_public_key,
            environment_id: self.environment_id,
            boot_identity: self.boot_identity.clone(),
            accepted_generation: accepted,
        };
        match check_generation_token(&acceptance, &nonce, token) {
            Ok(()) => {
                let mut current = self
                    .accepted_generation
                    .lock()
                    .expect("the generation lock is not poisoned");
                *current = Some(token.generation);
                let mut bound = self
                    .generation_connection
                    .lock()
                    .expect("the generation lock is not poisoned");
                // Installing this connection fences whatever was bound before it, including an
                // earlier connection of the same generation.
                let fenced_previous = bound.replace(state.connection_id).is_some();
                state.controller = true;
                ControlMessage::GenerationAccepted(kr_protocol::worker::GenerationAccepted {
                    generation: token.generation,
                    fenced_previous,
                })
            }
            Err(error) => failure(
                RequestId::new(0),
                &ProtocolError::new(ErrorCode::PermissionDenied, error.to_string()),
            ),
        }
    }

    fn request(&self, state: &mut ConnectionState, request: &Request) -> ControlMessage {
        if !state.negotiated {
            return failure(request.request_id, &not_negotiated());
        }
        let Some(method) = request.method.method() else {
            return failure(request.request_id, &unlisted());
        };
        if !self.reachable(method, request.method_version) {
            return failure(request.request_id, &unlisted());
        }
        let outcome = match method {
            Method::SessionRead => self.session_read(&request.params),
            Method::EventsSnapshot => self.events_snapshot(&request.params),
            Method::HistoryPage => self.history_page(&request.params),
            Method::EventsSubscribe => self.events_subscribe(state, &request.params),
            Method::AttachmentViewport => self.attachment_viewport(&request.params),
            Method::InputWrite => self.input_write(state, &request.params),
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a read this worker serves",
                method.as_str()
            ))),
        };
        respond(request.request_id, outcome)
    }

    fn mutation(&self, state: &mut ConnectionState, mutation: &MutationRequest) -> ControlMessage {
        if !state.negotiated {
            return failure(mutation.request_id, &not_negotiated());
        }
        let Some(method) = mutation.method.method() else {
            return failure(mutation.request_id, &unlisted());
        };
        if !self.reachable(method, mutation.method_version) {
            return failure(mutation.request_id, &unlisted());
        }
        let outcome = match method {
            Method::SessionAttach => self.session_attach(state, &mutation.params),
            Method::SessionDetach => self.session_detach(state, &mutation.params),
            Method::SessionClose => self.session_close(),
            Method::AttachmentConfigure => self.attachment_configure(&mutation.params),
            Method::TerminalResize => self.terminal_resize(&mutation.params),
            Method::TerminalGeometryTransfer => self.geometry_transfer(&mutation.params),
            Method::InputAcquire => self.input_acquire(state, &mutation.params),
            Method::InputRelease => self.input_release(&mutation.params),
            Method::InputInterrupt => self.input_interrupt(&mutation.params),
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a mutation this worker serves",
                method.as_str()
            ))),
        };
        respond(mutation.request_id, outcome)
    }

    fn reachable(&self, method: Method, version: MethodVersion) -> bool {
        matches!(
            kr_protocol::method::decide(method.as_str(), version, ActorIngress::LocalIpc),
            kr_protocol::authority::AuthorityDecision::Listed(_)
        )
    }

    fn session_read(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let _params: SessionReadParams = parse(params)?;
        let session = self.runtime.session();
        let running = session.state().is_running();
        encode(&SessionReadResult {
            session: session.summary(),
            endpoint: Nullable(running.then(|| self.endpoint.as_text())),
        })
    }

    fn events_snapshot(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let _params: EventsSnapshotParams = parse(params)?;
        encode(&self.runtime.session().snapshot())
    }

    fn history_page(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: HistoryPageParams = parse(params)?;
        let page = self
            .runtime
            .session()
            .history_page(params.from_cursor.get(), params.max_bytes.get())?;
        encode(&page)
    }

    fn events_subscribe(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: EventsSubscribeParams = parse(params)?;
        let mut session = self.runtime.session();
        let stream = session.subscribe(params.attachment_id)?;
        let from = params
            .from_cursor
            .as_ref()
            .map_or_else(|| session.output_cursor(), |cursor| cursor.get());
        let oldest = session.snapshot().oldest_retained_cursor.get();
        let gap = (from < oldest).then_some(kr_protocol::recovery::HistoryGap {
            from_cursor: U64::new(from),
            to_cursor: U64::new(oldest),
        });
        drop(session);
        state.subscribed = Some((params.attachment_id, stream));
        encode(&EventsSubscribeResult {
            stream_id: state.stream_id.clone(),
            from_cursor: U64::new(from.max(oldest)),
            oldest_retained_cursor: U64::new(oldest),
            gap: Nullable(gap),
        })
    }

    fn attachment_viewport(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: AttachmentViewportParams = parse(params)?;
        let mut session = self.runtime.session();
        let presentation = session.viewport(params.attachment_id, params.dimensions)?;
        encode(&AttachmentViewportResult {
            geometry: session.geometry(),
            presentation,
        })
    }

    fn input_write(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: InputWriteParams = parse(params)?;
        let accepted = {
            let mut session = self.runtime.session();
            session.write_input(
                params.attachment_id,
                params.epoch.get(),
                params.sequence.get(),
                params.bytes.as_slice(),
                std::time::Instant::now(),
            )?
        };
        self.runtime.flush_input();
        state.input_sequence = params.sequence.get();
        encode(&InputWriteResult {
            sequence: params.sequence,
            forwarded_bytes: U64::new(accepted.forwarded_bytes),
            held_prefix_bytes: U64::new(accepted.held_prefix_bytes),
        })
    }

    fn session_attach(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: SessionAttachParams = parse(params)?;
        let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
        // A local owner attachment receives what it asked for: peer credentials already proved the
        // caller is this user, and the worker's own authority covers its session.
        let granted = params.requested.clone();
        let result = {
            let mut session = self.runtime.session();
            session.attach(&params, granted, attachment_id)?
        };
        state.attachments.push(attachment_id);
        encode(&result)
    }

    fn session_detach(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: SessionDetachParams = parse(params)?;
        let result = {
            let mut session = self.runtime.session();
            session.detach(params.attachment_id)?
        };
        state
            .attachments
            .retain(|attachment| *attachment != params.attachment_id);
        encode(&result)
    }

    fn session_close(&self) -> Result<ParamsValue> {
        let acceptance = self.runtime.close(ClosureReason::CloseRequested);
        encode(&SessionCloseResult {
            session_id: self.runtime.session().id(),
            state: acceptance.state,
            durability: acceptance.durability,
            closure: Nullable(acceptance.closure),
        })
    }

    fn attachment_configure(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: AttachmentConfigureParams = parse(params)?;
        let mut session = self.runtime.session();
        let geometry = session.configure(params.attachment_id, params.claim_geometry)?;
        encode(&GeometryResult { geometry })
    }

    fn terminal_resize(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: TerminalResizeParams = parse(params)?;
        let mut session = self.runtime.session();
        let geometry = session.resize(
            params.attachment_id,
            params.dimensions,
            params.expected_geometry_epoch.get(),
        )?;
        encode(&GeometryResult { geometry })
    }

    fn geometry_transfer(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: TerminalGeometryTransferParams = parse(params)?;
        let mut session = self.runtime.session();
        let geometry = session
            .transfer_geometry(params.attachment_id, params.expected_geometry_epoch.get())?;
        encode(&GeometryResult { geometry })
    }

    fn input_acquire(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: InputAcquireParams = parse(params)?;
        let result = {
            let mut session = self.runtime.session();
            session.acquire_input(
                params.attachment_id,
                state.connection_id,
                params.expected_epoch.as_ref().map(|epoch| epoch.get()),
            )?
        };
        self.runtime.flush_input();
        encode(&result)
    }

    fn input_release(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: InputReleaseParams = parse(params)?;
        let mut session = self.runtime.session();
        let lease = session.release_input(params.attachment_id, params.epoch.get())?;
        encode(&InputLeaseResult { lease })
    }

    fn input_interrupt(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: InputInterruptParams = parse(params)?;
        if params.action != InterruptAction::NativeInterrupt {
            return Err(WorkerError::InvalidArgument(
                "the interrupt method accepts only the configured native interrupt".to_owned(),
            ));
        }
        let mut session = self.runtime.session();
        session.interrupt(params.attachment_id, params.epoch.get())?;
        encode(&InputLeaseResult {
            lease: session.lease(),
        })
    }
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
    /// The freshness window the host stamped.
    pub action_window: ActionWindowId,
    /// The event stream identifier notifications carry.
    pub stream_id: StreamId,
    /// The challenge this connection issued to a controller, consumed once.
    pub generation_nonce: Option<Nonce256>,
    /// The attachments this connection owns.
    pub attachments: Vec<AttachmentId>,
    /// The output subscription waiting to be started.
    pub subscribed: Option<(AttachmentId, crate::output::OutputStream)>,
    /// The last input sequence accepted on this connection.
    pub input_sequence: u64,
    next_request: u64,
}

impl ConnectionState {
    /// Builds the state for a fresh connection.
    #[must_use]
    pub fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            negotiated: false,
            controller: false,
            action_window: ActionWindowId::new(format!("local:{connection_id}"))
                .unwrap_or_else(|_| ActionWindowId::new("local").expect("a valid window")),
            stream_id: StreamId::new(OUTPUT_STREAM).expect("a valid stream name"),
            generation_nonce: None,
            attachments: Vec::new(),
            subscribed: None,
            input_sequence: 0,
            next_request: 0,
        }
    }

    fn next_request_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }
}

fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| WorkerError::InvalidArgument(error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(value).map_err(|error| WorkerError::InvalidArgument(error.to_string()))
}

fn respond(request_id: RequestId, outcome: Result<ParamsValue>) -> ControlMessage {
    match outcome {
        Ok(value) => ControlMessage::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Err(error) => failure(request_id, &error.to_protocol_error()),
    }
}

fn failure(request_id: RequestId, error: &ProtocolError) -> ControlMessage {
    ControlMessage::Response(Response {
        request_id,
        outcome: Outcome::Error(error.clone()),
    })
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
) -> Option<ControlMessage> {
    Some(ControlMessage::Notification(
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
