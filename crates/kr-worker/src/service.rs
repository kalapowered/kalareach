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
use kr_protocol::envelope::{MutationRequest, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{
    ActionWindowId, ActorId, AttachmentId, ConnectionId, ControllerGeneration, EnvironmentId,
    RequestId, SessionId, StreamId,
};
use kr_protocol::input::{
    InputAcquireParams, InputInterruptParams, InputLeaseResult, InputReleaseParams,
    InputWriteParams, InputWriteResult, InterruptAction,
};
use kr_protocol::local::{ControlMessage, LocalClientKind, LocalHello, LocalHelloAck, LocalRole};
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

/// The largest replay page one notification carries.
///
/// A control frame is bounded at 1 MiB including its metadata, so a replay page stays well inside
/// that rather than filling it exactly.
pub const MAX_REPLAY_PAGE_BYTES: u64 = 512 * 1024;

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
        let mut state = ConnectionState::new(connection_id, &peer);
        loop {
            let message: ControlMessage = match reader.read_message().await {
                Ok(message) => message,
                Err(_) => break,
            };
            let reply = self.handle(&mut state, &peer, message).await;
            if let Some(reply) = reply {
                let mut sender = writer.lock().await;
                if sender.write_message(&reply).await.is_err() {
                    break;
                }
                drop(sender);
                // Whatever the reply was, it has reached the peer now. A close admitted while
                // building it may start its termination sequence.
                if let Some(gate) = state.close_gate.take() {
                    gate.release();
                }
                // A controller announces itself in its hello; the worker answers with a challenge
                // it will only accept once.
                if let Some(challenge) = state.pending_challenge.take() {
                    let mut sender = writer.lock().await;
                    if sender.write_message(&challenge).await.is_err() {
                        break;
                    }
                }
            }
            if state.subscribed.is_none() {
                continue;
            }
            if let Some((attachment_id, mut stream)) = state.subscribed.take() {
                let sender = Arc::clone(&writer);
                let stream_id = state.stream_id.clone();
                let replay_from = state.replay_from.take();
                let runtime = Arc::clone(self.runtime());
                let task = tokio::spawn(async move {
                    let mut sequence = 0_u64;
                    // The retained range between the requested cursor and the live edge is sent
                    // before live output, so a reconnecting client sees one ordered stream rather
                    // than a hole it never learns about.
                    if let Some(mut cursor) = replay_from {
                        loop {
                            let page = {
                                let session = runtime.session();
                                session.history_page(cursor, MAX_REPLAY_PAGE_BYTES)
                            };
                            let Ok(page) = page else { break };
                            if page.bytes.is_empty() {
                                break;
                            }
                            let event = OutputEvent {
                                cursor: page.from_cursor,
                                bytes: page.bytes.clone(),
                            };
                            let Some(notification) =
                                notification(&stream_id, sequence, "session.output", &event)
                            else {
                                break;
                            };
                            sequence += 1;
                            let mut sender = sender.lock().await;
                            if sender.write_message(&notification).await.is_err() {
                                return;
                            }
                            drop(sender);
                            cursor = page.next_cursor.get();
                        }
                    }
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
                state.delivery = Some(task);
            }
        }
        // A connection that goes away takes its delivery task and its attachments with it.
        // Undelivered input from them is discarded rather than replayed.
        if let Some(task) = state.delivery.take() {
            task.abort();
        }
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
        if hello.client == LocalClientKind::Controller {
            // A controller has to prove which generation it speaks for before it acts. The
            // challenge is issued here, bound to this connection, and consumed exactly once.
            state.pending_challenge = Self::generation_challenge(state);
        }
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
            Method::AttachmentViewport => self.attachment_viewport(state, &request.params),
            Method::InputWrite => self.input_write(state, &request.params),
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a read this worker serves",
                method.as_str()
            ))),
        };
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
        match self.receipted(state, mutation, method) {
            Ok(value) => ControlMessage::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(value),
            }),
            Err(error) => failure(mutation.request_id, &error.to_protocol_error()),
        }
    }

    fn receipted(
        &self,
        state: &mut ConnectionState,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<ParamsValue> {
        let actor_id = state.actor_id.clone();
        let digest = kr_protocol::digest::mutation_digest(mutation, &actor_id)
            .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?;
        let submission = crate::journal::Submission {
            actor_id: actor_id.clone(),
            action_id: mutation.action_id,
            method: mutation.method.clone(),
            method_version: mutation.method_version,
            payload_digest: digest,
            accepted_deadline_ms: Some(state.accepted_deadline(mutation.requested_ttl_ms.get())),
            now_ms: kr_ipc::now_ms(),
        };

        // Storage failure stops an ordinary typed mutation before dispatch. An authorised stop is
        // the named exception: section 7 requires `session.close` to proceed on current in-memory
        // authority and report `durability=volatile`.
        let admission = {
            let mut session = self.runtime.session();
            match session.journal_mut() {
                Some(journal) => Some(journal.accept(&submission)?),
                None if method == Method::SessionClose => None,
                None => {
                    return Err(WorkerError::JournalUnavailable {
                        detail:
                            "the session journal is unavailable, so no durable mutation is accepted"
                                .to_owned(),
                    });
                }
            }
        };

        if let Some(admission) = admission.as_ref()
            && admission.deduplicated
        {
            let retained = {
                let mut session = self.runtime.session();
                match session.journal_mut() {
                    Some(journal) => journal.read_result(&actor_id, mutation.action_id)?,
                    None => None,
                }
            };
            if let Some(bytes) = retained {
                let value = kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(|error| WorkerError::InvalidArgument(error.to_string()))?;
                return Ok(ParamsValue::new(value));
            }
            // The action is known and its result is not available yet, which is the honest answer
            // rather than performing it a second time.
            return Err(WorkerError::InvalidArgument(format!(
                "action {} is already {} and has no retained result",
                mutation.action_id, admission.receipt.state
            )));
        }

        // Revalidate before the marker. Anything that was true at acceptance may not be now.
        if let Err(error) = self.validate(state, mutation, method) {
            self.reject(&actor_id, mutation, &error);
            return Err(error);
        }
        if admission.is_some() {
            let mut session = self.runtime.session();
            if let Some(journal) = session.journal_mut() {
                journal.mark_dispatching(actor_id.clone(), mutation.action_id, kr_ipc::now_ms())?;
            }
        }

        let outcome = self.apply(state, mutation, method);
        let now = kr_ipc::now_ms();
        let mut session = self.runtime.session();
        match (&outcome, session.journal_mut()) {
            (Ok(value), Some(journal)) => {
                let bytes = kr_cbor::encode(value.as_value());
                journal.record_result(&actor_id, mutation.action_id, &bytes)?;
                journal.complete(
                    actor_id,
                    mutation.action_id,
                    kr_protocol::receipt::ReceiptState::Applied,
                    None,
                    now,
                )?;
            }
            (Err(error), Some(journal)) => {
                // Past the marker there is no rejection. Whether the effect happened cannot be
                // established from here, so the outcome is recorded as unknown.
                journal.complete(
                    actor_id,
                    mutation.action_id,
                    kr_protocol::receipt::ReceiptState::Unknown,
                    Some(error.to_protocol_error()),
                    now,
                )?;
            }
            (_, None) => {}
        }
        outcome
    }

    fn reject(&self, actor_id: &ActorId, mutation: &MutationRequest, error: &WorkerError) {
        let mut session = self.runtime.session();
        if let Some(journal) = session.journal_mut() {
            let _ = journal.reject(
                actor_id.clone(),
                mutation.action_id,
                kr_protocol::receipt::RejectionReason::AdmissionFailed,
                Some(error.to_protocol_error()),
                kr_ipc::now_ms(),
            );
        }
    }

    /// Checks a mutation's target, authority and preconditions without acting on it.
    fn validate(
        &self,
        state: &ConnectionState,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<()> {
        match method {
            Method::SessionAttach => {
                let params: SessionAttachParams = parse(&mutation.params)?;
                self.check_session(params.session_id)
            }
            Method::SessionDetach => {
                let params: SessionDetachParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)
            }
            Method::SessionClose => {
                let params: kr_protocol::session::SessionCloseParams = parse(&mutation.params)?;
                self.check_session(params.session_id)
            }
            Method::AttachmentConfigure => {
                let params: AttachmentConfigureParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)?;
                if params.claim_geometry {
                    self.check_capability(params.attachment_id, AttachmentCapability::Geometry)?;
                }
                Ok(())
            }
            Method::TerminalResize => {
                let params: TerminalResizeParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)?;
                self.check_capability(params.attachment_id, AttachmentCapability::Geometry)
            }
            Method::TerminalGeometryTransfer => {
                let params: TerminalGeometryTransferParams = parse(&mutation.params)?;
                Self::check_attachment(state, params.attachment_id)?;
                self.check_capability(params.attachment_id, AttachmentCapability::Geometry)
            }
            Method::InputAcquire => {
                let params: InputAcquireParams = parse(&mutation.params)?;
                self.check_session(params.session_id)?;
                Self::check_attachment(state, params.attachment_id)?;
                self.check_capability(params.attachment_id, AttachmentCapability::Input)
            }
            Method::InputRelease => {
                let params: InputReleaseParams = parse(&mutation.params)?;
                self.check_session(params.session_id)?;
                Self::check_attachment(state, params.attachment_id)
            }
            Method::InputInterrupt => {
                let params: InputInterruptParams = parse(&mutation.params)?;
                self.check_session(params.session_id)?;
                Self::check_attachment(state, params.attachment_id)?;
                self.check_capability(params.attachment_id, AttachmentCapability::Input)
            }
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a mutation this worker serves",
                method.as_str()
            ))),
        }
    }

    fn apply(
        &self,
        state: &mut ConnectionState,
        mutation: &MutationRequest,
        method: Method,
    ) -> Result<ParamsValue> {
        match method {
            Method::SessionAttach => self.session_attach(state, &mutation.params),
            Method::SessionDetach => self.session_detach(state, &mutation.params),
            Method::SessionClose => self.session_close(state, &mutation.params),
            Method::AttachmentConfigure => self.attachment_configure(state, &mutation.params),
            Method::TerminalResize => self.terminal_resize(state, &mutation.params),
            Method::TerminalGeometryTransfer => self.geometry_transfer(state, &mutation.params),
            Method::InputAcquire => self.input_acquire(state, &mutation.params),
            Method::InputRelease => self.input_release(state, &mutation.params),
            Method::InputInterrupt => self.input_interrupt(state, &mutation.params),
            _ => Err(WorkerError::InvalidArgument(format!(
                "{} is not a mutation this worker serves",
                method.as_str()
            ))),
        }
    }

    fn reachable(&self, method: Method, version: MethodVersion) -> bool {
        matches!(
            kr_protocol::method::decide(method.as_str(), version, ActorIngress::LocalIpc),
            kr_protocol::authority::AuthorityDecision::Listed(_)
        )
    }

    /// Refuses a request that names a session this worker does not own.
    ///
    /// A worker owns exactly one session. A request that arrives on this endpoint naming another
    /// session is not a request for this session with a typo in it; acting on it would let a
    /// caller close one session by addressing another.
    fn check_session(&self, named: SessionId) -> Result<()> {
        let owned = self.runtime.session().id();
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
    fn check_attachment(state: &ConnectionState, attachment_id: AttachmentId) -> Result<()> {
        if state.attachments.contains(&attachment_id) {
            Ok(())
        } else {
            Err(WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            })
        }
    }

    /// Refuses an operation the attachment was not granted.
    fn check_capability(
        &self,
        attachment_id: AttachmentId,
        capability: AttachmentCapability,
    ) -> Result<()> {
        let session = self.runtime.session();
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
        self.check_session(params.session_id)?;
        let session = self.runtime.session();
        let running = session.state().is_running();
        encode(&SessionReadResult {
            session: session.summary(),
            endpoint: Nullable(running.then(|| self.endpoint.as_text())),
        })
    }

    fn events_snapshot(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: EventsSnapshotParams = parse(params)?;
        self.check_session(params.session_id)?;
        encode(&self.runtime.session().snapshot())
    }

    fn history_page(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: HistoryPageParams = parse(params)?;
        self.check_session(params.session_id)?;
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
        self.check_session(params.session_id)?;
        Self::check_attachment(state, params.attachment_id)?;
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
        let replay_from = from.max(oldest);
        drop(session);
        state.subscribed = Some((params.attachment_id, stream));
        state.replay_from = Some(replay_from);
        encode(&EventsSubscribeResult {
            stream_id: state.stream_id.clone(),
            from_cursor: U64::new(from.max(oldest)),
            oldest_retained_cursor: U64::new(oldest),
            gap: Nullable(gap),
        })
    }

    fn attachment_viewport(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: AttachmentViewportParams = parse(params)?;
        Self::check_attachment(state, params.attachment_id)?;
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
        self.check_session(params.session_id)?;
        Self::check_attachment(state, params.attachment_id)?;
        self.check_capability(params.attachment_id, AttachmentCapability::Input)?;
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
        self.check_session(params.session_id)?;
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
        Self::check_attachment(state, params.attachment_id)?;
        let result = {
            let mut session = self.runtime.session();
            session.detach(params.attachment_id)?
        };
        state
            .attachments
            .retain(|attachment| *attachment != params.attachment_id);
        encode(&result)
    }

    fn session_close(
        &self,
        state: &mut ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::session::SessionCloseParams = parse(params)?;
        self.check_session(params.session_id)?;
        let (acceptance, gate) = self.runtime.close(ClosureReason::CloseRequested);
        // The gate is held until the acceptance has been written. The requester is often a command
        // running inside the process group this closure is about to stop.
        state.close_gate = Some(gate);
        encode(&SessionCloseResult {
            session_id: params.session_id,
            state: acceptance.state,
            durability: acceptance.durability,
            closure: Nullable(acceptance.closure),
        })
    }

    fn attachment_configure(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: AttachmentConfigureParams = parse(params)?;
        Self::check_attachment(state, params.attachment_id)?;
        if params.claim_geometry {
            self.check_capability(params.attachment_id, AttachmentCapability::Geometry)?;
        }
        let mut session = self.runtime.session();
        let geometry = session.configure(params.attachment_id, params.claim_geometry)?;
        encode(&GeometryResult { geometry })
    }

    fn terminal_resize(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: TerminalResizeParams = parse(params)?;
        Self::check_attachment(state, params.attachment_id)?;
        self.check_capability(params.attachment_id, AttachmentCapability::Geometry)?;
        let mut session = self.runtime.session();
        let geometry = session.resize(
            params.attachment_id,
            params.dimensions,
            params.expected_geometry_epoch.get(),
        )?;
        encode(&GeometryResult { geometry })
    }

    fn geometry_transfer(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: TerminalGeometryTransferParams = parse(params)?;
        Self::check_attachment(state, params.attachment_id)?;
        self.check_capability(params.attachment_id, AttachmentCapability::Geometry)?;
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
        self.check_session(params.session_id)?;
        Self::check_attachment(state, params.attachment_id)?;
        self.check_capability(params.attachment_id, AttachmentCapability::Input)?;
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

    fn input_release(&self, state: &ConnectionState, params: &ParamsValue) -> Result<ParamsValue> {
        let params: InputReleaseParams = parse(params)?;
        self.check_session(params.session_id)?;
        Self::check_attachment(state, params.attachment_id)?;
        let mut session = self.runtime.session();
        let lease = session.release_input(params.attachment_id, params.epoch.get())?;
        encode(&InputLeaseResult { lease })
    }

    fn input_interrupt(
        &self,
        state: &ConnectionState,
        params: &ParamsValue,
    ) -> Result<ParamsValue> {
        let params: InputInterruptParams = parse(params)?;
        self.check_session(params.session_id)?;
        Self::check_attachment(state, params.attachment_id)?;
        self.check_capability(params.attachment_id, AttachmentCapability::Input)?;
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
    /// A close that has been admitted and whose acceptance has not yet been written.
    pub close_gate: Option<crate::runtime::CloseGate>,
    /// A generation challenge waiting to be sent after the current reply.
    pub pending_challenge: Option<ControlMessage>,
    /// Where a new subscription replays retained output from before live output resumes.
    pub replay_from: Option<u64>,
    /// The delivery task this connection owns, cancelled when the connection goes.
    pub delivery: Option<tokio::task::JoinHandle<()>>,
    /// The host-issued principal this connection acts under.
    ///
    /// It is built from the authenticated operating-system caller. A local caller never asserts
    /// its own provenance and never borrows a device identity.
    pub actor_id: ActorId,
    /// When this connection's freshness window expires.
    pub window_expires_at_ms: u64,
    next_request: u64,
}

impl ConnectionState {
    /// Builds the state for a fresh connection.
    #[must_use]
    pub fn new(connection_id: ConnectionId, peer: &PeerIdentity) -> Self {
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
            close_gate: None,
            pending_challenge: None,
            replay_from: None,
            delivery: None,
            actor_id: ActorId::new(format!("local:{}", peer.uid))
                .unwrap_or_else(|_| ActorId::new("local").expect("a valid principal")),
            window_expires_at_ms: kr_ipc::now_ms().get().saturating_add(ACTION_WINDOW_MS),
            next_request: 0,
        }
    }

    /// Returns the deadline the host derives for a mutation.
    ///
    /// It is the earliest of the window's expiry and the receipt time plus the requested lifetime,
    /// bounded by the protocol maximum. The client never supplies an authoritative deadline.
    #[must_use]
    pub fn accepted_deadline(&self, requested_ttl_ms: u64) -> kr_protocol::scalars::TimestampMs {
        let requested = requested_ttl_ms.min(kr_protocol::limits::MAX_MUTATION_TTL.get());
        let from_ttl = kr_ipc::now_ms().get().saturating_add(requested);
        kr_protocol::scalars::TimestampMs::new(from_ttl.min(self.window_expires_at_ms))
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
