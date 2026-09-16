//! Serving one authorised remote connection.
//!
//! Everything a paired device asks for passes through here, and the order is the contract:
//!
//! 1. **The registry decides.** `ConnectionActor::admit` resolves the method against the authority
//!    table at the *paired-device* ingress, so a method kept to private IPC is unreachable however
//!    broad the device's grant is, and no mutation is admitted in 0-RTT.
//! 2. **The registration decides.** The connection's registration in the daemon's authority store
//!    is checked before anything is read, before anything is dispatched, and again before the
//!    answer is written. That is the fence a revocation sets: section 9's dispatch barrier covers a
//!    worker's dispatch, and this covers a read or a subscription on a connection that was
//!    authorised a moment earlier.
//! 3. **The grant decides.** The rights the method requires are checked against the grant the
//!    device holds: its expiry, the environment and session its selectors admit, the rights it
//!    carries, and the content its history scope reaches.
//! 4. **The window decides.** A mutation's accepted deadline is the earliest of what its action
//!    window has left, receipt time plus the requested lifetime, what remains of the grant's own
//!    lifetime, and the dispatch lease's remaining time.
//! 5. **The subject acts.** The daemon performs what it owns; everything else is forwarded to the
//!    worker that owns the session, under the verified envelope and the accepted deadline, through
//!    the same serial barrier a local caller's mutation passes through.
//!
//! # The write boundary
//!
//! Every frame this connection sends — a response, a receipt, a relayed notification — is decided
//! and written behind one turn, and a withdrawal takes the same turn's latch before it closes the
//! connection. So no write can *begin* after the authority behind it was withdrawn. A write that
//! had already begun decided its bytes while the registration stood, and the closed connection is
//! what stops it reaching a peer; the withdrawal itself never waits for a peer.
//!
//! # What outlives the connection
//!
//! A mutation's effect runs on its own task, so a durable commit is never left half done because a
//! peer went away. So does the release of what the connection owned at its worker, and that runs
//! from a guard's destructor rather than from the end of the serve loop, because the transport
//! drops the handler's future the moment the control stream ends.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::actor::ActorEnvelope;
use kr_protocol::authority::{
    EffectClass, HistoryFilter, MethodEntry, RequiredAuthority, ResourceSelectorKind,
    RightCondition,
};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AuthorityRevision, ConnectionId, DeviceId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::session::SessionListResult;
use kr_transport::actor::ConnectionActor;
use kr_transport::clock::ContinuousClock as _;
use kr_transport::listener::{AuthorisedSession, ControlSender};
use kr_transport::window::AcceptedDeadline;

use super::devices::DeviceRecord;
use super::proxy::{RELAY_QUEUED_BYTES, RelayBudget, Relayed, WorkerProxy};
use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// The QUIC application error code a withdrawn connection is closed with.
pub const WITHDRAWN: u32 = 4;

/// One connection's write boundary, and the latch a withdrawal sets.
///
/// Deciding what to send and sending it are one step, and a withdrawal is the other side of the
/// same step. Without that, a notification that had passed its authority check could sit waiting
/// for the peer, have its authority withdrawn, and then be delivered.
#[derive(Debug)]
pub struct RemoteOutput {
    /// Whose turn it is to write. Exactly one frame is in flight at a time.
    turn: tokio::sync::Mutex<()>,
    withdrawn: AtomicBool,
    sender: ControlSender,
    connection: iroh::endpoint::Connection,
}

impl RemoteOutput {
    fn new(session: &AuthorisedSession) -> Self {
        Self {
            turn: tokio::sync::Mutex::new(()),
            withdrawn: AtomicBool::new(false),
            sender: session.control.sender(),
            connection: session.connection.clone(),
        }
    }

    /// Sends one frame, and returns whether it was sent.
    ///
    /// The latch is read after the turn is taken, so a frame is never begun on a connection whose
    /// authority has been withdrawn.
    pub async fn send(&self, frame: &ControlFrame) -> bool {
        let _turn = self.turn.lock().await;
        if self.has_withdrawn() {
            return false;
        }
        self.sender.send(frame).await.is_ok()
    }

    /// Withdraws this connection. No write begins after this returns.
    ///
    /// It does not wait for the turn, and it must not: a peer that has stopped reading would
    /// otherwise hold a revocation up for as long as it cared to. A write that is already in
    /// progress decided its bytes while the registration stood; closing the connection is what
    /// stops it reaching a peer that is no longer authorised to receive it.
    pub fn withdraw(&self) {
        self.withdrawn.store(true, Ordering::Release);
        self.connection.close(
            WITHDRAWN.into(),
            b"this connection's authority was withdrawn",
        );
    }

    fn has_withdrawn(&self) -> bool {
        self.withdrawn.load(Ordering::Acquire)
    }
}

/// What one authorised remote connection is serving.
pub struct RemoteConnection {
    controller: Arc<Controller>,
    /// The device this connection belongs to, as the record stood when it was admitted.
    device: DeviceRecord,
    actor: ConnectionActor,
    connection_id: ConnectionId,
    output: Arc<RemoteOutput>,
    /// This connection's own link to the worker it has attached to, opened on first use.
    proxy: tokio::sync::Mutex<Option<Arc<WorkerProxy>>>,
    /// Where a notification the proxy read is written.
    notifications: tokio::sync::mpsc::Sender<Relayed>,
    /// What this connection has queued for the device and not yet had written.
    budget: Arc<RelayBudget>,
    windows: Arc<kr_transport::window::ActionWindowIssuer>,
    /// Set the first time this connection's grant is found to have expired.
    ///
    /// A grant that has run out never comes back, and section 9 says so of an expired grant
    /// explicitly. The wall clock can be stepped backwards; this cannot.
    grant_expired: AtomicBool,
}

impl std::fmt::Debug for RemoteConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteConnection")
            .field("connection", &self.connection_id)
            .field("device", &self.device.device_id)
            .finish_non_exhaustive()
    }
}

impl RemoteConnection {
    /// Builds the server of one authorised connection.
    #[must_use]
    pub fn new(
        controller: Arc<Controller>,
        device: DeviceRecord,
        session: &AuthorisedSession,
        notifications: tokio::sync::mpsc::Sender<Relayed>,
    ) -> Self {
        Self {
            controller,
            device,
            actor: session.actor.clone(),
            connection_id: session.connection_id,
            output: Arc::new(RemoteOutput::new(session)),
            proxy: tokio::sync::Mutex::new(None),
            notifications,
            budget: Arc::new(RelayBudget::new(RELAY_QUEUED_BYTES)),
            windows: Arc::clone(&session.windows),
            grant_expired: AtomicBool::new(false),
        }
    }

    /// Returns this connection's write boundary.
    #[must_use]
    pub fn output(&self) -> &Arc<RemoteOutput> {
        &self.output
    }

    /// Returns the connection this serves.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the device this connection belongs to.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device.device_id
    }

    /// Returns true when this connection's grant still has time on it.
    ///
    /// Once it has been found expired it stays expired, so a wall clock stepped backwards cannot
    /// revive authority that ran out.
    pub fn grant_is_current(&self) -> bool {
        if self.grant_expired.load(Ordering::Acquire) {
            return false;
        }
        if self.device.grant.expiry.is_valid_at(kr_ipc::now_ms().get()) {
            return true;
        }
        self.grant_expired.store(true, Ordering::Release);
        false
    }

    /// Answers one frame from the device.
    ///
    /// Returns `None` for a frame that does not belong on this ingress, which ends the connection:
    /// the union is closed so that a receiver can name what arrived, and naming it is only worth
    /// anything if it then refuses it.
    pub async fn answer(&self, frame: ControlFrame) -> Option<ControlFrame> {
        match frame {
            ControlFrame::Request(request) => Some(self.read(&request).await),
            ControlFrame::Mutation(mutation) => Some(self.mutate(&mutation).await),
            // A host does not call a client, and none of the daemon's own local frames belongs on
            // a network ingress. They are named rather than swept up, so a variant added later has
            // to be decided here.
            ControlFrame::Response(_)
            | ControlFrame::Receipt(_)
            | ControlFrame::Notification(_)
            | ControlFrame::Event(_)
            | ControlFrame::Hello(_)
            | ControlFrame::HelloAck(_)
            | ControlFrame::Rendezvous(_)
            | ControlFrame::LaunchSpec(_)
            | ControlFrame::WorkerReady(_)
            | ControlFrame::WorkerFailed(_)
            | ControlFrame::VerifyChallenge(_)
            | ControlFrame::VerifyProof(_)
            | ControlFrame::ControllerRole(_)
            | ControlFrame::GenerationChallenge(_)
            | ControlFrame::GenerationToken(_)
            | ControlFrame::GenerationAccepted(_)
            | ControlFrame::AuthorityRevision(_)
            | ControlFrame::AuthorityRevisionAck(_)
            | ControlFrame::Forwarded(_)
            | ControlFrame::ForwardedRead(_)
            | ControlFrame::AcceptanceDelivered(_) => None,
        }
    }

    /// Serves one read.
    async fn read(&self, request: &Request) -> ControlFrame {
        let entry = match self.admit(request.method.as_str(), request.method_version) {
            Ok(entry) => entry,
            Err(error) => return failure(request.request_id, error),
        };
        // Raw input is the one write that does not carry an action: section 9 makes it a separate
        // ordered stream with no durable de-duplication. Everything else that writes arrives as a
        // mutation, because a write needs an action identity and a freshness context.
        if entry.effect != EffectClass::Read && entry.method != Method::InputWrite {
            return failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} is a mutation and carries an action", entry.name),
                ),
            );
        }
        // Before the read, not only after it. A registration withdrawn before this request arrived
        // must stop it, and a read that is refused must not have reached the subject first.
        if let Err(error) = self.authorised().await {
            return failure(request.request_id, error);
        }
        let named = session_of(&request.params, entry).ok();
        let validated = self.validation_revision().await;
        // A read never claims geometry: the condition on `terminal.geometry` is about a request
        // that claims or adds a claim, and only a mutation does either.
        if let Err(error) = self.check_grant(named, entry, false) {
            return failure(request.request_id, error);
        }
        let answer = match entry.method {
            Method::HostInfo | Method::EnvironmentList | Method::HostDoctor => {
                self.controller.read_method(request).await
            }
            // The daemon answers these itself, and what it answers with is narrowed to the grant:
            // a list is every session this actor may observe, not every session this host runs.
            Method::SessionList | Method::SessionRead => {
                let answer = self.controller.read_method(request).await;
                self.narrow(answer)
            }
            Method::EventsSubscribe
            | Method::EventsSnapshot
            | Method::HistoryPage
            | Method::ActionRead
            | Method::InputWrite => self.proxied_read(request, entry, validated).await,
            _ => failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} is not a read this host serves", entry.name),
                ),
            ),
        };
        // Checked again now the read has finished. A read that passed its check and then waited
        // for a worker can complete after the authority behind it was withdrawn, and what the
        // contract forbids is *serving* that state rather than reading it.
        if let Err(error) = self.authorised().await {
            return failure(request.request_id, error);
        }
        answer
    }

    /// Serves one mutation.
    async fn mutate(&self, mutation: &MutationRequest) -> ControlFrame {
        let entry = match self.admit(mutation.method.as_str(), mutation.method_version) {
            Ok(entry) => entry,
            Err(error) => return failure(mutation.request_id, error),
        };
        if entry.effect != EffectClass::Write {
            return failure(
                mutation.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} is a read and carries no action", entry.name),
                ),
            );
        }
        // The registration first, before a retained result is looked up and before any effect is
        // considered. A revoked device gets no further dispatch, and it does not get its own
        // retained results back either: section 9 has the host check current authority before it
        // returns a retained receipt.
        if let Err(error) = self.authorised().await {
            return failure(mutation.request_id, error);
        }
        // A retained action is answered before anything about a first admission is considered.
        // Applying the freshness window to a retry would refuse a caller its own completed result
        // because the window it was admitted under has since been replaced. Its authority is
        // checked above, and the grant below, because an authority that has gone does not entitle
        // a caller to a result it once produced.
        let actor_id = self.device.principal();
        let validated = self.validation_revision().await;
        if let Err(error) = self.check_grant(
            mutation.target.session_id.as_ref().copied(),
            entry,
            claims_geometry(mutation),
        ) {
            return failure(mutation.request_id, error);
        }
        if let Some(retained) = self
            .controller
            .retained(&actor_id, mutation, entry.method)
            .await
        {
            return retained;
        }
        let accepted = match self.check_envelope(mutation, entry) {
            Ok(accepted) => accepted,
            Err(error) => return failure(mutation.request_id, error),
        };
        match entry.method {
            // The daemon's own effects. They run on a task that outlives this connection, because
            // dropping a future is a cancellation and a durable commit cannot be left half done
            // because a peer went away.
            Method::SessionCreate => {
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let effect = tokio::spawn(async move {
                    controller
                        .session_create(&actor_id, &mutation, accepted)
                        .await
                });
                settled(request_id, effect.await)
            }
            Method::SessionClose => {
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let envelope = self.envelope(validated);
                let request_id = mutation.request_id;
                let effect = tokio::spawn(async move {
                    controller
                        .session_close(&mutation, &envelope, accepted)
                        .await
                });
                settled(request_id, effect.await)
            }
            // Everything else belongs to the worker that owns the session.
            _ => self.proxied_mutation(mutation, accepted, validated).await,
        }
    }

    /// Narrows a session listing to what this device's grant admits.
    ///
    /// A request that names a session is already checked against the selector. A listing names
    /// none, so the selector has nothing to check and the narrowing has to happen to the answer:
    /// the registry's own words for this method are "the sessions this actor may observe".
    fn narrow(&self, answer: ControlFrame) -> ControlFrame {
        let ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }) = answer
        else {
            return answer;
        };
        let Ok(listed) = value.to_typed::<SessionListResult>() else {
            // Not a listing: `session.read` names its session and was checked against the
            // selector, so its result passes through as it is.
            return ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Ok(value),
            });
        };
        let selector = &self.device.grant.session_selector;
        let narrowed = SessionListResult {
            sessions: listed
                .sessions
                .into_iter()
                .filter(|summary| selector.admits(summary.session_id))
                .collect(),
        };
        match ParamsValue::from_typed(&narrowed) {
            Ok(value) => ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Ok(value),
            }),
            Err(error) => failure(
                request_id,
                ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
            ),
        }
    }

    /// Forwards one read to the worker that owns the session it names.
    async fn proxied_read(
        &self,
        request: &Request,
        entry: &'static MethodEntry,
        validated: AuthorityRevision,
    ) -> ControlFrame {
        let session_id = match session_of(&request.params, entry) {
            Ok(session_id) => session_id,
            Err(error) => return failure(request.request_id, error),
        };
        let proxy = match self.proxy_for(session_id).await {
            Ok(proxy) => proxy,
            Err(error) => return failure(request.request_id, error.to_protocol_error()),
        };
        let envelope = self.envelope(validated);
        match proxy.forward_read(request, &envelope).await {
            Ok(response) => ControlFrame::Response(Response {
                request_id: request.request_id,
                outcome: response.outcome,
            }),
            Err(error) => failure(request.request_id, error.to_protocol_error()),
        }
    }

    /// Forwards one mutation to the worker that owns the session it names.
    ///
    /// Remote dispatch additionally needs a live lease from the current generation and revision,
    /// taken at the moment the dispatch runs rather than one that was valid when the request
    /// arrived, and the lease's own remaining time bounds the deadline the worker is given.
    async fn proxied_mutation(
        &self,
        mutation: &MutationRequest,
        accepted: AcceptedDeadline,
        validated: AuthorityRevision,
    ) -> ControlFrame {
        let Some(session_id) = mutation.target.session_id.as_ref().copied() else {
            return failure(
                mutation.request_id,
                ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "this mutation names the session it acts on",
                ),
            );
        };
        let proxy = match self.proxy_for(session_id).await {
            Ok(proxy) => proxy,
            Err(error) => return failure(mutation.request_id, error.to_protocol_error()),
        };
        let envelope = self.envelope(validated);
        let deadline = match self
            .controller
            .forwarded_deadline(session_id, &envelope, accepted)
            .await
        {
            Ok(deadline) => deadline,
            Err(error) => return failure(mutation.request_id, error.to_protocol_error()),
        };
        // The effect runs on a task that outlives this connection, for the same reason the
        // daemon's own effects do: the worker commits the intent before it answers, and a
        // cancellation here must not be what decides whether the outcome is recorded.
        let mutation = mutation.clone();
        let request_id = mutation.request_id;
        let effect =
            tokio::spawn(
                async move { proxy.forward_mutation(&mutation, &envelope, deadline).await },
            );
        match effect.await {
            Ok(Ok(response)) => ControlFrame::Response(Response {
                request_id,
                outcome: response.outcome,
            }),
            Ok(Err(error)) => failure(request_id, error.to_protocol_error()),
            Err(_) => failure(request_id, outcome_unknown()),
        }
    }

    /// Returns this connection's link to one worker, opening it on first use.
    ///
    /// One link per connection, and one worker per link: a device attaches to one session at a
    /// time on one connection, and its attachment, its subscription and its input all have to
    /// belong to the same worker connection for the worker's own ownership rules to hold.
    async fn proxy_for(&self, session_id: SessionId) -> Result<Arc<WorkerProxy>> {
        let mut held = self.proxy.lock().await;
        if let Some(proxy) = held.as_ref() {
            if proxy.session_id() == session_id && proxy.is_open() {
                return Ok(Arc::clone(proxy));
            }
            if proxy.session_id() != session_id {
                return Err(ControllerError::InvalidArgument(
                    "this connection is already serving another session; open another connection"
                        .to_owned(),
                ));
            }
            // The link to this session has ended. A new one would be a new subscription and a new
            // attachment, which is a reconnection rather than something to do behind the caller's
            // back: section 8 has the client restore its state through cursors.
            return Err(ControllerError::supervision(
                "this connection's link to its session has ended; reconnect and subscribe again",
            ));
        }
        let proxy = self
            .controller
            .open_proxy(
                session_id,
                self.notifications.clone(),
                Arc::clone(&self.budget),
            )
            .await?;
        *held = Some(Arc::clone(&proxy));
        Ok(proxy)
    }

    /// Ends this connection's worker link and detaches whatever it owned.
    ///
    /// Closing the link is what the worker reads as the connection ending, and the worker's own
    /// deregistration then detaches the attachments and stops the delivery task. It runs on a task
    /// that outlives the connection, because dropping the handler is a cancellation.
    pub async fn release(&self) {
        if let Some(proxy) = self.proxy.lock().await.take() {
            proxy.close();
        }
    }

    /// Returns the envelope every request on this connection is attributed to.
    ///
    /// It is built from what the connection established and the record it was admitted against: a
    /// request names the grant it claims, and it cannot name its own device, its ingress or the
    /// generation that admitted it. The revision is the one this request's grant check was made
    /// at, not the one the grant was issued under: the worker compares it with the revision it
    /// holds, so it has to be the moment the host actually looked.
    fn envelope(&self, validated: AuthorityRevision) -> ActorEnvelope {
        self.actor
            .envelope(Some((self.device.grant.grant_id, validated)))
    }

    /// Returns the authority revision this request's checks are made at.
    ///
    /// Read once per request, before the grant is checked, and carried into the envelope. Reading
    /// it twice would let a request claim it was validated at a revision later than the one its
    /// grant was actually checked against.
    async fn validation_revision(&self) -> AuthorityRevision {
        self.controller
            .authority_revision()
            .await
            .unwrap_or(self.device.grant.authority_revision)
    }

    /// Resolves one method against the registry at this connection's ingress.
    fn admit(
        &self,
        method: &str,
        version: kr_protocol::method::MethodVersion,
    ) -> std::result::Result<&'static MethodEntry, ProtocolError> {
        self.actor.admit(method, version)
    }

    /// Returns whether this connection's registration still stands.
    pub async fn is_authorised(&self) -> bool {
        self.authorised().await.is_ok()
    }

    /// Refuses a request on a connection whose registration has been withdrawn.
    async fn authorised(&self) -> std::result::Result<(), ProtocolError> {
        self.controller
            .authorised(self.connection_id)
            .await
            .map(|_| ())
            .map_err(|error| error.to_protocol_error())
    }

    /// Checks the envelope of one mutation and returns the deadline the host accepted.
    ///
    /// The window is this connection's own, issued by the transport when the connection was
    /// authorised and replaced on the live connection at half its validity. A window from another
    /// connection, or from before a restart, first-admits nothing.
    fn check_envelope(
        &self,
        mutation: &MutationRequest,
        entry: &'static MethodEntry,
    ) -> std::result::Result<AcceptedDeadline, ProtocolError> {
        mutation
            .target
            .validate()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        if mutation.target.environment_id != self.controller.paths().environment_id() {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "this daemon owns environment {}",
                    self.controller.paths().environment_id()
                ),
            ));
        }
        // The target and the parameters have to name the same subject. One that pointed at a
        // session the grant admits and carried another in its parameters would act on the one
        // nobody addressed, and the grant check above would have looked at the wrong one.
        let names_session = entry
            .resource_selectors
            .contains(&ResourceSelectorKind::Session);
        match (
            mutation.target.session_id.as_ref().copied(),
            session_of(&mutation.params, entry).ok(),
        ) {
            (Some(named), Some(carried)) if named != carried => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "the request's target and its parameters name different sessions",
                ));
            }
            (None, Some(_)) => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} names the session it acts on in its target", entry.name),
                ));
            }
            (None, None) if names_session && entry.method != Method::SessionCreate => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} names the session it acts on", entry.name),
                ));
            }
            // A create allocates the session it is for, so it names none.
            (Some(_), None) if entry.method == Method::SessionCreate => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "a create allocates the session it is for, so it names none",
                ));
            }
            _ => {}
        }
        // The caller states the grant it is acting under. It may only be the one this device holds:
        // a device cannot name another device's grant, and the host records the grant it checked
        // rather than the one the request claimed.
        if let Some(claimed) = mutation.grant_id.as_ref()
            && *claimed != self.device.grant.grant_id
        {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "that grant is not the one this device holds",
            ));
        }
        // The requested lifetime is the caller's request, not its decision.
        if mutation.requested_ttl_ms.get() > kr_protocol::limits::MAX_MUTATION_TTL.get() {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "a mutation lifetime is at most {} milliseconds",
                    kr_protocol::limits::MAX_MUTATION_TTL.get()
                ),
            ));
        }
        // Preconditions belong to the subject, and are forwarded unchanged. What is checked here is
        // that the field is a map at all, so a malformed envelope is refused before anything acts.
        if !matches!(
            mutation.expected.as_value(),
            kr_cbor::CanonicalValue::Map(_)
        ) {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the subject preconditions are a map of the facts the caller depends on",
            ));
        }
        self.windows
            .accept(
                &mutation.action_window_id,
                self.connection_id,
                self.controller.boot_epoch,
                mutation.requested_ttl_ms,
                self.grant_deadline(),
            )
            .map_err(|refusal| {
                ProtocolError::new(ErrorCode::PermissionDenied, window_refusal_detail(refusal))
            })
    }

    /// Returns the authority deadline the grant's own expiry imposes.
    ///
    /// Section 9 makes the accepted deadline the earliest of the window's expiry, receipt time plus
    /// the requested lifetime and any applicable authority deadline. A grant that runs out in ten
    /// seconds is exactly such a deadline, and without it an action admitted a moment before the
    /// expiry could dispatch a minute after it.
    ///
    /// It is anchored on the continuous clock from what the wall clock says is left, so a wall
    /// clock stepped forwards cannot shorten an action's life and one stepped backwards cannot
    /// lengthen it.
    fn grant_deadline(&self) -> Option<kr_transport::clock::ContinuousInstant> {
        let kr_protocol::grant::GrantExpiry::At { expires_at_ms } = self.device.grant.expiry else {
            return None;
        };
        let now = kr_ipc::now_ms().get();
        let remaining = expires_at_ms.get().saturating_sub(now);
        self.controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_millis(remaining))
    }

    /// Checks the grant this device holds against what the method requires.
    ///
    /// What is checked here is what a grant on its own can answer: whether it has expired, the
    /// environment and session its selectors admit, the rights it carries for the conditions this
    /// request meets, and whether the content the method returns is inside its history scope. A
    /// requirement that depends on the resolved subject — resource ownership, a local caller's
    /// token — is the subject's to answer, and the worker answers it inside its own dispatch
    /// barrier where the subject cannot move.
    fn check_grant(
        &self,
        session_id: Option<SessionId>,
        entry: &'static MethodEntry,
        claims_geometry: bool,
    ) -> std::result::Result<(), ProtocolError> {
        let grant = &self.device.grant;
        if !self.grant_is_current() {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant has expired",
            ));
        }
        if !grant
            .environment_selector
            .admits(self.controller.paths().environment_id())
        {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant does not cover this environment",
            ));
        }
        if let Some(session_id) = session_id
            && !grant.session_selector.admits(session_id)
        {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant does not cover that session",
            ));
        }
        for required in entry.required_rights {
            if !Self::condition_holds(required.when, claims_geometry) {
                continue;
            }
            match required.authority {
                RequiredAuthority::Right { right } if !grant.permits(right) => {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        format!("this device's grant does not carry {}", right.as_str()),
                    ));
                }
                // Current read authority over the subject. For a session subject that is
                // `session.view` at the session's scope, which is what the grant can answer; the
                // subject's own state is the worker's to answer inside its barrier.
                RequiredAuthority::PresentViewAuthority
                    if !grant.permits(ActionRight::SessionView) =>
                {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this device's grant carries no current read authority over that subject",
                    ));
                }
                // A basis a grant does not express. The subject resolves it, and a caller that
                // reaches the subject at all has already passed everything above.
                _ => {}
            }
        }
        self.check_history(entry)
    }

    /// Returns whether a conditional requirement applies to this request.
    ///
    /// A condition the host cannot evaluate is treated as holding, so the requirement is checked
    /// rather than skipped: a condition nobody can decide must not be the reason a right goes
    /// unasked for.
    const fn condition_holds(when: RightCondition, claims_geometry: bool) -> bool {
        match when {
            RightCondition::Always => true,
            // A geometry claim is what the request asks for, and the request is what says so.
            // `session.attach` and `attachment.configure` both carry the flag and the capability.
            RightCondition::GeometryClaim => claims_geometry,
            // Whose subject it is belongs to the subject, and a condition the host cannot decide
            // is treated as holding so the right is asked for rather than skipped: a condition
            // nobody can evaluate must not be the reason a requirement goes unchecked.
            RightCondition::OwnSubject
            | RightCondition::OtherActor
            | RightCondition::CandidateEndpoint
            | RightCondition::IssuingOwner => true,
        }
    }

    /// Refuses a read whose content is outside the grant's history scope.
    fn check_history(&self, entry: &'static MethodEntry) -> std::result::Result<(), ProtocolError> {
        let scope = &self.device.grant.history;
        match entry.method {
            // The only method that returns *retained* history. Its scope is the grant's lower
            // bound, and nothing on this path can apply one: the bound is a moment in time and a
            // history page is a byte range. A host that cannot narrow content to a grant refuses
            // it rather than serving more than the grant allows.
            Method::HistoryPage => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host does not serve retained history to a paired device",
            )),
            // These return the session's current screen and the stream that follows it, which is
            // the live view the scope either includes or does not.
            Method::EventsSubscribe | Method::EventsSnapshot | Method::SessionAttach
                if !scope.include_live_screen =>
            {
                Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this device's grant does not include the session's live screen",
                ))
            }
            // Everything else returns metadata or an effect rather than session content. The
            // registry's filter is recorded here so a method added later is decided rather than
            // admitted by omission.
            _ => match entry.history_filter {
                HistoryFilter::NotApplicable
                | HistoryFilter::GrantLowerBound
                | HistoryFilter::LiveViewOnly
                | HistoryFilter::NamedCurrentResources => Ok(()),
            },
        }
    }
}

/// Returns whether one request claims or adds a geometry claim.
///
/// The condition on `terminal.geometry` is "when the request claims or adds a geometry claim", so
/// the request is what decides it. `session.attach` and `attachment.configure` both carry the flag
/// and the requested capability, and either one is a claim.
fn claims_geometry(mutation: &MutationRequest) -> bool {
    let kr_cbor::CanonicalValue::Map(map) = mutation.params.as_value() else {
        return false;
    };
    let claim = matches!(
        map.get("claim_geometry"),
        Some(kr_cbor::CanonicalValue::Bool(true))
    );
    let requested = match map.get("requested") {
        Some(kr_cbor::CanonicalValue::Array(items)) => items
            .iter()
            .any(|item| matches!(item, kr_cbor::CanonicalValue::Text(text) if text == "geometry")),
        _ => false,
    };
    claim || requested
}

/// Returns the session a request names, from the encoded parameters.
///
/// It is read out of the encoded parameters rather than through a typed shape of its own, because
/// the typed shape belongs to the subject: the daemon needs one field to decide which worker a
/// request goes to and which session its grant is checked against, and parsing the whole thing
/// here would mean two places that have to agree on every parameter of every method.
fn session_of(
    params: &ParamsValue,
    entry: &'static MethodEntry,
) -> std::result::Result<SessionId, ProtocolError> {
    let named = || {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{} names the session it acts on", entry.name),
        )
    };
    let kr_cbor::CanonicalValue::Map(map) = params.as_value() else {
        return Err(named());
    };
    let Some(kr_cbor::CanonicalValue::Bytes(bytes)) = map.get("session_id") else {
        return Err(named());
    };
    let bytes = <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| named())?;
    Ok(SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
        bytes,
    )))
}

/// Returns what one spawned effect settled as.
fn settled(
    request_id: RequestId,
    outcome: std::result::Result<Result<ParamsValue>, tokio::task::JoinError>,
) -> ControlFrame {
    match outcome {
        Ok(Ok(value)) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Ok(Err(error)) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error.to_protocol_error()),
        }),
        Err(_) => failure(request_id, outcome_unknown()),
    }
}

fn outcome_unknown() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        "this host could not report what happened to the action",
    )
}

fn failure(request_id: RequestId, error: ProtocolError) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Error(error),
    })
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
