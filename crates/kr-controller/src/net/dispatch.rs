//! Serving one authorised remote connection.
//!
//! Everything a paired device asks for passes through here, and the order is the contract:
//!
//! 1. **The registry decides.** `ConnectionActor::admit` resolves the method against the authority
//!    table at the *paired-device* ingress, so a method kept to private IPC is unreachable however
//!    broad the device's grant is, and no mutation is admitted in 0-RTT.
//! 2. **The registration decides.** The connection's registration in the daemon's authority store
//!    is checked before the request is served and again before its answer is written. That is the
//!    fence a revocation sets: section 9's dispatch barrier covers a worker's dispatch, and this
//!    covers a read or a subscription on a connection that was authorised a moment earlier.
//! 3. **The grant decides.** The rights the method requires are checked against the grant the
//!    device holds, at the revision it was issued under, against the environment and session its
//!    selectors admit and against its expiry.
//! 4. **The window decides.** A mutation's accepted deadline is the earliest of what its action
//!    window has left, receipt time plus the requested lifetime, and the dispatch lease's own
//!    remaining time.
//! 5. **The subject acts.** The daemon performs what it owns; everything else is forwarded to the
//!    worker that owns the session, under the verified envelope and the accepted deadline, through
//!    the same serial barrier a local caller's mutation passes through.
//!
//! Two things outlive the connection on purpose. A mutation's effect runs on its own task, so a
//! durable commit is never left half done because a peer went away; and the attachments a
//! connection created are detached by a task that runs after it, so a device that disappears does
//! not leave its attachment holding the session's geometry.

use std::sync::Arc;

use kr_protocol::actor::ActorEnvelope;
use kr_protocol::authority::{EffectClass, MethodEntry, RequiredAuthority, RightCondition};
use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ConnectionId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_transport::actor::ConnectionActor;
use kr_transport::listener::AuthorisedSession;
use kr_transport::window::AcceptedDeadline;

use super::devices::DeviceRecord;
use super::proxy::WorkerProxy;
use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// What one authorised remote connection is serving.
pub struct RemoteConnection {
    controller: Arc<Controller>,
    /// The device this connection belongs to, as the record stood when it was admitted.
    device: DeviceRecord,
    actor: ConnectionActor,
    connection_id: ConnectionId,
    /// This connection's own link to the worker it has attached to, opened on first use.
    proxy: tokio::sync::Mutex<Option<Arc<WorkerProxy>>>,
    /// Where a notification the proxy read is written.
    notifications: tokio::sync::mpsc::Sender<kr_protocol::envelope::Notification>,
    windows: Arc<kr_transport::window::ActionWindowIssuer>,
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
        notifications: tokio::sync::mpsc::Sender<kr_protocol::envelope::Notification>,
    ) -> Self {
        Self {
            controller,
            device,
            actor: session.actor.clone(),
            connection_id: session.connection_id,
            proxy: tokio::sync::Mutex::new(None),
            notifications,
            windows: Arc::clone(&session.windows),
        }
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
        if entry.effect != EffectClass::Read {
            // Every write travels as a mutation, because a write needs an action identity and a
            // freshness context. Raw input is the one exception the protocol names, and its entry
            // is what says so.
            if entry.method != Method::InputWrite {
                return failure(
                    request.request_id,
                    ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        format!("{} is a mutation and carries an action", entry.name),
                    ),
                );
            }
        }
        // The grant decides for a read as much as for a mutation. A read is where a grant that
        // does not cover this environment, this session or this right is most easily overlooked,
        // because there is no action identity to make it look like an effect.
        if let Err(error) = self.check_grant(session_of(&request.params, entry).ok(), entry) {
            return failure(request.request_id, error);
        }
        let answer = match entry.method {
            Method::HostInfo
            | Method::EnvironmentList
            | Method::HostDoctor
            | Method::SessionList
            | Method::SessionRead => self.controller.read_method(request).await,
            Method::EventsSubscribe
            | Method::EventsSnapshot
            | Method::HistoryPage
            | Method::ActionRead
            | Method::InputWrite => self.proxied_read(request, entry).await,
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
        // A retained action is answered before anything about a first admission is considered.
        // Applying the freshness window to a retry would refuse a caller its own completed result
        // because the window it was admitted under has since been replaced.
        let actor_id = self.device.principal();
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
                let actor_id = actor_id.clone();
                let request_id = mutation.request_id;
                let effect = tokio::spawn(async move {
                    controller
                        .session_create(&actor_id, &mutation, accepted)
                        .await
                });
                match effect.await {
                    Ok(outcome) => respond(request_id, outcome),
                    Err(_) => failure(
                        request_id,
                        ProtocolError::new(
                            ErrorCode::OutcomeUnknown,
                            "this host could not report what happened to the action",
                        ),
                    ),
                }
            }
            Method::SessionClose => {
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let envelope = self.envelope();
                let request_id = mutation.request_id;
                let effect = tokio::spawn(async move {
                    controller
                        .session_close(&mutation, &envelope, accepted)
                        .await
                });
                match effect.await {
                    Ok(outcome) => respond(request_id, outcome),
                    Err(_) => failure(
                        request_id,
                        ProtocolError::new(
                            ErrorCode::OutcomeUnknown,
                            "this host could not report what happened to the action",
                        ),
                    ),
                }
            }
            // Everything else belongs to the worker that owns the session.
            _ => self.proxied_mutation(mutation, accepted).await,
        }
    }

    /// Forwards one read to the worker that owns the session it names.
    async fn proxied_read(&self, request: &Request, entry: &'static MethodEntry) -> ControlFrame {
        let session_id = match session_of(&request.params, entry) {
            Ok(session_id) => session_id,
            Err(error) => return failure(request.request_id, error),
        };
        let proxy = match self.proxy_for(session_id).await {
            Ok(proxy) => proxy,
            Err(error) => return failure(request.request_id, error.to_protocol_error()),
        };
        match proxy.forward_read(request, &self.envelope()).await {
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
        let envelope = self.envelope();
        let deadline = match self
            .controller
            .forwarded_deadline(session_id, &envelope, accepted)
            .await
        {
            Ok(deadline) => deadline,
            Err(error) => return failure(mutation.request_id, error.to_protocol_error()),
        };
        // The effect runs on a task that outlives this connection, for the same reason the
        // daemon's own effects do: the worker has committed the intent by the time it answers, and
        // a cancellation here must not be what decides whether the outcome is recorded.
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
            Err(_) => failure(
                request_id,
                ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "this host could not report what happened to the action",
                ),
            ),
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
            if proxy.session_id() == session_id {
                return Ok(Arc::clone(proxy));
            }
            return Err(ControllerError::InvalidArgument(
                "this connection is already serving another session; open another connection"
                    .to_owned(),
            ));
        }
        let proxy = self
            .controller
            .open_proxy(session_id, self.notifications.clone())
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
    /// generation that admitted it.
    fn envelope(&self) -> ActorEnvelope {
        self.actor.envelope(Some((
            self.device.grant.grant_id,
            self.device.grant.authority_revision,
        )))
    }

    /// Resolves one method against the registry at this connection's ingress.
    fn admit(
        &self,
        method: &str,
        version: kr_protocol::method::MethodVersion,
    ) -> std::result::Result<&'static MethodEntry, ProtocolError> {
        self.actor.admit(method, version)
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
        self.check_grant(mutation.target.session_id.as_ref().copied(), entry)?;
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
                None,
            )
            .map_err(|refusal| {
                ProtocolError::new(ErrorCode::PermissionDenied, window_refusal_detail(refusal))
            })
    }

    /// Checks the grant this device holds against what the method requires.
    ///
    /// What is checked here is what a grant on its own can answer: the rights it carries, the
    /// environment and session its selectors admit, and whether it has expired. A requirement that
    /// depends on the resolved subject — resource ownership, present view authority, a local
    /// caller's token — is the subject's to answer, and the worker answers it inside its own
    /// dispatch barrier where the subject cannot move.
    fn check_grant(
        &self,
        session_id: Option<SessionId>,
        entry: &'static MethodEntry,
    ) -> std::result::Result<(), ProtocolError> {
        let grant = &self.device.grant;
        if !grant.expiry.is_valid_at(kr_ipc::now_ms().get()) {
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
            if required.when != RightCondition::Always {
                continue;
            }
            if let RequiredAuthority::Right { right } = required.authority
                && !grant.permits(right)
            {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    format!("this device's grant does not carry {}", right.as_str()),
                ));
            }
        }
        Ok(())
    }
}

/// Returns the session a proxied read names.
///
/// It is read out of the encoded parameters rather than through a typed shape of its own, because
/// the typed shape belongs to the worker: the daemon needs one field to decide which worker the
/// read goes to, and parsing the whole thing here would mean two places that have to agree on
/// every parameter of every read.
fn session_of(
    params: &kr_protocol::envelope::ParamsValue,
    entry: &'static MethodEntry,
) -> std::result::Result<SessionId, ProtocolError> {
    let named = || {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{} names the session it reads", entry.name),
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

fn respond(
    request_id: RequestId,
    outcome: Result<kr_protocol::envelope::ParamsValue>,
) -> ControlFrame {
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
