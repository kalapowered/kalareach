//! Serving a local client: its hello, its window, its keepalive and the mutation it performs.

use std::sync::Arc;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::peer::PeerIdentity;
use kr_protocol::envelope::{ControlEvent, ControlFrame, MutationRequest, Outcome, Response};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId, RequestId};
use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_transport::window::MAX_WINDOW_VALIDITY;

use crate::error::{ControllerError, Result};

use super::authority_changes::declaration_answer;
use super::routes::LOCAL_PRINCIPAL_PREFIX;
use super::{Controller, error_reply, net, respond};

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

/// How long the loop that serves a local connection waits for the peer to take one frame it
/// writes without being asked: a keepalive or a replacement window.
///
/// The loop writes them between reads, so while it waits for the peer it reads nothing, and a
/// peer that has stopped reading would hold the connection for ever. Past this the connection
/// ends, as a failed write ends it. The same bound the daemon gives a worker's answer.
pub const LOCAL_WRITE_BOUND: std::time::Duration = super::workers::WORKER_EXCHANGE;

/// How often the loop that serves a local connection writes unasked, and how long it waits for the
/// peer to take what it writes.
#[derive(Clone, Copy, Debug)]
pub(super) struct LocalPace {
    renewal: std::time::Duration,
    keepalive: std::time::Duration,
    write_bound: std::time::Duration,
}

impl Default for LocalPace {
    fn default() -> Self {
        Self {
            renewal: WINDOW_RENEWAL,
            keepalive: LOCAL_KEEPALIVE,
            write_bound: LOCAL_WRITE_BOUND,
        }
    }
}

impl Controller {
    /// Makes this daemon's local connections write unasked at the pace given, and wait for their
    /// peer for `write_bound`, from the next connection on.
    #[cfg(feature = "testing")]
    pub fn pace_local_connections(
        &self,
        renewal: std::time::Duration,
        keepalive: std::time::Duration,
        write_bound: std::time::Duration,
    ) {
        *self
            .local_pace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = LocalPace {
            renewal,
            keepalive,
            write_bound,
        };
    }

    /// How many writes of a local connection's loop have had to wait for their peer.
    #[cfg(feature = "testing")]
    pub fn local_writes_blocked(&self) -> usize {
        self.local_writes_blocked
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The pace local connections write unasked at.
    fn local_pace(&self) -> LocalPace {
        #[cfg(feature = "testing")]
        {
            *self
                .local_pace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        #[cfg(not(feature = "testing"))]
        {
            LocalPace::default()
        }
    }

    /// Writes one frame the loop was not asked for, and says whether the connection goes on.
    ///
    /// The write waits for the peer for at most `bound`: a peer that has stopped reading is a
    /// connection that ends rather than one that holds its loop, and the frame it was part way
    /// through is not continued, because the connection goes with it. The wait is the one
    /// [`kr_ipc::framed::Writable`] gives a caller whose peer may stall, under a deadline of its
    /// own.
    async fn write_within(
        &self,
        writer: &mut kr_ipc::framed::FrameWriter,
        kind: StreamKind,
        frame: &ControlFrame,
        bound: std::time::Duration,
    ) -> bool {
        use kr_ipc::framed::{FrameWriter, Wrote};

        let Ok(bytes) = FrameWriter::encode(kind, frame) else {
            return false;
        };
        let written = async {
            let mut outcome = writer.begin_frame(&bytes)?;
            let mut waited = false;
            while outcome == Wrote::Blocked {
                if !waited {
                    waited = true;
                    #[cfg(feature = "testing")]
                    self.local_writes_blocked
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                writer.writable().ready().await?;
                outcome = writer.resume_frame()?;
            }
            kr_ipc::Result::Ok(())
        };
        matches!(tokio::time::timeout(bound, written).await, Ok(Ok(())))
    }

    /// Arms the pause the next call stops at once it has looked for a retained answer, whether or
    /// not it found one, before the admission it arrived under is asked again. Returns the end that
    /// says the call has arrived, and the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_retained_lookup(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.after_the_retained_lookup.arm()
    }

    /// Arms the pause the next network connection stops at once the transport has authorised it,
    /// before this host registers it. Returns the end that says the connection has arrived, and
    /// the end that lets it go. The pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_connection_registration(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        self.before_a_connection_is_registered.arm()
    }

    /// Answers an action this daemon has already admitted for this caller, if it has.
    ///
    /// The de-duplication key is the actor and the action together, and the payload digest decides
    /// whether it is the same action or a reused identifier. Only `session.create` has a retained
    /// record here; a close is retained by the worker that owns the session, which answers its own
    /// duplicates.
    pub(super) async fn retained(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
    ) -> Option<ControlFrame> {
        if matches!(method, Method::AgentToolsInstall | Method::AgentToolsRemove) {
            return self
                .retained_installation(actor_id, mutation, connection_id, admitted)
                .await;
        }
        // An authority change this host already holds a claim on is answered from it, here, before
        // freshness is asked for: its result, its refusal, that it is still running, or what this
        // host's records prove an attempt that ended unrecorded did. Section 9 keeps a receipt
        // readable after the window that admitted it has expired, and a retry of a revocation that
        // cannot reach its result would otherwise be told its window is gone rather than what
        // happened.
        if matches!(
            method,
            Method::GrantCreate
                | Method::GrantRevoke
                | Method::DeviceRevoke
                | Method::DevicePreviewKeyUpdate
                | Method::DeliveryDestinationSecretSet
                | Method::PrivacySet
                | Method::SessionRename
                | Method::DescriptionConfigure
                | Method::DescriptionDownload
                | Method::EnvironmentEnrol
                | Method::EnvironmentForget
                | Method::EnvironmentRefresh
        ) {
            return self.retained_authority_answer(actor_id, mutation).await;
        }
        // A machine group step is claimed in the same store and answered from it the same way, and
        // from the machine group record where an attempt ended without recording what it did.
        if matches!(
            method,
            Method::MachineJoin | Method::MachineMerge | Method::MachineSplit
        ) {
            return self.machine_retained(actor_id, mutation).await;
        }
        // A declaration of a device's keys is answered the same way, from the outcome the device
        // directory recorded beside the keys: a completion or a refusal alike, so a retry whose
        // reply was lost is told what happened rather than that its window is gone.
        if method == Method::DeviceKeysComplete {
            let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
            return match self
                .devices
                .recorded_declaration(actor_id, mutation.action_id)
            {
                Ok(Some(recorded)) => Some(respond(
                    mutation.request_id,
                    declaration_answer(mutation, &digest, recorded),
                )),
                Ok(None) => None,
                Err(error) => Some(respond(mutation.request_id, Err(error))),
            };
        }
        // A voice change is claimed in the same store and answered the same way: section 9 keeps
        // a receipt readable after the window that admitted it has expired, and a retry that
        // cannot reach its result would otherwise be told its window is gone rather than what
        // happened. A delegation is not here, because it does not go through that store.
        if crate::voice::VoiceModule::serves(method) && method != Method::VoiceDelegate {
            return match self.voice_answered(actor_id, mutation).await {
                Ok(Some(answered)) => Some(ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Ok(answered),
                })),
                Ok(None) => None,
                Err(error) => Some(respond(mutation.request_id, Err(error))),
            };
        }

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

    pub(super) fn acknowledgement(
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
            build: Some(kr_protocol::local::LocalBuild::this(self.build_id.clone())),
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
        self.deregister(connection_id);
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
        let actor_id = ActorId::new(format!("{LOCAL_PRINCIPAL_PREFIX}{}", peer.uid))
            .unwrap_or_else(|_| ActorId::new("local").expect("a valid principal"));
        let mut negotiated = false;
        // Where this connection's requests originally entered, when it is a process bridge's
        // helper and said so in its hello. Kept for the life of the connection and never replaced:
        // a connection says hello once.
        let mut origin: Option<kr_protocol::local::BridgeOrigin> = None;
        // Both timers fire once immediately; that first tick is consumed here so a connection is
        // not handed a replacement window before it has read the first one.
        let pace = self.local_pace();
        let mut renewal = tokio::time::interval(pace.renewal);
        renewal.tick().await;
        let mut keepalive = tokio::time::interval(pace.keepalive);
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
                    if !self.write_within(writer, kind, &renewed, pace.write_bound).await {
                        break;
                    }
                    continue;
                }
                _ = keepalive.tick(), if negotiated => {
                    let beat = ControlFrame::Event(ControlEvent::Keepalive);
                    if !self.write_within(writer, kind, &beat, pace.write_bound).await {
                        break;
                    }
                    continue;
                }
            };
            let reply = match frame {
                // A connection says hello once. Admitting it again would let a connection that
                // was admitted as a bridge's helper take its origin off, or a controller's
                // registration be replaced by a client's, so a second hello is answered and
                // changes nothing.
                ControlFrame::Hello(_) if negotiated => error_reply(
                    RequestId::new(0),
                    ErrorCode::UnsupportedSchema,
                    "this connection has already negotiated; open another one to change client",
                ),
                ControlFrame::Hello(hello) => {
                    // An origin is something only a bridge's helper has, and only for an
                    // invocation that was locally authenticated where it started. Anything else is
                    // refused here, on this side, whatever the helper checked before connecting.
                    if let Some(declared) = hello.origin.as_ref()
                        && (hello.client != kr_protocol::local::LocalClientKind::Cli
                            || !declared.is_admissible())
                    {
                        let refusal = error_reply(
                            RequestId::new(0),
                            ErrorCode::PermissionDenied,
                            "a process bridge carries locally authenticated invocations only, \
                             and only a command-line client may declare where one began",
                        );
                        let _ = writer.write_message(&refusal).await;
                        break;
                    }
                    // A peer that says it can hold no outstanding mutation at all is refused
                    // rather than quietly read as one. The worker's endpoint refuses the same
                    // offer, and a limit this host would then ignore is worse than a refusal.
                    if hello.max_receive.max_outstanding_mutations.get() == 0 {
                        let refusal = error_reply(
                            RequestId::new(0),
                            ErrorCode::InvalidArgument,
                            "a connection holds at least one outstanding mutation; offering none \
                             is not a limit this host serves",
                        );
                        let _ = writer.write_message(&refusal).await;
                        break;
                    }
                    if hello
                        .offered_versions
                        .iter()
                        .any(|offered| offered.major == PROTOCOL_VERSION.major)
                    {
                        // Validating the caller's record and registering the connection in the
                        // authority store happen together, under the store's own lock, so a
                        // revocation cannot land between the two and leave a connection admitted
                        // under authority that has already been withdrawn.
                        match self
                            .admit_connection(connection_id, &actor_id, peer, hello.client)
                            .await
                        {
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
                        origin = hello.origin;
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
                ControlFrame::Request(request)
                    if negotiated
                        && request
                            .method
                            .method()
                            .is_some_and(crate::attention::AttentionModule::serves) =>
                {
                    // The attention store's reads carry session text, which leaves this daemon only
                    // under the text's privacy fence: its ticket is checked before every write.
                    match self.authorised(connection_id) {
                        Ok(_) => {
                            let released = self
                                .attention
                                .read_released(
                                    self.attention_reach().as_ref(),
                                    &crate::attention::Caller::Owner,
                                    &actor_id,
                                    &request,
                                )
                                .await;
                            match self.authorised(connection_id) {
                                Ok(_) => {
                                    if self
                                        .attention
                                        .write_released(writer, kind, released)
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    continue;
                                }
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
                ControlFrame::Request(request) if negotiated => {
                    match self.authorised(connection_id) {
                        Ok(_) => {
                            let answer = self.read_method(&actor_id, &request).await;
                            // Checked again now the read has finished. A read that passed its check
                            // and then waited for the registry can complete after the authority
                            // behind it was withdrawn, and what the contract forbids is *serving*
                            // that state rather than reading it.
                            match self.authorised(connection_id) {
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
                    let reply = self
                        .perform(&actor_id, connection_id, origin, *mutation)
                        .await;
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
    pub(super) async fn perform(
        self: &Arc<Self>,
        actor_id: &ActorId,
        connection_id: ConnectionId,
        origin: Option<kr_protocol::local::BridgeOrigin>,
        mutation: MutationRequest,
    ) -> ControlFrame {
        // Receipt time, recorded before anything this daemon then waits for. Section 9 measures a
        // requested lifetime from when the request arrived, and the retained lookup below takes
        // the registry lock: sampling the clock after it would hand the request its whole lifetime
        // back after the wait.
        let received_at = self.clock.now();
        if let Err(error) = self.authorised(connection_id) {
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
        //
        // Every store that retains an action here is asked in turn, and whichever answers, the
        // answer passes through the same guard. Finding a retained action takes a lock and can
        // wait for a blocking thread; what the contract forbids is *disclosing* a retained result
        // under authority that has since been withdrawn, so the check belongs where the answer is
        // about to be written rather than only where the lookup began.
        // The authority revision this mutation is admitted under, read here: beside the
        // registration check above and before the first thing this daemon waits for. The network
        // ingress reads its own in the same critical section as that check, and the two doors have
        // to agree. A revocation of somebody else's device advances the revision and leaves every
        // surviving registration stamped with the new one, so a door that read the revision after
        // a retained lookup, a lock or a task being scheduled would admit a mutation under an
        // authority the other door refuses the same mutation under. A retained answer is checked
        // against it, and so is every effect this door performs.
        let admitted = self.admitted_revision(connection_id).ok();
        let mut retained = self
            .retained(actor_id, &mutation, method, connection_id, admitted)
            .await;
        if retained.is_none() && crate::transfer::TransferModule::serves(method) {
            retained = self.transfer.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::project::ProjectModule::serves(method) {
            retained = self.project.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::catalogue::CatalogueModule::serves(method) {
            retained = self.catalogue.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::changeset::ChangeSetModule::serves(method) {
            retained = self.changesets.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::automation::AutomationModule::serves(method) {
            retained = self.automation.retained(actor_id, &mutation, method).await;
        }
        if retained.is_none() && crate::attention::AttentionModule::serves(method) {
            retained = self.attention.retained(actor_id, &mutation, method);
        }
        if retained.is_none() && net::methods::serves(method) {
            retained = self
                .pairing_retained(
                    net::owner::Caller::local(actor_id.clone()),
                    method,
                    &mutation,
                )
                .await
                .map(|outcome| respond(mutation.request_id, outcome));
        }
        #[cfg(feature = "testing")]
        self.after_the_retained_lookup.wait().await;
        if let Some(retained) = retained {
            if let Err(error) = self.check_retained_answer(connection_id, admitted) {
                return error_reply(mutation.request_id, error.code(), error.to_string());
            }
            return retained;
        }
        let accepted = match self.check_envelope(connection_id, &mutation, method, received_at) {
            Ok(accepted) => Some(accepted),
            // A window that admits nothing says nothing about an action the host may already
            // hold. Section 9 keeps a receipt readable after the freshness that admitted it is
            // gone, and for a mutation this daemon forwards, the worker that owns the session is
            // the only thing that knows whether it holds one. So the mutation goes on with no
            // freshness at all: a retry finds its receipt there, and a first admission is refused
            // there for the same reason it would have been refused here.
            Err(ControllerError::WindowExpired { .. }) if forwarded_to_worker(method) => None,
            // The same holds for an exact repeat of a transfer action that claimed an effect and
            // was interrupted before it settled. The repeat is the original request, window
            // included, and on a replacement connection that window is not one this connection
            // issued. The service finishes what the claim began and begins nothing.
            Err(error @ ControllerError::WindowExpired { .. })
                if crate::transfer::TransferModule::serves(method) =>
            {
                match self.transfer.settles(actor_id, &mutation, method).await {
                    crate::transfer::Settling::Open => None,
                    // The claim was settled between the lookup above and this one, by another copy
                    // of the action or by the sweep: what it recorded is the answer, under the
                    // check any retained answer is owed.
                    crate::transfer::Settling::Answered(answer) => {
                        if let Err(error) = self.check_retained_answer(connection_id, admitted) {
                            return error_reply(
                                mutation.request_id,
                                error.code(),
                                error.to_string(),
                            );
                        }
                        return answer;
                    }
                    crate::transfer::Settling::No => {
                        return ControlFrame::Response(Response {
                            request_id: mutation.request_id,
                            outcome: Outcome::Error(error.to_protocol_error()),
                        });
                    }
                }
            }
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
                .write_method(
                    &actor_id,
                    &mutation,
                    method,
                    connection_id,
                    origin,
                    accepted,
                    admitted,
                )
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

    /// Returns the answer a retained installation action is owed.
    ///
    /// It runs before first-admission freshness, like every other retained action: a caller that
    /// reconnects and asks again about work it already submitted must get its own result rather
    /// than a refusal about a window that has since been replaced.
    async fn retained_installation(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
    ) -> Option<ControlFrame> {
        let installer = self.installer().ok()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let _admission = self.agent_tools.lock().await;
        // Waiting for that lock takes time, and a retained result is a read of somebody's action.
        // Section 9 checks current authority before returning one, so it is checked after the wait
        // rather than before it.
        if let Err(error) = self.check_retained_answer(connection_id, admitted) {
            return Some(respond(mutation.request_id, Err(error)));
        }
        match installer.retained(actor_id, mutation.action_id, &digest) {
            Ok(Some(result)) => Some(ControlFrame::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(result),
            })),
            Ok(None) => None,
            Err(error) => Some(respond(mutation.request_id, Err(error))),
        }
    }
}

/// Returns whether this daemon forwards the method to the worker that owns the session.
///
/// It decides what a window refusal means. A mutation this daemon performs itself has its
/// retained action here, and a window that admits nothing has already been past it; one it
/// forwards has its retained action in the worker's journal, which only the worker can read.
const fn forwarded_to_worker(method: Method) -> bool {
    matches!(
        method,
        Method::SessionClose | Method::AgentPromptSubmit | Method::AgentPromptQueue
    )
}
