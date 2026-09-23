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
use super::proxy::{RELAY_QUEUED_BYTES, RelayBudget, Relayed, Vouched, WorkerProxy};
use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// Why a claim on an action's identity did not succeed.
///
/// The two are answered differently. A conflict is this host's answer about the action: section 9
/// makes a reused identifier carrying a different payload `ID_CONFLICT`, and nothing is dispatched
/// under it. Storage being unavailable says nothing about the action, and section 7 does not let a
/// storage failure stop an authorised stop, so a close goes on without its route while every other
/// mutation is refused.
enum RouteRefusal {
    Conflict(ProtocolError),
    Unavailable(ProtocolError),
}

impl RouteRefusal {
    fn into_error(self) -> ProtocolError {
        match self {
            Self::Conflict(error) | Self::Unavailable(error) => error,
        }
    }
}

/// The QUIC application error code a withdrawn connection is closed with.
pub const WITHDRAWN: u32 = 4;

/// How long a caller waits for an effect the daemon owns before it is told the outcome is unknown.
///
/// The effect runs on a task that outlives the connection, so this bounds what the *caller* waits
/// for rather than the work: a device holding a request slot for a session that has stopped
/// answering is told, and the effect goes on to whatever end it reaches.
pub const EFFECT_WAIT: std::time::Duration = std::time::Duration::from_secs(45);

/// How often a waiting write asks whether the authority behind it still stands.
///
/// It bounds how long a frame can sit waiting for a peer after the authority that admitted it went
/// away. Nothing polls while nothing is waiting.
pub const AUTHORITY_POLL: std::time::Duration = std::time::Duration::from_millis(100);

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
    /// Who is waiting to hear that one answer reached the device, by the request it answers.
    ///
    /// A close is the reason this exists: the worker holds the session's termination until the
    /// acceptance has been delivered, and whatever released that hold has to know the device
    /// actually has the acceptance. A waiter whose connection goes learns it from the sender being
    /// dropped with the connection.
    delivery:
        std::sync::Mutex<std::collections::BTreeMap<RequestId, tokio::sync::oneshot::Sender<()>>>,
    sender: ControlSender,
    connection: iroh::endpoint::Connection,
    /// The authority this connection writes under, read inside the turn.
    ///
    /// The latch above is what a *device* revocation sets. An authority revision the daemon
    /// advances for another reason withdraws the registration without touching this connection, so
    /// the registration itself is read here as well: either way, no frame begins on a connection
    /// whose authority has gone.
    authority: Arc<Authorisation>,
}

/// Records a grant's expiry for work that outlives the connection which admitted it.
///
/// An action can be admitted under the grant's own deadline and then wait: for a lock, for a
/// worker, for a link. The task that finds nothing left of that deadline is the one that observed
/// the grant running out, and section 9 wants that written down wherever it is seen. It is not the
/// same observation as a window or a requested lifetime running out, which say nothing about the
/// grant, so only the authority deadline reaches this.
#[derive(Clone, Debug)]
pub struct ExpiryObserver(Arc<Authorisation>);

impl ExpiryObserver {
    /// Records this grant's expiry, when the grant has in fact run out.
    ///
    /// A deadline that could not be forwarded is not evidence about the grant: a lease that was
    /// refused, an acknowledgement that never came, a window that ran out first. The grant's own
    /// anchored deadline is the evidence, and it is the only thing consulted here.
    pub fn grant_expired(&self) {
        if !self.0.has_time_left() {
            self.0.note_expiry();
        }
    }
}

/// What a connection must still hold for a frame to be written on it.
#[derive(Debug)]
struct Authorisation {
    controller: Arc<Controller>,
    /// Where an observed expiry is written, so the decision outlives this connection.
    devices: Arc<super::devices::DeviceDirectory>,
    /// What this host owes its directory, for an expiry whose write did not succeed here.
    pending: Arc<super::devices::PendingExpiry>,
    /// The boundary every reading of this host's wall clock takes.
    clock: Arc<super::devices::ClockTrust>,
    device_id: DeviceId,
    connection_id: ConnectionId,
    /// When this connection's grant runs out, on the continuous clock.
    ///
    /// Anchored once, when the connection was admitted, from what the wall clock then said was
    /// left. A wall clock stepped afterwards cannot lengthen it, and the continuous clock is the
    /// one every other deadline on this host is measured on.
    grant_deadline: Option<kr_transport::clock::ContinuousInstant>,
    /// Set the first time the grant is found to have run out. It never comes back.
    expired: AtomicBool,
    /// Set once the expiry above has been written down, so it is written once.
    recorded: AtomicBool,
}

impl Authorisation {
    /// Returns whether this connection may still be served.
    async fn stands(&self) -> bool {
        if !self.has_time_left() {
            self.note_expiry();
            return false;
        }
        self.controller.authorised(self.connection_id).is_ok()
    }

    /// Returns whether this connection's grant still has time on it.
    ///
    /// Nothing but a clock read and two atomics, because this is also what decides at every
    /// attempt to write a frame: a decision made inside a poll cannot wait on a lock or a
    /// database. Writing the expiry down is [`Self::note_expiry`], which the checks that can
    /// afford it call.
    /// Records that this grant has run out, and writes it down.
    ///
    /// For a caller that established the expiry some other way than by reading the deadline here:
    /// the latch is what makes it an observation rather than a fence for another reason.
    fn expire(&self) {
        self.expired.store(true, Ordering::Release);
        self.note_expiry();
    }

    fn has_time_left(&self) -> bool {
        if self.expired.load(Ordering::Acquire) {
            return false;
        }
        let Some(deadline) = self.grant_deadline else {
            return true;
        };
        if self.controller.clock.now() < deadline {
            return true;
        }
        self.expired.store(true, Ordering::Release);
        false
    }

    /// Hands an expiry this connection has observed to the host, and tries to write it.
    ///
    /// The record is what makes the decision outlive this connection: the grant's expiry is a UTC
    /// moment, and a later boot would read it against a wall clock that can be stepped backwards.
    /// Section 9 does not let withdrawn authority come back, so every observation is handed over,
    /// whichever check made it, against a UTC moment that never goes earlier than the latest this
    /// host has recorded. What the host holds it does not lose: a write that fails here is retried
    /// by the host's own task, which outlives this connection.
    ///
    /// Only an expiry something actually observed is written. A connection can be fenced for
    /// reasons that have nothing to do with its grant's lifetime - a device revocation, an
    /// authority revision - and writing a tombstone for one of those would end a grant that had
    /// years left on it.
    fn note_expiry(&self) {
        if !self.expired.load(Ordering::Acquire) {
            return;
        }
        if !self.recorded.swap(true, Ordering::AcqRel) {
            // Through the boundary, like every other reading of this clock: a rollback observed
            // while writing a tombstone is the same fact as one observed anywhere else, and it
            // becomes this host's decision about its clock rather than a number nobody kept.
            let now = self
                .clock
                .observe(&self.devices)
                .unwrap_or_else(|_| kr_ipc::now_ms());
            self.pending.owe(self.device_id, now);
        }
        // Written here when it can be, so the ordinary case costs nothing but this call.
        self.pending.settle(&self.devices);
    }
}

impl RemoteOutput {
    fn new(session: &AuthorisedSession, authority: Arc<Authorisation>) -> Self {
        Self {
            turn: tokio::sync::Mutex::new(()),
            withdrawn: AtomicBool::new(false),
            delivery: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            sender: session.control.sender(),
            connection: session.connection.clone(),
            authority,
        }
    }

    /// Sends one frame, and returns whether it was sent.
    ///
    /// The authority is read at every attempt to put bytes on the stream, not once before the
    /// wait for one:
    ///
    /// * The turn keeps this connection's frames in order, one at a time.
    /// * The writer is shared with the keepalive and the window renewal, so a frame can wait for
    ///   it. The fence is read after it has been taken.
    /// * A frame that has the writer can still wait for the peer to make room. The fence is read
    ///   in the same poll as each attempt to hand bytes over, so no byte goes under authority that
    ///   went while the frame waited. An abandoned frame leaves the stream in pieces, which is
    ///   exactly right for a connection being fenced: the connection is closed with it.
    /// * The registration cannot be read from a poll, so it is read here, by every request, and by
    ///   the watch below. A revocation that withdraws one closes the connection itself, which is
    ///   what stops a frame that is already waiting.
    pub async fn send(&self, frame: &ControlFrame) -> bool {
        let _turn = self.turn.lock().await;
        if self.has_withdrawn() {
            return false;
        }
        if !self.fence() {
            // Outside the poll, where a durable write belongs: the fence itself only reads the
            // clock, and an expiry it observed has to be written down by something that can.
            self.authority.note_expiry();
            self.withdraw();
            return false;
        }
        let fence = || self.fence();
        let written = tokio::select! {
            written = self.sender.send_while(frame, &fence) => written,
            () = self.authority_lost() => {
                self.withdraw();
                return false;
            }
        };
        match written {
            Ok(true) => {
                self.delivered(frame);
                true
            }
            // Refused at the boundary: the authority this connection writes under has gone, so the
            // connection goes with it rather than waiting to be asked for something else.
            Ok(false) => {
                self.authority.note_expiry();
                self.withdraw();
                false
            }
            Err(_) => false,
        }
    }

    /// Says who wants to hear that the answer to `request_id` reached the device.
    ///
    /// The sender goes with this connection, so a waiter whose device disconnected is told at once
    /// rather than left waiting for a frame nothing is going to write.
    pub fn on_delivery(&self, request_id: RequestId, tell: tokio::sync::oneshot::Sender<()>) {
        self.delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id, tell);
    }

    /// Tells whoever was waiting that this frame has been written.
    ///
    /// Only an answer that carries a result counts. A refusal or an unknown outcome is not an
    /// acceptance, and whatever is waiting for one is left to its own bound rather than told that
    /// something arrived which the device cannot act on.
    fn delivered(&self, frame: &ControlFrame) {
        let request_id = match frame {
            ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Ok(_),
            }) => *request_id,
            ControlFrame::Receipt(receipt) => receipt.request_id,
            _ => return,
        };
        let waiting = self
            .delivery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id);
        if let Some(waiting) = waiting {
            let _ = waiting.send(());
        }
    }

    /// Returns whether a byte of a frame may go on this connection at this instant.
    ///
    /// Synchronous on purpose: it is evaluated inside the poll that hands bytes to the stream, so
    /// no byte is accepted without it having just held. The latch is what a device revocation sets
    /// and what a withdrawn registration sets through [`Self::withdraw`]; the grant covers its own
    /// expiry. The registration itself is read by the checks that can wait, which is every request
    /// and the watch below.
    fn fence(&self) -> bool {
        !self.has_withdrawn() && self.authority.has_time_left()
    }

    /// Resolves once this connection stops being one this host may write to.
    ///
    /// It polls, because the daemon's own revocation path withdraws a registration without
    /// knowing which network connections hold it, and a grant runs out on a clock rather than on
    /// an event. The interval only matters while a write is waiting, which is the only time
    /// anything is watching.
    async fn authority_lost(&self) {
        loop {
            tokio::time::sleep(AUTHORITY_POLL).await;
            if self.has_withdrawn() || !self.authority.stands().await {
                return;
            }
        }
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
    /// This host's device directory, which also records where each action was dispatched.
    devices: Arc<super::devices::DeviceDirectory>,
    /// The device this connection belongs to, as the record stood when it was admitted.
    device: DeviceRecord,
    actor: ConnectionActor,
    connection_id: ConnectionId,
    output: Arc<RemoteOutput>,
    authority: Arc<Authorisation>,
    /// This connection's own link to the worker it has attached to, opened on first use.
    proxy: tokio::sync::Mutex<Option<Arc<WorkerProxy>>>,
    /// Where a notification the proxy read is written.
    notifications: tokio::sync::mpsc::Sender<Relayed>,
    /// What this connection has queued for the device and not yet had written.
    budget: Arc<RelayBudget>,
    /// Notified when this connection's link to its worker ends, whichever way it ends.
    lost: Arc<tokio::sync::Notify>,
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
        records: super::devices::HostRecords,
        device: DeviceRecord,
        session: &AuthorisedSession,
        notifications: tokio::sync::mpsc::Sender<Relayed>,
        grant_deadline: Option<kr_transport::clock::ContinuousInstant>,
    ) -> Self {
        let authority = Arc::new(Authorisation {
            grant_deadline,
            controller: Arc::clone(&controller),
            device_id: device.device_id,
            devices: Arc::clone(&records.devices),
            pending: Arc::clone(&records.pending),
            clock: Arc::clone(&records.clock),
            connection_id: session.connection_id,
            expired: AtomicBool::new(false),
            recorded: AtomicBool::new(false),
        });
        Self {
            controller,
            devices: Arc::clone(&records.devices),
            device,
            actor: session.actor.clone(),
            connection_id: session.connection_id,
            output: Arc::new(RemoteOutput::new(session, Arc::clone(&authority))),
            authority,
            proxy: tokio::sync::Mutex::new(None),
            notifications,
            // What this connection said it could receive, never more than the protocol's own
            // bound: a peer that offered a smaller send queue is held to what it offered.
            budget: Arc::new(RelayBudget::new(
                usize::try_from(session.selection.limits.max_send_queue_bytes.get())
                    .unwrap_or(RELAY_QUEUED_BYTES)
                    .min(RELAY_QUEUED_BYTES),
            )),
            lost: Arc::new(tokio::sync::Notify::new()),
            windows: Arc::clone(&session.windows),
        }
    }

    /// Returns what records this device's grant expiry, for work that outlives this connection.
    #[must_use]
    pub fn expiry_observer(&self) -> ExpiryObserver {
        ExpiryObserver(Arc::clone(&self.authority))
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
    /// The deadline was anchored on the continuous clock when the connection was admitted, and
    /// once it has passed it stays passed: a wall clock stepped backwards revives nothing.
    pub fn grant_is_current(&self) -> bool {
        if self.authority.has_time_left() {
            return true;
        }
        self.authority.note_expiry();
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
            | ControlFrame::RetainedResponse(_)
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
        // must stop it, and a read that is refused must not have reached the subject first. The
        // revision comes from the same critical section, so a request can never be stamped with a
        // revision the registration was not still standing at.
        let validated = match self.admitted_at().await {
            Ok(validated) => validated,
            Err(error) => return failure(request.request_id, error),
        };
        let named = session_of(&request.params, entry).ok();
        // A read never claims geometry: the condition on `terminal.geometry` is about a request
        // that claims or adds a claim, and only a mutation does either.
        if let Err(error) = self.check_grant(named, entry, false) {
            return failure(request.request_id, error);
        }
        // The daemon's own reads are served as this device, not as the daemon: a module that keeps
        // its own subjects decides them against the actor that asked, and a read served under the
        // host's own principal would be answered about the host's own objects.
        let actor_id = self.device.principal();
        let answer = match entry.method {
            // `host.info` carries this host's sleep inhibition and the reason for it, and
            // `environment.capabilities` carries the desktop's capability records with their
            // platform distinctions. Both are the daemon's own answer, and a device is given the
            // answer the owner's own socket is given: capability evidence describes feasibility
            // and never authority, so narrowing it would say something untrue about the machine
            // rather than protect anything.
            Method::HostInfo
            | Method::EnvironmentList
            | Method::EnvironmentCapabilities
            | Method::HostDoctor => self.controller.read_method(&actor_id, request).await,
            // The project and workspace metadata reads. They name no session, so the grant's
            // environment selector and the rights the registry lists are the whole of what
            // narrows them, and the service answers a device exactly as it answers this user's
            // own client.
            Method::ProjectList
            | Method::ProjectRead
            | Method::WorkspaceList
            | Method::WorkspaceRead => self.controller.read_method(&actor_id, request).await,
            // The daemon answers these itself, and what it answers with is narrowed to the grant:
            // a list is every session this actor may observe, not every session this host runs.
            Method::SessionList | Method::SessionRead => {
                let answer = self.controller.read_method(&actor_id, request).await;
                self.narrow(answer)
            }
            Method::EventsSubscribe
            | Method::EventsSnapshot
            | Method::HistoryPage
            | Method::ActionRead
            | Method::InputWrite => self.proxied_read(request, entry, validated).await,
            // The voice coordinator's own read. It runs on this host rather than on a worker: the
            // selection is built from what this daemon holds about the session, filtered under
            // this device's own grant, and what comes back goes to this device and nowhere else.
            Method::VoiceContext => {
                self.controller
                    .voice()
                    .read_frame(
                        self.device.device_id,
                        request,
                        super::super::wall_clock_ms(),
                    )
                    .await
            }
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
        // Section 9 measures a requested lifetime from *receipt* time, so it is read here, before
        // the first thing that can wait. Everything between this and the envelope check can take
        // time — the registry's lock, a retained lookup, a worker's answer about a receipt — and
        // deriving the deadline from a reading taken after those waits would hand a request its
        // whole lifetime back after it had already spent part of it.
        let received_at = self.controller.clock.now();
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
        // returns a retained receipt. The revision it is stamped with comes from the same critical
        // section as that check.
        let validated = match self.admitted_at().await {
            Ok(validated) => validated,
            Err(error) => return failure(mutation.request_id, error),
        };
        // A retained action is answered before anything about a first admission is considered.
        // Applying the freshness window to a retry would refuse a caller its own completed result
        // because the window it was admitted under has since been replaced. Its authority is
        // checked above, and the grant below, because an authority that has gone does not entitle
        // a caller to a result it once produced.
        let actor_id = self.device.principal();
        if let Err(error) = self.check_grant(
            mutation.target.session_id.as_ref().copied(),
            entry,
            claims_geometry(mutation),
        ) {
            return failure(mutation.request_id, error);
        }
        // Every store that retains an action is asked in turn, in the order the local ingress asks
        // them: the daemon's own reservations first, then the project service's own record. A
        // project mutation's receipt lives with the project service, so a retry of one that lost
        // its reply is answered there rather than dispatched again.
        let mut held = self
            .controller
            .retained(&actor_id, mutation, entry.method, self.connection_id)
            .await;
        if held.is_none() && crate::project::ProjectModule::serves(entry.method) {
            held = self
                .controller
                .project
                .retained(&actor_id, mutation, entry.method)
                .await;
        }
        if let Some(retained) = held {
            // The daemon's own retained answer is a read of what an earlier submission produced,
            // and a create's names the session it made. Section 23 wants present view authority
            // over that subject before either half of a retained result goes back, and the subject
            // is in the answer rather than in the request.
            if let Err(error) = self.may_read_receipts(answered_session(&retained)) {
                return failure(mutation.request_id, error);
            }
            return retained;
        }
        // A worker holds the receipts of its own actions, and the route says which worker. Section
        // 9 has an existing receipt readable under current authority after the window that
        // admitted it has expired, and answers a duplicate from a still-authorised actor from that
        // receipt without dispatching anything: so the receipt is asked for before the window is
        // considered, and a reused identifier carrying a different payload is refused here.
        match self.retained_remotely(mutation, validated).await {
            Ok(Some(answered)) => return answered,
            Ok(None) => {}
            // Storage that cannot say whether this action has been dispatched says nothing about
            // the action. Section 7 does not let that stop an authorised stop, so a close goes on
            // and reports whatever durability it then had; anything else is refused.
            //
            // What a close then loses is this host's own check of `action.read` over the session,
            // because it is the route that would have said the close is a resubmission. The
            // worker's journal still decides idempotently, so a second close can come back from
            // the receipt the first produced. What that returns is the outcome of this device's
            // own close on a session its grant admits closing, and nothing else travels with it,
            // so the stop is allowed to happen and the narrower check is the one that gives way.
            Err(RouteRefusal::Unavailable(error)) => {
                if entry.method != Method::SessionClose {
                    return failure(mutation.request_id, error);
                }
            }
            Err(RouteRefusal::Conflict(error)) => return failure(mutation.request_id, error),
        }
        let accepted = match self.check_envelope(mutation, entry, received_at) {
            Ok(accepted) => accepted,
            Err(error) => return failure(mutation.request_id, error),
        };
        // The last check this connection's own turn makes before the effect is admitted. It
        // guarantees nothing about what happens next: it releases the connection table before it
        // returns, a revocation runs on a task of its own, and the arms below wait — for a link to
        // a worker, for a dispatch lease, for a blocking thread. What stops a revoked action is
        // where each subject puts it.
        //
        // For a mutation a worker performs, section 9's own rule: every dispatch revalidates
        // current authority and expiry in the worker's serial path immediately before it acts, and
        // durable acceptance preserves neither. For a create or a project mutation, which this
        // host performs itself, the admission it carries is asked about again inside the daemon —
        // at the transition that lets a create launch, and in the project service's own work
        // before the action. The project service's own preparation is still behind that second
        // answer, which `Controller::project_mutation` records as the gap it is.
        //
        // What this check does is keep an already-withdrawn connection from getting that far.
        // What this host reports meanwhile is the revocation as pending for a worker until it
        // acknowledges the revision.
        if let Err(error) = self.authorised().await {
            return failure(mutation.request_id, error);
        }
        match entry.method {
            // The daemon's own effects. They run on a task that outlives this connection, because
            // dropping a future is a cancellation and a durable commit cannot be left half done
            // because a peer went away.
            Method::SessionCreate => {
                // A create claims the same action identity every other mutation claims, with this
                // host named as the owner of what it produces. Without it, an identifier spent on
                // a create would be free for a mutation on a worker, and section 9 makes
                // `(verified actor, action)` one operation whoever ends up holding its receipt.
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                // The admission travels with the create: the connection it arrived on, the
                // revision it was admitted under and the deadline this host accepted. A create
                // reserves its identity and then waits for a lock, for a process to start and for
                // that process to report itself, and a revocation that completes during that wait
                // must stop the launch. The daemon checks all three again at the moment the launch
                // becomes possible, which nothing out here can do on its behalf.
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .session_create(&actor_id, &mutation, carried)
                        .await
                });
                let answer = settled(request_id, tokio::time::timeout(EFFECT_WAIT, effect).await);
                // A create the daemon answered from the reservation an earlier submission made is
                // the same read of somebody's result as a retained answer anywhere else, and it
                // says so: `deduplicated` is what distinguishes it from a session made now.
                if deduplicated(&answer)
                    && let Err(error) = self.may_read_receipts(answered_session(&answer))
                {
                    return failure(request_id, error);
                }
                answer
            }
            // A close is dispatched to the worker, so it goes over a bounded link of its own
            // rather than over the connection this host announces authority revisions on: a worker
            // that stopped answering a close would otherwise hold that connection. Opening the
            // link is also what asks the worker for the acknowledgement a dispatch lease needs,
            // which a device closing a session it never attached to has not caused yet.
            Method::SessionClose => {
                let Some(session_id) = mutation.target.session_id.as_ref().copied() else {
                    return failure(
                        mutation.request_id,
                        ProtocolError::new(
                            ErrorCode::InvalidArgument,
                            "this mutation names the session it acts on",
                        ),
                    );
                };
                // A conflicting identifier refuses the close; storage that cannot record the
                // route does not. Section 7 has an authorised stop go ahead when storage fails,
                // and the worker reports what its own durability then was.
                match self.claim_route(mutation, Some(session_id)) {
                    Ok(()) | Err(RouteRefusal::Unavailable(_)) => {}
                    Err(RouteRefusal::Conflict(error)) => {
                        return failure(mutation.request_id, error);
                    }
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let envelope = self.envelope(validated);
                let grant_rights = self.device.grant.actions.clone();
                let request_id = mutation.request_id;
                // The answer comes back before the link that carried the close is released,
                // because releasing it is what tells the worker the acceptance was delivered.
                let (answer, answered) = tokio::sync::oneshot::channel();
                let (tell, delivered) = tokio::sync::oneshot::channel();
                self.output().on_delivery(request_id, tell);
                let observer = self.expiry_observer();
                tokio::spawn(async move {
                    controller
                        .close_remote_session(
                            &mutation,
                            Vouched {
                                actor: &envelope,
                                grant_rights: &grant_rights,
                            },
                            accepted,
                            &observer,
                            answer,
                            delivered,
                        )
                        .await;
                });
                match tokio::time::timeout(EFFECT_WAIT, answered).await {
                    Ok(Ok(Ok(closed))) => {
                        // A close the worker answered from its journal is a read of that receipt,
                        // and this is the check section 23 wants before either half of a retained
                        // result goes back. The close itself happened: section 7's stop does not
                        // wait on this, and only the answer does.
                        if closed.retained
                            && let Err(error) = self.may_read_receipts(Some(session_id))
                        {
                            return failure(request_id, error);
                        }
                        ControlFrame::Response(Response {
                            request_id,
                            outcome: Outcome::Ok(closed.value),
                        })
                    }
                    Ok(Ok(Err(error))) => failure(request_id, error.to_protocol_error()),
                    // The close is running on a task that outlives this connection, so a wait
                    // that ended says the outcome is not known rather than that it failed.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The project and workspace mutations. Like a create, they are the daemon's own
            // effect: no session owns them, so they go to the project service rather than to a
            // worker proxy, and the admission travels with them so the service can ask about it
            // again after the waiting it does of its own.
            _ if crate::project::ProjectModule::serves(entry.method) => {
                // Five of these name a destination or a source that this host cannot yet check a
                // device's authority over. Until it can, they are not served to one.
                if let Err(error) = resource_authority(entry.method) {
                    return failure(mutation.request_id, error);
                }
                // A project mutation claims its action identity the way every other mutation
                // does, with this host named as the owner of what it produces. Storage that
                // cannot record the route refuses it: only section 7's stop goes on without one.
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                // On a task that outlives this connection, because a clone reaches the network and
                // a materialisation copies files: dropping that future part way through is a
                // cancellation, and what it would leave behind is exactly what an action identity
                // exists to make recoverable.
                let effect = tokio::spawn(async move {
                    controller
                        .project_mutation(&actor_id, &mutation, method, carried)
                        .await
                });
                match tokio::time::timeout(EFFECT_WAIT, effect).await {
                    Ok(Ok(outcome)) => ControlFrame::Response(Response {
                        request_id,
                        outcome: match outcome {
                            Ok(value) => Outcome::Ok(value),
                            Err(error) => Outcome::Error(error),
                        },
                    }),
                    // The effect is still running, so a wait that ended says the outcome is not
                    // known rather than that the action failed.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The four voice mutations. Like a create, they are the daemon's own effect: a voice
            // session belongs to this host rather than to one terminal session, and the
            // coordinator decides each one against the voice grant and this device's ordinary
            // grant, intersected at the moment of the decision.
            _ if crate::voice::VoiceModule::serves(entry.method) => {
                // The deadline this mutation was admitted under, checked last: everything between
                // the envelope check and here can wait, and an action whose deadline passed while
                // it queued does not go on to write. A retry of a completed voice change is
                // answered from its own record before the effect.
                if self.controller.clock.now() >= accepted.deadline {
                    return failure(
                        mutation.request_id,
                        ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "the deadline this action was admitted under passed before it could \
                             run",
                        ),
                    );
                }
                let actor_id = self.device.principal();
                match self
                    .controller
                    .voice_mutation(
                        &actor_id,
                        crate::voice::VoiceActor::Device(self.device.device_id),
                        mutation,
                        entry.method,
                        validated,
                        accepted,
                    )
                    .await
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: mutation.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(mutation.request_id, error.to_protocol_error()),
                }
            }
            Method::DevicePreviewKeyUpdate => {
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
                }
                let actor_id = self.device.principal();
                // A completed registration is answered from what it produced, before the deadline
                // is looked at: a device whose answer was lost asks again with the same action and
                // is told what it was told, after a later rotation or once its window has closed.
                if let Some(answer) = self
                    .controller
                    .retained_authority_change(&actor_id, mutation)
                {
                    return answer;
                }
                if self.controller.clock.now() >= accepted.deadline {
                    return failure(
                        mutation.request_id,
                        ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "the deadline this action was admitted under passed before it could \
                             run",
                        ),
                    );
                }
                match self
                    .controller
                    .preview_key_update_action(&actor_id, mutation)
                    .await
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: mutation.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(mutation.request_id, error.to_protocol_error()),
                }
            }
            // Everything else belongs to the worker that owns the session.
            _ => self.proxied_mutation(mutation, accepted, validated).await,
        }
    }

    /// Narrows an answer to what this device's grant admits.
    ///
    /// Two things need it. A listing names no session, so the selector has nothing to check and
    /// the narrowing has to happen to the answer: the registry's own words for this method are
    /// "the sessions this actor may observe". And a session read carries the last command block,
    /// which is session content rather than metadata: a command line and the directory it ran in.
    /// The grant's history lower bound decides whether this device sees it.
    fn narrow(&self, answer: ControlFrame) -> ControlFrame {
        let ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }) = answer
        else {
            return answer;
        };
        let Ok(listed) = value.to_typed::<SessionListResult>() else {
            return self.narrow_read(request_id, value);
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

    /// Removes from a session read the content this device's grant does not reach.
    ///
    /// The command block the private hooks reported is a command line and a working directory,
    /// which is what the person typed and where it ran. A grant whose history lower bound is after
    /// the command started, or which retains no history at all, does not see it; the rest of the
    /// read is metadata and passes through. Anything that is not a session read passes through
    /// too: it named its session and was already checked against the selector.
    fn narrow_read(&self, request_id: RequestId, value: ParamsValue) -> ControlFrame {
        let passed = |value| {
            ControlFrame::Response(Response {
                request_id,
                outcome: Outcome::Ok(value),
            })
        };
        let Ok(read) = value.to_typed::<kr_protocol::session::SessionReadResult>() else {
            return passed(value);
        };
        let bound = self.device.grant.history.lower_bound_ms.0;
        let admitted = read.last_command_block.as_ref().is_some_and(|block| {
            bound.is_some_and(|bound| block.started_at_ms.get() >= bound.get())
        });
        if admitted {
            return passed(value);
        }
        let narrowed = kr_protocol::session::SessionReadResult {
            last_command_block: kr_protocol::scalars::Nullable::null(),
            ..read
        };
        match ParamsValue::from_typed(&narrowed) {
            Ok(value) => passed(value),
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
        // A read that names its session goes to that session's worker. `action.read` names an
        // action rather than a session, and an action's receipt lives in the journal of whichever
        // session it was performed on, so the route this host recorded when it dispatched the
        // action is what says where to ask.
        let proxy = match session_of(&request.params, entry) {
            Ok(session_id) => self
                .proxy_for(session_id)
                .await
                .map_err(|error| error.to_protocol_error()),
            Err(_) if entry.method == Method::ActionRead => {
                self.receipt_owner(request, entry).await
            }
            Err(error) => return failure(request.request_id, error),
        };
        let proxy = match proxy {
            Ok(proxy) => proxy,
            Err(error) => return failure(request.request_id, error),
        };
        let envelope = self.envelope(validated);
        let authority = match self.authority_deadline() {
            Ok(authority) => authority,
            Err(error) => return failure(request.request_id, error),
        };
        match proxy.forward_read(request, &envelope, authority).await {
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
        if let Err(refusal) = self.claim_route(mutation, Some(session_id)) {
            return failure(mutation.request_id, refusal.into_error());
        }
        let envelope = self.envelope(validated);
        let deadline = match self
            .controller
            .forwarded_deadline(session_id, &envelope, accepted)
            .await
        {
            Ok(deadline) => deadline,
            Err(error) => {
                // The grant may have run out while this waited, and wherever that is observed it
                // is written down. What decides is the grant's own deadline: everything else this
                // failure can mean says nothing about the grant.
                self.expiry_observer().grant_expired();
                return failure(mutation.request_id, error.to_protocol_error());
            }
        };
        // The effect runs on a task that outlives this connection, for the same reason the
        // daemon's own effects do: the worker commits the intent before it answers, and a
        // cancellation here must not be what decides whether the outcome is recorded.
        let mutation = mutation.clone();
        let request_id = mutation.request_id;
        // The grant's rights travel with the mutation. The worker admits an attachment and holds
        // no grants: section 8's intersection of requested capabilities with the actor's rights is
        // made where the attachment is admitted, out of what the host checked this request against.
        let grant_rights = self.device.grant.actions.clone();
        let effect = tokio::spawn(async move {
            proxy
                .forward_mutation(
                    &mutation,
                    Vouched {
                        actor: &envelope,
                        grant_rights: &grant_rights,
                    },
                    deadline,
                )
                .await
        });
        match effect.await {
            Ok(Ok(answered)) => {
                if answered.retained
                    && let Err(error) = self.may_read_receipts(Some(session_id))
                {
                    return failure(request_id, error);
                }
                ControlFrame::Response(Response {
                    request_id,
                    outcome: answered.response.outcome,
                })
            }
            Ok(Err(error)) => failure(request_id, error.to_protocol_error()),
            Err(_) => failure(request_id, outcome_unknown()),
        }
    }

    /// Returns whether this device may be told what one of its own actions produced.
    ///
    /// A retained answer is a read of a receipt, and section 23 has present view authority over
    /// the subject decide whether either half of a retained result is returned. The rights that
    /// decide it are `action.read`'s over the session the receipt belongs to, not the ones the
    /// mutation needed: a device that may act on a session it cannot observe does not learn what
    /// its action produced by submitting it twice.
    fn may_read_receipts(
        &self,
        session_id: Option<SessionId>,
    ) -> std::result::Result<(), ProtocolError> {
        let entry = self.admit(
            Method::ActionRead.as_str(),
            Method::ActionRead.entry().version,
        )?;
        self.check_grant(session_id, entry, false)
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
                Arc::clone(&self.lost),
            )
            .await?;
        *held = Some(Arc::clone(&proxy));
        Ok(proxy)
    }

    /// Claims this action's route before it is dispatched, and refuses a reused identifier.
    ///
    /// Where the action is going is written down before it goes. A receipt lives in the journal of
    /// the session the action was performed on, and a device whose connection ends before the
    /// answer arrives has nothing else left to say which session that was. An action whose route
    /// cannot be recorded is not dispatched: an unrecoverable result is worse than a refusal the
    /// device can submit again under the same identity.
    ///
    /// The claim is also this host's `(verified actor, action)` uniqueness check. Section 9 makes
    /// a reused identifier carrying a different payload `ID_CONFLICT`, and the digest the route
    /// holds is what a second submission is compared against.
    fn claim_route(
        &self,
        mutation: &MutationRequest,
        session_id: Option<SessionId>,
    ) -> std::result::Result<(), RouteRefusal> {
        let actor_id = self.device.principal();
        let digest =
            kr_protocol::digest::mutation_digest(mutation, &actor_id).map_err(|error| {
                RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?;
        let claimed = self
            .devices
            .claim_action_route(
                &actor_id,
                mutation.action_id,
                session_id,
                digest,
                kr_ipc::now_ms(),
            )
            .map_err(|error| RouteRefusal::Unavailable(error.to_protocol_error()))?;
        match claimed {
            super::devices::ActionRoute::Recorded => Ok(()),
            super::devices::ActionRoute::Existing(existing)
                if existing.payload_digest == Some(digest) && existing.session_id == session_id =>
            {
                Ok(())
            }
            super::devices::ActionRoute::Existing(_) => {
                Err(RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::IdConflict,
                    format!(
                        "action {} was already used with a different request",
                        mutation.action_id
                    ),
                )))
            }
        }
    }

    /// Answers a resubmitted action from the receipt the worker that ran it still holds.
    ///
    /// Only an action this host has already dispatched is looked up, so an ordinary first
    /// submission costs nothing. A digest that does not match the route's is a reused identifier,
    /// which section 9 refuses; a matching digest is the same action, and the worker's own receipt
    /// is the answer. A worker that holds no receipt for it leaves the request to the ordinary
    /// first-admission path, where its window decides.
    async fn retained_remotely(
        &self,
        mutation: &MutationRequest,
        validated: AuthorityRevision,
    ) -> std::result::Result<Option<ControlFrame>, RouteRefusal> {
        let actor_id = self.device.principal();
        let Some(routed) = self
            .devices
            .action_route(&actor_id, mutation.action_id)
            .map_err(|error| RouteRefusal::Unavailable(error.to_protocol_error()))?
        else {
            return Ok(None);
        };
        let digest =
            kr_protocol::digest::mutation_digest(mutation, &actor_id).map_err(|error| {
                RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?;
        if routed.payload_digest != Some(digest) {
            return Err(RouteRefusal::Conflict(ProtocolError::new(
                ErrorCode::IdConflict,
                format!(
                    "action {} was already used with a different request",
                    mutation.action_id
                ),
            )));
        }
        // An action this host itself owns the receipt of is answered by the daemon or not at all.
        // Asking a worker about it would ask the wrong journal.
        let Some(session_id) = routed.session_id else {
            return Ok(None);
        };
        // A refusal here is the answer, not a reason to go on. This action has already been
        // dispatched, and forwarding it again would have the worker answer from the receipt this
        // device may not read.
        self.may_read_receipts(Some(session_id))
            .map_err(RouteRefusal::Conflict)?;
        // A link that cannot be opened is not an answer. The ordinary path decides what this
        // request gets, which for a session whose worker has gone is that session's own refusal
        // rather than a second dispatch.
        let Ok(proxy) = self.proxy_for(session_id).await else {
            return Ok(None);
        };
        let request = Request {
            request_id: mutation.request_id,
            method: Method::ActionRead.into(),
            method_version: Method::ActionRead.entry().version,
            params: ParamsValue::from_typed(&kr_protocol::receipt::ActionReadParams {
                action_id: mutation.action_id,
                // This request goes to the worker that owns the session, which serves the
                // receipts of the one session it has. Naming it would say nothing more.
                session_id: None,
            })
            .map_err(|error| {
                RouteRefusal::Conflict(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    error.to_string(),
                ))
            })?,
        };
        let envelope = self.envelope(validated);
        let authority = self.authority_deadline().map_err(RouteRefusal::Conflict)?;
        let Ok(response) = proxy.forward_read(&request, &envelope, authority).await else {
            // The link failed, not the lookup. The ordinary path decides what happens next.
            return Ok(None);
        };
        let Outcome::Ok(value) = response.outcome else {
            // No receipt for it there, or the worker refused the read. Either way this is not an
            // answer, and the request goes on to be admitted or refused on its own terms.
            return Ok(None);
        };
        let Ok(read) = value.to_typed::<kr_protocol::receipt::ActionReadResult>() else {
            return Ok(None);
        };
        // The result when the action produced one, and the receipt when it has not: a caller that
        // resubmitted is told what became of its action, and nothing is dispatched again.
        Ok(Some(match read.result.0 {
            Some(result) => ControlFrame::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(result),
            }),
            None => ControlFrame::Receipt(Box::new(kr_protocol::receipt::ReceiptResponse {
                request_id: mutation.request_id,
                receipt: read.receipt,
            })),
        }))
    }

    /// Returns the link to the worker holding one action's receipt.
    ///
    /// The route is durable, so a device that lost its connection, or found this host restarted,
    /// can still ask for its own result. Owning an action identifier is not authority: the grant
    /// is checked again against the session the route names, because what the action was
    /// dispatched under may since have been narrowed.
    async fn receipt_owner(
        &self,
        request: &Request,
        entry: &'static MethodEntry,
    ) -> std::result::Result<Arc<WorkerProxy>, ProtocolError> {
        let params: kr_protocol::receipt::ActionReadParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let routed = self
            .devices
            .action_route(&self.device.principal(), params.action_id)
            .map_err(|error| error.to_protocol_error())?;
        // A receipt lives in the journal of the session the action was performed on, and the
        // route says which. Two routes cannot be answered here, and they are answered differently
        // because they mean different things.
        let session_id = match routed {
            Some(routed) => match routed.session_id {
                Some(session_id) => session_id,
                // The route says this host owns whatever this identifier produced rather than a
                // session: a create, or a repository or workspace mutation. The route is claimed
                // before the action is admitted, so it says where an outcome would live rather
                // than that anything ran. Either way there is no receipt here to read, because
                // what such an action leaves is kept by the service that would have performed it
                // and not in the shape this method answers with. Submitting the action again
                // under the same identifier is what gives the caller its outcome, and the
                // sentence says so rather than leaving a caller to conclude that a recorded
                // action has gone missing.
                None => {
                    let detail = format!(
                        "action {} belongs to this host rather than to a session, and this host \
                         keeps no receipt for one; submit the action again under the same \
                         identifier to be given its outcome",
                        params.action_id
                    );
                    return Err(ProtocolError::new(ErrorCode::InvalidArgument, detail));
                }
            },
            // Nothing recorded it. An action nobody recorded is not an action this device can be
            // told about.
            None => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("no receipt for action {}", params.action_id),
                ));
            }
        };
        self.check_grant(Some(session_id), entry, false)?;
        self.proxy_for(session_id)
            .await
            .map_err(|error| error.to_protocol_error())
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

    /// Returns when the authority behind this connection's requests runs out.
    ///
    /// On the machine's own continuous clock, which is the clock the worker reads, and shortened
    /// rather than lengthened by a pause between the two readings. A read carries no accepted
    /// deadline of its own, and raw input is a read: without this, a batch admitted a moment
    /// before the grant expired could still be written to the application after it. Null when the
    /// grant does not expire.
    fn authority_deadline(
        &self,
    ) -> std::result::Result<kr_protocol::scalars::Nullable<kr_protocol::scalars::U64>, ProtocolError>
    {
        let Some(deadline) = self.authority.grant_deadline else {
            return Ok(kr_protocol::scalars::Nullable::null());
        };
        // Null means "this authority does not expire", so a deadline that has already passed can
        // never be sent as null: that would forward expired authority as unlimited authority. It
        // is a refusal instead, and this connection is fenced with it.
        let remaining = crate::service::remaining_deadline(
            &*self.controller.shared_clock,
            &*self.controller.clock,
            deadline,
            None,
        )
        .ok_or_else(|| {
            // Nothing is left of the deadline, which is this grant having run out: the latch is
            // set here because that is the observation, and the record follows it.
            self.authority.expire();
            ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant has run out",
            )
        })?;
        Ok(kr_protocol::scalars::Nullable(Some(remaining)))
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

    /// Returns the authority revision this request is admitted at, or a refusal.
    ///
    /// The registration and the revision are read in one critical section, taking the registry
    /// lock and then the connection table — the order a revocation takes. So a request is never
    /// stamped with a revision that was installed *by* the revocation that withdrew its
    /// registration: either the registration is still there and the revision is the one it stands
    /// under, or the request is refused.
    async fn admitted_at(&self) -> std::result::Result<AuthorityRevision, ProtocolError> {
        let registry = self.controller.registry.lock().await;
        let revision = registry
            .authority_revision()
            .map_err(|error| error.to_protocol_error())?;
        self.controller
            .authorised(self.connection_id)
            .map_err(|error| error.to_protocol_error())?;
        drop(registry);
        Ok(revision)
    }

    /// Resolves one method against the registry at this connection's ingress.
    fn admit(
        &self,
        method: &str,
        version: kr_protocol::method::MethodVersion,
    ) -> std::result::Result<&'static MethodEntry, ProtocolError> {
        self.actor.admit(method, version)
    }

    /// Resolves once this connection's link to its worker has ended.
    ///
    /// A connection with no link has no subscription and no attachment, so it is not a connection
    /// that can go on being served. It resolves immediately when there is no link to lose, so a
    /// caller selecting on it does not have to know whether one was ever opened — except that a
    /// connection which has not attached yet has nothing to lose, and waits.
    pub async fn link_lost(&self) {
        let held = self.proxy.lock().await.as_ref().map(Arc::clone);
        match held {
            Some(proxy) => proxy.lost().await,
            // Nothing to lose yet. Waiting for the notification the first link will send is what
            // keeps a connection that has not attached from ending itself.
            None => self.lost.notified().await,
        }
    }

    /// Returns whether this connection's registration still stands.
    pub async fn is_authorised(&self) -> bool {
        self.authorised().await.is_ok()
    }

    /// Refuses a request on a connection whose registration has been withdrawn.
    async fn authorised(&self) -> std::result::Result<(), ProtocolError> {
        self.controller
            .authorised(self.connection_id)
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
        received_at: kr_transport::clock::ContinuousInstant,
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
        // A project acts on a repository or a working copy. Its own subject check is the one the
        // local ingress makes: a target naming a session or an application is refused rather than
        // producing a receipt against something the effect never touched, and a destination
        // environment in the parameters has to be the one the target names.
        if crate::project::ProjectModule::serves(entry.method) {
            crate::project::ProjectModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // A voice mutation's subject is this host. A voice session is not a shell session, so the
        // target names none, and the session a delegation acts on travels in the parameters where
        // the coordinator checks it against what that voice session may reach. Its own subject
        // check is the one the local ingress makes.
        let voice = crate::voice::VoiceModule::serves(entry.method);
        if voice {
            crate::voice::VoiceModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // The target and the parameters have to name the same subject. One that pointed at a
        // session the grant admits and carried another in its parameters would act on the one
        // nobody addressed, and the grant check above would have looked at the wrong one.
        let names_session = !voice
            && entry
                .resource_selectors
                .contains(&ResourceSelectorKind::Session);
        match (
            mutation.target.session_id.as_ref().copied(),
            if voice {
                None
            } else {
                session_of(&mutation.params, entry).ok()
            },
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
            .accept_at(
                &mutation.action_window_id,
                self.connection_id,
                self.controller.boot_epoch,
                received_at,
                mutation.requested_ttl_ms,
                self.authority.grant_deadline,
            )
            .map_err(|refusal| {
                ProtocolError::new(ErrorCode::PermissionDenied, window_refusal_detail(refusal))
            })
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
                // The voice right lives in the separate voice grant section 15 ¶7 intersects with
                // this one, not in the grant this connection was admitted under: a person holds
                // their ordinary authority and chooses separately how much of it voice may use.
                // It is resolved against that grant here, and the coordinator takes the
                // intersection again at the moment of each decision.
                RequiredAuthority::Right {
                    right: ActionRight::VoiceUse,
                } if !self.holds_voice_grant() => {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this device holds no voice grant on this host",
                    ));
                }
                RequiredAuthority::Right {
                    right: ActionRight::VoiceUse,
                } => {}
                RequiredAuthority::Right { right } if !grant.permits(right) => {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        format!("this device's grant does not carry {}", right.as_str()),
                    ));
                }
                // Current read authority over the subject, which is the subject the request
                // names. For a session that is `session.view` at the session's scope, which is
                // what the grant can answer; the session's own state is the worker's to answer
                // inside its barrier. A request that names no session has a subject of another
                // kind — a repository, a working copy, this host itself — and demanding
                // `session.view` for one of those would ask for authority over something the
                // answer is not about. What still decides such a request is everything else this
                // check makes: the grant's expiry, its environment selector, the rights the method
                // requires outright, and its history scope.
                RequiredAuthority::PresentViewAuthority
                    if session_id.is_some() && !grant.permits(ActionRight::SessionView) =>
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

    /// Whether this device holds a live voice grant on this host.
    ///
    /// Read from the host's one authority store at the moment of the question, because a voice
    /// grant is written, replaced and withdrawn while a connection stands.
    fn holds_voice_grant(&self) -> bool {
        let now_ms = super::super::wall_clock_ms();
        self.controller
            .sharing()
            .grants()
            .records_for_device(self.device.device_id)
            .is_ok_and(|records| {
                records.into_iter().any(|record| {
                    record.state(now_ms) == kr_protocol::sharing::GrantState::Active
                        && record.grant.permits(ActionRight::VoiceUse)
                })
            })
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
            // Whose subject it is belongs to the subject, and these conditions are alternatives
            // keyed to that answer: `own_subject` and `other_actor` cannot both hold, so treating
            // both as holding would demand the authority for somebody else's subject from a caller
            // acting on its own. The subject resolves them inside its own barrier, where it
            // refuses what it must: a device detaches the attachment its connection created, and
            // a receipt lookup keyed by the verified actor finds only that actor's own actions.
            RightCondition::OwnSubject
            | RightCondition::OtherActor
            | RightCondition::CandidateEndpoint
            | RightCondition::IssuingOwner => false,
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

/// Refuses a project mutation whose destination or source this host cannot authorise for a device.
///
/// Section 14 requires an authorised destination handle for a creation, and section 23's rows
/// require a destination and remote-credential policy for one and source and destination grants
/// for a working copy. The project service has neither: it resolves the absolute parent directory
/// the request names with this host's own filesystem authority, and it bounds the repository a
/// working copy is taken from by nothing but the environment. For a caller on the machine's own
/// socket that is the user's own authority over the user's own filesystem. For a paired device it
/// is not, and the grant's action right would be the whole of the restriction: `project.create`
/// would reach every directory this host can open, and `workspace.manage` every repository the
/// environment holds.
///
/// So this host refuses those five rather than acting on a destination or a source nobody
/// authorised it to reach. The reads, and cancelling work the caller itself started, are
/// unaffected. The refusal is lifted when the project service bounds a destination and a source by
/// the grant that asked.
fn resource_authority(method: Method) -> std::result::Result<(), ProtocolError> {
    let names = match method {
        Method::ProjectInit | Method::ProjectClone | Method::ProjectAdopt => {
            "the directory it creates a repository in"
        }
        Method::WorkspaceCreate => "the repository it takes a working copy from",
        Method::WorkspaceRemove => "the working copy it removes",
        _ => return Ok(()),
    };
    Err(ProtocolError::new(
        ErrorCode::PermissionDenied,
        format!(
            "{} names {}, and this host does not yet establish a paired device's authority over \
             one: the project service resolves it with the host's own authority and checks \
             nothing else against the device. Until it does, this host serves the repository and \
             workspace reads to a device and not this.",
            method.as_str(),
            names
        ),
    ))
}

/// Returns whether one request claims or adds a geometry claim.
///
/// The condition on `terminal.geometry` is "when the request claims or adds a geometry claim", so
/// the request is what decides it: `claim_geometry` is the field that registers one, and
/// `session.attach` and `attachment.configure` both carry it.
///
/// A *requested capability* is not a claim. Section 8 makes an attachment's granted capabilities
/// the requested ones intersected with the actor's rights, so asking for `geometry` in a grant
/// that does not carry `terminal.geometry` yields an attachment without it rather than a refusal,
/// and the summary the caller is given says which it got. Refusing here instead would mean a
/// client that asks for everything it can use gets nothing, which is the opposite of what an
/// intersection is for. What it may still never do is register the claim: `claim_geometry` needs
/// the right here, and every later operation is checked against the capability the attachment was
/// actually granted.
fn claims_geometry(mutation: &MutationRequest) -> bool {
    let kr_cbor::CanonicalValue::Map(map) = mutation.params.as_value() else {
        return false;
    };
    matches!(
        map.get("claim_geometry"),
        Some(kr_cbor::CanonicalValue::Bool(true))
    )
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
///
/// The task owns the effect and outlives this connection, so a wait that ran out says the outcome
/// is unknown rather than that the action failed: the effect is still running, and section 9
/// forbids reporting an action that may have happened as refused.
type Effect = std::result::Result<
    std::result::Result<Result<ParamsValue>, tokio::task::JoinError>,
    tokio::time::error::Elapsed,
>;

fn settled(request_id: RequestId, outcome: Effect) -> ControlFrame {
    match outcome {
        Ok(Ok(Ok(value))) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Ok(value),
        }),
        Ok(Ok(Err(error))) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(error.to_protocol_error()),
        }),
        Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
    }
}

/// Returns whether an answer is a create the daemon deduplicated rather than performed.
fn deduplicated(answer: &ControlFrame) -> bool {
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(value),
        ..
    }) = answer
    else {
        return false;
    };
    value
        .to_typed::<kr_protocol::session::SessionCreateResult>()
        .is_ok_and(|created| created.deduplicated)
}

/// Returns the session a retained answer is about, when it names one.
///
/// A create's result names the session it made, which is the subject the answer is a read of. An
/// answer that names none leaves the selector nothing to check, and the grant's own scope decides.
fn answered_session(answer: &ControlFrame) -> Option<SessionId> {
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(value),
        ..
    }) = answer
    else {
        return None;
    };
    value
        .to_typed::<kr_protocol::session::SessionCreateResult>()
        .ok()
        .map(|created| created.session.session_id)
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

#[cfg(test)]
mod tests {
    use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
    use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
    use kr_protocol::ids::{
        ActionId, ActionWindowId, EnvironmentId, RequestId, SessionEpoch, SessionId,
    };
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{Nullable, Uuid};

    fn attach(claim_geometry: bool, requested: &[AttachmentCapability]) -> MutationRequest {
        let session_id = SessionId::new(Uuid::from_bytes([3; 16]));
        MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionAttach.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(Uuid::from_bytes([4; 16])),
            target: ActionTarget {
                environment_id: EnvironmentId::new(Uuid::from_bytes([5; 16])),
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            params: ParamsValue::from_typed(&SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry,
                dimensions: Nullable::null(),
                terminal_profile_id: Nullable::null(),
                requested: requested.iter().copied().collect(),
            })
            .expect("encodes"),
            grant_id: Nullable::null(),
            expected: ParamsValue::from_typed(&std::collections::BTreeMap::<String, u64>::new())
                .expect("encodes"),
            action_window_id: ActionWindowId::new("window").expect("a window identifier"),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
        }
    }

    /// KR-REQ-08.68: registering a claim is what needs the geometry right, and asking is not
    /// registering.
    #[test]
    fn a_requested_capability_is_not_a_geometry_claim() {
        assert!(
            super::claims_geometry(&attach(true, &[])),
            "the flag that registers a claim is a claim"
        );
        assert!(
            !super::claims_geometry(&attach(false, &[AttachmentCapability::Geometry])),
            "asking for the capability is a request the host intersects, not a claim"
        );
        assert!(
            !super::claims_geometry(&attach(
                false,
                &[
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Input
                ]
            )),
            "and an ordinary observing attachment claims nothing"
        );
    }
}
