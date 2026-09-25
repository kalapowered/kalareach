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
//! 3. **The grant decides, through the one intersection.** The grant the device holds is intersected
//!    with this host's policy and with the rights ceiling its configuration put in force, and the
//!    method is decided against what is left: the grant's expiry, the environment and session its
//!    selectors admit, the rights the method requires, and the content its history scope reaches.
//!    A right the configuration removed is refused by its name.
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
//! A batch a subscription carries is a read that goes on, so it is also written under the decision
//! that allowed it: the grant, this host's policy and the configured ceiling, taken for that batch.
//! The boundary holds the batch to that decision after every wait and at every attempt to hand
//! bytes over, through an epoch that any change to the policy or the ceiling moves and the moment
//! the decision's own time bound runs out; the watch takes the whole decision again while the write
//! waits. A decision that stops holding before the first byte goes has the batch decided again,
//! and one that stops holding once bytes are moving ends the connection.
//!
//! # What outlives the connection
//!
//! A mutation's effect runs on its own task, so a durable commit is never left half done because a
//! peer went away. So does the release of what the connection owned at its worker, and that runs
//! from a guard's destructor rather than from the end of the serve loop, because the transport
//! drops the handler's future the moment the control stream ends.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::authority::{
    EffectClass, HistoryFilter, MethodEntry, RequiredAuthority, ResourceSelectorKind,
};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AuthorityRevision, ConnectionId, DeviceId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::session::SessionListResult;
use kr_transport::actor::ConnectionActor;
use kr_transport::listener::{AuthorisedSession, ControlSender};
use kr_transport::window::AcceptedDeadline;

use super::devices::DeviceRecord;
use super::proxy::{RELAY_QUEUED_BYTES, RelayBudget, Relayed, Vouched, WorkerProxy};
use crate::config::ceilings::CeilingRefusal;
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

/// How many times one relayed batch is decided before the relay gives up on it.
///
/// A decision stops holding before the batch's first byte goes when this host's policy or rights
/// ceiling changed while the batch waited, and the batch is then decided again. A change that
/// lands on every attempt is not one a batch waits out.
pub const RELAY_DECISIONS: usize = 3;

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
    /// Where the frames go: the connection's control stream.
    sink: Box<dyn FrameSink>,
    /// The authority this connection writes under, read inside the turn.
    ///
    /// The latch above is what a *device* revocation sets. An authority revision the daemon
    /// advances for another reason withdraws the registration without touching this connection, so
    /// the registration itself is read here as well: either way, no frame begins on a connection
    /// whose authority has gone.
    authority: Arc<Authorisation>,
}

/// Where one connection's frames go.
///
/// The control stream, for every connection this host serves. It is a seam so the write boundary
/// can be exercised against a writer that is held and a peer that stops reading, which a real
/// stream does not let a test arrange on demand.
trait FrameSink: Send + Sync + std::fmt::Debug {
    /// Sends one frame for as long as `admits` holds, as [`ControlSender::send_while`] does.
    fn send_while<'a>(
        &'a self,
        frame: &'a ControlFrame,
        admits: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>;

    /// Ends the connection, which is what stops a write that is still waiting on it.
    fn close(&self);
}

/// A connection's control stream, and the connection it closes.
#[derive(Debug)]
struct ControlStream {
    sender: ControlSender,
    connection: iroh::endpoint::Connection,
}

impl FrameSink for ControlStream {
    fn send_while<'a>(
        &'a self,
        frame: &'a ControlFrame,
        admits: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>>
    {
        Box::pin(self.sender.send_while(frame, admits))
    }

    fn close(&self) {
        self.connection.close(
            WITHDRAWN.into(),
            b"this connection's authority was withdrawn",
        );
    }
}

/// The decision a batch a subscription carries is written under, for as long as it holds.
///
/// Every part is read in the poll that hands bytes to the stream, so each is an atomic or a clock
/// reading that never waits: the authority epoch the decision was taken at, which any change to
/// this host's policy or rights ceiling moves; the offline bound as the host anchored it on the
/// continuous clock, which a wall clock wound back cannot lengthen; and the moment in UTC the
/// decision stops holding, against this host's reading of UTC, so a clock stepped forward or a
/// floor another decision raised ends it at once.
///
/// What the poll reads of time, it keeps. Its reading of UTC raises the floor every later decision
/// stands on, and a lapse it finds is owed its record: by UTC, the floor it read; on the continuous
/// clock, the time the offline bound has spent. Both are written outside the poll, by the relay,
/// the next decision or the network's record task. A clock wound back after the poll refused
/// therefore gives nothing back: not to the batch decided again, and not to a connection that comes
/// after this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelayGrant {
    epoch: u64,
    until: Option<kr_transport::clock::ContinuousInstant>,
    lapses_at_ms: Option<u64>,
}

impl RelayGrant {
    /// Returns whether the decision still holds at this instant.
    fn holds(&self, controller: &Controller) -> bool {
        if controller.authority_epoch() != self.epoch {
            return false;
        }
        if self
            .until
            .is_some_and(|until| controller.clock.now() >= until)
        {
            controller.owe_offline_time();
            return false;
        }
        if let Some(lapses_at_ms) = self.lapses_at_ms {
            let settled = controller.settled_utc_now();
            if settled >= lapses_at_ms {
                controller.keep_lapse(settled);
                return false;
            }
        }
        true
    }
}

/// What a relayed batch is written under.
#[derive(Clone, Copy)]
struct Relaying<'a> {
    /// The decision that allowed it.
    grant: RelayGrant,
    /// Takes the whole decision again. The watch calls it while the write waits, because a clock
    /// stepped forward ends a decision without moving the epoch or the continuous clock.
    redecide: &'a (dyn Fn() -> bool + Send + Sync),
}

/// How one write ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Written {
    /// The frame reached the stream whole.
    Sent,
    /// The decision the batch was written under stopped holding before any of it went. Nothing is
    /// in pieces, so the batch can be decided again.
    Undecided,
    /// Nothing more goes on this connection.
    Withdrawn,
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

    /// Records that this grant has run out, and writes it down.
    ///
    /// For a caller that established the expiry some other way than by reading the deadline here:
    /// the latch is what makes it an observation rather than a fence for another reason.
    fn expire(&self) {
        self.expired.store(true, Ordering::Release);
        self.note_expiry();
    }

    /// Returns whether this connection's grant still has time on it.
    ///
    /// Nothing but a clock read and two atomics, because this is also what decides at every
    /// attempt to write a frame: a decision made inside a poll cannot wait on a lock or a
    /// database. Writing the expiry down is [`Self::note_expiry`], which the checks that can
    /// afford it call.
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
        Self::writing_to(
            Box::new(ControlStream {
                sender: session.control.sender(),
                connection: session.connection.clone(),
            }),
            authority,
        )
    }

    fn writing_to(sink: Box<dyn FrameSink>, authority: Arc<Authorisation>) -> Self {
        Self {
            turn: tokio::sync::Mutex::new(()),
            withdrawn: AtomicBool::new(false),
            delivery: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            sink,
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
        self.write(frame, None).await == Written::Sent
    }

    /// Writes one frame, and, for a batch a subscription carries, the decision that allowed it.
    ///
    /// A response answers a request that was decided when it arrived, so it is written under the
    /// connection's own authority alone. A relayed batch is written under its decision as well, at
    /// every point [`Self::send`] reads the connection's: after the turn, after the writer, at
    /// every attempt to hand bytes over, and in the watch while the write waits, which also takes
    /// the whole decision again. A decision that stops holding before the first byte goes leaves
    /// nothing in pieces, so the batch is decided again; once bytes are moving the connection ends
    /// with it.
    async fn write(&self, frame: &ControlFrame, relaying: Option<Relaying<'_>>) -> Written {
        let _turn = self.turn.lock().await;
        if self.has_withdrawn() {
            return Written::Withdrawn;
        }
        if !self.fence() {
            // Outside the poll, where a durable write belongs: the fence itself only reads the
            // clock, and an expiry it observed has to be written down by something that can.
            self.authority.note_expiry();
            self.withdraw();
            return Written::Withdrawn;
        }
        let decided = || {
            relaying
                .as_ref()
                .is_none_or(|relaying| relaying.grant.holds(&self.authority.controller))
        };
        if !decided() {
            return Written::Undecided;
        }
        // Set the first time a byte may have gone. Until then the stream is whole whatever
        // happens to this frame.
        let begun = AtomicBool::new(false);
        let admits = || {
            let admitted = self.fence() && decided();
            if admitted {
                begun.store(true, Ordering::Release);
            }
            admitted
        };
        let redecide = relaying.map(|relaying| relaying.redecide);
        let written = tokio::select! {
            written = self.sink.send_while(frame, &admits) => written,
            () = self.authority_lost(&decided, redecide) => {
                if !begun.load(Ordering::Acquire)
                    && !self.has_withdrawn()
                    && self.authority.stands().await
                {
                    return Written::Undecided;
                }
                self.withdraw();
                return Written::Withdrawn;
            }
        };
        match written {
            Ok(true) => {
                self.delivered(frame);
                Written::Sent
            }
            // Refused before the first byte, and not by the connection's own authority: only the
            // decision moved, and the stream is whole.
            Ok(false) if !begun.load(Ordering::Acquire) && self.fence() => Written::Undecided,
            // Refused at the boundary: the authority this connection writes under has gone, so the
            // connection goes with it rather than waiting to be asked for something else.
            Ok(false) => {
                self.authority.note_expiry();
                self.withdraw();
                Written::Withdrawn
            }
            Err(_) => Written::Withdrawn,
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

    /// Resolves once this connection stops being one this host may write to, or the decision a
    /// relayed write is under stops holding.
    ///
    /// It polls, because the daemon's own revocation path withdraws a registration without
    /// knowing which network connections hold it, and a grant runs out on a clock rather than on
    /// an event. The interval only matters while a write is waiting, which is the only time
    /// anything is watching. A relayed write's decision is taken again here too, outside the poll
    /// where a durable write belongs.
    async fn authority_lost(
        &self,
        decided: &(dyn Fn() -> bool + Send + Sync),
        redecide: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) {
        loop {
            tokio::time::sleep(AUTHORITY_POLL).await;
            if self.has_withdrawn()
                || !self.authority.stands().await
                || !decided()
                || redecide.is_some_and(|redecide| !redecide())
            {
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
        self.sink.close();
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
            | ControlFrame::AcceptanceDelivered(_)
            | ControlFrame::AttentionSources(_)
            | ControlFrame::AttentionSourcePage(_)
            | ControlFrame::AttentionText(_)
            | ControlFrame::AttentionTextAnswer(_)
            | ControlFrame::AttentionBarrier(_)
            | ControlFrame::AttentionBarrierAcknowledged(_) => None,
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
            // The four host-and-environment reads are the daemon's own answers, and what a device
            // reads of them is their export form: the daemon decides the form by who asked, in the
            // one function every such answer leaves through, so a device is told which
            // environments these are, what they run on and what they can do, and never an account
            // name, a local path or what the platform said.
            Method::HostInfo
            | Method::EnvironmentList
            | Method::EnvironmentCapabilities
            | Method::HostDoctor => self.controller.read_method(&actor_id, request).await,
            // The project and workspace metadata reads. They name no session, so the grant's
            // environment selector and the rights the registry lists are the whole of what
            // narrows them, and the service answers a device exactly as it answers this user's
            // own client.
            Method::ProjectList | Method::WorkspaceList => {
                let answer = self.controller.read_method(&actor_id, request).await;
                self.narrow(answer)
            }
            // A read of one repository or one working copy. It names its subject, so it is
            // refused rather than narrowed when the grant does not reach that subject's
            // environment: a list this grant narrowed must not be a way to find an identifier the
            // read then answers for. What the read does narrow is the same session content the
            // list narrows, so neither door shows more than the other.
            Method::ProjectRead | Method::WorkspaceRead => {
                let answer = self.controller.read_method(&actor_id, request).await;
                self.narrow(answer)
            }
            // A diff of a **captured version** is retained content, and its answer carries the
            // moment of the read rather than the moment of the capture, so nothing on this path
            // can apply the grant's lower bound to it: a host that cannot narrow content to a
            // grant refuses it rather than serving more than the grant allows. A change-set read
            // does carry the capture, and its answer is narrowed below.
            //
            // A diff of a **working copy** is refused for the other reason, the same one the five
            // repository operations are refused for: reading one opens the repository and runs
            // the Git program, and this host cannot bound what that program reaches. The rule is
            // about starting Git for a device, so it reaches every method that starts Git and not
            // only the ones that write.
            Method::DiffRead => {
                if let Ok(params) = request
                    .params
                    .to_typed::<kr_protocol::changeset::DiffReadParams>()
                    && params.change_set_id.is_present()
                {
                    return failure(
                        request.request_id,
                        ProtocolError::new(
                            ErrorCode::PermissionDenied,
                            "this host does not serve a diff of a recorded change-set version to \
                             a paired device",
                        ),
                    );
                }
                return failure(request.request_id, refuses_to_run_git());
            }
            Method::ChangesetRead => {
                let answer = self.controller.read_method(&actor_id, request).await;
                self.narrow(answer)
            }
            // The devices this host paired and the keys their pairing bound. An owner's other
            // device reads it to learn a device's keys from the pairing the owner approved rather
            // than from anything the device says of itself; the registry requires `host.manage`,
            // and the grant check above has applied it.
            Method::DeviceList => self.controller.read_method(&actor_id, request).await,
            // The daemon answers these itself, and what it answers with is narrowed to the grant:
            // a list is every session this actor may observe, not every session this host runs.
            Method::SessionList | Method::SessionRead => {
                let answer = self.controller.read_method(&actor_id, request).await;
                self.narrow(answer)
            }
            // A receipt of an action this host performed itself, rather than a session's, is kept
            // by the service that performed it. The catalogue's are answered here; anything else
            // goes to the session whose journal holds it.
            Method::ActionRead => match self.host_receipt(request).await {
                Some(answer) => answer,
                None => self.proxied_read(request, entry, validated).await,
            },
            Method::EventsSubscribe
            | Method::EventsSnapshot
            | Method::HistoryPage
            | Method::InputWrite => self.proxied_read(request, entry, validated).await,
            // The automation group's read. A device is shown the workflows that act under the
            // grant it holds, their runs and receipts, and the budgets and alerts of the chains
            // those runs belong to; a workflow under another grant is not this device's to see.
            Method::WorkflowRead => {
                self.controller
                    .automation()
                    .read_frame(request, Some(self.device.grant.grant_id))
                    .await
            }
            // The voice coordinator's own reads. They run on this host rather than on a worker:
            // a selection is built from what this daemon holds about the session, filtered under
            // this device's own grant, a preparation reads this device's grants and the managed
            // service's published terms, and what comes back goes to this device and nowhere else.
            Method::VoiceContext | Method::VoicePrepare => {
                self.controller
                    .voice()
                    .read_frame(
                        self.device.device_id,
                        request,
                        super::super::wall_clock_ms(),
                    )
                    .await
            }
            // The catalogue and plugin reads. A catalogue belongs to the environment rather than to
            // a session, so there is no worker to forward them to and no session content to narrow:
            // the grant's environment selector and `host.manage` are the whole of what admits them,
            // and the module answers a device exactly as it answers this user's own client. The
            // ingress travels with the read so the module decides it at the connection's own.
            _ if crate::catalogue::CatalogueModule::serves(entry.method) => {
                self.controller
                    .catalogue
                    .read_frame(kr_protocol::actor::ActorIngress::PairedDevice, request)
                    .await
            }
            // The review and attention group is this host's own store, and a device reads it under
            // its grant: the sessions its selector admits with `session.view`, the automation of
            // its own grant with `automation.manage`, the host's own items with `host.manage`, and
            // no session text.
            _ if crate::attention::AttentionModule::serves(entry.method) => {
                let caller = crate::attention::Caller::device(&self.device.grant);
                let reach = self.controller.attention_reach();
                self.controller
                    .attention()
                    .read_frame(reach.as_ref(), &caller, &actor_id, request)
                    .await
            }
            // The pairing and owner-confirmation reads. A device is the issuing owner of nothing,
            // because invitations are issued over local IPC, so its `pair.status` is refused by the
            // pairing service; an owner device reads the confirmations it can approve.
            Method::PairStatus | Method::OwnerConfirmationPending => {
                let caller = super::owner::Caller::device(self.device.clone());
                match self
                    .controller
                    .pairing_read(caller, entry.method, &request.params)
                    .await
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: request.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(request.request_id, error.to_protocol_error()),
                }
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
        // The rights this request was decided with: the grant as this host's policy and its
        // configured ceiling leave it. They are what the worker is told the host checked.
        let rights = match self.check_grant(
            mutation.target.session_id.as_ref().copied(),
            entry,
            claims_geometry(mutation),
        ) {
            Ok(decision) => decision.decided.permitted.rights,
            Err(error) => return failure(mutation.request_id, error),
        };
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
        // An automation action's record is the workflow journal's, written in the transaction
        // that performed it, so a device that lost its reply is answered from it.
        if held.is_none() && crate::automation::AutomationModule::serves(entry.method) {
            held = self
                .controller
                .automation()
                .retained(&actor_id, mutation, entry.method)
                .await;
        }
        // A catalogue mutation's receipt lives with the catalogue, beside the state the effect
        // changed, so a retry of one that lost its reply is answered there rather than performed a
        // second time.
        if held.is_none() && crate::catalogue::CatalogueModule::serves(entry.method) {
            held = self
                .controller
                .catalogue
                .retained(&actor_id, mutation, entry.method)
                .await;
        }
        if held.is_none() && crate::attention::AttentionModule::serves(entry.method) {
            held = self
                .controller
                .attention()
                .retained(&actor_id, mutation, entry.method);
        }
        // An owner device's own confirmation answers are retained by the pairing service, and a
        // repeat of one over a new connection is answered from there.
        if held.is_none() && super::methods::serves(entry.method) {
            held = self
                .controller
                .pairing_retained(
                    super::owner::Caller::device(self.device.clone()),
                    entry.method,
                    mutation,
                )
                .await
                .map(|outcome| match outcome {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: mutation.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(mutation.request_id, error.to_protocol_error()),
                });
        }
        if let Some(retained) = held {
            if let Err(error) = self.admitted_to_answer(validated) {
                return failure(mutation.request_id, error);
            }
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
            Ok(Some(answered)) => {
                return match self.admitted_to_answer(validated) {
                    Ok(()) => answered,
                    Err(error) => failure(mutation.request_id, error),
                };
            }
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
        // before the action and inside the transaction that begins it, which is after the
        // service's own preparation.
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
                let grant_rights = rights;
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
                if let Err(error) = self.check_project_authority(entry.method, mutation) {
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
                // The service is told this caller is bounded by this device's grant, so nothing
                // the request carries can make it the owner.
                let grant = self.device.grant.grant_id;
                // On a task that outlives this connection, because a clone reaches the network and
                // a materialisation copies files: dropping that future part way through is a
                // cancellation, and what it would leave behind is exactly what an action identity
                // exists to make recoverable.
                let effect = tokio::spawn(async move {
                    controller
                        .project_mutation(&actor_id, &mutation, method, carried, Some(grant))
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
            // The change-set mutations. Like the project's, they are the daemon's own effect and
            // no session owns them, so a worker proxy is not where they belong either. They are
            // **not served to a device**, and the reason is admission rather than routing.
            //
            // A project mutation carries its admission into the transaction that begins its
            // effect, so a revocation or an expiry that completes while the service prepares
            // reaches an action that then does not begin. The change-set service offers no such
            // check: its write waits for a blocking thread and for its own store's lock with
            // nothing but the answer this door already gave, and a grant withdrawn inside that
            // window reaches an effect that goes on. For the owner's own client that window is
            // bounded by the owner being the one revoking; for a device it is the difference
            // between a revoked grant and a change this host still made on its behalf. Until the
            // change-set service asks inside its own transaction, this door does not open.
            _ if crate::changeset::ChangeSetModule::serves(entry.method) => failure(
                mutation.request_id,
                ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    format!(
                        "{} is not served to a paired device: this host cannot yet refuse a \
                         change-set write whose grant is withdrawn while the write prepares",
                        entry.method.as_str()
                    ),
                ),
            ),
            // The ten catalogue and plugin mutations. They are the daemon's own effect: a catalogue
            // and an installed package belong to the environment, so no worker owns them and the
            // module performs them under its own lock.
            _ if crate::catalogue::CatalogueModule::serves(entry.method) => {
                // The route is claimed before the effect, the way a project mutation claims its
                // own. It is this host's `(verified actor, action)` uniqueness check, and it is
                // what a device that lost its connection has left to say the daemon owns the
                // receipt. Storage that cannot record it refuses the mutation: only section 7's
                // stop goes on without a route.
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
                }
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                // The owner's own ceremony, checked by this host's pairing service against its owner
                // devices; a host with none refuses the two confirmed methods rather than
                // performing them under the identity of whoever asked.
                let pairing = self
                    .controller
                    .network
                    .get()
                    .map(|guard| Arc::clone(guard.pairing()));
                let controller = Arc::clone(&self.controller);
                let admitting = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                // On a task that outlives this connection: a sync writes verified metadata and an
                // installation extracts a package onto disk, and dropping that future part way
                // through is a cancellation. The admission travels with it, because the module
                // waits for its own lock, for the repository's and for downloads, and asks about
                // the registration again where the change becomes durable.
                let effect = tokio::spawn(async move {
                    let confirmations = pairing
                        .as_deref()
                        .map(|host| host as &dyn crate::sharing::OwnerConfirmations);
                    let admission: Arc<dyn crate::catalogue::Admission> =
                        Arc::new(crate::catalogue::DaemonAdmission::new(admitting, carried));
                    controller
                        .catalogue
                        .write(&actor_id, &mutation, method, confirmations, admission)
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
                    // known rather than that the action failed. The action record the module
                    // settles is what a resubmission is answered from.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The review and attention group's mutations are this host's own store's actions, like
            // a project's: no worker owns them, and the admission travels with them into the
            // store's transaction.
            _ if crate::attention::AttentionModule::serves(entry.method) => {
                if let Err(error) =
                    crate::attention::AttentionModule::check_subject(entry.method, mutation)
                {
                    return failure(mutation.request_id, error.to_protocol_error());
                }
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
                }
                let controller = Arc::clone(&self.controller);
                let mutation = mutation.clone();
                let request_id = mutation.request_id;
                let method = entry.method;
                let caller = crate::attention::Caller::device(&self.device.grant);
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                let effect = tokio::spawn(async move {
                    controller
                        .attention()
                        .write_frame(&controller, &caller, &actor_id, &mutation, method, &carried)
                        .await
                });
                match tokio::time::timeout(EFFECT_WAIT, effect).await {
                    Ok(Ok(answer)) => answer,
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
                // The admission travels with the change, as it does with a project or an
                // automation mutation, and the voice service asks it again where it writes.
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                match self
                    .controller
                    .voice_mutation(
                        &actor_id,
                        crate::voice::VoiceActor::Device(self.device.device_id),
                        mutation,
                        entry.method,
                        validated,
                        carried,
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
            // A device completing its own record: the daemon's own effect, on this device's own
            // row and nothing else. The parameters name no device; the one written is the one this
            // connection authenticated as. The admission travels with the declaration, so the
            // transaction that writes the keys asks about it again and records the outcome beside
            // them, which is what a retry of this action is answered from.
            Method::DeviceKeysComplete => {
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
                }
                let carried = crate::authority::AdmittedMutation {
                    connection_id: self.connection_id(),
                    admitted_revision: validated,
                    deadline: Some(accepted.deadline),
                };
                match self
                    .controller
                    .device_keys_declared(&actor_id, self.device.device_id, mutation, carried)
                    .await
                {
                    Ok(value) => ControlFrame::Response(Response {
                        request_id: mutation.request_id,
                        outcome: Outcome::Ok(value),
                    }),
                    Err(error) => failure(mutation.request_id, error.to_protocol_error()),
                }
            }
            // The automation group. Like a project mutation it is the daemon's own effect: a
            // workflow belongs to this environment rather than to a session, so it goes to the
            // automation service rather than to a worker proxy. The admission travels with it into
            // the workflow journal's own transaction, and the device reaches only the workflows
            // that act under the grant it holds, so a workflow cannot give it rights its grant
            // does not carry.
            _ if crate::automation::AutomationModule::serves(entry.method) => {
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
                let caller_grant = Some(self.device.grant.grant_id);
                // On a task that outlives this connection: a run dispatches its nodes, and
                // dropping that future part way through would be a cancellation.
                let effect = tokio::spawn(async move {
                    controller
                        .automation_mutation(&actor_id, &mutation, method, carried, caller_grant)
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
                    // The run is still going, or its task ended without an answer. Whether the
                    // action was committed is the journal's to say: if it was, a repeat is
                    // answered from its record, and if it was not, a repeat performs it.
                    Ok(Err(_)) | Err(_) => failure(request_id, outcome_unknown()),
                }
            }
            // The pairing and owner-confirmation mutations. An owner device completes the
            // confirmations it signed; `pair.confirm` and `pair.cancel` are the issuing owner's,
            // and a device never issued an invitation, so the pairing service refuses them.
            _ if super::methods::serves(entry.method) => {
                // A pairing mutation claims its action identity the way every other mutation does,
                // with this host named as the owner of what it produces.
                if let Err(refusal) = self.claim_route(mutation, None) {
                    return failure(mutation.request_id, refusal.into_error());
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
                let caller = super::owner::Caller::device(self.device.clone());
                let admission = self.controller.pairing_admission(
                    self.connection_id(),
                    Some(validated),
                    Some(accepted.deadline),
                );
                match self
                    .controller
                    .pairing_write(caller, entry.method, mutation, admission)
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
            _ => {
                self.proxied_mutation(mutation, accepted, validated, rights)
                    .await
            }
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
        if let Ok(listed) = value.to_typed::<SessionListResult>() {
            let selector = &self.device.grant.session_selector;
            let narrowed = SessionListResult {
                sessions: listed
                    .sessions
                    .into_iter()
                    .filter(|summary| selector.admits(summary.session_id))
                    .collect(),
            };
            return match ParamsValue::from_typed(&narrowed) {
                Ok(value) => ControlFrame::Response(Response {
                    request_id,
                    outcome: Outcome::Ok(value),
                }),
                Err(error) => failure(
                    request_id,
                    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
                ),
            };
        }
        if let Ok(listed) = value.to_typed::<kr_protocol::project::ProjectListResult>() {
            let selector = &self.device.grant.environment_selector;
            let narrowed = kr_protocol::project::ProjectListResult {
                projects: listed
                    .projects
                    .into_iter()
                    .filter(|summary| selector.admits(summary.environment_id))
                    .collect(),
            };
            return match ParamsValue::from_typed(&narrowed) {
                Ok(value) => ControlFrame::Response(Response {
                    request_id,
                    outcome: Outcome::Ok(value),
                }),
                Err(error) => failure(
                    request_id,
                    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
                ),
            };
        }
        if let Ok(listed) = value.to_typed::<kr_protocol::project::WorkspaceListResult>() {
            let env_selector = &self.device.grant.environment_selector;
            let session_selector = &self.device.grant.session_selector;
            let narrowed = kr_protocol::project::WorkspaceListResult {
                workspaces: listed
                    .workspaces
                    .into_iter()
                    .filter(|summary| env_selector.admits(summary.environment_id))
                    .map(|mut summary| {
                        summary
                            .bound_sessions
                            .retain(|s| session_selector.admits(*s));
                        summary
                    })
                    .collect(),
            };
            return match ParamsValue::from_typed(&narrowed) {
                Ok(value) => ControlFrame::Response(Response {
                    request_id,
                    outcome: Outcome::Ok(value),
                }),
                Err(error) => failure(
                    request_id,
                    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()),
                ),
            };
        }
        if let Ok(read) = value.to_typed::<kr_protocol::project::WorkspaceReadResult>() {
            let env_selector = &self.device.grant.environment_selector;
            if !env_selector.admits(read.workspace.environment_id) {
                return failure(request_id, outside_the_grant("working copy"));
            }
            let session_selector = &self.device.grant.session_selector;
            let mut workspace = read.workspace;
            workspace
                .bound_sessions
                .retain(|session| session_selector.admits(*session));
            return encoded(
                request_id,
                &kr_protocol::project::WorkspaceReadResult { workspace },
            );
        }
        if let Ok(read) = value.to_typed::<kr_protocol::project::ProjectReadResult>() {
            let env_selector = &self.device.grant.environment_selector;
            if !env_selector.admits(read.project.environment_id) {
                return failure(request_id, outside_the_grant("repository"));
            }
            let session_selector = &self.device.grant.session_selector;
            let narrowed = kr_protocol::project::ProjectReadResult {
                workspaces: read
                    .workspaces
                    .into_iter()
                    .filter(|summary| env_selector.admits(summary.environment_id))
                    .map(|mut summary| {
                        summary
                            .bound_sessions
                            .retain(|session| session_selector.admits(*session));
                        summary
                    })
                    .collect(),
                ..read
            };
            return encoded(request_id, &narrowed);
        }
        if let Ok(read) = value.to_typed::<kr_protocol::changeset::ChangesetReadResult>() {
            // Retained content, and the grant says how far back it reaches. A grant with no lower
            // bound retains none of it, which is the reading every other retained answer on this
            // path takes.
            let Some(bound) = self.device.grant.history.lower_bound_ms.0 else {
                return failure(
                    request_id,
                    ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this device's grant retains no history, so it does not read a recorded \
                         change-set version",
                    ),
                );
            };
            if read.version.captured_at_ms.get() < bound.get() {
                return failure(
                    request_id,
                    ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this version was captured before the moment this device's grant reaches \
                         back to",
                    ),
                );
            }
            let narrowed = kr_protocol::changeset::ChangesetReadResult {
                versions: read
                    .versions
                    .into_iter()
                    .filter(|summary| summary.captured_at_ms.get() >= bound.get())
                    .collect(),
                ..read
            };
            return encoded(request_id, &narrowed);
        }
        self.narrow_read(request_id, value)
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

    /// Answers `action.read` for a catalogue action this device performed, where there is one.
    ///
    /// A catalogue action names no session: its receipt is kept by the catalogue, beside the
    /// state the action changed, under the actor that submitted it. It is read as this device,
    /// and it is disclosed only while this device's grant still carries `host.manage`, the right
    /// every catalogue action required. Owning an action identifier is not authority, and a device
    /// whose authority over the catalogue was withdrawn is not told what it did there.
    ///
    /// `None` is a request this does not answer: one that names a session, or an action the
    /// catalogue holds no receipt for, which the session route then answers.
    async fn host_receipt(&self, request: &Request) -> Option<ControlFrame> {
        let params: kr_protocol::receipt::ActionReadParams = request.params.to_typed().ok()?;
        if params.session_id.is_some() {
            return None;
        }
        let actor_id = self.device.principal();
        let read = match self
            .controller
            .catalogue
            .action_read(&actor_id, params.action_id)
            .await
        {
            Ok(Some(read)) => read,
            Ok(None) => return None,
            Err(error) => return Some(failure(request.request_id, error)),
        };
        if !self.device.grant.permits(ActionRight::HostManage) {
            return Some(failure(
                request.request_id,
                ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this device's grant no longer carries host.manage, which the catalogue \
                     action it names required",
                ),
            ));
        }
        Some(match ParamsValue::from_typed(&read) {
            Ok(value) => ControlFrame::Response(Response {
                request_id: request.request_id,
                outcome: Outcome::Ok(value),
            }),
            Err(error) => failure(
                request.request_id,
                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()),
            ),
        })
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
        grant_rights: CanonicalSet<ActionRight>,
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
        // The rights this request was decided with travel with the mutation: the grant as this
        // host's policy and its configured ceiling leave it. The worker admits an attachment and
        // holds no grants: section 8's intersection of requested capabilities with the actor's
        // rights is made where the attachment is admitted, out of what the host checked this
        // request against.
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
        self.check_grant(session_id, entry, false).map(|_| ())
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

    /// Asks, where a retained answer is about to go back, the admission this request arrived
    /// under.
    ///
    /// Finding the answer waited, for the registry, a blocking thread or a worker's journal, and
    /// section 23 has the host check current authority before a retained receipt goes back, so a
    /// device whose registration was withdrawn or replaced meanwhile cannot use an old action
    /// identifier to read protected information. It is the check every service asks from inside
    /// its work, asked without a deadline: section 9 keeps a receipt readable after the window that
    /// admitted it is gone.
    fn admitted_to_answer(
        &self,
        validated: AuthorityRevision,
    ) -> std::result::Result<(), ProtocolError> {
        self.controller
            .check_registration(&crate::authority::AdmittedMutation {
                connection_id: self.connection_id,
                admitted_revision: validated,
                deadline: None,
            })
            .map_err(|error| error.to_protocol_error())
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

    /// Writes one batch this connection's subscription carries, and returns whether it went.
    ///
    /// What a subscription carries is a read that goes on after it was answered, and a continued
    /// read still needs valid authority. So each batch is decided through the same intersection a
    /// request is, as a subscription to the session this connection is attached to: its grant,
    /// this host's policy and the configured ceiling as they stand at that moment. The batch is
    /// then written under that decision, which the write boundary holds it to until the last byte
    /// goes. A grant the decision finds expired is latched and written down, as a request's is.
    /// Any other refusal leaves the grant alone, because nothing about the grant has ended: a
    /// lapsed offline bound, for one, holds again once the authority feed synchronises, and the
    /// device is told why by the next request it makes. Either way the batch is not written, and
    /// the relay ends the connection.
    pub async fn relay(&self, frame: &ControlFrame) -> bool {
        let attached = self
            .proxy
            .lock()
            .await
            .as_ref()
            .map(|proxy| proxy.session_id());
        // Only a link relays anything, so a batch with none behind it is not one to write.
        let Some(session_id) = attached else {
            return false;
        };
        let redecide = || self.relay_grant(session_id).is_some();
        // A decision that stopped holding before the first byte went is taken again. A change that
        // lands on every attempt is not one this batch waits out.
        for _ in 0..RELAY_DECISIONS {
            let Some(grant) = self.relay_grant(session_id) else {
                break;
            };
            let relaying = Relaying {
                grant,
                redecide: &redecide,
            };
            match self.output.write(frame, Some(relaying)).await {
                Written::Sent => return true,
                Written::Undecided => {}
                Written::Withdrawn => break,
            }
        }
        // However the batch was refused, a lapse the write boundary found on the way is owed its
        // record, and the boundary could not write it: this is the first step outside the poll
        // that can.
        self.controller.settle_floor();
        false
    }

    /// Decides whether this connection may be written what its subscription carries now, and
    /// returns the decision for the write boundary to hold the batch to.
    fn relay_grant(&self, session_id: SessionId) -> Option<RelayGrant> {
        // Read before the decision, so a change that lands while it is taken is one the write
        // sees. The time bounds are the decision's own: the offline bound as the host anchored it
        // on the continuous clock, which a decision taken again finds unchanged, and the moment in
        // UTC the decision stops holding.
        let epoch = self.controller.authority_epoch();
        let decision = self
            .check_grant(Some(session_id), Method::EventsSubscribe.entry(), false)
            .ok()?;
        Some(RelayGrant {
            epoch,
            until: decision.offline_until,
            lapses_at_ms: decision.decided.lapses_at_ms,
        })
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
        if crate::changeset::ChangeSetModule::serves(entry.method) {
            crate::changeset::ChangeSetModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // A workflow belongs to this environment rather than to a session or an application, and
        // its own subject check is the one the local ingress makes.
        if crate::automation::AutomationModule::serves(entry.method) {
            crate::automation::AutomationModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // A catalogue mutation acts on a catalogue or on an installed package, both of which belong
        // to the environment. A target naming a session or an application is refused rather than
        // producing a receipt against something the effect never touched, and the environment in
        // the parameters has to be the one the target names. Its own subject check is the one the
        // local ingress makes.
        if crate::catalogue::CatalogueModule::serves(entry.method) {
            crate::catalogue::CatalogueModule::check_subject(entry.method, mutation)
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

    /// Decides this device's request through the one intersection, and returns the rights it was
    /// decided with.
    ///
    /// Checked here first is what only this connection knows: whether the grant's own deadline,
    /// anchored on the continuous clock when the connection was admitted, has passed. Everything a
    /// grant, this host's policy and this host's configuration decide is then
    /// [`Controller::decide_for_device`]'s, which is [`crate::config::ceilings::decide_with_ceiling`]:
    /// the method's reachability, the grant's standing and expiry, the policy's organisation
    /// leases and offline bound, the environment and session its selectors admit, and every right
    /// the method requires under the conditions this request meets, taken from the grant as the
    /// policy and the configured rights ceiling leave it. A right the configuration removed is
    /// refused by name, and a grant that decision finds expired ends this connection exactly as
    /// its own deadline passing would. Last comes the history scope. A requirement that depends on the resolved
    /// subject - resource ownership, a local caller's token - is the subject's to answer, and the
    /// worker answers it inside its own dispatch barrier where the subject cannot move.
    fn check_grant(
        &self,
        session_id: Option<SessionId>,
        entry: &'static MethodEntry,
        claims_geometry: bool,
    ) -> std::result::Result<super::DeviceDecision, ProtocolError> {
        if !self.grant_is_current() {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant has expired",
            ));
        }
        let grant = self.decided_grant(entry);
        // The device's record is where its grant's standing is written: when it was committed,
        // which is when its invitation was redeemed, and when it was revoked.
        let record = crate::grants::GrantRecord {
            grant: grant.clone(),
            session_id: None,
            issued_at_ms: self.device.paired_at_ms.get(),
            activated_at_ms: Some(self.device.paired_at_ms.get()),
            revoked_at_ms: self.device.revoked_at_ms.map(|at| at.get()),
            revoked_by_parent: None,
        };
        let request = crate::grants::AccessRequest {
            method: entry.method,
            ingress: ActorIngress::PairedDevice,
            environment_id: self.controller.paths().environment_id(),
            session_id,
            claims_geometry,
            own_subject: None,
            now_ms: self.controller.wall_now_ms(),
            continuous_now: self.controller.clock.now(),
        };
        let decided = self
            .controller
            .decide_for_device(&grant, &record, request)
            .map_err(|refusal| match refusal {
                CeilingRefusal::Refused(crate::grants::Refusal::MissingRight {
                    right: ActionRight::VoiceUse,
                }) => ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this device holds no voice grant on this host",
                ),
                // The grant ran out by this host's wall clock, or by the floor under it, while
                // the deadline this connection anchored still has time on it: a clock stepped
                // forward, or a floor another decision raised. It is the same observation the
                // deadline makes, so it goes where that one goes: the latch stops every frame
                // this connection would write next, its subscription's output among them, and
                // the record keeps the device from coming back on another connection.
                expired @ CeilingRefusal::Refused(
                    crate::grants::Refusal::Expired { .. }
                    | crate::grants::Refusal::ExpiryUnrecorded { .. },
                ) => {
                    self.authority.expire();
                    expired.to_protocol_error()
                }
                other => other.to_protocol_error(),
            })?;
        self.check_history(entry)?;
        Ok(decided)
    }

    /// The grant this device's requests are decided against ([`decided_with_voice`]).
    fn decided_grant(&self, entry: &'static MethodEntry) -> kr_protocol::grant::Grant {
        decided_with_voice(&self.device.grant, entry, || self.holds_voice_grant())
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

    /// Refuses the five repository operations to a device, and says why in one sentence.
    ///
    /// Section 14 paragraph 5 puts filesystem authority in opened directory handles: a grant
    /// reaches the objects the owner authorised and nothing else. This host holds that rule over
    /// every name **it** resolves, and it does not hold it over the Git program, which finds its
    /// own repository, reads its own configuration and follows its own metadata once it is
    /// running. So an operation that runs Git for a device would give that device reach the owner
    /// never named, and this host does not start one.
    ///
    /// The local owner is unaffected: the owner's own authority runs the owner's own program,
    /// which is the posture this product has always had. The metadata methods are unaffected too:
    /// they answer from this host's own store and start nothing.
    fn check_project_authority(
        &self,
        method: Method,
        _mutation: &MutationRequest,
    ) -> std::result::Result<(), ProtocolError> {
        if matches!(
            method,
            Method::ProjectInit
                | Method::ProjectClone
                | Method::ProjectAdopt
                | Method::WorkspaceCreate
                | Method::WorkspaceRemove
        ) {
            return Err(refuses_to_run_git());
        }
        Ok(())
    }
}

/// The one refusal every method that would start the Git program for a device is given.
///
/// Section 14 paragraph 5 puts filesystem authority in opened directory handles: a grant reaches
/// the objects the owner authorised and nothing else. This host holds that rule over every name
/// **it** resolves, and it does not hold it over the Git program, which finds its own repository,
/// reads its own configuration and follows its own metadata once it is running. So it does not
/// start that program for a device, whether the method would write or only read.
fn refuses_to_run_git() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        "this host does not yet confine what the Git program reaches to the directories the \
         owner authorised, so it does not run that program for a paired device",
    )
}

/// Refuses a read of a subject in an environment this device's grant does not reach.
fn outside_the_grant(subject: &str) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        format!(
            "this device's grant does not cover this environment, so it does not read that {subject}"
        ),
    )
}

/// Answers with one narrowed result, or with the refusal encoding it produced.
fn encoded<T: serde::Serialize + serde::de::DeserializeOwned>(
    request_id: RequestId,
    value: &T,
) -> ControlFrame {
    match ParamsValue::from_typed(value) {
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

/// The grant a paired device's request for `entry` is decided against: the one its pairing
/// committed (`paired`), with one right resolved elsewhere.
///
/// `voice.use` lives in the separate voice grant section 15 paragraph 7 intersects with this one,
/// not in the grant a connection was admitted under: a person holds their ordinary authority and
/// chooses separately how much of it voice may use. So it is taken out of the pairing grant and
/// put back only for a method that needs it, when the device holds a live voice grant carrying it
/// (`holds_voice_grant`, asked only then). The policy and the configured ceiling then apply to it
/// like any other right, and the coordinator takes the intersection again at the moment of each
/// decision.
///
/// Every method that needs it is a voice method this daemon serves itself, so the rights a
/// forwarded mutation carries to a worker, which its decision cut from this grant, never include
/// it: a worker holds no work under a voice grant, and a voice grant's withdrawal owes no fence.
fn decided_with_voice(
    paired: &kr_protocol::grant::Grant,
    entry: &MethodEntry,
    holds_voice_grant: impl FnOnce() -> bool,
) -> kr_protocol::grant::Grant {
    let needs_voice = entry.required_rights.iter().any(|required| {
        matches!(
            required.authority,
            RequiredAuthority::Right {
                right: ActionRight::VoiceUse
            }
        )
    });
    let mut actions: CanonicalSet<ActionRight> = paired
        .actions
        .iter()
        .copied()
        .filter(|right| *right != ActionRight::VoiceUse)
        .collect();
    if needs_voice && holds_voice_grant() {
        actions.insert(ActionRight::VoiceUse);
    }
    kr_protocol::grant::Grant {
        actions,
        ..paired.clone()
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

    /// No frame a worker receives carries a voice right, whatever the method, which is why a
    /// voice grant's withdrawal owes no fence. A forwarded mutation carries the rights its decision
    /// permitted, cut from the grant this door decides under, and a forwarded read or input
    /// carries none. For a device whose pairing grant carries every right, `voice.use` included,
    /// and which holds a live voice grant, that grant carries `voice.use` only for a method that
    /// requires it, and every such method is one the daemon's voice module serves itself, so none
    /// of them is forwarded.
    #[test]
    fn no_frame_a_worker_receives_carries_a_voice_right() {
        use kr_protocol::authority::RequiredAuthority;
        use kr_protocol::rights::ActionRight;

        let (mut paired, _) = crate::service::net::tests::granted(
            kr_protocol::grant::GrantExpiry::Never,
            kr_protocol::ids::AuthorityRevision::new(1),
        );
        paired.actions = ActionRight::ALL.iter().copied().collect();
        let mut voice_methods = 0;
        for method in Method::ALL {
            let entry = method.entry();
            let decided = super::decided_with_voice(&paired, entry, || true);
            let requires_voice = entry.required_rights.iter().any(|required| {
                matches!(
                    required.authority,
                    RequiredAuthority::Right {
                        right: ActionRight::VoiceUse
                    }
                )
            });
            assert_eq!(
                decided.permits(ActionRight::VoiceUse),
                requires_voice,
                "{method:?} is decided with voice.use exactly when it requires it"
            );
            if requires_voice {
                voice_methods += 1;
                assert!(
                    crate::voice::VoiceModule::serves(*method),
                    "{method:?} requires voice.use, so the daemon serves it and never forwards it"
                );
            }
            // Every other right the pairing grant carries is decided as it stands.
            assert!(
                paired
                    .actions
                    .iter()
                    .filter(|right| **right != ActionRight::VoiceUse)
                    .all(|right| decided.permits(*right)),
                "{method:?}"
            );
        }
        assert!(voice_methods > 0, "the registry has voice methods");
        // Without a live voice grant not even a voice method is decided with it.
        let voice_start = Method::VoiceStart.entry();
        assert!(
            !super::decided_with_voice(&paired, voice_start, || false)
                .permits(ActionRight::VoiceUse)
        );
    }
}

#[cfg(test)]
mod write_boundary {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use kr_protocol::envelope::{ControlEvent, ControlFrame};
    use kr_protocol::ids::{ActorId, ConnectionId, DeviceId};
    use kr_protocol::scalars::{DurationMs, Nullable};

    use super::{Authorisation, FrameSink, RelayGrant, Relaying, RemoteOutput, Written};
    use crate::service::Controller;

    /// How far one frame got at the peer.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Reached {
        /// The first part of the frame, and then the peer stopped making room.
        Part,
        /// All of it.
        Whole,
    }

    /// A control stream whose writer, and whose peer, a test holds.
    ///
    /// It keeps the contract a real one keeps: the writer is taken first, and `admits` is read
    /// after it has been taken and before every attempt to hand bytes over.
    #[derive(Debug)]
    struct HeldStream {
        /// The writer. A write takes a permit, and there are none until the test gives one.
        writer: tokio::sync::Semaphore,
        /// Room at the peer for the rest of a frame, when the peer stops reading part way.
        room: Option<tokio::sync::Semaphore>,
        /// One permit each time a write starts to wait: for the writer, or for the peer.
        waits: tokio::sync::Semaphore,
        reached: std::sync::Mutex<Vec<Reached>>,
        closed: AtomicBool,
    }

    impl HeldStream {
        fn new(peer_stops_reading: bool) -> Arc<Self> {
            Arc::new(Self {
                writer: tokio::sync::Semaphore::new(0),
                room: peer_stops_reading.then(|| tokio::sync::Semaphore::new(0)),
                waits: tokio::sync::Semaphore::new(0),
                reached: std::sync::Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            })
        }

        /// Returns once writes have started to wait `times` times.
        async fn waited(&self, times: u32) {
            self.waits
                .acquire_many(times)
                .await
                .expect("the count stays open")
                .forget();
        }

        fn reached(&self) -> Vec<Reached> {
            self.reached
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn closed(&self) -> bool {
            self.closed.load(Ordering::Acquire)
        }
    }

    impl FrameSink for Arc<HeldStream> {
        fn send_while<'a>(
            &'a self,
            _frame: &'a ControlFrame,
            admits: &'a (dyn Fn() -> bool + Send + Sync),
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>,
        > {
            Box::pin(async move {
                self.waits.add_permits(1);
                let _writer = self.writer.acquire().await.expect("the writer stays open");
                if !admits() {
                    return Ok(false);
                }
                if let Some(room) = &self.room {
                    self.reached
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(Reached::Part);
                    self.waits.add_permits(1);
                    let _room = room.acquire().await.expect("the peer stays open");
                }
                if !admits() {
                    return Ok(false);
                }
                self.reached
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Reached::Whole);
                Ok(true)
            })
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Release);
        }
    }

    /// A registered connection's write boundary, writing to `stream`.
    fn output(controller: &Arc<Controller>, stream: &Arc<HeldStream>) -> RemoteOutput {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        controller.admitted_table().insert(
            connection_id,
            crate::service::AdmittedConnection {
                actor_id: ActorId::new("device:test").expect("a principal"),
                admitted_revision: controller.policy().authority_revision(),
            },
        );
        RemoteOutput::writing_to(
            Box::new(Arc::clone(stream)),
            Arc::new(Authorisation {
                controller: Arc::clone(controller),
                devices: Arc::clone(controller.devices()),
                pending: Arc::new(crate::service::net::devices::PendingExpiry::default()),
                clock: Arc::new(crate::service::net::devices::ClockTrust::default()),
                device_id: DeviceId::new(kr_ipc::new_uuid()),
                connection_id,
                grant_deadline: None,
                expired: AtomicBool::new(false),
                recorded: AtomicBool::new(false),
            }),
        )
    }

    /// The decision a batch was written under, taken now and bounded by nothing but events.
    fn decided_now(controller: &Controller) -> RelayGrant {
        RelayGrant {
            epoch: controller.authority_epoch(),
            until: None,
            lapses_at_ms: None,
        }
    }

    fn batch() -> ControlFrame {
        ControlFrame::Event(ControlEvent::Keepalive)
    }

    /// The owner chooses a bounded offline policy with no synchronisation to measure from, so a
    /// paired device's remote access is outside its bound at once.
    fn lapse_the_offline_bound(controller: &Controller) {
        controller
            .update_policy(|policy| {
                policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                    maximum_offline_ms: DurationMs::new(60_000),
                    last_synchronised_at_ms: Nullable::null(),
                }));
            })
            .expect("the owner's choice is recorded");
    }

    /// Asserts that the grant the connection writes under was left as it was.
    fn grant_left_alone(output: &RemoteOutput) {
        assert!(
            output.authority.has_time_left(),
            "a lapsed bound is not an expiry of the grant"
        );
        assert_eq!(
            output.authority.pending.owed(),
            0,
            "and no expiry is written"
        );
    }

    /// A batch decided while the bound held, and then held at the writer while it lapsed, does not
    /// reach the peer when the writer comes free. Nothing of it went, so the stream is whole and
    /// the batch is decided again rather than the connection ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_held_at_the_writer_is_not_written_once_the_policy_moves() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();

        stream.writer.add_permits(1);
        let redecide = || true;
        let relaying = Relaying {
            grant: decided_now(&controller),
            redecide: &redecide,
        };
        assert_eq!(
            output.write(&batch(), Some(relaying)).await,
            Written::Sent,
            "with nothing moving, the batch goes"
        );
        // The writer is held again from here, and the wait that write made is counted.
        stream
            .writer
            .try_acquire()
            .expect("the writer came back")
            .forget();
        stream.waited(1).await;

        let relaying = Relaying {
            grant: decided_now(&controller),
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
            stream.waited(1).await;
            lapse_the_offline_bound(&controller);
            stream.writer.add_permits(1);
        });
        assert_eq!(written, Written::Undecided);
        assert_eq!(
            stream.reached(),
            vec![Reached::Whole],
            "only the first batch went"
        );
        assert!(
            !stream.closed(),
            "the stream is whole, so the connection stands"
        );
        grant_left_alone(&output);
        drop(controller);
    }

    /// The same, with the writer never coming free: the watch finds the decision gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_that_waits_for_the_writer_is_decided_again_by_the_watch() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();

        let redecide = || true;
        let relaying = Relaying {
            grant: decided_now(&controller),
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
            stream.waited(1).await;
            lapse_the_offline_bound(&controller);
        });
        assert_eq!(written, Written::Undecided);
        assert!(stream.reached().is_empty(), "nothing reached the peer");
        assert!(!stream.closed());
        grant_left_alone(&output);
        drop(controller);
    }

    /// A batch part way to a peer that stopped reading is abandoned when the policy moves, and the
    /// connection is closed, which is what stops the rest of it: a frame left in pieces ends the
    /// stream. Whether the peer makes room again or never does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_waiting_for_the_peer_is_abandoned_once_the_policy_moves() {
        for peer_makes_room in [true, false] {
            let temp = kr_ipc::testing::TempHost::create();
            let controller = super::super::tests::daemon(&temp).await;
            let stream = HeldStream::new(true);
            let output = output(&controller, &stream);
            let frame = batch();
            stream.writer.add_permits(1);

            let redecide = || true;
            let relaying = Relaying {
                grant: decided_now(&controller),
                redecide: &redecide,
            };
            let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
                // Once for the writer, and once for the peer.
                stream.waited(2).await;
                lapse_the_offline_bound(&controller);
                if peer_makes_room {
                    stream.room.as_ref().expect("a slow peer").add_permits(1);
                }
            });
            assert_eq!(
                written,
                Written::Withdrawn,
                "peer makes room: {peer_makes_room}"
            );
            assert_eq!(stream.reached(), vec![Reached::Part], "the rest never went");
            assert!(stream.closed(), "the connection is closed");
            grant_left_alone(&output);
            drop(controller);
        }
    }

    /// A decision bounded in time stops holding when its bound passes while the batch waits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_held_past_its_decisions_bound_is_not_written() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();

        let redecide = || true;
        let relaying = Relaying {
            grant: RelayGrant {
                epoch: controller.authority_epoch(),
                until: controller
                    .clock
                    .now()
                    .checked_add(Duration::from_millis(30)),
                lapses_at_ms: None,
            },
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
            stream.waited(1).await;
            tokio::time::sleep(Duration::from_millis(60)).await;
            stream.writer.add_permits(1);
        });
        assert_eq!(written, Written::Undecided);
        assert!(stream.reached().is_empty());
        assert!(!stream.closed());
        drop(controller);
    }

    /// A decision the watch takes again and finds refused stops a waiting batch, although nothing
    /// the poll reads has moved: a clock stepped forward ends a decision that way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_the_decision_no_longer_allows_is_not_written() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();

        let allowed = AtomicBool::new(true);
        let redecide = || allowed.load(Ordering::Acquire);
        let relaying = Relaying {
            grant: decided_now(&controller),
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
            stream.waited(1).await;
            allowed.store(false, Ordering::Release);
        });
        assert_eq!(written, Written::Undecided);
        assert!(stream.reached().is_empty());
        drop(controller);
    }

    /// A batch whose decision runs out at a moment in UTC is not written once another decision
    /// has read a clock past that moment, although the epoch has not moved and the wall clock
    /// the boundary reads may be behind: the floor that decision raised is read at every attempt.
    /// Whether the batch waited for the writer, or had started and waited for the peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_is_not_written_once_the_floor_passes_its_decision() {
        for peer_stops_reading in [false, true] {
            let temp = kr_ipc::testing::TempHost::create();
            let controller = super::super::tests::daemon(&temp).await;
            let stream = HeldStream::new(peer_stops_reading);
            let output = output(&controller, &stream);
            let frame = batch();
            if peer_stops_reading {
                stream.writer.add_permits(1);
            }
            let (lasting, lasting_record) = super::super::tests::granted(
                kr_protocol::grant::GrantExpiry::Never,
                controller.policy().authority_revision(),
            );
            let lapses_at_ms = kr_ipc::now_ms().get() + 60 * 60 * 1000;

            let redecide = || true;
            let relaying = Relaying {
                grant: RelayGrant {
                    epoch: controller.authority_epoch(),
                    until: None,
                    lapses_at_ms: Some(lapses_at_ms),
                },
                redecide: &redecide,
            };
            let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
                stream.waited(if peer_stops_reading { 2 } else { 1 }).await;
                // Another request is decided at a reading past the moment, which raises the floor.
                controller
                    .decide_for_device(
                        &lasting,
                        &lasting_record,
                        super::super::tests::listing(&temp, lapses_at_ms + 1),
                    )
                    .expect("a grant that does not expire");
                if peer_stops_reading {
                    stream.room.as_ref().expect("a slow peer").add_permits(1);
                } else {
                    stream.writer.add_permits(1);
                }
            });
            if peer_stops_reading {
                assert_eq!(written, Written::Withdrawn);
                assert_eq!(stream.reached(), vec![Reached::Part]);
                assert!(stream.closed());
            } else {
                assert_eq!(written, Written::Undecided);
                assert!(stream.reached().is_empty());
                assert!(!stream.closed());
            }
            drop(controller);
        }
    }

    /// Records a paired device whose grant runs out at `expiry`, and returns the grant's identifier.
    fn a_paired_device(
        controller: &Controller,
        expiry: kr_protocol::grant::GrantExpiry,
    ) -> kr_protocol::ids::GrantId {
        let (grant, _) =
            super::super::tests::granted(expiry, controller.policy().authority_revision());
        let record = crate::service::net::devices::DeviceRecord {
            device_id: grant.recipient_device_id,
            endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([7; 32]),
            device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
            authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([8; 32]),
            stored_envelope: None,
            notification_preview: None,
            device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
            platform: kr_protocol::pairing::DevicePlatform::Ios,
            grant: grant.clone(),
            paired_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            revoked_at_ms: None,
            committed_invitation_id: None,
            expired_at_ms: None,
        };
        controller
            .devices()
            .commit(&record)
            .expect("the device is recorded");
        grant.grant_id
    }

    /// A floor raised while the policy's lock is held stops a batch as surely as one a device's
    /// decision raised. A workflow's grant that runs out at the moment the batch's decision does is
    /// refused at a reading past it, and the lock is then held while that refusal's write waits for
    /// storage. The batch is not written, whether it waited for the writer or had started and
    /// waited for the peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_is_not_written_once_a_floor_raised_under_the_lock_passes_its_decision() {
        use kr_automation::authority::AuthoritySource as _;

        for peer_stops_reading in [false, true] {
            let temp = kr_ipc::testing::TempHost::create();
            let controller = super::super::tests::daemon(&temp).await;
            let stream = HeldStream::new(peer_stops_reading);
            let output = output(&controller, &stream);
            let frame = batch();
            if peer_stops_reading {
                stream.writer.add_permits(1);
            }
            let lapses_at_ms = kr_ipc::now_ms().get() + 60 * 60 * 1000;
            let grant_id = a_paired_device(
                &controller,
                kr_protocol::grant::GrantExpiry::At {
                    expires_at_ms: kr_protocol::scalars::TimestampMs::new(lapses_at_ms),
                },
            );
            let grants = crate::automation::HostGrants::for_daemon(&controller);
            // The grant's anchor in this boot is taken the first time anything asks, which writes;
            // it is asked here, before storage is held, so the decision below waits only on the
            // floor's write.
            grants
                .grant(grant_id, kr_ipc::now_ms().get())
                .expect("the grant stands before it runs out");

            // Another writer holds storage, so the write that decision owes waits with the lock
            // held.
            let storage = rusqlite::Connection::open(temp.environment().registry_database())
                .expect("opens the registry");
            storage
                .execute_batch("BEGIN IMMEDIATE;")
                .expect("storage is held");

            let redecide = || true;
            let relaying = Relaying {
                grant: RelayGrant {
                    epoch: controller.authority_epoch(),
                    until: None,
                    lapses_at_ms: Some(lapses_at_ms),
                },
                redecide: &redecide,
            };
            let mut deciding = None;
            let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
                stream.waited(if peer_stops_reading { 2 } else { 1 }).await;
                deciding = Some(std::thread::spawn(move || {
                    grants.grant(grant_id, lapses_at_ms + 1)
                }));
                while controller.policy.try_lock().is_ok() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                if peer_stops_reading {
                    stream.room.as_ref().expect("a slow peer").add_permits(1);
                } else {
                    stream.writer.add_permits(1);
                }
                // Long enough for the write to decide, and well inside what storage waits.
                tokio::time::sleep(Duration::from_millis(300)).await;
            });
            storage.execute_batch("ROLLBACK;").expect("storage is free");
            let _ = deciding.expect("the workflow's grant was decided").join();
            if peer_stops_reading {
                assert_eq!(written, Written::Withdrawn);
                assert_eq!(stream.reached(), vec![Reached::Part]);
                assert!(stream.closed());
            } else {
                assert_eq!(written, Written::Undecided);
                assert!(stream.reached().is_empty());
                assert!(!stream.closed());
            }
            drop(controller);
        }
    }

    /// A moment in UTC the boundary reads for itself stays read. A grant runs out while its batch
    /// waits and nothing but the boundary reads the clock; the floor that reading raised is written
    /// down by the next step that may write, and a decision after the wall clock was wound back,
    /// on this connection or on another after a restart, finds the grant run out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_moment_the_boundary_reads_holds_for_every_later_decision() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();
        let lapses_at_ms = kr_ipc::now_ms().get() + 200;
        let (expiring, expiring_record) = super::super::tests::granted(
            kr_protocol::grant::GrantExpiry::At {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(lapses_at_ms),
            },
            controller.policy().authority_revision(),
        );

        let redecide = || true;
        let relaying = Relaying {
            grant: RelayGrant {
                epoch: controller.authority_epoch(),
                until: None,
                lapses_at_ms: Some(lapses_at_ms),
            },
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
            stream.waited(1).await;
            tokio::time::sleep(Duration::from_millis(400)).await;
            stream.writer.add_permits(1);
        });
        assert_eq!(written, Written::Undecided);
        assert!(stream.reached().is_empty());

        // What the relay and the record task do outside the poll.
        controller.settle_floor();
        assert!(
            super::super::tests::written_floor(&controller) >= lapses_at_ms,
            "the moment the boundary read is written down"
        );
        let wound_back = super::super::tests::listing(&temp, lapses_at_ms - 60_000);
        let refused = controller
            .decide_for_device(&expiring, &expiring_record, wound_back.clone())
            .expect_err("the moment the boundary read holds for the retry");
        assert!(
            matches!(
                refused,
                crate::config::ceilings::CeilingRefusal::Refused(
                    crate::grants::Refusal::Expired { .. }
                )
            ),
            "{refused:?}"
        );

        drop(output);
        drop(controller);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let controller = super::super::tests::daemon(&temp).await;
        controller
            .decide_for_device(&expiring, &expiring_record, wound_back)
            .expect_err("and for another connection after a restart");
        drop(controller);
    }

    /// An offline bound the boundary finds run out on the continuous clock stops the batch, and
    /// the boundary writes nothing itself: it owes the record of the time the bound has spent, and
    /// the step outside the poll that settles the floor writes it down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bound_the_boundary_finds_run_out_is_written_down_outside_the_poll() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller = super::super::tests::daemon(&temp).await;
        let stream = HeldStream::new(false);
        let output = output(&controller, &stream);
        let frame = batch();
        let synchronised = kr_ipc::now_ms().get();
        controller
            .update_policy(|policy| {
                policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                    maximum_offline_ms: DurationMs::new(200),
                    last_synchronised_at_ms: Nullable::some(
                        kr_protocol::scalars::TimestampMs::new(synchronised),
                    ),
                }));
            })
            .expect("the owner's choice is recorded");
        let (lasting, lasting_record) = super::super::tests::granted(
            kr_protocol::grant::GrantExpiry::Never,
            controller.policy().authority_revision(),
        );
        let decision = controller
            .decide_for_device(
                &lasting,
                &lasting_record,
                super::super::tests::listing(&temp, synchronised),
            )
            .expect("inside the bound");
        let recorded = |controller: &Controller| {
            controller
                .devices()
                .offline_anchor_for(synchronised, &controller.boot_identity)
                .expect("reads the record")
                .expect("the bound's time is recorded")
                .0
                .elapsed_ms
        };

        let redecide = || true;
        let relaying = Relaying {
            grant: RelayGrant {
                epoch: controller.authority_epoch(),
                until: decision.offline_until,
                lapses_at_ms: None,
            },
            redecide: &redecide,
        };
        let (written, ()) = tokio::join!(output.write(&frame, Some(relaying)), async {
            stream.waited(1).await;
            tokio::time::sleep(Duration::from_millis(400)).await;
            stream.writer.add_permits(1);
        });
        assert_eq!(written, Written::Undecided);
        assert!(stream.reached().is_empty());
        assert!(
            recorded(&controller) < 200,
            "the boundary wrote nothing itself"
        );

        // What the relay and the record task do outside the poll.
        controller.settle_floor();
        assert!(
            recorded(&controller) > 200,
            "the time the bound has spent is written down"
        );
        drop(output);
        drop(controller);
    }
}
