//! The write boundary: every frame this connection sends, and the latch a withdrawal sets.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::ids::{ConnectionId, DeviceId, RequestId};
use kr_transport::listener::{AuthorisedSession, ControlSender};

use crate::grants::policy::{BoundIdentity, HeldBound, Stands};
use crate::service::Controller;

/// The QUIC application error code a withdrawn connection is closed with.
pub const WITHDRAWN: u32 = 4;

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
    /// Set once nothing more may go on this connection: by [`Self::withdraw`], and by the
    /// connection's registration going, which sets it in the critical section that removes the
    /// registration ([`Controller::latch_registration`]).
    withdrawn: Arc<AtomicBool>,
    /// How many writes have begun to wait for the turn. Read by this host's own tests, to know a
    /// write is queued behind another.
    #[cfg(test)]
    queued: std::sync::atomic::AtomicUsize,
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
    /// The latch above is set by whatever removes the registration, in the same critical section,
    /// so a frame that begins after a withdrawal finds it. The authority is read here as well, for
    /// the grant's own expiry and for a registration this connection never held: either way, no
    /// frame begins on a connection whose authority has gone.
    pub(super) authority: Arc<Authorisation>,
}

/// Where one connection's frames go.
///
/// The control stream, for every connection this host serves. It is a seam so the write boundary
/// can be exercised against a writer that is held and a peer that stops reading, which a real
/// stream does not let a test arrange on demand.
pub(super) trait FrameSink: Send + Sync + std::fmt::Debug {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelayGrant {
    pub(super) epoch: u64,
    pub(super) until: Option<kr_transport::clock::ContinuousInstant>,
    pub(super) lapses_at_ms: Option<u64>,
    /// The bounds the decision loaded, each with its cell: the batch holds only while every cell
    /// still publishes the snapshot it was decided under, and neither of that snapshot's deadlines
    /// has passed. A renewal publishes a new snapshot, so the batch is decided again under it.
    pub(super) under: Vec<HeldBound>,
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
            controller.lifetimes().owe_offline_time();
            return false;
        }
        if let Some(lapses_at_ms) = self.lapses_at_ms {
            let settled = controller.settled_utc_now();
            if settled >= lapses_at_ms {
                controller.keep_lapse(settled);
                return false;
            }
        }
        bounds_hold(controller, &self.under, HeldBound::holds_as_decided)
    }
}

/// Whether every bound in `under` still holds by `judge`, reading each clock once, and never
/// waiting: a check inside a poll takes no lock and calls no store. A bound found ended owes only
/// what a lapse owes today, which the next step outside the poll writes: in UTC, the floor the
/// reading raised; on the continuous clock, for the offline bound, the time it has spent.
pub(super) fn bounds_hold(
    controller: &Controller,
    under: &[HeldBound],
    judge: impl Fn(&HeldBound, kr_transport::clock::ContinuousInstant, u64) -> Stands,
) -> bool {
    if under.is_empty() {
        return true;
    }
    let now = controller.clock.now();
    let settled = controller.settled_utc_now();
    for held in under {
        match judge(held, now, settled) {
            Stands::Holds => {}
            Stands::Moved => return false,
            Stands::EndedInUtc => {
                controller.keep_lapse(settled);
                return false;
            }
            Stands::EndedOnTheContinuousClock => {
                if matches!(held.snapshot().identity, BoundIdentity::Offline { .. }) {
                    controller.lifetimes().owe_offline_time();
                }
                return false;
            }
        }
    }
    true
}

/// What a relayed batch is written under.
pub(super) struct Relaying<'a> {
    /// The decision that allowed it.
    pub(super) grant: RelayGrant,
    /// Takes the whole decision again. The watch calls it while the write waits, because a clock
    /// stepped forward ends a decision without moving the epoch or the continuous clock.
    pub(super) redecide: &'a (dyn Fn() -> bool + Send + Sync),
}

/// How one write ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Written {
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
pub struct ExpiryObserver(pub(super) Arc<Authorisation>);

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
pub(super) struct Authorisation {
    pub(super) controller: Arc<Controller>,
    /// Where an observed expiry is written, so the decision outlives this connection.
    pub(super) devices: Arc<super::super::devices::DeviceDirectory>,
    /// What this host owes its directory, for an expiry whose write did not succeed here.
    pub(super) pending: Arc<super::super::devices::PendingExpiry>,
    /// The boundary every reading of this host's wall clock takes.
    pub(super) clock: Arc<super::super::devices::ClockTrust>,
    pub(super) device_id: DeviceId,
    pub(super) connection_id: ConnectionId,
    /// When this connection's grant runs out, on the continuous clock.
    ///
    /// Anchored once, when the connection was admitted, from what the wall clock then said was
    /// left. A wall clock stepped afterwards cannot lengthen it, and the continuous clock is the
    /// one every other deadline on this host is measured on.
    pub(super) grant_deadline: Option<kr_transport::clock::ContinuousInstant>,
    /// When this connection's grant ends in UTC milliseconds, its expiry, when it has one. Read
    /// against this host's reading of UTC through its floor, which the reading raises.
    pub(super) grant_expires_at_ms: Option<u64>,
    /// Set the first time the grant is found to have run out. It never comes back.
    pub(super) expired: AtomicBool,
    /// Set once the expiry above has been written down, so it is written once.
    pub(super) recorded: AtomicBool,
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
    pub(super) fn expire(&self) {
        self.expired.store(true, Ordering::Release);
        self.note_expiry();
    }

    /// Returns whether this connection's grant still has time on it, on both of its clocks: its
    /// anchor on the continuous clock, and its expiry at this host's reading of UTC.
    ///
    /// Nothing but clock reads and atomics, because this is also what decides at every attempt to
    /// write a frame: a decision made inside a poll cannot wait on a lock or a database. Writing
    /// the expiry down is [`Self::note_expiry`], which the checks that can afford it call, and an
    /// expiry found in UTC also leaves the floor it was found at owed its record, which the next
    /// step that may write writes.
    pub(super) fn has_time_left(&self) -> bool {
        if self.expired.load(Ordering::Acquire) {
            return false;
        }
        if self
            .grant_deadline
            .is_some_and(|deadline| self.controller.clock.now() >= deadline)
        {
            self.expired.store(true, Ordering::Release);
            return false;
        }
        if let Some(expires_at_ms) = self.grant_expires_at_ms {
            let settled = self.controller.settled_utc_now();
            if settled >= expires_at_ms {
                self.controller.keep_lapse(settled);
                self.expired.store(true, Ordering::Release);
                return false;
            }
        }
        true
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
    pub(super) fn note_expiry(&self) {
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
    pub(super) fn new(session: &AuthorisedSession, authority: Arc<Authorisation>) -> Self {
        Self::writing_to(
            Box::new(ControlStream {
                sender: session.control.sender(),
                connection: session.connection.clone(),
            }),
            authority,
        )
    }

    pub(super) fn writing_to(sink: Box<dyn FrameSink>, authority: Arc<Authorisation>) -> Self {
        // Tied to the registration before anything can be sent: a withdrawal that removes the
        // registration sets the latch with it, so the fence below needs no read of the connection
        // table, which a poll may not take.
        let withdrawn = Arc::new(AtomicBool::new(false));
        authority
            .controller
            .latch_registration(authority.connection_id, &withdrawn);
        Self {
            turn: tokio::sync::Mutex::new(()),
            withdrawn,
            #[cfg(test)]
            queued: std::sync::atomic::AtomicUsize::new(0),
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
    /// * The registration cannot be read from a poll, so what removes it sets the latch the poll
    ///   reads, and the watch below reads it as well. A revocation that withdraws one closes the
    ///   connection itself, which is what stops a frame that is already waiting.
    pub async fn send(&self, frame: &ControlFrame) -> bool {
        self.write(frame, &[], None).await == Written::Sent
    }

    /// Writes one frame under the time bounds it was decided under, `under`, and, for a batch a
    /// subscription carries, the decision that allowed it.
    ///
    /// A response answers a request that was decided when it arrived, under the connection's own
    /// authority and the bounds its decision loaded, each read from its cell as it stands when the
    /// response is written: a renewal published meanwhile lets it go, and a bound that has ended
    /// stops it. A relayed batch is written under its decision as well. Both are read at every
    /// point [`Self::send`] reads the connection's authority: after the turn, after the writer, at
    /// every attempt to hand bytes over, and in the watch while the write waits, which also takes
    /// a batch's whole decision again. A decision or a bound that stops holding before the first
    /// byte goes leaves nothing in pieces, so the frame is answered again; once bytes are moving the
    /// connection ends with it.
    pub(super) async fn write(
        &self,
        frame: &ControlFrame,
        under: &[HeldBound],
        relaying: Option<Relaying<'_>>,
    ) -> Written {
        #[cfg(test)]
        self.queued.fetch_add(1, Ordering::SeqCst);
        let _turn = self.turn.lock().await;
        if self.has_withdrawn() {
            // Found withdrawn here and not by a call to [`Self::withdraw`] when its registration
            // went, so the connection is ended as that call ends it.
            self.withdraw();
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
            bounds_hold(&self.authority.controller, under, HeldBound::stands_at)
                && relaying
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
        let redecide = relaying.as_ref().map(|relaying| relaying.redecide);
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
    /// and what a withdrawn registration sets, by being removed ([`Controller::latch_registration`])
    /// or through [`Self::withdraw`]; the grant covers its own expiry. The registration itself is
    /// never read here, because it is behind a lock: it is read by the checks that can wait, which
    /// is every request and the watch below, and its going has already set the latch.
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

    /// Takes the turn, as a frame being written does, and holds it until it is dropped.
    #[cfg(test)]
    pub(super) async fn hold_the_turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.turn.lock().await
    }

    /// How many writes have begun to wait for the turn.
    #[cfg(test)]
    pub(super) fn writes_queued(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }
}
