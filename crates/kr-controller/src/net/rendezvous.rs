//! The host's side of a short-code invitation's rendezvous room.
//!
//! A code invitation reserves a four-character locator at a rendezvous origin, and a candidate
//! reaches the host through that locator's room: the service admits candidates, relays opaque
//! frames between each of them and the host, and never holds pairing authority. Everything the
//! room carries for a pairing is a [`RendezvousMessage`], and the room reads none of it.
//!
//! ```text
//!   candidate --room socket--> room <--room socket-- this host
//!       |                                               |
//!       |   admit, client_pake, client_confirmation,    |   host_pake, host_confirmation,
//!       |   bundle                                      |   bundle, refused
//!       |                                               |
//!       +-------- pair.finish over iroh (pre-auth) ---->+
//! ```
//!
//! The room's frame vocabulary is the rendezvous service's own wire contract, in
//! [`kr_protocol::rendezvous`], and the socket both roles open is kr-client's
//! ([`kr_client::pairing::room`]). This module holds the host's two parts: the [`Rendezvous`] a
//! host reaches the service through, so a test can put an in-process room where a deployment has
//! the real one; and [`serve_room`], the task that relays one invitation's room to the pairing
//! service for as long as the invitation is on offer. The pairing decisions themselves stay in
//! kr-pairing, behind the invitation's one lock: this module decodes, forwards and sends, and
//! decides nothing.

use std::convert::Infallible;
use std::sync::{Arc, Weak};
use std::time::Duration;

use kr_client::pairing::room::RoomSocket;
use kr_crypto::secret::SymmetricKey;
use kr_pairing::platform::RendezvousHost;
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::invitation::RendezvousMessage;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::rendezvous::{ClientFrame, CloseReason, ServiceFrame, decode_message};
use kr_transport::listener::BoxFuture;
use tokio::sync::watch;

use super::pairing::PairingHost;

/// How long the host waits before attaching to its room again after the socket ended.
pub const REATTACH_DELAY: Duration = Duration::from_secs(1);

/// A rendezvous service, as a host reaches it.
///
/// The control requests are kr-pairing's [`RendezvousHost`]: a reservation and a release, which
/// the invitation's own state machine makes. Attaching to the room is the host's, because it is a
/// socket the host keeps open for as long as the invitation is on offer.
pub trait Rendezvous: RendezvousHost + Send + Sync {
    /// Opens the host's socket in the room of `locator` at `origin`, proving possession of the
    /// reservation's control token.
    fn attach(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> BoxFuture<'static, kr_pairing::Result<RoomSocket>>;
}

/// What the room relay asks of the pairing service, one invitation at a time.
///
/// The pairing service answers each of these under the invitation's one lock, so a relay never
/// decides anything itself; the trait is what lets the relay's own lifecycle be exercised against
/// a host a test controls.
pub trait RoomHost: Send + Sync + 'static {
    /// Takes one message a candidate sent through the room and returns the frames to send back.
    fn room_step(
        &self,
        invitation_id: InvitationId,
        attempt_id: AttemptId,
        message: RendezvousMessage,
    ) -> Vec<ClientFrame>;

    /// Ends one candidate's attempt, charging no guess.
    fn room_abort(&self, invitation_id: InvitationId, attempt_id: AttemptId);

    /// Answers whether the invitation is still on offer, consuming it first if its deadline has
    /// passed, and when it is not, whether releasing its locator is the relay's.
    fn room_offer(&self, invitation_id: InvitationId) -> RoomOffer;
}

/// Whether a room's invitation is still on offer, as the pairing service answers its relay.
///
/// An invitation's locator is released once, by whoever takes its release first under the
/// invitation's lock: the owner's call that ends the invitation, or the relay that finds it ended
/// by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomOffer {
    /// On offer, open or locked.
    Open,
    /// Ended by itself (its deadline passed, its guesses were spent, or its state can no longer
    /// be read), and the relay releases the locator.
    Lapsed,
    /// Ended by a call of the owner's (a cancellation, a denial, a commitment or the next
    /// invitation), which releases the locator itself.
    Withdrawn,
}

impl RoomHost for PairingHost {
    fn room_step(
        &self,
        invitation_id: InvitationId,
        attempt_id: AttemptId,
        message: RendezvousMessage,
    ) -> Vec<ClientFrame> {
        Self::room_step(self, invitation_id, attempt_id, message)
    }

    fn room_abort(&self, invitation_id: InvitationId, attempt_id: AttemptId) {
        Self::room_abort(self, invitation_id, attempt_id);
    }

    fn room_offer(&self, invitation_id: InvitationId) -> RoomOffer {
        Self::room_offer(self, invitation_id)
    }
}

/// Where one code invitation's room is, and the token that proves the host holds it.
#[derive(Clone)]
pub struct RoomTicket {
    /// The invitation the room serves.
    pub invitation_id: InvitationId,
    /// The origin the locator is reserved at.
    pub origin: RendezvousOrigin,
    /// The locator.
    pub locator: Locator,
    /// The reservation's control token.
    pub control_token: SymmetricKey,
}

impl std::fmt::Debug for RoomTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoomTicket")
            .field("invitation_id", &self.invitation_id)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// How often the relay asks the host whether its invitation is still on offer, whatever it is
/// waiting for.
///
/// The host decides expiry on its own suspend-aware clock, and the runtime's timers do not count
/// time the machine spent asleep. So the relay keeps no deadline of its own: it asks, this often,
/// and an invitation that ran out, however it ran out, ends its room within this much of the
/// machine being awake.
pub const EXPIRY_RECHECK: Duration = Duration::from_secs(1);

/// How long the relay spends delivering an ended invitation's last frames and waiting for the
/// room to confirm it closed the attempts they ended, before it releases the locator anyway.
///
/// The room acknowledges a closed attempt with `attempt_closed` on the same socket, after every
/// frame the host sent before it. Releasing only then keeps the release from overtaking the last
/// answer a candidate is owed: the release is a separate request, and nothing orders it against
/// the socket otherwise. The bound covers the sending too, so a room that stops reading cannot
/// hold an ended invitation's relay.
pub const CLOSE_ACKNOWLEDGEMENT: Duration = Duration::from_secs(5);

/// How the relay's work for one invitation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// Nothing to release here: the owner's call that ended the invitation releases its locator,
    /// or the room says the record has expired or has another host.
    Finished,
    /// The invitation ended by itself, or the pairing service let it go without ending it: its
    /// locator is released here.
    Over,
}

/// Relays one code invitation's room to the pairing service until the invitation ends.
///
/// The host attaches with its control token, and attaches again [`REATTACH_DELAY`] after the
/// socket ends while the invitation is still on offer: the room keeps candidates that arrive
/// meanwhile and tells the host about them when it is back. Every wait on the room, the pause
/// before attaching again included, goes through one [`Watch`], which watches the owner ending the
/// invitation through `stop` and asks the host whether the invitation is still on offer: the relay
/// asks before it first attaches, and the watch asks again no later than one [`EXPIRY_RECHECK`]
/// after that question and every [`EXPIRY_RECHECK`] from then on, so no room outlives its
/// invitation by more than one recheck. An invitation that ended by itself, or that the pairing
/// service let go without ending, has its locator released here; one the owner ended is released
/// by the owner's own call.
pub async fn serve_room<H: RoomHost>(
    host: Weak<H>,
    service: Arc<dyn Rendezvous>,
    ticket: RoomTicket,
    stop: watch::Receiver<bool>,
) {
    let mut watch = Watch::new(host, ticket.invitation_id, stop);
    let Err(ended) = attend(&mut watch, &*service, &ticket).await;
    if ended == Ended::Over {
        release(&service, &ticket).await;
    }
}

/// Keeps the host attached to the room while the invitation is on offer, and returns how the
/// invitation ended.
async fn attend<H: RoomHost>(
    watch: &mut Watch<H>,
    service: &dyn Rendezvous,
    ticket: &RoomTicket,
) -> Result<Infallible, Ended> {
    loop {
        watch.on_offer().await?;
        let attaching = service.attach(&ticket.origin, &ticket.locator, &ticket.control_token);
        if let Ok(socket) = watch.until(attaching).await? {
            relay(watch, socket).await?;
        }
        // The socket ended, or never opened. An invitation that ended meanwhile ends the relay
        // now; one still on offer is attached again after the pause.
        #[cfg(test)]
        probe::mark(probe::Moment::SocketEnded);
        watch.on_offer().await?;
        #[cfg(test)]
        probe::mark(probe::Moment::PauseBegan);
        watch.until(tokio::time::sleep(REATTACH_DELAY)).await?;
    }
}

/// What every wait of a relay watches besides the thing it waits for.
///
/// It owns the owner's stop and the recheck interval, and nothing else in the relay holds either,
/// so every wait on the room (attaching, reading, sending, and the pause before attaching again)
/// goes through [`Watch::until`]. None can therefore miss the owner ending the invitation, or
/// outlive the invitation by more than one [`EXPIRY_RECHECK`] of the machine being awake. The
/// relay's other waits are the pairing service's own answers, which take the invitation's lock,
/// and an ended invitation's last frames, under [`CLOSE_ACKNOWLEDGEMENT`].
struct Watch<H> {
    host: Weak<H>,
    invitation_id: InvitationId,
    stop: watch::Receiver<bool>,
    recheck: tokio::time::Interval,
}

impl<H: RoomHost> Watch<H> {
    fn new(host: Weak<H>, invitation_id: InvitationId, stop: watch::Receiver<bool>) -> Self {
        // The relay asks the host itself before it first attaches, after the watch begins, so the
        // first recheck falls due one period after the watch begins: a recheck at once would only
        // ask again what was just answered.
        let mut recheck =
            tokio::time::interval_at(tokio::time::Instant::now() + EXPIRY_RECHECK, EXPIRY_RECHECK);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            host,
            invitation_id,
            stop,
            recheck,
        }
    }

    /// Returns how the invitation ended, when it has: the owner's stop first, then the host's
    /// answer.
    async fn on_offer(&self) -> Result<(), Ended> {
        if *self.stop.borrow() {
            return Err(Ended::Finished);
        }
        self.offered().await
    }

    /// Waits for `future`, unless the invitation ends first.
    async fn until<F: Future>(&mut self, future: F) -> Result<F::Output, Ended> {
        tokio::pin!(future);
        loop {
            // In this order: an invitation the owner ended takes nothing more from the room, not
            // even what is already waiting, and a due recheck is asked before anything else.
            tokio::select! {
                biased;
                changed = self.stop.changed() => {
                    return Err(match changed {
                        Ok(()) => Ended::Finished,
                        Err(_) => self.let_go(),
                    });
                }
                _ = self.recheck.tick() => self.offered().await?,
                output = &mut future => return Ok(output),
            }
        }
    }

    /// Asks the pairing service whether the invitation is still on offer, and whose release it is
    /// when it is not, off the runtime's threads: the answer takes the invitation's lock, which a
    /// durable write may be holding.
    async fn offered(&self) -> Result<(), Ended> {
        let host = self.host.clone();
        let invitation_id = self.invitation_id;
        let answer = tokio::task::spawn_blocking(move || {
            host.upgrade()
                .map(|pairing| pairing.room_offer(invitation_id))
        })
        .await;
        match answer {
            Ok(Some(RoomOffer::Open)) => Ok(()),
            Ok(Some(RoomOffer::Lapsed)) => Err(Ended::Over),
            Ok(Some(RoomOffer::Withdrawn)) => Err(Ended::Finished),
            Ok(None) | Err(_) => Err(self.let_go()),
        }
    }

    /// How the invitation ended when the pairing service let it go without an answer, as a daemon
    /// that is going does. An owner's call that ends an invitation stops its relay and takes its
    /// release in one step, so a stopped relay leaves the release to that call; any other relay
    /// is the only one left to release the locator.
    fn let_go(&self) -> Ended {
        if *self.stop.borrow() {
            Ended::Finished
        } else {
            Ended::Over
        }
    }

    /// Runs one room step on a blocking thread: it takes the invitation's lock, which a durable
    /// write may be holding. The pairing service being gone ends the invitation, as
    /// [`Self::let_go`] says.
    async fn step(
        &self,
        attempt_id: AttemptId,
        message: RendezvousMessage,
    ) -> Result<Vec<ClientFrame>, Ended> {
        let pairing = self.host.upgrade().ok_or_else(|| self.let_go())?;
        let invitation_id = self.invitation_id;
        Ok(tokio::task::spawn_blocking(move || {
            pairing.room_step(invitation_id, attempt_id, message)
        })
        .await
        .unwrap_or_else(|_| vec![ClientFrame::CloseAttempt { attempt_id }]))
    }

    /// Ends one attempt under the invitation's lock. The pairing service being gone ends the
    /// invitation, as [`Self::let_go`] says.
    async fn abort(&self, attempt_id: AttemptId) -> Result<(), Ended> {
        let pairing = self.host.upgrade().ok_or_else(|| self.let_go())?;
        let invitation_id = self.invitation_id;
        let _ = tokio::task::spawn_blocking(move || pairing.room_abort(invitation_id, attempt_id))
            .await;
        Ok(())
    }
}

/// Relays one attachment's frames. Returns `Ok` when the socket ends while the invitation is still
/// on offer, and how the invitation ended otherwise.
async fn relay<H: RoomHost>(watch: &mut Watch<H>, mut socket: RoomSocket) -> Result<(), Ended> {
    loop {
        let Some(frame) = watch.until(socket.incoming.recv()).await? else {
            return Ok(());
        };
        let replies = match frame {
            ServiceFrame::Relay {
                attempt_id,
                payload,
            } => match decode_message(payload.as_slice()) {
                Ok(message) => watch.step(attempt_id, message).await?,
                // A payload that is not one pairing message ends that attempt, and costs the
                // invitation nothing: no confirmation result was produced. It ends here, under
                // the invitation's lock, before anything queued behind it is read; the close
                // frame only tells the room.
                Err(_) => {
                    watch.abort(attempt_id).await?;
                    vec![ClientFrame::CloseAttempt { attempt_id }]
                }
            },
            ServiceFrame::AttemptClosed { attempt_id, .. } => {
                watch.abort(attempt_id).await?;
                Vec::new()
            }
            ServiceFrame::Closed { reason } => {
                return match reason {
                    CloseReason::Expired | CloseReason::Cancelled | CloseReason::Superseded => {
                        Err(Ended::Finished)
                    }
                    _ => Ok(()),
                };
            }
            // The attachment's confirmation, a candidate declaring an attempt before it sends
            // anything, and a candidate's own record: nothing to decide until a message arrives.
            ServiceFrame::Attached { .. }
            | ServiceFrame::AttemptOpened { .. }
            | ServiceFrame::Record { .. } => Vec::new(),
        };
        if let Err(ended) = watch.offered().await {
            // This step ended the invitation: its last answers are owed before the release. An
            // owner's call that ended it meanwhile releases the locator itself, and the room
            // closes with it.
            if ended == Ended::Over {
                last_frames(&mut socket, replies).await;
            }
            return Err(ended);
        }
        for reply in replies {
            // A permit first, so a wait that the invitation's end interrupts loses no frame.
            let Ok(permit) = watch.until(socket.outgoing.reserve()).await? else {
                return Ok(());
            };
            permit.send(reply);
        }
    }
}

/// Delivers an ended invitation's last frames, and waits for the room to confirm it closed the
/// attempts they end, within one [`CLOSE_ACKNOWLEDGEMENT`] for both.
async fn last_frames(socket: &mut RoomSocket, replies: Vec<ClientFrame>) {
    let closed: Vec<AttemptId> = replies
        .iter()
        .filter_map(|reply| match reply {
            ClientFrame::CloseAttempt { attempt_id } => Some(*attempt_id),
            _ => None,
        })
        .collect();
    #[cfg(test)]
    probe::mark(probe::Moment::AcknowledgementBegan);
    let _ = tokio::time::timeout(CLOSE_ACKNOWLEDGEMENT, async {
        for reply in replies {
            if socket.outgoing.send(reply).await.is_err() {
                return;
            }
        }
        acknowledged(socket, closed).await;
    })
    .await;
}

/// Waits until the room has confirmed closing every one of `closed`, or the socket ends.
async fn acknowledged(socket: &mut RoomSocket, mut closed: Vec<AttemptId>) {
    while !closed.is_empty() {
        match socket.incoming.recv().await {
            Some(ServiceFrame::AttemptClosed { attempt_id, .. }) => {
                closed.retain(|waiting| *waiting != attempt_id);
            }
            Some(ServiceFrame::Closed { .. }) | None => return,
            Some(_) => {}
        }
    }
}

/// Releases the room's locator, so a code that can no longer pair stops reaching the host.
///
/// Best effort: a record that is not released expires by itself within the invitation's five
/// minutes.
async fn release(service: &Arc<dyn Rendezvous>, ticket: &RoomTicket) {
    let service = Arc::clone(service);
    let ticket = ticket.clone();
    let _ = tokio::task::spawn_blocking(move || {
        service.release_locator(&ticket.origin, &ticket.locator, &ticket.control_token)
    })
    .await;
}

/// The moments a relay's tests measure its own bounded waits from, marked by the relay itself on
/// its own task as each wait begins.
#[cfg(test)]
pub(crate) mod probe {
    use std::sync::{Mutex, PoisonError};
    use std::time::Instant;

    /// A moment in a relay's life.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Moment {
        /// A socket ended, or failed to open, and the relay is about to ask the host.
        SocketEnded,
        /// The pause before attaching again begins.
        PauseBegan,
        /// The bound on an ended invitation's last frames begins.
        AcknowledgementBegan,
    }

    static MARKED: Mutex<Vec<(tokio::task::Id, Moment, Instant)>> = Mutex::new(Vec::new());

    /// Marks `moment` for the task running now.
    pub(crate) fn mark(moment: Moment) {
        if let Some(task) = tokio::task::try_id() {
            MARKED.lock().unwrap_or_else(PoisonError::into_inner).push((
                task,
                moment,
                Instant::now(),
            ));
        }
    }

    /// When `task` marked `moment`, each time it did.
    pub(crate) fn marked(task: tokio::task::Id, moment: Moment) -> Vec<Instant> {
        MARKED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(by, marked, _)| *by == task && *marked == moment)
            .map(|(_, _, at)| *at)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::probe::{Moment, marked};
    use super::*;
    use kr_protocol::rendezvous::encode_message;
    use kr_protocol::scalars::{Nonce256, Uuid};
    use std::time::Instant;
    use tokio::sync::mpsc;

    /// What a relay test's host does to its invitation when it takes a step.
    #[derive(Clone, Copy)]
    enum OnStep {
        /// Keeps it on offer.
        Keeps,
        /// Ends it by itself, as the last guess does.
        Lapses,
        /// Nothing, while an owner's call ends it meanwhile and takes its release.
        Withdraws,
    }

    /// Holds the host's answers while shut, as an owner's call holding the invitation's lock does.
    #[derive(Default)]
    struct Gate {
        shut: std::sync::Mutex<bool>,
        opened: std::sync::Condvar,
        waiting: std::sync::atomic::AtomicUsize,
    }

    impl Gate {
        fn shut(&self) {
            *self.shut.lock().expect("the gate") = true;
        }

        fn open(&self) {
            *self.shut.lock().expect("the gate") = false;
            self.opened.notify_all();
        }

        /// Returns once the gate is open, or after [`WATCHDOG`]: the answer it holds runs on a
        /// blocking thread, which the runtime waits for as it shuts down, so a test that fails
        /// with the gate shut still ends.
        fn pass(&self) {
            let shut = self.shut.lock().expect("the gate");
            if *shut {
                self.waiting
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let _ = self
                .opened
                .wait_timeout_while(shut, WATCHDOG, |shut| *shut)
                .expect("the gate");
        }

        fn waiting(&self) -> usize {
            self.waiting.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// How a relay test's host answers the relay's questions. The first, which the relay asks
    /// before it attaches, is answered at once from the invitation as it stands; the others as
    /// each variant says.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Answers {
        /// At once, from the invitation as it stands.
        AtOnce,
        /// Only once the invitation has ended, as a host that a busy machine runs late does: a
        /// question the relay asks while the invitation is on offer finds it over. A question
        /// still waiting after [`WATCHDOG`] is answered as the invitation stands, so a test that
        /// fails before it ends the invitation still ends.
        AfterTheEnd,
        /// At once, and the invitation runs out just after the first answer, as a deadline that
        /// passes while the relay attaches does.
        RunningOutAfterTheFirst,
    }

    /// A host a relay test controls: on offer until the test says otherwise, answering every step
    /// with the same frames, and noting when it answered the relay and what.
    struct TestHost {
        offer: std::sync::Mutex<RoomOffer>,
        changed: std::sync::Condvar,
        replies: Vec<ClientFrame>,
        on_step: OnStep,
        answering: Answers,
        questions: std::sync::atomic::AtomicUsize,
        answers: std::sync::Mutex<Vec<(Instant, RoomOffer)>>,
        gate: Arc<Gate>,
    }

    impl TestHost {
        fn new(replies: Vec<ClientFrame>, on_step: OnStep) -> Arc<Self> {
            Self::answering(replies, on_step, Answers::AtOnce)
        }

        fn answering(replies: Vec<ClientFrame>, on_step: OnStep, answering: Answers) -> Arc<Self> {
            Arc::new(Self {
                offer: std::sync::Mutex::new(RoomOffer::Open),
                changed: std::sync::Condvar::new(),
                replies,
                on_step,
                answering,
                questions: std::sync::atomic::AtomicUsize::new(0),
                answers: std::sync::Mutex::new(Vec::new()),
                gate: Arc::new(Gate::default()),
            })
        }

        fn set(&self, offer: RoomOffer) {
            *self.offer.lock().expect("the offer") = offer;
            self.changed.notify_all();
        }

        /// The invitation ends by itself: its deadline passes.
        fn end(&self) {
            self.set(RoomOffer::Lapsed);
        }

        /// When the host answered the relay's first question.
        fn first_answered(&self) -> Instant {
            self.answers
                .lock()
                .expect("the answers")
                .first()
                .expect("the relay asked")
                .0
        }

        /// When the host first gave `answer` after `after`.
        fn answered(&self, answer: RoomOffer, after: Instant) -> Option<Instant> {
            self.answers
                .lock()
                .expect("the answers")
                .iter()
                .find(|(at, given)| *given == answer && *at > after)
                .map(|(at, _)| *at)
        }
    }

    impl RoomHost for TestHost {
        fn room_step(
            &self,
            _invitation_id: InvitationId,
            _attempt_id: AttemptId,
            _message: RendezvousMessage,
        ) -> Vec<ClientFrame> {
            match self.on_step {
                OnStep::Keeps => {}
                OnStep::Lapses => self.set(RoomOffer::Lapsed),
                OnStep::Withdraws => self.set(RoomOffer::Withdrawn),
            }
            self.replies.clone()
        }

        fn room_abort(&self, _invitation_id: InvitationId, _attempt_id: AttemptId) {}

        fn room_offer(&self, _invitation_id: InvitationId) -> RoomOffer {
            self.gate.pass();
            let first = self
                .questions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0;
            let (at, offer) = {
                let mut offer = self.offer.lock().expect("the offer");
                if !first && self.answering == Answers::AfterTheEnd {
                    offer = self
                        .changed
                        .wait_timeout_while(offer, WATCHDOG, |offer| *offer == RoomOffer::Open)
                        .expect("the offer")
                        .0;
                }
                let answer = (Instant::now(), *offer);
                if first && self.answering == Answers::RunningOutAfterTheFirst {
                    *offer = RoomOffer::Lapsed;
                }
                answer
            };
            self.answers.lock().expect("the answers").push((at, offer));
            offer
        }
    }

    /// A service whose room sockets the test holds the far ends of, and never reads.
    struct TestService {
        capacity: usize,
        released: std::sync::Mutex<Vec<Instant>>,
        attached: std::sync::Mutex<Vec<Instant>>,
        rooms: std::sync::Mutex<Vec<(mpsc::Sender<ServiceFrame>, mpsc::Receiver<ClientFrame>)>>,
        /// Whether the room answers an attach: while `false`, every attach waits.
        answering: watch::Sender<bool>,
    }

    impl TestService {
        /// A service whose room answers every attach at once.
        fn new(capacity: usize) -> Arc<Self> {
            Self::build(capacity, true)
        }

        /// A service whose room answers an attach only once the test says so, with
        /// [`Self::answer_attaches`].
        fn holding_attaches(capacity: usize) -> Arc<Self> {
            Self::build(capacity, false)
        }

        fn build(capacity: usize, answering: bool) -> Arc<Self> {
            Arc::new(Self {
                capacity,
                released: std::sync::Mutex::new(Vec::new()),
                attached: std::sync::Mutex::new(Vec::new()),
                rooms: std::sync::Mutex::new(Vec::new()),
                answering: watch::Sender::new(answering),
            })
        }

        /// The room answers the attaches waiting for it, and every one after.
        fn answer_attaches(&self) {
            self.answering.send_replace(true);
        }

        fn released(&self) -> usize {
            self.released.lock().expect("the releases").len()
        }

        /// When the locator was first released.
        fn released_at(&self) -> Instant {
            *self
                .released
                .lock()
                .expect("the releases")
                .first()
                .expect("the locator is released")
        }

        /// When the host attached, each time it did.
        fn attached(&self) -> Vec<Instant> {
            self.attached.lock().expect("the attachments").clone()
        }

        fn room(&self) -> Option<mpsc::Sender<ServiceFrame>> {
            self.rooms
                .lock()
                .expect("the rooms")
                .last()
                .map(|(sender, _)| sender.clone())
        }

        /// How many frames the host sent that the room has not read.
        fn unread(&self) -> usize {
            self.rooms
                .lock()
                .expect("the rooms")
                .last()
                .map_or(0, |(_, receiver)| receiver.len())
        }

        /// Waits until the host has filled its socket, and so waits to send more.
        async fn filled(&self) {
            tokio::time::timeout(WATCHDOG, async {
                while self.unread() < self.capacity {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the relay fills its socket");
        }

        /// Ends the room's side of every socket, as a service that restarts does.
        fn hang_up(&self) {
            self.rooms.lock().expect("the rooms").clear();
        }

        /// Closes the host's socket from the room's side, as a room does with a host that sent it
        /// something it could not read, and returns once the relay has let go of the socket.
        async fn close_socket(&self) {
            let room = self.room().expect("attached");
            room.send(ServiceFrame::Closed {
                reason: CloseReason::Invalid,
            })
            .await
            .expect("the relay reads");
            tokio::time::timeout(WATCHDOG, room.closed())
                .await
                .expect("the relay lets go of the socket");
        }
    }

    impl RendezvousHost for TestService {
        fn reserve_locator(
            &self,
            _origin: &RendezvousOrigin,
            _locator: &Locator,
            _invitation_id: InvitationId,
            _advertised_expires_at_ms: kr_protocol::scalars::TimestampMs,
            _control_token_hash: kr_protocol::scalars::Digest256,
        ) -> kr_pairing::Result<bool> {
            Ok(true)
        }

        fn release_locator(
            &self,
            _origin: &RendezvousOrigin,
            _locator: &Locator,
            _control_token: &SymmetricKey,
        ) -> kr_pairing::Result<()> {
            self.released
                .lock()
                .expect("the releases")
                .push(Instant::now());
            Ok(())
        }
    }

    impl Rendezvous for TestService {
        fn attach(
            &self,
            _origin: &RendezvousOrigin,
            _locator: &Locator,
            _control_token: &SymmetricKey,
        ) -> BoxFuture<'static, kr_pairing::Result<RoomSocket>> {
            let (to_host, incoming) = mpsc::channel(self.capacity);
            let (outgoing, from_host) = mpsc::channel(self.capacity);
            // The attach is noted before the room, so a test that sees the room sees when.
            self.attached
                .lock()
                .expect("the attachments")
                .push(Instant::now());
            self.rooms
                .lock()
                .expect("the rooms")
                .push((to_host, from_host));
            let mut answering = self.answering.subscribe();
            Box::pin(async move {
                // A service the test has dropped holds nothing back.
                let _ = answering.wait_for(|answering| *answering).await;
                Ok(RoomSocket { outgoing, incoming })
            })
        }
    }

    fn ticket() -> RoomTicket {
        RoomTicket {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            origin: RendezvousOrigin::new("https://rendezvous.example").expect("an origin"),
            locator: Locator::new("abcd").expect("a locator"),
            control_token: SymmetricKey::random().expect("a token"),
        }
    }

    /// How far past a bound a relay may end in these tests: the machine's own scheduling, never
    /// another recheck or another pause.
    const SLACK: Duration = Duration::from_millis(500);

    /// How long a stuck test waits before it fails, far past every bound these tests assert.
    const WATCHDOG: Duration = Duration::from_secs(20);

    /// How often a test that needs two events in one order before a recheck runs its sequence
    /// again when the machine's scheduling put a recheck between them.
    const PHASE_ATTEMPTS: usize = 5;

    /// The resolution of the runtime's timers: a timer fires once the runtime's clock has passed
    /// the end of the millisecond its deadline falls in, and the clock passes its milliseconds in
    /// order. So a test that has slept until one tick past an instant knows that every timer due
    /// by that instant has fallen due, whether or not its task has run since.
    const CLOCK_TICK: Duration = Duration::from_millis(1);

    /// Starts a relay for `host` over `service`, and returns it once it has attached.
    async fn relaying(
        host: &Arc<TestHost>,
        service: &Arc<TestService>,
    ) -> (tokio::task::JoinHandle<()>, watch::Sender<bool>) {
        let (stop, stopped) = watch::channel(false);
        let relay = tokio::spawn(serve_room(
            Arc::downgrade(host),
            Arc::clone(service) as Arc<dyn Rendezvous>,
            ticket(),
            stopped,
        ));
        tokio::time::timeout(WATCHDOG, async {
            while service.room().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the relay attaches");
        (relay, stop)
    }

    /// Waits for the relay to end, and fails a test that is stuck rather than slow.
    async fn finished(relay: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(WATCHDOG, relay)
            .await
            .expect("the relay ends")
            .expect("cleanly");
    }

    /// Hands the relay one message from a candidate.
    async fn deliver(service: &TestService) {
        let payload = encode_message(&RendezvousMessage::Admit {
            client_nonce: Nonce256::from_bytes([3; 32]),
        })
        .expect("a message");
        service
            .room()
            .expect("attached")
            .send(ServiceFrame::Relay {
                attempt_id: AttemptId::new(Uuid::from_bytes([2; 16])),
                payload,
            })
            .await
            .expect("the relay reads");
    }

    fn closes(count: usize) -> Vec<ClientFrame> {
        vec![
            ClientFrame::CloseAttempt {
                attempt_id: AttemptId::new(Uuid::from_bytes([2; 16])),
            };
            count
        ]
    }

    /// KR-REQ-10.33: an idle room ends with its invitation. Nothing arrives on the socket and the
    /// relay keeps no timer of its own: the host says, on its own clock, that the invitation is
    /// over, and within one recheck the relay ends and releases the locator.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_room_ends_when_its_host_says_the_invitation_is_over() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, _stop) = relaying(&host, &service).await;
        let ended = Instant::now();
        host.end();
        finished(relay).await;
        assert_eq!(service.released(), 1);
        let late = service.released_at().duration_since(ended);
        assert!(
            late <= EXPIRY_RECHECK + SLACK,
            "released {late:?} after the end"
        );
    }

    /// An invitation that runs out just after the host answered the question its relay attaches
    /// on ends its room within one recheck of running out, whether the room has answered the
    /// attach or not: that question is the relay's first, and it asks again no later than one
    /// recheck after it. The socket stays open and the owner's stop stays unsent, so only a
    /// recheck can end the relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invitation_that_runs_out_as_its_relay_attaches_ends_its_room_within_one_recheck() {
        for answered in [true, false] {
            let host =
                TestHost::answering(Vec::new(), OnStep::Keeps, Answers::RunningOutAfterTheFirst);
            let service = if answered {
                TestService::new(8)
            } else {
                TestService::holding_attaches(8)
            };
            let (relay, _stop) = relaying(&host, &service).await;
            finished(relay).await;
            let attach = if answered { "answered" } else { "waiting" };
            assert_eq!(service.released(), 1, "released, with the attach {attach}");
            let late = service.released_at().duration_since(host.first_answered());
            assert!(
                late <= EXPIRY_RECHECK + SLACK,
                "released {late:?} after the invitation ran out, with the attach {attach}"
            );
            assert_eq!(
                service.attached().len(),
                1,
                "an ended invitation is not attached again"
            );
        }
    }

    /// KR-REQ-10.33: a socket that ends after its invitation did is not followed by the pause
    /// before attaching again: the relay asks the host as the socket ends and releases the locator
    /// at once.
    ///
    /// A relay that asked the host again between attaching and its socket's end would find the
    /// invitation over there, every time: the room answers the attach only once a recheck due as
    /// the relay attached has fallen due, which the relay takes before anything the room sends,
    /// and the host answers every question after the one the relay attaches on only once the
    /// invitation has ended, as a busy machine can make it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_socket_that_ends_after_its_invitation_is_released_at_once() {
        for attempt in 1..=PHASE_ATTEMPTS {
            let host = TestHost::answering(Vec::new(), OnStep::Keeps, Answers::AfterTheEnd);
            let service = TestService::holding_attaches(8);
            let (relay, _stop) = relaying(&host, &service).await;
            let task = relay.id();
            let attached = tokio::time::Instant::from_std(service.attached()[0]);
            tokio::time::sleep_until(attached + CLOCK_TICK).await;
            host.end();
            service.answer_attaches();
            service.hang_up();
            finished(relay).await;
            // The relay marks the socket's end before it asks the host. A recheck that found the
            // end first releases without that mark, and proves nothing about the socket's end.
            let Some(ended) = marked(task, Moment::SocketEnded).first().copied() else {
                eprintln!("attempt {attempt}: a recheck ended the relay before its socket did");
                continue;
            };
            assert!(
                host.answered(RoomOffer::Lapsed, ended).is_some(),
                "the host was asked as the socket ended"
            );
            assert_eq!(service.released(), 1);
            let late = service.released_at().duration_since(ended);
            assert!(late <= SLACK, "released {late:?} after the socket ended");
            assert_eq!(
                service.attached().len(),
                1,
                "an ended invitation is not attached again"
            );
            return;
        }
        panic!("a recheck fell between the invitation's end and the socket's every time");
    }

    /// A socket that ends while the invitation is on offer is attached again after the pause, and
    /// the locator stays reserved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_socket_that_ends_while_the_invitation_is_on_offer_is_attached_again() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, _stop) = relaying(&host, &service).await;
        let task = relay.id();
        service.close_socket().await;
        tokio::time::timeout(WATCHDOG, async {
            while service.attached().len() < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the relay attaches again");
        let began = *marked(task, Moment::PauseBegan)
            .first()
            .expect("the relay paused");
        let paused = service.attached()[1].duration_since(began);
        assert!(
            paused >= REATTACH_DELAY && paused <= REATTACH_DELAY + SLACK,
            "attached again {paused:?} after the pause began"
        );
        assert_eq!(service.released(), 0, "the invitation is still on offer");
        host.end();
        finished(relay).await;
        assert_eq!(service.released(), 1);
    }

    /// The pause before attaching again is one of the relay's watched waits: the owner ending the
    /// invitation during it ends the relay at once, and leaves the release to the owner's own
    /// call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_pausing_before_it_attaches_again_still_stops() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, stop) = relaying(&host, &service).await;
        let task = relay.id();
        service.close_socket().await;
        tokio::time::timeout(WATCHDOG, async {
            while marked(task, Moment::PauseBegan).is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the relay pauses");
        let stopped = Instant::now();
        stop.send(true).expect("the relay listens");
        finished(relay).await;
        let late = stopped.elapsed();
        assert!(late <= SLACK, "ended {late:?} after the owner stopped it");
        assert_eq!(service.attached().len(), 1);
        assert_eq!(service.released(), 0, "the owner's own call releases it");
    }

    /// A relay waiting on a socket nobody reads still ends when its invitation does, without the
    /// owner stopping it, and releases the locator within one recheck.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_blocked_on_its_socket_ends_with_its_invitation() {
        let host = TestHost::new(closes(8), OnStep::Keeps);
        let service = TestService::new(1);
        let (relay, _stop) = relaying(&host, &service).await;
        deliver(&service).await;
        service.filled().await;
        assert!(!relay.is_finished(), "waiting on the socket");
        let ended = Instant::now();
        host.end();
        finished(relay).await;
        assert_eq!(service.released(), 1);
        let late = service.released_at().duration_since(ended);
        assert!(
            late <= EXPIRY_RECHECK + SLACK,
            "released {late:?} after the end"
        );
    }

    /// A step that ends the invitation has its last frames delivered and acknowledged within one
    /// bound. A room that stops reading holds the relay for that bound and no longer: the locator
    /// is released anyway.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ended_invitations_last_frames_are_bounded() {
        let host = TestHost::new(closes(8), OnStep::Lapses);
        let service = TestService::new(1);
        let (relay, _stop) = relaying(&host, &service).await;
        let task = relay.id();
        deliver(&service).await;
        finished(relay).await;
        assert_eq!(service.released(), 1);
        let began = *marked(task, Moment::AcknowledgementBegan)
            .first()
            .expect("the relay began its last frames");
        let held = service.released_at().duration_since(began);
        assert!(
            held >= CLOSE_ACKNOWLEDGEMENT,
            "the room's acknowledgement is awaited for the whole bound, and it was {held:?}"
        );
        assert!(
            held <= CLOSE_ACKNOWLEDGEMENT + SLACK,
            "released {held:?} after the bound began"
        );
    }

    /// An owner's call that ends the invitation while a step is being answered releases the
    /// locator itself: the relay ends at once, with no last frames to wait for and no release of
    /// its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invitation_the_owner_ends_during_a_step_is_left_to_the_owner() {
        let host = TestHost::new(closes(8), OnStep::Withdraws);
        let service = TestService::new(1);
        let (relay, _stop) = relaying(&host, &service).await;
        let delivered = Instant::now();
        deliver(&service).await;
        finished(relay).await;
        let late = delivered.elapsed();
        assert!(late <= SLACK, "ended {late:?} after the step");
        assert_eq!(service.released(), 0, "the owner's own call releases it");
    }

    /// An owner's call that ends the invitation while the relay waits for the host's answer takes
    /// the locator's release under the invitation's lock: the relay ends when it is answered, and
    /// the locator is released once, by the owner.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invitation_the_owner_ends_during_a_recheck_is_released_once() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, stop) = relaying(&host, &service).await;
        host.gate.shut();
        tokio::time::timeout(WATCHDOG, async {
            while host.gate.waiting() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the relay asks the host");
        // The owner's call, holding the lock: it ends the invitation, stops the relay and
        // releases the locator.
        host.set(RoomOffer::Withdrawn);
        stop.send(true).expect("the relay listens");
        let ticket = ticket();
        service
            .release_locator(&ticket.origin, &ticket.locator, &ticket.control_token)
            .expect("released");
        let answered = Instant::now();
        host.gate.open();
        finished(relay).await;
        let late = answered.elapsed();
        assert!(late <= SLACK, "ended {late:?} after the host answered");
        assert_eq!(service.released(), 1, "released once, by the owner");
    }

    /// An invitation the owner ended, with a candidate's message still waiting on the socket, is
    /// not released again when the pairing service goes too: the owner's stop is taken before
    /// anything waiting, and a relay that finds the service gone releases only an invitation the
    /// owner never ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invitation_the_owner_ended_is_not_released_again_when_its_host_goes() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, stop) = relaying(&host, &service).await;
        let gate = Arc::clone(&host.gate);
        gate.shut();
        tokio::time::timeout(WATCHDOG, async {
            while gate.waiting() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the relay asks the host");
        // While the relay waits for its answer: a message arrives, the owner ends the invitation
        // and releases the locator, and the pairing service goes.
        deliver(&service).await;
        stop.send(true).expect("the relay listens");
        let ticket = ticket();
        service
            .release_locator(&ticket.origin, &ticket.locator, &ticket.control_token)
            .expect("released");
        drop(host);
        gate.open();
        finished(relay).await;
        assert_eq!(service.released(), 1, "released once, by the owner");
    }

    /// A relay waiting on a socket nobody reads still ends at once when the owner ends the
    /// invitation, and leaves the release to the owner's own call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_blocked_on_its_socket_still_stops() {
        let host = TestHost::new(closes(8), OnStep::Keeps);
        let service = TestService::new(1);
        let (relay, stop) = relaying(&host, &service).await;
        deliver(&service).await;
        service.filled().await;
        assert!(!relay.is_finished(), "waiting on the socket");
        let stopped = Instant::now();
        stop.send(true).expect("the relay listens");
        finished(relay).await;
        let late = stopped.elapsed();
        assert!(late <= SLACK, "ended {late:?} after the owner stopped it");
        assert_eq!(service.released(), 0, "the owner's own call releases it");
    }

    /// A relay whose invitation the pairing service let go without ending it, as a daemon that is
    /// going does, releases at once the locator it still holds the token for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_room_the_host_let_go_is_released() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, stop) = relaying(&host, &service).await;
        let let_go = Instant::now();
        drop(stop);
        finished(relay).await;
        assert_eq!(service.released(), 1);
        let late = service.released_at().duration_since(let_go);
        assert!(late <= SLACK, "released {late:?} after the host let it go");
    }

    /// A relay whose pairing service has gone while the owner's stop is still there to be sent
    /// finds it gone at its next question, within one recheck, and releases the locator it still
    /// holds the token for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_whose_host_has_gone_releases_within_one_recheck() {
        let host = TestHost::new(Vec::new(), OnStep::Keeps);
        let service = TestService::new(8);
        let (relay, _stop) = relaying(&host, &service).await;
        let gone = Instant::now();
        drop(host);
        finished(relay).await;
        assert_eq!(service.released(), 1);
        let late = service.released_at().duration_since(gone);
        assert!(
            late <= EXPIRY_RECHECK + SLACK,
            "released {late:?} after the host went"
        );
    }
}
