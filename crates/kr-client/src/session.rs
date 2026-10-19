//! The client session: requests, receipts, events and the connection's freshness resource.
//!
//! One task reads the control stream and routes what arrives: a response to whoever is waiting on
//! that request identifier, a receipt to the receipt tracker, a notification to the event
//! subscribers, and a connection event to the session's own state. Everything a caller does goes
//! through [`Session`], which owns the bookkeeping the protocol requires:
//!
//! * the method registry decides the shape of a call, so a read cannot be submitted as a mutation
//!   and a mutation cannot be submitted without the freshness its entry demands;
//! * `action_id` is a fresh UUIDv4 the client generates, and it is recorded *before* the request is
//!   sent, so a connection that fails before the receipt arrives still leaves the client able to
//!   name the action whose outcome is uncertain;
//! * the outstanding-mutation bound is the one the connection negotiated, and a cancelled call
//!   returns its place in that bound rather than spending it;
//! * the current action window is whatever the host last issued, and the host renews it on the live
//!   connection without being asked.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::authority::{EffectClass, FreshnessRequirement};
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, MutationRequest, Notification, Outcome, ParamsValue,
    Request, Response,
};
use kr_protocol::hello::ActionWindow;
use kr_protocol::ids::{ActionId, GrantId, RequestId, StreamId};
use kr_protocol::method::Method;
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, Receipt};
use kr_protocol::scalars::{DurationMs, Nullable};
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::cursors::{Delivery, ReceiptTracker, StreamCursors};
use crate::error::{ClientError, Result};
use crate::retry::{Attempts, Failure, Recovery, RequestClass};
use crate::transport::{ControlTransport, Reach};

/// How many events the session buffers for each subscriber.
///
/// A subscriber that falls this far behind is told so rather than being waited for: section 9 says
/// a slow client receives a resynchronisation requirement and cannot hold the host's loop.
pub const EVENT_BUFFER: usize = 1024;

/// What the host answered one request with.
#[derive(Clone)]
enum Answer {
    /// A read's response.
    Response(Response),
    /// A mutation's receipt.
    Receipt(Box<Receipt>),
}

impl std::fmt::Debug for Answer {
    /// Which kind of answer it is and, for a receipt, the action and its state; never a result.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Response(_) => formatter.write_str("Response(..)"),
            Self::Receipt(receipt) => formatter
                .debug_struct("Receipt")
                .field("action_id", &receipt.action_id)
                .field("state", &receipt.state)
                .finish_non_exhaustive(),
        }
    }
}

/// How the host settled one mutation.
///
/// Section 23 gives a mutation two kinds of answer and they mean different things. A response
/// correlates the request and carries the method's own result, which is what a caller needs to go
/// on with: the attachment a `session.attach` allocated, the lease a `input.acquire` took. A
/// receipt carries the action's durable execution state, which is what a caller asks about when it
/// does not know whether its action happened. A host sends whichever it has; this names which
/// arrived rather than making a caller guess.
#[derive(Clone)]
pub enum Settled {
    /// The host answered with the method's own result.
    Result(ParamsValue),
    /// The host answered with a receipt for the action.
    Receipt(Box<Receipt>),
}

impl std::fmt::Debug for Settled {
    /// Which kind of settlement it is and, for a receipt, the action and its state; never a result.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Result(_) => formatter.write_str("Result(..)"),
            Self::Receipt(receipt) => formatter
                .debug_struct("Receipt")
                .field("action_id", &receipt.action_id)
                .field("state", &receipt.state)
                .finish_non_exhaustive(),
        }
    }
}

impl Settled {
    /// Returns the receipt, when the host answered with one.
    #[must_use]
    pub fn receipt(&self) -> Option<&Receipt> {
        match self {
            Self::Receipt(receipt) => Some(receipt),
            Self::Result(_) => None,
        }
    }

    /// Returns the method's result, when the host answered with one.
    #[must_use]
    pub const fn result(&self) -> Option<&ParamsValue> {
        match self {
            Self::Result(value) => Some(value),
            Self::Receipt(_) => None,
        }
    }

    /// Parses the method's result.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Cbor`] when the result is not this type, and
    /// [`ClientError::Host`] when the host answered with a receipt instead of a result: an action
    /// whose receipt is all the host had has produced no result to parse.
    pub fn to_typed<R>(&self) -> Result<R>
    where
        R: kr_protocol::wire::WireMessage,
    {
        match self {
            Self::Result(value) => Ok(value.to_typed()?),
            Self::Receipt(receipt) => Err(ClientError::refusal(
                kr_protocol::error::ErrorCode::OutcomeUnknown,
                crate::shown!(
                    "action {} is {} and has no result yet",
                    receipt.action_id,
                    receipt.state.as_str()
                ),
            )),
        }
    }
}

/// Whom this connection owes an answer, and whether it can still give one.
///
/// The map and the ended flag are one thing under one synchronous lock. With two, a request could
/// be registered after the reader stopped and wait for an answer that is never coming; and a
/// waiter's destructor could not remove its own entry, because a destructor cannot await.
#[derive(Debug, Default)]
struct Waiters {
    pending: HashMap<RequestId, oneshot::Sender<Answer>>,
    ended: bool,
}

/// One mutation this client sent and has not seen settled.
///
/// The identifier alone is not enough to act on: a person asking what happened needs to know which
/// intent is uncertain, and two cancelled calls leave two identifiers that would otherwise be
/// indistinguishable. The record is immutable, and it is what a reconnect carries.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmittedAction {
    /// The durable operation identity.
    pub action_id: ActionId,
    /// The method it asked for.
    pub method: Method,
    /// The exact subject it named.
    pub target: ActionTarget,
    /// The parameters it carried.
    ///
    /// Two calls of the same method on the same subject differ only here — two renames of one
    /// session to two labels, say — so without this a caller could not tell which of its own
    /// uncertain actions is which.
    pub params: ParamsValue,
    /// The request it was sent as, which correlates the host's answer.
    pub request_id: RequestId,
    /// Whether the caller settles this action, and no answer does.
    ///
    /// An action sent through [`Session::send`] or [`Session::repeat`] is one whose caller keeps
    /// its own record of the attempt, and stays unresolved here until the caller says what the
    /// answer came to ([`Session::settle`]), whatever the answer was: a refusal of any code is not
    /// a decision about an action whose outcome is being asked after.
    pub held: bool,
}

crate::debug_fields!(SubmittedAction {
    action_id,
    method,
    request_id,
    held
});

/// Whose identity a mutation is submitted under.
///
/// A first submission is a new intent and takes a new identifier. A continuation answers a demand
/// the host made about one action it has already settled by asking, and so has to carry that
/// action's own identifier: the host bound its demand to it, and anything else is a request it
/// never made.
#[derive(Clone, Copy, Debug)]
enum Continuation {
    /// A new intent.
    None,
    /// The action a host asked about, and whose answer this is.
    Of(ActionId),
}

impl Continuation {
    /// The identifier this submission goes out under.
    fn action_id(self) -> Result<ActionId> {
        match self {
            Self::None => Ok(ActionId::new(kr_transport::random::fresh_uuid_v4()?)),
            Self::Of(action_id) => Ok(action_id),
        }
    }

    /// Whether this submission reuses an identifier rather than minting one.
    const fn is_continuation(self) -> bool {
        matches!(self, Self::Of(_))
    }
}

/// A mutation built and not yet sent: the request, exactly, the connection it was built on, and the
/// host and actor it is for.
///
/// It is what a client keeps to ask the host again about an action whose answer it lost. The
/// request is kept whole, window included, because the host's record of an action is keyed by what
/// the action was, and a request composed anew under a later window is a different request for the
/// same action, which the host refuses. The host keys that record by the actor that sent the
/// request too, so a repeat is sent only to the host, and as the actor, it was composed for. It
/// never prints the request.
#[derive(Clone, PartialEq, Eq)]
pub struct ComposedMutation {
    request: MutationRequest,
    /// The session that composed it, none for one read back from a record kept across a restart.
    composed_on: Option<u64>,
    /// The host and actor it was composed for, none when the transport could not say.
    reach: Option<Reach>,
    window_issued_at_ms: u64,
    window_valid_for_ms: u64,
}

crate::debug_fields!(ComposedMutation {
    composed_on,
    window_issued_at_ms,
    window_valid_for_ms
});

impl ComposedMutation {
    /// A composed mutation read back from a record a client kept, for a connection that did not
    /// compose it. It can be repeated and never sent first, and not at all by a connection whose
    /// host and actor are not `reach`.
    ///
    /// Whether a connection issued the window it carries is decided by the window, so a restored
    /// request is not repeated on the connection that was issued it either.
    #[must_use]
    pub const fn restored(
        request: MutationRequest,
        window_issued_at_ms: u64,
        window_valid_for_ms: u64,
        reach: Option<Reach>,
    ) -> Self {
        Self {
            request,
            composed_on: None,
            reach,
            window_issued_at_ms,
            window_valid_for_ms,
        }
    }

    /// The request, for a client to keep.
    #[must_use]
    pub const fn request(&self) -> &MutationRequest {
        &self.request
    }

    /// The action the request carries.
    #[must_use]
    pub const fn action_id(&self) -> ActionId {
        self.request.action_id
    }

    /// The host and actor the request is for, for a client to keep.
    #[must_use]
    pub const fn reach(&self) -> Option<&Reach> {
        self.reach.as_ref()
    }

    /// When the host issued the window the request carries, in UTC milliseconds.
    #[must_use]
    pub const fn window_issued_at_ms(&self) -> u64 {
        self.window_issued_at_ms
    }

    /// How long the host said that window stays valid, in milliseconds.
    #[must_use]
    pub const fn window_valid_for_ms(&self) -> u64 {
        self.window_valid_for_ms
    }
}

/// What this client knows about its own mutations.
///
/// `correlations` is what lets the reader settle an action whose caller has gone: a correlated
/// answer names a request, and only this map knows which action that request carried.
#[derive(Clone, Debug, Default)]
struct Outcomes {
    receipts: ReceiptTracker,
    submitted: BTreeMap<ActionId, SubmittedAction>,
    correlations: HashMap<RequestId, ActionId>,
}

impl Outcomes {
    /// Settles the action one correlated answer belongs to, if it is still pending.
    ///
    /// An action its caller holds ([`SubmittedAction::held`]) stays: only the caller settles it.
    fn settle(&mut self, request_id: RequestId) {
        if let Some(action_id) = self.correlations.remove(&request_id)
            && !self
                .submitted
                .get(&action_id)
                .is_some_and(|action| action.held)
        {
            self.submitted.remove(&action_id);
        }
    }

    /// Settles one action by the caller's word, whatever its answer was.
    fn settle_action(&mut self, action_id: ActionId) {
        self.submitted.remove(&action_id);
        self.correlations.retain(|_, held| *held != action_id);
    }

    /// Refuses to reuse an identifier that still stands for something this client must report.
    ///
    /// Two records would otherwise share one identifier: the intent already submitted and the one
    /// arriving now. The book holds one record per action, so the first would be lost, and both
    /// requests would stay correlated to the same action, so whichever answered first would settle
    /// the other's submission as well. Section 9 forbids forgetting an action, and an action whose
    /// outcome is unknown or whose receipt has not finished is exactly one that must not be lost.
    fn refuse_replacement(&self, action_id: ActionId) -> Result<()> {
        let unknown = self.submitted.contains_key(&action_id);
        let receipted = self.receipts.get(&action_id).is_some();
        if unknown || receipted {
            return Err(ClientError::refusal(
                kr_protocol::error::ErrorCode::InvalidArgument,
                crate::shown::Shown::said(
                    "that action is one this client is still accounting for, so it cannot carry \
                 another request",
                ),
            ));
        }
        Ok(())
    }

    /// Records one submission, or refuses when too many are already unresolved.
    fn submit(&mut self, action: SubmittedAction) -> Result<()> {
        if self.submitted.len() >= MAX_UNRESOLVED_ACTIONS
            && !self.submitted.contains_key(&action.action_id)
        {
            return Err(ClientError::TooManyUnresolvedActions {
                limit: MAX_UNRESOLVED_ACTIONS,
            });
        }
        self.correlations
            .insert(action.request_id, action.action_id);
        self.submitted.insert(action.action_id, action);
        Ok(())
    }
}

/// How many of this client's actions may be unresolved at once.
///
/// An unresolved action is one whose outcome nobody knows, and section 9 forbids forgetting one.
/// The bound is what stops "never forget" becoming "grow for ever". A client reaches it through
/// accepted actions whose receipts have not settled as much as through a host it cannot reach, and
/// either way submitting more would only add to the pile.
pub const MAX_UNRESOLVED_ACTIONS: usize = 1024;

/// The shared state of one connection.
struct SessionState {
    waiters: std::sync::Mutex<Waiters>,
    action_window: Mutex<ActionWindow>,
    /// Every action window the host issued to this connection, the current one included. A window
    /// admits a request on the connection it was issued to and on no other, so a request carrying
    /// one of these is one this connection could admit.
    issued_windows: std::sync::Mutex<Vec<kr_protocol::ids::ActionWindowId>>,
    cursors: Mutex<StreamCursors>,
    /// What each action's receipt last said, and which actions were sent without a settled outcome.
    ///
    /// One lock, because a reconnect copies both and a receipt moves an action from one to the
    /// other. Two locks would let a snapshot fall between the two writes and carry neither.
    outcomes: Mutex<Outcomes>,
    events: broadcast::Sender<Notification>,
    /// True once the connection has ended, which a holder of the session may wait for.
    ended: tokio::sync::watch::Sender<bool>,
    /// Raised each time the host refuses a request on the connection as not permitted, except a
    /// read sent with [`Session::read_unsignalled`].
    denied: tokio::sync::Notify,
    /// The requests whose refusal is not raised: those a holder asks to learn whether the host
    /// withdrew the connection, whose refusal is its answer and not a new question.
    unsignalled: std::sync::Mutex<std::collections::BTreeSet<RequestId>>,
    outstanding: AtomicU64,
    max_outstanding: u64,
}

crate::debug_fields!(SessionState {
    outstanding,
    max_outstanding
});

impl SessionState {
    /// Ends the session, waking every waiter.
    ///
    /// A waiter that is dropped rather than answered resolves as [`ClientError::ConnectionEnded`],
    /// which is what its caller is waiting to hear. Ending twice is harmless.
    fn end(&self) {
        let mut waiters = self.waiters();
        waiters.ended = true;
        waiters.pending.clear();
        drop(waiters);
        self.ended.send_replace(true);
    }

    fn waiters(&self) -> std::sync::MutexGuard<'_, Waiters> {
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn answer(&self, request_id: RequestId, answer: Answer) {
        let waiter = self.waiters().pending.remove(&request_id);
        if let Some(sender) = waiter {
            let _ = sender.send(answer);
        }
    }
}

/// A client's connection to one host.
pub struct Session {
    /// Which session this is, among every one started in this process.
    id: u64,
    transport: Arc<dyn ControlTransport>,
    state: Arc<SessionState>,
    next_request_id: AtomicU64,
    reader: tokio::task::JoinHandle<()>,
}

/// The identity the next session started in this process takes.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

crate::debug_as_name!(Session);

impl Session {
    /// Starts a session on an authorised connection.
    ///
    /// The reader task begins immediately, because the host may send a window renewal or an event
    /// before the client asks for anything.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ConnectionEnded`] when another session already reads this
    /// connection. Two sessions on one control stream would divide its frames between them.
    pub fn start(transport: Arc<dyn ControlTransport>) -> Result<Self> {
        Self::resume(transport, StreamCursors::new())
    }

    /// Starts a session that carries what a previous connection had reached.
    ///
    /// This is the client half of section 8's restoration: the cursors come from
    /// [`crate::reconnect::ClientState`], which kept each stream's content position and dropped the
    /// previous connection's event sequences.
    ///
    /// # Errors
    ///
    /// As [`Session::start`].
    pub fn resume(transport: Arc<dyn ControlTransport>, cursors: StreamCursors) -> Result<Self> {
        transport.claim_receiver()?;
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let limits = transport.limits();
        let initial = transport.initial_action_window();
        let state = Arc::new(SessionState {
            waiters: std::sync::Mutex::new(Waiters::default()),
            issued_windows: std::sync::Mutex::new(vec![initial.action_window_id.clone()]),
            action_window: Mutex::new(initial),
            cursors: Mutex::new(cursors),
            outcomes: Mutex::new(Outcomes::default()),
            events,
            ended: tokio::sync::watch::channel(false).0,
            denied: tokio::sync::Notify::new(),
            unsignalled: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            outstanding: AtomicU64::new(0),
            max_outstanding: limits.max_outstanding_mutations.get(),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&transport), Arc::clone(&state)));
        Ok(Self {
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            transport,
            state,
            next_request_id: AtomicU64::new(1),
            reader,
        })
    }

    /// The host this connection reaches and the actor it acts as, when the transport can say.
    #[must_use]
    pub fn reach(&self) -> Option<Reach> {
        self.transport.reach()
    }

    /// Returns the transport, for opening data streams.
    #[must_use]
    pub fn transport(&self) -> &Arc<dyn ControlTransport> {
        &self.transport
    }

    /// Returns the action window the host last issued.
    pub async fn action_window(&self) -> ActionWindow {
        self.state.action_window.lock().await.clone()
    }

    /// Subscribes to the events the host sends on this connection.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<Notification> {
        self.state.events.subscribe()
    }

    /// Returns the cursors this session has reached.
    pub async fn cursors(&self) -> StreamCursors {
        self.state.cursors.lock().await.clone()
    }

    /// Returns the receipts this session has seen.
    pub async fn receipts(&self) -> ReceiptTracker {
        self.state.outcomes.lock().await.receipts.clone()
    }

    /// Returns the actions this client submitted whose outcome it has not seen settled.
    ///
    /// A reconnecting client asks the host about these. It never resubmits one: section 9 forbids
    /// dispatching an identifier again because its receipt is incomplete.
    pub async fn submitted_actions(&self) -> Vec<SubmittedAction> {
        self.state
            .outcomes
            .lock()
            .await
            .submitted
            .values()
            .cloned()
            .collect()
    }

    /// Returns the receipts and the unsettled submissions together.
    ///
    /// A reconnect takes both in one step: a receipt that arrives between two separate reads would
    /// be missing from one and already removed from the other.
    pub async fn outcomes(&self) -> (ReceiptTracker, Vec<SubmittedAction>) {
        let outcomes = self.state.outcomes.lock().await;
        (
            outcomes.receipts.clone(),
            outcomes.submitted.values().cloned().collect(),
        )
    }

    /// Records that a consumer applied everything up to `sequence` on `stream_id`.
    ///
    /// Only this moves the position a reconnect subscribes from. Receiving an event is not applying
    /// it: an event the connection delivered but nothing folded into its state has to arrive again.
    pub async fn applied(&self, stream_id: &StreamId, sequence: kr_protocol::ids::EventSequence) {
        self.state.cursors.lock().await.applied(stream_id, sequence);
    }

    /// Records that a snapshot at `sequence` was installed, which makes the stream usable again.
    pub async fn installed_snapshot(
        &self,
        stream_id: &StreamId,
        sequence: kr_protocol::ids::EventSequence,
    ) {
        self.state
            .cursors
            .lock()
            .await
            .installed_snapshot(stream_id, sequence);
    }

    /// Calls a read method and parses its result.
    ///
    /// A read the registry marks idempotent is sent again when the host refuses it with a
    /// transient code, under [`crate::retry`]'s bounded attempt count and jittered backoff. The
    /// caller sees the last answer rather than each attempt. Every other refusal comes straight
    /// back, and [`ClientError::decision`] says what the policy makes of it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongEffect`] when the registry says the method mutates, and the
    /// host's error when it refuses.
    pub async fn read<P, R>(&self, method: Method, params: &P) -> Result<R>
    where
        P: Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        self.read_signalling(method, params, true).await
    }

    /// Reads as [`Self::read`] does, without raising [`Self::denied`] when the host refuses it as
    /// not permitted, however late the refusal arrives.
    ///
    /// For a holder that asks the host whether it withdrew this connection: the question's own
    /// refusal is its answer, and must not start the question again.
    ///
    /// # Errors
    ///
    /// As [`Self::read`].
    pub async fn read_unsignalled<P, R>(&self, method: Method, params: &P) -> Result<R>
    where
        P: Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        self.read_signalling(method, params, false).await
    }

    async fn read_signalling<P, R>(&self, method: Method, params: &P, signalling: bool) -> Result<R>
    where
        P: Serialize + ?Sized,
        R: kr_protocol::wire::WireMessage,
    {
        let entry = method.entry();
        if entry.effect != EffectClass::Read {
            return Err(ClientError::WrongEffect {
                method,
                expected: "mutation",
                actual: "read",
            });
        }
        // The registry decides the class, not this call site. A read it does not mark idempotent
        // is not one section 23 permits an automatic retry for, whatever its effect class says.
        let class =
            if entry.idempotency == kr_protocol::authority::IdempotencyBehaviour::IdempotentRead {
                RequestClass::IdempotentRead
            } else {
                RequestClass::Dispatchable
            };
        // Encoded once. Each attempt is the same request, and encoding it again per attempt would
        // let a caller's value change under the retry.
        let params = ParamsValue::from_typed(params)?;
        let mut attempts = Attempts::new();
        loop {
            match self
                .send_read(method, entry.version, &params, signalling)
                .await?
            {
                Ok(value) => return Ok(value.to_typed()?),
                Err(error) => {
                    let decision = attempts.decide(Failure::new(error.code), class);
                    let Recovery::Retry { delay } = decision.recovery else {
                        return Err(ClientError::from(error));
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Sends one read and returns the host's answer, or the client-side failure that stopped it.
    ///
    /// The two failures are separated because only one of them is a decision the policy makes: a
    /// host that refused said why, and a connection that ended did not. A transport failure is
    /// never retried here: the reconnect loop owns that, and a second request on a connection
    /// that has gone would fail the same way.
    async fn send_read(
        &self,
        method: Method,
        version: kr_protocol::method::MethodVersion,
        params: &ParamsValue,
        signalling: bool,
    ) -> Result<std::result::Result<ParamsValue, kr_protocol::error::ProtocolError>> {
        let request_id = self.next_request_id();
        let waiter = self.register(request_id)?;
        if !signalling {
            self.state
                .unsignalled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(request_id);
        }
        let request = Request {
            request_id,
            method: method.into(),
            method_version: version,
            params: params.clone(),
        };
        self.transport.send(&ControlFrame::Request(request)).await?;

        match waiter.wait().await? {
            Answer::Response(response) => match response.outcome {
                Outcome::Ok(value) => Ok(Ok(value)),
                Outcome::Error(error) => Ok(Err(error)),
            },
            Answer::Receipt(_) => Err(ClientError::refusal(
                kr_protocol::error::ErrorCode::InvalidArgument,
                crate::shown::Shown::said("a read was answered with a receipt"),
            )),
        }
    }

    /// Submits a mutation and waits for the host to settle it.
    ///
    /// The identifier is generated here and recorded before the request is sent. A retry is a new
    /// request with the same identifier, which the host de-duplicates; a new intent is a new
    /// identifier.
    ///
    /// This library never sends a mutation again by itself, whatever the host refused it with.
    /// Section 23 permits an automatic retry for idempotent reads, transfer chunks and requests
    /// whose receipt proves no dispatch, and a mutation is none of those until its receipt says so.
    /// The caller decides, with [`ClientError::decision`] for
    /// [`crate::retry::RequestClass::Dispatchable`] to hand it the policy's answer. A caller that
    /// wants to ask the host what became of an action it lost the answer to composes the request
    /// first ([`Session::compose`]) and repeats exactly that request ([`Session::repeat`]); an
    /// exact repeat is a question, answered from the host's record, and not a retry.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongEffect`] for a read method,
    /// [`ClientError::TooManyOutstandingMutations`] at the negotiated bound, and
    /// [`ClientError::SubmissionUncertain`] when the connection ends after the request was sent:
    /// that error names the action whose outcome the client must ask about rather than resubmit.
    pub async fn mutate<P, E>(
        &self,
        method: Method,
        target: ActionTarget,
        grant_id: Option<GrantId>,
        expected: &E,
        params: &P,
        requested_ttl: DurationMs,
    ) -> Result<Settled>
    where
        P: Serialize + ?Sized,
        E: Serialize + ?Sized,
    {
        self.submit_mutation(
            Continuation::None,
            method,
            target,
            grant_id,
            expected,
            params,
            requested_ttl,
        )
        .await
    }

    /// Submits the evidence a host asked for, under the identity of the request that asked.
    ///
    /// Some methods answer a first submission by naming what else they need before they will act:
    /// a confirmation taken on the device's unlocked screen, for instance. The host binds that
    /// demand to the action it was asked about, so the answer has to come back as the same action.
    /// A fresh identifier here would be a second intent, and the host would refuse it for naming a
    /// request it never challenged.
    ///
    /// `continues` is therefore the identifier the host's own challenge carries, read out of the
    /// evidence the caller is submitting rather than chosen. Nothing about this weakens what the
    /// host checks: the host still compares the evidence against the action it issued the demand
    /// for, and a caller that names a different action is refused there.
    ///
    /// Only an action this client has already heard about can be continued. One whose outcome is
    /// still unknown is refused: its record is the only thing that can name the intent a person
    /// must be able to ask about, and replacing it with a second set of parameters would lose that
    /// intent while leaving two requests correlated to one action, either of whose answers would
    /// then settle the other. One whose receipt this client already holds is refused for the same
    /// reason. Section 9 forbids forgetting an action, and this is where that would happen.
    ///
    /// In every other respect this is [`Session::mutate`], including the outstanding bound and the
    /// uncertainty an interrupted send leaves behind.
    ///
    /// # Errors
    ///
    /// The same as [`Session::mutate`], and a refusal when `continues` names an action this client
    /// is still waiting on or already holds a receipt for.
    #[allow(clippy::too_many_arguments)]
    pub async fn mutate_continuing<P, E>(
        &self,
        continues: ActionId,
        method: Method,
        target: ActionTarget,
        grant_id: Option<GrantId>,
        expected: &E,
        params: &P,
        requested_ttl: DurationMs,
    ) -> Result<Settled>
    where
        P: Serialize + ?Sized,
        E: Serialize + ?Sized,
    {
        self.submit_mutation(
            Continuation::Of(continues),
            method,
            target,
            grant_id,
            expected,
            params,
            requested_ttl,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn submit_mutation<P, E>(
        &self,
        identity: Continuation,
        method: Method,
        target: ActionTarget,
        grant_id: Option<GrantId>,
        expected: &E,
        params: &P,
        requested_ttl: DurationMs,
    ) -> Result<Settled>
    where
        P: Serialize + ?Sized,
        E: Serialize + ?Sized,
    {
        let entry = method.entry();
        if entry.effect != EffectClass::Write {
            return Err(ClientError::WrongEffect {
                method,
                expected: "read",
                actual: "mutation",
            });
        }
        // The permit is returned when it is dropped, including when the caller cancels this future
        // part way through. Without that, eight cancelled calls would spend the connection's whole
        // mutation allowance for its lifetime.
        let _permit = MutationPermit::acquire(&self.state)?;

        // The registry decides whether this method needs the connection's freshness resource. A
        // method whose entry does not name one still carries the current window: the host derives
        // the accepted deadline from whichever bound is earliest, and a window it did not need
        // costs nothing.
        let action_window_id = {
            let window = self.state.action_window.lock().await;
            if entry.freshness == FreshnessRequirement::ActionWindow
                && window.valid_for_ms.get() == 0
            {
                return Err(ClientError::NoActionWindow);
            }
            window.action_window_id.clone()
        };

        let action_id = identity.action_id()?;
        let request_id = self.next_request_id();
        let waiter = self.register(request_id)?;
        let target_record = target.clone();
        let params_record = ParamsValue::from_typed(params)?;
        let mutation = MutationRequest {
            request_id,
            method: method.into(),
            method_version: entry.version,
            action_id,
            grant_id: Nullable(grant_id),
            target,
            expected: ParamsValue::from_typed(expected)?,
            action_window_id,
            requested_ttl_ms: requested_ttl,
            params: params_record.clone(),
        };

        // The frame is built and checked against the negotiated bound *before* the action is
        // recorded. A frame that cannot be sent was never sent, so it is a definite failure rather
        // than an unknown outcome.
        let frame = ControlFrame::Mutation(Box::new(mutation));
        // The bound in force is the smaller of the stream kind's ceiling and what the peer
        // negotiated, which is exactly what the writer will apply.
        let bound = usize::try_from(self.transport.limits().max_control_frame_len.get())
            .unwrap_or(usize::MAX)
            .saturating_sub(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN)
            .min(kr_protocol::frame::StreamKind::Control.max_payload_len());
        kr_cbor::to_canonical_vec_within(
            &frame,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(bound),
        )?;

        // Recorded before the send: once the frame is on the wire the host may dispatch it, and a
        // client that cannot name the action cannot ask what happened to it. The correlation goes
        // in at the same time, so the reader can settle this action even if this caller goes away.
        //
        // A continuation is checked against the same book under the same lock, so nothing can
        // submit the action between the check and the record.
        {
            let mut outcomes = self.state.outcomes.lock().await;
            if identity.is_continuation() {
                outcomes.refuse_replacement(action_id)?;
            }
            outcomes.submit(SubmittedAction {
                action_id,
                method,
                target: target_record,
                params: params_record,
                request_id,
                held: false,
            })?;
        }
        if self.transport.send(&frame).await.is_err() {
            // The frame may or may not have reached the host, so the action stays on the pending
            // list and the caller is told the outcome is unknown.
            return Err(ClientError::SubmissionUncertain { action_id });
        }

        match waiter.wait().await {
            Ok(Answer::Receipt(receipt)) => Ok(Settled::Receipt(receipt)),
            Ok(Answer::Response(response)) => {
                // Whether this action is settled was decided where the answer was routed, and it
                // is not decided twice: an answer that says the outcome is unknown leaves the
                // action on the unresolved list, and section 9 forbids forgetting one.
                match response.outcome {
                    Outcome::Error(error) => Err(refused_or_unknown(action_id, error)),
                    Outcome::Ok(value) => Ok(Settled::Result(value)),
                }
            }
            Err(_) => Err(ClientError::SubmissionUncertain { action_id }),
        }
    }

    /// Builds a mutation and sends nothing.
    ///
    /// It takes the connection's current action window, as [`Session::mutate`] does, and returns
    /// the whole request: the action identifier the caller chose, the window's identity and the
    /// requested time to live. Nothing is recorded in this session's book and nothing leaves, so a
    /// caller can write its own record of the attempt first and send afterwards
    /// ([`Session::send`]), and can ask the host again with exactly this request
    /// ([`Session::repeat`]).
    ///
    /// The identifier is the caller's because a caller may have to name it before it exists: an
    /// owner's confirmation of a transfer is asked for the action that will spend it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongEffect`] for a read method, [`ClientError::NoActionWindow`] when
    /// the host has issued no usable window, and [`ClientError::Cbor`] when the request does not
    /// encode or does not fit the connection's frame bound: a request that cannot be sent was never
    /// sent.
    #[allow(clippy::too_many_arguments)]
    pub async fn compose<P, E>(
        &self,
        method: Method,
        action_id: ActionId,
        target: ActionTarget,
        grant_id: Option<GrantId>,
        expected: &E,
        params: &P,
        requested_ttl: DurationMs,
    ) -> Result<ComposedMutation>
    where
        P: Serialize + ?Sized,
        E: Serialize + ?Sized,
    {
        let entry = method.entry();
        if entry.effect != EffectClass::Write {
            return Err(ClientError::WrongEffect {
                method,
                expected: "read",
                actual: "mutation",
            });
        }
        let window = {
            let window = self.state.action_window.lock().await;
            if entry.freshness == FreshnessRequirement::ActionWindow
                && window.valid_for_ms.get() == 0
            {
                return Err(ClientError::NoActionWindow);
            }
            window.clone()
        };
        let request = MutationRequest {
            // Replaced by whichever session sends it.
            request_id: RequestId::new(0),
            method: method.into(),
            method_version: entry.version,
            action_id,
            grant_id: Nullable(grant_id),
            target,
            expected: ParamsValue::from_typed(expected)?,
            action_window_id: window.action_window_id,
            requested_ttl_ms: requested_ttl,
            params: ParamsValue::from_typed(params)?,
        };
        self.check_frame(&request)?;
        Ok(ComposedMutation {
            request,
            composed_on: Some(self.id),
            reach: self.transport.reach(),
            window_issued_at_ms: window.issued_at_ms.get(),
            window_valid_for_ms: window.valid_for_ms.get(),
        })
    }

    /// Sends a composed mutation for the first time, on the connection that composed it.
    ///
    /// The window it carries is bound to this connection, so this is the one connection that can
    /// admit it. The action is recorded here before the request is sent, as [`Session::mutate`]
    /// records it, and stays unresolved until the caller settles it ([`Session::settle`]),
    /// whatever the answer was.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the mutation was composed on another connection, which cannot admit
    /// it, or when this client is still accounting for the action; and otherwise as
    /// [`Session::mutate`].
    pub async fn send(&self, composed: &ComposedMutation) -> Result<Settled> {
        if composed.composed_on != Some(self.id) {
            return Err(ClientError::Misdirected { repeating: false });
        }
        self.submit_composed(composed).await
    }

    /// Asks the host again with exactly the request that was composed, on another connection.
    ///
    /// This is how a client asks what became of an action whose answer it lost: the host answers a
    /// repeat of an action from the record it kept of it, before it looks at the window, and the
    /// window the request carries admits nothing on a connection other than the one it was issued
    /// to. So a repeat can only ever be answered from that record, and can never be the first
    /// admission of the action; the host performs an action at most once however often it is asked.
    /// A repeat on the connection that composed the request is refused for that reason.
    ///
    /// The library never repeats by itself. The action is recorded in this session's book like any
    /// other and stays unresolved until the caller settles it ([`Session::settle`]), so a second
    /// lost answer still leaves something to report. A repeat gets no new deadline: the host
    /// answers it from its record or not at all.
    ///
    /// # Errors
    ///
    /// Returns a refusal when this is the connection that composed the request or was issued its
    /// window ([`ClientError::Misdirected`]), when it reaches another host or acts as another actor
    /// than the request was composed for ([`ClientError::OtherHost`]), or when this client is still
    /// accounting for the action ([`ClientError::StillAccounting`]); and otherwise as
    /// [`Session::mutate`].
    pub async fn repeat(&self, composed: &ComposedMutation) -> Result<Settled> {
        // Whether this connection composed the request is decided by the window it carries as well
        // as by the record of it: a request read back from a kept record names no session, and its
        // window still admits it here when the host has not seen it.
        if composed.composed_on == Some(self.id)
            || self
                .state
                .issued_windows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&composed.request.action_window_id)
        {
            return Err(ClientError::Misdirected { repeating: true });
        }
        // The host keeps its record under the actor that sent the request. Sent to another host or
        // as another actor it would find none, which is a first admission or a refusal that says
        // nothing of the action; it is not sent.
        match (&composed.reach, self.transport.reach()) {
            (Some(composed_for), Some(this)) if *composed_for == this => {}
            _ => return Err(ClientError::OtherHost),
        }
        self.submit_composed(composed).await
    }

    /// Reads what the host recorded of an action, and lets that record settle the action here.
    ///
    /// An action whose answer was lost, or whose answer said the host could not establish its
    /// outcome, stays on the unresolved list: section 9 forbids forgetting it. A record that says
    /// it was applied, refused or rejected is the host deciding what became of it, so the action
    /// leaves the list, as it would have had the answer come. A record that says less settles
    /// nothing, and an action its caller holds ([`Session::send`] and [`Session::repeat`]) stays
    /// until the caller settles it.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, as [`Session::read`] does.
    pub async fn read_receipt(&self, params: &ActionReadParams) -> Result<ActionReadResult> {
        let read: ActionReadResult = self.read(Method::ActionRead, params).await?;
        if read.receipt.action_id == params.action_id && read.receipt.state.is_terminal() {
            let mut outcomes = self.state.outcomes.lock().await;
            outcomes.receipts.record(read.receipt.clone());
            if !outcomes
                .submitted
                .get(&params.action_id)
                .is_some_and(|action| action.held)
            {
                outcomes.settle_action(params.action_id);
            }
        }
        Ok(read)
    }

    /// Settles an action by the caller's word, once it has decided what the answers came to.
    ///
    /// Only an action sent through [`Session::send`] or [`Session::repeat`] needs this: the
    /// library settles every other action itself, as the host answers it.
    pub async fn settle(&self, action_id: ActionId) {
        self.state.outcomes.lock().await.settle_action(action_id);
    }

    /// Checks a request against the negotiated frame bound, before anything is recorded.
    fn check_frame(&self, request: &MutationRequest) -> Result<()> {
        let frame = ControlFrame::Mutation(Box::new(request.clone()));
        // The bound in force is the smaller of the stream kind's ceiling and what the peer
        // negotiated, which is exactly what the writer will apply.
        let bound = usize::try_from(self.transport.limits().max_control_frame_len.get())
            .unwrap_or(usize::MAX)
            .saturating_sub(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN)
            .min(kr_protocol::frame::StreamKind::Control.max_payload_len());
        kr_cbor::to_canonical_vec_within(
            &frame,
            &kr_cbor::Limits::DEFAULT.with_max_message_len(bound),
        )?;
        Ok(())
    }

    /// Records a composed mutation as held by its caller and sends it under a request identifier
    /// of this session's.
    async fn submit_composed(&self, composed: &ComposedMutation) -> Result<Settled> {
        let Some(method) = composed.request.method.method() else {
            return Err(ClientError::Cbor(crate::shown::Shown::said(
                "a composed mutation names a method this build lacks",
            )));
        };
        let _permit = MutationPermit::acquire(&self.state)?;
        let action_id = composed.request.action_id;
        let request_id = self.next_request_id();
        let waiter = self.register(request_id)?;
        let mut request = composed.request.clone();
        request.request_id = request_id;
        self.check_frame(&request)?;
        let frame = ControlFrame::Mutation(Box::new(request));
        {
            let mut outcomes = self.state.outcomes.lock().await;
            outcomes
                .refuse_replacement(action_id)
                .map_err(|_| ClientError::StillAccounting)?;
            outcomes.submit(SubmittedAction {
                action_id,
                method,
                target: composed.request.target.clone(),
                params: composed.request.params.clone(),
                request_id,
                held: true,
            })?;
        }
        if self.transport.send(&frame).await.is_err() {
            return Err(ClientError::SubmissionUncertain { action_id });
        }
        match waiter.wait().await {
            Ok(Answer::Receipt(receipt)) => Ok(Settled::Receipt(receipt)),
            Ok(Answer::Response(response)) => match response.outcome {
                Outcome::Error(error) => Err(refused_or_unknown(action_id, error)),
                Outcome::Ok(value) => Ok(Settled::Result(value)),
            },
            Err(_) => Err(ClientError::SubmissionUncertain { action_id }),
        }
    }

    /// Subscribes to a session's event streams from the cursor the parameters name.
    ///
    /// Section 8 fixes the order: subscribe from a cursor *before* installing the snapshot, so the
    /// host can return the state at that cursor and queue everything after it. The parameters come
    /// from [`crate::cursors::Restoration::subscribe_params`], which is what keeps the cursor this
    /// asks for the one the client actually holds.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, including [`ClientError::ResyncRequired`] when the client's
    /// position is no longer usable.
    pub async fn subscribe_events(
        &self,
        params: &kr_protocol::recovery::EventsSubscribeParams,
    ) -> Result<kr_protocol::recovery::EventsSubscribeResult> {
        self.read(Method::EventsSubscribe, params).await
    }

    /// Takes a session's snapshot and the cursor it was taken at.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal.
    pub async fn events_snapshot(
        &self,
        params: &kr_protocol::recovery::EventsSnapshotParams,
    ) -> Result<kr_protocol::recovery::EventsSnapshotResult> {
        self.read(Method::EventsSnapshot, params).await
    }

    /// Reads one page of a session's retained output history.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal.
    pub async fn history_page(
        &self,
        params: &kr_protocol::recovery::HistoryPageParams,
    ) -> Result<kr_protocol::recovery::HistoryPageResult> {
        self.read(Method::HistoryPage, params).await
    }

    /// Reads what an installed decoder read of one approval request and the decisions it offered.
    ///
    /// The answer is the record the host's approval ledger keeps: whose package's decoder read the
    /// request, the request's original bytes and their digest, the decisions offered in the
    /// upstream's order, the upstream's deadline and where the request stands now. It states what
    /// the decoder offered, not that the decoder read the request correctly, and the original bytes
    /// are there for a person to check the one against the other.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal. A resource of another instance, one no decoder interpreted and
    /// one the host does not hold are one refusal, and the host does not say which it was.
    pub async fn inspect_approval(
        &self,
        params: &kr_protocol::agent::AgentApprovalInspectParams,
    ) -> Result<kr_protocol::agent::AgentApprovalInspectResult> {
        self.read(Method::AgentApprovalInspect, params).await
    }

    /// Writes one ordered batch of raw input under the lease this attachment holds.
    ///
    /// Raw input is the one write that is not a mutation. Section 9 makes it a separate ordered
    /// stream keyed by connection, lease epoch and sequence, with no durable de-duplication and
    /// nothing replayed on reconnection, so it carries no action identifier and receives no
    /// receipt: it is ordered by its own sequence and acknowledged by what the host forwarded.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, including the lease refusal when this attachment no longer
    /// holds input.
    pub async fn write_input(
        &self,
        params: &kr_protocol::input::InputWriteParams,
    ) -> Result<kr_protocol::input::InputWriteResult> {
        let entry = Method::InputWrite.entry();
        debug_assert!(
            entry.idempotency == kr_protocol::authority::IdempotencyBehaviour::OrderedStream,
            "input is written as an ordered stream"
        );
        let request_id = self.next_request_id();
        let waiter = self.register(request_id)?;
        let request = Request {
            request_id,
            method: Method::InputWrite.into(),
            method_version: entry.version,
            params: ParamsValue::from_typed(params)?,
        };
        self.transport.send(&ControlFrame::Request(request)).await?;
        match waiter.wait().await? {
            Answer::Response(response) => match response.outcome {
                Outcome::Ok(value) => Ok(value.to_typed()?),
                Outcome::Error(error) => Err(ClientError::from(error)),
            },
            Answer::Receipt(_) => Err(ClientError::refusal(
                kr_protocol::error::ErrorCode::InvalidArgument,
                crate::shown::Shown::said("raw input is an ordered stream and receives no receipt"),
            )),
        }
    }

    /// Records that a consumer applied a stream's content up to `cursor`.
    ///
    /// This is the position the next subscription resumes from, so only a consumer that has folded
    /// the content into its state moves it.
    pub async fn applied_content(&self, stream_id: &StreamId, cursor: kr_protocol::scalars::U64) {
        self.state
            .cursors
            .lock()
            .await
            .applied_content(stream_id, cursor);
    }

    /// Forgets every per-connection sequence and keeps every content position.
    ///
    /// A client that carries its cursors onto a new connection calls this: the host numbers a
    /// fresh subscription's events from its own beginning, so the previous connection's sequences
    /// would make the first event of the new one read as a duplicate.
    pub async fn reconnected(&self) {
        self.state.cursors.lock().await.reconnected();
    }

    /// Resolves once the connection has ended, whichever end ended it.
    ///
    /// The event stream does not say so: it belongs to the session, which lives as long as a holder
    /// keeps it, so a holder that wants to know the host went away waits here.
    pub async fn closed(&self) {
        let mut ended = self.state.ended.subscribe();
        // The value is read once the subscription exists, so an end that came first is not missed.
        let _ = ended.wait_for(|ended| *ended).await;
    }

    /// Resolves when the host refuses a request on this connection as not permitted, except a read
    /// sent with [`Self::read_unsignalled`], whose refusal raises nothing.
    ///
    /// A holder that owns the connection uses it to ask the host again, over another connection,
    /// whether it was the connection the host refused: a host that has withdrawn what a connection
    /// was admitted under refuses everything on it and does not close it, so nothing else says the
    /// connection is dead. Refusals that arrive while nobody waits are kept as one, so a holder is
    /// told once it asks, and told once for any number that arrived meanwhile.
    pub async fn denied(&self) {
        self.state.denied.notified().await;
    }

    /// Ends the session and the connection, waking every waiting call.
    ///
    /// The transition is synchronous, so a caller that drops this future still leaves the session
    /// ended and every waiter woken.
    pub fn close(&self) {
        self.transport.close();
        self.state.end();
        self.reader.abort();
    }

    fn register(&self, request_id: RequestId) -> Result<Waiter> {
        let mut waiters = self.state.waiters();
        if waiters.ended {
            return Err(ClientError::ConnectionEnded);
        }
        let (sender, receiver) = oneshot::channel();
        waiters.pending.insert(request_id, sender);
        drop(waiters);
        Ok(Waiter {
            state: Arc::clone(&self.state),
            request_id,
            receiver: Some(receiver),
        })
    }

    fn next_request_id(&self) -> RequestId {
        RequestId::new(self.next_request_id.fetch_add(1, Ordering::AcqRel))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A dropped session ends its connection. Leaving it open would hold the transport, its
        // streams and its queued traffic with nothing left to read or answer them.
        self.transport.close();
        self.state.end();
        self.reader.abort();
    }
}

/// One outstanding mutation's place in the connection's bound.
#[derive(Debug)]
struct MutationPermit {
    state: Arc<SessionState>,
}

impl MutationPermit {
    fn acquire(state: &Arc<SessionState>) -> Result<Self> {
        let taken = state.outstanding.fetch_add(1, Ordering::AcqRel);
        if taken >= state.max_outstanding {
            state.outstanding.fetch_sub(1, Ordering::AcqRel);
            return Err(ClientError::TooManyOutstandingMutations {
                limit: usize::try_from(state.max_outstanding).unwrap_or(usize::MAX),
            });
        }
        Ok(Self {
            state: Arc::clone(state),
        })
    }
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        self.state.outstanding.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One registered request, deregistered if its caller goes away before the answer arrives.
#[derive(Debug)]
struct Waiter {
    state: Arc<SessionState>,
    request_id: RequestId,
    receiver: Option<oneshot::Receiver<Answer>>,
}

impl Waiter {
    async fn wait(mut self) -> Result<Answer> {
        let Some(receiver) = self.receiver.take() else {
            unreachable!("a waiter waits once");
        };
        receiver.await.map_err(|_| ClientError::ConnectionEnded)
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        // A cancelled call leaves nothing behind. The lock is synchronous and is never held across
        // an await, so this always removes the entry rather than hoping to.
        self.state.waiters().pending.remove(&self.request_id);
    }
}

/// Reads the control stream until it ends, routing what arrives.
async fn read_loop(transport: Arc<dyn ControlTransport>, state: Arc<SessionState>) {
    loop {
        let frame = match transport.recv().await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        if !route(&state, frame).await {
            break;
        }
    }
    // The control stream has ended, so the connection goes with it: closing revokes every data
    // stream it authorised and releases the transport rather than leaving queued traffic on a
    // connection nothing is reading. Every waiter learns that its answer is not coming.
    transport.close();
    state.end();
}

/// What a host's refusal of a mutation is, given the action the mutation carried.
///
/// A host that says it cannot establish whether the action happened has not refused it, and the
/// client holds the identifier the host's answer lacks, so the two travel together.
fn refused_or_unknown(
    action_id: ActionId,
    error: kr_protocol::error::ProtocolError,
) -> ClientError {
    if error.code.retry_category() == kr_protocol::error::RetryCategory::OutcomeUnknown {
        ClientError::OutcomeUnknown { action_id, error }
    } else {
        ClientError::from(error)
    }
}

/// Returns whether one response settled what it answered.
///
/// An error whose retry category is an unknown outcome has settled nothing: the host is saying it
/// does not know whether the action happened. Everything else is a decision, including a refusal.
fn definite(response: &Response) -> bool {
    match &response.outcome {
        Outcome::Ok(_) => true,
        Outcome::Error(error) => {
            error.code.retry_category() != kr_protocol::error::RetryCategory::OutcomeUnknown
        }
    }
}

/// Routes one frame, and returns whether the session may continue.
///
/// A frame that does not belong on this ingress ends the session. The union is closed so that a
/// receiver can *name* what arrived rather than guess at it, and naming it is only worth anything
/// if the receiver then refuses it: a host that sent a client a worker's startup handshake is not
/// a host this client understands, and carrying on would mean deciding, frame by frame, which of
/// its messages to believe.
async fn route(state: &Arc<SessionState>, frame: ControlFrame) -> bool {
    match frame {
        ControlFrame::Response(response) => {
            let request_id = response.request_id;
            let unsignalled = state
                .unsignalled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&request_id);
            if let Outcome::Error(error) = &response.outcome
                && error.code == kr_protocol::error::ErrorCode::PermissionDenied
                && !unsignalled
            {
                state.denied.notify_one();
            }
            // A correlated answer settles the action *when it is definite*. Most are: the host
            // reached a decision about whatever the request carried, and settling it here rather
            // than in the caller means a caller that has gone away does not leave its action
            // pending for ever. An answer that says the outcome is unknown is not a decision, and
            // section 9 forbids forgetting one: the action stays on the unresolved list so the
            // client can ask what became of it rather than assume.
            if definite(&response) {
                state.outcomes.lock().await.settle(request_id);
            } else {
                state.outcomes.lock().await.correlations.remove(&request_id);
            }
            state.answer(request_id, Answer::Response(response));
        }
        ControlFrame::Receipt(answer) => {
            let request_id = answer.request_id;
            let receipt = answer.receipt;
            {
                let mut outcomes = state.outcomes.lock().await;
                outcomes.receipts.record(receipt.clone());
                outcomes.correlations.remove(&request_id);
                if receipt.state.is_terminal()
                    && !outcomes
                        .submitted
                        .get(&receipt.action_id)
                        .is_some_and(|action| action.held)
                {
                    outcomes.submitted.remove(&receipt.action_id);
                }
            }
            state.answer(request_id, Answer::Receipt(Box::new(receipt)));
        }
        ControlFrame::Notification(notification) => {
            // A gap leaves the stream owing a snapshot, which the cursors record: no later event
            // can establish a position on top of state with a hole in it. The event is still
            // delivered, because a subscriber that is rebuilding wants to know why, but a duplicate
            // is not: a subscriber that already applied it would apply it twice.
            let delivery = state.cursors.lock().await.accept(&notification);
            if delivery != Delivery::Duplicate {
                let _ = state.events.send(notification);
            }
        }
        ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
            {
                let mut issued = state
                    .issued_windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !issued.contains(&window.action_window_id) {
                    issued.push(window.action_window_id.clone());
                }
            }
            *state.action_window.lock().await = window;
        }
        ControlFrame::Event(ControlEvent::Keepalive) => {}
        // A client never receives a request or a mutation: the host does not call the client. The
        // rest of the union belongs to the host's own local endpoints — the local opening frames,
        // a worker's startup handshake, the generation and revision exchange, and a mutation one
        // host process forwarded to another. None of them is a frame a network peer may send a
        // client. They are named rather than swept up by a wildcard, so a variant added later has
        // to be decided here instead of quietly joining this list.
        ControlFrame::Request(_)
        | ControlFrame::Mutation(_)
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
        | ControlFrame::LocalAccess(_)
        | ControlFrame::LocalAccessAck(_)
        // A daemon's plugin admissions and a worker's report on them are that pair's own.
        | ControlFrame::PluginAdmissions(_)
        | ControlFrame::PluginAdmissionsAck(_)
        // A worker's request for the plugin runtime and the daemon's answer are that pair's own.
        | ControlFrame::PluginRuntimeWanted(_)
        | ControlFrame::PluginRuntimeState(_)
        | ControlFrame::DraftWanted(_)
        | ControlFrame::DraftAnswer(_)
        | ControlFrame::Forwarded(_)
        | ControlFrame::ForwardedRead(_)
        // A marked retained answer travels between a host and a worker, never to a client: what a
        // client submitted is answered as its own action, retained or performed.
        | ControlFrame::RetainedResponse(_)
        | ControlFrame::AcceptanceDelivered(_)
        // The control daemon's attention link to a worker, which is a local endpoint's too.
        | ControlFrame::AttentionSources(_)
        | ControlFrame::AttentionSourcePage(_)
        | ControlFrame::AttentionText(_)
        | ControlFrame::AttentionTextAnswer(_)
        | ControlFrame::AttentionBarrier(_)
        | ControlFrame::AttentionBarrierAcknowledged(_)
        // The control daemon's privacy notice to a worker and the worker's answer.
        | ControlFrame::PrivacyGeneration(_)
        | ControlFrame::PrivacyGenerationAck(_)
        // The control daemon's request for a session's description facts, and the worker's page.
        | ControlFrame::DescriptionFacts(_)
        | ControlFrame::DescriptionFactsPage(_)
        // The control daemon's request that a worker perform the disclosed checks, and the
        // worker's findings.
        | ControlFrame::DesktopChecks(_)
        | ControlFrame::DesktopChecksAnswer(_) => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};

    fn receipt() -> Receipt {
        Receipt {
            action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
            actor_id: kr_protocol::ids::ActorId::new("device:test").expect("a principal"),
            method: Method::SessionCreate.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            revision: kr_protocol::scalars::U64::new(2),
            state: kr_protocol::receipt::ReceiptState::Dispatching,
            reason: Nullable::null(),
            payload_digest: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::null(),
            error_withheld: false,
            updated_at_ms: kr_protocol::scalars::TimestampMs::new(0),
        }
    }

    /// An answer and a settlement render which kind they are and, for a receipt, the action and
    /// its state, exactly: never a result a host sent.
    #[test]
    fn an_answer_and_a_settlement_render_only_their_kind_and_the_receipts_place() {
        let result =
            ParamsValue::from_typed(&BTreeMap::from([("text", NEVER_RENDERED)])).expect("a result");
        let receipt_rendered = "Receipt{action_id:ActionId(Uuid(\
                                01010101-0101-0101-0101-010101010101)),state:Dispatching,..}";
        renders_only(&Settled::Result(result.clone()), "Result(..)");
        renders_only(&Settled::Receipt(Box::new(receipt())), receipt_rendered);
        renders_only(
            &Answer::Response(kr_protocol::envelope::Response {
                request_id: RequestId::new(1),
                outcome: kr_protocol::envelope::Outcome::Ok(result),
            }),
            "Response(..)",
        );
        renders_only(&Answer::Receipt(Box::new(receipt())), receipt_rendered);
    }
}
