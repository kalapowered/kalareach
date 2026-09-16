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
use kr_protocol::receipt::Receipt;
use kr_protocol::scalars::{DurationMs, Nullable};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::cursors::{Delivery, ReceiptTracker, StreamCursors};
use crate::error::{ClientError, Result};
use crate::transport::ControlTransport;

/// How many events the session buffers for each subscriber.
///
/// A subscriber that falls this far behind is told so rather than being waited for: section 9 says
/// a slow client receives a resynchronisation requirement and cannot hold the host's loop.
pub const EVENT_BUFFER: usize = 1024;

/// What the host answered one request with.
#[derive(Clone, Debug)]
enum Answer {
    /// A read's response.
    Response(Response),
    /// A mutation's receipt.
    Receipt(Box<Receipt>),
}

/// How the host settled one mutation.
///
/// Section 23 gives a mutation two kinds of answer and they mean different things. A response
/// correlates the request and carries the method's own result, which is what a caller needs to go
/// on with: the attachment a `session.attach` allocated, the lease a `input.acquire` took. A
/// receipt carries the action's durable execution state, which is what a caller asks about when it
/// does not know whether its action happened. A host sends whichever it has; this names which
/// arrived rather than making a caller guess.
#[derive(Clone, Debug)]
pub enum Settled {
    /// The host answered with the method's own result.
    Result(ParamsValue),
    /// The host answered with a receipt for the action.
    Receipt(Box<Receipt>),
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
        R: DeserializeOwned + Serialize,
    {
        match self {
            Self::Result(value) => Ok(value.to_typed()?),
            Self::Receipt(receipt) => {
                Err(ClientError::Host(kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::OutcomeUnknown,
                    format!(
                        "action {} is {} and has no result yet",
                        receipt.action_id,
                        receipt.state.as_str()
                    ),
                )))
            }
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn settle(&mut self, request_id: RequestId) {
        if let Some(action_id) = self.correlations.remove(&request_id) {
            self.submitted.remove(&action_id);
        }
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
#[derive(Debug)]
struct SessionState {
    waiters: std::sync::Mutex<Waiters>,
    action_window: Mutex<ActionWindow>,
    cursors: Mutex<StreamCursors>,
    /// What each action's receipt last said, and which actions were sent without a settled outcome.
    ///
    /// One lock, because a reconnect copies both and a receipt moves an action from one to the
    /// other. Two locks would let a snapshot fall between the two writes and carry neither.
    outcomes: Mutex<Outcomes>,
    events: broadcast::Sender<Notification>,
    outstanding: AtomicU64,
    max_outstanding: u64,
}

impl SessionState {
    /// Ends the session, waking every waiter.
    ///
    /// A waiter that is dropped rather than answered resolves as [`ClientError::ConnectionEnded`],
    /// which is what its caller is waiting to hear. Ending twice is harmless.
    fn end(&self) {
        let mut waiters = self.waiters();
        waiters.ended = true;
        waiters.pending.clear();
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
#[derive(Debug)]
pub struct Session {
    transport: Arc<dyn ControlTransport>,
    state: Arc<SessionState>,
    next_request_id: AtomicU64,
    reader: tokio::task::JoinHandle<()>,
}

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
        let state = Arc::new(SessionState {
            waiters: std::sync::Mutex::new(Waiters::default()),
            action_window: Mutex::new(transport.initial_action_window()),
            cursors: Mutex::new(cursors),
            outcomes: Mutex::new(Outcomes::default()),
            events,
            outstanding: AtomicU64::new(0),
            max_outstanding: limits.max_outstanding_mutations.get(),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&transport), Arc::clone(&state)));
        Ok(Self {
            transport,
            state,
            next_request_id: AtomicU64::new(1),
            reader,
        })
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

    /// Discards what this client held for one stream, which is what a resynchronisation means.
    ///
    /// The stream then owes a snapshot: nothing it delivers establishes a position until one is
    /// installed.
    pub async fn discard_stream(&self, stream_id: &StreamId) {
        self.state.cursors.lock().await.discard(stream_id);
    }

    /// Calls a read method and parses its result.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongEffect`] when the registry says the method mutates, and the
    /// host's error when it refuses.
    pub async fn read<P, R>(&self, method: Method, params: &P) -> Result<R>
    where
        P: Serialize + ?Sized,
        R: DeserializeOwned + Serialize,
    {
        let entry = method.entry();
        if entry.effect != EffectClass::Read {
            return Err(ClientError::WrongEffect {
                method,
                expected: "mutation",
                actual: "read",
            });
        }
        let request_id = self.next_request_id();
        let waiter = self.register(request_id)?;
        let request = Request {
            request_id,
            method: method.into(),
            method_version: entry.version,
            params: ParamsValue::from_typed(params)?,
        };
        self.transport.send(&ControlFrame::Request(request)).await?;

        match waiter.wait().await? {
            Answer::Response(response) => match response.outcome {
                Outcome::Ok(value) => Ok(value.to_typed()?),
                Outcome::Error(error) => Err(ClientError::from(error)),
            },
            Answer::Receipt(_) => Err(ClientError::Host(kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::InvalidArgument,
                "a read was answered with a receipt",
            ))),
        }
    }

    /// Submits a mutation and waits for the host to settle it.
    ///
    /// The identifier is generated here and recorded before the request is sent. A retry is a new
    /// request with the same identifier, which the host de-duplicates; a new intent is a new
    /// identifier.
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
        // the accepted deadline from whichever bound is earliest, and a window it did not need costs
        // nothing.
        let action_window_id = {
            let window = self.state.action_window.lock().await;
            if entry.freshness == FreshnessRequirement::ActionWindow
                && window.valid_for_ms.get() == 0
            {
                return Err(ClientError::NoActionWindow);
            }
            window.action_window_id.clone()
        };

        let action_id = ActionId::new(kr_transport::random::fresh_uuid_v4()?);
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
        self.state.outcomes.lock().await.submit(SubmittedAction {
            action_id,
            method,
            target: target_record,
            params: params_record,
            request_id,
        })?;
        if self.transport.send(&frame).await.is_err() {
            // The frame may or may not have reached the host, so the action stays on the pending
            // list and the caller is told the outcome is unknown.
            return Err(ClientError::SubmissionUncertain { action_id });
        }

        match waiter.wait().await {
            Ok(Answer::Receipt(receipt)) => Ok(Settled::Receipt(receipt)),
            Ok(Answer::Response(response)) => {
                // A correlated answer is definite, whichever way it went: the host reached a
                // decision about this action, so it is no longer an unknown outcome.
                self.state
                    .outcomes
                    .lock()
                    .await
                    .submitted
                    .remove(&action_id);
                match response.outcome {
                    Outcome::Error(error) => Err(ClientError::from(error)),
                    Outcome::Ok(value) => Ok(Settled::Result(value)),
                }
            }
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
        debug_assert_eq!(
            entry.idempotency,
            kr_protocol::authority::IdempotencyBehaviour::OrderedStream
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
            Answer::Receipt(_) => Err(ClientError::Host(kr_protocol::error::ProtocolError::new(
                kr_protocol::error::ErrorCode::InvalidArgument,
                "raw input is an ordered stream and receives no receipt",
            ))),
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
        let receiver = self.receiver.take().expect("a waiter waits once");
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
                if receipt.state.is_terminal() {
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
        | ControlFrame::Forwarded(_)
        | ControlFrame::ForwardedRead(_)
        | ControlFrame::AcceptanceDelivered(_) => return false,
    }
    true
}
