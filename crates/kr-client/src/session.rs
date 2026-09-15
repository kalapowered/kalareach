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

use std::collections::{BTreeSet, HashMap};
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

/// The shared state of one connection.
#[derive(Debug)]
struct SessionState {
    waiters: Mutex<HashMap<RequestId, oneshot::Sender<Answer>>>,
    action_window: Mutex<ActionWindow>,
    cursors: Mutex<StreamCursors>,
    receipts: Mutex<ReceiptTracker>,
    /// Actions this client submitted. An entry stays until its receipt is terminal, so a connection
    /// that fails mid-flight leaves the uncertain action named rather than forgotten.
    submitted: Mutex<BTreeSet<ActionId>>,
    events: broadcast::Sender<Notification>,
    outstanding: AtomicU64,
    max_outstanding: u64,
    /// Set once the control stream has ended. Every waiter is woken and no new one is registered.
    ended: std::sync::atomic::AtomicBool,
}

impl SessionState {
    /// Ends the session, waking every waiter.
    ///
    /// A waiter that is dropped rather than answered resolves as [`ClientError::ConnectionEnded`],
    /// which is what its caller is waiting to hear.
    async fn end(&self) {
        self.ended.store(true, Ordering::Release);
        self.waiters.lock().await.clear();
    }

    fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
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
    #[must_use]
    pub fn start(transport: Arc<dyn ControlTransport>) -> Self {
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let limits = transport.limits();
        let state = Arc::new(SessionState {
            waiters: Mutex::new(HashMap::new()),
            action_window: Mutex::new(transport.initial_action_window()),
            cursors: Mutex::new(StreamCursors::new()),
            receipts: Mutex::new(ReceiptTracker::new()),
            submitted: Mutex::new(BTreeSet::new()),
            events,
            outstanding: AtomicU64::new(0),
            max_outstanding: limits.max_outstanding_mutations.get(),
            ended: std::sync::atomic::AtomicBool::new(false),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&transport), Arc::clone(&state)));
        Self {
            transport,
            state,
            next_request_id: AtomicU64::new(1),
            reader,
        }
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
        self.state.receipts.lock().await.clone()
    }

    /// Returns the actions this client submitted whose outcome it has not seen settled.
    ///
    /// A reconnecting client asks the host about these. It never resubmits one: section 9 forbids
    /// dispatching an identifier again because its receipt is incomplete.
    pub async fn submitted_actions(&self) -> Vec<ActionId> {
        self.state.submitted.lock().await.iter().copied().collect()
    }

    /// Discards what this client held for one stream, which is what a resynchronisation means.
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
        let waiter = self.register(request_id).await?;
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

    /// Submits a mutation and waits for its first receipt.
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
    ) -> Result<Receipt>
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
        let waiter = self.register(request_id).await?;
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
            params: ParamsValue::from_typed(params)?,
        };

        // Recorded before the send: once the frame is on the wire the host may dispatch it, and a
        // client that cannot name the action cannot ask what happened to it.
        self.state.submitted.lock().await.insert(action_id);
        self.transport
            .send(&ControlFrame::Mutation(Box::new(mutation)))
            .await
            .map_err(|_| ClientError::SubmissionUncertain { action_id })?;

        match waiter.wait().await {
            Ok(Answer::Receipt(receipt)) => Ok(*receipt),
            Ok(Answer::Response(response)) => match response.outcome {
                // A correlated error is the host's answer to this mutation, not a lost connection.
                Outcome::Error(error) => Err(ClientError::from(error)),
                Outcome::Ok(_) => Err(ClientError::Host(kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::InvalidArgument,
                    "a mutation was answered without a receipt",
                ))),
            },
            Err(_) => Err(ClientError::SubmissionUncertain { action_id }),
        }
    }

    /// Ends the session and the connection, waking every waiting call.
    pub async fn close(&self) {
        self.transport.close();
        self.state.end().await;
        self.reader.abort();
    }

    async fn register(&self, request_id: RequestId) -> Result<Waiter> {
        if self.state.has_ended() {
            return Err(ClientError::ConnectionEnded);
        }
        let (sender, receiver) = oneshot::channel();
        self.state.waiters.lock().await.insert(request_id, sender);
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
        // A cancelled call leaves nothing behind. The entry is removed on a best-effort basis: the
        // routing task holds the map only for the length of one lookup, and an entry that survives
        // is cleared when the session ends.
        if let Ok(mut waiters) = self.state.waiters.try_lock() {
            waiters.remove(&self.request_id);
        }
    }
}

/// Reads the control stream until it ends, routing what arrives.
async fn read_loop(transport: Arc<dyn ControlTransport>, state: Arc<SessionState>) {
    loop {
        let frame = match transport.recv().await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        route(&state, frame).await;
    }
    // The control stream has ended, so every data stream it authorised goes with it and every
    // waiter learns that its answer is not coming.
    transport.revoke_streams();
    state.end().await;
}

async fn route(state: &Arc<SessionState>, frame: ControlFrame) {
    match frame {
        ControlFrame::Response(response) => {
            let waiter = state.waiters.lock().await.remove(&response.request_id);
            if let Some(sender) = waiter {
                let _ = sender.send(Answer::Response(response));
            }
        }
        ControlFrame::Receipt(answer) => {
            let request_id = answer.request_id;
            let receipt = answer.receipt;
            state.receipts.lock().await.record(receipt.clone());
            if receipt.state.is_terminal() {
                state.submitted.lock().await.remove(&receipt.action_id);
            }
            let waiter = state.waiters.lock().await.remove(&request_id);
            if let Some(sender) = waiter {
                let _ = sender.send(Answer::Receipt(Box::new(receipt)));
            }
        }
        ControlFrame::Notification(notification) => {
            // A gap means this client's state for the stream is no longer usable. The cursor is
            // discarded so the next restoration starts from a fresh snapshot; the event is still
            // delivered, because a subscriber that is rebuilding wants to know why. A duplicate is
            // not delivered again: a subscriber that already applied it would apply it twice.
            let delivery = {
                let mut cursors = state.cursors.lock().await;
                let delivery = cursors.accept(&notification);
                if matches!(delivery, Delivery::Gap { .. }) {
                    cursors.discard(&notification.stream_id);
                }
                delivery
            };
            if delivery != Delivery::Duplicate {
                let _ = state.events.send(notification);
            }
        }
        ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
            *state.action_window.lock().await = window;
        }
        ControlFrame::Event(ControlEvent::Keepalive) => {}
        // A client never receives a request or a mutation: the host does not call the client.
        ControlFrame::Request(_) | ControlFrame::Mutation(_) => {}
    }
}
