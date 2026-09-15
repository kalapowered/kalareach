//! The client session: requests, receipts, events and the connection's freshness resource.
//!
//! One task reads the control stream and routes what arrives: a response to whoever is waiting on
//! that request identifier, a receipt to the receipt tracker, a notification to the event
//! subscribers, and a connection event to the session's own state. Everything a caller does goes
//! through [`Session`], which owns the bookkeeping the protocol requires:
//!
//! * the method registry decides the shape of a call, so a read cannot be submitted as a mutation
//!   and a mutation cannot be submitted without the freshness its entry demands;
//! * `action_id` is a fresh UUIDv4 the client generates, and the outstanding-mutation bound is the
//!   one the connection negotiated;
//! * the current action window is whatever the host last issued, and the host renews it on the
//!   live connection without being asked.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::authority::{EffectClass, FreshnessRequirement};
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, MutationRequest, Notification, Outcome, ParamsValue,
    Request, Response,
};
use kr_protocol::hello::ActionWindow;
use kr_protocol::ids::{ActionId, GrantId, RequestId};
use kr_protocol::method::Method;
use kr_protocol::receipt::Receipt;
use kr_protocol::scalars::{DurationMs, Nullable};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex, broadcast, oneshot};

use crate::cursors::{Delivery, ReceiptTracker, StreamCursors};
use crate::error::{ClientError, Result};
use crate::transport::{ControlSender, NetworkTransport};

/// How many events the session buffers for each subscriber.
///
/// A subscriber that falls this far behind is told so rather than being waited for: section 9 says
/// a slow client receives a resynchronisation requirement and cannot hold the host's loop.
pub const EVENT_BUFFER: usize = 1024;

/// What one caller is waiting for.
#[derive(Debug)]
enum Waiter {
    /// A read's response.
    Response(oneshot::Sender<Response>),
    /// A mutation's first receipt.
    Receipt(oneshot::Sender<Receipt>),
}

/// The shared state of one connection.
#[derive(Debug)]
struct SessionState {
    waiters: Mutex<HashMap<RequestId, Waiter>>,
    action_window: Mutex<ActionWindow>,
    cursors: Mutex<StreamCursors>,
    receipts: Mutex<ReceiptTracker>,
    events: broadcast::Sender<Notification>,
    outstanding: AtomicU64,
    max_outstanding: u64,
}

/// A client's connection to one host.
#[derive(Debug)]
pub struct Session {
    transport: Arc<NetworkTransport>,
    sender: ControlSender,
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
    pub fn start(transport: Arc<NetworkTransport>) -> Self {
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let limits = <NetworkTransport as crate::transport::ControlTransport>::limits(&transport);
        let state = Arc::new(SessionState {
            waiters: Mutex::new(HashMap::new()),
            action_window: Mutex::new(
                <NetworkTransport as crate::transport::ControlTransport>::initial_action_window(
                    &transport,
                ),
            ),
            cursors: Mutex::new(StreamCursors::new()),
            receipts: Mutex::new(ReceiptTracker::new()),
            events,
            outstanding: AtomicU64::new(0),
            max_outstanding: limits.max_outstanding_mutations.get(),
        });
        let sender = transport.sender();
        let reader = tokio::spawn(read_loop(Arc::clone(&transport), Arc::clone(&state)));
        Self {
            transport,
            sender,
            state,
            next_request_id: AtomicU64::new(1),
            reader,
        }
    }

    /// Returns the transport, for opening data streams.
    #[must_use]
    pub fn transport(&self) -> &Arc<NetworkTransport> {
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
        let (sender, receiver) = oneshot::channel();
        self.state
            .waiters
            .lock()
            .await
            .insert(request_id, Waiter::Response(sender));
        let request = Request {
            request_id,
            method: method.into(),
            method_version: entry.version,
            params: ParamsValue::from_typed(params)?,
        };
        self.sender.send(&ControlFrame::Request(request)).await?;

        let response = receiver.await.map_err(|_| ClientError::ConnectionEnded)?;
        match response.outcome {
            Outcome::Ok(value) => Ok(value.to_typed()?),
            Outcome::Error(error) => Err(ClientError::from(error)),
        }
    }

    /// Submits a mutation and waits for its first receipt.
    ///
    /// The identifier is generated here, and the same identifier is never submitted twice: a
    /// retry is a new request with the same identifier, which the host de-duplicates, and a new
    /// intent is a new identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongEffect`] for a read method,
    /// [`ClientError::TooManyOutstandingMutations`] at the negotiated bound, and the host's error
    /// when it refuses.
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
        let outstanding = self.state.outstanding.fetch_add(1, Ordering::AcqRel);
        if outstanding >= self.state.max_outstanding {
            self.state.outstanding.fetch_sub(1, Ordering::AcqRel);
            return Err(ClientError::TooManyOutstandingMutations {
                limit: usize::try_from(self.state.max_outstanding).unwrap_or(usize::MAX),
            });
        }
        let outcome = self
            .submit(method, target, grant_id, expected, params, requested_ttl)
            .await;
        self.state.outstanding.fetch_sub(1, Ordering::AcqRel);
        outcome
    }

    async fn submit<P, E>(
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
        let request_id = self.next_request_id();
        let (sender, receiver) = oneshot::channel();
        self.state
            .waiters
            .lock()
            .await
            .insert(request_id, Waiter::Receipt(sender));
        let mutation = MutationRequest {
            request_id,
            method: method.into(),
            method_version: entry.version,
            action_id: ActionId::new(kr_transport::random::fresh_uuid_v4()?),
            grant_id: Nullable(grant_id),
            target,
            expected: ParamsValue::from_typed(expected)?,
            action_window_id,
            requested_ttl_ms: requested_ttl,
            params: ParamsValue::from_typed(params)?,
        };
        self.sender
            .send(&ControlFrame::Mutation(Box::new(mutation)))
            .await?;
        receiver.await.map_err(|_| ClientError::ConnectionEnded)
    }

    /// Ends the session and the connection.
    pub fn close(&self) {
        self.reader.abort();
        self.transport.close();
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

/// Reads the control stream until it ends, routing what arrives.
async fn read_loop(transport: Arc<NetworkTransport>, state: Arc<SessionState>) {
    let Some(mut reader) = transport.take_reader().await else {
        return;
    };
    loop {
        let frame = match reader.read_message::<ControlFrame>().await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        route(&state, frame).await;
    }
    // The control stream has ended, so every data stream it authorised goes with it and every
    // waiter learns that its answer is not coming.
    transport.revoke_streams();
    state.waiters.lock().await.clear();
}

async fn route(state: &Arc<SessionState>, frame: ControlFrame) {
    match frame {
        ControlFrame::Response(response) => {
            let waiter = state.waiters.lock().await.remove(&response.request_id);
            if let Some(Waiter::Response(sender)) = waiter {
                let _ = sender.send(response);
            }
        }
        ControlFrame::Receipt(receipt) => {
            state.receipts.lock().await.record(receipt.receipt.clone());
            let waiter = state.waiters.lock().await.remove(&receipt.request_id);
            if let Some(Waiter::Receipt(sender)) = waiter {
                let _ = sender.send(receipt.receipt);
            }
        }
        ControlFrame::Notification(notification) => {
            // A gap means this client's state for the stream is no longer usable. The cursor is
            // discarded so the next restoration starts from a fresh snapshot; the event is still
            // delivered, because a subscriber that is rebuilding wants to know why.
            if let Delivery::Gap { .. } = state.cursors.lock().await.accept(&notification) {
                state.cursors.lock().await.discard(&notification.stream_id);
            }
            let _ = state.events.send(notification);
        }
        ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)) => {
            *state.action_window.lock().await = window;
        }
        ControlFrame::Event(ControlEvent::Keepalive) => {}
        // A client never receives a request or a mutation: the host does not call the client.
        ControlFrame::Request(_) | ControlFrame::Mutation(_) => {}
    }
}
