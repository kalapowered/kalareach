//! One remote connection's own link to the worker that owns its session.
//!
//! A worker's attachments, subscriptions and input lane all belong to the connection that created
//! them, and that is the right design: it is what makes withdrawing a registration end everything
//! the caller had. It also means a paired device's attachment cannot share a connection with the
//! daemon's own housekeeping, so the daemon opens one link per remote connection and tells the
//! worker what it is for before it presents a generation token.
//!
//! The link is demultiplexed here rather than call by call. A subscription delivers notifications
//! whenever the session produces output, including while a request is outstanding and while
//! nothing is outstanding at all, so one task reads the socket and routes what arrives: a response
//! to whoever is waiting on that request, a notification to the relay, a renewed window to
//! nobody. A reader that only ran inside a call would drop the output it was not waiting for.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_ipc::client::LocalClient;
use kr_protocol::actor::ActorEnvelope;
use kr_protocol::envelope::{
    ControlEvent, ControlFrame, MutationRequest, Notification, ParamsValue, Request, Response,
};
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::local::{
    ControllerConnectionRole, ForwardedMutation, ForwardedRequest, LocalClientKind,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::U64;
use tokio::sync::{Mutex, oneshot};

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// How long a proxied call waits for the worker before the caller is told the outcome is unknown.
///
/// A worker holds the dispatch barrier for the length of one effect, so a call can legitimately
/// wait; what it must not do is wait for ever, because the remote caller is holding a request
/// slot while it does.
pub const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long opening a proxy link to a worker may take, handshake and all.
///
/// Verifying the worker, declaring what this connection is for and presenting a generation are
/// three round trips on a socket a busy worker may not be reading yet. A device waits for this
/// once, when it attaches.
pub const OPEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How many notifications the relay holds for a remote connection that is not reading them.
///
/// Section 9's rule for a slow client is that it is told rather than waited for. A relay this far
/// behind ends its connection; the alternative is holding the worker's own delivery task.
pub const RELAY_DEPTH: usize = 256;

/// How many queued *bytes* the relay holds for one remote connection.
///
/// A count of notifications is not a bound on memory: one output notification can carry a large
/// batch, so 256 of them would be far more than section 9's 8 MiB send queue per peer. This is
/// that bound, charged before a notification is queued and released once it has been written or
/// discarded.
pub const RELAY_QUEUED_BYTES: usize = kr_protocol::limits::MAX_SEND_QUEUE_BYTES;

/// One notification on its way to a remote connection, holding its charge until it is delivered.
///
/// The charge is released by the destructor and by nothing else, so it is released exactly once
/// and it covers the notification's whole life: from the moment the proxy reads it to the moment
/// it has been written or dropped. A charge released before the write would let the producer refill
/// the budget while the write was still waiting, which is the memory the bound exists to cap.
#[derive(Debug)]
pub struct Relayed {
    notification: Notification,
    charged: usize,
    budget: Arc<RelayBudget>,
}

impl Relayed {
    /// Returns the notification this carries.
    #[must_use]
    pub const fn notification(&self) -> &Notification {
        &self.notification
    }
}

impl Drop for Relayed {
    fn drop(&mut self) {
        self.budget.release(self.charged);
    }
}

/// What one remote connection has queued and not yet had written.
#[derive(Debug)]
pub struct RelayBudget {
    queued: std::sync::atomic::AtomicUsize,
    ceiling: usize,
}

impl RelayBudget {
    /// Creates a budget with the connection's ceiling.
    #[must_use]
    pub const fn new(ceiling: usize) -> Self {
        Self {
            queued: std::sync::atomic::AtomicUsize::new(0),
            ceiling,
        }
    }

    /// Charges `bytes`, or refuses when the connection is already holding its ceiling.
    fn charge(&self, bytes: usize) -> bool {
        let mut held = self.queued.load(Ordering::Acquire);
        loop {
            let next = held.saturating_add(bytes);
            if next > self.ceiling {
                return false;
            }
            match self
                .queued
                .compare_exchange_weak(held, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(current) => held = current,
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.queued.fetch_sub(bytes, Ordering::AcqRel);
    }
}

/// One remote connection's link to one worker.
#[derive(Debug)]
pub struct WorkerProxy {
    session_id: SessionId,
    /// Notified once this link has ended, whichever way it ended.
    ///
    /// A connection whose link has gone has no subscription and no attachment at the worker, so it
    /// is not a connection that can go on being served: section 8 has the device reconnect and
    /// restore its state from the cursor it holds.
    lost: Arc<tokio::sync::Notify>,
    writer: Mutex<kr_ipc::framed::FrameWriter>,
    /// Shared with the reader task, because a response and the request that is waiting for it are
    /// one fact. Two maps would let a response arrive for a request that was never recorded.
    waiters: Arc<std::sync::Mutex<Waiters>>,
    reader: tokio::task::JoinHandle<()>,
    next_request: AtomicU64,
}

/// Whom this link owes an answer, and whether it can still give one.
#[derive(Debug, Default)]
struct Waiters {
    pending: HashMap<RequestId, oneshot::Sender<Response>>,
    ended: bool,
}

impl WorkerProxy {
    /// Opens a proxy link to one worker and proves what it is and what it is for.
    ///
    /// Four steps, in this order: the worker proves it is the session the descriptor names; this
    /// connection declares that it is a proxy rather than the authority; it presents the generation
    /// it speaks for; and only then does it carry anything. Declaring before presenting is what
    /// keeps a proxy from displacing the daemon's own authority connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker cannot be reached, does not prove itself, or refuses the
    /// generation.
    pub async fn open(
        controller: &Arc<Controller>,
        worker: &KnownWorker,
        notifications: tokio::sync::mpsc::Sender<Relayed>,
        budget: Arc<RelayBudget>,
        lost: Arc<tokio::sync::Notify>,
    ) -> Result<Arc<Self>> {
        // Bounded, because every step of it waits for a worker: a session that has stopped reading
        // its socket must not be able to hold a device's attachment open indefinitely.
        tokio::time::timeout(
            OPEN_TIMEOUT,
            Self::handshake(controller, worker, notifications, budget, lost),
        )
        .await
        .map_err(|_| {
            ControllerError::supervision("the worker did not accept a proxy connection in time")
        })?
    }

    async fn handshake(
        controller: &Arc<Controller>,
        worker: &KnownWorker,
        notifications: tokio::sync::mpsc::Sender<Relayed>,
        budget: Arc<RelayBudget>,
        lost: Arc<tokio::sync::Notify>,
    ) -> Result<Arc<Self>> {
        let mut client = LocalClient::connect(
            &worker.endpoint,
            LocalClientKind::Controller,
            controller.build_id.clone(),
        )
        .await?;
        client.verify_worker(&worker.descriptor).await?;
        client
            .writer()
            .write_message(&ControlFrame::ControllerRole(
                ControllerConnectionRole::Proxy,
            ))
            .await?;
        match client.recv().await? {
            ControlFrame::ControllerRole(ControllerConnectionRole::Proxy) => {}
            other => {
                return Err(ControllerError::supervision(format!(
                    "the worker did not accept this connection as a proxy: {}",
                    frame_name(&other)
                )));
            }
        }
        let generation = controller.generation;
        let boot = controller.boot_identity.clone();
        let identity = &controller.identity;
        client
            .present_generation(|nonce| {
                identity
                    .generation_token(generation, &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await?;

        let (reader, writer, _acknowledgement) = client.into_halves();
        let waiters: Arc<std::sync::Mutex<Waiters>> =
            Arc::new(std::sync::Mutex::new(Waiters::default()));
        let reader = tokio::spawn(read_loop(
            reader,
            Arc::clone(&waiters),
            notifications,
            budget,
            Arc::clone(&lost),
        ));
        Ok(Arc::new(Self {
            session_id: worker.descriptor.session_id,
            lost,
            writer: Mutex::new(writer),
            waiters,
            reader,
            next_request: AtomicU64::new(1),
        }))
    }

    /// Returns true while this link can still carry a call.
    ///
    /// A link whose reader has stopped is not a link a caller may reuse: its subscription is gone
    /// and its attachment at the worker went with the socket.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.waiters().ended
    }

    /// Returns the session this link serves.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Forwards one admitted mutation and returns what the worker answered.
    ///
    /// # Errors
    ///
    /// Returns an error when the link fails or the worker does not answer in time.
    pub async fn forward_mutation(
        &self,
        mutation: &MutationRequest,
        actor: &ActorEnvelope,
        accepted_deadline_boot_ms: U64,
    ) -> Result<Response> {
        let request_id = self.next_request_id();
        let mut forwarded = mutation.clone();
        // The request identity is this link's; the durable identity is the action's, and that
        // travels unchanged because it is what the payload digest covers.
        forwarded.request_id = request_id;
        let frame = ControlFrame::Forwarded(Box::new(ForwardedMutation {
            mutation: forwarded,
            actor: actor.clone(),
            accepted_deadline_boot_ms,
        }));
        self.call(request_id, &frame).await
    }

    /// Forwards one admitted read and returns what the worker answered.
    ///
    /// # Errors
    ///
    /// As [`Self::forward_mutation`].
    pub async fn forward_read(&self, request: &Request, actor: &ActorEnvelope) -> Result<Response> {
        let request_id = self.next_request_id();
        let mut forwarded = request.clone();
        forwarded.request_id = request_id;
        let frame = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
            request: forwarded,
            actor: actor.clone(),
        }));
        self.call(request_id, &frame).await
    }

    /// Calls one read on this link as the daemon itself, for its own housekeeping.
    ///
    /// # Errors
    ///
    /// As [`Self::forward_mutation`].
    pub async fn read<T: serde::Serialize + ?Sized>(
        &self,
        method: Method,
        params: &T,
    ) -> Result<Response> {
        let request_id = self.next_request_id();
        let params = ParamsValue::from_typed(params)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let frame = ControlFrame::Request(Request {
            request_id,
            method: method.into(),
            method_version: method.entry().version,
            params,
        });
        self.call(request_id, &frame).await
    }

    /// Ends the link.
    pub fn close(&self) {
        {
            let mut waiters = self.waiters();
            waiters.ended = true;
            waiters.pending.clear();
        }
        self.reader.abort();
        self.lost.notify_waiters();
    }

    async fn call(&self, request_id: RequestId, frame: &ControlFrame) -> Result<Response> {
        let receiver = {
            let mut waiters = self.waiters();
            if waiters.ended {
                return Err(ControllerError::supervision(
                    "this session's proxy link has ended",
                ));
            }
            let (sender, receiver) = oneshot::channel();
            waiters.pending.insert(request_id, sender);
            receiver
        };
        // The whole exchange is bounded, not only the wait for the answer. A worker that is not
        // reading its socket can block the write itself, and a timeout that started afterwards
        // would never start at all.
        //
        // A frame that was interrupted part way through leaves the stream in pieces, and the frame
        // writer refuses to continue one: the link ends rather than staying open with a suffix the
        // worker is still waiting for. Whether the frame reached the worker is then unknown, which
        // is what the caller is told.
        let exchange = async {
            let mut writer = self.writer.lock().await;
            let written = writer.write_message(frame).await;
            let interrupted = writer.is_mid_frame();
            drop(writer);
            (written, interrupted)
        };
        let sent = match tokio::time::timeout(CALL_TIMEOUT, exchange).await {
            Ok((written, interrupted)) => {
                if interrupted {
                    self.close();
                    return Err(ControllerError::Uncertain {
                        detail: "this session's link was interrupted part way through the action, \
                                 so what became of it is unknown"
                            .to_owned(),
                    });
                }
                written
            }
            Err(_) => {
                self.close();
                return Err(ControllerError::Uncertain {
                    detail: "this session did not take the action in time, so what became of it \
                             is unknown"
                        .to_owned(),
                });
            }
        };
        if let Err(error) = sent {
            self.waiters().pending.remove(&request_id);
            return Err(error.into());
        }
        match tokio::time::timeout(CALL_TIMEOUT, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(ControllerError::Uncertain {
                detail: "this session's link ended before it answered, so what became of the \
                         action is unknown"
                    .to_owned(),
            }),
            Err(_) => {
                self.waiters().pending.remove(&request_id);
                Err(ControllerError::Uncertain {
                    detail: "this session did not answer in time, so what became of the action is \
                             unknown"
                        .to_owned(),
                })
            }
        }
    }

    /// Resolves once this link has ended.
    pub async fn lost(&self) {
        // Checked before and after parking: a link that ended before anybody waited would
        // otherwise fire into an empty room.
        if !self.is_open() {
            return;
        }
        let waiting = self.lost.notified();
        if !self.is_open() {
            return;
        }
        waiting.await;
    }

    fn waiters(&self) -> std::sync::MutexGuard<'_, Waiters> {
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_request_id(&self) -> RequestId {
        RequestId::new(self.next_request.fetch_add(1, Ordering::AcqRel))
    }
}

impl Drop for WorkerProxy {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Reads one proxy link and routes what arrives.
async fn read_loop(
    mut reader: kr_ipc::framed::FrameReader,
    waiters: Arc<std::sync::Mutex<Waiters>>,
    notifications: tokio::sync::mpsc::Sender<Relayed>,
    budget: Arc<RelayBudget>,
    lost: Arc<tokio::sync::Notify>,
) {
    loop {
        let frame: ControlFrame = match reader.read_message().await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame {
            ControlFrame::Response(response) => {
                let waiter = waiters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pending
                    .remove(&response.request_id);
                if let Some(sender) = waiter {
                    let _ = sender.send(response);
                }
            }
            // A subscription this link started. It goes to the relay, which is what decides
            // whether the remote connection may still be served it. A connection that is not
            // keeping up is told rather than waited for: the link ends, which takes its
            // subscription and its attachment with it, and the device reconnects and resubscribes
            // from the cursor it holds. Holding the worker's delivery task instead would make one
            // slow device everybody's problem.
            ControlFrame::Notification(notification) => {
                let charged = kr_cbor::to_canonical_value(&notification)
                    .map(|value| kr_cbor::encoded_len(&value))
                    .unwrap_or(usize::MAX);
                if !budget.charge(charged) {
                    break;
                }
                let relayed = Relayed {
                    notification,
                    charged,
                    budget: Arc::clone(&budget),
                };
                // A refused item releases its own charge when the returned value is dropped.
                if notifications.try_send(relayed).is_err() {
                    break;
                }
            }
            // The worker's own freshness resource for this link. A forwarded mutation carries the
            // deadline the daemon accepted rather than this window, so nothing here uses it.
            ControlFrame::Event(ControlEvent::ActionWindowRenewed(_) | ControlEvent::Keepalive) => {
            }
            // A worker does not send a proxy anything else. Carrying on would mean deciding, frame
            // by frame, which of its messages to believe.
            _ => break,
        }
    }
    {
        let mut held = waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.ended = true;
        held.pending.clear();
    }
    // The connection is told, rather than left to discover it when it next asks for something: its
    // subscription has stopped and its attachment at the worker has gone with the socket.
    lost.notify_waiters();
}

fn frame_name(frame: &ControlFrame) -> &'static str {
    match frame {
        ControlFrame::Response(_) => "a response",
        ControlFrame::Notification(_) => "a notification",
        ControlFrame::Event(_) => "a connection event",
        _ => "another message",
    }
}
