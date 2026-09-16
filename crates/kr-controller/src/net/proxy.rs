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
use kr_protocol::error::{ErrorCode, ProtocolError};
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

/// How many notifications the relay holds for a remote connection that is not reading them.
///
/// Section 9's rule for a slow client is that it is told rather than waited for. A relay this far
/// behind ends its connection; the alternative is holding the worker's own delivery task.
pub const RELAY_DEPTH: usize = 256;

/// One remote connection's link to one worker.
#[derive(Debug)]
pub struct WorkerProxy {
    session_id: SessionId,
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
        notifications: tokio::sync::mpsc::Sender<Notification>,
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
        let reader = tokio::spawn(read_loop(reader, Arc::clone(&waiters), notifications));
        Ok(Arc::new(Self {
            session_id: worker.descriptor.session_id,
            writer: Mutex::new(writer),
            waiters,
            reader,
            next_request: AtomicU64::new(1),
        }))
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
        if let Err(error) = self.writer.lock().await.write_message(frame).await {
            self.waiters().pending.remove(&request_id);
            return Err(error.into());
        }
        match tokio::time::timeout(CALL_TIMEOUT, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(ControllerError::supervision(
                "this session's proxy link ended before the worker answered",
            )),
            Err(_) => {
                self.waiters().pending.remove(&request_id);
                Err(ControllerError::supervision(
                    "the worker did not answer in time",
                ))
            }
        }
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
    notifications: tokio::sync::mpsc::Sender<Notification>,
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
            // whether the remote connection may still be served it.
            ControlFrame::Notification(notification) => {
                if notifications.try_send(notification).is_err() {
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
    let mut held = waiters
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.ended = true;
    held.pending.clear();
}

/// Returns the protocol error a failed proxied call is reported as.
#[must_use]
pub fn proxy_failure(detail: &str) -> ProtocolError {
    ProtocolError::new(ErrorCode::OutcomeUnknown, detail)
}

fn frame_name(frame: &ControlFrame) -> &'static str {
    match frame {
        ControlFrame::Response(_) => "a response",
        ControlFrame::Notification(_) => "a notification",
        ControlFrame::Event(_) => "a connection event",
        _ => "another message",
    }
}
