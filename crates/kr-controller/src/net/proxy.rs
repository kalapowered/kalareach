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
    ControlEvent, ControlFrame, MutationRequest, ParamsValue, Request, Response,
};
use kr_protocol::grant::HistoryScope;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::local::{
    ControllerConnectionRole, ForwardedMutation, ForwardedRequest, LocalClientKind,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use tokio::sync::{Mutex, oneshot};

use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};

/// What the host vouches for about one forwarded mutation.
///
/// The worker can establish neither half for itself: it did not authenticate the caller, and it
/// holds no grants. The two travel together because they are one statement — this is the actor,
/// and these are the rights of the grant this request was checked against — and a caller acting
/// under no grant carries an empty set rather than a missing one.
#[derive(Clone, Copy, Debug)]
pub struct Vouched<'a> {
    /// The actor the host verified, with the ingress it arrived on.
    pub actor: &'a ActorEnvelope,
    /// The rights of the grant the host checked this request against.
    pub grant_rights: &'a CanonicalSet<ActionRight>,
    /// The history scope of that grant, for a caller that acts under one.
    ///
    /// The worker holds what it retains to it: the first answer to a question and the retained
    /// answer to a duplicate are shown as far as it reaches. It goes only to a worker that states
    /// it holds results to a scope ([`kr_protocol::local::FORWARDED_RESULT_SCOPE`]), because an
    /// earlier worker ends the link a frame with a member it does not know arrived on.
    pub history: Option<&'a HistoryScope>,
}
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

/// How many queued *bytes* the relay holds for one remote connection by default.
///
/// A count of notifications is not a bound on memory: one output notification can carry a large
/// batch, so 256 of them would be far more than section 9's 8 MiB send queue per peer. This is
/// that bound, charged before a frame is queued and released once it has been written or
/// discarded. A connection that negotiated a smaller send queue is held to what it negotiated.
pub const RELAY_QUEUED_BYTES: usize = kr_protocol::limits::MAX_SEND_QUEUE_BYTES;

/// One frame on its way to a remote connection, holding its charge until it is delivered.
///
/// The charge is released by the destructor and by nothing else, so it is released exactly once
/// and it covers the frame's whole life: from the moment the proxy reads it to the moment it has
/// been written or dropped. A charge released before the write would let the producer refill the
/// budget while the write was still waiting, which is the memory the bound exists to cap.
///
/// What is carried is the frame the connection will send, measured here against the connection's
/// queue so that what is charged is what the connection will hold. The transport encodes it again
/// when it writes it, which is one encoding of one frame at a time rather than a second copy held
/// alongside this one.
#[derive(Debug)]
pub struct Relayed {
    frame: ControlFrame,
    charged: usize,
    budget: Arc<RelayBudget>,
}

impl Relayed {
    /// Returns the frame this carries.
    #[must_use]
    pub const fn frame(&self) -> &ControlFrame {
        &self.frame
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

/// What a worker answered one forwarded request with.
#[derive(Debug)]
pub struct Forwarded {
    /// The response itself.
    pub response: Response,
    /// Whether the worker answered from an action it had already performed.
    ///
    /// Passing one of those on is a read of somebody's receipt, and section 23 has the host check
    /// present view authority over the subject before it returns either half of a retained
    /// result. Keeping the two apart here is what lets the dispatcher make that check.
    pub retained: bool,
    /// Whether the worker holds what it retains to the history scope a forwarded frame carries.
    ///
    /// A worker that does not keeps a retained answer whole, so passing one on to a paired device
    /// would show it more than its grant reaches. The dispatcher refuses it by name, after this
    /// daemon has used it for its own purposes.
    pub holds_results_to_scopes: bool,
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
    /// The write half, released as soon as nothing is using it.
    ///
    /// A link that has ended closes its socket, which is what the worker reads as the connection
    /// going: that is how the attachment this link held is detached. A closed link that kept its
    /// writer would keep the attachment as well.
    writer: Mutex<Option<kr_ipc::framed::FrameWriter>>,
    /// Shared with the reader task, because a response and the request that is waiting for it are
    /// one fact. Two maps would let a response arrive for a request that was never recorded.
    waiters: Arc<std::sync::Mutex<Waiters>>,
    reader: tokio::task::JoinHandle<()>,
    next_request: AtomicU64,
    /// Whether the worker said, in its answer to this link's hello, that it reads the history
    /// scope a forwarded read carries.
    ///
    /// A worker survives an upgrade of this daemon, a forwarded frame is a closed schema, and a
    /// worker ends the link a frame it cannot read arrived on. So a worker that did not say so is
    /// sent no scope, and it refuses the reads a scope narrows by itself.
    reads_history_scopes: bool,
    /// Whether the worker said, in the same answer, that it holds a question read to the scope the
    /// read carries.
    ///
    /// A worker of an earlier build reads a scope and still answers a question read with every
    /// question it holds, so a question read with a scope goes only to a worker that says this.
    holds_question_reads: bool,
    /// Whether the worker said, in the same answer, that it holds what it retains to the history
    /// scope a forwarded mutation carries.
    ///
    /// A worker of an earlier build keeps a retained answer whole and ends the link a mutation with
    /// a scope arrived on, so such a worker is sent none.
    holds_results_to_scopes: bool,
}

/// Whom this link owes an answer, and whether it can still give one.
#[derive(Debug, Default)]
struct Waiters {
    pending: HashMap<RequestId, oneshot::Sender<Forwarded>>,
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

        let (reader, writer, acknowledgement) = client.into_halves();
        let reads_history_scopes =
            kr_protocol::local::reads_history_scopes(&acknowledgement.capabilities);
        let holds_question_reads =
            kr_protocol::local::holds_question_reads_to_scopes(&acknowledgement.capabilities);
        let holds_results_to_scopes =
            kr_protocol::local::holds_results_to_scopes(&acknowledgement.capabilities);
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
            writer: Mutex::new(Some(writer)),
            waiters,
            reader,
            next_request: AtomicU64::new(1),
            reads_history_scopes,
            holds_question_reads,
            holds_results_to_scopes,
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
    /// The rights it carries never include `voice.use`
    /// ([`kr_protocol::local::may_travel_to_a_worker`]): a mutation vouched for with it is refused
    /// before anything is sent.
    ///
    /// # Errors
    ///
    /// Returns an error when the rights hold a voice right, when the link fails, or when the
    /// worker does not answer in time, and `UNSUPPORTED_CAPABILITY` for an answer or a
    /// cancellation of a question for a caller that has a history scope, to a worker that does not
    /// hold results to one, before anything is sent.
    pub async fn forward_mutation(
        &self,
        mutation: &MutationRequest,
        vouched: Vouched<'_>,
        accepted_deadline_boot_ms: U64,
    ) -> Result<Forwarded> {
        if !kr_protocol::local::may_travel_to_a_worker(vouched.grant_rights) {
            return Err(ControllerError::PermissionDenied {
                detail: "voice.use never travels to a worker".to_owned(),
            });
        }
        // What a worker shows of the answer to a question is held to the caller's grant there, so a
        // worker that does not hold results to a scope is not asked to resolve one for a caller
        // that has one: it would answer with the whole question.
        if vouched.history.is_some()
            && !self.holds_results_to_scopes
            && matches!(
                mutation.method.method(),
                Some(Method::QuestionAnswer | Method::QuestionCancel)
            )
        {
            return Err(self.cannot_hold_results_to_a_scope());
        }
        let request_id = self.next_request_id();
        let mut forwarded = mutation.clone();
        // The request identity is this link's; the durable identity is the action's, and that
        // travels unchanged because it is what the payload digest covers.
        forwarded.request_id = request_id;
        let frame = ControlFrame::Forwarded(Box::new(ForwardedMutation {
            mutation: forwarded,
            actor: vouched.actor.clone(),
            grant_rights: vouched.grant_rights.clone(),
            accepted_deadline_boot_ms,
            history: vouched
                .history
                .filter(|_| self.holds_results_to_scopes)
                .cloned(),
        }));
        let mut answered = self.call(request_id, &frame).await?;
        answered.holds_results_to_scopes = self.holds_results_to_scopes;
        Ok(answered)
    }

    /// Returns whether the worker holds what it retains to the history scope a forwarded frame
    /// carries.
    #[must_use]
    pub const fn holds_results_to_scopes(&self) -> bool {
        self.holds_results_to_scopes
    }

    /// The refusal for an action whose answer a worker of an earlier build would give whole.
    fn cannot_hold_results_to_a_scope(&self) -> ControllerError {
        ControllerError::Refused {
            code: kr_protocol::error::ErrorCode::UnsupportedCapability,
            detail:
                "this session's worker is of a build that does not hold what it retains to the \
                     grant a caller acts under, so it is not asked; the session's own owner can \
                     still resolve a question at the session"
                    .to_owned(),
        }
    }

    /// Forwards one admitted read and returns what the worker answered.
    ///
    /// `history` is the history scope of the grant the read was decided under, which the worker
    /// holds what it retains to. It goes only to a worker that said, in its answer to this link's
    /// hello, that it reads one. A question read with one goes only to a worker that also said it
    /// holds a question read to it, and a read of a retained receipt only to one that said it holds
    /// what it retains to a scope: the worker is the one place its answer is narrowed, and a worker
    /// that does not would answer with every question it holds, or with a retained answer whole.
    ///
    /// # Errors
    ///
    /// As [`Self::forward_mutation`], and `UNSUPPORTED_CAPABILITY` for a question read or a read of
    /// a receipt with a scope to a worker that does not hold one to it, before anything is sent.
    pub async fn forward_read(
        &self,
        request: &Request,
        actor: &ActorEnvelope,
        authority_deadline_boot_ms: Nullable<U64>,
        history: Option<&HistoryScope>,
    ) -> Result<Response> {
        if history.is_some()
            && request.method == Method::ActionRead.into()
            && !self.holds_results_to_scopes
        {
            return Err(self.cannot_hold_results_to_a_scope());
        }
        if history.is_some()
            && request.method == Method::QuestionRead.into()
            && !self.holds_question_reads
        {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::UnsupportedCapability,
                detail: "this session's worker is of a build that does not hold a question read \
                         to the grant it is made under, so it is not asked"
                    .to_owned(),
            });
        }
        let request_id = self.next_request_id();
        let mut forwarded = request.clone();
        forwarded.request_id = request_id;
        let frame = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
            request: forwarded,
            actor: actor.clone(),
            authority_deadline_boot_ms,
            history: history.filter(|_| self.reads_history_scopes).cloned(),
        }));
        // A read is a read whichever way the worker answered it, so the marker means nothing here.
        Ok(self.call(request_id, &frame).await?.response)
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
        Ok(self.call(request_id, &frame).await?.response)
    }

    /// Ends the link.
    pub fn close(&self) {
        {
            let mut waiters = self.waiters();
            waiters.ended = true;
            waiters.pending.clear();
        }
        self.reader.abort();
        // The write half goes with it. A call that is in flight holds it and releases it when it
        // finds the link ended; the reader's abort drops its own half. Once both are gone the
        // socket closes, which is what detaches whatever this link held at the worker.
        if let Ok(mut held) = self.writer.try_lock() {
            held.take();
        }
        self.lost.notify_waiters();
    }

    async fn call(&self, request_id: RequestId, frame: &ControlFrame) -> Result<Forwarded> {
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
            let mut held = self.writer.lock().await;
            let Some(writer) = held.as_mut() else {
                return (
                    Err(kr_ipc::IpcError::UnexpectedMessage("this link has ended")),
                    false,
                    false,
                );
            };
            let written = writer.write_message(frame).await;
            let interrupted = writer.is_mid_frame();
            // A frame that stopped part way through leaves the stream in pieces, and the writer
            // refuses to continue one. A frame that could not be encoded at all left the stream
            // untouched, so the writer is still usable and the failure is this call's alone.
            let unusable = interrupted || (written.is_err() && writer.is_mid_frame());
            if unusable {
                held.take();
            }
            (written, interrupted, unusable)
        };
        let sent = match tokio::time::timeout(CALL_TIMEOUT, exchange).await {
            Ok((written, interrupted, unusable)) => {
                if unusable && !interrupted {
                    // The half is gone, so this link cannot carry anything else. Ending it is what
                    // the worker reads as the connection going, which detaches what it held.
                    self.close();
                }
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
            Ok(Ok(answered)) => Ok(answered),
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
            ControlFrame::Response(mut response) => {
                // A refusal of the link itself is the worker saying this connection no longer
                // speaks for the generation that holds it. The caller is given the refusal as any
                // other refusal of authority, without the marker, which is not for a device; and
                // then the link ends, since nothing more can be asked over it.
                let spent = take_the_link_fence(&mut response);
                answer(
                    &waiters,
                    Forwarded {
                        response,
                        retained: false,
                        holds_results_to_scopes: false,
                    },
                    spent,
                );
                if spent {
                    break;
                }
            }
            // The worker answered from a receipt it already held rather than by performing the
            // action. Whether that may be passed on is the caller's authority to read it, which
            // the dispatcher decides; this only has to keep the two apart.
            ControlFrame::RetainedResponse(response) => answer(
                &waiters,
                Forwarded {
                    response: *response,
                    retained: true,
                    holds_results_to_scopes: false,
                },
                false,
            ),
            // A subscription this link started. It goes to the relay, which is what decides
            // whether the remote connection may still be served it. A connection that is not
            // keeping up is told rather than waited for: the link ends, which takes its
            // subscription and its attachment with it, and the device reconnects and resubscribes
            // from the cursor it holds. Holding the worker's delivery task instead would make one
            // slow device everybody's problem.
            ControlFrame::Notification(notification) => {
                let frame = ControlFrame::Notification(notification);
                // The complete frame, its length prefix included, because that is what the
                // connection holds while the write is waiting.
                let charged = kr_cbor::to_canonical_value(&frame)
                    .map(|value| {
                        kr_cbor::encoded_len(&value)
                            .saturating_add(kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN)
                    })
                    .unwrap_or(usize::MAX);
                if !budget.charge(charged) {
                    break;
                }
                let relayed = Relayed {
                    frame,
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

/// Takes the mark off a response that refuses the link itself
/// ([`kr_protocol::error::ProtocolError::link_fenced`]),
/// and says whether it carried it.
fn take_the_link_fence(response: &mut Response) -> bool {
    match &mut response.outcome {
        kr_protocol::envelope::Outcome::Error(error) => std::mem::take(&mut error.link_fenced),
        kr_protocol::envelope::Outcome::Ok(_) => false,
    }
}

/// Hands one answer to whatever is waiting for that request.
///
/// An answer that ends the link ends it in the same step that takes its waiter, before the answer
/// is handed over: whoever reacts to the answer at once finds the link ended, and not open for one
/// more call that the worker would refuse.
fn answer(waiters: &Arc<std::sync::Mutex<Waiters>>, answered: Forwarded, ends_the_link: bool) {
    let waiter = {
        let mut held = waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let waiter = held.pending.remove(&answered.response.request_id);
        if ends_the_link {
            held.ended = true;
            held.pending.clear();
        }
        waiter
    };
    if let Some(sender) = waiter {
        let _ = sender.send(answered);
    }
}

fn frame_name(frame: &ControlFrame) -> &'static str {
    match frame {
        ControlFrame::Response(_) | ControlFrame::RetainedResponse(_) => "a response",
        ControlFrame::Notification(_) => "a notification",
        ControlFrame::Event(_) => "a connection event",
        _ => "another message",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kr_protocol::envelope::Outcome;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::ids::SessionId;
    use kr_protocol::method::Method;
    use kr_protocol::session::SessionReadParams;

    use super::{RELAY_DEPTH, RELAY_QUEUED_BYTES, RelayBudget, WorkerProxy};
    use crate::service::a_link_that_is_not_given_back::Served;

    /// KR-REQ-09.12: a worker's refusal of the link itself, because a newer control daemon has
    /// taken it over, is delivered to the caller as the ordinary refusal of authority it is, without
    /// the marker that only the worker and this daemon read, and the link ends once it has been
    /// delivered, so that nothing more is asked over it. The control: an ordinary refusal leaves the
    /// link open, and the next call over it is answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_refusal_of_the_link_itself_is_delivered_and_ends_the_link() {
        let served = Served::start().await;
        let (notifications, _relayed) = tokio::sync::mpsc::channel(RELAY_DEPTH);
        let lost = Arc::new(tokio::sync::Notify::new());
        let proxy = WorkerProxy::open(
            &served.controller,
            &served.worker,
            notifications,
            Arc::new(RelayBudget::new(RELAY_QUEUED_BYTES)),
            lost,
        )
        .await
        .expect("the worker accepts the link");
        let own = SessionReadParams {
            session_id: served.session_id,
        };

        // A read that names another session is refused for that, and the link is still good.
        let other = SessionReadParams {
            session_id: SessionId::new(kr_ipc::new_uuid()),
        };
        let ordinary = proxy
            .read(Method::SessionRead, &other)
            .await
            .expect("the worker answers")
            .outcome;
        let Outcome::Error(ordinary) = ordinary else {
            panic!("a read that names another session is refused");
        };
        assert!(!ordinary.link_fenced, "{ordinary:?}");
        assert!(proxy.is_open(), "an ordinary refusal leaves the link open");
        assert!(
            matches!(
                proxy
                    .read(Method::SessionRead, &own)
                    .await
                    .expect("the worker answers")
                    .outcome,
                Outcome::Ok(_)
            ),
            "and the next call over it is answered"
        );

        let _newer = served.a_newer_generation_takes_over().await;
        let fenced = proxy
            .read(Method::SessionRead, &own)
            .await
            .expect("the refusal is delivered")
            .outcome;
        let Outcome::Error(fenced) = fenced else {
            panic!("the worker refuses the link of a daemon it has been taken from");
        };
        assert_eq!(fenced.code, ErrorCode::PermissionDenied, "{fenced:?}");
        assert!(
            !fenced.link_fenced,
            "the marker is between the worker and this daemon, and a device is not given it"
        );
        // The link ended in the step that handed the refusal over, so a caller that reacts to it at
        // once finds the link ended.
        assert!(!proxy.is_open());
        proxy
            .read(Method::SessionRead, &own)
            .await
            .expect_err("nothing more is asked over a link the worker refused");
    }
}
