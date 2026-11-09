//! What a worker uses to reach the plugin host.
//!
//! A worker finds the host through the published descriptor, challenges the process behind the
//! endpoint, and then registers bindings, delivers events and makes calls. It never links the
//! engine and never runs a component.
//!
//! # Delivering an event never waits on a component
//!
//! Two forms, and neither enters an instance.
//!
//! [`PluginClient::offer`] is the one the terminal path uses. It puts the event on a bounded queue
//! and returns: no lock a component holds, no socket write, no answer waited for. A full queue is
//! an immediate refusal, which the caller records as a gap, rather than a wait.
//!
//! [`PluginClient::deliver`] writes one frame and reads its acknowledgement, for a caller that
//! wants the queue's answer. The acknowledgement is the queue's, not a component's: the host
//! answers an observation on the task that read it, without entering an instance, so a component in
//! the middle of an unbounded loop does not delay it.
//!
//! # Every request carries one deadline
//!
//! The deadline covers being admitted, being written and being answered. A host that stopped
//! reading its socket cannot hold a caller past it, and a connection that fails answers every call
//! waiting on it at once rather than leaving each to time out on its own.
//!
//! # What a plugin-host crash costs this worker
//!
//! Its rich bindings, and nothing else. The connection fails, the calls in flight return
//! [`crate::error::ServiceError::Unavailable`], and the worker's own ledger is untouched because
//! it was never in the other process. Re-registering the bindings is the whole of the recovery.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_protocol::frame::StreamKind;
use kr_protocol::scalars::Uuid;
use tokio::sync::oneshot;

use kr_plugin_sdk::identity::PluginIdentity;

use crate::error::{ServiceError, ServiceResult};
#[cfg(feature = "testing")]
use crate::hold::{Hold, HoldHandle};
use crate::launcher::{self, LaunchError};
use crate::notices::{self, MAX_NOTICE_BYTES, NoticeSink, NoticeStream, Offered};
use crate::protocol::{
    BindingRegistration, CallValue, ComponentSource, DecodeCall, EncodeCall, Frame, HostDescriptor,
    HostHealth, HostProtocol, Notice, PrepareActionCall, Request, RequestBody, ResponseBody,
    WireDecoded, WireEncoded, WireNamedArgument, WirePlan, WireRequestSnapshot, WireToken,
};
use crate::vocabulary::{
    Admission, AttachmentFact, BindingFacts, BindingId, COMPILE_DEADLINE_MS, MAX_NODE_BYTES,
    ScopedSourceEvent, wire_attachments, wire_event, wire_facts,
};

/// How long a worker waits for an answer before it stops waiting.
///
/// Every call the host makes into a component is bounded by that component's own deadline, so an
/// answer that has not arrived in this long means the host itself is not answering. The worker is
/// told so and carries on; nothing on the terminal path is behind this.
pub const DEFAULT_DEADLINE: core::time::Duration = core::time::Duration::from_secs(5);

/// How long a worker waits for a registration.
///
/// A registration contains a compile, so it is the one request that can legitimately take seconds.
/// It is deliberately longer than the host's own registration deadline: a client that gave up
/// first would report its own patience as the host's failure.
pub const REGISTER_DEADLINE: core::time::Duration =
    core::time::Duration::from_millis(COMPILE_DEADLINE_MS + 5_000);

/// How much longer than a component's own deadline a caller waits for the answer.
///
/// A call carries the deadline the component runs under, and the host stops the component at it.
/// What is left is the round trip: two frames and whatever the host's own queues are doing. A
/// caller that allowed 10 ms for a component should not then wait seconds for the answer, so the
/// exchange is that deadline plus this and nothing more.
pub const ROUND_TRIP_ALLOWANCE: core::time::Duration = core::time::Duration::from_millis(500);

/// The largest single event this client will hand over.
///
/// A control frame carries a mebibyte including its envelope, so an event larger than this is one
/// the writer could never deliver. Refusing it at the handoff is what keeps one oversized event
/// from ending every delivery that would have followed it.
pub const MAX_OFFERED_EVENT_BYTES: u64 = MAX_NODE_BYTES;

/// What one offered event costs of the handoff's allowance before its bytes are counted.
const OFFER_OVERHEAD_BYTES: u64 = 128;

/// How long one offered event is given to reach the host.
///
/// An offered event is not something anybody is waiting for an answer to, and a host that has not
/// taken one in this long is a host that has stopped reading. The writer stops rather than holding
/// the lock every request on this connection needs.
const OFFER_WRITE_DEADLINE: core::time::Duration = core::time::Duration::from_secs(10);

/// How many offered events may be waiting to be written.
///
/// The terminal path hands an event over and carries on, so there has to be somewhere for it to
/// wait, and that somewhere has to be bounded in both directions: how many, and how much they hold.
const MAX_OFFERED_EVENTS: usize = 256;

/// The connection's writer, held by a test until this is dropped.
#[cfg(feature = "testing")]
pub struct WriterHold {
    _writer: tokio::sync::OwnedMutexGuard<Option<FrameWriter>>,
}

#[cfg(feature = "testing")]
impl core::fmt::Debug for WriterHold {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("WriterHold").finish_non_exhaustive()
    }
}

/// What this client is doing about the registrations and removals of one identifier, and what it
/// knows of its live registrations, for as long as there is anything to know.
#[derive(Debug, Default)]
struct Churn {
    /// How many registrations of the identifier this client has started.
    started: u64,
    /// How many registrations of it wait for their answers now.
    registering: usize,
    /// How many removals of it wait for their answers now.
    removing: usize,
    /// How many registrations of it the host has answered as registered, until the answer to a
    /// removal that no registration overlapped, which sets it to nothing. It is the client's account,
    /// from the answers it has read, of the registrations the host stands behind, and it is never
    /// below what the host holds, so a count of nothing is the client's word that no registration
    /// of the identifier is live. A removal that a registration overlapped changes nothing: the
    /// host answers a removal for the registration it was about, which can be one that was still
    /// being made and was refused, and nothing in the answer says which. The count can stay above
    /// what the host holds then, which keeps the queue, until the next removal that nothing
    /// overlapped or until the client is dropped.
    live: usize,
}

impl Churn {
    /// Returns true when there is nothing about the identifier to remember.
    const fn idle(&self) -> bool {
        self.registering == 0 && self.removing == 0 && self.live == 0
    }
}

/// What the client is doing about each identifier it is registering or removing.
type Churning = Mutex<HashMap<Uuid, Churn>>;

/// What the client does about the answer to a request, whether or not the caller that made the
/// request is still waiting for it.
///
/// A request the host has read is about the registration the host holds, and the host answers it
/// whatever its caller does after. So the record of what the client is doing about the identifier
/// ends when the client reads the answer, in the task that reads the connection, and not when the
/// caller's future ends: a caller that stops waiting leaves the registration or the removal under
/// way at the host, and the client's queue is emptied, or kept, as the answer says.
#[derive(Debug)]
enum Settle {
    Registration(Registering),
    Removal(Removing),
}

impl Settle {
    fn answered(self, body: &ResponseBody) {
        match self {
            Self::Registration(registering) => registering.answered(body),
            Self::Removal(removing) => removing.answered(body),
        }
    }
}

/// One request to register a binding, counted from before it is sent until its answer has been read,
/// or until the client has no answer to read because the request was never sent or the connection
/// ended.
#[derive(Debug)]
struct Registering {
    churning: Arc<Churning>,
    sink: NoticeSink,
    binding_id: Uuid,
    released: bool,
}

impl Registering {
    fn begin(churning: &Arc<Churning>, sink: &NoticeSink, binding_id: Uuid) -> Self {
        if let Ok(mut churning) = churning.lock() {
            let churn = churning.entry(binding_id).or_default();
            churn.started += 1;
            churn.registering += 1;
        }
        Self {
            churning: Arc::clone(churning),
            sink: sink.clone(),
            binding_id,
            released: false,
        }
    }

    fn answered(mut self, body: &ResponseBody) {
        self.release(Some(body));
    }

    /// Ends the request's place in the record, and acts on the host's answer if there is one.
    ///
    /// A registration the host answered as registered is live until a removal says otherwise. One
    /// it refused may have written notices before it failed, which the host retracts from its queue
    /// but cannot take back from the connection, and the refusal is the only word the client has that
    /// the registration they came from is gone. They are taken out of the client's queue when
    /// nothing else could own them: no registration of the identifier is live, and no other
    /// registration of it waits for its answer. The host wrote everything the refused registration
    /// wrote before it answered the refusal, so what the queue holds then belongs to it or to a
    /// registration that is gone. The decision and the cleanup are one step under the record of
    /// what the client is doing, so a registration that is started afterwards sends its request
    /// after the cleanup.
    fn release(&mut self, answer: Option<&ResponseBody>) {
        if self.released {
            return;
        }
        self.released = true;
        let Ok(mut churning) = self.churning.lock() else {
            return;
        };
        let Some(churn) = churning.get_mut(&self.binding_id) else {
            return;
        };
        match answer {
            Some(ResponseBody::Registered { .. }) => churn.live += 1,
            Some(ResponseBody::Refused { .. }) if churn.registering == 1 && churn.live == 0 => {
                self.sink.forget(self.binding_id);
            }
            _ => {}
        }
        churn.registering = churn.registering.saturating_sub(1);
        if churn.idle() {
            churning.remove(&self.binding_id);
        }
    }
}

impl Drop for Registering {
    fn drop(&mut self) {
        self.release(None);
    }
}

/// One request to remove a binding, counted from before it is sent until its answer has been read,
/// or until the client has no answer to read because the request was never sent or the connection
/// ended.
#[derive(Debug)]
struct Removing {
    churning: Arc<Churning>,
    sink: NoticeSink,
    binding_id: Uuid,
    /// How many registrations of the identifier had been started when the request began.
    started_before: u64,
    /// Whether a registration of the identifier was waiting for its answer when the request began.
    registering_before: bool,
    released: bool,
}

impl Removing {
    fn begin(churning: &Arc<Churning>, sink: &NoticeSink, binding_id: Uuid) -> Self {
        let mut started_before = 0;
        let mut registering_before = false;
        if let Ok(mut churning) = churning.lock() {
            let churn = churning.entry(binding_id).or_default();
            churn.removing += 1;
            started_before = churn.started;
            registering_before = churn.registering > 0;
        }
        Self {
            churning: Arc::clone(churning),
            sink: sink.clone(),
            binding_id,
            started_before,
            registering_before,
            released: false,
        }
    }

    fn answered(mut self, body: &ResponseBody) {
        self.release(Some(body));
    }

    /// Ends the request's place in the record, and acts on the host's answer if there is one.
    ///
    /// When the host removed a registration, either way it says so, the client takes out of its
    /// queue everything it holds for the identifier, unless a registration of the identifier was
    /// under way when this removal began or has been started since. The host can write such a
    /// registration's first notices before it answers this removal, and nothing in a notice says
    /// which registration it is from, so what the queue holds may be that registration's. The
    /// decision and the cleanup are one step under the record of what the client is doing: a
    /// registration that is started afterwards sends its request after the cleanup, and the host
    /// writes nothing for it before it reads that request.
    ///
    /// An answer that found nothing removed nothing: the host held no registration of the
    /// identifier when it read the request.
    fn release(&mut self, answer: Option<&ResponseBody>) {
        if self.released {
            return;
        }
        self.released = true;
        let Ok(mut churning) = self.churning.lock() else {
            return;
        };
        let Some(churn) = churning.get_mut(&self.binding_id) else {
            return;
        };
        let answered = matches!(
            answer,
            Some(ResponseBody::Unbound { .. } | ResponseBody::Refused { .. })
        );
        let removed = match answer {
            Some(ResponseBody::Unbound { existed }) => *existed,
            Some(ResponseBody::Refused { .. }) => true,
            _ => false,
        };
        let overlapped = self.registering_before || churn.started != self.started_before;
        if answered && !overlapped {
            // With no registration under way when the request began and none started since, every
            // registration of the identifier had been answered before the host read the request,
            // and the host's answer, whichever it is, leaves it holding none: a registration it
            // held was removed by this request or by another removal, and a refusal takes the
            // registration out of the runtime as well. So nothing is live, whatever the count was,
            // and a count that an overlap left too high ends here.
            churn.live = 0;
            if removed {
                self.sink.forget(self.binding_id);
            }
        }
        churn.removing = churn.removing.saturating_sub(1);
        if churn.idle() {
            churning.remove(&self.binding_id);
        }
    }
}

impl Drop for Removing {
    fn drop(&mut self) {
        self.release(None);
    }
}

/// What an event handed over without waiting became.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handoff {
    /// The event is on its way to the host.
    Accepted,
    /// The queue is full. The event was not taken, and the caller records the loss.
    Refused {
        /// How many bytes the queue was holding.
        held_bytes: u64,
    },
    /// The event is larger than one frame carries, so nothing could have delivered it.
    TooLarge {
        /// What it would have cost.
        bytes: u64,
        /// The bound.
        limit: u64,
    },
    /// The connection to the host is gone.
    Unavailable,
}

/// One request's answer, on its way back to whoever asked.
type Answer = oneshot::Sender<ResponseBody>;

/// What one client shuts down when its connection ends.
///
/// Set once, after the tasks exist. Closing the connection has to be one thing: a flag that stops
/// new requests, the waiting senders dropped, the reader and the writer of offered events stopped,
/// and the notice queue closed. Doing only the first two would leave a reader waiting on a socket
/// nothing will answer and a caller offering events nothing will send.
#[derive(Debug)]
struct Transport {
    reader: tokio::task::AbortHandle,
    offers: tokio::task::AbortHandle,
    notices: NoticeSink,
    /// The writer, so closing takes it and drops it. A client that had declared its connection over
    /// and still held the socket's write half would leave a host waiting for the rest of a frame
    /// that is never coming.
    writer: Writer,
    /// What offered events have reserved, so closing gives it all back: the queue they were in is
    /// gone, and a charge for events nobody will send would make every later offer a refusal.
    offered_bytes: Arc<AtomicU64>,
}

/// The one writer this connection has, until it is closed.
type Writer = Arc<tokio::sync::Mutex<Option<FrameWriter>>>;

/// One request waiting for its answer.
#[derive(Debug)]
struct Waiter {
    /// Where the answer goes while the caller still waits for it.
    caller: Option<Answer>,
    /// What is done with the answer whether or not anybody still waits for it.
    settle: Option<Settle>,
    /// Whether the request's frame has been written in full, which is when the host can answer it.
    written: bool,
}

impl Waiter {
    /// Acts on the answer, and hands it to the caller if the caller still waits.
    fn answered(self, body: ResponseBody) {
        if let Some(settle) = self.settle {
            settle.answered(&body);
        }
        if let Some(caller) = self.caller {
            let _delivered = caller.send(body);
        }
    }
}

/// The requests this client is waiting on, and whether its connection still exists.
#[derive(Debug, Default)]
struct Pending {
    waiting: Mutex<HashMap<u64, Waiter>>,
    closed: AtomicBool,
    transport: Mutex<Option<Transport>>,
    /// What the client is doing about each identifier it is registering or removing. It is kept
    /// here, with the waiting set, because it is only about answers this connection can still
    /// bring: when the connection ends it is emptied with them.
    churning: Arc<Churning>,
}

impl Pending {
    /// Records that a request is waiting for its number, unless the connection has already gone.
    ///
    /// The check and the insertion are one step under the lock. Two steps would let a request be
    /// admitted between a reader deciding the connection was over and its clearing the waiting
    /// set, and that request would then wait for an answer nobody could send.
    fn wait_for(&self, request_id: u64, answer: Answer, settle: Option<Settle>) -> bool {
        let Ok(mut waiting) = self.waiting.lock() else {
            return false;
        };
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        waiting.insert(
            request_id,
            Waiter {
                caller: Some(answer),
                settle,
                written: false,
            },
        );
        true
    }

    /// Records that a request's frame has been written in full.
    fn written(&self, request_id: u64) {
        if let Ok(mut waiting) = self.waiting.lock()
            && let Some(waiter) = waiting.get_mut(&request_id)
        {
            waiter.written = true;
        }
    }

    /// Takes one request's place, if it is still waiting.
    fn take(&self, request_id: u64) -> Option<Waiter> {
        self.waiting
            .lock()
            .ok()
            .and_then(|mut waiting| waiting.remove(&request_id))
    }

    /// Ends a caller's wait for one request's answer.
    ///
    /// A request that something is to be done about when its answer comes, and whose frame has been
    /// written in full, stays among those waiting without a caller, so that the answer is acted on
    /// when it is read. Every other request goes: an answer nobody is waiting for is dropped.
    fn stop_waiting(&self, request_id: u64) {
        let gone = {
            let Ok(mut waiting) = self.waiting.lock() else {
                return;
            };
            let outlives_its_caller = waiting
                .get(&request_id)
                .is_some_and(|waiter| waiter.written && waiter.settle.is_some());
            if outlives_its_caller {
                if let Some(waiter) = waiting.get_mut(&request_id) {
                    waiter.caller = None;
                }
                None
            } else {
                waiting.remove(&request_id)
            }
        };
        // Outside the lock: what a waiter holds takes locks of its own when it goes.
        drop(gone);
    }

    /// Drops every waiting sender and records that the connection is gone.
    ///
    /// Dropping a sender is what tells its caller the host closed the connection, at once, rather
    /// than each caller waiting out its own deadline for an answer that cannot arrive. What the
    /// client knew of its registrations goes with them: no answer will come to act on it, and a
    /// client over a closed connection refuses every request and cannot be connected again.
    fn close(&self) {
        // The flag is set under the lock an admission takes, so an admission either happens before
        // the connection ended or is refused by it; there is no order in which it happens after.
        let drained = if let Ok(mut waiting) = self.waiting.lock() {
            self.closed.store(true, Ordering::Release);
            core::mem::take(&mut *waiting)
        } else {
            self.closed.store(true, Ordering::Release);
            HashMap::new()
        };
        // Outside the lock: what a waiter holds takes locks of its own when it goes.
        drop(drained);
        if let Ok(mut churning) = self.churning.lock() {
            churning.clear();
        }
        // And the transport goes with them: a reader still waiting on the socket, a writer still
        // sending events, or a socket still half open would be this client carrying on with a
        // connection it has declared over.
        if let Ok(mut transport) = self.transport.lock()
            && let Some(transport) = transport.take()
        {
            transport.reader.abort();
            transport.offers.abort();
            transport.notices.close();
            transport.offered_bytes.store(0, Ordering::Release);
            // The writer, if nobody is using it. Whoever is holds it out of the slot for the length
            // of their own frame and drops it rather than putting it back once this flag is set, so
            // there is no case in which it survives a closure and no cleanup to schedule.
            if let Ok(mut writer) = transport.writer.try_lock() {
                let _closed = writer.take();
            }
        }
    }

    /// Records what closing this connection has to stop.
    fn serves(&self, transport: Transport) {
        if self.closed.load(Ordering::Acquire) {
            transport.reader.abort();
            transport.offers.abort();
            transport.notices.close();
            transport.offered_bytes.store(0, Ordering::Release);
            return;
        }
        if let Ok(mut slot) = self.transport.lock() {
            *slot = Some(transport);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// One frame on its way out, and what happens if it does not get there.
///
/// A frame that is abandoned part way -- by a failure, by a deadline, or by a caller that stopped
/// polling -- is the end of this connection: the writer it was using is dropped where it stands,
/// and this closes the rest, so the reader stops, everyone waiting is told, and the socket goes with
/// the last of its halves. Without this, a cancelled write would leave a host waiting for bytes
/// that are never coming and a client waiting for an answer it can never get.
struct Framing<'a> {
    pending: &'a Pending,
    finished: bool,
}

impl Framing<'_> {
    fn finished(mut self, wrote: bool) {
        self.finished = wrote;
    }
}

impl Drop for Framing<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.pending.close();
        }
    }
}

/// One request's place in the waiting set, ended however the caller leaves.
///
/// A timeout, a write failure and a cancelled future all end the same way: the caller's sender goes,
/// and so does the entry, unless the request is one whose answer is acted on whoever is waiting for
/// it. Without this, a caller that gave up would leave its sender behind and the set would grow
/// with every call that did not arrive.
struct Waiting<'a> {
    pending: &'a Pending,
    request_id: u64,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.pending.stop_waiting(self.request_id);
    }
}

/// A worker's connection to the plugin host.
pub struct PluginClient {
    writer: Writer,
    pending: Arc<Pending>,
    /// Behind a lock so that a caller reading notices and a caller making a call hold the client
    /// by shared reference together: one task waits for news while others ask the host to prepare
    /// an action.
    notices: tokio::sync::Mutex<NoticeStream>,
    /// The other end of the notice queue, so a binding that goes takes its records with it.
    sink: NoticeSink,
    offered: tokio::sync::mpsc::Sender<Request>,
    offered_bytes: Arc<AtomicU64>,
    #[cfg(feature = "testing")]
    offer_hold: Arc<Hold>,
    /// How long a registration is waited for.
    register_deadline: core::time::Duration,
    /// How long an unbind is waited for.
    unbind_deadline: core::time::Duration,
    next_request: AtomicU64,
    descriptor: HostDescriptor,
    reader_task: tokio::task::JoinHandle<()>,
    offer_task: tokio::task::JoinHandle<()>,
}

impl core::fmt::Debug for PluginClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PluginClient")
            .field("endpoint", &self.descriptor.endpoint)
            .finish_non_exhaustive()
    }
}

impl PluginClient {
    /// Connects to the plugin host of this build's protocol named in the environment's descriptor
    /// (`plugin-host-3.json`), and verifies it. A host of another protocol has a descriptor of its
    /// own, which this client never reads, so it never opens a connection to that host.
    ///
    /// The descriptor is a hint. What settles which process is answering is the challenge below:
    /// the host signs a fresh nonce with the key the descriptor records, and a process that cannot
    /// is not the one the launcher started.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when there is no descriptor or the endpoint
    /// cannot be reached, and [`ServiceError::Protocol`] when the host answers with
    /// something this client cannot read or cannot verify.
    pub async fn connect(environment: &EnvironmentPaths) -> ServiceResult<Self> {
        let descriptor = launcher::read_descriptor(environment, &HostProtocol::THIS)
            .map_err(unavailable)?
            .ok_or_else(|| ServiceError::Unavailable {
                detail: "this environment has no plugin host".to_owned(),
            })?;
        let endpoint = Endpoint::from_path(&descriptor.endpoint).map_err(|error| {
            ServiceError::Unavailable {
                detail: error.to_string(),
            }
        })?;
        let connection =
            Connection::connect(&endpoint)
                .await
                .map_err(|error| ServiceError::Unavailable {
                    detail: error.to_string(),
                })?;
        Self::over(connection, descriptor).await
    }

    /// Opens a client over an existing connection and verifies the host.
    ///
    /// # Errors
    ///
    /// Returns the handshake or verification failure.
    pub async fn over(connection: Connection, descriptor: HostDescriptor) -> ServiceResult<Self> {
        let (reader, writer) = split(connection, StreamKind::Control);
        let writer: Writer = Arc::new(tokio::sync::Mutex::new(Some(writer)));
        let pending = Arc::new(Pending::default());
        let (sink, notices) = notices::channel();
        let sink_for_client = sink.clone();
        let reader_task = tokio::spawn(read_frames(reader, Arc::clone(&pending), sink.clone()));

        // The handoff the terminal path uses: bounded, written by a task of its own, never waited
        // on by whoever offered the event.
        let (offered, waiting_events) = tokio::sync::mpsc::channel::<Request>(MAX_OFFERED_EVENTS);
        let offered_bytes = Arc::new(AtomicU64::new(0));
        #[cfg(feature = "testing")]
        let offer_hold = Arc::new(Hold::default());
        let offer_task = tokio::spawn(write_offered(
            waiting_events,
            Arc::clone(&writer),
            Arc::clone(&offered_bytes),
            Arc::clone(&pending),
            #[cfg(feature = "testing")]
            Arc::clone(&offer_hold),
        ));
        // What closing this connection has to stop, recorded before anything can close it.
        pending.serves(Transport {
            reader: reader_task.abort_handle(),
            offers: offer_task.abort_handle(),
            notices: sink,
            writer: Arc::clone(&writer),
            offered_bytes: Arc::clone(&offered_bytes),
        });

        let client = Self {
            writer,
            pending,
            notices: tokio::sync::Mutex::new(notices),
            sink: sink_for_client,
            offered,
            offered_bytes,
            #[cfg(feature = "testing")]
            offer_hold,
            register_deadline: REGISTER_DEADLINE,
            unbind_deadline: DEFAULT_DEADLINE,
            next_request: AtomicU64::new(1),
            descriptor,
            reader_task,
            offer_task,
        };

        let hello = client
            .request(RequestBody::Hello {
                protocol: HostProtocol::THIS.name.to_owned(),
            })
            .await?;
        let ResponseBody::Hello { protocol, .. } = hello else {
            return Err(protocol_error(&hello));
        };
        if protocol != HostProtocol::THIS.name {
            return Err(ServiceError::Protocol {
                detail: format!("the host speaks {protocol}"),
            });
        }

        // The challenge. Until it is answered, the descriptor is a file and the endpoint is a path.
        let nonce = launcher::fresh_challenge().map_err(unavailable)?;
        let verified = client.request(RequestBody::Verify { nonce }).await?;
        let ResponseBody::Verified(proof) = verified else {
            return Err(protocol_error(&verified));
        };
        launcher::check_proof(&client.descriptor, &nonce, &proof).map_err(|error| {
            ServiceError::Protocol {
                detail: error.to_string(),
            }
        })?;
        Ok(client)
    }

    /// Returns the descriptor the host was reached through and verified against.
    #[must_use]
    pub const fn descriptor(&self) -> &HostDescriptor {
        &self.descriptor
    }

    /// Registers a binding: the host compiles the component, instantiates it and binds it.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, including a component that imports something outside the
    /// contract, or [`ServiceError::Unavailable`] when the host is gone.
    pub async fn register(
        &self,
        binding_id: BindingId,
        identity: &PluginIdentity,
        facts: &BindingFacts,
        executable: &str,
        component: &ComponentSource,
    ) -> ServiceResult<Registration> {
        let registering = Registering::begin(&self.pending.churning, &self.sink, binding_id.get());
        let body = self
            .request_settling(
                RequestBody::RegisterBinding(Box::new(BindingRegistration {
                    binding_id: binding_id.get(),
                    identity: identity.clone(),
                    facts: wire_facts(facts),
                    executable: executable.to_owned(),
                    component: component.clone(),
                })),
                self.register_deadline,
                Some(Settle::Registration(registering)),
            )
            .await?;
        match body {
            ResponseBody::Registered { origin, elapsed_ms } => Ok(Registration {
                cached: origin == "cached",
                elapsed_ms,
            }),
            ResponseBody::Refused { detail, .. } => Err(ServiceError::Protocol { detail }),
            other => Err(protocol_error(&other)),
        }
    }

    /// Hands one source event over without waiting for anything.
    ///
    /// This is the terminal path's form. It takes no lock a component holds, writes no frame and
    /// waits for no answer: the event goes on a bounded queue and a task of this client's own
    /// writes it. A full queue is an immediate refusal the caller records as a gap, which is the
    /// same answer the host's own queue gives when it overflows and for the same reason.
    pub fn offer(&self, binding_id: BindingId, event: &ScopedSourceEvent) -> Handoff {
        if self.pending.is_closed() {
            return Handoff::Unavailable;
        }
        let wire = wire_event(event);
        let cost = offered_cost(&wire);
        // An event a frame cannot carry is one nothing could deliver. Saying so here is what keeps
        // it from stopping the writer and taking every later delivery with it.
        if cost > MAX_OFFERED_EVENT_BYTES {
            return Handoff::TooLarge {
                bytes: cost,
                limit: MAX_OFFERED_EVENT_BYTES,
            };
        }
        // Reserved before the event is published, and in one step, because the writer releases the
        // reservation when it has written the event: a charge made afterwards could be made after
        // its own release, and the allowance would drift until it admitted nothing.
        let Ok(held) =
            self.offered_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                    let wanted = held.saturating_add(cost);
                    (wanted <= MAX_NOTICE_BYTES).then_some(wanted)
                })
        else {
            return Handoff::Refused {
                held_bytes: self.offered_bytes.load(Ordering::Acquire),
            };
        };
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let request = Request {
            request_id,
            body: RequestBody::Event {
                binding_id: binding_id.get(),
                event: wire,
            },
        };
        match self.offered.try_send(request) {
            Ok(()) => {
                // The connection can end between the check above and this point, and closing sets
                // the total to zero rather than subtracting: a charge made after that would be a
                // charge for an event in a queue nobody is reading, and it would make every later
                // offer a refusal instead of the refusal it should be.
                if self.pending.is_closed() {
                    release(&self.offered_bytes, cost);
                    return Handoff::Unavailable;
                }
                Handoff::Accepted
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                release(&self.offered_bytes, cost);
                Handoff::Refused { held_bytes: held }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                release(&self.offered_bytes, cost);
                Handoff::Unavailable
            }
        }
    }

    /// Returns how many bytes of offered events have been handed over and not yet written.
    ///
    /// An event counts until its write has finished, the one being written included, so zero says
    /// that every event handed over has been written, or that the connection is over and refuses
    /// every request. A request made on this connection after the count was read as zero is
    /// written after those events. That is the order the host receives them in; whether the
    /// component has observed them by then is not something the count says.
    #[must_use]
    pub fn offered_bytes(&self) -> u64 {
        self.offered_bytes.load(Ordering::Acquire)
    }

    /// Holds the task that writes offered events, between taking an event off the queue and writing
    /// it, until the returned hold is released. For the tests of a crate that drives this client.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_offered_writes(&self) -> HoldHandle {
        self.offer_hold.set()
    }

    /// Returns how many bytes of notices this client's queue holds and nobody has read, for the
    /// tests of a crate that drives this client.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn held_notice_bytes(&self) -> u64 {
        self.sink.held_bytes()
    }

    /// Returns how many identifiers this client holds a record of registrations and removals for,
    /// for the tests of a crate that drives this client: a client whose connection has ended holds
    /// none.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn identifiers_in_flight_or_live(&self) -> usize {
        self.pending
            .churning
            .lock()
            .map_or(0, |churning| churning.len())
    }

    /// Takes the connection's writer, as a task in the middle of writing a frame holds it, and
    /// keeps it until the returned hold is dropped. For the tests of a crate that drives this
    /// client: what is handed over while it is held waits in the queue for it.
    #[cfg(feature = "testing")]
    pub async fn hold_writer(&self) -> WriterHold {
        WriterHold {
            _writer: Arc::clone(&self.writer).lock_owned().await,
        }
    }

    /// Waits `deadline` for a registration instead of [`REGISTER_DEADLINE`]. For the tests of a
    /// crate that drives this client against a host that waits for a registration for a time of
    /// its own choosing, which this should exceed, as the default does: a registration contains a
    /// compile, which a machine that other work keeps busy delays for minutes, and a test that
    /// registers a component decides by what the registration comes to.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn registering_within(mut self, deadline: core::time::Duration) -> Self {
        self.register_deadline = deadline;
        self
    }

    /// Waits `deadline` for the answer to an unbind instead of [`DEFAULT_DEADLINE`], for the
    /// tests of a host whose unbind is held up for a time the test decides: a test that decides
    /// by what the host answers does not decide by how long a machine takes to get to the step that
    /// lets the host go.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn unbinding_within(mut self, deadline: core::time::Duration) -> Self {
        self.unbind_deadline = deadline;
        self
    }

    /// Offers one source event and waits for the queue's answer.
    ///
    /// Nothing runs a component here either: the host answers an observation on the task that read
    /// it. This form exists for a caller that wants to know what the queue did with the event.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Unavailable`].
    pub async fn deliver(
        &self,
        binding_id: BindingId,
        event: &ScopedSourceEvent,
    ) -> ServiceResult<Admission> {
        let body = self
            .request(RequestBody::Event {
                binding_id: binding_id.get(),
                event: wire_event(event),
            })
            .await?;
        match body {
            ResponseBody::Admitted {
                admission,
                lost_events,
                lost_bytes,
            } => match admission.as_str() {
                "queued" => Ok(Admission::Queued),
                "queued_with_gap" => Ok(Admission::QueuedWithGap {
                    events: lost_events,
                    bytes: lost_bytes,
                }),
                "refused" => Ok(Admission::Refused {
                    held_bytes: lost_bytes,
                }),
                other => Err(ServiceError::Protocol {
                    detail: format!("{other} is not an admission this client knows"),
                }),
            },
            ResponseBody::Refused {
                detail, disabled, ..
            } => Err(refused(detail, disabled)),
            other => Err(protocol_error(&other)),
        }
    }

    /// Asks a binding for a fresh document.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Unavailable`].
    pub async fn snapshot(
        &self,
        binding_id: BindingId,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        self.call(
            RequestBody::Snapshot {
                binding_id: binding_id.get(),
                deadline_ms: millis(deadline),
            },
            deadline,
        )
        .await
    }

    /// Takes a binding's resumable state.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Unavailable`].
    pub async fn checkpoint(
        &self,
        binding_id: BindingId,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        self.call(
            RequestBody::Checkpoint {
                binding_id: binding_id.get(),
                deadline_ms: millis(deadline),
            },
            deadline,
        )
        .await
    }

    /// Restores a binding from a checkpoint.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Unavailable`].
    pub async fn restore(
        &self,
        binding_id: BindingId,
        state: Vec<u8>,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        self.call(
            RequestBody::Restore {
                binding_id: binding_id.get(),
                state,
                deadline_ms: millis(deadline),
            },
            deadline,
        )
        .await
    }

    /// Removes a binding.
    ///
    /// Any answer from the host means the binding is gone: it has been removed, or the host took it
    /// out of its runtime without waiting for the removal to finish and said so in a refusal, or it
    /// held none. A worker reads each as gone. The client takes out of its queue everything it was
    /// holding for the binding when the host removed one, either way it says so: the host writes
    /// what a registration produced before it answers that registration's removal and nothing
    /// after it, so what the queue holds when the answer comes is the removed registration's, and
    /// none of it is shown to the identifier's next one.
    ///
    /// That is done when the answer is read, whatever the caller of this has done by then: a
    /// caller that stops waiting for the answer after the request was written in full, by a
    /// deadline of its own or by dropping this future, leaves the removal with the host, which
    /// carries it out, and the queue is emptied as the answer comes, where a retry would find
    /// nothing to remove. One that stops before the request was written sends nothing, and a retry
    /// finds the binding.
    ///
    /// That holds for a caller that registers the identifier again only after this returns, which
    /// is what a worker does. A caller that has a registration of the identifier under way when
    /// this begins, or starts one while this waits, has the host's word for nothing more than that
    /// the old registration's notices came before the answer, and the new registration's first
    /// notices can have come before it too, with nothing to tell the two apart. A registration is
    /// under way until the host has answered it, also when its caller has stopped waiting. Such a
    /// caller keeps everything its queue holds.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Protocol`] for the host's refusal, which is an answer and not a
    /// failure to get one, and [`ServiceError::Unavailable`] when the host is gone.
    pub async fn unbind(&self, binding_id: BindingId) -> ServiceResult<bool> {
        let removing = Removing::begin(&self.pending.churning, &self.sink, binding_id.get());
        let body = self
            .request_settling(
                RequestBody::Unbind {
                    binding_id: binding_id.get(),
                },
                self.unbind_deadline,
                Some(Settle::Removal(removing)),
            )
            .await?;
        match body {
            ResponseBody::Unbound { existed } => Ok(existed),
            ResponseBody::Refused {
                detail, disabled, ..
            } => Err(refused(detail, disabled)),
            other => Err(protocol_error(&other)),
        }
    }

    /// Asks what the host is doing.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when the host is gone.
    pub async fn health(&self) -> ServiceResult<HostHealth> {
        let body = self.request(RequestBody::Health).await?;
        match body {
            ResponseBody::Health(health) => Ok(*health),
            other => Err(protocol_error(&other)),
        }
    }

    /// Waits for the next notice a binding produced.
    pub async fn notice(&self) -> Option<Notice> {
        self.notices.lock().await.recv().await
    }

    /// Asks a binding's component to turn an invoked control into a proposed effect.
    ///
    /// The component returns a plan and sends nothing. What it returns is a proposal: the caller
    /// compares it with the invocation and the declaration before anything happens.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Disabled`], and [`ServiceError::Unavailable`]
    /// when the host is gone.
    pub async fn prepare_action(
        &self,
        binding_id: BindingId,
        token: WireToken,
        arguments: Vec<WireNamedArgument>,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        self.call(
            RequestBody::PrepareAction(Box::new(PrepareActionCall {
                binding_id: binding_id.get(),
                token,
                arguments,
                deadline_ms: millis(deadline),
            })),
            deadline,
        )
        .await
    }

    /// Asks a binding's component to interpret one native request.
    ///
    /// The component returns a proposal and sends nothing. What it returns is data to compare with
    /// the request the caller holds, and not something to believe: the caller checks the identifier
    /// it names, the decisions it offers and the length of what it says.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, [`ServiceError::Disabled`] and [`ServiceError::Unavailable`] as
    /// [`Self::prepare_action`] does, and a refusal at once, with the connection untouched, for a
    /// request no frame could carry.
    pub async fn decode(
        &self,
        binding_id: BindingId,
        event: &ScopedSourceEvent,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        self.call_that_fits(
            RequestBody::Decode(Box::new(DecodeCall {
                binding_id: binding_id.get(),
                event: wire_event(event),
                deadline_ms: millis(deadline),
            })),
            deadline,
        )
        .await
    }

    /// Asks a binding's component to encode a decision the caller validated as the bytes of a
    /// response.
    ///
    /// The bytes come back and have not gone anywhere: the host has no way to send them.
    ///
    /// # Errors
    ///
    /// As [`Self::decode`].
    pub async fn encode(
        &self,
        binding_id: BindingId,
        request: WireRequestSnapshot,
        decision: &str,
        event: Option<&ScopedSourceEvent>,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        self.call_that_fits(
            RequestBody::Encode(Box::new(EncodeCall {
                binding_id: binding_id.get(),
                request,
                decision: decision.to_owned(),
                event: event.map(wire_event),
                deadline_ms: millis(deadline),
            })),
            deadline,
        )
        .await
    }

    /// Replaces the facts a binding's component reads about its bound execution.
    ///
    /// Answered when the host has accepted them. The component sees them in its next call.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Unavailable`], and a refusal at once for a
    /// request no frame could carry.
    pub async fn revise_facts(
        &self,
        binding_id: BindingId,
        facts: &BindingFacts,
    ) -> ServiceResult<()> {
        let request = RequestBody::ReviseFacts {
            binding_id: binding_id.get(),
            facts: wire_facts(facts),
        };
        check_fits(&request)?;
        revised(self.request(request).await?)
    }

    /// Replaces the attachments a binding's component reads the current draft as holding.
    ///
    /// # Errors
    ///
    /// As [`Self::revise_facts`].
    pub async fn revise_attachments(
        &self,
        binding_id: BindingId,
        attachments: &[AttachmentFact],
    ) -> ServiceResult<()> {
        let request = RequestBody::ReviseAttachments {
            binding_id: binding_id.get(),
            attachments: wire_attachments(attachments),
        };
        check_fits(&request)?;
        revised(self.request(request).await?)
    }

    /// Tells the host whether privacy mode stands for the worker this connection serves.
    ///
    /// The answer comes once the host holds it: from then on, until it is told otherwise, no
    /// document of this connection is written and no decoded request carries its presentation.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`ServiceError::Unavailable`], and a protocol error for an
    /// answer that says something other than what was asked.
    pub async fn privacy(&self, private: bool) -> ServiceResult<()> {
        let body = self.request(RequestBody::Privacy { private }).await?;
        match body {
            ResponseBody::PrivacySet { private: held } if held == private => Ok(()),
            ResponseBody::PrivacySet { private: held } => Err(ServiceError::Protocol {
                detail: format!("privacy mode was set to {held} and the request said {private}"),
            }),
            ResponseBody::Refused {
                detail, disabled, ..
            } => Err(refused(detail, disabled)),
            other => Err(protocol_error(&other)),
        }
    }

    /// Makes a call after checking that its request fits one frame.
    ///
    /// A request that will not encode once the writer is taken ends the connection, which is the
    /// right end for a connection that cannot be written and the wrong one for a caller that asked
    /// for too much.
    async fn call_that_fits(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        check_fits(&body)?;
        self.call(body, deadline).await
    }

    async fn call(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
    ) -> ServiceResult<Called> {
        // The component's own deadline plus the round trip, rather than a fixed figure: a caller
        // that allowed ten milliseconds for a component did not mean to wait five seconds for the
        // answer when the host stops answering.
        let answered = self
            .request_within(body, deadline.saturating_add(ROUND_TRIP_ALLOWANCE))
            .await?;
        match answered {
            ResponseBody::Called {
                value,
                fault,
                document,
            } => {
                let mut called = Called {
                    state: None,
                    plan: None,
                    decoded: None,
                    encoded: None,
                    fault,
                    document,
                };
                match value {
                    Some(CallValue::State(state)) => called.state = Some(state),
                    Some(CallValue::Plan(plan)) => called.plan = Some(*plan),
                    Some(CallValue::Decoded(decoded)) => called.decoded = Some(*decoded),
                    Some(CallValue::Encoded(encoded)) => called.encoded = Some(*encoded),
                    Some(CallValue::Document) | None => {}
                }
                Ok(called)
            }
            ResponseBody::Refused {
                detail, disabled, ..
            } => Err(refused(detail, disabled)),
            other => Err(protocol_error(&other)),
        }
    }

    async fn request(&self, body: RequestBody) -> ServiceResult<ResponseBody> {
        self.request_within(body, DEFAULT_DEADLINE).await
    }

    /// Sends one request and waits for its answer, all inside one deadline.
    ///
    /// The deadline covers being admitted to the waiting set, taking the writer, writing the frame
    /// and receiving the answer. Starting it after the write would let a host that stopped reading
    /// its socket hold a caller for as long as it liked, which is the one thing a deadline on this
    /// path exists to prevent.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::Unavailable`] when the connection is gone,
    /// [`ServiceError::CallerDeadline`] when the deadline passes first.
    async fn request_within(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
    ) -> ServiceResult<ResponseBody> {
        self.request_settling(body, deadline, None).await
    }

    /// Sends one request as [`Self::request_within`] does, and has `settle` acted on its answer
    /// when the client reads it, whether or not this call is still waiting for it by then.
    ///
    /// The answer to a request that was written in full is read and acted on even when the caller
    /// has stopped waiting, by a deadline or by dropping this future; one that was never written
    /// in full has no answer to wait for, and `settle` goes with the caller.
    async fn request_settling(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
        settle: Option<Settle>,
    ) -> ServiceResult<ResponseBody> {
        if self.pending.is_closed() {
            return Err(ServiceError::Unavailable {
                detail: "the plugin host closed the connection".to_owned(),
            });
        }
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (answer, reply) = oneshot::channel();
        if !self.pending.wait_for(request_id, answer, settle) {
            return Err(ServiceError::Unavailable {
                detail: "the plugin host closed the connection".to_owned(),
            });
        }
        // Removed however this call ends: answered, timed out, failed to write, or dropped by a
        // caller that stopped waiting.
        let _place = Waiting {
            pending: &self.pending,
            request_id,
        };

        let exchange = async {
            {
                let mut held = self.writer.lock().await;
                // Taken out for the write and put back only if the frame finished. A frame that is
                // half written and then abandoned -- by a failure, by a deadline, or by a caller
                // that stopped polling -- leaves a writer that refuses every later frame, and there
                // is no way back from that on this connection. Holding the writer here means the
                // abandoning drops it; nothing has to be scheduled and nothing has to run on an
                // executor that may not exist. A writer found in the slot after the connection
                // closed is dropped rather than used, which is what makes the one narrow order --
                // a frame put back at the instant of closure -- harmless.
                let Some(mut writer) = held.take() else {
                    return Err(ServiceError::Unavailable {
                        detail: "the plugin host closed the connection".to_owned(),
                    });
                };
                if self.pending.is_closed() {
                    drop(writer);
                    return Err(ServiceError::Unavailable {
                        detail: "the plugin host closed the connection".to_owned(),
                    });
                }
                // The connection ends unless the frame finishes. Dropping the writer stops this
                // side sending; closing the rest stops this side reading and tells everyone
                // waiting, which is what makes a cancelled write the end of a connection rather
                // than one silent call.
                let frame = Framing {
                    pending: &self.pending,
                    finished: false,
                };
                let written = writer.write_message(&Request { request_id, body }).await;
                frame.finished(written.is_ok());
                if written.is_ok() {
                    self.pending.written(request_id);
                }
                if written.is_ok() && !self.pending.is_closed() {
                    *held = Some(writer);
                } else {
                    drop(writer);
                    self.pending.close();
                }
                drop(held);
                // Closing takes the writer when nobody is holding it, and this caller was holding
                // it: a closure that happened between the check above and the line after it found
                // the lock taken and did nothing. Looking again now, with the lock free, is what
                // leaves no order in which a writer outlives its connection.
                if self.pending.is_closed()
                    && let Ok(mut slot) = self.writer.try_lock()
                {
                    let _closed = slot.take();
                }
                written.map_err(|error| ServiceError::Unavailable {
                    detail: error.to_string(),
                })?;
            }
            match reply.await {
                Ok(body) => Ok(body),
                // The reader dropped the sender, which means the connection is gone.
                Err(_closed) => Err(ServiceError::Unavailable {
                    detail: "the plugin host closed the connection".to_owned(),
                }),
            }
        };
        match tokio::time::timeout(deadline, exchange).await {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err(ServiceError::CallerDeadline {
                deadline_ms: millis(deadline),
            }),
        }
    }
}

impl Drop for PluginClient {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.offer_task.abort();
        self.pending.close();
    }
}

/// What a registration produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    /// Whether the component came from the compiled-code cache.
    pub cached: bool,
    /// How long obtaining the compiled component took.
    pub elapsed_ms: u64,
}

/// What a call produced.
///
/// The document it drew is not here. Nodes arrive as notices, because one call may draw more than
/// one frame carries; a caller that wants the document reads [`PluginClient::notice`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Called {
    /// A component's own resumable state, where the call returns one.
    pub state: Option<Vec<u8>>,
    /// The effect the component proposed, where the call is `prepare-action` and it answered.
    pub plan: Option<WirePlan>,
    /// The request the component decoded, where the call is `decode-request` and it answered.
    pub decoded: Option<WireDecoded>,
    /// The response the component encoded, where the call is `encode-response` and it answered.
    pub encoded: Option<WireEncoded>,
    /// The fault the component declared, where it declared one.
    pub fault: Option<String>,
    /// Which of this binding's documents the call drew, where it drew one.
    ///
    /// The notices that carry that document name the same number, so a caller can tell which
    /// document belongs to which call, and nothing here means the call drew nothing.
    pub document: Option<u64>,
}

impl Called {
    /// Returns true when the component answered rather than declared a fault.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.fault.is_none()
    }
}

/// Reads frames until the connection ends, then tells everyone waiting that it has.
async fn read_frames(mut reader: FrameReader, pending: Arc<Pending>, notices: NoticeSink) {
    loop {
        let frame: Frame = match reader.read_message_without_schema().await {
            Ok(frame) => frame,
            // The connection is gone, or the host sent something this protocol does not admit.
            // Either way every caller waiting on it is told now: an answer that cannot arrive is
            // not something to make each of them wait out its own deadline for.
            Err(_error) => break,
        };
        match frame {
            Frame::Response { reply_to, body } => {
                if let Some(waiter) = pending.take(reply_to) {
                    waiter.answered(body);
                }
            }
            Frame::Notice(notice) => {
                // A queue that cannot hold what must arrive is a connection this worker cannot
                // trust to tell it when a binding stops working, so it ends here rather than
                // carrying on with a partial account.
                match notices.send(notice) {
                    Offered::Kept | Offered::Dropped | Offered::Withheld => {}
                    Offered::Overflowed | Offered::Closed => break,
                }
            }
        }
    }
    pending.close();
    notices.close();
}

/// Writes the events a caller handed over without waiting.
async fn write_offered(
    mut offered: tokio::sync::mpsc::Receiver<Request>,
    writer: Writer,
    held: Arc<AtomicU64>,
    pending: Arc<Pending>,
    #[cfg(feature = "testing")] hold: Arc<Hold>,
) {
    while let Some(request) = offered.recv().await {
        let cost = offered_bytes_of(&request);
        #[cfg(feature = "testing")]
        hold.pause().await;
        // The charge is kept until the write has finished, so that the count is zero only when
        // every event handed over has been written or the connection is over: a caller that waits
        // for it and then makes a request on this connection has the request written after those
        // events, since both take the writer, or refused. A charge released before the write would
        // leave the last event uncounted while it is still to be written, and one released after a
        // failure but before the close would leave a connection that still takes requests with an
        // unwritten event uncounted. This task can be stopped at any await below, which leaves the
        // charge in place; closing the connection sets the count to zero, so nothing survives the
        // queue it was for.
        // Bounded, the wait for the writer included: a host that stopped reading would otherwise
        // hold this task and the lock every request on this connection needs.
        let written = tokio::time::timeout(OFFER_WRITE_DEADLINE, async {
            // Taken out and put back, for the reason the request path takes it out: this task can
            // be stopped at the await below, and a writer left in the slot part way through a frame
            // would refuse every frame after it.
            let mut held = writer.lock().await;
            let Some(mut owned) = held.take() else {
                return Err(kr_ipc::IpcError::PeerClosed);
            };
            if pending.is_closed() {
                drop(owned);
                return Err(kr_ipc::IpcError::PeerClosed);
            }
            let written = owned.write_message(&request).await;
            if written.is_ok() && !pending.is_closed() {
                *held = Some(owned);
            }
            drop(held);
            // The same look as the request path takes, for the same order: a closure while this
            // task held the writer found the lock taken and left the writer where it was.
            if pending.is_closed()
                && let Ok(mut slot) = writer.try_lock()
            {
                let _closed = slot.take();
            }
            written
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            // A frame that failed or was never taken leaves the writer with a part-written frame,
            // and nothing after it could be delivered. The connection is over, and everything
            // waiting on it is told rather than left to time out one by one. Closing sets the
            // count to zero and refuses every request, so the count is never zero while an event
            // is unwritten on a connection that still takes requests. What is still queued is
            // released and reported by the queue emptying.
            pending.close();
            offered.close();
            while let Some(abandoned) = offered.recv().await {
                release(&held, offered_bytes_of(&abandoned));
            }
            return;
        }
        release(&held, cost);
    }
}

/// Gives back what one offered event reserved.
fn release(held: &AtomicU64, cost: u64) {
    let _released = held.fetch_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
        Some(bytes.saturating_sub(cost))
    });
}

/// Returns what one offered event costs of the handoff's allowance.
///
/// The bytes it carries, the handle that names it, and a fixed cost for the record itself: a
/// request number, a binding identifier and the envelope that carries them.
fn offered_cost(event: &crate::protocol::WireSourceEvent) -> u64 {
    OFFER_OVERHEAD_BYTES
        + event.bytes.len() as u64
        + event.handle.as_str().len() as u64
        + event.provenance.len() as u64
        + event.request_id.as_ref().map_or(0, |id| id.len() as u64)
}

/// Returns what one offered event was counted as when it was admitted.
fn offered_bytes_of(request: &Request) -> u64 {
    match &request.body {
        RequestBody::Event { event, .. } => offered_cost(event),
        _ => 0,
    }
}

/// Turns the host's refusal into the error a caller reads: a binding the host disabled is not a
/// request it refused.
fn refused(detail: String, disabled: bool) -> ServiceError {
    if disabled {
        ServiceError::Disabled { reason: detail }
    } else {
        ServiceError::Protocol { detail }
    }
}

/// Reads the answer to a revision.
fn revised(body: ResponseBody) -> ServiceResult<()> {
    match body {
        ResponseBody::Revised => Ok(()),
        ResponseBody::Refused {
            detail, disabled, ..
        } => Err(refused(detail, disabled)),
        other => Err(protocol_error(&other)),
    }
}

/// Checks that a request encodes to one frame the host reads.
///
/// # Errors
///
/// Returns a protocol error, and writes nothing, when it does not.
fn check_fits(body: &RequestBody) -> ServiceResult<()> {
    let request = Request {
        request_id: u64::MAX,
        body: body.clone(),
    };
    let fits = kr_cbor::to_canonical_vec(&request)
        .is_ok_and(|encoded| encoded.len() <= StreamKind::Control.max_payload_len());
    if fits {
        Ok(())
    } else {
        Err(ServiceError::Protocol {
            detail: format!(
                "the {} request is larger than one frame carries",
                body.name()
            ),
        })
    }
}

fn millis(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unavailable(error: LaunchError) -> ServiceError {
    ServiceError::Unavailable {
        detail: error.to_string(),
    }
}

fn protocol_error(body: &ResponseBody) -> ServiceError {
    ServiceError::Protocol {
        detail: format!("an answer of the wrong kind: {body:?}"),
    }
}

/// Returns the binding identifier a notice concerns.
#[must_use]
pub fn notice_binding(notice: &Notice) -> BindingId {
    BindingId::new(notice.binding_id())
}

/// Returns a fresh binding identifier.
#[must_use]
pub fn new_binding_id() -> BindingId {
    BindingId::new(Uuid::from_bytes(*uuid_bytes()))
}

fn uuid_bytes() -> Box<[u8; 16]> {
    let generated = kr_ipc::new_uuid();
    Box::new(*generated.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_is_carried_in_whole_milliseconds() {
        assert_eq!(millis(core::time::Duration::from_millis(250)), 250);
        assert_eq!(millis(DEFAULT_DEADLINE), 5_000);
    }

    #[test]
    fn a_call_that_declared_a_fault_did_not_answer() {
        let answered = Called {
            state: None,
            plan: None,
            decoded: None,
            encoded: None,
            fault: None,
            document: Some(1),
        };
        assert!(answered.answered());
        let refused = Called {
            state: None,
            plan: None,
            decoded: None,
            encoded: None,
            fault: Some("refused: not mine".to_owned()),
            document: None,
        };
        assert!(!refused.answered());
    }

    #[test]
    fn two_binding_identifiers_are_distinct() {
        assert_ne!(new_binding_id(), new_binding_id());
    }

    #[test]
    fn a_notice_names_the_binding_it_belongs_to() {
        let binding_id = new_binding_id();
        let notice = Notice::Disabled {
            binding_id: binding_id.get(),
            reason: "three faults".to_owned(),
        };
        assert_eq!(notice_binding(&notice), binding_id);
    }
}
