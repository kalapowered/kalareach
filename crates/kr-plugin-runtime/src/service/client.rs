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
//! [`crate::RuntimeError::ServiceUnavailable`], and the worker's own ledger is untouched because
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

use crate::runtime::binding::BindingId;
use crate::runtime::error::{RuntimeError, RuntimeResult};
use crate::runtime::host::{BindingFacts, ScopedSourceEvent};
use crate::runtime::queue::Admission;
use crate::service::host::{wire_event, wire_facts};
use crate::service::launcher::{self, LaunchError};
use crate::service::notices::{self, MAX_NOTICE_BYTES, NoticeSink, NoticeStream, Offered};
use crate::service::protocol::{
    BindingRegistration, CallValue, ComponentSource, Frame, HostDescriptor, HostHealth, Notice,
    Request, RequestBody, ResponseBody,
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
    core::time::Duration::from_millis(crate::runtime::compile::COMPILE_DEADLINE_MS + 5_000);

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
pub const MAX_OFFERED_EVENT_BYTES: u64 = crate::runtime::host::MAX_NODE_BYTES;

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

/// The requests this client is waiting on, and whether its connection still exists.
#[derive(Debug, Default)]
struct Pending {
    waiting: Mutex<HashMap<u64, Answer>>,
    closed: AtomicBool,
}

impl Pending {
    /// Records that a request is waiting for its number, unless the connection has already gone.
    ///
    /// The check and the insertion are one step under the lock. Two steps would let a request be
    /// admitted between a reader deciding the connection was over and its clearing the waiting
    /// set, and that request would then wait for an answer nobody could send.
    fn wait_for(&self, request_id: u64, answer: Answer) -> bool {
        let Ok(mut waiting) = self.waiting.lock() else {
            return false;
        };
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        waiting.insert(request_id, answer);
        true
    }

    /// Takes one request's sender, if it is still waiting.
    fn take(&self, request_id: u64) -> Option<Answer> {
        self.waiting
            .lock()
            .ok()
            .and_then(|mut waiting| waiting.remove(&request_id))
    }

    /// Drops every waiting sender and records that the connection is gone.
    ///
    /// Dropping a sender is what tells its caller the host closed the connection, at once, rather
    /// than each caller waiting out its own deadline for an answer that cannot arrive.
    fn close(&self) {
        // The flag is set under the lock an admission takes, so an admission either happens before
        // the connection ended or is refused by it; there is no order in which it happens after.
        if let Ok(mut waiting) = self.waiting.lock() {
            self.closed.store(true, Ordering::Release);
            waiting.clear();
        } else {
            self.closed.store(true, Ordering::Release);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// One request's place in the waiting set, removed however the caller leaves.
///
/// A timeout, a write failure and a cancelled future all end the same way: the entry goes. Without
/// this, a caller that gave up would leave its sender behind and the set would grow with every call
/// that did not arrive.
struct Waiting<'a> {
    pending: &'a Pending,
    request_id: u64,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let _taken = self.pending.take(self.request_id);
    }
}

/// One frame on its way to the host, and what happens if it does not get there.
///
/// A [`FrameWriter`] that is part way through a frame refuses every later one, and nothing on this
/// side can resume a frame whose sender has gone. So a write that did not finish, for whatever
/// reason, is the end of the connection rather than the end of one call.
struct Attempting<'a> {
    pending: &'a Pending,
    finished: bool,
}

impl Attempting<'_> {
    fn finished(mut self, wrote: bool) {
        self.finished = wrote;
    }
}

impl Drop for Attempting<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.pending.close();
        }
    }
}

/// A worker's connection to the plugin host.
pub struct PluginClient {
    writer: Arc<tokio::sync::Mutex<FrameWriter>>,
    pending: Arc<Pending>,
    notices: NoticeStream,
    offered: tokio::sync::mpsc::Sender<Request>,
    offered_bytes: Arc<AtomicU64>,
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
    /// Connects to the plugin host named in the environment's descriptor, and verifies it.
    ///
    /// The descriptor is a hint. What settles which process is answering is the challenge below:
    /// the host signs a fresh nonce with the key the descriptor records, and a process that cannot
    /// is not the one the launcher started.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ServiceUnavailable`] when there is no descriptor or the endpoint
    /// cannot be reached, and [`RuntimeError::ServiceProtocol`] when the host answers with
    /// something this client cannot read or cannot verify.
    pub async fn connect(environment: &EnvironmentPaths) -> RuntimeResult<Self> {
        let descriptor = launcher::read_descriptor(environment)
            .map_err(unavailable)?
            .ok_or_else(|| RuntimeError::ServiceUnavailable {
                detail: "this environment has no plugin host".to_owned(),
            })?;
        let endpoint = Endpoint::from_path(&descriptor.endpoint).map_err(|error| {
            RuntimeError::ServiceUnavailable {
                detail: error.to_string(),
            }
        })?;
        let connection = Connection::connect(&endpoint).await.map_err(|error| {
            RuntimeError::ServiceUnavailable {
                detail: error.to_string(),
            }
        })?;
        Self::over(connection, descriptor).await
    }

    /// Opens a client over an existing connection and verifies the host.
    ///
    /// # Errors
    ///
    /// Returns the handshake or verification failure.
    pub async fn over(connection: Connection, descriptor: HostDescriptor) -> RuntimeResult<Self> {
        let (reader, writer) = split(connection, StreamKind::Control);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let pending = Arc::new(Pending::default());
        let (sink, notices) = notices::channel();
        let reader_task = tokio::spawn(read_frames(reader, Arc::clone(&pending), sink));

        // The handoff the terminal path uses: bounded, written by a task of its own, never waited
        // on by whoever offered the event.
        let (offered, waiting_events) = tokio::sync::mpsc::channel::<Request>(MAX_OFFERED_EVENTS);
        let offered_bytes = Arc::new(AtomicU64::new(0));
        let offer_task = tokio::spawn(write_offered(
            waiting_events,
            Arc::clone(&writer),
            Arc::clone(&offered_bytes),
            Arc::clone(&pending),
        ));

        let client = Self {
            writer,
            pending,
            notices,
            offered,
            offered_bytes,
            next_request: AtomicU64::new(1),
            descriptor,
            reader_task,
            offer_task,
        };

        let hello = client
            .request(RequestBody::Hello {
                protocol: crate::service::protocol::PROTOCOL.to_owned(),
            })
            .await?;
        let ResponseBody::Hello { protocol, .. } = hello else {
            return Err(protocol_error(&hello));
        };
        if protocol != crate::service::protocol::PROTOCOL {
            return Err(RuntimeError::ServiceProtocol {
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
            RuntimeError::ServiceProtocol {
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
    /// contract, or [`RuntimeError::ServiceUnavailable`] when the host is gone.
    pub async fn register(
        &self,
        binding_id: BindingId,
        identity: &PluginIdentity,
        facts: &BindingFacts,
        executable: &str,
        component: &ComponentSource,
    ) -> RuntimeResult<Registration> {
        let body = self
            .request_within(
                RequestBody::RegisterBinding(Box::new(BindingRegistration {
                    binding_id: binding_id.get(),
                    identity: identity.clone(),
                    facts: wire_facts(facts),
                    executable: executable.to_owned(),
                    component: component.clone(),
                })),
                REGISTER_DEADLINE,
            )
            .await?;
        match body {
            ResponseBody::Registered { origin, elapsed_ms } => Ok(Registration {
                cached: origin == "cached",
                elapsed_ms,
            }),
            ResponseBody::Refused { detail, .. } => Err(RuntimeError::ServiceProtocol { detail }),
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
        // reservation when it consumes the event: a charge made afterwards could be made after its
        // own release, and the allowance would drift until it admitted nothing.
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
            Ok(()) => Handoff::Accepted,
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

    /// Returns how many bytes of offered events are waiting to be written.
    #[must_use]
    pub fn offered_bytes(&self) -> u64 {
        self.offered_bytes.load(Ordering::Acquire)
    }

    /// Offers one source event and waits for the queue's answer.
    ///
    /// Nothing runs a component here either: the host answers an observation on the task that read
    /// it. This form exists for a caller that wants to know what the queue did with the event.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`RuntimeError::ServiceUnavailable`].
    pub async fn deliver(
        &self,
        binding_id: BindingId,
        event: &ScopedSourceEvent,
    ) -> RuntimeResult<Admission> {
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
                other => Err(RuntimeError::ServiceProtocol {
                    detail: format!("{other} is not an admission this client knows"),
                }),
            },
            ResponseBody::Refused { detail, .. } => Err(RuntimeError::ServiceProtocol { detail }),
            other => Err(protocol_error(&other)),
        }
    }

    /// Asks a binding for a fresh document.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal or [`RuntimeError::ServiceUnavailable`].
    pub async fn snapshot(
        &self,
        binding_id: BindingId,
        deadline: core::time::Duration,
    ) -> RuntimeResult<Called> {
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
    /// Returns the host's refusal or [`RuntimeError::ServiceUnavailable`].
    pub async fn checkpoint(
        &self,
        binding_id: BindingId,
        deadline: core::time::Duration,
    ) -> RuntimeResult<Called> {
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
    /// Returns the host's refusal or [`RuntimeError::ServiceUnavailable`].
    pub async fn restore(
        &self,
        binding_id: BindingId,
        state: Vec<u8>,
        deadline: core::time::Duration,
    ) -> RuntimeResult<Called> {
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
    /// # Errors
    ///
    /// Returns [`RuntimeError::ServiceUnavailable`] when the host is gone.
    pub async fn unbind(&self, binding_id: BindingId) -> RuntimeResult<bool> {
        let body = self
            .request(RequestBody::Unbind {
                binding_id: binding_id.get(),
            })
            .await?;
        match body {
            ResponseBody::Unbound { existed } => Ok(existed),
            other => Err(protocol_error(&other)),
        }
    }

    /// Asks what the host is doing.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ServiceUnavailable`] when the host is gone.
    pub async fn health(&self) -> RuntimeResult<HostHealth> {
        let body = self.request(RequestBody::Health).await?;
        match body {
            ResponseBody::Health(health) => Ok(*health),
            other => Err(protocol_error(&other)),
        }
    }

    /// Takes the next notice a binding produced, if one is waiting.
    pub fn try_notice(&mut self) -> Option<Notice> {
        self.notices.try_recv()
    }

    /// Waits for the next notice a binding produced.
    pub async fn notice(&mut self) -> Option<Notice> {
        self.notices.recv().await
    }

    async fn call(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
    ) -> RuntimeResult<Called> {
        // The component's own deadline plus the round trip, rather than a fixed figure: a caller
        // that allowed ten milliseconds for a component did not mean to wait five seconds for the
        // answer when the host stops answering.
        let answered = self
            .request_within(body, deadline.saturating_add(ROUND_TRIP_ALLOWANCE))
            .await?;
        match answered {
            ResponseBody::Called { value, fault } => Ok(Called {
                state: match value {
                    Some(CallValue::State(state)) => Some(state),
                    Some(CallValue::Document) | None => None,
                },
                fault,
            }),
            ResponseBody::Refused {
                detail, disabled, ..
            } => {
                if disabled {
                    Err(RuntimeError::Disabled { reason: detail })
                } else {
                    Err(RuntimeError::ServiceProtocol { detail })
                }
            }
            other => Err(protocol_error(&other)),
        }
    }

    async fn request(&self, body: RequestBody) -> RuntimeResult<ResponseBody> {
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
    /// Returns [`RuntimeError::ServiceUnavailable`] when the connection is gone,
    /// [`RuntimeError::CallerDeadline`] when the deadline passes first.
    async fn request_within(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
    ) -> RuntimeResult<ResponseBody> {
        if self.pending.is_closed() {
            return Err(RuntimeError::ServiceUnavailable {
                detail: "the plugin host closed the connection".to_owned(),
            });
        }
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (answer, reply) = oneshot::channel();
        if !self.pending.wait_for(request_id, answer) {
            return Err(RuntimeError::ServiceUnavailable {
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
                let mut writer = self.writer.lock().await;
                // Armed once the writer is held, and not before: a caller whose deadline ran out
                // while it was queueing for the writer has written nothing, and ending the
                // connection over that would be a failure it did not cause. From here on, a frame
                // that is half written and then abandoned -- by a failure, by a deadline, or by a
                // caller that stopped polling -- leaves the writer unable to start another one, and
                // there is no way back from that on this connection.
                let attempt = Attempting {
                    pending: &self.pending,
                    finished: false,
                };
                let written = writer.write_message(&Request { request_id, body }).await;
                attempt.finished(written.is_ok());
                written.map_err(|error| RuntimeError::ServiceUnavailable {
                    detail: error.to_string(),
                })?;
            }
            match reply.await {
                Ok(body) => Ok(body),
                // The reader dropped the sender, which means the connection is gone.
                Err(_closed) => Err(RuntimeError::ServiceUnavailable {
                    detail: "the plugin host closed the connection".to_owned(),
                }),
            }
        };
        match tokio::time::timeout(deadline, exchange).await {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err(RuntimeError::CallerDeadline {
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
    /// The fault the component declared, where it declared one.
    pub fault: Option<String>,
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
        let frame: Frame = match reader.read_message().await {
            Ok(frame) => frame,
            // The connection is gone, or the host sent something this protocol does not admit.
            // Either way every caller waiting on it is told now: an answer that cannot arrive is
            // not something to make each of them wait out its own deadline for.
            Err(_error) => break,
        };
        match frame {
            Frame::Response { reply_to, body } => {
                if let Some(answer) = pending.take(reply_to) {
                    let _delivered = answer.send(body);
                }
            }
            Frame::Notice(notice) => {
                // A queue that cannot hold what must arrive is a connection this worker cannot
                // trust to tell it when a binding stops working, so it ends here rather than
                // carrying on with a partial account.
                match notices.send(notice) {
                    Offered::Kept | Offered::Dropped => {}
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
    writer: Arc<tokio::sync::Mutex<FrameWriter>>,
    held: Arc<AtomicU64>,
    pending: Arc<Pending>,
) {
    while let Some(request) = offered.recv().await {
        let cost = offered_bytes_of(&request);
        // Bounded, the wait for the writer included: a host that stopped reading would otherwise
        // hold this task and the lock every request on this connection needs.
        let written = tokio::time::timeout(OFFER_WRITE_DEADLINE, async {
            let mut writer = writer.lock().await;
            writer.write_message(&request).await
        })
        .await;
        release(&held, cost);
        if !matches!(written, Ok(Ok(()))) {
            // A frame that failed or was never taken leaves the writer with a part-written frame,
            // and nothing after it could be delivered. The connection is over, and everything
            // waiting on it is told rather than left to time out one by one. What is still queued
            // is released and reported by the queue emptying.
            pending.close();
            offered.close();
            while let Some(abandoned) = offered.recv().await {
                release(&held, offered_bytes_of(&abandoned));
            }
            return;
        }
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
fn offered_cost(event: &crate::service::protocol::WireSourceEvent) -> u64 {
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

fn millis(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unavailable(error: LaunchError) -> RuntimeError {
    RuntimeError::ServiceUnavailable {
        detail: error.to_string(),
    }
}

fn protocol_error(body: &ResponseBody) -> RuntimeError {
    RuntimeError::ServiceProtocol {
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
    fn a_registration_is_given_longer_than_the_host_gives_itself() {
        // A client that gave up first would report its own patience as the host's failure.
        assert!(REGISTER_DEADLINE > crate::service::host::REGISTER_DEADLINE);
    }

    #[test]
    fn a_call_that_declared_a_fault_did_not_answer() {
        let answered = Called {
            state: None,
            fault: None,
        };
        assert!(answered.answered());
        let refused = Called {
            state: None,
            fault: Some("refused: not mine".to_owned()),
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
