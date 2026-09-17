//! What a worker uses to reach the plugin host.
//!
//! A worker finds the host through the published descriptor, challenges the process behind the
//! endpoint, and then registers bindings, delivers events and makes calls. It never links the
//! engine and never runs a component.
//!
//! # Delivering an event never waits on a component
//!
//! [`PluginClient::deliver`] writes one frame and reads its acknowledgement. The acknowledgement is
//! the queue's answer, not a component's: the host pushes onto the bounded queue and replies
//! without entering an instance. A component in the middle of an unbounded loop does not delay it,
//! which is what keeps PTY draining independent of an observation callback.
//!
//! # What a plugin-host crash costs this worker
//!
//! Its rich bindings, and nothing else. The connection fails, the calls in flight return
//! [`crate::RuntimeError::ServiceUnavailable`], and the worker's own ledger is untouched because
//! it was never in the other process. Re-registering the bindings is the whole of the recovery.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::{Endpoint, EnvironmentPaths};
use kr_protocol::frame::StreamKind;
use kr_protocol::scalars::Uuid;
use tokio::sync::{Mutex, oneshot};

use kr_plugin_sdk::identity::PluginIdentity;

use crate::runtime::binding::BindingId;
use crate::runtime::error::{RuntimeError, RuntimeResult};
use crate::runtime::host::{BindingFacts, ScopedSourceEvent};
use crate::runtime::queue::Admission;
use crate::service::host::{wire_event, wire_facts};
use crate::service::launcher::{self, LaunchError};
use crate::service::protocol::{
    BindingRegistration, CallValue, ComponentSource, Frame, HostDescriptor, HostHealth, Notice,
    Request, RequestBody, ResponseBody, WireNode,
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

/// One request's answer, on its way back to whoever asked.
type Answer = oneshot::Sender<ResponseBody>;

/// The requests this client is waiting on, by the number their answers will carry.
type Waiting = Arc<Mutex<Vec<(u64, Answer)>>>;

/// A worker's connection to the plugin host.
pub struct PluginClient {
    writer: Mutex<FrameWriter>,
    waiting: Waiting,
    notices: tokio::sync::mpsc::UnboundedReceiver<Notice>,
    next_request: AtomicU64,
    descriptor: HostDescriptor,
    reader_task: tokio::task::JoinHandle<()>,
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
        let waiting: Waiting = Arc::new(Mutex::new(Vec::new()));
        let (notices, received) = tokio::sync::mpsc::unbounded_channel();
        let reader_task = tokio::spawn(read_frames(reader, Arc::clone(&waiting), notices));

        let client = Self {
            writer: Mutex::new(writer),
            waiting,
            notices: received,
            next_request: AtomicU64::new(1),
            descriptor,
            reader_task,
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

    /// Offers one source event to a binding's observation queue.
    ///
    /// Nothing runs a component here. The answer is the queue's, and it comes back whatever the
    /// component is doing.
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
        self.call(RequestBody::Snapshot {
            binding_id: binding_id.get(),
            deadline_ms: millis(deadline),
        })
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
        self.call(RequestBody::Checkpoint {
            binding_id: binding_id.get(),
            deadline_ms: millis(deadline),
        })
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
        self.call(RequestBody::Restore {
            binding_id: binding_id.get(),
            state,
            deadline_ms: millis(deadline),
        })
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
        self.notices.try_recv().ok()
    }

    /// Waits for the next notice a binding produced.
    pub async fn notice(&mut self) -> Option<Notice> {
        self.notices.recv().await
    }

    async fn call(&self, body: RequestBody) -> RuntimeResult<Called> {
        let answered = self.request(body).await?;
        match answered {
            ResponseBody::Called {
                value,
                fault,
                nodes,
            } => Ok(Called {
                state: match value {
                    Some(CallValue::State(state)) => Some(state),
                    Some(CallValue::Document) | None => None,
                },
                fault,
                nodes,
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

    async fn request_within(
        &self,
        body: RequestBody,
        deadline: core::time::Duration,
    ) -> RuntimeResult<ResponseBody> {
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (answer, reply) = oneshot::channel();
        self.waiting.lock().await.push((request_id, answer));
        {
            let mut writer = self.writer.lock().await;
            writer
                .write_message(&Request { request_id, body })
                .await
                .map_err(|error| RuntimeError::ServiceUnavailable {
                    detail: error.to_string(),
                })?;
        }
        match tokio::time::timeout(deadline, reply).await {
            Ok(Ok(body)) => Ok(body),
            // The reader task dropped the sender, which means the connection is gone.
            Ok(Err(_)) => Err(RuntimeError::ServiceUnavailable {
                detail: "the plugin host closed the connection".to_owned(),
            }),
            Err(_elapsed) => {
                self.waiting
                    .lock()
                    .await
                    .retain(|(waiting, _answer)| *waiting != request_id);
                Err(RuntimeError::CallerDeadline {
                    deadline_ms: millis(deadline),
                })
            }
        }
    }
}

impl Drop for PluginClient {
    fn drop(&mut self) {
        self.reader_task.abort();
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Called {
    /// A component's own resumable state, where the call returns one.
    pub state: Option<Vec<u8>>,
    /// The fault the component declared, where it declared one.
    pub fault: Option<String>,
    /// The nodes it emitted while answering.
    pub nodes: Vec<WireNode>,
}

impl Called {
    /// Returns true when the component answered rather than declared a fault.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.fault.is_none()
    }
}

async fn read_frames(
    mut reader: FrameReader,
    waiting: Waiting,
    notices: tokio::sync::mpsc::UnboundedSender<Notice>,
) {
    loop {
        let frame: Frame = match reader.read_message().await {
            Ok(frame) => frame,
            // The connection is gone, or the host sent something this protocol does not admit.
            // Either way the waiting callers are told by their senders being dropped here.
            Err(_error) => return,
        };
        match frame {
            Frame::Response { reply_to, body } => {
                let mut held = waiting.lock().await;
                if let Some(position) = held
                    .iter()
                    .position(|(request_id, _answer)| *request_id == reply_to)
                {
                    let (_request_id, answer) = held.remove(position);
                    drop(held);
                    let _ = answer.send(body);
                }
            }
            Frame::Notice(notice) => {
                if notices.send(notice).is_err() {
                    return;
                }
            }
        }
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
            nodes: Vec::new(),
        };
        assert!(answered.answered());
        let refused = Called {
            state: None,
            fault: Some("refused: not mine".to_owned()),
            nodes: Vec::new(),
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
