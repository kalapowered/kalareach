//! Keystrokes that go ahead of a request on their connection that cannot change what they meet.
//!
//! A connection's loop reads one frame, runs it, answers it and only then reads the next. A request
//! that waits, for the commits of a mutation or for the session another connection's mutation
//! holds, therefore stops the connection from reading a key sent behind it, and the key waits as
//! long as the request does. A client sends its keys and its viewport reports and resizes on one
//! connection, so the wait is the client's own.
//!
//! While such a request runs, `Overtaking` is a task that reads the connection ahead and serves
//! the keys it finds at once, from the connection's facts and the input domain, which is all the
//! loop would use for them. What it reads and does not serve is handed back to the loop in the
//! order it was sent, to be acted on exactly as if the loop had read it.
//!
//! # What a key goes ahead of
//!
//! `kr_protocol::ordering` says which requests a key goes ahead of and keeps the order of what is
//! read ahead; this module maps the frames of a connection to it. A key is an `input.write` sent as
//! a request, or forwarded by the control daemon for a paired device on its proxy link. It goes
//! ahead of a read, and of a mutation that leaves alone everything a key meets (the geometry and
//! the viewport). Every other frame keeps its place: a key sent after a detach is refused because
//! the detach comes first, and a frame that is new to the protocol blocks keys until someone has
//! decided it does not.
//!
//! The answer to a key can come before the answer to a request it went ahead of. A response names
//! the request it answers, and the clients match on that.
//!
//! # Limits
//!
//! The task reads no more from the connection once it holds [`ordering::MOST_HELD`] frames that it
//! cannot serve, and a key it has not read by then waits for the request, as it did before. Frames
//! the loop had already read ahead of a finished preparation are not held to that limit.
//! The task ends when the request does, and the loop writes the request's answer after that, so a
//! key that arrives while a large answer is being written to a slow peer waits for the write, up to
//! the bound on a write. While a client keeps the connection's loop supplied with frames the task
//! handed back, the loop does not look at its withdrawal, window renewal, keepalive or
//! finished-preparation branches; that ends with the burst and touches no other connection.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use kr_ipc::framed::{FrameReader, FrameWriter};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::ordering::{self, Judgement, Kind, Sorting};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{ConnectionFacts, Withdrawal, WorkerService, Writing, write_frame};

/// Whether the keys of a connection are served beside a request that waits: a local client's, and
/// the control daemon's proxy link, which carries a paired device's. The daemon's other links carry
/// its own housekeeping and no keys.
pub(super) fn takes_keys_beside_a_request(facts: &ConnectionFacts) -> bool {
    facts.negotiated
        && (!facts.controller || facts.controller_role == ControllerConnectionRole::Proxy)
}

/// Returns what `frame` is to the order a key keeps.
pub(super) fn kind_of(frame: &ControlFrame) -> Kind {
    match frame {
        ControlFrame::Request(request) => ordering::request_kind(request.method.method()),
        ControlFrame::ForwardedRead(forwarded) => {
            ordering::request_kind(forwarded.request.method.method())
        }
        ControlFrame::Mutation(mutation) => ordering::mutation_kind(mutation.method.method()),
        ControlFrame::Forwarded(forwarded) => {
            ordering::mutation_kind(forwarded.mutation.method.method())
        }
        _ => Kind::Blocking,
    }
}

/// How the task writes an answer to the peer.
pub(super) struct Link {
    pub(super) writable: Writing,
    pub(super) writer: Arc<Mutex<FrameWriter>>,
    pub(super) withdrawn: Arc<Withdrawal>,
}

/// What the task is given to read.
pub(super) struct Reading {
    /// The connection's reader, which the loop gets back when the task ends.
    pub(super) reader: FrameReader,
    /// Frames the loop had read already and has not acted on, which come before anything the
    /// reader has.
    pub(super) pending: VecDeque<Option<ControlFrame>>,
    /// Whether the reader may be read. It may not while a finished preparation waits for the frames
    /// before it: the reader's frames come after the action.
    pub(super) socket: bool,
}

/// What the task hands back.
pub(super) struct Closed {
    pub(super) reader: FrameReader,
    /// The frames not served, in the order they were sent: those judged and held, then those
    /// `pending` still had when the task ended.
    pub(super) deferred: VecDeque<Option<ControlFrame>>,
    /// An answer could not be written whole, so the stream cannot be written to again.
    pub(super) broken: bool,
}

/// A task serving the keys of a connection while its loop runs a request.
pub(super) struct Overtaking {
    stop: oneshot::Sender<()>,
    task: JoinHandle<Closed>,
}

impl Overtaking {
    /// Starts serving.
    pub(super) fn open(
        service: Arc<WorkerService>,
        facts: ConnectionFacts,
        link: Link,
        reading: Reading,
    ) -> Self {
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(run(service, facts, link, reading, stopped));
        Self { stop, task }
    }

    /// Ends the task once the frame it is serving beside has been handled, and takes back what it
    /// read. An error means the task panicked and the connection's reader is lost with it.
    pub(super) async fn close(self) -> std::result::Result<Closed, tokio::task::JoinError> {
        // The task also stops when this is dropped, so a send that finds it gone has nothing to do.
        let _ = self.stop.send(());
        self.task.await
    }
}

async fn run(
    service: Arc<WorkerService>,
    facts: ConnectionFacts,
    link: Link,
    reading: Reading,
    mut stop: oneshot::Receiver<()>,
) -> Closed {
    let Reading {
        mut reader,
        mut pending,
        socket,
    } = reading;
    let mut sorting = Sorting::default();
    let mut deferred = VecDeque::new();
    let mut broken = false;
    loop {
        // Once per frame, so the loop gets its reader back as soon as its request is done.
        if !matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
            break;
        }
        let frame = if let Some(next) = pending.pop_front() {
            next
        } else if socket && sorting.may_read() {
            tokio::select! {
                biased;
                _ = &mut stop => break,
                read = reader.read_message::<ControlFrame>() => read.ok(),
            }
        } else {
            // Nothing more can be judged, so the task waits to be told the request has ended.
            let _ = (&mut stop).await;
            break;
        };
        match (sorting.judge(frame.as_ref().map(kind_of)), frame) {
            (Judgement::Serve, Some(key)) => {
                if !serve(&service, &facts, &link, &key).await {
                    broken = true;
                    break;
                }
            }
            (_, frame) => deferred.push_back(frame),
        }
    }
    // The one way out: what was held, then what was never looked at.
    deferred.extend(pending);
    Closed {
        reader,
        deferred,
        broken,
    }
}

/// Serves one key and writes its answer, and says whether the connection can go on: it cannot when
/// the answer was not written, whether the stream was cut part way or nothing of it was written (a
/// withdrawal, an answer that could not be encoded, the local owner's lease refusing it). The loop
/// ends the connection in each case, as it does when an answer of its own is not written.
async fn serve(
    service: &WorkerService,
    facts: &ConnectionFacts,
    link: &Link,
    key: &ControlFrame,
) -> bool {
    // Taken before the answer is produced, as the loop takes it before it handles a frame: an
    // answer produced while the connection held its registration carries what that gave it, and a
    // withdrawal that lands before it reaches the peer must stop it.
    let protected = !link.withdrawn.is_set();
    // Only a request is recorded as waiting for the local owner's lease and counted off after its
    // answer, as the loop does: a forwarded read is neither.
    let (served, counted) = match key {
        ControlFrame::Request(request) => {
            #[cfg(feature = "testing")]
            service.record_received(&request.method, &request.params);
            (
                service.keystroke_of_a_request(facts, request),
                Some(request.request_id),
            )
        }
        ControlFrame::ForwardedRead(forwarded) => (
            service.keystroke_of_a_forwarded_read(facts, forwarded),
            None,
        ),
        _ => unreachable!("only a key is served ahead of a request"),
    };
    let written = tokio::time::timeout(
        crate::runtime::ACCEPTANCE_WRITE_TIMEOUT,
        write_frame(
            &link.writable,
            &link.writer,
            &served.reply,
            &link.withdrawn,
            protected,
        ),
    )
    .await
    .unwrap_or_default();
    // Counted off whatever came of the write, as the loop does.
    if let (Some(request_id), Some(local)) = (counted, link.writable.local.as_ref()) {
        local.answered(request_id, served.held);
    }
    written
}

#[cfg(test)]
mod tests {
    use kr_protocol::actor::{ActorEnvelope, ActorIngress};
    use kr_protocol::envelope::{MutationRequest, ParamsValue, Request};
    use kr_protocol::ids::{ActionId, ActorId, ConnectionId, ControllerGeneration, RequestId};
    use kr_protocol::local::{ForwardedMutation, ForwardedRequest};
    use kr_protocol::method::{Method, MethodVersion};
    use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64, Uuid};

    use super::*;

    fn request(method: Method) -> ControlFrame {
        ControlFrame::Request(Request {
            request_id: RequestId::new(1),
            method: method.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        })
    }

    fn mutation_of(method: Method) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(1),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(Uuid::from_bytes([1; 16])),
            grant_id: Nullable::null(),
            target: kr_protocol::envelope::ActionTarget {
                environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: kr_protocol::ids::ActionWindowId::new("window").expect("an id"),
            requested_ttl_ms: DurationMs::new(1),
            params: ParamsValue::empty(),
        }
    }

    fn actor() -> ActorEnvelope {
        ActorEnvelope {
            actor_id: ActorId::new("device:phone").expect("an actor"),
            ingress: ActorIngress::PairedDevice,
            device_id: Nullable::some(kr_protocol::ids::DeviceId::new(Uuid::from_bytes([3; 16]))),
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
        }
    }

    fn forwarded_read(method: Method) -> ControlFrame {
        ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
            request: Request {
                request_id: RequestId::new(1),
                method: method.into(),
                method_version: MethodVersion::V1,
                params: ParamsValue::empty(),
            },
            actor: actor(),
            authority_deadline_boot_ms: Nullable::null(),
            history: None,
        }))
    }

    fn forwarded(method: Method) -> ControlFrame {
        ControlFrame::Forwarded(Box::new(ForwardedMutation {
            mutation: mutation_of(method),
            actor: actor(),
            grant_rights: CanonicalSet::new(),
            accepted_deadline_boot_ms: U64::new(1),
            history: None,
            screen_basis: None,
        }))
    }

    /// KR-PERF-002: a worker maps a frame to the order a key keeps by the method it carries, the
    /// control daemon's forwarded frames among them, and every frame that is not a request keeps
    /// its place.
    #[test]
    fn a_frame_is_mapped_by_the_method_it_carries_and_a_frame_that_is_not_a_request_blocks_keys() {
        assert_eq!(kind_of(&request(Method::InputWrite)), Kind::Key);
        assert_eq!(kind_of(&request(Method::SessionRead)), Kind::Independent);
        assert_eq!(kind_of(&forwarded_read(Method::InputWrite)), Kind::Key);
        assert_eq!(
            kind_of(&forwarded_read(Method::SessionOpen)),
            Kind::Blocking
        );
        assert_eq!(
            kind_of(&forwarded(Method::AttachmentViewport)),
            Kind::Independent
        );
        assert_eq!(kind_of(&forwarded(Method::SessionDetach)), Kind::Blocking);
        assert_eq!(
            kind_of(&ControlFrame::Mutation(Box::new(mutation_of(
                Method::TerminalResize
            )))),
            Kind::Independent
        );
        assert_eq!(
            kind_of(&ControlFrame::Event(
                kr_protocol::envelope::ControlEvent::Keepalive
            )),
            Kind::Blocking
        );
    }
}
