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
//! A key never goes ahead of an earlier key. It goes ahead of a read, and of a mutation that
//! leaves alone everything a key meets: the lease, the capabilities, the fence, the paste framing,
//! which attachments exist and the session's state. The geometry and the viewport are such. Every
//! other frame, a mutation not named here and every frame that is not a request, keeps its place:
//! a key sent after a detach is refused because the detach comes first, and a frame that is new to
//! the protocol blocks keys until someone has decided it does not.
//!
//! The answer to a key can come before the answer to a request it went ahead of. A response names
//! the request it answers, and the clients match on that.
//!
//! # Limits
//!
//! The task reads ahead of at most [`MOST_HELD`] frames that it cannot serve; a key behind more
//! than that waits for the request, as it did before. The task ends when the request does, and the
//! loop writes the request's answer after that, so a key that arrives while a large answer is being
//! written to a slow peer waits for the write, up to the bound on a write. While a client keeps the
//! connection's loop supplied with frames the task handed back, the loop does not look at its
//! withdrawal, window renewal, keepalive or finished-preparation branches; that ends with the burst
//! and touches no other connection.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use kr_ipc::framed::{FrameReader, FrameWriter};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::method::Method;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{ConnectionFacts, Withdrawal, WorkerService, Writing, write_frame};

/// How many frames the task holds that it cannot serve before it reads no more.
pub(super) const MOST_HELD: usize = 16;

/// What a frame is to the order a key keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// An `input.write` sent as a request.
    Key,
    /// A frame a key goes ahead of: a read, and a mutation that leaves keys alone.
    Independent,
    /// Any other frame. A key does not go ahead of it.
    Blocking,
}

/// Returns what `frame` is to the order a key keeps.
pub(super) fn kind_of(frame: &ControlFrame) -> Kind {
    match frame {
        ControlFrame::Request(request) => match request.method.method() {
            Some(Method::InputWrite) => Kind::Key,
            _ => Kind::Independent,
        },
        ControlFrame::Mutation(mutation) => match mutation.method.method() {
            Some(method) if leaves_keys_alone(method) => Kind::Independent,
            _ => Kind::Blocking,
        },
        _ => Kind::Blocking,
    }
}

/// Whether a mutation of `method` changes nothing a key meets.
///
/// The geometry owner's size, who owns the size, whether an attachment claims it and where an
/// attachment's window is: none moves the lease, an attachment's capabilities, the fence, the
/// paste framing, which attachments exist or the session's state. A method that is not named is
/// taken to be able to.
const fn leaves_keys_alone(method: Method) -> bool {
    matches!(
        method,
        Method::TerminalResize
            | Method::TerminalGeometryTransfer
            | Method::AttachmentConfigure
            | Method::AttachmentViewport
    )
}

/// What becomes of a frame the task has read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Judgement {
    /// Serve it now.
    Serve,
    /// Hand it back to the loop, in its place.
    Defer,
}

/// The order the task keeps, as a function of the frames in the order they were sent.
#[derive(Debug, Default)]
pub(super) struct Sorting {
    /// A frame that keys do not go ahead of has been held, so no key goes ahead now.
    blocked: bool,
    /// How many frames that cannot be served are held.
    held: usize,
}

impl Sorting {
    /// Decides what becomes of the next frame. `None` stands for a frame that could not be read
    /// or for the end of the stream.
    pub(super) fn judge(&mut self, frame: Option<&ControlFrame>) -> Judgement {
        let Some(frame) = frame else {
            self.blocked = true;
            return Judgement::Defer;
        };
        match kind_of(frame) {
            Kind::Key if !self.blocked => Judgement::Serve,
            // A key is never served before an earlier key, so one held holds every key after it.
            Kind::Key => Judgement::Defer,
            Kind::Independent => {
                self.held += 1;
                Judgement::Defer
            }
            Kind::Blocking => {
                self.blocked = true;
                Judgement::Defer
            }
        }
    }

    /// Whether the connection may be read for another frame: a key could still be served, and the
    /// frames held are few enough.
    pub(super) const fn may_read(&self) -> bool {
        !self.blocked && self.held < MOST_HELD
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
        match (sorting.judge(frame.as_ref()), frame) {
            (Judgement::Serve, Some(ControlFrame::Request(request))) => {
                if !serve(&service, &facts, &link, &request).await {
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
    request: &kr_protocol::envelope::Request,
) -> bool {
    // Taken before the answer is produced, as the loop takes it before it handles a frame: an
    // answer produced while the connection held its registration carries what that gave it, and a
    // withdrawal that lands before it reaches the peer must stop it.
    let protected = !link.withdrawn.is_set();
    #[cfg(feature = "testing")]
    service.record_received(&request.method, &request.params);
    let served = service.keystroke_of_a_request(facts, request);
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
    if let Some(local) = link.writable.local.as_ref() {
        local.answered(request.request_id, served.held);
    }
    written
}

#[cfg(test)]
mod tests {
    use kr_protocol::envelope::{MutationRequest, ParamsValue, Request};
    use kr_protocol::ids::{ActionId, RequestId};
    use kr_protocol::method::MethodVersion;
    use kr_protocol::scalars::{DurationMs, Nullable};

    use super::*;

    fn request(method: Method) -> Option<ControlFrame> {
        Some(ControlFrame::Request(Request {
            request_id: RequestId::new(1),
            method: method.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::empty(),
        }))
    }

    fn mutation(method: Method) -> Option<ControlFrame> {
        Some(ControlFrame::Mutation(Box::new(MutationRequest {
            request_id: RequestId::new(1),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: kr_protocol::envelope::ActionTarget {
                environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: kr_protocol::ids::ActionWindowId::new("window").expect("an id"),
            requested_ttl_ms: DurationMs::new(1),
            params: ParamsValue::empty(),
        })))
    }

    /// The decisions for `frames`, in order, and whether the connection could still be read after
    /// each.
    fn judged(frames: &[Option<ControlFrame>]) -> Vec<(Judgement, bool)> {
        let mut sorting = Sorting::default();
        frames
            .iter()
            .map(|frame| (sorting.judge(frame.as_ref()), sorting.may_read()))
            .collect()
    }

    /// KR-PERF-002: a key goes ahead of a read and of a mutation that leaves keys alone, and of
    /// nothing else.
    #[test]
    fn a_key_goes_ahead_of_reads_and_geometry_and_of_nothing_else() {
        use Judgement::{Defer, Serve};
        let key = request(Method::InputWrite);
        let frames = [
            request(Method::SessionRead),
            mutation(Method::AttachmentViewport),
            mutation(Method::TerminalResize),
            key.clone(),
            mutation(Method::SessionDetach),
            key.clone(),
            request(Method::SessionRead),
            key,
        ];
        let decisions: Vec<_> = judged(&frames).into_iter().map(|(what, _)| what).collect();
        assert_eq!(
            decisions,
            [Defer, Defer, Defer, Serve, Defer, Defer, Defer, Defer],
            "a key is served ahead of the reads and the geometry before it, and held behind the \
             detach and behind the key held ahead of it"
        );
    }

    /// KR-PERF-002: the connection is read for as long as a key could still be served, and for no
    /// more than the most frames that cannot be.
    #[test]
    fn the_connection_is_read_until_a_key_cannot_be_served_or_too_many_frames_are_held() {
        let reads = |count: usize| vec![request(Method::SessionRead); count];
        assert!(
            judged(&reads(MOST_HELD - 1))
                .last()
                .is_some_and(|(_, more)| *more)
        );
        assert!(
            judged(&reads(MOST_HELD))
                .last()
                .is_some_and(|(_, more)| !*more)
        );
        assert!(
            judged(&[mutation(Method::SessionClose)])
                .last()
                .is_some_and(|(_, more)| !*more),
            "a frame a key does not go ahead of ends the reading"
        );
        assert!(
            judged(&[None]).last().is_some_and(|(_, more)| !*more),
            "so does a frame that could not be read"
        );
        // Keys served do not count against the frames held.
        let keys = vec![request(Method::InputWrite); MOST_HELD * 2];
        assert!(
            judged(&keys)
                .iter()
                .all(|(what, more)| *what == Judgement::Serve && *more)
        );
    }

    /// KR-PERF-002: a frame that is not a request blocks keys, whatever it is.
    #[test]
    fn a_frame_that_is_not_a_request_or_a_mutation_blocks_keys() {
        let frame = Some(ControlFrame::Event(
            kr_protocol::envelope::ControlEvent::Keepalive,
        ));
        assert_eq!(
            judged(&[frame, request(Method::InputWrite)])
                .into_iter()
                .map(|(what, _)| what)
                .collect::<Vec<_>>(),
            [Judgement::Defer, Judgement::Defer]
        );
    }
}
