//! The reply a local caller reads for a mutation is the reply the door made.
//!
//! Every reply to a mutation is made by `told` or `declined` and written by the one sink that
//! consumes it, which notes each reply it writes for these tests. Through a real local connection
//! this sends one mutation for each local write in the method table, a mutation on a stream of the
//! wrong kind, a mutation before the hello and a mutation whose answer is written while the local
//! owner's lease ends, and requires that for each request the frame the caller reads is the frame
//! the sink consumed, or the lease's own word for the lease case. A reply replaced after the check
//! differs.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue, Response};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, ActionWindowId, BuildId, RequestId};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::method::Method;
use kr_protocol::privacy::PrivacySetParams;
use kr_protocol::scalars::CanonicalSet;

use super::the_fence_at_every_effect::{daemon, mutation_of};
use super::writes::LocalWrite;
use crate::service::{Controller, error_reply};

/// How long a reply may take to arrive.
const REPLY: Duration = Duration::from_secs(60);

/// A local connection to the daemon, as a caller holds it.
struct Caller {
    reader: FrameReader,
    writer: FrameWriter,
    /// The window the daemon issued, once the hello is answered.
    window: Option<ActionWindowId>,
    /// The identifier the next request carries.
    next: u64,
    serving: tokio::task::JoinHandle<()>,
}

impl Caller {
    /// Connects a stream of `kind` and says nothing yet.
    async fn connect(
        temp: &kr_ipc::testing::TempHost,
        controller: &Arc<Controller>,
        listener: &Listener,
        kind: StreamKind,
    ) -> Self {
        let endpoint = temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let dialled = tokio::spawn(async move { Connection::connect(&endpoint).await });
        let (connection, peer) = listener.accept().await.expect("accepts");
        let caller = dialled.await.expect("the task ends").expect("connects");
        let serving = tokio::spawn({
            let controller = Arc::clone(controller);
            async move {
                let _ = controller.client(connection, peer, kind).await;
            }
        });
        let (reader, writer) = split(caller, kind);
        Self {
            reader,
            writer,
            window: None,
            next: 1,
            serving,
        }
    }

    /// Connects and negotiates, and keeps the action window the daemon issues.
    async fn negotiated(
        temp: &kr_ipc::testing::TempHost,
        controller: &Arc<Controller>,
        listener: &Listener,
        kind: StreamKind,
    ) -> Self {
        let mut caller = Self::connect(temp, controller, listener, kind).await;
        caller
            .writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                client: LocalClientKind::Cli,
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .expect("writes the hello");
        let ControlFrame::HelloAck(acknowledged) = caller.read().await else {
            panic!("the daemon acknowledges the hello");
        };
        caller.window = Some(acknowledged.action_window.action_window_id);
        caller
    }

    /// The next frame that is not an event the daemon sends of its own accord.
    async fn read(&mut self) -> ControlFrame {
        loop {
            let frame = tokio::time::timeout(REPLY, self.reader.read_message::<ControlFrame>())
                .await
                .expect("the daemon answers")
                .expect("the answer reads");
            if !matches!(frame, ControlFrame::Event(_)) {
                return frame;
            }
        }
    }

    /// A mutation of `method` under the window and the next request identifier.
    fn mutation(
        &mut self,
        temp: &kr_ipc::testing::TempHost,
        method: Method,
        params: ParamsValue,
    ) -> MutationRequest {
        let mut mutation = mutation_of(temp, method, params);
        mutation.request_id = RequestId::new(self.next);
        self.next += 1;
        mutation.action_id = ActionId::new(kr_ipc::new_uuid());
        if let Some(window) = &self.window {
            mutation.action_window_id = window.clone();
        }
        mutation
    }

    async fn send(&mut self, mutation: MutationRequest) {
        self.writer
            .write_message(&ControlFrame::Mutation(Box::new(mutation)))
            .await
            .expect("writes the mutation");
    }

    /// Sends `mutation` and reads the reply to it.
    async fn ask(&mut self, mutation: MutationRequest) -> ControlFrame {
        self.send(mutation).await;
        self.read().await
    }
}

/// The endpoint the daemon would serve clients on.
fn bound(temp: &kr_ipc::testing::TempHost) -> Listener {
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    Listener::bind(&endpoint).expect("binds the endpoint")
}

/// The one reply the sink noted for `request_id`.
fn noted(controller: &Controller, request_id: RequestId) -> ControlFrame {
    let mut written: Vec<ControlFrame> = controller
        .replies_written()
        .into_iter()
        .filter(|(noted_for, _)| *noted_for == request_id)
        .map(|(_, frame)| frame)
        .collect();
    assert_eq!(
        written.len(),
        1,
        "the sink consumed one reply for request {request_id:?}: {written:?}"
    );
    written.remove(0)
}

fn code_of(frame: &ControlFrame) -> Option<ErrorCode> {
    match frame {
        ControlFrame::Response(Response {
            outcome: Outcome::Error(error),
            ..
        }) => Some(error.code),
        _ => None,
    }
}

/// KR-REQ-09.09: a caller is read the reply the door made for each mutation it sent: one for each
/// local write in the method table, and the same for a mutation on a stream of the wrong kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_mutation_reply_is_the_reply_that_was_checked() {
    let (temp, controller, _clock) = daemon().await;
    let listener = bound(&temp);
    let mut caller = Caller::negotiated(&temp, &controller, &listener, StreamKind::Control).await;
    let mut asked = 0_usize;
    for method in Method::ALL.iter().copied() {
        if LocalWrite::of(method).is_none() {
            continue;
        }
        let mutation = caller.mutation(&temp, method, ParamsValue::empty());
        let request_id = mutation.request_id;
        let read = caller.ask(mutation).await;
        assert_eq!(
            read,
            noted(&controller, request_id),
            "{method:?}: the caller is read the reply the sink consumed"
        );
        asked += 1;
    }
    assert!(asked > 50, "a mutation for each local write: {asked}");

    // A mutation on a stream that does not carry it is declined, and the caller reads that.
    let mutation = caller.mutation(&temp, Method::UploadChunk, ParamsValue::empty());
    let request_id = mutation.request_id;
    let read = caller.ask(mutation).await;
    assert_eq!(read, noted(&controller, request_id));
    assert_eq!(
        code_of(&read),
        Some(ErrorCode::PermissionDenied),
        "{read:?}"
    );
    caller.serving.abort();

    let mut chunks =
        Caller::negotiated(&temp, &controller, &listener, StreamKind::AttachmentChunks).await;
    // The requests of this connection are numbered apart from the first one's.
    chunks.next = 1_000_000;
    let mutation = chunks.mutation(&temp, Method::PrivacyRetainedDelete, ParamsValue::empty());
    let request_id = mutation.request_id;
    let read = chunks.ask(mutation).await;
    assert_eq!(read, noted(&controller, request_id));
    assert_eq!(
        code_of(&read),
        Some(ErrorCode::PermissionDenied),
        "{read:?}"
    );
    chunks.serving.abort();
}

/// KR-REQ-09.09: a mutation sent before the hello is answered with the constant the loop keeps
/// for it, and the sink writes nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_before_the_hello_is_answered_with_the_constant_for_it() {
    let (temp, controller, _clock) = daemon().await;
    let listener = bound(&temp);
    let mut caller = Caller::connect(&temp, &controller, &listener, StreamKind::Control).await;
    let mutation = caller.mutation(&temp, Method::PrivacyRetainedDelete, ParamsValue::empty());
    let read = caller.ask(mutation).await;
    assert_eq!(
        read,
        error_reply(
            RequestId::new(0),
            ErrorCode::UnsupportedSchema,
            "a local connection negotiates its version before anything else",
        )
    );
    assert!(
        controller.replies_written().is_empty(),
        "no reply to a mutation was made before the hello"
    );
    caller.serving.abort();
}

/// KR-REQ-09.09, KR-REQ-09.12: an answer written while the local owner's lease ends is the
/// lease's own word, outcome unknown for a write, and not the answer the door made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_written_while_the_lease_ends_is_the_leases_own_word() {
    let (temp, controller, _clock) = daemon().await;
    let listener = bound(&temp);
    let mut caller = Caller::negotiated(&temp, &controller, &listener, StreamKind::Control).await;
    assert_eq!(
        kr_protocol::method::local_hold(Method::PrivacySet),
        kr_protocol::method::LocalHold::Held,
        "the method this sends is held to the lease"
    );
    let (arrived, release) = controller.pause_before_a_reply_is_told();
    let mutation = caller.mutation(
        &temp,
        Method::PrivacySet,
        ParamsValue::from_typed(&PrivacySetParams { enabled: false }).expect("encodes"),
    );
    let request_id = mutation.request_id;
    caller.send(mutation).await;
    tokio::time::timeout(REPLY, arrived)
        .await
        .expect("the door reaches the place its answer is told")
        .expect("the pause is armed");
    controller
        .policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_exclusively_managed(true);
    release.send(()).expect("the door goes on");
    let read = caller.read().await;
    assert_eq!(
        read,
        controller.lease_ended_reply(request_id, Some(Method::PrivacySet)),
        "the lease's own word"
    );
    assert_eq!(code_of(&read), Some(ErrorCode::OutcomeUnknown), "{read:?}");
    assert_ne!(
        read,
        noted(&controller, request_id),
        "it is not the answer the door made"
    );
    caller.serving.abort();
}
