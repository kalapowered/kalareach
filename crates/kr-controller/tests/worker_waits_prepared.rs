//! What a worker does with an accepted, prepared action whose client has gone while the dispatch
//! boundary is held.
//!
//! A real daemon, this test process as the worker it started, a real plugin host and a real
//! component that prepares each action: the plugin world that `plugin_actions.rs` uses, which is the
//! only fixture that prepares an action. The cases hold the worker's dispatch boundary on a thread
//! of their own after the action is accepted and its preparation has been stopped at the seam that
//! stands for the component's call, then let the preparation go, so that the action waits for the
//! boundary. Every wait is for a state the worker reaches: the receipt, the preparation at its stop,
//! the action waiting, the connection's place given back, and the owner's work done.
//!
//! Where the test components are not built the cases skip with words, and fail when
//! `KR_REQUIRE_PLUGIN_FIXTURES=1` is set, which is what the fixture's own cases do.

#![cfg(unix)]

mod plugin_world;

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::receipt::{ActionCancelParams, Receipt, ReceiptState, RejectionReason};
use kr_protocol::scalars::Nullable;
use kr_worker::service::WorkerService;
use plugin_world::PATIENCE;
use plugin_world::acting::{Acting, ask_for_receipt, read_receipt, send, until_receipt};

/// What a holder takes on a thread of its own, in the order a mutation takes them.
#[derive(Clone, Copy)]
enum Hold {
    /// The dispatch boundary.
    Boundary,
    /// The dispatch boundary and, inside it, the session.
    BoundaryAndSession,
}

/// The worker's locks, held on a thread of its own until they are let go. A holder that a failed
/// case drops lets go too, so that what waits for it ends and the program ends with the case's own
/// message.
struct Held {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Held {
    async fn take(service: &Arc<WorkerService>, hold: Hold) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = tokio::sync::oneshot::channel::<()>();
        let service = Arc::clone(service);
        let thread = std::thread::spawn(move || {
            let _boundary = service.hold_the_dispatch_boundary();
            let _session =
                matches!(hold, Hold::BoundaryAndSession).then(|| service.runtime().session());
            let _ = held.send(());
            let _ = wait.recv();
        });
        tokio::time::timeout(PATIENCE, confirmed)
            .await
            .expect("the locks are held in time")
            .expect("the holder ended without holding the locks");
        Self {
            release: Some(release),
            thread: Some(thread),
        }
    }

    fn release(mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the holding thread finishes");
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        drop(self.release.take());
    }
}

/// Waits until `settled` holds, or `PATIENCE` has passed, and says whether it held.
async fn settles(mut settled: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + PATIENCE;
    while !settled() {
        if tokio::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// How the client that sent the action goes.
#[derive(Clone, Copy, Debug)]
enum Goes {
    /// Its connection is shut down and dropped.
    Plainly,
    /// It asks about the action first and then goes, so that a frame is still unread when the end
    /// comes.
    BehindAFrame,
}

/// An accepted action whose component has answered and which waits for the dispatch boundary.
struct Waiting {
    acting: Acting,
    service: Arc<WorkerService>,
    watcher: LocalClient,
    /// The client that sent the action, until it goes.
    asking: Option<LocalClient>,
    action_id: ActionId,
    /// The receipt as the action was accepted.
    accepted: Receipt,
    /// What holds the worker's locks.
    held: Held,
    /// The connections the worker serves while the action waits.
    start: usize,
}

/// Starts the world, sends a `turn.cancel` action on a connection of its own and waits until it is
/// accepted and its preparation stands at its stop. A cancellation by `cancel_first`, when asked
/// for, is made then. The holder takes `hold`, the preparation is let go, and the function returns
/// once the action waits for the dispatch boundary. It returns nothing where the world cannot be
/// started, which the fixture has said in words.
async fn waiting_for_the_boundary(hold: Hold, cancel_first: bool) -> Option<Waiting> {
    let acting = Acting::start_on(Arc::new(kr_transport::clock::ManualClock::new())).await?;
    let service = Arc::clone(&acting.hosted._service);
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mutation = acting.invocation(&asking, "turn.cancel", b"{}");
    let action_id = mutation.action_id;
    let (arrived, release) = service.stall_next_preparation();
    asking
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    let mut accepted = until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;
    tokio::time::timeout(PATIENCE, arrived)
        .await
        .expect("the preparation reaches its stop")
        .expect("the stop is not dropped before the preparation reaches it");
    if cancel_first {
        let mut cancel = acting.invocation(&watcher, "turn.cancel", b"{}");
        cancel.method = Method::ActionCancel.into();
        cancel.action_id = ActionId::new(kr_ipc::new_uuid());
        cancel.target = ActionTarget {
            environment_id: acting.hosted.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        cancel.params =
            ParamsValue::from_typed(&ActionCancelParams { action_id }).expect("encodes");
        let cancelled = send(&mut watcher, cancel).await;
        assert!(matches!(cancelled, Outcome::Ok(_)), "{cancelled:?}");
        accepted = until_receipt(&mut watcher, action_id, ReceiptState::Rejected).await;
    }
    let held = Held::take(&service, hold).await;
    release
        .send(())
        .expect("the preparation is waiting at its stop");
    assert!(
        settles(|| service.prepared_waiting_for_tests() == 1).await,
        "the prepared action waits for the dispatch boundary: {} waiting",
        service.prepared_waiting_for_tests()
    );
    let start = service.connections_held_for_tests();
    Some(Waiting {
        acting,
        service,
        watcher,
        asking: Some(asking),
        action_id,
        accepted,
        held,
        start,
    })
}

impl Waiting {
    /// The client that sent the action goes. Its socket is shut down first: closing the client's end
    /// is not enough to end the connection when a process that another case has started holds a
    /// copy of the descriptor until it executes.
    async fn client_goes(&mut self, how: Goes) -> LocalClient {
        let mut asking = self.asking.take().expect("the client is still there");
        if matches!(how, Goes::BehindAFrame) {
            ask_for_receipt(&mut asking, self.action_id).await;
        }
        asking
            .writer()
            .shut_down(std::net::Shutdown::Both)
            .expect("shuts the client's socket down");
        asking
    }

    /// Waits until the connection of the client that went is given back, while the locks are held.
    async fn given_back(&self, what: &str) {
        let service = &self.service;
        assert!(
            settles(|| service.connections_held_for_tests() < self.start
                && service.prepared_waiting_for_tests() == 0)
            .await,
            "{what}: the connection of the client that went is given back while the locks are held: \
             {} held, {} at the start, {} waiting",
            service.connections_held_for_tests(),
            self.start,
            service.prepared_waiting_for_tests()
        );
    }
}

/// KR-REQ-23.30: a prepared action whose client goes while the boundary is held is rejected at
/// once, and its connection's place is given back, without the boundary.
///
/// Only the boundary is held, and the rejection needs the session alone, which nobody holds: the
/// receipt is `rejected` before the holder lets go. The connection's path owes the rejection and the
/// owner makes it, once. The loop that served the client has ended, and nothing was written to the
/// upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_prepared_action_whose_client_goes_under_a_held_boundary_is_rejected_at_once()
 {
    for how in [Goes::Plainly, Goes::BehindAFrame] {
        let Some(mut waiting) = waiting_for_the_boundary(Hold::Boundary, false).await else {
            return;
        };
        let gone = waiting.client_goes(how).await;
        waiting.given_back(&format!("{how:?}")).await;
        let receipt = until_receipt(
            &mut waiting.watcher,
            waiting.action_id,
            ReceiptState::Rejected,
        )
        .await;
        assert_eq!(
            receipt.reason.as_ref(),
            Some(&RejectionReason::AdmissionFailed),
            "{how:?}: {receipt:?}"
        );
        assert_eq!(
            receipt.revision.get(),
            waiting.accepted.revision.get() + 1,
            "{how:?}: rejected once: {receipt:?}"
        );
        assert!(
            settles(|| waiting.service.owed_done_for_tests().0 == 1).await,
            "{how:?}: the owner made the rejection while the boundary was held: {:?}",
            waiting.service.owed_done_for_tests()
        );
        waiting.held.release();
        drop(gone);
        assert!(
            waiting.acting.frames().is_empty(),
            "{how:?}: nothing was written to the upstream: {:?}",
            waiting.acting.frames()
        );
    }
}

/// KR-REQ-23.30: a prepared action whose client goes while the boundary and the session are held
/// stays accepted until the session is let go, and is then rejected once.
///
/// A receipt cannot be read while the session is held, so the case reads the owner's count of
/// rejections done: none while the holder has the session, one after it lets go. The connection's
/// place is given back while both are held, whether the client went plainly or with a frame of its
/// own still unread behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_prepared_action_whose_client_goes_under_the_session_is_rejected_when_it_is_let_go()
 {
    for how in [Goes::Plainly, Goes::BehindAFrame] {
        let Some(mut waiting) = waiting_for_the_boundary(Hold::BoundaryAndSession, false).await
        else {
            return;
        };
        let gone = waiting.client_goes(how).await;
        waiting.given_back(&format!("{how:?}")).await;
        assert_eq!(
            waiting.service.owed_done_for_tests().0,
            0,
            "{how:?}: the rejection is not made while the session is held"
        );
        waiting.held.release();
        drop(gone);
        assert!(
            settles(|| waiting.service.owed_done_for_tests().0 == 1).await,
            "{how:?}: the owner rejects the action when the session is let go: {:?}",
            waiting.service.owed_done_for_tests()
        );
        let receipt = read_receipt(&mut waiting.watcher, waiting.action_id)
            .await
            .expect("a receipt");
        assert_eq!(
            receipt.state,
            ReceiptState::Rejected,
            "{how:?}: {receipt:?}"
        );
        assert_eq!(
            receipt.revision.get(),
            waiting.accepted.revision.get() + 1,
            "{how:?}: rejected once, one revision higher: {receipt:?}"
        );
        assert_eq!(
            waiting.service.owed_done_for_tests().0,
            1,
            "{how:?}: the rejection was made once"
        );
        assert!(
            waiting.acting.frames().is_empty(),
            "{how:?}: nothing was written to the upstream: {:?}",
            waiting.acting.frames()
        );
    }
}

/// KR-REQ-23.30: a cancellation that came before the client went stays what it was: the owner's
/// rejection finds the receipt no longer accepted and leaves it.
///
/// The action is cancelled while its preparation is stopped, then waits for the boundary with the
/// session held, and its client goes. The owner's entry names the journal's sequence of the
/// acceptance, and is done to no effect: the receipt keeps the cancellation's reason and revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_cancellation_that_came_first_stays_when_the_owner_rejects_a_dropped_action()
{
    let Some(mut waiting) = waiting_for_the_boundary(Hold::BoundaryAndSession, true).await else {
        return;
    };
    let cancelled = waiting.accepted.clone();
    assert_eq!(
        cancelled.reason.as_ref(),
        Some(&RejectionReason::Cancelled),
        "{cancelled:?}"
    );
    let gone = waiting.client_goes(Goes::Plainly).await;
    waiting.given_back("a cancelled action").await;
    waiting.held.release();
    drop(gone);
    assert!(
        settles(|| waiting.service.owed_done_for_tests().0 == 1).await,
        "the owner's entry is done when the session is let go: {:?}",
        waiting.service.owed_done_for_tests()
    );
    let receipt = read_receipt(&mut waiting.watcher, waiting.action_id)
        .await
        .expect("a receipt");
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&RejectionReason::Cancelled),
        "the cancellation's reason stands: {receipt:?}"
    );
    assert_eq!(
        receipt.revision.get(),
        cancelled.revision.get(),
        "the owner's rejection changed nothing: {receipt:?}"
    );
}

/// KR-REQ-23.30: a cancellation that the client sends behind an action that waits for the boundary
/// is read after the action is dispatched, not before.
///
/// The client's loop is held in the wait for the boundary and reads nothing from its socket, so the
/// cancellation the client writes behind the action stays unread. At the release the action is
/// dispatched first and then the cancellation is read, and it refuses to cancel an action that has
/// been dispatched. Both are answered; the order of the two answers is not promised, since the
/// action's is written when the upstream has answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_cancel_sent_behind_a_waiting_prepared_action_is_read_after_the_action() {
    let Some(mut waiting) = waiting_for_the_boundary(Hold::Boundary, false).await else {
        return;
    };
    let asking = waiting.asking.as_mut().expect("the client is there");
    let mut cancel = waiting.acting.invocation(asking, "turn.cancel", b"{}");
    cancel.method = Method::ActionCancel.into();
    cancel.request_id = kr_protocol::ids::RequestId::new(2);
    cancel.action_id = ActionId::new(kr_ipc::new_uuid());
    cancel.target = ActionTarget {
        environment_id: waiting.acting.hosted.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    cancel.params = ParamsValue::from_typed(&ActionCancelParams {
        action_id: waiting.action_id,
    })
    .expect("encodes");
    asking
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(cancel)))
        .await
        .expect("writes the cancellation behind the action");
    // The state this case stands on: the action waits for the boundary, and the cancellation is
    // queued on its connection behind it and is not read. A read of the connection would show as
    // a request waiting at the boundary beside the action, which the window below would see.
    assert_eq!(
        waiting.service.prepared_waiting_for_tests(),
        1,
        "the action waits while the cancellation is written behind it"
    );
    let read_while_the_action_waits = tokio::time::timeout(
        Duration::from_millis(300),
        settles(|| waiting.service.mutations_waiting_for_tests() != 0),
    )
    .await
    .is_ok();
    assert!(
        !read_while_the_action_waits,
        "the connection was read while the action waited: the cancellation waits at the boundary"
    );
    assert_eq!(
        waiting.service.prepared_waiting_for_tests(),
        1,
        "the action still waits, with the cancellation queued behind it"
    );
    waiting.held.release();
    let mut order = Vec::new();
    let mut outcomes = std::collections::BTreeMap::new();
    while order.len() < 2 {
        let frame = tokio::time::timeout(PATIENCE, asking.recv()).await;
        assert!(
            matches!(frame, Ok(Ok(_))),
            "both requests are answered after the release on a connection that is still read, \
             and the answers so far are {order:?}: {frame:?}"
        );
        if let Ok(Ok(ControlFrame::Response(response))) = frame {
            order.push(response.request_id.get());
            outcomes.insert(response.request_id.get(), response.outcome);
        }
    }
    // The two answers are written by different tasks: the action's by the one that waits for the
    // upstream to answer, the cancellation's by the connection's loop as soon as it reads it. Their
    // order is not promised and is not asserted. What is promised is the order of the two requests'
    // effects: the action was dispatched before the cancellation was read, so the action's answer is
    // its own and the cancellation is refused.
    assert!(
        matches!(outcomes[&1], Outcome::Ok(_)),
        "the action was dispatched: {:?}",
        outcomes[&1]
    );
    assert!(
        !matches!(outcomes[&2], Outcome::Ok(_)),
        "the cancellation was read after the action was dispatched and is refused: {:?}",
        outcomes[&2]
    );
    let receipt = read_receipt(&mut waiting.watcher, waiting.action_id)
        .await
        .expect("a receipt");
    assert_ne!(
        receipt.reason.as_ref(),
        Some(&RejectionReason::Cancelled),
        "the action was not cancelled: {receipt:?}"
    );
}
