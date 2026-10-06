//! A request for a worker that a closure overtakes, and the links a session's worker is reached by.
//!
//! A closure takes its worker out of everything this daemon holds of it, and what it records is the
//! answer to every later ask. So a link a remote connection holds to the worker ends with the
//! closure and one that is being opened when the closure lands is refused, rather than leaving a
//! connection to a worker whose session has closed; and a close that read its worker from the
//! directory and finds the closure recorded before it reaches the worker is answered from the
//! record, as a close that came after the closure is.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::envelope::Outcome;
use kr_protocol::method::Method;
use kr_protocol::session::{SessionCloseResult, SessionReadParams, SessionState};
use kr_transport::window::{AcceptedDeadline, DeadlineBound};

use super::a_close_a_worker_never_answers as world;
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use crate::error::ControllerError;
use crate::service::net::proxy::{Purpose, RELAY_DEPTH, RELAY_QUEUED_BYTES, RelayBudget};

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it: a daemon that never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// The things a remote connection gives the link it asks for: where the worker's notifications go,
/// what they may queue and how the connection is told its link has ended.
struct Connection {
    notifications: tokio::sync::mpsc::Sender<crate::service::net::proxy::Relayed>,
    /// Held, so a notification the worker sends has somewhere to go.
    _relayed: tokio::sync::mpsc::Receiver<crate::service::net::proxy::Relayed>,
    budget: Arc<RelayBudget>,
    lost: Arc<tokio::sync::Notify>,
}

impl Connection {
    fn new() -> Self {
        let (notifications, relayed) = tokio::sync::mpsc::channel(RELAY_DEPTH);
        Self {
            notifications,
            _relayed: relayed,
            budget: Arc::new(RelayBudget::new(RELAY_QUEUED_BYTES)),
            lost: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

/// KR-REQ-09.12: a closure ends the links remote connections hold to its session's worker, and tells
/// each connection its link has ended so that the device reconnects. The control: before the
/// closure the link reaches the worker and answers a read of the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_ends_the_links_held_to_its_worker() {
    let world = Served::start().await;
    let connection = Connection::new();
    let proxy = world
        .controller
        .open_proxy(
            world.session_id,
            connection.notifications.clone(),
            Arc::clone(&connection.budget),
            Arc::clone(&connection.lost),
            Purpose::Attachment,
        )
        .await
        .expect("the worker accepts the link");
    let read = SessionReadParams {
        session_id: world.session_id,
    };
    assert!(
        matches!(
            proxy
                .read(Method::SessionRead, &read)
                .await
                .expect("the worker answers")
                .outcome,
            Outcome::Ok(_)
        ),
        "before the closure the link reaches the worker"
    );
    let lost = connection.lost.notified();
    tokio::pin!(lost);
    lost.as_mut().enable();

    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");

    assert!(!proxy.is_open(), "the closure ended the link");
    assert!(
        tokio::time::timeout(WAIT, lost).await.is_ok(),
        "the connection is told its link has ended"
    );
    proxy
        .read(Method::SessionRead, &read)
        .await
        .expect_err("nothing more is asked of the worker of a closed session");
}

/// KR-REQ-09.12: the link a close is delivered over is not ended by the closure that close's own
/// answer records. The worker holds what its session ran until the link is released, which tells it
/// the answer has been delivered, so a closure that ended the link first would release it early.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_does_not_end_the_link_a_close_is_delivered_over() {
    let world = Served::start().await;
    let connection = Connection::new();
    let proxy = world
        .controller
        .open_proxy(
            world.session_id,
            connection.notifications.clone(),
            Arc::clone(&connection.budget),
            Arc::clone(&connection.lost),
            Purpose::Close,
        )
        .await
        .expect("the worker accepts the link");

    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");

    assert!(
        proxy.is_open(),
        "the closure left the close's link to its holder"
    );
    proxy.close();
}

/// KR-REQ-09.12: a link that a closure overtakes while it is being opened is refused. The worker
/// has not ended, as when the daemon records the closure of a worker it found gone, so a link
/// opened to it would be answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_a_closure_overtakes_while_it_opens_is_refused() {
    let world = Served::start().await;
    let (arrived, go) = world.controller.before_a_proxy_is_opened.arm();
    let opening = tokio::spawn({
        let controller = Arc::clone(&world.controller);
        let session_id = world.session_id;
        async move {
            let connection = Connection::new();
            controller
                .open_proxy(
                    session_id,
                    connection.notifications.clone(),
                    Arc::clone(&connection.budget),
                    Arc::clone(&connection.lost),
                    Purpose::Attachment,
                )
                .await
        }
    });
    arrived.await.expect("the open reaches the worker's door");

    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    go.send(()).expect("the open is waiting");

    let opened = opening.await.expect("the open's task ends");
    let Err(refused) = opened else {
        panic!("a link to a worker whose session closed was opened");
    };
    assert!(
        matches!(refused, ControllerError::UnknownSession { .. }),
        "{refused:?}"
    );
}

/// KR-REQ-09.12: a close that read its worker from the directory and finds the closure recorded
/// before it asks for the worker's connection is answered from the closure record: the session is
/// closed, with the record that closed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_that_a_closure_overtakes_is_answered_from_the_closure() {
    let world = Served::start().await;
    let controller = &world.controller;
    let actor = crate::service::local_actor(
        kr_protocol::ids::ActorId::new("local:test").expect("a principal"),
        kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
        controller.generation,
    );
    let accepted = AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(Duration::from_secs(300))
            .expect("a deadline five minutes out"),
        bound: DeadlineBound::RequestedTtl,
    };
    let carried = world::admission(controller, accepted).await;
    let environment_id = controller.paths().environment_id();
    let request = world::close_request(environment_id, world.session_id);
    let (arrived, go) = controller.before_a_close_asks_for_its_link.arm();
    let closing = tokio::spawn({
        let controller = Arc::clone(controller);
        async move {
            controller
                .session_close(&request, &actor, Some(accepted), carried)
                .await
        }
    });
    arrived.await.expect("the close has read its worker");

    controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    go.send(()).expect("the close is waiting");

    let answered = closing
        .await
        .expect("the close's task ends")
        .expect("a close that a closure overtakes is answered from the closure");
    let answered: SessionCloseResult = answered.to_typed().expect("a close result");
    assert_eq!(answered.session_id, world.session_id);
    assert_eq!(answered.state, SessionState::Closed);
    assert_eq!(
        answered.closure.as_ref().map(|record| record.session_id),
        Some(world.session_id),
        "the record that closed the session is the answer"
    );
}
