//! A create whose worker reported itself and whose session closed before the create described it.
//!
//! The create answers with the session as its worker describes it. A closure that is recorded
//! between the worker's report and that description takes the worker out of what the daemon holds,
//! and the session is then closed rather than unknown: the closure is the answer, as it is to the
//! same create asked again afterwards.

use kr_protocol::session::{SessionCreateResult, SessionState};

use super::a_create_that_launches_nothing::create_params;
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use crate::registry::Reservation;

/// A daemon, a real worker that has reported itself, and the create it reported for.
async fn reported() -> (Served, Reservation) {
    let (world, reservation_id) = Served::claimed().await;
    let reservation = world
        .controller
        .registry
        .lock()
        .await
        .reservation(reservation_id)
        .expect("the registry answers")
        .expect("the reservation is recorded");
    world
        .controller
        .directory
        .lock()
        .await
        .insert(world.worker.clone(), None);
    (world, reservation)
}

/// What a create is answered with, for the worker `world` serves.
async fn answered(world: &Served, reservation: &Reservation) -> SessionCreateResult {
    world
        .controller
        .answer_a_created_session(
            &create_params(world.controller.paths().environment_id()),
            reservation,
            world.worker.endpoint.as_text(),
        )
        .await
        .expect("the create is answered")
        .to_typed()
        .expect("a create result")
}

fn assert_closed(answer: &SessionCreateResult, world: &Served) {
    assert_eq!(answer.session.state, SessionState::Closed);
    assert_eq!(
        answer
            .session
            .closure
            .0
            .as_ref()
            .map(|record| record.session_id),
        Some(world.session_id),
        "the session carries its closure"
    );
    assert!(
        answer.endpoint.0.is_none(),
        "a closed session has no endpoint"
    );
    assert!(
        !answer.deduplicated,
        "an answer made for the create itself is not a replay of it"
    );
}

/// KR-REQ-09.12: a create whose session closed after its worker reported itself is answered from
/// the session's closure, with the session closed and no endpoint to attach to, whether the closure
/// has finished by the time the create looks for its worker or lands between that look and the
/// worker's description of the session. The control is the same create before any closure, which
/// is answered with the worker's own description of the session and its endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_session_closed_after_its_worker_reported_is_answered_from_the_closure() {
    let (world, reservation) = reported().await;
    let controller = &world.controller;

    let open = answered(&world, &reservation).await;
    assert_eq!(
        open.endpoint.0.as_deref(),
        Some(world.worker.endpoint.as_text().as_str())
    );
    assert_ne!(open.session.state, SessionState::Closed);

    // The closure lands between the create's look at the directory and its read of the worker.
    let (arrived, go) = controller.before_a_created_session_is_read.arm();
    let (during, ()) = tokio::join!(answered(&world, &reservation), async {
        arrived.await.expect("the create has found its worker");
        controller
            .retire(&closure_of(world.session_id))
            .await
            .expect("the closure is recorded");
        go.send(()).expect("the create is waiting");
    });
    assert_closed(&during, &world);

    // The closure is complete when the create looks for its worker: nothing is in the directory.
    assert_closed(&answered(&world, &reservation).await, &world);
}
