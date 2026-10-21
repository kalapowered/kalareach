//! A create whose worker reported itself and whose session closed before the create described it.
//!
//! The create answers with the session as its worker describes it. A closure that is recorded
//! between the worker's report and that description takes the worker out of what the daemon holds,
//! and the session is then closed rather than unknown: the closure is the answer, as it is to the
//! same create asked again afterwards. So is the closure of a worker that has ended before the
//! daemon has recorded one, as the worker of a command that ends at once does.

use kr_protocol::identity::{DesktopBinding, ProcessStartIdentity, WorkerProfile};
use kr_protocol::ids::AuthorityRevision;
use kr_protocol::session::{SessionCreateResult, SessionState};

use super::a_create_that_launches_nothing::create_params;
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use crate::error::ControllerError;
use crate::registry::{Reservation, WorkerRecord};

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
    answer(world, reservation)
        .await
        .expect("the create is answered")
        .to_typed()
        .expect("a create result")
}

/// The create's answer or its failure, for the worker `world` serves.
async fn answer(
    world: &Served,
    reservation: &Reservation,
) -> crate::error::Result<kr_protocol::envelope::ParamsValue> {
    world
        .controller
        .answer_a_created_session(
            &create_params(world.controller.paths().environment_id()),
            reservation,
            world.worker.endpoint.as_text(),
        )
        .await
}

/// Leaves the worker of `world` gone as the worker of a command that ended at once is: its
/// endpoint is taken away, and the registry names `process` as the worker's process.
async fn gone(world: &Served, reservation: &Reservation, process: ProcessStartIdentity) {
    world
        .controller
        .registry
        .lock()
        .await
        .adopt_worker(
            &WorkerRecord {
                session_id: world.session_id,
                display_number: reservation.display_number,
                public_key: world.worker.descriptor.worker_public_key,
                process_identity: process,
                endpoint: world.worker.endpoint.as_text(),
                profile: WorkerProfile::HeadlessUser,
                state: SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            },
            Some(&DesktopBinding::none()),
        )
        .expect("the registry records the worker");
    std::fs::remove_file(world.worker.endpoint.as_path()).expect("the endpoint is taken away");
}

/// The identity of a process that has ended: one started, described while it ran, and ended.
fn the_identity_of_an_ended_process() -> ProcessStartIdentity {
    let mut child = std::process::Command::new("sleep")
        .arg("600")
        .spawn()
        .expect("a process starts");
    let identity = kr_ipc::identity::process_start_identity(child.id())
        .expect("a running process is described");
    child.kill().expect("the process is ended");
    child.wait().expect("the process is collected");
    identity
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

/// KR-REQ-09.12: a create whose worker ended before the create could describe the session, with no
/// closure recorded yet, is answered from the closure the daemon establishes for a worker the
/// kernel says has ended: the session closed, with no endpoint to attach to. A command that ends at
/// once takes its worker with it, and the create meets the worker's endpoint gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_worker_ended_before_it_was_described_is_answered_from_a_closure_for_it() {
    let (world, reservation) = reported().await;
    assert!(
        world
            .controller
            .registry
            .lock()
            .await
            .closure(world.session_id)
            .expect("the registry answers")
            .is_none(),
        "no closure is recorded"
    );
    gone(&world, &reservation, the_identity_of_an_ended_process()).await;

    assert_closed(&answered(&world, &reservation).await, &world);
}

/// KR-REQ-09.12: where no closure is established for a worker that cannot be reached, the create
/// fails as it did, with the failure of the connection. The worker here has no endpoint any more
/// and the kernel says its process is running, so nothing says its session ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_worker_cannot_be_reached_and_has_not_ended_fails_with_the_connection() {
    let (world, reservation) = reported().await;
    gone(
        &world,
        &reservation,
        kr_ipc::identity::current_process_start_identity().expect("this process is described"),
    )
    .await;

    let refused = answer(&world, &reservation)
        .await
        .expect_err("a worker that has not ended and cannot be reached leaves no answer");
    assert!(
        matches!(refused, ControllerError::Ipc(_)),
        "the failure names the connection: {refused:?}"
    );
    assert!(
        world
            .controller
            .registry
            .lock()
            .await
            .closure(world.session_id)
            .expect("the registry answers")
            .is_none(),
        "no closure was invented"
    );
}
