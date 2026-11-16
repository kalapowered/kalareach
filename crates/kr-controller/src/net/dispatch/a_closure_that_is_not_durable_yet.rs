//! A worker's closure that its daemon has not recorded yet, at the daemon's two doors for a close.
//!
//! A worker answers a close with the closure it has, durable or volatile. That account is the
//! answer to the close, and the daemon keeps it as the worker gave it, with the word it gave, and
//! records it on a task of its own. A volatile closure keeps its word: until a durable record of
//! the session says otherwise, the registry, what the daemon holds and both doors say volatile.
//! The same close at either door, while the registry's write has not returned, is answered from
//! what the daemon holds, without reaching the worker again.

use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, Response};
use kr_protocol::ids::SessionEpoch;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Durability, SessionCloseParams, SessionCloseResult, SessionState};

use super::a_copy_from_a_services_record::{EVERY_RIGHT, mutation_of};
use super::write_boundary::paired_connection;
use crate::service::a_close_a_worker_never_answers::{self as fake, Silent};
use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

/// What the daemon answers a close at its local door with.
async fn closed_at_the_local_door(world: &Silent) -> SessionCloseResult {
    world
        .controller
        .session_close(
            &fake::close_request(world.environment_id, world.session_id),
            &world.actor,
            Some(world.accepted),
            fake::admission(&world.controller, world.accepted).await,
        )
        .await
        .into_answer_for_test()
        .expect("the close is answered")
        .to_typed()
        .expect("decodes")
}

/// What the daemon answers a close from a paired device with.
async fn closed_at_the_paired_door(
    world: &Silent,
    connection: &super::RemoteConnection,
    action: u64,
) -> SessionCloseResult {
    let mut close = mutation_of(
        world,
        connection,
        Method::SessionClose,
        action,
        kr_protocol::envelope::ParamsValue::from_typed(&SessionCloseParams {
            session_id: world.session_id,
        })
        .expect("encodes"),
    );
    close.target = ActionTarget {
        environment_id: world.environment_id,
        session_id: Nullable::some(world.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let answered = connection
        .answer_now(ControlFrame::Mutation(Box::new(close)))
        .await
        .expect("the close is answered");
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(value),
        ..
    }) = answered.frame()
    else {
        panic!(
            "the close is answered with a result: {:?}",
            answered.frame()
        );
    };
    value.to_typed().expect("decodes")
}

/// The record the daemon's registry holds of the session's closure, if it holds one.
async fn recorded_durability(world: &Silent) -> Option<Durability> {
    world
        .controller
        .registry
        .lock()
        .await
        .closure(world.session_id)
        .expect("the registry answers")
        .map(|closure| closure.durability)
}

/// Waits for what a task of the daemon does after the answer: the closure's record, and the
/// worker's leaving the directory with the links that end with it.
async fn until_recorded_and_retired(world: &Silent) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let retired = world
                .controller
                .directory
                .lock()
                .await
                .get(world.session_id)
                .is_none();
            if retired && recorded_durability(world).await.is_some() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the closure is recorded and the worker is retired");
}

/// A worker's closure, durable or volatile, is answered at once; while the registry's write of it
/// stands, the same close at the local door and from a paired device is answered with the closure
/// as the worker gave it, without reaching the worker; once the write is let go the registry holds
/// the record with the word the worker gave it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_whose_write_stands_is_answered_at_both_doors_and_recorded_as_it_was_given() {
    for volatile in [false, true] {
        let given = if volatile {
            Durability::Volatile
        } else {
            Durability::Durable
        };
        let script = Scripted::new();
        script.accepts_with_its_closure();
        script.its_closure_is_volatile(volatile);
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let (connection, _) = paired_connection(controller, 36, EVERY_RIGHT);
        let (arrived, release) = controller.stall_the_next_closure_write();

        let local = closed_at_the_local_door(&world).await;
        assert_eq!(local.durability, given, "{local:?}");
        tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await
        .expect("the wait for the write ends")
        .expect("the closure's write reaches the registry");
        let paired = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            closed_at_the_paired_door(&world, &connection, 91),
        )
        .await
        .expect("a close from a paired device is answered while the write stands");
        assert_eq!(
            (paired.state, paired.durability),
            (SessionState::Closed, given),
            "{paired:?}"
        );
        let again = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            closed_at_the_local_door(&world),
        )
        .await
        .expect("a close at the local door is answered while the write stands");
        assert_eq!(
            (again.state, again.durability),
            (SessionState::Closed, given),
            "{again:?}"
        );
        assert_eq!(
            script.forwarded().len(),
            1,
            "only the first close reaches the worker, volatile {volatile}"
        );
        release.send(()).expect("the write is let go");
        until_recorded_and_retired(&world).await;
        assert_eq!(
            recorded_durability(&world).await,
            Some(given),
            "the registry holds the closure with the word the worker gave it, volatile {volatile}"
        );
        world.serving.abort();
    }
}
