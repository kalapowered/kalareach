//! A worker's volatile closure, at the daemon's two doors for a close.
//!
//! A worker that has drained its session and has not yet written its durable closure answers a
//! close with the closure it has, volatile. That account is the answer to the close, and it does
//! not stand in for the durable one: the daemon keeps it without recording it, keeps the worker
//! and its links, and records the durable closure when the worker gives it. The same close at
//! either door, before the worker's storage returns, is answered as often as it is sent.

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

/// A worker that answers a close with a durable closure is recorded durably, and one that answers
/// with its volatile closure is not recorded until it gives the durable one: before then, the same
/// close at the local door and from a paired device is answered with the volatile closure each time
/// it is sent, the worker is still in the directory, and the close reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_volatile_closure_is_answered_at_both_doors_and_the_durable_one_is_recorded_when_it_comes()
 {
    for volatile_first in [false, true] {
        let script = Scripted::new();
        script.accepts_with_its_closure();
        script.its_closure_is_volatile(volatile_first);
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let (connection, _) = paired_connection(controller, 36, EVERY_RIGHT);

        if volatile_first {
            let local = closed_at_the_local_door(&world).await;
            assert_eq!(local.state, SessionState::Closing, "{local:?}");
            assert_eq!(local.durability, Durability::Volatile, "{local:?}");
            let paired = closed_at_the_paired_door(&world, &connection, 91).await;
            assert_eq!(paired.durability, Durability::Volatile, "{paired:?}");
            let again = closed_at_the_local_door(&world).await;
            assert_eq!(again.durability, Durability::Volatile, "{again:?}");
            assert_eq!(
                script.forwarded().len(),
                3,
                "each close of a session whose closure is volatile reaches the worker"
            );
            assert_eq!(
                recorded_durability(&world).await,
                None,
                "a volatile closure is not recorded"
            );
            assert!(
                controller
                    .directory
                    .lock()
                    .await
                    .get(world.session_id)
                    .is_some(),
                "the worker stays in the directory until its durable closure is collected"
            );
            script.its_closure_is_volatile(false);
        }

        let collected = closed_at_the_local_door(&world).await;
        assert_eq!(collected.durability, Durability::Durable, "{collected:?}");
        until_recorded_and_retired(&world).await;
        assert_eq!(
            recorded_durability(&world).await,
            Some(Durability::Durable),
            "the closure the daemon holds is the durable one, volatile first: {volatile_first}"
        );
        world.serving.abort();
    }
}
