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

/// What the daemon answers a close at its local door with. The admission is taken by the caller,
/// because it reads the registry.
async fn closed_at_the_local_door(
    world: &Silent,
    carried: crate::authority::AdmittedMutation,
) -> SessionCloseResult {
    world
        .controller
        .session_close(
            &fake::close_request(world.environment_id, world.session_id),
            &world.actor,
            Some(world.accepted),
            carried,
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

/// A worker's closure, durable or volatile, is answered at once to a close from a paired device,
/// while the registry's write of it stands; the same close at the local door is then answered with
/// the closure as the worker gave it, without reaching the worker; once the write is let go the
/// registry holds the record with the word the worker gave it.
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
        // The admission of a close at the local door reads the registry, which the stalled write
        // holds.
        let carried = fake::admission(controller, world.accepted).await;
        let (arrived, release) = controller.stall_the_next_closure_write();

        let paired = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            closed_at_the_paired_door(&world, &connection, 91),
        )
        .await;
        let reached = tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await;
        let local = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            closed_at_the_local_door(&world, carried),
        )
        .await;
        let forwarded = script.forwarded().len();
        // Let go before any assertion, so that a close that was not answered does not hold the
        // program with the write that stands.
        let _ = release.send(());
        let paired = paired.expect(
            "a close from a paired device is answered while the write of its closure stands",
        );
        reached
            .expect("the wait for the write ends")
            .expect("the closure's write reaches the registry");
        let local = local.expect("a close at the local door is answered while the write stands");
        assert_eq!(paired.durability, given, "{paired:?}");
        assert_eq!(
            (local.state, local.durability),
            (SessionState::Closed, given),
            "{local:?}"
        );
        assert_eq!(
            forwarded, 1,
            "only the first close reaches the worker, volatile {volatile}"
        );
        until_recorded_and_retired(&world).await;
        assert_eq!(
            recorded_durability(&world).await,
            Some(given),
            "the registry holds the closure with the word the worker gave it, volatile {volatile}"
        );
        world.serving.abort();
    }
}

/// A worker's closure that its daemon has not recorded is the answer to a close at either door
/// after the worker has stopped accepting connections: the daemon does not reach for a worker that
/// would refuse it, and answers from what it knows, with the word the worker gave.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_after_the_worker_stopped_accepting_is_answered_from_what_the_daemon_knows() {
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
        let registry = || {
            rusqlite::Connection::open(controller.paths.registry_database())
                .expect("the registry opens beside the daemon's own handle")
        };
        registry()
            .execute_batch(
                "CREATE TRIGGER the_closure_is_not_kept BEFORE INSERT ON tombstones
                 BEGIN SELECT RAISE(ABORT, 'the registry keeps no closure'); END;",
            )
            .expect("the registry is made to refuse the write that records a closure");

        let first =
            closed_at_the_local_door(&world, fake::admission(controller, world.accepted).await)
                .await;
        assert_eq!(first.durability, given, "{first:?}");
        world.serving.abort();

        let local =
            closed_at_the_local_door(&world, fake::admission(controller, world.accepted).await)
                .await;
        assert_eq!(
            (local.state, local.durability),
            (SessionState::Closed, given),
            "{local:?}"
        );
        let paired = closed_at_the_paired_door(&world, &connection, 91).await;
        assert_eq!(
            (paired.state, paired.durability),
            (SessionState::Closed, given),
            "{paired:?}"
        );
        assert_eq!(
            script.forwarded().len(),
            1,
            "the closes after the first are answered without reaching the worker, volatile \
             {volatile}"
        );

        registry()
            .execute_batch("DROP TRIGGER the_closure_is_not_kept;")
            .expect("the registry takes a closure again");
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            // A close asks for the write again; the write's own retries may be spent.
            while recorded_durability(&world).await.is_none() {
                closed_at_the_local_door(&world, fake::admission(controller, world.accepted).await)
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the closure is recorded once the registry takes it");
        assert_eq!(recorded_durability(&world).await, Some(given));
        world.serving.abort();
    }
}

/// A paired device's repeat of a close records the account that this daemon knows, where the worker
/// has left the directory with its account not written and nothing else writes it: the device's
/// door asks what the daemon knows before it asks the directory, so the write that failed is made
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_from_a_paired_device_records_the_account_of_a_worker_that_left_the_directory() {
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
        let registry = || {
            rusqlite::Connection::open(controller.paths.registry_database())
                .expect("the registry opens beside the daemon's own handle")
        };
        registry()
            .execute_batch(
                "CREATE TRIGGER the_closure_is_not_kept BEFORE INSERT ON tombstones
                 BEGIN SELECT RAISE(ABORT, 'the registry keeps no closure'); END;",
            )
            .expect("the registry is made to refuse the write that records a closure");
        // The admission of a close at the local door reads the registry, which the stalled write
        // holds.
        let carried = fake::admission(controller, world.accepted).await;
        let (arrived, release) = controller.stall_the_next_closure_write();
        let first = closed_at_the_local_door(&world, carried).await;
        let reached = tokio::task::spawn_blocking(move || {
            arrived.recv_timeout(std::time::Duration::from_secs(30))
        })
        .await;
        // Let go before any assertion, so that a write that did not arrive holds nothing.
        let _ = release.send(());
        reached
            .expect("the wait for the write ends")
            .expect("the closure's write reaches the registry");
        // The write holds the registry's lock until the registry has answered it: the lock is
        // taken once the write is over, and finds that it was refused.
        let held = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            controller.registry.lock(),
        )
        .await
        .expect("the registry is free once its write has been refused");
        assert!(
            held.closure(world.session_id)
                .expect("the registry answers")
                .is_none(),
            "the first write of the account was refused: the registry holds no closure"
        );
        drop(held);
        assert_eq!(first.durability, given, "{first:?}");

        // The worker leaves the directory with its account not written, and the registry takes a
        // closure again. Only a repeat from the paired device is asked from here on.
        controller.forget_worker_for_tests(world.session_id).await;
        registry()
            .execute_batch("DROP TRIGGER the_closure_is_not_kept;")
            .expect("the registry takes a closure again");
        let mut action = 91;
        let asked = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let paired = closed_at_the_paired_door(&world, &connection, action).await;
                assert_eq!(
                    (paired.state, paired.durability),
                    (SessionState::Closed, given),
                    "{paired:?}"
                );
                if recorded_durability(&world).await.is_some() {
                    return;
                }
                action += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await;
        asked.expect("a repeat from a paired device records the account the daemon knows");
        assert_eq!(recorded_durability(&world).await, Some(given));
        world.serving.abort();
    }
}
