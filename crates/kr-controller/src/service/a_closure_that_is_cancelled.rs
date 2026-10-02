//! A closure whose recording is dropped part way through.
//!
//! A closure is recorded under the registry's lock and the rest of what it does waits for other
//! locks: the directory, the connection table and the presentations. A request that stops waiting
//! while the closure is parked at one of those leaves the closure recorded and nothing to repeat
//! its tail, because a recorded closure is the answer to every later ask. What the barrier is told
//! must therefore be told in the section that records the closure, or a worker that has ended stays
//! pending for every revocation after it.

use std::future::Future;
use std::task::Poll;

use kr_protocol::action::BarrierState;
use kr_protocol::ids::SessionId;

use super::a_close_a_worker_never_answers::Silent;
use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, closure_of, recorded, scripted};

/// The lock a closure's recording is parked at.
#[derive(Clone, Copy, Debug)]
enum Parked {
    /// The registry, where the closure is recorded: nothing has been recorded when it is dropped.
    Registry,
    /// The worker directory, the first wait after the record is written.
    Directory,
    /// The table of connections to workers, the second.
    Connections,
    /// The presentations a create replays from, the third.
    Presentations,
}

/// What the barrier says about a session's worker.
fn state_of(controller: &crate::service::Controller, session_id: SessionId) -> BarrierState {
    let revision = controller.leases.authority_revision();
    controller.leases.report(revision, [session_id]).workers[0].state
}

/// Whether the registry's file holds the closure, read on a connection of this test's own: the
/// daemon's registry is behind a lock that this test may be holding, and another task of the
/// daemon may hold that lock while it waits for one this test holds.
fn on_disk(world: &Silent) -> bool {
    let database = world._temp.environment().registry_database();
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("the registry's file opens");
    connection
        .query_row(
            "SELECT COUNT(*) FROM tombstones WHERE session_id = ?1",
            [world.session_id.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the registry answers")
        > 0
}

/// How many times a test polls a closure that has not yet reached the lock it is held at before it
/// calls that a failure: a bound on a count of polls, never a wait for a time to pass.
const POLLS: usize = 10_000;

/// Records a closure and drops the future that records it while it waits at `parked`, and answers
/// whether the closure was recorded and what the barrier says about the worker afterwards.
///
/// The future is polled by hand until it has recorded the closure, and dropped at the wait it is
/// then at: the lock the test holds, unless another task of the daemon holds a lock the closure
/// needs for a moment, in which case it is an earlier wait after the record. Either way it is a wait
/// between the record and what is done once the closure is out.
async fn cancelled_at(parked: Parked) -> (bool, BarrierState) {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let record = closure_of(world.session_id);
    let held: Box<dyn Send + '_> = match parked {
        Parked::Registry => Box::new(world.controller.registry.lock().await),
        Parked::Directory => Box::new(world.controller.directory.lock().await),
        Parked::Connections => Box::new(world.controller.connections.lock().await),
        Parked::Presentations => Box::new(world.controller.presentations.lock().await),
    };
    let mut closing = Box::pin(world.controller.retire(&record));
    for _ in 0..POLLS {
        let polled =
            std::future::poll_fn(|context| Poll::Ready(closing.as_mut().poll(context))).await;
        assert!(
            polled.is_pending(),
            "the closure waits at the {parked:?} lock the test holds"
        );
        // Nothing is recorded while the registry is held, and it is held for the whole of this
        // case, so the one poll is the whole of it.
        if matches!(parked, Parked::Registry) || on_disk(&world) {
            break;
        }
        tokio::task::yield_now().await;
    }
    drop(closing);
    drop(held);
    let closed = recorded(&world).await;
    let state = state_of(&world.controller, world.session_id);
    world.serving.abort();
    (closed, state)
}

/// The control: a closure that is not dropped ends the worker, whichever way it is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_that_is_not_dropped_ends_the_worker() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    assert_ne!(
        state_of(&world.controller, world.session_id),
        BarrierState::Ended
    );
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    assert!(recorded(&world).await);
    assert_eq!(
        state_of(&world.controller, world.session_id),
        BarrierState::Ended
    );
    world.serving.abort();
}

/// A closure dropped before it is recorded leaves the worker as it was: nothing ended, nothing
/// recorded, and a later closure still ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_before_it_is_recorded_ends_nothing() {
    let (closed, state) = cancelled_at(Parked::Registry).await;
    assert!(!closed);
    assert_ne!(state, BarrierState::Ended);
}

/// A closure that is recorded and then dropped, wherever it waits next, has told the barrier the
/// worker ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_at_the_directory_has_ended_the_worker() {
    let (closed, state) = cancelled_at(Parked::Directory).await;
    assert!(closed);
    assert_eq!(state, BarrierState::Ended);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_at_the_connections_has_ended_the_worker() {
    let (closed, state) = cancelled_at(Parked::Connections).await;
    assert!(closed);
    assert_eq!(state, BarrierState::Ended);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_at_the_presentations_has_ended_the_worker() {
    let (closed, state) = cancelled_at(Parked::Presentations).await;
    assert!(closed);
    assert_eq!(state, BarrierState::Ended);
}
