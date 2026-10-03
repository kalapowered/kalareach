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
use kr_protocol::ids::{AuthorityRevision, SessionId};

use super::a_close_a_worker_never_answers::Silent;
use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, closure_of, recorded, scripted};
use crate::authority::Round;

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

/// What a round that began while the worker ran says about it.
fn state_of(round: &Round<'_>, session_id: SessionId, revision: AuthorityRevision) -> BarrierState {
    round.report(revision, [session_id]).workers[0].state
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

/// Whether the closure has recorded and has done everything it does before the wait at `parked`,
/// which is what makes that wait the one it is at: the worker is out of the directory before the
/// wait for the connection table, and its connection is out of the table before the wait for the
/// presentations. Read with `try_lock`, because this test may be holding a lock and another task of
/// the daemon may be holding the one it asks for.
fn reached(parked: Parked, world: &Silent) -> bool {
    let out_of_the_directory = || {
        world
            .controller
            .directory
            .try_lock()
            .is_ok_and(|directory| directory.get(world.session_id).is_none())
    };
    let out_of_the_table = || {
        world
            .controller
            .connections
            .try_lock()
            .is_ok_and(|table| !table.contains_key(&world.session_id))
    };
    match parked {
        // Nothing is recorded while the registry is held, and the test holds it for the whole case.
        Parked::Registry => true,
        Parked::Directory => on_disk(world),
        Parked::Connections => on_disk(world) && out_of_the_directory(),
        Parked::Presentations => on_disk(world) && out_of_the_directory() && out_of_the_table(),
    }
}

/// How many times a test polls a closure that has not yet reached the lock it is held at before it
/// calls that a failure: a bound on a count of polls, never a wait for a time to pass.
const POLLS: usize = 10_000;

/// Records a closure and drops the future that records it while it waits at `parked`, and answers
/// whether the closure was recorded and what the barrier says about the worker afterwards.
///
/// The future is polled by hand until it has done everything it does before the wait at `parked`
/// ([`reached`]), so it is at that wait and no earlier one, and then dropped.
async fn cancelled_at(parked: Parked) -> (bool, BarrierState, usize) {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let record = closure_of(world.session_id);
    let revision = world.controller.leases.authority_revision();
    // A round that began while the worker ran, which is what holds an ended worker for it to report.
    let round = world.controller.leases.begin_round();
    // A link to the worker, so that its removal from the table is something to wait for.
    world.controller.connections.lock().await.insert(
        world.session_id,
        std::sync::Arc::new(tokio::sync::Mutex::new(None)),
    );
    let held: Box<dyn Send + '_> = match parked {
        Parked::Registry => Box::new(world.controller.registry.lock().await),
        Parked::Directory => Box::new(world.controller.directory.lock().await),
        Parked::Connections => Box::new(world.controller.connections.lock().await),
        Parked::Presentations => Box::new(world.controller.presentations.lock().await),
    };
    let mut closing = Box::pin(world.controller.retire(&record));
    let mut at_the_wait = false;
    for _ in 0..POLLS {
        let polled =
            std::future::poll_fn(|context| Poll::Ready(closing.as_mut().poll(context))).await;
        assert!(
            polled.is_pending(),
            "the closure waits at the {parked:?} lock the test holds"
        );
        if reached(parked, &world) {
            at_the_wait = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        at_the_wait,
        "the closure did not reach the {parked:?} wait in {POLLS} polls"
    );
    drop(closing);
    drop(held);
    let closed = recorded(&world).await;
    let state = state_of(&round, world.session_id, revision);
    // Once the round is over nothing can ask about an ended worker that named nothing.
    drop(round);
    let held = world.controller.leases.workers_held();
    world.serving.abort();
    (closed, state, held)
}

/// The control: a closure that is not dropped ends the worker, whichever way it is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_that_is_not_dropped_ends_the_worker() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let revision = world.controller.leases.authority_revision();
    let round = world.controller.leases.begin_round();
    assert_ne!(
        state_of(&round, world.session_id, revision),
        BarrierState::Ended
    );
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    assert!(recorded(&world).await);
    assert_eq!(
        state_of(&round, world.session_id, revision),
        BarrierState::Ended
    );
    drop(round);
    assert_eq!(world.controller.leases.workers_held(), 0);
    world.serving.abort();
}

/// A closure dropped before it is recorded leaves the worker as it was: nothing ended, nothing
/// recorded, and the worker still held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_before_it_is_recorded_ends_nothing() {
    let (closed, state, held) = cancelled_at(Parked::Registry).await;
    assert!(!closed);
    assert_ne!(state, BarrierState::Ended);
    assert_eq!(held, 1);
}

/// A closure that is recorded and then dropped, wherever it waits next, has told the barrier the
/// worker ended: a round that began while it ran reports it ended, and once that round is over
/// nothing of it is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_at_the_directory_has_ended_the_worker() {
    let (closed, state, held) = cancelled_at(Parked::Directory).await;
    assert!(closed);
    assert_eq!(state, BarrierState::Ended);
    assert_eq!(held, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_at_the_connections_has_ended_the_worker() {
    let (closed, state, held) = cancelled_at(Parked::Connections).await;
    assert!(closed);
    assert_eq!(state, BarrierState::Ended);
    assert_eq!(held, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_dropped_at_the_presentations_has_ended_the_worker() {
    let (closed, state, held) = cancelled_at(Parked::Presentations).await;
    assert!(closed);
    assert_eq!(state, BarrierState::Ended);
    assert_eq!(held, 0);
}
