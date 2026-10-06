//! A closure whose recording is dropped part way through.
//!
//! A closure is recorded under the registry's lock and the rest of what it does waits for other
//! locks: the directory, the connection table and the presentations. A request that stops waiting
//! while the closure is parked at one of those leaves the closure recorded and nothing to repeat
//! its tail, because a recorded closure is the answer to every later ask. So what the barrier is
//! told is told in the section that records the closure, and the tail runs to its end on a task
//! of its own, whatever becomes of the request that began it: a worker that has ended neither
//! stays pending for every revocation after it nor stays in what this daemon holds of its
//! workers.

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use kr_protocol::action::BarrierState;
use kr_protocol::identity::DesktopBinding;
use kr_protocol::ids::{AuthorityRevision, SessionId};

use super::LeaseDenied;
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use super::the_fence_at_every_effect::a_paired_device;
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
pub(super) fn on_disk(world: &Served) -> bool {
    let database = world.controller.paths().registry_database();
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
fn reached(parked: Parked, world: &Served) -> bool {
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

/// How long a test waits for the daemon's own task to get where the test expects it before it
/// calls that a failure. Nothing is decided by it: the waits are on conditions, and a task that
/// never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// Waits until `condition` holds, polling it between yields to the other tasks of the runtime.
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let waited = tokio::time::timeout(WAIT, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(waited.is_ok(), "{what}");
}

/// Whether the daemon still holds the session's worker in its directory, its connection table, the
/// set of workers the plugin admissions wait for, and the descriptors it published. Read with
/// `try_lock`, because another task of the daemon may be holding a lock for a moment.
fn held_of(world: &Served) -> Option<[bool; 4]> {
    let directory = world.controller.directory.try_lock().ok()?;
    let connections = world.controller.connections.try_lock().ok()?;
    Some([
        directory.get(world.session_id).is_some(),
        connections.contains_key(&world.session_id),
        world.controller.plugin_bridge.holds(world.session_id),
        kr_ipc::descriptor::read(world.controller.paths(), world.session_id)
            .expect("the descriptor directory reads")
            .is_some(),
    ])
}

/// A revocation holds with no worker for the session to wait for.
async fn assert_revocation_holds_without(world: &Served) {
    let report = world
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement is made");
    assert!(report.holds(), "{report:?}");
    assert!(report.workers.is_empty(), "{report:?}");
}

/// A paired device is given no dispatch lease for the session's worker, whatever the daemon still
/// holds of it.
async fn assert_no_lease(world: &Served) {
    let device = a_paired_device(&world.controller);
    assert!(matches!(
        world
            .controller
            .dispatch_lease(world.session_id, &device)
            .await,
        Err(LeaseDenied::NotAcknowledged(_))
    ));
}

/// Records a closure of a daemon's session with a real worker and drops the future that records it
/// while it waits at `parked`, and answers whether the closure was recorded and what the barrier
/// says about the worker afterwards. The closure is the daemon's own record, as when it finds a
/// worker gone; the worker here keeps running.
///
/// The future is polled by hand until the closure has done everything it does before the wait at
/// `parked` ([`reached`]), so it is at that wait and no earlier one, and then dropped. While the
/// tail is held there, and again once it has run, a revocation holds without the worker and a
/// paired device's lease for it is refused. What the daemon holds of the worker is read once the
/// locks are let go: the whole of it where the closure was never recorded, and none of it where it
/// was, since the tail does not need the request that began it.
async fn cancelled_at(parked: Parked) -> (bool, BarrierState, usize) {
    let world = Served::start().await;
    let record = closure_of(world.session_id);
    let revision = world.controller.leases.authority_revision();
    // A round that began while the worker ran, which is what holds an ended worker for it to report.
    let round = world.controller.leases.begin_round();
    // The worker as this daemon holds it once it has published it: a link, a descriptor, a place in
    // the plugin admissions' set.
    world.controller.connections.lock().await.insert(
        world.session_id,
        std::sync::Arc::new(tokio::sync::Mutex::new(None)),
    );
    kr_ipc::descriptor::publish(world.controller.paths(), &world.worker.descriptor)
        .expect("the descriptor is published");
    // And the registry's row for it, which is what a revocation's members are read from and what
    // the closure takes out.
    world
        .controller
        .registry
        .lock()
        .await
        .adopt_worker(&world.row(), Some(&DesktopBinding::none()))
        .expect("the registry records the worker");
    world.controller.plugin_bridge.recorded(
        world.session_id,
        world.worker.descriptor.process_start_identity.clone(),
    );
    until("the daemon holds the worker in all four places", || {
        held_of(&world) == Some([true; 4])
    })
    .await;
    let held: Box<dyn Send + '_> = match parked {
        Parked::Registry => Box::new(world.controller.registry.lock().await),
        Parked::Directory => Box::new(world.controller.directory.lock().await),
        Parked::Connections => Box::new(world.controller.connections.lock().await),
        Parked::Presentations => Box::new(world.controller.presentations.lock().await),
    };
    let mut closing = Box::pin(world.controller.retire(&record));
    let mut at_the_wait = false;
    let reaching = async {
        while !at_the_wait {
            let polled =
                std::future::poll_fn(|context| Poll::Ready(closing.as_mut().poll(context))).await;
            assert!(
                polled.is_pending(),
                "the closure waits at the {parked:?} lock the test holds"
            );
            at_the_wait = reached(parked, &world);
            tokio::task::yield_now().await;
        }
    };
    assert!(
        tokio::time::timeout(WAIT, reaching).await.is_ok(),
        "the closure did not reach the {parked:?} wait"
    );
    // The closure is recorded wherever it waits after the registry, and nothing is while it waits
    // for the registry. With its tail still held at the wait, a worker that ended is already sent
    // no lease, and a revocation already holds without it: the announcement reads the directory, so
    // where the tail waits for that, it is made once the lock is let go.
    let recorded_by_now = !matches!(parked, Parked::Registry);
    if recorded_by_now {
        assert_eq!(
            state_of(&round, world.session_id, revision),
            BarrierState::Ended
        );
        assert_no_lease(&world).await;
        if !matches!(parked, Parked::Directory) {
            assert_revocation_holds_without(&world).await;
        }
    }
    drop(closing);
    drop(held);
    let closed = world
        .controller
        .registry
        .lock()
        .await
        .closure(world.session_id)
        .expect("the registry answers")
        .is_some();
    assert_eq!(closed, recorded_by_now);
    // What the closure left of the worker: all of it where nothing was recorded, and none of it
    // once the closure's own task has run to its end.
    until(
        "the daemon's view of the worker is as the closure leaves it",
        || held_of(&world) == Some(if closed { [false; 4] } else { [true; 4] }),
    )
    .await;
    if closed {
        assert_revocation_holds_without(&world).await;
        assert_no_lease(&world).await;
    }
    let state = state_of(&round, world.session_id, revision);
    // Once the round is over nothing can ask about an ended worker that named nothing.
    drop(round);
    let held = world.controller.leases.workers_held();
    (closed, state, held)
}

/// The control: a closure that is not dropped ends the worker, whichever way it is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closure_that_is_not_dropped_ends_the_worker() {
    let world = Served::recorded().await;
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
    assert!(world.has_a_closure().await);
    assert_eq!(
        state_of(&round, world.session_id, revision),
        BarrierState::Ended
    );
    drop(round);
    assert_eq!(world.controller.leases.workers_held(), 0);
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

/// KR-REQ-09.12: a closure that is recorded and then dropped, wherever it waits next, has told the
/// barrier the worker ended: a round that began while it ran reports it ended, once that round is
/// over nothing of it is held, a revocation holds without it, and no lease is issued for it. The
/// closure's own task has taken the worker out of everything else this daemon held of it.
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
