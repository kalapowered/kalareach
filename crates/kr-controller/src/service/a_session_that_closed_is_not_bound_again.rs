//! What this daemon makes of a session whose closure is recorded.
//!
//! A worker that has ended is no worker the daemon has any use to keep a record of in its barrier:
//! nothing can ask about it once the work that began while it ran is over, and a record made after
//! its closure would never be ended by anything. So a record is made only by a bind taken under the
//! registry's lock, and only for a session that has no closure there; the closure tells the
//! barrier in the section that records it, so the two cannot pass each other; a recovery that
//! reaches a worker after its closure leaves the closure as it is, and one that a closure overtakes
//! publishes nothing; no connection is opened to a worker whose session has closed; and a
//! revocation's answer is about the workers that are recorded and not closed.

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use crate::error::ControllerError;

/// How long a test waits for a real worker to answer before it calls that a failure. Nothing is
/// decided by it: the wait is on a condition, and a worker that never answers is the one thing that
/// runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// A session that has closed is not bound again, by either of the calls that bind: the worker has
/// ended, and a record of it would be one nothing could end. The control is the same session
/// before its closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_with_a_closure_is_not_bound() {
    let world = Served::recorded().await;
    assert!(
        world
            .controller
            .bind_worker(world.session_id)
            .await
            .expect("the registry answers")
            .is_some()
    );
    assert!(
        world
            .controller
            .binding_or_bind(world.session_id)
            .await
            .expect("the registry answers")
            .is_some()
    );
    assert_eq!(world.controller.leases.workers_held(), 1);

    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    assert_eq!(
        world.controller.leases.workers_held(),
        0,
        "the closure ended the worker and nothing was left to ask about it"
    );
    assert!(
        world
            .controller
            .bind_worker(world.session_id)
            .await
            .expect("the registry answers")
            .is_none()
    );
    assert!(
        world
            .controller
            .binding_or_bind(world.session_id)
            .await
            .expect("the registry answers")
            .is_none()
    );
    assert_eq!(world.controller.leases.workers_held(), 0);
}

/// Polls a future once and says it is waiting: for a test that wants two futures queued for one lock
/// in a known order, with nothing waited for but the lock.
async fn parked<F: Future + ?Sized>(mut future: std::pin::Pin<&mut F>, what: &str) {
    let polled = std::future::poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await;
    assert!(polled.is_pending(), "{what} waits for the registry");
}

/// A bind and a closure that wait for the registry together leave nothing held, whichever of them
/// the registry lets in first: a bind that comes first is ended by the closure in its own section,
/// and one that comes after sees the closure and binds nothing. Answers whether the bind bound.
async fn a_bind_and_a_closure_wait_together(bind_first: bool) -> bool {
    let world = Served::recorded().await;
    let record = closure_of(world.session_id);
    let registry = world.controller.registry.lock().await;
    let binding = world.controller.bind_worker(world.session_id);
    let closing = world.controller.write_closure(&record);
    tokio::pin!(binding, closing);
    // The lock is fair: they are let in in the order they asked.
    if bind_first {
        parked(binding.as_mut(), "the bind").await;
        parked(closing.as_mut(), "the closure").await;
    } else {
        parked(closing.as_mut(), "the closure").await;
        parked(binding.as_mut(), "the bind").await;
    }
    drop(registry);
    let (bound, closed) = tokio::join!(binding, closing);
    closed.expect("the closure is recorded");
    assert!(world.has_a_closure().await);
    assert_eq!(
        world.controller.leases.workers_held(),
        0,
        "nothing is held of a session whose closure is recorded"
    );
    bound.expect("the registry answers").is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bind_that_comes_before_a_closure_is_ended_by_it() {
    assert!(a_bind_and_a_closure_wait_together(true).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bind_that_comes_after_a_closure_binds_nothing() {
    assert!(!a_bind_and_a_closure_wait_together(false).await);
}

/// An exchange with a worker whose session has closed, found in the directory because the closure's
/// own tidying was dropped, makes no record of it, and says the session is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exchange_with_a_worker_whose_session_closed_makes_no_record() {
    let world = Served::recorded().await;
    world.controller.leases.worker_ended(world.session_id);
    assert_eq!(world.controller.leases.workers_held(), 0);
    world
        .controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(world.session_id))
        .expect("the closure is recorded");
    let refused = world
        .controller
        .acknowledge_worker_revision(world.session_id)
        .await
        .expect_err("a closed session has no worker to ask");
    assert!(matches!(refused, ControllerError::UnknownSession { .. }));
    assert_eq!(world.controller.leases.workers_held(), 0);
}

/// A closure lands while work that began before it waits for the registry: the worker is held for
/// that work until it is over, and forgotten then. Answers how many workers the barrier held while
/// the work waited and after it was done. The registry is held by the test, which records the
/// closure in it as a closure's own section does, so the work is at its first wait with its ticket.
async fn a_closure_lands_while_work_that_began_before_it_waits(exchange: bool) -> (usize, usize) {
    let world = Served::recorded().await;
    let session_id = world.session_id;
    let controller = std::sync::Arc::clone(&world.controller);
    let mut registry = world.controller.registry.lock().await;
    let mut work: std::pin::Pin<Box<dyn Future<Output = ()> + Send>> = if exchange {
        Box::pin(async move {
            let _ = controller.acknowledge_worker_revision(session_id).await;
        })
    } else {
        Box::pin(async move {
            let _ = controller.announce_authority_revision().await;
        })
    };
    parked(work.as_mut(), "the work").await;
    registry
        .record_closure(&closure_of(session_id))
        .expect("the closure is recorded");
    world.controller.leases.worker_ended(session_id);
    let during = world.controller.leases.workers_held();
    drop(registry);
    work.await;
    let after = world.controller.leases.workers_held();
    (during, after)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exchange_that_began_before_a_closure_holds_the_worker_until_it_is_over() {
    assert_eq!(
        a_closure_lands_while_work_that_began_before_it_waits(true).await,
        (1, 0)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_announcement_that_began_before_a_closure_holds_the_worker_until_it_is_over() {
    assert_eq!(
        a_closure_lands_while_work_that_began_before_it_waits(false).await,
        (1, 0)
    );
}

/// What a recovery has of a worker it challenged: the proof and the description the worker gave
/// of its session.
async fn challenged(
    world: &Served,
) -> (
    kr_protocol::worker::WorkerVerifyProof,
    Option<kr_protocol::session::SessionSummary>,
) {
    world
        .controller
        .challenge(
            &world.worker.endpoint,
            &world.worker.descriptor.worker_public_key,
            world.session_id,
        )
        .await
        .expect("the worker answers its challenge")
}

/// Adopts the worker on what a challenge of it gave.
async fn adopt(
    world: &Served,
    (proof, described): (
        kr_protocol::worker::WorkerVerifyProof,
        Option<kr_protocol::session::SessionSummary>,
    ),
) -> crate::error::Result<()> {
    let descriptor = &world.worker.descriptor;
    world
        .controller
        .adopt(
            descriptor.display_number,
            &descriptor.worker_public_key,
            &proof,
            &world.worker.endpoint,
            described,
        )
        .await
}

/// A recovery that reached a worker, and found its closure recorded while it waited for the
/// worker's answer, writes no row for it and publishes nothing. The control is the same adoption
/// before any closure, which writes the row and puts the worker in the directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adoption_after_a_closure_writes_no_row_and_publishes_nothing() {
    let world = Served::recorded().await;

    // The control.
    let answered = challenged(&world).await;
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    adopt(&world, answered)
        .await
        .expect("a worker that is not closed is adopted");
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_some()
    );

    // Closed while the challenge waited.
    let answered = challenged(&world).await;
    world
        .controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(world.session_id))
        .expect("the closure is recorded");
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    adopt(&world, answered)
        .await
        .expect("an adoption that finds the closure has nothing to do");
    assert!(
        world
            .controller
            .registry
            .lock()
            .await
            .workers()
            .expect("the registry answers")
            .is_empty(),
        "no row is written for a session that has closed"
    );
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_none()
    );
}

/// A row an earlier build's recovery left beside a closure is no worker: a revocation's answer
/// does not list it pending, so the revocation completes. The control is the same row with no
/// closure, a worker this daemon cannot reach and has not established is gone, which is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_beside_a_closure_does_not_keep_a_revocation_pending() {
    let world = Served::recorded().await;
    // The daemon has not reached the worker: nothing in its directory, the row in its registry.
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    let control = world
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement is made");
    assert!(!control.holds(), "{control:?}");
    assert_eq!(control.pending(), vec![world.session_id]);

    // The closure, and then the row an earlier recovery wrote after it.
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    world
        .controller
        .registry
        .lock()
        .await
        .adopt_worker(
            &world.row(),
            Some(&kr_protocol::identity::DesktopBinding::none()),
        )
        .expect("the stale row is written");
    assert_eq!(
        world
            .controller
            .registry
            .lock()
            .await
            .workers()
            .expect("the registry answers")
            .len(),
        1
    );
    let report = world
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement is made");
    assert!(report.holds(), "{report:?}");
    assert!(report.workers.is_empty(), "{report:?}");
    assert_eq!(world.controller.leases.workers_held(), 0);
}

/// What the daemon holds of the session's worker: its entry in the directory, its slot in the
/// connection table, its place in the set the plugin admissions wait for, and its published
/// descriptor. The locks are taken, so the answer is never that something could not be read.
pub(super) async fn held_by_the_daemon(world: &Served) -> [bool; 4] {
    let in_the_directory = world
        .controller
        .directory
        .lock()
        .await
        .get(world.session_id)
        .is_some();
    let has_a_slot = world
        .controller
        .connections
        .lock()
        .await
        .contains_key(&world.session_id);
    [
        in_the_directory,
        has_a_slot,
        world.controller.plugin_bridge.holds(world.session_id),
        kr_ipc::descriptor::read(world.controller.paths(), world.session_id)
            .expect("the descriptor directory reads")
            .is_some(),
    ]
}

/// Starts an adoption of a real worker on a task of its own, on the proof and the description the
/// worker gave to a challenge, and holds it where it has recorded the worker and not yet published
/// it. The daemon has not reached the worker before that: nothing is in its directory.
async fn an_adoption_held_before_its_publication(
    world: &Served,
) -> (
    tokio::task::JoinHandle<crate::error::Result<()>>,
    tokio::sync::oneshot::Sender<()>,
) {
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    let descriptor = world.worker.descriptor.clone();
    let (proof, described) = world
        .controller
        .challenge(
            &world.worker.endpoint,
            &descriptor.worker_public_key,
            world.session_id,
        )
        .await
        .expect("the worker answers its challenge");
    let (arrived, go) = world.controller.before_a_worker_is_published.arm();
    let endpoint = world.worker.endpoint.clone();
    let controller = std::sync::Arc::clone(&world.controller);
    let adopting = tokio::spawn(async move {
        controller
            .adopt(
                descriptor.display_number,
                &descriptor.worker_public_key,
                &proof,
                &endpoint,
                described,
            )
            .await
    });
    arrived.await.expect("the adoption reaches its publication");
    (adopting, go)
}

/// KR-REQ-09.12: a worker whose row is recorded and that is not yet published is pending in a
/// revocation, never absent from it: the barrier's members are the registry's, which an adoption
/// writes before it publishes anything a dispatch could reach the worker through. The worker is one
/// this daemon has not reached, as after a start that found it running: the lease issuer holds
/// nothing of it, so the registry's row is the only thing that makes it a member. Once the adoption
/// has published the worker it is held in every place the daemon holds a worker, and the next
/// revocation reaches it and holds when it has acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_recorded_and_not_yet_published_is_pending_in_a_revocation() {
    let world = Served::start().await;
    world.controller.leases.worker_ended(world.session_id);
    assert_eq!(world.controller.leases.workers_held(), 0);
    let (adopting, go) = an_adoption_held_before_its_publication(&world).await;
    assert_eq!(held_by_the_daemon(&world).await, [false; 4]);
    assert_eq!(world.controller.leases.workers_held(), 0);

    let barrier = world
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is raised");
    assert!(!barrier.holds(), "{barrier:?}");
    assert_eq!(barrier.pending(), vec![world.session_id]);

    go.send(()).expect("the adoption is waiting");
    adopting
        .await
        .expect("the adoption's task ends")
        .expect("the adoption is made");
    // Its slot in the connection table is not asked for: the plugin admissions are woken by the
    // publication, and a round they send is entitled to open it.
    let [in_the_directory, _, in_the_admissions, described] = held_by_the_daemon(&world).await;
    assert!(in_the_directory && in_the_admissions && described);
    // The worker answers within the bound an announcement gives it, or the next announcement is
    // the one that reaches it: a round the publication woke may be holding its connection.
    let held = tokio::time::timeout(WAIT, async {
        loop {
            let barrier = world
                .controller
                .announce_authority_revision()
                .await
                .expect("the announcement is made");
            if barrier.holds() {
                return barrier;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        held.is_ok(),
        "the revocation holds once the worker has answered"
    );
}

/// KR-REQ-09.12: an adoption that a closure overtakes between its row and its publication
/// publishes nothing: no directory entry, no descriptor, no place in the plugin admissions' set,
/// and the revocation that follows holds with no worker to wait for. The control is the same
/// adoption with no closure, above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adoption_that_a_closure_overtakes_publishes_nothing() {
    let world = Served::start().await;
    let (adopting, go) = an_adoption_held_before_its_publication(&world).await;

    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    go.send(()).expect("the adoption is waiting");
    adopting
        .await
        .expect("the adoption's task ends")
        .expect("an adoption that finds the closure has nothing to do");

    // Nothing of it is held, and no reclaim that needs room waits for a worker that will not
    // report.
    assert_eq!(held_by_the_daemon(&world).await, [false; 4]);
    assert!(
        world
            .controller
            .pending_admissions()
            .await
            .expect("the catalogue's revision is read")
            .is_empty()
    );
    let report = world
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement is made");
    assert!(report.holds(), "{report:?}");
    assert!(report.workers.is_empty(), "{report:?}");
}

/// KR-REQ-09.12: a worker's descriptor is written while the registry is held by another operation,
/// as a closure's section holds it, so the write, which waits for the disk, is not spent holding
/// every admitted request back; and where the closure lands in the meantime, the publication finds
/// it and takes the descriptor away again, so nothing is left of the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_is_written_without_the_registry_and_taken_away_when_a_closure_lands() {
    let world = Served::recorded().await;
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    let mut registry = world.controller.registry.lock().await;
    let publishing = tokio::spawn({
        let controller = std::sync::Arc::clone(&world.controller);
        let worker = world.worker.clone();
        async move { controller.publish_worker(worker, None).await }
    });
    let written = tokio::time::timeout(WAIT, async {
        while kr_ipc::descriptor::read(world.controller.paths(), world.session_id)
            .expect("the descriptor directory reads")
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        written.is_ok(),
        "the descriptor is written while the registry is held"
    );

    registry
        .record_closure(&closure_of(world.session_id))
        .expect("the closure is recorded");
    world.controller.leases.worker_ended(world.session_id);
    drop(registry);
    publishing
        .await
        .expect("the publication's task ends")
        .expect("a publication that finds the closure has nothing to do");
    assert_eq!(held_by_the_daemon(&world).await, [false; 4]);
}

/// KR-REQ-09.12: a publication whose request stops waiting once the descriptor is written, after
/// the session's closure has finished, leaves no descriptor: nothing but the publication would
/// remove it, since the closure's own tidying has run, and a start that found it would find no row
/// to repair it by.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publication_that_is_cancelled_leaves_no_descriptor_of_a_closed_session() {
    let world = Served::recorded().await;
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded and its tidying has run");
    let registry = world.controller.registry.lock().await;
    let publishing = tokio::spawn({
        let controller = std::sync::Arc::clone(&world.controller);
        let worker = world.worker.clone();
        async move { controller.publish_worker(worker, None).await }
    });
    let written = tokio::time::timeout(WAIT, async {
        while kr_ipc::descriptor::read(world.controller.paths(), world.session_id)
            .expect("the descriptor directory reads")
            .is_none()
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        written.is_ok(),
        "the descriptor is written while the registry is held"
    );

    // The request stops waiting at the registry, after the descriptor is written.
    publishing.abort();
    assert!(
        publishing
            .await
            .expect_err("the request was cancelled")
            .is_cancelled()
    );
    drop(registry);
    let gone = tokio::time::timeout(WAIT, async {
        while kr_ipc::descriptor::read(world.controller.paths(), world.session_id)
            .expect("the descriptor directory reads")
            .is_some()
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(gone.is_ok(), "no descriptor is left for the closed session");
    assert_eq!(held_by_the_daemon(&world).await, [false; 4]);
}

/// KR-REQ-09.12: a publication for a session that has closed has nothing to do, even where the
/// write of the descriptor it would then remove reports a failure: the closure is looked at first,
/// since a write can fail after the file has its name and leave a descriptor that nothing else
/// would remove. Here the directory takes no new file; where it does anyway (a user that is not
/// held to file modes) the write cannot fail and there is nothing to show.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publication_for_a_closed_session_does_not_fail_on_the_descriptor_it_would_remove() {
    use std::os::unix::fs::PermissionsExt as _;

    /// Gives the directory its modes back, whatever becomes of the test.
    struct Restore(std::path::PathBuf, std::fs::Permissions);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, self.1.clone());
        }
    }

    let world = Served::recorded().await;
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded and its tidying has run");
    let descriptors = world.controller.paths().descriptors_dir();
    let modes = std::fs::metadata(&descriptors)
        .expect("the descriptors' directory exists")
        .permissions();
    let _restore = Restore(descriptors.clone(), modes);
    std::fs::set_permissions(&descriptors, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made read only");
    let probe = descriptors.join(".probe");
    if std::fs::File::create(&probe).is_ok() {
        let _ = std::fs::remove_file(&probe);
        return;
    }

    world
        .controller
        .publish_worker(world.worker.clone(), None)
        .await
        .expect("a publication for a closed session has nothing to do");
    assert_eq!(held_by_the_daemon(&world).await, [false; 4]);
}

/// No connection is opened to a worker whose session has closed, by a caller that took the worker
/// from the directory before the closure and asks for its connection after it: the caller is told
/// the session is unknown and the connection table holds nothing for it. The control is the same
/// call before the closure, which gives the link and keeps its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_connection_is_opened_to_a_worker_whose_session_closed() {
    let world = Served::start().await;
    let stale = world.worker.clone();

    let mut link = world
        .controller
        .worker_client(&stale)
        .await
        .expect("a worker that is not closed is given its link");
    link.give_back();
    drop(link);
    assert!(
        world
            .controller
            .connections
            .lock()
            .await
            .contains_key(&world.session_id)
    );

    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    let refused = world
        .controller
        .worker_client(&stale)
        .await
        .expect_err("a worker whose session closed is given no link");
    assert!(matches!(refused, ControllerError::UnknownSession { .. }));
    assert!(
        !world
            .controller
            .connections
            .lock()
            .await
            .contains_key(&world.session_id),
        "the connection table holds nothing for a closed session"
    );
}
