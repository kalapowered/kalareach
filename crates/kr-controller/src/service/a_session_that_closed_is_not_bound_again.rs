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

use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::AuthorityRevision;
use kr_protocol::session::SessionState;

use super::a_close_a_worker_never_answers::Silent;
use super::a_read_that_meets_a_worker_on_its_way_out::{Scripted, closure_of, recorded, scripted};
use crate::error::ControllerError;
use crate::registry::WorkerRecord;

/// The registry's row for a world's worker, as an earlier build's recovery wrote it.
fn row_of(world: &Silent) -> WorkerRecord {
    let descriptor = &world.worker.descriptor;
    WorkerRecord {
        session_id: world.session_id,
        display_number: descriptor.display_number,
        public_key: descriptor.worker_public_key,
        process_identity: descriptor.process_start_identity.clone(),
        endpoint: descriptor.endpoint.clone(),
        profile: WorkerProfile::HeadlessUser,
        state: SessionState::Live,
        acknowledged_revision: AuthorityRevision::new(0),
    }
}

/// A session that has closed is not bound again, by either of the calls that bind: the worker has
/// ended, and a record of it would be one nothing could end. The control is the same session
/// before its closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_with_a_closure_is_not_bound() {
    let script = Scripted::new();
    let world = scripted(&script).await;
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
    world.serving.abort();
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
    let script = Scripted::new();
    let world = scripted(&script).await;
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
    assert!(recorded(&world).await);
    assert_eq!(
        world.controller.leases.workers_held(),
        0,
        "nothing is held of a session whose closure is recorded"
    );
    world.serving.abort();
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
    let script = Scripted::new();
    let world = scripted(&script).await;
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
    world.serving.abort();
}

/// A closure lands while work that began before it waits for the registry: the worker is held for
/// that work until it is over, and forgotten then. Answers how many workers the barrier held while
/// the work waited and after it was done. The registry is held by the test, which records the
/// closure in it as a closure's own section does, so the work is at its first wait with its ticket.
async fn a_closure_lands_while_work_that_began_before_it_waits(exchange: bool) -> (usize, usize) {
    let script = Scripted::new();
    let world = scripted(&script).await;
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
    world.serving.abort();
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

/// The proof a worker's challenge answers with, as far as an adoption reads it.
fn a_proof_of(world: &Silent) -> kr_protocol::worker::WorkerVerifyProof {
    let descriptor = &world.worker.descriptor;
    kr_protocol::worker::WorkerVerifyProof {
        session_id: descriptor.session_id,
        session_epoch: descriptor.session_epoch,
        boot_identity: descriptor.boot_identity.clone(),
        process_start_identity: descriptor.process_start_identity.clone(),
        protocol_version: descriptor.protocol_version,
        endpoint: descriptor.endpoint.clone(),
        signature: kr_protocol::scalars::Signature64::from_bytes([0; 64]),
    }
}

/// A recovery that reached a worker, and found its closure recorded while it waited for the
/// worker's answer, writes no row for it and publishes nothing. The control is the same adoption
/// before any closure, which writes the row and puts the worker in the directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adoption_after_a_closure_writes_no_row_and_publishes_nothing() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let descriptor = world.worker.descriptor.clone();
    let proof = a_proof_of(&world);
    let adopt = |controller: std::sync::Arc<crate::service::Controller>| {
        let (descriptor, proof, endpoint) = (
            descriptor.clone(),
            proof.clone(),
            world.worker.endpoint.clone(),
        );
        async move {
            controller
                .adopt(
                    descriptor.display_number,
                    &descriptor.worker_public_key,
                    &proof,
                    &endpoint,
                    None,
                )
                .await
        }
    };

    // The control.
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    adopt(std::sync::Arc::clone(&world.controller))
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
    adopt(std::sync::Arc::clone(&world.controller))
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
    world.serving.abort();
}

/// A row an earlier build's recovery left beside a closure is no worker: a revocation's answer
/// does not list it pending, so the revocation completes. The control is the same row with no
/// closure, a worker this daemon cannot reach and has not established is gone, which is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_beside_a_closure_does_not_keep_a_revocation_pending() {
    let script = Scripted::new();
    let world = scripted(&script).await;
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
            &row_of(&world),
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
    world.serving.abort();
}

/// Starts an adoption of the world's worker on a task of its own, and holds it where it has
/// recorded the worker and not yet published it. The daemon has not reached the worker before
/// that: nothing is in its directory.
async fn an_adoption_held_before_its_publication(
    world: &Silent,
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
    let (arrived, go) = world.controller.before_a_worker_is_published.arm();
    let descriptor = world.worker.descriptor.clone();
    let proof = a_proof_of(world);
    let endpoint = world.worker.endpoint.clone();
    let controller = std::sync::Arc::clone(&world.controller);
    let adopting = tokio::spawn(async move {
        controller
            .adopt(
                descriptor.display_number,
                &descriptor.worker_public_key,
                &proof,
                &endpoint,
                None,
            )
            .await
    });
    arrived.await.expect("the adoption reaches its publication");
    (adopting, go)
}

/// KR-REQ-09.12: a worker whose row is recorded and that is not yet published is pending in a
/// revocation, never absent from it: the barrier's members are the registry's, which an adoption
/// writes before it publishes anything a dispatch could reach the worker through. Once the adoption
/// has published the worker it is held in every place the daemon holds a worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_recorded_and_not_yet_published_is_pending_in_a_revocation() {
    let script = Scripted::new();
    let world = scripted(&script).await;
    let (adopting, go) = an_adoption_held_before_its_publication(&world).await;
    assert_eq!(
        super::a_closure_that_is_cancelled::held_of(&world),
        Some([false; 4])
    );

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
    assert_eq!(
        super::a_closure_that_is_cancelled::held_of(&world),
        Some([true, false, true, true])
    );
    world.serving.abort();
}

/// KR-REQ-09.12: an adoption that a closure overtakes between its row and its publication
/// publishes nothing: no directory entry, no descriptor, no place in the plugin admissions' set,
/// and the revocation that follows holds with no worker to wait for. The control is the same
/// adoption with no closure, above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adoption_that_a_closure_overtakes_publishes_nothing() {
    let script = Scripted::new();
    let world = scripted(&script).await;
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

    assert_eq!(
        super::a_closure_that_is_cancelled::held_of(&world),
        Some([false; 4])
    );
    let report = world
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement is made");
    assert!(report.holds(), "{report:?}");
    assert!(report.workers.is_empty(), "{report:?}");
    world.serving.abort();
}

/// No connection is opened to a worker whose session has closed, by a caller that took the worker
/// from the directory before the closure and asks for its connection after it: the caller is told
/// the session is unknown and the connection table holds nothing for it. The control is the same
/// call before the closure, which gives the link and keeps its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_connection_is_opened_to_a_worker_whose_session_closed() {
    let script = Scripted::new();
    let world = scripted(&script).await;
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
    world.serving.abort();
}
