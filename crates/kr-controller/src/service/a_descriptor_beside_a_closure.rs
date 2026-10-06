//! A published descriptor that a closure's own tidying did not remove.
//!
//! A closure records itself and takes the session's worker row with it, and a worker's descriptor
//! is written outside the registry's lock and removed after it. Three things leave a closed
//! session's descriptor on disk with no row beside it: a stop between the descriptor's write and
//! the section that looks for the closure, a refused removal, and a stop inside the closure's own
//! tail. Nothing running repeats any of them, so a descriptor left that way is found by the next
//! start, which has no row to repair it by and used to report it as unusable at every start after.
//! A start retires the descriptor of every session whose closure is recorded.
//!
//! Each stop is made by the daemon's own test seam at the point a crash would end the step, over a
//! real worker.

use super::StopPoint;
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use super::a_session_that_closed_is_not_bound_again::held_by_the_daemon;

/// Whether the session's descriptor is on disk.
fn published(world: &Served) -> bool {
    kr_ipc::descriptor::read(world.controller.paths(), world.session_id)
        .expect("the descriptor directory reads")
        .is_some()
}

/// What a daemon that starts over the descriptor finds of the worker's session: nothing is held,
/// the descriptor is gone from disk, and it was not reported as one the daemon could not use.
async fn assert_it_is_retired_by_a_start(world: Served) {
    assert!(
        published(&world),
        "the descriptor is on disk before the start"
    );
    let world = world.restarted().await;
    assert!(
        !published(&world),
        "the start retired the descriptor of a closed session"
    );
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .quarantined
            .is_empty(),
        "and left no descriptor to be reported as unusable"
    );
    assert_eq!(held_by_the_daemon(&world).await, [false; 4]);
}

/// KR-REQ-09.12: a daemon that stopped between writing a worker's descriptor and the section that
/// looks for a closure, over a session that closed in the meantime, left a descriptor with no row
/// beside it, and the next start retires it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_written_for_a_session_that_closed_is_retired_by_a_start_after_a_stop_before_its_section()
 {
    let world = Served::recorded().await;
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    // The closure lands between the worker's row and its publication.
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the closure is recorded");
    world
        .controller
        .stop_at(StopPoint::AfterADescriptorIsWritten);
    world
        .controller
        .publish_worker(world.worker.clone(), None, &world.held().await)
        .await
        .expect_err("the publication ends after its write");
    assert_it_is_retired_by_a_start(world).await;
}

/// KR-REQ-09.12: a closure whose removal of the descriptor was refused leaves the descriptor
/// beside the closure, and the next start retires it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_whose_removal_was_refused_is_retired_by_a_start() {
    let world = Served::recorded().await;
    world
        .controller
        .publish_worker(world.worker.clone(), None, &world.held().await)
        .await
        .expect("the worker is published");
    world
        .controller
        .stop_at(StopPoint::AtADescriptorsRetirement);
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect_err("the removal of the descriptor is refused");
    assert!(world.has_a_closure().await, "the closure is recorded");
    assert_it_is_retired_by_a_start(world).await;
}

/// KR-REQ-09.12: a daemon that stopped inside a closure's tail, after the closure was recorded and
/// before anything of the tail ran, leaves the descriptor beside the closure, and the next start
/// retires it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_left_by_a_stop_inside_a_closures_tail_is_retired_by_a_start() {
    let world = Served::recorded().await;
    world
        .controller
        .publish_worker(world.worker.clone(), None, &world.held().await)
        .await
        .expect("the worker is published");
    world.controller.stop_at(StopPoint::InAClosuresTail);
    world
        .controller
        .retire(&closure_of(world.session_id))
        .await
        .expect_err("the tail ends where the test stops it");
    assert!(world.has_a_closure().await, "the closure is recorded");
    assert_it_is_retired_by_a_start(world).await;
}

/// The control of the three above: the same stop between the write and the section, over a session
/// that has not closed, leaves a descriptor with a row beside it, and a start takes the worker up
/// from it rather than retiring it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_written_for_a_session_that_is_open_is_kept_by_a_start() {
    let world = Served::recorded().await;
    world
        .controller
        .directory
        .lock()
        .await
        .remove(world.session_id);
    world
        .controller
        .stop_at(StopPoint::AfterADescriptorIsWritten);
    world
        .controller
        .publish_worker(world.worker.clone(), None, &world.held().await)
        .await
        .expect_err("the publication ends after its write");
    assert!(published(&world));

    let world = world.restarted().await;
    let [in_the_directory, _, in_the_admissions, described] = held_by_the_daemon(&world).await;
    assert!(in_the_directory, "the worker is in the directory");
    assert!(in_the_admissions, "the plugin admissions wait for it");
    assert!(described, "its descriptor is kept");
}
