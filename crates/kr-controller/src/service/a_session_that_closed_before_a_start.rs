//! What a daemon that starts takes up of a session whose closure is recorded.
//!
//! A start restores the workers an earlier daemon left from the registry's rows and the published
//! descriptors, and then sets going what the daemon does for each worker it holds. A session with a
//! closure has no worker to restore: an earlier build's recovery could write a row for a worker it
//! reached after the session had closed, and a start that restored it would give the session's
//! requests, its revocations and its plugin admissions a worker whose closure is the answer to
//! every ask. What a start begins for the workers it holds (the attention store's reading, the
//! description host's) is begun in a section under the registry's lock, which is where a closure is
//! recorded, so it is begun for a worker whose session has no closure, or not at all.

use std::sync::Arc;

use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::AuthorityRevision;
use kr_protocol::session::SessionState;

use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use super::a_session_that_closed_is_not_bound_again::{held_by_the_daemon, parked};
use crate::directory::KnownWorker;
use crate::registry::WorkerRecord;

/// The registry's row for a worker, as an earlier build's recovery wrote it.
fn row_of(worker: &KnownWorker) -> WorkerRecord {
    let descriptor = &worker.descriptor;
    WorkerRecord {
        session_id: descriptor.session_id,
        display_number: descriptor.display_number,
        public_key: descriptor.worker_public_key,
        process_identity: descriptor.process_start_identity.clone(),
        endpoint: descriptor.endpoint.clone(),
        profile: WorkerProfile::HeadlessUser,
        state: SessionState::Live,
        acknowledged_revision: AuthorityRevision::new(0),
    }
}

/// What a daemon that stopped leaves for the next one to find of a worker that kept running: its
/// row in the registry and its descriptor on disk, and, where `closed`, the closure of its session
/// with the row written after it, which is what an earlier build's recovery wrote for a worker it
/// reached after the session had closed.
async fn left_for_the_next_start(world: &Served, closed: bool) {
    let mut registry = world.controller.registry.lock().await;
    if closed {
        registry
            .record_closure(&closure_of(world.session_id))
            .expect("the closure is recorded");
    }
    registry
        .adopt_worker(&row_of(&world.worker), Some(&DesktopBinding::none()))
        .expect("the registry records the worker");
    drop(registry);
    kr_ipc::descriptor::publish(world.controller.paths(), &world.worker.descriptor)
        .expect("the descriptor is published");
}

/// A daemon that starts over what an earlier one left for a worker that is still running.
async fn started_over(closed: bool) -> Served {
    let world = Served::start().await;
    left_for_the_next_start(&world, closed).await;
    world.restarted().await
}

/// KR-REQ-09.12: a worker whose session has no closure is found again at a start: the daemon holds
/// it in its directory, in the set the plugin admissions wait for and by its published descriptor.
/// This is the control of the case below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_found_at_a_start_is_taken_up() {
    let world = started_over(false).await;
    let [in_the_directory, _, in_the_admissions, described] = held_by_the_daemon(&world).await;
    assert!(in_the_directory, "the worker is in the directory");
    assert!(in_the_admissions, "the plugin admissions wait for it");
    assert!(described, "its descriptor is kept");
}

/// KR-REQ-09.12: a worker whose session closed is not found again at a start, though its row and
/// its descriptor are on disk and it answers its challenge: the daemon holds nothing of it, no
/// reclaim that needs room waits for it, no descriptor is reported as one it could not use, and a
/// revocation holds with no worker to wait for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_whose_session_closed_is_not_taken_up_at_a_start() {
    let world = started_over(true).await;
    // The directory, the table of connections and the set the plugin admissions wait for.
    let [in_the_directory, has_a_slot, in_the_admissions, _] = held_by_the_daemon(&world).await;
    assert_eq!(
        [in_the_directory, has_a_slot, in_the_admissions],
        [false; 3],
        "the daemon holds nothing of the worker"
    );
    assert!(
        world
            .controller
            .pending_admissions()
            .await
            .expect("the catalogue's revision is read")
            .is_empty()
    );
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .quarantined
            .is_empty(),
        "the descriptor of a closed session is retired, not left to be reported"
    );
    let report = world
        .controller
        .announce_authority_revision()
        .await
        .expect("the announcement is made");
    assert!(report.holds(), "{report:?}");
    assert!(report.workers.is_empty(), "{report:?}");
}

/// KR-REQ-09.12: what a start begins for the workers its directory holds is not begun for a worker
/// whose session has a closure, whatever the directory still lists: the closure is recorded and the
/// tidying that takes the worker out of the directory has not run, or a copy of the directory was
/// taken before it did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_with_a_closure_is_not_read_by_what_a_start_begins() {
    let world = Served::start().await;
    let session_id = world.session_id;
    world
        .controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(session_id))
        .expect("the closure is recorded");
    world.controller.leases.worker_ended(session_id);
    assert!(
        world
            .controller
            .directory
            .lock()
            .await
            .get(session_id)
            .is_some()
    );
    world
        .controller
        .watch_open_sessions()
        .await
        .expect("the attention store starts");
    world
        .controller
        .describe_open_workers()
        .await
        .expect("the description host starts");
    assert_eq!(
        [
            world.controller.attention.watching(session_id),
            world.controller.descriptions.reading(session_id),
        ],
        [false, false]
    );
}

/// What a start sets going for the workers its directory holds, begun while a closure's section
/// has the registry, as a closure that lands between a start's reading of the directory and what
/// it does with it would have it. The attention store's reading and the description host's are each
/// asked to begin and are found waiting for the registry. Where `closure_lands`, the closure is
/// recorded in the section that has the registry, and the daemon's own directory still lists the
/// worker, as it does until the closure's tidying has run. Answers whether the store reads the
/// session and whether the host reads its facts once the registry is let go.
async fn begun_while_the_registry_is_held(closure_lands: bool) -> [bool; 2] {
    let world = Served::start().await;
    let session_id = world.session_id;
    assert!(!world.controller.attention.watching(session_id));
    assert!(!world.controller.descriptions.reading(session_id));
    let mut registry = world.controller.registry.lock().await;
    let attention = Arc::clone(&world.controller);
    let descriptions = Arc::clone(&world.controller);
    let mut attending = Box::pin(async move { attention.watch_open_sessions().await });
    let mut describing = Box::pin(async move { descriptions.describe_open_workers().await });
    parked(attending.as_mut(), "the attention store's start").await;
    parked(describing.as_mut(), "the description host's start").await;
    if closure_lands {
        registry
            .record_closure(&closure_of(session_id))
            .expect("the closure is recorded");
        world.controller.leases.worker_ended(session_id);
    }
    drop(registry);
    let (attended, described) = tokio::join!(attending, describing);
    attended.expect("the attention store starts");
    described.expect("the description host starts");
    [
        world.controller.attention.watching(session_id),
        world.controller.descriptions.reading(session_id),
    ]
}

/// The control: with no closure, what a start begins for a worker it holds is begun.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_start_begins_for_a_worker_is_begun_when_its_session_has_no_closure() {
    assert_eq!(begun_while_the_registry_is_held(false).await, [true, true]);
}

/// KR-REQ-09.12: a closure that lands while a start's attention store and description host are
/// about to begin on a worker leaves neither of them reading it: a session whose closure is
/// recorded is read by nothing that a start sets going.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_a_start_begins_reads_a_session_a_closure_has_ended() {
    assert_eq!(begun_while_the_registry_is_held(true).await, [false, false]);
}
