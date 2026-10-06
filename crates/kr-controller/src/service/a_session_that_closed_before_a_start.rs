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
use std::task::Poll;

use kr_protocol::identity::DesktopBinding;

use super::a_closure_that_is_cancelled::on_disk;
use super::a_link_that_is_not_given_back::Served;
use super::a_read_that_meets_a_worker_on_its_way_out::closure_of;
use super::a_session_that_closed_is_not_bound_again::held_by_the_daemon;

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
        .adopt_worker(&world.row(), Some(&DesktopBinding::none()))
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

/// The readers a start sets going for the workers its directory holds.
#[derive(Clone, Copy, Debug)]
enum Reader {
    /// The attention store's reading of the session's sources.
    Attention,
    /// The description host's reading of the session's facts.
    Descriptions,
}

/// How long a test waits for the attention store to finish with a closed session before it calls
/// that a failure. Nothing is decided by it: the wait is on a condition.
const WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Starts `reader` on the workers the directory holds, stops it once it has read them from the
/// directory and before it begins on them, and, where `closure_lands`, lets a closure of the
/// worker's session try to land there: its first step is taken while the reader is stopped, and
/// where that step records the closure it is carried through the closure's tidying, and the
/// attention store's part of that, before the reader goes on, as a closure on another thread would
/// be. Answers whether the reader reads the session at its worker once both are done.
///
/// A start that holds the registry's lock from reading the directory to beginning on what it read
/// has the closure wait for it and undo what it began, and a start that does not begins on a worker
/// that a closure has already tidied away.
async fn read_while_a_closure_lands(reader: Reader, closure_lands: bool) -> bool {
    let world = Served::start().await;
    let session_id = world.session_id;
    let controller = &world.controller;
    assert!(!controller.attention.watching(session_id));
    assert!(!controller.descriptions.reading(session_id));
    let (arrived, go) = controller.after_a_start_reads_the_directory.arm();
    let reading = tokio::spawn({
        let controller = Arc::clone(controller);
        async move {
            match reader {
                Reader::Attention => controller.watch_open_sessions().await,
                Reader::Descriptions => controller.describe_open_workers().await,
            }
        }
    });
    arrived.await.expect("the reader has read the directory");

    let record = closure_of(session_id);
    let mut closing = Box::pin(controller.retire(&record));
    let mut closed = false;
    if closure_lands {
        let first =
            std::future::poll_fn(|context| Poll::Ready(closing.as_mut().poll(context))).await;
        match first {
            Poll::Ready(finished) => {
                finished.expect("the closure is recorded");
                closed = true;
            }
            // Recorded by that step: nothing holds the closure back, and it is carried through.
            Poll::Pending if on_disk(&world) => {
                closing.as_mut().await.expect("the closure is recorded");
                closed = true;
            }
            // Waiting for the registry, which the reader holds.
            Poll::Pending => {}
        }
    }
    if closed {
        until_the_store_has_finished_with(&world).await;
    }
    go.send(()).expect("the reader is waiting");
    reading
        .await
        .expect("the reader's task ends")
        .expect("the reader starts");
    if closure_lands && !closed {
        closing.await.expect("the closure is recorded");
        until_the_store_has_finished_with(&world).await;
    }
    match reader {
        Reader::Attention => controller.attention.watching(session_id),
        Reader::Descriptions => controller.descriptions.reading(session_id),
    }
}

/// Waits until the attention store has finished with the session. A closure's tidying hands that to
/// a task of its own, so the closure has returned before the store has stopped reading the session.
async fn until_the_store_has_finished_with(world: &Served) {
    let finished = tokio::time::timeout(WAIT, async {
        while !world.controller.attention.finished_with(world.session_id) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        finished.is_ok(),
        "the attention store finishes with the closed session"
    );
}

/// What each of the two readers does with a session, in the order of [`Reader`].
async fn both_read_while_a_closure_lands(closure_lands: bool) -> [bool; 2] {
    [
        read_while_a_closure_lands(Reader::Attention, closure_lands).await,
        read_while_a_closure_lands(Reader::Descriptions, closure_lands).await,
    ]
}

/// The control: with no closure, what a start begins for a worker is begun.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_start_begins_for_a_worker_is_begun_when_its_session_has_no_closure() {
    assert_eq!(
        both_read_while_a_closure_lands(false).await,
        [true, true],
        "the attention store and the description host read a session that has no closure"
    );
}

/// KR-REQ-09.12: a closure that tries to land after a start has read a worker from the directory
/// and before it begins on it leaves nothing reading the session: the closure waits for the
/// registry's lock, which the start holds until it has begun, and its tidying then stops what the
/// start began.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_a_start_begins_reads_a_session_a_closure_has_ended() {
    assert_eq!(
        both_read_while_a_closure_lands(true).await,
        [false, false],
        "the attention store and the description host read a session a closure has ended"
    );
}
