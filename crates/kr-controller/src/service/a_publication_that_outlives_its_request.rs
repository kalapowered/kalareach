//! A recovery whose request stops waiting while its publication is still running.
//!
//! A worker is made known on a task of its own, so that a request which stops waiting leaves
//! neither a descriptor nor a half-held worker behind. That task can therefore outlive the request
//! that began it, and the request's hold on the worker's reservation must not end before the task
//! does: a look at the reservation presents a generation token to the worker, and one presented
//! while the worker is being made known fences the connections that begins to open.

use std::sync::Arc;

use super::a_link_that_is_not_given_back::Served;

/// How long a test waits for the daemon's own tasks to get where it expects before it calls that a
/// failure. Nothing is decided by it: the waits are on conditions.
const WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// KR-REQ-09.12: a look at a reservation that comes after a recovery request stopped waiting does
/// not begin while the publication that request left running is in flight: it waits for the
/// reservation, and once the publication is over it finds the worker published and has nothing to
/// challenge. A look that did begin would challenge the worker again before the first publication
/// has put it in the directory, and, having adopted it itself, publish the same worker twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_that_follows_a_cancelled_recovery_waits_for_the_publication_it_left_running() {
    let (world, _reservation) = Served::claimed().await;
    let controller = &world.controller;
    let (arrived, go) = controller.before_a_worker_is_made_known.arm();

    // A look at the claim challenges the worker, adopts it, and hands the publication to a task of
    // its own. The request that began it then stops waiting.
    let first = tokio::spawn({
        let controller = Arc::clone(controller);
        async move { controller.recover_claims().await }
    });
    arrived.await.expect("the publication is in flight");
    first.abort();
    assert!(
        first
            .await
            .expect_err("the look was cancelled")
            .is_cancelled()
    );

    // The next look comes while that publication is in flight. It either waits for the reservation
    // or, having taken it, runs through to the end and publishes the worker itself; the publication
    // in flight is held where it is until the test lets it go.
    let mut second = tokio::spawn({
        let controller = Arc::clone(controller);
        async move { controller.recover_claims().await }
    });
    let outcome = tokio::time::timeout(WAIT, async {
        loop {
            if controller.reservations.waiting() > 0 {
                return false;
            }
            tokio::select! {
                _ = &mut second => return true,
                () = tokio::task::yield_now() => {}
            }
        }
    })
    .await
    .expect("the next look either waits or ends");
    assert!(
        !outcome,
        "the next look ran to its end, challenging the worker and publishing it, while the \
         publication a cancelled request left running was still in flight"
    );
    assert!(
        controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_none(),
        "the worker is not in the directory while its publication is in flight"
    );

    // Once the publication is over the reservation is given back, the worker is published, and the
    // look that waited finds nothing to do.
    go.send(()).expect("the publication is waiting");
    second
        .await
        .expect("the look's task ends")
        .expect("the look ends");
    assert!(
        controller
            .directory
            .lock()
            .await
            .get(world.session_id)
            .is_some(),
        "the worker is in the directory"
    );
}
