//! A descriptor write that the task waiting for it stops waiting for.
//!
//! A worker's descriptor is written on a thread that may block, and the task that waits for the
//! write can end before the write does: the daemon's runtime going is one way. The environment's
//! lock goes with the daemon, so a write that went on without it could put a descriptor in place
//! after the next daemon's start had looked for the ones left beside a closure. The thread keeps
//! the daemon, and with it the environment, until the write has ended.

use std::sync::Arc;

use super::a_link_that_is_not_given_back::Served;
use crate::error::ControllerError;
use crate::singleton::SingletonLock;

/// How long a test waits for something the daemon does before it calls that a failure. Nothing is
/// decided by it: the waits are on conditions.
const WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// KR-REQ-09.12: while a worker's descriptor is still to be written, the daemon is held by the
/// write and the environment stays held with it, though the task that waited for the write and
/// every holder of the test's own have let go; once the write has ended the environment is let go.
/// A daemon that let the environment go first would have the next daemon take it, and look for
/// descriptors beside closures, before this write put one there.
///
/// The daemon's own periodic tasks hold it for a moment each time they run, so a count of its
/// holders says what is certain only in one direction: a count above the test's own proves a
/// holder, and the write is the one holder that is there for as long as the write is paused. What
/// decides the claim is therefore both reads, the holder while the test still holds the daemon and
/// the environment's lock once it has let go, and a run that ends with the environment free while
/// the write is paused fails the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_write_still_to_be_made_keeps_the_environment_held() {
    let world = Served::recorded().await;
    let (arrived, go) = world.controller.before_a_descriptor_is_written.arm();
    let writing = tokio::spawn({
        let controller = Arc::clone(&world.controller);
        let worker = world.worker.clone();
        async move { controller.write_descriptor(&worker).await }
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT))
        .await
        .expect("the wait ends")
        .expect("the write is on its thread");
    // The task that waited for the write stops waiting, and lets go of the daemon it held.
    writing.abort();
    assert!(
        writing
            .await
            .expect_err("the wait was ended")
            .is_cancelled()
    );
    let lock = world.controller.paths().singleton_lock();
    let environment_id = world.controller.paths().environment_id();
    let (controller, standing) = world.into_daemon();
    assert!(
        Arc::strong_count(&controller) > 1,
        "the write that is still to be made holds the daemon beside this test"
    );
    drop(controller);

    let taken = SingletonLock::hold(&lock, environment_id);
    assert!(
        matches!(taken, Err(ControllerError::AlreadyRunning { .. })),
        "the environment is held while the daemon's write is still to be made: {:?}",
        taken.map(|_| ())
    );

    go.send(()).expect("the write is waiting");
    let released = std::time::Instant::now() + WAIT;
    let taken = loop {
        match SingletonLock::hold(&lock, environment_id) {
            Ok(held) => break Some(held),
            Err(_) if std::time::Instant::now() < released => tokio::task::yield_now().await,
            Err(_) => break None,
        }
    };
    assert!(
        taken.is_some(),
        "the environment is let go once the write has ended"
    );
    // The lock goes before the tree it is in.
    drop(taken);
    drop(standing);
}
