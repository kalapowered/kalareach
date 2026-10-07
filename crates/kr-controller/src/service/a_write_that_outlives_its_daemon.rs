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

/// How long a test waits for the daemon's own tasks to let go of it before it calls that a
/// failure. Nothing is decided by it: the waits are on conditions.
const WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// KR-REQ-09.12: while a worker's descriptor is still to be written, the environment stays held
/// though the task that waited for the write and every other holder of the daemon have let go, and
/// it is let go once the write has ended. A daemon that let the environment go first would have the
/// next daemon take it, and look for descriptors beside closures, before this write put one there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descriptor_write_still_to_be_made_keeps_the_environment_held() {
    let world = Served::recorded().await;
    let (arrived, go) = world.controller.before_a_descriptor_is_written.arm();
    let writing = tokio::spawn({
        let controller = Arc::clone(&world.controller);
        let worker = world.worker.clone();
        async move { controller.write_descriptor(&worker).await }
    });
    tokio::task::spawn_blocking(move || arrived.recv())
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
    let daemon = Arc::downgrade(&controller);
    drop(controller);
    let others_gone = std::time::Instant::now() + WAIT;
    while daemon.strong_count() > 1 && std::time::Instant::now() < others_gone {
        tokio::task::yield_now().await;
    }
    assert!(
        daemon.strong_count() <= 1,
        "nothing but the write holds the daemon"
    );

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
    drop(standing);
}
