//! The pass that raises a barrier for every published debt no change's own barrier is coming
//! for: at start, at every pass, and at once when it is woken.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::a_floor_owed_its_record::{WAIT, daemon_passing_by_hand, until};
use super::one_barrier_for_every_restriction::{beside, owed, revision};
use super::{Controller, Reach};
use crate::error::ControllerError;

/// A change that publishes its debt and stops waiting before its barrier's first step, as a
/// request whose caller went away does. The registry is held meanwhile, so that barrier never
/// captures anything, and no barrier of the change's own is coming for the debt.
async fn a_change_that_stopped_waiting(controller: &Controller) {
    let registry = controller.registry.lock().await;
    let stopped =
        tokio::time::timeout(Duration::from_millis(50), controller.revoke_authority()).await;
    assert!(stopped.is_err(), "the change waits for the registry");
    drop(registry);
}

/// Sends passes until a barrier the pass raised arrives at its pause.
async fn until_the_pass_tells(passes: &UnboundedSender<()>, mut arrived: oneshot::Receiver<()>) {
    let deadline = Instant::now() + WAIT;
    loop {
        let _ = passes.send(());
        match tokio::time::timeout(Duration::from_millis(100), &mut arrived).await {
            Ok(arrival) => {
                arrival.expect("the pause reports its arrival");
                return;
            }
            Err(_) => assert!(
                Instant::now() < deadline,
                "the pass raised no barrier within {WAIT:?}"
            ),
        }
    }
}

/// A debt no change's own barrier is coming for is raised the moment the pass is woken. The
/// change that stopped waiting wakes it, and no pass has to come round.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_debt_left_to_the_pass_is_raised_at_once_when_it_wakes() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, _passes) = daemon_passing_by_hand(&temp).await;
    let before = revision(&controller).await;

    a_change_that_stopped_waiting(&controller).await;
    until("the woken pass raising the debt", async || {
        controller.check_fence().is_ok()
    })
    .await;
    assert_eq!(revision(&controller).await, before + 1, "one barrier");
    drop(controller);
}

/// A debt a start could not raise its barrier for is raised by the first pass after storage
/// takes a barrier again, with nothing else waking the pass. A debt left to the pass therefore
/// stays published for at most one pass once a barrier can be raised, inside the two passes
/// this host allows it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_debt_left_to_the_pass_is_raised_by_the_first_pass_that_can_raise_it() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let before = revision(&controller).await;
    controller
        .owe_debt("a change the daemon stopped in", Reach::Host)
        .expect("written");
    super::net::tests::stopped(controller).await;

    let registry = beside(&temp);
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_revision BEFORE UPDATE OF authority_revision ON environment
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let (controller, passes) = daemon_passing_by_hand(&temp).await;
    controller
        .check_fence()
        .expect_err("the start could not raise its barrier, so the debt is owed");
    registry
        .execute_batch("DROP TRIGGER refuse_revision;")
        .expect("the fault is cleared");

    passes.send(()).expect("the pass is running");
    // Its row is deleted once the workers are told, which the pass does on a task of its own.
    until(
        "the first pass raising the debt and retiring its row",
        async || controller.check_fence().is_ok() && owed(&controller).is_empty(),
    )
    .await;
    assert_eq!(revision(&controller).await, before + 1, "one barrier");
    drop(controller);
}

/// The pass raises a debt left to it while a barrier it raised earlier still waits to tell the
/// workers: that wait holds up nothing captured after it. Released, the earlier barrier
/// completes, and nothing is left owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_debt_is_raised_while_an_earlier_barrier_of_the_pass_waits_for_its_workers() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, passes) = daemon_passing_by_hand(&temp).await;
    let before = revision(&controller).await;
    let (arrived, go) = controller.before_the_pass_tells.arm();
    a_change_that_stopped_waiting(&controller).await;
    until_the_pass_tells(&passes, arrived).await;
    assert_eq!(revision(&controller).await, before + 1);
    controller
        .check_fence()
        .expect("the first debt is captured, so nothing refuses");

    // Another change stops waiting while that barrier waits.
    a_change_that_stopped_waiting(&controller).await;
    passes.send(()).expect("the pass is running");
    until("the pass raising the second debt", async || {
        controller.check_fence().is_ok()
    })
    .await;
    assert_eq!(revision(&controller).await, before + 2);

    go.send(())
        .expect("the earlier barrier was still waiting to tell the workers");
    until("both barriers completing", async || {
        controller.debts().retiring.is_empty()
    })
    .await;
    drop(controller);
}

/// A daemon let go while a barrier its pass raised waits to tell the workers lets its
/// environment go at once: the pass holds it only while something else does too, and a daemon
/// started on the environment takes it over without waiting for those workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_let_go_while_its_pass_waits_for_workers_lets_its_environment_go() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, passes) = daemon_passing_by_hand(&temp).await;
    let (arrived, _never) = controller.before_the_pass_tells.arm();
    a_change_that_stopped_waiting(&controller).await;
    until_the_pass_tells(&passes, arrived).await;

    let held = Arc::downgrade(&controller);
    drop(controller);
    let deadline = Instant::now() + WAIT;
    let replacement = loop {
        match Controller::start(super::a_floor_owed_its_record::setup(&temp)).await {
            Ok(replacement) => break replacement,
            Err(ControllerError::AlreadyRunning { .. }) => assert!(
                Instant::now() < deadline,
                "the daemon let go still held its environment after {WAIT:?}"
            ),
            Err(error) => panic!("the replacement does not start: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(held.strong_count(), 0, "the daemon let go is gone");
    drop(replacement);
}

/// The pass never takes a debt a change's own barrier is coming for. Woken for a debt left to
/// it, the pass reaches the registry before a change that has just published its own debt; it
/// captures only the debt left to it, and the change's barrier captures the change's own and
/// reports it, so the revision advances once for each.
///
/// On one thread, so the order is exact: the pass waits for the registry first, the change
/// waits behind it, and only then is the registry let go.
#[tokio::test]
async fn the_pass_leaves_a_change_its_own_debt() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, _passes) = daemon_passing_by_hand(&temp).await;
    let before = revision(&controller).await;

    let registry = controller.registry.lock().await;
    let stopped =
        tokio::time::timeout(Duration::from_millis(50), controller.revoke_authority()).await;
    assert!(stopped.is_err(), "the first change waits for the registry");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let change = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move { controller.revoke_authority().await }
    });
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    drop(registry);

    let reported = change
        .await
        .expect("the change runs")
        .expect("its barrier is raised");
    assert_eq!(
        reported.authority_revision.get(),
        before + 2,
        "the change's own barrier captured its own debt, after the pass captured the other"
    );
    until("the pass's barrier completing", async || {
        controller.check_fence().is_ok() && controller.debts().retiring.is_empty()
    })
    .await;
    assert_eq!(revision(&controller).await, before + 2);
    drop(controller);
}
