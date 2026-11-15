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
    let (arrived, go) = controller.before_a_barrier_tells.arm();
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
    let (arrived, _never) = controller.before_a_barrier_tells.arm();
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

/// What a task that holds the daemon through `while_held` tells a case, in the order it happens.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Just before the task asks to hold the daemon, which takes the task count.
    AboutToBegin,
    /// The task's work has begun, which is after the task is counted.
    Began,
    /// The task's work is over, and the task stands where it is about to leave the count.
    AboutToLeave,
    /// The task has left the count and let the daemon go.
    Ended,
    /// The task stands between the two counts of a look, holding the task count.
    Looking,
    /// The task asked for the task count and found it held, and waits for it.
    WaitsAtTheCount,
}

/// A task that holds the daemon through `while_held` for work that lasts until it is told to
/// finish, and what it says as it goes.
///
/// A case waits on what the task says, never on the runtime's timers: a task that stands at a
/// look holds a thread of the runtime, and a task that waits for the task count holds another, and
/// either may be the thread that drives the timers. The case's own thread is not one of the
/// runtime's, so it can wait on a channel while they stand.
struct Holder {
    task: tokio::task::JoinHandle<()>,
    says: std::sync::mpsc::Sender<Step>,
    steps: std::sync::mpsc::Receiver<Step>,
    begin: Option<oneshot::Sender<()>>,
    finish: Option<oneshot::Sender<()>>,
}

impl Holder {
    /// Spawns the task. It does nothing until [`Holder::begin`], so that a case can stop it at its
    /// first look.
    fn new(daemon: &std::sync::Weak<Controller>) -> Self {
        let daemon = daemon.clone();
        let (begin, begins) = oneshot::channel();
        let (finish, finishes) = oneshot::channel();
        let (says, steps) = std::sync::mpsc::channel();
        let task = tokio::spawn({
            let says = says.clone();
            async move {
                let _ = begins.await;
                let _ = says.send(Step::AboutToBegin);
                let in_work = says.clone();
                let _ = super::barrier::while_held(&daemon, async move |_: &Arc<Controller>| {
                    let _ = in_work.send(Step::Began);
                    let _ = finishes.await;
                })
                .await;
                let _ = says.send(Step::Ended);
            }
        });
        Self {
            task,
            says,
            steps,
            begin: Some(begin),
            finish: Some(finish),
        }
    }

    fn begin(&mut self) {
        let _ = self.begin.take().expect("a task begins once").send(());
    }

    fn finish(&mut self) {
        let _ = self.finish.take().expect("a task finishes once").send(());
    }

    /// Stops the task at its next look between the two counts, where it says [`Step::Looking`]
    /// and waits for the answer to be used.
    fn stop_at_its_next_look(&self, controller: &Controller) -> std::sync::mpsc::SyncSender<()> {
        let says = self.says.clone();
        controller
            .between_the_task_counts
            .arm_for(self.task.id(), move || {
                let _ = says.send(Step::Looking);
            })
    }

    /// Stops the task when its work is over, before it leaves the count, where it says
    /// [`Step::AboutToLeave`] and waits for the answer to be used. Past its look, so the task has
    /// no look left to wait in.
    fn stop_before_it_leaves(&self, controller: &Controller) -> std::sync::mpsc::SyncSender<()> {
        let says = self.says.clone();
        controller
            .before_a_task_leaves_the_count
            .arm_for(self.task.id(), move || {
                let _ = says.send(Step::AboutToLeave);
            })
    }

    /// Arms the record that the task finds the task count held and waits for it, which it says as
    /// [`Step::WaitsAtTheCount`]. Armed for the task's next such wait, so a case arms it when the
    /// guard is held by what the case stopped and the task is yet to ask.
    fn hear_when_it_waits_at_the_count(&self, controller: &Controller) {
        let says = self.says.clone();
        controller
            .task_holds
            .say_when_it_waits(self.task.id(), move || {
                let _ = says.send(Step::WaitsAtTheCount);
            });
    }

    /// Waits for the task to say `step` as its next, and fails with `otherwise` when it says
    /// something else or nothing within [`WAIT`].
    fn says(&self, step: Step, otherwise: &str) {
        let said = self.steps.recv_timeout(WAIT).ok();
        assert_eq!(said.as_ref(), Some(&step), "{otherwise}");
    }
}

/// The first task of a case, begun and stopped at a look between the two counts: it holds the
/// daemon, is counted, and holds the task count while the case goes on.
fn stopped_between_its_counts(
    daemon: &std::sync::Weak<Controller>,
    controller: &Controller,
) -> (Holder, std::sync::mpsc::SyncSender<()>) {
    let mut first = Holder::new(daemon);
    first.begin();
    first.says(Step::AboutToBegin, "the first task begins");
    first.says(Step::Began, "the first task's work begins");
    // Armed once the task has begun: its first look is due at once and can come before its work
    // starts, and a task is stopped at a look it has not reached yet, the next one at the latest.
    let release = first.stop_at_its_next_look(controller);
    first.says(
        Step::Looking,
        "the first task looks and stands between its counts",
    );
    (first, release)
}

/// Lets the stopped first task go on from its look, and says that it did not let the daemon go
/// there: a task that did would say [`Step::Ended`], and one that did not stands at its next look,
/// which is let go at once.
fn goes_on_from_its_look(
    controller: &Controller,
    first: &Holder,
    release: &std::sync::mpsc::SyncSender<()>,
) {
    let release_next = first.stop_at_its_next_look(controller);
    release.send(()).expect("the first task waits at its look");
    first.says(
        Step::Looking,
        "the first task let the daemon go while its owner holds it",
    );
    release_next
        .send(())
        .expect("the first task waits at its next look");
}

/// A task that looks at whether it is the daemon's last holder does not let the daemon go while
/// its owner holds it, though another task that holds the daemon the same way begins between the
/// two counts the look compares.
///
/// The first task stands between its counts, holding the task count, and the second asks to begin.
/// The second may not begin while the first stands there: it counts itself under the same lock, and
/// the case waits for the record that it waits for it. A look that does not keep the lock lets it
/// begin at once, and the case fails on that, with no wait for a silence. Then the first goes on,
/// and it does not let the daemon go, because the owner holds it, though the second holds it too.
/// Both end once the owner lets the daemon go.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_task_that_begins_between_the_two_counts_does_not_make_another_let_the_daemon_go() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, _passes) = daemon_passing_by_hand(&temp).await;
    let daemon = Arc::downgrade(&controller);
    let (first, release) = stopped_between_its_counts(&daemon, &controller);

    let mut second = Holder::new(&daemon);
    second.hear_when_it_waits_at_the_count(&controller);
    second.begin();
    second.says(Step::AboutToBegin, "the second task asks to begin");
    second.says(
        Step::WaitsAtTheCount,
        "the second task did not wait for the task count while the first stood between its \
         counts, so the first look no longer holds the task count there",
    );

    goes_on_from_its_look(&controller, &first, &release);
    second.says(
        Step::Began,
        "the second task begins once the first look is over",
    );

    drop(controller);
    first.says(
        Step::Ended,
        "the first task lets the daemon go once its owner has",
    );
    second.says(
        Step::Ended,
        "the second task lets the daemon go once its owner has",
    );
    until("the daemon let go being gone", async || {
        daemon.strong_count() == 0
    })
    .await;
}

/// A task that looks at whether it is the daemon's last holder does not let the daemon go while
/// its owner holds it, though another task that holds the daemon the same way ends between the two
/// counts the look compares.
///
/// A task that ends takes itself out of the count first and lets go of the daemon after. The
/// second task's work is over and it stands before leaving the count. Then the first task stands
/// between its counts, holding the task count, with the second still in it, and the second is let
/// go on. It may not leave the count while the first stands there, and the case waits for the
/// record that it waits for it. A look that does not keep the lock lets it leave both, and the case
/// fails on that: the first would read the task count with the second in it and the daemon's count
/// without it. Then the first goes on, and it does not let the daemon go. Both end once the owner
/// lets the daemon go.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_task_that_ends_between_the_two_counts_does_not_make_another_let_the_daemon_go() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, _passes) = daemon_passing_by_hand(&temp).await;
    let daemon = Arc::downgrade(&controller);
    let mut second = Holder::new(&daemon);
    let leave = second.stop_before_it_leaves(&controller);
    second.begin();
    second.says(Step::AboutToBegin, "the second task begins");
    second.says(Step::Began, "the second task's work begins");
    second.finish();
    second.says(
        Step::AboutToLeave,
        "the second task's work ends and it stands before it leaves the count",
    );
    let (first, release) = stopped_between_its_counts(&daemon, &controller);

    second.hear_when_it_waits_at_the_count(&controller);
    leave
        .send(())
        .expect("the second task waits before it leaves the count");
    second.says(
        Step::WaitsAtTheCount,
        "the second task left the count and let the daemon go while the first stood between its \
         counts, so the first look no longer holds the task count there",
    );

    goes_on_from_its_look(&controller, &first, &release);
    second.says(
        Step::Ended,
        "the second task leaves the count once the first look is over",
    );

    drop(controller);
    first.says(
        Step::Ended,
        "the first task lets the daemon go once its owner has",
    );
    until("the daemon let go being gone", async || {
        daemon.strong_count() == 0
    })
    .await;
}
