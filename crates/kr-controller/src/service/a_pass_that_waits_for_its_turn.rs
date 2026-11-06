//! A pass the daemon runs on its own keeps nothing of the daemon while it waits.
//!
//! A pass that waits, for its turn behind another or for a blocking thread, holds the daemon
//! weakly: a daemon its owner lets go meanwhile goes at once, with the environment's lock, and
//! the pass whose turn comes after that finds it gone and does nothing. A pass holds the daemon
//! where it acts on it, and the removal and the automation sweep hold it while they write, so that
//! no write goes on once the daemon has let go of its environment. Each case makes a pass wait,
//! lets the daemon go, and reads that nothing of the daemon was held; the third also reads that the
//! release that waited wrote nothing once its turn came.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use kr_ipc::testing::TempHost;

use crate::service::Controller;
use crate::service::net::tests::daemon;

/// How long a case waits for the daemon to be let go before it calls the wait hung. Nothing is
/// decided by it: the daemon is let go when the last holder lets go, whenever that is.
const WAIT: Duration = Duration::from_secs(120);

/// Waits until `condition` holds, or fails when it does not within [`WAIT`].
async fn until(what: &str, condition: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !condition() {
        assert!(started.elapsed() < WAIT, "never: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Polls `future` once, so that it has run as far as its first wait.
async fn polled_once<F: Future + Unpin>(future: &mut F) {
    std::future::poll_fn(|context| {
        let _ = std::pin::Pin::new(&mut *future).poll(context);
        std::task::Poll::Ready(())
    })
    .await;
}

/// The removal of what closed sessions retained, which the privacy tick makes, waiting for its turn
/// behind another removal, keeps nothing of the daemon.
///
/// Another removal holds the turn here. The removal is polled once, so that it has taken what it
/// needs of the daemon and waits for its turn, and then the case lets the daemon go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_waiting_for_its_turn_keeps_nothing_of_its_daemon() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let daemon = Arc::downgrade(&controller);
    let turn = Arc::clone(&controller.removing_closed).lock_owned().await;
    let mut removing = Box::pin(Controller::remove_closed_content(&daemon));
    polled_once(&mut removing).await;

    drop(controller);
    until(
        "the daemon is let go while a removal waits for its turn",
        || daemon.strong_count() == 0,
    )
    .await;

    drop(turn);
    assert_eq!(
        removing.await,
        Some(()),
        "the removal ends once its turn comes, with the daemon gone"
    );
}

/// The look the automation module makes at what node dispatches left behind, which the daemon
/// makes as it starts, keeps nothing of the daemon while it waits for a blocking thread to read
/// the ledger.
///
/// The runtime here has one blocking thread, which the case takes once the daemon's own first
/// look has ended. The look is polled once, so that it has run as far as its wait for that thread,
/// and then the case lets the daemon go.
#[test]
fn a_look_at_what_dispatches_left_behind_waiting_for_a_thread_keeps_nothing_of_its_daemon() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        until("the daemon's own first look ends", || {
            controller.automation().sweep_passes() >= 1
        })
        .await;

        // The runtime's one blocking thread, taken until the case lets it go.
        let (taken, taking) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let occupied = tokio::task::spawn_blocking(move || {
            let _ = taken.send(());
            let _ = held.recv();
        });
        taking.await.expect("the blocking thread is taken");

        let automation = Arc::clone(controller.automation());
        let daemon = Arc::downgrade(&controller);
        let mut looking = Box::pin(async move { automation.sweep_once().await });
        polled_once(&mut looking).await;

        drop(controller);
        until(
            "the daemon is let go while a look waits for a thread",
            || daemon.strong_count() == 0,
        )
        .await;

        let _ = release.send(());
        occupied.await.expect("the blocking thread is let go");
        assert_eq!(
            looking.await,
            0,
            "the look ends once its thread is there, with the daemon gone"
        );
    });
}

/// A release that waits for a blocking thread keeps nothing of the daemon, and one whose turn comes
/// after the daemon has gone releases nothing and leaves its row owed for the next daemon's sweep:
/// the daemon is held while what a row owns is released and the row written, and not while the
/// job waits to start, so no write goes on once the daemon has let go of its environment.
///
/// The runtime here has one blocking thread, which the case takes once the daemon's own first look
/// has ended, so that no look of the daemon's releases the rows the case writes. One row is
/// released while the daemon is there, which is what the other must differ from. The other's
/// release is polled once, so that it waits for the thread, and then the case lets the daemon go.
#[test]
fn a_release_waiting_for_a_thread_keeps_nothing_of_its_daemon_and_writes_nothing_after_it() {
    use kr_automation::resources::{Owned, OwnedState};
    use kr_protocol::automation::WorkflowActionKind;
    use kr_protocol::ids::{ActionId, GrantId, WorkflowRunId};
    use kr_protocol::scalars::Uuid;

    let row = |byte: u8| Owned {
        action_id: ActionId::new(Uuid::from_bytes([byte; 16])),
        run_id: WorkflowRunId::new(Uuid::from_bytes([9; 16])),
        node_id: format!("command-{byte}"),
        kind: WorkflowActionKind::ShellCommand,
        grant_id: GrantId::new(Uuid::from_bytes([8; 16])),
        owns_session: false,
        materialisation_id: None,
        scratch: None,
        scratch_identity: None,
        workspace_id: None,
        session_id: None,
        worker: None,
        boot: None,
        state: OwnedState::Open,
    };
    let (released, owed) = (row(1), row(2));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        let automation = Arc::clone(controller.automation());
        until("the daemon's own first look ends", || {
            automation.sweep_passes() >= 1
        })
        .await;
        for owned in [&released, &owed] {
            automation
                .ledger()
                .begin(owned, kr_ipc::now_ms().get())
                .expect("writes the row");
        }
        let state_of = |owned: &Owned| {
            automation
                .ledger()
                .get(owned.action_id)
                .expect("reads the row")
                .expect("the row is there")
                .state
        };

        assert!(
            automation.release_once(released.action_id).await,
            "with the daemon there, a release is made"
        );
        assert_eq!(state_of(&released), OwnedState::Released);

        // The runtime's one blocking thread, taken until the case lets it go.
        let (taken, taking) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let occupied = tokio::task::spawn_blocking(move || {
            let _ = taken.send(());
            let _ = held.recv();
        });
        taking.await.expect("the blocking thread is taken");

        let mut releasing = Box::pin(async { automation.release_once(owed.action_id).await });
        polled_once(&mut releasing).await;

        let daemon = Arc::downgrade(&controller);
        drop(controller);
        until(
            "the daemon is let go while a release waits for a thread",
            || daemon.strong_count() == 0,
        )
        .await;

        let _ = release.send(());
        occupied.await.expect("the blocking thread is let go");
        assert!(
            !releasing.await,
            "a release whose turn comes after the daemon has gone releases nothing"
        );
        assert_eq!(state_of(&owed), OwnedState::Open);
    });
}
