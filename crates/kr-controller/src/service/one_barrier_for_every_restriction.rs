//! Every restrictive change owes its own debt, and the one barrier retires exactly what it
//! captured, once each change has tried to take effect.

use std::sync::Arc;
use std::time::Duration;

use super::{Controller, Reach};

pub(super) async fn revision(controller: &Controller) -> u64 {
    controller
        .registry
        .lock()
        .await
        .authority_revision()
        .expect("readable")
        .get()
}

pub(super) fn owed(controller: &Controller) -> Vec<crate::grants::store::DebtId> {
    controller
        .sharing()
        .grants()
        .fence_owed()
        .expect("readable")
}

/// Opens the registry beside the daemon, for a fault the test puts in place.
pub(super) fn beside(temp: &kr_ipc::testing::TempHost) -> rusqlite::Connection {
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
}

async fn restarted(
    controller: Arc<Controller>,
    temp: &kr_ipc::testing::TempHost,
) -> Arc<Controller> {
    super::net::tests::stopped(controller).await;
    super::a_floor_owed_its_record::daemon(temp).await
}

/// A debt whose change has not tried to take effect refuses nothing and no barrier captures
/// it. The control: once published, one barrier retires it, advancing one revision and leaving
/// no row and no refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_debt_is_not_captured_and_one_barrier_retires_a_published_one() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let before = revision(&controller).await;
    let pending = controller
        .owe_debt("a change still to take effect", Reach::Host)
        .expect("written");
    controller
        .check_fence()
        .expect("a pending debt refuses nothing");
    controller
        .barrier(controller.publish_debts(&[]))
        .await
        .expect("a barrier");
    assert_eq!(
        revision(&controller).await,
        before,
        "a pending debt is not captured"
    );
    assert_eq!(owed(&controller), vec![pending]);

    let own = controller.publish_debts(&[(pending, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");
    assert_eq!(revision(&controller).await, before + 1);
    assert!(owed(&controller).is_empty(), "the row is retired");
    controller.check_fence().expect("and nothing refuses");

    // Two restrictions, the second published after the first barrier captured: two rows, two
    // revisions, and the first barrier left the second one's row owed.
    let first = controller.owe_debt("one", Reach::Host).expect("written");
    let second = controller.owe_debt("two", Reach::Host).expect("written");
    let own = controller.publish_debts(&[(first, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");
    assert_eq!(owed(&controller), vec![second]);
    let own = controller.publish_debts(&[(second, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");
    assert_eq!(revision(&controller).await, before + 3);
    assert!(owed(&controller).is_empty());
    drop(controller);
}

/// The barrier captures only what this run holds as published and reads no row from disk, so a
/// row no change of this run holds is neither captured before its restriction nor twice: only
/// a start publishes it, and that start's barrier retires it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_no_change_of_this_run_holds_is_captured_only_by_a_start() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let before = revision(&controller).await;
    let row = controller
        .sharing()
        .grants()
        .owe_fence("a change this run does not hold", kr_ipc::now_ms().get())
        .expect("written");
    controller
        .barrier(controller.publish_debts(&[]))
        .await
        .expect("a barrier");
    assert_eq!(
        revision(&controller).await,
        before,
        "a row read from disk is not captured"
    );
    assert_eq!(owed(&controller), vec![row]);
    controller.check_fence().expect("and it refuses nothing");

    let controller = restarted(controller, &temp).await;
    assert_eq!(
        revision(&controller).await,
        before + 1,
        "the start publishes it and its barrier retires it"
    );
    assert!(owed(&controller).is_empty());
    drop(controller);
}

/// A barrier that cannot advance the revision leaves its debt published: every admission and
/// forward is refused meanwhile, and the debt pass raises it once a barrier can be raised.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_barrier_that_cannot_be_raised_keeps_its_debt_and_refuses_until_the_next_pass() {
    let temp = kr_ipc::testing::TempHost::create();
    let (controller, passes) = super::a_floor_owed_its_record::daemon_passing_by_hand(&temp).await;
    let before = revision(&controller).await;
    let registry = beside(&temp);
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_revision BEFORE UPDATE OF authority_revision ON environment
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let debt = controller
        .owe_debt("a narrowed ceiling", Reach::Host)
        .expect("written");
    let own = controller.publish_debts(&[(debt, Reach::Host)]);
    controller
        .barrier(own)
        .await
        .expect_err("the revision cannot advance");
    controller
        .check_fence()
        .expect_err("every admission is refused while the debt is owed");
    assert_eq!(owed(&controller), vec![debt]);
    assert_eq!(revision(&controller).await, before);

    registry
        .execute_batch("DROP TRIGGER refuse_revision;")
        .expect("the fault is cleared");
    passes.send(()).expect("the pass is running");
    super::a_floor_owed_its_record::until("the pass raising the debt", async || {
        controller.check_fence().is_ok() && owed(&controller).is_empty()
    })
    .await;
    assert_eq!(revision(&controller).await, before + 1);
    drop(controller);
}

/// A stop after a barrier advanced the revision and before it deleted the rows it captured
/// leaves them on disk, and the next start raises exactly one more barrier for them. A start
/// after the rows were deleted, and one after a barrier that completed, raise none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_barrier_whose_rows_outlived_it_is_raised_once_more_at_the_next_start() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let before = revision(&controller).await;
    let registry = beside(&temp);
    registry
        .execute_batch(
            "CREATE TRIGGER keep_debt BEFORE DELETE ON fence_debt
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let debt = controller
        .owe_debt("a revocation", Reach::Host)
        .expect("written");
    let own = controller.publish_debts(&[(debt, Reach::Host)]);
    controller
        .barrier(own)
        .await
        .expect("the barrier completes, its rows undeleted");
    assert_eq!(revision(&controller).await, before + 1);
    assert_eq!(
        owed(&controller),
        vec![debt],
        "the row outlived its barrier"
    );
    controller
        .check_fence()
        .expect("in this run the barrier retired it");
    registry
        .execute_batch("DROP TRIGGER keep_debt;")
        .expect("the fault is cleared");

    let controller = restarted(controller, &temp).await;
    assert_eq!(
        revision(&controller).await,
        before + 2,
        "the start raised exactly one more barrier"
    );
    assert!(owed(&controller).is_empty());
    controller.check_fence().expect("nothing refuses");

    // A start after the rows were deleted raises none.
    let controller = restarted(controller, &temp).await;
    assert_eq!(revision(&controller).await, before + 2);

    // Nor does one after a barrier that completed normally.
    let normal = controller
        .owe_debt("another revocation", Reach::Host)
        .expect("written");
    let own = controller.publish_debts(&[(normal, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");
    assert_eq!(revision(&controller).await, before + 3);
    let controller = restarted(controller, &temp).await;
    assert_eq!(revision(&controller).await, before + 3);
    drop(controller);
}

/// A configuration acceptance whose ceiling could not move owes no fence of its own, so it
/// never creates a debt for one. It fences because another change's debt is published; when a
/// barrier captures that debt while the acceptance waits for the registry, the acceptance
/// captures nothing and reports that barrier, and the revision advances once.
///
/// On one thread, so the order is exact: the other barrier waits for the registry first, the
/// acceptance decides to fence and waits behind it, and only then is the registry let go.
#[tokio::test]
async fn an_acceptance_whose_ceiling_could_not_move_fences_under_no_debt_of_its_own() {
    use kr_protocol::hostinfo::configuration::{Change, ConfigurationDocument};
    use kr_protocol::rights::ActionRight;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    controller
        .apply_configuration(&Change::GrantRights(Some(vec![
            ActionRight::SessionView.as_str().to_owned(),
            ActionRight::SessionRename.as_str().to_owned(),
        ])))
        .await
        .expect("a ceiling this host accepts");
    let before = revision(&controller).await;
    let registry = beside(&temp);
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_debt BEFORE INSERT ON fence_debt
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("no debt can be written");
    // Another change's debt, published, its own barrier still to come.
    let other = crate::grants::store::DebtId::fresh();
    let own = controller.publish_debts(&[(other, Reach::Host)]);
    let mut narrowed = ConfigurationDocument::empty();
    narrowed.revision = 3;
    narrowed.ceilings.grant_rights =
        kr_protocol::scalars::Nullable::some(vec![ActionRight::SessionView.as_str().to_owned()]);
    let path = kr_worker::config::document_path(&temp.environment());
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&narrowed).as_bytes(),
    )
    .expect("the narrowed document");

    let held = controller.registry.lock().await;
    let capture = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move { controller.barrier(own).await }
    });
    tokio::task::yield_now().await;
    let acceptance = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move { controller.accept_configuration().await }
    });
    tokio::task::yield_now().await;
    drop(held);
    let captured = capture
        .await
        .expect("the barrier runs")
        .expect("it is raised");
    let accepted = acceptance.await.expect("the acceptance runs");

    assert!(
        accepted
            .not_in_force
            .as_ref()
            .is_some_and(|problem| problem.as_str().contains("did not change")),
        "the ceiling could not move: {:?}",
        accepted.not_in_force
    );
    assert_eq!(
        accepted
            .barrier
            .as_ref()
            .map(|barrier| barrier.authority_revision),
        Some(captured.authority_revision),
        "the acceptance fenced, and reports the barrier that captured the published debt"
    );
    assert_eq!(
        revision(&controller).await,
        before + 1,
        "one barrier: the acceptance created no debt of its own"
    );
    controller.check_fence().expect("and nothing is left owed");
    drop(controller);
}

/// KR-REQ-10.45: a revision is announced with the grants its withdrawal reached to a worker that
/// says it reads them, and as the whole host's to a worker that does not, and for a page of the
/// evidence that follows its first announcement.
///
/// A worker of an earlier build ends the link a frame with a member it does not know arrived on,
/// so the member is never sent to one, and no worker built here can be made to stand in for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_does_not_read_a_revisions_reach_is_announced_the_whole_host() {
    use kr_protocol::ids::{AuthorityRevision, CapabilityId, GrantId};
    use kr_protocol::scalars::{CanonicalSet, Uuid};
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let grant = GrantId::new(Uuid::from_bytes([0x61; 16]));
    let reaching = Reach::Grants([grant].into_iter().collect());
    let debt = controller
        .owe_debt("a share", reaching.clone())
        .expect("written");
    let own = controller.publish_debts(&[(debt, reaching)]);
    controller.barrier(own).await.expect("a barrier");
    let revision = AuthorityRevision::new(revision(&controller).await);

    let stating =
        CanonicalSet::from_iter([
            CapabilityId::new(kr_protocol::local::AUTHORITY_REVISION_REACH).expect("a capability"),
        ]);
    let names_the_grant = RevisionReach::Within {
        grants: [grant].into_iter().collect(),
        devices: CanonicalSet::new(),
    };
    assert_eq!(
        controller.revision_notice(revision, 0, &stating).reach,
        names_the_grant
    );
    assert_eq!(
        controller
            .revision_notice(revision, 0, &CanonicalSet::new())
            .reach,
        RevisionReach::Host,
        "a worker that states nothing is told nothing of the reach"
    );
    assert_eq!(
        controller.revision_notice(revision, 3, &stating).reach,
        RevisionReach::Host,
        "a page of the evidence of a revision the worker has fenced names no reach"
    );
    drop(controller);
}
