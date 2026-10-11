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

/// The capability a worker states when it reads a revision's reach.
fn stating() -> kr_protocol::scalars::CanonicalSet<kr_protocol::ids::CapabilityId> {
    kr_protocol::scalars::CanonicalSet::from_iter([kr_protocol::ids::CapabilityId::new(
        kr_protocol::local::AUTHORITY_REVISION_REACH,
    )
    .expect("a capability")])
}

fn a_grant(byte: u8) -> kr_protocol::ids::GrantId {
    kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
}

/// Raises one barrier for a change whose debt reaches `reach`, and returns the revision it
/// advanced to.
async fn barrier_for(controller: &Controller, reach: Reach) -> kr_protocol::ids::AuthorityRevision {
    let debt = controller
        .owe_debt("a change", reach.clone())
        .expect("written");
    let own = controller.publish_debts(&[(debt, reach)]);
    controller.barrier(own).await.expect("a barrier");
    kr_protocol::ids::AuthorityRevision::new(revision(controller).await)
}

fn grants_reach(bytes: &[u8]) -> Reach {
    let grants: std::collections::BTreeSet<_> = bytes.iter().map(|byte| a_grant(*byte)).collect();
    Reach::Grants {
        with_input: grants.clone(),
        grants,
    }
}

/// A worker that has acknowledged no revision.
fn nothing_held() -> kr_protocol::ids::AuthorityRevision {
    kr_protocol::ids::AuthorityRevision::new(0)
}

fn within(
    since: kr_protocol::ids::AuthorityRevision,
    grants: &[u8],
) -> kr_protocol::worker::RevisionReach {
    kr_protocol::worker::RevisionReach::Within {
        since,
        grants: grants.iter().map(|byte| a_grant(*byte)).collect(),
        devices: kr_protocol::scalars::CanonicalSet::new(),
    }
}

fn one_before(
    revision: kr_protocol::ids::AuthorityRevision,
) -> kr_protocol::ids::AuthorityRevision {
    kr_protocol::ids::AuthorityRevision::new(revision.get() - 1)
}

/// KR-REQ-10.45: a revision is announced with the grants its withdrawal reached to a worker that
/// says it reads them, and as the whole host's to a worker that does not, and for a page of the
/// evidence that follows its first announcement.
///
/// A worker of an earlier build ends the link a frame with a member it does not know arrived on,
/// so the member is never sent to one, and no worker built here can be made to stand in for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_does_not_read_a_revisions_reach_is_announced_the_whole_host() {
    use kr_protocol::scalars::CanonicalSet;
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let revision = barrier_for(&controller, grants_reach(&[0x61])).await;

    assert_eq!(
        controller
            .revision_notice(revision, nothing_held(), 0, &stating())
            .reach,
        within(one_before(revision), &[0x61])
    );
    assert_eq!(
        controller
            .revision_notice(revision, nothing_held(), 0, &CanonicalSet::new())
            .reach,
        RevisionReach::Host,
        "a worker that states nothing is told nothing of the reach"
    );
    assert_eq!(
        controller
            .revision_notice(revision, nothing_held(), 3, &stating())
            .reach,
        RevisionReach::Host,
        "a page of the evidence of a revision the worker has fenced names no reach"
    );
    drop(controller);
}

/// KR-REQ-10.45: the reach of a revision is what its barrier captured: every debt it took joined,
/// and the whole host as soon as one of them reaches the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revision_is_announced_with_every_debt_its_barrier_captured_or_as_the_host() {
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;

    // Two withdrawals whose debts one barrier takes: a grant and a device, and then a grant with a
    // restriction that reaches the host in any position.
    let first = controller
        .owe_debt("a grant", grants_reach(&[0x61, 0x62]))
        .expect("written");
    let second = controller
        .owe_debt(
            "a device",
            Reach::Device(kr_protocol::ids::DeviceId::new(
                kr_protocol::scalars::Uuid::from_bytes([0x71; 16]),
            )),
        )
        .expect("written");
    let own = controller.publish_debts(&[
        (first, grants_reach(&[0x61, 0x62])),
        (
            second,
            Reach::Device(kr_protocol::ids::DeviceId::new(
                kr_protocol::scalars::Uuid::from_bytes([0x71; 16]),
            )),
        ),
    ]);
    controller.barrier(own).await.expect("a barrier");
    let both = kr_protocol::ids::AuthorityRevision::new(revision(&controller).await);
    let RevisionReach::Within {
        grants, devices, ..
    } = controller
        .revision_notice(both, nothing_held(), 0, &stating())
        .reach
    else {
        panic!("a grant and a device are named");
    };
    assert_eq!((grants.len(), devices.len()), (2, 1));

    for position in 0..3 {
        let mut debts = vec![
            (
                controller
                    .owe_debt("a", grants_reach(&[0x63]))
                    .expect("written"),
                grants_reach(&[0x63]),
            ),
            (
                controller
                    .owe_debt("b", grants_reach(&[0x64]))
                    .expect("written"),
                grants_reach(&[0x64]),
            ),
        ];
        debts.insert(
            position,
            (
                controller
                    .owe_debt("the host", Reach::Host)
                    .expect("written"),
                Reach::Host,
            ),
        );
        let own = controller.publish_debts(&debts);
        controller.barrier(own).await.expect("a barrier");
        let revision = kr_protocol::ids::AuthorityRevision::new(revision(&controller).await);
        assert_eq!(
            controller
                .revision_notice(revision, nothing_held(), 0, &stating())
                .reach,
            RevisionReach::Host,
            "a restriction that reaches the host is the host's whatever else it took ({position})"
        );
    }
    drop(controller);
}

/// KR-REQ-10.45: a worker that has missed some revisions, or that is told of a later revision than
/// the one that was written, is told what the revisions it has not fenced withdrew: the reaches of
/// the consecutive revisions that name their authority are joined, back to the first one that
/// cannot be named, which the notice says it follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revision_is_announced_with_the_reach_of_the_revisions_before_it_that_name_theirs() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;

    let host = barrier_for(&controller, Reach::Host).await;
    let first = barrier_for(&controller, grants_reach(&[0x61])).await;
    let second = barrier_for(&controller, grants_reach(&[0x62])).await;
    assert_eq!(
        controller
            .revision_notice(second, nothing_held(), 0, &stating())
            .reach,
        within(host, &[0x61, 0x62]),
        "the two revisions after the one that reached the host"
    );
    assert_eq!(
        controller
            .revision_notice(first, nothing_held(), 0, &stating())
            .reach,
        within(host, &[0x61]),
        "a revision announced after a later one was written is described as it was"
    );
    assert!(
        controller
            .revision_notice(host, nothing_held(), 0, &stating())
            .reach
            .is_host()
    );
    drop(controller);
}

/// KR-REQ-10.45: a revision is named exactly. A viewer's grant holds no input lease, so a
/// revocation that reached only viewers names nobody and is not the whole host's; and the debts one
/// barrier takes together are never more than one notice names: the rest stay published and have
/// a barrier of their own, with the debts of the change that raises it taken first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revision_names_the_input_grants_it_reached_and_never_more_than_a_notice_carries() {
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let many = |first: u32, count: u32| -> std::collections::BTreeSet<_> {
        (first..first + count)
            .map(|number| {
                let mut bytes = [0_u8; 16];
                bytes[..4].copy_from_slice(&number.to_be_bytes());
                kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
            })
            .collect()
    };
    let named = |notice: kr_protocol::worker::AuthorityRevisionNotice| match notice.reach {
        RevisionReach::Within {
            since,
            grants,
            devices,
        } => (since, grants, devices),
        RevisionReach::Host => panic!("the revision names whose authority it withdrew"),
    };

    // Viewers only: the revision names nobody, and is not the host's.
    let viewers = barrier_for(
        &controller,
        Reach::Grants {
            grants: many(1, 3),
            with_input: std::collections::BTreeSet::new(),
        },
    )
    .await;
    let (since, grants, devices) =
        named(controller.revision_notice(viewers, one_before(viewers), 0, &stating()));
    assert_eq!(since, one_before(viewers));
    assert!(grants.is_empty() && devices.is_empty());

    // Two debts of 3,000 input grants each, published together: one barrier takes the first, the
    // second waits for its own.
    let bound = u32::try_from(kr_protocol::worker::MAX_REVISION_REACH_NAMES).expect("fits");
    let big = |first: u32| {
        let grants = many(first, 3 * bound / 4);
        Reach::Grants {
            with_input: grants.clone(),
            grants,
        }
    };
    let (one, other) = (
        controller.owe_debt("one", big(10_000)).expect("written"),
        controller.owe_debt("other", big(20_000)).expect("written"),
    );
    let before = revision(&controller).await;
    let own = controller.publish_debts(&[(one, big(10_000)), (other, big(20_000))]);
    controller.barrier(own).await.expect("a barrier");
    // One revision for the debts that fit together: the notice for it names one debt in full,
    // not both. (The revision a barrier reports is the one in force when it announces, which the
    // debt pass may already have advanced for the other debt.)
    let first = kr_protocol::ids::AuthorityRevision::new(before + 1);
    let (_, grants, _) = named(controller.revision_notice(first, one_before(first), 0, &stating()));
    assert_eq!(
        grants.len(),
        usize::try_from(3 * bound / 4).expect("fits"),
        "the debts one barrier takes together are one notice's worth"
    );
    drop(controller);
}

/// KR-REQ-10.45: a worker not told a revision before the next advanced is told every revision after
/// the one it acknowledged by name, oldest first, as many to a notice as fit one: two revisions that
/// fit alone and not together are two notices, each following the one before, so the worker has fenced
/// what each describes and keeps every lease no revision named; a worker that is told only the
/// newest has fenced nothing of the older and fences every caller under a grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_that_missed_a_revision_is_told_each_in_order_by_name() {
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let bound = u32::try_from(kr_protocol::worker::MAX_REVISION_REACH_NAMES).expect("fits");
    let input_grants = |first: u32, count: u32| {
        let grants: std::collections::BTreeSet<_> = (first..first + count)
            .map(|number| {
                let mut bytes = [0_u8; 16];
                bytes[..4].copy_from_slice(&number.to_be_bytes());
                kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
            })
            .collect();
        Reach::Grants {
            with_input: grants.clone(),
            grants,
        }
    };
    let older = barrier_for(&controller, input_grants(1, bound / 2 + 1)).await;
    let newer = barrier_for(&controller, input_grants(100_000, bound / 2 + 1)).await;
    let count = usize::try_from(bound / 2 + 1).expect("fits");

    let notices = controller.revision_notices(newer, one_before(older), 0, &stating());
    let told: Vec<_> = notices
        .iter()
        .map(|notice| match &notice.reach {
            RevisionReach::Within { since, grants, .. } => (notice.revision, *since, grants.len()),
            RevisionReach::Host => panic!("the revisions are named"),
        })
        .collect();
    assert_eq!(
        told,
        vec![(older, one_before(older), count), (newer, older, count)],
        "each revision by name, oldest first, each following the one before"
    );

    // Two that fit together are one notice.
    let small = barrier_for(&controller, input_grants(200_000, 10)).await;
    let notices = controller.revision_notices(small, newer, 0, &stating());
    assert_eq!(notices.len(), 1);
    drop(controller);
}

/// KR-REQ-10.45: a worker that missed revisions in more groups than the daemon keeps reports for is
/// told one revision of the whole host's, and not the notices a result could not read: it takes the lease of
/// every caller under a grant, which is safe, and its fence files its names under the revision the
/// result is for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_told_more_notices_than_a_result_reads_is_told_the_host() {
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let bound = u32::try_from(kr_protocol::worker::MAX_REVISION_REACH_NAMES).expect("fits");
    let input_grants = |first: u32, count: u32| {
        let grants: std::collections::BTreeSet<_> = (first..first + count)
            .map(|number| {
                let mut bytes = [0_u8; 16];
                bytes[..4].copy_from_slice(&number.to_be_bytes());
                kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
            })
            .collect();
        Reach::Grants {
            with_input: grants.clone(),
            grants,
        }
    };
    let groups = crate::authority::MAX_HELD_FENCE_REPORTS;
    let mut newest = None;
    for number in 0..=groups {
        let first = u32::try_from(number).expect("fits") * 10_000;
        newest = Some(barrier_for(&controller, input_grants(first, bound / 2 + 1)).await);
    }
    let newest = newest.expect("revisions were advanced");
    let behind = kr_protocol::ids::AuthorityRevision::new(newest.get() - (groups as u64 + 1));

    // Each revision is a group of its own, and one more than a result reads is told as the host's.
    let notices = controller.revision_notices(newest, behind, 0, &stating());
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].revision, newest);
    assert_eq!(notices[0].reach, RevisionReach::Host);

    // One fewer is told by name, each in a notice of its own.
    let notices = controller.revision_notices(
        newest,
        kr_protocol::ids::AuthorityRevision::new(behind.get() + 1),
        0,
        &stating(),
    );
    assert_eq!(notices.len(), groups);
    assert!(
        notices
            .iter()
            .all(|notice| matches!(notice.reach, RevisionReach::Within { .. }))
    );
    drop(controller);
}

/// A grant of the kind a device holds below another, for the store, that carries `actions`.
fn a_typists_grant(
    id: kr_protocol::ids::GrantId,
    parent: Option<kr_protocol::ids::GrantId>,
    actions: &[kr_protocol::rights::ActionRight],
) -> kr_protocol::grant::Grant {
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{AuthorityRevision, DeviceId};
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};

    kr_protocol::grant::Grant {
        grant_id: id,
        parent_grant_id: Nullable(parent),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: actions.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(1)),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

/// KR-REQ-10.45: a revocation fences everything of its subtree that anyone held, not only what
/// it revoked itself. A grant a concurrent revocation withdrew just before the subtree was read is
/// already revoked and is not this call's, and its own change may not have raised its barrier yet;
/// the barrier of the revocation that reaches it names it, and a proposal nobody redeemed, which
/// has no holder, is not named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_names_every_held_grant_of_its_subtree_including_one_revoked_a_moment_before()
{
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let (parent, child, proposal) = (a_grant(0x81), a_grant(0x82), a_grant(0x83));
    for (id, parent_id, activated) in [
        (parent, None, true),
        (child, Some(parent), true),
        (proposal, Some(parent), false),
    ] {
        controller
            .sharing()
            .grants()
            .issue(
                &crate::grants::GrantRecord {
                    grant: a_typists_grant(
                        id,
                        parent_id,
                        &[
                            kr_protocol::rights::ActionRight::SessionView,
                            kr_protocol::rights::ActionRight::TerminalInput,
                        ],
                    ),
                    session_id: None,
                    issued_at_ms: 1_000,
                    activated_at_ms: activated.then_some(1_000),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("written");
    }

    // The child's revocation has committed and has not published its debt.
    controller
        .sharing()
        .revoke(child, 2_000, || Ok(()), None)
        .expect("the child is revoked");

    let before = revision(&controller).await;
    controller
        .revoke_grant(parent, super::Audience::Host, None, None)
        .await
        .expect("the parent is revoked");
    let revision = kr_protocol::ids::AuthorityRevision::new(revision(&controller).await);
    assert_eq!(revision.get(), before + 1);
    let RevisionReach::Within { grants, .. } = controller
        .revision_notice(revision, nothing_held(), 0, &stating())
        .reach
    else {
        panic!("the revocation names its grants");
    };
    assert!(grants.contains(&parent), "the parent");
    assert!(
        grants.contains(&child),
        "the child a concurrent revocation withdrew first"
    );
    assert!(
        !grants.contains(&proposal),
        "a proposal nobody redeemed has no holder"
    );
    drop(controller);
}

/// KR-REQ-10.45: the revocation of a delegation tree at the most it may hold is named in full, to
/// the grant, in one notice, and names nothing of another tree: the host never needs the fence of
/// the whole host for a revocation of a device's own subtree, and the lease of a device that holds
/// a grant of another tree is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_of_a_tree_at_the_limit_is_named_in_full_and_names_nothing_else() {
    use kr_protocol::rights::ActionRight::{SessionView, TerminalInput};
    use kr_protocol::worker::RevisionReach;

    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::a_floor_owed_its_record::daemon(&temp).await;
    let typing = [SessionView, TerminalInput];
    let issue = |grant: kr_protocol::grant::Grant| {
        controller
            .sharing()
            .grants()
            .issue(
                &crate::grants::GrantRecord {
                    grant,
                    session_id: None,
                    issued_at_ms: 1_000,
                    activated_at_ms: Some(1_000),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("written");
    };
    let numbered = |number: u32| {
        let mut bytes = [0_u8; 16];
        bytes[..4].copy_from_slice(&number.to_be_bytes());
        bytes[15] = 0x44;
        kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
    };
    let (root, other_root) = (numbered(0), numbered(u32::MAX));
    issue(a_typists_grant(root, None, &typing));
    issue(a_typists_grant(other_root, None, &typing));
    let limit = u32::try_from(crate::grants::MAX_GRANTS_PER_TREE).expect("fits");
    for number in 1..limit {
        issue(a_typists_grant(numbered(number), Some(root), &typing));
    }
    issue(a_typists_grant(
        numbered(u32::MAX - 1),
        Some(other_root),
        &typing,
    ));

    let before = revision(&controller).await;
    controller
        .revoke_grant(root, super::Audience::Host, None, None)
        .await
        .expect("the tree is revoked");
    let revision = kr_protocol::ids::AuthorityRevision::new(revision(&controller).await);
    assert_eq!(revision.get(), before + 1);
    let RevisionReach::Within {
        since,
        grants,
        devices,
    } = controller
        .revision_notice(revision, one_before(revision), 0, &stating())
        .reach
    else {
        panic!("a tree at the limit is named, not the whole host");
    };
    assert_eq!(since, one_before(revision));
    assert!(devices.is_empty());
    assert_eq!(
        grants.len(),
        crate::grants::MAX_GRANTS_PER_TREE,
        "every grant of the tree, to the last"
    );
    assert!(grants.contains(&root) && grants.contains(&numbered(limit - 1)));
    assert!(
        !grants.contains(&other_root) && !grants.contains(&numbered(u32::MAX - 1)),
        "and nothing of another tree"
    );
    drop(controller);
}
