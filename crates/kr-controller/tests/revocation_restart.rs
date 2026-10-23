//! A revocation whose revision could not be published, finished by the next start.
//!
//! One real daemon on the loopback network with a real worker it adopts, and a share the daemon
//! writes and a device redeems. The registry is made to refuse the revision's update after the
//! revocation's own transaction has committed, and the daemon ends there. What the next start finds
//! is the debt the revocation's transaction wrote.

#![cfg(unix)]

mod net_support;

use std::time::Duration;

use kr_protocol::action::RevocationBarrier;
use kr_protocol::ids::ActorId;
use kr_protocol::method::Method;
use kr_protocol::sharing::{RoleSelection, SessionRole};
use net_support::worker::{Adopted, Worker, share};
use net_support::{Host, on_the_host, recipient};

/// KR-REQ-10.45: a revocation commits its withdrawal and the fence debt it owes in one
/// transaction, and the revision follows from the debt. When the registry cannot publish the
/// revision and the daemon ends there, the next start advances it once and the worker fences it;
/// the repeat of the revocation is answered with a barrier that holds at that revision.
///
/// The fault stays in place until the daemon has stopped, so nothing of the first daemon's debt
/// pass can publish the revision before the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_whose_revision_could_not_be_published_is_finished_by_the_next_start() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let session_id = workers[0].session_id;
    let (device, record) = recipient(&host, &owner).await;
    let granted = share(
        &host,
        session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    let before = host.controller().policy().authority_revision();

    let mut client = host.client().await;
    let mutation = client
        .compose(
            Method::GrantRevoke,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: granted.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let registry = rusqlite::Connection::open(host.tree().environment().registry_database())
        .expect("the registry opens");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_revision BEFORE UPDATE OF authority_revision ON environment
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");

    let refused = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers the call");
    assert!(
        refused.is_err(),
        "a revocation whose revision cannot be published is not answered as done"
    );
    assert_eq!(host.controller().policy().authority_revision(), before);
    assert!(
        !host
            .controller()
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty(),
        "the withdrawal committed with the fence it owes"
    );

    // The daemon ends with the fault still in place, and the fault is cleared after.
    drop(client);
    let stopped = host.shut_down().await;
    registry
        .execute_batch("DROP TRIGGER refuse_revision;")
        .expect("the fault is cleared");
    drop(registry);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let acknowledged = host.controller().policy().authority_revision().get() > before.get()
            && host
                .controller()
                .revision_pending()
                .await
                .expect("the daemon reports what is pending")
                .is_empty();
        if acknowledged {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the start did not advance the revision and have the worker fence it"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        host.controller().policy().authority_revision().get(),
        before.get() + 1,
        "the start advanced the revision once"
    );
    assert!(
        host.controller()
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty()
    );

    let mut client = host.client().await;
    let answered: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered from the rows")
        .to_typed()
        .expect("a revocation result");
    assert!(answered.revoked_grants.contains(&granted.grant_id));
    assert_eq!(answered.authority_revision.get(), before.get() + 1);
    assert!(answered.barrier.holds(), "{answered:?}");
    let fenced = answered
        .barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == session_id)
        .expect("the worker is in the barrier");
    assert_eq!(
        fenced.acknowledged_revision.0,
        Some(answered.authority_revision),
        "the worker fenced the revision the start advanced to: {fenced:?}"
    );
    host.stop().await;
    drop(workers);
}

/// How many intents the worker of a restart case takes back.
const SEEDED: usize = 3;

/// Announces the revision in force until its barrier holds and no worker owes a name, as a person
/// reads a result again: a worker that is busy for a moment answers the next announcement.
async fn until_the_revision_holds(host: &Host) -> RevocationBarrier {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let barrier = host
            .controller()
            .announce_authority_revision()
            .await
            .expect("the revision is announced");
        if barrier.holds()
            && barrier
                .workers
                .iter()
                .all(|worker| worker.names_pending.get() == 0)
        {
            return barrier;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the revision did not hold: {barrier:?}"
        );
        tokio::task::yield_now().await;
    }
}

/// The revision the registry holds the worker as having acknowledged.
fn acknowledged_in_the_registry(host: &Host) -> u64 {
    let registry = rusqlite::Connection::open(host.tree().environment().registry_database())
        .expect("the registry opens");
    let held: i64 = registry
        .query_row("SELECT acknowledged_revision FROM workers", [], |row| {
            row.get(0)
        })
        .expect("the worker is recorded");
    u64::try_from(held).expect("a revision")
}

/// A worker that refused a revocation while it was inside a dispatch transition and fenced it by
/// itself afterwards, a daemon that stopped before it asked the worker about that revision again,
/// and a registry that went `later` revisions on without the daemon announcing them. Returns the
/// daemon that started on that registry, once its start has announced the revision in force and
/// the worker has acknowledged it, the workers, and the revision the registry held for the worker.
///
/// `first_acknowledged` says whether the worker had acknowledged an earlier revocation before the
/// refused one: the registry then holds that revision for it, and holds nothing for it otherwise.
async fn a_daemon_restarted_after_a_worker_fenced_alone(
    first_acknowledged: bool,
    later: u64,
) -> (Host, Vec<Worker>, u64) {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let mut acknowledged = 0;
    if first_acknowledged {
        host.controller()
            .revoke_authority()
            .await
            .expect("the revocation is recorded");
        let barrier = until_the_revision_holds(&host).await;
        acknowledged = barrier.authority_revision.get();
        assert_eq!(
            acknowledged_in_the_registry(&host),
            acknowledged,
            "the registry holds the revision the worker acknowledged"
        );
    }
    worker.seed_undispatched_intents(&ActorId::new("device:phone").expect("a principal"), SEEDED);

    let boundary = worker.hold_the_dispatch_boundary().await;
    let refused = tokio::time::timeout(
        Duration::from_secs(60),
        host.controller().revoke_authority(),
    )
    .await
    .expect("the revocation reports")
    .expect("the revocation is recorded");
    assert_eq!(refused.pending(), vec![worker.session_id], "{refused:?}");
    let announced = host.controller().announcements_sent_for_tests().len();
    boundary.release();
    worker.service.fence_what_is_owed_for_tests();
    assert_eq!(
        host.controller().announcements_sent_for_tests().len(),
        announced,
        "nothing asked the worker about the refused revision again before the stop"
    );

    let stopped = host.shut_down().await;
    let environment_id = stopped.tree().environment_id();
    let mut registry = kr_controller::registry::Registry::open(
        stopped.tree().environment().registry_database(),
        environment_id,
    )
    .expect("the registry opens");
    // What a revocation commits before it announces, and the daemon stops before it does.
    for _ in 0..later {
        registry
            .advance_authority_revision()
            .expect("the revision advances");
    }
    drop(registry);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    (host, workers, acknowledged)
}

/// KR-REQ-10.45, 09.13: a daemon that restarts asks a worker what it fenced alone before the
/// stop, and the result of the revision its start announces names it.
///
/// The worker refused the revocation while it was inside a dispatch transition and fenced it by
/// itself afterwards, so the names are filed under a revision the daemon never asked about. The
/// registry holds the revision before it for the worker, and the daemon's memory of what it told
/// the worker is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_restarted_daemon_names_what_a_worker_fenced_alone_before_it_stopped() {
    let (host, workers, _) = a_daemon_restarted_after_a_worker_fenced_alone(true, 1).await;
    let barrier = until_the_revision_holds(&host).await;
    let reported = barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == workers[0].session_id)
        .expect("the worker is in the barrier");
    assert_eq!(
        reported.rejected_actions.len(),
        SEEDED,
        "every intent the worker took back on its own is named: {reported:?}"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-10.45, 09.13: a worker the registry holds at nought is read as well. It acknowledged
/// nothing before the refused revocation, so the revisions after nought are the ones it may have
/// fenced alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_restarted_daemon_reads_a_worker_the_registry_holds_at_nought() {
    let (host, workers, _) = a_daemon_restarted_after_a_worker_fenced_alone(false, 1).await;
    let barrier = until_the_revision_holds(&host).await;
    let reported = barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == workers[0].session_id)
        .expect("the worker is in the barrier");
    assert_eq!(reported.rejected_actions.len(), SEEDED, "{reported:?}");
    host.stop().await;
    drop(workers);
}

/// KR-REQ-10.45, 09.13: a gap of more revisions than a result carries is read for the newest of
/// them, and the result says that the others are not read.
///
/// The worker fenced the refused revision alone, and the registry then went ten revisions on
/// without the daemon announcing them. The worker was told none of those ten, so it cannot say
/// what its fence named for them, and the result says so for the seven it asks about.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_restarted_daemon_reads_the_newest_revisions_of_a_long_gap_and_says_the_rest_are_not_read()
 {
    let (host, workers, acknowledged) =
        a_daemon_restarted_after_a_worker_fenced_alone(true, 10).await;
    let barrier = until_the_revision_holds(&host).await;
    let reported = barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == workers[0].session_id)
        .expect("the worker is in the barrier");
    let revision = barrier.authority_revision.get();
    let asked: std::collections::BTreeSet<u64> = host
        .controller()
        .announcements_sent_for_tests()
        .iter()
        .filter(|sent| sent.evidence_from == 0 && sent.revision > acknowledged)
        .filter(|sent| sent.revision < revision)
        .map(|sent| sent.revision)
        .collect();
    assert_eq!(
        asked,
        (revision - 7..revision).collect(),
        "the worker is asked about the newest seven revisions of the gap"
    );
    assert!(
        reported.detail.contains("cannot say") && reported.detail.contains("not read"),
        "the result says what the worker could not answer for and what it did not read: {:?}",
        reported.detail
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-10.45, 09.13: a restarted daemon collects the names a revocation left owing, which the
/// repeat of that revocation then carries.
///
/// The daemon is stopped with most of the names still at the worker, as a revocation with more
/// names than one announcement collects leaves them. The worker keeps them for the daemon that
/// took none, and the new daemon asks for them again once it has started.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_restarted_daemon_collects_the_names_a_revocation_left_owing() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let session_id = workers[0].session_id;
    let (device, record) = recipient(&host, &owner).await;
    let granted = share(
        &host,
        session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    let owed = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    workers[0].seed_undispatched_intents(&ActorId::new("device:phone").expect("a principal"), owed);
    host.controller().limit_evidence_pages_for_tests(0);

    let mut client = host.client().await;
    let mutation = client
        .compose(
            Method::GrantRevoke,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: granted.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    let first: kr_protocol::sharing::RevocationResult = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is done")
        .to_typed()
        .expect("a revocation result");
    let given = first
        .barrier
        .workers
        .iter()
        .find(|reported| reported.session_id == session_id)
        .expect("the worker is in the barrier");
    assert!(
        given.names_pending.get() > 0,
        "the names did not all arrive with the first answer: {given:?}"
    );

    drop(client);
    let stopped = host.shut_down().await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    host.controller()
        .what_workers_hold_is_read_back_for_tests()
        .await;

    let mut client = host.client().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let repeated: kr_protocol::sharing::RevocationResult = client
            .repeat(&mutation)
            .await
            .expect("the daemon answers")
            .expect("the revocation is answered")
            .to_typed()
            .expect("a revocation result");
        let carried = repeated
            .barrier
            .workers
            .iter()
            .find(|reported| reported.session_id == session_id)
            .expect("the worker is in the barrier");
        if carried.names_pending.get() == 0 {
            assert_eq!(
                carried.rejected_actions_total.get(),
                owed as u64,
                "the repeat carries every name the worker took back: {carried:?}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the repeat never carried the names: {carried:?}"
        );
        tokio::task::yield_now().await;
    }
    host.stop().await;
    drop(workers);
}

/// KR-REQ-10.45, 09.13: a restarted daemon asks a worker about the newest eight revocations it
/// acknowledged and no older one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_restarted_daemon_asks_a_worker_about_the_newest_eight_revocations_only() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    for _ in 0..10 {
        host.controller()
            .revoke_authority()
            .await
            .expect("the revocation is recorded");
        until_the_revision_holds(&host).await;
    }
    let held = acknowledged_in_the_registry(&host);
    assert!(held > 8, "more revocations than a worker keeps names for");

    let stopped = host.shut_down().await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    host.controller()
        .what_workers_hold_is_read_back_for_tests()
        .await;

    let asked: std::collections::BTreeSet<u64> = host
        .controller()
        .announcements_sent_for_tests()
        .iter()
        .filter(|sent| sent.evidence_from == 0)
        .map(|sent| sent.revision)
        .collect();
    assert_eq!(
        asked,
        (held - 7..=held).collect(),
        "the worker is asked about the newest eight revisions it acknowledged"
    );
    host.stop().await;
    drop(workers);
}
