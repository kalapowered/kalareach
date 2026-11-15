//! A worker that has not acknowledged the revision in force is asked again by the daemon.
//!
//! Real daemons on the loopback network with real workers they adopt. A worker is made pending by
//! a refusal of the announcement of a restriction, or by a dispatch boundary that stays held, and
//! nothing a person does follows: no request that needs the worker, no further restriction, no
//! restart. What the cases watch is what the daemon's own pass does about it.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_controller::registry::LaunchPhase;
use kr_controller::service::{Controller, DEBT_PASS_INTERVAL};
use kr_protocol::ids::{ActorId, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::{RoleSelection, SessionRole};
use net_support::worker::{Adopted, Worker, share};
use net_support::{Host, Stopped, on_the_host, recipient};
use rusqlite::params;

/// How long a case waits for something the daemon does on its own timer, past the passes it is
/// owed.
const SLACK: Duration = Duration::from_secs(5);

/// The longest a refusal on a live link may take to be asked again: the next pass.
const REFUSED_AGAIN_WITHIN: Duration = Duration::from_secs(7);

/// Waits until `done` is true, polling, for at most `bound`.
async fn until(bound: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + bound;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {bound:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Waits until the registry holds no worker as pending, for at most `bound`.
async fn until_nobody_is_pending(controller: &Arc<Controller>, bound: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let pending = controller
            .revision_pending()
            .await
            .expect("the registry is read");
        if pending.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: still pending after {bound:?}: {pending:?}, asks made {}",
            controller.pending_asks_for_tests().len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The asks the pass made of one worker, as the times they began.
fn asks_of(controller: &Controller, session_id: SessionId) -> Vec<tokio::time::Instant> {
    controller
        .pending_asks_for_tests()
        .into_iter()
        .filter(|(asked, _)| *asked == session_id)
        .map(|(_, at)| at)
        .collect()
}

/// A restriction made while the worker's dispatch boundary is held: the worker is pending.
async fn restricted_while_the_boundary_is_held(
    controller: &Arc<Controller>,
    worker: &Worker,
) -> net_support::worker::HeldBoundary {
    let held = worker.hold_the_dispatch_boundary().await;
    let barrier = controller
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(
        !barrier.holds(),
        "a worker whose boundary is held is pending: {barrier:?}"
    );
    held
}

/// KR-REQ-09.12, KR-ACC-022: the ask that follows a refusal for a held dispatch boundary uses the
/// link the refusal came on.
///
/// The worker refused for the moment, which is a complete exchange: it has recorded what it owes,
/// and the link is good. An ask that opens a link of its own presents a generation at a boundary
/// that stays held, waits there for the whole of its acknowledgement time, and leaves one thread
/// and one socket at the worker for the length of the hold. The real boundary is held for three
/// passes, and the worker's own count of the connections it serves is what shows a link opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_ask_after_a_boundary_refusal_uses_the_same_link() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let service = Arc::clone(&worker.service);
    let connections = service.controller_connections_for_tests();
    let refused = service.refusals_for_the_boundary();
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;
    assert_eq!(
        service.refusals_for_the_boundary() - refused,
        1,
        "the restriction's own announcement met the held boundary"
    );

    // Three asks of the pass, each refused at once: the restriction's refusal and these make four.
    let window = DEBT_PASS_INTERVAL * 3 + SLACK;
    tokio::time::timeout(window, service.refused_for_the_boundary_beyond(refused + 3))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the worker was asked three more times within {window:?}, and refused {} in all",
                service.refusals_for_the_boundary() - refused
            )
        });
    assert_eq!(
        service.controller_connections_for_tests(),
        connections,
        "every ask used the link the first refusal came on, so the worker served no new connection"
    );

    held.release();
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the worker acknowledged once its boundary was free",
    )
    .await;
    assert_eq!(
        service.controller_connections_for_tests(),
        connections,
        "the acknowledgement came over the same link"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: a refusal on a live link is asked again after one pass, and no sooner.
///
/// A refusal costs one frame, so the interval stays at the pass's own five seconds however long the
/// boundary is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_refusal_on_a_live_link_is_asked_again_at_each_pass_and_no_sooner() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;

    until(
        DEBT_PASS_INTERVAL * 4 + SLACK,
        "four asks of the pass",
        || asks_of(host.controller(), session_id).len() >= 4,
    )
    .await;
    let asks = asks_of(host.controller(), session_id);
    for pair in asks.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= DEBT_PASS_INTERVAL - Duration::from_millis(500),
            "a worker is asked at most once a pass, and these asks were {gap:?} apart"
        );
        assert!(
            gap <= REFUSED_AGAIN_WITHIN,
            "a refusal on a live link is asked again at the next pass, and this took {gap:?}"
        );
    }
    held.release();
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: an ask that timed out doubles its interval, from five seconds towards a minute.
///
/// The worker's one connection is held by the case, so each ask waits for it for its whole
/// acknowledgement time and ends without an answer. The interval is counted from the end of the
/// ask: the second ask comes ten seconds after the first one ended, the third twenty after the
/// second.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_ask_that_timed_out_doubles_its_interval() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");
    let link = host
        .controller()
        .hold_a_worker_link_for_tests(session_id)
        .await
        .expect("the worker is reached");

    until(
        Duration::from_secs(90),
        "three asks of the pass, each ending without an answer",
        || asks_of(host.controller(), session_id).len() >= 3,
    )
    .await;
    let asks = asks_of(host.controller(), session_id);
    // Ten seconds for the ask to give up, then the interval.
    assert!(
        asks[1] - asks[0] >= Duration::from_secs(19),
        "the second ask came {:?} after the first, which gave up after 10 s and waits 10 s more",
        asks[1] - asks[0]
    );
    assert!(
        asks[2] - asks[1] >= Duration::from_secs(29),
        "the third ask came {:?} after the second, which gave up after 10 s and waits 20 s more",
        asks[2] - asks[1]
    );
    drop(link);
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: any answer puts the interval back to five seconds.
///
/// The first ask times out, which doubles the interval. The connection is then given back and the
/// boundary is held, so the next ask is refused on a live link: an answer. The ask after it comes
/// at the next pass and not after the doubled interval.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_answer_puts_the_interval_back_to_five_seconds() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");
    let link = host
        .controller()
        .hold_a_worker_link_for_tests(session_id)
        .await
        .expect("the worker is reached");
    until(
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the first ask of the pass",
        || !asks_of(host.controller(), session_id).is_empty(),
    )
    .await;
    let held = worker.hold_the_dispatch_boundary().await;
    // The first ask gives up after ten seconds; the connection goes back after it did.
    tokio::time::sleep(Duration::from_secs(11)).await;
    drop(link);

    until(
        Duration::from_secs(40),
        "two asks that met the held boundary",
        || asks_of(host.controller(), session_id).len() >= 3,
    )
    .await;
    let asks = asks_of(host.controller(), session_id);
    assert!(
        asks[1] - asks[0] >= Duration::from_secs(19),
        "the ask that timed out was followed after {:?}",
        asks[1] - asks[0]
    );
    assert!(
        asks[2] - asks[1] <= REFUSED_AGAIN_WITHIN,
        "the ask after an answer came {:?} later, not at the next pass",
        asks[2] - asks[1]
    );
    held.release();
    host.stop().await;
    drop(workers);
}

/// How much before its time the pass may ask a worker again, so that a worker that is due at the
/// next pass is asked at it.
const ASKED_EARLY_BY: Duration = Duration::from_millis(250);

/// KR-REQ-09.12: a worker that acknowledges a revision and sends no names with it is asked again
/// at an interval that doubles, and stays pending.
///
/// The acknowledgement is two statements, the revision installed and what the fence named, and the
/// worker makes the first only. Nothing a new ask can do changes that, so the asks are paced as
/// asks that failed are, ten seconds and then twenty after the one before, and not one for each
/// pass for as long as the daemon runs. The worker is no more and no less pending than before, and
/// no ask of this kind asks whether the worker has ended.
///
/// The case reads the instants the asks began at and measures the gaps between them: each ask comes
/// no sooner than its pace allows, and it does come. It counts nothing at an instant of its own,
/// since which pass an ask falls into depends on how long the asks before it took.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_acknowledgement_with_no_names_is_asked_again_at_a_doubling_interval() {
    asked_again_at_a_doubling_interval(Duration::ZERO).await;
}

/// KR-REQ-09.12: the interval after an acknowledgement with no names is counted from the end of the
/// ask, which here takes a second because the worker's link is not free.
///
/// The pass asks at its ticks, five seconds apart, so a second more in the first ask moves the
/// second ask from the tick that is ten seconds after the first to the one after it, and the third
/// with it. The asks still come at their paces, counted from where each ask ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_late_acknowledgement_with_no_names_is_asked_again_at_a_doubling_interval() {
    asked_again_at_a_doubling_interval(Duration::from_secs(1)).await;
}

/// The two cases above: the worker acknowledges with no names, and the first ask of the pass takes
/// `first_ask_takes` to be answered, the worker's link being held for that long when it is not
/// nothing.
async fn asked_again_at_a_doubling_interval(first_ask_takes: Duration) {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");
    let revision = barrier.authority_revision;
    worker.service.forget_evidence_for_tests(revision.get());
    let reconciled = host.controller().reconciliations_for_tests(session_id);
    let link = if first_ask_takes.is_zero() {
        None
    } else {
        Some(
            host.controller()
                .hold_a_worker_link_for_tests(session_id)
                .await
                .expect("the worker is reached"),
        )
    };

    until(DEBT_PASS_INTERVAL * 2 + SLACK, "the first ask", || {
        !asks_of(host.controller(), session_id).is_empty()
    })
    .await;
    // The first ask cannot end before this instant.
    let mut not_ended_before = asks_of(host.controller(), session_id)[0];
    if let Some(link) = link {
        tokio::time::sleep(first_ask_takes).await;
        not_ended_before = tokio::time::Instant::now();
        drop(link);
    }
    // The wait after an acknowledgement with no names is ten seconds from the end of the ask, and
    // twenty after the next.
    let mut interval = Duration::from_secs(10);
    for later in 1..=2 {
        until(
            interval + DEBT_PASS_INTERVAL + SLACK + first_ask_takes,
            "the next ask, at the first pass after its time",
            || asks_of(host.controller(), session_id).len() > later,
        )
        .await;
        let asks = asks_of(host.controller(), session_id);
        assert!(
            asks[later] >= not_ended_before + interval - ASKED_EARLY_BY,
            "ask {} came {:?} after the instant that the ask before it could not have ended before, \
             and its wait was {interval:?}: {:?}",
            later + 1,
            asks[later] - not_ended_before,
            asks.iter().map(|at| *at - asks[0]).collect::<Vec<_>>()
        );
        not_ended_before = asks[later];
        interval *= 2;
    }
    assert_eq!(
        host.controller().revision_pending().await.expect("a read"),
        vec![session_id],
        "the worker has installed the revision and is still pending"
    );
    assert!(
        !host
            .controller()
            .barrier_as_it_stands_for_tests()
            .await
            .expect("the barrier is read")
            .holds(),
        "the barrier counts it pending"
    );
    assert_eq!(
        host.controller().reconciliations_for_tests(session_id),
        reconciled,
        "an acknowledgement is not a worker that may have ended"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: an acknowledgement that carries the names, after one that did not, clears the
/// pending state, and the asks end.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_acknowledgement_with_the_names_after_one_without_clears_the_pending_state() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");
    let revision = barrier.authority_revision;
    worker.service.forget_evidence_for_tests(revision.get());

    until(DEBT_PASS_INTERVAL * 2 + SLACK, "the first ask", || {
        !asks_of(host.controller(), session_id).is_empty()
    })
    .await;
    // The first ask is over in a moment; it came to an acknowledgement with no names.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        host.controller().revision_pending().await.expect("a read"),
        vec![session_id],
        "no names, so the worker is pending"
    );
    worker.service.remember_evidence_for_tests(revision.get());

    until_nobody_is_pending(
        host.controller(),
        Duration::from_secs(30),
        "the ask that carried the names",
    )
    .await;
    // The second ask came when the interval after the first allowed it, and nothing asks after it.
    tokio::time::sleep(DEBT_PASS_INTERVAL * 3).await;
    assert_eq!(
        asks_of(host.controller(), session_id).len(),
        2,
        "the first ask and the one that was answered with the names"
    );
    assert!(
        host.controller()
            .fence_owed_for_tests()
            .await
            .expect("the registry is read")
            .is_none(),
        "the pass settled the fence once nobody was pending"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: a worker whose ask is stuck does not hold up the ask of another pending worker.
///
/// Both workers refused the restriction for the moment. The connection of the one the pass asks
/// first is held by the case, so its ask waits for the whole of its time. The other is told in the
/// same pass, and not after the first ask has given up.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_stuck_ask_does_not_hold_up_the_ask_of_another_pending_worker() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(2).await;
    for worker in &workers {
        worker
            .service
            .hold_the_boundary_for_one_announcement_after(0);
    }
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "both workers refused for the moment");
    let pending = host
        .controller()
        .revision_pending()
        .await
        .expect("the registry is read");
    assert_eq!(pending.len(), 2, "both workers are pending");
    // The pass asks in the order the registry lists them.
    let (stuck, free) = (pending[0], pending[1]);
    let link = host
        .controller()
        .hold_a_worker_link_for_tests(stuck)
        .await
        .expect("the worker is reached");

    until(
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the first ask of the pass at the worker whose connection is held",
        || !asks_of(host.controller(), stuck).is_empty(),
    )
    .await;
    let began = asks_of(host.controller(), stuck)[0];
    let by = began + Duration::from_secs(3);
    loop {
        let pending = host
            .controller()
            .revision_pending()
            .await
            .expect("the registry is read");
        if !pending.contains(&free) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < by,
            "the other worker was not told within 3 s of the stuck ask's beginning: {pending:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read")
            .contains(&stuck),
        "the worker whose connection is held is still pending"
    );
    drop(link);
    until_nobody_is_pending(
        host.controller(),
        Duration::from_secs(60),
        "the worker acknowledged once its connection was free",
    )
    .await;
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: the asks end when the worker has acknowledged the revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_asks_end_when_the_worker_acknowledged() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 4,
        "the worker acknowledged",
    )
    .await;
    let asked = asks_of(host.controller(), session_id).len();
    assert!(asked >= 1, "the acknowledgement was the pass's");

    tokio::time::sleep(DEBT_PASS_INTERVAL * 2 + Duration::from_secs(1)).await;
    assert_eq!(
        asks_of(host.controller(), session_id).len(),
        asked,
        "a worker that acknowledged is not asked again"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: the asks end when a worker is confirmed ended, and only then.
///
/// Two workers are pending, each behind a boundary that stays held. One has no live link, so the
/// pass's ask opens one that waits at the boundary: an ask that does not answer, after which the
/// pass asks whether the worker has ended. Its process is the test's own and is running, so the
/// answer is that it has not, and it must stay pending, be looked at again and keep the fence
/// owed. The other worker's session is closed, and it leaves the barrier and is asked no more.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_asks_end_when_the_worker_is_confirmed_ended() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(2).await;
    let ended = &workers[0];
    let live = &workers[1];
    let held_ended = ended.hold_the_dispatch_boundary().await;
    let held_live = live.hold_the_dispatch_boundary().await;
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "both workers are pending: {barrier:?}");
    host.controller()
        .forget_the_worker_link_for_tests(live.session_id)
        .await;
    until(
        Duration::from_secs(40),
        "an ask of each worker and a look at whether the live one has ended",
        || {
            !asks_of(host.controller(), ended.session_id).is_empty()
                && !asks_of(host.controller(), live.session_id).is_empty()
                && host.controller().reconciliations_for_tests(live.session_id) > 0
        },
    )
    .await;

    host.controller()
        .retire(&kr_protocol::session::ClosureRecord {
            session_id: ended.session_id,
            session_epoch: SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::CloseRequested,
            root_exit_code: Nullable::some(kr_protocol::scalars::U64::new(0)),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        })
        .await
        .expect("the closure is recorded");
    let asked = asks_of(host.controller(), ended.session_id).len();
    let looked_at = host.controller().reconciliations_for_tests(live.session_id);

    until(
        Duration::from_secs(70),
        "a look at the worker that is running, after the closure",
        || host.controller().reconciliations_for_tests(live.session_id) > looked_at,
    )
    .await;
    assert_eq!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read"),
        vec![live.session_id],
        "a worker confirmed ended is not pending, and a worker that is running still is"
    );
    assert_eq!(
        asks_of(host.controller(), ended.session_id).len(),
        asked,
        "a worker confirmed ended is not asked again"
    );
    assert!(
        host.controller()
            .fence_owed_for_tests()
            .await
            .expect("the registry is read")
            .is_some(),
        "a worker that is running keeps the fence owed"
    );
    held_live.release();
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 3 + SLACK,
        "the running worker acknowledged once its boundary was free",
    )
    .await;
    held_ended.release();
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: a pending worker outside the directory is not asked, and the pass itself asks
/// whether it has ended.
///
/// Nothing can be sent to a worker the daemon does not list, and what can still be established is
/// whether it is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_pending_worker_outside_the_directory_is_reconciled_by_the_pass_itself() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;
    until(DEBT_PASS_INTERVAL * 2 + SLACK, "an ask of the pass", || {
        !asks_of(host.controller(), session_id).is_empty()
    })
    .await;

    host.controller().forget_worker_for_tests(session_id).await;
    let asked = asks_of(host.controller(), session_id).len();
    let reconciled = host.controller().reconciliations_for_tests(session_id);
    until(
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the pass's own look at whether the worker has ended",
        || host.controller().reconciliations_for_tests(session_id) > reconciled,
    )
    .await;
    assert_eq!(
        asks_of(host.controller(), session_id).len(),
        asked,
        "nothing is sent to a worker outside the directory"
    );
    held.release();
    host.stop().await;
    drop(workers);
}

/// KR-REQ-10.45, KR-REQ-09.13: the names that other workers owe are collected while one worker's
/// ask is stuck.
///
/// One worker owes names of the restriction, and another is pending and cannot be reached: its
/// connection is held, so the pass's ask waits for it. One pass is arranged to find both at its
/// beginning, the names collectible and the ask due, and it must collect the names before it begins
/// the ask. A pass that asked first would hold the names for the whole of the ask and collect them
/// only after the ask gave up. The pending worker acknowledges once its connection is free.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_names_other_workers_owe_are_collected_while_one_ask_is_stuck() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(2).await;
    let owing = &workers[0];
    let stuck = &workers[1];
    let device = ActorId::new("device:phone").expect("a principal");
    owing.limit_evidence_page_for_tests(1);
    owing.seed_undispatched_intents(&device, 3);
    // No pass begins from here until the case lets this one go, so that the pass that finds the
    // names and the ask together is the one the case arranges, and not one that came before it.
    let (arrived, go) = host.controller().stop_before_an_evidence_pass_for_tests();
    host.controller().limit_evidence_pages_for_tests(0);
    stuck
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "one worker refused for the moment");
    assert_eq!(
        host.controller().names_owed_for_tests(),
        vec![owing.session_id],
        "the first worker owes names that the restriction did not collect"
    );
    let link = host
        .controller()
        .hold_a_worker_link_for_tests(stuck.session_id)
        .await
        .expect("the worker is reached");
    tokio::time::timeout(DEBT_PASS_INTERVAL * 2 + SLACK, arrived)
        .await
        .expect("a pass of the daemon began")
        .expect("the pass says that it has arrived");
    assert!(
        asks_of(host.controller(), stuck.session_id).is_empty(),
        "no ask of the worker whose connection is held was made before the pass"
    );
    // The pass finds the names collectible and the ask due, both at its beginning.
    host.controller().limit_evidence_pages_for_tests(usize::MAX);
    go.send(()).expect("the pass is waiting");
    until(
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the pass's ask of the worker whose connection is held",
        || !asks_of(host.controller(), stuck.session_id).is_empty(),
    )
    .await;
    // The ask waits for the connection the case holds, so it is still going. A pass that collects
    // first has collected the names by now; one that asks first holds them until the ask gives up.
    assert_eq!(
        host.controller().names_owed_for_tests(),
        Vec::new(),
        "the pass began its ask of the worker whose connection is held before it collected the \
         names that the first worker owed"
    );
    assert_eq!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read"),
        vec![stuck.session_id],
        "the second worker is still pending, its connection held"
    );

    drop(link);
    until_nobody_is_pending(
        host.controller(),
        Duration::from_secs(60),
        "the worker acknowledged once its connection was free",
    )
    .await;
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: nothing reports a restriction complete while a worker is pending,
/// and the fence it owed is settled once the pass has told the last worker.
///
/// A change made after every worker has acknowledged shows no fence owed, which is what a result
/// that reads the fence tells a person. While the boundary is held the fence stays owed, through
/// every ask; once it is free the pass's ask is acknowledged and the fence is settled, with no
/// announcement of the daemon's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_fence_is_owed_while_a_worker_is_pending_and_settled_when_the_pass_has_told_it() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;
    let announced = host.controller().announcements_sent_for_tests().len();
    until(DEBT_PASS_INTERVAL * 2 + SLACK, "an ask of the pass", || {
        asks_of(host.controller(), session_id).len() >= 2
    })
    .await;
    assert!(
        host.controller()
            .fence_owed_for_tests()
            .await
            .expect("the registry is read")
            .is_some(),
        "the fence is owed while a worker is pending, through every ask"
    );

    held.release();
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the worker acknowledged once its boundary was free",
    )
    .await;
    let deadline = tokio::time::Instant::now() + DEBT_PASS_INTERVAL * 2 + SLACK;
    while host
        .controller()
        .fence_owed_for_tests()
        .await
        .expect("the registry is read")
        .is_some()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the fence was still owed after the last worker acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        host.controller().announcements_sent_for_tests().len(),
        announced + host.controller().pending_asks_for_tests().len(),
        "the daemon made no announcement of its own: each one after the restriction's was an ask \
         of the pass"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: at most one presentation of the host waits at a worker's held
/// dispatch boundary, however many passes go by.
///
/// An ask that has no link opens one, and its presentation waits at the boundary for the whole
/// hold, on one thread of the worker's and with one of its connections. A host that opened another
/// at each ask would take the worker's connections one after another, the owner's own included.
/// The real boundary is held for twenty passes with no link in the slot, and the worker's own
/// count of the presentations waiting is what shows how many the host made.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_worker_whose_boundary_is_held_through_twenty_passes_holds_one_presentation_of_the_host()
{
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let service = Arc::clone(&worker.service);
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;
    host.controller()
        .forget_the_worker_link_for_tests(worker.session_id)
        .await;

    // Twenty passes. Between them, something other than the pass needs the link: whoever does waits
    // for the presentation that is under way, and begins none of its own.
    let until = tokio::time::Instant::now() + DEBT_PASS_INTERVAL * 20;
    while tokio::time::Instant::now() < until {
        let another = tokio::time::timeout(
            Duration::from_secs(3),
            host.controller()
                .hold_a_worker_link_for_tests(worker.session_id),
        )
        .await;
        assert!(
            another.is_err(),
            "nothing else gets a link while the boundary is held"
        );
        tokio::time::sleep(DEBT_PASS_INTERVAL * 3).await;
    }
    assert_eq!(
        service.presentations_waiting_for_tests(),
        1,
        "the host's presentations waiting at the held boundary after twenty passes"
    );
    tokio::time::timeout(Duration::from_secs(10), worker.client())
        .await
        .expect("a connection of another client is still accepted");

    held.release();
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 3 + SLACK,
        "the worker acknowledged once its boundary was free",
    )
    .await;
    assert_eq!(
        service.presentations_waiting_for_tests(),
        0,
        "the one presentation was decided once the boundary was free"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: after a restart the pass asks the worker that the barrier counts
/// pending, though the registry's row says it acknowledged, and the fence settles.
///
/// Two workers, one of which refuses the restriction: the other acknowledges, and its row says so.
/// The daemon stops, and starts again with that other worker refusing every announcement, so the
/// start's announcement is not answered. The registry then says every worker acknowledged and the
/// barrier of the new daemon counts one pending. The pass asks it at every pass while it refuses,
/// and the fence stays owed, which no check of the rows alone can see. It is settled once the
/// pass has been answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn after_a_restart_the_pass_asks_a_worker_the_barrier_counts_pending() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(2).await;
    let acknowledged_before = &workers[0];
    let refusing = &workers[1];
    let held_refusing = refusing.hold_the_dispatch_boundary().await;
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert_eq!(
        barrier.pending(),
        vec![refusing.session_id],
        "one worker refused, the other acknowledged"
    );
    let stopped = host.shut_down().await;
    held_refusing.release();
    let service = Arc::clone(&acknowledged_before.service);
    service.refuse_announcements_for_tests(true);
    let refused = service.refusals_for_the_boundary();
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;

    assert!(
        service.refusals_for_the_boundary() > refused,
        "the start's announcement met the boundary held"
    );
    assert!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read")
            .is_empty(),
        "the registry says every worker acknowledged: the start's announcement told the one, and \
         the other's row was written before the restart"
    );
    until(
        DEBT_PASS_INTERVAL * 3 + SLACK,
        "an ask of the pass for the worker the barrier counts pending",
        || !asks_of(host.controller(), acknowledged_before.session_id).is_empty(),
    )
    .await;
    tokio::time::sleep(DEBT_PASS_INTERVAL * 2).await;
    assert!(
        host.controller()
            .fence_owed_for_tests()
            .await
            .expect("the registry is read")
            .is_some(),
        "the barrier counts a worker pending, so the fence is owed while it refuses"
    );
    let mut client = host.client().await;
    let doctor: kr_protocol::hostinfo::HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape");
    let check = doctor
        .checks
        .iter()
        .find(|check| check.id() == "authority-revision")
        .expect("the doctor has the authority revision check");
    assert_eq!(
        check.status,
        kr_protocol::hostinfo::DoctorStatus::Warning,
        "the doctor counts the worker the barrier counts pending, though every row says \
         acknowledged: {}",
        check.detail()
    );
    drop(client);

    service.refuse_announcements_for_tests(false);
    let deadline = tokio::time::Instant::now() + DEBT_PASS_INTERVAL * 3 + SLACK;
    while host
        .controller()
        .fence_owed_for_tests()
        .await
        .expect("the registry is read")
        .is_some()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the fence was still owed {:?} after the worker stopped refusing, with {} asks of the \
             pass",
            DEBT_PASS_INTERVAL * 3 + SLACK,
            host.controller().pending_asks_for_tests().len()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    host.stop().await;
    drop(workers);
}

/// The revocation of a share that `session_id`'s worker has an undispatched intent of, composed
/// for a repeat: the actions the fence takes back are named in its result.
async fn a_revocation_to_repeat(
    host: &Host,
    owner: &kr_crypto::keys::DeviceKeys,
    worker: &Worker,
    intents: usize,
) -> (
    kr_ipc::client::LocalClient,
    kr_protocol::envelope::MutationRequest,
) {
    let (device, record) = recipient(host, owner).await;
    let granted = share(
        host,
        worker.session_id,
        &device,
        &record,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    worker.seed_undispatched_intents(&ActorId::new("device:phone").expect("a principal"), intents);
    let mut client = host.client().await;
    let mutation = client
        .compose(
            Method::GrantRevoke,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            on_the_host(host),
            &kr_protocol::sharing::GrantRevokeParams {
                grant_id: granted.grant_id,
            },
        )
        .await
        .expect("the revocation is composed");
    (client, mutation)
}

/// The answer to a revocation, or to its repeat, and the entry of one worker in its barrier.
async fn the_answer_to(
    client: &mut kr_ipc::client::LocalClient,
    mutation: &kr_protocol::envelope::MutationRequest,
    session_id: SessionId,
) -> (
    kr_protocol::sharing::RevocationResult,
    kr_protocol::action::WorkerBarrier,
) {
    let result: kr_protocol::sharing::RevocationResult = client
        .repeat(mutation)
        .await
        .expect("the daemon answers")
        .expect("the revocation is answered")
        .to_typed()
        .expect("a revocation result");
    let entry = result
        .barrier
        .workers
        .iter()
        .find(|entry| entry.session_id == session_id)
        .expect("the worker is in the barrier")
        .clone();
    (result, entry)
}

/// KR-REQ-09.12, KR-REQ-10.45: a repeat of a revocation names the actions at a worker that was
/// pending in the first answer, once that worker has acknowledged.
///
/// The first answer carries the worker as pending, with no names. The pass tells the worker, and
/// the names of what its fence took back reach the daemon. The repeat reads them into the entry
/// that was pending, as it does for a worker that owed names.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_a_revocation_names_the_actions_of_a_worker_that_acknowledged_later() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let (mut client, mutation) = a_revocation_to_repeat(&host, &owner, worker, 3).await;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let (_, first) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert!(
        !first.state.holds() && first.rejected_actions_total.get() == 0,
        "the first answer carries the worker as pending, with no names: {first:?}"
    );
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the worker acknowledged at a pass",
    )
    .await;

    let (_, repeated) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert!(
        repeated.state.holds(),
        "the repeat carries the worker's answer: {repeated:?}"
    );
    assert_eq!(
        repeated.rejected_actions_total.get(),
        3,
        "the repeat names the actions the fence took back at this worker: {repeated:?}"
    );
    drop(client);
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: a repeat of a revocation asks a worker that is still pending, and
/// carries what it answers.
///
/// The repeat comes straight after the first answer, before the pass has asked again, so the
/// worker is still pending and the repeat's own ask is the first to be answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_a_revocation_asks_the_worker_that_is_still_pending() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let (mut client, mutation) = a_revocation_to_repeat(&host, &owner, worker, 3).await;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let (_, first) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert!(
        !first.state.holds(),
        "the first answer carries the worker as pending: {first:?}"
    );

    let (_, repeated) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert!(
        repeated.state.holds() && repeated.rejected_actions_total.get() == 3,
        "the repeat asked the worker and carries what it named: {repeated:?}"
    );
    drop(client);
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: a repeat of a revocation says so when the worker no longer holds the
/// names.
///
/// A worker keeps the names of its newest eight revocations, and answers for an older one that it
/// holds none. The repeat asks, and the entry that was pending becomes the worker's answer: it
/// installed the revision, holds no names for it, and the revocation is not complete for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_a_revocation_says_so_when_the_worker_no_longer_holds_the_names() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let (mut client, mutation) = a_revocation_to_repeat(&host, &owner, worker, 3).await;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let (first_answer, first) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert!(
        !first.state.holds() && first.acknowledged_revision.0.is_none(),
        "the first answer carries the worker as pending, having installed nothing: {first:?}"
    );
    worker
        .service
        .forget_evidence_for_tests(first_answer.authority_revision.get());

    let (_, repeated) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert_eq!(
        repeated.acknowledged_revision.0,
        Some(first_answer.authority_revision),
        "the repeat carries the worker's answer, which installed the revision: {repeated:?}"
    );
    assert!(
        repeated.detail.contains("no longer holds"),
        "the entry says that the worker no longer holds the names: {repeated:?}"
    );
    drop(client);
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: a repeat of a revocation gives the ask of a pending worker the bound
/// and the deadline the pass's asks have, so its ask does not end with a page on the wire and the
/// worker's lease goes on renewing.
///
/// The repeat comes straight after the first answer, which lists the worker as pending. The worker
/// acknowledges at once and its names come a page at a time, each page after the first taking four
/// seconds. The fourth would begin with three of the ask's fifteen seconds left, inside the page's
/// own five: an ask that ends with that page on the wire is dropped with the link out, which stops
/// the renewal of the lease of a worker that has acknowledged. The repeat's ask returns what it has
/// before that page begins, and the repeat is answered with the lease as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_a_revocation_whose_ask_has_more_pages_than_its_time_leaves_the_renewal_going()
{
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    let (mut client, mutation) = a_revocation_to_repeat(&host, &owner, worker, 6).await;
    worker.limit_evidence_page_for_tests(1);
    worker
        .service
        .delay_evidence_continuations_for_tests(Duration::from_secs(4));
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let (_, first) = the_answer_to(&mut client, &mutation, session_id).await;
    assert!(
        !first.state.holds(),
        "the first answer carries the worker as pending: {first:?}"
    );

    let began = tokio::time::Instant::now();
    let (_, repeated) = the_answer_to(&mut client, &mutation, session_id).await;
    let lasted = began.elapsed();
    assert!(
        !host.controller().renewal_stopped_for_tests(session_id),
        "the worker acknowledged, and its renewal stopped when the repeat's ask ended"
    );
    assert!(
        lasted < Duration::from_secs(14),
        "the repeat was answered {lasted:?} after it was made, which is its bound and not a return \
         with what it had"
    );
    assert!(
        repeated.state.holds() || repeated.rejected_actions_total.get() > 0,
        "the repeat carries the worker's answer: {repeated:?}"
    );
    drop(client);
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: an ask with more pages of names than its time holds is over within its bound,
/// however long the names step after an acknowledgement would take.
///
/// The worker acknowledges at once, and every page of names after the first takes four seconds,
/// inside the page's own bound, so the pages that follow could take as long as there are pages. The
/// ask is over by fifteen seconds, and the pass, which settles the fence when its asks have ended,
/// settles it then. The ask ends by returning before a page that does not fit in what is left of
/// its time, which the next case reads. The bound itself, for the waits that no page's exchange
/// covers, has its case with the daemon's other link cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_ask_with_more_pages_of_names_than_its_time_holds_is_over_within_its_bound() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let device = ActorId::new("device:phone").expect("a principal");
    worker.limit_evidence_page_for_tests(1);
    worker.seed_undispatched_intents(&device, 10);
    worker
        .service
        .delay_evidence_continuations_for_tests(Duration::from_secs(4));
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");

    until(DEBT_PASS_INTERVAL * 2 + SLACK, "an ask of the pass", || {
        !asks_of(host.controller(), worker.session_id).is_empty()
    })
    .await;
    let began = asks_of(host.controller(), worker.session_id)[0];
    let by = began + Duration::from_secs(15) + SLACK;
    while host
        .controller()
        .fence_owed_for_tests()
        .await
        .expect("the registry is read")
        .is_some()
    {
        assert!(
            tokio::time::Instant::now() < by,
            "the ask had not ended {:?} after it began, so the fence was still owed",
            tokio::time::Instant::now() - began
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: an ask that has too little time left for another page of names gives the link back
/// and ends, and the worker's lease goes on renewing.
///
/// The worker acknowledges and its names come a page at a time, each page after the first taking
/// four seconds. The fourth of them would begin with three of the ask's fifteen seconds left,
/// inside the page's own five, and an ask that ends with the page on the wire is dropped with the
/// link out: a link that goes out of its holder's hand stops the renewal of the worker's lease,
/// though the worker has acknowledged. The ask returns what it has before that page begins, and
/// the pass collects the names that are left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_ask_with_too_little_time_for_another_page_leaves_the_renewal_of_the_worker_going() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    let device = ActorId::new("device:phone").expect("a principal");
    worker.limit_evidence_page_for_tests(1);
    worker.seed_undispatched_intents(&device, 6);
    worker
        .service
        .delay_evidence_continuations_for_tests(Duration::from_secs(4));
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "the worker refused for the moment");
    assert!(
        !host.controller().renewal_stopped_for_tests(session_id),
        "a refusal that was read to its end leaves the renewal as it was"
    );

    until(DEBT_PASS_INTERVAL * 2 + SLACK, "an ask of the pass", || {
        !asks_of(host.controller(), session_id).is_empty()
    })
    .await;
    let began = asks_of(host.controller(), session_id)[0];
    // The pass settles the fence once its asks have ended, so that is when this one has.
    let by = began + Duration::from_secs(15) + SLACK;
    while host
        .controller()
        .fence_owed_for_tests()
        .await
        .expect("the registry is read")
        .is_some()
    {
        assert!(
            tokio::time::Instant::now() < by,
            "the ask had not ended {:?} after it began",
            tokio::time::Instant::now() - began
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let lasted = tokio::time::Instant::now() - began;
    assert!(
        !host.controller().renewal_stopped_for_tests(session_id),
        "the worker acknowledged, and its renewal stopped when the ask ended"
    );
    assert!(
        lasted < Duration::from_secs(14),
        "the ask ended {lasted:?} after it began, which is its bound and not a return with what \
         it had"
    );
    assert_eq!(
        host.controller().names_owed_for_tests(),
        vec![session_id],
        "the ask left names for the pass to collect"
    );

    until(
        Duration::from_secs(60),
        "the pass to collect the names that the ask left",
        || host.controller().names_owed_for_tests().is_empty(),
    )
    .await;
    assert!(
        !host.controller().renewal_stopped_for_tests(session_id),
        "the renewal is going when the names are all collected"
    );
    assert!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read")
            .is_empty(),
        "the worker stays acknowledged"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: a long names step does not bring an ask of a refused worker forward.
///
/// One worker owes more names than a pass collects in the time between two passes, and another
/// refuses every ask for its held boundary. The names step comes before the asks in a pass, so the
/// refused worker is asked late in a pass that began long before. Its next ask is one pass after
/// that ask began, not one pass after the pass began, which would have made it due again as soon as
/// the pass ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_long_names_step_does_not_bring_the_next_ask_of_a_refused_worker_forward() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(2).await;
    let owing = &workers[0];
    let refusing = &workers[1];
    let device = ActorId::new("device:phone").expect("a principal");
    owing.limit_evidence_page_for_tests(1);
    owing.seed_undispatched_intents(&device, 5);
    owing
        .service
        .delay_evidence_continuations_for_tests(Duration::from_secs(3));
    host.controller().limit_evidence_pages_for_tests(0);
    let held = refusing.hold_the_dispatch_boundary().await;
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(!barrier.holds(), "one worker refused for its held boundary");
    assert_eq!(
        host.controller().names_owed_for_tests(),
        vec![owing.session_id],
        "the first worker owes names that the restriction did not collect"
    );
    host.controller().limit_evidence_pages_for_tests(usize::MAX);

    until(
        Duration::from_secs(60),
        "two asks of the worker that refuses",
        || asks_of(host.controller(), refusing.session_id).len() >= 2,
    )
    .await;
    let asks = asks_of(host.controller(), refusing.session_id);
    assert!(
        host.controller().names_owed_for_tests().is_empty(),
        "the pass collected the names, which took longer than a pass"
    );
    assert!(
        asks[1] - asks[0] >= DEBT_PASS_INTERVAL - Duration::from_millis(500),
        "the refused worker was asked again {:?} after it was asked, which is less than a pass",
        asks[1] - asks[0]
    );
    held.release();
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: two openings that wait at held boundaries do not keep a stopped daemon
/// alive.
///
/// Each opening is a task of the daemon that holds the daemon while it waits for the worker to
/// decide the presentation, which a held boundary delays for the whole hold. Two such tasks must not
/// count each other as owners of the daemon: once its owner has let it go the tasks end, and the
/// daemon and its environment's lock go with them. The case holds a weak handle and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_openings_waiting_at_held_boundaries_do_not_keep_a_stopped_daemon_alive() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(2).await;
    let mut held = Vec::new();
    for worker in &workers {
        held.push(worker.hold_the_dispatch_boundary().await);
    }
    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert!(
        !barrier.holds(),
        "both workers are pending behind held boundaries: {barrier:?}"
    );
    for worker in &workers {
        host.controller()
            .forget_the_worker_link_for_tests(worker.session_id)
            .await;
    }
    until(
        Duration::from_secs(40),
        "an opening of the host at each held boundary",
        || {
            workers
                .iter()
                .all(|worker| worker.service.presentations_waiting_for_tests() == 1)
        },
    )
    .await;

    // The owner lets the daemon go, which is all a stop does, and keeps no handle to it.
    let daemon = Arc::downgrade(host.controller());
    host.stop().await;
    until(
        Duration::from_secs(10),
        "the daemon let go with two openings waiting at held boundaries",
        || daemon.strong_count() == 0,
    )
    .await;
    for held in held {
        held.release();
    }
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: a repeat of a revocation resolves the entry of a worker that was
/// pending in the first answer and has ended since.
///
/// The barrier lets go of a worker that ended and names nothing, so the repeat finds no entry for
/// it. The session's closure is the record that it has ended, and the entry stands for the worker
/// as ended, not as pending for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_of_a_revocation_resolves_a_pending_worker_that_has_ended_since() {
    let Adopted {
        host,
        owner,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let (mut client, mutation) = a_revocation_to_repeat(&host, &owner, worker, 3).await;
    worker
        .service
        .hold_the_boundary_for_one_announcement_after(0);
    let (_, first) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert!(
        !first.state.holds(),
        "the first answer carries the worker as pending: {first:?}"
    );

    host.controller()
        .retire(&kr_protocol::session::ClosureRecord {
            session_id: worker.session_id,
            session_epoch: SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::CloseRequested,
            root_exit_code: Nullable::some(kr_protocol::scalars::U64::new(0)),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        })
        .await
        .expect("the closure is recorded");

    let (result, repeated) = the_answer_to(&mut client, &mutation, worker.session_id).await;
    assert_eq!(
        repeated.state,
        kr_protocol::action::BarrierState::Ended,
        "the repeat carries the worker as ended: {repeated:?}"
    );
    assert!(
        result.barrier.holds(),
        "the revocation is complete once its only worker has ended: {result:?}"
    );
    drop(client);
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-REQ-10.45: the fence stays owed while the registry says a worker has not
/// acknowledged, though the barrier as it stands holds for it.
///
/// The worker acknowledges, which the barrier takes before the registry's row is written, and the
/// write is refused. Settling the fence then would be settling it on the barrier alone: the row is
/// what the host reads after a restart. The fence is settled once the write has gone through at a
/// later ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_fence_stays_owed_while_a_row_says_pending_though_the_barrier_holds() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;
    host.controller()
        .refuse_acknowledged_rows_for_tests(true)
        .await
        .expect("the registry takes the seam");
    held.release();

    let deadline = tokio::time::Instant::now() + DEBT_PASS_INTERVAL * 3 + SLACK;
    loop {
        let barrier = host
            .controller()
            .barrier_as_it_stands_for_tests()
            .await
            .expect("the barrier is read");
        if barrier.holds() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker's acknowledgement did not reach the barrier: {barrier:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(DEBT_PASS_INTERVAL * 2).await;
    assert_eq!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read"),
        vec![worker.session_id],
        "the row of a worker whose write was refused says pending"
    );
    assert!(
        host.controller()
            .fence_owed_for_tests()
            .await
            .expect("the registry is read")
            .is_some(),
        "the fence is still owed while a row says pending, though the barrier holds"
    );

    host.controller()
        .refuse_acknowledged_rows_for_tests(false)
        .await
        .expect("the registry takes the seam");
    until_nobody_is_pending(
        host.controller(),
        Duration::from_secs(70),
        "the row was written at a later ask",
    )
    .await;
    let deadline = tokio::time::Instant::now() + DEBT_PASS_INTERVAL * 3 + SLACK;
    while host
        .controller()
        .fence_owed_for_tests()
        .await
        .expect("the registry is read")
        .is_some()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the fence was still owed after the row was written"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12: the pass looks at whether a worker has ended while a presentation of the host is
/// still waiting there, and makes no ask of it.
///
/// The worker's boundary is held and its link is gone, so the pass's first ask begins a
/// presentation that waits for the whole hold, and the ask itself ends in a look at whether the
/// worker has ended. Each pass after that only looks, at this worker alone: the count of looks at
/// this worker must keep rising while the asks of it do not.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_pass_looks_at_a_worker_whose_presentation_is_waiting_and_asks_it_no_more() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let worker = &workers[0];
    let held = restricted_while_the_boundary_is_held(host.controller(), worker).await;
    host.controller()
        .forget_the_worker_link_for_tests(worker.session_id)
        .await;
    until(
        Duration::from_secs(40),
        "the pass's ask of the worker, which begins a presentation that waits",
        || {
            worker.service.presentations_waiting_for_tests() == 1
                && !asks_of(host.controller(), worker.session_id).is_empty()
        },
    )
    .await;
    let asked = asks_of(host.controller(), worker.session_id).len();
    let looked = host
        .controller()
        .reconciliations_for_tests(worker.session_id);

    // The ask's own look at its end is one, and the passes after it are the others.
    until(
        DEBT_PASS_INTERVAL * 8 + SLACK,
        "three more looks at the worker: the ask's own, and two of passes while its presentation waits",
        || {
            host.controller()
                .reconciliations_for_tests(worker.session_id)
                >= looked + 3
        },
    )
    .await;
    assert_eq!(
        asks_of(host.controller(), worker.session_id).len(),
        asked,
        "a worker whose presentation is waiting is not asked again"
    );
    assert_eq!(
        worker.service.presentations_waiting_for_tests(),
        1,
        "the host's one presentation is still waiting"
    );
    held.release();
    until_nobody_is_pending(
        host.controller(),
        DEBT_PASS_INTERVAL * 3 + SLACK,
        "the worker acknowledged once its boundary was free",
    )
    .await;
    host.stop().await;
    drop(workers);
}

/// A daemon that starts again while one worker's dispatch boundary is held. The start meets the
/// held boundary with its own look at the worker, which the worker decides only when the boundary
/// is let go, so the worker is unlisted until then.
struct RestartedAtAHeldBoundary {
    host: Host,
    workers: Vec<Worker>,
    held: net_support::worker::HeldBoundary,
}

async fn restarted_with_the_boundary_held() -> RestartedAtAHeldBoundary {
    restarted_with_the_boundary_held_after(|_, _| {}).await
}

/// As [`restarted_with_the_boundary_held`], for a session whose worker the daemon that stopped had
/// claimed and not yet recorded: its reservation is a claim nobody resolved, and the registry has
/// no row of the worker. The start's look is then the claim's, which no list of the rows makes.
async fn restarted_with_a_claim_and_the_boundary_held() -> RestartedAtAHeldBoundary {
    restarted_with_the_boundary_held_after(leave_the_claim_unresolved).await
}

async fn restarted_with_the_boundary_held_after(
    leave: impl FnOnce(&Stopped, SessionId),
) -> RestartedAtAHeldBoundary {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let held = workers[0].hold_the_dispatch_boundary().await;
    let stopped = host.shut_down().await;
    leave(&stopped, workers[0].session_id);
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    RestartedAtAHeldBoundary {
        host,
        workers,
        held,
    }
}

/// Records the session's reservation as claimed by the worker's own key, and takes the worker's row
/// away, as a daemon that ended between the worker's claim and the record of the worker leaves
/// them.
fn leave_the_claim_unresolved(stopped: &Stopped, session_id: SessionId) {
    let tree = stopped.tree();
    let connection = rusqlite::Connection::open(tree.environment().registry_database())
        .expect("opens the registry");
    let session = session_id.get();
    let key: Vec<u8> = connection
        .query_row(
            "SELECT public_key FROM workers WHERE session_id = ?1",
            params![session.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the worker's row");
    connection
        .execute(
            "UPDATE reservations SET phase = ?2, claimed_key = ?3 WHERE session_id = ?1",
            params![
                session.as_bytes().as_slice(),
                LaunchPhase::Claimed.as_str(),
                key.as_slice()
            ],
        )
        .expect("the reservation is a claim");
    connection
        .execute(
            "DELETE FROM workers WHERE session_id = ?1",
            params![session.as_bytes().as_slice()],
        )
        .expect("the worker's row is taken away");
}

/// The sessions one `session.list` names.
async fn listed(client: &mut kr_ipc::client::LocalClient) -> Vec<SessionId> {
    let listed: kr_protocol::session::SessionListResult = client
        .request(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await
        .expect("the daemon answers")
        .expect("a list is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape");
    listed
        .sessions
        .iter()
        .map(|session| session.session_id)
        .collect()
}

/// Whether the daemon serves a read of the session: it does once it has reached the worker.
async fn read_is_served(client: &mut kr_ipc::client::LocalClient, session_id: SessionId) -> bool {
    client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await
        .expect("the daemon answers")
        .is_ok()
}

/// What a look that waits for a presentation under way would not meet: the bound that look waits
/// for is [`kr_controller::directory::RECONNECT_TIMEOUT`], and nothing else ends it while the
/// worker's boundary is held.
const ANSWERED_AT_ONCE: Duration = Duration::from_secs(3);

/// KR-REQ-09.12, KR-ACC-022: a client that polls `session.list` while a restarted daemon's worker
/// holds its dispatch boundary adds no presentation at that boundary.
///
/// A presentation stays at the boundary for the whole hold, on a thread of the worker's and with one
/// of its connections. The start leaves two: the one of its reading of the worker's published
/// descriptor, whose future is dropped after five seconds, and the one of its recovery's look at
/// the worker, which is a task of the worker's opening. Each list looks again for the unlisted
/// worker, so a look that presented anew would leave one more at each poll, and an hour of polling
/// would take the connections of the worker, its owner's own included. The three lists run
/// together; the worker's count of the presentations waiting is what shows how many the daemon
/// made, and it is the same after the lists as after the start. The lists are then answered in less
/// than two bounds, which looks that waited for the presentation under way, one list after the
/// other, would not manage.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_list_polled_while_a_boundary_is_held_leaves_one_presentation_at_it() {
    let RestartedAtAHeldBoundary {
        host,
        workers,
        held,
    } = restarted_with_the_boundary_held().await;
    let service = Arc::clone(&workers[0].service);
    let at_the_start = service.presentations_waiting_for_tests();
    let mut first = host.client().await;
    let mut second = host.client().await;
    let mut third = host.client().await;
    // Three bounds and the slack: the lists of a daemon that waits for each presentation, one after
    // the other, end inside it, so that the count below is read for them too.
    let began = tokio::time::Instant::now();
    tokio::time::timeout(
        kr_controller::directory::RECONNECT_TIMEOUT * 3 + SLACK * 2,
        async { tokio::join!(listed(&mut first), listed(&mut second), listed(&mut third)) },
    )
    .await
    .expect("the three lists were answered");
    let took = began.elapsed();
    assert_eq!(
        service.presentations_waiting_for_tests(),
        at_the_start,
        "the daemon's presentations waiting at the held boundary after three lists: the start \
         left {at_the_start}, and a list adds none"
    );
    assert!(
        host.controller()
            .presentation_in_flight_for_tests(workers[0].session_id),
        "the one presentation is still under way"
    );
    assert!(
        took < kr_controller::directory::RECONNECT_TIMEOUT * 2 + SLACK,
        "the three lists took {took:?}: a look that waits for the presentation under way holds up \
         the lists after it"
    );
    held.release();
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: the answer of a presentation that outlived the look that made it is
/// used: once the boundary is let go and the presentation's task has ended, the next read reaches
/// the session's worker, and no further challenge is presented for it.
///
/// The worker decides the presentation when the hold ends, long after the start's look gave up on
/// it. The next look after the task has ended finds that answer and adopts the worker on it, with
/// no restart of the daemon; adopting opens the daemon's normal link, which presents the
/// generation once more and is not a challenge. The daemon's count of the challenges its recoveries
/// presented is what shows a second one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_answer_of_a_presentation_that_outlived_its_look_is_used_when_the_boundary_is_let_go() {
    let RestartedAtAHeldBoundary {
        host,
        workers,
        held,
    } = restarted_with_the_boundary_held().await;
    let worker = &workers[0];
    let session_id = worker.session_id;
    let service = Arc::clone(&worker.service);
    let mut client = host.client().await;
    assert!(
        !read_is_served(&mut client, session_id).await,
        "a worker whose boundary is held is not reached"
    );

    held.release();
    until(
        Duration::from_secs(10),
        "the worker's decision of the presentation that waited",
        || service.presentations_waiting_for_tests() == 0,
    )
    .await;
    // The decision comes before the task has asked for the description and ended: a read between
    // them passes the session over.
    until(
        Duration::from_secs(10),
        "the end of the task of the presentation",
        || {
            !host
                .controller()
                .presentation_in_flight_for_tests(session_id)
        },
    )
    .await;
    assert_eq!(
        host.controller().challenges_presented_for_tests(),
        1,
        "the start's look presented the one challenge"
    );
    assert!(
        read_is_served(&mut client, session_id).await,
        "the next read of the session reaches the worker"
    );
    assert_eq!(
        host.controller().challenges_presented_for_tests(),
        1,
        "the read adopted the worker on the answer that waited, and presented no second challenge"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: a closure while a presentation waits at a held boundary ends the
/// daemon's task of it, with the daemon still running.
///
/// The presentation is the task of the session's opening. The closure takes the opening away, and
/// the task ends with it: the worker's boundary is still held, and nothing of the daemon waits at
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_closure_while_a_presentation_waits_ends_its_task() {
    let RestartedAtAHeldBoundary {
        host,
        workers,
        held,
    } = restarted_with_the_boundary_held().await;
    let session_id = workers[0].session_id;
    let task_runs = host
        .controller()
        .presentation_task_running_for_tests(session_id);
    assert!(task_runs(), "the start's look left its task running");
    host.controller()
        .retire(&kr_protocol::session::ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::CloseRequested,
            root_exit_code: Nullable::some(kr_protocol::scalars::U64::new(0)),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_ipc::now_ms(),
        })
        .await
        .expect("the closure is recorded");
    until(
        Duration::from_secs(10),
        "the end of the presentation's task after the closure, with the daemon running",
        || !task_runs(),
    )
    .await;
    assert!(
        !host
            .controller()
            .presentation_in_flight_for_tests(session_id),
        "the closure took the opening away"
    );
    host.stop().await;
    held.release();
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: a daemon's stop does not wait for a presentation that waits at a held
/// boundary, and the task of it does not keep the daemon.
///
/// Nothing ends the presentation but the stop: no closure, no decision of the worker. The daemon
/// still lets go of everything it holds while the boundary is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_stop_while_a_presentation_waits_does_not_wait_for_it() {
    let RestartedAtAHeldBoundary {
        host,
        workers,
        held,
    } = restarted_with_the_boundary_held().await;
    assert!(
        host.controller()
            .presentation_in_flight_for_tests(workers[0].session_id),
        "the start's look left its presentation under way"
    );
    let daemon = Arc::downgrade(host.controller());
    host.stop().await;
    until(
        Duration::from_secs(10),
        "the daemon let go with the boundary still held",
        || daemon.strong_count() == 0,
    )
    .await;
    held.release();
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: a look at the claim of a worker that the start could not reach is
/// answered at once while the start's presentation is still under way, and presents nothing.
///
/// The worker's reservation is a claim and the registry holds no row of it, so the look that a list
/// makes at every claim is the only one that reaches it, and no scan of rows passes it over. The
/// start's challenge waited its five seconds and left the presentation at the held boundary. A list
/// is then answered at once, with no wait for that presentation and none added to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_claim_whose_presentation_waits_is_looked_at_again_at_once() {
    let RestartedAtAHeldBoundary {
        host,
        workers,
        held,
    } = restarted_with_a_claim_and_the_boundary_held().await;
    let session_id = workers[0].session_id;
    let service = Arc::clone(&workers[0].service);
    assert!(
        host.controller()
            .presentation_in_flight_for_tests(session_id),
        "the start's look at the claim left its presentation under way"
    );
    let presented = host.controller().challenges_presented_for_tests();
    assert_eq!(presented, 1, "the start's look presented the one challenge");
    let waiting = service.presentations_waiting_for_tests();
    let mut client = host.client().await;
    tokio::time::timeout(ANSWERED_AT_ONCE, listed(&mut client))
        .await
        .expect("the list was answered at once, with no wait for the presentation under way");
    assert_eq!(
        host.controller().challenges_presented_for_tests(),
        presented,
        "a look at the claim while its presentation is under way presents no second challenge"
    );
    assert_eq!(
        service.presentations_waiting_for_tests(),
        waiting,
        "nothing is added at the held boundary"
    );
    held.release();
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.12, KR-ACC-022: a list that arrives while another look's presentation waits is
/// answered while that look still holds the worker's reservation through its wait.
///
/// The first list presents to the unlisted worker and waits for its answer, which the held boundary
/// does not give, and holds the worker's reservation for that wait. The second list finds the
/// presentation under way and passes the row over before it asks for the reservation, so it does
/// not wait for the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_list_is_answered_while_another_look_holds_the_reservation_through_its_wait() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let session_id = workers[0].session_id;
    let service = Arc::clone(&workers[0].service);
    // As a start that could not verify the worker leaves it, with its boundary held after.
    host.controller().forget_worker_for_tests(session_id).await;
    let held = workers[0].hold_the_dispatch_boundary().await;
    let mut first = host.client().await;
    let mut second = host.client().await;
    let first_list = tokio::spawn(async move { listed(&mut first).await });
    until(
        Duration::from_secs(10),
        "the first look's presentation at the held boundary",
        || {
            service.presentations_waiting_for_tests() == 1
                && host
                    .controller()
                    .presentation_in_flight_for_tests(session_id)
        },
    )
    .await;
    tokio::time::timeout(ANSWERED_AT_ONCE, listed(&mut second))
        .await
        .expect("the second list was answered at once, with no wait for the reservation");
    assert!(
        !first_list.is_finished(),
        "the second list was answered while the first look still waited for its presentation"
    );
    assert_eq!(
        service.presentations_waiting_for_tests(),
        1,
        "the second list added no presentation"
    );
    held.release();
    first_list.await.expect("the first list ends");
    host.stop().await;
    drop(workers);
}
