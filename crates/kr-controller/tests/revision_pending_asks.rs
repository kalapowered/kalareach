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

use kr_controller::service::{Controller, DEBT_PASS_INTERVAL};
use kr_protocol::ids::{ActorId, SessionEpoch, SessionId};
use kr_protocol::scalars::Nullable;
use net_support::worker::{Adopted, Worker};

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

/// KR-REQ-09.12: the asks end when the worker is confirmed ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_asks_end_when_the_worker_is_confirmed_ended() {
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
    let asked = asks_of(host.controller(), session_id).len();
    assert!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read")
            .is_empty(),
        "a worker confirmed ended is not pending"
    );

    tokio::time::sleep(DEBT_PASS_INTERVAL * 2 + Duration::from_secs(1)).await;
    assert_eq!(
        asks_of(host.controller(), session_id).len(),
        asked,
        "a worker confirmed ended is not asked again"
    );
    held.release();
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
    let reconciled = host.controller().reconciliations_for_tests();
    until(
        DEBT_PASS_INTERVAL * 2 + SLACK,
        "the pass's own look at whether the worker has ended",
        || host.controller().reconciliations_for_tests() > reconciled,
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
/// connection is held, so the pass's ask waits for it. The names are collected by the pass all the
/// same, and the pending worker acknowledges once its connection is free.
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
    host.controller().limit_evidence_pages_for_tests(usize::MAX);

    until(
        DEBT_PASS_INTERVAL * 3 + Duration::from_secs(10),
        "the names the first worker owed were collected",
        || host.controller().names_owed_for_tests().is_empty(),
    )
    .await;
    assert_eq!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read"),
        vec![stuck.session_id],
        "the second worker is still pending, its connection held"
    );
    assert!(
        !asks_of(host.controller(), stuck.session_id).is_empty(),
        "the pass asked the worker whose connection is held"
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
