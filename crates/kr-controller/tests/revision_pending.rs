//! A worker that refused the announcement of a restriction is told the revision again.
//!
//! One real daemon on the loopback network with a real worker it adopts. The worker's dispatch
//! boundary is held for the daemon's first announcement, so the worker refuses it and the
//! restriction reports the worker as pending. Nothing a person does follows: no request that needs
//! the worker, no further restriction, no restart.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_controller::service::DEBT_PASS_INTERVAL;
use net_support::worker::Adopted;

/// How many passes of the daemon's own timer a worker that is reachable may stay pending for.
const PASSES_TO_BE_TOLD_WITHIN: u32 = 4;

/// KR-REQ-09.12, KR-ACC-022: a worker remains pending until it acknowledges the revision or is
/// confirmed ended. A worker that is reachable, and was refused only for the moment, acknowledges
/// within a bounded number of the daemon's own passes, with nobody asking it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_worker_that_refused_the_announcement_of_a_restriction_is_told_again_by_the_daemon() {
    let Adopted {
        host,
        owner: _,
        workers,
    } = Adopted::start(1).await;
    let service = Arc::clone(&workers[0].service);
    let refused_before = service.refusals_for_the_boundary();
    service.hold_the_boundary_for_one_announcement_after(0);

    let barrier = host
        .controller()
        .revoke_authority()
        .await
        .expect("the restriction is recorded");
    assert_eq!(
        service.refusals_for_the_boundary() - refused_before,
        1,
        "the worker refused the restriction's announcement"
    );
    assert!(
        !barrier.holds(),
        "a worker that refused the announcement is pending: {barrier:?}"
    );
    assert_eq!(
        host.controller()
            .revision_pending()
            .await
            .expect("the registry is read")
            .len(),
        1,
        "the registry holds the worker as not having acknowledged the revision"
    );

    let bound = DEBT_PASS_INTERVAL * PASSES_TO_BE_TOLD_WITHIN;
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let pending = host
            .controller()
            .revision_pending()
            .await
            .expect("the registry is read");
        if pending.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker was not told the revision again within {PASSES_TO_BE_TOLD_WITHIN} passes \
             of the debt pass ({bound:?}): still pending {pending:?}, announcements made {:?}",
            host.controller().announcements_sent_for_tests().len()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    host.stop().await;
    drop(workers);
}
