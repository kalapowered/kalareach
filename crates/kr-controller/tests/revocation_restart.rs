//! A revocation whose revision could not be published, finished by the next start.
//!
//! One real daemon on the loopback network with a real worker it adopts, and a share the daemon
//! writes and a device redeems. The registry is made to refuse the revision's update after the
//! revocation's own transaction has committed, and the daemon ends there. What the next start finds
//! is the debt the revocation's transaction wrote.

#![cfg(unix)]

mod net_support;

use std::time::Duration;

use kr_protocol::method::Method;
use kr_protocol::sharing::{RoleSelection, SessionRole};
use net_support::environment::Environment;
use net_support::worker::share;
use net_support::{on_the_host, recipient};

/// KR-REQ-10.45: a revocation commits its withdrawal and the fence debt it owes in one
/// transaction, and the revision follows from the debt. When the registry cannot publish the
/// revision and the daemon ends there, the next start advances it once and the worker fences it;
/// the repeat of the revocation is answered with a barrier that holds at that revision.
///
/// The fault stays in place until the daemon has stopped, so nothing of the first daemon's debt
/// pass can publish the revision before the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_whose_revision_could_not_be_published_is_finished_by_the_next_start() {
    let Environment {
        host,
        owner,
        worker,
    } = Environment::start().await;
    let session_id = worker.session_id;
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
    drop(worker);
}
