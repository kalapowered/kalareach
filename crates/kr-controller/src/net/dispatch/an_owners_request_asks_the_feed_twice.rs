//! The authority feed's refusal at the record of an owner's request.
//!
//! The feed's refusal moves no revision and sets no latch, so the footing's question does not see
//! it. The record asks it where it takes its locks, inside the transaction and before anything
//! that allocates, and asks it again with no lock immediately before the write. A refusal that
//! rises in the last wait, between the two, stops the record with nothing written.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use kr_protocol::confirmation::{ConfirmationDisplay, OwnerConfirmationRequestResult};
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256};

use super::write_boundary::{Recording, paired_connection_expiring};
use crate::error::ControllerError;
use crate::service::an_owner_establishes_the_clock::registry;
use crate::service::net::owner::{Caller, Resolved};

/// What a request found at its record, and the refusal the feed puts on the connection's grants.
struct Found {
    answered: Result<OwnerConfirmationRequestResult, ControllerError>,
    rows: i64,
    feed_refusal: Option<String>,
}

async fn recorded_where_the_feed_refuses(refuses: bool) -> Found {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, _wall, clocks) = super::super::tests::manual_clocks();
    let controller = super::super::tests::daemon_on(&temp, clocks).await;
    let recording = Arc::new(Recording::default());
    let connection = paired_connection_expiring(
        &controller,
        71,
        &[ActionRight::SessionView],
        kr_protocol::grant::GrantExpiry::Never,
        Box::new(Arc::clone(&recording)),
    );
    let admitted = connection
        .admitted_at()
        .await
        .expect("the connection is admitted");
    let connection_id = connection.connection_id;
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    // The landing of a paired connection, whose grants the feed's refusal is asked of.
    let caller = Caller::local(ActorId::new("local:test").expect("a principal"))
        .landed(controller.pairing_landing(connection_id, Some(admitted), Some(deadline)));
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([5; 32]),
    );
    let (arrived, go) = controller.pause_after_the_record_asks_the_feed();
    let owner = Arc::clone(controller.owner_authority());
    let asking = tokio::task::spawn_blocking(move || {
        owner.request(
            &caller,
            Resolved {
                action: SensitiveAction::ChangeHostAuthority,
                digest: Digest256::from_bytes([6; 32]),
                destination: None,
                rights: CanonicalSet::new(),
                display: ConfirmationDisplay::EstablishClock,
                bootstrap: false,
            },
            action,
            &AtomicBool::new(false),
        )
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches its last wait");
    // The raise sets the refusal's word and then waits for every write to the pairing records that
    // is under way, and the paused record's transaction is one: the raise is started, the case
    // waits until the word is up, and the raise ends once the record has.
    let raising = refuses.then(|| {
        let controller = Arc::clone(&controller);
        tokio::spawn(async move {
            controller
                .move_a_feed_refusal(
                    crate::grants::RemoteRefusal::WITHDRAWAL_UNVERIFIED,
                    true,
                    crate::grants::HostPolicy::withdrawal_unverified,
                    crate::grants::HostPolicy::set_withdrawal_unverified,
                )
                .await;
        })
    });
    if raising.is_some() {
        tokio::time::timeout(Duration::from_secs(30), async {
            while controller
                .feed_grants_on(connection_id)
                .and_then(|grants| controller.feed_refusal_in(&grants))
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the refusal's word is raised");
    }
    go.send(()).expect("the record goes on");
    let answered = asking.await.expect("the request ends");
    if let Some(raising) = raising {
        raising.await.expect("the raise ends once the record has");
    }
    let feed_refusal = controller
        .feed_grants_on(connection_id)
        .and_then(|grants| controller.feed_refusal_in(&grants))
        .map(|refusal| refusal.detail());
    let rows = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            [action.0.get().as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .expect("the records are read");
    Found {
        answered,
        rows,
        feed_refusal,
    }
}

/// KR-REQ-09.12: where the feed puts no refusal on the connection's grants, the request is
/// recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_is_recorded_where_the_feed_refuses_nothing() {
    let found = recorded_where_the_feed_refuses(false).await;
    assert_eq!(found.feed_refusal, None);
    found.answered.expect("the request is answered");
    assert_eq!(found.rows, 1, "the record is written once");
}

/// KR-REQ-09.12: a refusal the feed raises in the last wait, after the first ask took its locks,
/// is found by the second ask, which takes none: the request is refused in the feed's words and
/// nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_is_refused_where_the_feed_refuses_in_the_last_wait() {
    let found = recorded_where_the_feed_refuses(true).await;
    let detail = found.feed_refusal.expect("the feed refuses the grants now");
    let Err(ControllerError::PermissionDenied { detail: told }) = found.answered else {
        panic!(
            "the request is refused as the feed refuses: {:?}",
            found.answered
        );
    };
    assert_eq!(told, detail);
    assert_eq!(found.rows, 0, "nothing is written");
}
