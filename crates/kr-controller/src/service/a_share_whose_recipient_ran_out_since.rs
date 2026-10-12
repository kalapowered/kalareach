//! A share whose recipient's pairing ran out after it was checked.
//!
//! The recipient's pairing is decided before the session's worker is asked and before the waits for
//! the registry and the grant store, and the write is the last place a pairing that ran out during
//! them can be found. The check made there reads the clocks and nothing else, because it runs
//! inside a transaction on the grant store's connection: a pairing that stood when it was decided
//! and has run out when the share is written is refused, and one that never ends is not.

use std::sync::atomic::Ordering;

use kr_protocol::error::ErrorCode;

use super::a_voice_grant_on_the_floor::paired;
use super::authority_changes::AuthorityCaller;
use crate::service::net::tests::{daemon_on, manual_clocks};

/// KR-REQ-25.10: a share is not written to a device whose pairing ran out since it was checked, and
/// a paired device that delegates is given the one sentence it is always given. The controls are a
/// pairing that has time left and one that never ends, which are written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pairing_that_ran_out_since_the_check_is_refused_where_the_share_is_written() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let ending = paired(&controller, 1, Some(now + 60_000));
    let lasting = paired(&controller, 2, None);

    // The check made before the write anchors the pairing's lifetime, as it does in a request.
    for device in [&ending, &lasting] {
        assert!(
            controller
                .lifetimes()
                .in_force(device)
                .expect("the lifetime is read")
        );
    }
    let host = AuthorityCaller::Owner;
    controller
        .recipient_still_paired(host, ending.device_id, &ending.grant)
        .expect("a pairing with time left carries a share");

    wall.store(now + 120_000, Ordering::SeqCst);
    let refused = controller
        .recipient_still_paired(host, ending.device_id, &ending.grant)
        .expect_err("a pairing that ran out since is refused where the share is written");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(
        refused.to_string().contains("pairing has run out"),
        "{refused}"
    );

    // A delegating device is told one sentence whatever the reason.
    let delegating = AuthorityCaller::Device(lasting.device_id);
    let told = controller
        .recipient_still_paired(delegating, ending.device_id, &ending.grant)
        .expect_err("refused for a device that delegates too");
    assert!(
        !told.to_string().contains("pairing"),
        "it says nothing of a pairing: {told}"
    );

    controller
        .recipient_still_paired(host, lasting.device_id, &lasting.grant)
        .expect("a pairing that never ends is not affected by the time");
}
