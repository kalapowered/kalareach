//! An action an earlier build claimed in the grant store alone, as the route check finds it.
//!
//! A voice mutation was claimed only in the grant store, so the record of its identifier has a
//! receipt and no route. Once the daemon starts, the route is there, and the identifier is spent on
//! every route that checks it.

use kr_protocol::ids::ActionId;
use kr_protocol::scalars::Digest256;

use super::a_voice_grant_on_the_floor::paired;
use crate::grants::ActionClaim;
use crate::service::net::tests::daemon;

/// KR-REQ-09.07: a receipt written in the shape the earlier build wrote it, with no route, is given
/// its route when the daemon starts: a second route under the identifier is refused from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voice_action_an_earlier_build_claimed_is_spent_on_every_route() {
    let temp = kr_ipc::testing::TempHost::create();
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let digest = Digest256::from_bytes([9; 32]);
    let actor_id = {
        let controller = daemon(&temp).await;
        let actor_id = paired(&controller, 51, None).principal();
        let now = kr_ipc::now_ms().get();
        let ActionClaim::Claimed { hold } = controller
            .sharing()
            .grants()
            .claim_action(&actor_id, action_id, &digest, now)
            .expect("claims")
        else {
            panic!("the first attempt claims the action");
        };
        controller
            .sharing()
            .grants()
            .retain_result(&hold, &[0xa0], now)
            .expect("keeps the answer");
        drop(hold);
        assert!(
            controller
                .devices()
                .action_route(&actor_id, action_id)
                .expect("the directory answers")
                .is_none(),
            "the earlier build recorded no route"
        );
        actor_id
    };

    let controller = daemon(&temp).await;
    let routed = controller
        .devices()
        .action_route(&actor_id, action_id)
        .expect("the directory answers")
        .expect("the receipt has its route once the daemon has started");
    assert_eq!(routed.payload_digest, Some(digest));
    assert_eq!(routed.session_id, None);
}
