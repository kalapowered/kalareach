//! A withdrawal of the invitations over a closed session that meets an end a request found and has
//! not written down yet.
//!
//! A request that finds a grant's end on the continuous clock owes the end its record and writes it
//! only once its own transaction is over, so for a moment the grant's row says nothing of it. The
//! withdrawal asks for the owed end beside the row, and leaves such an invitation as it ended.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use kr_protocol::ids::{GrantId, InvitationId, SessionId};
use kr_protocol::sharing::{AuthorityNotice, RoleSelection, SessionRole};

use super::a_voice_grant_on_the_floor::paired;
use crate::service::net::tests::{daemon_on, manual_clocks};
use crate::sharing::ShareRequest;

/// KR-REQ-18.13: a withdrawal leaves the grant of an invitation whose end a request found on the
/// continuous clock, both while the end is owed and once it is written down, and withdraws the
/// invitation that waits beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_leaves_an_invitation_whose_end_is_owed_its_record() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let now = wall.load(Ordering::SeqCst);
    let device = paired(&controller, 1, None);
    let session = SessionId::new(kr_ipc::new_uuid());
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let share = |byte: u8| {
        controller
            .sharing()
            .share(
                &ShareRequest {
                    invitation_id: InvitationId::new(kr_protocol::scalars::Uuid::from_bytes(
                        [byte; 16],
                    )),
                    grant_id: GrantId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
                    environment_id: controller.paths().environment_id(),
                    session_id: session,
                    issuer_device_id: controller.sharing().host_device_id(),
                    recipient_device_id: device.device_id,
                    parent_grant_id: None,
                    accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                    selection: selection.clone(),
                    lifetime_ms: Some(3_600_000),
                    live_screen: None,
                    named_questions: Vec::new(),
                    named_approvals: Vec::new(),
                    authority_revision: controller.policy().authority_revision(),
                    owner_confirmed: false,
                    now_ms: now,
                },
                || Ok(()),
            )
            .expect("the share is written")
            .grant
            .grant_id
    };
    let (found, beside) = (share(0x71), share(0x72));
    let grants = controller.sharing().grants();
    let read = grants
        .waiting_invitations(&BTreeSet::from([session]), now)
        .expect("the waiting invitations are read");
    let ids: Vec<GrantId> = read.iter().map(|record| record.grant.grant_id).collect();
    assert_eq!(ids.len(), 2);

    // A redeem finds the first grant's end on the continuous clock and owes it its record.
    controller.lifetimes().owe_stored_expiry(found);
    let withdrawn = grants
        .withdraw_waiting_grants(&ids, now)
        .expect("the withdrawal runs");
    assert_eq!(withdrawn, [beside]);

    // Once the end is written down it is still the grant's end.
    controller.lifetimes().settle_stored(grants);
    assert!(
        grants
            .withdraw_waiting_grants(&[found], now)
            .expect("the withdrawal runs")
            .is_empty()
    );
    assert!(
        grants
            .grant_expired_at(found)
            .expect("the end is read")
            .is_some()
    );
}
