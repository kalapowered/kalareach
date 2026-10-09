//! A transfer of control from a device that holds a grant the given-up grant was delegated from.
//!
//! Such a device keeps control of the session through the grant above, and could revoke the
//! replacement through it, so handing the session over would hand over nothing. It is refused when
//! the transfer is described to the owner, before the owner is asked to confirm it.

use kr_protocol::ids::{ActionId, ActorId, DeviceId, GrantId, InvitationId, SessionId};
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::sharing::{AuthorityNotice, GrantTransferParams, RoleSelection, SessionRole};

use super::a_transfer_left_unanswered::{daemon, owner_share};
use super::a_voice_grant_on_the_floor::paired;
use crate::sharing::ShareRequest;

/// A paired device whose four keys this host holds, which a transfer can hand control to.
fn paired_with_all_keys(controller: &crate::service::Controller) -> DeviceId {
    let keys = kr_crypto::keys::DeviceKeys::generate()
        .expect("keys")
        .public_keys();
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let record = crate::service::net::devices::DeviceRecord {
        device_id,
        endpoint_id: keys.transport,
        device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
        authorisation: keys.authorisation,
        stored_envelope: Some(keys.stored_envelope),
        notification_preview: Some(keys.notification_preview),
        device_name: kr_protocol::pairing::DeviceName::new("A phone").expect("a name"),
        platform: kr_protocol::pairing::DevicePlatform::Ios,
        grant: kr_protocol::grant::Grant {
            grant_id: GrantId::new(kr_ipc::new_uuid()),
            parent_grant_id: Nullable::null(),
            issuer_device_id: controller.sharing().host_device_id(),
            recipient_device_id: device_id,
            authority_revision: controller.policy().authority_revision(),
            environment_selector: kr_protocol::grant::EnvironmentSelector::Any,
            session_selector: kr_protocol::grant::SessionSelector::None,
            actions: [kr_protocol::rights::ActionRight::SessionView]
                .into_iter()
                .collect(),
            history: kr_protocol::grant::HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: kr_protocol::scalars::CanonicalSet::new(),
                named_approvals: kr_protocol::scalars::CanonicalSet::new(),
            },
            expiry: kr_protocol::grant::GrantExpiry::Never,
            organisation: Nullable::null(),
        },
        paired_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    };
    controller.devices().commit(&record).expect("paired");
    device_id
}

/// KR-REQ-18.03: a transfer of a grant the giving device delegated to itself from a share it holds
/// is refused, and the same device's share, which descends from nothing it holds, is described.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_from_a_device_that_holds_the_grant_above_is_not_described() {
    let (_temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let session_id = SessionId::new(Uuid::from_bytes([0xa0; 16]));
    let giver = paired(&controller, 1, None).device_id;
    let taker = paired_with_all_keys(&controller);
    let share = owner_share(&controller, session_id, giver);
    let now_ms = kr_ipc::now_ms().get();

    // The giving device delegates an owner's share of the session to itself, and redeems it.
    let selection = RoleSelection::plain(SessionRole::Owner);
    let own = controller
        .sharing()
        .share(
            &ShareRequest {
                invitation_id: InvitationId::new(Uuid::from_bytes([3; 16])),
                grant_id: GrantId::new(Uuid::from_bytes([4; 16])),
                environment_id: controller.paths().environment_id(),
                session_id,
                issuer_device_id: giver,
                recipient_device_id: giver,
                parent_grant_id: Some(share.grant_id),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Some(600_000),
                live_screen: None,
                named_questions: Vec::new(),
                named_approvals: Vec::new(),
                authority_revision: controller.policy().authority_revision(),
                owner_confirmed: false,
                now_ms,
            },
            || Ok(()),
        )
        .expect("the device delegates to itself");
    controller
        .sharing()
        .redeem(
            own.preview.invitation_id,
            giver,
            now_ms + 1,
            || Ok(()),
            None,
        )
        .expect("and redeems it");

    let action_id = ActionId::new(Uuid::from_bytes([9; 16]));
    let describe = |from_grant_id: GrantId, to_device_id: DeviceId| {
        controller.transfer_plan(
            &actor_id,
            &GrantTransferParams {
                session_id,
                from_grant_id,
                to_device_id,
            },
            action_id,
        )
    };
    let refused = describe(own.grant.grant_id, taker)
        .expect_err("the device would keep control of the session through the grant above");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused}"
    );
    assert!(
        refused.to_string().contains("keep control"),
        "refused for the grant above, not for something else: {refused}"
    );
    let plan = describe(share.grant_id, taker).expect("a share that descends from nothing held");
    assert_eq!(plan.source_grant_id, share.grant_id);
    assert_eq!(plan.parent_grant_id, Nullable::null());
}
