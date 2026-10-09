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

/// KR-REQ-18.03: however long the chain between the grant the giving device holds and the one it
/// gives up, the grant above is found. A chain of three hundred grants held by other devices sits
/// between them, longer than any search a host could cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_grant_above_is_found_however_long_the_chain_below_it() {
    let (_temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let session_id = SessionId::new(Uuid::from_bytes([0xa0; 16]));
    let giver = paired(&controller, 1, None).device_id;
    let taker = paired_with_all_keys(&controller);
    let share = owner_share(&controller, session_id, giver);
    let now_ms = kr_ipc::now_ms().get();

    let mut parent = share.clone();
    for link in 0_u32..300 {
        let holder = if link == 299 {
            giver
        } else {
            DeviceId::new(Uuid::from_bytes(
                (0x1_0000 + u128::from(link)).to_be_bytes(),
            ))
        };
        let child = kr_protocol::grant::Grant {
            grant_id: GrantId::new(Uuid::from_bytes(
                (0x2_0000 + u128::from(link)).to_be_bytes(),
            )),
            parent_grant_id: Nullable::some(parent.grant_id),
            issuer_device_id: parent.recipient_device_id,
            recipient_device_id: holder,
            ..parent.clone()
        };
        controller
            .sharing()
            .grants()
            .issue(
                &crate::grants::GrantRecord {
                    grant: child.clone(),
                    session_id: Some(session_id),
                    issued_at_ms: now_ms,
                    activated_at_ms: Some(now_ms),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the chain is written");
        parent = child;
    }
    assert_eq!(parent.recipient_device_id, giver);

    let refused = controller
        .transfer_plan(
            &actor_id,
            &GrantTransferParams {
                session_id,
                from_grant_id: parent.grant_id,
                to_device_id: taker,
            },
            ActionId::new(Uuid::from_bytes([9; 16])),
        )
        .expect_err("the giving device holds the grant at the top of the chain");
    assert!(
        refused.to_string().contains("keep control"),
        "refused for the grant above: {refused}"
    );
}

/// KR-REQ-18.03: a chain that cannot be walked to its top is not one with no grant held above, so a
/// transfer from the end of it is refused rather than described. The grant in the middle of the
/// chain is gone from the store, which no host does, and the giving device holds a share above it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_with_a_missing_link_is_not_one_without_a_grant_above() {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let session_id = SessionId::new(Uuid::from_bytes([0xa0; 16]));
    let giver = paired(&controller, 1, None).device_id;
    let taker = paired_with_all_keys(&controller);
    let share = owner_share(&controller, session_id, giver);
    let now_ms = kr_ipc::now_ms().get();

    let mut parent = share.clone();
    let mut chain = Vec::new();
    for link in 0_u8..2 {
        let child = kr_protocol::grant::Grant {
            grant_id: GrantId::new(Uuid::from_bytes([0x40 + link; 16])),
            parent_grant_id: Nullable::some(parent.grant_id),
            issuer_device_id: parent.recipient_device_id,
            recipient_device_id: if link == 1 {
                giver
            } else {
                DeviceId::new(Uuid::from_bytes([0x50; 16]))
            },
            ..parent.clone()
        };
        controller
            .sharing()
            .grants()
            .issue(
                &crate::grants::GrantRecord {
                    grant: child.clone(),
                    session_id: Some(session_id),
                    issued_at_ms: now_ms,
                    activated_at_ms: Some(now_ms),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the chain is written");
        chain.push(child.clone());
        parent = child;
    }
    let describe = || {
        controller.transfer_plan(
            &actor_id,
            &GrantTransferParams {
                session_id,
                from_grant_id: chain[1].grant_id,
                to_device_id: taker,
            },
            ActionId::new(Uuid::from_bytes([9; 16])),
        )
    };
    assert!(
        describe()
            .expect_err("the giving device holds the share at the top")
            .to_string()
            .contains("keep control"),
        "with the chain whole, the share above is found"
    );

    // The middle of the chain is removed from the store.
    super::one_barrier_for_every_restriction::beside(&temp)
        .execute(
            "DELETE FROM grants WHERE grant_id = ?1",
            [chain[0].grant_id.get().as_bytes().as_slice()],
        )
        .expect("the row is removed");
    let refused =
        describe().expect_err("a chain that cannot be walked is not one with nothing above");
    assert!(
        refused.to_string().contains("names a parent"),
        "refused for the missing link, not described: {refused}"
    );

    // A device that asks to revoke a grant on the broken chain is refused in the words it is
    // refused in for a grant that does not exist: it learns nothing of which grants exist.
    let broken = controller
        .require_delegating_ancestor(giver, chain[1].grant_id)
        .expect_err("the chain cannot be walked");
    let missing = controller
        .require_delegating_ancestor(giver, GrantId::new(Uuid::from_bytes([0x77; 16])))
        .expect_err("there is no such grant");
    assert_eq!(broken.to_string(), missing.to_string());
}
