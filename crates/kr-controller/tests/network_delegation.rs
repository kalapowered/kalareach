//! A paired device delegating a narrower grant from the one it holds, over real paired connections.
//!
//! What these demonstrate: KR-REQ-18.03 (delegation narrows what the delegator holds and no
//! more; a device revokes only what descends from a grant it holds) and KR-REQ-23.49 (the sharing
//! method group over a paired device: `grant.create`, `grant.revoke` and `grant.list`, each decided
//! under a share the device holds). Nothing here starts a worker, so every answer is the daemon's.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, GrantId, QuestionId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, Uuid};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantListParams, GrantListResult,
    GrantRedeemParams, GrantRevokeParams, RevocationResult, RoleSelection, SessionRole,
};
use net_support::{
    Host, RawDevice, delegated, holds, on_the_host, on_the_session, owned_by, recipient,
};

/// What a device sends to delegate `selection` of `session_id` to `recipient` from `parent`.
fn delegation(
    session_id: SessionId,
    recipient: kr_protocol::ids::DeviceId,
    parent: Option<GrantId>,
    selection: RoleSelection,
    lifetime_ms: u64,
) -> GrantCreateParams {
    GrantCreateParams {
        session_id,
        recipient_device_id: recipient,
        parent_grant_id: Nullable(parent),
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: Nullable::some(DurationMs::new(lifetime_ms)),
        owner_confirmation: Nullable::null(),
    }
}

/// Sends `grant.create` from a device and returns what the host answered.
async fn create(
    host: &Host,
    from: &RawDevice,
    params: &GrantCreateParams,
) -> Result<GrantCreateResult, ProtocolError> {
    from.mutate(
        Method::GrantCreate,
        ActionId::new(kr_ipc::new_uuid()),
        on_the_session(host, params.session_id),
        params,
    )
    .await
    .map(|answer| answer.to_typed().expect("decodes"))
}

/// Sends `grant.revoke` from a device and returns what the host answered.
async fn revoke(
    host: &Host,
    from: &RawDevice,
    action: ActionId,
    grant_id: GrantId,
) -> Result<RevocationResult, ProtocolError> {
    from.mutate(
        Method::GrantRevoke,
        action,
        on_the_host(host),
        &GrantRevokeParams { grant_id },
    )
    .await
    .map(|answer| answer.to_typed().expect("decodes"))
}

/// KR-REQ-18.03 and KR-REQ-23.49: a device holding an owner's share delegates a viewer's share of
/// the session to another device over its own connection. The grant is the device's to issue, and
/// is delegated from the grant it holds; it authorises nothing until the other device redeems it;
/// the device lists what it issued and revokes it, which ends the connection acting under it, and
/// the grant it delegated from is untouched. A repeat of the revocation is answered as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_a_device_delegates_a_narrower_grant_and_revokes_what_it_delegated() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (boss, boss_record) = recipient(&host, &owner).await;
    let (friend, friend_record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (above, boss_connection) = owned_by(&host, session_id, &boss, &boss_record).await;

    let params = delegation(
        session_id,
        friend_record.device_id,
        Some(above.grant.grant_id),
        RoleSelection::plain(SessionRole::Viewer),
        600_000,
    );
    let created = create(&host, &boss_connection, &params)
        .await
        .expect("the device delegates from the grant it holds");
    let child = &created.grant;
    assert_eq!(child.issuer_device_id, boss_record.device_id);
    assert_eq!(child.recipient_device_id, friend_record.device_id);
    assert_eq!(child.parent_grant_id, Nullable::some(above.grant.grant_id));
    assert!(child.permits(ActionRight::SessionView));
    assert!(
        !child.permits(ActionRight::TerminalInput) && !child.permits(ActionRight::SessionShare),
        "a viewer's share is narrower than the owner's it comes from"
    );
    assert!(
        !holds(&host, child.grant_id),
        "a delegation authorises nothing until the device it names redeems it"
    );

    let connection = RawDevice::connect(&host, &friend, &friend_record).await;
    connection
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            },
        )
        .await
        .expect("the friend redeems it");
    assert!(holds(&host, child.grant_id));
    // The friend's pairing grant reaches no session, so the delegation is the only thing that
    // admits it; there is no worker to answer, which is not a refusal of the grant.
    let read = connection
        .read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await;
    assert_ne!(
        read.expect_err("there is no worker").code,
        ErrorCode::PermissionDenied,
        "the friend is admitted to the session by what it was given"
    );

    // The device lists what it issued, and nothing it was issued.
    let listed: GrantListResult = boss_connection
        .read(
            Method::GrantList,
            &GrantListParams {
                session_id: Nullable::some(session_id),
                include_resolved: false,
            },
        )
        .await
        .expect("the device lists what it issued")
        .to_typed()
        .expect("decodes");
    let listed: Vec<GrantId> = listed
        .grants
        .iter()
        .map(|summary| summary.grant.grant_id)
        .collect();
    assert_eq!(listed, vec![child.grant_id]);

    // And revokes it: the connection acting under it ends, the grant it came from stands, and a
    // repeat of the action is answered as it was.
    let action = ActionId::new(kr_ipc::new_uuid());
    let revoked = revoke(&host, &boss_connection, action, child.grant_id)
        .await
        .expect("the device revokes what it delegated");
    assert!(revoked.revoked_grants.contains(&child.grant_id));
    assert!(!holds(&host, child.grant_id));
    assert!(holds(&host, above.grant.grant_id));
    assert_eq!(
        connection
            .answered_before_closing(RequestId::new(u64::MAX), std::time::Duration::from_secs(5))
            .await,
        Some(false),
        "the friend's connection is ended with the grant it acted under"
    );
    let again = revoke(&host, &boss_connection, action, child.grant_id)
        .await
        .expect("a repeat of the action is answered");
    assert_eq!(again, revoked);
    host.stop().await;
}

/// KR-REQ-18.03 and KR-REQ-23.49: a device delegates nothing it does not hold and nothing wider
/// than what it holds, and revokes nothing that does not descend from a grant it holds. Each
/// refusal writes nothing, and the one that exceeds the parent is decided before the session is
/// asked for any text of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_a_device_delegates_nothing_wider_than_it_holds_and_revokes_only_its_own() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (boss, boss_record) = recipient(&host, &owner).await;
    let (friend, friend_record) = recipient(&host, &owner).await;
    let (stranger, stranger_record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (above, boss_connection) = owned_by(&host, session_id, &boss, &boss_record).await;
    let (strangers, stranger_connection) =
        owned_by(&host, session_id, &stranger, &stranger_record).await;
    let viewer = RoleSelection::plain(SessionRole::Viewer);
    let nothing_written = |host: &Host| {
        assert!(
            host.controller()
                .sharing()
                .grants()
                .records_for_device(friend_record.device_id)
                .expect("readable")
                .is_empty(),
            "nothing was written for the friend"
        );
    };

    // Longer than the grant it is delegated from.
    let refused = create(
        &host,
        &boss_connection,
        &delegation(
            session_id,
            friend_record.device_id,
            Some(above.grant.grant_id),
            viewer.clone(),
            2 * 60 * 60 * 1000,
        ),
    )
    .await
    .expect_err("a delegation does not outlive its parent");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    nothing_written(&host);

    // Naming a question its parent does not name. The session has no worker here: a request that
    // reached the preview would be refused for that, so a refusal for the grant is one decided
    // before anything of the session was asked for.
    let refused = create(
        &host,
        &boss_connection,
        &delegation(
            session_id,
            friend_record.device_id,
            Some(above.grant.grant_id),
            RoleSelection {
                named_questions: [QuestionId::new(Uuid::from_bytes([5; 16]))]
                    .into_iter()
                    .collect(),
                ..viewer.clone()
            },
            600_000,
        ),
    )
    .await
    .expect_err("a delegation names nothing its parent does not");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("history"), "{refused:?}");
    nothing_written(&host);

    // Including the screen, which its parent does not include.
    let refused = create(
        &host,
        &boss_connection,
        &delegation(
            session_id,
            friend_record.device_id,
            Some(above.grant.grant_id),
            RoleSelection {
                include_live_screen: true,
                ..viewer.clone()
            },
            600_000,
        ),
    )
    .await
    .expect_err("a delegation shows nothing its parent does not");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    nothing_written(&host);

    // Delegating from nothing, from a grant that is another device's, and from a pairing grant.
    let from_nothing = delegation(
        session_id,
        friend_record.device_id,
        None,
        viewer.clone(),
        600_000,
    );
    let refused = create(&host, &boss_connection, &from_nothing)
        .await
        .expect_err("a device delegates from a grant it holds");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    let refused = create(
        &host,
        &boss_connection,
        &delegation(
            session_id,
            friend_record.device_id,
            Some(strangers.grant.grant_id),
            viewer.clone(),
            600_000,
        ),
    )
    .await
    .expect_err("a grant is not delegated from by a device that does not hold it");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    let owner_record = host.owner.clone().expect("the owner device's record");
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let owners = RawDevice::connect(&host, owner_device, &owner_record).await;
    let refused = create(
        &host,
        &owners,
        &delegation(
            session_id,
            friend_record.device_id,
            Some(owner_record.grant.grant_id),
            viewer.clone(),
            600_000,
        ),
    )
    .await
    .expect_err("a pairing grant is not one to delegate from");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("pairing grant"),
        "the refusal says why: {refused:?}"
    );
    nothing_written(&host);

    // Revoking: a device revokes what descends from a grant it holds, and nothing else.
    let (given, friend_connection) = delegated(
        &host,
        session_id,
        &above.grant,
        &boss_connection,
        &friend,
        &friend_record,
    )
    .await;
    for (name, from, target) in [
        (
            "a grant the device itself holds",
            &boss_connection,
            above.grant.grant_id,
        ),
        (
            "a grant another device holds",
            &boss_connection,
            strangers.grant.grant_id,
        ),
        (
            "the grant its own was delegated from",
            &friend_connection,
            above.grant.grant_id,
        ),
        (
            "a grant delegated to another device's",
            &stranger_connection,
            given.grant_id,
        ),
    ] {
        let refused = revoke(&host, from, ActionId::new(kr_ipc::new_uuid()), target)
            .await
            .expect_err(name);
        assert_eq!(
            refused.code,
            ErrorCode::PermissionDenied,
            "{name}: {refused:?}"
        );
    }
    assert!(holds(&host, above.grant.grant_id));
    assert!(holds(&host, strangers.grant.grant_id));
    assert!(holds(&host, given.grant_id));
    friend_connection.close();
    owners.close();
    host.stop().await;
}
