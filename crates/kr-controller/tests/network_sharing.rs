//! Redeeming a session invitation over a real paired connection.
//!
//! A session shared with a device is a grant written beside an invitation, and the grant
//! authorises nothing until the device the invitation names redeems it. What these demonstrate,
//! for the paired-device ingress: KR-REQ-25.10 (single-use, expiring invitations) and KR-REQ-18.03
//! (scoped invitations). The session itself, the worker that serves it and what a redeemed share
//! lets a device read are the end-to-end suite's (`network.rs`); nothing here starts a worker, so
//! every answer below is the daemon's own.

mod net_support;

use kr_controller::service::net::dispatch::EFFECT_WAIT;
use kr_controller::sharing::ShareRequest;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{ActionId, DeviceId, GrantId, InvitationId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantRedeemParams, GrantRedeemResult,
    GrantRevokeParams, InvitationState, RoleSelection, SessionRole,
};
use net_support::{Device, Host, RawDevice, pair_with, proposal};

/// A target that names this host and no session, which is what a redemption and a revocation act
/// on.
fn on_the_host(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A device paired under a grant that reaches no session: the way a person who was only ever asked
/// to look at one session is paired.
async fn recipient(
    host: &Host,
    owner: &DeviceKeys,
) -> (Device, kr_controller::service::net::devices::DeviceRecord) {
    let device = Device::create().await;
    let mut grant = proposal(&[ActionRight::SessionView]);
    grant.session_selector = SessionSelector::None;
    let record = pair_with(host, &device, owner, grant).await;
    (device, record)
}

/// Shares `session_id` with `recipient` as a viewer, as the owner at this machine does.
async fn shared(host: &Host, session_id: SessionId, recipient: DeviceId) -> GrantCreateResult {
    shared_for(host, session_id, recipient, None).await
}

/// As [`shared`], for `lifetime_ms` when it names one.
async fn shared_for(
    host: &Host,
    session_id: SessionId,
    recipient: DeviceId,
    lifetime_ms: Option<u64>,
) -> GrantCreateResult {
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let params = GrantCreateParams {
        session_id,
        recipient_device_id: recipient,
        parent_grant_id: Nullable::null(),
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: Nullable(lifetime_ms.map(kr_protocol::scalars::DurationMs::new)),
        owner_confirmation: Nullable::null(),
    };
    host.client()
        .await
        .mutate(
            Method::GrantCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                ..on_the_host(host)
            },
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the share is written")
        .to_typed()
        .expect("decodes")
}

/// Whether the host holds `grant_id` as active.
fn is_active(host: &Host, grant_id: GrantId) -> bool {
    host.controller()
        .sharing()
        .grants()
        .record(grant_id)
        .expect("readable")
        .expect("present")
        .is_active()
}

/// KR-REQ-25.10 and KR-REQ-18.03: the device an invitation names redeems it once. An exact repeat
/// of the action, even on a later connection, is answered as it was, and a second redemption under
/// a new action is refused by name, after which the grant is active exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_device_redeems_its_invitation_once_and_a_repeat_of_the_action_is_answered_as_before()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let issued = shared(&host, session_id, record.device_id).await;
    assert!(
        !is_active(&host, issued.grant.grant_id),
        "a share nobody redeemed authorises nothing"
    );

    let redeem = GrantRedeemParams {
        invitation_id: issued.preview.invitation_id,
    };
    let action = ActionId::new(kr_ipc::new_uuid());
    let connection = RawDevice::connect(&host, &device, &record).await;
    let first = connection
        .mutate(Method::GrantRedeem, action, on_the_host(&host), &redeem)
        .await
        .expect("the invitation is redeemed");
    let redeemed: GrantRedeemResult = first.to_typed().expect("decodes");
    assert_eq!(redeemed.grant.grant_id, issued.grant.grant_id);
    assert_eq!(redeemed.invitation_id, issued.preview.invitation_id);
    assert!(is_active(&host, issued.grant.grant_id));

    // The same action again, on a connection that never saw the first answer, presented with the
    // window it was first admitted under.
    let first_window = connection.action_window_id();
    connection.close();
    let later = RawDevice::connect(&host, &device, &record).await;
    let repeated = later
        .mutate_in(
            first_window,
            Method::GrantRedeem,
            action,
            on_the_host(&host),
            &redeem,
        )
        .await
        .expect("a repeat of the action is answered");
    assert_eq!(repeated, first, "as it was answered the first time");

    // Another action by the same device finds the work done.
    let second = later
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &redeem,
        )
        .await
        .expect_err("an invitation is redeemed once");
    assert_eq!(second.code, ErrorCode::PermissionDenied, "{second:?}");
    assert!(
        second.message.contains("already been redeemed"),
        "{second:?}"
    );
    let invitation = host
        .controller()
        .sharing()
        .invitation(issued.preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(invitation.state, InvitationState::Redeemed);
    assert_eq!(invitation.redeemed_by, Some(record.device_id));
    later.close();
    host.stop().await;
}

/// KR-REQ-25.10: withdrawing an invitation is revoking the grant it carries, and a withdrawn
/// invitation activates nothing: the device is told it was withdrawn, and the grant stays as it
/// was withdrawn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_withdrawn_invitation_activates_nothing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let issued = shared(&host, SessionId::new(kr_ipc::new_uuid()), record.device_id).await;

    host.client()
        .await
        .mutate(
            Method::GrantRevoke,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &GrantRevokeParams {
                grant_id: issued.grant.grant_id,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the proposal is withdrawn");

    let connection = RawDevice::connect(&host, &device, &record).await;
    let refused = connection
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &GrantRedeemParams {
                invitation_id: issued.preview.invitation_id,
            },
        )
        .await
        .expect_err("a withdrawn invitation activates nothing");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("withdrawn"), "{refused:?}");
    assert!(!is_active(&host, issued.grant.grant_id));
    let invitation = host
        .controller()
        .sharing()
        .invitation(issued.preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(invitation.state, InvitationState::Cancelled);
    connection.close();
    host.stop().await;
}

/// KR-REQ-25.10: an invitation whose time ran out activates nothing, and says so: the grant it
/// carried is never active.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_an_expired_invitation_activates_nothing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    // Written as an hour-old share with a lifetime of a second, so it ran out long before this
    // test reads it: no part of this waits for time to pass.
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let invitation_id = InvitationId::new(kr_ipc::new_uuid());
    let grant_id = GrantId::new(kr_ipc::new_uuid());
    let issued = host
        .controller()
        .sharing()
        .share(
            &ShareRequest {
                invitation_id,
                grant_id,
                environment_id: host.environment_id,
                session_id: SessionId::new(kr_ipc::new_uuid()),
                issuer_device_id: host.controller().sharing().host_device_id(),
                recipient_device_id: record.device_id,
                parent_grant_id: None,
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Some(1_000),
                live_screen: None,
                named_questions: Vec::new(),
                named_approvals: Vec::new(),
                authority_revision: host.controller().policy().authority_revision(),
                owner_confirmed: false,
                now_ms: kr_ipc::now_ms().get() - 3_600_000,
            },
            || Ok(()),
        )
        .expect("the share is written");

    let connection = RawDevice::connect(&host, &device, &record).await;
    let refused = connection
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &GrantRedeemParams { invitation_id },
        )
        .await
        .expect_err("an expired invitation activates nothing");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("expired"), "{refused:?}");
    assert!(!is_active(&host, issued.grant.grant_id));
    connection.close();
    host.stop().await;
}

/// KR-REQ-25.10: a connection is ended at the end of the share it acts under though a request of
/// its is still waiting to be served. The device read under a share, and then sent a redemption
/// that is held at the store; the share ends, and the host closes the connection without waiting
/// for the request. What a connection that was looked at only between requests would do is wait
/// for the request, which the host gives up on after [`EFFECT_WAIT`], so the connection has to be
/// closed well inside that wait. (The end of the device's own pairing grant is a day away, so
/// nothing but the share's end can end the connection here.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_connection_is_ended_with_its_share_though_a_request_is_pending() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let other = shared(&host, SessionId::new(kr_ipc::new_uuid()), record.device_id).await;
    let connection = RawDevice::connect(&host, &device, &record).await;
    // Written once the connection is up, so the share's life is spent on the exchange below and
    // not on setting the connection up. It lasts a third of the host's wait for an effect.
    let short = shared_for(
        &host,
        session_id,
        record.device_id,
        Some(u64::try_from(EFFECT_WAIT.as_millis() / 3).expect("a lifetime in milliseconds")),
    )
    .await;

    connection
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &GrantRedeemParams {
                invitation_id: short.preview.invitation_id,
            },
        )
        .await
        .expect("the short share is redeemed");
    // A read of the session it was shared with is decided under the share. The session has no
    // worker here, so the read is refused after it was decided, and the connection has acted
    // under the share all the same.
    let _ = connection
        .read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await;

    let (arrived, go) = host.controller().sharing().grants().pause_before_effect();
    let held = connection
        .submit(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &GrantRedeemParams {
                invitation_id: other.preview.invitation_id,
            },
        )
        .await;
    tokio::task::spawn_blocking(move || arrived.recv_timeout(std::time::Duration::from_secs(60)))
        .await
        .expect("the wait for the request ran")
        .expect("the redemption reached the store and is held there");
    assert!(
        !is_active(&host, other.grant.grant_id),
        "the request is pending: nothing was written"
    );

    // The share ends while the request is held. The connection is closed then, and the request
    // is never answered. A connection that is only looked at between requests is closed after the
    // host gives up on the request, which is no earlier than the whole of its wait, so two thirds
    // of that wait is the longest this one is given.
    let answered = connection
        .answered_before_closing(held, EFFECT_WAIT / 3 * 2)
        .await
        .expect("the connection was closed inside the host's wait for the request");
    assert!(
        !answered,
        "the connection was ended with its share while a request of its was still pending, and \
         the request was not answered first"
    );
    go.send(()).expect("the held redemption is let go");
    host.stop().await;
}
