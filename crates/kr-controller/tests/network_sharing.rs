//! Redeeming a session invitation over a real paired connection.
//!
//! A session shared with a device is a grant written beside an invitation, and the grant
//! authorises nothing until the device the invitation names redeems it. What these demonstrate,
//! for the paired-device ingress: KR-REQ-25.10 (single-use, expiring invitations) and KR-REQ-18.03
//! (scoped invitations). The session itself, the worker that serves it and what a redeemed share
//! lets a device read are the end-to-end suite's (`network.rs`); nothing here starts a worker, so
//! every answer below is the daemon's own.

mod net_support;

use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::net::dispatch::EFFECT_WAIT;
use kr_controller::sharing::ShareRequest;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::GrantExpiry;
use kr_protocol::ids::{ActionId, DeviceId, GrantId, InvitationId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::scalars::TimestampMs;
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantRedeemParams, GrantRedeemResult,
    GrantRevokeParams, InvitationState, RoleSelection, SessionRole,
};
use kr_protocol::sharing::{
    DeviceListParams, DeviceListResult, DeviceRevokeParams, GrantListParams, GrantListResult,
};
use net_support::{
    Device, Host, MovedWall, RawDevice, on_the_host, owned_by, pair_with, proposal, recipient,
};
use std::time::Duration;

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
    try_share(host, session_id, recipient, lifetime_ms)
        .await
        .expect("the share is written")
}

/// As [`shared_for`], for a share the host may refuse.
async fn try_share(
    host: &Host,
    session_id: SessionId,
    recipient: DeviceId,
    lifetime_ms: Option<u64>,
) -> Result<GrantCreateResult, ProtocolError> {
    net_support::share_with(
        host,
        session_id,
        recipient,
        RoleSelection::plain(SessionRole::Viewer),
        lifetime_ms,
    )
    .await
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

/// KR-REQ-25.10: an invitation of a session that has ended activates nothing, and says so. The host
/// does not offer such an invitation (`grant.held` leaves it out), so a device that asks for it
/// anyway is refused in the host's words and not given a grant over a session nobody can reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_an_invitation_of_a_session_that_has_ended_activates_nothing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let (session_id, _) = net_support::an_open_session(&host);
    let issued = shared(&host, session_id, record.device_id).await;
    net_support::end_session(&host, session_id);

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
        .expect_err("an invitation of an ended session activates nothing");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("no longer open"), "{refused:?}");
    assert!(!is_active(&host, issued.grant.grant_id));
    let invitation = host
        .controller()
        .sharing()
        .invitation(issued.preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(invitation.state, InvitationState::Open);
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

/// The pairing end of `record`, in milliseconds.
fn pairing_end(record: &DeviceRecord) -> u64 {
    match record.grant.expiry {
        GrantExpiry::At { expires_at_ms } => expires_at_ms.get(),
        GrantExpiry::Never => panic!("this pairing ends"),
    }
}

/// The host's device list, as the person at this machine reads it.
async fn devices(host: &Host) -> DeviceListResult {
    net_support::pairing::read(
        &mut host.client().await,
        Method::DeviceList,
        &DeviceListParams {
            include_revoked: true,
        },
    )
    .await
    .expect("the list is read")
}

/// KR-REQ-25.10: a share may not outlast its recipient's pairing. A device's pairing bounds
/// everything it does, so a share that ran past it would end early without its issuer being told.
/// It is refused, with the pairing's end named, and never shortened to fit; one that fits is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_share_may_not_outlast_its_recipients_pairing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, record) =
        net_support::recipient_ending_in(&host, &owner, Duration::from_secs(30 * 60)).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());

    // The default lifetime is an hour, and the pairing has half of that.
    let refused = try_share(&host, session_id, record.device_id, None)
        .await
        .expect_err("a share past the pairing's end is refused");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(refused.message.contains("pairing ends in"), "{refused:?}");

    let fits = try_share(&host, session_id, record.device_id, Some(10 * 60_000))
        .await
        .expect("a share inside the pairing is written");
    let GrantExpiry::At { expires_at_ms } = fits.grant.expiry else {
        panic!("a share ends");
    };
    assert!(expires_at_ms.get() <= pairing_end(&record));
    host.stop().await;
}

/// KR-REQ-25.10: a share to a device this host does not pair with, or no longer pairs with, is
/// refused: it would never work, and nothing tells its issuer so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_share_to_a_device_this_host_does_not_pair_with_is_refused() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());

    let unknown = try_share(&host, session_id, DeviceId::new(kr_ipc::new_uuid()), None)
        .await
        .expect_err("a device with no record is refused");
    assert_eq!(unknown.code, ErrorCode::PermissionDenied, "{unknown:?}");

    let mut client = host.client().await;
    net_support::pairing::mutate::<_, kr_protocol::sharing::RevocationResult>(
        host.environment_id,
        &mut client,
        Method::DeviceRevoke,
        &DeviceRevokeParams {
            device_id: record.device_id,
        },
    )
    .await
    .expect("the owner revokes the device");
    let revoked = try_share(&host, session_id, record.device_id, None)
        .await
        .expect_err("a revoked device is refused");
    assert_eq!(revoked.code, ErrorCode::PermissionDenied, "{revoked:?}");
    host.stop().await;
}

/// KR-REQ-25.10: the host decides that a pairing has run out on its own clock, as admission does,
/// and not from a record that changes only when it first finds the end: a share to such a device is
/// refused, and the device list says so, with the end, the platform and whether the pairing opens
/// every session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_pairing_that_has_run_out_takes_no_share_and_the_device_list_says_so() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let wall = MovedWall::new();
    let host = Host::start_on_clocks(&owner, wall.clocks()).await;
    let (_device, record) =
        net_support::recipient_ending_in(&host, &owner, Duration::from_secs(5 * 60)).await;
    let wide = Device::create().await;
    let wide_record = pair_with(&host, &wide, &owner, proposal(&[ActionRight::SessionView])).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());

    let listed = devices(&host).await;
    let entry = |list: &DeviceListResult, device_id: DeviceId| {
        list.devices
            .iter()
            .find(|device| device.device_id == device_id)
            .cloned()
            .expect("the device is listed")
    };
    let narrow = entry(&listed, record.device_id);
    assert_eq!(narrow.platform, record.platform);
    assert_eq!(
        narrow.grant_expires_at_ms,
        Nullable::some(TimestampMs::new(pairing_end(&record)))
    );
    assert!(!narrow.grant_expired);
    assert!(
        !narrow.all_sessions,
        "a pairing that names no session opens none"
    );
    assert!(
        entry(&listed, wide_record.device_id).all_sessions,
        "a pairing over every session opens every session"
    );

    wall.advance(Duration::from_secs(10 * 60));
    let refused = try_share(&host, session_id, record.device_id, Some(60_000))
        .await
        .expect_err("a pairing that has run out takes no share");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        entry(&devices(&host).await, record.device_id).grant_expired,
        "the list says the pairing has run out"
    );
    host.stop().await;
}

/// KR-REQ-18.03: a paired device that delegates a share is refused, for every way the recipient's
/// pairing cannot carry it, with one sentence and one code that say nothing of another device's
/// pairing: the list that would tell it needs a right it does not hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_a_device_that_delegates_learns_nothing_of_the_recipients_pairing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (boss, boss_record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (above, issuing) = owned_by(&host, session_id, &boss, &boss_record).await;
    let (_short, short_record) =
        net_support::recipient_ending_in(&host, &owner, Duration::from_secs(5 * 60)).await;

    let mut refusals = Vec::new();
    // A recipient whose pairing ends before the delegation would, and one this host never paired.
    for recipient in [short_record.device_id, DeviceId::new(kr_ipc::new_uuid())] {
        let selection = RoleSelection::plain(SessionRole::Viewer);
        let refused = issuing
            .mutate(
                Method::GrantCreate,
                ActionId::new(kr_ipc::new_uuid()),
                net_support::on_the_session(&host, session_id),
                &GrantCreateParams {
                    session_id,
                    recipient_device_id: recipient,
                    parent_grant_id: Nullable::some(above.grant.grant_id),
                    accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                    selection,
                    lifetime_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(600_000)),
                    owner_confirmation: Nullable::null(),
                },
            )
            .await
            .expect_err("the delegation is refused");
        refusals.push((refused.code, refused.message));
    }
    assert_eq!(
        refusals[0], refusals[1],
        "the two refusals are one sentence under one code"
    );
    assert_eq!(refusals[0].0, ErrorCode::PermissionDenied);
    assert!(
        !refusals[0].1.contains("pairing"),
        "the sentence says nothing of a pairing: {:?}",
        refusals[0]
    );
    issuing.close();
    host.stop().await;
}

/// KR-REQ-18.03: `grant.list` carries the end a grant really has, which is the earlier of its own
/// expiry and the end of its recipient's pairing, so a share written before the host refused one
/// that outlasts the pairing is listed with the end it will have.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_the_grant_list_carries_the_earlier_of_the_shares_end_and_the_pairings() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_short, short_record) =
        net_support::recipient_ending_in(&host, &owner, Duration::from_secs(30 * 60)).await;
    let (_long, long_record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    // Written below the host's checks, as a share was before they existed: an hour for a device
    // that has half of it.
    let write = |recipient: DeviceId| {
        let selection = RoleSelection::plain(SessionRole::Viewer);
        host.controller()
            .sharing()
            .share(
                &ShareRequest {
                    invitation_id: InvitationId::new(kr_ipc::new_uuid()),
                    grant_id: GrantId::new(kr_ipc::new_uuid()),
                    environment_id: host.environment_id,
                    session_id,
                    issuer_device_id: host.controller().sharing().host_device_id(),
                    recipient_device_id: recipient,
                    parent_grant_id: None,
                    accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                    selection,
                    lifetime_ms: Some(60 * 60_000),
                    live_screen: None,
                    named_questions: Vec::new(),
                    named_approvals: Vec::new(),
                    authority_revision: host.controller().policy().authority_revision(),
                    owner_confirmed: false,
                    now_ms: kr_ipc::now_ms().get(),
                },
                || Ok(()),
            )
            .expect("the share is written")
    };
    let on_short = write(short_record.device_id);
    let on_long = write(long_record.device_id);

    let listed: GrantListResult = net_support::pairing::read(
        &mut host.client().await,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(session_id),
            include_resolved: false,
        },
    )
    .await
    .expect("the list is read");
    let ends = |grant_id: GrantId| {
        listed
            .grants
            .iter()
            .find(|summary| summary.grant.grant_id == grant_id)
            .expect("the grant is listed")
            .ends_at_ms
    };
    assert_eq!(
        ends(on_short.grant.grant_id),
        Nullable::some(TimestampMs::new(pairing_end(&short_record))),
        "the pairing ends first"
    );
    let GrantExpiry::At { expires_at_ms } = on_long.grant.expiry else {
        panic!("a share ends");
    };
    assert_eq!(
        ends(on_long.grant.grant_id),
        Nullable::some(expires_at_ms),
        "the share ends first"
    );
    host.stop().await;
}

/// KR-REQ-18.03: a paired device that lists what it delegated is told each grant's own end, and
/// nothing of the end of its recipient's pairing, which only the person at this machine is told:
/// it would otherwise read another device's pairing from a share that outlasts it, the one thing
/// the refusal of a delegation is worded to keep from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_a_device_that_lists_its_delegations_is_not_told_the_recipients_pairing_end() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (boss, boss_record) = recipient(&host, &owner).await;
    let (_short, short_record) =
        net_support::recipient_ending_in(&host, &owner, Duration::from_secs(10 * 60)).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (above, issuing) = owned_by(&host, session_id, &boss, &boss_record).await;

    // Written below the host's checks, as a delegation was before they existed: the boss issued
    // half an hour to a device whose pairing has ten minutes, and half an hour is less than the
    // boss's own share has left.
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let written = host
        .controller()
        .sharing()
        .share(
            &ShareRequest {
                invitation_id: InvitationId::new(kr_ipc::new_uuid()),
                grant_id: GrantId::new(kr_ipc::new_uuid()),
                environment_id: host.environment_id,
                session_id,
                issuer_device_id: boss_record.device_id,
                recipient_device_id: short_record.device_id,
                parent_grant_id: Some(above.grant.grant_id),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Some(30 * 60_000),
                live_screen: None,
                named_questions: Vec::new(),
                named_approvals: Vec::new(),
                authority_revision: host.controller().policy().authority_revision(),
                owner_confirmed: false,
                now_ms: kr_ipc::now_ms().get(),
            },
            || Ok(()),
        )
        .expect("the delegation is written");
    let GrantExpiry::At { expires_at_ms } = written.grant.expiry else {
        panic!("a share ends");
    };

    let params = GrantListParams {
        session_id: Nullable::some(session_id),
        include_resolved: false,
    };
    let by_the_device: GrantListResult = issuing
        .read(Method::GrantList, &params)
        .await
        .expect("the device lists what it delegated")
        .to_typed()
        .expect("decodes");
    let by_the_person: GrantListResult =
        net_support::pairing::read(&mut host.client().await, Method::GrantList, &params)
            .await
            .expect("the person lists");
    let end_in = |list: &GrantListResult| {
        list.grants
            .iter()
            .find(|summary| summary.grant.grant_id == written.grant.grant_id)
            .expect("the delegation is listed")
            .ends_at_ms
    };
    assert_eq!(
        end_in(&by_the_device),
        Nullable::some(expires_at_ms),
        "the device is told the grant's own end"
    );
    assert_eq!(
        end_in(&by_the_person),
        Nullable::some(TimestampMs::new(pairing_end(&short_record))),
        "the person at this machine is told the end it really has"
    );
    issuing.close();
    host.stop().await;
}

/// KR-REQ-25.10: a pairing that runs out while the share waits for the store is found where the
/// share is written. The request was checked while the pairing stood, and is held after that check
/// and before the transaction; the pairing ends while it is held; the write finds it and refuses,
/// and no share is written. The control is the same request released with the pairing still
/// standing, which is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_25_10_a_pairing_that_runs_out_while_the_share_waits_takes_no_share() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let wall = MovedWall::new();
    let host = Host::start_on_clocks(&owner, wall.clocks()).await;
    // Seventy seconds of pairing, for a share of thirty, in a request whose time to live is two
    // minutes: the pairing ends while the request is held, and the request's own deadline does not.
    let (_device, record) =
        net_support::recipient_ending_in(&host, &owner, Duration::from_secs(70)).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let params = GrantCreateParams {
        session_id,
        recipient_device_id: record.device_id,
        parent_grant_id: Nullable::null(),
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(30_000)),
        owner_confirmation: Nullable::null(),
    };
    let target = net_support::on_the_session(&host, session_id);
    let held_request = |host: &Host| {
        let endpoint = host.endpoint().clone();
        let (params, target) = (params.clone(), target.clone());
        async move {
            let mut client = kr_ipc::client::LocalClient::connect(
                &endpoint,
                kr_protocol::local::LocalClientKind::Cli,
                net_support::build(),
            )
            .await
            .expect("connects to the control endpoint");
            client
                .mutate(
                    Method::GrantCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &params,
                )
                .await
                .expect("the call reaches the daemon")
        }
    };

    // Released with the pairing still standing: written.
    let (arrived, go) = host.controller().sharing().grants().pause_before_effect();
    let standing = tokio::spawn(held_request(&host));
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(60)))
        .await
        .expect("the wait ran")
        .expect("the request is held at the store");
    go.send(()).expect("the request is let go");
    standing
        .await
        .expect("the request ran")
        .expect("a pairing that still stands takes the share");

    // Held, and the pairing ends while it is held: refused where the share is written.
    let (arrived, go) = host.controller().sharing().grants().pause_before_effect();
    let ending = tokio::spawn(held_request(&host));
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(60)))
        .await
        .expect("the wait ran")
        .expect("the request is held at the store");
    wall.advance(Duration::from_secs(100));
    go.send(()).expect("the request is let go");
    let refused = ending
        .await
        .expect("the request ran")
        .expect_err("a pairing that ran out while the request waited takes no share");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("pairing has run out"),
        "{refused:?}"
    );
    let listed: GrantListResult = net_support::pairing::read(
        &mut host.client().await,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(session_id),
            include_resolved: true,
        },
    )
    .await
    .expect("the list is read");
    assert_eq!(listed.grants.len(), 1, "only the first share was written");
    host.stop().await;
}
