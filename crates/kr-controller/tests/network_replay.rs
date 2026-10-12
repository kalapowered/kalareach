//! Asking the host what became of an action whose answer was lost, over real connections.
//!
//! The host performs an action at most once and keeps its answer, so the only question a client
//! has after a lost answer is what became of the action. It asks with a repeat of the exact request
//! it sent, on a connection other than the one that sent it: the host answers a repeat from its
//! record before it looks at the window, and the window admits nothing on another connection, so a
//! repeat can only ever be answered from the record and never performs the action. What these
//! demonstrate: KR-REQ-09.08 (a retried action is answered from what the host kept) and
//! KR-REQ-23.49 (the sharing methods are claimed per actor and action). Nothing here starts a
//! worker.

mod net_support;

use kr_client::ClientError;
use kr_client::attempt::{Attempt, Found, Kind, Next, Outcome, Reply};
use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantListParams, GrantListResult,
    GrantRedeemParams, GrantRedeemResult, RoleSelection, SessionRole, share_identities,
};
use net_support::{
    Device, Host, an_open_session, connect, local_session, on_the_host, on_the_session, recipient,
    share_with,
};

const TTL: DurationMs = DurationMs::new(120_000);

fn share_params(session_id: SessionId, to: &DeviceRecord) -> GrantCreateParams {
    let selection = RoleSelection::plain(SessionRole::Viewer);
    GrantCreateParams {
        session_id,
        recipient_device_id: to.device_id,
        parent_grant_id: Nullable::null(),
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: Nullable::null(),
        owner_confirmation: Nullable::null(),
    }
}

/// What the host lists for one session, resolved grants included.
async fn listed(host: &Host, session_id: SessionId) -> GrantListResult {
    net_support::pairing::read(
        &mut host.client().await,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(session_id),
            include_resolved: true,
        },
    )
    .await
    .expect("the list is read")
}

/// KR-REQ-09.08: a share whose answer was lost is asked about with the exact request, on another
/// connection, and answered from the record the host kept: the same grant and invitation, derived
/// from the actor the host authenticated and the action, which is how the client finds them in a
/// list. The same action composed anew under the other connection's window is a different request
/// for it, which the host refuses; and a call on the wrong connection is refused by the library
/// before anything is sent, as an error that is not the host's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_09_08_a_share_asked_again_on_another_connection_is_answered_from_the_hosts_record()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, record) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let (first, uid) = local_session(&host).await;
    let (second, _) = local_session(&host).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let params = share_params(session_id, &record);

    let composed = first
        .compose(
            Method::GrantCreate,
            action,
            on_the_session(&host, session_id),
            None,
            &ParamsValue::empty(),
            &params,
            TTL,
        )
        .await
        .expect("composed, nothing sent");
    assert!(
        listed(&host, session_id).await.grants.is_empty(),
        "composing sends nothing"
    );

    // The library keeps a repeat off the connection that sent, and a first send off any other.
    assert!(matches!(
        first.repeat(&composed).await,
        Err(ClientError::Misdirected { repeating: true })
    ));
    assert!(matches!(
        second.send(&composed).await,
        Err(ClientError::Misdirected { repeating: false })
    ));
    assert!(
        listed(&host, session_id).await.grants.is_empty(),
        "neither sent anything"
    );

    let answered: GrantCreateResult = first
        .send(&composed)
        .await
        .expect("the host answers")
        .to_typed()
        .expect("a share result");
    let asked_again = second.repeat(&composed).await;
    assert_eq!(Reply::of(&asked_again), Reply::Result);
    let again: GrantCreateResult = asked_again.expect("answered").to_typed().expect("a result");
    assert_eq!(again, answered, "answered from the record, as it was");
    assert_eq!(
        listed(&host, session_id).await.grants.len(),
        1,
        "and nothing was written again"
    );

    // The grant a lost answer would have written is found by its derived identity.
    let (grant_id, invitation_id) =
        share_identities(&kr_protocol::sharing::local_actor(uid), action.get());
    assert_eq!(answered.grant.grant_id, grant_id);
    assert_eq!(answered.preview.invitation_id, invitation_id);
    let found = |list: &GrantListResult, id| {
        if list
            .grants
            .iter()
            .any(|summary| summary.grant.grant_id == id)
        {
            Found::Present
        } else {
            Found::Absent
        }
    };
    assert_eq!(
        found(&listed(&host, session_id).await, grant_id),
        Found::Present
    );
    let (never_sent, _) =
        share_identities(&kr_protocol::sharing::local_actor(uid), kr_ipc::new_uuid());
    assert_eq!(
        found(&listed(&host, session_id).await, never_sent),
        Found::Absent
    );

    // The action composed anew on the other connection is another request for it: the window is in
    // the digest, so the host refuses it, and it is the host's answer.
    second.settle(action).await;
    let anew = second
        .compose(
            Method::GrantCreate,
            action,
            on_the_session(&host, session_id),
            None,
            &ParamsValue::empty(),
            &params,
            TTL,
        )
        .await
        .expect("composed");
    let conflict = second.send(&anew).await;
    assert!(
        matches!(&conflict, Err(ClientError::Host(error)) if error.code == ErrorCode::IdConflict),
        "{conflict:?}"
    );
    first.close();
    second.close();
    host.stop().await;
}

/// KR-REQ-23.49: while the first attempt at a redemption is still running, a repeat on another
/// connection is told it has not finished, which closes nothing and which the library keeps
/// unresolved until its caller settles it. When the first attempt ends, a repeat on a third
/// connection is answered with the result, the same one the first attempt recorded, and the grant
/// is activated once. A refusal of an ordinary mutation settles it as it always has, and a repeat
/// the host refuses stays held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_49_a_repeat_while_the_action_runs_is_told_so_and_a_later_repeat_gets_the_result()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record): (Device, DeviceRecord) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let issued = share_with(
        &host,
        session_id,
        record.device_id,
        RoleSelection::plain(SessionRole::Viewer),
        None,
    )
    .await
    .expect("the share is written");
    let redeem = GrantRedeemParams {
        invitation_id: issued.preview.invitation_id,
    };
    let first = connect(&host, &device, &record).await;
    let second = connect(&host, &device, &record).await;
    let third = connect(&host, &device, &record).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let composed = first
        .compose(
            Method::GrantRedeem,
            action,
            on_the_host(&host),
            None,
            &ParamsValue::empty(),
            &redeem,
            TTL,
        )
        .await
        .expect("composed");
    let mut attempt = Attempt::new(
        Kind::Redeem,
        &composed,
        Some(issued.grant.grant_id),
        0,
        "Accept",
    );

    // The first attempt is under way: its claim is written and held, as the daemon holds one while
    // it performs the action, and nothing is recorded yet.
    let actor = kr_transport::listener::device_principal(&record.device_id);
    let digest =
        kr_protocol::digest::mutation_digest(composed.request(), &actor).expect("a digest");
    let grants = host.controller().sharing().grants();
    let kr_controller::grants::ActionClaim::Claimed { hold } = grants
        .claim_action(&actor, action, &digest, kr_ipc::now_ms().get())
        .expect("the claim is written")
    else {
        panic!("the first attempt claims the action");
    };

    let told = second.repeat(&composed).await;
    assert!(
        matches!(&told, Err(ClientError::Host(error)) if error.code == ErrorCode::ResourceUnavailable),
        "{told:?}"
    );
    assert_eq!(attempt.after_first_send(Reply::Lost), Next::Repeat);
    assert_eq!(
        attempt.after_repeat(Reply::of(&told)),
        Next::Check,
        "a refusal to a repeat is a read of the host and closes nothing"
    );
    assert_eq!(
        second.submitted_actions().await.len(),
        1,
        "and the library keeps the action unresolved until its caller settles it"
    );
    second.settle(action).await;
    assert!(second.submitted_actions().await.is_empty());

    // A refusal settles an ordinary mutation by itself, which the library has always done, and
    // does not settle a repeat, whose caller holds the action: the host refuses a repeat that
    // finds no record because the window it carries admits nothing on this connection.
    let stranger = GrantRedeemParams {
        invitation_id: kr_protocol::ids::InvitationId::new(kr_ipc::new_uuid()),
    };
    let plain = third
        .mutate(
            Method::GrantRedeem,
            on_the_host(&host),
            None,
            &ParamsValue::empty(),
            &stranger,
            TTL,
        )
        .await;
    assert!(
        matches!(&plain, Err(ClientError::Host(error)) if error.code == ErrorCode::PermissionDenied),
        "{plain:?}"
    );
    assert!(
        third.submitted_actions().await.is_empty(),
        "a plain mutation the host refused is settled"
    );
    let unknown_action = ActionId::new(kr_ipc::new_uuid());
    let unrecorded = first
        .compose(
            Method::GrantRedeem,
            unknown_action,
            on_the_host(&host),
            None,
            &ParamsValue::empty(),
            &stranger,
            TTL,
        )
        .await
        .expect("composed");
    let refused = third.repeat(&unrecorded).await;
    assert!(
        matches!(&refused, Err(ClientError::Host(error)) if error.code == ErrorCode::PermissionDenied),
        "{refused:?}"
    );
    assert_eq!(
        third.submitted_actions().await.len(),
        1,
        "a repeat the host refused stays unresolved until its caller settles it"
    );
    third.settle(unknown_action).await;
    assert!(third.submitted_actions().await.is_empty());

    // The first attempt ends: the redemption and its answer are one commit under the claim.
    let activated = host
        .controller()
        .sharing()
        .redeem(
            issued.preview.invitation_id,
            record.device_id,
            kr_ipc::now_ms().get(),
            || Ok(()),
            Some(&hold),
        )
        .expect("the invitation is redeemed under the claim");
    drop(hold);
    let later = third.repeat(&composed).await;
    assert_eq!(Reply::of(&later), Reply::Result);
    let from_record: GrantRedeemResult = later.expect("answered").to_typed().expect("a result");
    assert_eq!(
        from_record.grant, activated,
        "answered from the record, as it was"
    );
    assert_eq!(from_record.grant.grant_id, issued.grant.grant_id);
    assert_eq!(
        attempt.after_repeat(Reply::Result),
        Next::Closed(Outcome::Happened)
    );
    first.close();
    second.close();
    third.close();
    host.stop().await;
}

/// KR-REQ-09.08: a request read back from a kept record is repeated nowhere it could be admitted
/// for the first time, and nowhere the host's record of the action is not. The window it carries
/// admits it on the connection that was issued the window, whether or not that connection composed
/// it in this run, so a repeat there is refused before anything is sent; the host keeps its record
/// under the actor that sent the request, so a repeat to another host, or as another actor, is
/// refused before anything is sent too, and none of them wrote a share.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_09_08_a_request_from_a_record_is_repeated_only_where_the_hosts_record_can_answer() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let (first, _) = local_session(&host).await;
    let (second, _) = local_session(&host).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let params = share_params(session_id, &record);
    let composed = first
        .compose(
            Method::GrantCreate,
            action,
            on_the_session(&host, session_id),
            None,
            &ParamsValue::empty(),
            &params,
            TTL,
        )
        .await
        .expect("composed, nothing sent");

    // What a client keeps and reads back: the request, its window, and the host and actor.
    let kept = Attempt::new(Kind::Invite, &composed, None, 0, "Invite");
    let restored = kept.composed();
    assert_eq!(restored.request(), composed.request());
    assert_eq!(restored.reach(), composed.reach());
    assert!(
        restored.reach().is_some(),
        "a local connection says who it is"
    );

    // The connection that was issued the window refuses the repeat, though it is the same run and
    // nothing was ever sent: the window would admit it there.
    assert!(matches!(
        first.repeat(&restored).await,
        Err(ClientError::Misdirected { repeating: true })
    ));
    // And a restored request is never a first send.
    assert!(matches!(
        second.send(&restored).await,
        Err(ClientError::Misdirected { repeating: false })
    ));
    assert!(
        listed(&host, session_id).await.grants.is_empty(),
        "neither sent anything"
    );

    // Another host: a second daemon, with a local connection of its own.
    let elsewhere = Host::start(&owner).await;
    let (other_host, _) = local_session(&elsewhere).await;
    assert!(matches!(
        other_host.repeat(&restored).await,
        Err(ClientError::OtherHost)
    ));
    assert!(
        listed(&elsewhere, session_id).await.grants.is_empty(),
        "nothing was sent to the other host"
    );

    // Another actor on the same host: a paired device's connection acts as the device, not as the
    // user the local socket authenticated.
    let as_device = connect(&host, &device, &record).await;
    assert!(matches!(
        as_device.repeat(&restored).await,
        Err(ClientError::OtherHost)
    ));
    assert!(
        listed(&host, session_id).await.grants.is_empty(),
        "and nothing was sent as another actor"
    );
    assert_eq!(
        Reply::of(&as_device.repeat(&restored).await),
        Reply::NotSent,
        "a refusal made here is not the host's answer"
    );

    // A connection that cannot say who it is, or a record that does not, is not repeated to.
    let mut anonymous = kept.clone();
    anonymous.host = String::new();
    assert!(anonymous.composed().reach().is_none());
    assert!(matches!(
        second.repeat(&anonymous.composed()).await,
        Err(ClientError::OtherHost)
    ));

    // The same connection as before, a fresh one of the same user, asks and the host answers from
    // nothing: it has no record of an action never sent, and writes nothing.
    let unsent = second.repeat(&restored).await;
    assert!(
        matches!(&unsent, Err(ClientError::Host(_))),
        "the host refuses what it never saw: {unsent:?}"
    );
    assert!(
        listed(&host, session_id).await.grants.is_empty(),
        "and a repeat is never a first admission"
    );
    first.close();
    second.close();
    other_host.close();
    as_device.close();
    elsewhere.stop().await;
    host.stop().await;
}

/// KR-REQ-23.49: the library refuses a second send of an action it is still accounting for, and
/// says so as its own refusal and not as the host's: a client that took it for a refusal of the
/// action would close an attempt whose first send was committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_49_a_second_send_of_a_held_action_is_refused_locally_and_is_not_the_hosts_answer()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, record) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let (first, _) = local_session(&host).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let composed = first
        .compose(
            Method::GrantCreate,
            action,
            on_the_session(&host, session_id),
            None,
            &ParamsValue::empty(),
            &share_params(session_id, &record),
            TTL,
        )
        .await
        .expect("composed");
    let sent = first.send(&composed).await;
    assert_eq!(Reply::of(&sent), Reply::Result);
    assert_eq!(
        first.submitted_actions().await.len(),
        1,
        "the action is held until its caller settles it"
    );
    let again = first.send(&composed).await;
    assert!(
        matches!(again, Err(ClientError::StillAccounting)),
        "{again:?}"
    );
    assert_eq!(
        Reply::of(&again),
        Reply::NotSent,
        "nothing the host said, so nothing that closes the attempt"
    );
    assert_eq!(
        listed(&host, session_id).await.grants.len(),
        1,
        "and the share was written once"
    );
    first.settle(action).await;
    first.close();
    host.stop().await;
}
