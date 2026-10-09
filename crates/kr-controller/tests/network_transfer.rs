//! Handing a session's control to another paired device, over real paired connections.
//!
//! The person at this machine asks the host to describe the transfer, an owner device answers the
//! challenge, and `grant.transfer` spends that answer once. What these demonstrate: KR-REQ-18.03
//! (transfer of control is not a delegation: the receiving device holds the session, the giving
//! device does not) and KR-REQ-23.49 (the sharing method group: the transfer is confirmed by the
//! owner for exactly this plan, fenced through the barrier, and answered again, never performed
//! again, to a repeat). Nothing here starts a worker, so every answer is the daemon's own.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::confirmation::{
    ConfirmationDisplay, ConfirmationSubject, OwnerConfirmationRequestParams,
    TransferControlSubject,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{ActionId, DeviceId, RequestId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::{GrantTransferParams, GrantTransferResult};
use net_support::pairing::{self as calls, Signer};
use net_support::{
    Host, RawDevice, delegated, holds, on_the_host, on_the_session, owned_by, recipient,
};

/// The subject an owner confirmation is asked for.
fn subject(params: &GrantTransferParams, action_id: ActionId) -> ConfirmationSubject {
    ConfirmationSubject::TransferControl(Box::new(TransferControlSubject {
        params: params.clone(),
        action_id,
    }))
}

/// Sends `grant.transfer` from the person at this machine.
async fn transfer(
    host: &Host,
    client: &mut kr_ipc::client::LocalClient,
    params: &GrantTransferParams,
    action_id: ActionId,
) -> Result<GrantTransferResult, kr_protocol::error::ProtocolError> {
    client
        .mutate(
            Method::GrantTransfer,
            action_id,
            on_the_session(host, params.session_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("decodes"))
}

/// Whether the owner's answer to `challenge` is still waiting to be spent.
async fn still_waiting(
    host: &Host,
    challenge: &kr_protocol::pairing::OwnerConfirmationRequest,
) -> bool {
    let mut client = host.client().await;
    calls::pending(&mut client)
        .await
        .expect("readable")
        .pending
        .iter()
        .any(|waiting| waiting.answered && &waiting.request == challenge)
}

/// KR-REQ-18.03 and KR-REQ-23.49: an owner device confirms a transfer of control for exactly the
/// plan the host describes, and `grant.transfer` spends that confirmation once. The giving device
/// holds a grant that another device delegated to it; the receiving device is given an active grant
/// over the session that keeps that issuer and parent and ends no later than the grant it replaces,
/// the giving device's grant is revoked through the barrier and the grant it was delegated from is
/// not, a connection acting under the grant that was given up is ended promptly, and a repeat of
/// the action is answered as it was, spending nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_a_transfer_hands_a_session_to_another_device_on_the_owners_confirmation() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (boss, boss_record) = recipient(&host, &owner).await;
    let (giver, giver_record) = recipient(&host, &owner).await;
    let (taker, taker_record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (above, above_connection) = owned_by(&host, session_id, &boss, &boss_record).await;
    let (held, giving) = delegated(
        &host,
        session_id,
        &above.grant,
        &above_connection,
        &giver,
        &giver_record,
    )
    .await;
    // The giving device acts under the grant it holds, which is what a transfer has to end.
    let _ = giving
        .read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await;

    let params = GrantTransferParams {
        session_id,
        from_grant_id: held.grant_id,
        to_device_id: taker_record.device_id,
    };
    let action = ActionId::new(kr_ipc::new_uuid());
    let other_action = ActionId::new(kr_ipc::new_uuid());
    let mut client = host.client().await;
    // A confirmation the owner gave for a transfer under another action: it is never spent by this
    // one.
    let other_challenge = calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&params, other_action),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms the transfer under the other action");
    let challenge = calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&params, action),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms this transfer");

    // What the owner device was shown is the plan the host then writes, and its digest is the
    // challenge's own.
    let shown = calls::pending(&mut client)
        .await
        .expect("readable")
        .pending
        .into_iter()
        .find(|waiting| waiting.request == challenge)
        .expect("the challenge is listed");
    let ConfirmationDisplay::TransferControl(plan) = &shown.display else {
        panic!("a transfer is shown as one: {:?}", shown.display);
    };
    assert_eq!(
        plan.action_digest().expect("a digest"),
        challenge.action_digest
    );
    assert_eq!(plan.from_device_id, giver_record.device_id);
    assert_eq!(plan.to_device_id, taker_record.device_id);
    assert_eq!(
        plan.to_keys,
        taker_record.public_keys().expect("all four keys")
    );
    assert_eq!(plan.source_grant_id, held.grant_id);

    let before = host.controller().policy().authority_revision();
    let done = transfer(&host, &mut client, &params, action)
        .await
        .expect("the owner's confirmation is spent");

    // The receiving device holds an active grant over the session and nothing else, which keeps
    // the issuer and the parent the giving device's grant had: it is not a delegation.
    let replacement = &done.replacement;
    assert_eq!(replacement.grant_id, plan.new_grant_id);
    assert_eq!(replacement.recipient_device_id, taker_record.device_id);
    assert_eq!(replacement.issuer_device_id, boss_record.device_id);
    assert_eq!(
        replacement.parent_grant_id,
        Nullable::some(above.grant.grant_id)
    );
    assert_eq!(
        replacement.session_selector,
        SessionSelector::These {
            session_ids: [session_id].into_iter().collect()
        }
    );
    assert!(replacement.actions.is_subset(&held.actions));
    assert!(replacement.permits(ActionRight::SessionShare));
    assert!(holds(&host, replacement.grant_id), "active at once");
    // And the giving device does not keep what it handed over, while the grant that was delegated
    // to it is the issuer's still.
    assert!(!holds(&host, held.grant_id));
    assert!(holds(&host, above.grant.grant_id));
    // The receiving device's grant ends when the giving device's would have: the deadline recorded
    // for one is the other's.
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let deadlines = host.controller().sharing().grants();
    let given = deadlines
        .grant_deadline_in(held.grant_id, &boot)
        .expect("readable");
    assert!(
        given.is_some(),
        "the grant that was given up had a deadline"
    );
    assert_eq!(
        deadlines
            .grant_deadline_in(replacement.grant_id, &boot)
            .expect("readable"),
        given
    );
    assert!(done.revoked.revoked_grants.contains(&held.grant_id));
    assert!(done.revoked.authority_revision.get() > before.get());
    assert_eq!(
        done.revoked.barrier.authority_revision, done.revoked.authority_revision,
        "completed through the barrier"
    );

    // The connection acting under the grant that was given up is ended when the transfer takes
    // effect, and not when the host next looks at the grants it stands on, which is much later than
    // this waits. The receiving device is decided under the grant it was given: its pairing grant
    // reaches no session, so the replacement is the only thing that admits it, and there is no
    // worker to answer.
    assert_eq!(
        giving
            .answered_before_closing(RequestId::new(u64::MAX), std::time::Duration::from_secs(5))
            .await,
        Some(false),
        "the giving device's connection is ended with its grant"
    );
    let taking = RawDevice::connect(&host, &taker, &taker_record).await;
    let read = taking
        .read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await;
    assert_ne!(
        read.expect_err("there is no worker").code,
        ErrorCode::PermissionDenied,
        "the receiving device is admitted to the session"
    );

    // A repeat of the action is answered as before. It could not be performed again: the owner's
    // answer for it is spent, and the answer for the other action is not touched.
    let repeated = transfer(&host, &mut client, &params, action)
        .await
        .expect("a repeat of the action is answered");
    assert_eq!(repeated.replacement, done.replacement);
    assert_eq!(repeated.revoked.revoked_grants, done.revoked.revoked_grants);
    assert!(
        still_waiting(&host, &other_challenge).await,
        "and nothing else of the owner's was spent"
    );
    taking.close();
    host.stop().await;
}

/// KR-REQ-18.03 and KR-REQ-23.49: nothing is handed over without the owner's confirmation of this
/// exact transfer. An answer for another destination is not spent, a destination that is not
/// paired is refused before any answer is looked at, no answer at all hands over nothing, and a
/// paired device asks neither for the confirmation nor for the transfer. After each the giving
/// device still holds the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_03_a_transfer_the_owner_did_not_confirm_hands_nothing_over() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (giver, giver_record) = recipient(&host, &owner).await;
    let (_taker, taker_record) = recipient(&host, &owner).await;
    let (_other, other_record) = recipient(&host, &owner).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let (held, giving) = owned_by(&host, session_id, &giver, &giver_record).await;
    let to_taker = GrantTransferParams {
        session_id,
        from_grant_id: held.grant.grant_id,
        to_device_id: taker_record.device_id,
    };
    let mut client = host.client().await;
    let untouched = |host: &Host| {
        assert!(
            holds(host, held.grant.grant_id),
            "the giving device kept its grant"
        );
    };

    // The owner confirmed handing the session to one device; the transfer names another. The plan
    // differs, so the answer is not an answer to it, and it stays unspent.
    let action = ActionId::new(kr_ipc::new_uuid());
    let challenge = calls::confirm_subject(
        host.environment_id,
        &mut client,
        subject(&to_taker, action),
        &Signer::OwnerDevice(&owner),
    )
    .await
    .expect("the owner confirms the transfer to the first device");
    let to_other = GrantTransferParams {
        to_device_id: other_record.device_id,
        ..to_taker.clone()
    };
    let refused = transfer(&host, &mut client, &to_other, action)
        .await
        .expect_err("an answer for another destination is not an answer to this transfer");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    untouched(&host);
    assert!(still_waiting(&host, &challenge).await);

    // A destination that is not paired is refused when the host is asked to describe the transfer,
    // and when it is asked to make it.
    let nobody = GrantTransferParams {
        to_device_id: DeviceId::new(kr_ipc::new_uuid()),
        ..to_taker.clone()
    };
    let unpaired = ActionId::new(kr_ipc::new_uuid());
    let refused = calls::request(host.environment_id, &mut client, subject(&nobody, unpaired))
        .await
        .expect_err("the host describes no transfer to a device it has not paired");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    let refused = transfer(&host, &mut client, &nobody, unpaired)
        .await
        .expect_err("and makes none");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    untouched(&host);

    // No answer at all.
    let refused = transfer(
        &host,
        &mut client,
        &to_taker,
        ActionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect_err("nobody confirmed this transfer");
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    untouched(&host);

    // A paired device, an owner device included, asks neither for the confirmation nor for the
    // transfer: the person at this machine does.
    let owner_record = host.owner.clone().expect("the owner device's record");
    let owner_device = host.owner_device.as_ref().expect("the owner device");
    let asking = RawDevice::connect(&host, owner_device, &owner_record).await;
    let refused = asking
        .mutate(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &OwnerConfirmationRequestParams {
                subject: subject(&to_taker, ActionId::new(kr_ipc::new_uuid())),
            },
        )
        .await
        .expect_err("a paired device does not open this confirmation");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    asking
        .mutate(
            Method::GrantTransfer,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_session(&host, session_id),
            &to_taker,
        )
        .await
        .expect_err("a paired device does not make the transfer");
    untouched(&host);
    asking.close();
    giving.close();
    host.stop().await;
}
