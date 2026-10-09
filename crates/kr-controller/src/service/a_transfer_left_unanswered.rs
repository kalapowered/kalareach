//! A transfer of control whose attempt ended before its answer was recorded.
//!
//! The grant it writes and the grant it revokes are one commit, and the action's claim holds what
//! was withdrawn in that commit. An attempt that ends after the commit and before the answer is
//! recorded leaves a claim with no answer, and a retry of the action is answered from what the
//! commit wrote, never performed again. One that ended before the commit wrote nothing, and its
//! retry is told the outcome is not known.

use std::sync::Arc;

use kr_ipc::peer::PeerIdentity;
use kr_protocol::confirmation::TransferControlPlan;
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, ConnectionId, DeviceId, DeviceKeyRevision, GrantId,
    RequestId, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable, Uuid};
use kr_protocol::sharing::{
    AuthorityNotice, GrantTransferParams, GrantTransferResult, RoleSelection, SessionRole,
};
use kr_transport::clock::ManualClock;

use crate::grants::ActionClaim;
use crate::service::{Clocks, Controller, WallClock};
use crate::sharing::{ConfirmedAction, ShareRequest};

/// The clock the owner-confirmation ceremony reads, on this machine's own boot.
#[derive(Debug)]
struct Ceremony;

impl kr_pairing::platform::PairingClock for Ceremony {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        let value = kr_ipc::identity::boot_identity()
            .map(|identity| identity.value.as_slice().to_vec())
            .unwrap_or_default();
        kr_pairing::platform::BootIdentity(kr_cbor::sha256(&value))
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
    }
}

/// A daemon on a tree of its own, with a supervisor that starts nothing.
async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = Controller::start_on_clocks(
        super::a_floor_owed_its_record::setup(&temp),
        Clocks {
            continuous: Arc::new(ManualClock::new()),
            wall: WallClock::system(),
        },
    )
    .await
    .expect("the daemon starts");
    (temp, controller)
}

/// The owner's confirmation of `plan`, accepted for the host `host_device_id`, as the ceremony does.
fn confirmed(plan: &TransferControlPlan, host_device_id: DeviceId) -> ConfirmedAction {
    let clock = Ceremony;
    let endpoint = kr_protocol::scalars::EndpointKey::from_bytes([3; 32]);
    let request = kr_pairing::confirm::request_confirmation(
        &clock,
        TransferControlPlan::sensitive_action(),
        plan.action_digest().expect("a digest"),
        Some(plan.to_keys),
        plan.actions.iter().copied().collect(),
        host_device_id,
        endpoint,
    )
    .expect("a challenge");
    let mut ledger = kr_pairing::confirm::ConfirmationLedger::new();
    ledger.issue(&request, &clock);
    let owner = kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key");
    let proof = kr_pairing::confirm::sign_confirmation(
        &owner,
        &request,
        kr_protocol::pairing::ConfirmationChannel::PairedOwnerDevice,
    )
    .expect("a proof");
    ConfirmedAction::verify(
        &kr_pairing::confirm::ConfirmationExpectation {
            action: TransferControlPlan::sensitive_action(),
            action_digest: plan.action_digest().expect("a digest"),
            host_device_id,
            host_endpoint_id: endpoint,
            destination_keys: Some(&plan.to_keys),
            destination_rights: &plan.actions,
        },
        &mut ledger,
        &clock,
        &request,
        &proof,
        owner.public(),
        kr_pairing::confirm::HostEnrolment::Enrolled,
    )
    .expect("the owner confirmed this transfer")
}

/// A `grant.transfer` under a fresh action, for the grant `from` and the device `to`.
fn transfer_request(
    temp: &kr_ipc::testing::TempHost,
    session_id: SessionId,
    from: GrantId,
    to: DeviceId,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::GrantTransfer.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            ..ActionTarget::environment(temp.environment_id())
        },
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&GrantTransferParams {
            session_id,
            from_grant_id: from,
            to_device_id: to,
        })
        .expect("encodes"),
    }
}

/// KR-REQ-23.49: a transfer that committed and was never answered is answered to its retry from the
/// grant it wrote and what it withdrew, and is not performed again. The control is an action that
/// claimed and wrote nothing, which is told the outcome is not known.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_that_committed_and_was_not_answered_is_answered_from_what_it_wrote() {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    controller
        .admit_connection(
            connection_id,
            &actor_id,
            &PeerIdentity {
                uid: kr_ipc::paths::current_uid(),
                gid: 0,
                pid: None,
            },
            kr_protocol::local::LocalClientKind::Cli,
        )
        .await
        .expect("the connection is registered");
    let environment_id = controller.paths().environment_id();
    let host_device_id = DeviceId::new(environment_id.get());
    let session_id = SessionId::new(Uuid::from_bytes([0xa0; 16]));
    let giver = DeviceId::new(Uuid::from_bytes([0xf1; 16]));
    let taker = DeviceId::new(Uuid::from_bytes([0xf2; 16]));

    // A device holds an owner's share of the session.
    let now_ms = kr_ipc::now_ms().get();
    let selection = RoleSelection::plain(SessionRole::Owner);
    let shared = controller
        .sharing()
        .share(
            &ShareRequest {
                invitation_id: kr_protocol::ids::InvitationId::new(Uuid::from_bytes([1; 16])),
                grant_id: GrantId::new(Uuid::from_bytes([2; 16])),
                environment_id,
                session_id,
                issuer_device_id: host_device_id,
                recipient_device_id: giver,
                parent_grant_id: None,
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: None,
                live_screen: None,
                named_questions: Vec::new(),
                named_approvals: Vec::new(),
                authority_revision: controller.policy().authority_revision(),
                owner_confirmed: false,
                now_ms,
            },
            || Ok(()),
        )
        .expect("the host shares the session");
    controller
        .sharing()
        .redeem(
            shared.preview.invitation_id,
            giver,
            now_ms + 1,
            || Ok(()),
            None,
        )
        .expect("the device redeems it");
    let source = shared.grant;

    let mutation = transfer_request(&temp, session_id, source.grant_id, taker);
    let plan = TransferControlPlan {
        environment_id,
        session_id,
        source_grant_id: source.grant_id,
        parent_grant_id: source.parent_grant_id,
        issuer_device_id: source.issuer_device_id,
        from_device_id: giver,
        from_device_name: kr_protocol::pairing::DeviceName::new("a laptop").expect("a name"),
        to_device_id: taker,
        to_device_name: kr_protocol::pairing::DeviceName::new("a phone").expect("a name"),
        to_keys: kr_crypto::keys::DeviceKeys::generate()
            .expect("keys")
            .public_keys(),
        to_key_revision: DeviceKeyRevision::new(1),
        new_grant_id: Controller::transfer_identity(&actor_id, mutation.action_id),
        environment_selector: source.environment_selector.clone(),
        actions: crate::sharing::transfer::transferable_actions(&source),
        history: source.history.clone(),
        expiry: source.expiry,
        organisation: source.organisation,
    };
    let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("a digest");
    let grants = controller.sharing().grants();

    // The attempt claims its action, commits the transfer, and ends before it records an answer.
    let ActionClaim::Claimed { hold } = grants
        .claim_action(&actor_id, mutation.action_id, &digest, now_ms + 2)
        .expect("the claim is written")
    else {
        panic!("the first claim of an action is this attempt's");
    };
    let (done, completed) = controller
        .transfer_control(
            &plan,
            &confirmed(&plan, host_device_id),
            &Ceremony,
            None,
            Some(&hold),
        )
        .await
        .expect("the transfer commits");
    drop(hold);

    // Its retry is answered from the commit.
    let ControlFrame::Response(response) = controller
        .retained_authority_answer(&actor_id, &mutation)
        .await
        .expect("this host holds a claim on the action")
    else {
        panic!("a retry is answered with a response");
    };
    let Outcome::Ok(value) = response.outcome else {
        panic!("a committed transfer is answered: {response:?}");
    };
    let answered: GrantTransferResult = value.to_typed().expect("decodes");
    assert_eq!(answered.replacement, done.issued);
    assert_eq!(answered.replacement.grant_id, plan.new_grant_id);
    assert!(answered.revoked.revoked_grants.contains(&source.grant_id));
    // And it was not performed again: the revision, the grants withdrawn and the one grant the
    // receiving device holds are the first attempt's.
    assert_eq!(
        answered.revoked.authority_revision,
        completed.authority_revision
    );
    assert_eq!(answered.revoked.revoked_grants, completed.revoked_grants);
    assert_eq!(
        grants
            .records_for_device(taker)
            .expect("readable")
            .iter()
            .map(|record| record.grant.grant_id)
            .collect::<Vec<_>>(),
        vec![plan.new_grant_id]
    );

    // The control: an action that claimed and wrote nothing is told the outcome is not known.
    let nothing = transfer_request(
        &temp,
        session_id,
        GrantId::new(Uuid::from_bytes([9; 16])),
        taker,
    );
    let digest = kr_protocol::digest::mutation_digest(&nothing, &actor_id).expect("a digest");
    let ActionClaim::Claimed { hold } = grants
        .claim_action(&actor_id, nothing.action_id, &digest, now_ms + 3)
        .expect("the claim is written")
    else {
        panic!("the first claim of an action is this attempt's");
    };
    drop(hold);
    let ControlFrame::Response(response) = controller
        .retained_authority_answer(&actor_id, &nothing)
        .await
        .expect("this host holds a claim on the action")
    else {
        panic!("a retry is answered with a response");
    };
    assert!(
        matches!(response.outcome, Outcome::Error(_)),
        "an action that wrote nothing is not answered as a transfer: {response:?}"
    );
}
