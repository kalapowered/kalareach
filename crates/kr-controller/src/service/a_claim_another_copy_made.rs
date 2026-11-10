//! What a conflict that another copy of an action caused goes back under.
//!
//! A claim another copy made for the same identifier and another request is a record of that copy,
//! as the answer it recorded is. A copy that waited, and meets that claim where it claims its own
//! action or looks for its record, is told of the conflict only under the authority it arrived
//! under, asked with the conflict in hand: a fence this host owes stops it, as it stops a recorded
//! answer. Each case plants the other copy's claim, and asks the service the control (nothing
//! owed, the conflict is told) and then a fence owed. Where the service asks its check with the
//! conflict in hand on the async side (a machine group step, the authority changes), the fence
//! lands at the pause that check starts with, so the case shows the check is asked after the claim.
//! Where the check is asked by the door's own function or a store on a thread that blocks (a
//! privacy change, a transfer), no pause stops it, the fence is set before the call, and the case
//! shows that the check runs, not when.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable};

use super::a_recorded_answer_another_copy_wrote::{
    answered_after_a_fence_lands_at_the_check, refused_for_a_fence_landing_at_the_check,
};
use super::the_fence_at_every_effect::{
    accepted, admitted, carried, daemon, mutation_of, refusal, refused_for_a_fence,
};
use crate::service::Controller;

/// A claim for the action `action_id` that another request made, left unsettled: what a copy of
/// the action with this payload meets as the conflict of a reused identifier.
fn a_claim_for_another_request(controller: &Controller, actor_id: &ActorId, action_id: ActionId) {
    let claimed = controller
        .sharing()
        .grants()
        .claim_action(actor_id, action_id, &Digest256::from_bytes([0x42; 32]), 1)
        .expect("the claim is written");
    assert!(
        matches!(claimed, crate::grants::ActionClaim::Claimed { .. }),
        "the first claim of an action is the one that makes it"
    );
}

/// KR-REQ-09.09, the conflict of a reused identifier, found where a machine group step claims its
/// action: another attempt claimed the identifier for another request, and what that says goes back
/// only under the authority this attempt arrived under. The control: with nothing owed the conflict
/// is told. A fence that lands once the conflict is in hand refuses it for the fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_group_steps_conflict_is_not_told_after_a_fence_lands() {
    use kr_protocol::machine::{MachineExpected, MachineSplitParams};

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let group = controller
        .machine_report()
        .expect("this daemon serves a machine group record");
    let mutation = mutation_of(
        &temp,
        Method::MachineSplit,
        ParamsValue::from_typed(&MachineSplitParams {
            expected: MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            },
        })
        .expect("encodes"),
    );
    a_claim_for_another_request(&controller, &actor_id, mutation.action_id);
    let attempt = || {
        controller.write_method(
            &actor_id,
            &mutation,
            Method::MachineSplit,
            connection_id,
            None,
            Some(accepted(&controller)),
            controller.admitted_revision(connection_id).ok(),
        )
    };
    let control = attempt().await;
    assert_eq!(
        refusal(&control).map(|error| error.code),
        Some(ErrorCode::IdConflict),
        "with nothing owed the conflict is told: {control:?}"
    );

    let refused = answered_after_a_fence_lands_at_the_check(&controller, attempt()).await;
    refused_for_a_fence(
        refusal(&refused)
            .unwrap_or_else(|| panic!("a fence this host owes stops the conflict: {refused:?}")),
    );
}

/// KR-REQ-09.09, the conflict of a reused identifier, found where an authority change, a preview
/// key's update and a push registration claim their action: another attempt claimed the identifier
/// for another request, and what that says goes back only under the authority this attempt arrived
/// under. The control: with nothing owed each conflict is told. A fence that lands once the conflict
/// is in hand refuses each for the fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_changes_conflict_is_not_told_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);

    let revoking = mutation_of(&temp, Method::GrantRevoke, ParamsValue::empty());
    a_claim_for_another_request(&controller, &actor_id, revoking.action_id);
    let revoke = async || {
        controller
            .authority_change(
                &actor_id,
                super::authority_changes::AuthorityCaller::Owner,
                &revoking,
                Method::GrantRevoke,
                admission,
            )
            .await
            .into_answer()
            .map_err(|error| error.to_protocol_error())
    };
    let rotating = mutation_of(&temp, Method::DevicePreviewKeyUpdate, ParamsValue::empty());
    a_claim_for_another_request(&controller, &actor_id, rotating.action_id);
    let rotate = async || {
        controller
            .preview_key_update_action(&actor_id, &rotating, admission)
            .await
            .into_answer()
            .map_err(|error| error.to_protocol_error())
    };
    let registering = mutation_of(&temp, Method::DevicePushRegister, ParamsValue::empty());
    a_claim_for_another_request(&controller, &actor_id, registering.action_id);
    let register = async || {
        controller
            .push_register_action(&actor_id, &registering, admission)
            .await
            .into_answer()
            .map_err(|error| error.to_protocol_error())
    };

    // The control: with nothing owed each conflict is told.
    for told in [revoke().await, rotate().await, register().await] {
        assert_eq!(
            told.expect_err("the conflict is told").code,
            ErrorCode::IdConflict
        );
    }
    refused_for_a_fence_landing_at_the_check(&controller, revoke).await;
    refused_for_a_fence_landing_at_the_check(&controller, rotate).await;
    refused_for_a_fence_landing_at_the_check(&controller, register).await;
}

/// KR-REQ-09.09, the conflict of a reused identifier, found where an action the host performs under
/// one claim in the shared store (a privacy change, an environment's record, an account's sign-in)
/// claims its action: another attempt claimed the identifier for another request, and what that says
/// goes back only under the authority this attempt arrived under. The control: with nothing owed the
/// conflict is told. While this host owes a fence it is refused for the fence.
/// The fence is set before the call: the door's own function asks the check, with no pause before
/// it, so the case shows that the check runs, not when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_changes_conflict_is_not_told_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::PrivacySet,
        ParamsValue::from_typed(&kr_protocol::privacy::PrivacySetParams { enabled: true })
            .expect("encodes"),
    );
    a_claim_for_another_request(&controller, &actor_id, mutation.action_id);
    let attempt = || {
        controller.write_method(
            &actor_id,
            &mutation,
            Method::PrivacySet,
            connection_id,
            None,
            Some(accepted(&controller)),
            controller.admitted_revision(connection_id).ok(),
        )
    };
    let control = attempt().await;
    assert_eq!(
        refusal(&control).map(|error| error.code),
        Some(ErrorCode::IdConflict),
        "with nothing owed the conflict is told: {control:?}"
    );

    controller.hold_fence(true);
    let refused = attempt().await;
    refused_for_a_fence(
        refusal(&refused)
            .unwrap_or_else(|| panic!("a fence this host owes stops the conflict: {refused:?}")),
    );
    controller.hold_fence(false);
}

/// KR-REQ-09.09, the conflict of a reused identifier, found where the transfer service looks for the
/// record of its action: another attempt recorded the identifier for another request, and what that
/// says goes back only under the authority this attempt arrived under. The control: with nothing
/// owed the conflict is told. While this host owes a fence it is refused for the fence.
/// The fence is set before the call: the transfer service's admission asks the check on a thread
/// that blocks, where no pause stops it, so the case shows that the check runs, not when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfers_conflict_is_not_told_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let draft = |text: &str| kr_protocol::transfer::DraftCreateParams {
        environment_id: temp.environment_id(),
        device_id: Nullable::null(),
        session_id: Nullable::null(),
        application_instance_id: Nullable::null(),
        text: text.to_owned(),
    };
    let mutation = mutation_of(
        &temp,
        Method::DraftCreate,
        ParamsValue::from_typed(&draft("what the first attempt recorded")).expect("encodes"),
    );
    let mut other = mutation.clone();
    other.params = ParamsValue::from_typed(&draft("another request under the same identifier"))
        .expect("encodes");
    let admission = carried(&controller, connection_id);
    let write = async |request: &MutationRequest| {
        controller
            .transfer()
            .write(
                &actor_id,
                request,
                Method::DraftCreate,
                crate::transfer::TransferAdmission::new(Arc::clone(&controller), admission),
                None,
            )
            .await
            .into_answer()
    };
    write(&mutation).await.expect("the first attempt records");

    let told = write(&other)
        .await
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.code, ErrorCode::IdConflict, "{told:?}");

    controller.hold_fence(true);
    let refused = write(&other)
        .await
        .expect_err("a fence this host owes stops the conflict");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}
