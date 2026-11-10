//! What a paired device is told of an answer its service copied from the record of an earlier
//! submission of the same action.
//!
//! Two copies of one action reach the door together. The first is stopped before its effect, the
//! second performs and records, and the first goes on to find the record: the service answers it
//! from there rather than performing again. That answer is the record's, as one the door found
//! itself is, and a device is told it as one: whatever it was, as an outcome that is unknown,
//! when the device may not read the record or when the authority feed raises its refusal before the
//! answer is written, and as the recorded answer when it may read it and nothing refuses. The copy
//! that performed is a fresh answer and is told as ever.

use std::sync::Arc;

use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable};

use super::decision::Answered;
use super::write_boundary::{Recording, paired_connection};
use crate::service::Controller;
use crate::service::a_close_a_worker_never_answers as fake;

/// How long a case waits for a copy to reach the place it is stopped at.
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// A mutation of `method` that names the whole environment, on `connection`.
pub(super) fn mutation_of(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    method: Method,
    request_id: u64,
    params: ParamsValue,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(request_id),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(world.environment_id),
        expected: ParamsValue::empty(),
        action_window_id: connection
            .windows
            .issue(connection.connection_id, world.controller.boot_epoch)
            .expect("a window")
            .action_window_id,
        requested_ttl_ms: DurationMs::new(30_000),
        params,
    }
}

/// Serves `mutation` twice at once and returns what each copy was answered with, the first being
/// the one that found the record.
///
/// The first copy is stopped before its effect, once the door has found no record of the action.
/// The second then goes through the door whole: it performs the action and records what it came
/// to. The first is let go and its service finds that record.
pub(super) async fn two_copies(
    controller: &Arc<Controller>,
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
) -> (Answered, Answered) {
    two_copies_stopped_at(controller.before_the_effect.arm(), connection, mutation).await
}

/// As [`two_copies`], the first copy stopped at the place `armed` names.
pub(super) async fn two_copies_stopped_at(
    (arrived, go): (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
) -> (Answered, Answered) {
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone())));
    tokio::pin!(first);
    tokio::select! {
        arrived = tokio::time::timeout(WAIT_BOUND, arrived) => {
            arrived
                .expect("the first copy reaches the place it is stopped at")
                .expect("the pause is armed");
        }
        early = &mut first => panic!("the first copy was answered before its effect: {early:?}"),
    }
    let (copied, fresh) = tokio::join!(first, async {
        let fresh = connection
            .answer_now(ControlFrame::Mutation(Box::new(mutation.clone())))
            .await;
        go.send(()).expect("the first copy goes on");
        fresh
    });
    (
        copied.expect("the first copy is answered"),
        fresh.expect("the second copy is answered"),
    )
}

/// The refusal an answer carries.
pub(super) fn refusal_of(answered: &Answered) -> ProtocolError {
    let ControlFrame::Response(Response {
        outcome: Outcome::Error(refusal),
        ..
    }) = answered.frame()
    else {
        panic!("a refusal was expected: {:?}", answered.frame());
    };
    refusal.clone()
}

/// What the device is written for `answered`, once the connection has been asked to write it.
pub(super) async fn written(
    connection: &super::RemoteConnection,
    recording: &Recording,
    answered: Answered,
) -> ProtocolError {
    assert!(
        connection.write_answer(answered).await,
        "the connection stands"
    );
    let frames = recording.frames();
    let Some(ControlFrame::Response(Response {
        outcome: Outcome::Error(told),
        ..
    })) = frames.last()
    else {
        panic!("the answer was written past the refusal: {frames:?}");
    };
    told.clone()
}

/// A device of every right, paired under the endpoint and key `byte` makes.
pub(super) const EVERY_RIGHT: &[ActionRight] = ActionRight::ALL;

/// Gives the device on `connection` a live voice grant, the narrower grant a device is held to for
/// a voice change beside its pairing grant.
pub(super) fn with_a_voice_grant(controller: &Controller, connection: &super::RemoteConnection) {
    let voice_grant = kr_protocol::grant::Grant {
        grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
        issuer_device_id: controller.sharing().host_device_id(),
        actions: [ActionRight::VoiceUse, ActionRight::SessionView]
            .into_iter()
            .collect(),
        ..connection.device.grant.clone()
    };
    controller
        .sharing()
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant: voice_grant,
                session_id: None,
                issued_at_ms: 1,
                activated_at_ms: Some(1),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("a live voice grant");
}

/// A mutation of `method`, which a service of the host refuses and records under its action, is
/// served twice at once (see [`two_copies`]). The copy that found the record is given the refusal
/// the other was recorded with; when the authority feed refuses before it is written, the device is
/// told the outcome is unknown, as it is for an answer the door finds in a record, and not the
/// refusal it was recorded with, which would show a device that may not read the record that the
/// action did not happen. The copy that performed is a fresh refusal and is told as ever.
///
async fn a_refusal_copied_from_the_record_is_told_as_unknown(
    method: Method,
    byte: u8,
    params: impl FnOnce(&fake::Silent) -> ParamsValue,
) {
    a_refusal_copied_where_the_first_copy_is_stopped(method, byte, params, |controller| {
        controller.before_the_effect.arm()
    })
    .await;
}

/// As [`a_refusal_copied_from_the_record_is_told_as_unknown`], the first copy stopped at the place
/// `stop` arms: the door, before the service is asked, or a place inside the service.
async fn a_refusal_copied_where_the_first_copy_is_stopped(
    method: Method,
    byte: u8,
    params: impl FnOnce(&fake::Silent) -> ParamsValue,
    stop: impl FnOnce(
        &Controller,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
) {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    if method == Method::ProjectInit && !controller.qualification().qualifies() {
        // The door refuses a repository operation to a device before the project service is
        // asked, on a host that has not proved Git's reads confined, so there is no record for a
        // service to copy from.
        println!(
            "not exercised: {method:?} needs a host that proves Git's reads confined, and this one \
             does not"
        );
        world.serving.abort();
        return;
    }
    let (connection, recording) = paired_connection(controller, byte, EVERY_RIGHT);
    if method == Method::VoiceStop {
        with_a_voice_grant(controller, &connection);
    }
    let mutation = mutation_of(&world, &connection, method, 91, params(&world));

    let (copied, fresh) = two_copies_stopped_at(stop(controller), &connection, &mutation).await;
    let recorded = refusal_of(&fresh);
    assert!(
        super::is_definite(&recorded),
        "the case needs a refusal that says the action did not happen: {recorded:?}"
    );
    assert_eq!(
        refusal_of(&copied).code,
        recorded.code,
        "the control: the copy that found the record is given the recorded refusal"
    );

    controller.raise_the_unverified_withdrawal_refusal().await;
    let told = written(&connection, &recording, copied).await;
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert_eq!(told.message, super::outcome_not_shown().message);
    let told = written(&connection, &recording, fresh).await;
    assert_eq!(
        told.code,
        ErrorCode::PermissionDenied,
        "a fresh refusal is told as ever: {told:?}"
    );
    world.serving.abort();
}

/// A mutation of `method` that a service of the host performs and records is served twice at once
/// (see [`two_copies`]). Both copies are given the result the one that performed recorded, and the
/// door holds only the copy that read it from the record as a kept answer, which a device that may
/// not read the record is told as unknown; the copy that performed is a fresh answer.
pub(super) async fn a_result_copied_from_the_record_is_held_as_kept(
    method: Method,
    byte: u8,
    params: impl FnOnce(&fake::Silent) -> ParamsValue,
) {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, byte, EVERY_RIGHT);
    let mutation = mutation_of(&world, &connection, method, 91, params(&world));

    let (copied, fresh) = two_copies(controller, &connection, &mutation).await;
    for answered in [&copied, &fresh] {
        assert!(
            matches!(
                answered.frame(),
                ControlFrame::Response(Response {
                    outcome: Outcome::Ok(_),
                    ..
                })
            ),
            "{method:?} is performed once and answered to both copies: {:?}",
            answered.frame()
        );
    }
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "{method:?}: the copy that read the result from the record is held as a kept answer"
    );
    assert!(
        fresh.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
        "{method:?}: the copy that performed is a fresh answer"
    );
    world.serving.abort();
}

/// KR-REQ-09.09: the attention group's mutations: clearing the quiet hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_the_attention_store_copies_from_its_record_is_held_as_kept() {
    a_result_copied_from_the_record_is_held_as_kept(Method::AttentionQuietHours, 84, |_| {
        ParamsValue::from_typed(&kr_protocol::attention::AttentionQuietHoursParams {
            quiet_hours: Nullable::null(),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a create the daemon answers from the reservation another copy of it made is an
/// answer read from a record, like any other, and goes under the checks every such answer goes
/// under before it is written. The copy is stopped before its effect, and meanwhile another copy
/// has made the session and the session has closed: the reservation under the create token and the
/// closure record stand, so the create is answered from them as one already made. With nothing
/// owed, the device is given the answer, held as a kept answer. When the host owes a fence it could
/// not raise, the answer is not shown and the device is told the outcome is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deduplicated_create_is_told_as_a_kept_answer() {
    for owed in [false, true] {
        let world = fake::fake_worker(None).await;
        let controller = &world.controller;
        let (connection, _) = paired_connection(controller, 85, EVERY_RIGHT);
        let create =
            crate::service::a_create_that_launches_nothing::create_params(world.environment_id);
        let mutation = mutation_of(
            &world,
            &connection,
            Method::SessionCreate,
            91,
            ParamsValue::from_typed(&create).expect("encodes"),
        );

        let (arrived, go) = controller.before_the_effect.arm();
        let (answered, ()) = tokio::join!(
            connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone()))),
            async {
                tokio::time::timeout(WAIT_BOUND, arrived)
                    .await
                    .expect("the copy reaches the place it is stopped at")
                    .expect("the pause is armed");
                let actor = connection.device.principal();
                let digest =
                    kr_protocol::digest::mutation_digest(&mutation, &actor).expect("a digest");
                let intent = kr_cbor::to_canonical_vec(&create).expect("encodes");
                let reserved = {
                    let mut registry = controller.registry.lock().await;
                    let admitted = registry
                        .reserve(
                            &actor,
                            mutation.action_id.get(),
                            digest,
                            &intent,
                            kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
                        )
                        .expect("the other copy's reservation");
                    registry
                        .set_phase(
                            admitted.reservation.reservation_id,
                            crate::registry::LaunchPhase::Closed,
                        )
                        .expect("the session has closed");
                    admitted.reservation
                };
                controller
                    .retire(
                        &crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of(
                            reserved.session_id,
                        ),
                    )
                    .await
                    .expect("the closure is recorded");
                controller.hold_fence(owed);
                go.send(()).expect("the copy goes on");
            }
        );
        let answered = answered.expect("the copy is answered");
        if owed {
            let told = refusal_of(&answered);
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            let ControlFrame::Response(Response {
                outcome: Outcome::Ok(value),
                ..
            }) = answered.frame()
            else {
                panic!(
                    "the create was answered from the record: {:?}",
                    answered.frame()
                );
            };
            let created: kr_protocol::session::SessionCreateResult =
                value.to_typed().expect("a create result");
            assert!(created.deduplicated, "an answer read from the record");
            assert!(
                answered
                    .asked
                    .as_ref()
                    .is_some_and(super::decision::Asked::is_kept),
                "and held as a kept answer"
            );
        }
        world.serving.abort();
    }
}

/// KR-REQ-09.09: a create the daemon answers from a reservation whose first attempt failed is an
/// answer read from a record, as one made from a session that was launched is. The copy is stopped
/// before its effect, and meanwhile another copy has reserved the session and failed to launch it.
/// A device that may read the session the reservation holds is given the refusal the reservation
/// leaves, held as a kept answer; one that may not is told the outcome is unknown, since that the
/// create failed is not for a device that may not read the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deduplicated_create_that_failed_is_told_as_a_kept_answer() {
    let without_viewing: Vec<ActionRight> = ActionRight::ALL
        .iter()
        .copied()
        .filter(|right| *right != ActionRight::SessionView)
        .collect();
    for (rights, may_read) in [(without_viewing.as_slice(), false), (EVERY_RIGHT, true)] {
        let world = fake::fake_worker(None).await;
        let controller = &world.controller;
        let (connection, _) = paired_connection(controller, 86, rights);
        let create =
            crate::service::a_create_that_launches_nothing::create_params(world.environment_id);
        let mutation = mutation_of(
            &world,
            &connection,
            Method::SessionCreate,
            91,
            ParamsValue::from_typed(&create).expect("encodes"),
        );

        let (arrived, go) = controller.before_the_effect.arm();
        let (answered, ()) = tokio::join!(
            connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone()))),
            async {
                tokio::time::timeout(WAIT_BOUND, arrived)
                    .await
                    .expect("the copy reaches the place it is stopped at")
                    .expect("the pause is armed");
                let actor = connection.device.principal();
                let digest =
                    kr_protocol::digest::mutation_digest(&mutation, &actor).expect("a digest");
                let intent = kr_cbor::to_canonical_vec(&create).expect("encodes");
                {
                    let mut registry = controller.registry.lock().await;
                    let admitted = registry
                        .reserve(
                            &actor,
                            mutation.action_id.get(),
                            digest,
                            &intent,
                            kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
                        )
                        .expect("the other copy's reservation");
                    registry
                        .set_phase(
                            admitted.reservation.reservation_id,
                            crate::registry::LaunchPhase::Failed,
                        )
                        .expect("the launch failed");
                }
                go.send(()).expect("the copy goes on");
            }
        );
        let answered = answered.expect("the copy is answered");
        let told = refusal_of(&answered);
        if may_read {
            assert_eq!(told.code, ErrorCode::ResourceUnavailable, "{told:?}");
            assert!(
                told.message.contains("failed"),
                "the recorded phase is told: {told:?}"
            );
            assert!(
                answered
                    .asked
                    .as_ref()
                    .is_some_and(super::decision::Asked::is_kept),
                "and held as a kept answer"
            );
        } else {
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        }
        world.serving.abort();
    }
}

/// KR-REQ-09.09: an owner device's request for the confirmation that establishes the host's clock.
/// The challenge is recorded with the action, and a copy of the request is given the challenge the
/// first recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_challenge_the_owner_authority_copies_from_its_record_is_held_as_kept() {
    a_result_copied_from_the_record_is_held_as_kept(Method::OwnerConfirmationRequest, 83, |_| {
        ParamsValue::from_typed(&kr_protocol::confirmation::OwnerConfirmationRequestParams {
            subject: kr_protocol::confirmation::ConfirmationSubject::EstablishClock,
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: the authority changes (`grant.create`, `grant.revoke`, `grant.redeem`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_an_authority_change_copies_from_its_record_is_told_as_unknown() {
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::GrantRedeem, 90, |_| {
        ParamsValue::from_typed(&kr_protocol::sharing::GrantRedeemParams {
            invitation_id: kr_protocol::ids::InvitationId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a device's declaration of its keys. Four keys that are not four different keys
/// are refused, and the refusal is recorded beside the keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_key_declaration_copies_from_its_record_is_told_as_unknown() {
    let byte = 92;
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::DeviceKeysComplete, byte, |_| {
        ParamsValue::from_typed(&kr_protocol::sharing::DeviceKeysCompleteParams {
            keys: kr_protocol::pairing::DevicePublicKeys {
                transport: kr_protocol::scalars::EndpointKey::from_bytes([byte; 32]),
                authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([byte; 32]),
                stored_envelope: kr_protocol::scalars::StoredEnvelopeKey::from_bytes([byte; 32]),
                notification_preview: kr_protocol::scalars::NotificationPreviewKey::from_bytes(
                    [byte; 32],
                ),
            },
            signature: kr_protocol::scalars::Signature64::from_bytes([0; 64]),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a device's registration of its push destination, refused for a device that has
/// declared no notification-preview key. Its service claims the action and records the refusal under
/// the claim, and answers a copy from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_push_registration_copies_from_its_record_is_told_as_unknown() {
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::DevicePushRegister, 87, |_| {
        ParamsValue::from_typed(&kr_protocol::push::DevicePushRegisterParams {
            credential: kr_protocol::push::PushDeliveryCredential {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(2_000_000_000_000),
                gateway_origin: kr_protocol::service::GatewayOrigin::new("https://reach.invalid")
                    .expect("an origin"),
                installation_id: kr_protocol::ids::InstallationId::new(
                    kr_protocol::scalars::Uuid::from_bytes([2; 16]),
                ),
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(1_999_000_000_000),
                revision: kr_protocol::ids::PushSenderRevision::new(1),
                secret: kr_protocol::scalars::SecretBytes32::from_bytes([9; 32]),
                sender_record_id: kr_protocol::ids::PushSenderRecordId::new(
                    kr_protocol::scalars::Uuid::from_bytes([3; 16]),
                ),
            },
            previews_enabled: true,
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a voice change refused for a voice session that does not exist. Two copies pass the
/// early look for a record before either has claimed the action; the copy that claims second finds
/// the claim of the first, and the service answers it from the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_voice_change_copies_from_its_claim_is_told_as_unknown() {
    a_refusal_copied_where_the_first_copy_is_stopped(
        Method::VoiceStop,
        86,
        |_| {
            ParamsValue::from_typed(&kr_protocol::voice::VoiceStopParams {
                voice_session_id: kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes")
        },
        |controller| controller.before_a_voice_change_claims.arm(),
    )
    .await;
}

/// KR-REQ-09.09: a machine group step approved against a record that is not the one on this host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_machine_group_step_copies_from_its_record_is_told_as_unknown() {
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::MachineSplit, 93, |_| {
        ParamsValue::from_typed(&kr_protocol::machine::MachineSplitParams {
            expected: kr_protocol::machine::MachineExpected {
                machine_id: kr_protocol::ids::MachineId::new(kr_ipc::new_uuid()),
                revision: kr_protocol::scalars::U64::new(7),
            },
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: the project service's mutations: creating a repository under a name that is not
/// one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_project_service_copies_from_its_record_is_told_as_unknown() {
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::ProjectInit, 94, |world| {
        ParamsValue::from_typed(&kr_protocol::project::ProjectInitParams {
            destination: kr_protocol::project::DestinationRequest {
                environment_id: world.environment_id,
                parent: kr_protocol::project::DestinationParent::Location {
                    location_id: kr_protocol::ids::ProjectLocationId::new(kr_ipc::new_uuid()),
                },
                name: "a/b".to_owned(),
            },
            label: "a repository".to_owned(),
            initial_branch: Nullable::null(),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: the catalogue's mutations: enrolling a repository that names no place to fetch
/// from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_catalogue_copies_from_its_record_is_told_as_unknown() {
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::CatalogueAdd, 95, |world| {
        ParamsValue::from_typed(&kr_protocol::catalogue::CatalogueAddParams {
            environment_id: world.environment_id,
            catalogue_id: "a-repository".to_owned(),
            kind: kr_protocol::catalogue::CatalogueKind::Local,
            metadata_url: String::new(),
            targets_url: String::new(),
            root: String::new(),
            budgets: kr_protocol::catalogue::CatalogueBudgets {
                metadata_bytes: kr_protocol::scalars::U64::new(1),
                metadata_entries: kr_protocol::scalars::U64::new(1),
                retained_generations: kr_protocol::scalars::U64::new(1),
                retained_metadata_bytes: kr_protocol::scalars::U64::new(1),
                payload_cache_bytes: kr_protocol::scalars::U64::new(1),
                full_offline_mirror: false,
            },
            ceiling: Vec::new(),
            owner_confirmation: Nullable::null(),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: the workflow journal's mutations: enabling a workflow that is not installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_the_workflow_journal_copies_from_its_record_is_told_as_unknown() {
    a_refusal_copied_from_the_record_is_told_as_unknown(Method::WorkflowEnable, 96, |_| {
        ParamsValue::from_typed(&kr_protocol::automation::WorkflowEnableParams {
            workflow_id: kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
            revision: kr_protocol::scalars::U64::new(1),
        })
        .expect("encodes")
    })
    .await;
}

/// The step that joins this environment's machine group to another group, approved against the
/// record the environment holds now.
pub(super) fn a_join(world: &fake::Silent) -> ParamsValue {
    let current = world
        .controller
        .machine_report()
        .expect("the daemon records a machine group");
    ParamsValue::from_typed(&kr_protocol::machine::MachineJoinParams {
        machine_id: kr_protocol::ids::MachineId::new(kr_ipc::new_uuid()),
        expected: kr_protocol::machine::MachineExpected {
            machine_id: current.machine_id,
            revision: current.revision,
        },
    })
    .expect("encodes")
}

/// KR-REQ-09.09: the result a service copies from its record is told as unknown too, when the
/// authority feed refuses before it is written: it is the same answer to the device as a
/// refusal, and the device cannot tell the one from the other. The copy that found the record is
/// given the result the other recorded, and nothing else changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_a_machine_group_step_copies_from_its_record_is_told_as_unknown() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, recording) = paired_connection(controller, 97, EVERY_RIGHT);
    let join = mutation_of(&world, &connection, Method::MachineJoin, 91, a_join(&world));

    let (copied, fresh) = two_copies(controller, &connection, &join).await;
    for answered in [&copied, &fresh] {
        assert!(
            matches!(
                answered.frame(),
                ControlFrame::Response(Response {
                    outcome: Outcome::Ok(_),
                    ..
                })
            ),
            "the step is performed once and answered to both copies: {:?}",
            answered.frame()
        );
    }
    assert_eq!(
        copied.frame(),
        fresh.frame(),
        "the copy is given the result the other recorded"
    );

    controller.raise_the_unverified_withdrawal_refusal().await;
    let told = written(&connection, &recording, copied).await;
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    let told = written(&connection, &recording, fresh).await;
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "a result that was carried out is not refused: {told:?}"
    );
    world.serving.abort();
}

/// KR-REQ-09.09: two copies of a project mutation that is refused before it claims anything both
/// pass the service's look for a record before either has written one. The copy that records
/// second finds the first's row, and the service gives that refusal as the copy it is; the copy that
/// recorded first answers for itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_project_service_gives_a_refusal_another_copy_recorded_first_as_a_copy() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 98, EVERY_RIGHT);
    let mutation = mutation_of(
        &world,
        &connection,
        Method::ProjectInit,
        91,
        ParamsValue::from_typed(&kr_protocol::project::ProjectInitParams {
            destination: kr_protocol::project::DestinationRequest {
                environment_id: world.environment_id,
                parent: kr_protocol::project::DestinationParent::Location {
                    location_id: kr_protocol::ids::ProjectLocationId::new(kr_ipc::new_uuid()),
                },
                name: "a-name".to_owned(),
            },
            label: String::new(),
            initial_branch: Nullable::null(),
        })
        .expect("encodes"),
    );
    let actor = connection.device.principal();
    let module = Arc::clone(controller.project());
    let (arrived_tx, arrived) = std::sync::mpsc::channel::<()>();
    let (go, go_rx) = std::sync::mpsc::channel::<()>();
    // The first copy waits in its admission, which the service asks after its look for a record
    // found none and before it does anything else.
    let held = {
        let (module, actor, mutation) = (Arc::clone(&module), actor.clone(), mutation.clone());
        tokio::spawn(async move {
            module
                .write(
                    &actor,
                    &mutation,
                    Method::ProjectInit,
                    move || {
                        let _ = arrived_tx.send(());
                        let _ = go_rx.recv();
                        Ok(())
                    },
                    || Ok(()),
                    None,
                )
                .await
        })
    };
    tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND))
        .await
        .expect("the wait ends")
        .expect("the first copy reaches its admission");
    let recorded_first = module
        .write(
            &actor,
            &mutation,
            Method::ProjectInit,
            || Ok(()),
            || Ok(()),
            None,
        )
        .await;
    go.send(()).expect("the first copy goes on");
    let held = held.await.expect("the first copy ends");

    assert!(
        !recorded_first.is_copied(),
        "the copy that recorded the refusal first answers for itself"
    );
    assert!(
        held.is_copied(),
        "the copy that finds the refusal another copy recorded is given it as a copy"
    );
    let (first, second) = (
        recorded_first
            .into_answer()
            .expect_err("the label is empty"),
        held.into_answer().expect_err("the label is empty"),
    );
    assert_eq!(first.code, second.code);
    assert!(super::is_definite(&first), "{first:?}");
    world.serving.abort();
}

/// KR-REQ-09.09: a reused identifier found by a service's own lookup is this host's word about the
/// identifier and names no result, so the door shows it as it is to a device that may not read the
/// record the identifier was spent on, as it shows a create's. It is written under the decision of
/// the request and not as an answer kept from an earlier submission, which a refusal to write it
/// would turn into an unknown outcome although nothing was carried out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_identifier_is_shown_to_a_device_that_may_not_read_the_record() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let without_reading: Vec<ActionRight> = ActionRight::ALL
        .iter()
        .copied()
        .filter(|right| *right != ActionRight::SessionView)
        .collect();
    let (connection, _) = paired_connection(controller, 84, &without_reading);
    let mut mutation = mutation_of(
        &world,
        &connection,
        Method::SessionRename,
        92,
        ParamsValue::empty(),
    );
    mutation.target = ActionTarget {
        environment_id: world.environment_id,
        session_id: Nullable::some(world.session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let entry = connection
        .admit(mutation.method.as_str(), mutation.method_version)
        .expect("the method is in the registry");
    let decided = connection
        .ask_mutation(&mutation, entry)
        .expect("the rename is decided for a device that holds every right but this one");
    let validated = connection
        .admitted_at()
        .await
        .expect("the registration stands");
    let kept = ControlFrame::Response(Response {
        request_id: mutation.request_id,
        outcome: Outcome::Error(ProtocolError::new(
            ErrorCode::IdConflict,
            "the identifier was used with another request",
        )),
    });
    let mut asked = None;
    let answer = connection
        .kept_answer(
            kept.clone(),
            Method::SessionRename,
            &mutation,
            validated,
            &decided,
            &mut asked,
        )
        .await;
    assert_eq!(answer.ok(), Some(kept));
    assert!(
        !asked
            .expect("the decision the answer is written under")
            .is_kept(),
        "a reused identifier is not an answer kept from an earlier submission"
    );
    world.serving.abort();
}

/// KR-REQ-09.09: an answer kept from an earlier submission of an action, whoever found it, is a
/// read of what that submission produced and is shown under the right to read that. A device that
/// holds the right over the session its action names is given the answer; one that does not is
/// told the outcome is unknown, and `asked` holds the decision the answer is written under either
/// way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_answer_is_shown_only_to_a_device_that_may_read_it() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let without_reading: Vec<ActionRight> = ActionRight::ALL
        .iter()
        .copied()
        .filter(|right| *right != ActionRight::SessionView)
        .collect();
    for (byte, rights, may_read) in [
        (82, EVERY_RIGHT, true),
        (83, without_reading.as_slice(), false),
    ] {
        let (connection, _) = paired_connection(controller, byte, rights);
        let mut mutation = mutation_of(
            &world,
            &connection,
            Method::SessionRename,
            91,
            ParamsValue::empty(),
        );
        mutation.target = ActionTarget {
            environment_id: world.environment_id,
            session_id: Nullable::some(world.session_id),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let entry = connection
            .admit(mutation.method.as_str(), mutation.method_version)
            .expect("the method is in the registry");
        let decided = connection
            .ask_mutation(&mutation, entry)
            .expect("the rename is decided for a device that holds every right but this one");
        let validated = connection
            .admitted_at()
            .await
            .expect("the registration stands");
        let kept = ControlFrame::Response(Response {
            request_id: mutation.request_id,
            outcome: Outcome::Error(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the recorded refusal",
            )),
        });
        let mut asked = None;
        let answer = connection
            .kept_answer(
                kept.clone(),
                Method::SessionRename,
                &mutation,
                validated,
                &decided,
                &mut asked,
            )
            .await;
        assert!(asked.is_some(), "the decision the answer is written under");
        if may_read {
            assert_eq!(answer.as_ref().ok(), Some(&kept));
        } else {
            let told = answer.expect_err("a device that may not read the record is not given it");
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        }
    }
    world.serving.abort();
}
