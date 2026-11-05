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
async fn two_copies(
    controller: &Arc<Controller>,
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
) -> (Answered, Answered) {
    let (arrived, go) = controller.before_the_effect.arm();
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
async fn written(
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
    let mutation = mutation_of(&world, &connection, method, 91, params(&world));

    let (copied, fresh) = two_copies(controller, &connection, &mutation).await;
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
fn a_join(world: &fake::Silent) -> ParamsValue {
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
        .write(&actor, &mutation, Method::ProjectInit, || Ok(()), None)
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
