//! What the door does with `draft.discard`, the write by which a paired device ends a draft of its
//! own.
//!
//! The transfer service performs it under the device's own principal, so a device ends its own
//! drafts and no one else's, and the refusal for another principal's draft is the one for a draft
//! that is not there. An ended draft frees its place against the bound at once. The action is an
//! ordinary one: the same action asked again, on this connection or another, is answered from the
//! record, and a copy that reaches the service after the first has ended the draft is told as the
//! copy it is.

use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActorId, DraftId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    DraftCreateResult, DraftDiscardParams, DraftDiscardResult, DraftUpdateParams,
    DraftUpdateResult, InsertionMethod,
};

use super::a_copy_from_a_services_record::{EVERY_RIGHT, mutation_of, two_copies};
use super::a_draft_a_device_writes::{
    a_draft_for, create_params, manual_contribution, result_of, the_owner,
    two_copies_stopped_in_the_service, write_naming,
};
use super::write_boundary::paired_connection;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::transfer::DEVICE_OPEN_DRAFTS;

/// A `draft.discard` of `draft_id` on `connection`.
fn discard(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    request_id: u64,
    draft_id: DraftId,
) -> MutationRequest {
    write_naming(
        world,
        connection,
        Method::DraftDiscard,
        request_id,
        &DraftDiscardParams { draft_id },
        None,
    )
}

/// The refusal in `answer`, with `draft_id` taken out of its words so that two compare byte for
/// byte.
fn refusal_without(answer: &ControlFrame, draft_id: DraftId) -> (ErrorCode, String) {
    let refusal = super::tests::error_of(answer);
    (
        refusal.code,
        refusal.message.replace(&draft_id.to_string(), "<draft>"),
    )
}

/// KR-REQ-23.41: a device ends a draft of its own, and only that. Another device's draft, the local
/// owner's draft and a draft that never existed are refused in the same words, `INVALID_ARGUMENT`,
/// so the refusal shows nothing of what exists, and the drafts they name stand. The control is the
/// device's own draft, which is ended and answered with its identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_ends_a_draft_of_its_own_and_is_told_alike_of_every_draft_that_is_not() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let service = controller.transfer().service();
    let (connection, _) = paired_connection(controller, 51, EVERY_RIGHT);
    let device = connection.device.principal();
    let (other, _) = paired_connection(controller, 52, EVERY_RIGHT);
    let other_device = other.device.principal();
    let owner = the_owner();
    let theirs = a_draft_for(&world, &other_device, None);
    let owners = a_draft_for(&world, &owner, None);
    let own = a_draft_for(&world, &device, None);
    let never = DraftId::new(Uuid::from_bytes([0x66; 16]));

    let mut told = Vec::new();
    for (request_id, draft_id) in [(1, theirs.draft_id), (2, owners.draft_id), (3, never)] {
        let answer = connection
            .mutate(&discard(&world, &connection, request_id, draft_id))
            .await;
        told.push(refusal_without(&answer, draft_id));
    }
    assert_eq!(told[0].0, ErrorCode::InvalidArgument, "{told:?}");
    assert!(
        told.iter().all(|one| *one == told[0]),
        "the refusal is one for every draft that is not the device's: {told:?}"
    );
    service
        .draft(&other_device, theirs.draft_id)
        .expect("the other device's draft stands");
    service
        .draft(&owner, owners.draft_id)
        .expect("the owner's draft stands");

    let ended: DraftDiscardResult = result_of(
        &connection
            .mutate(&discard(&world, &connection, 4, own.draft_id))
            .await,
    );
    assert_eq!(ended.draft_id, own.draft_id);
    assert!(
        service.draft(&device, own.draft_id).is_err(),
        "the device's own draft is gone"
    );
    world.serving.abort();
}

/// KR-REQ-23.41: an ended draft frees its place at once. A device at the bound is refused a create
/// that names the bound and `draft.discard`; it ends one draft and the next create is served, with
/// no session's end between; and it is at the bound again after. Another device's create is
/// served throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ended_draft_frees_its_place_at_once() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 53, EVERY_RIGHT);
    let device = connection.device.principal();
    for _ in 1..DEVICE_OPEN_DRAFTS {
        a_draft_for(&world, &device, None);
    }
    let create = |request_id: u64| {
        write_naming(
            &world,
            &connection,
            Method::DraftCreate,
            request_id,
            &create_params(&world, None, None, "one more"),
            None,
        )
    };

    let last: DraftCreateResult = result_of(&connection.mutate(&create(1)).await);
    let refused = connection.mutate(&create(2)).await;
    let refusal = super::tests::error_of(&refused);
    assert_eq!(refusal.code, ErrorCode::QuotaExceeded, "{refusal:?}");
    assert!(
        refusal.message.contains("draft.discard"),
        "the words name how a place is freed: {refusal:?}"
    );

    let (another, _) = paired_connection(controller, 54, EVERY_RIGHT);
    let _: DraftCreateResult = result_of(
        &another
            .mutate(&write_naming(
                &world,
                &another,
                Method::DraftCreate,
                1,
                &create_params(&world, None, None, "the other device's"),
                None,
            ))
            .await,
    );

    let _: DraftDiscardResult = result_of(
        &connection
            .mutate(&discard(&world, &connection, 3, last.draft.draft_id))
            .await,
    );
    let _: DraftCreateResult = result_of(&connection.mutate(&create(4)).await);
    assert_eq!(
        super::tests::error_of(&connection.mutate(&create(5)).await).code,
        ErrorCode::QuotaExceeded,
        "the freed place is taken"
    );
    world.serving.abort();
}

/// A device's draft for the session of `world`, with one upload of its own bound to it.
fn a_draft_with_a_file(
    world: &fake::Silent,
    device: &ActorId,
) -> (
    kr_protocol::transfer::DraftRecord,
    kr_protocol::ids::TransferId,
) {
    let session = world.session_id;
    let service = world.controller.transfer().service();
    let draft = a_draft_for(world, device, Some(session));
    let handle = super::tests::a_published_attachment_for(
        &world.controller,
        world.environment_id,
        device,
        "taken.bin",
        Some(session),
    );
    service
        .draft_add_attachment(
            device,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec![handle.declared_media_type.clone()],
                    max_byte_len: U64::new(1024),
                    max_count: U64::new(4),
                    insertion_method: InsertionMethod::TypedSubmission,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
            None,
            None,
        )
        .expect("binds the file");
    (draft, handle.transfer_id)
}

/// The agent of `session` takes the file bound to a draft, as a worker reports it.
fn the_agent_takes(
    world: &fake::Silent,
    device: &ActorId,
    draft_id: DraftId,
    transfer_id: kr_protocol::ids::TransferId,
) {
    use kr_protocol::broker::ActionProvenance;
    use kr_protocol::insertion::{InsertionBegin, InsertionReport, ReportedOutcome};

    let session: SessionId = world.session_id;
    let service = world.controller.transfer().service();
    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let facts = service
        .insertion_facts(device, session, draft_id)
        .expect("reads the draft's facts");
    let attempt = facts
        .bindings
        .iter()
        .find(|binding| binding.transfer_id == transfer_id)
        .expect("the file is bound")
        .attempt;
    let clock = kr_ipc::clock::ManualSharedClock::new();
    clock.advance(std::time::Duration::from_millis(1_000));
    service
        .insertion_begin(
            device,
            session,
            &InsertionBegin {
                action_id,
                draft_id,
                transfer_id,
                attempt,
                max_count: U64::new(4),
                deadline_boot_ms: U64::new(61_000),
            },
            &clock,
        )
        .expect("claims the binding for an offer");
    service
        .record_insertion_outcome(
            device,
            session,
            &InsertionReport {
                action_id,
                draft_id,
                transfer_id,
                attempt,
                outcome: ReportedOutcome::AcceptedByAgent {
                    provenance: ActionProvenance::UpstreamTypedRpc,
                    evidence: "upstream part msg_01H".to_owned(),
                },
            },
        )
        .expect("records the acceptance");
}

/// KR-REQ-23.41: a draft whose files the agent took stops counting against the bound. A device
/// holding the bound is refused a create; the agent takes the files of one of its drafts; the next
/// create is served, and the device is at the bound again after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_is_served_once_the_agent_has_taken_the_files_of_a_draft() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 55, EVERY_RIGHT);
    let device = connection.device.principal();
    let (draft, transfer_id) = a_draft_with_a_file(&world, &device);
    for _ in 1..DEVICE_OPEN_DRAFTS {
        a_draft_for(&world, &device, None);
    }
    let create = |request_id: u64| {
        write_naming(
            &world,
            &connection,
            Method::DraftCreate,
            request_id,
            &create_params(&world, None, None, "one more"),
            None,
        )
    };
    assert_eq!(
        super::tests::error_of(&connection.mutate(&create(1)).await).code,
        ErrorCode::QuotaExceeded,
        "the device holds the bound"
    );

    the_agent_takes(&world, &device, draft.draft_id, transfer_id);
    let _: DraftCreateResult = result_of(&connection.mutate(&create(2)).await);
    assert_eq!(
        super::tests::error_of(&connection.mutate(&create(3)).await).code,
        ErrorCode::QuotaExceeded,
        "the place is taken, and the bound holds"
    );
    controller
        .transfer()
        .service()
        .draft(&device, draft.draft_id)
        .expect("the draft whose files were taken is still there");
    world.serving.abort();
}

/// KR-REQ-23.41: a file bound to a draft whose files the agent took makes the draft count again, so
/// the binding is asked the bound as a create is. A device holding the bound is refused the binding
/// with the quota code in words that name `draft.discard`, and nothing is bound; it ends one draft
/// and the same binding is served. Another device's binding to a draft of its own is served
/// throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binding_that_makes_a_spent_draft_count_again_is_asked_the_bound() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let service = controller.transfer().service();
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 56, EVERY_RIGHT);
    let device = connection.device.principal();
    let (spent, transfer_id) = a_draft_with_a_file(&world, &device);
    the_agent_takes(&world, &device, spent.draft_id, transfer_id);
    let counting = (0..DEVICE_OPEN_DRAFTS)
        .map(|_| a_draft_for(&world, &device, None))
        .collect::<Vec<_>>();
    assert_eq!(
        service.open_drafts(&device).expect("counts"),
        DEVICE_OPEN_DRAFTS,
        "the device holds its bound"
    );

    let second = super::tests::a_published_attachment_for(
        controller,
        world.environment_id,
        &device,
        "second.bin",
        Some(session),
    );
    let bind = |connection: &super::RemoteConnection,
                request_id: u64,
                draft_id: DraftId,
                actor: &ActorId,
                handle: &kr_protocol::transfer::AttachmentHandle| {
        let revision = service.draft(actor, draft_id).expect("the draft").revision;
        write_naming(
            &world,
            connection,
            Method::AgentDraftAddAttachment,
            request_id,
            &AgentDraftAddAttachmentParams {
                draft_id,
                expected_revision: revision,
                transfer_id: handle.transfer_id,
                contribution: manual_contribution(handle),
            },
            Some(session),
        )
    };
    let attachments = |actor: &ActorId, draft_id: DraftId| {
        service
            .draft(actor, draft_id)
            .expect("the draft")
            .attachments
            .len()
    };

    let refused = connection
        .mutate(&bind(&connection, 1, spent.draft_id, &device, &second))
        .await;
    let refusal = super::tests::error_of(&refused);
    assert_eq!(refusal.code, ErrorCode::QuotaExceeded, "{refusal:?}");
    assert!(
        refusal.message.contains("draft.discard"),
        "the words name how a place is freed: {refusal:?}"
    );
    assert_eq!(attachments(&device, spent.draft_id), 1, "nothing was bound");

    let (another, _) = paired_connection(controller, 57, EVERY_RIGHT);
    let another_actor = another.device.principal();
    let (theirs, their_transfer) = a_draft_with_a_file(&world, &another_actor);
    the_agent_takes(&world, &another_actor, theirs.draft_id, their_transfer);
    let their_second = super::tests::a_published_attachment_for(
        controller,
        world.environment_id,
        &another_actor,
        "second.bin",
        Some(session),
    );
    let _: AgentDraftAddAttachmentResult = result_of(
        &another
            .mutate(&bind(
                &another,
                1,
                theirs.draft_id,
                &another_actor,
                &their_second,
            ))
            .await,
    );

    let _: DraftDiscardResult = result_of(
        &connection
            .mutate(&discard(&world, &connection, 2, counting[0].draft_id))
            .await,
    );
    let _: AgentDraftAddAttachmentResult = result_of(
        &connection
            .mutate(&bind(&connection, 3, spent.draft_id, &device, &second))
            .await,
    );
    assert_eq!(attachments(&device, spent.draft_id), 2);
    assert_eq!(
        service.open_drafts(&device).expect("counts"),
        DEVICE_OPEN_DRAFTS,
        "the draft counts again, and the device is at its bound"
    );
    world.serving.abort();
}

/// KR-REQ-23.41 and KR-REQ-09.09: an exact repeat of a discard that another copy performed while this
/// one was on its way to the service is told as the copy it is. The draft the first copy ended is
/// gone when the second reaches the service, and the service answers it from the record; the door
/// does not refuse it as a draft it does not know, which would tell a device that ended its draft
/// that it never had one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_a_discard_that_reaches_the_service_after_the_draft_is_gone_is_answered_from_the_record()
 {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 56, EVERY_RIGHT);
    let device = connection.device.principal();
    let own = a_draft_for(&world, &device, None);
    let mutation = discard(&world, &connection, 91, own.draft_id);

    let (copied, fresh) = two_copies(controller, &connection, &mutation).await;
    for answered in [&copied, &fresh] {
        let ended: DraftDiscardResult = result_of(answered.frame());
        assert_eq!(ended.draft_id, own.draft_id);
    }
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the copy that read the record is held as a kept answer"
    );
    assert!(
        fresh.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
        "the copy that performed is a fresh answer"
    );
    world.serving.abort();
}

/// KR-REQ-23.41 and KR-REQ-09.09: a copy of a discard that is stopped inside the service, after the
/// door's check and before the service takes its lock, is answered from the record the other copy
/// made, and is told as the copy it is. The copy that performed is a fresh answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_discard_copied_inside_the_service_is_answered_from_the_record_and_told_as_a_copy() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 59, EVERY_RIGHT);
    let device = connection.device.principal();
    let own = a_draft_for(&world, &device, None);
    let mutation = discard(&world, &connection, 92, own.draft_id);

    let (copied, fresh) =
        two_copies_stopped_in_the_service(controller, &connection, &mutation).await;
    for answered in [&copied, &fresh] {
        let ended: DraftDiscardResult = result_of(answered.frame());
        assert_eq!(ended.draft_id, own.draft_id);
    }
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the copy that read the record is held as a kept answer"
    );
    assert!(
        fresh.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
        "the copy that performed is a fresh answer"
    );
    world.serving.abort();
}

/// Serves `action` twice, the first copy stopped before its effect, and between the two copies' ends
/// serves `then`: the second copy performs the action, `then` follows it, and the first copy goes on
/// to meet what both did to the draft. Returns the first copy's answer and the second's.
async fn a_copy_that_meets_a_draft_ended_meanwhile(
    controller: &std::sync::Arc<crate::service::Controller>,
    connection: &super::RemoteConnection,
    action: &MutationRequest,
    then: &MutationRequest,
) -> (super::Answered, super::Answered) {
    let (arrived, go) = controller.before_the_effect.arm();
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(action.clone())));
    tokio::pin!(first);
    tokio::select! {
        arrived = tokio::time::timeout(std::time::Duration::from_secs(30), arrived) => {
            arrived
                .expect("the first copy reaches the place it is stopped at")
                .expect("the pause is armed");
        }
        early = &mut first => panic!("the first copy was answered before its effect: {early:?}"),
    }
    let performed = connection
        .answer_now(ControlFrame::Mutation(Box::new(action.clone())))
        .await
        .expect("the second copy is answered");
    let ended = connection
        .answer_now(ControlFrame::Mutation(Box::new(then.clone())))
        .await
        .expect("the discard is answered");
    let _: DraftDiscardResult = result_of(ended.frame());
    go.send(()).expect("the first copy goes on");
    (first.await.expect("the first copy is answered"), performed)
}

/// KR-REQ-23.41 and KR-REQ-09.09: a copy of an update, or of a binding, whose draft another copy
/// changed and a discard then ended while it was on its way is answered from the record the other
/// copy made, as a copy: the door does not refuse it as a draft it does not know. The control is a
/// new update of the same gone draft, which is refused as unknown and does nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_an_update_or_a_binding_whose_draft_was_ended_meanwhile_is_answered_from_the_record()
 {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 60, EVERY_RIGHT);
    let device = connection.device.principal();

    let updated = a_draft_for(&world, &device, None);
    let update = write_naming(
        &world,
        &connection,
        Method::DraftUpdate,
        93,
        &DraftUpdateParams {
            draft_id: updated.draft_id,
            expected_revision: updated.revision,
            text: "the second words".to_owned(),
        },
        None,
    );
    // The second copy performs the update; the discard that follows ends the draft before the first
    // copy, stopped at the door, goes on.
    let (copied, performed) = a_copy_that_meets_a_draft_ended_meanwhile(
        controller,
        &connection,
        &update,
        &discard(&world, &connection, 94, updated.draft_id),
    )
    .await;
    let _: DraftUpdateResult = result_of(performed.frame());
    let _: DraftUpdateResult = result_of(copied.frame());
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the update the draft's end followed is told as the copy it is"
    );
    let stale = connection
        .mutate(&write_naming(
            &world,
            &connection,
            Method::DraftUpdate,
            95,
            &DraftUpdateParams {
                draft_id: updated.draft_id,
                expected_revision: updated.revision,
                text: "a new action".to_owned(),
            },
            None,
        ))
        .await;
    assert_eq!(
        super::tests::error_of(&stale).code,
        ErrorCode::InvalidArgument,
        "a new action for the gone draft is refused as unknown"
    );

    let bound = a_draft_for(&world, &device, Some(session));
    let handle = super::tests::a_published_attachment_for(
        controller,
        world.environment_id,
        &device,
        "meanwhile.bin",
        Some(session),
    );
    let bind = write_naming(
        &world,
        &connection,
        Method::AgentDraftAddAttachment,
        96,
        &AgentDraftAddAttachmentParams {
            draft_id: bound.draft_id,
            expected_revision: bound.revision,
            transfer_id: handle.transfer_id,
            contribution: manual_contribution(&handle),
        },
        Some(session),
    );
    let (copied, performed) = a_copy_that_meets_a_draft_ended_meanwhile(
        controller,
        &connection,
        &bind,
        &write_naming(
            &world,
            &connection,
            Method::DraftDiscard,
            97,
            &DraftDiscardParams {
                draft_id: bound.draft_id,
            },
            Some(session),
        ),
    )
    .await;
    let _: AgentDraftAddAttachmentResult = result_of(performed.frame());
    let _: AgentDraftAddAttachmentResult = result_of(copied.frame());
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the binding the draft's end followed is told as the copy it is"
    );
    world.serving.abort();
}

/// KR-REQ-09.09: a first discard is withheld while this host owes a fence it could not raise, as
/// every write is: it is refused at the ask and the draft stands. The control is the same discard
/// once the fence is gone, which ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_discard_is_refused_while_a_fence_is_owed_and_the_draft_stands() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let service = controller.transfer().service();
    let (connection, _) = paired_connection(controller, 57, EVERY_RIGHT);
    let device = connection.device.principal();
    let own = a_draft_for(&world, &device, None);

    controller.hold_fence(true);
    let refused = connection
        .mutate(&discard(&world, &connection, 1, own.draft_id))
        .await;
    controller.hold_fence(false);
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::PermissionDenied,
        "{refused:?}"
    );
    service
        .draft(&device, own.draft_id)
        .expect("the draft stands");
    let _: DraftDiscardResult = result_of(
        &connection
            .mutate(&discard(&world, &connection, 2, own.draft_id))
            .await,
    );
}

/// KR-REQ-09.09 and 26.16: the record of a performed discard is not given back to a repeat while
/// this host owes a fence it could not raise: the record is withheld and the repeat is told the
/// fence's refusal. The control is the same repeat with nothing owed, which is given the record, and
/// again once the fence is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_a_performed_discard_is_withheld_while_a_fence_is_owed() {
    use crate::service::the_fence_at_every_effect::{
        admitted, carried, daemon, mutation_of as local_mutation, refused_for_a_fence,
    };

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let draft = controller
        .transfer()
        .service()
        .draft_create(
            &actor_id,
            &kr_protocol::transfer::DraftCreateParams {
                environment_id: temp.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::null(),
                application_instance_id: Nullable::null(),
                text: "to be ended".to_owned(),
            },
            None,
            None,
        )
        .expect("the owner's draft")
        .draft;
    let mutation = local_mutation(
        &temp,
        Method::DraftDiscard,
        ParamsValue::from_typed(&DraftDiscardParams {
            draft_id: draft.draft_id,
        })
        .expect("encodes"),
    );
    let attempt = || {
        controller.transfer().write(
            &actor_id,
            &mutation,
            Method::DraftDiscard,
            crate::transfer::TransferAdmission::new(
                std::sync::Arc::clone(&controller),
                carried(&controller, connection_id),
            ),
            None,
        )
    };

    let first = attempt().await;
    assert!(!first.is_copied(), "the first attempt performs");
    first.into_answer().expect("the draft is ended");
    let copy = attempt().await;
    assert!(copy.is_copied(), "the repeat is given the record");
    copy.into_answer()
        .expect("with nothing owed the repeat is answered from the record");

    controller.hold_fence(true);
    let refused = attempt()
        .await
        .into_withheld()
        .expect_err("a fence this host owes stops the record");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
    attempt()
        .await
        .into_answer()
        .expect("once the fence is gone it is answered again");
}

/// KR-REQ-23.41: the person at this machine ends the owner's own drafts at the local door, and
/// cannot end a device's: the owner is told of a device's draft what a device is told of the
/// owner's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_ends_its_own_draft_at_the_local_door_and_none_of_a_devices() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let service = controller.transfer().service();
    let (connection, _) = paired_connection(controller, 58, EVERY_RIGHT);
    let device = connection.device.principal();
    let owner = the_owner();
    let theirs = a_draft_for(&world, &device, None);
    let owners = a_draft_for(&world, &owner, None);
    let admission = fake::admission(controller, world.accepted).await;

    let at_the_local_door = |request_id: u64, draft_id: DraftId| {
        let window = controller
            .windows
            .issue(admission.connection_id, controller.boot_epoch)
            .expect("a window");
        let mut local = mutation_of(
            &world,
            &connection,
            Method::DraftDiscard,
            request_id,
            ParamsValue::from_typed(&DraftDiscardParams { draft_id }).expect("encodes"),
        );
        local.action_window_id = window.action_window_id;
        local
    };
    let refused = controller
        .perform(
            &owner,
            admission.connection_id,
            None,
            at_the_local_door(1, theirs.draft_id),
        )
        .await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::InvalidArgument,
        "{refused:?}"
    );
    service
        .draft(&device, theirs.draft_id)
        .expect("the device's draft stands");

    let ended = controller
        .perform(
            &owner,
            admission.connection_id,
            None,
            at_the_local_door(2, owners.draft_id),
        )
        .await;
    let ended: DraftDiscardResult = result_of(&ended);
    assert_eq!(ended.draft_id, owners.draft_id);
    assert!(
        service.draft(&owner, owners.draft_id).is_err(),
        "the owner's draft is gone"
    );
    world.serving.abort();
}
