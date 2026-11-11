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
    AgentDraftAddAttachmentParams, AttachmentContribution, DraftCreateResult, DraftDiscardParams,
    DraftDiscardResult, InsertionMethod,
};

use super::a_copy_a_service_withheld::two_copies_with_a_fence_between_the_checks;
use super::a_copy_from_a_services_record::{EVERY_RIGHT, mutation_of, refusal_of, two_copies};
use super::a_draft_a_device_writes::{
    a_draft_for, create_params, result_of, the_owner, write_naming,
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

/// KR-REQ-09.09: a discard is withheld while this host owes a fence it could not raise, as every
/// write is. A first discard is refused at the ask and the draft stands; the control is the same
/// discard once the fence is gone, which ends it. A copy that read the record another copy left, and
/// whose service asked its check with the fence owed, is told the outcome is not shown when the
/// fence is gone by the time the door asks its own, and not the record; with no fence owed both
/// copies are given the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_discard_is_withheld_while_a_fence_is_owed() {
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

    for (fence, rid) in [(false, 91), (true, 92)] {
        let draft = a_draft_for(&world, &device, None);
        let mutation = discard(&world, &connection, rid, draft.draft_id);
        let (copied, fresh) =
            two_copies_with_a_fence_between_the_checks(controller, &connection, &mutation, fence)
                .await;
        let _: DraftDiscardResult = result_of(fresh.frame());
        if fence {
            let told = refusal_of(&copied);
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            let _: DraftDiscardResult = result_of(copied.frame());
        }
    }
    world.serving.abort();
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
