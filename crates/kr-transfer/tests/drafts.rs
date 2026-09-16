//! Drafts, attachment contributions and the separation of transfer from insertion.
//!
//! Requirement rows closed here: KR-REQ-11.49, KR-REQ-12.28 and KR-REQ-23.41.

mod support;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ApplicationInstanceId, DeviceId, DraftId, DraftRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AttachmentContribution, AttachmentHandle, DraftCreateParams,
    DraftState, DraftUpdateParams, InsertionMethod, InsertionState,
};
use kr_transfer::InsertionOutcome;
use support::{Harness, pattern};

fn contribution(
    handle: &AttachmentHandle,
    insertion_method: InsertionMethod,
) -> AttachmentContribution {
    AttachmentContribution {
        operation_id: "attach".to_owned(),
        accepted_media_types: vec![handle.declared_media_type.clone()],
        max_byte_len: U64::new(1024 * 1024),
        max_count: U64::new(4),
        insertion_method,
        external_destination: Nullable::null(),
        model_media_capability: false,
    }
}

fn draft(harness: &Harness) -> kr_protocol::transfer::DraftRecord {
    harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([8; 16]))),
                session_id: Nullable::some(SessionId::new(Uuid::from_bytes([9; 16]))),
                application_instance_id: Nullable::some(ApplicationInstanceId::new(
                    Uuid::from_bytes([10; 16]),
                )),
                text: "have a look at this".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft
}

/// KR-REQ-23.41: a draft carries its owner, its revision and its environment, and every update
/// names the revision it expects.
#[test]
fn a_draft_carries_its_owner_revision_and_environment() {
    let harness = Harness::create();
    let created = draft(&harness);
    assert_eq!(created.environment_id, harness.environment_id());
    assert_eq!(created.revision, DraftRevision::new(1));
    assert_eq!(created.state, DraftState::Open);
    assert!(created.attachments.is_empty());
    assert!(created.device_id.is_present());
    assert!(created.session_id.is_present());

    let stale = harness
        .service
        .draft_update(
            &harness.actor,
            &DraftUpdateParams {
                draft_id: created.draft_id,
                expected_revision: DraftRevision::new(99),
                text: "changed".to_owned(),
            },
            None,
        )
        .expect_err("refuses a stale revision");
    assert_eq!(stale.code(), ErrorCode::DraftConflict);
    let updated = harness
        .service
        .draft_update(
            &harness.actor,
            &DraftUpdateParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                text: "changed".to_owned(),
            },
            None,
        )
        .expect("updates at the current revision")
        .draft;
    assert_eq!(updated.revision, DraftRevision::new(2));
    assert_eq!(updated.text, "changed");

    // Another principal's draft and an identifier that names nothing are refused the same way, so
    // the refusal is never a signal that something with that identifier exists.
    let other = kr_protocol::ids::ActorId::new("local:someone-else").expect("a valid principal");
    let refusal = harness
        .service
        .draft(&other, created.draft_id)
        .expect_err("refuses another principal");
    let unknown = harness
        .service
        .draft(&harness.actor, DraftId::new(Uuid::from_bytes([200; 16])))
        .expect_err("refuses an identifier that names nothing");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert_eq!(unknown.code(), refusal.code());
}

/// KR-REQ-12.28: `upload.finish`, `agent.draft.add_attachment` and `agent.prompt.submit` are three
/// separate actions, and this service performs only the first two.
#[test]
fn transfer_insertion_and_submission_are_three_separate_actions() {
    let harness = Harness::create();
    let bytes = pattern(512);
    let handle = harness.publish(&bytes, "image/png", "photo.png");
    let created = draft(&harness);

    // Publishing changed nothing about the draft.
    let read = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert!(
        read.attachments.is_empty(),
        "a published upload is not a binding"
    );
    assert!(!handle.submitted, "and it is not submitted");

    // Binding records the offer and nothing more.
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect("binds the attachment");
    assert_eq!(bound.attachment.state, InsertionState::Recorded);
    assert!(
        bound.attachment.upstream_evidence.as_ref().is_none(),
        "the adapter was asked; the agent has accepted nothing"
    );
    assert!(
        !bound.attachment.handle.submitted,
        "binding is not submission"
    );

    // Submission is a third action. It changes what retention applies and nothing else.
    assert_eq!(
        harness
            .service
            .mark_submitted(&harness.actor, created.draft_id)
            .expect("records the submission"),
        1
    );
    let read = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert!(read.attachments[0].handle.submitted);
    assert_eq!(
        read.attachments[0].state,
        InsertionState::Recorded,
        "submitting a draft does not make an agent accept its attachment"
    );

    // The registry keeps the three methods separate too, and the submission is an agent mutation
    // this service does not serve.
    assert_eq!(
        Method::UploadFinish.group(),
        kr_protocol::method::MethodGroup::DraftsAndMedia
    );
    assert_eq!(
        Method::AgentDraftAddAttachment.group(),
        kr_protocol::method::MethodGroup::DraftsAndMedia
    );
    assert_eq!(
        Method::AgentPromptSubmit.group(),
        kr_protocol::method::MethodGroup::AgentMutations
    );
}

/// KR-REQ-11.49: a contribution declares its accepted types, limits, count and insertion method,
/// and the host checks a handle against that declaration.
#[test]
fn a_contribution_declares_what_it_accepts_and_the_host_checks_it() {
    let harness = Harness::create();
    let bytes = pattern(2048);
    let handle = harness.publish(&bytes, "image/png", "photo.png");
    let created = draft(&harness);

    let wrong_type = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    accepted_media_types: vec!["application/pdf".to_owned()],
                    ..contribution(&handle, InsertionMethod::TypedSubmission)
                },
            },
            None,
        )
        .expect_err("refuses a type the operation does not accept");
    assert_eq!(wrong_type.code(), ErrorCode::InvalidArgument);

    let too_large = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    max_byte_len: U64::new(16),
                    ..contribution(&handle, InsertionMethod::TypedSubmission)
                },
            },
            None,
        )
        .expect_err("refuses a file above the selected model's limit");
    assert_eq!(too_large.code(), ErrorCode::InvalidArgument);

    let none_accepted = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    max_count: U64::new(0),
                    ..contribution(&handle, InsertionMethod::TypedSubmission)
                },
            },
            None,
        )
        .expect_err("refuses an operation that accepts nothing");
    assert_eq!(none_accepted.code(), ErrorCode::InvalidArgument);

    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    max_count: U64::new(1),
                    ..contribution(&handle, InsertionMethod::TypedSubmission)
                },
            },
            None,
        )
        .expect("binds the attachment");

    let second = harness.publish(&pattern(256), "image/png", "second.png");
    let over_count = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: bound.draft.revision,
                transfer_id: second.transfer_id,
                contribution: AttachmentContribution {
                    max_count: U64::new(1),
                    ..contribution(&second, InsertionMethod::TypedSubmission)
                },
            },
            None,
        )
        .expect_err("refuses more attachments than the operation accepts");
    assert_eq!(over_count.code(), ErrorCode::InvalidArgument);
}

/// KR-REQ-11.49: only upstream evidence makes an insertion accepted, and a failure keeps both the
/// draft and the completed upload.
#[test]
fn a_failed_insertion_keeps_the_draft_and_the_upload_and_only_evidence_accepts() {
    let harness = Harness::create();
    let bytes = pattern(1024);
    let handle = harness.publish(&bytes, "image/png", "photo.png");
    let created = draft(&harness);
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::VerifiedComposerInsertion),
            },
            None,
        )
        .expect("binds the attachment");
    assert_eq!(bound.attachment.state, InsertionState::Recorded);

    let failed = harness
        .service
        .record_insertion_outcome(
            &harness.actor,
            created.draft_id,
            handle.transfer_id,
            &InsertionOutcome::Failed {
                detail: "the composer was not empty".to_owned(),
            },
        )
        .expect("records the failure");
    assert_eq!(failed.state, InsertionState::Failed);
    assert_eq!(
        failed.failure_detail.0.as_deref(),
        Some("the composer was not empty")
    );
    assert!(failed.upstream_evidence.as_ref().is_none());

    // Both survive the failure, which is the whole point of keeping them separate.
    let read = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("the draft is still there");
    assert_eq!(read.text, "have a look at this");
    assert_eq!(read.attachments.len(), 1);
    harness
        .service
        .attachment_handle(&harness.actor, handle.transfer_id)
        .expect("the completed upload is still there");

    // Acceptance needs evidence, and empty evidence is not evidence.
    let refusal = harness
        .service
        .record_insertion_outcome(
            &harness.actor,
            created.draft_id,
            handle.transfer_id,
            &InsertionOutcome::AcceptedByAgent {
                upstream_evidence: "   ".to_owned(),
            },
        )
        .expect_err("refuses acceptance without evidence");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);

    let accepted = harness
        .service
        .record_insertion_outcome(
            &harness.actor,
            created.draft_id,
            handle.transfer_id,
            &InsertionOutcome::AcceptedByAgent {
                upstream_evidence: "upstream part msg_01H".to_owned(),
            },
        )
        .expect("records the acceptance");
    assert_eq!(accepted.state, InsertionState::AcceptedByAgent);
    assert_eq!(
        accepted.upstream_evidence.0.as_deref(),
        Some("upstream part msg_01H")
    );
    assert!(accepted.failure_detail.as_ref().is_none());

    // A retry after the failure is the same binding, not a second one.
    let read = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert_eq!(read.attachments.len(), 1);
}

/// KR-REQ-11.49: an operation that claims a model media capability cannot present unsupported
/// media as an image.
#[test]
fn unsupported_media_is_never_offered_as_a_model_image() {
    let harness = Harness::create();
    // Bytes that are not an image at all, declared as one.
    let handle = harness.publish(b"this is not a picture", "image/png", "photo.png");
    assert!(
        !handle.presented_as_image,
        "nothing decoded, so nothing is presented as an image"
    );
    assert!(handle.preview.as_ref().is_none());
    let created = draft(&harness);
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: AttachmentContribution {
                    model_media_capability: true,
                    ..contribution(&handle, InsertionMethod::TypedSubmission)
                },
            },
            None,
        )
        .expect_err("refuses to present a file as a model image");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);

    // It still transfers as a file: the operation just does not claim a media capability for it.
    harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::ManualTerminalWorkflow),
            },
            None,
        )
        .expect("binds it as a file");
}

/// KR-REQ-23.41: a binding cannot name an attachment that is not published, and the draft's
/// revision has to be current.
#[test]
fn a_binding_needs_a_published_attachment_and_the_current_revision() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let begun = harness
        .begin(&bytes, "image/png", "photo.png")
        .expect("reserves the upload");
    let created = draft(&harness);
    let unpublished = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: begun.transfer_id,
                contribution: AttachmentContribution {
                    operation_id: "attach".to_owned(),
                    accepted_media_types: vec!["image/png".to_owned()],
                    max_byte_len: U64::new(1024),
                    max_count: U64::new(1),
                    insertion_method: InsertionMethod::TypedSubmission,
                    external_destination: Nullable::null(),
                    model_media_capability: false,
                },
            },
            None,
        )
        .expect_err("refuses an attachment that is not published");
    assert_eq!(unpublished.code(), ErrorCode::ResourceUnavailable);

    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let handle = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment")
        .handle;
    let stale = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: DraftRevision::new(77),
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("refuses a stale revision");
    assert_eq!(stale.code(), ErrorCode::DraftConflict);
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect("binds at the current revision");
    assert_eq!(bound.draft.revision, DraftRevision::new(2));
}

/// KR-REQ-14.01, KR-REQ-23.41: a binding needs the attachment and the draft to belong to the same
/// principal, and to the same session where both name one.
#[test]
fn a_binding_needs_one_principal_and_one_session() {
    let harness = Harness::create();
    let bytes = pattern(256);
    let session = SessionId::new(Uuid::from_bytes([21; 16]));
    let other_session = SessionId::new(Uuid::from_bytes([22; 16]));

    let begun = harness
        .begin_for(&bytes, "image/png", "photo.png", Nullable::some(session))
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let handle = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment")
        .handle;

    // A draft for another session cannot hold it: the attachment would be retained against one
    // session while a draft for another held it.
    let elsewhere = harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(other_session),
                application_instance_id: Nullable::null(),
                text: "not this session".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft;
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: elsewhere.draft_id,
                expected_revision: elsewhere.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("refuses another session's draft");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);

    // Another principal's draft cannot hold it either, and neither can this principal's draft hold
    // another principal's attachment.
    let other = kr_protocol::ids::ActorId::new("local:someone-else").expect("a valid principal");
    let theirs = harness
        .service
        .draft_create(
            &other,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: "someone else's draft".to_owned(),
            },
            None,
        )
        .expect("creates their draft")
        .draft;
    let refusal = harness
        .service
        .draft_add_attachment(
            &other,
            &AgentDraftAddAttachmentParams {
                draft_id: theirs.draft_id,
                expected_revision: theirs.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("refuses another principal's attachment");
    assert_eq!(
        refusal.code(),
        ErrorCode::InvalidArgument,
        "and the refusal is the one an unknown identifier gets"
    );

    // The draft for the attachment's own session, under its own principal, does hold it.
    let mine = harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: "this session".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft;
    harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: mine.draft_id,
                expected_revision: mine.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect("binds the attachment");
}

/// KR-REQ-23.41: a read grant is narrow, expires, and is refused once it has.
#[test]
fn a_read_grant_is_narrow_and_expires() {
    let harness = Harness::create();
    let bytes = pattern(512);
    let handle = harness.publish(&bytes, "image/png", "photo.png");
    let created = draft(&harness);
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::ManualTerminalWorkflow),
            },
            None,
        )
        .expect("binds the attachment");
    let grant = bound
        .attachment
        .read_grant
        .as_ref()
        .expect("a readable path")
        .clone();
    assert_eq!(
        grant.expires_at_ms.get(),
        support::START_MS + kr_transfer::service::READ_GRANT_LIFETIME_MS
    );
    assert_eq!(
        grant.insertion_method,
        InsertionMethod::ManualTerminalWorkflow
    );
    harness
        .service
        .read_grant(grant.grant_id)
        .expect("resolves while it holds");

    harness
        .clock
        .advance(kr_transfer::service::READ_GRANT_LIFETIME_MS);
    let refusal = harness
        .service
        .read_grant(grant.grant_id)
        .expect_err("refuses an expired grant");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}
