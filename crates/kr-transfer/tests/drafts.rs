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
use kr_transfer::service::{Action, Admission};
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
/// KR-REQ-06.08: a draft update is bound to the exact draft revision: one naming another revision
/// is refused, the current one advances it, and the revision it moved past is refused afterwards.
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

    // The revision the update was made at is now stale in its turn.
    let superseded = harness
        .service
        .draft_update(
            &harness.actor,
            &DraftUpdateParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                text: "changed again".to_owned(),
            },
            None,
        )
        .expect_err("refuses the revision it has moved past");
    assert_eq!(superseded.code(), ErrorCode::DraftConflict);

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
            .record_prompt(
                &harness.actor,
                created.draft_id,
                created.session_id.0.expect("a session"),
                &Admission::none()
            )
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

/// KR-REQ-11.49: a declared external destination is recorded with the binding and disclosed by the
/// draft, and one that is declared without being named is refused.
#[test]
fn a_declared_external_destination_is_recorded_and_disclosed() {
    let harness = Harness::create();
    let bytes = pattern(512);
    let handle = harness.publish(&bytes, "image/png", "shot.png");
    let draft = draft(&harness);
    let mut declared = contribution(&handle, InsertionMethod::TypedSubmission);
    declared.external_destination = Nullable::some("amp-service:media-uploads".to_owned());

    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                transfer_id: handle.transfer_id,
                expected_revision: draft.revision,
                contribution: declared.clone(),
            },
            None,
        )
        .expect("binds the attachment");
    assert_eq!(
        bound.attachment.external_destination,
        Nullable::some("amp-service:media-uploads".to_owned()),
        "the destination the operation declared is disclosed on the binding"
    );

    // The disclosure is a row, not a value that lived only in the reply: a client that reads the
    // draft later still learns where the bytes go.
    let reread = harness
        .service
        .draft(&harness.actor, draft.draft_id)
        .expect("reads the draft back");
    assert_eq!(
        reread.attachments[0].external_destination,
        Nullable::some("amp-service:media-uploads".to_owned())
    );

    // A destination declared without being named is refused, because an unnamed destination
    // discloses nothing.
    let second = harness.publish(&bytes, "image/png", "second.png");
    let mut blank = contribution(&second, InsertionMethod::TypedSubmission);
    blank.external_destination = Nullable::some("   ".to_owned());
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                transfer_id: second.transfer_id,
                expected_revision: reread.revision,
                contribution: blank.clone(),
            },
            None,
        )
        .expect_err("refuses an unnamed destination");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);

    // So is one longer than a person reads.
    let mut long = contribution(&second, InsertionMethod::TypedSubmission);
    long.external_destination =
        Nullable::some("d".repeat(kr_protocol::transfer::MAX_EXTERNAL_DESTINATION_LEN + 1));
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                transfer_id: second.transfer_id,
                expected_revision: reread.revision,
                contribution: long,
            },
            None,
        )
        .expect_err("refuses an unbounded destination");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);

    // The refusals changed nothing: the draft still holds exactly the one binding that was made.
    let after = harness
        .service
        .draft(&harness.actor, draft.draft_id)
        .expect("reads the draft back");
    assert_eq!(after.attachments.len(), 1);
    assert_eq!(after.revision, reread.revision);
}

/// KR-REQ-24.09: ending a session fails what its agent never confirmed and leaves what it did, for
/// a draft that was sent to the session. The binding the agent accepted stays accepted, a prompt,
/// a binding or an adapter's late report for the ended session is refused, and an upload that
/// belongs to the ended session cannot be bound to a draft that names none.
#[test]
fn ending_a_session_fails_only_the_insertions_its_agent_never_confirmed() {
    let harness = Harness::create();
    let session = SessionId::new(Uuid::from_bytes([21; 16]));
    let sessionless = |harness: &Harness| {
        harness
            .service
            .draft_create(
                &harness.actor,
                &DraftCreateParams {
                    environment_id: harness.environment_id(),
                    device_id: Nullable::null(),
                    session_id: Nullable::null(),
                    application_instance_id: Nullable::null(),
                    text: "no session yet".to_owned(),
                },
                None,
            )
            .expect("creates the draft")
            .draft
    };
    let bind = |harness: &Harness, draft: &kr_protocol::transfer::DraftRecord, name: &str| {
        let handle = harness.publish(&pattern(70 + name.len()), "image/png", name);
        let bound = harness
            .service
            .draft_add_attachment(
                &harness.actor,
                &AgentDraftAddAttachmentParams {
                    draft_id: draft.draft_id,
                    expected_revision: draft.revision,
                    transfer_id: handle.transfer_id,
                    contribution: contribution(&handle, InsertionMethod::TypedSubmission),
                },
                None,
            )
            .expect("binds the attachment");
        (bound.draft, handle)
    };

    // A draft that names no session, two bindings, one of them accepted by the agent, then sent.
    let (draft_one, first) = bind(&harness, &sessionless(&harness), "first.png");
    let (draft_one, second) = bind(&harness, &draft_one, "second.png");
    harness
        .service
        .record_insertion_outcome(
            &harness.actor,
            draft_one.draft_id,
            second.transfer_id,
            &InsertionOutcome::AcceptedByAgent {
                upstream_evidence: "the agent's own part".to_owned(),
            },
        )
        .expect("records the agent's evidence");
    harness
        .service
        .record_prompt(
            &harness.actor,
            draft_one.draft_id,
            session,
            &Admission::none(),
        )
        .expect("sends the draft to the session");

    let accepted_before = harness
        .service
        .draft(&harness.actor, draft_one.draft_id)
        .expect("reads the draft")
        .attachments
        .into_iter()
        .find(|attachment| attachment.handle.transfer_id == second.transfer_id)
        .expect("the accepted binding is there");

    let failed = harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([session]))
        .expect("ends the session's insertions");
    assert_eq!(failed, 1, "only the binding nobody confirmed");
    let read = harness
        .service
        .draft(&harness.actor, draft_one.draft_id)
        .expect("reads the draft");
    let state_of = |transfer_id| {
        read.attachments
            .iter()
            .find(|attachment| attachment.handle.transfer_id == transfer_id)
            .expect("the binding is there")
            .state
    };
    assert_eq!(state_of(first.transfer_id), InsertionState::Failed);
    assert_eq!(
        state_of(second.transfer_id),
        InsertionState::AcceptedByAgent
    );
    let accepted_after = read
        .attachments
        .iter()
        .find(|attachment| attachment.handle.transfer_id == second.transfer_id)
        .expect("the accepted binding is there");
    assert_eq!(
        accepted_after, &accepted_before,
        "an insertion the agent accepted is untouched, evidence and all"
    );

    // The session has ended: a later prompt, binding and report are each refused as such.
    let other = sessionless(&harness);
    let prompt = harness
        .service
        .record_prompt(&harness.actor, other.draft_id, session, &Admission::none())
        .expect_err("a prompt for an ended session");
    assert_eq!(prompt.code(), ErrorCode::SessionClosed);
    let report = harness
        .service
        .record_insertion_outcome(
            &harness.actor,
            draft_one.draft_id,
            first.transfer_id,
            &InsertionOutcome::AcceptedByAgent {
                upstream_evidence: "a report that came late".to_owned(),
            },
        )
        .expect_err("a report for an ended session");
    assert_eq!(report.code(), ErrorCode::SessionClosed);

    // An upload that belongs to the ended session cannot be offered to a draft that names none.
    let owned = harness
        .begin_for(
            &pattern(90),
            "image/png",
            "owned.png",
            Nullable::some(session),
        )
        .expect("reserves an upload for the session");
    harness
        .send_all(owned.transfer_id, &pattern(90))
        .expect("sends it");
    let owned = harness
        .finish(owned.transfer_id, &pattern(90))
        .expect("publishes it")
        .handle;
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: other.draft_id,
                expected_revision: other.revision,
                transfer_id: owned.transfer_id,
                contribution: contribution(&owned, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("an upload of an ended session");
    assert_eq!(refusal.code(), ErrorCode::SessionClosed);
}

/// KR-REQ-24.09: an insertion whose upload belongs to the session that ends fails with it, though
/// its draft names no session and was never sent to one, and an insertion whose upload belongs to
/// another session stays. The draft takes one revision for the one binding.
#[test]
fn ending_a_session_fails_an_insertion_whose_upload_it_owns_though_the_draft_names_none() {
    let harness = Harness::create();
    let ending = SessionId::new(Uuid::from_bytes([31; 16]));
    let staying = SessionId::new(Uuid::from_bytes([32; 16]));
    let upload_of = |session: SessionId, name: &str| {
        let bytes = pattern(60 + name.len());
        let begun = harness
            .begin_for(&bytes, "image/png", name, Nullable::some(session))
            .expect("reserves an upload for the session");
        harness
            .send_all(begun.transfer_id, &bytes)
            .expect("sends it");
        harness
            .finish(begun.transfer_id, &bytes)
            .expect("publishes it")
            .handle
    };
    let owned = upload_of(ending, "owned.png");
    let other = upload_of(staying, "other.png");

    let bound = |draft: &kr_protocol::transfer::DraftRecord,
                 handle: &kr_protocol::transfer::AttachmentHandle| {
        harness
            .service
            .draft_add_attachment(
                &harness.actor,
                &AgentDraftAddAttachmentParams {
                    draft_id: draft.draft_id,
                    expected_revision: draft.revision,
                    transfer_id: handle.transfer_id,
                    contribution: contribution(handle, InsertionMethod::TypedSubmission),
                },
                None,
            )
            .expect("binds the attachment")
            .draft
    };
    let created = harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::null(),
                application_instance_id: Nullable::null(),
                text: "names no session".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft;
    let current = bound(&bound(&created, &owned), &other);

    let failed = harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([ending]))
        .expect("ends the session's insertions");
    assert_eq!(failed, 1, "only the binding whose upload the session owns");
    let read = harness
        .service
        .draft(&harness.actor, current.draft_id)
        .expect("reads the draft");
    let state_of = |transfer_id| {
        read.attachments
            .iter()
            .find(|attachment| attachment.handle.transfer_id == transfer_id)
            .expect("the binding is there")
            .state
    };
    assert_eq!(state_of(owned.transfer_id), InsertionState::Failed);
    assert_eq!(state_of(other.transfer_id), InsertionState::Recorded);
    assert_eq!(read.revision.get(), current.revision.get() + 1);
}

/// KR-REQ-24.09: the end of a session's worker fails the insertion its agent never confirmed, and
/// that never makes a draft unreadable. A draft grown to the largest size the service takes is
/// still readable afterwards, because a failed binding carries no reason text, and a binding for
/// the ended session's draft is refused from then on.
#[test]
fn ending_a_session_fails_its_unconfirmed_insertion_and_leaves_a_full_draft_readable() {
    let harness = Harness::create();
    let handle = harness.publish(&pattern(64), "image/png", "photo.png");
    let created = draft(&harness);
    let session = created.session_id.0.expect("a session");
    let mut current = harness
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
        .expect("binds the attachment")
        .draft;

    // Grow the text to the largest the service takes: a refused update changes nothing, so the
    // search ends holding the last text that was accepted.
    let (mut accepted, mut refused) = (0_usize, 1024 * 1024_usize);
    while refused - accepted > 1 {
        let middle = accepted + (refused - accepted) / 2;
        match harness.service.draft_update(
            &harness.actor,
            &DraftUpdateParams {
                draft_id: current.draft_id,
                expected_revision: current.revision,
                text: "a".repeat(middle),
            },
            None,
        ) {
            Ok(updated) => {
                current = updated.draft;
                accepted = middle;
            }
            Err(error) => {
                assert_eq!(error.code(), ErrorCode::QuotaExceeded, "{error:?}");
                refused = middle;
            }
        }
    }
    assert!(accepted > 1024, "the search found a limit near the budget");

    let failed = harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([session]))
        .expect("ends the session's insertions");
    assert_eq!(failed, 1);
    let read = harness
        .service
        .draft(&harness.actor, current.draft_id)
        .expect("a draft at its size limit is still readable");
    assert_eq!(read.attachments[0].state, InsertionState::Failed);
    assert_eq!(read.text.len(), accepted, "the text is what it was");
    let kept = &read.attachments[0].handle;
    assert_eq!(
        kept.transfer_id, handle.transfer_id,
        "the file is what it was"
    );
    assert_eq!(kept.content_digest, handle.content_digest);
    assert_eq!(kept.byte_len, handle.byte_len);

    let late = harness.publish(&pattern(65), "image/png", "later.png");
    let another = draft(&harness);
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: another.draft_id,
                expected_revision: another.revision,
                transfer_id: late.transfer_id,
                contribution: contribution(&late, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("a binding for an ended session is refused");
    assert_eq!(refusal.code(), ErrorCode::SessionClosed);
}

/// KR-REQ-24.09: a binding found `recorded` for a session that is already ended is failed the next
/// time the session is ended, because the end reads every `recorded` binding and not only those of
/// sessions it newly ends. Such a binding is left by a build that does not know the record of ended
/// sessions, running over a journal still at the unsettled version, and by a stop between the
/// start's closure step and a settling that gives an unassigned upload to an ended session. SQL
/// writes one here.
#[test]
fn a_binding_recorded_for_an_already_ended_session_is_failed_when_the_session_is_ended_again() {
    let harness = Harness::create();
    let handle = harness.publish(&pattern(64), "image/png", "photo.png");
    let created = draft(&harness);
    let session = created.session_id.0.expect("a session");
    harness
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
    let sessions = std::collections::BTreeSet::from([session]);
    assert_eq!(
        harness
            .service
            .end_session_insertions(&sessions)
            .expect("ends the session's insertions"),
        1
    );
    assert_eq!(
        harness
            .service
            .end_session_insertions(&sessions)
            .expect("ends them again"),
        0,
        "nothing is left to fail"
    );

    // A binding written beneath the service: asked, and not confirmed.
    rusqlite::Connection::open(kr_transfer::StagingArea::store_path(
        &harness.host.environment(),
    ))
    .expect("opens the journal")
    .execute("UPDATE draft_attachments SET state = 'recorded'", [])
    .expect("writes the binding");
    let before = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert_eq!(before.attachments[0].state, InsertionState::Recorded);

    assert_eq!(
        harness
            .service
            .end_session_insertions(&sessions)
            .expect("ends the session's insertions again"),
        1
    );
    let after = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert_eq!(after.attachments[0].state, InsertionState::Failed);
    let kept = &after.attachments[0].handle;
    assert_eq!(
        kept.transfer_id, handle.transfer_id,
        "the file is what it was"
    );
    assert_eq!(kept.content_digest, handle.content_digest);
}

/// KR-REQ-24.09: an insertion whose upload names no session still fails with the session its draft
/// targets, or the session its draft was sent to, and a late report for it is refused by the same
/// session. The service gives a bound upload its draft's session, so SQL clears it here, as a
/// journal written before it did would hold it.
#[test]
fn ending_a_session_fails_an_insertion_by_its_draft_when_its_upload_names_no_session() {
    let harness = Harness::create();
    let targeted_session = SessionId::new(Uuid::from_bytes([41; 16]));
    let sent_session = SessionId::new(Uuid::from_bytes([42; 16]));
    let bind_for = |draft: &kr_protocol::transfer::DraftRecord, name: &str| {
        let handle = harness.publish(&pattern(50 + name.len()), "image/png", name);
        harness
            .service
            .draft_add_attachment(
                &harness.actor,
                &AgentDraftAddAttachmentParams {
                    draft_id: draft.draft_id,
                    expected_revision: draft.revision,
                    transfer_id: handle.transfer_id,
                    contribution: contribution(&handle, InsertionMethod::TypedSubmission),
                },
                None,
            )
            .expect("binds the attachment")
            .draft
    };
    let create = |session: Nullable<SessionId>| {
        harness
            .service
            .draft_create(
                &harness.actor,
                &DraftCreateParams {
                    environment_id: harness.environment_id(),
                    device_id: Nullable::null(),
                    session_id: session,
                    application_instance_id: Nullable::null(),
                    text: "a draft".to_owned(),
                },
                None,
            )
            .expect("creates the draft")
            .draft
    };

    // One draft targets the first session. Another names none and is sent to the second.
    let targeting = bind_for(&create(Nullable::some(targeted_session)), "targeted.png");
    let sent = bind_for(&create(Nullable::null()), "sent.png");
    harness
        .service
        .record_prompt(
            &harness.actor,
            sent.draft_id,
            sent_session,
            &Admission::none(),
        )
        .expect("sends the draft to the session");
    rusqlite::Connection::open(kr_transfer::StagingArea::store_path(
        &harness.host.environment(),
    ))
    .expect("opens the journal")
    .execute("UPDATE uploads SET session_id = NULL", [])
    .expect("clears the uploads' sessions");

    let failed = harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([
            targeted_session,
            sent_session,
        ]))
        .expect("ends the sessions' insertions");
    assert_eq!(failed, 2, "one by the draft's target, one by its prompt");
    for draft in [targeting.draft_id, sent.draft_id] {
        let read = harness
            .service
            .draft(&harness.actor, draft)
            .expect("reads the draft");
        assert_eq!(read.attachments[0].state, InsertionState::Failed);

        // A late report is refused by the draft's own session, there being no other to match: the
        // upload names none and the report carries none.
        let report = harness
            .service
            .record_insertion_outcome(
                &harness.actor,
                draft,
                read.attachments[0].handle.transfer_id,
                &InsertionOutcome::AcceptedByAgent {
                    upstream_evidence: "a report that came late".to_owned(),
                },
            )
            .expect_err("a report for an ended session");
        assert_eq!(report.code(), ErrorCode::SessionClosed);
    }
}

/// The action a draft call is performed under: `id` is the caller's durable identifier, and the
/// payload stands for what the call carries.
fn draft_action(harness: &Harness, id: Uuid, method: &str, payload: &[u8]) -> Action {
    Action {
        actor_id: harness.actor.clone(),
        action_id: id,
        method: method.to_owned(),
        payload_digest: support::digest(payload),
        admission: Admission::none(),
    }
}

/// KR-REQ-09.07: an action identifier reused with another payload is `ID_CONFLICT` on a draft update
/// and on a binding as it is everywhere else. It is not the draft's own conflict, which says the
/// revision moved, and which a direct caller of the service would read as a reason to read the
/// draft again and retry under the same identifier.
#[test]
fn a_draft_action_reused_with_another_payload_is_an_id_conflict() {
    let harness = Harness::create();
    let created = draft(&harness);
    let update = |text: &str, expected: DraftRevision| DraftUpdateParams {
        draft_id: created.draft_id,
        expected_revision: expected,
        text: text.to_owned(),
    };

    let update_id = kr_ipc::new_uuid();
    let first = harness
        .service
        .draft_update(
            &harness.actor,
            &update("one", created.revision),
            Some(&draft_action(&harness, update_id, "draft.update", b"one")),
        )
        .expect("performs the update");
    let reused = harness
        .service
        .draft_update(
            &harness.actor,
            &update("two", first.draft.revision),
            Some(&draft_action(&harness, update_id, "draft.update", b"two")),
        )
        .expect_err("the identifier belongs to the first update");
    assert_eq!(reused.code(), ErrorCode::IdConflict);
    let after = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert_eq!(after.text, "one", "the second payload was not applied");
    assert_eq!(after.revision, first.draft.revision);

    let attach = |name: &str| {
        let bytes = pattern(64);
        let begun = harness
            .begin(&bytes, "image/png", name)
            .expect("reserves the upload");
        harness
            .send_all(begun.transfer_id, &bytes)
            .expect("sends every chunk");
        harness
            .finish(begun.transfer_id, &bytes)
            .expect("publishes the attachment")
            .handle
    };
    let (one, other) = (attach("one.png"), attach("other.png"));
    let bind = |handle: &AttachmentHandle, expected: DraftRevision| AgentDraftAddAttachmentParams {
        draft_id: created.draft_id,
        expected_revision: expected,
        transfer_id: handle.transfer_id,
        contribution: contribution(handle, InsertionMethod::TypedSubmission),
    };
    let bind_id = kr_ipc::new_uuid();
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &bind(&one, first.draft.revision),
            Some(&draft_action(
                &harness,
                bind_id,
                "agent.draft.add_attachment",
                b"one",
            )),
        )
        .expect("binds the first attachment");
    let reused = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &bind(&other, bound.draft.revision),
            Some(&draft_action(
                &harness,
                bind_id,
                "agent.draft.add_attachment",
                b"other",
            )),
        )
        .expect_err("the identifier belongs to the first binding");
    assert_eq!(reused.code(), ErrorCode::IdConflict);
    let after = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert_eq!(
        after.attachments.len(),
        1,
        "the second binding was not made"
    );

    // The control: the same payload under the same identifier is a repeat, and is answered with
    // what the first attempt produced.
    let repeated = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &bind(&one, first.draft.revision),
            Some(&draft_action(
                &harness,
                bind_id,
                "agent.draft.add_attachment",
                b"one",
            )),
        )
        .expect("a repeat is answered");
    assert_eq!(repeated.draft.revision, bound.draft.revision);
}
