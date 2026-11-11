//! Drafts, attachment contributions and the separation of transfer from insertion.

mod support;

use kr_protocol::broker::ActionProvenance;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, ApplicationInstanceId, DeviceId, DraftId, DraftRevision, SessionId,
};
use kr_protocol::insertion::ReportedOutcome;
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AttachmentContribution, AttachmentHandle, DraftCreateParams,
    DraftDiscardParams, DraftState, DraftUpdateParams, InsertionMethod, InsertionState,
};
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
                crate::support::an_application(),
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
            None,
        )
        .expect_err("refuses more attachments than the operation accepts");
    assert_eq!(over_count.code(), ErrorCode::InvalidArgument);
}

/// KR-REQ-11.49 and KR-REQ-14.03: only upstream evidence makes an insertion accepted, and bytes
/// written into the terminal are not evidence. A failure keeps both the draft and the completed
/// upload. The offer that failed is offered again as a new attempt of the same binding, under a
/// new action, and the draft holds one binding throughout.
#[test]
fn a_failed_insertion_keeps_the_draft_and_the_upload_and_only_evidence_accepts() {
    let harness = Harness::create();
    let bytes = pattern(1024);
    let handle = harness.publish(&bytes, "image/png", "photo.png");
    let created = draft(&harness);
    let session = created.session_id.0.expect("a session");
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
            None,
        )
        .expect("binds the attachment");
    assert_eq!(bound.attachment.state, InsertionState::Recorded);

    let first = ActionId::new(Uuid::from_bytes([61; 16]));
    harness
        .claim(session, created.draft_id, handle.transfer_id, first)
        .expect("claims the binding for the first offer");
    let begin = harness.begin_of(session, created.draft_id, handle.transfer_id, first);
    assert_eq!(
        harness
            .report(
                session,
                &begin,
                ReportedOutcome::Failed {
                    detail: "the composer was not empty".to_owned(),
                },
            )
            .expect("records the failure"),
        InsertionState::Failed
    );
    let read = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("the draft is still there");
    assert_eq!(read.text, "have a look at this");
    assert_eq!(read.attachments.len(), 1);
    assert_eq!(read.attachments[0].state, InsertionState::Failed);
    assert_eq!(
        read.attachments[0].failure_detail.0.as_deref(),
        Some("the composer was not empty")
    );
    assert!(read.attachments[0].upstream_evidence.as_ref().is_none());
    harness
        .service
        .attachment_handle(&harness.actor, handle.transfer_id)
        .expect("the completed upload is still there");

    // Acceptance needs evidence, and empty evidence is not evidence. A write into the terminal is
    // not either.
    let again = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: read.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
            None,
        )
        .expect("binds it again, as a new attempt of the same binding");
    assert_eq!(
        again.draft.attachments.len(),
        1,
        "one binding, not a second"
    );
    let second = ActionId::new(Uuid::from_bytes([62; 16]));
    harness
        .claim(session, created.draft_id, handle.transfer_id, second)
        .expect("claims the new attempt");
    let begin = harness.begin_of(session, created.draft_id, handle.transfer_id, second);
    for (outcome, code) in [
        (
            ReportedOutcome::AcceptedByAgent {
                provenance: ActionProvenance::UpstreamTypedRpc,
                evidence: "   ".to_owned(),
            },
            ErrorCode::InvalidArgument,
        ),
        (
            ReportedOutcome::AcceptedByAgent {
                provenance: ActionProvenance::TerminalInput,
                evidence: "the path was typed".to_owned(),
            },
            ErrorCode::PermissionDenied,
        ),
    ] {
        let refusal = harness
            .report(session, &begin, outcome)
            .expect_err("is not acceptance");
        assert_eq!(refusal.code(), code);
    }
    assert_eq!(
        harness
            .report(
                session,
                &begin,
                ReportedOutcome::AcceptedByAgent {
                    provenance: ActionProvenance::UpstreamTypedRpc,
                    evidence: "upstream part msg_01H".to_owned(),
                },
            )
            .expect("records the acceptance"),
        InsertionState::AcceptedByAgent
    );
    let accepted = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    assert_eq!(accepted.attachments.len(), 1);
    assert_eq!(
        accepted.attachments[0].upstream_evidence.0.as_deref(),
        Some("upstream part msg_01H")
    );
    assert!(accepted.attachments[0].failure_detail.as_ref().is_none());
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
/// a draft that targets the session. A binding the agent accepted stays accepted, one a worker was
/// offering when it went fails and its read grant is revoked, a prompt, a binding or an adapter's
/// late report for the ended session is refused, and an upload that belongs to the ended session
/// cannot be bound to a draft that names none.
#[test]
fn ending_a_session_fails_only_the_insertions_its_agent_never_confirmed() {
    let harness = Harness::create();
    let session = SessionId::new(Uuid::from_bytes([21; 16]));
    let draft_for = |harness: &Harness, session: SessionId| {
        harness
            .service
            .draft_create(
                &harness.actor,
                &DraftCreateParams {
                    environment_id: harness.environment_id(),
                    device_id: Nullable::null(),
                    session_id: Nullable::some(session),
                    application_instance_id: Nullable::null(),
                    text: "for the session".to_owned(),
                },
                None,
                None,
            )
            .expect("creates the draft")
            .draft
    };
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
                None,
            )
            .expect("binds the attachment");
        (bound.draft, handle)
    };

    // A draft for the session, two bindings: one the agent accepted, and one a worker was offering
    // when it went. Then the draft is sent.
    let (draft_one, first) = bind(&harness, &draft_for(&harness, session), "first.png");
    let (draft_one, second) = bind(&harness, &draft_one, "second.png");
    let accepting = ActionId::new(Uuid::from_bytes([71; 16]));
    harness
        .claim(session, draft_one.draft_id, second.transfer_id, accepting)
        .expect("claims the binding for an offer");
    harness
        .report(
            session,
            &harness.begin_of(session, draft_one.draft_id, second.transfer_id, accepting),
            ReportedOutcome::AcceptedByAgent {
                provenance: ActionProvenance::UpstreamTypedRpc,
                evidence: "the agent's own part".to_owned(),
            },
        )
        .expect("records the agent's evidence");
    let offering = ActionId::new(Uuid::from_bytes([72; 16]));
    let offered = harness
        .claim(session, draft_one.draft_id, first.transfer_id, offering)
        .expect("claims the other binding for an offer");
    let offering_begin = harness.begin_of(session, draft_one.draft_id, first.transfer_id, offering);

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
    assert!(
        harness.service.read_grant(offered.grant.grant_id).is_err(),
        "the grant of the offer that ended with its session is revoked"
    );
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
        .record_prompt(
            &harness.actor,
            other.draft_id,
            session,
            crate::support::an_application(),
            &Admission::none(),
        )
        .expect_err("a prompt for an ended session");
    assert_eq!(prompt.code(), ErrorCode::SessionClosed);
    let report = harness
        .report(
            session,
            &offering_begin,
            ReportedOutcome::AcceptedByAgent {
                provenance: ActionProvenance::UpstreamTypedRpc,
                evidence: "a report that came late".to_owned(),
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

    // A second draft for the same session, small enough to take a binding.
    let another = draft(&harness);
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

    // A draft is not made for the ended session, and a binding for the draft it had is refused.
    let refused_draft = harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: "for a session that is gone".to_owned(),
            },
            None,
            None,
        )
        .expect_err("a draft for an ended session is refused");
    assert_eq!(refused_draft.code(), ErrorCode::SessionClosed);
    let late = harness.publish(&pattern(65), "image/png", "later.png");
    let ended_draft = harness
        .service
        .draft(&harness.actor, another.draft_id)
        .expect("the second draft is readable");
    let refusal = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: ended_draft.draft_id,
                expected_revision: ended_draft.revision,
                transfer_id: late.transfer_id,
                contribution: contribution(&late, InsertionMethod::TypedSubmission),
            },
            None,
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
            crate::support::an_application(),
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
    for (draft, reporting_session) in [
        (targeting.draft_id, targeted_session),
        (sent.draft_id, sent_session),
    ] {
        let read = harness
            .service
            .draft(&harness.actor, draft)
            .expect("reads the draft");
        assert_eq!(read.attachments[0].state, InsertionState::Failed);

        // A late report is refused by the draft's own session, there being no other to match: the
        // upload names none and the report carries none.
        let report = harness
            .report(
                reporting_session,
                &kr_protocol::insertion::InsertionBegin {
                    action_id: ActionId::new(Uuid::from_bytes([73; 16])),
                    draft_id: draft,
                    transfer_id: read.attachments[0].handle.transfer_id,
                    attempt: U64::new(0),
                    max_count: U64::new(4),
                    deadline_boot_ms: U64::new(0),
                },
                ReportedOutcome::AcceptedByAgent {
                    provenance: ActionProvenance::UpstreamTypedRpc,
                    evidence: "a report that came late".to_owned(),
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
            None,
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
            None,
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
            None,
        )
        .expect("a repeat is answered");
    assert_eq!(repeated.draft.revision, bound.draft.revision);
}

/// KR-REQ-12.06 and KR-REQ-14.11: a prompt for another application than the one a draft was
/// written for is a conflict, and a draft that is wrong in its session is refused as that whichever
/// application the prompt is for. A draft that names no application is sent to any.
#[test]
fn a_draft_for_another_application_is_a_conflict_and_a_wrong_session_keeps_its_own_refusal() {
    let harness = Harness::create();
    let create = |application_instance_id: Nullable<ApplicationInstanceId>| {
        harness
            .service
            .draft_create(
                &harness.actor,
                &DraftCreateParams {
                    environment_id: harness.environment_id(),
                    device_id: Nullable::null(),
                    session_id: Nullable::null(),
                    application_instance_id,
                    text: "have a look at this".to_owned(),
                },
                None,
                None,
            )
            .expect("creates the draft")
            .draft
    };
    let session = SessionId::new(Uuid::from_bytes([9; 16]));
    let other_session = SessionId::new(Uuid::from_bytes([11; 16]));
    let elsewhere = ApplicationInstanceId::new(Uuid::from_bytes([12; 16]));
    let written = create(Nullable::some(support::an_application()));
    let record = |draft: &kr_protocol::transfer::DraftRecord, session, application| {
        harness.service.record_prompt(
            &harness.actor,
            draft.draft_id,
            session,
            application,
            &Admission::none(),
        )
    };

    let conflict =
        record(&written, session, elsewhere).expect_err("written for another application");
    assert_eq!(conflict.code(), ErrorCode::DraftConflict);
    // Nothing was recorded, so the prompt for what the draft was written for is the first record.
    record(&written, session, support::an_application()).expect("records the prompt");
    // A draft sent to a session is wrong for another whatever application the prompt is for, and
    // keeps that refusal.
    let wrong = record(&written, other_session, elsewhere).expect_err("sent to another session");
    assert_eq!(wrong.code(), ErrorCode::InvalidArgument);

    // A draft that names no application is sent by a prompt for any.
    let open = create(Nullable::null());
    record(&open, session, elsewhere).expect("a draft that names no application goes to any");
}

/// A draft for no session, made for `actor` with at most `limit` open drafts.
fn a_sessionless_draft(
    harness: &Harness,
    actor: &kr_protocol::ids::ActorId,
    limit: Option<u64>,
) -> Result<kr_protocol::transfer::DraftRecord, kr_transfer::TransferError> {
    harness
        .service
        .draft_create(
            actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::null(),
                application_instance_id: Nullable::null(),
                text: "an open draft".to_owned(),
            },
            None,
            limit,
        )
        .map(|created| created.draft)
}

/// KR-REQ-23.41: the drafts a principal holds open are bounded when the caller asks for a bound,
/// and the refusal is the service's quota code in words that name the bound. The control is the
/// same creates with no bound, which are all served: the person at this machine is not held to
/// one.
#[test]
fn a_create_past_the_bound_is_refused_under_the_quota_code_naming_the_bound() {
    let harness = Harness::create();
    let device = kr_protocol::ids::ActorId::new("device:bounded").expect("a principal");
    for _ in 0..3 {
        a_sessionless_draft(&harness, &device, Some(3)).expect("a place is free");
    }
    let refused = a_sessionless_draft(&harness, &device, Some(3)).expect_err("no place is free");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);
    assert!(
        refused.to_string().contains("3 of the 3"),
        "the words name the bound: {refused}"
    );
    assert!(
        refused.to_string().contains("draft.discard"),
        "the words name how a place is freed: {refused}"
    );

    for _ in 0..6 {
        a_sessionless_draft(&harness, &harness.actor, None).expect("no bound");
    }
}

/// KR-REQ-23.41: a draft counts against the principal that made it and no other, and every one
/// of them is counted whichever session it targets.
#[test]
fn one_principals_open_drafts_are_not_counted_against_another() {
    let harness = Harness::create();
    let first = kr_protocol::ids::ActorId::new("device:first").expect("a principal");
    let second = kr_protocol::ids::ActorId::new("device:second").expect("a principal");
    for _ in 0..2 {
        a_sessionless_draft(&harness, &first, Some(2)).expect("a place is free");
    }
    a_sessionless_draft(&harness, &first, Some(2)).expect_err("the first device is at its bound");
    for _ in 0..2 {
        a_sessionless_draft(&harness, &second, Some(2))
            .expect("the second device holds none of the first's places");
    }
}

/// KR-REQ-23.41: a draft stops counting when a prompt sends it to a session, which is how a device
/// frees its place, and the places it frees are the ones it held: a draft that was not sent still
/// counts.
#[test]
fn a_draft_a_prompt_has_sent_stops_counting_against_the_bound() {
    let harness = Harness::create();
    let device = kr_protocol::ids::ActorId::new("device:sending").expect("a principal");
    let session = SessionId::new(Uuid::from_bytes([4; 16]));
    let first = a_sessionless_draft(&harness, &device, Some(2)).expect("a place is free");
    a_sessionless_draft(&harness, &device, Some(2)).expect("a place is free");
    a_sessionless_draft(&harness, &device, Some(2)).expect_err("at the bound");

    assert_eq!(
        harness
            .service
            .record_prompt(
                &device,
                first.draft_id,
                session,
                crate::support::an_application(),
                &Admission::none(),
            )
            .expect("the prompt sends the draft"),
        0,
        "no attachment moves with it"
    );
    a_sessionless_draft(&harness, &device, Some(2)).expect("the sent draft's place is free");
    a_sessionless_draft(&harness, &device, Some(2)).expect_err("and only that one");
}

/// KR-REQ-23.41: a draft stops counting when the session it targets ends, whether or not it holds
/// anything, and a draft for another session still counts.
#[test]
fn a_draft_whose_session_has_ended_stops_counting_against_the_bound() {
    let harness = Harness::create();
    let device = kr_protocol::ids::ActorId::new("device:ending").expect("a principal");
    let ending = SessionId::new(Uuid::from_bytes([5; 16]));
    let staying = SessionId::new(Uuid::from_bytes([6; 16]));
    let create_for = |session: SessionId, limit: Option<u64>| {
        harness.service.draft_create(
            &device,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session),
                application_instance_id: Nullable::null(),
                text: "for a session".to_owned(),
            },
            None,
            limit,
        )
    };
    create_for(ending, Some(2)).expect("a place is free");
    create_for(staying, Some(2)).expect("a place is free");
    create_for(staying, Some(2)).expect_err("at the bound");

    harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([ending]))
        .expect("the session's end is recorded");
    create_for(staying, Some(2)).expect("the ended session's draft stopped counting");
    create_for(staying, Some(2)).expect_err("the draft for the other session still counts");
}

/// KR-REQ-23.41 and section 9: a repeat of the create that took the last place is answered with the
/// draft it made, and is not refused for the bound it filled; a create under a new identifier is
/// refused, and the service writes no record of that refusal, so the service itself would take the
/// identifier it carried for a create that has a place (the host keeps a refusal as the action's
/// outcome, and a caller whose place is free asks under a new action).
#[test]
fn a_repeat_of_the_create_that_took_the_last_place_is_answered_from_its_record() {
    let harness = Harness::create();
    let device = kr_protocol::ids::ActorId::new("device:repeating").expect("a principal");
    let action_for = |payload: &[u8]| Action {
        actor_id: device.clone(),
        action_id: kr_ipc::new_uuid(),
        method: "draft.create".to_owned(),
        payload_digest: support::digest(payload),
        admission: Admission::none(),
    };
    let params = DraftCreateParams {
        environment_id: harness.environment_id(),
        device_id: Nullable::null(),
        session_id: Nullable::null(),
        application_instance_id: Nullable::null(),
        text: "the last place".to_owned(),
    };
    let last = action_for(b"the last place");
    let made = harness
        .service
        .draft_create(&device, &params, Some(&last), Some(1))
        .expect("the one place is free");
    let again = harness
        .service
        .draft_create(&device, &params, Some(&last), Some(1))
        .expect("the repeat is answered from the record");
    assert_eq!(again, made, "one action, one draft");

    let refused_action = action_for(b"the last place");
    let refused = harness
        .service
        .draft_create(&device, &params, Some(&refused_action), Some(1))
        .expect_err("a new action finds no place");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);

    // Taking the place back, the identifier the refusal carried makes its draft.
    harness
        .service
        .record_prompt(
            &device,
            made.draft.draft_id,
            SessionId::new(Uuid::from_bytes([7; 16])),
            crate::support::an_application(),
            &Admission::none(),
        )
        .expect("the prompt sends the draft");
    harness
        .service
        .draft_create(&device, &params, Some(&refused_action), Some(1))
        .expect("the service wrote no record of the refusal");
}

/// What became of the one binding a draft holds for the cases that end a draft.
#[derive(Clone, Copy, Debug)]
enum Offered {
    /// Bound and nothing more.
    Recorded,
    /// Claimed by a worker that has not reported.
    Inserting,
    /// Reported accepted, with evidence.
    Accepted,
    /// Reported unknown.
    Unknown,
    /// Reported failed.
    Failed,
}

/// Binds a new upload to `created` as `method` says and takes it as far as `offered` says, for the
/// actor of the harness. Returns the draft as it reads afterwards and the upload's handle.
fn bound_and_offered(
    harness: &Harness,
    created: &kr_protocol::transfer::DraftRecord,
    method: InsertionMethod,
    offered: Offered,
    salt: u8,
) -> (kr_protocol::transfer::DraftRecord, AttachmentHandle) {
    let handle = harness.publish(&pattern(64 + usize::from(salt)), "image/png", "photo.png");
    harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: created.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, method),
            },
            None,
            None,
        )
        .expect("binds the attachment");
    if !matches!(offered, Offered::Recorded) {
        let session = created.session_id.0.expect("a session");
        let action = ActionId::new(Uuid::from_bytes([salt; 16]));
        harness
            .claim(session, created.draft_id, handle.transfer_id, action)
            .expect("claims the binding for an offer");
        let begin = harness.begin_of(session, created.draft_id, handle.transfer_id, action);
        let outcome = match offered {
            Offered::Recorded | Offered::Inserting => None,
            Offered::Accepted => Some(ReportedOutcome::AcceptedByAgent {
                provenance: ActionProvenance::UpstreamTypedRpc,
                evidence: "upstream part msg_01H".to_owned(),
            }),
            Offered::Unknown => Some(ReportedOutcome::Unknown {
                detail: "the offer may have reached the agent".to_owned(),
            }),
            Offered::Failed => Some(ReportedOutcome::Failed {
                detail: "the composer was not empty".to_owned(),
            }),
        };
        if let Some(outcome) = outcome {
            harness
                .report(session, &begin, outcome)
                .expect("records what became of the offer");
        }
    }
    let read = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect("reads the draft");
    (read, handle)
}

/// The refusal for a draft that is not there, with the draft's identifier taken out, so two of them
/// compare byte for byte.
fn unknown_draft_words(
    error: &kr_transfer::TransferError,
    draft_id: DraftId,
) -> (ErrorCode, String) {
    (
        error.code(),
        error.to_string().replace(&draft_id.to_string(), "<draft>"),
    )
}

/// KR-REQ-23.41: ending a draft deletes it with its attachment records, revokes the read grants of
/// its attachments, and changes no upload: the files stay published, and the bytes they charge stay
/// charged. A binding the agent was never offered (`recorded`) and one whose offer failed go with
/// the draft. The draft's place is free at once.
#[test]
fn ending_a_draft_deletes_it_with_what_it_holds_and_changes_no_upload() {
    let harness = Harness::create();
    let created = draft(&harness);
    let (read, manual) = bound_and_offered(
        &harness,
        &created,
        InsertionMethod::ManualTerminalWorkflow,
        Offered::Recorded,
        1,
    );
    let grant = read.attachments[0]
        .read_grant
        .as_ref()
        .expect("a readable path")
        .grant_id;
    let (read, typed) = bound_and_offered(
        &harness,
        &read,
        InsertionMethod::TypedSubmission,
        Offered::Failed,
        2,
    );
    assert_eq!(read.attachments.len(), 2);
    harness.service.read_grant(grant).expect("the grant holds");
    let staged = harness.service.staged_byte_len().expect("reads the total");
    assert!(staged > 0, "the uploads charge their bytes");
    let handle_of = |handle: &AttachmentHandle| {
        harness
            .service
            .attachment_handle(&harness.actor, handle.transfer_id)
            .expect("the upload is published")
    };
    let before = [handle_of(&manual), handle_of(&typed)];
    assert_eq!(
        harness.service.open_drafts(&harness.actor).expect("counts"),
        1
    );

    let ended = harness
        .service
        .draft_discard(
            &harness.actor,
            &DraftDiscardParams {
                draft_id: created.draft_id,
            },
            None,
        )
        .expect("ends the draft");
    assert_eq!(ended.draft_id, created.draft_id);

    let gone = harness
        .service
        .draft(&harness.actor, created.draft_id)
        .expect_err("the draft is gone");
    assert_eq!(gone.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        harness
            .service
            .read_grant(grant)
            .expect_err("the grant is revoked")
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        [handle_of(&manual), handle_of(&typed)],
        before,
        "each upload is as it was: its session, its expiry and its state"
    );
    assert_eq!(
        harness.service.staged_byte_len().expect("reads the total"),
        staged,
        "no byte was released"
    );
    assert_eq!(
        harness.service.open_drafts(&harness.actor).expect("counts"),
        0
    );
}

/// KR-REQ-23.41: a draft a prompt sent, and one with a binding the agent was offered (`inserting`),
/// took (`accepted_by_agent`) or may have been given (`unknown`), is the record of what the agent was
/// offered. Ending it is refused `DRAFT_CONFLICT` and nothing is deleted: the draft reads as it did,
/// with its bindings, and the read grant of its other binding still holds.
#[test]
fn a_draft_in_use_is_refused_and_nothing_is_deleted() {
    let session = SessionId::new(Uuid::from_bytes([9; 16]));
    for (name, offered) in [
        ("sent", None),
        ("inserting", Some(Offered::Inserting)),
        ("accepted", Some(Offered::Accepted)),
        ("unknown", Some(Offered::Unknown)),
    ] {
        let harness = Harness::create();
        let created = draft(&harness);
        let (mut read, _) = bound_and_offered(
            &harness,
            &created,
            InsertionMethod::ManualTerminalWorkflow,
            Offered::Recorded,
            1,
        );
        let grant = read.attachments[0]
            .read_grant
            .as_ref()
            .expect("a readable path")
            .grant_id;
        match offered {
            Some(offered) => {
                read = bound_and_offered(
                    &harness,
                    &read,
                    InsertionMethod::TypedSubmission,
                    offered,
                    2,
                )
                .0;
            }
            None => {
                harness
                    .service
                    .record_prompt(
                        &harness.actor,
                        created.draft_id,
                        session,
                        support::an_application(),
                        &Admission::none(),
                    )
                    .expect("the prompt sends the draft");
                read = harness
                    .service
                    .draft(&harness.actor, created.draft_id)
                    .expect("reads the draft");
            }
        }

        let refused = harness
            .service
            .draft_discard(
                &harness.actor,
                &DraftDiscardParams {
                    draft_id: created.draft_id,
                },
                None,
            )
            .expect_err(name);
        assert_eq!(
            refused.code(),
            ErrorCode::DraftConflict,
            "{name}: {refused}"
        );
        let kept = harness
            .service
            .draft(&harness.actor, created.draft_id)
            .unwrap_or_else(|error| panic!("{name}: the draft was deleted: {error}"));
        assert_eq!(kept, read, "{name}: the draft is as it was");
        harness
            .service
            .read_grant(grant)
            .unwrap_or_else(|error| panic!("{name}: a grant was revoked: {error}"));
    }
}

/// KR-REQ-23.41: only the draft's own principal ends it. Another principal's draft and a draft that
/// was never made are refused in the same words, so the refusal shows nothing of what exists, and the
/// draft stands. The control is the owner's own call, which ends it; after that the draft is gone and
/// a call for it is refused as the others were.
#[test]
fn another_principals_draft_and_a_gone_draft_are_refused_alike_and_the_draft_stands() {
    let harness = Harness::create();
    let other = kr_protocol::ids::ActorId::new("device:another").expect("a principal");
    let created = draft(&harness);
    let never = DraftId::new(Uuid::from_bytes([77; 16]));
    let discard = |actor: &kr_protocol::ids::ActorId, draft_id: DraftId| {
        harness
            .service
            .draft_discard(actor, &DraftDiscardParams { draft_id }, None)
    };

    let theirs = discard(&other, created.draft_id).expect_err("not the other's draft");
    let nothing = discard(&other, never).expect_err("no such draft");
    assert_eq!(theirs.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        unknown_draft_words(&theirs, created.draft_id),
        unknown_draft_words(&nothing, never),
        "the refusal is the same for a draft that exists and one that does not"
    );
    assert_eq!(
        harness
            .service
            .draft(&harness.actor, created.draft_id)
            .expect("the draft stands")
            .revision,
        created.revision
    );

    discard(&harness.actor, created.draft_id).expect("the owner ends its own draft");
    let gone = discard(&harness.actor, created.draft_id).expect_err("the draft is gone");
    assert_eq!(
        unknown_draft_words(&gone, created.draft_id),
        unknown_draft_words(&nothing, never)
    );
}

/// KR-REQ-23.41: a draft stops counting against a bound when every file bound to it was taken by
/// the agent (there is at least one binding), and in no other case: a binding the agent was offered
/// or may have been given (`inserting`, `unknown`) goes on counting, as does one taken beside one
/// that was not, and a draft with no binding or with a `recorded` or `failed` one. The place is the
/// device's to take again, and the refusal names the way to free one.
#[test]
fn a_draft_whose_every_file_the_agent_took_stops_counting_and_every_other_goes_on_counting() {
    let harness = Harness::create();
    let open = || harness.service.open_drafts(&harness.actor).expect("counts");
    let session_draft = || draft(&harness);

    let all_taken = session_draft();
    bound_and_offered(
        &harness,
        &all_taken,
        InsertionMethod::TypedSubmission,
        Offered::Accepted,
        1,
    );
    assert_eq!(open(), 0, "every file taken: the draft stops counting");

    let offering = session_draft();
    bound_and_offered(
        &harness,
        &offering,
        InsertionMethod::TypedSubmission,
        Offered::Inserting,
        2,
    );
    assert_eq!(open(), 1, "an offer is being made");

    let unknown = session_draft();
    bound_and_offered(
        &harness,
        &unknown,
        InsertionMethod::TypedSubmission,
        Offered::Unknown,
        3,
    );
    assert_eq!(open(), 2, "a report may still come");

    let mixed = session_draft();
    let (read, _) = bound_and_offered(
        &harness,
        &mixed,
        InsertionMethod::TypedSubmission,
        Offered::Accepted,
        4,
    );
    bound_and_offered(
        &harness,
        &read,
        InsertionMethod::ManualTerminalWorkflow,
        Offered::Recorded,
        5,
    );
    assert_eq!(open(), 3, "one file was taken and another was not");

    let failed_beside = session_draft();
    let (read, _) = bound_and_offered(
        &harness,
        &failed_beside,
        InsertionMethod::TypedSubmission,
        Offered::Accepted,
        6,
    );
    bound_and_offered(
        &harness,
        &read,
        InsertionMethod::TypedSubmission,
        Offered::Failed,
        7,
    );
    assert_eq!(open(), 4, "a failed offer beside a taken one");

    session_draft();
    assert_eq!(open(), 5, "a draft with no binding");

    let device = harness.actor.clone();
    a_sessionless_draft(&harness, &device, Some(6)).expect("the sixth place is free");
    let refused = a_sessionless_draft(&harness, &device, Some(6)).expect_err("no place is free");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);
    assert!(
        refused.to_string().contains("draft.discard"),
        "the words name how a place is freed: {refused}"
    );
}

/// Binds `handle` to `draft` for the actor of the harness, with at most `limit` open drafts.
fn bind_with_limit(
    harness: &Harness,
    draft: &kr_protocol::transfer::DraftRecord,
    handle: &AttachmentHandle,
    limit: Option<u64>,
) -> Result<kr_protocol::transfer::AgentDraftAddAttachmentResult, kr_transfer::TransferError> {
    harness.service.draft_add_attachment(
        &harness.actor,
        &AgentDraftAddAttachmentParams {
            draft_id: draft.draft_id,
            expected_revision: draft.revision,
            transfer_id: handle.transfer_id,
            contribution: contribution(handle, InsertionMethod::TypedSubmission),
        },
        None,
        limit,
    )
}

/// KR-REQ-23.41: a binding that brings a draft whose files the agent took back into the count asks
/// the bound as a create does, so a device cannot pass its bound by binding another file to such a
/// draft. A device holding the bound is refused with the quota code in the bound's words and
/// nothing is written; it ends a draft, and the same binding is served. A binding to a draft that
/// already counts changes no count and is served at the bound, another device's places are not the
/// device's own, and the person at this machine has no bound.
#[test]
fn a_binding_that_brings_a_spent_draft_back_into_the_count_asks_the_bound() {
    let harness = Harness::create();
    let device = harness.actor.clone();
    let other = kr_protocol::ids::ActorId::new("device:other").expect("a principal");
    let open =
        |actor: &kr_protocol::ids::ActorId| harness.service.open_drafts(actor).expect("counts");
    for _ in 0..3 {
        a_sessionless_draft(&harness, &other, Some(3)).expect("a place is free");
    }

    let spent = draft(&harness);
    let (spent, _) = bound_and_offered(
        &harness,
        &spent,
        InsertionMethod::TypedSubmission,
        Offered::Accepted,
        1,
    );
    assert_eq!(
        open(&device),
        0,
        "every file taken: the draft takes no place"
    );
    let counting = (0..3)
        .map(|_| a_sessionless_draft(&harness, &device, Some(3)).expect("a place is free"))
        .collect::<Vec<_>>();
    assert_eq!(open(&device), 3, "the device holds its bound");

    // The control: a draft that already counts is bound to at the bound, and counts as before.
    let first = harness.publish(&pattern(80), "image/png", "first.png");
    bind_with_limit(&harness, &counting[0], &first, Some(3))
        .expect("a binding to a draft that counts changes no count");
    assert_eq!(open(&device), 3);

    // A binding that would make the spent draft count again is refused, and writes nothing.
    let second = harness.publish(&pattern(81), "image/png", "second.png");
    let refused = bind_with_limit(&harness, &spent, &second, Some(3))
        .expect_err("the device holds its bound");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);
    assert!(
        refused.to_string().contains("3 of the 3"),
        "the words name the bound: {refused}"
    );
    assert!(
        refused.to_string().contains("draft.discard"),
        "the words name how a place is freed: {refused}"
    );
    let unchanged = harness
        .service
        .draft(&device, spent.draft_id)
        .expect("reads the draft");
    assert_eq!(unchanged.revision, spent.revision, "nothing was written");
    assert_eq!(unchanged.attachments.len(), 1);
    assert_eq!(open(&device), 3, "the spent draft still takes no place");

    // The device ends a draft; the same binding is served, though the other device holds its bound.
    harness
        .service
        .draft_discard(
            &device,
            &DraftDiscardParams {
                draft_id: counting[1].draft_id,
            },
            None,
        )
        .expect("ends the draft");
    assert_eq!(open(&other), 3, "the other device's places are its own");
    bind_with_limit(&harness, &spent, &second, Some(3)).expect("a place is free");
    assert_eq!(open(&device), 3, "the spent draft counts again");
    a_sessionless_draft(&harness, &device, Some(3)).expect_err("the place is taken");

    // The person at this machine has no bound.
    let owned = draft(&harness);
    let (owned, _) = bound_and_offered(
        &harness,
        &owned,
        InsertionMethod::TypedSubmission,
        Offered::Accepted,
        2,
    );
    let third = harness.publish(&pattern(82), "image/png", "third.png");
    bind_with_limit(&harness, &owned, &third, None).expect("no bound");
    assert_eq!(open(&device), 4);
}

/// KR-REQ-09.07 and KR-REQ-23.41: the same action asked again is answered from its record, though the
/// draft it ended is gone, and does nothing twice; a new action for the gone draft is refused as
/// unknown; the identifier reused for another payload is `ID_CONFLICT`.
#[test]
fn a_draft_ended_by_an_action_is_answered_from_its_record_when_the_action_is_asked_again() {
    let harness = Harness::create();
    let created = draft(&harness);
    let params = DraftDiscardParams {
        draft_id: created.draft_id,
    };
    let id = kr_ipc::new_uuid();
    let action = draft_action(&harness, id, "draft.discard", b"discard");

    let first = harness
        .service
        .draft_discard(&harness.actor, &params, Some(&action))
        .expect("ends the draft");
    let again = harness
        .service
        .draft_discard(&harness.actor, &params, Some(&action))
        .expect("the repeat is answered from the record");
    assert_eq!(again, first);

    let fresh = draft_action(&harness, kr_ipc::new_uuid(), "draft.discard", b"discard");
    let unknown = harness
        .service
        .draft_discard(&harness.actor, &params, Some(&fresh))
        .expect_err("a new action finds no draft");
    assert_eq!(unknown.code(), ErrorCode::InvalidArgument);

    let reused = draft_action(&harness, id, "draft.discard", b"another payload");
    let conflict = harness
        .service
        .draft_discard(&harness.actor, &params, Some(&reused))
        .expect_err("the identifier carried another payload");
    assert_eq!(conflict.code(), ErrorCode::IdConflict);
}

/// KR-REQ-23.41: while this host cannot yet say that no session of an earlier build was sent a draft
/// (its worker may have taken a prompt that names one without the host being told), a draft that
/// targets such a session may be a sent draft and is kept: ending it is refused `DRAFT_CONFLICT` and
/// the draft stands. A draft for another session is ended as ever.
#[test]
fn a_draft_a_session_of_an_earlier_build_may_have_been_sent_is_kept() {
    let harness = Harness::create();
    let noted = draft(&harness);
    let session = noted.session_id.0.expect("a session");
    let other_session = SessionId::new(Uuid::from_bytes([3; 16]));
    let other = harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(other_session),
                application_instance_id: Nullable::null(),
                text: "for another session".to_owned(),
            },
            None,
            None,
        )
        .expect("creates the draft")
        .draft;
    harness
        .service
        .note_unseen_prompt_sessions(&std::collections::BTreeSet::from([session]))
        .expect("notes the session");
    let discard = |draft_id: DraftId| {
        harness
            .service
            .draft_discard(&harness.actor, &DraftDiscardParams { draft_id }, None)
    };

    let refused = discard(noted.draft_id).expect_err("the session may have been sent it");
    assert_eq!(refused.code(), ErrorCode::DraftConflict, "{refused}");
    harness
        .service
        .draft(&harness.actor, noted.draft_id)
        .expect("the draft stands");
    discard(other.draft_id).expect("a draft for another session is ended");
}
