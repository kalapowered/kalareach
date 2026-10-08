//! A worker's offer of an attachment to its agent: what the worker reads of a draft, the claim of
//! one binding, the report of what became of the offer, and what ends an offer that was never
//! reported.
//!
//! Everything here runs against the real journal and the real staging area. The worker and the
//! daemon's wire are not here: the calls are the ones the daemon makes for a worker.

mod support;

use kr_protocol::broker::ActionProvenance;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ApplicationInstanceId, DeviceId, DraftId, SessionId, TransferId};
use kr_protocol::insertion::{InsertionBegin, MAX_INSERTION_REPORT_BYTES, ReportedOutcome};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AttachmentContribution, AttachmentHandle, DraftCreateParams,
    DraftRecord, DraftState, DraftUpdateParams, InsertionMethod, InsertionState,
    UNUSED_ATTACHMENT_LIFETIME,
};
use kr_transfer::service::{Action, Admission, AdmissionHook};
use kr_transfer::{RetainEverything, TransferError};
use support::{BOOT_NOW_MS, Harness, pattern};

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([9; 16]))
}

fn action(number: u8) -> ActionId {
    ActionId::new(Uuid::from_bytes([number; 16]))
}

fn contribution(handle: &AttachmentHandle, method: InsertionMethod) -> AttachmentContribution {
    AttachmentContribution {
        operation_id: "attach".to_owned(),
        accepted_media_types: vec![handle.declared_media_type.clone()],
        max_byte_len: U64::new(1024 * 1024),
        max_count: U64::new(8),
        insertion_method: method,
        external_destination: Nullable::null(),
        model_media_capability: false,
    }
}

fn draft_for(harness: &Harness, session: Option<SessionId>) -> DraftRecord {
    harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([8; 16]))),
                session_id: Nullable(session),
                application_instance_id: Nullable::some(ApplicationInstanceId::new(
                    Uuid::from_bytes([10; 16]),
                )),
                text: "a private draft, never shown to a worker".to_owned(),
            },
            None,
        )
        .expect("creates the draft")
        .draft
}

/// Binds a new typed attachment named `name` to `draft`, and returns the draft and the handle.
fn bind(
    harness: &Harness,
    draft: &DraftRecord,
    name: &str,
    method: InsertionMethod,
) -> (DraftRecord, AttachmentHandle) {
    let handle = harness.publish(&pattern(64 + name.len()), "image/png", name);
    let bound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, method),
            },
            None,
        )
        .expect("binds the attachment");
    (bound.draft, handle)
}

fn read(harness: &Harness, draft_id: DraftId) -> DraftRecord {
    harness
        .service
        .draft(&harness.actor, draft_id)
        .expect("reads the draft")
}

fn state_of(draft: &DraftRecord, transfer_id: TransferId) -> InsertionState {
    draft
        .attachments
        .iter()
        .find(|attachment| attachment.handle.transfer_id == transfer_id)
        .expect("the attachment is bound")
        .state
}

fn accepted(evidence: &str) -> ReportedOutcome {
    ReportedOutcome::AcceptedByAgent {
        provenance: ActionProvenance::UpstreamTypedRpc,
        evidence: evidence.to_owned(),
    }
}

fn failed(detail: &str) -> ReportedOutcome {
    ReportedOutcome::Failed {
        detail: detail.to_owned(),
    }
}

/// KR-REQ-24.09 and KR-REQ-12.30: a worker reads what a draft holds, and not its text or the names
/// of its files, so that what it later puts in a frame is identifiers. A draft that is another
/// actor's, another session's, names no session or was sent by a prompt is not offered from.
#[test]
fn a_worker_reads_the_facts_of_a_draft_and_never_its_text_or_the_names_of_its_files() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (current, handle) = bind(
        &harness,
        &created,
        "a name with spaces and \"quotes\" and ünïcode.png",
        InsertionMethod::TypedSubmission,
    );

    let facts = harness
        .service
        .insertion_facts(&harness.actor, session(), created.draft_id)
        .expect("reads the facts");
    assert_eq!(facts.revision, current.revision);
    assert_eq!(facts.state, DraftState::Open);
    assert_eq!(facts.bindings.len(), 1);
    let binding = &facts.bindings[0];
    assert_eq!(binding.transfer_id, handle.transfer_id);
    assert_eq!(binding.state, InsertionState::Recorded);
    assert_eq!(binding.media_type, "image/png");
    assert_eq!(binding.byte_len, handle.byte_len);
    assert_eq!(binding.content_digest, handle.content_digest);
    let encoded = kr_cbor::to_canonical_vec(&facts).expect("encodes");
    for secret in [
        "a private draft".as_bytes(),
        "ünïcode".as_bytes(),
        "quotes".as_bytes(),
    ] {
        assert!(
            !encoded.windows(secret.len()).any(|window| window == secret),
            "the facts name {:?}",
            String::from_utf8_lossy(secret)
        );
    }

    // The attempt is the binding's order: bound again, it is the next one.
    let (_, second) = bind(
        &harness,
        &current,
        "second.png",
        InsertionMethod::TypedSubmission,
    );
    let facts = harness
        .service
        .insertion_facts(&harness.actor, session(), created.draft_id)
        .expect("reads the facts");
    let attempts: Vec<_> = facts
        .bindings
        .iter()
        .map(|binding| (binding.transfer_id, binding.attempt.get()))
        .collect();
    assert_eq!(
        attempts,
        [(handle.transfer_id, 0), (second.transfer_id, 1)],
        "each binding has the order it was bound in"
    );

    // Another actor's draft and another session's are unknown, one that names no session or was
    // sent by a prompt is a conflict.
    let stranger = kr_protocol::ids::ActorId::new("local:someone-else").expect("valid");
    let other = harness
        .service
        .insertion_facts(&stranger, session(), created.draft_id)
        .expect_err("another actor's draft");
    assert_eq!(other.code(), ErrorCode::InvalidArgument);
    let elsewhere = harness
        .service
        .insertion_facts(
            &harness.actor,
            SessionId::new(Uuid::from_bytes([99; 16])),
            created.draft_id,
        )
        .expect_err("a draft of another session");
    assert_eq!(elsewhere.code(), ErrorCode::InvalidArgument);
    let sessionless = draft_for(&harness, None);
    let none = harness
        .service
        .insertion_facts(&harness.actor, session(), sessionless.draft_id)
        .expect_err("a draft that names no session");
    assert_eq!(none.code(), ErrorCode::DraftConflict);
    harness
        .service
        .record_prompt(
            &harness.actor,
            created.draft_id,
            session(),
            &Admission::none(),
        )
        .expect("sends the draft by a prompt");
    let sent = harness
        .service
        .insertion_facts(&harness.actor, session(), created.draft_id)
        .expect_err("a draft a prompt has sent");
    assert_eq!(sent.code(), ErrorCode::DraftConflict);
}

/// KR-REQ-24.09: a claim turns a recorded binding into one being offered, once, for one owner, and
/// issues the read grant of the one file, which the draft does not show. The draft takes one
/// revision, and the owner's repeat of the claim is the same claim and the same grant.
#[test]
fn a_claim_marks_the_binding_inserting_for_its_owner_and_a_repeat_by_the_owner_is_the_same_claim() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (current, handle) = bind(
        &harness,
        &created,
        "photo.png",
        InsertionMethod::TypedSubmission,
    );
    let owner = action(31);

    let claim = harness
        .claim(session(), created.draft_id, handle.transfer_id, owner)
        .expect("claims the binding");
    assert_eq!(claim.facts.revision.get(), current.revision.get() + 1);
    assert_eq!(claim.facts.bindings[0].state, InsertionState::Inserting);
    assert_eq!(claim.grant.transfer_id, handle.transfer_id);
    assert!(
        harness.service.read_grant(claim.grant.grant_id).is_ok(),
        "the grant stands"
    );
    let shown = read(&harness, created.draft_id);
    assert_eq!(
        state_of(&shown, handle.transfer_id),
        InsertionState::Inserting
    );
    assert!(
        shown.attachments[0].read_grant.as_ref().is_none(),
        "a draft's reply never names the host path of the file being offered"
    );
    assert_eq!(shown.revision, claim.facts.revision);

    // The owner asks again, because its reply was lost: the same claim, and nothing advances.
    let again = harness
        .claim(session(), created.draft_id, handle.transfer_id, owner)
        .expect("a repeat by the owner");
    assert_eq!(again.grant, claim.grant);
    assert_eq!(again.facts.revision, claim.facts.revision);
    assert_eq!(
        read(&harness, created.draft_id).revision,
        claim.facts.revision
    );

    // Another action cannot claim a binding that is being offered.
    let rival = harness.service.insertion_begin(
        &harness.actor,
        session(),
        &InsertionBegin {
            action_id: action(32),
            ..harness.begin_of(session(), created.draft_id, handle.transfer_id, owner)
        },
        &|| BOOT_NOW_MS,
    );
    assert_eq!(
        rival.expect_err("another owner").code(),
        ErrorCode::DraftConflict
    );
}

/// KR-REQ-24.09: a claim is refused unless every condition holds, and a refused claim changes
/// nothing.
#[test]
fn a_claim_is_refused_unless_the_draft_the_binding_the_attempt_the_count_and_the_deadline_hold() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (current, handle) = bind(
        &harness,
        &created,
        "photo.png",
        InsertionMethod::TypedSubmission,
    );
    let good = harness.begin_of(session(), created.draft_id, handle.transfer_id, action(41));
    let refused = |begin: &InsertionBegin, boot: &dyn Fn() -> u64, why: &str| {
        let refusal = harness
            .service
            .insertion_begin(&harness.actor, session(), begin, boot)
            .expect_err(why);
        assert_eq!(
            refusal.code(),
            ErrorCode::DraftConflict,
            "{why}: {refusal:?}"
        );
    };

    refused(
        &InsertionBegin {
            attempt: U64::new(7),
            ..good.clone()
        },
        &|| BOOT_NOW_MS,
        "an attempt the binding is not at",
    );
    refused(
        &InsertionBegin {
            max_count: U64::new(0),
            ..good.clone()
        },
        &|| BOOT_NOW_MS,
        "more attachments than the operation accepts",
    );
    refused(
        &good,
        &|| good.deadline_boot_ms.get(),
        "a deadline that has passed",
    );

    // A binding that is not recorded.
    let (_, second) = bind(
        &harness,
        &current,
        "second.png",
        InsertionMethod::TypedSubmission,
    );
    let owner = action(42);
    harness
        .claim(session(), created.draft_id, second.transfer_id, owner)
        .expect("claims the second binding");
    harness
        .report(
            session(),
            &harness.begin_of(session(), created.draft_id, second.transfer_id, owner),
            failed("refused"),
        )
        .expect("records the failure");
    refused(
        &harness.begin_of(session(), created.draft_id, second.transfer_id, action(43)),
        &|| BOOT_NOW_MS,
        "a binding that failed and has not been bound again",
    );

    // The refusals so far changed nothing about the first draft: its binding is still recorded.
    let unchanged = read(&harness, created.draft_id);
    assert_eq!(
        state_of(&unchanged, handle.transfer_id),
        InsertionState::Recorded
    );

    // A draft that is not open, and a method no worker offers.
    let orphan = draft_for(&harness, Some(session()));
    let (orphan, orphaned) = bind(
        &harness,
        &orphan,
        "orphan.png",
        InsertionMethod::TypedSubmission,
    );
    let by_composer = bind(
        &harness,
        &draft_for(&harness, Some(session())),
        "composer.png",
        InsertionMethod::VerifiedComposerInsertion,
    );
    let refusal = harness
        .service
        .insertion_begin(
            &harness.actor,
            session(),
            &harness.begin_of(
                session(),
                by_composer.0.draft_id,
                by_composer.1.transfer_id,
                action(44),
            ),
            &|| BOOT_NOW_MS,
        )
        .expect_err("a binding a worker does not offer");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    let begin = harness.begin_of(session(), orphan.draft_id, orphaned.transfer_id, action(45));
    harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([session()]))
        .expect("ends the session");
    let late = harness
        .service
        .insertion_begin(&harness.actor, session(), &begin, &|| BOOT_NOW_MS)
        .expect_err("a draft whose session has ended");
    assert_eq!(
        late.code(),
        ErrorCode::DraftConflict,
        "it is orphaned, and an orphaned draft is not open"
    );
}

/// KR-REQ-24.09: the outcome of an offer is recorded for its owner, at the attempt it was claimed
/// for, with evidence for acceptance and none from the terminal; the same report again is answered
/// as it stands and another is refused; and the claim's grant goes with the report.
#[test]
fn an_offer_is_reported_by_its_owner_once_and_its_grant_goes_with_the_report() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (_, handle) = bind(
        &harness,
        &created,
        "photo.png",
        InsertionMethod::TypedSubmission,
    );
    let owner = action(51);
    let claim = harness
        .claim(session(), created.draft_id, handle.transfer_id, owner)
        .expect("claims the binding");
    let begin = harness.begin_of(session(), created.draft_id, handle.transfer_id, owner);

    // Not by another action, and not for another attempt.
    let stranger = harness.service.record_insertion_outcome(
        &harness.actor,
        session(),
        &kr_protocol::insertion::InsertionReport {
            action_id: action(52),
            draft_id: begin.draft_id,
            transfer_id: begin.transfer_id,
            attempt: begin.attempt,
            outcome: accepted("evidence"),
        },
    );
    assert_eq!(
        stranger.expect_err("another action").code(),
        ErrorCode::DraftConflict
    );
    let wrong_attempt = harness.service.record_insertion_outcome(
        &harness.actor,
        session(),
        &kr_protocol::insertion::InsertionReport {
            action_id: owner,
            draft_id: begin.draft_id,
            transfer_id: begin.transfer_id,
            attempt: U64::new(5),
            outcome: accepted("evidence"),
        },
    );
    assert_eq!(
        wrong_attempt.expect_err("another attempt").code(),
        ErrorCode::DraftConflict
    );
    // Acceptance needs evidence, and a write into the terminal is not evidence.
    assert_eq!(
        harness
            .report(session(), &begin, accepted("  "))
            .expect_err("no evidence")
            .code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        harness
            .report(
                session(),
                &begin,
                ReportedOutcome::AcceptedByAgent {
                    provenance: ActionProvenance::TerminalInput,
                    evidence: "typed".to_owned(),
                },
            )
            .expect_err("a write into the terminal")
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        state_of(&read(&harness, created.draft_id), handle.transfer_id),
        InsertionState::Inserting,
        "the refused reports changed nothing"
    );

    // The owner's report, cut to what a draft keeps room for.
    let long = "e".repeat(MAX_INSERTION_REPORT_BYTES * 3);
    assert_eq!(
        harness
            .report(session(), &begin, accepted(&long))
            .expect("records it"),
        InsertionState::AcceptedByAgent
    );
    let recorded = &read(&harness, created.draft_id).attachments[0];
    assert_eq!(
        recorded.upstream_evidence.0.as_deref().map(str::len),
        Some(MAX_INSERTION_REPORT_BYTES)
    );
    assert!(
        harness.service.read_grant(claim.grant.grant_id).is_err(),
        "the grant of an offer that was reported is revoked"
    );

    // The same report again is answered as it stands; any other is refused.
    let revision = read(&harness, created.draft_id).revision;
    assert_eq!(
        harness
            .report(session(), &begin, accepted(&long))
            .expect("a repeat"),
        InsertionState::AcceptedByAgent
    );
    assert_eq!(read(&harness, created.draft_id).revision, revision);
    assert_eq!(
        harness
            .report(session(), &begin, failed("it did not"))
            .expect_err("a report that differs")
            .code(),
        ErrorCode::DraftConflict
    );
    // And an attachment the agent accepted is not bound again over its evidence.
    let rebound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("an accepted attachment");
    assert_eq!(rebound.code(), ErrorCode::DraftConflict);
}

/// KR-REQ-24.09: an offer that may have reached the agent and was not answered is unknown, not
/// failed; it is offered again as a new attempt of the same binding, which the draft shows, and a
/// report for the first attempt no longer settles anything.
#[test]
fn an_unknown_offer_is_offered_again_as_a_new_attempt() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (_, handle) = bind(
        &harness,
        &created,
        "photo.png",
        InsertionMethod::TypedSubmission,
    );
    let first = action(61);
    harness
        .claim(session(), created.draft_id, handle.transfer_id, first)
        .expect("claims the binding");
    let first_begin = harness.begin_of(session(), created.draft_id, handle.transfer_id, first);
    assert_eq!(
        harness
            .report(
                session(),
                &first_begin,
                ReportedOutcome::Unknown {
                    detail: "the upstream did not answer".to_owned(),
                },
            )
            .expect("records it"),
        InsertionState::Unknown
    );
    let shown = read(&harness, created.draft_id);
    assert_eq!(
        state_of(&shown, handle.transfer_id),
        InsertionState::Unknown
    );
    assert_eq!(
        shown.attachments[0].failure_detail.0.as_deref(),
        Some("the upstream did not answer")
    );

    // Nothing offers the attachment again until it is bound again, as a new attempt.
    let refused = harness
        .service
        .insertion_begin(
            &harness.actor,
            session(),
            &InsertionBegin {
                action_id: action(62),
                ..first_begin.clone()
            },
            &|| BOOT_NOW_MS,
        )
        .expect_err("an unknown offer is not claimed again as it stands");
    assert_eq!(refused.code(), ErrorCode::DraftConflict);
    let rebound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: shown.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect("binds it again");
    assert_eq!(rebound.draft.attachments.len(), 1, "one binding");
    assert_eq!(rebound.attachment.state, InsertionState::Recorded);
    let second = action(63);
    let again = harness
        .claim(session(), created.draft_id, handle.transfer_id, second)
        .expect("claims the new attempt");
    assert_eq!(
        again.facts.bindings[0].attempt.get(),
        first_begin.attempt.get() + 1,
        "bound again is a new attempt"
    );
    // The first attempt's owner cannot settle the second.
    assert_eq!(
        harness
            .report(session(), &first_begin, failed("late"))
            .expect_err("the first attempt's report")
            .code(),
        ErrorCode::DraftConflict
    );
}

/// KR-REQ-24.09: a draft is not sent by a prompt while an offer from it is unreported, and a
/// binding being offered is not bound again.
#[test]
fn a_draft_with_an_offer_in_flight_is_neither_sent_nor_rebound() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (_, handle) = bind(
        &harness,
        &created,
        "photo.png",
        InsertionMethod::TypedSubmission,
    );
    let owner = action(71);
    let claim = harness
        .claim(session(), created.draft_id, handle.transfer_id, owner)
        .expect("claims the binding");

    let prompt = harness
        .service
        .record_prompt(
            &harness.actor,
            created.draft_id,
            session(),
            &Admission::none(),
        )
        .expect_err("a draft with an offer in flight");
    assert_eq!(prompt.code(), ErrorCode::DraftConflict);
    let rebound = harness
        .service
        .draft_add_attachment(
            &harness.actor,
            &AgentDraftAddAttachmentParams {
                draft_id: created.draft_id,
                expected_revision: claim.facts.revision,
                transfer_id: handle.transfer_id,
                contribution: contribution(&handle, InsertionMethod::TypedSubmission),
            },
            None,
        )
        .expect_err("a binding being offered");
    assert_eq!(rebound.code(), ErrorCode::DraftConflict);

    harness
        .report(
            session(),
            &harness.begin_of(session(), created.draft_id, handle.transfer_id, owner),
            failed("nothing"),
        )
        .expect("reports the offer");
    harness
        .service
        .record_prompt(
            &harness.actor,
            created.draft_id,
            session(),
            &Admission::none(),
        )
        .expect("the draft is sent once the offer is reported");
}

/// KR-REQ-24.09: the room a draft's reply needs for the longest report of every offer in flight is
/// kept. A draft grown to the most its reply holds with one offer in flight takes no second claim,
/// because that claim's report would not fit; the report of the offer that was claimed always
/// does; and the draft is still readable once that report is recorded.
#[test]
fn the_room_for_the_report_of_every_offer_in_flight_is_kept() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (current, first) = bind(
        &harness,
        &created,
        "first.png",
        InsertionMethod::TypedSubmission,
    );
    let (_, second) = bind(
        &harness,
        &current,
        "second.png",
        InsertionMethod::TypedSubmission,
    );
    let (first_owner, second_owner) = (action(81), action(82));
    harness
        .claim(session(), created.draft_id, first.transfer_id, first_owner)
        .expect("claims the first binding");

    // Grow the text to the most the service takes with that offer in flight: a refused update
    // changes nothing, so the search ends holding the last text that was accepted.
    let mut now = read(&harness, created.draft_id);
    let (mut accepted_len, mut refused_len) = (now.text.len(), 1024 * 1024_usize);
    while refused_len - accepted_len > 1 {
        let middle = accepted_len + (refused_len - accepted_len) / 2;
        match harness.service.draft_update(
            &harness.actor,
            &DraftUpdateParams {
                draft_id: now.draft_id,
                expected_revision: now.revision,
                text: "a".repeat(middle),
            },
            None,
        ) {
            Ok(updated) => {
                now = updated.draft;
                accepted_len = middle;
            }
            Err(error) => {
                assert_eq!(error.code(), ErrorCode::QuotaExceeded, "{error:?}");
                refused_len = middle;
            }
        }
    }
    assert!(
        accepted_len > 1024,
        "the search found a limit near the budget"
    );

    // The second claim would leave two reports to record and room for one.
    let second_begin = harness.begin_of(
        session(),
        created.draft_id,
        second.transfer_id,
        second_owner,
    );
    let refused = harness
        .service
        .insertion_begin(&harness.actor, session(), &second_begin, &|| BOOT_NOW_MS)
        .expect_err("a claim that leaves no room for its report");
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);
    assert_eq!(
        state_of(&read(&harness, created.draft_id), second.transfer_id),
        InsertionState::Recorded,
        "and the refusal changed nothing"
    );

    // The report of the claim that was made fits at its longest, because its room was kept, and
    // the draft is still readable with it.
    harness
        .report(
            session(),
            &harness.begin_of(session(), created.draft_id, first.transfer_id, first_owner),
            accepted(&"e".repeat(MAX_INSERTION_REPORT_BYTES)),
        )
        .expect("the report fits");
    let settled = read(&harness, created.draft_id);
    assert_eq!(
        state_of(&settled, first.transfer_id),
        InsertionState::AcceptedByAgent
    );
}

/// KR-REQ-24.09: a session that ends orphans every draft that targets it, fails an offer that was
/// in flight and revokes its grant, and leaves an offer the agent accepted and one whose outcome was
/// unknown as they were. A draft that was only sent to the session is not orphaned.
#[test]
fn a_session_that_ends_orphans_its_drafts_and_ends_the_offers_in_flight() {
    let harness = Harness::create();
    let ending = session();
    let created = draft_for(&harness, Some(ending));
    let (current, offered) = bind(
        &harness,
        &created,
        "offered.png",
        InsertionMethod::TypedSubmission,
    );
    let (current, taken) = bind(
        &harness,
        &current,
        "taken.png",
        InsertionMethod::TypedSubmission,
    );
    let (_, unknown) = bind(
        &harness,
        &current,
        "unknown.png",
        InsertionMethod::TypedSubmission,
    );
    let offering = harness
        .claim(ending, created.draft_id, offered.transfer_id, action(91))
        .expect("claims the first binding");
    for (handle, owner, outcome) in [
        (&taken, action(92), accepted("the agent's own part")),
        (
            &unknown,
            action(93),
            ReportedOutcome::Unknown {
                detail: "no answer".to_owned(),
            },
        ),
    ] {
        harness
            .claim(ending, created.draft_id, handle.transfer_id, owner)
            .expect("claims the binding");
        harness
            .report(
                session(),
                &harness.begin_of(ending, created.draft_id, handle.transfer_id, owner),
                outcome,
            )
            .expect("reports the offer");
    }
    let before = read(&harness, created.draft_id);
    let bare = draft_for(&harness, Some(ending));

    let failed_count = harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([ending]))
        .expect("ends the session");
    assert_eq!(failed_count, 1, "only the offer in flight");
    assert!(
        harness.service.read_grant(offering.grant.grant_id).is_err(),
        "the grant of the offer in flight is revoked"
    );

    let after = read(&harness, created.draft_id);
    assert_eq!(after.state, DraftState::Orphaned);
    assert_eq!(
        after.revision.get(),
        before.revision.get() + 1,
        "one revision"
    );
    assert_eq!(
        state_of(&after, offered.transfer_id),
        InsertionState::Failed
    );
    assert_eq!(
        state_of(&after, taken.transfer_id),
        InsertionState::AcceptedByAgent
    );
    assert_eq!(
        state_of(&after, unknown.transfer_id),
        InsertionState::Unknown
    );
    let find = |draft: &DraftRecord, handle: &AttachmentHandle| {
        draft
            .attachments
            .iter()
            .find(|attachment| attachment.handle.transfer_id == handle.transfer_id)
            .cloned()
            .expect("bound")
    };
    assert_eq!(
        find(&after, &taken),
        find(&before, &taken),
        "accepted, as it was"
    );
    assert_eq!(
        find(&after, &unknown),
        find(&before, &unknown),
        "unknown, as it was"
    );
    assert_eq!(
        read(&harness, bare.draft_id).state,
        DraftState::Orphaned,
        "a draft with no binding that targets the session is orphaned too"
    );

    // The report of the offer that was in flight arrives after the end: it cannot change what the
    // end decided, and the refusal says the session has ended.
    let report = harness
        .report(
            ending,
            &harness.begin_of(ending, created.draft_id, offered.transfer_id, action(91)),
            accepted("too late"),
        )
        .expect_err("a report for a session that has ended");
    assert_eq!(report.code(), ErrorCode::SessionClosed, "{report:?}");
    assert_eq!(
        state_of(&read(&harness, created.draft_id), offered.transfer_id),
        InsertionState::Failed
    );

    // Nothing is offered from an orphaned draft, and ending the session again changes nothing.
    let late = harness
        .service
        .insertion_facts(&harness.actor, ending, created.draft_id)
        .expect("a worker may still read it");
    assert_eq!(late.state, DraftState::Orphaned);
    assert_eq!(
        harness
            .service
            .end_session_insertions(&std::collections::BTreeSet::from([ending]))
            .expect("ends it again"),
        0
    );
    assert_eq!(
        read(&harness, created.draft_id).revision,
        after.revision,
        "and the draft takes no revision for it"
    );
}

/// KR-REQ-24.09: no claim is made while the journal still holds sessions of an earlier build, which
/// a build that cannot read an `inserting` binding could open; the refusal names the reason and
/// changes nothing, and the claim is made once those sessions have ended.
#[test]
fn no_claim_is_made_while_the_journal_holds_sessions_of_an_earlier_build() {
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (_, handle) = bind(
        &harness,
        &created,
        "photo.png",
        InsertionMethod::TypedSubmission,
    );
    let journal = rusqlite::Connection::open(kr_transfer::StagingArea::store_path(
        &harness.host.environment(),
    ))
    .expect("opens the journal");
    journal
        .execute("UPDATE schema_version SET version = 2", [])
        .expect("leaves the journal at the unsettled version");
    let refused = harness
        .claim(session(), created.draft_id, handle.transfer_id, action(95))
        .expect_err("an unsettled journal");
    assert_eq!(refused.code(), ErrorCode::StorageUnavailable, "{refused:?}");
    assert!(
        refused.to_string().contains("earlier build"),
        "the refusal says why: {refused}"
    );
    assert_eq!(
        state_of(&read(&harness, created.draft_id), handle.transfer_id),
        InsertionState::Recorded
    );
    journal
        .execute(
            "UPDATE schema_version SET version = ?1",
            [kr_transfer::store::SCHEMA_VERSION],
        )
        .expect("settles the journal");
    harness
        .claim(session(), created.draft_id, handle.transfer_id, action(95))
        .expect("the claim is made once the journal is settled");
}

/// The claim a worker of `worker` makes of the one binding a draft holds at its first attempt, built
/// by hand because the draft may be one a worker cannot read the facts of.
fn first_claim(draft: &DraftRecord, handle: &AttachmentHandle, number: u8) -> InsertionBegin {
    InsertionBegin {
        action_id: action(number),
        draft_id: draft.draft_id,
        transfer_id: handle.transfer_id,
        attempt: U64::new(0),
        max_count: U64::new(4),
        deadline_boot_ms: U64::new(BOOT_NOW_MS + 60_000),
    }
}

/// KR-REQ-24.09: the claim itself, and not only the read before it, is refused for a draft that is
/// not the worker's (another session's, one that targets no session, one a prompt sent) and for an
/// attachment whose file is gone, and the draft is as it was.
#[test]
fn a_claim_is_refused_for_a_draft_that_is_not_the_workers_and_for_a_file_that_is_gone() {
    let harness = Harness::create();
    let other = SessionId::new(Uuid::from_bytes([7; 16]));
    let claim = |worker: SessionId, draft: &DraftRecord, handle: &AttachmentHandle, number: u8| {
        harness.service.insertion_begin(
            &harness.actor,
            worker,
            &first_claim(draft, handle, number),
            &|| BOOT_NOW_MS,
        )
    };

    let own = draft_for(&harness, Some(session()));
    let (own, own_handle) = bind(&harness, &own, "own.png", InsertionMethod::TypedSubmission);
    let free = draft_for(&harness, None);
    let (free, free_handle) = bind(
        &harness,
        &free,
        "free.png",
        InsertionMethod::TypedSubmission,
    );
    let sent = draft_for(&harness, None);
    let (sent, sent_handle) = bind(
        &harness,
        &sent,
        "sent.png",
        InsertionMethod::TypedSubmission,
    );
    harness
        .service
        .record_prompt(&harness.actor, sent.draft_id, session(), &Admission::none())
        .expect("a prompt sends the draft to the session");
    let gone = draft_for(&harness, Some(session()));
    let (gone, gone_handle) = bind(
        &harness,
        &gone,
        "gone.png",
        InsertionMethod::TypedSubmission,
    );

    let error = claim(other, &own, &own_handle, 51).expect_err("another session's worker");
    assert!(
        matches!(error, TransferError::UnknownDraft { .. }),
        "{error:?}"
    );
    for (what, draft, handle, number) in [
        ("a draft that targets no session", &free, &free_handle, 52),
        ("a draft a prompt sent", &sent, &sent_handle, 53),
    ] {
        let error = claim(session(), draft, handle, number).expect_err(what);
        assert_eq!(error.code(), ErrorCode::DraftConflict, "{what}: {error:?}");
    }
    for (draft, handle) in [
        (&own, &own_handle),
        (&free, &free_handle),
        (&sent, &sent_handle),
    ] {
        let after = read(&harness, draft.draft_id);
        assert_eq!(
            after.revision, draft.revision,
            "a refused claim moved nothing"
        );
        assert_eq!(
            state_of(&after, handle.transfer_id),
            InsertionState::Recorded
        );
    }

    // The control: the worker of the session claims its own draft.
    claim(session(), &own, &own_handle, 54).expect("the session's own draft");

    // An attachment nothing submitted expires after seven days and leaves its binding `recorded`
    // with no file behind it: the claim would send the receiver to nothing.
    harness
        .clock
        .set(support::START_MS + UNUSED_ATTACHMENT_LIFETIME.get() + 1);
    let sweep = harness
        .service
        .sweep(&RetainEverything)
        .expect("runs a sweep");
    assert!(sweep.expired_attachments >= 1, "{sweep:?}");
    assert_eq!(
        state_of(&read(&harness, gone.draft_id), gone_handle.transfer_id),
        InsertionState::Recorded,
        "the binding is as it was"
    );
    let error = claim(session(), &gone, &gone_handle, 55).expect_err("a file that is gone");
    assert_eq!(error.code(), ErrorCode::DraftConflict, "{error:?}");
}

/// KR-REQ-24.09: only the worker of the session settles an offer, and a report that repeats what was
/// recorded is no exception: another session's worker is told nothing of the draft, and once the
/// session has ended the repeat is refused as the session's end, as every other report is.
#[test]
fn a_report_is_taken_only_from_the_sessions_worker_and_a_repeat_is_no_exception() {
    let harness = Harness::create();
    let other = SessionId::new(Uuid::from_bytes([7; 16]));
    let created = draft_for(&harness, Some(session()));
    let (current, taken) = bind(
        &harness,
        &created,
        "taken.png",
        InsertionMethod::TypedSubmission,
    );
    let (_, pending) = bind(
        &harness,
        &current,
        "pending.png",
        InsertionMethod::TypedSubmission,
    );
    let owner = action(71);
    let pending_owner = action(72);
    harness
        .claim(session(), created.draft_id, taken.transfer_id, owner)
        .expect("claims the first binding");
    harness
        .claim(
            session(),
            created.draft_id,
            pending.transfer_id,
            pending_owner,
        )
        .expect("claims the second binding");
    let taken_begin = harness.begin_of(session(), created.draft_id, taken.transfer_id, owner);
    let pending_begin = harness.begin_of(
        session(),
        created.draft_id,
        pending.transfer_id,
        pending_owner,
    );
    harness
        .report(session(), &taken_begin, accepted("the agent's own part"))
        .expect("the worker reports the first offer");

    // A report that settles nothing yet, from the worker of another session.
    let error = harness
        .report(other, &pending_begin, failed("not mine to say"))
        .expect_err("another session's worker");
    assert!(
        matches!(error, TransferError::UnknownDraft { .. }),
        "{error:?}"
    );
    assert_eq!(
        state_of(&read(&harness, created.draft_id), pending.transfer_id),
        InsertionState::Inserting
    );

    // The repeat of what was recorded: answered for the session's worker, and not for another's.
    let repeated = harness
        .report(session(), &taken_begin, accepted("the agent's own part"))
        .expect("the same report again");
    assert_eq!(repeated, InsertionState::AcceptedByAgent);
    let error = harness
        .report(other, &taken_begin, accepted("the agent's own part"))
        .expect_err("another session's worker repeating it");
    assert!(
        matches!(error, TransferError::UnknownDraft { .. }),
        "{error:?}"
    );

    // And once the session has ended, the repeat is refused like any report.
    harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([session()]))
        .expect("ends the session");
    let error = harness
        .report(session(), &taken_begin, accepted("the agent's own part"))
        .expect_err("the session has ended");
    assert_eq!(error.code(), ErrorCode::SessionClosed, "{error:?}");
}

/// KR-REQ-24.09: a session that ends fails the offers of a draft that was only sent to it, and does
/// not orphan that draft, because it never targeted the session; a draft that targets it is.
#[test]
fn a_draft_only_sent_to_a_session_that_ends_has_its_offer_failed_and_stays_open() {
    let harness = Harness::create();
    let sent = draft_for(&harness, None);
    let (sent, handle) = bind(
        &harness,
        &sent,
        "sent.png",
        InsertionMethod::TypedSubmission,
    );
    harness
        .service
        .record_prompt(&harness.actor, sent.draft_id, session(), &Admission::none())
        .expect("a prompt sends the draft to the session");
    let targeting = draft_for(&harness, Some(session()));
    let before = read(&harness, sent.draft_id);

    harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([session()]))
        .expect("ends the session");

    let after = read(&harness, sent.draft_id);
    assert_eq!(state_of(&after, handle.transfer_id), InsertionState::Failed);
    assert_eq!(
        after.state,
        DraftState::Open,
        "it never targeted the session"
    );
    assert_eq!(
        after.revision.get(),
        before.revision.get() + 1,
        "one revision"
    );
    assert_eq!(
        read(&harness, targeting.draft_id).state,
        DraftState::Orphaned,
        "the control: a draft that targets it is orphaned"
    );
}

/// KR-REQ-24.09: a draft is not made for a session that has already ended, which nothing could be
/// offered from and which the next pass over the ended sessions would orphan.
#[test]
fn a_draft_is_not_made_for_a_session_that_has_ended() {
    let harness = Harness::create();
    harness
        .service
        .end_session_insertions(&std::collections::BTreeSet::from([session()]))
        .expect("ends the session");
    let error = harness
        .service
        .draft_create(
            &harness.actor,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session()),
                application_instance_id: Nullable::null(),
                text: "for a session that is gone".to_owned(),
            },
            None,
        )
        .expect_err("a session that has ended");
    assert_eq!(error.code(), ErrorCode::SessionClosed, "{error:?}");
}

/// An admission that holds the store: it says it has arrived inside the service's lock and waits
/// there until the test lets it go.
struct HoldsTheStore {
    arrived: std::sync::mpsc::SyncSender<()>,
    go: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl AdmissionHook for HoldsTheStore {
    fn ask(&self) -> Result<(), kr_protocol::error::ProtocolError> {
        Ok(())
    }

    fn run(&self, commit: &mut dyn FnMut()) -> Result<(), kr_protocol::error::ProtocolError> {
        let _ = self.arrived.send(());
        let _ = self
            .go
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv();
        commit();
        Ok(())
    }
}

/// KR-REQ-24.09: a claim that waited for the store is judged by the time it commits at, not by the
/// time it was asked at. The worker gives up on a claim at its deadline and reports the offer failed
/// a moment after; a claim that read the clock before it waited for the store, and committed after
/// the deadline, would meet that report first (a binding no claim has been made for) and then leave
/// the binding `inserting` for good. Here another write holds the store while the clock passes the
/// claim's deadline, and the claim, which asked before the deadline, is refused when it gets the
/// store.
#[test]
fn a_claim_that_waits_for_the_store_past_its_deadline_is_refused() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let harness = Harness::create();
    let created = draft_for(&harness, Some(session()));
    let (created, handle) = bind(
        &harness,
        &created,
        "late.png",
        InsertionMethod::TypedSubmission,
    );
    let holder = draft_for(&harness, None);
    let mut begin = harness.begin_of(session(), created.draft_id, handle.transfer_id, action(61));
    begin.deadline_boot_ms = U64::new(BOOT_NOW_MS + 10);

    let (arrived, held) = std::sync::mpsc::sync_channel(1);
    let (release, go) = std::sync::mpsc::sync_channel(1);
    let hook = std::sync::Arc::new(HoldsTheStore {
        arrived,
        go: std::sync::Mutex::new(go),
    });
    let holding = Action {
        actor_id: harness.actor.clone(),
        action_id: kr_ipc::new_uuid(),
        method: "draft.update".to_owned(),
        payload_digest: support::digest(b"holds the store"),
        admission: Admission::new(hook as std::sync::Arc<dyn AdmissionHook>),
    };
    // The boot clock, which the claim reads where it decides, and says when it has.
    let boot = AtomicU64::new(BOOT_NOW_MS);
    let (asked, reading) = std::sync::mpsc::channel::<()>();
    let clock = || {
        let _ = asked.send(());
        boot.load(Ordering::SeqCst)
    };

    let claimed = std::thread::scope(|scope| {
        let update = scope.spawn(|| {
            harness.service.draft_update(
                &harness.actor,
                &DraftUpdateParams {
                    draft_id: holder.draft_id,
                    expected_revision: holder.revision,
                    text: "holds the store".to_owned(),
                },
                Some(&holding),
            )
        });
        held.recv().expect("the update holds the store");
        let claim = scope.spawn(|| {
            harness
                .service
                .insertion_begin(&harness.actor, session(), &begin, &clock)
        });
        // A claim that reads its clock before it waits for the store does so now, with the clock
        // before its deadline; one that reads it with the store in hand cannot until the store is
        // let go. The wait only gives the first the chance to show itself: what decides the case
        // is the answer below, whichever way this ends.
        let _ = reading.recv_timeout(std::time::Duration::from_millis(300));
        boot.store(BOOT_NOW_MS + 11, Ordering::SeqCst);
        release.send(()).expect("lets the store go");
        update
            .join()
            .expect("the update ends")
            .expect("the update is committed");
        claim.join().expect("the claim ends")
    });

    let error = claimed.expect_err("the claim's deadline passed while it waited for the store");
    assert_eq!(error.code(), ErrorCode::DraftConflict, "{error:?}");
    assert_eq!(
        state_of(&read(&harness, created.draft_id), handle.transfer_id),
        InsertionState::Recorded,
        "nothing was claimed"
    );
}
