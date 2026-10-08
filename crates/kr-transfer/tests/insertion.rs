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
};
use kr_transfer::service::Admission;
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
        BOOT_NOW_MS,
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
    let refused = |begin: &InsertionBegin, boot: u64, why: &str| {
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
        BOOT_NOW_MS,
        "an attempt the binding is not at",
    );
    refused(
        &InsertionBegin {
            max_count: U64::new(0),
            ..good.clone()
        },
        BOOT_NOW_MS,
        "more attachments than the operation accepts",
    );
    refused(
        &good,
        good.deadline_boot_ms.get(),
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
        BOOT_NOW_MS,
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
            BOOT_NOW_MS,
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
        .insertion_begin(&harness.actor, session(), &begin, BOOT_NOW_MS)
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
            BOOT_NOW_MS,
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
        .insertion_begin(&harness.actor, session(), &second_begin, BOOT_NOW_MS)
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
