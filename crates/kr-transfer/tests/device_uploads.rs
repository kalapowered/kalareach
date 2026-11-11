//! What a paired device is shown and held to when it reserves an upload: the bytes its own principal
//! has staged, the environment's limit and no one else's total, and a bound on the uploads it keeps
//! staged.

mod support;

use std::collections::BTreeSet;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActorId, SessionId, TransferId};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AttachmentContribution, DraftCreateParams, InsertionMethod,
    UNUSED_ATTACHMENT_LIFETIME, UploadBeginParams, UploadBeginResult, UploadCancelParams,
    UploadFinishParams, UploadState,
};
use kr_transfer::service::{Admission, DeviceView};
use kr_transfer::store::Limits;
use kr_transfer::{Result, SessionRetention};
use support::{Harness, START_MS, digest};

/// What a device of these cases is held to.
const fn bound(staged_upload_limit: u64) -> Option<DeviceView> {
    Some(DeviceView {
        staged_upload_limit,
    })
}

fn begin_params(harness: &Harness, bytes: &[u8], name: &str) -> UploadBeginParams {
    UploadBeginParams {
        environment_id: harness.environment_id(),
        session_id: Nullable::null(),
        device_id: Nullable::null(),
        declared_byte_len: U64::new(bytes.len() as u64),
        declared_digest: digest(bytes),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: name.to_owned(),
    }
}

/// Reserves an upload of `bytes` as `actor`, shown what `device` is shown.
fn begin_as(
    harness: &Harness,
    actor: &ActorId,
    bytes: &[u8],
    device: Option<DeviceView>,
) -> Result<UploadBeginResult> {
    harness.service.upload_begin(
        actor,
        &begin_params(harness, bytes, "kept.bin"),
        None,
        device,
    )
}

/// Reserves and publishes a file of no bytes, which reserves none of the environment's.
fn publish_empty_as(harness: &Harness, actor: &ActorId, device: Option<DeviceView>) -> TransferId {
    let transfer_id = begin_as(harness, actor, &[], device)
        .expect("reserves the upload")
        .transfer_id;
    harness
        .service
        .upload_finish(
            actor,
            &UploadFinishParams {
                transfer_id,
                declared_byte_len: U64::ZERO,
                declared_digest: digest(&[]),
            },
            None,
        )
        .expect("publishes the file");
    transfer_id
}

/// A host that holds every session it is asked about, with a clock it can prove.
struct Retains;

impl SessionRetention for Retains {
    fn retained(&self, sessions: &BTreeSet<SessionId>) -> Result<BTreeSet<SessionId>> {
        Ok(sessions.clone())
    }

    fn clock_is_proven(&self, _reading: kr_protocol::scalars::TimestampMs) -> bool {
        true
    }
}

fn another() -> ActorId {
    ActorId::new("device:another").expect("a valid principal")
}

/// KR-REQ-23.21: a device that reserves an upload is shown the bytes its own principal has staged,
/// this reservation included, and the environment's limit; the person at this machine is shown the
/// environment's total, as the member is documented for any caller but a device.
#[test]
fn a_device_is_shown_the_bytes_its_own_principal_has_staged() {
    let harness = Harness::create();
    let owner = harness.actor.clone();
    let device = another();
    begin_as(&harness, &owner, &[1; 3_000], None).expect("the owner stages 3,000 bytes");

    let own = begin_as(&harness, &device, &[2; 100], bound(8)).expect("the device begins");
    assert_eq!(own.staged_byte_len.get(), 100, "the device's own bytes");
    assert_eq!(
        own.staged_byte_limit.get(),
        harness.service.limits().expect("limits").max_staged_len,
        "the environment's limit"
    );

    let owners = begin_as(&harness, &owner, &[3; 50], None).expect("the owner begins");
    assert_eq!(
        owners.staged_byte_len.get(),
        3_000 + 100 + 50,
        "the owner sees the environment's total"
    );
}

/// KR-REQ-23.21: the refusal a device is given for the environment's bytes names the environment's
/// limit and no other principal's total. The control is the person at this machine, who is told how
/// much is staged.
#[test]
fn a_quota_refusal_to_a_device_names_the_environments_limit_and_no_ones_total() {
    let harness = Harness::create();
    let owner = harness.actor.clone();
    harness.set_limits(Limits {
        max_staged_len: 10_000,
        ..Limits::default()
    });
    begin_as(&harness, &owner, &[1; 6_321], None).expect("the owner stages 6,321 bytes");

    let refusal = begin_as(&harness, &another(), &[2; 5_000], bound(8))
        .expect_err("the environment has no room");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    let words = refusal.to_string();
    assert!(
        words.contains("10000"),
        "the refusal names the environment's limit: {words}"
    );
    assert!(
        !words.contains("6321"),
        "the refusal names no other principal's total: {words}"
    );

    let told = begin_as(&harness, &owner, &[3; 5_000], None)
        .expect_err("the environment has no room for the owner either")
        .to_string();
    assert!(
        told.contains("6321"),
        "the person at this machine is told what is staged: {told}"
    );
}

/// KR-REQ-23.21: a device keeps at most the bound of staged uploads, counted for its own principal:
/// one that is receiving, being published or published and not yet sent to a session. The next
/// reservation is refused with the quota code, in words that name the bound and how a place is
/// freed. A cancel of an upload that is still receiving frees a place, and so does an unused file
/// that expires; another device is held to its own count, and the person at this machine to none.
#[test]
fn a_device_keeps_at_most_the_bound_of_staged_uploads_and_a_cancel_or_an_expiry_frees_a_place() {
    let harness = Harness::create();
    let device = harness.actor.clone();
    let published = [
        publish_empty_as(&harness, &device, bound(3)),
        publish_empty_as(&harness, &device, bound(3)),
    ];
    let receiving = begin_as(&harness, &device, &[4; 64], bound(3))
        .expect("the third place is free")
        .transfer_id;

    let refusal = begin_as(&harness, &device, &[5; 64], bound(3))
        .expect_err("the device keeps as many uploads as it may");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    let words = refusal.to_string();
    assert!(
        words.contains("3 of the 3"),
        "the refusal names the bound: {words}"
    );
    assert!(
        words.contains("cancel an upload that is still receiving")
            && !words.contains("session to end"),
        "the refusal says how a place is freed: {words}"
    );

    // Another device is held to its own count, and the person at this machine to none.
    begin_as(&harness, &another(), &[6; 64], bound(3))
        .expect("another device has places of its own");
    let owner = ActorId::new("local:owner").expect("a valid principal");
    for _ in 0..4 {
        publish_empty_as(&harness, &owner, None);
    }

    // A cancel of an upload that is still receiving frees a place.
    let at_the_bound = Harness::create();
    let holder = at_the_bound.actor.clone();
    publish_empty_as(&at_the_bound, &holder, bound(2));
    let open = begin_as(&at_the_bound, &holder, &[7; 64], bound(2))
        .expect("the second place")
        .transfer_id;
    begin_as(&at_the_bound, &holder, &[8; 64], bound(2)).expect_err("at the bound");
    at_the_bound
        .service
        .upload_cancel(&holder, &UploadCancelParams { transfer_id: open }, None)
        .expect("cancels the upload that is still receiving");
    begin_as(&at_the_bound, &holder, &[9; 64], bound(2)).expect("the cancel freed a place");

    // An unused file expires after its window, which frees its place.
    harness
        .service
        .upload_cancel(
            &device,
            &UploadCancelParams {
                transfer_id: receiving,
            },
            None,
        )
        .expect("cancels the upload that is still receiving");
    publish_empty_as(&harness, &device, bound(3));
    begin_as(&harness, &device, &[5; 64], bound(3)).expect_err("the cancel's place is taken");
    harness
        .clock
        .set(START_MS + UNUSED_ATTACHMENT_LIFETIME.get() + 1);
    harness.service.sweep(&Retains).expect("runs a sweep");
    for transfer_id in published {
        let status = harness
            .service
            .upload_status(
                &device,
                &kr_protocol::transfer::UploadStatusParams { transfer_id },
            )
            .expect("the upload's status");
        assert_eq!(status.state, UploadState::Expired);
    }
    begin_as(&harness, &device, &[5; 64], bound(3)).expect("an expired file freed its place");
}

fn contribution() -> AttachmentContribution {
    AttachmentContribution {
        operation_id: "attach".to_owned(),
        accepted_media_types: vec!["application/octet-stream".to_owned()],
        max_byte_len: U64::new(1024 * 1024),
        max_count: U64::new(4),
        insertion_method: InsertionMethod::TypedSubmission,
        external_destination: Nullable::null(),
        model_media_capability: false,
    }
}

/// KR-REQ-23.21: an attachment a prompt has sent to a session follows that session's retention, which
/// can be long and which a device cannot end, so it stops counting against the bound when it is
/// submitted. A device at its bound that sends a draft's files with a prompt is served its next
/// reservation. An attachment taken by an agent through a manual path, with no prompt that names
/// its draft, is not submitted: it lives by the seven-day window and counts like any unsent file.
#[test]
fn an_attachment_a_prompt_has_sent_to_a_session_stops_counting() {
    let harness = Harness::create();
    let device = harness.actor.clone();
    let session_id = SessionId::new(Uuid::from_bytes([21; 16]));
    let first = publish_empty_as(&harness, &device, bound(2));
    let second = publish_empty_as(&harness, &device, bound(2));
    begin_as(&harness, &device, &[1; 64], bound(2)).expect_err("the device is at its bound");

    let draft = harness
        .service
        .draft_create(
            &device,
            &DraftCreateParams {
                environment_id: harness.environment_id(),
                device_id: Nullable::null(),
                session_id: Nullable::some(session_id),
                application_instance_id: Nullable::null(),
                text: "look at these".to_owned(),
            },
            None,
            None,
        )
        .expect("creates the draft")
        .draft;
    let mut revision = draft.revision;
    for transfer_id in [first, second] {
        let handle = harness
            .service
            .attachment_handle(&device, transfer_id)
            .expect("the handle");
        revision = harness
            .service
            .draft_add_attachment(
                &device,
                &AgentDraftAddAttachmentParams {
                    draft_id: draft.draft_id,
                    expected_revision: revision,
                    transfer_id: handle.transfer_id,
                    contribution: contribution(),
                },
                None,
            )
            .expect("binds the attachment")
            .draft
            .revision;
    }
    begin_as(&harness, &device, &[1; 64], bound(2)).expect_err("bound to a draft is not sent");

    harness
        .service
        .record_prompt(
            &device,
            draft.draft_id,
            session_id,
            support::an_application(),
            &Admission::none(),
        )
        .expect("records the submission");
    begin_as(&harness, &device, &[1; 64], bound(2))
        .expect("what a prompt sent follows its session and no longer counts");
}
