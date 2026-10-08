//! A package's component offers an attachment from a draft to its agent, and what the agent says is
//! what the draft records.
//!
//! The same world as the plugin-action suite: a real daemon, this test process as the worker it
//! started, a real plugin host with a real component, and a scripted upstream behind the production
//! transport. The drafts and the uploads are made through the daemon's own transfer service, and
//! the worker reads and claims them over the daemon's rendezvous endpoint, as it does in the
//! product. Nothing else is played.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-23.30 | an action that offers an attachment names a draft the daemon holds, is validated against it, and transmits nothing when the draft moved, the action was cancelled or the plan was not the invocation's own |
//! | KR-REQ-24.09 | what the agent answered is recorded on the binding: accepted with the upstream's evidence, failed when it refused, unknown when it did not answer, and a claim the worker could not make is settled by a report |

#![cfg(unix)]

use std::sync::Arc;

use kr_protocol::envelope::Outcome;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, DraftId, RequestId};
use kr_protocol::method::Method;
use kr_protocol::receipt::{ActionCancelParams, ReceiptState};
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::transfer::{AttachmentHandle, DraftRecord, InsertionState};

mod plugin_world;

use plugin_world::acting::{
    Acting, Upstream, answer, read_receipt, send, signal, supersede, until_receipt, until_settled,
};
use plugin_world::until;

/// The state of one binding of a draft.
fn state_of(draft: &DraftRecord, handle: &AttachmentHandle) -> InsertionState {
    draft
        .attachments
        .iter()
        .find(|attachment| attachment.handle.transfer_id == handle.transfer_id)
        .expect("the attachment is bound")
        .state
}

/// Waits until the daemon holds the binding in `state`, which a report makes true after the
/// action's answer.
async fn until_binding(
    acting: &Acting,
    draft_id: DraftId,
    handle: &AttachmentHandle,
    state: InsertionState,
) -> DraftRecord {
    until(&format!("the binding to be {state:?}"), || async {
        let draft = acting.draft(draft_id);
        (state_of(&draft, handle) == state).then_some(draft)
    })
    .await
}

/// A world with a draft that holds one published image, and the image.
async fn offering() -> Option<(Acting, DraftRecord, AttachmentHandle)> {
    let acting = Acting::start().await?;
    let handle = acting.publish(
        &[7; 64],
        "a name with spaces and \"quotes\" and ünïcode.png",
    );
    let draft = acting.bind(&acting.new_draft(), &handle);
    Some((acting, draft, handle))
}

/// KR-REQ-23.30 and KR-REQ-24.09: the plan a component prepares for an attachment is validated and
/// transmitted once with the draft it was claimed against, the upstream's answer is the receipt's,
/// and the binding is `accepted_by_agent` with the evidence the upstream gave, the draft having
/// moved by the claim and by the report and the upload not at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_component_offers_an_attachment_and_the_agent_taking_it_is_recorded() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");

    let frames = acting.frames();
    assert_eq!(frames.len(), 1, "the upstream was written once: {frames:?}");
    let frame: serde_json::Value = serde_json::from_str(&frames[0]).expect("a JSON frame");
    assert_eq!(frame["method"], "attach.photo");
    assert_eq!(frame["params"]["operation"], "upstream_attachment");
    assert_eq!(frame["params"]["draft_id"], draft.draft_id.to_string());
    assert_eq!(
        frame["params"]["draft_revision"],
        draft.revision.get() + 1,
        "the draft as the claim left it, which is what the worker acted on"
    );
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Applied
    );

    let accepted = until_binding(
        &acting,
        draft.draft_id,
        &handle,
        InsertionState::AcceptedByAgent,
    )
    .await;
    assert!(
        accepted.attachments[0]
            .upstream_evidence
            .0
            .as_deref()
            .is_some_and(|evidence| evidence.contains("upstream request")),
        "{:?}",
        accepted.attachments[0]
    );
    assert_eq!(
        accepted.revision.get(),
        draft.revision.get() + 2,
        "one revision for the claim and one for the report"
    );
    assert_eq!(
        accepted.attachments[0].handle, handle,
        "the upload is what it was"
    );
    until("the report to be recorded", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 0).then_some(())
    })
    .await;
}

/// KR-REQ-23.30: a draft the daemon does not hold, and an attachment the draft does not hold, are
/// refused with a receipt that says nothing was dispatched, before any binding is claimed, and the
/// draft is as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_draft_the_store_does_not_hold_is_refused_before_anything_is_claimed() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let other = acting.publish(&[9; 64], "not-bound.png");
    let mut client = acting.client().await;

    for (what, draft_id, attachment) in [
        (
            "a draft nobody made",
            DraftId::new(Uuid::from_bytes([0x5a; 16])),
            handle.transfer_id,
        ),
        (
            "an attachment the draft does not hold",
            draft.draft_id,
            other.transfer_id,
        ),
    ] {
        let mut mutation = acting.offering(&client, "attach.photo", draft_id, attachment);
        mutation.request_id = RequestId::new(20);
        let action_id = mutation.action_id;
        let Outcome::Error(refusal) = send(&mut client, mutation).await else {
            panic!("{what}: the action was carried");
        };
        assert!(
            matches!(
                refusal.code,
                ErrorCode::InvalidArgument | ErrorCode::DraftConflict
            ),
            "{what}: {refusal:?}"
        );
        assert_eq!(
            read_receipt(&mut client, action_id)
                .await
                .expect("a receipt")
                .state,
            ReceiptState::Rejected,
            "{what}"
        );
    }
    assert!(
        acting.frames().is_empty(),
        "nothing was written: {:?}",
        acting.frames()
    );
    let after = acting.draft(draft.draft_id);
    assert_eq!(after.revision, draft.revision, "the draft did not move");
    assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
}

/// KR-REQ-23.30: a claim at an attempt the binding has moved past transmits nothing. The draft is
/// read, the component is asked, and the attachment is bound again meanwhile: the claim names the
/// attempt that was read, the daemon refuses it, the action is rejected and the new attempt is as
/// it was left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_claim_at_a_moved_attempt_transmits_nothing() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mutation = acting.offering(&asking, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    asking
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
            mutation,
        )))
        .await
        .expect("writes the mutation");
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;

    // The same attachment, bound again while the component is asked: a new attempt.
    let moved = acting.bind(&acting.draft(draft.draft_id), &handle);
    signal(&host, rustix::process::Signal::CONT);
    let finished = answer(&mut asking, Some(1)).await;
    assert!(
        matches!(finished, Outcome::Error(_)),
        "the action is refused: {finished:?}"
    );
    let receipt = until_settled(&mut watcher, action_id).await;
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert!(
        acting.frames().is_empty(),
        "nothing was written: {:?}",
        acting.frames()
    );
    let after = acting.draft(draft.draft_id);
    assert_eq!(after.revision, moved.revision, "no claim moved the draft");
    assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
}

/// KR-REQ-23.30: an action cancelled while its component prepares it claims nothing: the receipt is
/// read again immediately before the claim, so a binding is never marked for an action that no
/// longer exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_action_cancelled_while_prepared_claims_nothing() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mutation = acting.offering(&asking, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    asking
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
            mutation,
        )))
        .await
        .expect("writes the mutation");
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;

    let mut cancel = acting.invocation(&watcher, "turn.cancel", b"{}");
    cancel.method = Method::ActionCancel.into();
    cancel.action_id = ActionId::new(kr_ipc::new_uuid());
    cancel.target = kr_protocol::envelope::ActionTarget {
        environment_id: acting.hosted.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    cancel.params =
        kr_protocol::envelope::ParamsValue::from_typed(&ActionCancelParams { action_id })
            .expect("encodes");
    assert!(matches!(send(&mut watcher, cancel).await, Outcome::Ok(_)));
    signal(&host, rustix::process::Signal::CONT);
    answer(&mut asking, Some(1)).await;

    assert!(acting.frames().is_empty());
    let after = acting.draft(draft.draft_id);
    assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
    assert_eq!(after.revision, draft.revision, "nothing was claimed");
}

/// KR-REQ-23.30: a plan that offers another attachment than the one the invocation names is
/// refused by name before the draft is claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_plan_that_offers_another_attachment_claims_nothing() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let mutation = acting.offering(&client, "attach.other", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let Outcome::Error(refusal) = send(&mut client, mutation).await else {
        panic!("a plan for another attachment was carried");
    };
    assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{refusal:?}");
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Rejected
    );
    assert!(acting.frames().is_empty());
    let after = acting.draft(draft.draft_id);
    assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
    assert_eq!(after.revision, draft.revision);
}

/// KR-REQ-24.09 and KR-REQ-12.30: an upstream that refuses leaves the binding `failed` with the
/// reason, one that does not answer leaves it `unknown`, and in both the draft and the completed
/// upload are kept; the same upload is then offered again as a new attempt and is accepted, and no
/// text-only prompt was written to the upstream at any point.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_a_refusing_or_silent_agent_leaves_the_draft_and_the_upload_for_a_retry() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;

    // The upstream refuses.
    *acting.upstream.lock().expect("not poisoned") = Upstream::Refuses;
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let Outcome::Error(refusal) = send(&mut client, mutation).await else {
        panic!("a refused offer was carried");
    };
    assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{refusal:?}");
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Refused
    );
    let failed = until_binding(&acting, draft.draft_id, &handle, InsertionState::Failed).await;
    assert!(
        failed.attachments[0].failure_detail.is_present(),
        "{:?}",
        failed.attachments[0]
    );
    assert_eq!(failed.attachments[0].handle, handle, "the upload is kept");
    assert_eq!(failed.text, draft.text, "and so is the draft's text");

    // Bound again, a new attempt, and the upstream does not answer.
    let again = acting.bind(&failed, &handle);
    assert_eq!(state_of(&again, &handle), InsertionState::Recorded);
    *acting.upstream.lock().expect("not poisoned") = Upstream::Silent;
    let mut mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    mutation.request_id = RequestId::new(2);
    let silent = mutation.action_id;
    let Outcome::Error(_) = send(&mut client, mutation).await else {
        panic!("an offer nothing answered was carried");
    };
    let uncertain = read_receipt(&mut client, silent).await.expect("a receipt");
    assert_eq!(uncertain.state, ReceiptState::Unknown);
    let unknown = until_binding(&acting, draft.draft_id, &handle, InsertionState::Unknown).await;
    assert_eq!(unknown.attachments[0].handle, handle);

    // The binding is bound again, and offered again, but an action on a subject with an uncertain
    // outcome has to name it: without that it is refused before the draft is claimed.
    let again = acting.bind(&unknown, &handle);
    assert_eq!(state_of(&again, &handle), InsertionState::Recorded);
    *acting.upstream.lock().expect("not poisoned") = Upstream::Answers;
    let mut unnamed = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    unnamed.request_id = RequestId::new(3);
    let Outcome::Error(refusal) = send(&mut client, unnamed).await else {
        panic!("a retry that does not name the uncertain outcome was carried");
    };
    assert_eq!(refusal.code, ErrorCode::DraftConflict, "{refusal:?}");
    assert_eq!(
        acting.draft(draft.draft_id).revision,
        again.revision,
        "and nothing was claimed"
    );

    let mut named = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    named.request_id = RequestId::new(4);
    supersede(&mut named, &uncertain);
    let outcome = send(&mut client, named).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    until_binding(
        &acting,
        draft.draft_id,
        &handle,
        InsertionState::AcceptedByAgent,
    )
    .await;

    // Three attempts were written, each an attachment, and nothing was a prompt.
    let frames = acting.frames();
    assert_eq!(frames.len(), 3, "{frames:?}");
    for frame in frames {
        let frame: serde_json::Value = serde_json::from_str(&frame).expect("a JSON frame");
        assert_eq!(frame["params"]["operation"], "upstream_attachment");
    }
}

/// KR-REQ-12.30: several images of one draft are offered together, each claimed for its own action,
/// and each ends `accepted_by_agent` with its own evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_12_30_two_images_offered_together_are_both_accepted() {
    let Some((acting, draft, first)) = offering().await else {
        return;
    };
    let second = acting.publish(&[11; 64], "second image.png");
    let draft = acting.bind(&draft, &second);
    let mut client = acting.client().await;
    for (id, handle) in [(10, &first), (11, &second)] {
        let mut mutation =
            acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
        mutation.request_id = RequestId::new(id);
        client
            .writer()
            .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
                mutation,
            )))
            .await
            .expect("writes the mutation");
    }
    // The two answers come in whichever order the actions finish.
    let mut answered = Vec::new();
    while answered.len() < 2 {
        if let kr_protocol::envelope::ControlFrame::Response(response) =
            client.recv().await.expect("the worker answers")
        {
            assert!(
                matches!(response.outcome, Outcome::Ok(_)),
                "{:?}",
                response.outcome
            );
            answered.push(response.request_id.get());
        }
    }
    answered.sort_unstable();
    assert_eq!(answered, [10, 11]);
    until_binding(
        &acting,
        draft.draft_id,
        &first,
        InsertionState::AcceptedByAgent,
    )
    .await;
    let both = until_binding(
        &acting,
        draft.draft_id,
        &second,
        InsertionState::AcceptedByAgent,
    )
    .await;
    assert_eq!(acting.frames().len(), 2);
    assert_eq!(
        both.revision.get(),
        draft.revision.get() + 4,
        "a claim and a report for each"
    );
}

/// KR-REQ-24.09: a worker with no place left for the report of another offer refuses the action
/// before it claims anything, and the same action is accepted once places are free.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_an_action_is_refused_before_its_claim_when_no_place_is_left_for_its_report() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let drafts = acting.hosted._service.broker().drafts();
    let mut held = Vec::new();
    while let Some(slot) = drafts.reserve() {
        held.push(slot);
    }
    let mut client = acting.client().await;
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let Outcome::Error(refusal) = send(&mut client, mutation).await else {
        panic!("an offer with no place for its report was carried");
    };
    assert_eq!(refusal.code, ErrorCode::ResourceUnavailable, "{refusal:?}");
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Rejected
    );
    assert_eq!(
        acting.draft(draft.draft_id).revision,
        draft.revision,
        "nothing was claimed"
    );

    drop(held);
    let mut mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    mutation.request_id = RequestId::new(2);
    assert!(matches!(send(&mut client, mutation).await, Outcome::Ok(_)));
}

/// KR-REQ-24.09: a report that the daemon cannot take when the agent answers is made when it can.
/// The daemon stops after the claim and the upstream answers while it is down; the daemon comes
/// back, and the binding becomes `accepted_by_agent`, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_a_report_made_while_the_daemon_is_down_is_recorded_when_it_returns() {
    let Some((mut acting, draft, handle)) = offering().await else {
        return;
    };
    let release = Arc::new(tokio::sync::Notify::new());
    *acting.upstream.lock().expect("not poisoned") = Upstream::Holds(Arc::clone(&release));
    let mut client = acting.client().await;
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    client
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
            mutation,
        )))
        .await
        .expect("writes the mutation");
    // The offer is claimed and written, and the upstream has not answered.
    until("the offer to be claimed", || async {
        (state_of(&acting.draft(draft.draft_id), &handle) == InsertionState::Inserting)
            .then_some(())
    })
    .await;
    until("the frame to reach the upstream", || async {
        (!acting.frames().is_empty()).then_some(())
    })
    .await;

    acting.hosted.stop_daemon().await;
    release.notify_one();
    let outcome = answer(&mut client, Some(1)).await;
    assert!(
        matches!(outcome, Outcome::Ok(_)),
        "the agent's answer is the receipt's whether or not the daemon is there: {outcome:?}"
    );
    until("the report to wait for the daemon", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 1).then_some(())
    })
    .await;
    acting.hosted.start_daemon_again().await;
    until_binding(
        &acting,
        draft.draft_id,
        &handle,
        InsertionState::AcceptedByAgent,
    )
    .await;
    until("the report to be recorded", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 0).then_some(())
    })
    .await;
}

/// KR-REQ-24.09: a claim the daemon was asked for and did not answer is settled: the daemon stops
/// between the read of the draft and the claim, the action is rejected, and a report that the offer
/// failed waits for the claim's deadline and is then made, whatever the daemon did with the claim.
/// Here it made none, so the binding is still `recorded` and the report ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_a_claim_the_daemon_did_not_answer_is_settled_by_a_report() {
    let Some((mut acting, draft, handle)) = offering().await else {
        return;
    };
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    let mutation = acting.offering(&asking, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    asking
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
            mutation,
        )))
        .await
        .expect("writes the mutation");
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;

    // The draft was read; the daemon goes away before the component answers.
    acting.hosted.stop_daemon().await;
    signal(&host, rustix::process::Signal::CONT);
    let finished = answer(&mut asking, Some(1)).await;
    let Outcome::Error(refusal) = finished else {
        panic!("an offer whose claim nobody answered was carried: {finished:?}");
    };
    assert_eq!(refusal.code, ErrorCode::ResourceUnavailable, "{refusal:?}");
    assert!(acting.frames().is_empty());

    until("a report to wait for the claim's deadline", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 1).then_some(())
    })
    .await;
    acting.hosted.start_daemon_again().await;
    until("the report to be made and refused for good", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 0).then_some(())
    })
    .await;
    let after = acting.draft(draft.draft_id);
    assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
    assert_eq!(after.revision, draft.revision, "no claim was made");
}
