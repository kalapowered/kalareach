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
//! | KR-REQ-23.30 | an action that offers an attachment names a draft the daemon holds, is validated against it, and transmits nothing when the draft moved, the package does not declare an offer of it, the action was cancelled, lost its ground or its connection while its component prepared it, or the plan was not the invocation's own; it is prepared over the connection the worker's own link holds to the plugin runtime, and again after that runtime was lost; a repeat of it is answered with its receipt and claims nothing again |
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
    Acting, Change, Upstream, answer, contribution, read_receipt, send, signal, supersede,
    until_receipt, until_settled,
};
use plugin_world::{PATIENCE, kill, until};

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
    // The receiver of the offer reads the file the frame names before it acknowledges it.
    *acting.upstream.lock().expect("not poisoned") = Upstream::Reads;
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
    let attachment = &frame["params"]["attachment"];
    assert_eq!(attachment["transfer_id"], handle.transfer_id.to_string());
    assert_eq!(attachment["media_type"], "image/png");
    assert_eq!(attachment["byte_len"], 64);
    let grant = &attachment["read_grant"];
    assert_eq!(
        grant["environment_id"],
        acting.hosted.environment_id.to_string()
    );
    assert!(
        grant["expires_at_ms"]
            .as_u64()
            .is_some_and(|expires| expires > kr_ipc::now_ms().get()),
        "{grant}"
    );
    assert!(
        std::path::Path::new(grant["path"].as_str().expect("a path"))
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(&staged_stem(&handle))),
        "the file is named by the transfer's identifier: {grant}"
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

/// Waits until the daemon holds a worker's question at one of its testing pauses: the answer to a
/// read of a draft, or a claim before or after the transfer service decides it.
async fn until_the_daemon_holds(held: std::sync::mpsc::Receiver<()>) {
    let arrived = tokio::task::spawn_blocking(move || held.recv_timeout(PATIENCE).is_ok())
        .await
        .expect("the waiting thread finishes");
    assert!(arrived, "the question never reached the daemon's pause");
}

/// KR-REQ-23.30: a claim is made at the attempt the worker read before it asked the component. The
/// attachment is bound again after the daemon answered the read and before the worker has it: the
/// worker claims the attempt it read, the daemon refuses it because the binding has moved, the
/// action is rejected and the new attempt is as it was left. A worker that read the draft again
/// before it claimed would claim the new attempt and carry the offer on the strength of facts it
/// had checked against the old.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_claim_at_a_moved_attempt_transmits_nothing() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let (read, go_on) = acting
        .hosted
        .controller
        .as_ref()
        .expect("a daemon")
        .transfer()
        .pause_after_a_read();
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    write(&mut client, mutation).await;
    until_the_daemon_holds(read).await;

    // The same attachment, bound again while the answer to the read is on its way: a new attempt.
    let moved = acting.bind(&acting.draft(draft.draft_id), &handle);
    go_on.send(()).expect("lets the answer go");
    let Outcome::Error(refusal) = answer(&mut client, Some(1)).await else {
        panic!("the claim at the old attempt was carried");
    };
    assert_eq!(refusal.code, ErrorCode::DraftConflict, "{refusal:?}");
    let receipt = until_settled(&mut client, action_id).await;
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

/// KR-REQ-24.09: a claim the daemon committed and did not answer in time is settled by the report
/// of the worker, so the binding is not left `inserting` with nobody to settle it. The daemon holds
/// the answer; the worker runs out of the time the action was given, rejects the action and, once
/// the claim's deadline has passed, reports that the offer failed. The binding is `failed`, the
/// draft took the claim's revision and the report's, nothing was written to the upstream, and the
/// daemon's answer, let go afterwards, reaches nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_a_claim_that_committed_without_an_answer_is_settled_by_the_workers_report() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let (decided, answer_now) = acting
        .hosted
        .controller
        .as_ref()
        .expect("a daemon")
        .transfer()
        .pause_after_a_claim();
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    write(&mut client, mutation).await;
    until_the_daemon_holds(decided).await;
    assert_eq!(
        state_of(&acting.draft(draft.draft_id), &handle),
        InsertionState::Inserting,
        "the claim committed and the answer is on hold"
    );

    let finished = answer(&mut client, Some(1)).await;
    assert!(
        matches!(finished, Outcome::Error(_)),
        "the action is refused: {finished:?}"
    );
    let failed = until_binding(&acting, draft.draft_id, &handle, InsertionState::Failed).await;
    assert_eq!(failed.revision.get(), draft.revision.get() + 2);
    until("the report to be recorded", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 0).then_some(())
    })
    .await;
    let receipt = until_settled(&mut client, action_id).await;
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert!(acting.frames().is_empty());
    answer_now.send(()).expect("lets the daemon answer");
}

/// KR-REQ-24.09: a claim that reaches the daemon after its action gave up on it commits nothing.
/// The daemon holds the claim until the worker has run out of the time the action was given and said
/// so; the worker then reports the offer failed once the claim's deadline has passed, and that
/// report finds no claim to settle. The claim, let go after that, is refused for its deadline, so
/// the binding is not left `inserting` with nobody to report it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_a_claim_let_go_after_its_deadline_commits_nothing_and_the_binding_is_not_stranded()
 {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let transfer = acting
        .hosted
        .controller
        .as_ref()
        .expect("a daemon")
        .transfer();
    let (held, release) = transfer.pause_before_a_claim();
    let (decided, answer_now) = transfer.pause_after_a_claim();
    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    write(&mut client, mutation).await;
    until_the_daemon_holds(held).await;

    // The worker runs out of time for the claim and rejects the action, with the daemon still
    // holding it. Its report that the offer failed waits for the claim's deadline, and is then
    // made, to a daemon that has made no claim.
    let finished = answer(&mut client, Some(1)).await;
    assert!(
        matches!(finished, Outcome::Error(_)),
        "the action is refused: {finished:?}"
    );
    until("the report to be made and ended", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 0).then_some(())
    })
    .await;
    assert_eq!(
        state_of(&acting.draft(draft.draft_id), &handle),
        InsertionState::Recorded,
        "the report found no claim"
    );

    // The claim is let go, and decided: refused for its deadline, so the draft is as it was.
    release.send(()).expect("lets the claim go");
    until_the_daemon_holds(decided).await;
    let after = acting.draft(draft.draft_id);
    assert_eq!(
        after.revision, draft.revision,
        "a claim past its deadline committed"
    );
    assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
    answer_now.send(()).expect("lets the daemon answer");
    let receipt = until_settled(&mut client, action_id).await;
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert!(acting.frames().is_empty());
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

/// KR-REQ-23.30: a plan that is of the declared class and names the attachment, but proposes
/// another operation than the one the action declares, is refused before the draft is claimed: the
/// attachment is not marked and the draft does not move for a plan that is refused after.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_plan_that_proposes_another_operation_claims_nothing() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let mutation = acting.offering(
        &client,
        "attach.as.cancel",
        draft.draft_id,
        handle.transfer_id,
    );
    let action_id = mutation.action_id;
    let Outcome::Error(refusal) = send(&mut client, mutation).await else {
        panic!("a plan that proposes another operation was carried");
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
    assert_eq!(after.revision, draft.revision, "nothing was claimed");
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

/// What keeps a runtime reading its sockets and firing its timers while one of its tasks is held
/// on a thread: a thread that hands the runtime a task every few milliseconds, until it is dropped.
///
/// A task of this runtime that waits inside a pause holds one of its threads, as a worker's own
/// process would hold one of its own. When that is the thread that was reading the runtime's sockets
/// and every other thread is asleep, nothing reads a socket or fires a timer until the pause ends,
/// and a wait for the worker to go on would be a wait for the release it has not yet been given. A
/// task handed to the runtime from outside wakes a sleeping thread, which polls the sockets and the
/// timers when it goes to sleep again.
struct Awake {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Awake {
    fn start(runtime: tokio::runtime::Handle) -> Self {
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            // Until the sender is dropped.
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                stopped.recv_timeout(std::time::Duration::from_millis(5))
            {
                drop(runtime.spawn(async {}));
            }
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Awake {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What the staged file of an attachment is called before its extension: the transfer's identifier,
/// in hexadecimal.
fn staged_stem(handle: &AttachmentHandle) -> String {
    handle
        .transfer_id
        .get()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The staged file of an attachment, found by what it is called and not by where the service keeps
/// it.
fn staged_file(acting: &Acting, handle: &AttachmentHandle) -> std::path::PathBuf {
    fn find(directory: &std::path::Path, stem: &str) -> Option<std::path::PathBuf> {
        for entry in std::fs::read_dir(directory).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = find(&path, stem) {
                    return Some(found);
                }
            } else if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(stem))
                && !path.to_string_lossy().ends_with(".part")
            {
                return Some(path);
            }
        }
        None
    }
    find(
        acting.hosted.environment().state_dir(),
        &staged_stem(handle),
    )
    .expect("the attachment's file is staged")
}

/// Writes a mutation to the worker without waiting for its answer.
async fn write(
    client: &mut kr_ipc::client::LocalClient,
    mutation: kr_protocol::envelope::MutationRequest,
) {
    client
        .writer()
        .write_message(&kr_protocol::envelope::ControlFrame::Mutation(Box::new(
            mutation,
        )))
        .await
        .expect("writes the mutation");
}

/// KR-REQ-23.30: an offer that was prepared and claimed when its connection ended is rejected, its
/// claim is settled, and nothing is written to the upstream.
///
/// The connection's loop is inside the dispatch boundary with a repeat of the offer when the
/// component answers, so the finished preparation waits for the loop. The client then goes, and the
/// loop finds the connection ended with the preparation unfinished. Which of the two ways the
/// worker ends such an action is the loop's to decide: it settles what is waiting for it when it
/// leaves, and a preparation that finishes later finds the connection gone and settles its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_offer_claimed_when_its_connection_ends_is_rejected_and_its_claim_settled()
{
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let service = Arc::clone(&acting.hosted._service);
    let mut watcher = acting.client().await;
    let mut asking = acting.client().await;
    // What holds the service when nothing is being prepared: the connections and this test.
    let idle = Arc::strong_count(&service);
    let mutation = acting.offering(&asking, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    write(&mut asking, mutation.clone()).await;
    until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;

    // A repeat of the offer holds the connection's loop inside the dispatch boundary. The loop
    // waits on a thread of this runtime, which may be the one that reads its sockets and fires its
    // timers, so the runtime is kept polling for as long as the loop is held.
    let _awake = Awake::start(tokio::runtime::Handle::current());
    let (arrived, release) = service.pause_inside_boundary();
    let mut repeat = mutation;
    repeat.request_id = RequestId::new(2);
    write(&mut asking, repeat).await;
    tokio::task::spawn_blocking(move || arrived.recv_timeout(PATIENCE))
        .await
        .expect("the waiting thread finishes")
        .expect("the repeat reached the dispatch boundary");

    // The component answers and the offer is claimed. The task that prepared it has handed it to
    // the connection once it no longer holds the service.
    signal(&host, rustix::process::Signal::CONT);
    until_binding(&acting, draft.draft_id, &handle, InsertionState::Inserting).await;
    until("the preparation to be handed to the connection", || async {
        (Arc::strong_count(&service) == idle).then_some(())
    })
    .await;

    // The client goes, and the loop is let go to find it so.
    drop(asking);
    release.send(()).expect("lets the repeat go");
    let receipt = until_settled(&mut watcher, action_id).await;
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&kr_protocol::receipt::RejectionReason::AdmissionFailed),
        "{receipt:?}"
    );
    assert!(
        acting.frames().is_empty(),
        "nothing was written to the upstream: {:?}",
        acting.frames()
    );
    let settled = until_binding(&acting, draft.draft_id, &handle, InsertionState::Failed).await;
    assert_eq!(settled.attachments[0].handle, handle, "the upload is kept");
    until("the report to be recorded", || async {
        (acting.hosted._service.broker().drafts().reports_waiting() == 0).then_some(())
    })
    .await;
}

/// KR-REQ-23.30: what changes while an offer is prepared decides where its claim ends. An offer
/// whose action was revoked before the component answered claims nothing, and one whose binding
/// moved after its attachment was claimed is rejected with the claim settled as an offer that was
/// never made; in both, nothing is written to the upstream and the upload is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_offer_that_loses_its_ground_while_prepared_settles_what_it_claimed() {
    for (change, claimed, reason) in [
        (
            Change::Authority,
            false,
            kr_protocol::receipt::RejectionReason::Revoked,
        ),
        (
            Change::Binding,
            true,
            kr_protocol::receipt::RejectionReason::StalePreconditions,
        ),
    ] {
        let Some((acting, draft, handle)) = offering().await else {
            return;
        };
        let mut watcher = acting.client().await;
        let mut asking = acting.client().await;
        let mutation = acting.offering(&asking, "attach.photo", draft.draft_id, handle.transfer_id);
        let action_id = mutation.action_id;
        let host = acting.stop_host();
        write(&mut asking, mutation).await;
        until_receipt(&mut watcher, action_id, ReceiptState::Accepted).await;
        let mut asking = Some(asking);
        acting.change(change, "attach.photo", &mut asking).await;
        signal(&host, rustix::process::Signal::CONT);
        if let Some(asking) = asking.as_mut() {
            answer(asking, Some(1)).await;
        }
        let receipt = until_settled(&mut watcher, action_id).await;
        assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
        assert_eq!(receipt.reason.as_ref(), Some(&reason), "{receipt:?}");
        assert!(
            acting.frames().is_empty(),
            "nothing was written to the upstream: {:?}",
            acting.frames()
        );
        if claimed {
            let settled =
                until_binding(&acting, draft.draft_id, &handle, InsertionState::Failed).await;
            assert_eq!(settled.attachments[0].handle, handle, "the upload is kept");
        } else {
            let after = acting.draft(draft.draft_id);
            assert_eq!(state_of(&after, &handle), InsertionState::Recorded);
            assert_eq!(after.revision, draft.revision, "nothing was claimed");
        }
    }
}

/// KR-REQ-23.30: a repeat of an offer is answered with the receipt the offer has and claims nothing
/// again, and the same action identifier with another attachment is a conflict that changes
/// nothing; the offer is claimed, written and reported once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_a_repeat_of_an_offer_claims_nothing_again_and_a_changed_one_conflicts() {
    let Some((acting, draft, first)) = offering().await else {
        return;
    };
    let second = acting.publish(&[12; 64], "second.png");
    let draft = acting.bind(&draft, &second);
    let mut asking = acting.client().await;
    let mut other = acting.client().await;
    let mutation = acting.offering(&asking, "attach.photo", draft.draft_id, first.transfer_id);
    let action_id = mutation.action_id;
    let host = acting.stop_host();
    write(&mut asking, mutation.clone()).await;
    until_receipt(&mut other, action_id, ReceiptState::Accepted).await;

    // The same offer from another connection is answered with the receipt as it stands.
    let mut repeat = mutation.clone();
    repeat.request_id = RequestId::new(5);
    let Outcome::Ok(repeated) = send(&mut other, repeat).await else {
        panic!("a repeat is answered with the receipt");
    };
    assert!(
        format!("{:?}", repeated.as_value()).contains("accepted"),
        "{repeated:?}"
    );

    // The same identifier for another attachment is another request under the same identifier.
    let mut changed = acting.offering(&other, "attach.photo", draft.draft_id, second.transfer_id);
    changed.action_id = action_id;
    changed.request_id = RequestId::new(6);
    let Outcome::Error(conflict) = send(&mut other, changed).await else {
        panic!("a changed request under the same identifier was carried");
    };
    assert_eq!(conflict.code, ErrorCode::IdConflict, "{conflict:?}");

    signal(&host, rustix::process::Signal::CONT);
    let finished = answer(&mut asking, Some(1)).await;
    assert!(matches!(finished, Outcome::Ok(_)), "{finished:?}");
    let accepted = until_binding(
        &acting,
        draft.draft_id,
        &first,
        InsertionState::AcceptedByAgent,
    )
    .await;
    assert_eq!(acting.frames().len(), 1, "the offer was written once");
    assert_eq!(
        state_of(&accepted, &second),
        InsertionState::Recorded,
        "the other attachment was not touched"
    );
    assert_eq!(
        accepted.revision.get(),
        draft.revision.get() + 2,
        "one claim and one report, whatever was repeated"
    );
}

/// KR-REQ-23.30: an offer is refused before anything is claimed when the package's declaration does
/// not admit it, one row for each thing the declaration decides: the media type and its family, the
/// size, the destination and the application instance the draft is for, which the worker checks
/// against what it read; and two the control daemon decides when it claims, given the declaration's
/// figure, the number of attachments and the way the binding was recorded to be inserted. The
/// control is a declaration that admits it, which is carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_offer_the_packages_declaration_does_not_admit_is_refused_before_a_claim() {
    use kr_plugin_sdk::effect::AttachmentContribution;
    use kr_plugin_sdk::scalars::{Count, U64 as Size};
    use kr_plugin_sdk::text::Label;
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let broker = acting.hosted._service.broker();
    let mut client = acting.client().await;
    let declaring = |change: &dyn Fn(&mut AttachmentContribution)| {
        let mut declared = contribution();
        change(&mut declared);
        broker
            .register_attachments(plugin_world::acting::binding(), Some(declared))
            .expect("the contribution is registered");
    };
    let mut number = 100_u64;

    // The draft holds a second image for the row about the count, and the draft of another
    // instance and the draft recorded for a composer are made for their rows.
    let second = acting.publish(&[13; 64], "second.png");
    let crowded = acting.bind(&acting.new_draft(), &handle);
    let crowded = acting.bind(&crowded, &second);
    let elsewhere = acting.bind(
        &acting.new_draft_for(kr_protocol::ids::ApplicationInstanceId::new(
            Uuid::from_bytes([3; 16]),
        )),
        &handle,
    );
    let composer = acting.bind_by(
        &acting.new_draft(),
        &handle,
        kr_protocol::transfer::InsertionMethod::VerifiedComposerInsertion,
    );

    type Alter = Box<dyn Fn(&mut AttachmentContribution)>;
    let rows: Vec<(&str, kr_protocol::ids::DraftId, Alter, ErrorCode)> = vec![
        (
            "a media type the package does not accept",
            draft.draft_id,
            Box::new(|declared| declared.accepted_media_types = vec!["image/jpeg".to_owned()]),
            ErrorCode::InvalidArgument,
        ),
        (
            "a family of media types the package does not accept",
            draft.draft_id,
            Box::new(|declared| declared.accepted_media_types = vec!["audio/*".to_owned()]),
            ErrorCode::InvalidArgument,
        ),
        (
            "a file larger than the package accepts",
            draft.draft_id,
            Box::new(|declared| declared.max_bytes = Size::new(63)),
            ErrorCode::InvalidArgument,
        ),
        (
            "a destination the package does not declare",
            draft.draft_id,
            Box::new(|declared| {
                declared.external_destination =
                    Nullable(Some(Label::new("elsewhere").expect("a label")));
            }),
            ErrorCode::DraftConflict,
        ),
        (
            "more attachments than the package accepts",
            crowded.draft_id,
            Box::new(|declared| declared.max_count = Count::new(1)),
            ErrorCode::DraftConflict,
        ),
        (
            "a binding recorded to be inserted another way",
            composer.draft_id,
            Box::new(|_| {}),
            ErrorCode::InvalidArgument,
        ),
        (
            "a draft for another application instance",
            elsewhere.draft_id,
            Box::new(|_| {}),
            ErrorCode::DraftConflict,
        ),
    ];
    for (what, draft_id, alter, code) in &rows {
        declaring(&**alter);
        let before = acting.draft(*draft_id);
        number += 1;
        let mut mutation = acting.offering(&client, "attach.photo", *draft_id, handle.transfer_id);
        mutation.request_id = RequestId::new(number);
        let action_id = mutation.action_id;
        let Outcome::Error(refusal) = send(&mut client, mutation).await else {
            panic!("{what}: the offer was carried");
        };
        assert_eq!(refusal.code, *code, "{what}: {refusal:?}");
        assert_eq!(
            read_receipt(&mut client, action_id)
                .await
                .expect("a receipt")
                .state,
            ReceiptState::Rejected,
            "{what}"
        );
        let after = acting.draft(*draft_id);
        assert_eq!(
            after.revision, before.revision,
            "{what}: nothing was claimed"
        );
        assert_eq!(
            state_of(&after, &handle),
            InsertionState::Recorded,
            "{what}"
        );
    }
    assert!(
        acting.frames().is_empty(),
        "no refused offer wrote anything: {:?}",
        acting.frames()
    );

    // The control: a family that admits the image, which carries the offer.
    declaring(&|declared| declared.accepted_media_types = vec!["image/*".to_owned()]);
    let mut control = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    control.request_id = RequestId::new(number + 1);
    let outcome = send(&mut client, control).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    until_binding(
        &acting,
        draft.draft_id,
        &handle,
        InsertionState::AcceptedByAgent,
    )
    .await;
}

/// KR-REQ-23.30: the connection the worker's own link holds to the plugin runtime is the one a
/// component is asked to prepare actions over. The link asks the daemon for the runtime, registers
/// the package's component and hands the broker the connection; an action is refused as one that
/// can be asked again until then, is prepared and carried once the component is registered, is
/// refused again when the runtime is lost, and is prepared once more when the link has registered
/// the component with the replacement the daemon started.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_30_an_action_is_prepared_over_the_links_connection_and_again_after_the_runtime_is_lost()
 {
    let Some(acting) = Acting::start_linked().await else {
        return;
    };
    let mut client = acting.client().await;
    let mut number = 0_u64;

    // Refused as one that can be asked again, and carried as soon as the link has registered the
    // component.
    async fn until_carried(
        acting: &Acting,
        client: &mut kr_ipc::client::LocalClient,
        number: &mut u64,
    ) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            *number += 1;
            let mut mutation = acting.invocation(client, "turn.cancel", b"{}");
            mutation.request_id = RequestId::new(*number);
            match send(client, mutation).await {
                Outcome::Ok(_) => return,
                Outcome::Error(refusal) => assert_eq!(
                    refusal.code,
                    ErrorCode::ResourceUnavailable,
                    "an action that cannot be prepared yet can be asked again: {refusal:?}"
                ),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "waited {PATIENCE:?} for an action to be prepared and carried"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    until_carried(&acting, &mut client, &mut number).await;
    assert_eq!(acting.frames().len(), 1);
    let first_host = acting.hosted.published().expect("a runtime is published");

    // The runtime is lost, and the daemon starts another when the link asks.
    kill(&first_host);
    until_carried(&acting, &mut client, &mut number).await;
    assert_eq!(acting.frames().len(), 2);
    let second_host = acting.hosted.published().expect("a runtime is published");
    assert_ne!(
        first_host, second_host,
        "the second action was prepared over a connection to the replacement"
    );
}

/// KR-REQ-12.30 and KR-REQ-24.09: the receiver of an offer opens the file the frame names and
/// checks it against the size and the digest the frame carries, so an acknowledgement follows a
/// file that was there to read. A staged file that is not what the frame says makes a receiver that
/// reads it refuse, the offer fails with the draft and the upload kept, and the same upload offered
/// again once the file is as it was is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_09_a_staged_file_that_is_not_what_the_frame_says_is_refused_by_a_receiver_that_reads_it()
 {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let mut client = acting.client().await;
    let staged = staged_file(&acting, &handle);
    let original = std::fs::read(&staged).expect("reads the staged file");
    let mut permissions = std::fs::metadata(&staged).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o600);
    std::fs::set_permissions(&staged, permissions).expect("the test may write the file");
    std::fs::write(&staged, vec![0xff; original.len()]).expect("corrupts the file");

    let mutation = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    let action_id = mutation.action_id;
    let Outcome::Error(refusal) = send(&mut client, mutation).await else {
        panic!("a receiver that read another file acknowledged the offer");
    };
    assert_eq!(refusal.code, ErrorCode::InvalidArgument, "{refusal:?}");
    assert_eq!(
        read_receipt(&mut client, action_id)
            .await
            .expect("a receipt")
            .state,
        ReceiptState::Refused
    );
    assert_eq!(acting.frames().len(), 1, "the frame was written");
    let failed = until_binding(&acting, draft.draft_id, &handle, InsertionState::Failed).await;
    assert_eq!(failed.attachments[0].handle, handle, "the upload is kept");

    // The file is as it was, the attachment is bound again, and the offer is accepted.
    std::fs::write(&staged, &original).expect("restores the file");
    acting.bind(&failed, &handle);
    let mut again = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    again.request_id = RequestId::new(2);
    let outcome = send(&mut client, again).await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    until_binding(
        &acting,
        draft.draft_id,
        &handle,
        InsertionState::AcceptedByAgent,
    )
    .await;
}

/// KR-REQ-12.30: whatever a file is called, the frame to the upstream names it by identifiers and
/// by the grant's path, which is derived from the transfer's identifier, and never by the name. The
/// names are a name with spaces, quotes and non-ASCII letters, one that looks like a relative path
/// out of a directory, a WSL path, a WSL network path and a Windows drive path; each is offered,
/// read by the receiver and accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_12_30_an_attachment_is_named_to_the_upstream_by_identifiers_whatever_its_file_is_called()
 {
    let Some(acting) = Acting::start().await else {
        return;
    };
    *acting.upstream.lock().expect("not poisoned") = Upstream::Reads;
    let mut client = acting.client().await;
    let names: [(&str, &[&str]); 5] = [
        (
            "a name with spaces and \"quotes\" and ünïcode.png",
            &["spaces", "quotes", "ünïcode"],
        ),
        ("../../outside/escape.png", &["outside", "escape"]),
        (
            "/mnt/c/Users/me/Pictures/holiday.png",
            &["holiday", "Pictures", "/mnt"],
        ),
        (
            "\\\\wsl.localhost\\Ubuntu\\home\\me\\wslshot.png",
            &["wslshot", "Ubuntu", "wsl.localhost"],
        ),
        (
            "C:\\Users\\me\\Desktop\\desktopshot.png",
            &["desktopshot", "Desktop", "C:"],
        ),
    ];
    for (index, (name, forbidden)) in names.iter().enumerate() {
        let handle = acting.publish(&[40 + index as u8; 64], name);
        let draft = acting.bind(&acting.new_draft(), &handle);
        let mut mutation =
            acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
        mutation.request_id = RequestId::new(10 + index as u64);
        let outcome = send(&mut client, mutation).await;
        assert!(matches!(outcome, Outcome::Ok(_)), "{name}: {outcome:?}");
        let frames = acting.frames();
        assert_eq!(frames.len(), index + 1, "{name}");
        let frame = &frames[index];
        for part in *forbidden {
            assert!(
                !frame.contains(part),
                "{name}: the frame carries {part}: {frame}"
            );
        }
        let parsed: serde_json::Value = serde_json::from_str(frame).expect("a JSON frame");
        assert_eq!(
            parsed["params"]["attachment"]["transfer_id"],
            handle.transfer_id.to_string(),
            "{name}"
        );
        let path = parsed["params"]["attachment"]["read_grant"]["path"]
            .as_str()
            .expect("a path");
        assert_eq!(
            std::path::Path::new(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
            Some(format!("{}.png", staged_stem(&handle))),
            "{name}"
        );
        until_binding(
            &acting,
            draft.draft_id,
            &handle,
            InsertionState::AcceptedByAgent,
        )
        .await;
        assert_eq!(
            acting.draft(draft.draft_id).attachments[0]
                .handle
                .original_file_name,
            *name,
            "the draft still shows the name the person gave it"
        );
    }
}

/// KR-REQ-12.30: a prompt that names a draft whose attachment is being offered is refused as a
/// conflict, and the draft is not sent: the offer goes on to be reported, and its attachment is
/// accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_12_30_a_prompt_naming_a_draft_whose_attachment_is_being_offered_is_a_conflict() {
    let Some((acting, draft, handle)) = offering().await else {
        return;
    };
    let release = Arc::new(tokio::sync::Notify::new());
    *acting.upstream.lock().expect("not poisoned") = Upstream::Holds(Arc::clone(&release));
    let mut client = acting.client().await;
    let offer = acting.offering(&client, "attach.photo", draft.draft_id, handle.transfer_id);
    write(&mut client, offer).await;
    until_binding(&acting, draft.draft_id, &handle, InsertionState::Inserting).await;

    // A caller at this machine prompts the session's agent with the draft, through the daemon.
    let mut caller = kr_ipc::client::LocalClient::connect(
        &acting
            .hosted
            .environment()
            .controller_endpoint()
            .expect("an endpoint"),
        kr_protocol::local::LocalClientKind::Cli,
        plugin_world::build(),
    )
    .await
    .expect("connects to the daemon");
    let mut prompt = acting.prompting(&caller, draft.draft_id);
    prompt.request_id = RequestId::new(1);
    let Outcome::Error(refusal) = plugin_world::submit(&mut caller, prompt).await else {
        panic!("a prompt was sent for a draft whose attachment was being offered");
    };
    assert_eq!(refusal.code, ErrorCode::DraftConflict, "{refusal:?}");
    assert!(
        refusal.message.contains("being offered"),
        "the refusal says why: {refusal:?}"
    );

    release.notify_one();
    let accepted = until_binding(
        &acting,
        draft.draft_id,
        &handle,
        InsertionState::AcceptedByAgent,
    )
    .await;
    assert_eq!(accepted.attachments[0].handle, handle);
    let offered = answer(&mut client, Some(1)).await;
    assert!(matches!(offered, Outcome::Ok(_)), "{offered:?}");

    // The other order: a draft a prompt has already sent to the session is not offered from.
    let sent = acting.publish(&[21; 64], "sent.png");
    let sent_draft = acting.bind(&acting.new_draft(), &sent);
    let mut prompt = acting.prompting(&caller, sent_draft.draft_id);
    prompt.request_id = RequestId::new(2);
    // The worker may answer the prompt or not; what matters is that the daemon recorded the draft
    // as sent before it passed the prompt on.
    let _ = plugin_world::submit(&mut caller, prompt).await;
    let mut late = acting.offering(
        &client,
        "attach.photo",
        sent_draft.draft_id,
        sent.transfer_id,
    );
    late.request_id = RequestId::new(3);
    let Outcome::Error(refusal) = send(&mut client, late).await else {
        panic!("an attachment was offered from a draft a prompt had sent");
    };
    assert_eq!(refusal.code, ErrorCode::DraftConflict, "{refusal:?}");
    assert!(
        refusal.message.contains("by a prompt"),
        "the refusal says the prompt sent it: {refusal:?}"
    );
    assert_eq!(
        state_of(&acting.draft(sent_draft.draft_id), &sent),
        InsertionState::Recorded
    );
}
