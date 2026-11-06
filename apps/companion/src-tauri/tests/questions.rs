//! An agent's questions, read and answered the way the page does, on the session's own worker.
//!
//! Each test calls a command through the invoke path, and the session's worker is one this test
//! scripts over a real local endpoint, so the worker sees exactly the calls the application makes:
//! a read, and an answer that names the revision the person was shown. What is also held here is
//! what the application does when the worker goes away: an answer is kept on this device, nothing
//! sends it again but the person, and a question that ended or moved while it was kept is not
//! answered.

#![cfg(unix)]

mod question_page;
mod scripted_worker;

use question_page::{Page, answered, code_of};

use std::time::Duration;

use kr_protocol::error::ErrorCode;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, ConnectionId, QuestionId, QuestionRevision, SessionEpoch,
};
use kr_protocol::method::Method;
use kr_protocol::question::{
    AnswerRecord, Question, QuestionAnswer, QuestionAnswerParams, QuestionChoice, QuestionKind,
    QuestionReadParams, QuestionReadResult, QuestionResolveResult, QuestionSource, QuestionState,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use scripted_worker::{CallKind, Challenge, ScriptedWorker};
use serde_json::{Value, json};

fn question_id() -> QuestionId {
    QuestionId::new(Uuid::from_bytes([5; 16]))
}

/// A question the agent asked, as the worker lists it.
fn question(worker: &ScriptedWorker, revision: u64, state: QuestionState) -> Question {
    Question {
        question_id: question_id(),
        revision: QuestionRevision::new(revision),
        state,
        session_id: worker.session_id,
        session_epoch: SessionEpoch::V1,
        kind: QuestionKind::Select,
        context: "The build finished with two failing tests.".to_owned(),
        question: "Which branch should the release be cut from?".to_owned(),
        choices: vec![
            QuestionChoice {
                choice_id: "main".to_owned(),
                label: "main".to_owned(),
            },
            QuestionChoice {
                choice_id: "release".to_owned(),
                label: "release/2026-09".to_owned(),
            },
            QuestionChoice::something_else(),
        ],
        source: QuestionSource {
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            process: ProcessStartIdentity::new(4242, ProcessStartSource::MacosProcBsdInfo, 77),
            executable: Nullable::some("/usr/local/bin/claude".to_owned()),
            agent_label: Nullable::some("Claude Code".to_owned()),
            connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
            launch_channel: true,
            session_member: true,
            ancestry: true,
            agent_binding_revision: Nullable::null(),
        },
        created_at_ms: TimestampMs::new(1_000),
        expires_at_ms: TimestampMs::new(1_000 + 86_400_000),
        answer: Nullable::null(),
        resolved_at_ms: Nullable::null(),
    }
}

fn choice(id: &str) -> QuestionAnswer {
    QuestionAnswer::Choice {
        choice_id: id.to_owned(),
    }
}

fn reads(worker: &ScriptedWorker, questions: Vec<Question>) -> QuestionReadResult {
    let _ = worker;
    QuestionReadResult { questions }
}

fn read_params(worker: &ScriptedWorker) -> Value {
    json!({ "params": {
        "session_id": worker.session_id.to_string(),
        "question_id": null,
        "include_resolved": false
    } })
}

fn answer_params(worker: &ScriptedWorker, revision: u64, answer: &QuestionAnswer) -> Value {
    json!({ "params": {
        "session_id": worker.session_id.to_string(),
        "question_id": question_id().to_string(),
        "expected_revision": revision.to_string(),
        "answer": serde_json::to_value(answer).expect("an answer's JSON")
    } })
}

fn resolution(worker: &ScriptedWorker, state: QuestionState) -> QuestionResolveResult {
    let mut resolved = question(worker, 3, state);
    resolved.answer = Nullable::some(AnswerRecord {
        answer: choice("main"),
        actor_id: ActorId::new("device:studio").expect("a principal"),
        device_id: Nullable::null(),
        question_revision: QuestionRevision::new(2),
        answered_at_ms: TimestampMs::new(9_000),
    });
    QuestionResolveResult::whole(resolved)
}

/// A session's questions are read on its own worker, after the worker proved its key, as a read
/// carrying the parameters the page sent, and the page is given the worker's answer in the
/// method's own shape.
#[tokio::test(flavor = "multi_thread")]
async fn a_sessions_questions_are_read_on_its_own_worker() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let asked = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    assert_eq!(
        call.kind,
        CallKind::Request,
        "a read of questions is a read"
    );
    let params: QuestionReadParams = call.params();
    assert_eq!(params.session_id, worker.session_id);
    assert!(!params.include_resolved);
    let listed = reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]);
    link.answer(&call, &listed).await;
    assert_eq!(
        answered(asked).await.expect("the questions"),
        serde_json::to_value(&listed).expect("the questions' JSON")
    );
    assert_eq!(
        page.links(),
        1,
        "the session's link is held for the next call"
    );
}

/// An answer names the question and the revision the person was shown, and the application sends
/// it to the worker as a mutation on the session alone: the worker's environment, the session at
/// its epoch, and no application instance. The page is told the worker's own record of it.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_names_the_revision_shown_and_the_session_alone() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    assert_eq!(call.kind, CallKind::Mutation);
    let target = call.target.clone().expect("a mutation's envelope");
    assert_eq!(target.environment_id, worker.descriptor.environment_id);
    assert_eq!(target.session_id.as_ref(), Some(&worker.session_id));
    assert_eq!(
        target.session_epoch.as_ref(),
        Some(&worker.descriptor.session_epoch)
    );
    assert!(
        target.application_instance_id.as_ref().is_none(),
        "a question's answer names no application instance"
    );
    assert!(target.agent_binding_revision.as_ref().is_none());
    let params: QuestionAnswerParams = call.params();
    assert_eq!(params.question_id, question_id());
    assert_eq!(params.expected_revision, QuestionRevision::new(2));
    assert_eq!(params.answer, choice("main"));
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = answered(asked).await.expect("the worker's answer");
    assert_eq!(told["outcome"], "taken");
    assert_eq!(told["leftover"], false);
    assert_eq!(told["resolution"]["state"], "answered");
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(
        kept["answers"],
        json!([]),
        "an answer the worker took is not kept"
    );
}

/// A question the page was never shown is not answered, and neither is one at another revision than
/// the application read: nothing is sent, so the worker is not asked to resolve what the person did
/// not see.
#[tokio::test(flavor = "multi_thread")]
async fn a_question_not_shown_or_shown_at_another_revision_is_not_answered() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let refused = answered(page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    ))
    .await
    .expect_err("it was never read");
    assert_eq!(code_of(&refused), "DRAFT_CONFLICT");

    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 3, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let refused = answered(page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    ))
    .await
    .expect_err("the person was shown revision 2, the worker is at 3");
    assert_eq!(code_of(&refused), "DRAFT_CONFLICT");
    assert!(
        link.quiet_for(Duration::from_millis(300)).await,
        "nothing was sent to the worker"
    );
}

/// Reading one question does not make the session's other questions unanswerable: what the page
/// was shown of them is still what it was shown until a read of them all says otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn reading_one_question_leaves_the_sessions_others_answerable() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let first = question(&worker, 2, QuestionState::Pending);
    let mut second = question(&worker, 2, QuestionState::Pending);
    second.question_id = QuestionId::new(Uuid::from_bytes([6; 16]));

    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(&call, &reads(&worker, vec![first.clone(), second.clone()]))
        .await;
    answered(read).await.expect("both questions");

    // The page reads the first alone.
    let one = page.call(
        "question_read",
        json!({ "params": {
            "session_id": worker.session_id.to_string(),
            "question_id": first.question_id.to_string(),
            "include_resolved": true
        } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(&call, &reads(&worker, vec![first.clone()]))
        .await;
    answered(one).await.expect("the one question");

    // The second is still the question the person was shown.
    let asked = page.call(
        "question_answer",
        json!({ "params": {
            "session_id": worker.session_id.to_string(),
            "question_id": second.question_id.to_string(),
            "expected_revision": "2",
            "answer": serde_json::to_value(choice("main")).expect("an answer's JSON")
        } }),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let mut resolved = resolution(&worker, QuestionState::Answered);
    resolved.question_id = second.question_id;
    if let Some(each) = resolved.question.0.as_mut() {
        each.question_id = second.question_id;
    }
    link.answer(&call, &resolved).await;
    let told = answered(asked).await.expect("the worker's answer");
    assert_eq!(told["outcome"], "taken");
}

/// An answer that does not fit the question's form is refused where the person is, and nothing is
/// sent or kept: a listed choice cannot be "something else", and a choice the question does not
/// offer is not one.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_does_not_fit_the_question_is_refused_and_not_kept() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    for answer in [
        choice("something_else"),
        choice("a-branch-nobody-offered"),
        QuestionAnswer::Decision { decided: true },
        QuestionAnswer::Other {
            text: String::new(),
        },
    ] {
        let refused = answered(page.call("question_answer", answer_params(&worker, 2, &answer)))
            .await
            .expect_err("that is not an answer to this question");
        assert_eq!(code_of(&refused), "INVALID_ARGUMENT", "{answer:?}");
    }
    assert!(link.quiet_for(Duration::from_millis(300)).await);
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"], json!([]));
}

/// The worker refuses the answer: another device answered first. The refusal is the page's to show,
/// and nothing is kept, because a refusal is the worker's own word and not a lost connection.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_worker_refuses_is_shown_and_not_kept() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    link.refuse_with(
        &call,
        ErrorCode::QuestionResolved,
        "another device answered first",
    )
    .await;
    let refused = answered(asked).await.expect_err("the worker's refusal");
    assert_eq!(code_of(&refused), "QUESTION_RESOLVED");
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"], json!([]));
}

/// KR-REQ-11.63: a worker that goes away before it answers the answer: a copy is kept on this
/// device, the page is told the host did not confirm it, and when the worker is back a settling only says whether
/// the question can still take it. Nothing but the person's own send goes to the worker, and that
/// reads the question again first.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_worker_could_not_take_is_kept_and_only_the_person_sends_it() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    // The worker has the answer and the connection goes before it says anything.
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    assert_eq!(call.kind, CallKind::Mutation);
    let sent = call
        .action_id
        .expect("the answer goes out under an identifier");
    drop(link);
    let told = answered(asked).await.expect("the answer is kept");
    assert_eq!(told["outcome"], "kept");
    assert_eq!(told["draft"]["question_revision"], "2");
    assert_eq!(told["draft"]["answer"]["choice_id"], "release");
    let drafted_at = told["draft"]["drafted_at_ms"].clone();

    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"].as_array().map(Vec::len), Some(1));
    assert_eq!(kept["answers"][0]["question_id"], question_id().to_string());

    // Contact is back. Settling reads the session's questions and sends nothing.
    let settling = page.call(
        "question_settle",
        json!({ "params": { "sessionId": worker.session_id.to_string() } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    assert_eq!(call.kind, CallKind::Request);
    let params: QuestionReadParams = call.params();
    assert!(
        params.include_resolved,
        "the resolved ones tell what became of it"
    );
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    has_no_receipt(&mut link, sent).await;
    let settled = answered(settling)
        .await
        .expect("the standing of the answers");
    assert_eq!(settled[0]["standing"], "offered");
    assert!(
        link.quiet_for(Duration::from_millis(300)).await,
        "settling sent nothing"
    );

    // The person sends it. The question is read again, and then the answer goes.
    let sending = page.call(
        "question_send_kept",
        json!({ "params": { "questionId": question_id().to_string(), "draftedAtMs": drafted_at } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    has_no_receipt(&mut link, sent).await;
    let call = link.expect(Method::QuestionAnswer).await;
    let params: QuestionAnswerParams = call.params();
    assert_eq!(params.expected_revision, QuestionRevision::new(2));
    assert_eq!(params.answer, choice("release"));
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = answered(sending).await.expect("the worker took it");
    assert_eq!(told["outcome"], "taken");
    assert_eq!(told["leftover"], false);
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(
        kept["answers"],
        json!([]),
        "an answer the worker took is no longer kept"
    );
}

/// KR-REQ-11.63: a question that ended or moved while the answer was kept is not answered, and the answer is not
/// lost: it stays kept, with what became of the question, until the person dismisses it. A dismissal
/// that names an older copy of the answer than the one kept removes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_whose_question_ended_is_kept_until_it_is_dismissed() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let sent = call
        .action_id
        .expect("the answer goes out under an identifier");
    drop(link);
    let told = answered(asked).await.expect("kept");
    let drafted_at = told["draft"]["drafted_at_ms"].clone();

    let settling = page.call(
        "question_settle",
        json!({ "params": { "sessionId": worker.session_id.to_string() } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    // Somebody else answered it.
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 3, QuestionState::Answered)]),
    )
    .await;
    has_no_receipt(&mut link, sent).await;
    let settled = answered(settling).await.expect("the standing");
    assert_eq!(settled[0]["standing"], "ended");
    assert_eq!(settled[0]["state"], "answered");

    // Sending it reads the question again and sends nothing.
    let sending = page.call(
        "question_send_kept",
        json!({ "params": { "questionId": question_id().to_string(), "draftedAtMs": drafted_at } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 3, QuestionState::Answered)]),
    )
    .await;
    has_no_receipt(&mut link, sent).await;
    let refused = answered(sending).await.expect_err("the question ended");
    assert_eq!(code_of(&refused), "QUESTION_RESOLVED");
    assert!(link.quiet_for(Duration::from_millis(300)).await);

    // Still kept: the text is the person's until they dismiss it.
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"].as_array().map(Vec::len), Some(1));
    let older = answered(page.call(
        "question_dismiss_kept",
        json!({ "params": { "questionId": question_id().to_string(), "draftedAtMs": "1" } }),
    ))
    .await
    .expect("a dismissal of an older copy");
    assert_eq!(older, json!(false));
    let dismissed = answered(page.call(
        "question_dismiss_kept",
        json!({ "params": { "questionId": question_id().to_string(), "draftedAtMs": drafted_at } }),
    ))
    .await
    .expect("the dismissal");
    assert_eq!(dismissed, json!(true));
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"], json!([]));
}

/// KR-REQ-11.63: a new application over the same place finds the answer a previous run kept: it lives on this
/// device and not in the page.
#[tokio::test(flavor = "multi_thread")]
async fn a_kept_answer_outlives_the_application() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    link.expect(Method::QuestionAnswer).await;
    drop(link);
    answered(asked).await.expect("kept");

    let Page { kept, app, window } = page;
    drop(window);
    drop(app);
    let state = companion_tauri::AppState::new();
    state.keep_under(kept.path());
    let next = Page::over(state, worker.paths(), kept);
    let kept = answered(next.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"].as_array().map(Vec::len), Some(1));
    assert_eq!(kept["answers"][0]["answer"]["choice_id"], "main");
}

/// KR-REQ-11.63: a second window of the application is a second process over the same kept answers. While it is in
/// the middle of changing them, this window changes nothing: a dismissal of a copy that window has
/// replaced since, or a send of an answer that window is removing, would lose or repeat a person's
/// answer.
#[tokio::test(flavor = "multi_thread")]
async fn kept_answers_are_not_changed_while_another_window_is_changing_them() {
    use tauri::Manager as _;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    link.expect(Method::QuestionAnswer).await;
    drop(link);
    let told = answered(asked).await.expect("kept");
    let drafted_at = told["draft"]["drafted_at_ms"].clone();

    // Another window holds the kept answers, as the file every window holds says.
    let other_window = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(page.kept.path().join("kept-answers").join(".windows.lock"))
        .expect("the file every window holds");
    kr_flush::lock::try_exclusive(&other_window).expect("the other window has it");
    page.app
        .state::<companion_tauri::AppState>()
        .questions()
        .wait_at_most(Duration::from_millis(100));

    let params =
        json!({ "params": { "questionId": question_id().to_string(), "draftedAtMs": drafted_at } });
    let refused = answered(page.call("question_dismiss_kept", params.clone()))
        .await
        .expect_err("the other window is changing the kept answers");
    assert_eq!(code_of(&refused), "RESOURCE_UNAVAILABLE");
    let refused = answered(page.call("question_send_kept", params.clone()))
        .await
        .expect_err("a send waits for the other window too");
    assert_eq!(code_of(&refused), "RESOURCE_UNAVAILABLE");
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(
        kept["answers"].as_array().map(Vec::len),
        Some(1),
        "nothing was changed"
    );

    drop(other_window);
    let dismissed = answered(page.call("question_dismiss_kept", params))
        .await
        .expect("the other window is done");
    assert_eq!(dismissed, json!(true));
}

/// Keeps an answer by hand, as another host's application or an earlier run would have, in the
/// directory for `environment_id`.
fn keep_by_hand(
    root: &std::path::Path,
    environment_id: kr_protocol::ids::EnvironmentId,
    session_id: kr_protocol::ids::SessionId,
    drafted_at_ms: u64,
) -> kr_client::answers::AnswerDraft {
    use kr_client::answers::{ANSWER_FORMAT, AnswerDraft, AnswerDrafts, WRITTEN};
    use kr_protocol::envelope::ActionTarget;

    let draft = AnswerDraft {
        version: ANSWER_FORMAT,
        target: ActionTarget {
            environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        session_id,
        question_id: question_id(),
        question_revision: QuestionRevision::new(2),
        answer: choice("main"),
        drafted_at_ms: TimestampMs::new(drafted_at_ms),
    };
    let kept = root.join("kept-answers");
    let store = AnswerDrafts::open(kept.join(environment_id.to_string())).expect("a store");
    let writers = kr_ipc::install::hold_writers(
        &kr_ipc::install::Writing::in_roots(&kept, &kept),
        &mut || {},
    )
    .expect("the writers lock");
    let leave = kr_client::answers::Leave {
        answers: writers.permit(&WRITTEN).expect("the leave to write"),
        sends: writers
            .permit(&kr_client::sends::WRITTEN)
            .expect("the leave to write"),
    };
    // Kept the way an earlier run left it, with no send recorded beside it.
    let basis = store.basis(draft.question_id).expect("the pair reads");
    let sent = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let digest = store
        .begin(&draft, &basis, &[], sent, &leave)
        .expect("kept");
    store
        .settle(draft.question_id, digest, &[sent], false, &leave)
        .expect("the record goes");
    draft
}

/// KR-REQ-11.63: an answer is sent only to the host it was given to. One kept for another host is
/// not settled against this one (nothing is said of it) and is not sent to it.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_kept_for_another_host_is_neither_settled_nor_sent_here() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let elsewhere = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([9; 16]));
    let draft = keep_by_hand(page.kept.path(), elsewhere, worker.session_id, 5);

    let settling = page.call(
        "question_settle",
        json!({ "params": { "sessionId": worker.session_id.to_string() } }),
    );
    let mut link = worker.link().await;
    let settled = answered(settling).await.expect("nothing to say");
    assert_eq!(
        settled,
        json!([]),
        "an answer for another host is not settled here"
    );

    let sending = page.call(
        "question_send_kept",
        json!({ "params": { "questionId": question_id().to_string(),
                            "draftedAtMs": draft.drafted_at_ms.get().to_string() } }),
    );
    let refused = answered(sending)
        .await
        .expect_err("it was given to another host");
    assert_eq!(code_of(&refused), "RESOURCE_UNAVAILABLE");
    assert!(
        link.quiet_for(Duration::from_millis(300)).await,
        "nothing was asked of this host"
    );
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(
        kept["answers"].as_array().map(Vec::len),
        Some(1),
        "it is still kept"
    );
}

/// KR-REQ-11.63: an answer is named, to be sent or dismissed, by its question and the time it was
/// kept at. An answer kept to a question that already has one kept is never kept at the same time or
/// earlier, so the name of the older answer is never the name of the newer one and a dismissal of
/// the older removes nothing of the newer.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_kept_over_an_older_one_is_kept_at_a_later_time() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    // An older answer to the same question, kept at a time that has not come yet, as a clock that
    // was set back (or a second answer inside one millisecond) leaves it.
    let ahead = kr_ipc::now_ms().get() + 3_600_000;
    keep_by_hand(
        page.kept.path(),
        worker.descriptor.environment_id,
        worker.session_id,
        ahead,
    );
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    link.expect(Method::QuestionAnswer).await;
    drop(link);
    let told = answered(asked).await.expect("the answer is kept");
    assert_eq!(told["outcome"], "kept");
    assert_eq!(
        told["draft"]["drafted_at_ms"],
        json!((ahead + 1).to_string()),
        "later than the answer it replaces"
    );
    let older = answered(page.call(
        "question_dismiss_kept",
        json!({ "params": { "questionId": question_id().to_string(),
                            "draftedAtMs": ahead.to_string() } }),
    ))
    .await
    .expect("a dismissal of the older answer");
    assert_eq!(
        older,
        json!(false),
        "the older name removes nothing of the newer answer"
    );
}

/// KR-REQ-11.63: an environment whose kept answers cannot be read does not hide another's, and the
/// page is told that some could not be read.
#[tokio::test(flavor = "multi_thread")]
async fn one_environments_unreadable_answers_do_not_hide_anothers() {
    let worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    keep_by_hand(
        page.kept.path(),
        kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([8; 16])),
        worker.session_id,
        5,
    );
    let damaged = page
        .kept
        .path()
        .join("kept-answers")
        .join(kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16])).to_string());
    std::fs::create_dir_all(&damaged).expect("a directory");
    std::fs::write(
        damaged.join(format!("{}.answer", Uuid::from_bytes([6; 16]))),
        b"not an answer",
    )
    .expect("a damaged file");

    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"].as_array().map(Vec::len), Some(1));
    assert_eq!(kept["unreadable"], 1);
}

/// KR-REQ-11.63: a worker that takes an answer and never replies leaves an outcome nobody knows.
/// The exchange ends within its time, the answer is kept as one the host did not confirm, and the
/// next thing the application does is not left waiting behind it.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_worker_never_replies_to_is_kept_within_the_time_an_exchange_has() {
    use tauri::Manager as _;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    page.app
        .state::<companion_tauri::AppState>()
        .questions()
        .exchange_within(Duration::from_millis(200));
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    // The worker has the answer and says nothing, and the link stays open.
    link.expect(Method::QuestionAnswer).await;
    let told = answered(asked).await.expect("the answer is kept");
    assert_eq!(told["outcome"], "kept");

    // Nothing waits behind it: the kept answers are listed at once.
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept["answers"].as_array().map(Vec::len), Some(1));
}

/// KR-REQ-11.63: the worker took a kept answer and the copy kept on this device cannot be removed
/// afterwards. The answer was taken, and the page is told so and that a copy is left, which is never
/// sent again.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_the_worker_took_is_reported_taken_when_its_kept_copy_cannot_be_removed() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let kept_in = page.kept.path().join("kept-answers");

    // An answer is given and the worker goes away before it replies, so the answer is kept.
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let sent = call
        .action_id
        .expect("the answer goes out under an identifier");
    drop(link);
    let told = answered(asked).await.expect("kept");
    let drafted_at = told["draft"]["drafted_at_ms"].clone();

    let directory = std::fs::read_dir(&kept_in)
        .expect("the kept answers")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("the worker's environment");

    let sending = page.call(
        "question_send_kept",
        json!({ "params": { "questionId": question_id().to_string(), "draftedAtMs": drafted_at } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    has_no_receipt(&mut link, sent).await;
    let call = link.expect(Method::QuestionAnswer).await;
    // The send is recorded and has reached the worker. From now on the directory can be listed and
    // read but nothing in it can be removed, so the copy cannot be removed once the worker took it.
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).expect("locked");
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let result = answered(sending).await;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).expect("unlocked");
    let told = result.expect("the worker took it");
    assert_eq!(told["outcome"], "taken");
    assert_eq!(told["leftover"], true);
}

/// The worker has no receipt of `sent`, as it answers an identifier it never saw.
async fn has_no_receipt(link: &mut scripted_worker::Link, sent: kr_protocol::ids::ActionId) {
    let call = link.expect(Method::ActionRead).await;
    let params: kr_protocol::receipt::ActionReadParams = call.params();
    assert_eq!(
        params.action_id, sent,
        "the read names the answer's identifier"
    );
    link.refuse(&call, &format!("no receipt for action {sent}"))
        .await;
}

/// The worker's receipt of a send, as `action.read` answers it.
fn receipt_of(
    action_id: kr_protocol::ids::ActionId,
    state: kr_protocol::receipt::ReceiptState,
) -> kr_protocol::receipt::ActionReadResult {
    receipt_at(action_id, state, 9_000)
}

/// The worker's receipt of a send, last written at `updated_at_ms` by the worker's clock.
fn receipt_at(
    action_id: kr_protocol::ids::ActionId,
    state: kr_protocol::receipt::ReceiptState,
    updated_at_ms: u64,
) -> kr_protocol::receipt::ActionReadResult {
    kr_protocol::receipt::ActionReadResult {
        receipt: kr_protocol::receipt::Receipt {
            action_id,
            actor_id: ActorId::new("local:1").expect("a principal"),
            method: Method::QuestionAnswer.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            revision: kr_protocol::scalars::U64::new(3),
            state,
            reason: Nullable::null(),
            payload_digest: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::null(),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(updated_at_ms),
        },
        result: Nullable::null(),
    }
}

/// The files the application keeps for one environment's answers, by extension.
fn kept_files(page: &Page, worker: &ScriptedWorker, extension: &str) -> usize {
    let directory = page
        .kept
        .path()
        .join("kept-answers")
        .join(worker.paths().environment_id().to_string());
    std::fs::read_dir(directory)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == extension))
                .count()
        })
        .unwrap_or(0)
}

/// KR-REQ-11.63: the identifier an answer goes out under is recorded on this device before the
/// answer reaches the worker, and a lost reply leaves it there. A settling then asks the worker what
/// became of it: here the worker has no receipt of it, which is reported and decides nothing, and
/// the answer stays offered.
#[tokio::test(flavor = "multi_thread")]
async fn the_identifier_of_an_answer_is_recorded_before_it_reaches_the_worker() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let sent = call
        .action_id
        .expect("the answer goes out under an identifier");
    assert_eq!(
        kept_files(&page, &worker, "send"),
        1,
        "the record was on this device when the answer reached the worker"
    );
    drop(link);
    answered(asked).await.expect("the answer is kept");

    // The worker never saw it: it has no receipt, and says so.
    let settling = page.call(
        "question_settle",
        json!({ "params": { "sessionId": worker.session_id.to_string() } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    let call = link.expect(Method::ActionRead).await;
    let params: kr_protocol::receipt::ActionReadParams = call.params();
    assert_eq!(params.action_id, sent);
    link.refuse(&call, &format!("no receipt for action {sent}"))
        .await;
    let settled = answered(settling).await.expect("the standing");
    assert_eq!(settled[0]["standing"], "offered", "{settled}");
    assert_eq!(settled[0]["earlier"][0]["state"], "no_record", "{settled}");
}

/// KR-REQ-11.63, KR-ACC-009: a send whose outcome the worker could not establish is shown first. A
/// new answer meets it: it sends nothing, says what it found and keeps what was typed, and the press
/// that names the send it was shown goes out quoting it.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncertain_send_is_held_back_until_the_press_that_names_it() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    // The first answer goes out and its reply is lost.
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let uncertain = call.action_id.expect("an identifier");
    drop(link);
    answered(asked).await.expect("the answer is kept");

    // A new answer asks the worker what became of the first, which it could not establish: nothing
    // is sent.
    let second = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::ActionRead).await;
    link.answer(
        &call,
        &receipt_of(uncertain, kr_protocol::receipt::ReceiptState::Unknown),
    )
    .await;
    let held = answered(second).await.expect("held, not refused");
    assert_eq!(held["outcome"], "held", "{held}");
    assert_eq!(held["action_id"], uncertain.to_string());

    // The press that names the send it was shown goes out quoting it. It is the next call the
    // worker sees, so the held press sent nothing.
    let third = page.call(
        "question_answer",
        json!({
            "params": answer_params(&worker, 2, &choice("main"))["params"].clone(),
            "acknowledged": uncertain.to_string()
        }),
    );
    let call = link.expect(Method::ActionRead).await;
    link.answer(
        &call,
        &receipt_of(uncertain, kr_protocol::receipt::ReceiptState::Unknown),
    )
    .await;
    let call = link.expect(Method::QuestionAnswer).await;
    let quoted = call.expected.clone().expect("a mutation's preconditions");
    let kr_cbor::CanonicalValue::Map(quoted) = quoted.into_value() else {
        panic!("preconditions are a map");
    };
    assert!(
        quoted
            .get(kr_protocol::action::SUPERSEDES_ACTION_KEY)
            .is_some(),
        "the answer names the uncertain send"
    );
    assert_ne!(call.action_id, Some(uncertain), "it is a new send");
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = answered(third).await.expect("the worker took it");
    assert_eq!(told["outcome"], "taken", "{told}");
    assert_eq!(kept_files(&page, &worker, "answer"), 0);
    assert_eq!(kept_files(&page, &worker, "send"), 0);
}

/// A page whose first answer to the question went out on a link that stays up, and whose worker
/// said it could not establish what became of it: the answer is kept, and the link holds the send.
/// Returns the identifier of that send and the time the kept answer carries.
async fn with_an_uncertain_send_on_a_live_link(
    worker: &mut ScriptedWorker,
    page: &Page,
) -> (
    scripted_worker::Link,
    kr_protocol::ids::ActionId,
    serde_json::Value,
) {
    let read = page.call("question_read", read_params(worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(worker, vec![question(worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    let asked = page.call(
        "question_answer",
        answer_params(worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let older = call.action_id.expect("an identifier");
    link.refuse_with(
        &call,
        ErrorCode::OutcomeUnknown,
        "the outcome cannot be established",
    )
    .await;
    let kept = answered(asked).await.expect("the answer is kept");
    assert_eq!(
        page.unsettled(worker.session_id).await,
        Some(vec![older]),
        "the link holds the send whose outcome the worker could not establish"
    );
    (link, older, kept["draft"]["drafted_at_ms"].clone())
}

/// KR-REQ-11.63: when the worker takes the send of a kept answer, the link stops holding the earlier
/// send of it whose outcome the worker could not establish, which no reading will settle.
#[tokio::test(flavor = "multi_thread")]
async fn the_send_of_a_kept_answer_the_worker_takes_frees_the_link_of_the_earlier_send() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (mut link, older, drafted_at) =
        with_an_uncertain_send_on_a_live_link(&mut worker, &page).await;

    let right = page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": question_id().to_string(),
            "draftedAtMs": drafted_at,
            "acknowledged": older.to_string()
        } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    let call = link.expect(Method::QuestionAnswer).await;
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = answered(right).await.expect("the worker took it");
    assert_eq!(told["outcome"], "taken", "{told}");
    assert_eq!(
        page.unsettled(worker.session_id).await,
        Some(vec![]),
        "the link no longer holds the earlier send"
    );
}

/// KR-REQ-11.63: so does a new answer that names the earlier send after it was shown.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_answer_the_worker_takes_frees_the_link_of_the_earlier_send() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (mut link, older, _) = with_an_uncertain_send_on_a_live_link(&mut worker, &page).await;

    // The earlier send is shown first, and the press that names it goes out.
    let held = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    let held = answered(held).await.expect("held, not refused");
    assert_eq!(held["outcome"], "held", "{held}");
    let again = page.call(
        "question_answer",
        json!({
            "params": answer_params(&worker, 2, &choice("main"))["params"].clone(),
            "acknowledged": older.to_string()
        }),
    );
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    let call = link.expect(Method::QuestionAnswer).await;
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = answered(again).await.expect("the worker took it");
    assert_eq!(told["outcome"], "taken", "{told}");
    assert_eq!(
        page.unsettled(worker.session_id).await,
        Some(vec![]),
        "the link no longer holds the earlier send"
    );
}

/// A page with two sends of an answer on a link that stays up, each of which the worker said it
/// could not establish: the link holds both. Returns the link, the two identifiers (the older
/// first), and the time the kept answer carries.
async fn with_two_uncertain_sends_on_a_live_link(
    worker: &mut ScriptedWorker,
    page: &Page,
) -> (
    scripted_worker::Link,
    kr_protocol::ids::ActionId,
    kr_protocol::ids::ActionId,
    serde_json::Value,
) {
    use kr_protocol::receipt::ReceiptState;

    let (mut link, older, _) = with_an_uncertain_send_on_a_live_link(worker, page).await;
    let held = page.call(
        "question_answer",
        answer_params(worker, 2, &choice("main")),
    );
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    answered(held).await.expect("held, not refused");
    let again = page.call(
        "question_answer",
        json!({
            "params": answer_params(worker, 2, &choice("main"))["params"].clone(),
            "acknowledged": older.to_string()
        }),
    );
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    let call = link.expect(Method::QuestionAnswer).await;
    let newer = call.action_id.expect("an identifier");
    link.refuse_with(
        &call,
        ErrorCode::OutcomeUnknown,
        "the outcome cannot be established",
    )
    .await;
    let kept = answered(again).await.expect("the answer is kept");
    let mut held_by_the_link = page
        .unsettled(worker.session_id)
        .await
        .expect("the link is held");
    held_by_the_link.sort_unstable();
    let mut both = vec![older, newer];
    both.sort_unstable();
    assert_eq!(held_by_the_link, both, "the link holds both sends");
    (link, older, newer, kept["draft"]["drafted_at_ms"].clone())
}

/// KR-REQ-11.63: the reading before the send of a kept answer finds one of its earlier sends taken.
/// The question is answered, so the link stops holding the others too, whose outcome the worker
/// could not establish and which no reading will settle.
#[tokio::test(flavor = "multi_thread")]
async fn a_kept_answer_whose_earlier_send_the_worker_took_frees_the_link_of_the_others() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (mut link, older, newer, drafted_at) =
        with_two_uncertain_sends_on_a_live_link(&mut worker, &page).await;

    let sending = page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": question_id().to_string(),
            "draftedAtMs": drafted_at,
            "acknowledged": newer.to_string()
        } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    for (id, state) in [(older, ReceiptState::Unknown), (newer, ReceiptState::Applied)] {
        let call = link.expect(Method::ActionRead).await;
        link.answer(&call, &receipt_at(id, state, 9_000)).await;
    }
    let told = answered(sending).await.expect("the earlier send was taken");
    assert_eq!(told["outcome"], "landed", "{told}");
    assert_eq!(told["action_id"], newer.to_string(), "{told}");
    assert_eq!(
        page.unsettled(worker.session_id).await,
        Some(vec![]),
        "the link no longer holds the other send"
    );
}

/// KR-REQ-11.63: so does a new answer whose reading finds an earlier send taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_answer_whose_earlier_send_the_worker_took_frees_the_link_of_the_others() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (mut link, older, newer, _) =
        with_two_uncertain_sends_on_a_live_link(&mut worker, &page).await;

    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    for (id, state) in [(older, ReceiptState::Unknown), (newer, ReceiptState::Applied)] {
        let call = link.expect(Method::ActionRead).await;
        link.answer(&call, &receipt_at(id, state, 9_000)).await;
    }
    let told = answered(asked).await.expect("the earlier send was taken");
    assert_eq!(told["outcome"], "landed", "{told}");
    assert_eq!(told["action_id"], newer.to_string(), "{told}");
    assert_eq!(
        page.unsettled(worker.session_id).await,
        Some(vec![]),
        "the link no longer holds the other send"
    );
}

/// KR-REQ-11.63: and so does the send the worker refused because an earlier one took the question,
/// which the reading after the refusal finds.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_refused_because_an_earlier_one_was_taken_frees_the_link_of_the_others() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let (mut link, older, newer, drafted_at) =
        with_two_uncertain_sends_on_a_live_link(&mut worker, &page).await;

    let sending = page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": question_id().to_string(),
            "draftedAtMs": drafted_at,
            "acknowledged": newer.to_string()
        } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    for id in [older, newer] {
        let call = link.expect(Method::ActionRead).await;
        link.answer(&call, &receipt_at(id, ReceiptState::Unknown, 9_000))
            .await;
    }
    let call = link.expect(Method::QuestionAnswer).await;
    let own = call.action_id.expect("an identifier");
    link.refuse_with(
        &call,
        ErrorCode::QuestionResolved,
        "the question was already answered",
    )
    .await;
    for (id, state) in [(older, ReceiptState::Unknown), (newer, ReceiptState::Applied)] {
        let call = link.expect(Method::ActionRead).await;
        link.answer(&call, &receipt_at(id, state, 9_000)).await;
    }
    let told = answered(sending).await.expect("the earlier send was taken");
    assert_eq!(told["outcome"], "landed", "{told}");
    assert_eq!(told["action_id"], newer.to_string(), "{told}");
    assert_eq!(told["refused"], own.to_string(), "{told}");
    assert_eq!(
        page.unsettled(worker.session_id).await,
        Some(vec![]),
        "the link no longer holds the other send"
    );
}

/// KR-REQ-11.63: an earlier send that lands while a later one is on its way is reported as the one
/// the host took, and the press says that its own send went out and was refused. The pair is
/// retired with the answer the host took.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_the_host_refused_because_an_earlier_one_landed_names_both() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    // The first answer goes out and its reply is lost.
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let first = call.action_id.expect("an identifier");
    drop(link);
    answered(asked).await.expect("the answer is kept");

    // A second answer finds no receipt of the first, and sends. The first lands before it, so the
    // host refuses the second, and a second reading finds the first applied.
    let second = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let mut link = worker.link().await;
    has_no_receipt(&mut link, first).await;
    let call = link.expect(Method::QuestionAnswer).await;
    let own = call.action_id.expect("an identifier");
    link.refuse_with(
        &call,
        ErrorCode::QuestionResolved,
        "the question was already answered",
    )
    .await;
    let call = link.expect(Method::ActionRead).await;
    link.answer(
        &call,
        &receipt_of(first, kr_protocol::receipt::ReceiptState::Applied),
    )
    .await;
    let told = answered(second).await.expect("the earlier send was taken");
    assert_eq!(told["outcome"], "landed", "{told}");
    assert_eq!(told["action_id"], first.to_string(), "{told}");
    assert_eq!(told["refused"], own.to_string(), "{told}");
    assert_eq!(kept_files(&page, &worker, "answer"), 0);
    assert_eq!(kept_files(&page, &worker, "send"), 0);
}

/// KR-REQ-11.63: when several earlier sends ended with an outcome the host could not establish, the
/// send of a kept answer names the newest by the host's own record of it, which the standing says;
/// naming another is refused and sends nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_send_of_a_kept_answer_names_the_newest_uncertain_send() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    // The first answer goes out and its reply is lost.
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let older = call.action_id.expect("an identifier");
    drop(link);
    answered(asked).await.expect("the answer is kept");

    // A second answer is held until the first is shown, and then goes out quoting it, and its reply
    // is lost too.
    let held = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("main")),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    answered(held).await.expect("held");
    let again = page.call(
        "question_answer",
        json!({
            "params": answer_params(&worker, 2, &choice("main"))["params"].clone(),
            "acknowledged": older.to_string()
        }),
    );
    let call = link.expect(Method::ActionRead).await;
    link.answer(&call, &receipt_at(older, ReceiptState::Unknown, 5_000))
        .await;
    let call = link.expect(Method::QuestionAnswer).await;
    let newer = call.action_id.expect("an identifier");
    drop(link);
    let kept = answered(again).await.expect("the answer is kept");
    let drafted_at = kept["draft"]["drafted_at_ms"].clone();

    // The host's record of the second send is the newer. Settling says which one a send names.
    let settling = page.call(
        "question_settle",
        json!({ "params": { "sessionId": worker.session_id.to_string() } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    for id in [older, newer] {
        let call = link.expect(Method::ActionRead).await;
        let at = if id == older { 5_000 } else { 9_000 };
        link.answer(&call, &receipt_at(id, ReceiptState::Unknown, at))
            .await;
    }
    let settled = answered(settling).await.expect("the standing");
    assert_eq!(settled[0]["standing"], "offered", "{settled}");
    assert_eq!(settled[0]["quote"], newer.to_string(), "{settled}");
    assert_eq!(
        settled[0]["earlier"].as_array().map(Vec::len),
        Some(2),
        "{settled}"
    );

    // A send that names the older one is refused, and the worker sees nothing of it.
    let wrong = page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": question_id().to_string(),
            "draftedAtMs": drafted_at,
            "acknowledged": older.to_string()
        } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    for id in [older, newer] {
        let call = link.expect(Method::ActionRead).await;
        let at = if id == older { 5_000 } else { 9_000 };
        link.answer(&call, &receipt_at(id, ReceiptState::Unknown, at))
            .await;
    }
    let refused = answered(wrong).await.expect_err("the wrong send is named");
    assert_eq!(code_of(&refused), "DRAFT_CONFLICT", "{refused}");

    // The newest goes out, quoting it.
    let right = page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": question_id().to_string(),
            "draftedAtMs": drafted_at,
            "acknowledged": newer.to_string()
        } }),
    );
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    for id in [older, newer] {
        let call = link.expect(Method::ActionRead).await;
        let at = if id == older { 5_000 } else { 9_000 };
        link.answer(&call, &receipt_at(id, ReceiptState::Unknown, at))
            .await;
    }
    let call = link.expect(Method::QuestionAnswer).await;
    let quoted = call.expected.clone().expect("a mutation's preconditions");
    let kr_cbor::CanonicalValue::Map(quoted) = quoted.into_value() else {
        panic!("preconditions are a map");
    };
    let named = quoted
        .get(kr_protocol::action::SUPERSEDES_ACTION_KEY)
        .and_then(|value| kr_cbor::from_canonical_value::<kr_protocol::ids::ActionId>(value).ok());
    assert_eq!(
        named,
        Some(newer),
        "the send names the newest uncertain one by the host's record of it"
    );
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = answered(right).await.expect("the worker took it");
    assert_eq!(told["outcome"], "taken", "{told}");
}

/// The worker's next call is a receipt read of `recorded`, the send this device recorded, and of no
/// other. It is counted in `asked_about`, and answered with `receipt`, or with "no receipt" when
/// there is none.
async fn read_of_the_recorded_receipt(
    link: &mut scripted_worker::Link,
    asked_about: &mut Vec<kr_protocol::ids::ActionId>,
    recorded: kr_protocol::ids::ActionId,
    receipt: Option<kr_protocol::receipt::ActionReadResult>,
) {
    let call = link.expect(Method::ActionRead).await;
    let params: kr_protocol::receipt::ActionReadParams = call.params();
    asked_about.push(params.action_id);
    assert_eq!(
        params.action_id, recorded,
        "the worker is asked about the send this device recorded"
    );
    match receipt {
        Some(receipt) => link.answer(&call, &receipt).await,
        None => {
            link.refuse(&call, &format!("no receipt for action {recorded}"))
                .await;
        }
    }
}

/// Waits for a command to end, and fails when it asks the worker for anything more before then.
async fn ends_without_asking_more(
    mut command: tokio::task::JoinHandle<Result<Value, Value>>,
    link: &mut scripted_worker::Link,
) -> Result<Value, Value> {
    tokio::select! {
        done = &mut command => done.expect("the command's thread finished"),
        call = link.call() => panic!(
            "the command asked the worker for more: {} {:?}",
            call.method, call.params
        ),
    }
}

/// KR-REQ-10.06, KR-REQ-11.63: the send a page says it was shown is only compared with the newest
/// uncertain send this device recorded. It is no method's parameter: a kept answer's send naming
/// another send is refused as a conflict, a new answer naming another is held, a send naming one
/// when no uncertain send is recorded goes out quoting nothing, and across all of it the worker is
/// asked about the send this device recorded and about no other.
#[tokio::test(flavor = "multi_thread")]
async fn the_send_a_page_says_it_was_shown_is_only_compared_with_the_record() {
    use kr_protocol::receipt::ReceiptState;

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = page.call("question_read", read_params(&worker));
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    answered(read).await.expect("the questions");

    // The first answer goes out and its reply is lost. The page will name a send that is not this one.
    let asked = page.call(
        "question_answer",
        answer_params(&worker, 2, &choice("release")),
    );
    let call = link.expect(Method::QuestionAnswer).await;
    let recorded = call.action_id.expect("an identifier");
    drop(link);
    let kept = answered(asked).await.expect("the answer is kept");
    let drafted_at = kept["draft"]["drafted_at_ms"].clone();
    let claimed = kr_protocol::ids::ActionId::new(Uuid::from_bytes([9; 16]));
    assert_ne!(claimed, recorded, "the page names a send never recorded");
    let mut asked_about = Vec::new();

    // A kept answer's send naming it is refused, after the worker was asked about the recorded send.
    let wrong = page.call(
        "question_send_kept",
        json!({ "params": {
            "questionId": question_id().to_string(),
            "draftedAtMs": drafted_at,
            "acknowledged": claimed.to_string()
        } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::QuestionRead).await;
    link.answer(
        &call,
        &reads(&worker, vec![question(&worker, 2, QuestionState::Pending)]),
    )
    .await;
    read_of_the_recorded_receipt(
        &mut link,
        &mut asked_about,
        recorded,
        Some(receipt_of(recorded, ReceiptState::Unknown)),
    )
    .await;
    let refused = ends_without_asking_more(wrong, &mut link)
        .await
        .expect_err("another send is named");
    assert_eq!(code_of(&refused), "DRAFT_CONFLICT", "{refused}");

    // A new answer naming it is held, and what it says was found is the recorded send.
    let held = page.call(
        "question_answer",
        json!({
            "params": answer_params(&worker, 2, &choice("main"))["params"].clone(),
            "acknowledged": claimed.to_string()
        }),
    );
    read_of_the_recorded_receipt(
        &mut link,
        &mut asked_about,
        recorded,
        Some(receipt_of(recorded, ReceiptState::Unknown)),
    )
    .await;
    let told = ends_without_asking_more(held, &mut link)
        .await
        .expect("held, not refused");
    assert_eq!(told["outcome"], "held", "{told}");
    assert_eq!(told["action_id"], recorded.to_string(), "{told}");

    // The worker has no receipt of the recorded send, so no uncertain send is recorded: the
    // press that names one anyway goes out quoting none.
    let sending = page.call(
        "question_answer",
        json!({
            "params": answer_params(&worker, 2, &choice("main"))["params"].clone(),
            "acknowledged": claimed.to_string()
        }),
    );
    read_of_the_recorded_receipt(&mut link, &mut asked_about, recorded, None).await;
    let call = link.expect(Method::QuestionAnswer).await;
    let kr_cbor::CanonicalValue::Map(quoted) = call
        .expected
        .clone()
        .expect("a mutation's preconditions")
        .into_value()
    else {
        panic!("preconditions are a map");
    };
    assert!(
        quoted
            .get(kr_protocol::action::SUPERSEDES_ACTION_KEY)
            .is_none(),
        "the send quotes nothing, since the record holds no uncertain send"
    );
    link.answer(&call, &resolution(&worker, QuestionState::Answered))
        .await;
    let told = ends_without_asking_more(sending, &mut link)
        .await
        .expect("the worker took it");
    assert_eq!(told["outcome"], "taken", "{told}");

    assert_eq!(
        asked_about,
        vec![recorded; 3],
        "the worker is asked about the recorded send each time, and never about the one named"
    );
}
