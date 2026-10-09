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
    assert_eq!(kept, json!([]), "an answer the worker took is not kept");
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
    assert_eq!(kept, json!([]));
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
    assert_eq!(kept, json!([]));
}

/// A worker that goes away before it answers the answer: the answer is kept on this device, the
/// page is told it is kept and not sent, and when the worker is back a settling only says whether
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
    drop(link);
    let told = answered(asked).await.expect("the answer is kept");
    assert_eq!(told["outcome"], "kept");
    assert_eq!(told["draft"]["question_revision"], "2");
    assert_eq!(told["draft"]["answer"]["choice_id"], "release");
    let drafted_at = told["draft"]["drafted_at_ms"].clone();

    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept.as_array().map(Vec::len), Some(1));
    assert_eq!(kept[0]["question_id"], question_id().to_string());

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
        kept,
        json!([]),
        "an answer the worker took is no longer kept"
    );
}

/// A question that ended or moved while the answer was kept is not answered, and the answer is not
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
    link.expect(Method::QuestionAnswer).await;
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
    let refused = answered(sending).await.expect_err("the question ended");
    assert_eq!(code_of(&refused), "QUESTION_RESOLVED");
    assert!(link.quiet_for(Duration::from_millis(300)).await);

    // Still kept: the text is the person's until they dismiss it.
    let kept = answered(page.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept.as_array().map(Vec::len), Some(1));
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
    assert_eq!(kept, json!([]));
}

/// A new application over the same place finds the answer a previous run kept: it lives on this
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
    state.questions().keep_at(kept.path().to_path_buf());
    let next = Page::over(state, worker.paths(), kept);
    let kept = answered(next.call("question_kept", json!({})))
        .await
        .expect("the kept answers");
    assert_eq!(kept.as_array().map(Vec::len), Some(1));
    assert_eq!(kept[0]["answer"]["choice_id"], "main");
}
