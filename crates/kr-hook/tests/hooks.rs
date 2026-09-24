//! Claude Code's hooks through the forwarder and the worker's own listener, and what they do to
//! the session's thread binding.
//!
//! Every case launches a stand-in application through the worker's gateway, with the bridge
//! installed; the application runs `kr-hook claude-code hook` for each event, as Claude Code does,
//! and the worker admits each hook and applies the one observation it reports.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.42 | `kr_req_12_18_each_registered_hook_observes_and_answers_neutrally` |
//! | KR-REQ-12.18 | `kr_req_12_18_each_registered_hook_observes_and_answers_neutrally` |
//! | KR-REQ-11.62 | `kr_req_11_62_a_thread_switch_the_hooks_report_invalidates_the_questions_asked_under_the_old_thread` |

#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::Placed;
use common::launched::{self, Launch};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActorId, ConnectionId, SessionEpoch, SessionId};
use kr_protocol::question::{
    QuestionAnswer, QuestionAnswerParams, QuestionCreateParams, QuestionKind, QuestionReadParams,
    QuestionState,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use kr_worker::broker::{BridgeSurface, HookReport, ObservedEvent, ThreadChange};
use kr_worker::questions::{Now, Questions, VerifiedSource};

const FIRST_THREAD: &str = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";
const SECOND_THREAD: &str = "9b2e6f10-7c4d-4e8a-a1f3-2d5c8b0e4f22";

fn session_start(thread: &str, source: &str) -> Vec<u8> {
    serde_json::json!({
        "session_id": thread,
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/tmp",
        "hook_event_name": "SessionStart",
        "source": source,
    })
    .to_string()
    .into_bytes()
}

/// A finished `ask_user` call of the contact skill, as Claude Code reports it.
fn asked(thread: &str, request_id: &str) -> Vec<u8> {
    serde_json::json!({
        "session_id": thread,
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/tmp",
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__kalareach__ask_user",
        "tool_input": {"request_id": request_id, "question": "Which one?", "type": "input"},
        "tool_response": {"content": [{"type": "text", "text": "{\"question_id\":\"...\"}"}]},
        "tool_use_id": "toolu_01",
        "mcp_server": {"name": "kalareach", "source": "user"},
    })
    .to_string()
    .into_bytes()
}

/// Has the application run one hook, admits it, applies what it observed, and returns the report
/// with what the hook itself answered and how long the whole round took.
async fn hook(launch: &mut Launch, payload: &[u8]) -> (HookReport, launched::Outcome, Duration) {
    let started = Instant::now();
    let request = launch.hook(payload);
    let admitted = launch.accept().await.expect("the hook is admitted");
    assert_eq!(admitted.surface, BridgeSurface::Hook);
    let report = tokio::time::timeout(common::LIVENESS, launch.gateway.observe_hook(admitted))
        .await
        .expect("the observation arrives")
        .expect("and is applied");
    let outcome = tokio::task::spawn_blocking(move || launched::outcome(&request))
        .await
        .expect("the hook ended");
    (report, outcome, started.elapsed())
}

fn start(placed: &Placed) -> Launch {
    Launch::start(
        placed,
        &placed.forwarder,
        launched::installed(
            &placed.forwarder,
            &[BridgeSurface::Hook, BridgeSurface::Channel],
        ),
    )
}

/// KR-REQ-11.42, KR-REQ-12.18: each of the five events the package registers runs the forwarder,
/// which reports its observation to the worker and answers exactly `{}` with exit 0, with nothing
/// on standard error, well inside the timeout the package registers for it. The worker records
/// each in the instance's observed history, and only the session starting and ending touch the
/// thread binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_each_registered_hook_observes_and_answers_neutrally() {
    let placed = Placed::new();
    let mut launch = start(&placed);
    let events = [
        (
            session_start(FIRST_THREAD, "startup"),
            ObservedEvent::ThreadStarted,
            Duration::from_secs(5),
        ),
        (
            serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "PostToolUse",
                "tool_name": "Bash", "tool_input": {"command": "ls"},
                "tool_response": {"stdout": "a\nb\n"}, "tool_use_id": "toolu_02"})
            .to_string()
            .into_bytes(),
            ObservedEvent::ToolFinished,
            Duration::from_secs(5),
        ),
        (
            serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "PostToolUseFailure",
                "tool_name": "Bash", "tool_input": {"command": "false"}, "error": "Exit code 1",
                "is_interrupt": false})
            .to_string()
            .into_bytes(),
            ObservedEvent::ToolFailed,
            Duration::from_secs(5),
        ),
        (
            serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "Notification",
                "message": "Claude needs your permission", "title": "Permission needed",
                "notification_type": "permission_prompt"})
            .to_string()
            .into_bytes(),
            ObservedEvent::Notification,
            Duration::from_secs(5),
        ),
        (
            serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "SessionEnd",
                "reason": "other"})
            .to_string()
            .into_bytes(),
            ObservedEvent::ThreadEnded,
            Duration::from_secs(1),
        ),
    ];
    let mut cursors = Vec::new();
    for (payload, event, timeout) in events {
        let (report, outcome, took) = hook(&mut launch, &payload).await;
        assert_eq!(report.observation.event, event);
        assert_eq!(report.observation.thread.as_str(), FIRST_THREAD);
        assert_eq!(outcome.code, 0, "{event:?}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, b"{}\n", "{event:?}");
        assert!(outcome.stderr.is_empty(), "{event:?}: {}", outcome.stderr);
        assert!(
            took < timeout,
            "{event:?} took {took:?}, past the {timeout:?} the package registers"
        );
        match event {
            ObservedEvent::ThreadStarted => {
                assert!(matches!(report.thread, ThreadChange::Selected(_)));
            }
            ObservedEvent::ThreadEnded => {
                assert!(matches!(report.thread, ThreadChange::Ended(_)));
            }
            _ => assert_eq!(report.thread, ThreadChange::Unchanged),
        }
        cursors.push(report.cursor);
    }
    assert!(
        cursors.windows(2).all(|pair| pair[0] < pair[1]),
        "each observation is recorded after the last: {cursors:?}"
    );
    let state = launch
        .broker
        .binding_state(launched::instance())
        .expect("the instance");
    assert!(
        state.thread_id.as_ref().is_none(),
        "the session ended, so no thread is selected"
    );
}

fn now(utc_ms: u64) -> Now {
    Now {
        utc_ms: TimestampMs::new(utc_ms),
        boot_ms: utc_ms,
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn ask(request_id: &str) -> QuestionCreateParams {
    QuestionCreateParams {
        session_id: session(),
        request_id: request_id.to_owned(),
        agent_name: Nullable::null(),
        context: String::new(),
        question: "Which one?".to_owned(),
        kind: QuestionKind::Input,
        choices: Vec::new(),
        requested_expiry_ms: Nullable::null(),
        wait_ms: Nullable::null(),
    }
}

fn state_of(
    questions: &Questions,
    question_id: kr_protocol::ids::QuestionId,
    at: u64,
) -> QuestionState {
    questions
        .read(
            &QuestionReadParams {
                session_id: session(),
                question_id: Nullable(Some(question_id)),
                include_resolved: true,
            },
            now(at),
        )
        .expect("the answering surface reads")
        .0
        .questions
        .into_iter()
        .find(|question| question.question_id == question_id)
        .expect("the question")
        .state
}

/// KR-REQ-11.62: a question is asked in the thread the application's bridge last reported
/// selected, and the application's own hook later says which thread ran the `ask_user` call that
/// asked it. When the two agree, the question is bound to the revision it was asked under; a later
/// `SessionStart` hook reporting another thread advances the binding in production code, and the
/// question from the old thread is invalidated for every client, with a person's answer refused.
/// A question asked in the new thread stays open, and one no hook placed in a thread stays
/// application-scoped. A report of the call that arrives after the thread was left and selected
/// again still binds the question to the revision it was asked under, not to the later one; and a
/// question whose reports disagree, as a retry from another thread makes them, is bound to nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_62_a_thread_switch_the_hooks_report_invalidates_the_questions_asked_under_the_old_thread()
 {
    let placed = Placed::new();
    let mut launch = start(&placed);
    let questions = Questions::open(None, session(), SessionEpoch::V1)
        .expect("a ledger")
        .with_agents(Arc::clone(&launch.broker) as Arc<dyn kr_worker::questions::AgentBindings>);
    // The contact helper stands where Claude Code starts it, under the launched application.
    let application = kr_ipc::identity::process_start_identity(launch.application.id())
        .expect("the application's identity");
    let helper = VerifiedSource {
        process: application,
        executable: None,
        session_member: false,
        ancestry: false,
        launch_channel: false,
        connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
    };

    let (started, _, _) = hook(&mut launch, &session_start(FIRST_THREAD, "startup")).await;
    assert!(
        matches!(started.thread, ThreadChange::Selected(_)),
        "{:?}",
        started.thread
    );

    let (old, _) = questions
        .create(&helper, &ask("asked-in-the-first-thread"), now(1_000))
        .expect("asked");
    let (unplaced, _) = questions
        .create(&helper, &ask("never-placed"), now(1_000))
        .expect("asked");
    assert!(
        old.question
            .source
            .agent_binding_revision
            .as_ref()
            .is_none(),
        "when it is asked, nothing yet says which thread asked it"
    );
    let (_, outcome, _) = hook(
        &mut launch,
        &asked(FIRST_THREAD, "asked-in-the-first-thread"),
    )
    .await;
    assert_eq!(outcome.stdout, b"{}\n");
    assert!(questions.sweep(now(1_100)).expect("sweeps").is_empty());
    assert_eq!(
        state_of(&questions, old.question.question_id, 1_200),
        QuestionState::Pending,
        "the thread it was asked in is still selected"
    );

    // The person runs `/clear`: Claude Code ends the first thread and starts another.
    let (ended, _, _) = hook(
        &mut launch,
        &serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "SessionEnd",
            "reason": "clear"})
        .to_string()
        .into_bytes(),
    )
    .await;
    assert!(
        matches!(ended.thread, ThreadChange::Ended(_)),
        "{:?}",
        ended.thread
    );
    let (switched, outcome, _) = hook(&mut launch, &session_start(SECOND_THREAD, "clear")).await;
    assert!(
        matches!(switched.thread, ThreadChange::Selected(_)),
        "{:?}",
        switched.thread
    );
    assert_eq!(outcome.stdout, b"{}\n");

    let (new, _) = questions
        .create(&helper, &ask("asked-in-the-second-thread"), now(2_000))
        .expect("asked");
    hook(
        &mut launch,
        &asked(SECOND_THREAD, "asked-in-the-second-thread"),
    )
    .await;

    // Every client reads the question from the old thread invalidated.
    assert_eq!(
        state_of(&questions, old.question.question_id, 2_100),
        QuestionState::Expired
    );
    assert_eq!(
        state_of(&questions, new.question.question_id, 2_100),
        QuestionState::Pending
    );
    assert_eq!(
        state_of(&questions, unplaced.question.question_id, 2_100),
        QuestionState::Pending,
        "a question no hook placed in a thread claims no thread-switch detection"
    );
    let refused = questions
        .answer(
            &ActorId::new("local:501").expect("a principal"),
            None,
            &QuestionAnswerParams {
                session_id: session(),
                question_id: old.question.question_id,
                expected_revision: old.question.revision,
                answer: QuestionAnswer::Input {
                    text: "the first".to_owned(),
                },
            },
            now(2_200),
        )
        .expect_err("an answer to the invalidated question is refused");
    assert_eq!(refused.code(), ErrorCode::QuestionExpired);

    // Asked in the second thread; the person resumes the first and returns to the second before
    // the call's report arrives. The report binds the question to the second thread's revision
    // when it was asked, which has been left, so it is invalidated, although the second thread is
    // selected again.
    let (late, _) = questions
        .create(&helper, &ask("reported-late"), now(3_000))
        .expect("asked");
    hook(&mut launch, &session_start(FIRST_THREAD, "resume")).await;
    let (back, _, _) = hook(&mut launch, &session_start(SECOND_THREAD, "resume")).await;
    assert!(
        matches!(back.thread, ThreadChange::Selected(_)),
        "{:?}",
        back.thread
    );
    hook(&mut launch, &asked(SECOND_THREAD, "reported-late")).await;
    assert_eq!(
        state_of(&questions, late.question.question_id, 3_100),
        QuestionState::Expired
    );

    // Asked in the second thread, and reported both from another thread (a retry the agent made
    // there, which returns this same question) and from its own: the reports disagree, so the
    // question is bound to nothing and a switch does not invalidate it.
    let (retried, _) = questions
        .create(&helper, &ask("retried"), now(4_000))
        .expect("asked");
    let (again, _) = questions
        .create(&helper, &ask("retried"), now(4_001))
        .expect("the exact retry");
    assert!(
        again.deduplicated,
        "a retry returns the question it asked before"
    );
    hook(&mut launch, &asked(FIRST_THREAD, "retried")).await;
    hook(&mut launch, &asked(SECOND_THREAD, "retried")).await;
    // Asked while the first thread is selected, and reported only from the second: the report
    // does not name the thread it was asked in, so it binds nothing either.
    hook(&mut launch, &session_start(FIRST_THREAD, "resume")).await;
    let (elsewhere, _) = questions
        .create(&helper, &ask("reported-from-elsewhere"), now(4_050))
        .expect("asked");
    hook(
        &mut launch,
        &asked(SECOND_THREAD, "reported-from-elsewhere"),
    )
    .await;
    hook(&mut launch, &session_start(SECOND_THREAD, "resume")).await;
    for unbound in [retried.question.question_id, elsewhere.question.question_id] {
        assert_eq!(state_of(&questions, unbound, 4_100), QuestionState::Pending);
    }
}
