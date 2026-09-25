//! Gemini CLI's and Qoder CLI's hooks through the forwarder and the worker's own listener.
//!
//! Every case launches a stand-in application through the worker's gateway, with the
//! application's bridge installed; the stand-in runs `kr-hook <application> hook` for each event,
//! with the payload that application writes, and the worker admits each hook as that application's
//! and applies the one observation it reports.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.20 | `kr_req_12_20_each_registered_gemini_cli_hook_observes_and_answers_neutrally` |
//! | KR-REQ-12.22 | `kr_req_12_22_each_registered_qoder_cli_hook_observes_and_answers_neutrally` |
//! | KR-REQ-12.27 | both of those: exactly `{}`, exit 0, nothing on standard error, inside the registered timeout |
//! | KR-REQ-05.09 | `kr_req_05_09_a_hook_is_admitted_only_as_the_application_it_was_installed_for` |

#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use common::Placed;
use common::launched::{self, Launch};
use kr_worker::broker::{BridgeSurface, HookReport, ObservedEvent, ThreadChange};

const FIRST_THREAD: &str = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";
const SECOND_THREAD: &str = "9b2e6f10-7c4d-4e8a-a1f3-2d5c8b0e4f22";

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

/// One event a registration names, what the worker should make of it, and the timeout the
/// registration gives it.
struct Case {
    payload: serde_json::Value,
    event: ObservedEvent,
    detail: Option<&'static str>,
    text: Option<&'static str>,
    contact_request: Option<&'static str>,
    thread: &'static str,
    change: fn(&ThreadChange) -> bool,
    timeout: Duration,
}

fn selected(change: &ThreadChange) -> bool {
    matches!(change, ThreadChange::Selected(_))
}

fn ended(change: &ThreadChange) -> bool {
    matches!(change, ThreadChange::Ended(_))
}

fn unchanged(change: &ThreadChange) -> bool {
    *change == ThreadChange::Unchanged
}

async fn observe_each(application: &str, cases: Vec<Case>) {
    let placed = Placed::new();
    let mut launch = Launch::start(
        &placed,
        &placed.forwarder,
        launched::installed_for(application, &placed.forwarder, &[BridgeSurface::Hook]),
    );
    let mut cursors = Vec::new();
    for case in cases {
        let (report, outcome, took) = hook(&mut launch, case.payload.to_string().as_bytes()).await;
        let named = format!("{application} {}", case.payload["hook_event_name"]);
        assert_eq!(report.observation.event, case.event, "{named}");
        assert_eq!(report.observation.thread.as_str(), case.thread, "{named}");
        assert_eq!(report.observation.detail.as_deref(), case.detail, "{named}");
        assert_eq!(report.observation.text.as_deref(), case.text, "{named}");
        assert_eq!(
            report.observation.contact_request.as_deref(),
            case.contact_request,
            "{named}"
        );
        assert!(
            (case.change)(&report.thread),
            "{named}: {:?}",
            report.thread
        );
        assert_eq!(outcome.code, 0, "{named}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, b"{}\n", "{named}");
        assert!(outcome.stderr.is_empty(), "{named}: {}", outcome.stderr);
        assert!(
            took < case.timeout,
            "{named} took {took:?}, past the {:?} the registration gives it",
            case.timeout
        );
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

/// KR-REQ-12.20, KR-REQ-12.27: the three events the Gemini CLI extension registers each run the
/// forwarder as Gemini CLI's hook, which reports its observation and answers exactly `{}` with
/// exit 0 and nothing on standard error, inside the registered timeout. A session starting
/// selects its thread, `/clear` starts another, a tool permission notification is recorded, and
/// the session ending leaves no thread selected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_20_each_registered_gemini_cli_hook_observes_and_answers_neutrally() {
    let base = |thread: &str, event: &str| {
        serde_json::json!({"session_id": thread, "transcript_path": "/tmp/t.jsonl", "cwd": "/tmp",
            "hook_event_name": event, "timestamp": "2026-09-25T17:39:42.013Z"})
    };
    let with = |mut payload: serde_json::Value, extra: serde_json::Value| {
        for (key, value) in extra.as_object().expect("members") {
            payload[key] = value.clone();
        }
        payload
    };
    observe_each(
        "gemini-cli",
        vec![
            Case {
                payload: with(
                    base(FIRST_THREAD, "SessionStart"),
                    serde_json::json!({"source": "startup"}),
                ),
                event: ObservedEvent::ThreadStarted,
                detail: Some("startup"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: selected,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base(FIRST_THREAD, "Notification"),
                    serde_json::json!({"notification_type": "ToolPermission",
                        "message": "Tool Shell requires execution",
                        "details": {"type": "exec", "title": "Shell", "command": "ls", "rootCommand": "ls"}}),
                ),
                event: ObservedEvent::Notification,
                detail: Some("ToolPermission"),
                text: Some("Tool Shell requires execution"),
                contact_request: None,
                thread: FIRST_THREAD,
                change: unchanged,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base(FIRST_THREAD, "SessionEnd"),
                    serde_json::json!({"reason": "clear"}),
                ),
                event: ObservedEvent::ThreadEnded,
                detail: Some("clear"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: ended,
                timeout: Duration::from_secs(1),
            },
            Case {
                payload: with(
                    base(SECOND_THREAD, "SessionStart"),
                    serde_json::json!({"source": "clear"}),
                ),
                event: ObservedEvent::ThreadStarted,
                detail: Some("clear"),
                text: None,
                contact_request: None,
                thread: SECOND_THREAD,
                change: selected,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base(SECOND_THREAD, "SessionEnd"),
                    serde_json::json!({"reason": "exit"}),
                ),
                event: ObservedEvent::ThreadEnded,
                detail: Some("exit"),
                text: None,
                contact_request: None,
                thread: SECOND_THREAD,
                change: ended,
                timeout: Duration::from_secs(1),
            },
        ],
    )
    .await;
}

/// KR-REQ-12.22, KR-REQ-12.27: each event Qoder CLI's hooks are registered for runs the forwarder
/// as Qoder CLI's hook, which reports its observation and answers exactly `{}` with exit 0 and
/// nothing on standard error, inside the registered timeout. A session starting selects its
/// thread and a compaction goes on in it; a finished tool, a failed one and a permission
/// notification are recorded; a finished call of the contact skill's `ask_user` names the request
/// it asked; the session ending leaves no thread selected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_22_each_registered_qoder_cli_hook_observes_and_answers_neutrally() {
    let base = |event: &str| {
        serde_json::json!({"session_id": FIRST_THREAD, "transcript_path": "/tmp/t.jsonl",
            "cwd": "/tmp", "hook_event_name": event, "permission_mode": "default"})
    };
    let with = |mut payload: serde_json::Value, extra: serde_json::Value| {
        for (key, value) in extra.as_object().expect("members") {
            payload[key] = value.clone();
        }
        payload
    };
    observe_each(
        "qoder-cli",
        vec![
            Case {
                payload: with(base("SessionStart"), serde_json::json!({"source": "startup"})),
                event: ObservedEvent::ThreadStarted,
                detail: Some("startup"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: selected,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base("PostToolUse"),
                    serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "ls"},
                        "tool_response": {"stdout": "a\n"}, "tool_use_id": "toolu_01"}),
                ),
                event: ObservedEvent::ToolFinished,
                detail: Some("Bash"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: unchanged,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base("PostToolUse"),
                    serde_json::json!({"tool_name": "mcp__kalareach__ask_user",
                        "tool_input": {"request_id": "r-7f3a", "question": "Which one?", "type": "input"},
                        "tool_response": {"content": []}, "tool_use_id": "toolu_02",
                        "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}),
                ),
                event: ObservedEvent::ToolFinished,
                detail: Some("mcp__kalareach__ask_user"),
                text: None,
                contact_request: Some("r-7f3a"),
                thread: FIRST_THREAD,
                change: unchanged,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base("PostToolUseFailure"),
                    serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "false"},
                        "tool_use_id": "toolu_03", "error": "Command exited with non-zero status code 1",
                        "error_type": "execution_failed", "is_interrupt": false}),
                ),
                event: ObservedEvent::ToolFailed,
                detail: Some("Bash"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: unchanged,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(
                    base("Notification"),
                    serde_json::json!({"notification_type": "permission_prompt",
                        "message": "Agent is requesting permission to run: ls",
                        "title": "Permission Required", "details": {}}),
                ),
                event: ObservedEvent::Notification,
                detail: Some("permission_prompt"),
                text: Some("Agent is requesting permission to run: ls"),
                contact_request: None,
                thread: FIRST_THREAD,
                change: unchanged,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(base("SessionStart"), serde_json::json!({"source": "compact"})),
                event: ObservedEvent::ThreadContinued,
                detail: Some("compact"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: unchanged,
                timeout: Duration::from_secs(5),
            },
            Case {
                payload: with(base("SessionEnd"), serde_json::json!({"reason": "other"})),
                event: ObservedEvent::ThreadEnded,
                detail: Some("other"),
                text: None,
                contact_request: None,
                thread: FIRST_THREAD,
                change: ended,
                timeout: Duration::from_secs(1),
            },
        ],
    )
    .await;
}

/// KR-REQ-05.09: a hook declares the application it was invoked for, and the worker admits it only
/// when that is the application the installation is for. Qoder CLI's forwarder, started under a
/// launch whose installed bridge is Gemini CLI's, is refused, and still answers `{}`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_05_09_a_hook_is_admitted_only_as_the_application_it_was_installed_for() {
    let placed = Placed::new();
    let mut launch = Launch::start_as(
        &placed,
        &placed.forwarder,
        "qoder-cli",
        launched::installed_for("gemini-cli", &placed.forwarder, &[BridgeSurface::Hook]),
    );
    let request = launch.hook(
        serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "SessionStart",
            "source": "startup"})
        .to_string()
        .as_bytes(),
    );
    let refused = launch
        .accept()
        .await
        .expect_err("a bridge for another application is refused");
    assert!(
        refused.to_string().contains("\"qoder-cli\"")
            && refused.to_string().contains("\"gemini-cli\""),
        "{refused}"
    );
    let outcome = launched::outcome(&request);
    assert_eq!((outcome.code, outcome.stdout.as_slice()), (0, &b"{}\n"[..]));
}
