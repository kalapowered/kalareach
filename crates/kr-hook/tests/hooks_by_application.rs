//! Hooks of Gemini CLI, Qoder CLI and a third application through the forwarder and the worker's own
//! listener.
//!
//! Every case launches a stand-in application through the worker's gateway, with the
//! application's bridge installed; the stand-in runs `kr-hook <application> hook` for each event,
//! with the payload that application writes, and the worker admits each hook as that application's
//! and applies the one observation it reports.

mod common;

use std::time::Duration;

use common::Placed;
use common::launched::{self, Launch};
use kr_worker::broker::connectors::{InstalledConnector, fixture};
use kr_worker::broker::{BridgeSurface, HookReport, ObservedEvent, ThreadChange};

const FIRST_THREAD: &str = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";
const SECOND_THREAD: &str = "9b2e6f10-7c4d-4e8a-a1f3-2d5c8b0e4f22";

/// Why a hook was not observed.
enum Missed {
    /// The hook ended before it was admitted: what it exited with and said.
    Ended(launched::Outcome),
    /// The worker refused the hook, or could not apply what it observed.
    Gateway(String),
    /// Nothing happened within the liveness bound.
    TimedOut,
}

impl std::fmt::Debug for Missed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ended(outcome) => write!(
                formatter,
                "the hook ended with exit code {} before it was admitted: {}",
                outcome.code, outcome.stderr
            ),
            Self::Gateway(why) => write!(formatter, "the worker did not take the hook: {why}"),
            Self::TimedOut => write!(formatter, "nothing happened within the liveness bound"),
        }
    }
}

/// Has the application run one hook, admits it, applies what it observed, and returns the report
/// with what the hook itself answered. A hook that ends before it connects, a refusal and a bound
/// that passes are returned and never panic here, so the case that asked decides what they mean.
async fn hook(
    launch: &mut Launch,
    payload: &[u8],
) -> Result<(HookReport, launched::Outcome), Missed> {
    let request = launch.hook(payload);
    let mut ending = tokio::task::spawn_blocking({
        let request = request.clone();
        move || launched::outcome(&request)
    });
    let admitted = tokio::select! {
        admitted = launch.gateway.accept_bridge() => {
            admitted.map_err(|error| Missed::Gateway(error.to_string()))?
        }
        ended = &mut ending => return Err(ended.map_or(Missed::TimedOut, Missed::Ended)),
        () = tokio::time::sleep(common::LIVENESS) => return Err(Missed::TimedOut),
    };
    if admitted.surface != BridgeSurface::Hook {
        return Err(Missed::Gateway(format!(
            "admitted as {:?}, not as a hook",
            admitted.surface
        )));
    }
    let report =
        match tokio::time::timeout(common::LIVENESS, launch.gateway.observe_hook(admitted)).await {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => return Err(Missed::Gateway(error.to_string())),
            Err(_) => return Err(Missed::TimedOut),
        };
    let outcome = ending.await.map_err(|_| Missed::TimedOut)?;
    Ok((report, outcome))
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

/// The cases a launch ran, what the worker applied for each and what each hook answered, and
/// whether a thread is selected after the last.
struct Observations {
    cases: Vec<Case>,
    seen: Vec<(HookReport, launched::Outcome)>,
    thread_selected: bool,
}

/// Runs each case's hook on `launch` and returns what came of them; it asserts nothing.
async fn observe_on(launch: &mut Launch, cases: Vec<Case>) -> Result<Observations, Missed> {
    let mut seen = Vec::new();
    for case in &cases {
        seen.push(hook(launch, case.payload.to_string().as_bytes()).await?);
    }
    let thread_selected = launch
        .broker
        .binding_state(launched::instance())
        .expect("the instance")
        .thread_id
        .as_ref()
        .is_some();
    Ok(Observations {
        cases,
        seen,
        thread_selected,
    })
}

/// Launches the stand-in with the bridge installed for `application`, and runs the cases on it.
async fn observe(application: &str, cases: Vec<Case>) -> Result<Observations, Missed> {
    let placed = Placed::new();
    let mut launch = Launch::start(
        &placed,
        &placed.forwarder,
        launched::installed_for(application, &placed.forwarder, &[BridgeSurface::Hook]),
    );
    observe_on(&mut launch, cases).await
}

/// What each case claims, held against what came of it.
fn assert_observed(application: &str, observed: &Observations) {
    let mut cursors = Vec::new();
    for (case, (report, outcome)) in observed.cases.iter().zip(&observed.seen) {
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
        // The hook's stderr is empty, so it answered from what the worker applied and not at its
        // deadline, which with the allowance after it is inside the timeout the registration gives.
        common::assert_answered_in_time(&outcome.stderr, case.timeout, &named);
        cursors.push(report.cursor);
    }
    assert!(
        cursors.windows(2).all(|pair| pair[0] < pair[1]),
        "each observation is recorded after the last: {cursors:?}"
    );
    assert!(
        !observed.thread_selected,
        "the session ended, so no thread is selected"
    );
}

async fn observe_each(application: &str, cases: Vec<Case>) {
    match observe(application, cases).await {
        Ok(observed) => assert_observed(application, &observed),
        Err(missed) => panic!("{application}: {missed:?}"),
    }
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

/// One event of a third application's hooks, with the answer the case expects.
fn amp_case(
    payload: serde_json::Value,
    event: ObservedEvent,
    detail: Option<&'static str>,
    text: Option<&'static str>,
    change: fn(&ThreadChange) -> bool,
) -> Case {
    Case {
        payload,
        event,
        detail,
        text,
        contact_request: None,
        thread: FIRST_THREAD,
        change,
        timeout: Duration::from_secs(5),
    }
}

/// KR-REQ-11.44, KR-REQ-11.01: a hook for an application the forwarder has no table for runs as
/// that application: the worker admits each of its events as it, and applies the observation the
/// one vocabulary gives. A session starting selects its thread, a notification and a tool finishing
/// or failing are recorded, a start from `compact` continues the thread, and the session ending
/// leaves none selected; each hook answers exactly `{}` with exit 0 and nothing on standard error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_44_a_hook_for_a_third_application_is_admitted_as_that_application() {
    let event = |name: &str, extra: serde_json::Value| {
        let mut payload = serde_json::json!({"session_id": FIRST_THREAD,
            "transcript_path": "/tmp/t.jsonl", "cwd": "/tmp", "hook_event_name": name});
        for (key, value) in extra.as_object().expect("members") {
            payload[key] = value.clone();
        }
        payload
    };
    let cases = vec![
        amp_case(
            event("SessionStart", serde_json::json!({"source": "startup"})),
            ObservedEvent::ThreadStarted,
            Some("startup"),
            None,
            selected,
        ),
        amp_case(
            event(
                "Notification",
                serde_json::json!({"notification_type": "permission_prompt", "message": "Needs permission"}),
            ),
            ObservedEvent::Notification,
            Some("permission_prompt"),
            Some("Needs permission"),
            unchanged,
        ),
        amp_case(
            event("PostToolUse", serde_json::json!({"tool_name": "Bash"})),
            ObservedEvent::ToolFinished,
            Some("Bash"),
            None,
            unchanged,
        ),
        amp_case(
            event(
                "PostToolUseFailure",
                serde_json::json!({"tool_name": "Bash", "error": "Exit code 1"}),
            ),
            ObservedEvent::ToolFailed,
            Some("Bash"),
            None,
            unchanged,
        ),
        amp_case(
            event("SessionStart", serde_json::json!({"source": "compact"})),
            ObservedEvent::ThreadContinued,
            Some("compact"),
            None,
            unchanged,
        ),
        amp_case(
            event("SessionEnd", serde_json::json!({"reason": "clear"})),
            ObservedEvent::ThreadEnded,
            Some("clear"),
            None,
            ended,
        ),
    ];
    let observed = match observe("amp", cases).await {
        Ok(observed) => observed,
        Err(Missed::Ended(outcome)) => panic!(
            "the hook for amp ended with exit code {} before it was admitted: {}",
            outcome.code, outcome.stderr
        ),
        Err(other) => panic!("the hook for amp was not observed: {other:?}"),
    };
    for (case, (report, outcome)) in observed.cases.iter().zip(&observed.seen) {
        let named = format!("amp {}", case.payload["hook_event_name"]);
        assert_eq!(report.observation.event, case.event, "{named}");
        assert_eq!(report.observation.thread.as_str(), case.thread, "{named}");
        assert_eq!(report.observation.detail.as_deref(), case.detail, "{named}");
        assert_eq!(report.observation.text.as_deref(), case.text, "{named}");
        assert!(
            (case.change)(&report.thread),
            "{named}: {:?}",
            report.thread
        );
        assert_eq!(outcome.code, 0, "{named}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, b"{}\n", "{named}");
        assert!(outcome.stderr.is_empty(), "{named}: {}", outcome.stderr);
    }
    assert!(
        !observed.thread_selected,
        "the session ended, so no thread is selected"
    );
}

/// KR-REQ-11.44, KR-REQ-11.01: a package that installs no native bridge, and whose own launch
/// registers the forwarder's hook, is admitted under its plugin name, with no change to a table:
/// the registered arguments are read from the package's own flag, the stand-in runs them, and the
/// worker applies what the hooks observe as that application's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_44_a_package_with_no_native_bridge_is_admitted_under_its_plugin_name_and_observed()
 {
    let placed = Placed::new();
    let handler = serde_json::json!({"type": "command",
        "command": kr_plugin_sdk::forwarder::PLACEHOLDER, "args": ["amp-cli", "hook"], "timeout": 5});
    let settings = serde_json::json!({"hooks": {
        "SessionStart": [{"hooks": [handler.clone()]}],
        "Notification": [{"hooks": [handler]}],
    }})
    .to_string();
    let directory = placed.host.root().join("amp-package");
    std::fs::create_dir_all(&directory).expect("the package's directory");
    let source = fixture::package(
        &directory,
        &placed.forwarder,
        &fixture::Shape {
            plugin_name: "amp-cli",
            display_name: "Amp CLI",
            executable: "amp-cli",
            directory: &[],
            integration: Some(fixture::declaration(
                "amp-cli",
                &["--settings", &settings],
                &[],
            )),
            ..fixture::Shape::qoder_cli()
        },
    )
    .expect("the package is written");
    let connector = match InstalledConnector::read(source) {
        Ok(connector) => connector,
        Err(refusal) => panic!("the package is refused: {}", refusal.detail),
    };
    let Some(bridge) = connector.launch_bridge(&placed.forwarder) else {
        panic!("a package with no native bridge gets its own hook");
    };
    assert_eq!(bridge.application, "amp-cli");
    assert_eq!(bridge.surfaces, [BridgeSurface::Hook].into_iter().collect());

    // The arguments the package registers are read from its own flag.
    let registered: serde_json::Value = serde_json::from_str(&settings).expect("the flag is JSON");
    let args: Vec<&str> = registered["hooks"]["SessionStart"][0]["hooks"][0]["args"]
        .as_array()
        .expect("an argument list")
        .iter()
        .map(|argument| argument.as_str().expect("text"))
        .collect();
    assert_eq!(args, ["amp-cli", "hook"]);

    let mut launch = Launch::start_as(&placed, &placed.forwarder, args[0], bridge);
    let cases = vec![
        amp_case(
            serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "SessionStart",
                "source": "startup"}),
            ObservedEvent::ThreadStarted,
            Some("startup"),
            None,
            selected,
        ),
        amp_case(
            serde_json::json!({"session_id": FIRST_THREAD, "hook_event_name": "Notification",
                "notification_type": "permission_prompt", "message": "Needs permission"}),
            ObservedEvent::Notification,
            Some("permission_prompt"),
            Some("Needs permission"),
            unchanged,
        ),
    ];
    let observed = match observe_on(&mut launch, cases).await {
        Ok(observed) => observed,
        Err(Missed::Ended(outcome)) => panic!(
            "the hook ended with exit code {} before it was admitted: {}",
            outcome.code, outcome.stderr
        ),
        Err(other) => panic!("the hook was not observed: {other:?}"),
    };
    for (case, (report, outcome)) in observed.cases.iter().zip(&observed.seen) {
        let named = format!("amp-cli {}", case.payload["hook_event_name"]);
        assert_eq!(report.observation.event, case.event, "{named}");
        assert_eq!(report.observation.detail.as_deref(), case.detail, "{named}");
        assert_eq!(report.observation.text.as_deref(), case.text, "{named}");
        assert!(
            (case.change)(&report.thread),
            "{named}: {:?}",
            report.thread
        );
        assert_eq!(outcome.code, 0, "{named}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, b"{}\n", "{named}");
    }
}
