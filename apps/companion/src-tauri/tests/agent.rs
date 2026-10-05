//! The agent's calls, on the session's own worker, made the way the page makes them.
//!
//! Each test calls a command through the invoke path, as the page does, and the session's worker is
//! one this test scripts, over a real local endpoint in a disposable host tree on the internal
//! disk. The worker has to prove the key its descriptor names before anything reaches it, and it
//! decodes every call it is sent into the method's own type. So what is checked is the whole of the
//! native half: the link, the proof, the read or mutation each command makes, the envelope a
//! mutation carries, and the answer the page is given.

#![cfg(unix)]

mod scripted_worker;

use std::time::Duration;

use kr_protocol::agent::{
    AgentApprovalInspectParams, AgentApprovalRespondParams, AgentBindingState, AgentCancelParams,
    AgentCapabilitiesParams, AgentCommand, AgentCommandsParams, AgentCommandsResult,
    AgentMutationResult, AgentPromptParams, AgentSnapshotEntry, AgentSnapshotParams,
    AgentSnapshotResult, AgentSteerParams,
};
use kr_protocol::attachment::GeometryState;
use kr_protocol::broker::{ActionProvenance, IntegrationMode};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DownstreamRequestId, NativeClassification, NativeMethodClass, PendingKind, PendingResource,
    PendingState,
};
use kr_protocol::ids::{
    AgentBindingRevision, AgentTurnId, ApplicationInstanceId, GatewayConnectionId, GeometryEpoch,
    InputLeaseEpoch, InputSequence, PendingResourceId, SessionId, SourceGeneration, UpstreamMethod,
    UpstreamRequestId,
};
use kr_protocol::input::InputLeaseState;
use kr_protocol::method::Method;
use kr_protocol::projection::{AgentInstanceList, AgentResourceSnapshot};
use kr_protocol::recovery::{
    EventsSnapshotParams, EventsSnapshotResult, HistoryPageParams, HistoryPageResult,
};
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{
    Dimensions, DisplayNumber, Durability, SessionState, SessionSummary, ShellMode,
};
use scripted_worker::{CallKind, Challenge, ScriptedWorker};
use serde_json::{Value, json};
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// Where the bundle's pages are served from.
const BUNDLE: &str = "tauri://localhost";

/// How long a worker that should be sent nothing is watched.
const QUIET: Duration = Duration::from_millis(300);

/// The page: an application with the agent's commands, reaching the workers of one host tree.
struct Page {
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
}

impl Page {
    fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        let app = tauri::test::mock_builder()
            .manage(companion_tauri::AppState::new())
            .manage(companion_tauri::agent::WorkerLinks::at(paths))
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::agent_capabilities,
                companion_tauri::commands::agent_snapshot,
                companion_tauri::commands::agent_commands,
                companion_tauri::commands::agent_approval_inspect,
                companion_tauri::commands::agent_prompt_submit,
                companion_tauri::commands::agent_prompt_queue,
                companion_tauri::commands::agent_turn_steer,
                companion_tauri::commands::agent_turn_cancel,
                companion_tauri::commands::agent_approval_respond,
                companion_tauri::commands::session_agents,
                companion_tauri::commands::history_page,
                companion_tauri::commands::action_read,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self { app, window }
    }

    /// Calls `command` as the page does, on a thread of its own, since its answer waits for the
    /// worker this test is scripting.
    fn call(
        &self,
        command: &'static str,
        body: Value,
    ) -> tokio::task::JoinHandle<Result<Value, Value>> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let window = self.window.clone();
        tokio::task::spawn_blocking(move || {
            tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .map(|answer| answer.deserialize().expect("an answer the page reads"))
        })
    }

    /// How many sessions the application holds a link to.
    fn links(&self) -> usize {
        self.app
            .state::<companion_tauri::agent::WorkerLinks>()
            .held()
    }
}

/// What a call answered, once it has.
async fn answered(call: tokio::task::JoinHandle<Result<Value, Value>>) -> Result<Value, Value> {
    tokio::time::timeout(scripted_worker::WATCHDOG, call)
        .await
        .expect("the command answered within the watchdog")
        .expect("the command's thread finished")
}

/// The code a refused call carries.
fn code_of(refusal: &Value) -> &str {
    refusal["code"].as_str().unwrap_or("not a refusal")
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn revision() -> AgentBindingRevision {
    AgentBindingRevision::new(4)
}

fn turn() -> AgentTurnId {
    AgentTurnId::new("turn-9").expect("a turn identifier")
}

fn binding() -> AgentBindingState {
    AgentBindingState {
        binding_revision: revision(),
        thread_id: Nullable::null(),
        turn_id: Nullable::some(turn()),
        profile_id: Nullable::null(),
        mode: IntegrationMode::Gateway,
        rich_mutations_suspended: false,
        suspension_reason: Nullable::null(),
    }
}

/// The subject every agent call about `worker`'s session names, as the page writes it.
fn subject(worker: &ScriptedWorker) -> Value {
    json!({
        "session_id": worker.session_id.to_string(),
        "application_instance_id": instance().to_string(),
    })
}

/// The target every agent mutation about `worker`'s session names, as the page writes it.
fn target(worker: &ScriptedWorker) -> Value {
    json!({ "subject": subject(worker), "binding_revision": revision().get().to_string() })
}

fn mutated() -> AgentMutationResult {
    AgentMutationResult {
        binding_revision: revision(),
        provenance: ActionProvenance::UpstreamTypedRpc,
        upstream_request_id: Nullable::null(),
        turn_id: Nullable::some(turn()),
    }
}

/// KR-REQ-13.12: a read of the agent goes to the session's own worker, after the worker proved its
/// key, as a read carrying exactly the parameters the page sent, and the page is given the
/// worker's answer in the method's own shape.
#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_is_read_on_the_sessions_own_worker_with_the_pages_parameters() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let asked = page.call(
        "agent_snapshot",
        json!({ "params": { "subject": subject(&worker), "from_node": "3" } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::AgentSnapshot).await;
    assert_eq!(call.kind, CallKind::Request, "a snapshot is a read");
    let params: AgentSnapshotParams = call.params();
    assert_eq!(params.subject.session_id, worker.session_id);
    assert_eq!(params.subject.application_instance_id, instance());
    assert_eq!(params.from_node.as_ref().map(|node| node.get()), Some(3));
    let snapshot = AgentSnapshotResult {
        binding: binding(),
        entries: vec![AgentSnapshotEntry {
            node: U64::new(3),
            kind: "message".to_owned(),
            text: "Found it: the test waits on a timer.".to_owned(),
            omitted_text_bytes: U64::ZERO,
            observed_at: TimestampMs::new(7),
            binding_revision: revision(),
            turn_id: Nullable::some(turn()),
        }],
        continuation: Nullable::null(),
        history_gap: false,
        withheld_entries: U64::new(1),
    };
    link.answer(&call, &snapshot).await;
    assert_eq!(
        answered(asked).await.expect("the snapshot"),
        serde_json::to_value(&snapshot).expect("the snapshot's JSON")
    );
    assert_eq!(
        page.links(),
        1,
        "the session's link is held for the next call"
    );
}

/// KR-REQ-13.12: the agent's other reads go to the same worker, each as the read it is, and all of
/// them on the one link the session's first call opened.
#[tokio::test(flavor = "multi_thread")]
async fn every_agent_read_goes_to_the_sessions_worker_on_one_link() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());

    let asked = page.call(
        "agent_commands",
        json!({ "params": { "subject": subject(&worker) } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::AgentCommands).await;
    assert_eq!(call.kind, CallKind::Request);
    let _: AgentCommandsParams = call.params();
    let commands = AgentCommandsResult {
        binding: binding(),
        commands: vec![AgentCommand {
            name: "compact".to_owned(),
            summary: "Shorten the conversation so far".to_owned(),
            parameter_encoding: "none".to_owned(),
        }],
    };
    link.answer(&call, &commands).await;
    assert_eq!(
        answered(asked).await.expect("the commands"),
        serde_json::to_value(&commands).expect("JSON")
    );

    let asked = page.call(
        "agent_capabilities",
        json!({ "params": { "subject": subject(&worker) } }),
    );
    let call = link.expect(Method::AgentCapabilities).await;
    assert_eq!(call.kind, CallKind::Request);
    let _: AgentCapabilitiesParams = call.params();
    link.refuse_with(&call, ErrorCode::StaleSession, "that instance has ended")
        .await;
    let refused = answered(asked).await.expect_err("the worker's refusal");
    assert_eq!(code_of(&refused), "STALE_SESSION");

    let resource = PendingResourceId::new(Uuid::from_bytes([7; 16]));
    let asked = page.call(
        "agent_approval_inspect",
        json!({ "params": { "subject": subject(&worker), "resource_id": resource.to_string() } }),
    );
    let call = link.expect(Method::AgentApprovalInspect).await;
    assert_eq!(call.kind, CallKind::Request);
    let params: AgentApprovalInspectParams = call.params();
    assert_eq!(params.resource_id, resource);
    link.refuse_with(&call, ErrorCode::StaleSession, "no such request")
        .await;
    assert_eq!(
        code_of(&answered(asked).await.expect_err("refused")),
        "STALE_SESSION"
    );

    assert!(
        !worker.connected(),
        "a refusal on the link leaves the link standing"
    );
    assert_eq!(page.links(), 1);
}

/// KR-REQ-13.12: each composer action is its own mutation on the session's worker, and its envelope
/// names what the parameters name and nothing the page chose: the worker's environment, its session
/// at its epoch, the instance and the binding revision the action was prepared against.
#[tokio::test(flavor = "multi_thread")]
async fn each_agent_mutation_names_the_workers_session_the_instance_and_the_revision() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let actions: [(&'static str, Method, Value); 5] = [
        (
            "agent_prompt_submit",
            Method::AgentPromptSubmit,
            json!({ "target": target(&worker), "draft_id": null, "text": "Try the subscription." }),
        ),
        (
            "agent_prompt_queue",
            Method::AgentPromptQueue,
            json!({ "target": target(&worker), "draft_id": null, "text": "Then run the suite." }),
        ),
        (
            "agent_turn_steer",
            Method::AgentTurnSteer,
            json!({ "target": target(&worker), "turn_id": turn().to_string(), "text": "Only the one test." }),
        ),
        (
            "agent_turn_cancel",
            Method::AgentTurnCancel,
            json!({ "target": target(&worker), "turn_id": turn().to_string() }),
        ),
        (
            "agent_approval_respond",
            Method::AgentApprovalRespond,
            json!({
                "target": target(&worker),
                "resource_id": PendingResourceId::new(Uuid::from_bytes([7; 16])).to_string(),
                "option_id": "allow_once"
            }),
        ),
    ];
    let mut link = None;
    for (command, method, params) in actions {
        let asked = page.call(command, json!({ "params": params }));
        if link.is_none() {
            link = Some(worker.link().await);
        }
        let link = link.as_mut().expect("the session's link");
        let call = link.expect(method).await;
        assert_eq!(call.kind, CallKind::Mutation, "{command} is a mutation");
        let target = call.target.clone().expect("a mutation's envelope");
        assert_eq!(target.environment_id, worker.descriptor.environment_id);
        assert_eq!(target.session_id.as_ref(), Some(&worker.session_id));
        assert_eq!(
            target.session_epoch.as_ref(),
            Some(&worker.descriptor.session_epoch)
        );
        assert_eq!(target.application_instance_id.as_ref(), Some(&instance()));
        assert_eq!(target.agent_binding_revision.as_ref(), Some(&revision()));
        match method {
            Method::AgentPromptSubmit | Method::AgentPromptQueue => {
                let _: AgentPromptParams = call.params();
            }
            Method::AgentTurnSteer => {
                let _: AgentSteerParams = call.params();
            }
            Method::AgentTurnCancel => {
                let _: AgentCancelParams = call.params();
            }
            _ => {
                let _: AgentApprovalRespondParams = call.params();
            }
        }
        link.answer(&call, &mutated()).await;
        let settled = answered(asked).await.expect("the worker's answer");
        assert_eq!(settled["receipt"], Value::Null);
        assert_eq!(
            settled["value"],
            serde_json::to_value(mutated()).expect("JSON"),
            "{command} is answered with the method's own result"
        );
    }
    assert!(!worker.connected(), "every action went on the one link");
}

/// KR-REQ-10.01: a prompt that names both a draft and text, or neither, is refused before anything
/// is sent: no link is opened for it, and the worker is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_that_names_both_a_draft_and_text_or_neither_reaches_nothing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let draft = "55555555-5555-4555-8555-555555555555";
    for params in [
        json!({ "target": target(&worker), "draft_id": draft, "text": "and text" }),
        json!({ "target": target(&worker), "draft_id": null, "text": null }),
    ] {
        let refused = answered(page.call("agent_prompt_submit", json!({ "params": params })))
            .await
            .expect_err("refused before it is sent");
        assert_eq!(code_of(&refused), "INVALID_ARGUMENT");
    }
    tokio::time::sleep(QUIET).await;
    assert!(!worker.connected(), "nothing reached the worker");
    assert_eq!(page.links(), 0);
}

/// KR-REQ-14.11: a prompt that names a draft never goes to the session's worker on a link of this
/// application's own. It goes through the host's control daemon, which records where the draft's
/// attachments go before it passes the prompt on, so with no connection to that daemon the prompt
/// is refused and the worker is sent nothing and is not even connected to.
#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_that_names_a_draft_never_goes_to_the_worker_directly() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let draft = "55555555-5555-4555-8555-555555555555";
    for command in ["agent_prompt_submit", "agent_prompt_queue"] {
        let params = json!({ "target": target(&worker), "draft_id": draft, "text": null });
        let refused = answered(page.call(command, json!({ "params": params })))
            .await
            .expect_err("there is no host to record the draft with");
        assert_eq!(code_of(&refused), "HOST_NOT_CONFIGURED", "{command}");
    }
    tokio::time::sleep(QUIET).await;
    assert!(!worker.connected(), "nothing reached the worker");
    assert_eq!(page.links(), 0);
}

/// Section 13's boundary: a worker that cannot prove the key its descriptor names is refused, and
/// nothing is sent to it; a session with no worker on this computer is an unknown session.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_cannot_prove_its_key_or_no_worker_at_all_reaches_nothing() {
    let mut forged = ScriptedWorker::start(Challenge::Forged);
    let page = Page::new(forged.paths());
    let refused = answered(page.call(
        "agent_snapshot",
        json!({ "params": { "subject": subject(&forged), "from_node": null } }),
    ))
    .await
    .expect_err("an impostor is refused");
    assert_eq!(code_of(&refused), "RESOURCE_UNAVAILABLE");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|message| message.contains("could not prove who it is")),
        "{refused}"
    );
    // The worker answered the challenge with another key's signature, and the application closed
    // the link having asked it for nothing.
    let mut link = forged.link().await;
    assert!(
        link.closed().await.is_empty(),
        "the worker was asked for nothing"
    );
    assert_eq!(
        page.links(),
        0,
        "no link is held for a worker that did not prove itself"
    );

    let nobody = SessionId::new(kr_ipc::new_uuid());
    let refused = answered(page.call(
        "agent_snapshot",
        json!({ "params": {
            "subject": { "session_id": nobody.to_string(), "application_instance_id": instance().to_string() },
            "from_node": null
        } }),
    ))
    .await
    .expect_err("no worker is running for it");
    assert_eq!(code_of(&refused), "UNKNOWN_SESSION");
}

/// A link whose worker went away is let go, and the next call opens a new one to the worker that
/// is there now.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_ended_is_let_go_and_the_next_call_opens_another() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let read = |page: &Page, worker: &ScriptedWorker| {
        page.call(
            "agent_commands",
            json!({ "params": { "subject": subject(worker) } }),
        )
    };
    let commands = AgentCommandsResult {
        binding: binding(),
        commands: Vec::new(),
    };

    let asked = read(&page, &worker);
    let mut link = worker.link().await;
    let call = link.expect(Method::AgentCommands).await;
    link.answer(&call, &commands).await;
    answered(asked).await.expect("the first answer");
    // The worker ends the connection.
    drop(link);

    let refused = answered(read(&page, &worker))
        .await
        .expect_err("the call made on the ended link fails");
    assert_ne!(code_of(&refused), "not a refusal");
    assert_eq!(page.links(), 0, "and the ended link is let go");

    let asked = read(&page, &worker);
    let mut link = worker.link().await;
    let call = link.expect(Method::AgentCommands).await;
    link.answer(&call, &commands).await;
    answered(asked).await.expect("a new link answers");
    assert_eq!(page.links(), 1);
}

fn resource(byte: u8) -> PendingResource {
    PendingResource {
        resource_id: PendingResourceId::new(Uuid::from_bytes([byte; 16])),
        application_instance_id: instance(),
        request: DownstreamRequestId::new(
            GatewayConnectionId::new(1),
            UpstreamRequestId::new(format!("upstream-{byte}")).expect("valid"),
        ),
        kind: PendingKind::Approval,
        method: UpstreamMethod::new("session/request_permission").expect("valid"),
        classification: NativeClassification::declared(NativeMethodClass::Mutation),
        source_generation: SourceGeneration::new(1),
        state: PendingState::Pending,
        durability: Durability::Durable,
        deadline_ms: Nullable::null(),
        recorded_at: TimestampMs::new(1),
        interpretation_verified: true,
    }
}

/// The session's one live instance.
fn instances() -> AgentInstanceList {
    AgentInstanceList {
        sequence: U64::new(1),
        instances: vec![kr_protocol::projection::AgentInstanceSummary {
            application_instance_id: instance(),
            plugin_id: Nullable::null(),
            profile_id: Nullable::null(),
            mode: IntegrationMode::NativeBridge,
            bypass: Nullable::null(),
            started_at: TimestampMs::new(1),
            ended_at: Nullable::null(),
            refusal: Nullable::null(),
        }],
    }
}

/// One page of the session's snapshot, carrying `resources` and continuing after the last of them
/// when `more` says so.
fn snapshot_page(
    worker: &ScriptedWorker,
    snapshot_id: u64,
    resources: Vec<PendingResource>,
    more: bool,
) -> EventsSnapshotResult {
    let continue_after = if more {
        Nullable::some(
            resources
                .last()
                .expect("a page that continues carries a resource")
                .resource_id,
        )
    } else {
        Nullable::null()
    };
    EventsSnapshotResult {
        cursor: U64::new(40),
        session: SessionSummary {
            session_id: worker.session_id,
            session_epoch: worker.descriptor.session_epoch,
            environment_id: worker.descriptor.environment_id,
            display_number: DisplayNumber::new(1),
            state: SessionState::Live,
            shell_mode: ShellMode::Managed,
            shell_path: "/bin/zsh".to_owned(),
            cwd: "/tmp".to_owned(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: TimestampMs::new(1),
            dimensions: Dimensions::new(80, 24),
            attachment_count: U64::ZERO,
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
            environment_sources: None,
        },
        geometry: GeometryState {
            owner: Nullable::null(),
            epoch: GeometryEpoch::new(1),
            dimensions: Dimensions::new(80, 24),
        },
        lease: InputLeaseState {
            epoch: InputLeaseEpoch::new(0),
            holder: Nullable::null(),
            connection_id: Nullable::null(),
            next_sequence: InputSequence::new(0),
        },
        attachments: Vec::new(),
        oldest_retained_cursor: U64::ZERO,
        taken_at_ms: TimestampMs::new(2),
        agent_resources: AgentResourceSnapshot {
            snapshot_id: U64::new(snapshot_id),
            stream_generation: U64::new(1),
            cursor: U64::new(9),
            resources,
            continue_after,
        },
        agent_instances: instances(),
    }
}

/// KR-REQ-13.12: a session's agents are its live instances and every request its broker still
/// arbitrates, read as every page of one snapshot on the session's own worker before the page is
/// told anything.
#[tokio::test(flavor = "multi_thread")]
async fn a_sessions_agents_are_every_page_of_one_snapshot() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let asked = page.call(
        "session_agents",
        json!({ "sessionId": worker.session_id.to_string() }),
    );
    let mut link = worker.link().await;
    let first = link.expect(Method::EventsSnapshot).await;
    assert_eq!(first.kind, CallKind::Request);
    let params: EventsSnapshotParams = first.params();
    assert_eq!(params.session_id, worker.session_id);
    assert!(
        !params.agent_resources_from.is_present(),
        "a fresh snapshot"
    );
    link.answer(&first, &snapshot_page(&worker, 7, vec![resource(1)], true))
        .await;
    let second = link.expect(Method::EventsSnapshot).await;
    let params: EventsSnapshotParams = second.params();
    let from = params
        .agent_resources_from
        .as_ref()
        .expect("the next page of the same snapshot");
    assert_eq!(from.snapshot_id.get(), 7);
    assert_eq!(from.after_resource_id, resource(1).resource_id);
    link.answer(
        &second,
        &snapshot_page(&worker, 7, vec![resource(2)], false),
    )
    .await;
    let agents = answered(asked).await.expect("the session's agents");
    assert_eq!(
        agents["instances"],
        serde_json::to_value(instances()).expect("JSON")
    );
    assert_eq!(
        agents["resources"],
        serde_json::to_value(vec![resource(1), resource(2)]).expect("JSON")
    );
    assert!(
        agents.get("cursor").is_none(),
        "the page is not told the snapshot's cursors"
    );
}

/// A snapshot the host let go part way through is read again from its first page, so what the
/// page is given is never parts of two snapshots.
#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_the_host_let_go_is_read_again_from_its_first_page() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let asked = page.call(
        "session_agents",
        json!({ "sessionId": worker.session_id.to_string() }),
    );
    let mut link = worker.link().await;
    let first = link.expect(Method::EventsSnapshot).await;
    link.answer(&first, &snapshot_page(&worker, 7, vec![resource(1)], true))
        .await;
    let second = link.expect(Method::EventsSnapshot).await;
    link.refuse_with(
        &second,
        ErrorCode::ResyncRequired,
        "that snapshot has ended",
    )
    .await;
    let again = link.expect(Method::EventsSnapshot).await;
    let params: EventsSnapshotParams = again.params();
    assert!(
        !params.agent_resources_from.is_present(),
        "a fresh snapshot"
    );
    link.answer(&again, &snapshot_page(&worker, 8, vec![resource(3)], false))
        .await;
    let agents = answered(asked).await.expect("the session's agents");
    assert_eq!(
        agents["resources"],
        serde_json::to_value(vec![resource(3)]).expect("JSON"),
        "only the snapshot that was read whole"
    );
}

/// KR-REQ-13.15: a live session's retained output is read on its own worker, from the cursor and
/// within the bound the page names; a session with no worker here is read from the host's archive,
/// which this test's application is not connected to.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_sessions_history_is_read_on_its_worker_and_an_ended_ones_from_the_host() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let asked = page.call(
        "history_page",
        json!({ "params": {
            "session_id": worker.session_id.to_string(),
            "from_cursor": "1024",
            "max_bytes": "16384"
        } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::HistoryPage).await;
    assert_eq!(call.kind, CallKind::Request);
    let params: HistoryPageParams = call.params();
    assert_eq!(params.from_cursor.get(), 1024);
    assert_eq!(params.max_bytes.get(), 16_384);
    let history = HistoryPageResult {
        from_cursor: U64::new(1024),
        next_cursor: U64::new(1030),
        bytes: Bytes::new(b"ls -l\n".to_vec()),
        oldest_retained_cursor: U64::new(0),
        gap: Nullable::null(),
    };
    link.answer(&call, &history).await;
    let answer = answered(asked).await.expect("the page");
    assert_eq!(answer, serde_json::to_value(&history).expect("JSON"));
    assert_eq!(
        answer["bytes"], "bHMgLWwK",
        "the bytes travel as unpadded base64url"
    );

    let ended = SessionId::new(kr_ipc::new_uuid());
    let refused = answered(page.call(
        "history_page",
        json!({ "params": { "session_id": ended.to_string(), "from_cursor": "0", "max_bytes": "16384" } }),
    ))
    .await
    .expect_err("the archive is the host's, and nothing here is connected to it");
    assert_eq!(code_of(&refused), "HOST_NOT_CONFIGURED");
    assert!(
        !worker.connected(),
        "the ended session's page did not go to a worker"
    );
}

/// KR-REQ-09.07: the receipt of an action on a live session is read on that session's own worker,
/// which holds it, with the action and the session the page names; a session with no worker here, and
/// an action that names no session, are read from the host, which this test's application is not
/// connected to.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_sessions_receipt_is_read_on_its_worker_and_every_other_from_the_host() {
    use kr_protocol::ids::{ActionId, ActorId};
    use kr_protocol::method::MethodVersion;
    use kr_protocol::receipt::{ActionReadParams, ActionReadResult, Receipt, ReceiptState};

    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let asked = page.call(
        "action_read",
        json!({ "params": {
            "action_id": action_id.to_string(),
            "session_id": worker.session_id.to_string()
        } }),
    );
    let mut link = worker.link().await;
    let call = link.expect(Method::ActionRead).await;
    assert_eq!(call.kind, CallKind::Request);
    let params: ActionReadParams = call.params();
    assert_eq!(params.action_id, action_id);
    assert_eq!(params.session_id, Some(worker.session_id));
    let receipt = ActionReadResult {
        receipt: Receipt {
            action_id,
            actor_id: ActorId::new("local:1").expect("a principal"),
            method: Method::AgentPromptSubmit.into(),
            method_version: MethodVersion::V1,
            revision: U64::new(2),
            state: ReceiptState::Applied,
            reason: Nullable::null(),
            payload_digest: kr_protocol::scalars::Digest256::from_bytes([7; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::null(),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(5),
        },
        result: Nullable::null(),
    };
    link.answer(&call, &receipt).await;
    let answer = answered(asked).await.expect("the page");
    assert_eq!(answer, serde_json::to_value(&receipt).expect("JSON"));

    let ended = SessionId::new(kr_ipc::new_uuid());
    for named in [Some(ended), None] {
        let refused = answered(page.call(
            "action_read",
            json!({ "params": {
                "action_id": ActionId::new(kr_ipc::new_uuid()).to_string(),
                "session_id": named.map(|session| session.to_string())
            } }),
        ))
        .await
        .expect_err("the host is not configured here");
        assert_eq!(code_of(&refused), "HOST_NOT_CONFIGURED", "{named:?}");
    }
    assert!(
        !worker.connected(),
        "neither read went to the live session's worker"
    );
}
