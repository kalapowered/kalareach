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
    AgentSnapshotResult, AgentSteerParams, PluginActionInvokeParams, PluginActionInvokeResult,
};
use kr_protocol::attachment::GeometryState;
use kr_protocol::broker::{ActionName, ActionProvenance, IntegrationMode};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DownstreamRequestId, NativeClassification, NativeMethodClass, PendingKind, PendingResource,
    PendingState,
};
use kr_protocol::ids::{
    AgentBindingRevision, AgentTurnId, ApplicationInstanceId, GatewayConnectionId, GeometryEpoch,
    InputLeaseEpoch, InputSequence, PendingResourceId, PluginId, SessionId, SourceGeneration,
    UpstreamMethod, UpstreamRequestId,
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
use scripted_worker::{CallKind, Challenge, Reached, ScriptedWorker};
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
                companion_tauri::commands::plugin_action_invoke,
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
    subject_of(worker, instance())
}

/// The subject of a call about `worker`'s session and the application `instance`.
fn subject_of(worker: &ScriptedWorker, instance: ApplicationInstanceId) -> Value {
    json!({
        "session_id": worker.session_id.to_string(),
        "application_instance_id": instance.to_string(),
    })
}

/// The target an agent mutation about `worker`'s session names, as the page writes it: the
/// application `instance` and the binding `revision` the action was prepared against.
fn target(
    worker: &ScriptedWorker,
    instance: ApplicationInstanceId,
    revision: AgentBindingRevision,
) -> Value {
    json!({
        "subject": subject_of(worker, instance),
        "binding_revision": revision.get().to_string(),
    })
}

/// The instance and the binding revision the page's `n`th mutation is prepared against. Each of the
/// six has an instance and a revision of its own, and neither is one that the double's binding or
/// another call holds, so an envelope can take them from nowhere but the call's own parameters.
fn own(n: u8) -> (ApplicationInstanceId, AgentBindingRevision) {
    (
        ApplicationInstanceId::new(Uuid::from_bytes([0x30 + n; 16])),
        AgentBindingRevision::new(10 + u64::from(n)),
    )
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

/// KR-REQ-13.12 and KR-REQ-15.22: each composer action is its own mutation on the session's worker,
/// and its envelope names what the parameters name and nothing the page chose: the worker's
/// environment, its session at its epoch, the instance and the binding revision the action was
/// prepared against. A cancellation is the typed `agent.turn.cancel` and carries the turn it names.
///
/// Each call is prepared against an instance and a revision of its own, which no double holds, and
/// each envelope is compared with the parameters the worker decoded, field by field. A command
/// that ends before it reaches the worker is a failure of this case.
#[tokio::test(flavor = "multi_thread")]
async fn each_agent_mutation_names_the_workers_session_the_instance_and_the_revision() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let actions: [(&'static str, Method, u8, Value); 5] = [
        (
            "agent_prompt_submit",
            Method::AgentPromptSubmit,
            1,
            json!({ "draft_id": null, "text": "Try the subscription." }),
        ),
        (
            "agent_prompt_queue",
            Method::AgentPromptQueue,
            2,
            json!({ "draft_id": null, "text": "Then run the suite." }),
        ),
        (
            "agent_turn_steer",
            Method::AgentTurnSteer,
            3,
            json!({ "turn_id": turn().to_string(), "text": "Only the one test." }),
        ),
        (
            "agent_turn_cancel",
            Method::AgentTurnCancel,
            4,
            json!({ "turn_id": turn().to_string() }),
        ),
        (
            "agent_approval_respond",
            Method::AgentApprovalRespond,
            5,
            json!({
                "resource_id": PendingResourceId::new(Uuid::from_bytes([7; 16])).to_string(),
                "option_id": "allow_once"
            }),
        ),
    ];
    let mut link = None;
    for (command, method, n, mut params) in actions {
        let (own_instance, own_revision) = own(n);
        params["target"] = target(&worker, own_instance, own_revision);
        let mut asked = page.call(command, json!({ "params": params }));
        if link.is_none() {
            link = Some(worker.link().await);
        }
        let link = link.as_mut().expect("the session's link");
        let reached = link.reached_by(&mut asked).await;
        assert!(
            matches!(reached, Reached::Call(_)),
            "{command} reached the worker: {reached:?}"
        );
        let Reached::Call(call) = reached else {
            unreachable!("asserted to be a call")
        };
        assert_eq!(call.method, method.to_string(), "{command}'s method");
        assert_eq!(call.kind, CallKind::Mutation, "{command} is a mutation");
        let envelope = call.target.clone().expect("a mutation's envelope");
        assert_eq!(envelope.environment_id, worker.descriptor.environment_id);
        assert_eq!(envelope.session_id.as_ref(), Some(&worker.session_id));
        assert_eq!(
            envelope.session_epoch.as_ref(),
            Some(&worker.descriptor.session_epoch)
        );
        let named = match method {
            Method::AgentPromptSubmit | Method::AgentPromptQueue => {
                let sent: AgentPromptParams = call.params();
                sent.target
            }
            Method::AgentTurnSteer => {
                let sent: AgentSteerParams = call.params();
                sent.target
            }
            Method::AgentTurnCancel => {
                let cancel: AgentCancelParams = call.params();
                assert_eq!(cancel.turn_id, turn(), "the cancellation names its turn");
                cancel.target
            }
            _ => {
                let sent: AgentApprovalRespondParams = call.params();
                sent.target
            }
        };
        assert_eq!(
            envelope.application_instance_id.as_ref(),
            Some(&named.subject.application_instance_id),
            "{command}'s envelope names the instance its parameters name"
        );
        assert_eq!(
            envelope.agent_binding_revision.as_ref(),
            Some(&named.binding_revision),
            "{command}'s envelope names the binding revision its parameters name"
        );
        assert_eq!(
            named.subject.application_instance_id, own_instance,
            "{command}'s parameters carry the page's instance"
        );
        assert_eq!(
            named.binding_revision, own_revision,
            "{command}'s parameters carry the page's binding revision"
        );
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

/// KR-REQ-13.14: a package's action is invoked on the session's own worker, in the method's own
/// parameters and under the envelope every agent mutation carries, and the page is given the
/// method's own result.
///
/// The page names the package, the action and the binding revision it read; the action's
/// arguments travel as the encoded object the worker hashes into the action's token, so an action
/// that takes none sends the empty object and not empty bytes.
#[tokio::test(flavor = "multi_thread")]
async fn a_package_action_is_invoked_on_the_sessions_worker_and_answered_in_the_methods_own_result()
{
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let plugin_id = PluginId::new("kalareach.codex").expect("a package");
    let action = ActionName::new("turn.cancel").expect("an action");
    let (own_instance, own_revision) = own(6);
    let mut asked = page.call(
        "plugin_action_invoke",
        json!({ "params": {
            "target": target(&worker, own_instance, own_revision),
            "plugin_id": plugin_id.to_string(),
            "action": action.to_string(),
            "draft_id": null,
            "resource_id": null,
            "parameters": "e30",
        } }),
    );
    let mut link = worker.link().await;
    let reached = link.reached_by(&mut asked).await;
    assert!(
        matches!(reached, Reached::Call(_)),
        "plugin_action_invoke reached the worker: {reached:?}"
    );
    let Reached::Call(call) = reached else {
        unreachable!("asserted to be a call")
    };
    assert_eq!(call.method, Method::PluginActionInvoke.to_string());
    assert_eq!(call.kind, CallKind::Mutation);
    let envelope = call.target.clone().expect("a mutation's envelope");
    assert_eq!(envelope.environment_id, worker.descriptor.environment_id);
    assert_eq!(envelope.session_id.as_ref(), Some(&worker.session_id));
    let sent: PluginActionInvokeParams = call.params();
    assert_eq!(
        envelope.application_instance_id.as_ref(),
        Some(&sent.target.subject.application_instance_id),
        "the envelope names the instance the parameters name"
    );
    assert_eq!(
        envelope.agent_binding_revision.as_ref(),
        Some(&sent.target.binding_revision),
        "the envelope names the binding revision the parameters name"
    );
    assert_eq!(
        sent.target.subject.application_instance_id, own_instance,
        "the parameters carry the page's instance"
    );
    assert_eq!(
        sent.target.binding_revision, own_revision,
        "the parameters carry the page's binding revision"
    );
    assert_eq!(sent.plugin_id, plugin_id);
    assert_eq!(sent.action, action);
    assert!(!sent.draft_id.is_present() && !sent.resource_id.is_present());
    assert_eq!(sent.parameters.as_slice(), b"{}");
    let result = PluginActionInvokeResult {
        mutation: Nullable::some(mutated()),
        action,
    };
    link.answer(&call, &result).await;
    let settled = answered(asked).await.expect("the worker's answer");
    assert_eq!(settled["receipt"], Value::Null);
    assert_eq!(
        settled["value"],
        serde_json::to_value(&result).expect("JSON"),
        "the page is given the method's own result"
    );
}

/// KR-REQ-10.01: a prompt that names both a draft and text, or neither, is refused before anything
/// is sent: no link is opened for it, and the worker is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_that_names_both_a_draft_and_text_or_neither_reaches_nothing() {
    let mut worker = ScriptedWorker::start(Challenge::Answered);
    let page = Page::new(worker.paths());
    let draft = "55555555-5555-4555-8555-555555555555";
    for params in [
        json!({ "target": target(&worker, instance(), revision()), "draft_id": draft, "text": "and text" }),
        json!({ "target": target(&worker, instance(), revision()), "draft_id": null, "text": null }),
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
        let params = json!({
            "target": target(&worker, instance(), revision()),
            "draft_id": draft,
            "text": null
        });
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
            root: None,
            application: None,
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

// The draft route: a prompt that names a draft goes through the host's control daemon, which
// passes the caller's envelope on to the session's worker.

/// A supervisor that starts nothing: the session's worker is this test's own.
#[derive(Debug)]
struct StartsNothing;

impl kr_controller::supervision::WorkerSupervisor for StartsNothing {
    fn start(
        &self,
        _launch: &kr_controller::supervision::WorkerLaunch,
    ) -> kr_controller::supervision::LaunchOutcome {
        kr_controller::supervision::LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// The host's control daemon, running in this process on a disposable tree, with the application
/// connected to it as it is to the host on this computer. The session's worker is the test's: the
/// daemon records it as it records every session it creates, and finds it when it starts.
struct Draft {
    worker: ScriptedWorker,
    page: Page,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    _controller: std::sync::Arc<kr_controller::service::Controller>,
    // Declared last: the directory is removed after every field above has let go of its files.
    _tree: kr_ipc::testing::TempHost,
}

impl Drop for Draft {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Draft {
    async fn start() -> Self {
        let tree = kr_ipc::testing::TempHost::create();
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let worker = ScriptedWorker::start_for_daemon(environment.clone(), environment_id);
        let secrets = environment.secrets_dir();
        let build_id = companion_tauri::connection::build_id().expect("a build identity");
        let controller =
            kr_controller::service::Controller::start(kr_controller::service::ControllerSetup {
                paths: environment.clone(),
                environment_id,
                identity: Box::new(move || {
                    let store = kr_crypto::store::open_store_in(&secrets)
                        .expect("a secret store for the test environment");
                    Ok(kr_ipc::verify::ControllerIdentity::open(
                        store.store.as_ref(),
                        environment_id,
                        false,
                    )
                    .expect("an identity"))
                }),
                secret_store: kr_crypto::store::StoreSelection::File,
                boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                supervisor: Box::new(StartsNothing),
                worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
                build_id: build_id.clone(),
                release: "0".to_owned(),
                shell_packages: None,
                terminal: Box::new(kr_controller::supervision::NoTerminal),
            })
            .await
            .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener =
            kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the control endpoint");
        let clients = tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(listener));
        let page = Page::new(environment);
        let transport = kr_client::ipc::IpcTransport::connect(&endpoint, build_id)
            .await
            .expect("connects to the control endpoint");
        page.app.state::<companion_tauri::AppState>().connected(
            companion_tauri::connection::Connection::over(transport).expect("a connection"),
        );
        Self {
            worker,
            page,
            clients,
            _controller: controller,
            _tree: tree,
        }
    }
}

/// What a prompt that names a draft came to.
#[derive(Debug)]
enum Driven {
    /// The worker was sent the probe that holds no lifetime and then the prompt itself, and the
    /// page was given the command's answer.
    Sent {
        probe: Box<scripted_worker::Call>,
        live: Box<scripted_worker::Call>,
        settled: Result<Value, Value>,
    },
    /// The command ended, or nothing came, before both reached the worker.
    Ended(Reached),
}

impl Draft {
    /// Calls `command` as the page does with a draft and the `n`th call's own instance and binding
    /// revision, and plays the worker: it says it holds no receipt for the probe, which is the one
    /// answer that has the daemon record the draft and send the prompt, and answers the prompt.
    async fn drives(&mut self, command: &'static str, n: u8) -> Driven {
        let (instance, revision) = own(n);
        let params = json!({
            "target": target(&self.worker, instance, revision),
            "draft_id": "55555555-5555-4555-8555-555555555555",
            "text": null
        });
        let mut asked = self.page.call(command, json!({ "params": params }));
        let mut link = match self.worker.reached_by(&mut asked).await {
            Ok(link) => link,
            Err(ended) => return Driven::Ended(ended),
        };
        let probe = link.call().await;
        link.refuse_with(&probe, ErrorCode::PermissionDenied, "no receipt")
            .await;
        let live = match link.reached_by(&mut asked).await {
            Reached::Call(call) => *call,
            ended => return Driven::Ended(ended),
        };
        link.answer(&live, &mutated()).await;
        let settled = answered(asked).await;
        Driven::Sent {
            probe: Box::new(probe),
            live: Box::new(live),
            settled,
        }
    }
}

/// KR-REQ-14.11: a prompt that names a draft is sent to the host's control daemon, which passes the
/// caller's envelope on to the session's worker as it arrived, first as the probe that holds no
/// lifetime and then as the prompt itself. Both envelopes name the application instance and the
/// binding revision that the call's own parameters name, which are the call's own and no other
/// the page, the daemon or the worker holds, and the page is given the worker's answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_draft_submit_reaches_the_worker_in_envelopes_that_name_its_own_instance_and_revision() {
    let mut draft = Draft::start().await;
    let driven = draft.drives("agent_prompt_submit", 1).await;
    assert!(
        matches!(driven, Driven::Sent { .. }),
        "agent_prompt_submit reached the worker twice: {driven:?}"
    );
    let Driven::Sent {
        probe,
        live,
        settled,
    } = driven
    else {
        let Driven::Ended(why) = driven else {
            unreachable!("asserted to be sent")
        };
        unreachable!("asserted to be sent: {why:?}")
    };
    let (own_instance, own_revision) = own(1);
    assert_eq!(
        probe.deadline_boot_ms,
        Some(0),
        "the first call holds no lifetime"
    );
    assert!(
        live.deadline_boot_ms.is_some_and(|deadline| deadline > 0),
        "the prompt carries the deadline it was admitted under: {:?}",
        live.deadline_boot_ms
    );
    for (which, call) in [("the probe", &probe), ("the prompt", &live)] {
        assert_eq!(
            call.method,
            Method::AgentPromptSubmit.to_string(),
            "{which}"
        );
        assert_eq!(call.kind, CallKind::Mutation, "{which}");
        let envelope = call.target.clone().expect("a mutation's envelope");
        assert_eq!(envelope.session_id.as_ref(), Some(&draft.worker.session_id));
        assert_eq!(
            envelope.session_epoch.as_ref(),
            Some(&draft.worker.descriptor.session_epoch)
        );
        let sent: AgentPromptParams = call.params();
        assert!(sent.draft_id.is_present(), "{which} names the draft");
        assert_eq!(
            envelope.application_instance_id.as_ref(),
            Some(&sent.target.subject.application_instance_id),
            "{which}'s envelope names the instance its parameters name"
        );
        assert_eq!(
            envelope.agent_binding_revision.as_ref(),
            Some(&sent.target.binding_revision),
            "{which}'s envelope names the binding revision its parameters name"
        );
        assert_eq!(
            sent.target.subject.application_instance_id, own_instance,
            "{which}'s parameters carry the page's instance"
        );
        assert_eq!(
            sent.target.binding_revision, own_revision,
            "{which}'s parameters carry the page's binding revision"
        );
    }
    assert_eq!(
        probe.target, live.target,
        "the probe and the prompt carry one envelope"
    );
    assert_eq!(probe.action_id, live.action_id);
    let settled = settled.expect("the worker's answer");
    assert_eq!(
        settled["value"],
        serde_json::to_value(mutated()).expect("JSON"),
        "the page is given the worker's answer"
    );
}

/// KR-REQ-14.11: a queued prompt that names a draft goes the same way as a submitted one, in the
/// queue method's own envelopes.
#[tokio::test(flavor = "multi_thread")]
async fn a_draft_queue_reaches_the_worker_in_envelopes_that_name_its_own_instance_and_revision() {
    let mut draft = Draft::start().await;
    let driven = draft.drives("agent_prompt_queue", 2).await;
    assert!(
        matches!(driven, Driven::Sent { .. }),
        "agent_prompt_queue reached the worker twice: {driven:?}"
    );
    let Driven::Sent {
        probe,
        live,
        settled,
    } = driven
    else {
        let Driven::Ended(why) = driven else {
            unreachable!("asserted to be sent")
        };
        unreachable!("asserted to be sent: {why:?}")
    };
    let (own_instance, own_revision) = own(2);
    assert_eq!(
        probe.deadline_boot_ms,
        Some(0),
        "the first call holds no lifetime"
    );
    assert!(
        live.deadline_boot_ms.is_some_and(|deadline| deadline > 0),
        "the prompt carries the deadline it was admitted under: {:?}",
        live.deadline_boot_ms
    );
    for (which, call) in [("the probe", &probe), ("the prompt", &live)] {
        assert_eq!(call.method, Method::AgentPromptQueue.to_string(), "{which}");
        assert_eq!(call.kind, CallKind::Mutation, "{which}");
        let envelope = call.target.clone().expect("a mutation's envelope");
        assert_eq!(envelope.session_id.as_ref(), Some(&draft.worker.session_id));
        assert_eq!(
            envelope.session_epoch.as_ref(),
            Some(&draft.worker.descriptor.session_epoch)
        );
        let sent: AgentPromptParams = call.params();
        assert!(sent.draft_id.is_present(), "{which} names the draft");
        assert_eq!(
            envelope.application_instance_id.as_ref(),
            Some(&sent.target.subject.application_instance_id),
            "{which}'s envelope names the instance its parameters name"
        );
        assert_eq!(
            envelope.agent_binding_revision.as_ref(),
            Some(&sent.target.binding_revision),
            "{which}'s envelope names the binding revision its parameters name"
        );
        assert_eq!(
            sent.target.subject.application_instance_id, own_instance,
            "{which}'s parameters carry the page's instance"
        );
        assert_eq!(
            sent.target.binding_revision, own_revision,
            "{which}'s parameters carry the page's binding revision"
        );
    }
    assert_eq!(
        probe.target, live.target,
        "the probe and the prompt carry one envelope"
    );
    assert_eq!(probe.action_id, live.action_id);
    let settled = settled.expect("the worker's answer");
    assert_eq!(
        settled["value"],
        serde_json::to_value(mutated()).expect("JSON"),
        "the page is given the worker's answer"
    );
}
