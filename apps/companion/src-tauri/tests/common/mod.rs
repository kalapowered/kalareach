//! A managed session hosted by a test with the product's own worker, a real bridge endpoint and the
//! reference reader, and the page's side of the raw terminal view's commands over it.

#![cfg(unix)]
#![allow(dead_code, reason = "each suite uses the part of the harness it needs")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    BuildId, ControllerGeneration, InputLeaseEpoch, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, FenceAcknowledgement,
    KeyQueueSnapshot, PendingReaderInput, PromptGeneration, QueueDrainReport, ReaderContext,
    ReaderRevision, RootCommandBlockParams, RootEditorEnterParams, RootEditorFenceResult,
};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_shell_integration::contract::events::{BridgeEvent, HooksActivated};
use kr_shell_integration::contract::fence::LeaseView;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchAccepted, LaunchDecision, LaunchMailboxRequest, WorkerRequest,
};
use kr_shell_integration::contract::transport::{
    EventOutcome, HandshakeOutcome, WorkerExpectation,
};
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::scripted::{
    ReferenceShell, ScriptedBridge, ToBridge, qualified_hello,
};
use kr_worker::fence::FenceDriver;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use serde_json::{Value, json};
use tauri::test::MockRuntime;

/// How long the test waits for a frame the worker should already have sent.
pub const SOON: Duration = Duration::from_secs(10);

/// Where the bundle's pages are served from.
pub const BUNDLE: &str = "tauri://localhost";

/// The numbers the scripted reader reports, all different, so that a report that reads one for
/// another shows.
pub const PROMPT: u64 = 12;
pub const BUFFER: u64 = 3;
pub const DIRECTORY: u64 = 5;

/// A managed session this test hosts, with its descriptor published where the application finds it
/// and its reader scripted by this test.
pub struct Hosted {
    pub session_id: SessionId,
    pub runtime: Arc<SessionRuntime>,
    pub bridge: ScriptedBridge,
    _service: Arc<WorkerService>,
    serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
    bridge_task: tokio::task::JoinHandle<()>,
    // Declared last: the directory is removed after every field above has let go of its files.
    pub temp: kr_ipc::testing::TempHost,
}

impl Hosted {
    /// Reads the next frame the worker sends the reader, or fails.
    pub async fn next(&mut self) -> ToBridge {
        tokio::time::timeout(SOON, self.bridge.recv())
            .await
            .expect("the worker sent a frame")
            .expect("a frame")
    }

    /// The reader enters the primary prompt `PROMPT` with an empty buffer, and the worker has
    /// handled it when this returns.
    pub async fn enters_the_prompt(&mut self) {
        self.bridge
            .send_event(BridgeEvent::EditorEnter(RootEditorEnterParams {
                session_id: self.session_id,
                root_process: kr_ipc::identity::current_process_start_identity()
                    .expect("this process"),
                prompt_generation: PromptGeneration::new(PROMPT),
                reader_revision: ReaderRevision::new(1),
                reader_context: ReaderContext::Primary,
                editor: editor_state(),
                cwd_revision: CwdRevision::new(DIRECTORY),
            }))
            .await
            .expect("enters");
        self.settled().await;
    }

    /// Returns once the worker has handled every event sent before this call.
    pub async fn settled(&mut self) {
        self.bridge
            .send_event(BridgeEvent::CommandBlock(Box::new(
                RootCommandBlockParams {
                    session_id: self.session_id,
                    prompt_generation: PromptGeneration::new(PROMPT),
                    command: "true".to_owned(),
                    started_at_ms: TimestampMs::new(1_700_000_000_000),
                    duration_ms: Nullable::null(),
                    exit_status: Nullable::null(),
                    cwd: "/tmp".to_owned(),
                    cwd_revision: CwdRevision::new(DIRECTORY),
                },
            )))
            .await
            .expect("reports");
        loop {
            if let ToBridge::EventResult { result, .. } = self.next().await
                && matches!(*result, EventOutcome::CommandBlockRecorded(_))
            {
                return;
            }
        }
    }

    /// The reader answers the worker's request for a fence, and the worker publishes it.
    pub async fn proves_a_fence(&mut self) {
        let fence_id = loop {
            if let ToBridge::Request { request, .. } = self.next().await
                && let WorkerRequest::Fence(params) = *request
            {
                break params.fence_id;
            }
        };
        self.bridge
            .answer(
                RequestId::new(0),
                BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(FenceAcknowledgement {
                    fence_id,
                    prompt_generation: PromptGeneration::new(PROMPT),
                    reader_revision: ReaderRevision::new(1),
                    reader_context: ReaderContext::Primary,
                    queues: QueueDrainReport::CLEAR,
                    snapshot: KeyQueueSnapshot::drained(),
                    editor: EditorState {
                        buffer_revision: EditorBufferRevision::new(BUFFER),
                        ..editor_state()
                    },
                    cwd_revision: CwdRevision::new(DIRECTORY),
                })),
            )
            .await
            .expect("acknowledges");
        loop {
            if let ToBridge::FencePublished(published) = self.next().await {
                assert!(
                    matches!(published, kr_protocol::root::FencePublication::Published(_)),
                    "the fence was withheld: {published:?}"
                );
                return;
            }
        }
    }

    /// The next install the worker asks the reader for.
    pub async fn install_asked(&mut self) -> LaunchMailboxRequest {
        loop {
            if let ToBridge::Request { request, .. } = self.next().await
                && let WorkerRequest::Launch(request) = *request
            {
                return request;
            }
        }
    }

    /// The reader installs what it was asked to, at the prompt it stands at.
    pub async fn installs(&mut self, asked: &LaunchMailboxRequest) {
        self.bridge
            .answer(
                RequestId::new(0),
                BridgeAnswer::Launch(LaunchDecision::Accepted(LaunchAccepted {
                    transaction: asked.transaction,
                    installed: asked.command.clone(),
                    fence_id: asked.fence_id,
                    prompt_generation: PromptGeneration::new(PROMPT),
                    buffer_revision: EditorBufferRevision::new(BUFFER + 1),
                    reader_revision: ReaderRevision::new(1),
                })),
            )
            .await
            .expect("installs");
    }

    /// Closes the session and waits for it, so the shell ends with it.
    pub async fn close(self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(Duration::from_secs(30), self.runtime.wait_closed()).await;
    }
}

impl Drop for Hosted {
    fn drop(&mut self) {
        self.serving.abort();
        self.bridge_task.abort();
    }
}

pub fn editor_state() -> EditorState {
    EditorState {
        buffer_empty: true,
        buffer_revision: EditorBufferRevision::new(1),
        keymap: EditorKeymap::Emacs,
        pending: PendingReaderInput::NONE,
    }
}

/// Hosts a managed session whose reader has registered and whose hooks are live, with no prompt
/// entered yet, and whose shell runs `script`: it prints what it prints and then reads its input
/// (`exec cat`) and says nothing.
pub async fn hosted(script: &str) -> Hosted {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display = DisplayNumber::new(1);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    // No controller connects in this suite, so the key a generation token would be checked against
    // is a fresh one rather than the environment's own.
    let controller_public_key = *kr_crypto::keys::AuthorisationKeyPair::generate()
        .expect("an authorisation key")
        .public();

    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: kr_worker::testing::posix_script(script),
        shell_mode: ShellMode::Managed,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let host_endpoint = HostEndpoint::open_for_session(
        environment.runtime_root(),
        environment.runtime_dir(),
        session_id,
    )
    .expect("binds the bridge");
    let address = host_endpoint.address().clone();
    let secret = host_endpoint.secret().clone();

    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    // The machine reads a clock that only this test could move, and this test never moves it, so
    // none of its deadlines passes because the test was slow to answer on a loaded machine.
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        clock,
    ));
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let server = kr_worker::fence::bridge::BridgeServer::new(
        Arc::clone(&runtime),
        host_endpoint,
        WorkerExpectation {
            session_id,
            // The reference bridge runs in this process, so this process is the root shell the
            // worker expects on its endpoint.
            root_process: process.clone(),
            supported_editor_abis: vec!["zle-5.9".to_owned()],
            supported_integration_versions: vec!["1".to_owned()],
            launched_package: None,
            already_registered: false,
            gesture: kr_shell_integration::contract::events::EofGesture::default(),
        },
    );
    let bridge_task = tokio::spawn(server.serve());
    let declared = ReferenceShell::new(ShellKind::Zsh, "/bin/cat", "5.9", "zle-5.9");
    let hello = qualified_hello(&declared, session_id, &address, process.clone(), &secret)
        .expect("a hello");
    let (mut bridge, outcome) =
        tokio::time::timeout(SOON, ScriptedBridge::connect(&address, &hello))
            .await
            .expect("the worker accepted a connection")
            .expect("connects");
    assert!(
        matches!(outcome, HandshakeOutcome::Accepted(_)),
        "a qualified root shell registers: {outcome:?}"
    );
    // The user's startup files have run and the integration's own hooks are live.
    bridge
        .send_event(BridgeEvent::HooksActivated(HooksActivated {
            session_id,
            prompt_generation: PromptGeneration::new(1),
            modules: Vec::new(),
        }))
        .await
        .expect("reports");

    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            Arc::clone(&identity),
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key,
                controller_generation: ControllerGeneration::new(1),
                build_id: BuildId::new("kr-test/0").expect("a build identifier"),
                journal_path: Some(environment.journal_database(session_id)),
            },
        )
        .expect("a service"),
    );
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));
    kr_ipc::descriptor::publish(
        &environment,
        &WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            boot_identity: boot,
            process_start_identity: process,
            protocol_version: PROTOCOL_VERSION,
            endpoint: endpoint.as_text(),
            worker_public_key: *identity.public_key(),
            worker_profile: WorkerProfile::HeadlessUser,
            published_at_ms: TimestampMs::new(0),
        },
    )
    .expect("publishes the descriptor");
    Hosted {
        temp,
        session_id,
        runtime,
        bridge,
        _service: service,
        serving,
        bridge_task,
    }
}

/// The page: an application with the view's commands, and every state each channel was sent.
pub struct Page {
    pub app: tauri::App<MockRuntime>,
    pub window: tauri::WebviewWindow<MockRuntime>,
    pub published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>>,
}

impl Page {
    /// The application, with its view registry reading descriptors from `paths`.
    pub fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        let published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>> = Arc::default();
        let heard = Arc::clone(&published);
        let builder = tauri::test::mock_builder()
            .manage(companion_tauri::AppState::new())
            .channel_interceptor(move |_webview, callback, _index, body| {
                if let tauri::ipc::InvokeResponseBody::Json(json) = body {
                    let state: Value = serde_json::from_str(json).expect("a state the page reads");
                    heard
                        .lock()
                        .expect("the record")
                        .entry(callback.0)
                        .or_default()
                        .push(state);
                }
                true
            })
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::terminal_view_open,
                companion_tauri::commands::terminal_view_move,
                companion_tauri::commands::terminal_view_input,
                companion_tauri::commands::terminal_view_close,
                companion_tauri::commands::terminal_view_launch_surface,
                companion_tauri::commands::terminal_view_launch,
            ]);
        let app = companion_tauri::terminal::install(
            builder,
            companion_tauri::terminal::TerminalViews::at(paths),
        )
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        Self {
            app,
            window,
            published,
        }
    }

    /// Calls `command` as the page does, on a thread of its own, since its answer waits for the
    /// worker this test is driving. The call is made at once; the answer is waited for within
    /// [`SOON`], so a product that never answers fails the case and does not hang it: the thread is
    /// not one the test's runtime waits for when the case ends, as a blocking task would be, so it
    /// stays where it is stuck and the case ends at the limit.
    pub fn call(
        &self,
        command: &str,
        body: Value,
    ) -> impl std::future::Future<Output = Result<Value, Value>> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let window = self.window.clone();
        let command = command.to_owned();
        let (reply, answered) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let answer = tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command,
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
            .map(|answer| answer.deserialize().expect("an answer the page reads"));
            let _ = reply.send(answer);
        });
        async move {
            tokio::time::timeout(SOON, answered)
                .await
                .expect("the page was answered within the limit")
                .expect("the page's call ended without an answer")
        }
    }

    /// Opens a view of `session`, publishing on `channel`.
    pub async fn open(&self, session: SessionId, channel: u32) -> String {
        let answer = self
            .call(
                "terminal_view_open",
                json!({
                    "sessionId": session.to_string(),
                    "columns": 40,
                    "rows": 8,
                    "onState": format!("__CHANNEL__:{channel}"),
                }),
            )
            .await
            .expect("the view opens");
        answer.as_str().expect("the view's handle").to_owned()
    }

    /// The newest state `channel` has been sent, once it is one `holds` accepts.
    pub async fn newest(&self, channel: u32, holds: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(SOON, async {
            loop {
                if let Some(state) = self
                    .published
                    .lock()
                    .expect("the record")
                    .get(&channel)
                    .and_then(|states| states.last())
                    && holds(state)
                {
                    return state.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a state the page waits for within the limit")
    }

    /// The first `showing` state `channel` was sent, read from its whole record, with the proof that
    /// only `waiting` states stand before it: a screen shown early and replaced is not passed over.
    pub async fn first_showing(&self, channel: u32) -> Value {
        self.newest(channel, |state| state["state"] == "showing")
            .await;
        let states = self
            .published
            .lock()
            .expect("the record")
            .get(&channel)
            .cloned()
            .unwrap_or_default();
        let at = states
            .iter()
            .position(|state| state["state"] == "showing")
            .expect("a showing state");
        assert!(
            states[..at].iter().all(|state| state["state"] == "waiting"),
            "{states:?}"
        );
        states[at].clone()
    }

    /// A view of `session` that shows its screen.
    pub async fn showing(&self, session: SessionId, channel: u32) -> String {
        let view = self.open(session, channel).await;
        self.newest(channel, |state| state["state"] == "showing")
            .await;
        view
    }

    /// Takes control of `view` as the page's control request 1, and waits until the session has
    /// given it.
    pub async fn takes_control(&self, view: &str, channel: u32) {
        self.call(
            "terminal_view_input",
            json!({"view": view, "input": {"kind": "take", "number": 1}}),
        )
        .await
        .expect("the take is taken");
        self.newest(channel, |state| state["control"]["state"] == "controlling")
            .await;
    }

    /// Opens a view of `session` of `columns` by `rows`, publishing on `channel`, that restores
    /// `anchor` when it is not null.
    pub async fn open_at(
        &self,
        session: SessionId,
        channel: u32,
        columns: u64,
        rows: u64,
        anchor: &Value,
    ) -> Result<String, Value> {
        self.call(
            "terminal_view_open",
            json!({
                "sessionId": session.to_string(),
                "columns": columns,
                "rows": rows,
                "anchor": anchor,
                "onState": format!("__CHANNEL__:{channel}"),
            }),
        )
        .await
        .map(|answer| answer.as_str().expect("the view's handle").to_owned())
    }

    /// Moves `view`'s window by `across` columns and `down` rows, as the page's move `number`.
    pub async fn pan(&self, view: &str, number: u64, across: i64, down: i64) {
        self.call(
            "terminal_view_move",
            json!({"view": view, "number": number, "across": across, "down": down, "live": false}),
        )
        .await
        .expect("the move is taken");
    }

    /// Closes `view`.
    pub async fn close(&self, view: &str) {
        self.call("terminal_view_close", json!({ "view": view }))
            .await
            .expect("the view closes");
    }

    /// Presses Return in `view`, under the page's take 1.
    pub async fn enter(&self, view: &str) {
        self.call(
            "terminal_view_input",
            json!({"view": view, "input": {
                "kind": "key", "take": 1, "key": "Enter", "base": null, "keypad": null,
                "shift": false, "alt": false, "control": false, "caps_lock": false,
                "num_lock": false, "event": "press",
            }}),
        )
        .await
        .expect("the key is taken");
    }

    /// The text of each line of a published screen.
    pub fn lines(state: &Value) -> Vec<String> {
        state["screen"]["lines"]
            .as_array()
            .map(|lines| {
                lines
                    .iter()
                    .map(|line| {
                        line["pieces"]
                            .as_array()
                            .expect("pieces")
                            .iter()
                            .map(|piece| piece["text"].as_str().expect("text").to_owned())
                            .collect::<String>()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The code a command was refused with.
pub fn code(refusal: &Value) -> &str {
    refusal["code"].as_str().expect("a refusal's code")
}
