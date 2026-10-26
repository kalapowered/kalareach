//! A launch pressed through a raw terminal view, on a real worker.
//!
//! The session is a managed one, hosted by this test with the product's own worker and a real
//! bridge endpoint. The reader on the other end of the bridge is the contract's reference bridge,
//! so the test decides when the reader enters a prompt, when it proves its queues and what it
//! answers to an install, and everything else is the product: the view's link, the attachment, the
//! input lease the view takes, the worker's acceptance of a launch from the connection that holds
//! it, and the refusals it makes before the reader is asked.

#![cfg(unix)]

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
use tauri::Manager as _;
use tauri::test::MockRuntime;

/// How long the test waits for a frame the worker should already have sent.
const SOON: Duration = Duration::from_secs(10);

/// Where the bundle's pages are served from.
const BUNDLE: &str = "tauri://localhost";

/// The numbers the scripted reader reports, all different, so that a report that reads one for
/// another shows.
const PROMPT: u64 = 12;
const BUFFER: u64 = 3;
const DIRECTORY: u64 = 5;

/// The channel the first view publishes on, and the second's.
const FIRST: u32 = 3;
const SECOND: u32 = 4;

/// A managed session this test hosts, with its descriptor published where the application finds it
/// and its reader scripted by this test.
struct Hosted {
    temp: kr_ipc::testing::TempHost,
    session_id: SessionId,
    runtime: Arc<SessionRuntime>,
    bridge: ScriptedBridge,
    _service: Arc<WorkerService>,
    serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
    bridge_task: tokio::task::JoinHandle<()>,
}

impl Hosted {
    /// Reads the next frame the worker sends the reader, or fails.
    async fn next(&mut self) -> ToBridge {
        tokio::time::timeout(SOON, self.bridge.recv())
            .await
            .expect("the worker sent a frame")
            .expect("a frame")
    }

    /// The reader enters the primary prompt `PROMPT` with an empty buffer, and the worker has
    /// handled it when this returns.
    async fn enters_the_prompt(&mut self) {
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
    async fn settled(&mut self) {
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
    async fn proves_a_fence(&mut self) {
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
    async fn install_asked(&mut self) -> LaunchMailboxRequest {
        loop {
            if let ToBridge::Request { request, .. } = self.next().await
                && let WorkerRequest::Launch(request) = *request
            {
                return request;
            }
        }
    }

    /// The reader installs what it was asked to, at the prompt it stands at.
    async fn installs(&mut self, asked: &LaunchMailboxRequest) {
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
    async fn close(self) {
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

fn editor_state() -> EditorState {
    EditorState {
        buffer_empty: true,
        buffer_revision: EditorBufferRevision::new(1),
        keymap: EditorKeymap::Emacs,
        pending: PendingReaderInput::NONE,
    }
}

/// Hosts a managed session whose reader has registered and whose hooks are live, with no prompt
/// entered yet.
async fn hosted() -> Hosted {
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
        // A program that reads its input and says nothing.
        shell: kr_worker::testing::posix_script("exec cat"),
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
struct Page {
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
    published: Arc<Mutex<BTreeMap<u32, Vec<Value>>>>,
}

impl Page {
    /// The application, with its view registry reading descriptors from `paths`.
    fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
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
    /// [`SOON`], so a product that never answers fails the case and does not hang it.
    fn call(
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
        let answered = tokio::task::spawn_blocking(move || {
            tauri::test::get_ipc_response(
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
            .map(|answer| answer.deserialize().expect("an answer the page reads"))
        });
        async move {
            tokio::time::timeout(SOON, answered)
                .await
                .expect("the page was answered within the limit")
                .expect("joins")
        }
    }

    /// Opens a view of `session`, publishing on `channel`.
    async fn open(&self, session: SessionId, channel: u32) -> String {
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
    async fn newest(&self, channel: u32, holds: impl Fn(&Value) -> bool) -> Value {
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

    /// A view of `session` that shows its screen.
    async fn showing(&self, session: SessionId, channel: u32) -> String {
        let view = self.open(session, channel).await;
        self.newest(channel, |state| state["state"] == "showing")
            .await;
        view
    }

    /// Takes control of `view` as the page's control request 1, and waits until the session has
    /// given it.
    async fn takes_control(&self, view: &str, channel: u32) {
        self.call(
            "terminal_view_input",
            json!({"view": view, "input": {"kind": "take", "number": 1}}),
        )
        .await
        .expect("the take is taken");
        self.newest(channel, |state| state["control"]["state"] == "controlling")
            .await;
    }

    /// The launch surface `view` reads on its own link.
    async fn surface(&self, view: &str) -> Value {
        self.call("terminal_view_launch_surface", json!({ "view": view }))
            .await
            .expect("the launch surface is read")
    }

    /// A launch of `claude` pressed on `view`, quoting the prompt and the buffer given.
    fn press(
        &self,
        view: &str,
        prompt: u64,
        buffer: u64,
    ) -> impl std::future::Future<Output = Result<Value, Value>> {
        self.call(
            "terminal_view_launch",
            json!({ "view": view, "press": {
                "command": { "arguments": ["claude"] },
                "expected_prompt_generation": prompt.to_string(),
                "expected_buffer_revision": buffer.to_string(),
            }}),
        )
    }
}

/// The code a command was refused with.
fn code(refusal: &Value) -> &str {
    refusal["code"].as_str().expect("a refusal's code")
}

/// A managed session at an empty prompt, a view of it that has taken control, and the reader's
/// proof of the fence that control asks for.
async fn controlled() -> (Hosted, Page, String) {
    let mut hosted = hosted().await;
    hosted.enters_the_prompt().await;
    let page = Page::new(hosted.temp.environment());
    let view = page.showing(hosted.session_id, FIRST).await;
    // The reader is answered while the take is waited for, since which of them comes first is the
    // worker's.
    tokio::join!(page.takes_control(&view, FIRST), hosted.proves_a_fence());
    (hosted, page, view)
}

/// KR-REQ-13.11: a press through a view is accepted by a real worker from the connection whose
/// attachment holds the input, and only from it. The view reads the surface as held here at the
/// prompt the reader reported; a press that quotes a prompt that has moved is refused by the worker
/// as `DRAFT_CONFLICT` before the reader is asked; a view that does not hold the input is refused
/// as `LEASE_LOST`; and the press that quotes what was read is installed by the reader, which the
/// page is told with the revision the reader reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_press_through_the_view_is_accepted_only_from_the_view_that_holds_the_input() {
    let (mut hosted, page, view) = controlled().await;

    let surface = page.surface(&view).await;
    assert_eq!(surface["state"], "served", "{surface}");
    assert_eq!(surface["surface"]["input"], "held_here", "{surface}");
    let editor = &surface["surface"]["editor"];
    assert_eq!(editor["state"], "verified", "{surface}");
    assert_eq!(editor["prompt_generation"], PROMPT.to_string(), "{surface}");
    assert_eq!(editor["buffer_revision"], BUFFER.to_string(), "{surface}");

    // A prompt that moved: the worker refuses the quote before anything reaches the reader.
    let stale = page
        .press(&view, PROMPT + 1, BUFFER)
        .await
        .expect_err("the prompt moved");
    assert_eq!(code(&stale), "DRAFT_CONFLICT", "{stale}");

    // A view that holds nothing: the worker refuses a press from a connection whose attachment is
    // not the one that holds the input.
    let watching = page.showing(hosted.session_id, SECOND).await;
    let refused = page
        .press(&watching, PROMPT, BUFFER)
        .await
        .expect_err("this view holds nothing");
    assert_eq!(code(&refused), "LEASE_LOST", "{refused}");

    // The quote the view read: the reader is asked for exactly it, and installs it.
    let pressing = page.press(&view, PROMPT, BUFFER);
    let asked = hosted.install_asked().await;
    assert_eq!(
        asked.command,
        kr_protocol::root::LaunchCommand::Arguments(vec!["claude".to_owned()])
    );
    assert_eq!(
        asked.expected_prompt_generation,
        PromptGeneration::new(PROMPT)
    );
    assert_eq!(
        asked.expected_buffer_revision,
        EditorBufferRevision::new(BUFFER)
    );
    hosted.installs(&asked).await;
    let installed = pressing.await.expect("the launch is installed");
    assert_eq!(
        installed["prompt_generation"],
        PROMPT.to_string(),
        "{installed}"
    );
    assert_eq!(
        installed["buffer_revision"],
        (BUFFER + 1).to_string(),
        "{installed}"
    );
    hosted.close().await;
}

/// KR-REQ-13.11: a view that is lost after its press was written, before the session answered, is
/// told the outcome is unknown and never that nothing was typed: the reader had been asked, and may
/// have installed the command. The press had reached a real worker, which has asked the reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_view_lost_after_its_press_was_sent_is_told_the_outcome_is_unknown() {
    let (mut hosted, page, view) = controlled().await;
    let pressing = page.press(&view, PROMPT, BUFFER);
    let asked = hosted.install_asked().await;
    assert_eq!(
        asked.expected_buffer_revision,
        EditorBufferRevision::new(BUFFER)
    );

    page.app
        .state::<companion_tauri::terminal::TerminalViews>()
        .lose_connection(&view);
    let told = pressing
        .await
        .expect_err("the view was lost before the session answered");
    assert_eq!(code(&told), "OUTCOME_UNKNOWN", "{told}");
    hosted.close().await;
}
