//! `kr status` against a session whose reader is scripted: the launch surface it reports is the
//! one the session's own worker answers, and the application it names is the one the worker was
//! told holds the foreground.
//!
//! The session is a managed one, hosted by this test with a real worker and a real bridge endpoint.
//! The reader on the other end of the bridge is the contract's reference bridge, so the test
//! decides when the reader enters a prompt and when it proves its queues, and the worker's answer
//! is decided by those events and nothing else.

#![cfg(unix)]

use std::sync::Arc;

use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    AttachmentId, BuildId, ConnectionId, ControllerGeneration, InputLeaseEpoch, SessionEpoch,
    SessionId,
};
use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, FenceAcknowledgement,
    KeyQueueSnapshot, PendingReaderInput, PromptGeneration, QueueDrainReport, ReaderContext,
    ReaderRevision, RootCommandBlockParams, RootEditorEnterParams, RootEditorFenceResult,
};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_shell_integration::contract::events::{BridgeEvent, HooksActivated};
use kr_shell_integration::contract::fence::LeaseView;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{BridgeAnswer, WorkerRequest};
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
use serde_json::Value;

mod support;

use support::kr;

/// How long the test waits for a frame the worker should already have sent.
const SOON: std::time::Duration = std::time::Duration::from_secs(5);

/// The numbers the scripted reader reports, all different, so that a report that reads one for
/// another shows.
const PROMPT: u64 = 12;
const BUFFER: u64 = 3;
const DIRECTORY: u64 = 5;

/// A managed session this test hosts, with its descriptor published where `kr` finds it and its
/// reader scripted by this test.
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
            .expect("the worker answered")
            .expect("a frame")
    }

    /// Attaches a terminal that is not on any connection `kr` makes, and gives it the keys.
    fn hold_the_keys(&self) -> AttachmentId {
        let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let params = SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        };
        let mut session = self.runtime.session();
        session
            .attach(&params, params.requested.clone(), attachment_id)
            .expect("attaches");
        session
            .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the keys");
        attachment_id
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
    ///
    /// The worker handles the reader's events in the order they came, and answers a later one after
    /// an earlier one, so the answer to a command block sent now is only here once everything
    /// sent before it has been handled.
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
                kr_protocol::ids::RequestId::new(0),
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

    /// Runs `kr` with `arguments` against this host and returns what it printed.
    async fn kr(&self, arguments: &[&str]) -> std::process::Output {
        let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
        let root = self.temp.root().to_path_buf();
        let runtime = self.temp.paths().runtime_root().display().to_string();
        let state = self.temp.paths().state_root().display().to_string();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(kr())
                .args(&arguments)
                // Never this test's own directory: the build tree can be on a removable volume.
                .current_dir(root)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("KR_RUNTIME_DIR", runtime)
                .env("KR_STATE_DIR", state)
                .output()
                .expect("runs kr")
        })
        .await
        .expect("joins")
    }

    /// Closes the session and waits for it, so the shell ends with it.
    async fn close(self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.runtime.wait_closed(),
        )
        .await;
    }

    /// The `--json` document `kr status` prints for this session.
    async fn status(&self) -> Value {
        let output = self.kr(&["--json", "status", "1"]).await;
        assert!(
            output.status.success(),
            "kr status failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("kr status prints a document")
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
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
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

/// KR-REQ-13.11: `kr status` reports the launch surface the session's worker answers. A reader at
/// an empty prompt that nobody holds the keys at has no fence, and its input is free; once another
/// connection holds the keys and the reader proves its queues, the surface is verified at that
/// prompt with the numbers the reader reported, and the input is held elsewhere, since `kr status`
/// holds no attachment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_13_11_status_reports_the_launch_surface_the_worker_answers() {
    let mut hosted = hosted().await;
    hosted.enters_the_prompt().await;

    let free = hosted.status().await;
    let surface = &free["launch_surface"];
    assert_eq!(
        surface["session_id"],
        hosted.session_id.to_string(),
        "{free}"
    );
    assert_eq!(surface["input"], "free", "{free}");
    assert_eq!(surface["editor"]["state"], "unverified", "{free}");
    assert_eq!(surface["editor"]["reason"], "no_fence", "{free}");
    assert_eq!(surface["shell"], "zsh", "{free}");
    assert!(surface["offers"].is_array(), "{free}");
    assert!(free.get("launch_surface_unread").is_none(), "{free}");

    let _holder = hosted.hold_the_keys();
    hosted.proves_a_fence().await;
    let held = hosted.status().await;
    let surface = &held["launch_surface"];
    assert_eq!(surface["editor"]["state"], "verified", "{held}");
    assert_eq!(
        surface["editor"]["prompt_generation"],
        PROMPT.to_string(),
        "{held}"
    );
    assert_eq!(
        surface["editor"]["buffer_revision"],
        BUFFER.to_string(),
        "{held}"
    );
    assert_eq!(
        surface["editor"]["cwd_revision"],
        DIRECTORY.to_string(),
        "{held}"
    );
    assert_eq!(surface["input"], "held_elsewhere", "{held}");

    // The line a person reads names the same numbers.
    let output = hosted.kr(&["status", "1"]).await;
    assert!(output.status.success());
    let printed = String::from_utf8_lossy(&output.stdout);
    let line = format!(
        "launch surface: verified at prompt {PROMPT} (buffer {BUFFER}, directory {DIRECTORY}); input held elsewhere"
    );
    assert!(printed.contains(&line), "{printed}");
    hosted.close().await;
}

/// KR-REQ-13.10: a session's row names the application in its foreground, in the line a person
/// reads and in the document a script reads, and names none once the foreground is no application.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_13_10_status_names_the_application_in_the_foreground() {
    let hosted = hosted().await;

    let at_the_prompt = hosted.status().await;
    assert_eq!(
        at_the_prompt["application"],
        Value::Null,
        "no application holds the foreground yet: {at_the_prompt}"
    );

    hosted
        .runtime
        .session()
        .set_application(Some("claude".to_owned()));
    let named = hosted.status().await;
    assert_eq!(named["application"], "claude", "{named}");
    let output = hosted.kr(&["status", "1"]).await;
    assert!(output.status.success());
    let printed = String::from_utf8_lossy(&output.stdout);
    let row = printed
        .lines()
        .next()
        .unwrap_or_else(|| panic!("a session line: {printed}"));
    assert!(row.contains("claude"), "the line names it: {row}");

    hosted.runtime.session().set_application(None);
    let back = hosted.status().await;
    assert_eq!(back["application"], Value::Null, "{back}");
    hosted.close().await;
}
