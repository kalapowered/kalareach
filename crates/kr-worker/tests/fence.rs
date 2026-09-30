//! The root editor's fence and detach machine, driven end to end.
//!
//! Every test here runs a real session with a real pseudo-terminal, a real owner-only endpoint and
//! a real handshake. The reader on the other end is the contract's reference bridge rather than a
//! patched shell, which is the point: what these tests exercise is the *host* half, and it has to
//! behave the same whichever qualified package is speaking to it. The package half is qualified
//! against the same corpus by its own tests.
//!
//! Every path is on the internal disk. The session's runtime directory, its journal, its spool and
//! its bridge socket all live under a temporary host tree, and nothing a launched process opens is
//! in the workspace.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ConnectionId, ControllerGeneration, InputLeaseEpoch,
    SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::root::{
    AcceptedOrigin, CwdRevision, EditorBufferRevision, EditorBusyReason, EditorKeymap, EditorState,
    FenceAcknowledgement, FenceState, KeyQueueSnapshot, LaunchCommand, PendingReaderInput,
    PromptGeneration, QueueDrainReport, ReaderContext, ReaderRevision, RootCommandAcceptedParams,
    RootEditorEnterParams, RootEditorFenceResult, RootEditorLeaveParams, RootEofDetachParams,
    ShellLaunchParams, ShellLaunchResult,
};
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_shell_integration::contract::events::{
    BridgeEvent, EofGesture, HooksActivated, LoadedModule, ModuleImports, ReaderIdle,
};
use kr_shell_integration::contract::fence::{AmbiguityReason, DetachTarget, InputRef, LeaseView};
use kr_shell_integration::contract::qualification::{IntegrationLoss, ShellKind};
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchAccepted, LaunchDecision, LaunchRejection, LaunchRejectionReason,
    WorkerRequest,
};
use kr_shell_integration::contract::transport::{HandshakeOutcome, WorkerExpectation};
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE;
use kr_shell_integration::host::scripted::{
    ReferenceShell, ScriptedBridge, ToBridge, qualified_hello,
};
use kr_transport::clock::SystemContinuousClock;
use kr_worker::fence::bridge::{FenceGate, FenceHold};
use kr_worker::fence::{FenceDriver, ReaderDiscards};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a test waits for something that should already have happened.
const SOON: Duration = Duration::from_secs(5);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn configuration(host: &kr_ipc::testing::TempHost, mode: ShellMode) -> SessionConfig {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(1),
        // A program that reads its input and says nothing, so what the session retains is what
        // the host wrote rather than what a prompt drew.
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: mode,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    }
}

fn terminal(session_id: SessionId) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

/// One session, its endpoint, its bridge and the client that talks to it.
struct Wired {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    _serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
    _bridge_task: tokio::task::JoinHandle<()>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    bridge: ScriptedBridge,
}

impl Wired {
    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Attaches a terminal and gives it the keys.
    fn holder(&self) -> AttachmentId {
        let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
        let params = terminal(self.session_id);
        let mut session = self.runtime.session();
        session
            .attach(&params, params.requested.clone(), attachment_id)
            .expect("attaches");
        session
            .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the keys");
        attachment_id
    }

    /// Reads the next frame the worker sends the bridge, or fails.
    async fn next(&mut self) -> ToBridge {
        tokio::time::timeout(SOON, self.bridge.recv())
            .await
            .expect("the worker answered")
            .expect("a frame")
    }

    /// Closes the session and waits for it, so the reader on the terminal ends with it.
    async fn close(self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(Duration::from_secs(30), self.runtime.wait_closed()).await;
        self._bridge_task.abort();
        self._serving.abort();
    }
}

/// A session with a fence on a clock this test moves, and no bridge reading it.
///
/// Nothing sweeps the machine's deadlines here except the stimuli this test sends, which is the
/// point: what a client's own request releases has to reach the terminal on that request's own
/// boundary, and a bridge timer running beside it would hide whether it did.
struct Unpumped {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    _serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    clock: Arc<kr_transport::clock::ManualClock>,
}

impl Unpumped {
    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    async fn close(self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(Duration::from_secs(30), self.runtime.wait_closed()).await;
        self._serving.abort();
    }
}

async fn unpumped() -> Unpumped {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let mut config = configuration(&temp, ShellMode::Managed);
    // A shell that echoes what it is sent and ignores an interrupt, because one of these tests
    // sends the configured native interrupt and still expects the application to be there to
    // receive what the machine released on the same boundary.
    config.shell = kr_worker::testing::posix_script(
        "trap '' INT; while IFS= read -r line; do printf '%s\\n' \"$line\"; done",
    );
    let session_id = config.session_id;
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let controller_public_key = *kr_crypto::keys::AuthorisationKeyPair::generate()
        .expect("an authorisation key")
        .public();

    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        Arc::clone(&clock) as Arc<_>,
    ));
    // Registered and qualified without a bridge: the phases are the driver's own, and what this
    // test needs from them is a session that accepts input and holds it for a reader.
    {
        let driver = session.fence_mut().expect("a driver");
        assert!(driver.registered(ShellKind::Zsh, "zle-5.9"));
        let _ = driver.bridge_event(
            kr_protocol::ids::RequestId::new(1),
            &BridgeEvent::HooksActivated(HooksActivated {
                session_id,
                prompt_generation: PromptGeneration::new(1),
                modules: Vec::new(),
            }),
        );
        assert!(driver.phase().reports_ready());
    }
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key,
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: Some(environment.journal_database(session_id)),
            },
        )
        .expect("a service"),
    );
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));
    Unpumped {
        _temp: temp,
        _service: service,
        _serving: serving,
        runtime,
        session_id,
        environment_id,
        endpoint,
        clock,
    }
}

/// Reads everything the session has retained.
fn retained(session: &Session) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = session
            .history_page(cursor, 1024 * 1024)
            .expect("reads the retained output");
        if page.bytes.as_slice().is_empty() {
            break;
        }
        seen.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
    seen
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    position(haystack, needle).is_some()
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn reference() -> ReferenceShell {
    ReferenceShell::new(ShellKind::Zsh, "/bin/cat", "5.9", "zle-5.9")
}

/// Attaches a terminal over `client` and gives it the keys.
///
/// The connection has to own the attachment that holds the lease: a launch is attributed to the
/// client that asked for it, so one that does not hold the keys on this connection cannot put a
/// command in the editor under somebody else's name.
async fn holder_over(client: &mut LocalClient, wired: &Wired) -> AttachmentId {
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::input::InputAcquireParams {
                session_id: wired.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("takes the keys");
    attachment_id
}

/// Asks the worker what one invocation resolves to, over the real endpoint.
async fn resolve_over(
    wired: &mut Wired,
    argv: &[&str],
    interactive: bool,
) -> kr_protocol::root::RootCommandResolveResult {
    resolve_at(wired, PromptGeneration::new(1), argv, interactive).await
}

/// Asks the worker what one invocation resolves to, at one prompt generation.
async fn resolve_at(
    wired: &mut Wired,
    prompt_generation: PromptGeneration,
    argv: &[&str],
    interactive: bool,
) -> kr_protocol::root::RootCommandResolveResult {
    // What a shell's own search would have found: the path it was given, or the name in a
    // directory on its search path.
    let executable = match argv.first() {
        Some(named) if named.contains('/') => (*named).to_owned(),
        Some(name) => format!("/usr/local/bin/{name}"),
        None => String::new(),
    };
    wired
        .bridge
        .send_event(BridgeEvent::CommandResolve(
            kr_protocol::root::RootCommandResolveParams {
                session_id: wired.session_id,
                prompt_generation,
                argv: argv.iter().map(|word| (*word).to_owned()).collect(),
                executable,
                interactive,
                cwd: "/Users/someone/project".to_owned(),
                cwd_revision: CwdRevision::new(1),
            },
        ))
        .await
        .expect("asks");
    loop {
        if let ToBridge::EventResult { result, .. } = wired.next().await
            && let kr_shell_integration::contract::transport::EventOutcome::CommandResolved(
                resolved,
            ) = *result
        {
            return *resolved;
        }
    }
}

/// Reports one command block over the real endpoint.
async fn block_over(
    wired: &mut Wired,
    block: kr_protocol::root::RootCommandBlockParams,
) -> kr_protocol::root::RootCommandBlockResult {
    wired
        .bridge
        .send_event(BridgeEvent::CommandBlock(Box::new(block)))
        .await
        .expect("reports");
    loop {
        if let ToBridge::EventResult { result, .. } = wired.next().await
            && let kr_shell_integration::contract::transport::EventOutcome::CommandBlockRecorded(
                recorded,
            ) = *result
        {
            return recorded;
        }
    }
}

/// Starts a managed session with its bridge registered.
async fn wired() -> Wired {
    wired_with(ShellMode::Managed, true).await
}

async fn wired_with(mode: ShellMode, register: bool) -> Wired {
    wired_profiled(
        mode,
        register,
        kr_protocol::session::LaunchProfile::default(),
    )
    .await
}

async fn wired_profiled(
    mode: ShellMode,
    register: bool,
    launch_profile: kr_protocol::session::LaunchProfile,
) -> Wired {
    wired_built(mode, register, Bridging::ordinary(), move |config| {
        config.launch_profile = launch_profile.clone();
    })
    .await
}

/// Starts a managed session with its bridge registered, on a clock this test moves, with the bridge
/// server keeping each published fence from its writer while `gate` is closed.
///
/// The machine's own deadlines pass only when the test moves `clock`, and a fence is written only
/// once the test opens the gate, so neither depends on how quickly anything here is scheduled.
async fn wired_holding_fences(
    clock: &Arc<kr_transport::clock::ManualClock>,
    gate: Option<&FenceGate>,
) -> Wired {
    wired_built(
        ShellMode::Managed,
        true,
        Bridging {
            clock: Arc::clone(clock) as Arc<_>,
            fence_hold: gate.map(|gate| FenceHold::Gate(gate.clone())),
            hello_abi: "zle-5.9",
        },
        |_| {},
    )
    .await
}

/// What a session's bridge server is built with.
struct Bridging {
    /// The clock the session's fence machine reads.
    clock: Arc<dyn kr_transport::clock::ContinuousClock>,
    /// What the server keeps each published fence from its connection's writer for, if anything.
    fence_hold: Option<FenceHold>,
    /// The editor ABI the reference shell's hello declares. The worker supports `zle-5.9`.
    hello_abi: &'static str,
}

impl Bridging {
    /// The ordinary clock, and every fence written as soon as the writer has it.
    fn ordinary() -> Self {
        Self {
            clock: Arc::new(SystemContinuousClock::new()),
            fence_hold: None,
            hello_abi: "zle-5.9",
        }
    }
}

async fn wired_built(
    mode: ShellMode,
    register: bool,
    bridging: Bridging,
    describe: impl FnOnce(&mut SessionConfig),
) -> Wired {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let mut config = configuration(&temp, mode);
    describe(&mut config);
    let session_id = config.session_id;
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
    // is a fresh one rather than the environment's own. Opening the environment's identity writes to
    // the platform credential store, which costs about a minute per session and proves nothing here.
    let controller_public_key = *kr_crypto::keys::AuthorisationKeyPair::generate()
        .expect("an authorisation key")
        .public();

    // The bridge endpoint is inside the session's own owner-only runtime directory, on the
    // internal disk, and it is bound before the shell starts.
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
    if mode == ShellMode::Managed {
        session.install_fence(FenceDriver::new(
            session_id,
            LeaseView::unheld(InputLeaseEpoch::new(0)),
            bridging.clock,
        ));
    }
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    let expectation = WorkerExpectation {
        session_id,
        // The reference bridge runs in this process, so this process is the root shell the worker
        // expects on its endpoint.
        root_process: process.clone(),
        supported_editor_abis: vec!["zle-5.9".to_owned()],
        supported_integration_versions: vec!["1".to_owned()],
        launched_package: None,
        already_registered: false,
        gesture: EofGesture::default(),
    };
    let mut server = kr_worker::fence::bridge::BridgeServer::new(
        Arc::clone(&runtime),
        host_endpoint,
        expectation,
    );
    if let Some(hold) = bridging.fence_hold {
        server = server.holding_fences(hold);
    }
    let bridge_task = tokio::spawn(server.serve());

    let declared = ReferenceShell::new(ShellKind::Zsh, "/bin/cat", "5.9", bridging.hello_abi);
    let hello =
        qualified_hello(&declared, session_id, &address, process, &secret).expect("a hello");
    let (mut bridge, outcome) =
        tokio::time::timeout(SOON, ScriptedBridge::connect(&address, &hello))
            .await
            .expect("the worker accepted a connection")
            .expect("connects");
    if bridging.hello_abi == "zle-5.9" {
        assert!(
            matches!(outcome, HandshakeOutcome::Accepted(_)),
            "a qualified root shell registers: {outcome:?}"
        );
    } else {
        assert!(
            matches!(outcome, HandshakeOutcome::Refused(_)),
            "a shell built against another editor is refused: {outcome:?}"
        );
    }
    if register {
        // The user's startup files have run and the integration's own hooks are live. Until this
        // the session is authenticated but not qualified, and it holds no fence.
        bridge
            .send_event(BridgeEvent::HooksActivated(HooksActivated {
                session_id,
                prompt_generation: PromptGeneration::new(1),
                modules: Vec::new(),
            }))
            .await
            .expect("reports");
    }

    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key,
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: Some(environment.journal_database(session_id)),
            },
        )
        .expect("a service"),
    );
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));

    Wired {
        _temp: temp,
        _service: service,
        _serving: serving,
        _bridge_task: bridge_task,
        runtime,
        session_id,
        environment_id,
        endpoint,
        bridge,
    }
}

fn editor_state(empty: bool, revision: u64) -> EditorState {
    EditorState {
        buffer_empty: empty,
        buffer_revision: EditorBufferRevision::new(revision),
        keymap: EditorKeymap::Emacs,
        pending: PendingReaderInput::NONE,
    }
}

fn enter(session_id: SessionId, prompt: u64, revision: u64) -> BridgeEvent {
    BridgeEvent::EditorEnter(RootEditorEnterParams {
        session_id,
        root_process: kr_ipc::identity::current_process_start_identity().expect("this process"),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        reader_context: ReaderContext::Primary,
        editor: editor_state(true, 1),
        cwd_revision: CwdRevision::new(1),
    })
}

fn idle(session_id: SessionId, prompt: u64, revision: u64) -> BridgeEvent {
    BridgeEvent::ReaderIdle(ReaderIdle {
        session_id,
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        reader_context: ReaderContext::Primary,
        snapshot: KeyQueueSnapshot::drained(),
        editor: editor_state(true, 1),
        cwd_revision: CwdRevision::new(1),
    })
}

fn drained(prompt: u64, revision: u64, fence_id: kr_protocol::root::FenceId) -> BridgeAnswer {
    BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(FenceAcknowledgement {
        fence_id,
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        reader_context: ReaderContext::Primary,
        queues: QueueDrainReport::CLEAR,
        snapshot: KeyQueueSnapshot::drained(),
        editor: editor_state(true, 1),
        cwd_revision: CwdRevision::new(1),
    }))
}

/// Takes the session to a published fence for a reader the `read` builtin opened.
///
/// The same exchange the primary prompt has, with the context the reader is actually in: a command
/// is running and it is reading its own input through the editor.
async fn fenced_read(
    wired: &mut Wired,
    prompt: u64,
    revision: u64,
) -> kr_protocol::root::EditorFence {
    let mut entry = enter(wired.session_id, prompt, revision);
    if let BridgeEvent::EditorEnter(params) = &mut entry {
        params.reader_context = ReaderContext::ReadBuiltin;
    }
    wired.bridge.send_event(entry).await.expect("enters");
    let fence_id = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(params) => break params.fence_id,
                _ => continue,
            },
            _ => continue,
        }
    };
    let mut answer = drained(prompt, revision, fence_id);
    if let BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement)) = &mut answer {
        acknowledgement.reader_context = ReaderContext::ReadBuiltin;
    }
    wired
        .bridge
        .answer(kr_protocol::ids::RequestId::new(0), answer)
        .await
        .expect("acknowledges");
    loop {
        match wired.next().await {
            ToBridge::FencePublished(kr_protocol::root::FencePublication::Published(fence)) => {
                return fence;
            }
            ToBridge::FencePublished(other) => panic!("the fence was withheld: {other:?}"),
            _ => {}
        }
    }
}

/// Takes the session through entry to a published fence, and returns it.
async fn fenced(wired: &mut Wired, prompt: u64, revision: u64) -> kr_protocol::root::EditorFence {
    wired
        .bridge
        .send_event(enter(wired.session_id, prompt, revision))
        .await
        .expect("enters");
    let fence_id = asked_for_a_fence(wired).await;
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            drained(prompt, revision, fence_id),
        )
        .await
        .expect("acknowledges");
    published(wired).await
}

/// Waits for the worker to ask the reader for a fence, and returns the fence it asked for.
async fn asked_for_a_fence(wired: &mut Wired) -> kr_protocol::root::FenceId {
    loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(params) => return params.fence_id,
                // A cancellation the entry asked for is not the exchange; it is answered by
                // whichever test needs it.
                _ => continue,
            },
            _ => continue,
        }
    }
}

/// Waits for the worker to publish a fence to the reader, and returns it.
async fn published(wired: &mut Wired) -> kr_protocol::root::EditorFence {
    loop {
        match wired.next().await {
            ToBridge::FencePublished(kr_protocol::root::FencePublication::Published(fence)) => {
                return fence;
            }
            ToBridge::FencePublished(other) => panic!("the fence was withheld: {other:?}"),
            _ => {}
        }
    }
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.22, KR-REQ-23.37: the bridge is authenticated and ABI-checked, and the root methods
// travel only on this endpoint.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.22, KR-REQ-23.37.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_launched_root_shell_registers_and_only_on_its_own_endpoint() {
    let wired = wired().await;
    // The registration succeeded in the harness. A second connection with the same proof is
    // refused, because this session already has a registered root integration.
    let registration = {
        let session = wired.runtime.session();
        session
            .root_integration()
            .expect("the handshake was recorded")
            .clone()
    };
    assert_eq!(registration.shell.kind, ShellKind::Zsh);
    assert_eq!(registration.shell.editor_abi, "zle-5.9");

    // Every root method is in the registry's own root-integration group, which no client endpoint
    // serves: they arrive here as bridge events and nowhere else.
    for method in [
        "root.editor.enter",
        "root.editor.leave",
        "root.editor.fence",
        "root.eof.detach",
        "root.command.accepted",
    ] {
        assert!(
            kr_worker::fence::bridge::BridgeServer::serves(method),
            "{method} belongs to the root integration"
        );
        let entry = kr_protocol::method::lookup(method).expect("a listed method");
        assert_eq!(
            entry.ingress,
            &[kr_protocol::actor::ActorIngress::LocalIpc],
            "{method} is private IPC only"
        );
    }
    assert!(!kr_worker::fence::bridge::BridgeServer::serves(
        "shell.launch"
    ));
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.77, KR-REQ-07.79: entry and a lease change start an exchange; a fence publishes only
// after an acknowledged drain.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.77, KR-REQ-07.79.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_publishes_only_after_the_reader_says_its_queues_are_clear() {
    let mut wired = wired().await;
    // The keys are taken before a reader is registered, so nothing waits for a fence: outside a
    // registered root editor the lease changes and input forwards immediately.
    let holder = wired.holder();
    let fence = fenced(&mut wired, 1, 1).await;
    assert_eq!(fence.originating_attachment, holder);
    assert_eq!(fence.prompt_generation, PromptGeneration::new(1));
    assert_eq!(
        wired.runtime.session().fence().expect("a driver").state(),
        FenceState::Fenced
    );
    wired.close().await;
}

/// KR-REQ-07.79: the 250 ms rule on plain editor entry, with the release and the event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unanswered_exchange_releases_the_held_input_and_says_the_editor_was_busy() {
    let mut wired = wired().await;
    let _holder = wired.holder();
    wired
        .bridge
        .send_event(enter(wired.session_id, 1, 1))
        .await
        .expect("enters");
    // The reader is asked and never answers.
    let asked = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(params) => break params,
                WorkerRequest::Cancel(_) => continue,
                other => panic!("unexpected request: {other:?}"),
            },
            _ => continue,
        }
    };
    assert_eq!(asked.deadline_ms.get(), 250);
    let withheld = loop {
        match wired.next().await {
            ToBridge::FencePublished(publication) => break publication,
            _ => continue,
        }
    };
    assert!(
        matches!(
            withheld,
            kr_protocol::root::FencePublication::Withheld {
                reason: kr_protocol::root::WithheldReason::ExchangeTimedOut,
                ..
            }
        ),
        "the exchange timed out: {withheld:?}"
    );
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert_eq!(
            driver.state(),
            FenceState::Unfenced,
            "the editor stays unfenced"
        );
        assert!(driver.held().is_empty(), "nothing is still held");
    }
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.79, KR-REQ-07.84: what a fence lets go of reaches the shell after the fence does.
// --------------------------------------------------------------------------------------------

/// How long the cases that keep a fence from the writer watch the shell for keys that should be
/// waiting.
///
/// A fence is written only when the case opens its gate, and the case reads the session's queue on
/// the step that decides, so this decides nothing by itself. It is many times what a key that did
/// not wait takes to reach the shell and come back as output, which is what the check beside that
/// read looks for.
const WHILE_HELD: Duration = Duration::from_millis(300);

/// Types `bytes` through the lease `holder` holds, as its client's `input.write` does, and hands
/// the session's queue for the terminal to the writer.
fn type_keys(wired: &Wired, holder: AttachmentId, sequence: u64, bytes: &[u8]) {
    let mut session = wired.runtime.session();
    let epoch = session.lease().epoch.get();
    session
        .write_input(
            holder,
            epoch,
            sequence,
            bytes,
            None,
            std::time::Instant::now(),
        )
        .expect("the keys are accepted");
    wired.runtime.flush_locked(&mut session);
}

/// Returns whether the shell has already echoed `keys`.
///
/// The shell here is `cat` on a terminal in its ordinary mode, which echoes what it is given the
/// moment it arrives, so keys in the output are keys that reached the shell.
fn echoed_now(runtime: &SessionRuntime, keys: &[u8]) -> bool {
    contains(&retained(&runtime.session()), keys)
}

/// Waits until the shell has echoed `keys`.
async fn echoed(runtime: &SessionRuntime, keys: &[u8]) {
    tokio::time::timeout(SOON, async {
        while !echoed_now(runtime, keys) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the shell never had {}",
            String::from_utf8_lossy(keys).escape_debug()
        )
    });
}

/// Waits until the machine has published the fence its reader acknowledged.
async fn until_fenced(runtime: &SessionRuntime) {
    tokio::time::timeout(SOON, async {
        while runtime.session().fence().expect("a driver").state() != FenceState::Fenced {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the acknowledged fence was published");
}

/// Returns how many batches the session keeps behind a fence its writer has not written.
fn waiting(runtime: &SessionRuntime) -> usize {
    runtime.session().waiting_for_fence()
}

/// Waits until the connection's writer has brought the published fence to `gate`, or fails.
///
/// A writer that ended before it got there would never arrive, and the case fails rather than
/// waiting for it.
async fn at_the_gate(gate: &FenceGate) {
    tokio::time::timeout(SOON, gate.arrived(1))
        .await
        .expect("the writer brought the published fence to the gate");
}

/// Takes the session through entry to a published fence, typing `held` while the reader is asked
/// when there is anything to type, and returns once the machine has published the fence.
async fn fenced_with(
    wired: &mut Wired,
    holder: AttachmentId,
    held: Option<&[u8]>,
) -> kr_protocol::root::FenceId {
    wired
        .bridge
        .send_event(enter(wired.session_id, 1, 1))
        .await
        .expect("enters");
    let fence_id = asked_for_a_fence(wired).await;
    if let Some(keys) = held {
        type_keys(wired, holder, 0, keys);
        assert_eq!(
            wired
                .runtime
                .session()
                .fence()
                .expect("a driver")
                .held()
                .len(),
            1,
            "the machine holds what arrives while the reader is asked"
        );
    }
    wired
        .bridge
        .answer(kr_protocol::ids::RequestId::new(0), drained(1, 1, fence_id))
        .await
        .expect("acknowledges");
    until_fenced(&wired.runtime).await;
    fence_id
}

/// KR-REQ-07.79, KR-REQ-07.84: keys held while the reader is asked reach the shell only once the
/// fence they were held for has been written to the reader.
///
/// A reader takes what is on its endpoint before it acts on a key, and only what is already there.
/// A key that reaches the shell ahead of the fence it was released under is accepted without it:
/// the line it makes is one the worker cannot attribute, and it runs without the capability the
/// fence exists to mint. The connection's writer here keeps the published fence back, as a writer
/// on a loaded machine sometimes does, until the case lets it go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_keys_reach_the_shell_only_once_their_fence_is_written() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let holder = wired.holder();
    let fence_id = fenced_with(&mut wired, holder, Some(b"held-keys\n")).await;
    // The machine published the fence and let the keys go on one step. The writer has the fence
    // and is keeping it, so the session keeps the keys.
    at_the_gate(&gate).await;
    assert_eq!(
        waiting(&wired.runtime),
        1,
        "the keys went to the terminal's writer before the fence they were held for was written"
    );
    tokio::time::sleep(WHILE_HELD).await;
    assert!(
        !echoed_now(&wired.runtime, b"held-keys"),
        "the keys reached the shell before the fence they were held for reached the reader"
    );

    gate.open();
    let fence = published(&mut wired).await;
    assert_eq!(fence.fence_id, fence_id);
    echoed(&wired.runtime, b"held-keys").await;
    assert_eq!(waiting(&wired.runtime), 0);
    assert_eq!(
        gate.kept_as_written(),
        [1],
        "the keys were still kept when the fence reached the socket"
    );
    wired.close().await;
}

/// KR-REQ-07.79, KR-REQ-07.84: keys typed once the fence is published, while it is still on its
/// way to the reader, wait for it as well.
///
/// The machine forwards them the moment they arrive, because it is fenced and nothing is being
/// decided; the reader is not fenced until it has the fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_typed_while_their_fence_is_on_its_way_wait_for_it() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let holder = wired.holder();
    let _ = fenced_with(&mut wired, holder, None).await;
    at_the_gate(&gate).await;

    type_keys(&wired, holder, 0, b"typed-keys\n");
    assert!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .held()
            .is_empty(),
        "a fenced machine forwards what arrives rather than holding it"
    );
    assert_eq!(
        waiting(&wired.runtime),
        1,
        "the keys went to the terminal's writer before the fence published for them was written"
    );
    tokio::time::sleep(WHILE_HELD).await;
    assert!(
        !echoed_now(&wired.runtime, b"typed-keys"),
        "the keys reached the shell before the fence published for them reached the reader"
    );

    gate.open();
    published(&mut wired).await;
    echoed(&wired.runtime, b"typed-keys").await;
    assert_eq!(
        gate.kept_as_written(),
        [1],
        "the keys were still kept when the fence reached the socket"
    );
    wired.close().await;
}

/// KR-REQ-07.79, KR-REQ-07.84, KR-REQ-07.24: keys waiting for a fence whose connection ends before
/// the fence is written go to the shell only once the worker has recorded the loss.
///
/// They are not fenced input: the fence went with the connection, the session is degraded, and
/// nothing the reader says about a line can reach the worker any more. So they go to the shell in
/// their order, as input a degraded session forwards like any application's, which is what the
/// machine does with what it was holding when a bridge is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_behind_a_fence_never_written_go_once_the_loss_is_recorded() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    // Never opened, so the fence is never written.
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let holder = wired.holder();
    let _ = fenced_with(&mut wired, holder, Some(b"stranded-keys\n")).await;
    at_the_gate(&gate).await;
    assert_eq!(waiting(&wired.runtime), 1, "the keys wait for their fence");
    tokio::time::sleep(WHILE_HELD).await;
    assert!(
        !echoed_now(&wired.runtime, b"stranded-keys"),
        "the keys reached the shell before the fence they were held for reached the reader"
    );

    // The reader goes away with the fence still unwritten.
    let Wired {
        _temp,
        _service,
        _serving,
        _bridge_task,
        runtime,
        bridge,
        ..
    } = wired;
    drop(bridge);
    echoed(&runtime, b"stranded-keys").await;
    {
        let session = runtime.session();
        let driver = session.fence().expect("a driver");
        assert!(
            driver.fence().is_none(),
            "the fence went with the connection"
        );
        assert_ne!(driver.state(), FenceState::Fenced);
        assert_eq!(
            driver.phase().phase(),
            kr_shell_integration::contract::qualification::IntegrationPhase::Degraded,
            "the loss was recorded before the keys went"
        );
        assert_eq!(session.waiting_for_fence(), 0);
    }

    runtime.close(ClosureReason::CloseRequested).1.release();
    let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
    _bridge_task.abort();
    _serving.abort();
}

/// KR-REQ-07.79, KR-REQ-07.24: a reader that does not take a published fence within the limit has
/// its connection ended, and the keys waiting for the fence go once the loss is recorded.
///
/// A reader that has stopped reading its own socket must not hold the terminal's input for as long
/// as it stays away. The writer here never writes the fence, as one stuck behind such a reader
/// would not, and the limit passes on the session's own clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_not_written_within_its_limit_ends_the_connection_and_lets_the_keys_go() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let holder = wired.holder();
    let _ = fenced_with(&mut wired, holder, Some(b"waiting-keys\n")).await;
    at_the_gate(&gate).await;
    assert_eq!(waiting(&wired.runtime), 1, "the keys wait for their fence");

    clock.advance(kr_worker::fence::FENCE_WRITE_LIMIT);
    wired
        .runtime
        .session()
        .fence()
        .expect("a driver")
        .waker()
        .notify_one();
    echoed(&wired.runtime, b"waiting-keys").await;
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert!(
            driver.fence().is_none(),
            "the fence went with the connection"
        );
        assert_eq!(
            driver.phase().phase(),
            kr_shell_integration::contract::qualification::IntegrationPhase::Degraded,
            "the loss was recorded before the keys went"
        );
        assert_eq!(session.waiting_for_fence(), 0);
    }
    // The bridge finds its connection over.
    tokio::time::timeout(SOON, async { while wired.bridge.recv().await.is_ok() {} })
        .await
        .expect("the connection ended");
    wired.close().await;
}

/// KR-REQ-07.79, KR-REQ-07.82: a takeover whose exchange times out lets the new holder's keys go at
/// the timeout, while the fence the previous holder had is still unwritten.
///
/// Input waits for a published fence only while it is the machine's. The takeover drops the first
/// fence, so nothing waits for its frame any more: an acceptance or a detach made through it is
/// refused as not the fence this session holds, however late it reaches the reader. The new
/// exchange's request waits on the writer behind the frame it is keeping, so the reader never
/// answers, and the 250 ms rule has the held keys released in order, unfenced, with the connection
/// still up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_that_times_out_lets_its_keys_go_while_an_earlier_fence_is_unwritten() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let first = wired.holder();
    let _ = fenced_with(&mut wired, first, None).await;
    at_the_gate(&gate).await;

    let second = wired.holder();
    type_keys(&wired, second, 0, b"second-keys\n");
    assert_eq!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .held()
            .len(),
        1,
        "the machine holds the new holder's keys while it asks for a new fence"
    );
    // The exchange's deadline passes on the machine's own clock.
    clock.advance(Duration::from_millis(250));
    wired
        .runtime
        .session()
        .fence()
        .expect("a driver")
        .waker()
        .notify_one();
    echoed(&wired.runtime, b"second-keys").await;
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert_eq!(
            driver.state(),
            FenceState::Unfenced,
            "the editor stays unfenced"
        );
        assert_eq!(
            driver.phase().phase(),
            kr_shell_integration::contract::qualification::IntegrationPhase::Qualified,
            "nothing ended the connection"
        );
        assert_eq!(session.waiting_for_fence(), 0);
    }
    gate.open();
    wired.close().await;
}

/// KR-REQ-07.77, KR-REQ-07.79: keys waiting for a fence go to the terminal the moment the reader
/// leaves the prompt, while that fence is still unwritten.
///
/// Outside a registered root editor input does not wait for a reader. The leave drops the fence,
/// so nothing waits for its frame, and the keys go to whatever reads the terminal now.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_waiting_for_a_fence_go_when_the_reader_leaves_the_prompt() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let holder = wired.holder();
    let _ = fenced_with(&mut wired, holder, None).await;
    at_the_gate(&gate).await;
    type_keys(&wired, holder, 0, b"leaving-keys\n");
    assert_eq!(waiting(&wired.runtime), 1, "the keys wait for their fence");

    // Another reader takes over from the prompt, a pager inside the shell, say.
    wired
        .bridge
        .send_event(BridgeEvent::EditorLeave(RootEditorLeaveParams {
            session_id: wired.session_id,
            prompt_generation: PromptGeneration::new(1),
            reader_revision: ReaderRevision::new(1),
            reason: kr_protocol::root::EditorLeaveReason::ReaderTakeover,
        }))
        .await
        .expect("leaves");
    echoed(&wired.runtime, b"leaving-keys").await;
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert_eq!(driver.state(), FenceState::Outside);
        assert!(driver.fence().is_none(), "the leave dropped the fence");
        assert_eq!(session.waiting_for_fence(), 0);
    }
    gate.open();
    wired.close().await;
}

/// KR-REQ-07.83, KR-REQ-07.79: a launch whose hold ends while the fence it reserved is still
/// unwritten gives up the connection, and the keys it held go at the end of the hold.
///
/// The fence is still the machine's, so the keys may not go ahead of it. A writer that has kept a
/// frame for a launch's whole hold is not delivering, and the connection is given up at once rather
/// than at the write limit: the loss drops the fence, the keys go unfenced at the time the 250 ms
/// rule gives, and the caller is told nothing can say whether a command was installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_that_times_out_behind_an_unwritten_fence_gives_up_the_connection() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let gate = FenceGate::closed();
    let mut wired = wired_holding_fences(&clock, Some(&gate)).await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let holder = holder_over(&mut client, &wired).await;
    let _ = fenced_with(&mut wired, holder, None).await;
    at_the_gate(&gate).await;

    // The launch reserves the fence, and its request waits on the writer behind it.
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::QuotedCommand("true".to_owned()),
        expected_prompt_generation: PromptGeneration::new(1),
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    tokio::time::timeout(SOON, async {
        while wired.runtime.session().fence().expect("a driver").state()
            != FenceState::LaunchReserved
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the launch reserved the fence");
    type_keys(&wired, holder, 0, b"launch-held-keys\n");
    assert_eq!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .held()
            .len(),
        1,
        "the machine holds what arrives while a launch is in flight"
    );

    // The launch's hold ends on the machine's own clock.
    clock.advance(Duration::from_millis(250));
    wired
        .runtime
        .session()
        .fence()
        .expect("a driver")
        .waker()
        .notify_one();
    echoed(&wired.runtime, b"launch-held-keys").await;
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert!(
            driver.fence().is_none(),
            "the fence went with the connection"
        );
        assert_eq!(
            driver.phase().phase(),
            kr_shell_integration::contract::qualification::IntegrationPhase::Degraded,
            "the loss was recorded before the keys went"
        );
        assert_eq!(session.waiting_for_fence(), 0);
    }
    let error = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect_err("refused");
    assert_eq!(
        error.code,
        ErrorCode::OutcomeUnknown,
        "nothing can say whether the reader installed the command"
    );
    wired.close().await;
}

/// KR-REQ-07.79: keys typed with no fence on its way to the reader are handed to the terminal's
/// writer on the step that accepted them.
///
/// Only a published fence the writer has not written holds anything back. Once the writer has
/// written it, a line typed at the prompt waits for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_typed_behind_a_written_fence_are_not_held() {
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let mut wired = wired_holding_fences(&clock, None).await;
    let holder = wired.holder();
    let _fence = fenced(&mut wired, 1, 1).await;
    // The reader has the fence; the writer says so on its own task, just after.
    tokio::time::timeout(SOON, async {
        while wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .unwritten_fence()
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the writer reported the fence written");

    let taken = {
        let mut session = wired.runtime.session();
        let epoch = session.lease().epoch.get();
        session
            .write_input(
                holder,
                epoch,
                0,
                b"ordinary-keys\n",
                None,
                std::time::Instant::now(),
            )
            .expect("the keys are accepted");
        session.take_pending_input()
    };
    assert!(
        taken.iter().any(|batch| matches!(
            batch,
            kr_worker::session::InputBatch::Lease { bytes, .. } if bytes == b"ordinary-keys\n"
        )),
        "the keys go to the writer at once: {taken:?}"
    );
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.78, KR-REQ-07.82: a takeover cancels the reader's incomplete operation, discards the
// old lease's undelivered input and reports it.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.78: the takeover receipt records pending, known and unknown rather than a zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_cancels_the_readers_wait_and_the_receipt_says_what_it_knows() {
    let mut wired = wired().await;
    let _first = wired.holder();
    let _fence = fenced(&mut wired, 1, 1).await;

    // A second client takes the keys while the reader is fenced.
    let second = AttachmentId::new(kr_ipc::new_uuid());
    {
        let params = terminal(wired.session_id);
        let mut session = wired.runtime.session();
        session
            .attach(&params, params.requested.clone(), second)
            .expect("attaches");
        session
            .acquire_input(second, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the keys");
    }
    // The reader is asked to end whatever key wait the previous holder left it in, without losing
    // the edit buffer.
    let cancellation = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Cancel(cancel) => break cancel,
                _ => continue,
            },
            _ => continue,
        }
    };
    {
        let session = wired.runtime.session();
        let receipt = session
            .fence()
            .expect("a driver")
            .open_receipt()
            .copied()
            .expect("a takeover opened a receipt");
        assert_eq!(
            receipt.reader_discards,
            ReaderDiscards::Pending,
            "the reader has been asked and has not answered"
        );
    }
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Cancel(
                kr_shell_integration::contract::requests::CancellationReport {
                    sequence: cancellation.sequence,
                    epoch: cancellation.epoch,
                    prompt_generation: cancellation.prompt_generation,
                    reader_revision: cancellation.reader_revision,
                    cancelled: kr_shell_integration::contract::requests::CancelledOperations {
                        partial_escape: true,
                        ..kr_shell_integration::contract::requests::CancelledOperations::NONE
                    },
                    buffer_preserved: true,
                    discarded_bytes: U64::new(3),
                },
            ),
        )
        .await
        .expect("reports");
    let receipt = tokio::time::timeout(SOON, async {
        loop {
            {
                let session = wired.runtime.session();
                let open = session.fence().expect("a driver").open_receipt().copied();
                if open.is_none() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        wired.runtime.session().last_takeover_receipt()
    })
    .await
    .expect("the receipt closed");
    let receipt = receipt.expect("a completed receipt");
    assert_eq!(
        receipt.reader_discards,
        ReaderDiscards::Known(U64::new(3)),
        "the reader answered inside the hold"
    );
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.80: the interrupt bypasses the hold, needs the current epoch and takes no bytes.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.80, KR-REQ-01.12.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_needs_the_current_lease_and_is_not_held_behind_a_reader() {
    let mut wired = wired().await;
    let holder = wired.holder();
    wired
        .bridge
        .send_event(enter(wired.session_id, 1, 1))
        .await
        .expect("enters");
    // An exchange is in flight, so ordinary input is being held. The interrupt is not.
    let epoch = wired.runtime.session().lease().epoch.get();
    {
        let mut session = wired.runtime.session();
        session.interrupt(holder, epoch).expect("interrupts");
        let refused = session
            .interrupt(holder, epoch.saturating_sub(1))
            .expect_err("a stale epoch holds no lease");
        assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);
        let stranger = AttachmentId::new(kr_ipc::new_uuid());
        let refused = session
            .interrupt(stranger, epoch)
            .expect_err("a caller that does not hold the keys interrupts nothing");
        assert_eq!(refused.to_protocol_error().code, ErrorCode::LeaseLost);
    }
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.81, KR-REQ-07.82, KR-REQ-01.12: an attributable detach, and a stale one refused.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.81, KR-REQ-07.82, KR-REQ-01.12.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_prompt_gesture_detaches_the_attachment_its_fence_names() {
    let mut wired = wired().await;
    let holder = wired.holder();
    let fence = fenced(&mut wired, 1, 1).await;
    assert_eq!(fence.originating_attachment, holder);

    wired
        .bridge
        .send_event(BridgeEvent::EofDetach(RootEofDetachParams {
            session_id: wired.session_id,
            fence_id: fence.fence_id,
            prompt_generation: fence.prompt_generation,
            input_epoch: fence.input_epoch,
        }))
        .await
        .expect("submits");
    let detached = loop {
        match wired.next().await {
            ToBridge::EventResult { result, .. } => match *result {
                kr_shell_integration::contract::transport::EventOutcome::Detached(result) => {
                    break result;
                }
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(detached.detached_attachment, holder);
    assert_eq!(detached.state, FenceState::Unfenced);
    assert!(
        wired
            .runtime
            .session()
            .attachments()
            .iter()
            .all(|summary| summary.attachment_id != holder),
        "the attachment the fence named is gone"
    );
    wired.close().await;
}

/// KR-REQ-07.81: a gesture with no fence behind it is refused, so the bridge consumes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gesture_with_a_stale_fence_is_refused_rather_than_becoming_an_end_of_file() {
    let mut wired = wired().await;
    let _holder = wired.holder();
    let fence = fenced(&mut wired, 1, 1).await;
    // The reader moves on, which invalidates the fence.
    wired
        .bridge
        .send_event(BridgeEvent::EditorLeave(RootEditorLeaveParams {
            session_id: wired.session_id,
            prompt_generation: fence.prompt_generation,
            reader_revision: ReaderRevision::new(1),
            reason: kr_protocol::root::EditorLeaveReason::CommandAccepted,
        }))
        .await
        .expect("leaves");
    wired
        .bridge
        .send_event(BridgeEvent::EofDetach(RootEofDetachParams {
            session_id: wired.session_id,
            fence_id: fence.fence_id,
            prompt_generation: fence.prompt_generation,
            input_epoch: fence.input_epoch,
        }))
        .await
        .expect("submits");
    let refusal = loop {
        match wired.next().await {
            ToBridge::EventResult { result, .. } => match *result {
                kr_shell_integration::contract::transport::EventOutcome::Refused(error) => {
                    break error;
                }
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(refusal.code, ErrorCode::EditorBusy);
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// A-17: a desktop reading never stands between the fence and the terminal.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.83: asking whether the desktop has gone costs no conversation with the platform.
///
/// The watch holds the answer and a reading reaches it from outside the session, so a session held
/// while a login facility was answering is not a thing that can happen. This is the shape of the
/// fix: a reading taken back under the lock would make this question as slow as the platform is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn asking_whether_the_desktop_has_gone_takes_no_reading() {
    let temp = kr_ipc::testing::TempHost::create();
    let mut config = configuration(&temp, ShellMode::Managed);
    config.worker_profile = WorkerProfile::DesktopBound;
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");

    // What a reading costs, taken here, on this thread, exactly as the supervision takes it.
    let probing = std::time::Instant::now();
    let _ = kr_worker::desktop::Probe::Session.take();
    let reading = probing.elapsed();

    // What the answer is depends on the host: a machine with no graphical login has already lost
    // the desktop a desktop-bound session was created for. What this is about is the cost.
    let asking = std::time::Instant::now();
    for _ in 0..1_000 {
        let _ = std::hint::black_box(session.desktop_lost());
    }
    let asked = asking.elapsed();
    assert!(
        asked < Duration::from_millis(50),
        "a thousand answers cost {asked:?}, and one reading costs {reading:?}: the answer is a \
         field of the watch rather than a question for the platform"
    );
}

/// KR-REQ-07.83: held input reaches the writer at its own deadline while a desktop reading is
/// outstanding.
///
/// The session is desktop-bound, so its supervision wants a reading; the reading is taken on a
/// blocking thread, and this runtime has one, which this test occupies. The probe is therefore
/// outstanding for the whole of what follows, and what follows is the fence releasing what it held
/// at the deadline A-17 gives it.
///
/// It needs a graphical login for the session to be bound to: a person logged in at the console,
/// as on a macOS workstation and continuous integration's macOS job. Where there is none it fails
/// and says so; elsewhere than macOS it is left out of an ordinary run.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs a graphical login for a desktop-bound session to watch; it runs on macOS with a person logged in at the console, and with --ignored on another desktop with one"
)]
fn held_input_reaches_the_writer_while_a_desktop_reading_is_outstanding() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        // One blocking thread, taken below, so the supervision's reading is queued behind it and
        // stays outstanding.
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let occupied = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let taken = Arc::clone(&occupied);
        let holding = tokio::task::spawn_blocking(move || {
            taken.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(20));
        });
        while !occupied.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let wired = wired_desktop_bound().await;
        if wired
            .runtime
            .session()
            .desktop_probe(std::time::Instant::now())
            .is_none()
        {
            // A host with no graphical login has nothing for a desktop-bound session to watch, so
            // there is no reading for this test to hold outstanding.
            holding.abort();
            wired.close().await;
            panic!(
                "this host has no graphical login, so a desktop-bound session wants no reading and \
                 this check cannot run here"
            );
        }
        let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let holder = holder_over(&mut client, &wired).await;
        let epoch = wired.runtime.session().lease().epoch.get();
        // A reader enters, which starts an exchange this test never answers, so the batch below is
        // held for the machine's own deadline and no longer.
        {
            let mut session = wired.runtime.session();
            let driver = session.fence_mut().expect("a driver");
            let _ = driver.bridge_event(
                kr_protocol::ids::RequestId::new(9),
                &enter(wired.session_id, 1, 1),
            );
            session
                .write_input(holder, epoch, 0, b"held\n", None, std::time::Instant::now())
                .expect("accepted");
        }
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if contains(&retained(&wired.runtime.session()), b"held") {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            delivered.is_ok(),
            "the held input reached the terminal while the desktop reading was still outstanding"
        );
        assert!(
            !holding.is_finished(),
            "the only blocking thread is still occupied, so the reading had not been taken"
        );
        holding.abort();
        wired.close().await;
    });
}

/// A managed session bound to this host's desktop, with its bridge registered.
async fn wired_desktop_bound() -> Wired {
    wired_built(ShellMode::Managed, true, Bridging::ordinary(), |config| {
        // Desktop-bound, so its watch wants a reading of its own rather than reporting none.
        config.worker_profile = WorkerProfile::DesktopBound;
    })
    .await
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.83: a login manager that never answers, on a host with no graphical login.
// --------------------------------------------------------------------------------------------

/// The variable that tells a case it is the one running in a process of its own, and names where
/// the login manager it was started with keeps its record.
#[cfg(target_os = "linux")]
const OWN_LOGIN_MANAGER: &str = "KR_CASE_LOGIN_MANAGER";

/// A login manager that fails the way one that cannot be reached does the first time it is asked,
/// which is when the session opens, and never answers again. It records the process that is
/// waiting, so the case knows a reading is outstanding and can tell when that process is gone.
#[cfg(target_os = "linux")]
const UNANSWERING_LOGIN_MANAGER: &str = r#"#!/bin/sh
here=$(dirname "$0")
if mkdir "$here/asked-once" 2>/dev/null; then
    echo "Failed to connect to bus: No such file or directory" >&2
    exit 1
fi
echo $$ > "$here/waiting.tmp"
mv "$here/waiting.tmp" "$here/waiting"
exec sleep 3600
"#;

/// A login manager with a graphical session, led by the process that started the case.
#[cfg(target_os = "linux")]
const ANSWERING_LOGIN_MANAGER: &str = r#"#!/bin/sh
printf '%s\n' "Type=x11" "Class=user" "State=active" "Remote=no" "LockedHint=no" "Active=yes" \
    "Leader=$KR_CASE_LEADER" "Desktop=test" "Name=tester"
"#;

/// A login manager that has no such session, which is what a logout leaves.
#[cfg(target_os = "linux")]
const LOGGED_OUT_LOGIN_MANAGER: &str = r#"#!/bin/sh
echo "Failed to get session: No such session" >&2
exit 1
"#;

/// Runs the named case again in a process of its own, whose search path holds a `loginctl` that
/// behaves as `script` says, and returns where that program keeps its record when this is that
/// process.
///
/// The platform reading finds its command by name on the process's own search path, and a test
/// cannot change that in place: the path is shared with every other case running in this binary.
/// So the case is started again, with only the search path it needs, and the outer call checks
/// that the inner one ran and passed. In the outer process this returns nothing and the case ends
/// there.
#[cfg(target_os = "linux")]
fn in_a_process_with_this_login_manager(case: &str, script: &str) -> Option<std::path::PathBuf> {
    if let Some(directory) = std::env::var_os(OWN_LOGIN_MANAGER) {
        return Some(directory.into());
    }
    let home = tempfile::tempdir().expect("a directory on the internal disk");
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).expect("a directory for the program");
    let source = home.path().join("loginctl.source");
    std::fs::write(&source, script).expect("the program's text");
    kr_ipc::testing::place_program(&source, &bin.join("loginctl"));
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", case, "--nocapture", "--test-threads=1"])
        .env(OWN_LOGIN_MANAGER, &bin)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("XDG_SESSION_ID", "42")
        .env("KR_CASE_LEADER", std::process::id().to_string())
        .output()
        .expect("starts the case in a process of its own");
    // A reading the case left outstanding is a process this test started, and it is stopped here
    // whatever became of the case. It is only ever the recorded one, and only while it is still
    // the program that was waiting.
    if let Some(waiting) = waiting_reading(&bin)
        && std::fs::read(format!("/proc/{waiting}/cmdline"))
            .is_ok_and(|command| command.starts_with(b"sleep"))
    {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &waiting.to_string()])
            .status();
    }
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && said.contains("test result: ok. 1 passed"),
        "the case, run in a process of its own, did not pass:\n{said}"
    );
    None
}

/// Returns the process the unanswering login manager recorded as waiting, once it has.
#[cfg(target_os = "linux")]
fn waiting_reading(record: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(record.join("waiting"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Returns whether a process is still in the process table, which one that has ended and not been
/// reaped is.
#[cfg(target_os = "linux")]
fn still_there(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// KR-REQ-07.83: a reading the platform never answers leaves the launch hold on its own deadline,
/// and ends with its command killed and reaped and the session not lost.
///
/// The session is desktop-bound on a host with no graphical login, and its login manager is a
/// program that never answers once the session has opened. The supervision's first reading
/// therefore stays outstanding for as long as the platform command is given. A launch reserves the
/// fence, the keys typed while it is in flight are held, and the machine's clock reaches the
/// hold's deadline: the reader is told the transaction is revoked, the held keys reach the
/// terminal in the order they were typed, and the reader, which installs nothing, refuses the
/// launch as `EDITOR_BUSY`. All of that happens while the reading is still outstanding. Later the
/// command the reading started is gone from the process table, which is what reaping it means,
/// and the reading, folded in as an answer that establishes nothing, has not closed the session.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_hold_ends_on_its_own_deadline_while_the_login_manager_never_answers() {
    let Some(record) = in_a_process_with_this_login_manager(
        "a_launch_hold_ends_on_its_own_deadline_while_the_login_manager_never_answers",
        UNANSWERING_LOGIN_MANAGER,
    ) else {
        return;
    };
    let clock = Arc::new(kr_transport::clock::ManualClock::new());
    let mut wired = wired_built(
        ShellMode::Managed,
        true,
        Bridging {
            clock: Arc::clone(&clock) as Arc<_>,
            fence_hold: None,
        },
        |config| config.worker_profile = WorkerProfile::DesktopBound,
    )
    .await;

    // The reading is outstanding when the login manager has been asked a second time and is
    // waiting: the first question was the session's own, when it opened.
    let waiting = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(waiting) = waiting_reading(&record) {
                return waiting;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the supervision asked the platform for its first reading");

    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let holder = holder_over(&mut client, &wired).await;
    let _ = fenced_with(&mut wired, holder, None).await;
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::QuotedCommand("kr-launched-command".to_owned()),
        expected_prompt_generation: PromptGeneration::new(1),
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    tokio::time::timeout(SOON, async {
        while wired.runtime.session().fence().expect("a driver").state()
            != FenceState::LaunchReserved
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the launch reserved the fence");
    type_keys(&wired, holder, 0, b"first\n");
    type_keys(&wired, holder, 1, b"second\n");
    assert_eq!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .held()
            .len(),
        2,
        "the machine holds what arrives while the launch is in flight"
    );
    assert!(
        !echoed_now(&wired.runtime, b"first"),
        "and nothing has reached the terminal"
    );

    // The hold's deadline is reached on the machine's own clock. Nothing but this and the reader's
    // own frames can end it, and the reading has not ended.
    clock.advance(Duration::from_millis(250));
    wired
        .runtime
        .session()
        .fence()
        .expect("a driver")
        .waker()
        .notify_one();
    echoed(&wired.runtime, b"second").await;
    assert!(
        still_there(waiting),
        "the reading had ended before the held keys were released, so this case did not show \
         that the release does not wait for it"
    );
    let seen = retained(&wired.runtime.session());
    assert!(
        position(&seen, b"first").expect("the first batch")
            < position(&seen, b"second").expect("the second batch"),
        "released in the order they were typed"
    );
    let revoked = loop {
        match wired.next().await {
            ToBridge::LaunchRevoked { transaction, .. } => break transaction,
            _ => continue,
        }
    };
    assert_eq!(revoked, request.transaction, "the reader was told to stop");
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Rejected(LaunchRejection {
                transaction: request.transaction,
                reason: LaunchRejectionReason::Revoked,
                fence_id: request.fence_id,
                prompt_generation: PromptGeneration::new(1),
                buffer_revision: EditorBufferRevision::new(1),
            })),
        )
        .await
        .expect("answers");
    let refused = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect_err("the reader installed nothing");
    assert_eq!(refused.code, ErrorCode::EditorBusy, "{refused}");
    assert!(
        !contains(&retained(&wired.runtime.session()), b"kr-launched-command"),
        "and the command never went into the terminal"
    );
    assert!(wired.runtime.session().late_installations().is_empty());

    // The reading's own deadline ends it: the command is killed and reaped, so its process is not
    // in the table at all.
    tokio::time::timeout(Duration::from_secs(60), async {
        while still_there(waiting) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the platform command was killed and reaped");
    // The session has been given what the reading found, which is nothing: the supervision does
    // not ask again until the slower cadence says so.
    tokio::time::timeout(Duration::from_secs(30), async {
        while wired
            .runtime
            .session()
            .desktop_probe(std::time::Instant::now())
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the reading was folded into the watch");
    {
        let session = wired.runtime.session();
        assert!(
            !session.desktop_lost(),
            "a reading the platform never answered is not a desktop that ended"
        );
        assert!(session.closure().is_none(), "and the session is still open");
    }
    wired.close().await;
}

/// The control for the case above: a login manager that answers reads as present, and the session
/// is bound to the login it names and is not lost.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answering_login_manager_reads_as_present_and_binds_the_session() {
    let Some(_record) = in_a_process_with_this_login_manager(
        "an_answering_login_manager_reads_as_present_and_binds_the_session",
        ANSWERING_LOGIN_MANAGER,
    ) else {
        return;
    };
    let wired = wired_desktop_bound().await;
    {
        let session = wired.runtime.session();
        let bound = session
            .summary()
            .desktop
            .desktop_session_id
            .as_ref()
            .map(|name| name.as_str().to_owned())
            .expect("the session is bound to the login the manager described");
        assert!(bound.contains(":session=42:"), "{bound}");
        assert!(!session.desktop_lost());
    }
    wired.close().await;
}

/// The other control: a login manager that has no such session is a desktop that ended, and this
/// same wiring closes the session for it, so the case above cannot pass by never being able to.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_login_manager_with_no_such_session_ends_a_desktop_bound_session() {
    let Some(_record) = in_a_process_with_this_login_manager(
        "a_login_manager_with_no_such_session_ends_a_desktop_bound_session",
        LOGGED_OUT_LOGIN_MANAGER,
    ) else {
        return;
    };
    let wired = wired_desktop_bound().await;
    let record = tokio::time::timeout(Duration::from_secs(30), wired.runtime.wait_closed())
        .await
        .expect("the session closes when its login is gone");
    assert_eq!(record.reason, ClosureReason::DesktopLost);
    wired._bridge_task.abort();
    wired._serving.abort();
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.22, KR-REQ-07.24: a bridge that closes only the side it reads from.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.22, KR-REQ-07.24: the loss is reported when the peer half-closes the connection.
///
/// A peer can close the side it reads from and leave the side it writes to open. The worker's
/// writes then fail while its read waits for a frame that is never coming, and nothing else would
/// report the loss. The condition is produced here rather than described: the bridge reaches the
/// worker through a relay of this test's own, which forwards bytes in both directions and, when
/// the test says so, shuts down the side it reads the worker's frames on. The relay's other
/// direction goes on running, so what ends the worker's read is its writer rather than an ordinary
/// end of the peer's stream.
///
/// Linux, because that is where a write to a socket whose peer has shut down reading is reported
/// to the writer. The same worker code answers a write that fails for any other reason the same
/// way, and two tests in `crates/kr-worker/src/fence/bridge.rs` pin that on every platform.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_closes_only_what_it_reads_from_is_reported_as_a_lost_bridge() {
    use std::os::fd::AsFd as _;

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let config = configuration(&temp, ShellMode::Managed);
    let session_id = config.session_id;
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let host_endpoint = HostEndpoint::open_for_session(
        environment.runtime_root(),
        environment.runtime_dir(),
        session_id,
    )
    .expect("binds the bridge");
    let worker_address = host_endpoint.address().clone();
    let secret = host_endpoint.secret().clone();

    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        Arc::new(SystemContinuousClock::new()),
    ));
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );
    let bridge_task = tokio::spawn(
        kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            host_endpoint,
            WorkerExpectation {
                session_id,
                root_process: process.clone(),
                supported_editor_abis: vec!["zle-5.9".to_owned()],
                supported_integration_versions: vec!["1".to_owned()],
                launched_package: None,
                already_registered: false,
                gesture: EofGesture::default(),
            },
        )
        .serve(),
    );

    // The relay sits between the bridge and the worker, in the same owner-only runtime directory.
    // It parses nothing: what reaches the worker is exactly what the bridge sent.
    let relay_path = environment.runtime_dir().join("relay");
    let relay = tokio::net::UnixListener::bind(&relay_path).expect("binds the relay");
    let (half_close, halved) = tokio::sync::oneshot::channel::<()>();
    let worker_path = worker_address.path.clone();
    let relaying = tokio::spawn(async move {
        let (inbound, _peer) = relay.accept().await.expect("the bridge connects");
        let outbound = tokio::net::UnixStream::connect(&worker_path)
            .await
            .expect("the relay reaches the worker");
        let inbound = Arc::new(inbound);
        let outbound = Arc::new(outbound);
        // Both directions are copied byte for byte. Nothing here parses a frame: what reaches the
        // worker is exactly what the bridge sent, and the other way round.
        let forward = copy(Arc::clone(&inbound), Arc::clone(&outbound));
        let back = copy(Arc::clone(&outbound), Arc::clone(&inbound));
        let shut = {
            let outbound = Arc::clone(&outbound);
            async move {
                if halved.await.is_ok() {
                    // The half-close: the relay stops reading what the worker writes and keeps
                    // its own write side open. This is the condition, produced on a real socket.
                    // A duplicate of the descriptor shuts down the socket both name.
                    if let Ok(duplicate) = outbound.as_fd().try_clone_to_owned() {
                        let socket = std::os::unix::net::UnixStream::from(duplicate);
                        let _ = socket.shutdown(std::net::Shutdown::Read);
                    }
                }
                std::future::pending::<()>().await;
            }
        };
        // The forward direction outlives the back one. A half-close makes the relay's own read of
        // the worker end, and a relay that stopped there would close the whole connection, which
        // the worker's read would notice by itself: the assertion below would then pass for a
        // reason that is not the one it is about.
        tokio::spawn(back);
        tokio::select! {
            () = forward => {}
            () = shut => {}
        }
    });

    // The bridge registers through the relay. Its proof is taken over the endpoint the worker
    // owns, which is what the worker rebuilds the transcript from; the path it dials is the
    // relay's.
    let hello = qualified_hello(&reference(), session_id, &worker_address, process, &secret)
        .expect("a hello");
    let relay_address = kr_shell_integration::contract::transport::BridgeEndpoint::unix(
        relay_path.display().to_string(),
    );
    let (mut bridge, outcome) =
        tokio::time::timeout(SOON, ScriptedBridge::connect(&relay_address, &hello))
            .await
            .expect("the worker answered")
            .expect("connects");
    assert!(
        matches!(outcome, HandshakeOutcome::Accepted(_)),
        "a qualified root shell registers through the relay: {outcome:?}"
    );
    bridge
        .send_event(BridgeEvent::HooksActivated(HooksActivated {
            session_id,
            prompt_generation: PromptGeneration::new(1),
            modules: Vec::new(),
        }))
        .await
        .expect("reports");
    tokio::time::timeout(SOON, async {
        loop {
            if wired_ready(&runtime) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the integration qualified");

    // Now the peer closes only what it reads from. The worker goes on being told things, so it
    // goes on answering, and its answers are what find the closed half.
    half_close.send(()).expect("the relay is listening");
    let lost = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if !wired_ready(&runtime) {
                return;
            }
            let _ = bridge.send_event(idle(session_id, 1, 1)).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(
        lost.is_ok(),
        "a peer that closed the side it reads from is reported as a lost bridge rather than \
         leaving the read waiting for a frame that is never coming"
    );

    runtime.close(ClosureReason::CloseRequested).1.release();
    let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
    relaying.abort();
    bridge_task.abort();
}

/// Copies every byte one socket receives into another, until either end stops.
#[cfg(target_os = "linux")]
async fn copy(from: Arc<tokio::net::UnixStream>, to: Arc<tokio::net::UnixStream>) {
    let mut buffer = vec![0_u8; 8 * 1024];
    loop {
        if from.readable().await.is_err() {
            return;
        }
        let read = match from.try_read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return,
        };
        let mut written = 0;
        while written < read {
            if to.writable().await.is_err() {
                return;
            }
            match to.try_write(&buffer[written..read]) {
                Ok(0) => return,
                Ok(sent) => written += sent,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    }
}

/// Returns whether this session's integration is registered and reporting ready.
#[cfg(target_os = "linux")]
fn wired_ready(runtime: &Arc<SessionRuntime>) -> bool {
    runtime
        .session()
        .fence()
        .is_some_and(|driver| driver.phase().reports_ready())
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.16, KR-REQ-07.17, KR-REQ-07.44: a real qualified package, launched by this host.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.16, KR-REQ-07.17, KR-REQ-07.44.
///
/// Everything this test touches is on the internal disk: the package is the installed build, and
/// the session's home, runtime directory, endpoint and working directory are all under the
/// platform temporary directory. Nothing a launched process opens is in the workspace.
///
/// It needs a built package, which only a run that built one has, so an ordinary run leaves it
/// out; see [`package_root`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_real_qualified_package_registers_and_qualifies_on_this_hosts_endpoint() {
    let package = installed_package();
    let shell = RealShell::start(
        &package,
        kr_protocol::session::LaunchProfile::default(),
        Vec::new(),
        None,
    )
    .await;
    assert_eq!(
        shell.qualified,
        Some(package.kind()),
        "the session's registered root integration is the package this host launched"
    );
    assert_eq!(
        shell.runtime.session().config().shell.program,
        package.executable().display().to_string(),
        "and the executable it launched is the package's own binary"
    );
    shell.close().await;
}

/// The question a startup file asks, in the shell's own words for reading a line, before the
/// package's entry: the shell prints what it read put together from two pieces, so its own echo of
/// the answer cannot make the marker appear.
#[cfg(unix)]
fn startup_question(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::Zsh => {
            "kr_answer=\nvared -p 'ASK> ' kr_answer\nprint -r -- \"kr-answer-<${kr_answer}>\"\n"
        }
        _ => "read -r -p 'ASK> ' kr_answer\nprintf 'kr-answer-<%s>\\n' \"$kr_answer\"\n",
    }
}

/// KR-REQ-07.23: a startup prompt takes its answer through the worker while the session is
/// authenticated, and the session is ready, and a launch is possible, only after the profile that
/// asked has finished.
///
/// The person's startup asks before the package's entry has run, in a real qualified package
/// launched by a real worker session. The worker takes the keystrokes because the bridge is
/// authenticated: a session that refused input until it was ready would leave the profile asking
/// a question nobody could answer.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_startup_prompt_takes_its_answer_through_the_worker_and_the_session_is_ready_after_the_profile()
 {
    for kind in [ShellKind::Zsh, ShellKind::Bash] {
        let package = installed_package_of(kind);
        let shell = RealShell::start_with_profile(
            &package,
            kr_protocol::session::LaunchProfile::default(),
            Vec::new(),
            None,
            startup_question(kind),
            false,
        )
        .await;
        shell.produced(b"ASK>", 1).await;
        {
            let session = shell.runtime.session();
            let phase = session.fence().expect("a driver").phase();
            assert!(
                phase.accepts_external_input(),
                "{kind:?}: the bridge is authenticated before the profile asks, so its answer is taken"
            );
            assert!(
                !phase.reports_ready(),
                "{kind:?}: the profile has not finished"
            );
            assert!(!phase.permits_launch(), "{kind:?}");
        }

        let mut keys = shell.keys();
        keys.type_line(&shell, "the-answer");
        shell.produced(b"kr-answer-<the-answer>", 1).await;
        // The profile has finished, so the entry's activation is what qualifies the session.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                {
                    let session = shell.runtime.session();
                    let phase = session.fence().expect("a driver").phase();
                    if phase.reports_ready() {
                        assert!(phase.permits_launch(), "{kind:?}");
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("{kind:?}: the session never reported ready after the profile finished")
        });
        shell.close().await;
    }
}

/// The control for the case above: a profile nobody answers leaves the session authenticated and
/// not ready, and the session still closes when asked.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_startup_prompt_nobody_answers_leaves_the_session_not_ready_and_it_still_closes() {
    for kind in [ShellKind::Zsh, ShellKind::Bash] {
        let package = installed_package_of(kind);
        let shell = RealShell::start_with_profile(
            &package,
            kr_protocol::session::LaunchProfile::default(),
            Vec::new(),
            None,
            startup_question(kind),
            false,
        )
        .await;
        shell.produced(b"ASK>", 1).await;
        {
            let session = shell.runtime.session();
            let phase = session.fence().expect("a driver").phase();
            assert!(phase.accepts_external_input(), "{kind:?}");
            assert!(
                !phase.reports_ready(),
                "{kind:?}: a profile that is still waiting for its answer is not a ready session"
            );
            assert!(!phase.permits_launch(), "{kind:?}");
        }
        let closed = std::time::Instant::now();
        shell.close().await;
        assert!(
            closed.elapsed() < Duration::from_secs(30),
            "{kind:?}: the session waiting for its profile did not close within its bound"
        );
    }
}

/// A real qualified package launched as this host's root shell, registered and qualified on the
/// host's own endpoint.
struct RealShell {
    _temp: kr_ipc::testing::TempHost,
    /// The shell's home, which is also the directory it starts in, kept for as long as it runs.
    _home: tempfile::TempDir,
    runtime: Arc<SessionRuntime>,
    bridge_task: tokio::task::JoinHandle<()>,
    qualified: Option<ShellKind>,
}

impl RealShell {
    /// Launches `package` with the package's guarded entry in the startup file the person would
    /// have, and waits until the entry has reported the hooks live after the startup files, which
    /// is what qualifies the session.
    ///
    /// The bridge server keeps each published fence from its writer as `fence_hold` says, when
    /// there is one.
    async fn start(
        package: &kr_shell_integration::host::package::ShellPackage,
        launch_profile: kr_protocol::session::LaunchProfile,
        extra: Vec<(String, String)>,
        fence_hold: Option<FenceHold>,
    ) -> Self {
        Self::start_with_profile(package, launch_profile, extra, fence_hold, "", true).await
    }

    /// Launches `package` as [`Self::start`] does, with `after_configuration` running in the
    /// person's startup file before the package's entry, and returns at once when `wait_ready` is
    /// false rather than after the entry has qualified the session.
    ///
    /// A session that is not waited for is one whose profile may be waiting for something, which
    /// is what a startup prompt is: the caller decides what to do about it and when.
    async fn start_with_profile(
        package: &kr_shell_integration::host::package::ShellPackage,
        launch_profile: kr_protocol::session::LaunchProfile,
        extra: Vec<(String, String)>,
        fence_hold: Option<FenceHold>,
        after_configuration: &str,
        wait_ready: bool,
    ) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        // The shell's own home, on the internal disk, with the package's guarded entry in the
        // startup file the person would have. The entry is what activates the integration after the
        // user's own configuration has run, which is the ordering section 7 requires.
        let home = tempfile::Builder::new()
            .prefix("kr-package-home-")
            .tempdir()
            .expect("a home directory on the internal disk");
        let entry =
            std::fs::read_to_string(package.startup_entry()).expect("the package's own entry");
        let startup = match package.kind() {
            ShellKind::Zsh => home.path().join(".zshrc"),
            _ => home.path().join(".bashrc"),
        };
        std::fs::write(
            &startup,
            format!("HISTFILE=\nKR_TEST_USER_CONFIGURATION=1\n\n{after_configuration}{entry}"),
        )
        .expect("the startup file");

        let mut config = configuration(&temp, ShellMode::Managed);
        let session_id = config.session_id;
        let host_endpoint = HostEndpoint::open_for_session(
            environment.runtime_root(),
            environment.runtime_dir(),
            session_id,
        )
        .expect("binds the bridge");
        let address = host_endpoint.address().clone();
        let bootstrap = host_endpoint.bootstrap();

        config.journal_path = Some(environment.journal_database(session_id));
        config.spool_directory = Some(environment.session_spool(session_id));
        config.launch_profile = launch_profile;
        let mut variables = vec![
            ("TERM".to_owned(), "xterm-256color".to_owned()),
            ("LANG".to_owned(), "C".to_owned()),
            ("HOME".to_owned(), home.path().display().to_string()),
            ("ZDOTDIR".to_owned(), home.path().display().to_string()),
            (
                kr_worker::environment::SESSION_VARIABLE.to_owned(),
                session_id.to_string(),
            ),
        ];
        variables.extend(extra);
        variables.extend(
            bootstrap
                .exported_variables()
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value)),
        );
        config.shell = kr_worker::pty::ShellCommand {
            program: package.executable().display().to_string(),
            arguments: package
                .arguments(kr_shell_integration::host::package::StartupMode::Interactive),
            cwd: home.path().display().to_string(),
            environment: variables,
        };

        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the packaged shell");
        let root_process = session
            .root_identity()
            .expect("the launched shell has a process identity");
        let identity = package.identity();
        session.install_fence(FenceDriver::new(
            session_id,
            LeaseView::unheld(InputLeaseEpoch::new(0)),
            Arc::new(SystemContinuousClock::new()),
        ));
        let runtime = Arc::new(
            SessionRuntime::start(
                session,
                std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        );
        let expectation = WorkerExpectation {
            session_id,
            root_process,
            supported_editor_abis: vec![identity.editor_abi.clone()],
            supported_integration_versions: vec![identity.integration_version.clone()],
            launched_package: Some(package.declaration()),
            already_registered: false,
            gesture: EofGesture::default(),
        };
        let mut server = kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            host_endpoint,
            expectation,
        );
        if let Some(hold) = fence_hold {
            server = server.holding_fences(hold);
        }
        let bridge_task = tokio::spawn(server.serve());

        // The package connects to the endpoint it was given, proves itself over the bootstrap
        // secret and is registered; then its own entry reports that the hooks are live after the
        // startup files, which is what qualifies the session.
        let qualified = if wait_ready {
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    {
                        let session = runtime.session();
                        if let Some(driver) = session.fence()
                            && driver.phase().reports_ready()
                        {
                            return driver.phase().shell();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the {} package at {} did not register and qualify on this host's endpoint at {}",
                    package.kind().as_str(),
                    package.directory.display(),
                    address.path
                )
            })
        } else {
            None
        };
        Self {
            _temp: temp,
            _home: home,
            runtime,
            bridge_task,
            qualified,
        }
    }

    /// The directory the shell started in, which is its home, as the kernel names it: the name a
    /// shell reports.
    #[cfg(unix)]
    fn home(&self) -> std::path::PathBuf {
        let started_in = self.runtime.session().config().shell.cwd.clone();
        std::fs::canonicalize(started_in).expect("the home resolves")
    }

    /// Attaches a terminal that takes the keys, as a person's terminal does.
    #[cfg(unix)]
    fn keys(&self) -> RealKeys {
        let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
        let params = terminal(self.runtime.session().config().session_id);
        let epoch = {
            let mut session = self.runtime.session();
            session
                .attach(&params, params.requested.clone(), attachment_id)
                .expect("attaches");
            session
                .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
                .expect("takes the keys");
            session.lease().epoch.get()
        };
        RealKeys {
            attachment_id,
            epoch,
            sequence: 0,
        }
    }

    /// Waits until the session's retained output carries `marker` `count` times.
    #[cfg(unix)]
    async fn produced(&self, marker: &[u8], count: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let seen = retained(&self.runtime.session());
            let times = seen
                .windows(marker.len())
                .filter(|window| *window == marker)
                .count();
            if times >= count {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "waited for {count} of {} in the session's output, which ends {}",
                String::from_utf8_lossy(marker).escape_debug(),
                String::from_utf8_lossy(&seen[seen.len().saturating_sub(512)..]).escape_debug()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Closes the session and waits for it, so the reader on the terminal ends with it.
    async fn close(self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(Duration::from_secs(30), self.runtime.wait_closed()).await;
        self.bridge_task.abort();
    }
}

/// The input lease a real shell's terminal holds.
#[cfg(unix)]
struct RealKeys {
    attachment_id: AttachmentId,
    epoch: u64,
    sequence: u64,
}

#[cfg(unix)]
impl RealKeys {
    /// Types one line into the shell through the lease, as a person at the terminal does.
    fn type_line(&mut self, shell: &RealShell, line: &str) {
        {
            let mut session = shell.runtime.session();
            session
                .write_input(
                    self.attachment_id,
                    self.epoch,
                    self.sequence,
                    format!("{line}\r").as_bytes(),
                    None,
                    std::time::Instant::now(),
                )
                .expect("the keystrokes are accepted");
        }
        self.sequence += 1;
        shell.runtime.flush_input();
    }
}

/// A recording program on the internal disk, what it recorded, and the integration's diagnostics.
///
/// The program is a POSIX shell script made executable through its permission bits, so it and the
/// cases that start it are for Unix only.
#[cfg(unix)]
struct RealProbes {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
}

#[cfg(unix)]
impl RealProbes {
    fn new() -> Self {
        // The directory's name holds an apostrophe, so every path below it is one a shell line has
        // to quote properly, and a line that did not would not survive it.
        let directory = tempfile::Builder::new()
            .prefix("kr-probes-it's-")
            .tempdir()
            .expect("a directory on the internal disk");
        let root = std::fs::canonicalize(directory.path()).expect("the directory resolves");
        std::fs::create_dir(root.join("bin")).expect("a directory for the program");
        let program = root.join("bin").join("kr-probe");
        // It records its arguments and every reserved variable it was started with, waits while
        // its first argument is `hold` and no release has been written, and prints a word it puts
        // together from two pieces.
        let text = root.join("kr-probe.text");
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\n\
                 {{\n\
                 printf 'run\\n'\n\
                 for word in \"$@\"; do printf 'arg %s\\n' \"$word\"; done\n\
                 env | LC_ALL=C sort | while IFS= read -r line; do\n\
                 case $line in KR_*) printf 'env %s\\n' \"$line\" ;; esac\n\
                 done\n\
                 printf 'end\\n'\n\
                 }} >> {record}\n\
                 if [ \"$1\" = hold ]; then\n\
                 while [ ! -e {release} ]; do sleep 0.05; done\n\
                 fi\n\
                 printf '%s%s\\n' 'probe-' 'ran'\n",
                record = shell_quoted(&root.join("record")),
                release = shell_quoted(&root.join("release")),
            ),
        )
        .expect("the program's text");
        // Placed by another process rather than written by this one, so no child another test
        // starts can hold it open for writing when a shell starts it; and started once here, where
        // nothing is timed, because some systems check a program the first time anything starts it
        // and on a busy machine that check can outlast a wait.
        kr_ipc::testing::place_and_start_once(&text, &program, &[]);
        let _ = std::fs::remove_file(&text);
        let _ = std::fs::remove_file(root.join("record"));
        std::fs::write(root.join("script.sh"), "kr-probe from-a-script\n").expect("a script");
        Self {
            _directory: directory,
            root,
        }
    }

    /// What the shell is started with: the program on its search path, and the file the
    /// integration writes its diagnostics to.
    fn variables(&self) -> Vec<(String, String)> {
        vec![
            (
                "PATH".to_owned(),
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            ),
            (
                "KR_SHELL_BRIDGE_TRACE".to_owned(),
                self.root.join("trace").display().to_string(),
            ),
        ]
    }

    fn program(&self) -> std::path::PathBuf {
        self.root.join("bin").join("kr-probe")
    }

    fn script(&self) -> std::path::PathBuf {
        self.root.join("script.sh")
    }

    fn release(&self) {
        std::fs::write(self.root.join("release"), "").expect("the release");
    }

    /// Takes a release back, so the next start that is told to hold waits again.
    fn hold(&self) {
        match std::fs::remove_file(self.root.join("release")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("the release is taken back: {error}"),
        }
    }

    /// Every start of the program: its arguments after its own name, and its reserved variables.
    fn runs(&self) -> Vec<(Vec<String>, std::collections::BTreeMap<String, String>)> {
        let text = std::fs::read_to_string(self.root.join("record")).unwrap_or_default();
        let mut runs = Vec::new();
        let mut current = None;
        for line in text.lines() {
            match line {
                "run" => current = Some((Vec::new(), std::collections::BTreeMap::new())),
                "end" => runs.extend(current.take()),
                _ => {
                    let Some((arguments, environment)) = current.as_mut() else {
                        continue;
                    };
                    if let Some(argument) = line.strip_prefix("arg ") {
                        arguments.push(argument.to_owned());
                    } else if let Some((name, value)) = line
                        .strip_prefix("env ")
                        .and_then(|pair| pair.split_once('='))
                    {
                        environment.insert(name.to_owned(), value.to_owned());
                    }
                }
            }
        }
        runs
    }

    /// The lines of the integration's diagnostics that record a question asked.
    fn asked(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("trace"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(": asked about "))
            .map(str::to_owned)
            .collect()
    }

    /// The lines of the integration's diagnostics.
    fn trace(&self) -> String {
        std::fs::read_to_string(self.root.join("trace")).unwrap_or_default()
    }
}

/// A path as one word of a POSIX shell line, whatever characters it holds.
///
/// Inside single quotes every character stands for itself except the quote, which ends them, so a
/// quote in the path is closed over, given as an escaped quote of its own, and reopened. The line
/// is text, as the session's environment and the keys typed into it are, so a path that is not
/// UTF-8 is refused here rather than quoted as some other path that its lossy spelling would name.
#[cfg(unix)]
fn shell_quoted(path: &std::path::Path) -> String {
    let text = path.to_str().unwrap_or_else(|| {
        panic!(
            "{} is not UTF-8, and a shell line, the keys typed into a session and its \
             environment are all text, so this case cannot put it in one",
            path.display()
        )
    });
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// A path that is not UTF-8 is refused, rather than quoted as the other path its lossy spelling
/// would name. The path is only a value here: no file system is asked to hold it.
#[cfg(unix)]
#[test]
#[should_panic(expected = "is not UTF-8")]
fn a_probe_path_that_is_not_text_is_refused_rather_than_quoted() {
    use std::os::unix::ffi::OsStringExt as _;

    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(
        b"/tmp/kr-probes-\xff/bin/kr-probe".to_vec(),
    ));
    let _ = shell_quoted(&path);
}

/// The recording program works where its directory's name holds an apostrophe: a held start
/// records its words and variables, waits for its release and then answers, and a script sourced
/// by its quoted path runs it.
#[cfg(unix)]
#[test]
fn the_recording_program_works_where_its_directory_holds_an_apostrophe() {
    let probes = RealProbes::new();
    assert!(
        probes.root.display().to_string().contains('\''),
        "the recording program's directory is one whose name holds an apostrophe: {}",
        probes.root.display()
    );

    let held = std::process::Command::new(probes.program())
        .args(["hold", "two words"])
        .env("KR_PROBE_CHECK", "set")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the recording program starts");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while probes.runs().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the held start recorded nothing"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    probes.release();
    let answered = held.wait_with_output().expect("the held start ends");
    assert!(
        answered.status.success(),
        "the held start failed: {}",
        String::from_utf8_lossy(&answered.stderr)
    );
    assert_eq!(answered.stdout, b"probe-ran\n");
    let (arguments, environment) = probes.runs().pop().expect("the held start was recorded");
    assert_eq!(arguments, ["hold", "two words"]);
    assert_eq!(
        environment.get("KR_PROBE_CHECK").map(String::as_str),
        Some("set")
    );

    let sourced = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(". {}", shell_quoted(&probes.script())))
        .envs(probes.variables())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("a shell starts");
    assert!(
        sourced.status.success(),
        "the script sourced by its quoted path failed: {}",
        String::from_utf8_lossy(&sourced.stderr)
    );
    assert_eq!(sourced.stdout, b"probe-ran\n");
    let (arguments, _) = probes
        .runs()
        .pop()
        .expect("the sourced script started the program");
    assert_eq!(arguments, ["from-a-script"]);
}

/// KR-REQ-12.07, KR-REQ-07.45, KR-REQ-07.84, KR-REQ-25.05: a real package asks the real worker
/// before each command of a line and runs a bypassed command exactly as it was typed; forms the
/// root shell does not start itself ask nothing; the line's capability and its block reach the
/// worker.
///
/// This host establishes no command backend yet, so every answer here is a bypass: `not_integrated`
/// for a session created with no integration, and `backend_unavailable` for one created with an
/// integration for the name.
///
/// Each package runs it twice: once as the host runs, and once with every published fence kept
/// from the bridge's writer for [`PACKAGE_FENCE_HOLD`], as a writer on a loaded machine now and
/// then keeps one. A line typed at the prompt goes through the fence either way.
///
/// It needs the built Zsh and Bash packages, which only a run that built them has, so an ordinary
/// run leaves it out; see [`package_root`].
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_real_package_asks_the_real_worker_before_each_command_and_runs_a_bypass_as_typed() {
    let root = package_root();
    let set =
        kr_shell_integration::host::package::PackageSet::discover(std::path::Path::new(&root))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}: {fault}"));
    for fence_hold in [None, Some(FenceHold::For(PACKAGE_FENCE_HOLD))] {
        for kind in [ShellKind::Zsh, ShellKind::Bash] {
            let package = set
                .select(Some(kind.as_str()))
                .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} has no {kind:?}: {fault}"))
                .clone();
            asks_the_real_worker_before_each_command(&package, fence_hold.clone()).await;
        }
    }
}

/// How long the real-package case's second run keeps each published fence from the writer.
#[cfg(unix)]
const PACKAGE_FENCE_HOLD: Duration = Duration::from_millis(100);

/// What [`a_real_package_asks_the_real_worker_before_each_command_and_runs_a_bypass_as_typed`]
/// asks of one package, with each published fence kept from the writer as `fence_hold` says.
#[cfg(unix)]
async fn asks_the_real_worker_before_each_command(
    package: &kr_shell_integration::host::package::ShellPackage,
    fence_hold: Option<FenceHold>,
) {
    for (integrations, bypass) in [
        (Vec::new(), "bypass not_integrated"),
        (
            vec![kr_protocol::session::CommandIntegration {
                plugin_id: kr_protocol::ids::PluginId::new("kalareach/probe")
                    .expect("a plugin identifier"),
                command: "kr-probe".to_owned(),
                flags: vec!["--kr-integrated".to_owned()],
                enabled: true,
            }],
            "bypass backend_unavailable",
        ),
    ] {
        let probes = RealProbes::new();
        let shell = RealShell::start(
            package,
            kr_protocol::session::LaunchProfile {
                command_integrations: integrations,
                ..kr_protocol::session::LaunchProfile::default()
            },
            probes.variables(),
            fence_hold.clone(),
        )
        .await;
        let mut keys = shell.keys();
        let mut printed = 0;

        // A pipeline runs in a child the shell forks and asks nothing; what it was started with is
        // what the shell passes a command it does not ask about.
        keys.type_line(&shell, "kr-probe control | cat");
        printed += 1;
        shell.produced(b"probe-ran", printed).await;
        assert!(probes.asked().is_empty(), "{}", probes.trace());
        let control = probes.runs().last().cloned().expect("the control ran");

        // One command of the line asks once, is answered by the worker, and runs as it was typed.
        keys.type_line(&shell, "kr-probe one 'two words'");
        printed += 1;
        shell.produced(b"probe-ran", printed).await;
        let asked = probes.asked();
        assert_eq!(asked.len(), 1, "{}", probes.trace());
        assert!(
            asked[0].contains(&format!(
                "asked about kr-probe as {} in {}",
                probes.program().display(),
                shell.home().display()
            )),
            "{}",
            probes.trace()
        );
        assert!(probes.trace().contains(bypass), "{}", probes.trace());
        let (arguments, environment) = probes.runs().last().cloned().expect("the command ran");
        assert_eq!(
            arguments,
            ["one", "two words"],
            "the vector as it was typed"
        );
        // Whether a line holds a capability depends on whether the worker could attribute the line;
        // everything else is the shell's own environment, with nothing added.
        let names = |environment: &std::collections::BTreeMap<String, String>| {
            environment
                .keys()
                .filter(|name| name.as_str() != "KR_DETACH_TOKEN")
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&environment),
            names(&control.1),
            "nothing was added to the environment"
        );
        assert!(!environment.contains_key("KR_REGISTRATION"));

        // A sourced script and a script of its own ask nothing for what they run.
        let sourced = format!(". {}", shell_quoted(&probes.script()));
        keys.type_line(&shell, &sourced);
        printed += 1;
        shell.produced(b"probe-ran", printed).await;
        assert_eq!(probes.asked().len(), 1, "{}", probes.trace());

        // The line's capability reaches the command, and the worker resolves it to the
        // attachment that typed the line while the line runs. A capability is minted only for a
        // line the reader accepted behind the fence the worker published for its prompt, so the
        // line is typed at the prompt: keys typed while the sourced script's line is still
        // finishing are typeahead, which the worker cannot attribute to anyone. A shell that had
        // no answer within its deadline runs the line without its capability, which is how it
        // keeps a command from waiting on the worker. What the worker recorded for the line, and
        // what the shell traced, say which happened. Keys typed at the prompt reach the shell only
        // behind its fence, so a line the worker did not record as fenced fails at once; a fenced
        // line the shell had its answer for must carry its capability; and a fenced line the shell
        // had no answer for in time is let finish and typed again at the next prompt, a bounded
        // number of times.
        const ATTEMPTS: usize = 5;
        let mut previous = sourced;
        let mut attempt = 0;
        let token = loop {
            attempt += 1;
            back_at_the_prompt(&shell, &probes, &previous).await;
            probes.hold();
            let before = probes.runs().len();
            // The bridge reports a line's acceptance before its block, on one connection, and the
            // worker takes them in that order. Once the worker holds a running block for this line
            // at a newer prompt than the line before, what it recorded about the acceptance is
            // about this line, whether or not the shell had the answer in time.
            let earlier = shell
                .runtime
                .session()
                .last_command_block()
                .map(|block| block.prompt_generation.0.get());
            keys.type_line(&shell, "kr-probe hold");
            let (token, fenced) = tokio::time::timeout(Duration::from_secs(30), async {
                let mut started = None;
                loop {
                    if started.is_none() {
                        let runs = probes.runs();
                        if runs.len() > before
                            && let Some((arguments, environment)) = runs.last()
                            && arguments.first().map(String::as_str) == Some("hold")
                        {
                            started = Some(environment.get("KR_DETACH_TOKEN").cloned());
                        }
                    }
                    if let Some(token) = &started {
                        let session = shell.runtime.session();
                        if let Some(block) = session.last_command_block()
                            && block.command == "kr-probe hold"
                            && !block.finished()
                            && earlier
                                .is_none_or(|earlier| block.prompt_generation.0.get() > earlier)
                        {
                            let fenced = session.fence().expect("a driver").detach_target()
                                == DetachTarget::Attachment(keys.attachment_id);
                            return (token.clone(), fenced);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the held command started and the worker has its block ({:?}, {bypass}, \
                     each published fence kept from the writer: {fence_hold:?}, attempt \
                     {attempt}): {}",
                    package.kind(),
                    probes.trace()
                )
            });
            // The shell's own word for the line it just accepted, which is its last.
            let answered = probes
                .trace()
                .lines()
                .rev()
                .find(|line| line.starts_with("line ") && line.contains(": "))
                .is_some_and(|line| !line.ends_with("no answer, so no capability"));
            match token {
                Some(token) => break token,
                None if fenced && !answered && attempt < ATTEMPTS => {
                    eprintln!(
                        "the {:?} package's held line was answered after the shell's deadline on \
                         attempt {attempt} (each published fence kept from the writer: \
                         {fence_hold:?}), so it is typed again at the next prompt",
                        package.kind()
                    );
                    probes.release();
                    printed += 1;
                    shell.produced(b"probe-ran", printed).await;
                    previous = "kr-probe hold".to_owned();
                }
                None => panic!(
                    "the {:?} package started the held command without its line's capability \
                     ({bypass}, each published fence kept from the writer: {fence_hold:?}, \
                     attempt {attempt}, the line {} through the fence and the shell {} its \
                     answer): {}",
                    package.kind(),
                    if fenced { "went" } else { "did not go" },
                    if answered { "had" } else { "did not have" },
                    probes.trace()
                ),
            }
        };
        assert_eq!(
            shell
                .runtime
                .session()
                .fence()
                .expect("a driver")
                .detach_for_token(&token),
            Some(keys.attachment_id),
            "the capability names the attachment that typed the line"
        );
        probes.release();
        printed += 1;
        shell.produced(b"probe-ran", printed).await;

        // The line's block reaches the worker with the shell's own status for it.
        keys.type_line(&shell, "sh -c 'exit 7'");
        let block = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(block) = shell.runtime.session().last_command_block()
                    && block.command == "sh -c 'exit 7'"
                    && block.finished()
                {
                    return block;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the line's finished block reached the worker");
        assert_eq!(block.exit_status.0.map(|status| status.get()), Some(7));
        assert_eq!(block.cwd, shell.home().display().to_string());
        assert!(block.duration_ms.0.is_some());

        shell.close().await;
    }
}

/// Waits until the line `command` has finished and the reader is back at its prompt behind a valid
/// fence, which is when a line typed next is typed at that prompt rather than ahead of it.
///
/// The bridge reports a line's block finished when the next reader starts, and the fence that
/// reader answers is valid only after that, so the two together say the prompt is the next one.
#[cfg(unix)]
async fn back_at_the_prompt(shell: &RealShell, probes: &RealProbes, command: &str) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            {
                let session = shell.runtime.session();
                let finished = session
                    .last_command_block()
                    .is_some_and(|block| block.command == command && block.finished());
                let fenced = session
                    .fence()
                    .is_some_and(|driver| driver.state() == FenceState::Fenced);
                if finished && fenced {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the shell did not come back to its prompt after {command:?}: {}",
            probes.trace()
        )
    });
}

/// Returns the root of the built packages this run named.
///
/// Only a run that names [`PACKAGE_ROOT_VARIABLE`] launches a package: the machine's own package
/// cache is not this suite's to depend on, and an ordinary acceptance run must not vary with it. So
/// the cases that launch one are left out of an ordinary run, and a run that built the packages
/// names their root and runs them with `--ignored`, as the build box's verification does. Run
/// without that variable, they fail and say so.
fn package_root() -> std::ffi::OsString {
    std::env::var_os(PACKAGE_ROOT_VARIABLE).unwrap_or_else(|| {
        panic!(
            "{PACKAGE_ROOT_VARIABLE} names no directory with a qualified package, so there is no \
             built package for this check to launch; build the packages and name their root in it"
        )
    })
}

/// Returns the qualified package of one shell this run named.
fn installed_package_of(kind: ShellKind) -> kr_shell_integration::host::package::ShellPackage {
    let root = package_root();
    let set =
        kr_shell_integration::host::package::PackageSet::discover(std::path::Path::new(&root))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}: {fault}"));
    set.get(kind)
        .unwrap_or_else(|| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}, which has no {kind:?}"))
        .clone()
}

/// Returns the qualified package this run named, the first the installation there has.
fn installed_package() -> kr_shell_integration::host::package::ShellPackage {
    let root = package_root();
    let set =
        kr_shell_integration::host::package::PackageSet::discover(std::path::Path::new(&root))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}: {fault}"));
    set.select(None)
        .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}: {fault}"))
        .clone()
}

/// KR-REQ-01.14, KR-REQ-22.05: a real managed shell that ran `cd` is described by the directory it
/// is in at the next prompt, with nothing more typed. The block the shell's hooks report names the
/// directory the command began in, so the worker reads the directory the shell is in once the
/// command has ended; the first command's own block is the control, naming the directory it ran in.
///
/// It needs the built Zsh and Bash packages, which only a run that built them has, so an ordinary
/// run leaves it out; see [`package_root`].
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_real_shell_that_ran_cd_is_described_by_its_new_directory_at_the_next_prompt() {
    let root = package_root();
    let set =
        kr_shell_integration::host::package::PackageSet::discover(std::path::Path::new(&root))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}: {fault}"));
    for kind in [ShellKind::Zsh, ShellKind::Bash] {
        let package = set
            .select(Some(kind.as_str()))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} has no {kind:?}: {fault}"))
            .clone();
        let shell = RealShell::start(
            &package,
            kr_protocol::session::LaunchProfile::default(),
            Vec::new(),
            None,
        )
        .await;
        let target = shell.home().join("kr-moved-here");
        std::fs::create_dir(&target).expect("a directory to move to");
        let home_name = shell
            .home()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a home with a name")
            .to_owned();

        let mut keys = shell.keys();
        keys.type_line(&shell, "true");
        shell
            .directory_described_as(&home_name, "the command that ran where the shell began")
            .await;
        keys.type_line(&shell, &format!("cd {}", shell_quoted(&target)));
        shell
            .directory_described_as("kr-moved-here", "the prompt after `cd`, with nothing typed")
            .await;
        shell.close().await;
    }
}

/// KR-REQ-22.05: a real managed shell names the program its own search resolved to a file, and
/// the word it found no file for is no program: a command found on the path is recorded as the
/// program of its line, and a token typed at the prompt as one plain word, which the shell
/// reports as not found, is recorded as no program and is in no fact.
///
/// It needs the built Zsh and Bash packages, which only a run that built them has, so an ordinary
/// run leaves it out; see [`package_root`].
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_real_shell_names_the_program_it_resolved_and_not_a_word_it_found_no_file_for() {
    use kr_protocol::describe::DescriptionCompletion;

    let root = package_root();
    let set =
        kr_shell_integration::host::package::PackageSet::discover(std::path::Path::new(&root))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} names {root:?}: {fault}"));
    for kind in [ShellKind::Zsh, ShellKind::Bash] {
        let package = set
            .select(Some(kind.as_str()))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} has no {kind:?}: {fault}"))
            .clone();
        let shell = RealShell::start(
            &package,
            kr_protocol::session::LaunchProfile::default(),
            Vec::new(),
            None,
        )
        .await;

        let mut keys = shell.keys();
        keys.type_line(&shell, "uname");
        let ran = shell
            .until_described("`uname` to end, named as the program it ran", |facts| {
                facts.completion.0 == Some(DescriptionCompletion::Succeeded)
            })
            .await;
        assert_eq!(ran.application.0.as_deref(), Some("uname"), "{kind:?}");

        keys.type_line(&shell, "kr-9f3a7c1e-notacommand");
        let pasted = shell
            .until_described("the word with no file to end as not found", |facts| {
                facts.completion.0 == Some(DescriptionCompletion::Failed)
            })
            .await;
        assert_eq!(
            pasted.application.0, None,
            "{kind:?}: a word the shell found no file for is no program"
        );
        let encoded = serde_json::to_string(&pasted).expect("facts encode");
        assert!(!encoded.contains("9f3a7c1e"), "{kind:?}: {encoded}");

        // A word with slashes in it is the word itself to a shell's search, found or not, and a
        // shell may ask about it with the path it would have been: a token with slashes in it and
        // an address pasted at the prompt name no program either.
        let mut before = pasted.revision.get();
        for word in [
            "kr-9f3a7c1e/kr-5d2b/notacommand",
            "https://hooks.example.test/services/kr-77aa31/notacommand",
        ] {
            keys.type_line(&shell, word);
            let after = before;
            let pasted = shell
                .until_described("the word with slashes to end", |facts| {
                    facts.revision.get() > after
                        && facts.completion.0 == Some(DescriptionCompletion::Failed)
                })
                .await;
            before = pasted.revision.get();
            assert_eq!(
                pasted.application.0, None,
                "{kind:?}: {word}: a word with slashes in it that is no file names no program"
            );
            let encoded = serde_json::to_string(&pasted).expect("facts encode");
            assert!(
                !encoded.contains("notacommand") && !encoded.contains("kr-77aa31"),
                "{kind:?}: {encoded}"
            );
        }
        shell.close().await;
    }
}

#[cfg(unix)]
impl RealShell {
    /// Waits until the session's description facts satisfy `holds`, and returns them; says what
    /// they were when they never do.
    async fn until_described(
        &self,
        waited_for: &str,
        holds: impl Fn(&kr_protocol::describe::DescriptionFacts) -> bool,
    ) -> kr_protocol::describe::DescriptionFacts {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let facts = self
                .runtime
                .session()
                .description_facts()
                .read(0, None)
                .facts;
            if let Some(facts) = facts.as_ref().filter(|facts| holds(facts)) {
                return facts.clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "waited for {waited_for}; the facts are {facts:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits until the session's description facts name `directory`, and says what they did name
    /// when they never do.
    async fn directory_described_as(&self, directory: &str, waited_for: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let facts = self
                .runtime
                .session()
                .description_facts()
                .read(0, None)
                .facts;
            if facts
                .as_ref()
                .is_some_and(|facts| facts.directory.0.as_deref() == Some(directory))
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "waited for the facts to name {directory:?} ({waited_for}); they are {facts:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

// --------------------------------------------------------------------------------------------
// KR-REQ-12.07, KR-REQ-25.05: the command hooks the private integration reports through.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.17: the bridge server compares the declaration against the package it launched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bridge_that_declares_another_build_is_refused_on_the_real_endpoint() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let config = configuration(&temp, ShellMode::Managed);
    let session_id = config.session_id;
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        Arc::new(SystemContinuousClock::new()),
    ));
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    // The reference bridge declares /bin/cat; this session launched a different build of the same
    // shell, with the same editor ABI and the same integration version.
    let declared = reference();
    let expectation = WorkerExpectation {
        session_id,
        root_process: process.clone(),
        supported_editor_abis: vec!["zle-5.9".to_owned()],
        supported_integration_versions: vec!["1".to_owned()],
        launched_package: Some(
            kr_shell_integration::contract::transport::PackageDeclaration {
                kind: ShellKind::Zsh,
                executable: "/opt/kalareach/shells/zsh/another-build/bin/zsh".to_owned(),
                upstream_version: "5.9".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
                integration_version: "1".to_owned(),
                patches: Vec::new(),
                modules: Vec::new(),
            },
        ),
        already_registered: false,
        gesture: EofGesture::default(),
    };
    let bridge_task = tokio::spawn(
        kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            host_endpoint,
            expectation,
        )
        .serve(),
    );

    let hello =
        qualified_hello(&declared, session_id, &address, process, &secret).expect("a hello");
    let (_bridge, outcome) = tokio::time::timeout(SOON, ScriptedBridge::connect(&address, &hello))
        .await
        .expect("the worker answered")
        .expect("connects");
    match outcome {
        HandshakeOutcome::Refused(refusal) => {
            assert_eq!(
                refusal.reason,
                kr_shell_integration::contract::qualification::QualificationReason::PackageMismatch
            );
            assert_eq!(refusal.error.code, ErrorCode::PermissionDenied);
        }
        HandshakeOutcome::Accepted(_) => {
            panic!("a declaration of another build is not this session's package")
        }
    }
    assert!(
        runtime
            .session()
            .fence()
            .expect("a driver")
            .phase()
            .shell()
            .is_none(),
        "and nothing is registered"
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
    let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
    bridge_task.abort();
}

/// KR-REQ-12.07: an integration this host can put no backend behind adds no flags.
///
/// Section 12 requires the worker-owned backend and its gateway to exist before the native program
/// does. This host establishes none, so an invocation that would need one runs exactly as it was
/// typed: an agent started with integration flags and nothing behind them is worse off than one
/// started without them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_integration_with_no_backend_behind_it_runs_the_invocation_as_typed() {
    let mut wired = wired_profiled(
        ShellMode::Managed,
        true,
        kr_protocol::session::LaunchProfile {
            command_integrations: vec![kr_protocol::session::CommandIntegration {
                plugin_id: kr_protocol::ids::PluginId::new("kalareach/codex")
                    .expect("a plugin identifier"),
                command: "codex".to_owned(),
                flags: vec!["--kr-gateway".to_owned()],
                enabled: true,
            }],
            ..kr_protocol::session::LaunchProfile::default()
        },
    )
    .await;
    let resolved = resolve_over(&mut wired, &["codex", "--model", "opus"], true).await;
    assert_eq!(
        resolved.bypass.0,
        Some(kr_protocol::root::CommandBypassReason::BackendUnavailable)
    );
    assert_eq!(
        resolved.arguments,
        vec!["codex".to_owned(), "--model".to_owned(), "opus".to_owned()],
        "the command name and the vector the person typed are what runs"
    );
    assert!(resolved.added.is_empty());
    assert!(
        resolved.backend.0.is_none(),
        "and no gateway is claimed for it, then or later"
    );

    // A session that is closing starts nothing new, whatever its integration last reported.
    wired
        .runtime
        .session()
        .begin_close(ClosureReason::CloseRequested);
    let refused = resolve_at(&mut wired, PromptGeneration::new(2), &["codex"], true).await;
    assert_eq!(
        refused.bypass.0,
        Some(kr_protocol::root::CommandBypassReason::SessionClosing)
    );
    assert!(refused.backend.0.is_none());
    assert_eq!(refused.arguments, vec!["codex".to_owned()]);
    wired.close().await;
}

/// KR-REQ-12.07: the three bypasses keep the invocation and get no gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bypassed_invocation_runs_as_typed_and_is_given_no_backend() {
    let mut wired = wired_profiled(
        ShellMode::Managed,
        true,
        kr_protocol::session::LaunchProfile {
            command_integrations: vec![
                kr_protocol::session::CommandIntegration {
                    plugin_id: kr_protocol::ids::PluginId::new("kalareach/codex")
                        .expect("a plugin identifier"),
                    command: "codex".to_owned(),
                    flags: vec!["--kr-gateway".to_owned()],
                    enabled: true,
                },
                kr_protocol::session::CommandIntegration {
                    plugin_id: kr_protocol::ids::PluginId::new("kalareach/opencode")
                        .expect("a plugin identifier"),
                    command: "opencode".to_owned(),
                    flags: vec!["--kr-gateway".to_owned()],
                    enabled: false,
                },
            ],
            ..kr_protocol::session::LaunchProfile::default()
        },
    )
    .await;
    for (argv, interactive, reason) in [
        (
            vec!["/usr/local/bin/codex".to_owned()],
            true,
            kr_protocol::root::CommandBypassReason::AbsolutePath,
        ),
        (
            vec!["opencode".to_owned()],
            true,
            kr_protocol::root::CommandBypassReason::Disabled,
        ),
        (
            vec!["codex".to_owned()],
            false,
            kr_protocol::root::CommandBypassReason::NotInteractive,
        ),
        (
            vec!["make".to_owned()],
            true,
            kr_protocol::root::CommandBypassReason::NotIntegrated,
        ),
    ] {
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let resolved = resolve_over(&mut wired, &borrowed, interactive).await;
        assert_eq!(
            resolved.arguments, argv,
            "the invocation is exactly as typed"
        );
        assert!(resolved.added.is_empty());
        assert_eq!(resolved.bypass.0, Some(reason));
        assert!(
            resolved.backend.0.is_none(),
            "a bypassed invocation never gets a gateway, then or later"
        );
    }
    wired.close().await;
}

/// KR-REQ-12.07: a shell whose integration is not yet a managed root shell is never intercepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unmanaged_shell_is_never_intercepted() {
    let mut wired = wired_profiled(
        ShellMode::Managed,
        false,
        kr_protocol::session::LaunchProfile {
            command_integrations: vec![kr_protocol::session::CommandIntegration {
                plugin_id: kr_protocol::ids::PluginId::new("kalareach/codex")
                    .expect("a plugin identifier"),
                command: "codex".to_owned(),
                flags: vec!["--kr-gateway".to_owned()],
                enabled: true,
            }],
            ..kr_protocol::session::LaunchProfile::default()
        },
    )
    .await;
    // Registered but not qualified: the user's startup files have not finished, so the hooks
    // that make this a managed root shell are not live yet.
    let resolved = resolve_over(&mut wired, &["codex"], true).await;
    assert_eq!(resolved.arguments, vec!["codex".to_owned()]);
    assert_eq!(
        resolved.bypass.0,
        Some(kr_protocol::root::CommandBypassReason::UnmanagedShell)
    );
    assert!(resolved.backend.0.is_none());
    wired.close().await;
}

/// KR-REQ-25.05: a command block carries its exit status, duration and directory to a reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_command_block_reaches_the_session_read_with_its_status_duration_and_directory() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    let started = kr_protocol::root::RootCommandBlockParams {
        session_id: wired.session_id,
        prompt_generation: PromptGeneration::new(4),
        command: "cargo test".to_owned(),
        started_at_ms: kr_protocol::scalars::TimestampMs::new(1_700_000_000_000),
        duration_ms: Nullable::null(),
        exit_status: Nullable::null(),
        cwd: "/tmp/project".to_owned(),
        cwd_revision: CwdRevision::new(3),
    };
    let recorded = block_over(&mut wired, started.clone()).await;
    assert_eq!(recorded.retained.get(), 1);

    let read: kr_protocol::session::SessionReadResult = client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams {
                session_id: wired.session_id,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("reads")
        .to_typed()
        .expect("decodes");
    let running = read.last_command_block.0.expect("a block");
    assert_eq!(running.command, "cargo test");
    assert!(!running.finished(), "it is still running");

    // The same command ends. One entry per command, with what it exited with.
    let finished = kr_protocol::root::RootCommandBlockParams {
        duration_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(4_200)),
        exit_status: Nullable::some(U64::new(101)),
        ..started
    };
    let recorded = block_over(&mut wired, finished).await;
    assert_eq!(recorded.retained.get(), 1, "the end replaces the start");

    let read: kr_protocol::session::SessionReadResult = client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams {
                session_id: wired.session_id,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("reads")
        .to_typed()
        .expect("decodes");
    let block = read.last_command_block.0.expect("a block");
    assert!(block.finished());
    assert!(block.completed_nonzero());
    assert_eq!(block.exit_status.0.expect("a status").get(), 101);
    assert_eq!(block.duration_ms.0.expect("a duration").get(), 4_200);
    assert_eq!(block.cwd, "/tmp/project");
    assert_eq!(block.cwd_revision, CwdRevision::new(3));
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.84: acceptance is attributed, and an unqualified detach resolves against it.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.84.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_line_names_the_client_that_typed_it_and_an_ambiguous_one_says_so() {
    let mut wired = wired().await;
    let holder = wired.holder();
    let fence = fenced(&mut wired, 1, 1).await;
    assert_eq!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .detach_target(),
        DetachTarget::Ambiguous(AmbiguityReason::NoAcceptedCommand)
    );
    wired
        .bridge
        .send_event(BridgeEvent::CommandAccepted(RootCommandAcceptedParams {
            session_id: wired.session_id,
            fence_id: Nullable::some(fence.fence_id),
            prompt_generation: fence.prompt_generation,
            origin: AcceptedOrigin::Fenced {
                attachment_id: holder,
                input_epoch: fence.input_epoch,
            },
        }))
        .await
        .expect("reports");
    let recorded = loop {
        match wired.next().await {
            ToBridge::EventResult { result, .. } => match *result {
                kr_shell_integration::contract::transport::EventOutcome::CommandRecorded(
                    result,
                ) => break result,
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(
        recorded.origin,
        AcceptedOrigin::Fenced {
            attachment_id: holder,
            input_epoch: fence.input_epoch,
        }
    );
    assert_eq!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .detach_target(),
        DetachTarget::Attachment(holder),
        "kr detach with no identifier targets the client that typed the line"
    );

    // A line whose input came from more than one place cannot be attributed at all.
    let fence = fenced(&mut wired, 2, 1).await;
    wired
        .bridge
        .send_event(BridgeEvent::CommandAccepted(RootCommandAcceptedParams {
            session_id: wired.session_id,
            fence_id: Nullable::some(fence.fence_id),
            prompt_generation: fence.prompt_generation,
            origin: AcceptedOrigin::Mixed,
        }))
        .await
        .expect("reports");
    tokio::time::timeout(SOON, async {
        loop {
            if wired
                .runtime
                .session()
                .fence()
                .expect("a driver")
                .detach_target()
                == DetachTarget::Ambiguous(AmbiguityReason::MixedContext)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the mixed context was recorded");
    assert_eq!(
        DetachTarget::Ambiguous(AmbiguityReason::MixedContext).code(),
        Some(ErrorCode::AmbiguousAttachment)
    );
    wired.close().await;
}

/// KR-REQ-23.38: the session's launch profile is one of the launch's preconditions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_profile_that_refuses_a_fenced_launch_installs_nothing() {
    let mut wired = wired_profiled(
        ShellMode::Managed,
        true,
        kr_protocol::session::LaunchProfile {
            fenced_launch: false,
            ..kr_protocol::session::LaunchProfile::default()
        },
    )
    .await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;

    let refused = client
        .mutate(
            Method::ShellLaunch,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &ShellLaunchParams {
                session_id: wired.session_id,
                command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
                expected_prompt_generation: fence.prompt_generation,
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("this session's profile admits no fenced launch");
    assert_eq!(refused.code, ErrorCode::ShellIntegrationUnsupported);
    assert!(
        refused.message.contains("launch profile"),
        "the refusal names the precondition that failed: {}",
        refused.message
    );
    assert!(
        !contains(&retained(&wired.runtime.session()), b"ls"),
        "and nothing was written into the terminal"
    );
    wired.close().await;
}

/// Section 7's own instruction to a caller whose attachment this host cannot name.
const DETACH_HINT: &str = "Use kr detach --attachment <id> to detach";

/// Reads the capability the worker minted for the line it has just recorded.
async fn recorded_token(wired: &mut Wired) -> Option<String> {
    loop {
        if let ToBridge::EventResult { result, .. } = wired.next().await
            && let kr_shell_integration::contract::transport::EventOutcome::CommandRecorded(
                recorded,
            ) = *result
        {
            return recorded.detach_token.0;
        }
    }
}

/// Calls `session.detach` with whatever this caller holds.
async fn detach(
    client: &mut LocalClient,
    wired: &Wired,
    attachment_id: Nullable<AttachmentId>,
    line_token: Nullable<String>,
) -> std::result::Result<
    kr_protocol::attachment::SessionDetachResult,
    kr_protocol::error::ProtocolError,
> {
    client
        .mutate(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::attachment::SessionDetachParams {
                attachment_id,
                line_token,
            },
        )
        .await
        .expect("reaches the worker")
        .map(|answered| answered.to_typed().expect("decodes"))
}

/// KR-REQ-07.84: `session.detach` with no attachment named resolves against the recorded origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_that_names_nothing_removes_the_attachment_the_line_was_typed_from() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let typist = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    wired
        .bridge
        .send_event(BridgeEvent::CommandAccepted(RootCommandAcceptedParams {
            session_id: wired.session_id,
            fence_id: Nullable::some(fence.fence_id),
            prompt_generation: fence.prompt_generation,
            origin: AcceptedOrigin::Fenced {
                attachment_id: typist,
                input_epoch: fence.input_epoch,
            },
        }))
        .await
        .expect("reports");
    let token = recorded_token(&mut wired).await;

    // A second client takes the keys while the command from that line is still running, which is
    // exactly the case section 7 refuses to let decide a detach.
    let later = holder_over(&mut client, &wired).await;
    assert_ne!(later, typist);
    assert_eq!(wired.runtime.session().lease().holder.0, Some(later));

    // A caller holding no capability is told to name the attachment, whatever it looks like.
    let refused = detach(&mut client, &wired, Nullable::null(), Nullable::null())
        .await
        .expect_err("a caller with no capability names the attachment it means");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert!(
        refused.message.contains(DETACH_HINT),
        "the refusal carries section 7's own instruction: {}",
        refused.message
    );

    // And one holding a capability that is not this line's is told the same.
    let refused = detach(
        &mut client,
        &wired,
        Nullable::null(),
        Nullable::some("not-a-token".to_owned()),
    )
    .await
    .expect_err("a capability this line does not hold names nothing");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert!(refused.message.contains(DETACH_HINT));
    assert_eq!(
        wired.runtime.session().attachments().len(),
        2,
        "and nothing was detached"
    );

    // The line's own capability names the attachment that line was typed in, not the lease holder
    // that took the keys after it.
    let detached = detach(
        &mut client,
        &wired,
        Nullable::null(),
        Nullable::some(token.expect("a capability was minted for the line")),
    )
    .await
    .expect("detaches");
    assert_eq!(detached.attachment_id, typist);
    assert!(
        wired
            .runtime
            .session()
            .attachment_capabilities(typist)
            .is_none()
    );
    wired.close().await;
}

/// KR-REQ-07.84: a capability from an earlier line names nothing once another line is accepted.
///
/// This is every arrangement a shell's job control can make of two attachments, at the level that
/// decides the answer. `(sleep 10; exec kr detach) &` from A followed by `fg %1` from B, a
/// background job of A's calling detach while B's line runs, and either of those with `set +m` so
/// that every child shares the shell's own process group: each one is a caller from A's line
/// asking after another line has been accepted. No reading of such a caller's process tells it
/// apart from the line running now — `exec` keeps the identifier, `fg` gives it the terminal, and
/// without job control it has the shell's own group — and none of that has to be told apart: the
/// capability A's line holds is not the one this session's current line holds, so it names
/// nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capability_from_an_earlier_line_names_nothing_after_another_is_accepted() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    // A types a line and is given a capability for it.
    let typist = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    accept(&mut wired, &fence, typist).await;
    let first = recorded_token(&mut wired)
        .await
        .expect("a capability for the line");

    // The next line is accepted, whatever A left running behind it.
    wired
        .bridge
        .send_event(BridgeEvent::CommandAccepted(RootCommandAcceptedParams {
            session_id: wired.session_id,
            fence_id: Nullable::some(fence.fence_id),
            prompt_generation: PromptGeneration::new(2),
            origin: AcceptedOrigin::Fenced {
                attachment_id: typist,
                input_epoch: fence.input_epoch,
            },
        }))
        .await
        .expect("reports");
    assert!(
        recorded_token(&mut wired).await.is_none(),
        "a line this host cannot attribute holds no capability"
    );

    // And A's caller, however its shell arranged the process it runs in, names nothing.
    let refused = detach(&mut client, &wired, Nullable::null(), Nullable::some(first))
        .await
        .expect_err("a capability from a line that has been replaced names nothing");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert!(refused.message.contains(DETACH_HINT));
    assert_eq!(
        wired.runtime.session().attachments().len(),
        1,
        "and nothing was detached"
    );
    wired.close().await;
}

/// KR-REQ-07.84: input a running command reads is not a line, and does not move the capability.
///
/// `read -e answer; kr detach` is one accepted line. The `read` builtin opens another reader and
/// the shell reports what it accepts there exactly as it reports a line, because to the editor it
/// is one. It is not: the command A typed is still running, and a detach from inside it is still
/// A's. Another attachment answering the question, under a fence of its own, changes neither the
/// record nor the capability.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_a_command_reads_is_not_a_line_and_leaves_the_capability_alone() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let typist = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    accept(&mut wired, &fence, typist).await;
    let token = recorded_token(&mut wired)
        .await
        .expect("a capability for the line");

    // The reader leaves, which is what running the command looks like from here.
    wired
        .bridge
        .send_event(BridgeEvent::EditorLeave(RootEditorLeaveParams {
            session_id: wired.session_id,
            prompt_generation: fence.prompt_generation,
            reader_revision: ReaderRevision::new(1),
            reason: kr_protocol::root::EditorLeaveReason::CommandAccepted,
        }))
        .await
        .expect("leaves");

    // The command asks its question, and another client has the keys by the time it does.
    let answerer = holder_over(&mut client, &wired).await;
    assert_ne!(answerer, typist);
    let read = fenced_read(&mut wired, 1, 2).await;
    accept(&mut wired, &read, answerer).await;
    assert!(
        recorded_token(&mut wired).await.is_none(),
        "an answer to a question is not a line, so nothing is minted for it"
    );

    // The capability the line holds is untouched, and it still names the terminal that typed it.
    let detached = detach(&mut client, &wired, Nullable::null(), Nullable::some(token))
        .await
        .expect("detaches");
    assert_eq!(
        detached.attachment_id, typist,
        "the line's own terminal goes, not the one that answered its question"
    );
    assert!(
        wired
            .runtime
            .session()
            .attachment_capabilities(typist)
            .is_none()
    );
    assert!(
        wired
            .runtime
            .session()
            .attachment_capabilities(answerer)
            .is_some(),
        "and the attachment that answered stays"
    );
    wired.close().await;
}

/// KR-REQ-07.84: a capability names nothing once its own line has finished.
///
/// Nothing else has to happen for a line to end: no second line is typed, no client takes the
/// keys, no attachment leaves. The command reports the status it exited with and the reader comes
/// back at the next prompt, and from that moment the question a bare `kr detach` asks — which
/// terminal typed the line I am running from — has no answer, because nothing is running from a
/// line any more. A caller still holding the capability that line was given is told to name the
/// attachment it means.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capability_names_nothing_once_its_own_line_has_finished() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let typist = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    accept(&mut wired, &fence, typist).await;
    let token = recorded_token(&mut wired)
        .await
        .expect("a capability for the line");

    // The command that line started ends, with the status it exited with.
    let finished = kr_protocol::root::RootCommandBlockParams {
        session_id: wired.session_id,
        prompt_generation: fence.prompt_generation,
        command: "sleep 10".to_owned(),
        started_at_ms: kr_protocol::scalars::TimestampMs::new(1_700_000_000_000),
        duration_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(10_000)),
        exit_status: Nullable::some(U64::ZERO),
        cwd: "/tmp/project".to_owned(),
        cwd_revision: CwdRevision::new(1),
    };
    let recorded = block_over(&mut wired, finished).await;
    assert_eq!(recorded.retained.get(), 1);

    // No further line is accepted, and the attachment that typed the first one is still here.
    assert_eq!(wired.runtime.session().attachments().len(), 1);
    let refused = detach(
        &mut client,
        &wired,
        Nullable::null(),
        Nullable::some(token.clone()),
    )
    .await
    .expect_err("a capability whose line has finished names nothing");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert!(
        refused.message.contains(DETACH_HINT),
        "the refusal carries section 7's own instruction: {}",
        refused.message
    );
    assert_eq!(
        wired.runtime.session().attachments().len(),
        1,
        "and nothing was detached"
    );
    wired.close().await;
}

/// KR-REQ-07.84: a capability names nothing once the reader is back at the next prompt.
///
/// The packaged shells report no command block today, so the reader's own return is what says a
/// line is over for them: a primary prompt after the one a line was accepted at is reached only
/// once that line has finished. Nothing else changes here — one attachment, no second line, no
/// lease change — and the capability from the prompt before names nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capability_names_nothing_once_the_reader_is_back_at_the_next_prompt() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let typist = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    accept(&mut wired, &fence, typist).await;
    let token = recorded_token(&mut wired)
        .await
        .expect("a capability for the line");
    let _next = fenced(&mut wired, 2, 2).await;

    let refused = detach(&mut client, &wired, Nullable::null(), Nullable::some(token))
        .await
        .expect_err("a capability from the prompt before this one names nothing");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert!(refused.message.contains(DETACH_HINT));
    assert_eq!(
        wired.runtime.session().attachments().len(),
        1,
        "and nothing was detached"
    );
    wired.close().await;
}

/// KR-REQ-07.84: a session that lost its integration holds no capability.
///
/// After a loss the host is no longer told anything it can rely on: the hooks, the reader or the
/// root shell itself has gone, so it would never learn that the line the capability names had
/// ended. The capability ends with the loss, and a detach that names nothing is answered with the
/// instruction to name one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capability_ends_with_the_integration_that_recorded_its_line() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let typist = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    accept(&mut wired, &fence, typist).await;
    let token = recorded_token(&mut wired)
        .await
        .expect("a capability for the line");

    let outcome = wired
        .runtime
        .drive_fence(|driver| driver.integration_lost(IntegrationLoss::SemanticHookLoss));
    assert_eq!(
        outcome.close_session, None,
        "a live session is not closed by it"
    );

    let refused = detach(&mut client, &wired, Nullable::null(), Nullable::some(token))
        .await
        .expect_err("a capability outlives neither the reader nor the hooks that recorded it");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert!(refused.message.contains(DETACH_HINT));
    assert_eq!(
        wired.runtime.session().attachments().len(),
        1,
        "and nothing was detached"
    );
    wired.close().await;
}

/// Records one accepted line for this attachment and waits for the machine to take it.
async fn accept(
    wired: &mut Wired,
    fence: &kr_protocol::root::EditorFence,
    attachment_id: AttachmentId,
) {
    wired
        .bridge
        .send_event(BridgeEvent::CommandAccepted(RootCommandAcceptedParams {
            session_id: wired.session_id,
            fence_id: Nullable::some(fence.fence_id),
            prompt_generation: fence.prompt_generation,
            origin: AcceptedOrigin::Fenced {
                attachment_id,
                input_epoch: fence.input_epoch,
            },
        }))
        .await
        .expect("reports");
}

/// KR-REQ-07.84: a mixed origin is refused rather than guessed at.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_that_names_nothing_is_refused_when_the_origin_was_mixed() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let holder = holder_over(&mut client, &wired).await;
    let _ = holder;

    // Before any line has been accepted there is no origin, and one remaining terminal is not
    // proof that it is the one a command would have come from.
    let refused = wired
        .runtime
        .session()
        .detach_origin()
        .expect_err("a session that has accepted no line names no originating attachment");
    assert!(refused.to_string().contains("--attachment"));

    let fence = fenced(&mut wired, 1, 1).await;
    wired
        .bridge
        .send_event(BridgeEvent::CommandAccepted(RootCommandAcceptedParams {
            session_id: wired.session_id,
            fence_id: Nullable::some(fence.fence_id),
            prompt_generation: fence.prompt_generation,
            origin: AcceptedOrigin::Mixed,
        }))
        .await
        .expect("reports");
    tokio::time::timeout(SOON, async {
        loop {
            if wired
                .runtime
                .session()
                .fence()
                .expect("a driver")
                .detach_target()
                == DetachTarget::Ambiguous(AmbiguityReason::MixedContext)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the mixed context was recorded");

    let refused = wired
        .runtime
        .session()
        .detach_origin()
        .expect_err("a mixed context cannot name one attachment");
    assert!(
        refused.to_string().contains("more than one attachment"),
        "the refusal says why: {refused}"
    );

    // And no capability was minted for it, so the method refuses it too.
    assert!(recorded_token(&mut wired).await.is_none());
    let refused = detach(&mut client, &wired, Nullable::null(), Nullable::null())
        .await
        .expect_err("a mixed context cannot name one attachment");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment);
    assert_eq!(
        wired.runtime.session().attachments().len(),
        1,
        "and nothing was detached"
    );
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.32, KR-REQ-07.33, KR-REQ-07.83, KR-REQ-23.38, KR-REQ-23.54: the launch transaction.
// --------------------------------------------------------------------------------------------

/// A launch the reader has not answered is work this host has outstanding.
///
/// Section 9's sleep demand reads it, so it has to survive the revocation A-17 sends at 250 ms:
/// that bounds how long input is held, not how long the reader may take to decide. What ends it
/// is the reader's answer, the bridge going, or the session closing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unanswered_launch_is_outstanding_through_its_revocation_and_ends_with_the_answer() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    assert_eq!(
        wired.runtime.session().outstanding_launches(),
        Some(0),
        "a managed session with nothing in flight says none, which is not the same as saying \
         nothing"
    );

    let fence = fenced(&mut wired, 1, 1).await;
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
        expected_prompt_generation: fence.prompt_generation,
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(
        wired.runtime.session().outstanding_launches(),
        Some(1),
        "the reader has it and the caller is waiting"
    );

    // The revocation comes and goes. The launch is still with the reader, and the caller is still
    // waiting for its decision, so it is still outstanding.
    let revoked = tokio::time::timeout(SOON, async {
        loop {
            if matches!(wired.next().await, ToBridge::LaunchRevoked { .. }) {
                return;
            }
        }
    })
    .await;
    assert!(
        revoked.is_ok(),
        "the hold expired and the launch was revoked"
    );
    assert_eq!(
        wired.runtime.session().outstanding_launches(),
        Some(1),
        "a revocation bounds the hold on input, not the reader's decision"
    );

    // The reader decides, the caller is answered, and nothing is outstanding.
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Rejected(LaunchRejection {
                transaction: request.transaction,
                reason: LaunchRejectionReason::Revoked,
                fence_id: request.fence_id,
                prompt_generation: fence.prompt_generation,
                buffer_revision: EditorBufferRevision::new(1),
            })),
        )
        .await
        .expect("answers");
    let _ = tokio::time::timeout(SOON, calling).await.expect("answered");
    tokio::time::timeout(SOON, async {
        loop {
            if wired.runtime.session().outstanding_launches() == Some(0) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the reader's answer ended it");

    // And a session with no managed editor says nothing at all, which is a different answer from
    // saying none.
    let stock = wired_with(ShellMode::NativeCompat, false).await;
    assert_eq!(stock.runtime.session().outstanding_launches(), None);
    stock.close().await;
    wired.close().await;
}

/// A bridge that goes takes every launch it was deciding with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_bridge_leaves_no_launch_outstanding() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
        expected_prompt_generation: fence.prompt_generation,
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    loop {
        if let ToBridge::Request { request, .. } = wired.next().await
            && matches!(*request, WorkerRequest::Launch(_))
        {
            break;
        }
    }
    assert_eq!(wired.runtime.session().outstanding_launches(), Some(1));

    let _ = wired
        .runtime
        .drive_fence(|driver| driver.integration_lost(IntegrationLoss::BridgeDisconnected));
    let _ = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller is answered rather than left waiting");
    assert_eq!(
        wired.runtime.session().outstanding_launches(),
        Some(0),
        "a bridge that has gone is deciding nothing"
    );
    wired.close().await;
}

/// KR-REQ-07.32, KR-REQ-23.38: a launch reaches the reader's mailbox and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_is_installed_through_the_reader_and_never_written_into_the_terminal() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::Arguments(vec![
            "git".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "it's done".to_owned(),
        ]),
        expected_prompt_generation: fence.prompt_generation,
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(
        request.command,
        LaunchCommand::Arguments(vec![
            "git".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "it's done".to_owned(),
        ]),
        "the argument vector reaches the reader literally"
    );
    assert_eq!(request.fence_id, fence.fence_id);
    assert_eq!(request.expected_cwd_revision, CwdRevision::new(1));
    assert!(request.deadline_ms.get() <= 200);
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Accepted(LaunchAccepted {
                transaction: request.transaction,
                installed: request.command.clone(),
                fence_id: request.fence_id,
                prompt_generation: fence.prompt_generation,
                buffer_revision: EditorBufferRevision::new(2),
                reader_revision: ReaderRevision::new(1),
            })),
        )
        .await
        .expect("installs");
    let outcome = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect("installed");
    let result: ShellLaunchResult = outcome.to_typed().expect("a launch result");
    assert_eq!(result.fence_id, fence.fence_id);
    assert_eq!(result.buffer_revision, EditorBufferRevision::new(2));
    wired.close().await;
}

/// KR-REQ-07.83, KR-REQ-23.54: a buffer that moved is DRAFT_CONFLICT, not a second install.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_intervening_local_edit_is_a_draft_conflict() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::QuotedCommand("cargo test".to_owned()),
        expected_prompt_generation: fence.prompt_generation,
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Rejected(LaunchRejection {
                transaction: request.transaction,
                fence_id: request.fence_id,
                reason: LaunchRejectionReason::BufferRevisionMismatch,
                prompt_generation: fence.prompt_generation,
                buffer_revision: EditorBufferRevision::new(9),
            })),
        )
        .await
        .expect("refuses");
    let error = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect_err("refused");
    assert_eq!(error.code, ErrorCode::DraftConflict);
    wired.close().await;
}

/// KR-REQ-07.83, decision A-17: a reader that never answers leaves the outcome unknown, and the
/// held input is released rather than lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_the_reader_never_answers_revokes_and_reports_what_it_can() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    let params = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::QuotedCommand("cargo test".to_owned()),
        expected_prompt_generation: fence.prompt_generation,
        expected_buffer_revision: EditorBufferRevision::new(1),
    };
    let target = wired.target();
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &params,
            )
            .await
    });
    // The worker revokes at its own deadline and waits for the reader's word.
    let revoked = loop {
        match wired.next().await {
            ToBridge::LaunchRevoked { reason, .. } => break reason,
            _ => continue,
        }
    };
    assert_eq!(revoked, LaunchRejectionReason::Timeout);
    // The reader is gone, so nothing can say whether a command reached the editor.
    let _ = wired
        .runtime
        .drive_fence(|driver| driver.integration_lost(IntegrationLoss::BridgeDisconnected));
    let error = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect_err("refused");
    assert_eq!(
        error.code,
        ErrorCode::OutcomeUnknown,
        "a command that may be in the editor is never reported as not installed"
    );
    wired.close().await;
}

/// KR-REQ-07.20, KR-ACC-035: `native_compat` claims none of this and installs nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stock_shell_session_claims_no_managed_editor() {
    let temp = kr_ipc::testing::TempHost::create();
    let config = configuration(&temp, ShellMode::NativeCompat);
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    assert!(
        session.fence().is_none(),
        "a stock shell registers no root editor"
    );
    assert!(!ShellMode::NativeCompat.claims_managed_editor());
    assert!(ShellMode::Managed.claims_managed_editor());
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
    let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
}

/// Section 7 paragraph 4: nothing external reaches the terminal before the bridge is authenticated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managed_session_takes_no_input_before_its_bridge_has_authenticated() {
    let temp = kr_ipc::testing::TempHost::create();
    let config = configuration(&temp, ShellMode::Managed);
    let session_id = config.session_id;
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        Arc::new(SystemContinuousClock::new()),
    ));
    let params = terminal(session_id);
    let holder = AttachmentId::new(kr_ipc::new_uuid());
    session
        .attach(&params, params.requested.clone(), holder)
        .expect("attaches");
    session
        .acquire_input(holder, ConnectionId::new(kr_ipc::new_uuid()), None)
        .expect("takes the keys");
    let epoch = session.lease().epoch.get();

    // A whole frame is refused, and so is one that is only part of a delimiter: a refusal that let
    // the recogniser keep the prefix would leave the session inside a paste nothing opened.
    for (sequence, bytes) in [b"\x1b[200~".as_slice(), b"\x1b".as_slice()]
        .into_iter()
        .enumerate()
    {
        let error = session
            .write_input(
                holder,
                epoch,
                sequence as u64,
                bytes,
                None,
                std::time::Instant::now(),
            )
            .expect_err("refused before the bridge authenticated");
        assert!(
            matches!(
                error,
                kr_worker::error::WorkerError::PreconditionFailed { .. }
            ),
            "{error}"
        );
    }
    assert!(
        retained(&session).is_empty(),
        "and nothing reached the terminal"
    );
    assert_eq!(
        session.expire_paste_prefix(std::time::Instant::now()),
        0,
        "the recogniser is holding nothing, so no prefix is waiting on a timer"
    );

    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
    let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
}

/// KR-REQ-07.22: a loss before the session has qualified closes the session that was being made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_integration_failure_before_qualification_closes_the_creating_session() {
    let wired = wired_with(ShellMode::Managed, false).await;
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert!(
            !driver.phase().reports_ready(),
            "a session whose startup files have not finished is not ready"
        );
        assert!(
            driver.phase().accepts_external_input(),
            "an authenticated bridge is enough for a startup prompt to read its input"
        );
        assert!(!driver.phase().permits_launch());
    }
    let outcome = wired
        .runtime
        .drive_fence(|driver| driver.integration_lost(IntegrationLoss::PostStartupFailure));
    assert_eq!(
        outcome.close_session,
        Some(IntegrationLoss::PostStartupFailure)
    );
    let record = tokio::time::timeout(SOON, wired.runtime.wait_closed())
        .await
        .expect("the session closed");
    assert_eq!(record.reason, ClosureReason::RootLaunchFailed);
}

/// KR-REQ-07.24: a live session that loses its hooks keeps the fail-safe gesture and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_session_that_loses_its_hooks_stops_attributing_and_stops_installing() {
    let mut wired = wired().await;
    let _holder = wired.holder();
    let _fence = fenced(&mut wired, 1, 1).await;
    let outcome = wired
        .runtime
        .drive_fence(|driver| driver.integration_lost(IntegrationLoss::SemanticHookLoss));
    assert_eq!(
        outcome.close_session, None,
        "a live session is not closed by it"
    );
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert!(!driver.phase().permits_launch());
        assert!(!driver.phase().permits_attribution());
        assert!(!driver.phase().retains_fence());
        assert!(
            driver.phase().consumes_eligible_eof(),
            "the pre-EOF hook stays fail-safe"
        );
        assert!(driver.fence().is_none(), "the fence went with the hooks");
        assert_eq!(
            driver.state(),
            FenceState::Outside,
            "the reader the session can no longer speak for is deregistered"
        );
    }

    // And a takeover afterwards starts no exchange, so no fence is published and no detach proof is
    // handed out by a session the phase says is degraded.
    let second = AttachmentId::new(kr_ipc::new_uuid());
    {
        let params = terminal(wired.session_id);
        let mut session = wired.runtime.session();
        session
            .attach(&params, params.requested.clone(), second)
            .expect("attaches");
        session
            .acquire_input(second, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the keys");
    }
    // The loss itself tells the bridge its fence has gone, which is a frame. What must not appear
    // is another exchange or another published fence.
    while let Ok(Ok(frame)) =
        tokio::time::timeout(Duration::from_millis(400), wired.bridge.recv()).await
    {
        match frame {
            ToBridge::Request { request, .. } => assert!(
                !matches!(*request, WorkerRequest::Fence(_)),
                "a degraded session asks the reader for no fence"
            ),
            ToBridge::FencePublished(publication) => assert!(
                !matches!(
                    publication,
                    kr_protocol::root::FencePublication::Published(_)
                ),
                "and publishes none"
            ),
            ToBridge::EventResult { .. } | ToBridge::LaunchRevoked { .. } => {}
        }
    }
    assert!(
        wired
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .fence()
            .is_none(),
        "and publishes no fence"
    );
    wired.close().await;
}

/// A-17: input a client's own request released reaches the terminal on that request's boundary.
///
/// The hold has a deadline, and every stimulus sweeps it. A request from a client can therefore be
/// what expires a hold, and the batches it releases are the application's from that moment: a
/// session that queued them and then waited for something else to come along would be holding
/// input nobody is holding it for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_expires_a_hold_delivers_what_it_released() {
    let wired = unpumped().await;
    // One client, which holds the keys and later asks for the launch: a launch belongs to the
    // attachment that holds the lease, and a second attachment taking the keys would discard what
    // the first one had handed over rather than release it.
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let holder = attached.attachment.attachment_id;
    client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::input::InputAcquireParams {
                session_id: wired.session_id,
                attachment_id: holder,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("takes the keys");

    let epoch = wired.runtime.session().lease().epoch.get();
    {
        // A reader enters, which starts an exchange nothing will answer: this session has no bridge.
        let mut session = wired.runtime.session();
        let driver = session.fence_mut().expect("a driver");
        let _ = driver.bridge_event(
            kr_protocol::ids::RequestId::new(2),
            &enter(wired.session_id, 1, 1),
        );
        session
            .write_input(holder, epoch, 0, b"held\n", None, std::time::Instant::now())
            .expect("accepted");
        assert_eq!(
            session.fence().expect("a driver").held().len(),
            1,
            "the exchange is in flight, so the batch waits"
        );
    }
    assert!(
        !contains(&retained(&wired.runtime.session()), b"held"),
        "and nothing has reached the terminal"
    );

    // The deadline passes with nothing else running. The next stimulus is this client's own launch,
    // which the machine refuses because no fence was ever published.
    wired.clock.advance(Duration::from_millis(400));
    let refused = client
        .mutate(
            Method::ShellLaunch,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::root::ShellLaunchParams {
                session_id: wired.session_id,
                command: kr_protocol::root::LaunchCommand::Arguments(vec!["ls".to_owned()]),
                expected_prompt_generation: PromptGeneration::new(1),
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("no fence is published, so nothing is installed");
    assert_eq!(refused.code, ErrorCode::EditorBusy, "{refused}");

    // What the machine let go of on that boundary is the application's, with nothing else running.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if contains(&retained(&wired.runtime.session()), b"held") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the released input never reached the terminal"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    wired.close().await;
}

/// A-17 again, on the interrupt's own boundary.
///
/// An interrupt is not held behind a reader transition, and the sweep it performs on the way can
/// let go of input that was. Those bytes are the application's from that moment: they reach it on
/// the interrupt's own boundary rather than waiting for whatever happens next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_delivers_what_its_own_sweep_released() {
    let wired = unpumped().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &terminal(wired.session_id),
        )
        .await
        .expect("reaches the worker")
        .expect("attaches")
        .to_typed()
        .expect("decodes");
    let holder = attached.attachment.attachment_id;
    client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::input::InputAcquireParams {
                session_id: wired.session_id,
                attachment_id: holder,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("takes the keys");

    let epoch = wired.runtime.session().lease().epoch.get();
    {
        let mut session = wired.runtime.session();
        let driver = session.fence_mut().expect("a driver");
        let _ = driver.bridge_event(
            kr_protocol::ids::RequestId::new(2),
            &enter(wired.session_id, 1, 1),
        );
        session
            .write_input(
                holder,
                epoch,
                0,
                b"waited\n",
                None,
                std::time::Instant::now(),
            )
            .expect("accepted");
    }
    assert!(!contains(&retained(&wired.runtime.session()), b"waited"));

    wired.clock.advance(Duration::from_millis(400));
    client
        .mutate(
            Method::InputInterrupt,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &kr_protocol::input::InputInterruptParams {
                session_id: wired.session_id,
                attachment_id: holder,
                epoch: kr_protocol::ids::InputLeaseEpoch::new(epoch),
                action: kr_protocol::input::InterruptAction::NativeInterrupt,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the holder interrupts at the epoch it holds");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if contains(&retained(&wired.runtime.session()), b"waited") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the interrupt kept what its own sweep released"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    wired.close().await;
}

/// KR-REQ-07.79: a retry happens at the reader's next idle callback, and waits for a drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withheld_fence_is_retried_at_the_next_idle_callback() {
    let mut wired = wired().await;
    let _holder = wired.holder();
    wired
        .bridge
        .send_event(enter(wired.session_id, 1, 1))
        .await
        .expect("enters");
    let asked = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(params) => break params,
                _ => continue,
            },
            _ => continue,
        }
    };
    // The reader answers with queues that are not clear. A retry never discards them.
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(FenceAcknowledgement {
                fence_id: asked.fence_id,
                prompt_generation: asked.prompt_generation,
                reader_revision: asked.reader_revision,
                reader_context: ReaderContext::Primary,
                queues: QueueDrainReport {
                    tty_typeahead_drained: false,
                    macro_input_drained: true,
                    partial_key_drained: true,
                },
                snapshot: KeyQueueSnapshot::drained(),
                editor: editor_state(true, 1),
                cwd_revision: CwdRevision::new(1),
            })),
        )
        .await
        .expect("acknowledges");
    let withheld = loop {
        match wired.next().await {
            ToBridge::FencePublished(publication) => break publication,
            _ => continue,
        }
    };
    assert!(
        matches!(
            withheld,
            kr_protocol::root::FencePublication::Withheld {
                reason: kr_protocol::root::WithheldReason::QueuesNotDrained,
                ..
            }
        ),
        "{withheld:?}"
    );
    // The reader goes idle: that is one of the three points a withheld fence is retried at.
    wired
        .bridge
        .send_event(idle(wired.session_id, 1, 1))
        .await
        .expect("idles");
    let retried = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(params) => break params,
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(retried.cause, kr_protocol::root::FenceCause::Retry);
    assert_ne!(retried.fence_id, asked.fence_id);
    let _ = EditorBusyReason::FenceExchangeTimedOut;
    let _ = InputRef::new("unused");
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.79, KR-REQ-07.82: what happens to a client's keystrokes while a fence is being made.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.79: the held input reaches the terminal in its original order, and the client is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_input_reaches_the_terminal_in_order_and_the_client_hears_why_it_waited() {
    let mut wired = wired().await;
    let holder = wired.holder();
    let mut events = {
        let mut session = wired.runtime.session();
        session.subscribe(holder).expect("subscribes")
    };
    // A reader starts and never answers the exchange, so everything typed is held.
    wired
        .bridge
        .send_event(enter(wired.session_id, 1, 1))
        .await
        .expect("enters");
    loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(_) => break,
                _ => continue,
            },
            _ => continue,
        }
    }
    let epoch = wired.runtime.session().lease().epoch.get();
    for (sequence, bytes) in [b"first\n".as_slice(), b"second\n".as_slice()]
        .into_iter()
        .enumerate()
    {
        let mut session = wired.runtime.session();
        session
            .write_input(
                holder,
                epoch,
                sequence as u64,
                bytes,
                None,
                std::time::Instant::now(),
            )
            .expect("accepted");
        assert_eq!(
            session.fence().expect("a driver").held().len(),
            sequence + 1,
            "each batch is held while the exchange is in flight"
        );
    }
    assert!(
        !contains(&retained(&wired.runtime.session()), b"first"),
        "nothing reaches the terminal while the exchange is in flight"
    );

    // The hold ends at its own deadline. The batches go to the terminal in the order they arrived,
    // which is what the program on the other end of it echoes back.
    let seen = tokio::time::timeout(SOON, async {
        loop {
            let seen = retained(&wired.runtime.session());
            if contains(&seen, b"first") && contains(&seen, b"second") {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the hold ended and both batches reached the terminal");
    let first = position(&seen, b"first").expect("the first batch");
    let second = position(&seen, b"second").expect("the second batch");
    assert!(
        first < second,
        "released in the order they arrived, not the order they were let go"
    );

    // And the client whose keystrokes waited is told why, on its own attachment event stream.
    let busy = tokio::time::timeout(SOON, async {
        loop {
            match events.recv().await {
                Some(kr_worker::output::OutputDelivery::EditorBusy(event)) => return Some(*event),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .expect("an attachment event")
    .expect("the stream stayed open");
    assert_eq!(busy.attachment_id, holder);
    assert_eq!(busy.reason, EditorBusyReason::FenceExchangeTimedOut);
    assert_eq!(busy.state, FenceState::Unfenced);
    assert_eq!(
        busy.released_input_bytes.get(),
        b"first\nsecond\n".len() as u64,
        "the event counts what went to the terminal"
    );
    assert_eq!(
        busy.input_epoch.get(),
        epoch,
        "the lease change stands: this is an event about the editor, not a failed acquire"
    );
    wired.close().await;
}

/// KR-REQ-07.78: a reader that never answers its cancellation leaves the receipt saying so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_never_answers_leaves_the_takeover_receipt_unknown() {
    let mut wired = wired().await;
    let _first = wired.holder();
    let _fence = fenced(&mut wired, 1, 1).await;
    let second = AttachmentId::new(kr_ipc::new_uuid());
    {
        let params = terminal(wired.session_id);
        let mut session = wired.runtime.session();
        session
            .attach(&params, params.requested.clone(), second)
            .expect("attaches");
        session
            .acquire_input(second, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the keys");
    }
    // The cancellation goes out and is never answered.
    loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Cancel(_) => break,
                _ => continue,
            },
            _ => continue,
        }
    }
    let receipt = tokio::time::timeout(SOON, async {
        loop {
            if let Some(receipt) = wired.runtime.session().last_takeover_receipt() {
                return receipt;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the receipt closed at the hold's deadline");
    assert_eq!(
        receipt.reader_discards,
        ReaderDiscards::Unknown,
        "nobody measured it, so the receipt says so rather than reporting a zero"
    );
    wired.close().await;
}

/// KR-REQ-07.83: a reader that answers after the revocation is believed, and the record kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_answered_after_its_revocation_is_reported_and_recorded() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    let target = wired.target();
    let session_id = wired.session_id;
    let prompt = fence.prompt_generation;

    let mut second = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    // The second connection has no attachment of its own, so it is refused before the machine sees
    // it: a launch belongs to the client that holds the keys on the connection that asked.
    let refused = second
        .mutate(
            Method::ShellLaunch,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &ShellLaunchParams {
                session_id,
                command: LaunchCommand::QuotedCommand("ls".to_owned()),
                expected_prompt_generation: prompt,
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::LeaseLost);

    // The holder's own launch is dispatched, times out, and is then answered by the reader.
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &ShellLaunchParams {
                    session_id,
                    command: LaunchCommand::QuotedCommand("ls".to_owned()),
                    expected_prompt_generation: prompt,
                    expected_buffer_revision: EditorBufferRevision::new(1),
                },
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    let revoked = loop {
        match wired.next().await {
            ToBridge::LaunchRevoked { transaction, .. } => break transaction,
            _ => continue,
        }
    };
    assert_eq!(revoked, request.transaction);
    // The reader answers after the revocation. The command is in the editor, so the caller is told
    // what happened rather than told it failed.
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Accepted(LaunchAccepted {
                transaction: request.transaction,
                installed: request.command.clone(),
                fence_id: request.fence_id,
                prompt_generation: prompt,
                buffer_revision: EditorBufferRevision::new(2),
                reader_revision: ReaderRevision::new(1),
            })),
        )
        .await
        .expect("installs");
    let result: ShellLaunchResult = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect("installed")
        .to_typed()
        .expect("a launch result");
    assert_eq!(result.buffer_revision, EditorBufferRevision::new(2));
    assert_eq!(
        wired.runtime.session().late_installations().len(),
        1,
        "the session records a command the reader installed after the transaction was revoked"
    );
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-12.03: a launch the foreground has moved past.
// --------------------------------------------------------------------------------------------

/// KR-REQ-12.03: a launch offered at the idle prompt is refused once an application has taken the
/// foreground, and it is never pasted into that application's input. The launch names the prompt
/// it was offered at. The person runs a command and the reader leaves the prompt for it, so the
/// launch is refused with the editor busy; once the application has ended and the shell prompts
/// again, the same launch is refused as a conflict. The reader is asked to install nothing, and
/// the terminal carries none of the command's bytes, while the keys the holder types reach it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_is_refused_once_an_application_takes_the_foreground_and_is_never_pasted() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let holder = holder_over(&mut client, &wired).await;
    let offered = fenced(&mut wired, 1, 1).await;
    let launch = ShellLaunchParams {
        session_id: wired.session_id,
        command: LaunchCommand::QuotedCommand("printf 'kala%s-launched\\n' reach".to_owned()),
        expected_prompt_generation: offered.prompt_generation,
        expected_buffer_revision: EditorBufferRevision::new(1),
    };

    // The person runs a command, and the application it starts has the terminal.
    wired
        .bridge
        .send_event(BridgeEvent::EditorLeave(RootEditorLeaveParams {
            session_id: wired.session_id,
            prompt_generation: offered.prompt_generation,
            reader_revision: ReaderRevision::new(1),
            reason: kr_protocol::root::EditorLeaveReason::CommandAccepted,
        }))
        .await
        .expect("leaves");
    let waited = tokio::time::Instant::now() + SOON;
    while wired.runtime.session().fence().expect("a driver").state() != FenceState::Outside {
        assert!(
            tokio::time::Instant::now() < waited,
            "the reader left the prompt"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let refused = client
        .mutate(
            Method::ShellLaunch,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &launch,
        )
        .await
        .expect("reaches the worker")
        .expect_err("a launch the foreground moved past is refused");
    assert_eq!(refused.code, ErrorCode::EditorBusy, "{refused:?}");
    type_keys(&wired, holder, 0, b"kr-typed-by-the-holder\n");
    echoed(&wired.runtime, b"kr-typed-by-the-holder").await;

    // The application ends and the shell prompts again, at a later prompt.
    let _ = fenced(&mut wired, 2, 1).await;
    let refused = client
        .mutate(
            Method::ShellLaunch,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &launch,
        )
        .await
        .expect("reaches the worker")
        .expect_err("a launch offered at an earlier prompt is refused");
    assert_eq!(refused.code, ErrorCode::DraftConflict, "{refused:?}");

    // The reader was asked to install nothing, and the terminal holds none of the command.
    while let Ok(Ok(frame)) =
        tokio::time::timeout(Duration::from_millis(400), wired.bridge.recv()).await
    {
        if let ToBridge::Request { request, .. } = frame {
            assert!(
                !matches!(*request, WorkerRequest::Launch(_)),
                "the reader was asked to install a launch the foreground moved past"
            );
        }
    }
    let seen = retained(&wired.runtime.session());
    assert!(contains(&seen, b"kr-typed-by-the-holder"));
    assert!(
        !contains(&seen, b"-launched") && !contains(&seen, b"printf"),
        "the launch reached the terminal: {}",
        String::from_utf8_lossy(&seen)
    );
    wired.close().await;
}

fn activation(session_id: SessionId, modules: Vec<LoadedModule>) -> BridgeEvent {
    BridgeEvent::HooksActivated(HooksActivated {
        session_id,
        prompt_generation: PromptGeneration::new(1),
        modules,
    })
}

/// KR-REQ-07.87: a session whose shell holds modules that bind qualifies, and the create that is
/// waiting on it is answered.
#[tokio::test]
async fn a_shell_holding_modules_that_bind_qualifies_and_the_create_is_answered() {
    let mut wired = wired_with(ShellMode::Managed, false).await;
    wired
        .bridge
        .send_event(activation(
            wired.session_id,
            vec![LoadedModule {
                name: "kr_user".to_owned(),
                path: "/home/person/modules/kr_user.so".to_owned(),
                imports: ModuleImports::Bound,
            }],
        ))
        .await
        .expect("reports");
    wired
        .runtime
        .await_qualification(Duration::from_secs(10))
        .await
        .expect("the create is answered");
    wired.close().await;
}

/// KR-REQ-07.87, KR-REQ-07.88: a module the editor cannot bind ends the create with the named
/// error, never a ready state, and the session it was creating is closed.
#[tokio::test]
async fn a_module_the_editor_cannot_bind_ends_the_create_with_the_named_error() {
    let mut wired = wired_with(ShellMode::Managed, false).await;
    wired
        .bridge
        .send_event(activation(
            wired.session_id,
            vec![LoadedModule {
                name: "kr_user".to_owned(),
                path: "/home/person/modules/kr_user.so".to_owned(),
                imports: ModuleImports::Missing("zle_abi_newer_entry".to_owned()),
            }],
        ))
        .await
        .expect("reports");
    let error = wired
        .runtime
        .await_qualification(Duration::from_secs(10))
        .await
        .expect_err("a session with a module that cannot bind is not answered ready");
    assert_eq!(error.code, ErrorCode::ShellIntegrationUnsupported);
    assert_eq!(
        error.message,
        "module_tree_unsupported: module kr_user imports zle_abi_newer_entry, which neither this \
         reader (zle-5.9) nor anything else the shell holds provides; rebuild the module for this \
         reader, stop loading it in KalaReach sessions, or create the session with --shell-mode \
         native_compat; where a name is missing, load the module that provides it before this one"
    );
    // The session that was being created is closed, and it was never ready.
    tokio::time::timeout(Duration::from_secs(30), wired.runtime.wait_closed())
        .await
        .expect("the session closes");
    assert_eq!(
        wired.runtime.state(),
        kr_protocol::session::SessionState::Closed
    );
    {
        let session = wired.runtime.session();
        assert!(!session.fence().expect("a driver").phase().reports_ready());
    }
    // The answer survives the closure: asking again names the same refusal.
    let again = wired
        .runtime
        .await_qualification(Duration::from_secs(1))
        .await
        .expect_err("still refused");
    assert_eq!(again.message, error.message);
    wired.close().await;
}

/// A session that has been qualified and then closed is no answer to a create that asks afterwards.
#[tokio::test]
async fn a_session_that_closed_after_it_qualified_is_not_answered_ready() {
    let mut wired = wired_with(ShellMode::Managed, false).await;
    wired
        .bridge
        .send_event(activation(wired.session_id, Vec::new()))
        .await
        .expect("reports");
    wired
        .runtime
        .await_qualification(Duration::from_secs(10))
        .await
        .expect("the create is answered while the session is live");
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
    tokio::time::timeout(Duration::from_secs(30), wired.runtime.wait_closed())
        .await
        .expect("the session closes");
    let error = wired
        .runtime
        .await_qualification(Duration::from_secs(1))
        .await
        .expect_err("a closed session is not ready");
    assert_eq!(error.code, ErrorCode::ShellIntegrationUnsupported);
    assert_eq!(
        error.message,
        "the session ended before the create was answered"
    );
    wired.close().await;
}

/// A shell refused for what it cannot do, and gone by the time the worker answers, still ends the
/// create with the named error: the reason is kept before the answer is written, so a write that
/// fails loses nothing. The shell hangs up before the worker serves, so the answer cannot be
/// written and nothing here depends on timing. Linux, where the peer of a closed connection is
/// still known.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_refused_at_the_handshake_that_has_gone_still_ends_the_create_by_name() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let config = configuration(&temp, ShellMode::Managed);
    let session_id = config.session_id;
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(InputLeaseEpoch::new(0)),
        Arc::new(SystemContinuousClock::new()),
    ));
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    // The shell, built against another editor, says hello and goes.
    let declared = ReferenceShell::new(ShellKind::Zsh, "/bin/cat", "5.9", "zle-5.8");
    let hello = qualified_hello(&declared, session_id, &address, process.clone(), &secret)
        .expect("a hello");
    ScriptedBridge::hello_and_hang_up(&address, &hello)
        .await
        .expect("the hello is written");

    let expectation = WorkerExpectation {
        session_id,
        root_process: process,
        supported_editor_abis: vec!["zle-5.9".to_owned()],
        supported_integration_versions: vec!["1".to_owned()],
        launched_package: None,
        already_registered: false,
        gesture: EofGesture::default(),
    };
    let bridge_task = tokio::spawn(
        kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            host_endpoint,
            expectation,
        )
        .serve(),
    );

    let error = runtime
        .await_qualification(Duration::from_secs(10))
        .await
        .expect_err("a shell built against another editor is not qualified");
    assert_eq!(error.code, ErrorCode::ShellIntegrationUnsupported);
    assert!(
        error.message.starts_with(
            "editor_abi_unsupported: editor ABI zle-5.8 is not one this build was qualified against"
        ),
        "{}",
        error.message
    );
    runtime.close(ClosureReason::CloseRequested).1.release();
    let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
    bridge_task.abort();
}

/// A hello refused for what the shell cannot do reaches the create as the named error at once,
/// where it used to wait out its bound and say the integration did not qualify.
#[tokio::test]
async fn a_shell_refused_at_the_handshake_ends_the_create_with_the_named_error() {
    let wired = wired_built(
        ShellMode::Managed,
        false,
        Bridging {
            hello_abi: "zle-5.8",
            ..Bridging::ordinary()
        },
        |_| {},
    )
    .await;
    let error = wired
        .runtime
        .await_qualification(Duration::from_secs(10))
        .await
        .expect_err("a shell built against another editor is not qualified");
    assert_eq!(error.code, ErrorCode::ShellIntegrationUnsupported);
    assert!(
        error.message.starts_with(
            "editor_abi_unsupported: editor ABI zle-5.8 is not one this build was qualified against"
        ),
        "{}",
        error.message
    );
    wired.close().await;
}

// --------------------------------------------------------------------------------------------
// KR-REQ-08.49: the host's answers to the application, and what they do to the reader.
// --------------------------------------------------------------------------------------------

/// KR-REQ-08.49: an answer leaves the response lane carrying the lane's own deadline.
///
/// The writer is the last boundary before the application, and an answer can wait in the queue for
/// the terminal behind an application that has stopped reading. What the writer drops an answer
/// against is the deadline the lane gave it when it was offered, two seconds on the lane's clock,
/// which is what this reads from the batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_leaves_the_lane_with_the_lanes_deadline() {
    let temp = kr_ipc::testing::TempHost::create();
    let config = configuration(&temp, ShellMode::NativeCompat);
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let before = kr_ipc::now_ms().get();
    // The terminal's own question about what it is talking to, which the host answers itself.
    session.ingest_output(b"\x1b[c");
    let after = kr_ipc::now_ms().get();
    let replies: Vec<_> = session
        .take_pending_input()
        .into_iter()
        .filter_map(|batch| match batch {
            kr_worker::session::InputBatch::Reply {
                bytes,
                expires_at_ms,
            } => Some((bytes, expires_at_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(replies.len(), 1, "the host answers the question once");
    let (bytes, expires_at_ms) = &replies[0];
    assert_eq!(bytes.as_slice(), b"\x1b[?62;22c");
    let expires = expires_at_ms.expect("the answer carries the lane's deadline");
    assert!(
        (before + 2_000..=after + 2_000).contains(&expires),
        "the deadline is two seconds after the answer was offered: {before}..{after} and {expires}"
    );
}

/// Queues the host's own answer to the application for the terminal, as the response lane does
/// when the program in the terminal asks what it is talking to.
fn the_host_answers_the_application(wired: &Wired) {
    let mut session = wired.runtime.session();
    session.ingest_output(b"\x1b[c");
    wired.runtime.flush_locked(&mut session);
}

/// KR-REQ-08.49: an answer the host queues for the terminal after the reader proved its queues
/// clear invalidates the fence, and a launch cannot be reserved on it until the reader has said
/// again, from its own snapshot, that it is clear.
///
/// The mechanism is `FenceDriver::host_reply_queued`, which tells the machine of every byte the
/// host puts into the terminal that no person typed. The driver had been told of a person's input
/// only, and an answer is never held behind an exchange because it holds no lease, so it could reach
/// the reader behind a published fence without the fence noticing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_queued_after_the_fence_invalidates_it_until_the_reader_proves_its_queues_again()
{
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;

    the_host_answers_the_application(&wired);
    let (invalidated, why) = loop {
        match wired.next().await {
            ToBridge::FencePublished(kr_protocol::root::FencePublication::Invalidated {
                fence_id,
                reason,
                ..
            }) => break (fence_id, reason),
            _ => continue,
        }
    };
    assert_eq!(
        invalidated, fence.fence_id,
        "the fence the bridge held is the one named"
    );
    assert_eq!(
        why,
        kr_protocol::root::WithheldReason::QueuesNotDrained,
        "the reader's queues are no longer known to be clear"
    );
    {
        let session = wired.runtime.session();
        let driver = session.fence().expect("a driver");
        assert_eq!(driver.state(), FenceState::Unfenced);
        assert!(driver.fence().is_none());
        assert_eq!(
            driver.host_reply_bytes(),
            b"\x1b[?62;22c".len() as u64,
            "every byte the host queued for the terminal is accounted for"
        );
    }

    // A launch asked for now has no fence to be reserved on.
    let refused = client
        .mutate(
            Method::ShellLaunch,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &ShellLaunchParams {
                session_id: wired.session_id,
                command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
                expected_prompt_generation: fence.prompt_generation,
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::EditorBusy, "{refused}");

    // The reader idles, which is where a withheld fence is asked for again, and its own snapshot
    // is what accounts for the bytes it was sent. A launch reserved on that fence is not refused.
    wired
        .bridge
        .send_event(idle(wired.session_id, 1, 1))
        .await
        .expect("idles");
    let second = asked_for_a_fence(&mut wired).await;
    wired
        .bridge
        .answer(kr_protocol::ids::RequestId::new(0), drained(1, 1, second))
        .await
        .expect("acknowledges");
    until_fenced(&wired.runtime).await;
    let target = wired.target();
    let session_id = wired.session_id;
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &ShellLaunchParams {
                    session_id,
                    command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
                    expected_prompt_generation: PromptGeneration::new(1),
                    expected_buffer_revision: EditorBufferRevision::new(1),
                },
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(
        wired.runtime.session().fence().expect("a driver").state(),
        FenceState::LaunchReserved,
        "the launch was reserved on the fence the reader proved again"
    );
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Accepted(LaunchAccepted {
                transaction: request.transaction,
                installed: request.command.clone(),
                fence_id: request.fence_id,
                prompt_generation: PromptGeneration::new(1),
                buffer_revision: EditorBufferRevision::new(2),
                reader_revision: ReaderRevision::new(1),
            })),
        )
        .await
        .expect("installs");
    let _ = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered");
    wired.close().await;
}

/// The control for the case above: output that asks nothing is answered with nothing, and the fence
/// stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn output_the_host_has_no_answer_for_leaves_the_fence_standing() {
    let mut wired = wired().await;
    let _holder = wired.holder();
    let fence = fenced(&mut wired, 1, 1).await;
    {
        let mut session = wired.runtime.session();
        session.ingest_output(b"plain output\r\n");
        wired.runtime.flush_locked(&mut session);
    }
    let session = wired.runtime.session();
    let driver = session.fence().expect("a driver");
    assert_eq!(driver.state(), FenceState::Fenced);
    assert_eq!(
        driver.fence().map(|held| held.fence_id),
        Some(fence.fence_id),
        "nothing was sent to the reader, so nothing it proved is in question"
    );
    assert_eq!(driver.host_reply_bytes(), 0);
    drop(session);
    wired.close().await;
}

/// KR-REQ-08.49: a launch reserved before the host's answer is revoked as queued prior input, and
/// the caller is refused as the editor being busy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_reserved_before_the_hosts_answer_is_revoked_and_refused() {
    let mut wired = wired().await;
    let mut client = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let _holder = holder_over(&mut client, &wired).await;
    let fence = fenced(&mut wired, 1, 1).await;
    let target = wired.target();
    let session_id = wired.session_id;
    let prompt = fence.prompt_generation;
    let calling = tokio::spawn(async move {
        client
            .mutate(
                Method::ShellLaunch,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &ShellLaunchParams {
                    session_id,
                    command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
                    expected_prompt_generation: prompt,
                    expected_buffer_revision: EditorBufferRevision::new(1),
                },
            )
            .await
    });
    let request = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Launch(request) => break request,
                _ => continue,
            },
            _ => continue,
        }
    };
    assert_eq!(
        wired.runtime.session().fence().expect("a driver").state(),
        FenceState::LaunchReserved
    );

    the_host_answers_the_application(&wired);
    let (transaction, reason) = loop {
        match wired.next().await {
            ToBridge::LaunchRevoked {
                transaction,
                reason,
            } => break (transaction, reason),
            _ => continue,
        }
    };
    assert_eq!(transaction, request.transaction);
    assert_eq!(
        reason,
        LaunchRejectionReason::QueuedPriorInput,
        "the reader's queue holds bytes the launch was not reserved against"
    );
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            BridgeAnswer::Launch(LaunchDecision::Rejected(LaunchRejection {
                transaction: request.transaction,
                reason: LaunchRejectionReason::QueuedPriorInput,
                fence_id: request.fence_id,
                prompt_generation: prompt,
                buffer_revision: EditorBufferRevision::new(1),
            })),
        )
        .await
        .expect("answers");
    let refused = tokio::time::timeout(SOON, calling)
        .await
        .expect("the caller was answered")
        .expect("joins")
        .expect("reaches the worker")
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::EditorBusy, "{refused}");
    wired.close().await;
}

/// KR-REQ-08.49: an answer queued while the exchange is in flight withholds the fence the reader's
/// acknowledgement would have published, and the next exchange, from the reader's own snapshot,
/// publishes one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_queued_during_the_exchange_withholds_the_fence_until_the_next_one() {
    let mut wired = wired().await;
    let _holder = wired.holder();
    wired
        .bridge
        .send_event(enter(wired.session_id, 1, 1))
        .await
        .expect("enters");
    let first = asked_for_a_fence(&mut wired).await;
    the_host_answers_the_application(&wired);
    wired
        .bridge
        .answer(kr_protocol::ids::RequestId::new(0), drained(1, 1, first))
        .await
        .expect("acknowledges");
    let withheld = loop {
        match wired.next().await {
            ToBridge::FencePublished(publication) => break publication,
            _ => continue,
        }
    };
    assert!(
        matches!(
            withheld,
            kr_protocol::root::FencePublication::Withheld {
                reason: kr_protocol::root::WithheldReason::QueuesNotDrained,
                ..
            }
        ),
        "an acknowledgement the answer overlapped proves nothing about it: {withheld:?}"
    );
    assert_eq!(
        wired.runtime.session().fence().expect("a driver").state(),
        FenceState::Unfenced
    );

    wired
        .bridge
        .send_event(idle(wired.session_id, 1, 1))
        .await
        .expect("idles");
    let second = asked_for_a_fence(&mut wired).await;
    wired
        .bridge
        .answer(kr_protocol::ids::RequestId::new(0), drained(1, 1, second))
        .await
        .expect("acknowledges");
    until_fenced(&wired.runtime).await;
    wired.close().await;
}

/// KR-REQ-08.49: with a real qualified reader at its prompt, the host's answer to the application
/// invalidates the fence the reader proved, and the reader proves it again from its own snapshot.
///
/// The mechanism is `FenceDriver::host_reply_queued`, which tells the fence machine of every byte
/// the host queues for the terminal that no person typed. The answer goes into the terminal the
/// real shell is reading, so what the reader's next snapshot accounts for is real input.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the built shell packages that KR_SHELL_PACKAGES names; it runs with --ignored in a run that has built them, as the build box's verification does"]
async fn a_real_readers_fence_is_invalidated_by_the_hosts_answer_and_proven_again() {
    for kind in [ShellKind::Zsh, ShellKind::Bash] {
        let package = installed_package_of(kind);
        let shell = RealShell::start(
            &package,
            kr_protocol::session::LaunchProfile::default(),
            Vec::new(),
            None,
        )
        .await;
        // Taking the keys is what starts an exchange, and the real reader answers it.
        let _keys = shell.keys();
        until_fenced(&shell.runtime).await;
        let proved = shell
            .runtime
            .session()
            .fence()
            .expect("a driver")
            .fence()
            .map(|fence| fence.fence_id)
            .expect("the reader proved a fence");

        {
            let mut session = shell.runtime.session();
            session.ingest_output(b"\x1b[c");
            shell.runtime.flush_locked(&mut session);
            let driver = session.fence().expect("a driver");
            assert!(
                driver.fence().is_none(),
                "{kind:?}: the answer reached the reader's terminal behind the fence it proved"
            );
            assert_eq!(driver.host_reply_bytes(), b"\x1b[?62;22c".len() as u64);
        }
        // The reader consumes what it was sent and idles, which is where the exchange is asked for
        // again, and it answers from its own snapshot.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                {
                    let session = shell.runtime.session();
                    let driver = session.fence().expect("a driver");
                    if driver.state() == FenceState::Fenced
                        && driver.fence().map(|fence| fence.fence_id) != Some(proved)
                    {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{kind:?}: the reader never proved its queues again"));
        shell.close().await;
    }
}
