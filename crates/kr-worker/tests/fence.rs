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
use kr_shell_integration::contract::events::{BridgeEvent, EofGesture, HooksActivated, ReaderIdle};
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
        assert!(driver.registered(ShellKind::Zsh));
        let _ = driver.bridge_event(
            kr_protocol::ids::RequestId::new(1),
            &BridgeEvent::HooksActivated(HooksActivated {
                session_id,
                prompt_generation: PromptGeneration::new(1),
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
    wired_built(mode, register, move |config| {
        config.launch_profile = launch_profile.clone();
    })
    .await
}

async fn wired_built(
    mode: ShellMode,
    register: bool,
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
            Arc::new(SystemContinuousClock::new()),
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
    let bridge_task = tokio::spawn(
        kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            host_endpoint,
            expectation,
        )
        .serve(),
    );

    let hello =
        qualified_hello(&reference(), session_id, &address, process, &secret).expect("a hello");
    let (mut bridge, outcome) =
        tokio::time::timeout(SOON, ScriptedBridge::connect(&address, &hello))
            .await
            .expect("the worker accepted a connection")
            .expect("connects");
    assert!(
        matches!(outcome, HandshakeOutcome::Accepted(_)),
        "a qualified root shell registers: {outcome:?}"
    );
    if register {
        // The user's startup files have run and the integration's own hooks are live. Until this
        // the session is authenticated but not qualified, and it holds no fence.
        bridge
            .send_event(BridgeEvent::HooksActivated(HooksActivated {
                session_id,
                prompt_generation: PromptGeneration::new(1),
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
    let fence_id = loop {
        match wired.next().await {
            ToBridge::Request { request, .. } => match *request {
                WorkerRequest::Fence(params) => break params.fence_id,
                // A cancellation the entry asked for is not the exchange; it is answered by
                // whichever test needs it.
                _ => continue,
            },
            _ => continue,
        }
    };
    wired
        .bridge
        .answer(
            kr_protocol::ids::RequestId::new(0),
            drained(prompt, revision, fence_id),
        )
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

/// A-17: asking whether the desktop has gone costs no conversation with the platform.
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

/// A-17: held input reaches the writer at its own deadline while a desktop reading is outstanding.
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
    wired_built(ShellMode::Managed, true, |config| {
        // Desktop-bound, so its watch wants a reading of its own rather than reporting none.
        config.worker_profile = WorkerProfile::DesktopBound;
    })
    .await
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
    async fn start(
        package: &kr_shell_integration::host::package::ShellPackage,
        launch_profile: kr_protocol::session::LaunchProfile,
        extra: Vec<(String, String)>,
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
            format!("HISTFILE=\nKR_TEST_USER_CONFIGURATION=1\n\n{entry}"),
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
        let bridge_task = tokio::spawn(
            kr_worker::fence::bridge::BridgeServer::new(
                Arc::clone(&runtime),
                host_endpoint,
                expectation,
            )
            .serve(),
        );

        // The package connects to the endpoint it was given, proves itself over the bootstrap
        // secret and is registered; then its own entry reports that the hooks are live after the
        // startup files, which is what qualifies the session.
        let qualified = tokio::time::timeout(Duration::from_secs(30), async {
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
        });
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
    for kind in [ShellKind::Zsh, ShellKind::Bash] {
        let package = set
            .select(Some(kind.as_str()))
            .unwrap_or_else(|fault| panic!("{PACKAGE_ROOT_VARIABLE} has no {kind:?}: {fault}"))
            .clone();
        asks_the_real_worker_before_each_command(&package).await;
    }
}

/// What [`a_real_package_asks_the_real_worker_before_each_command_and_runs_a_bypass_as_typed`]
/// asks of one package.
#[cfg(unix)]
async fn asks_the_real_worker_before_each_command(
    package: &kr_shell_integration::host::package::ShellPackage,
) {
    for (integrations, bypass) in [
        (Vec::new(), "bypass not_integrated"),
        (
            vec![kr_protocol::session::CommandIntegration {
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
        // finishing are typeahead, which the worker cannot attribute to anyone. Even at the
        // prompt, the publication travels on the bridge's socket and the keys on the terminal, and
        // nothing orders the two, so a line typed as the fence is published can still be accepted
        // ahead of it. What the worker recorded for the line says which happened: a line it
        // recorded as fenced must carry its capability, and one accepted ahead of the fence is let
        // finish and typed again at the next prompt, a bounded number of times.
        const ATTEMPTS: usize = 5;
        let mut previous = sourced;
        let mut attempt = 0;
        let token = loop {
            attempt += 1;
            back_at_the_prompt(&shell, &probes, &previous).await;
            probes.hold();
            let before = probes.runs().len();
            keys.type_line(&shell, "kr-probe hold");
            let token = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let runs = probes.runs();
                    if runs.len() > before
                        && let Some((arguments, environment)) = runs.last()
                        && arguments.first().map(String::as_str) == Some("hold")
                    {
                        return environment.get("KR_DETACH_TOKEN").cloned();
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the held command started ({:?}, {bypass}, attempt {attempt}): {}",
                    package.kind(),
                    probes.trace()
                )
            });
            let fenced = shell
                .runtime
                .session()
                .fence()
                .expect("a driver")
                .detach_target()
                == DetachTarget::Attachment(keys.attachment_id);
            match token {
                Some(token) => break token,
                None if !fenced && attempt < ATTEMPTS => {
                    eprintln!(
                        "the {:?} package's held line was accepted ahead of its fence on attempt \
                         {attempt}, so it is typed again at the next prompt",
                        package.kind()
                    );
                    probes.release();
                    printed += 1;
                    shell.produced(b"probe-ran", printed).await;
                    previous = "kr-probe hold".to_owned();
                }
                None => panic!(
                    "the {:?} package started the command with its line's capability ({bypass}, \
                     attempt {attempt}, the line {} through the fence): {}",
                    package.kind(),
                    if fenced { "went" } else { "did not go" },
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
                    command: "codex".to_owned(),
                    flags: vec!["--kr-gateway".to_owned()],
                    enabled: true,
                },
                kr_protocol::session::CommandIntegration {
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
