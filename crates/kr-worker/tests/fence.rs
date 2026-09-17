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
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
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
use kr_shell_integration::host::scripted::{
    ReferenceShell, ScriptedBridge, ToBridge, qualified_hello,
};
use kr_transport::clock::SystemContinuousClock;
use kr_worker::fence::{FenceDriver, ReaderDiscards};
use kr_worker::pty::ShellCommand;
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
        shell: ShellCommand {
            // A program that reads its input and says nothing, so what the session retains is what
            // the host wrote rather than what a prompt drew.
            program: "/bin/cat".to_owned(),
            arguments: Vec::new(),
            cwd: "/".to_owned(),
            environment: vec![("TERM".to_owned(), "xterm-256color".to_owned())],
        },
        shell_mode: mode,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
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

/// Starts a managed session with its bridge registered.
async fn wired() -> Wired {
    wired_with(ShellMode::Managed, true).await
}

async fn wired_with(mode: ShellMode, register: bool) -> Wired {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let config = configuration(&temp, mode);
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
    let store = kr_crypto::store::open_store("KalaReachFence", &environment.secrets_dir())
        .expect("a secret store");
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");

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
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts the runtime"));

    let expectation = WorkerExpectation {
        session_id,
        // The reference bridge runs in this process, so this process is the root shell the worker
        // expects on its endpoint.
        root_process: process.clone(),
        supported_editor_abis: vec!["zle-5.9".to_owned()],
        supported_integration_versions: vec!["1".to_owned()],
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
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
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
    let session = wired.runtime.session();
    let registration = session
        .root_integration()
        .expect("the handshake was recorded")
        .clone();
    drop(session);
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
    let session = wired.runtime.session();
    let driver = session.fence().expect("a driver");
    assert_eq!(
        driver.state(),
        FenceState::Unfenced,
        "the editor stays unfenced"
    );
    assert!(driver.held().is_empty(), "nothing is still held");
    drop(session);
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

// --------------------------------------------------------------------------------------------
// KR-REQ-07.32, KR-REQ-07.33, KR-REQ-07.83, KR-REQ-23.38, KR-REQ-23.54: the launch transaction.
// --------------------------------------------------------------------------------------------

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
    {
        let mut session = wired.runtime.session();
        let effects = session
            .fence_mut()
            .expect("a driver")
            .integration_lost(IntegrationLoss::BridgeDisconnected);
        drop(session);
        let _ = wired.runtime.apply_fence_effects(effects);
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
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts"));
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
    let effects = {
        let mut session = wired.runtime.session();
        session
            .fence_mut()
            .expect("a driver")
            .integration_lost(IntegrationLoss::PostStartupFailure)
    };
    assert_eq!(
        effects.close_session,
        Some(IntegrationLoss::PostStartupFailure)
    );
    let _ = wired.runtime.apply_fence_effects(effects);
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
    let effects = {
        let mut session = wired.runtime.session();
        session
            .fence_mut()
            .expect("a driver")
            .integration_lost(IntegrationLoss::SemanticHookLoss)
    };
    assert_eq!(
        effects.close_session, None,
        "a live session is not closed by it"
    );
    let _ = wired.runtime.apply_fence_effects(effects);
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
    drop(session);
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
