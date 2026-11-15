//! The worker's input lane, over a real endpoint with a real session behind it.
//!
//! A lane is a second link of one attachment: the control daemon's own connection, declared as an
//! input proxy, which carries that attachment's typing to the worker as forwarded `input.write`
//! requests and carries the worker's window, credit and answers back. Every case here is a host
//! that does what the daemon does, frame by frame, and reads what the worker puts on the lane.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::BoundLink;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentViewportParams, SessionAttachParams,
    SessionAttachResult, SessionDetachParams, SessionDetachResult,
};
use kr_protocol::envelope::{
    ActionTarget, ControlEvent, ControlFrame, Outcome, ParamsValue, Request,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActorId, AttachmentId, AuthorityRevision, BuildId, ConnectionId,
    ControllerGeneration, DeviceId, GrantId, InputLeaseEpoch, InputSequence, RequestId,
    SessionEpoch, SessionId,
};
use kr_protocol::input::{
    InputAcquireParams, InputAcquireResult, InputBarrier, InputContent, InputLeaseResult,
    InputReleaseParams, InputWriteParams, input_claim,
};
use kr_protocol::local::{
    ControllerConnectionRole, ForwardedRequest, InputLane, InputLaneReady, LaneCredit, LaneLaunch,
    LaneWindow,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, FenceAcknowledgement,
    KeyQueueSnapshot, LaunchCommand, PendingReaderInput, PromptGeneration, QueueDrainReport,
    ReaderContext, ReaderRevision, RootEditorEnterParams, RootEditorFenceResult,
    RootEofDetachParams, ShellLaunchParams,
};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable, U64};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::{AuthorityRevisionNotice, RevisionReach};
use kr_shell_integration::contract::events::{BridgeEvent, HooksActivated};
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::requests::{BridgeAnswer, WorkerRequest};
use kr_worker::fence::{Outbound, Step};
use kr_worker::input_room::Cost;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

/// How long a case waits for something it waits for by condition, and fails after. Nothing is
/// decided by it.
const WAIT: Duration = Duration::from_secs(60);

/// How long a case lets a refused frame go on after it was let go, before it reads what the
/// application received. A frame that was wrongly accepted is queued in the same hold that accepts
/// it and reaches the application in far less.
const SETTLE: Duration = Duration::from_millis(500);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// What the lane's host reads from the worker, with the answers told from the events.
#[derive(Debug)]
enum Seen {
    Answer(RequestId, Outcome),
    Window(LaneWindow),
    Credit(LaneCredit),
    Launch(LaneLaunch),
}

/// The control daemon's side of one input lane.
struct Lane {
    link: BoundLink,
    attachment: AttachmentId,
    session_id: SessionId,
    actor: ActorEnvelope,
    ready: InputLaneReady,
    epoch: InputLeaseEpoch,
    sequence: u64,
    requests: u64,
    /// Credit that arrived while the case was reading something else.
    credits: Vec<LaneCredit>,
}

impl Lane {
    /// Reads the worker's answer to the bind, which is the lane's first frame, and takes the
    /// lane's epoch from it.
    async fn read_ready(&mut self) {
        let ready = match tokio::time::timeout(WAIT, self.link.recv())
            .await
            .expect("the worker answers the bind")
        {
            Ok(ControlFrame::InputLaneReady(ready)) => ready,
            other => panic!("the lane was not bound: {other:?}"),
        };
        self.epoch = ready.epoch;
        self.ready = ready;
    }

    /// Writes one frame of the lane's attachment, in the epoch and the sequence it is at.
    async fn send(&mut self, bytes: &[u8]) -> RequestId {
        self.send_with(bytes, Nullable::null()).await
    }

    /// Writes one frame admitted under an authority that ends at `deadline`, on the machine's
    /// continuous clock in milliseconds.
    async fn send_before(&mut self, bytes: &[u8], deadline: u64) -> RequestId {
        self.send_with(bytes, Nullable::some(U64::new(deadline)))
            .await
    }

    async fn send_with(&mut self, bytes: &[u8], deadline: Nullable<U64>) -> RequestId {
        self.requests += 1;
        let id = RequestId::new(1_000 + self.requests);
        let params = InputWriteParams {
            session_id: self.session_id,
            attachment_id: self.attachment,
            epoch: self.epoch,
            sequence: InputSequence::new(self.sequence),
            input: InputContent::Bytes {
                bytes: Bytes::new(bytes.to_vec()),
            },
        };
        self.sequence += 1;
        self.link
            .send(&ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
                request: Request {
                    request_id: id,
                    method: Method::InputWrite.into(),
                    method_version: MethodVersion::V1,
                    params: ParamsValue::from_typed(&params).expect("encodes"),
                },
                actor: self.actor.clone(),
                authority_deadline_boot_ms: deadline,
                history: None,
            })))
            .await
            .expect("the frame is written");
        id
    }

    /// Writes `count` frames that name an attachment the lane does not carry, each of which the
    /// worker refuses and answers on the lane, and reads nothing. Stops at the first frame the link
    /// does not take, and returns how many it wrote.
    async fn flood(&mut self, count: usize) -> usize {
        for sent in 0..count {
            self.requests += 1;
            let params = InputWriteParams {
                session_id: self.session_id,
                attachment_id: AttachmentId::new(kr_ipc::new_uuid()),
                epoch: self.epoch,
                sequence: InputSequence::new(0),
                input: InputContent::Bytes {
                    bytes: Bytes::new(b"x".to_vec()),
                },
            };
            let frame = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
                request: Request {
                    request_id: RequestId::new(1_000 + self.requests),
                    method: Method::InputWrite.into(),
                    method_version: MethodVersion::V1,
                    params: ParamsValue::from_typed(&params).expect("encodes"),
                },
                actor: self.actor.clone(),
                authority_deadline_boot_ms: Nullable::null(),
                history: None,
            }));
            if self.link.send(&frame).await.is_err() {
                return sent;
            }
        }
        count
    }

    /// Reads the next thing the worker wrote on the lane, or none when the link has ended.
    async fn next(&mut self) -> Option<Seen> {
        let received = tokio::time::timeout(WAIT, self.link.recv())
            .await
            .expect("the worker wrote on the lane in time");
        match received.ok()? {
            ControlFrame::Response(response) => {
                Some(Seen::Answer(response.request_id, response.outcome))
            }
            ControlFrame::Event(ControlEvent::InputWindow(window)) => Some(Seen::Window(window)),
            ControlFrame::Event(ControlEvent::InputCredit(credit)) => Some(Seen::Credit(credit)),
            ControlFrame::Event(ControlEvent::InputLaunchReserved(launch)) => {
                Some(Seen::Launch(launch))
            }
            other => panic!("the lane carried {other:?}"),
        }
    }

    /// Reads one answer, which has to be an acceptance, and returns the request it answers.
    async fn accepted(&mut self) -> RequestId {
        match self.next_event().await {
            Some(Seen::Answer(id, Outcome::Ok(_))) => id,
            other => panic!("expected an accepted frame, read {other:?}"),
        }
    }

    /// Reads the next answer or window state, keeping the credit that comes before it: credit is
    /// given back as the writer finishes with frames, so it arrives between other things.
    async fn next_event(&mut self) -> Option<Seen> {
        loop {
            match self.next().await? {
                Seen::Credit(credit) => self.credits.push(credit),
                other => return Some(other),
            }
        }
    }

    /// Starts the lane at the window the worker gave for `epoch`.
    fn at(&mut self, epoch: InputLeaseEpoch) {
        self.epoch = epoch;
        self.sequence = 0;
    }

    /// Reads until credit for `epoch` adds up to `frames` and `bytes`, and returns everything else
    /// that came on the way. Credit past those sums is a fault.
    async fn credit_until(&mut self, epoch: InputLeaseEpoch, frames: u32, bytes: u64) -> Vec<Seen> {
        let (mut got_frames, mut got_bytes) = (0_u32, 0_u64);
        let mut others = Vec::new();
        let mut earlier = std::mem::take(&mut self.credits);
        while got_frames < frames || got_bytes < bytes {
            let seen = match earlier.pop() {
                Some(credit) => Seen::Credit(credit),
                None => self.next().await.expect("the lane stays open"),
            };
            match seen {
                Seen::Credit(credit) => {
                    assert_eq!(
                        credit.epoch, epoch,
                        "credit is for the epoch that was spent"
                    );
                    got_frames += credit.frames;
                    got_bytes += credit.bytes.get();
                }
                other => others.push(other),
            }
        }
        assert_eq!(
            (got_frames, got_bytes),
            (frames, bytes),
            "the credit given back is what the frames claimed, and no more"
        );
        others
    }
}

/// Waits until `condition` holds, which the case says by `what` when it does not within `bound`.
/// The bound decides nothing but how long a case that is wrong takes to say so.
async fn until(what: &str, bound: Duration, mut condition: impl FnMut() -> bool) {
    if tokio::time::timeout(bound, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_err()
    {
        panic!("{what}: not so after {bound:?}");
    }
}

/// The error code an answer refused with.
fn refusal(outcome: &Outcome) -> Option<ErrorCode> {
    match outcome {
        Outcome::Error(error) => Some(error.code),
        Outcome::Ok(_) => None,
    }
}

/// A worker with a session whose application keeps what it receives, the control daemon's proxy
/// link to it, and the identities that the daemon speaks for.
struct Rig {
    _temp: kr_ipc::testing::TempHost,
    _kept: tempfile::TempDir,
    received: std::path::PathBuf,
    /// The pipe that an application which waits to read its terminal is let go through.
    go: std::path::PathBuf,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    proxy: Option<BoundLink>,
    proxy_connection: ConnectionId,
    grant: GrantId,
    device: DeviceId,
}

impl Rig {
    async fn start() -> Self {
        Self::start_with(None).await
    }

    /// A rig whose worker ends the link of a closed lane queue after `close_bound`, where one is
    /// given, rather than after the five seconds of the shipped worker.
    async fn start_with(close_bound: Option<Duration>) -> Self {
        Self::start_built(close_bound, false, false).await
    }

    /// A rig whose session is a managed shell with the root editor's fence machine, its bridge
    /// registered and its hooks live, and no reader in an editor yet: input is accepted as it is
    /// outside an editor, and a launch asked of it is refused by the machine at once.
    async fn start_fenced() -> Self {
        Self::start_built(None, true, false).await
    }

    /// A rig whose application does not read its terminal until [`Self::let_the_application_read`]:
    /// what the worker writes to it waits in the terminal, which holds only a little.
    async fn start_unreading() -> Self {
        Self::start_built(None, false, true).await
    }

    /// A rig whose application keeps what it reads with the suite's own program and not with the
    /// system's `tee` ([`common::KEEPS_WHAT_IT_READS`] says why), for a case that writes a great
    /// deal to it at once.
    async fn start_keeping() -> Self {
        Self::start_reading_with(common::KEEPS_WHAT_IT_READS, None, false, false).await
    }

    async fn start_built(close_bound: Option<Duration>, fenced: bool, waits: bool) -> Self {
        Self::start_reading_with("tee", close_bound, fenced, waits).await
    }

    /// Starts the rig with `reader` as the program that keeps what the application receives in
    /// the file it is given.
    async fn start_reading_with(
        reader: &str,
        close_bound: Option<Duration>,
        fenced: bool,
        waits: bool,
    ) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let kept = tempfile::tempdir().expect("a directory for what the application keeps");
        let received = kept.path().join("received");
        let go = kept.path().join("go");
        let wait = if waits {
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&go)
                    .status()
                    .expect("mkfifo runs")
                    .success(),
                "the pipe for the application was made"
            );
            format!("read go < {}; ", kr_worker::testing::shell_quoted(&go))
        } else {
            String::new()
        };
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script(&format!(
                "stty raw -echo; printf '\\033[?2004hkr-ready.'; {wait}exec {reader} {}",
                kr_worker::testing::shell_quoted(&received)
            )),
            shell_mode: if fenced {
                ShellMode::Managed
            } else {
                ShellMode::NativeCompat
            },
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
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
        let store =
            kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
        let controller = Arc::new(
            ControllerIdentity::initialise(store.store.as_ref(), environment_id)
                .expect("a controller identity"),
        );
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        if fenced {
            session.install_fence(kr_worker::fence::FenceDriver::new(
                session_id,
                kr_shell_integration::contract::fence::LeaseView::unheld(InputLeaseEpoch::new(0)),
                Arc::new(kr_transport::clock::ManualClock::new()),
            ));
            // Registered and qualified without a bridge: the phases are the driver's own, and a
            // launch asked of the session reaches the machine.
            let mut driver = session.fence_mut().expect("a driver");
            assert!(driver.registered(ShellKind::Zsh, "zle-5.9"));
            let _ = driver.bridge_event(
                RequestId::new(1),
                &BridgeEvent::HooksActivated(HooksActivated {
                    session_id,
                    prompt_generation: PromptGeneration::new(1),
                    modules: Vec::new(),
                }),
            );
            assert!(driver.phase().reports_ready());
        }
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let service = WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service");
        let service = Arc::new(match close_bound {
            Some(bound) => service.with_lane_close_bound(bound),
            None => service,
        });
        tokio::spawn(Arc::clone(&service).serve(listener));
        common::produced(&runtime, b"kr-ready.").await;
        let mut rig = Self {
            _temp: temp,
            _kept: kept,
            received,
            go,
            service,
            runtime,
            session_id,
            environment_id,
            endpoint,
            controller,
            boot,
            proxy: None,
            proxy_connection: ConnectionId::new(kr_ipc::new_uuid()),
            grant: GrantId::new(kr_ipc::new_uuid()),
            device: DeviceId::new(kr_ipc::new_uuid()),
        };
        let proxy = rig.connect(1, Some(ControllerConnectionRole::Proxy)).await;
        rig.proxy_connection = proxy.acknowledgement().connection_id;
        rig.proxy = Some(proxy);
        // What the daemon does before it forwards a device's mutation: the worker acknowledges the
        // revision, over the authority connection.
        common::announced_over_a_link_of_its_own(
            &rig.endpoint,
            &rig.controller,
            &rig.boot,
            rig.environment_id,
            1,
            1,
        )
        .await;
        rig
    }

    /// A connection of the control daemon's of `generation`, declaring `role` first when it has
    /// one.
    async fn connect(&self, generation: u64, role: Option<ControllerConnectionRole>) -> BoundLink {
        let mut client = BoundLink::connect(&self.endpoint, build())
            .await
            .expect("connects");
        if let Some(role) = role {
            client
                .send(&ControlFrame::ControllerRole(role))
                .await
                .expect("declares the role");
            match client.recv().await.expect("the worker answers") {
                ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
                other => panic!("the worker answered {other:?}"),
            }
        }
        let identity = Arc::clone(&self.controller);
        let boot = self.boot.clone();
        client
            .present_generation(move |nonce| {
                identity
                    .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await
            .expect("the worker accepts the generation");
        client
    }

    fn proxy(&mut self) -> &mut BoundLink {
        self.proxy.as_mut().expect("the proxy link is open")
    }

    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// The device and grant the daemon speaks for, validated at `revision`.
    fn actor(&self, revision: u64) -> ActorEnvelope {
        ActorEnvelope {
            actor_id: ActorId::new("device:phone").expect("an actor"),
            ingress: ActorIngress::PairedDevice,
            device_id: Nullable::some(self.device),
            grant_id: Nullable::some(self.grant),
            grant_revision: Nullable::some(AuthorityRevision::new(revision)),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16])),
        }
    }

    fn rights() -> CanonicalSet<kr_protocol::rights::ActionRight> {
        [
            kr_protocol::rights::ActionRight::SessionView,
            kr_protocol::rights::ActionRight::TerminalInput,
        ]
        .into_iter()
        .collect()
    }

    /// The mutation `method`, as the daemon forwards it for the device at `revision`.
    async fn forward_at<T: serde::Serialize>(
        &mut self,
        method: Method,
        params: &T,
        revision: u64,
    ) -> Result<ParamsValue, ProtocolError> {
        let target = self.target();
        let actor = self.actor(revision);
        let proxy = self.proxy();
        let mutation = proxy
            .compose(method, ActionId::new(kr_ipc::new_uuid()), target, params)
            .await
            .expect("the mutation is composed");
        let deadline = U64::new(kr_ipc::clock::boot_elapsed_ms() + 120_000);
        let lease = Some(common::a_lease(1, revision));
        if method == Method::SessionAttach {
            return proxy
                .forward_within(
                    &mutation,
                    &actor,
                    &Self::rights(),
                    deadline,
                    lease,
                    common::a_scope_with_the_live_screen(),
                )
                .await
                .expect("reaches the worker");
        }
        proxy
            .forward(&mutation, &actor, &Self::rights(), deadline, lease)
            .await
            .expect("reaches the worker")
    }

    /// Asks for a launch that names a position and does not wait for the answer, which comes when
    /// the reader decides. The proxy link goes with the call and comes back with the answer, so
    /// the rig makes no other request in the meantime.
    fn launching(
        &mut self,
        after: Option<InputBarrier>,
    ) -> tokio::task::JoinHandle<(BoundLink, Result<ParamsValue, ProtocolError>)> {
        let params = self.launch_params(after);
        let target = self.target();
        let actor = self.actor(1);
        let mut proxy = self.proxy.take().expect("the proxy link is open");
        tokio::spawn(async move {
            let mutation = proxy
                .compose(
                    Method::ShellLaunch,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &params,
                )
                .await
                .expect("the mutation is composed");
            let deadline = U64::new(kr_ipc::clock::boot_elapsed_ms() + 120_000);
            let outcome = proxy
                .forward(
                    &mutation,
                    &actor,
                    &Self::rights(),
                    deadline,
                    Some(common::a_lease(1, 1)),
                )
                .await
                .expect("reaches the worker");
            (proxy, outcome)
        })
    }

    /// The editor state the reader reports at an empty prompt.
    fn an_empty_prompt() -> EditorState {
        EditorState {
            buffer_empty: true,
            buffer_revision: EditorBufferRevision::new(1),
            keymap: EditorKeymap::Emacs,
            pending: PendingReaderInput::NONE,
        }
    }

    /// Has the reader of the root editor enter an empty prompt, as the shell's bridge reports it,
    /// and returns the fence that the worker asks it for. Until the reader answers the fence, the
    /// machine holds the keys that the session accepts.
    fn reader_enters(&self) -> kr_protocol::root::FenceId {
        let session_id = self.session_id;
        let editor = Self::an_empty_prompt();
        let mut asked = None;
        self.runtime
            .session()
            .stimulate_fence(|driver| {
                let effects = driver.bridge_event(
                    RequestId::new(2),
                    &BridgeEvent::EditorEnter(RootEditorEnterParams {
                        session_id,
                        root_process: kr_ipc::identity::current_process_start_identity()
                            .expect("this process"),
                        prompt_generation: PromptGeneration::new(1),
                        reader_revision: ReaderRevision::new(1),
                        reader_context: ReaderContext::Primary,
                        editor,
                        cwd_revision: CwdRevision::new(1),
                    }),
                );
                asked = effects.steps.iter().find_map(|step| match step {
                    Step::Send(Outbound::Request(request)) => match request.as_ref() {
                        WorkerRequest::Fence(params) => Some(params.fence_id),
                        _ => None,
                    },
                    _ => None,
                });
                effects
            })
            .expect("the session has a fence machine");
        asked.expect("the reader was asked for a fence")
    }

    /// Puts the reader of the root editor at an empty prompt behind an acknowledged fence, so that
    /// a launch asked of the session is reserved, and returns the fence.
    fn at_a_prompt(&self) -> kr_protocol::root::FenceId {
        let fence_id = self.reader_enters();
        let editor = Self::an_empty_prompt();
        self.runtime
            .session()
            .stimulate_fence(|driver| {
                driver.bridge_answer(&BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(
                    FenceAcknowledgement {
                        fence_id,
                        reader_context: ReaderContext::Primary,
                        prompt_generation: PromptGeneration::new(1),
                        reader_revision: ReaderRevision::new(1),
                        queues: QueueDrainReport::CLEAR,
                        snapshot: KeyQueueSnapshot::drained(),
                        editor,
                        cwd_revision: CwdRevision::new(1),
                    },
                )))
            })
            .expect("the session has a fence machine");
        fence_id
    }

    /// Attaches a terminal that may type.
    async fn attach(&mut self) -> AttachmentId {
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
        let attached: SessionAttachResult = self
            .forward_at(Method::SessionAttach, &params, 1)
            .await
            .expect("the device attaches")
            .to_typed()
            .expect("an attachment");
        attached.attachment.attachment_id
    }

    /// Takes the keys for `attachment`, from whoever holds them.
    async fn acquire(&mut self, attachment: AttachmentId) -> InputLeaseEpoch {
        self.acquire_result(attachment).await.lease.epoch
    }

    /// Takes the keys for `attachment`, from whoever holds them, and returns the whole answer.
    async fn acquire_result(&mut self, attachment: AttachmentId) -> InputAcquireResult {
        let params = InputAcquireParams {
            session_id: self.session_id,
            attachment_id: attachment,
            expected_epoch: Nullable::null(),
        };
        self.forward_at(Method::InputAcquire, &params, 1)
            .await
            .expect("the device takes the keys")
            .to_typed()
            .expect("a lease")
    }

    /// Sends the bind of a lane that names `proxy_connection` and `attachment`, and returns the
    /// link it was sent on.
    async fn ask_for_a_lane(
        &self,
        generation: u64,
        proxy_connection: ConnectionId,
        attachment: AttachmentId,
    ) -> BoundLink {
        let mut link = self
            .connect(generation, Some(ControllerConnectionRole::ProxyInput))
            .await;
        link.send(&ControlFrame::InputLane(InputLane {
            proxy_connection,
            attachment_id: attachment,
        }))
        .await
        .expect("asks for the lane");
        link
    }

    /// Opens the lane of `attachment` under the proxy link, and reads the worker's answer.
    async fn lane(&self, attachment: AttachmentId) -> Lane {
        let link = self
            .ask_for_a_lane(1, self.proxy_connection, attachment)
            .await;
        let mut lane = self.lane_over(link, attachment, None);
        lane.read_ready().await;
        lane
    }

    /// The lane of `attachment` over a link that has been asked for it. Its ready frame is known
    /// when the case has read it, and `epoch` stands for it until then.
    fn lane_over(
        &self,
        link: BoundLink,
        attachment: AttachmentId,
        epoch: Option<InputLeaseEpoch>,
    ) -> Lane {
        let epoch = epoch.unwrap_or_else(|| InputLeaseEpoch::new(0));
        Lane {
            link,
            attachment,
            session_id: self.session_id,
            actor: self.actor(1),
            epoch,
            sequence: 0,
            requests: 0,
            credits: Vec::new(),
            ready: InputLaneReady {
                epoch,
                holder: false,
                frames: 0,
                bytes: U64::new(0),
            },
        }
    }

    /// Releases the keys as the daemon forwards a release that names a position.
    async fn release_with(
        &mut self,
        attachment: AttachmentId,
        epoch: InputLeaseEpoch,
        after: Option<InputBarrier>,
        report: bool,
    ) -> Result<InputLeaseResult, ProtocolError> {
        let params = InputReleaseParams {
            session_id: self.session_id,
            attachment_id: attachment,
            epoch,
            after_input: after,
            fenced_report: report,
        };
        self.forward_at(Method::InputRelease, &params, 1)
            .await
            .map(|answer| answer.to_typed().expect("a lease result"))
    }

    /// Detaches as the daemon forwards a detach that names a position.
    async fn detach_with(
        &mut self,
        attachment: AttachmentId,
        after: Option<InputBarrier>,
        report: bool,
    ) -> Result<SessionDetachResult, ProtocolError> {
        let params = SessionDetachParams {
            attachment_id: Nullable::some(attachment),
            line_token: Nullable::null(),
            after_input: after,
            fenced_report: report,
        };
        self.forward_at(Method::SessionDetach, &params, 1)
            .await
            .map(|answer| answer.to_typed().expect("a detach result"))
    }

    /// The launch of the cases, which names the position `after` when it is given.
    fn launch_params(&self, after: Option<InputBarrier>) -> ShellLaunchParams {
        ShellLaunchParams {
            session_id: self.session_id,
            command: LaunchCommand::QuotedCommand("true".to_owned()),
            expected_prompt_generation: PromptGeneration::new(1),
            expected_buffer_revision: EditorBufferRevision::new(1),
            after_input: after,
        }
    }

    /// Asks for a launch that names a position, as the daemon forwards it.
    async fn launch_with(
        &mut self,
        after: Option<InputBarrier>,
    ) -> Result<ParamsValue, ProtocolError> {
        let params = self.launch_params(after);
        self.forward_at(Method::ShellLaunch, &params, 1).await
    }

    /// Lets an application that waits to read its terminal go on.
    async fn let_the_application_read(&self) {
        let go = self.go.clone();
        tokio::task::spawn_blocking(move || std::fs::write(go, b"go\n"))
            .await
            .expect("the write ran")
            .expect("the application was let go");
    }

    /// What the application has received so far.
    fn received(&self) -> Vec<u8> {
        std::fs::read(&self.received).unwrap_or_default()
    }

    /// Waits until the application has received exactly `expected`.
    async fn received_exactly(&self, expected: &[u8]) {
        tokio::time::timeout(WAIT, async {
            while self.received() != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the application received {} bytes, not the {} expected; {}",
                self.received().len(),
                expected.len(),
                self.what_became_of_the_application()
            )
        });
    }

    /// What tells a worker that stopped writing from an application that stopped keeping what it
    /// read, for a failure that finds the application's file short: the total the writer recorded
    /// as written to the terminal, whether the writer found the terminal gone, the end of the
    /// session's retained output, where an error of the application shows, the application's
    /// state and exit, and the free space of the directory its file is in.
    fn what_became_of_the_application(&self) -> String {
        let writes = self.runtime.input().terminal_writes();
        let written: usize = writes.iter().map(|write| write.bytes.len()).sum();
        let gone = self
            .runtime
            .input()
            .lock()
            .terminal_gone_latch()
            .load(std::sync::atomic::Ordering::Acquire);
        let retained = common::retained(&self.runtime);
        let end =
            String::from_utf8_lossy(&retained[retained.len().saturating_sub(400)..]).into_owned();
        let exit = {
            let session = self.runtime.session();
            format!("{:?}, closure {:?}", session.state(), session.closure())
        };
        #[cfg(unix)]
        let free = rustix::fs::statvfs(self._kept.path()).map_or_else(
            |error| format!("not read: {error}"),
            |stat| format!("{} bytes", stat.f_bavail.saturating_mul(stat.f_frsize)),
        );
        #[cfg(not(unix))]
        let free = String::from("not read on this platform");
        format!(
            "the writer recorded {written} bytes in {} writes to the terminal; the terminal was \
             {}; the retained output ends {end:?}; the application's state is {exit}; the free \
             space of the directory its file is in is {free}",
            writes.len(),
            if gone { "found gone" } else { "not found gone" },
        )
    }

    /// Waits until the worker holds nothing for the terminal.
    async fn drained(&self) {
        tokio::time::timeout(WAIT, async {
            while self.runtime.input().lock().ledger().held != Cost::default() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the worker's writer was done with everything it held");
    }

    async fn finish(self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
    }
}

/// The byte of the `index`-th key of a run, so that order is told from the bytes.
fn letter(index: usize) -> u8 {
    b'a' + u8::try_from(index % 26).expect("a letter")
}

/// KR-REQ-23.36: a host that sends exactly the window's credit and waits is never refused. The
/// writer is held while it does; once the writer reads, the credit for the same epoch comes back
/// and the host sends the rest. Every frame is accepted once, in order, and the epoch never ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_spends_its_credit_and_waits_is_never_refused_and_the_epoch_never_ends() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    assert!(lane.ready.holder, "the lane's attachment holds the keys");
    assert_eq!(
        (lane.ready.frames, lane.ready.bytes.get()),
        (64, 512 * 1024)
    );
    let (_stopped, release) = rig.runtime.input().writer_hold().arm();

    // A one-byte frame claims two entries and seven bytes: the window is thirty-two of them.
    let each = input_claim(1);
    let first = 64 / each.frames;
    let mut typed = Vec::new();
    let mut sent = Vec::new();
    for index in 0..first {
        typed.push(letter(index));
        sent.push(lane.send(&[letter(index)]).await);
    }
    for id in &sent {
        assert_eq!(
            lane.accepted().await,
            *id,
            "answers come in the order of the frames"
        );
    }

    release.send(()).expect("lets the writer go");
    let spent = u64::try_from(first * each.bytes).expect("a count");
    let others = lane.credit_until(epoch, 64, spent).await;
    assert!(others.is_empty(), "nothing but credit came: {others:?}");

    // The host sends the rest, which the credit paid for.
    let mut sent = Vec::new();
    for index in first..2 * first {
        typed.push(letter(index));
        sent.push(lane.send(&[letter(index)]).await);
    }
    for id in &sent {
        assert_eq!(lane.accepted().await, *id);
    }
    rig.received_exactly(&typed).await;
    let others = lane.credit_until(epoch, 64, spent).await;
    assert!(others.is_empty(), "the epoch never ended: {others:?}");
    rig.finish().await;
}

/// KR-REQ-23.36: a frame beyond the credit the worker gave is a breach. The lane ends, the frame
/// is not written, and the attachment keeps the keys: ending a lane detaches nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_beyond_the_credit_closes_the_lane_and_is_never_written() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let (_stopped, release) = rig.runtime.input().writer_hold().arm();
    let first = 64 / input_claim(1).frames;
    let mut typed = Vec::new();
    for index in 0..first {
        typed.push(letter(index));
        lane.send(&[letter(index)]).await;
    }
    for _ in 0..first {
        lane.accepted().await;
    }
    // The window is spent and nothing has been given back: one frame more is beyond the credit.
    let beyond = lane.send(b"!").await;
    // The host is told why its link ends: the refusal of the frame, with its reason, comes first
    // and the close behind it.
    match lane.next_event().await {
        Some(Seen::Answer(answered, Outcome::Error(error))) => {
            assert_eq!(answered, beyond);
            assert_eq!(error.code, ErrorCode::ResourceUnavailable);
            assert!(
                error.message.contains("lane credit breach"),
                "the refusal says why: {}",
                error.message
            );
        }
        other => panic!("the link ended without the refusal of the breach: {other:?}"),
    }
    assert!(
        lane.next_event().await.is_none(),
        "the link closes behind the refusal"
    );
    release.send(()).expect("lets the writer go");
    rig.drained().await;
    rig.received_exactly(&typed).await;
    assert!(
        rig.runtime.session().lease().holder.is_present(),
        "the lane's end detached nothing"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: a frame is charged what the worker holds for it, which is not what it carries:
/// eight frames of 60,000 bytes give back eight times `input_claim(60000)`, and not eight times
/// 60,000.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_frame_is_charged_its_claim_and_the_credit_given_back_is_the_same() {
    let mut rig = Rig::start_keeping().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let claim = input_claim(60_000);
    assert_eq!(
        claim.bytes,
        60_000 + 6,
        "the claim adds the end of a paste delimiter"
    );
    let count = lane.ready.bytes.get() / u64::try_from(claim.bytes).expect("a count");
    assert_eq!(count, 8);
    let count = usize::try_from(count).expect("a count");
    for _ in 0..count {
        lane.send(&[b'q'; 60_000]).await;
    }
    for _ in 0..count {
        lane.accepted().await;
    }
    let frames = u32::try_from(count * claim.frames).expect("a count");
    let bytes = u64::try_from(count * claim.bytes).expect("a count");
    let others = lane.credit_until(epoch, frames, bytes).await;
    assert!(others.is_empty(), "{others:?}");
    rig.received_exactly(&vec![b'q'; count * 60_000]).await;
    rig.finish().await;
}

/// KR-REQ-23.36: a takeover with the whole window in flight. The worker tells the lane that the
/// epoch ended, after the answers of that epoch; every later frame of that epoch is refused with a
/// lost lease; no credit is owed for it; and when the same view takes the keys again its window is
/// whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_with_the_credit_in_flight_refuses_every_frame_and_the_next_window_is_whole() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let (_stopped, release) = rig.runtime.input().writer_hold().arm();
    let first = 64 / input_claim(1).frames;
    for index in 0..first {
        lane.send(&[letter(index)]).await;
    }
    for _ in 0..first {
        lane.accepted().await;
    }

    let taken = rig.acquire(other).await;
    assert_ne!(taken, epoch);
    let ended = match lane.next().await {
        Some(Seen::Window(window)) => window,
        other => panic!("expected the notice that the epoch ended, read {other:?}"),
    };
    assert!(!ended.holder);
    assert_eq!(
        ended
            .ended
            .0
            .expect("the notice says which epoch ended")
            .epoch,
        epoch
    );

    // Frames of the epoch that ended, sent after it: refused, each.
    for _ in 0..2 {
        let id = lane.send(b"x").await;
        match lane.next().await {
            Some(Seen::Answer(answered, outcome)) => {
                assert_eq!(answered, id);
                assert_eq!(refusal(&outcome), Some(ErrorCode::LeaseLost));
            }
            other => panic!("expected a refusal, read {other:?}"),
        }
    }

    // The stale entries are written or dropped, and the same view takes the keys again.
    release.send(()).expect("lets the writer go");
    rig.drained().await;
    let again = rig.acquire(attachment).await;
    let window = match lane.next().await.expect("the lane stays open") {
        Seen::Window(window) => window,
        Seen::Credit(credit) => panic!("credit was owed for an epoch that ended: {credit:?}"),
        Seen::Launch(launch) => panic!("a launch marker with no launch: {launch:?}"),
        Seen::Answer(..) => panic!("an answer with nothing sent"),
    };
    assert!(window.holder && window.ended.0.is_none());
    assert_eq!(window.epoch, again);
    assert_eq!((window.frames, window.bytes.get()), (64, 512 * 1024));
    rig.finish().await;
}

/// KR-REQ-23.36: the notice that an epoch ended never reaches the host before an answer of that
/// epoch, seen on the socket. A host streams single keys on the credit it is given while another
/// view takes the keys in the middle of the stream, and reads what the worker writes: every
/// acceptance comes before the notice, and every answer after it is a refusal. Each round runs the
/// takeover somewhere else in the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ended_notice_follows_every_answer_of_its_epoch_on_the_wire() {
    const ROUNDS: usize = 20;
    const FRAMES: usize = 600;
    const TAKEOVER_AFTER: usize = 40;

    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let claim = input_claim(1);
    let mut room = (
        usize::try_from(lane.ready.frames).expect("a count"),
        usize::try_from(lane.ready.bytes.get()).expect("a count"),
    );
    for round in 0..ROUNDS {
        let (trigger, triggered) = tokio::sync::oneshot::channel::<()>();
        let mut trigger = Some(trigger);
        let host = async {
            let mut sent = 0_usize;
            let mut waiting = std::collections::VecDeque::new();
            let mut answered = 0_usize;
            let mut ended = false;
            while !(ended && waiting.is_empty()) {
                while !ended && sent < FRAMES && room.0 >= claim.frames && room.1 >= claim.bytes {
                    room = (room.0 - claim.frames, room.1 - claim.bytes);
                    waiting.push_back(lane.send(&[letter(sent)]).await);
                    sent += 1;
                }
                match lane.next().await.expect("the lane stays open") {
                    Seen::Answer(id, outcome) => {
                        assert_eq!(waiting.pop_front(), Some(id), "answers keep their order");
                        answered += 1;
                        if ended {
                            assert_eq!(
                                refusal(&outcome),
                                Some(ErrorCode::LeaseLost),
                                "round {round}: an answer after the notice that the epoch ended \
                                 was an acceptance"
                            );
                        }
                        if answered == TAKEOVER_AFTER
                            && let Some(trigger) = trigger.take()
                        {
                            let _ = trigger.send(());
                        }
                    }
                    Seen::Credit(credit) => {
                        if credit.epoch == lane.epoch {
                            room.0 += usize::try_from(credit.frames).expect("a count");
                            room.1 += usize::try_from(credit.bytes.get()).expect("a count");
                        }
                    }
                    Seen::Window(window) => {
                        assert!(!window.holder, "round {round}: a window of a new epoch");
                        ended = true;
                        if let Some(trigger) = trigger.take() {
                            let _ = trigger.send(());
                        }
                    }
                    Seen::Launch(launch) => panic!("a launch marker with no launch: {launch:?}"),
                }
            }
        };
        let takeover = async {
            let _ = triggered.await;
            rig.acquire(other).await
        };
        let ((), _) = tokio::join!(host, takeover);

        // The same view takes the keys again for the next round, with the window that the worker
        // gives for the new epoch.
        let again = rig.acquire(attachment).await;
        let window = loop {
            match lane.next().await.expect("the lane stays open") {
                Seen::Window(window) if window.holder => break window,
                Seen::Window(_) | Seen::Credit(_) | Seen::Launch(_) => {}
                Seen::Answer(..) => panic!("an answer with nothing waiting"),
            }
        };
        assert_eq!(window.epoch, again);
        lane.at(again);
        room = (
            usize::try_from(window.frames).expect("a count"),
            usize::try_from(window.bytes.get()).expect("a count"),
        );
    }
    rig.finish().await;
}

/// KR-REQ-23.36: a lane that names an attachment its parent does not own, or a parent that is not a
/// live proxy connection of its generation, is closed with no frame written: the host reads the
/// close as the refusal. A lane bound under a replaced generation ends with that generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lane_that_names_what_its_parent_does_not_own_is_closed_and_a_replaced_generation_ends_it()
 {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;

    // An attachment that the parent does not own.
    let mut stranger = rig
        .ask_for_a_lane(
            1,
            rig.proxy_connection,
            AttachmentId::new(kr_ipc::new_uuid()),
        )
        .await;
    assert!(
        tokio::time::timeout(WAIT, stranger.recv())
            .await
            .expect("the worker acts")
            .is_err(),
        "a lane for an attachment its parent does not own was bound"
    );

    // A parent that is no connection of the worker's at all.
    let mut nobody = rig
        .ask_for_a_lane(1, ConnectionId::new(kr_ipc::new_uuid()), attachment)
        .await;
    assert!(
        tokio::time::timeout(WAIT, nobody.recv())
            .await
            .expect("the worker acts")
            .is_err(),
        "a lane for a parent that does not exist was bound"
    );

    // A parent that is a live connection of the generation but not a proxy that owns the
    // attachment: the lane's own sibling.
    let sibling = rig
        .connect(1, Some(ControllerConnectionRole::ProxyInput))
        .await;
    let mut under_a_lane = rig
        .ask_for_a_lane(1, sibling.acknowledgement().connection_id, attachment)
        .await;
    assert!(
        tokio::time::timeout(WAIT, under_a_lane.recv())
            .await
            .expect("the worker acts")
            .is_err(),
        "a lane for a parent that is not a proxy was bound"
    );

    // A good lane, then a replacement generation: the lane ends with the generation, and a lane
    // that names the old generation's proxy under the new one is refused.
    let mut lane = rig.lane(attachment).await;
    let _second = rig.connect(2, None).await;
    while lane.next().await.is_some() {}
    let mut stale = rig
        .ask_for_a_lane(2, rig.proxy_connection, attachment)
        .await;
    assert!(
        tokio::time::timeout(WAIT, stale.recv())
            .await
            .expect("the worker acts")
            .is_err(),
        "a lane was bound under a proxy of another generation"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: closing a lane detaches nothing. The attachment keeps the keys, the proxy link
/// keeps its attachment, and a second lane for it binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_a_lane_detaches_nothing_and_a_second_lane_binds() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let lane = rig.lane(attachment).await;
    drop(lane);
    tokio::time::timeout(WAIT, async {
        while rig.runtime.input().lock().lane_count() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the worker noticed that the lane's link ended");
    assert!(rig.runtime.session().lease().holder.is_present());
    let again = rig.lane(attachment).await;
    assert!(again.ready.holder);
    assert_eq!(again.ready.epoch, epoch, "the lease did not move");
    rig.finish().await;
}

/// Waits for the end that the pause reports a frame has reached it on.
async fn arrived(at: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || at.recv_timeout(WAIT))
        .await
        .expect("the wait ran")
        .expect("the frame reached the pause");
}

/// A frame of a lane that has passed everything the connection checks and has not yet taken the
/// input domain, while the lane's parent withdraws by `how`. The withdrawal's first step has run
/// and its detach waits for the session, which a thread of the case holds: the frame is let go
/// between the two, so that only that first step can refuse it. It is refused and never written.
///
/// Every wait of the case is inside the bound of `within`, which fails it with the step it stood at:
/// a worker that does not take the first step leaves the window where it was and the case waiting
/// for it.
async fn a_frame_at_the_seam_when_the_parent_goes(how: Withdrawal, stage: Stage) {
    stage.at("the lane to bind");
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    assert_eq!(lane.epoch, epoch);
    let (at, release) = rig.service.pause_input_before_the_session();
    lane.send(b"seam-frame").await;
    stage.at("the frame to reach the pause before the session");
    arrived(at).await;

    // A thread of the case holds the session, as a commit does, until the case lets it go.
    stage.at("a thread of the case to take the session");
    let (held, holding) = std::sync::mpsc::channel::<()>();
    let (let_go, letting_go) = std::sync::mpsc::channel::<()>();
    let commit = {
        let runtime = Arc::clone(&rig.runtime);
        std::thread::spawn(move || {
            let _commit = runtime.session();
            held.send(()).expect("says it holds the session");
            let _ = letting_go.recv();
        })
    };
    tokio::task::spawn_blocking(move || holding.recv_timeout(WAIT))
        .await
        .expect("the wait ran")
        .expect("the session was taken");
    assert_ne!(
        rig.runtime.input().lock().ledger().reserved,
        Cost::default(),
        "the lane has its window before the parent goes"
    );

    // The first step of the parent's withdrawal takes the input domain alone, which nothing holds,
    // and ends the window; everything after it waits for the session.
    if matches!(how, Withdrawal::ItsLinkEnds) {
        rig.proxy = None;
    }
    let steps = async {
        stage.at("the first step of the parent's withdrawal to end the lane's window");
        until(
            "the first step of the withdrawal ended the lane's window",
            WAIT,
            || rig.runtime.input().lock().ledger().reserved == Cost::default(),
        )
        .await;
        stage.at("the held frame to be refused and the lane to end");
        release.send(()).expect("lets the frame go");
        while let Some(seen) = lane.next().await {
            if let Seen::Answer(_, outcome) = seen {
                assert!(refusal(&outcome).is_some(), "the held frame was accepted");
            }
        }
        // A frame that was wrongly accepted is queued in the hold that accepts it, and the writer
        // has it in far less than this.
        tokio::time::sleep(SETTLE).await;
        let_go.send(()).expect("lets the session go");
    };
    match how {
        Withdrawal::ItsLinkEnds => steps.await,
        Withdrawal::AReplacementGeneration => {
            // The generation's handshake waits for the withdrawals it makes.
            let ((), _second) = tokio::join!(steps, rig.connect(2, None));
        }
    }
    stage.at("the thread that held the session to end, and the terminal's writer to drain");
    commit.join().expect("the thread ended");
    rig.drained().await;
    assert!(
        !String::from_utf8_lossy(&rig.received()).contains("seam-frame"),
        "a frame held while its parent withdrew reached the application"
    );
    rig.finish().await;
}

/// How long a seam case is given in all, which decides nothing but how long a worker that fails it
/// takes to say so: the case itself takes about a second.
const SEAM_BOUND: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum Withdrawal {
    ItsLinkEnds,
    AReplacementGeneration,
}

/// KR-REQ-23.36: the connection's clean-up path.
#[test]
fn a_frame_held_before_the_domain_is_refused_when_the_parents_link_ends() {
    within(
        SEAM_BOUND,
        "a frame held before the domain was not refused when its parent's link ended",
        |stage| a_frame_at_the_seam_when_the_parent_goes(Withdrawal::ItsLinkEnds, stage),
    );
}

/// KR-REQ-23.36: the generation fence's withdrawal.
#[test]
fn a_frame_held_before_the_domain_is_refused_when_a_replacement_generation_withdraws_the_parent() {
    within(
        SEAM_BOUND,
        "a frame held before the domain was not refused when a replacement generation withdrew its parent",
        |stage| a_frame_at_the_seam_when_the_parent_goes(Withdrawal::AReplacementGeneration, stage),
    );
}

/// KR-PERF-002: credit reaches the host while a commit holds the session. The writer's give-back
/// asks for the top-up, and the task that makes it takes the input domain alone, so a lane's
/// frames are paid for while something else has the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credit_arrives_while_a_commit_holds_the_session() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    // A thread of the case holds the session, as a commit does, until the case lets it go.
    let (held, holding) = std::sync::mpsc::channel::<()>();
    let (let_go, letting_go) = std::sync::mpsc::channel::<()>();
    let commit = {
        let runtime = Arc::clone(&rig.runtime);
        std::thread::spawn(move || {
            let _commit = runtime.session();
            held.send(()).expect("says it holds the session");
            let _ = letting_go.recv();
        })
    };
    tokio::task::spawn_blocking(move || holding.recv_timeout(WAIT))
        .await
        .expect("the wait ran")
        .expect("the session was taken");
    let each = input_claim(1);
    for index in 0..8 {
        lane.send(&[letter(index)]).await;
    }
    for _ in 0..8 {
        lane.accepted().await;
    }
    let others = lane
        .credit_until(
            epoch,
            u32::try_from(8 * each.frames).expect("a count"),
            u64::try_from(8 * each.bytes).expect("a count"),
        )
        .await;
    assert!(others.is_empty(), "{others:?}");
    // The credit came with the session still held by the case's thread.
    let_go.send(()).expect("lets the session go");
    commit.join().expect("the thread ended");
    rig.finish().await;
}

/// The reach of a revision that names the device only, the grant only, the whole host, and one that
/// the worker cannot apply because it has not seen the revisions before it (which it applies as the
/// whole host). Each ends the lease of a holder that it reaches, in the hold that installs it.
fn reach(rig: &Rig, kind: Reach) -> RevisionReach {
    match kind {
        Reach::Device => RevisionReach::Within {
            since: AuthorityRevision::new(1),
            grants: CanonicalSet::new(),
            devices: [rig.device].into_iter().collect(),
        },
        Reach::Grant => RevisionReach::Within {
            since: AuthorityRevision::new(1),
            grants: [rig.grant].into_iter().collect(),
            devices: CanonicalSet::new(),
        },
        Reach::Host => RevisionReach::Host,
        Reach::Unseen => RevisionReach::Within {
            since: AuthorityRevision::new(5),
            grants: CanonicalSet::new(),
            devices: CanonicalSet::new(),
        },
        Reach::Others => RevisionReach::Within {
            since: AuthorityRevision::new(1),
            grants: [GrantId::new(kr_ipc::new_uuid())].into_iter().collect(),
            devices: [DeviceId::new(kr_ipc::new_uuid())].into_iter().collect(),
        },
    }
}

#[derive(Clone, Copy)]
enum Reach {
    Device,
    Grant,
    Host,
    Unseen,
    Others,
}

/// The daemon's announcement of revision 2 with `reach`, over its authority connection.
async fn announce_two(rig: &Rig, reach: RevisionReach) {
    let mut authority = rig.connect(1, None).await;
    let acknowledged = authority
        .announce_revision(AuthorityRevisionNotice {
            environment_id: rig.environment_id,
            revision: AuthorityRevision::new(2),
            reach,
            evidence_from: 0,
        })
        .await
        .expect("the worker acknowledges the revision");
    assert_eq!(acknowledged.revision.get(), 2);
}

/// A forwarded `input.write` on the proxy link, whose caller was validated at `revision`.
async fn proxy_write(
    rig: &mut Rig,
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    revision: u64,
) -> Outcome {
    proxy_write_of(
        rig,
        attachment,
        epoch,
        sequence,
        b"p",
        Nullable::null(),
        revision,
    )
    .await
}

/// A forwarded `input.write` of `bytes` on the proxy link, admitted under an authority that ends
/// at `deadline`, whose caller was validated at `revision`.
async fn proxy_write_of(
    rig: &mut Rig,
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    bytes: &[u8],
    deadline: Nullable<U64>,
    revision: u64,
) -> Outcome {
    let params = InputWriteParams {
        session_id: rig.session_id,
        attachment_id: attachment,
        epoch,
        sequence: InputSequence::new(sequence),
        input: InputContent::Bytes {
            bytes: Bytes::new(bytes.to_vec()),
        },
    };
    let id = RequestId::new(9_000 + sequence);
    let actor = rig.actor(revision);
    let proxy = rig.proxy();
    proxy
        .send(&ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
            request: Request {
                request_id: id,
                method: Method::InputWrite.into(),
                method_version: MethodVersion::V1,
                params: ParamsValue::from_typed(&params).expect("encodes"),
            },
            actor,
            authority_deadline_boot_ms: deadline,
            history: None,
        })))
        .await
        .expect("the frame is written");
    loop {
        match tokio::time::timeout(WAIT, proxy.recv())
            .await
            .expect("the worker answers")
            .expect("the proxy link stays open")
        {
            ControlFrame::Response(response) if response.request_id == id => {
                return response.outcome;
            }
            _ => {}
        }
    }
}

/// KR-REQ-23.36: a revision that reaches the holder ends its lease in the hold that installs the
/// revision, so the lane's frames in flight are refused with a lost lease and the notice that the
/// epoch ended follows. Nothing is accepted from a holder that a revision reached.
async fn a_revision_that_reaches_the_holder(kind: Reach) {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    lane.send(b"a").await;
    lane.accepted().await;

    let notice = reach(&rig, kind);
    announce_two(&rig, notice).await;

    let ended = match lane.next_event().await {
        Some(Seen::Window(window)) => window,
        other => panic!("expected the notice that the epoch ended, read {other:?}"),
    };
    assert!(!ended.holder);
    assert_eq!(ended.ended.0.expect("which epoch ended").epoch, epoch);
    let id = lane.send(b"b").await;
    match lane.next_event().await {
        Some(Seen::Answer(answered, outcome)) => {
            assert_eq!(answered, id);
            assert_eq!(refusal(&outcome), Some(ErrorCode::LeaseLost));
        }
        other => panic!("expected a refusal, read {other:?}"),
    }
    rig.drained().await;
    rig.received_exactly(b"a").await;
    rig.finish().await;
}

/// KR-REQ-23.36: the revision names the holder's device only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_naming_the_holders_device_ends_its_lease_and_its_lane_frames_are_refused() {
    a_revision_that_reaches_the_holder(Reach::Device).await;
}

/// KR-REQ-23.36: the revision names the holder's grant only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_naming_the_holders_grant_ends_its_lease_and_its_lane_frames_are_refused() {
    a_revision_that_reaches_the_holder(Reach::Grant).await;
}

/// KR-REQ-23.36: the revision reaches the whole host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_reaching_the_whole_host_ends_the_lease_and_its_lane_frames_are_refused() {
    a_revision_that_reaches_the_holder(Reach::Host).await;
}

/// KR-REQ-23.36: a reach that the worker cannot apply because it missed the revisions before it is
/// applied as the whole host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reach_the_worker_cannot_apply_ends_the_lease_as_the_whole_host_does() {
    a_revision_that_reaches_the_holder(Reach::Unseen).await;
}

/// KR-REQ-23.36: the exemption from the revision check is for the lane's `input.write` alone. A
/// holder that the revision does not reach keeps typing on its lane although its caller was
/// validated at an older revision, and its epoch does not end; the same `input.write` on the proxy
/// link, and every mutation, are refused at that older revision and accepted at the new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_holder_the_revision_does_not_reach_keeps_typing_on_its_lane_and_nothing_else_is_exempt()
{
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    lane.send(b"a").await;
    lane.accepted().await;

    let notice = reach(&rig, Reach::Others);
    announce_two(&rig, notice).await;

    // The lane's caller was validated at revision 1 and the worker holds 2.
    lane.send(b"b").await;
    lane.accepted().await;

    // The same method on the proxy link, validated at 1: refused. Validated at 2: accepted.
    let refused = proxy_write(&mut rig, attachment, epoch, 2, 1).await;
    assert_eq!(refusal(&refused), Some(ErrorCode::PermissionDenied));
    let accepted = proxy_write(&mut rig, attachment, epoch, 2, 2).await;
    assert!(refusal(&accepted).is_none(), "{accepted:?}");

    // A mutation at 1 is refused too, and the same mutation at 2 is not.
    let report = AttachmentViewportParams {
        attachment_id: attachment,
        dimensions: Dimensions::new(80, 24),
        position: Nullable::null(),
        column: U64::new(0),
    };
    let refused = rig
        .forward_at(Method::AttachmentViewport, &report, 1)
        .await
        .expect_err("a mutation validated at an older revision is refused");
    assert_eq!(refused.code, ErrorCode::PermissionDenied);
    rig.forward_at(Method::AttachmentViewport, &report, 2)
        .await
        .expect("the same mutation at the revision the worker holds");

    // The lane has still not heard that its epoch ended: it did not. The proxy's accepted write took
    // the sequence after the lane's own.
    lane.sequence += 1;
    lane.send(b"c").await;
    loop {
        match lane.next().await.expect("the lane stays open") {
            Seen::Answer(_, outcome) => {
                assert!(refusal(&outcome).is_none(), "{outcome:?}");
                break;
            }
            Seen::Credit(_) | Seen::Launch(_) => {}
            Seen::Window(window) => panic!("the epoch ended: {window:?}"),
        }
    }
    rig.finish().await;
}

/// Where a case that `within` runs has got to, which the words of its bound say.
#[derive(Clone, Default)]
struct Stage(Arc<std::sync::Mutex<&'static str>>);

impl Stage {
    /// Says what the case is about to wait for.
    fn at(&self, step: &'static str) {
        *self.0.lock().expect("the stage is not poisoned") = step;
    }

    fn step(&self) -> &'static str {
        *self.0.lock().expect("the stage is not poisoned")
    }
}

/// Runs a case on a runtime and a thread of its own, and waits for it by `bound` on the calling
/// thread, which depends on nothing the case's runtime does. A worker whose threads wait for
/// each other, or whose runtime stops turning its timers because threads of it are blocked,
/// then fails the case with its say, and with the step it had reached, and the test process is
/// not held by threads that never return.
fn within<Fut: std::future::Future<Output = ()>>(
    bound: Duration,
    what: &str,
    case: impl FnOnce(Stage) -> Fut + Send + 'static,
) {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let stage = Stage::default();
    let reached = stage.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(case(stage));
        let _ = done.send(());
    });
    match finished.recv_timeout(bound) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let step = reached.step();
            if step.is_empty() {
                panic!("{what}: the case did not finish within {bound:?}")
            }
            panic!("{what}: the case did not finish within {bound:?}; it was waiting for {step}")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: the case failed"),
    }
}

/// A lane's bind and a deferred revision announcement each hold one of the two locks the other
/// takes, and let go of it only by taking the second. The bind stands between its two locks and the
/// announcement between its own; with one order everywhere they pass each other, and with two they
/// wait for each other for good.
#[test]
fn a_lane_bind_and_a_deferred_revision_announcement_do_not_wait_for_each_other() {
    within(
        Duration::from_secs(20),
        "a lane bind and a deferred revision announcement waited for each other",
        |_| async {
            let mut rig = Rig::start().await;
            let attachment = rig.attach().await;
            rig.acquire(attachment).await;
            // The daemon's authority link, open before anything stands: its own handshake takes
            // the authority lock.
            let mut daemon = rig.connect(1, None).await;
            let notice = AuthorityRevisionNotice {
                environment_id: rig.environment_id,
                revision: AuthorityRevision::new(2),
                reach: reach(&rig, Reach::Others),
                evidence_from: 0,
            };
            let (bind_at, bind_go) = rig.service.stall_next_lane_bind();
            let (fence_at, fence_go) = rig.service.stall_next_owed_fence();
            // The next announcement finds the dispatch boundary held, which is the path that
            // records the revision as owed.
            rig.service.hold_the_boundary_for_one_announcement_after(0);
            let waits = rig.service.authority_waits();

            // The bind first: it reaches its stop holding the first lock it takes.
            let mut lane_link = rig
                .ask_for_a_lane(1, rig.proxy_connection, attachment)
                .await;
            bind_at.await.expect("the bind reached its stop");
            let announcing = tokio::spawn(async move { daemon.announce_revision(notice).await });
            // The announcement either holds its first lock at its own stop or waits for the lock
            // the bind holds: the authority lock is counted as found held when it waits.
            let mut fence_at = fence_at;
            until(
                "the announcement is at its stop or waits for the bind",
                WAIT,
                || fence_at.try_recv().is_ok() || rig.service.authority_waits() > waits,
            )
            .await;
            bind_go.send(()).expect("lets the bind go");
            fence_go.send(()).expect("lets the announcement go");

            match lane_link.recv().await {
                Ok(ControlFrame::InputLaneReady(_)) => {}
                other => panic!("the lane was not bound: {other:?}"),
            }
            let answered = announcing.await.expect("the announcement task ended");
            assert!(
                answered.is_err(),
                "the held boundary refused the announcement"
            );
            rig.finish().await;
        },
    );
}

/// A forwarded `input.write` that the worker refuses before it reads the frame, because a paired
/// device's envelope names no device, is answered on the lane: the host gets the refusal and the
/// lane goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_refused_before_it_is_read_is_answered_on_the_lane() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let device = std::mem::replace(&mut lane.actor.device_id, Nullable::null());
    let refused = lane.send(b"k").await;
    match tokio::time::timeout(Duration::from_secs(10), lane.next_event()).await {
        Ok(Some(Seen::Answer(answered, outcome))) => {
            assert_eq!(answered, refused);
            assert_eq!(refusal(&outcome), Some(ErrorCode::PermissionDenied));
        }
        other => panic!("the refused frame was not answered on the lane: {other:?}"),
    }
    // The refusal took no sequence number, and the lane is still bound.
    lane.actor.device_id = device;
    lane.sequence -= 1;
    lane.send(b"a").await;
    lane.accepted().await;
    rig.received_exactly(b"a").await;
    rig.finish().await;
}

/// A request that carries nothing for a lane.
fn a_request() -> ControlFrame {
    ControlFrame::Request(Request {
        request_id: RequestId::new(7),
        method: Method::SessionRead.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::empty(),
    })
}

/// Before its ready frame, a lane connection is written nothing: a frame it sends ahead of its bind
/// ends the link, whatever the frame is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lane_connection_that_sends_before_its_bind_is_written_nothing_and_is_closed() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let lane = rig.lane(attachment).await;
    let write = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request: Request {
            request_id: RequestId::new(8),
            method: Method::InputWrite.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&InputWriteParams {
                session_id: rig.session_id,
                attachment_id: attachment,
                epoch: lane.epoch,
                sequence: InputSequence::new(0),
                input: InputContent::Bytes {
                    bytes: Bytes::new(b"k".to_vec()),
                },
            })
            .expect("encodes"),
        },
        actor: rig.actor(1),
        authority_deadline_boot_ms: Nullable::null(),
        history: None,
    }));
    for early in [a_request(), write] {
        let mut link = rig
            .connect(1, Some(ControllerConnectionRole::ProxyInput))
            .await;
        link.send(&early).await.expect("the frame is written");
        let read = tokio::time::timeout(WAIT, link.recv())
            .await
            .expect("the worker acts");
        assert!(
            read.is_err(),
            "a lane connection that had not bound was written a frame: {read:?}"
        );
    }
    rig.finish().await;
}

/// A frame that a bound lane refuses by its role, sent straight behind the bind, is written behind
/// the ready frame, as everything else on the lane is. The lane's writer stands before it takes
/// the ready frame until the refusal has been dealt with, so that the order is the case's and not
/// the scheduler's: a refusal that the connection wrote to the link itself would be read first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_the_lane_refuses_by_its_role_comes_behind_the_ready_frame() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let (writer_at, writer_go) = rig.service.stall_next_lane_writer();
    let mut link = rig
        .connect(1, Some(ControllerConnectionRole::ProxyInput))
        .await;
    link.send(&ControlFrame::InputLane(InputLane {
        proxy_connection: rig.proxy_connection,
        attachment_id: attachment,
    }))
    .await
    .expect("asks for the lane");
    tokio::time::timeout(WAIT, writer_at)
        .await
        .expect("the lane's writer stood before the ready frame in time")
        .expect("the lane's writer stood before the ready frame");
    let queued = rig.runtime.input().lock().queued_lane_frames();
    assert_ne!(
        queued, 0,
        "the ready frame is queued, and nothing has taken it"
    );
    link.send(&a_request()).await.expect("the frame is written");
    until(
        "the refusal was queued on the lane behind the ready frame",
        Duration::from_secs(20),
        || rig.runtime.input().lock().queued_lane_frames() > queued,
    )
    .await;
    writer_go.send(()).expect("lets the writer go");
    match tokio::time::timeout(WAIT, link.recv())
        .await
        .expect("the worker answers")
    {
        Ok(ControlFrame::InputLaneReady(_)) => {}
        other => panic!("the ready frame did not come first: {other:?}"),
    }
    match tokio::time::timeout(WAIT, link.recv())
        .await
        .expect("the worker answers")
    {
        Ok(ControlFrame::Response(response)) => {
            assert_eq!(response.request_id, RequestId::new(7));
            assert_eq!(
                refusal(&response.outcome),
                Some(ErrorCode::PermissionDenied)
            );
        }
        other => panic!("the refusal did not follow the ready frame: {other:?}"),
    }
    rig.finish().await;
}

/// How long a case that expects a closed lane to be gone waits for it, which is longer than the
/// bound the worker is given and decides nothing.
const GONE: Duration = Duration::from_secs(20);

/// KR-REQ-23.36: a host that stops reading ends its own lane. The answers it never reads pile up
/// until the queue passes its bound and closes; the lane's task, its registration and its window
/// then go within the worker's bound, though a write to the host is waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_stops_reading_loses_its_lane_when_the_queue_overflows() {
    let mut rig = Rig::start_with(Some(Duration::from_millis(300))).await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    assert_eq!(rig.service.lane_writers(), 1);
    assert_ne!(
        rig.runtime.input().lock().ledger().reserved,
        Cost::default()
    );
    let served = rig.service.served_connections();
    let admitted = rig.service.admitted_connections();

    // Far more answers than a socket and the queue's bound hold, and the host reads none.
    lane.flood(12_000).await;

    until("the lane's task is gone", GONE, || {
        rig.service.lane_writers() == 0
    })
    .await;
    until(
        "the lane's connection and registration are gone",
        GONE,
        || {
            rig.service.served_connections() == served - 1
                && rig.service.admitted_connections() == admitted - 1
        },
    )
    .await;
    assert_eq!(rig.runtime.input().lock().lane_count(), 0);
    assert_eq!(
        rig.runtime.input().lock().ledger().reserved,
        Cost::default(),
        "the window was returned"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: five lanes of one attachment in a row, each replaced while its host reads
/// nothing and the worker waits to write to it, leave no task and no registration behind but the
/// live lane's, which has the window. The last lane types before the older lanes are cut, so the
/// window has to be with it and not with a lane that is still on its way out; the bound is long
/// enough that no older lane is cut before then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_replacements_in_a_row_leave_no_lane_behind_but_the_last() {
    let mut rig = Rig::start_with(Some(Duration::from_secs(3))).await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let served = rig.service.served_connections();
    let admitted = rig.service.admitted_connections();

    // Each lane has more answers waiting for its host than a socket holds, below the queue's bound.
    let mut hosts = Vec::new();
    for _ in 0..5 {
        let mut lane = rig.lane(attachment).await;
        lane.flood(3_000).await;
        hosts.push(lane);
    }
    let mut last = hosts.pop().expect("the last lane");
    // It types at once. The flood's refusals stand ahead of the answer to the new frame, which has
    // to be an acceptance.
    last.sequence = 0;
    let typed = last.send(b"k").await;
    loop {
        match last.next_event().await {
            Some(Seen::Answer(id, outcome)) if id == typed => {
                assert!(
                    matches!(outcome, Outcome::Ok(_)),
                    "the last lane did not take its key: {outcome:?}"
                );
                break;
            }
            Some(Seen::Answer(id, outcome)) => assert!(
                refusal(&outcome).is_some(),
                "a frame of the flood, {id:?}, was accepted"
            ),
            Some(Seen::Window(_) | Seen::Credit(_) | Seen::Launch(_)) => {}
            None => panic!("the last lane ended before its key was answered"),
        }
    }
    until("one lane's task is left", GONE, || {
        rig.service.lane_writers() == 1
    })
    .await;
    until(
        "one lane's connection and registration are left",
        GONE,
        || {
            rig.service.served_connections() == served + 1
                && rig.service.admitted_connections() == admitted + 1
        },
    )
    .await;
    assert_eq!(rig.runtime.input().lock().lane_count(), 1);
    assert_ne!(
        rig.runtime.input().lock().ledger().reserved,
        Cost::default(),
        "the window is with the last lane"
    );
    rig.received_exactly(b"k").await;
    rig.finish().await;
}

/// KR-REQ-23.36: the answer to a lane's frame is queued in the hold that accepted it, before the
/// frame has left the connection's hands. A frame that stands there while another view takes the
/// keys is answered before the notice that its epoch ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acceptance_stopped_after_its_hold_is_still_answered_before_the_ended_notice() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let (at, release) = rig.service.stall_next_lane_acceptance();
    let sent = lane.send(b"k").await;
    at.await.expect("the frame reached its stop");
    // Another view takes the keys while the frame stands: the notice that the epoch ended is queued.
    rig.acquire(other).await;
    release.send(()).expect("lets the frame go");
    assert_eq!(lane.accepted().await, sent, "the answer is first");
    match lane.next_event().await {
        Some(Seen::Window(window)) => assert!(!window.holder && window.ended.is_present()),
        other => panic!("the ended notice did not follow the answer: {other:?}"),
    }
    rig.finish().await;
}

/// Reads the next window state the worker puts on the lane, keeping nothing else but credit.
async fn next_window(lane: &mut Lane) -> LaneWindow {
    loop {
        match lane.next().await.expect("the lane stays open") {
            Seen::Window(window) => return window,
            Seen::Credit(_) | Seen::Launch(_) => {}
            Seen::Answer(id, outcome) => {
                panic!("an answer, {id:?}: {outcome:?}, with nothing sent")
            }
        }
    }
}

/// Reads the notice that the end of an epoch owes, once the terminal's writer has given back the
/// room of the batch it dropped. The writer asks for the epoch's end before it gives the room
/// back, so a notice that has not come within this bound, which is far shorter than a case's wait,
/// is one the worker never sent.
async fn the_notice_after_the_room_came_back(rig: &Rig, lane: &mut Lane) -> LaneWindow {
    rig.drained().await;
    tokio::time::timeout(Duration::from_secs(10), next_window(lane))
        .await
        .expect("the writer gave the room back and the end of the epoch was not told")
}

/// Holds the writer while a frame admitted under an authority that ends soon is accepted, and lets
/// it go once that authority has ended. The writer then meets a batch it must not write.
async fn a_batch_that_expires_in_the_writer(rig: &Rig, lane: &mut Lane, bytes: &[u8]) {
    let (stopped, release) = rig.runtime.input().writer_hold().arm();
    let deadline = kr_ipc::clock::boot_elapsed_ms() + 1_500;
    let id = lane.send_before(bytes, deadline).await;
    assert_eq!(
        lane.accepted().await,
        id,
        "the frame is accepted before its deadline"
    );
    stopped.await.expect("the writer took the batch");
    until("the batch's authority ended", WAIT, || {
        kr_ipc::clock::boot_elapsed_ms() >= deadline
    })
    .await;
    release.send(()).expect("lets the writer go");
}

/// KR-REQ-23.36: typing that the session accepted is never discarded with no word. A batch whose
/// authority ends while the writer holds it is not written, it ends its holder's epoch, and the
/// lane's notice carries its bytes as fenced bytes. The view's next frame is refused with the
/// lease's word and nothing of the batch reaches the application.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_the_writer_drops_at_its_deadline_ends_the_epoch_and_the_notice_carries_its_bytes()
{
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    a_batch_that_expires_in_the_writer(&rig, &mut lane, b"abc").await;

    let notice = the_notice_after_the_room_came_back(&rig, &mut lane).await;
    assert!(!notice.holder, "the view no longer holds the keys");
    let ended = notice.ended.0.expect("the notice says an epoch ended");
    assert_eq!((ended.epoch, ended.fenced_bytes.get()), (epoch, 3));

    let late = lane.send(b"z").await;
    match lane.next_event().await {
        Some(Seen::Answer(answered, outcome)) => {
            assert_eq!(answered, late);
            assert_eq!(refusal(&outcome), Some(ErrorCode::LeaseLost));
        }
        other => panic!("expected the lease's refusal, read {other:?}"),
    }
    tokio::time::sleep(SETTLE).await;
    assert!(
        rig.received().is_empty(),
        "no piece of the batch reached the application"
    );
    rig.finish().await;
}

/// The position of the first `count` frames of `epoch` for `attachment`, for a launch numbered
/// `launch` when one is given.
fn barrier(
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
    count: u64,
    launch: Option<u32>,
) -> InputBarrier {
    InputBarrier {
        attachment_id: attachment,
        epoch,
        count: U64::new(count),
        launch: Nullable(launch),
    }
}

/// Sends the bytes as frames of the lane and reads each acceptance.
async fn typed(lane: &mut Lane, frames: &[&[u8]]) {
    for frame in frames {
        lane.send(frame).await;
    }
    for _ in frames {
        lane.accepted().await;
    }
}

/// KR-REQ-23.36, C21: a release or a detach that names a position the live epoch has not reached
/// is a definite refusal with nothing applied, and both go through once the position is reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_or_a_detach_beyond_the_position_of_a_live_epoch_applies_nothing() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    typed(&mut lane, &[b"a", b"b", b"c"]).await;
    rig.received_exactly(b"abc").await;

    let release = rig
        .release_with(
            attachment,
            epoch,
            Some(barrier(attachment, epoch, 4, None)),
            true,
        )
        .await
        .expect_err("the position was not reached");
    assert_eq!(release.code, ErrorCode::DraftConflict);
    let detach = rig
        .detach_with(attachment, Some(barrier(attachment, epoch, 4, None)), true)
        .await
        .expect_err("the position was not reached");
    assert_eq!(detach.code, ErrorCode::DraftConflict);

    // Nothing was applied: the view still holds the keys and is still attached.
    typed(&mut lane, &[b"d"]).await;
    rig.received_exactly(b"abcd").await;
    let released = rig
        .release_with(
            attachment,
            epoch,
            Some(barrier(attachment, epoch, 3, None)),
            true,
        )
        .await
        .expect("the position is reached");
    assert_eq!(released.fenced_bytes.map(U64::get), Some(0));

    // A refused ending is sent once more with no position, as the client does, and the refusal
    // leaves no outcome behind that holds the resend back.
    let epoch = rig.acquire(attachment).await;
    let early = Some(barrier(attachment, epoch, 1, None));
    let release = rig
        .release_with(attachment, epoch, early.clone(), true)
        .await
        .expect_err("nothing was typed in this epoch");
    assert_eq!(release.code, ErrorCode::DraftConflict);
    rig.release_with(attachment, epoch, None, true)
        .await
        .expect("the resend with no position is taken");
    let epoch = rig.acquire(attachment).await;
    let detach = rig
        .detach_with(attachment, Some(barrier(attachment, epoch, 1, None)), true)
        .await
        .expect_err("nothing was typed in this epoch");
    assert_eq!(detach.code, ErrorCode::DraftConflict);
    let detached = rig
        .detach_with(attachment, None, true)
        .await
        .expect("the resend with no position is taken");
    assert_eq!(detached.attachment_id, attachment);
    rig.finish().await;
}

/// KR-REQ-23.36, C21: after a takeover the old epoch accepts no more frames, so there is no
/// position to wait for. The old view's release is a lost lease, as it is today, and its detach
/// succeeds whatever position it names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_takeover_the_old_view_releases_lease_lost_and_detaches_with_no_position() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    typed(&mut lane, &[b"a", b"b"]).await;
    rig.acquire(other).await;

    let unreached = barrier(attachment, epoch, 9, None);
    let release = rig
        .release_with(attachment, epoch, Some(unreached.clone()), true)
        .await
        .expect_err("the old view no longer holds the keys");
    assert_eq!(release.code, ErrorCode::LeaseLost);
    let detached = rig
        .detach_with(attachment, Some(unreached), true)
        .await
        .expect("a detach does not depend on the lease");
    assert_eq!(detached.attachment_id, attachment);
    assert_eq!(
        detached.fenced_bytes.map(U64::get),
        Some(0),
        "the takeover had already counted what the old view left"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: the count a release or a detach answers is the count the lane's notice carries,
/// and both are the bytes the session accepted and the terminal did not take. The count is in the
/// answer only when the request asked for it. A takeover's notice carries the count too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fenced_count_is_exact_in_the_answer_and_in_the_notice() {
    let mut rig = Rig::start().await;

    // A release that asks: the writer holds the first batch, so all five bytes are fenced.
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let (stopped, go) = rig.runtime.input().writer_hold().arm();
    typed(&mut lane, &[b"abc"]).await;
    stopped.await.expect("the writer took the batch");
    typed(&mut lane, &[b"de"]).await;
    let released = rig
        .release_with(attachment, epoch, None, true)
        .await
        .expect("released");
    assert_eq!(released.fenced_bytes.map(U64::get), Some(5));
    let notice = next_window(&mut lane).await;
    assert_eq!(
        notice.ended.0.expect("an epoch ended").fenced_bytes.get(),
        5
    );
    go.send(()).expect("lets the writer go");
    rig.drained().await;

    // A release that does not ask is answered as an older worker answers.
    let epoch = rig.acquire(attachment).await;
    let window = next_window(&mut lane).await;
    assert!(window.holder && window.epoch == epoch);
    lane.at(epoch);
    let (stopped, go) = rig.runtime.input().writer_hold().arm();
    typed(&mut lane, &[b"xy"]).await;
    stopped.await.expect("the writer took the batch");
    let released = rig
        .release_with(attachment, epoch, None, false)
        .await
        .expect("released");
    assert_eq!(released.fenced_bytes, None);
    assert_eq!(
        next_window(&mut lane)
            .await
            .ended
            .0
            .expect("an epoch ended")
            .fenced_bytes
            .get(),
        2
    );
    go.send(()).expect("lets the writer go");
    rig.drained().await;

    // A takeover.
    let other = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let _ = next_window(&mut lane).await;
    lane.at(epoch);
    let (stopped, go) = rig.runtime.input().writer_hold().arm();
    typed(&mut lane, &[b"pqr"]).await;
    stopped.await.expect("the writer took the batch");
    rig.acquire(other).await;
    let notice = next_window(&mut lane).await;
    assert_eq!(
        notice.ended.0.expect("an epoch ended").fenced_bytes.get(),
        3
    );
    go.send(()).expect("lets the writer go");
    rig.drained().await;

    // A detach that asks.
    let epoch = rig.acquire(attachment).await;
    let _ = next_window(&mut lane).await;
    lane.at(epoch);
    let (stopped, go) = rig.runtime.input().writer_hold().arm();
    typed(&mut lane, &[b"mn"]).await;
    stopped.await.expect("the writer took the batch");
    typed(&mut lane, &[b"o"]).await;
    let detached = rig
        .detach_with(attachment, None, true)
        .await
        .expect("detached");
    assert_eq!(detached.fenced_bytes.map(U64::get), Some(3));
    assert_eq!(
        next_window(&mut lane)
            .await
            .ended
            .0
            .expect("an epoch ended")
            .fenced_bytes
            .get(),
        3
    );
    go.send(()).expect("lets the writer go");
    rig.finish().await;
}

/// KR-REQ-23.36, C21: a launch whose barrier names an epoch the attachment no longer holds, or an
/// attachment that is not the holder, is a lost lease with nothing reserved, and a position the
/// live epoch has not reached is a definite refusal. A refusal of the barrier is the launch's
/// whole answer: it writes no marker on the lane and leaves no outcome that holds the next launch
/// back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_launch_is_checked_against_the_holder_the_epoch_and_the_position() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    let first = rig.acquire(attachment).await;
    rig.acquire(other).await;
    let second = rig.acquire(attachment).await;
    assert_ne!(first, second);
    let mut lane = rig.lane(attachment).await;

    let stale = rig
        .launch_with(Some(barrier(attachment, first, 0, Some(1))))
        .await
        .expect_err("the barrier marked an epoch that ended");
    assert_eq!(stale.code, ErrorCode::LeaseLost);
    let not_the_holder = rig
        .launch_with(Some(barrier(other, second, 0, Some(2))))
        .await
        .expect_err("another attachment than the holder");
    assert_eq!(not_the_holder.code, ErrorCode::LeaseLost);
    let early = rig
        .launch_with(Some(barrier(attachment, second, 2, Some(3))))
        .await
        .expect_err("the position was not reached");
    assert_eq!(early.code, ErrorCode::DraftConflict);

    // No marker was written for any of the three: the first thing the lane carries is the
    // acceptance of a key typed afterwards.
    typed(&mut lane, &[b"k"]).await;
    // And the next launch is dealt with by the machine, which has no reader in an editor to ask.
    let dealt_with = rig
        .launch_with(Some(barrier(attachment, second, 1, Some(4))))
        .await
        .expect_err("the machine refuses a launch while its reader is not in an editor");
    assert_eq!(dealt_with.code, ErrorCode::EditorBusy);
    rig.finish().await;
}

/// KR-REQ-23.36, C26: the worker writes the launch marker when it has dealt with the launch, also
/// when the machine refused the launch at once, and the marker is the launch's own number.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_immediate_refusal_of_a_launch_writes_the_marker() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;

    let refused = rig
        .launch_with(Some(barrier(attachment, epoch, 0, Some(7))))
        .await
        .expect_err("the machine refuses a launch while its reader is not in an editor");
    assert_eq!(refused.code, ErrorCode::EditorBusy);
    match lane.next_event().await {
        Some(Seen::Launch(marker)) => {
            assert_eq!((marker.attachment_id, marker.launch), (attachment, 7));
        }
        other => panic!("the launch's marker did not come: {other:?}"),
    }
    rig.finish().await;
}

/// KR-REQ-23.36, C26: a launch that the machine has reserved for its reader is marked on the lane
/// while it is still unanswered, and the marker comes behind the acceptance of every frame before
/// the barrier. The lane's writer stands before the ready frame and the terminal's writer holds the
/// first batch, so the three answers and the marker wait in the lane's queue, and the link shows
/// the order in which they were queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_marker_of_a_reserved_launch_follows_the_acceptances_before_its_barrier() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    rig.at_a_prompt();
    let (lane_at, lane_go) = rig.service.stall_next_lane_writer();
    let link = rig
        .ask_for_a_lane(1, rig.proxy_connection, attachment)
        .await;
    let mut lane = rig.lane_over(link, attachment, Some(epoch));
    tokio::time::timeout(WAIT, lane_at)
        .await
        .expect("the lane's writer stood before the ready frame in time")
        .expect("the lane's writer stood before the ready frame");
    let (held_at, held_go) = rig.runtime.input().writer_hold().arm();

    // Three frames, whose answers wait in the lane's queue.
    for frame in [b"a", b"b", b"c"] {
        lane.send(frame).await;
    }
    held_at
        .await
        .expect("the terminal's writer took the first batch");
    until("the worker accepted the three frames", WAIT, || {
        rig.runtime.input().lock().lease().next_sequence.get() == 3
    })
    .await;
    let before = rig.runtime.input().lock().queued_lane_frames();
    let launching = rig.launching(Some(barrier(attachment, epoch, 3, Some(9))));
    until(
        "the launch's marker was queued on the lane behind the three answers",
        Duration::from_secs(20),
        || rig.runtime.input().lock().queued_lane_frames() == before + 1,
    )
    .await;

    lane_go.send(()).expect("lets the lane's writer go");
    held_go.send(()).expect("lets the terminal's writer go");
    lane.read_ready().await;
    for _ in 0..3 {
        lane.accepted().await;
    }
    match lane.next_event().await {
        Some(Seen::Launch(marker)) => {
            assert_eq!((marker.attachment_id, marker.launch), (attachment, 9));
        }
        other => panic!("the launch's marker did not follow the acceptances: {other:?}"),
    }
    assert!(
        !launching.is_finished(),
        "the launch is with its reader and unanswered when the marker comes"
    );

    // The session's close revokes the reservation, which answers the launch.
    rig.runtime.close(ClosureReason::CloseRequested).1.release();
    let (_proxy, answer) = tokio::time::timeout(WAIT, launching)
        .await
        .expect("the close answers the launch")
        .expect("the launch's task ran");
    assert!(
        answer.is_err(),
        "nothing was installed in the closing session"
    );
}

/// KR-REQ-23.36: a parent's withdrawal ends its lanes' windows as its first step. A replacement
/// generation's withdrawal is stopped after its latch is set and before it has detached anything,
/// and the lane's window has ended by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parents_withdrawal_ends_its_lanes_window_before_it_sets_its_latch() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    rig.acquire(attachment).await;
    let _lane = rig.lane(attachment).await;
    assert_ne!(
        rig.runtime.input().lock().ledger().reserved,
        Cost::default(),
        "the lane has its window while its parent is linked"
    );

    let (stopped, go) = rig.service.stall_next_withdrawal_after_the_latch();
    let steps = async {
        tokio::time::timeout(WAIT, stopped)
            .await
            .expect("the withdrawal reached its latch")
            .expect("the stop was armed");
        assert_eq!(
            rig.runtime.input().lock().ledger().reserved,
            Cost::default(),
            "the lane's window had not ended when the withdrawal set its latch"
        );
        go.send(()).expect("lets the withdrawal go");
    };
    // The new generation's handshake waits for the withdrawals it makes.
    let ((), _second) = tokio::join!(steps, rig.connect(2, None));
    rig.finish().await;
}

/// KR-REQ-23.36: typing that the session accepted from a holder with no lane is never discarded
/// with no word. The writer drops the batch at its deadline and ends the epoch, and the count of
/// the bytes it dropped is what the next acquire reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_dropped_for_a_holder_with_no_lane_is_counted_by_the_next_acquire() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let (stopped, release) = rig.runtime.input().writer_hold().arm();
    let deadline = kr_ipc::clock::boot_elapsed_ms() + 1_500;
    let outcome = proxy_write_of(
        &mut rig,
        attachment,
        epoch,
        0,
        b"abc",
        Nullable::some(U64::new(deadline)),
        1,
    )
    .await;
    assert!(
        matches!(outcome, Outcome::Ok(_)),
        "the key is accepted before its deadline: {outcome:?}"
    );
    stopped.await.expect("the writer took the batch");
    until("the batch's authority ended", WAIT, || {
        kr_ipc::clock::boot_elapsed_ms() >= deadline
    })
    .await;
    release.send(()).expect("lets the writer go");
    rig.drained().await;
    until(
        "the writer ended the holder's epoch",
        Duration::from_secs(10),
        || rig.runtime.input().lock().lease().holder.0.is_none(),
    )
    .await;

    let taken = rig.acquire_result(other).await;
    assert_eq!(
        taken.discarded_bytes.get(),
        3,
        "the next acquire reports what the writer dropped"
    );
    rig.drained().await;
    assert!(
        rig.received().is_empty(),
        "no piece of the batch reached the application"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: a revision that takes the keys from the holder counts what it discarded in the
/// lane's notice, the batch the writer holds and the frame behind it together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_that_reaches_the_holder_counts_what_it_discarded_in_the_notice() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let (stopped, go) = rig.runtime.input().writer_hold().arm();
    typed(&mut lane, &[b"abc"]).await;
    stopped.await.expect("the writer took the batch");
    typed(&mut lane, &[b"de"]).await;

    announce_two(&rig, reach(&rig, Reach::Device)).await;
    let notice = next_window(&mut lane).await;
    let ended = notice.ended.0.expect("the notice says an epoch ended");
    assert_eq!((ended.epoch, ended.fenced_bytes.get()), (epoch, 5));
    go.send(()).expect("lets the writer go");
    rig.drained().await;
    rig.finish().await;
}

/// KR-REQ-23.36: a batch whose authority ends while the writer is part way through it is not
/// written past its deadline, and the notice counts the rest: what the application received and
/// what the notice counts are the bytes of the frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_remainder_of_a_batch_the_writer_abandons_at_its_deadline_is_counted_in_the_notice() {
    const FRAME: usize = 60_000;
    let mut rig = Rig::start_unreading().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;

    // The terminal holds only a little of a frame while its application does not read, so the
    // writer is part way through the batch when the authority behind it ends.
    let deadline = kr_ipc::clock::boot_elapsed_ms() + 5_000;
    let frame = [b'q'; FRAME];
    let id = lane.send_before(&frame, deadline).await;
    assert_eq!(
        lane.accepted().await,
        id,
        "the frame is accepted before its deadline"
    );
    until("the batch's authority ended", WAIT, || {
        kr_ipc::clock::boot_elapsed_ms() >= deadline
    })
    .await;
    rig.let_the_application_read().await;

    let notice = the_notice_after_the_room_came_back(&rig, &mut lane).await;
    let ended = notice.ended.0.expect("the notice says an epoch ended");
    assert_eq!(ended.epoch, epoch);
    let fenced = usize::try_from(ended.fenced_bytes.get()).expect("a count");
    assert!(
        fenced > 0 && fenced < FRAME,
        "the writer was part way through the batch: {fenced} of {FRAME} bytes were not written"
    );
    rig.received_exactly(&frame[..FRAME - fenced]).await;
    rig.finish().await;
}

/// KR-REQ-23.36: a host's answer never goes into a paste that a dropped batch was to close. The
/// writer is part way through a paste when the authority behind it ends: the delivered part is
/// what the application has, and the closing delimiter that the view sent after it, which the
/// writer will not write, is already in the stream that the response lane reads. The writer ends
/// the application's open paste when it abandons the batch, so that the answer to the question the
/// application asks next comes after the end of the paste and not inside it.
///
/// The service ends the epoch of a dropped batch from a task of its own, and an epoch's end moves
/// the fence, which also makes the writer end a paste. That task is held until the answer has
/// been checked, so the end of the paste that the answer follows can only be the writer's own, at
/// the drop. The epoch's end then comes, and the next acquire says that a paste was closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_writer_ends_the_paste_it_abandons_part_way_before_a_reply_is_written() {
    const BODY: usize = 60_000;
    const END_AND_ANSWER: &[u8] = b"\x1b[201~\x1b[0n";
    let mut rig = Rig::start_unreading().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;

    let deadline = kr_ipc::clock::boot_elapsed_ms() + 5_000;
    let mut opening = b"\x1b[200~".to_vec();
    opening.extend_from_slice(&[b'q'; BODY]);
    let id = lane.send_before(&opening, deadline).await;
    assert_eq!(lane.accepted().await, id, "the paste is accepted in time");
    // The frame that closes the paste is accepted too, and the writer will not write it.
    lane.send(b"\x1b[201~").await;
    lane.accepted().await;
    let boundary = rig.service.hold_the_dispatch_boundary();
    until("the opening frame's authority ended", WAIT, || {
        kr_ipc::clock::boot_elapsed_ms() >= deadline
    })
    .await;
    // The accepted stream says the paste is closed, so the answer is let out behind the frames.
    rig.runtime.session().ingest_output(b"\x1b[5n");
    rig.runtime.flush_input();
    rig.let_the_application_read().await;

    // What the application has: the part of the paste that was written, the end of the paste that
    // the writer wrote in its place, and then the answer. How much of the paste was written is
    // for the epoch's end to say.
    tokio::time::timeout(WAIT, async {
        while !rig.received().ends_with(END_AND_ANSWER) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the application did not get the end of the paste and then the answer, but {} bytes \
             ending {:?}",
            rig.received().len(),
            String::from_utf8_lossy(&rig.received()[rig.received().len().saturating_sub(24)..])
        )
    });
    drop(boundary);

    let notice = the_notice_after_the_room_came_back(&rig, &mut lane).await;
    let ended = notice.ended.0.expect("the notice says an epoch ended");
    assert_eq!(ended.epoch, epoch);
    let fenced = usize::try_from(ended.fenced_bytes.get()).expect("a count");
    let sent = 6 + BODY + 6;
    assert!(
        fenced > 6 && fenced < sent,
        "the writer was part way through the paste: {fenced} of {sent} bytes were not written"
    );
    let mut expected = opening[..sent - fenced].to_vec();
    expected.extend_from_slice(END_AND_ANSWER);
    rig.received_exactly(&expected).await;
    // The writer closed the paste the application was inside before the next holder took the
    // keys, and the next acquire says so.
    let next = rig.acquire_result(attachment).await;
    assert!(
        next.closed_open_paste,
        "the next acquire says that no paste was closed, though the worker closed the one the \
         application was inside before it handed input over"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: what the root editor's machine holds for a lease that ends is part of the fenced
/// count, in the answer of a release and in the notice. The reader has not answered the fence it
/// was asked for, so the machine holds the two bytes that the session accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fenced_count_includes_what_the_root_editors_machine_holds() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    rig.reader_enters();
    typed(&mut lane, &[b"x", b"y"]).await;

    let released = rig
        .release_with(attachment, epoch, None, true)
        .await
        .expect("released");
    assert_eq!(released.fenced_bytes.map(U64::get), Some(2));
    let notice = next_window(&mut lane).await;
    assert_eq!(
        notice.ended.0.expect("an epoch ended").fenced_bytes.get(),
        2
    );
    rig.finish().await;
}

/// KR-REQ-23.36: what the root editor's machine holds for a holder who detaches is part of the
/// fenced count, in the answer and in the notice, and the next acquire reports it once. The reader
/// has not answered the fence it was asked for, so the machine holds the two bytes that the session
/// accepted, and the detach drops them with no lease change to acknowledge them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_counts_what_the_root_editors_machine_holds_in_the_answer_and_in_the_notice() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    rig.reader_enters();
    typed(&mut lane, &[b"x", b"y"]).await;

    let detached = rig
        .detach_with(attachment, None, true)
        .await
        .expect("detached");
    assert_eq!(
        detached.fenced_bytes.map(U64::get),
        Some(2),
        "the answer counts the two keys the machine held"
    );
    let ended = next_window(&mut lane)
        .await
        .ended
        .0
        .expect("an epoch ended");
    assert_eq!(
        (ended.epoch, ended.fenced_bytes.get()),
        (epoch, 2),
        "the notice counts the two keys the machine held"
    );

    let other = rig.attach().await;
    assert_eq!(
        rig.acquire_result(other).await.discarded_bytes.get(),
        2,
        "the next acquire reports the same two keys, once"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: a person who types after the launch marker and then closes the view loses the
/// keys that the machine holds behind the launch, and the notice counts them. The view's end is
/// the session's detach of its attachment, as the service makes it when a view's connection ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keys_typed_behind_a_launch_are_counted_when_the_view_closes() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    rig.at_a_prompt();
    let launching = rig.launching(Some(barrier(attachment, epoch, 0, Some(4))));
    match lane.next_event().await {
        Some(Seen::Launch(marker)) => assert_eq!(marker.launch, 4),
        other => panic!("the launch's marker did not come: {other:?}"),
    }
    typed(&mut lane, &[b"x", b"y"]).await;

    let detached = rig
        .runtime
        .session()
        .detach(attachment, None)
        .expect("the view's attachment is removed");
    assert_eq!(
        detached.fenced_bytes.map(U64::get),
        Some(2),
        "the removal counts the two keys held behind the launch"
    );
    let ended = next_window(&mut lane)
        .await
        .ended
        .0
        .expect("an epoch ended");
    assert_eq!(
        (ended.epoch, ended.fenced_bytes.get()),
        (epoch, 2),
        "the notice counts the two keys held behind the launch"
    );

    // The launch waits for its reader's word, which the close gives up on.
    rig.runtime.close(ClosureReason::CloseRequested).1.release();
    let (_proxy, answer) = tokio::time::timeout(WAIT, launching)
        .await
        .expect("the close answers the launch")
        .expect("the launch's task ran");
    assert!(
        answer.is_err(),
        "nothing was installed for a view that left"
    );
}

/// KR-REQ-23.36: the session's close drops what the machine holds, and the notice that the epoch
/// ended counts it. The notice is told when the close's hold ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_close_counts_what_the_root_editors_machine_holds_in_the_notice() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    rig.reader_enters();
    typed(&mut lane, &[b"x", b"y"]).await;

    rig.runtime.close(ClosureReason::CloseRequested).1.release();
    let ended = next_window(&mut lane)
        .await
        .ended
        .0
        .expect("an epoch ended");
    assert_eq!(
        (ended.epoch, ended.fenced_bytes.get()),
        (epoch, 2),
        "the close's notice counts the two keys the machine held"
    );
}

/// KR-REQ-23.36: the root editor's own gesture that detaches the view whose fence it holds ends
/// the view's lease with the machine's share already dropped. The notice counts the keys held
/// behind the launch, and the next acquire reports them once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_roots_end_counts_what_the_machine_dropped_with_the_attachment_in_the_notice() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let fence_id = rig.at_a_prompt();
    let launching = rig.launching(Some(barrier(attachment, epoch, 0, Some(5))));
    match lane.next_event().await {
        Some(Seen::Launch(marker)) => assert_eq!(marker.launch, 5),
        other => panic!("the launch's marker did not come: {other:?}"),
    }
    typed(&mut lane, &[b"x", b"y"]).await;

    let session_id = rig.session_id;
    rig.runtime
        .session()
        .stimulate_fence(|driver| {
            driver.bridge_event(
                RequestId::new(3),
                &BridgeEvent::EofDetach(RootEofDetachParams {
                    session_id,
                    fence_id,
                    prompt_generation: PromptGeneration::new(1),
                    input_epoch: epoch,
                }),
            )
        })
        .expect("the session has a fence machine");
    let ended = next_window(&mut lane)
        .await
        .ended
        .0
        .expect("an epoch ended");
    assert_eq!(
        (ended.epoch, ended.fenced_bytes.get()),
        (epoch, 2),
        "the notice counts the two keys the machine dropped with the attachment"
    );

    assert_eq!(
        rig.runtime.session().interrupted_input().bytes,
        2,
        "the same two keys are carried to the next acquire, once"
    );

    // The launch waits for its reader's word, which the close gives up on.
    rig.runtime.close(ClosureReason::CloseRequested).1.release();
    let (_proxy, answer) = tokio::time::timeout(WAIT, launching)
        .await
        .expect("the close answers the launch")
        .expect("the launch's task ran");
    assert!(
        answer.is_err(),
        "nothing was installed for a view that left"
    );
}

/// Ends the view of `attachment` by the root editor's own gesture, with the recogniser's timer
/// stopped at its deadline and the session's carry-out stopped before the removal, as it is
/// between the machine's stimulus and the session's removal: the input domain is let go there, so
/// the timer can forward a delimiter prefix in that gap. The timer is let go when the removal has
/// arrived, and the removal when the carried count has `carried` bytes, which says that the
/// stimulus and the timer have both done what they do.
///
/// Returns what the lane's notice counts for the epoch and what the next acquire would report.
async fn the_roots_end_with_the_timer_let_go_in_the_gap(
    rig: &mut Rig,
    lane: &mut Lane,
    epoch: InputLeaseEpoch,
    fence_id: kr_protocol::root::FenceId,
    timer: (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    carried: u64,
) -> (u64, u64) {
    let (at_its_deadline, let_the_timer_go) = timer;
    tokio::time::timeout(WAIT, at_its_deadline)
        .await
        .expect("the timer reached the deadline of the held prefix")
        .expect("the timer is waiting");
    let (at_the_removal, go_on) = rig.runtime.session().pause_before_a_removal();
    let runtime = Arc::clone(&rig.runtime);
    let session_id = rig.session_id;
    let detaching = tokio::task::spawn_blocking(move || {
        runtime.session().stimulate_fence(|driver| {
            driver.bridge_event(
                RequestId::new(3),
                &BridgeEvent::EofDetach(RootEofDetachParams {
                    session_id,
                    fence_id,
                    prompt_generation: PromptGeneration::new(1),
                    input_epoch: epoch,
                }),
            )
        })
    });
    tokio::time::timeout(WAIT, at_the_removal)
        .await
        .expect("the stimulus reached the removal")
        .expect("the removal is waiting");
    let_the_timer_go.send(()).expect("lets the timer go on");
    let input = rig.runtime.input();
    until(
        "the carried count has the stimulus's and the timer's",
        WAIT,
        || input.lock().interrupted_input().bytes == carried,
    )
    .await;
    go_on.send(()).expect("lets the removal go on");
    detaching
        .await
        .expect("the stimulus ends")
        .expect("the session has a fence machine");
    let ended = next_window(lane).await.ended.0.expect("an epoch ended");
    assert_eq!(ended.epoch, epoch);
    (
        ended.fenced_bytes.get(),
        rig.runtime.session().interrupted_input().bytes,
    )
}

/// KR-REQ-23.36: a delimiter prefix that the worker accepted and the recogniser holds when the
/// root editor ends the view is part of that end. The recogniser's timer can come due between the
/// machine's stimulus and the session's removal; the prefix is taken in the stimulus's hold, so
/// the notice counts it and the next acquire reports it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prefix_held_when_the_root_ends_the_view_is_counted_in_its_notice() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let fence_id = rig.at_a_prompt();
    let timer = rig.runtime.pause_the_timer_at_its_deadline();
    typed(&mut lane, &[b"\x1b"]).await;

    let (notice, carried) = the_roots_end_with_the_timer_let_go_in_the_gap(
        &mut rig, &mut lane, epoch, fence_id, timer, 1,
    )
    .await;
    assert_eq!(
        notice, 1,
        "the notice counts the Escape the recogniser held"
    );
    assert_eq!(
        carried, 1,
        "the same byte is carried to the next acquire, once"
    );
    rig.finish().await;
}

/// KR-REQ-23.36: the same end with the prefix held inside an open paste. The paste is open at the
/// application, and the recogniser holds the Escape that may begin its closing delimiter. The
/// removal takes that prefix as it takes any other, so the notice counts it and the next acquire
/// reports it once, and the application is not sent it: the writer's own terminator is the only
/// thing that ends the paste.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prefix_held_inside_an_open_paste_when_the_root_ends_the_view_is_counted_in_its_notice() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let fence_id = rig.at_a_prompt();
    let timer = rig.runtime.pause_the_timer_at_its_deadline();
    typed(&mut lane, &[b"\x1b[200~x\x1b"]).await;
    rig.received_exactly(b"\x1b[200~x").await;

    let (notice, carried) = the_roots_end_with_the_timer_let_go_in_the_gap(
        &mut rig, &mut lane, epoch, fence_id, timer, 1,
    )
    .await;
    assert_eq!(
        notice, 1,
        "the notice counts the Escape the recogniser held inside the paste"
    );
    assert_eq!(
        carried, 1,
        "the same byte is carried to the next acquire, once"
    );
    // The end was applied through the session's own seam, which leaves what it queued for the
    // writer to the caller.
    rig.runtime.flush_input();
    rig.received_exactly(b"\x1b[200~x\x1b[201~").await;
    rig.finish().await;
}

/// KR-REQ-23.36: the same end with keys held behind a reserved launch as well: the machine's two
/// keys and the recogniser's prefix are three bytes in the notice and three in the carried count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prefix_and_the_keys_behind_a_launch_are_counted_together_when_the_root_ends_the_view() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let fence_id = rig.at_a_prompt();
    let launching = rig.launching(Some(barrier(attachment, epoch, 0, Some(5))));
    match lane.next_event().await {
        Some(Seen::Launch(marker)) => assert_eq!(marker.launch, 5),
        other => panic!("the launch's marker did not come: {other:?}"),
    }
    let timer = rig.runtime.pause_the_timer_at_its_deadline();
    typed(&mut lane, &[b"x", b"y", b"\x1b"]).await;

    let (notice, carried) = the_roots_end_with_the_timer_let_go_in_the_gap(
        &mut rig, &mut lane, epoch, fence_id, timer, 3,
    )
    .await;
    assert_eq!(
        notice, 3,
        "the notice counts the two keys the machine dropped and the Escape the recogniser held"
    );
    assert_eq!(
        carried, 3,
        "the same three bytes are carried to the next acquire, once"
    );

    rig.runtime.close(ClosureReason::CloseRequested).1.release();
    let (_proxy, answer) = tokio::time::timeout(WAIT, launching)
        .await
        .expect("the close answers the launch")
        .expect("the launch's task ran");
    assert!(
        answer.is_err(),
        "nothing was installed for a view that left"
    );
}

/// KR-REQ-23.36: the release that an application's keyboard negotiation causes has no request to
/// answer, so its count is told in the notice and carried to the next acquire. The machine holds
/// two keys of the holder, and both reports have them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keyboard_mode_release_counts_what_the_root_editors_machine_holds_in_the_notice() {
    let mut rig = Rig::start_fenced().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    rig.reader_enters();
    typed(&mut lane, &[b"x", b"y"]).await;

    // The application asks for every key as an escape code, which the attached terminal does not
    // produce.
    rig.runtime.session().ingest_output(b"\x1b[=8;1u");
    let ended = next_window(&mut lane)
        .await
        .ended
        .0
        .expect("an epoch ended");
    assert_eq!(
        (ended.epoch, ended.fenced_bytes.get()),
        (epoch, 2),
        "the notice counts the two keys the machine held"
    );
    assert_eq!(
        rig.runtime.session().interrupted_input().bytes,
        2,
        "the same two keys are carried to the next acquire"
    );
    rig.finish().await;
}

/// Takes `attachment`'s next frame in the session's own hold: the first four bytes of a bracketed
/// paste's opener, which the framer holds back as a delimiter prefix. The session's hold does not
/// stop the recogniser's timer, which takes only the input domain, so the caller pauses the timer
/// at its deadline first (`SessionRuntime::pause_the_timer_at_its_deadline`) and ends the lease
/// in the same hold: the prefix is discarded by that end, and no timer forwards it first.
fn hold_a_delimiter_prefix(
    session: &mut Session,
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
) {
    let accepted = session
        .write_input(
            attachment,
            epoch.get(),
            0,
            b"\x1b[20",
            None,
            std::time::Instant::now(),
        )
        .expect("the first four bytes of a delimiter");
    assert_eq!(accepted.held_prefix_bytes, 4);
}

/// KR-REQ-23.36: the delimiter prefix that the framer holds and an end of the lease drops is part
/// of the count the lane's notice carries, whether the lease ends by a release, a takeover or a
/// detach; and the answer of each says the same number.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fenced_count_includes_the_delimiter_prefix_the_framer_dropped_at_every_end() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let other = rig.attach().await;
    let taker = ConnectionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));

    // A release.
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    let timer = rig.runtime.pause_the_timer_at_its_deadline();
    let (_, fenced) = {
        let mut session = rig.runtime.session();
        hold_a_delimiter_prefix(&mut session, attachment, epoch);
        session
            .release_input(attachment, epoch.get(), None)
            .expect("released")
    };
    drop(timer);
    assert_eq!(fenced, 4, "the answer counts the dropped prefix");
    assert_eq!(
        next_window(&mut lane)
            .await
            .ended
            .0
            .expect("an epoch ended")
            .fenced_bytes
            .get(),
        4,
        "the notice of a release counts the dropped prefix"
    );

    // A takeover.
    let epoch = rig.acquire(attachment).await;
    let _ = next_window(&mut lane).await;
    let timer = rig.runtime.pause_the_timer_at_its_deadline();
    let acquired = {
        let mut session = rig.runtime.session();
        hold_a_delimiter_prefix(&mut session, attachment, epoch);
        session
            .acquire_input(other, taker, None)
            .expect("the other view takes the keys")
    };
    drop(timer);
    assert_eq!(acquired.discarded_bytes.get(), 4);
    assert_eq!(
        next_window(&mut lane)
            .await
            .ended
            .0
            .expect("an epoch ended")
            .fenced_bytes
            .get(),
        4,
        "the notice of a takeover counts the dropped prefix"
    );

    // A detach.
    let epoch = rig.acquire(attachment).await;
    let _ = next_window(&mut lane).await;
    let timer = rig.runtime.pause_the_timer_at_its_deadline();
    let detached = {
        let mut session = rig.runtime.session();
        hold_a_delimiter_prefix(&mut session, attachment, epoch);
        session.detach(attachment, None).expect("detached")
    };
    drop(timer);
    assert_eq!(detached.fenced_bytes.map(U64::get), Some(4));
    assert_eq!(
        next_window(&mut lane)
            .await
            .ended
            .0
            .expect("an epoch ended")
            .fenced_bytes
            .get(),
        4,
        "the notice of a detach counts the dropped prefix"
    );
    rig.finish().await;
}

/// KR-REQ-23.36, C21: the session refuses a position its live epoch has not reached in the hold of
/// the action itself, for a release, a detach and a launch, so a caller that did not ask before
/// the marker still changes nothing and starts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_refuses_an_unreached_position_in_the_hold_of_the_action() {
    let mut rig = Rig::start().await;
    let attachment = rig.attach().await;
    let epoch = rig.acquire(attachment).await;
    let mut lane = rig.lane(attachment).await;
    typed(&mut lane, &[b"a", b"b"]).await;
    rig.received_exactly(b"ab").await;

    {
        let mut session = rig.runtime.session();
        let beyond = barrier(attachment, epoch, 3, Some(1));
        let release = session
            .release_input(attachment, epoch.get(), Some(&beyond))
            .expect_err("the position was not reached");
        assert_eq!(release.code(), ErrorCode::DraftConflict);
        let detach = session
            .detach(attachment, Some(&beyond))
            .expect_err("the position was not reached");
        assert_eq!(detach.code(), ErrorCode::DraftConflict);
        let launch = session
            .stimulate_fence_after(&beyond, |_| panic!("the machine saw a refused launch"))
            .expect_err("the position was not reached");
        assert_eq!(launch.code(), ErrorCode::DraftConflict);
    }

    // Nothing was applied: the view still holds the keys and is still attached.
    typed(&mut lane, &[b"c"]).await;
    rig.received_exactly(b"abc").await;
    rig.release_with(
        attachment,
        epoch,
        Some(barrier(attachment, epoch, 3, None)),
        true,
    )
    .await
    .expect("the position is reached");
    rig.finish().await;
}

/// KR-REQ-23.36: the hello states the lane's capability, which promises the window, the position
/// checks, the fenced count and the launch marker together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_states_the_input_lane() {
    let rig = Rig::start().await;
    let link = rig.connect(1, Some(ControllerConnectionRole::Proxy)).await;
    assert!(
        link.acknowledgement()
            .capabilities
            .iter()
            .any(|capability| capability.as_str() == "input.lane/1"),
        "the worker does not state the input lane"
    );
    rig.finish().await;
}
