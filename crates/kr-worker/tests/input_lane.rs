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
    SessionAttachResult,
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
    InputAcquireParams, InputAcquireResult, InputContent, InputWriteParams, input_claim,
};
use kr_protocol::local::{
    ControllerConnectionRole, ForwardedRequest, InputLane, InputLaneReady, LaneCredit, LaneWindow,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable, U64};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::{AuthorityRevisionNotice, RevisionReach};
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
    /// Writes one frame of the lane's attachment, in the epoch and the sequence it is at.
    async fn send(&mut self, bytes: &[u8]) -> RequestId {
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
                authority_deadline_boot_ms: Nullable::null(),
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
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let kept = tempfile::tempdir().expect("a directory for what the application keeps");
        let received = kept.path().join("received");
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script(&format!(
                "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec tee {}",
                kr_worker::testing::shell_quoted(&received)
            )),
            shell_mode: ShellMode::NativeCompat,
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
        let params = InputAcquireParams {
            session_id: self.session_id,
            attachment_id: attachment,
            expected_epoch: Nullable::null(),
        };
        let lease: InputAcquireResult = self
            .forward_at(Method::InputAcquire, &params, 1)
            .await
            .expect("the device takes the keys")
            .to_typed()
            .expect("a lease");
        lease.lease.epoch
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
        let mut link = self
            .ask_for_a_lane(1, self.proxy_connection, attachment)
            .await;
        let ready = match tokio::time::timeout(WAIT, link.recv())
            .await
            .expect("the worker answers the bind")
        {
            Ok(ControlFrame::InputLaneReady(ready)) => ready,
            other => panic!("the lane was not bound: {other:?}"),
        };
        Lane {
            link,
            attachment,
            session_id: self.session_id,
            actor: self.actor(1),
            epoch: ready.epoch,
            sequence: 0,
            requests: 0,
            credits: Vec::new(),
            ready,
        }
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
                "the application received {} bytes, not the {} expected",
                self.received().len(),
                expected.len()
            )
        });
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
    let mut rig = Rig::start().await;
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
                Seen::Window(_) | Seen::Credit(_) => {}
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
    let params = InputWriteParams {
        session_id: rig.session_id,
        attachment_id: attachment,
        epoch,
        sequence: InputSequence::new(sequence),
        input: InputContent::Bytes {
            bytes: Bytes::new(b"p".to_vec()),
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
            authority_deadline_boot_ms: Nullable::null(),
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
            Seen::Credit(_) => {}
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
            Some(Seen::Window(_) | Seen::Credit(_)) => {}
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
