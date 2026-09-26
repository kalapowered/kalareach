//! What only the local owner may do at a worker, whichever socket another caller came in on.
//!
//! The local owner is the operating-system user the worker's listener authenticated, acting under
//! no grant. The control daemon forwards callers it heard on its own local socket as well as
//! paired devices, and a caller it heard locally can still act under a grant, so the socket a
//! request entered the host on does not say whether its caller is the owner. Every owner exemption
//! here is decided by that alone, and every other caller is narrowed:
//!
//! * it is drawn the screen that is showing, and never the buffer behind it;
//! * it is not served the session's retained output;
//! * it is given the last command only when its history scope reaches it;
//! * it detaches the attachments its own connection made, and no other;
//! * an authority revision takes its input lease away;
//! * it cancels its own undispatched intents, and no other actor's.
//!
//! Each rule has two tests. The first asks it of a caller the daemon heard on its local socket,
//! acting under a grant. The second asks it of the callers whose answer does not depend on the
//! socket: the owner in one of its own windows on the worker's socket, the owner as the daemon
//! forwards it, and a paired device. `the_local_owner_is_the_local_ingress_holding_no_grant` states
//! the question all of them ask, over every ingress.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.50 | `a_local_caller_under_a_grant_is_drawn_the_live_screen_alone`, `the_local_owner_is_drawn_the_whole_screen_and_a_device_the_live_screen` |
//! | KR-REQ-10.49 | `a_local_caller_under_a_grant_is_refused_the_retained_history`, `the_local_owner_reads_the_retained_history_on_either_socket`, `a_local_caller_under_a_grant_reads_the_last_command_only_inside_its_scope`, `the_local_owner_reads_the_last_command_on_either_socket` |
//! | KR-REQ-10.41 | `a_local_caller_under_a_grant_detaches_only_what_its_own_connection_made`, `the_local_owner_detaches_another_windows_attachment_and_a_device_does_not` |
//! | KR-REQ-10.45 | `a_revision_takes_the_lease_from_a_local_caller_under_a_grant`, `a_revision_takes_a_devices_lease_and_leaves_the_local_owners` |
//! | KR-REQ-23.46 | `a_local_caller_under_a_grant_cancels_its_own_intent_and_no_other`, `the_local_owner_cancels_another_actors_intent_and_a_device_does_not` |

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{LIVENESS_DEADLINE, carries};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    SessionDetachParams, TerminalPresentationMode,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::HistoryScope;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, AttachmentId, AuthorityRevision, BuildId, ConnectionId,
    ControllerGeneration, DeviceId, GrantId, InputLeaseEpoch, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::input::InputAcquireParams;
use kr_protocol::local::{ControllerConnectionRole, ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{ActionCancelParams, Receipt, ReceiptState, RejectionReason};
use kr_protocol::recovery::{
    EventStream, EventsSubscribeParams, HistoryPageParams, HistoryPageResult, OutputEvent,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{
    ClosureReason, Dimensions, DisplayNumber, SessionReadParams, SessionReadResult, ShellMode,
};
use kr_protocol::worker::AuthorityRevisionNotice;
use kr_shell_integration::contract::events::{BridgeEvent, EofGesture, HooksActivated};
use kr_shell_integration::contract::fence::LeaseView;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::transport::{
    EventOutcome, HandshakeOutcome, WorkerExpectation,
};
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::scripted::{
    ReferenceShell, ScriptedBridge, ToBridge, qualified_hello,
};
use kr_transport::clock::SystemContinuousClock;
use kr_worker::fence::FenceDriver;
use kr_worker::journal::Submission;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{Caller, ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// A line the shell prints before the application takes the screen, and so the buffer that is not
/// showing once it has.
const BEHIND: &[u8] = b"kr-printed-before-the-application";

/// A line the application prints on the screen it takes, which is the screen that is showing.
const SHOWN: &[u8] = b"kr-the-application-screen";

/// A shell that prints [`BEHIND`], then takes the alternate screen and prints [`SHOWN`] there.
const TWO_BUFFERS: &str = "printf 'kr-printed-before-the-application\\n'; printf '\\033[?1049h'; \
                           printf 'kr-the-application-screen\\n'; sleep 120";

/// What a grant that lets its holder watch the terminal and type into it carries.
const WATCH_AND_TYPE: &[ActionRight] = &[ActionRight::SessionView, ActionRight::TerminalInput];

/// The actor whose intents the cancellation tests try to take back.
const ANOTHER_ACTOR: &str = "device:another-phone";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A request identifier that no other request on any of this test's connections uses.
fn next_request() -> RequestId {
    static NEXT: AtomicU64 = AtomicU64::new(1_000_000);
    RequestId::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Waits for `work`, and fails the test rather than hanging when the worker stops answering.
async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS_DEADLINE, work)
        .await
        .unwrap_or_else(|_| panic!("{what} within {LIVENESS_DEADLINE:?}"))
}

/// The owner as the daemon forwards it: heard on the daemon's local socket, acting under no grant.
fn the_owner_forwarded() -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new("local:the-owner").expect("an actor"),
        ingress: ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
    }
}

/// The principal of the caller [`local_under_a_grant`] describes.
const UNDER_A_GRANT: &str = "local:under-a-grant";

/// A caller the daemon heard on its local socket, acting under a grant the daemon checked at
/// `revision`.
fn local_under_a_grant(revision: u64) -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new(UNDER_A_GRANT).expect("an actor"),
        ingress: ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([2; 16]))),
        grant_revision: Nullable::some(AuthorityRevision::new(revision)),
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([3; 16])),
    }
}

/// A paired device, acting under a grant the daemon checked at `revision`.
fn device(revision: u64) -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([4; 16]))),
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([5; 16]))),
        grant_revision: Nullable::some(AuthorityRevision::new(revision)),
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
    }
}

fn detaching(attachment_id: AttachmentId) -> SessionDetachParams {
    SessionDetachParams {
        attachment_id: Nullable::some(attachment_id),
        line_token: Nullable::null(),
    }
}

fn cancelling(action_id: ActionId) -> ActionCancelParams {
    ActionCancelParams { action_id }
}

/// Asserts that the terminal an attachment was admitted as is served the stream, so the screen it
/// is drawn arrives as bytes.
#[track_caller]
fn served_the_stream(attached: &SessionAttachResult) {
    assert_eq!(
        attached.attachment.presentation.as_ref().copied(),
        Some(TerminalPresentationMode::Direct),
        "a terminal of the session's own size is served the stream: {attached:?}"
    );
}

/// Asserts that an intent was taken back before it was dispatched.
#[track_caller]
fn cancelled(receipt: &Receipt) {
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert_eq!(
        receipt.reason.as_ref(),
        Some(&RejectionReason::Cancelled),
        "{receipt:?}"
    );
}

/// Writes a subscription and returns the screen it is drawn.
///
/// That is everything the subscription is sent up to and including [`SHOWN`]. The screen a
/// subscription joins on paints the buffer that is not showing before the one that is, so any of
/// [`BEHIND`] this caller is drawn has arrived by the time [`SHOWN`] has, and the wait ends on
/// something the application printed rather than on a length of time.
async fn drawn(client: &mut LocalClient, frame: ControlFrame, request_id: RequestId) -> Vec<u8> {
    within("the subscription", client.writer().write_message(&frame))
        .await
        .expect("writes the subscription");
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let mut answered = false;
    let mut seen = Vec::new();
    while !answered || !carries(&seen, SHOWN) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(ControlFrame::Response(response))) if response.request_id == request_id => {
                if let Outcome::Error(error) = response.outcome {
                    panic!("the subscription is refused: {error:?}");
                }
                answered = true;
            }
            Ok(Ok(ControlFrame::Notification(notification)))
                if notification.event_type.as_str() == "session.output" =>
            {
                let event: OutputEvent = notification
                    .payload
                    .to_typed()
                    .expect("an output event decodes");
                seen.extend_from_slice(event.bytes.as_slice());
            }
            // Anything else this connection is sent is not the screen.
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!(
                "waited {:?} for the screen and the connection ended ({error}): {}",
                started.elapsed(),
                printable(&seen)
            ),
            Err(_) => panic!(
                "waited {:?} for the screen: {}",
                started.elapsed(),
                printable(&seen)
            ),
        }
    }
    seen
}

/// What a terminal was sent, as text a failure message can show.
fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).escape_debug().to_string()
}

/// One read, forwarded by the control daemon for the actor it vouches for, with the history scope
/// of the grant the daemon decided it under when one travels with it.
///
/// A caller under a grant has authority that runs out, so its read carries a deadline; the owner's
/// does not.
fn forwarded_read(
    actor: &ActorEnvelope,
    request: Request,
    history: Option<HistoryScope>,
) -> ControlFrame {
    ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request,
        authority_deadline_boot_ms: if actor.grant_id.is_present() {
            Nullable::some(U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000))
        } else {
            Nullable::null()
        },
        actor: actor.clone(),
        history,
    }))
}

/// A grant's history scope that reaches back to `lower_bound_ms`, or that retains no history, and
/// includes the live screen either way.
fn reaching(lower_bound_ms: Option<u64>) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable(lower_bound_ms.map(TimestampMs::new)),
        include_live_screen: true,
        named_questions: CanonicalSet::new(),
        named_approvals: CanonicalSet::new(),
    }
}

/// Writes one request and returns the worker's answer to it.
async fn answer(
    client: &mut LocalClient,
    frame: ControlFrame,
    request_id: RequestId,
) -> Result<ParamsValue, ProtocolError> {
    within("the worker's answer", async {
        client
            .writer()
            .write_message(&frame)
            .await
            .expect("writes the request");
        loop {
            if let ControlFrame::Response(response) =
                client.recv().await.expect("the worker answers")
                && response.request_id == request_id
            {
                return match response.outcome {
                    Outcome::Ok(value) => Ok(value),
                    Outcome::Error(error) => Err(error),
                };
            }
        }
    })
    .await
}

/// One worker service with a real session behind it, and the daemon identity to forward through.
struct Wired {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    /// The root shell's side of a managed session's bridge, which this test plays, and the task
    /// serving the worker's side. Neither exists for an unmanaged session.
    bridge: Option<(ScriptedBridge, tokio::task::JoinHandle<()>)>,
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

    /// A terminal of the session's own size, asking for `requested`.
    fn terminal(&self, requested: &[AttachmentCapability]) -> SessionAttachParams {
        SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested: requested.iter().copied().collect(),
        }
    }

    /// A subscription of one attachment to the session's output.
    fn subscription(&self, request_id: RequestId, attachment_id: AttachmentId) -> Request {
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        Request {
            request_id,
            method: Method::EventsSubscribe.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&EventsSubscribeParams {
                session_id: self.session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::null(),
            })
            .expect("encodes"),
        }
    }

    /// One of the owner's own windows: a connection on the worker's own socket.
    async fn window(&self) -> LocalClient {
        within(
            "a window's connection",
            LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build()),
        )
        .await
        .expect("connects")
    }

    /// One of the control daemon's connections to this worker, proved for the generation it
    /// accepts.
    ///
    /// The daemon forwards each caller over a proxy of that caller's own, which owns the caller's
    /// attachments, and it announces authority revisions over its authority connection.
    async fn daemon(&self, role: ControllerConnectionRole) -> LocalClient {
        let mut daemon = within(
            "the daemon's connection",
            LocalClient::connect(&self.endpoint, LocalClientKind::Controller, build()),
        )
        .await
        .expect("connects as the daemon");
        within(
            "the role",
            daemon
                .writer()
                .write_message(&ControlFrame::ControllerRole(role)),
        )
        .await
        .expect("declares the role");
        match within("the worker's answer to the role", daemon.recv())
            .await
            .expect("the worker answers")
        {
            ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
            other => panic!("the worker answered {other:?}"),
        }
        let identity = Arc::clone(&self.controller);
        let boot = self.boot.clone();
        within(
            "the worker's acceptance of the generation",
            daemon.present_generation(move |nonce| {
                identity
                    .generation_token(ControllerGeneration::new(1), &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            }),
        )
        .await
        .expect("the worker accepts the generation");
        daemon
    }

    /// Forwards one mutation for `actor`, admitted under a grant that carries `rights`.
    async fn forward<T: serde::Serialize>(
        &self,
        daemon: &mut LocalClient,
        actor: &ActorEnvelope,
        rights: &[ActionRight],
        method: Method,
        params: &T,
    ) -> Result<ParamsValue, ProtocolError> {
        let mutation = MutationRequest {
            request_id: next_request(),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            target: self.target(),
            params: ParamsValue::from_typed(params).expect("encodes"),
            grant_id: Nullable::null(),
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("forwarded").expect("a window identifier"),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
        };
        within(
            "the worker's answer",
            daemon.forward(
                &mutation,
                actor,
                &rights.iter().copied().collect(),
                U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000),
            ),
        )
        .await
        .expect("the forward reaches the worker")
    }

    /// Forwards an attach for `actor` of a terminal of the session's own size.
    async fn attach_for(
        &self,
        daemon: &mut LocalClient,
        actor: &ActorEnvelope,
        rights: &[ActionRight],
        requested: &[AttachmentCapability],
    ) -> SessionAttachResult {
        self.forward(
            daemon,
            actor,
            rights,
            Method::SessionAttach,
            &self.terminal(requested),
        )
        .await
        .expect("the attach is admitted")
        .to_typed()
        .expect("an attachment")
    }

    /// Attaches a terminal of the session's own size in one of the owner's windows.
    async fn attach_in(
        &self,
        window: &mut LocalClient,
        requested: &[AttachmentCapability],
    ) -> SessionAttachResult {
        within(
            "the attach",
            window.mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &self.terminal(requested),
            ),
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach is admitted")
        .to_typed()
        .expect("an attachment")
    }

    /// Attaches a terminal for `actor` over `daemon`, subscribes it, and returns the screen it is
    /// drawn.
    async fn drawn_for(&self, daemon: &mut LocalClient, actor: &ActorEnvelope) -> Vec<u8> {
        let attached = self
            .attach_for(
                daemon,
                actor,
                &[ActionRight::SessionView],
                &[AttachmentCapability::ObserveTerminal],
            )
            .await;
        served_the_stream(&attached);
        let request_id = next_request();
        let frame = forwarded_read(
            actor,
            self.subscription(request_id, attached.attachment.attachment_id),
            None,
        );
        drawn(daemon, frame, request_id).await
    }

    /// Attaches a terminal in one of the owner's windows, subscribes it, and returns the screen it
    /// is drawn.
    async fn drawn_in(&self, window: &mut LocalClient) -> Vec<u8> {
        let attached = self
            .attach_in(window, &[AttachmentCapability::ObserveTerminal])
            .await;
        served_the_stream(&attached);
        let request_id = next_request();
        let frame =
            ControlFrame::Request(self.subscription(request_id, attached.attachment.attachment_id));
        drawn(window, frame, request_id).await
    }

    /// A read of the session's retained output from its beginning.
    fn page(&self, request_id: RequestId) -> Request {
        Request {
            request_id,
            method: Method::HistoryPage.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&HistoryPageParams {
                session_id: self.session_id,
                from_cursor: U64::ZERO,
                max_bytes: U64::new(64 * 1024),
            })
            .expect("encodes"),
        }
    }

    /// Forwards a read of the session's retained output for `actor`.
    async fn page_for(
        &self,
        daemon: &mut LocalClient,
        actor: &ActorEnvelope,
    ) -> Result<HistoryPageResult, ProtocolError> {
        let request_id = next_request();
        let frame = forwarded_read(actor, self.page(request_id), None);
        answer(daemon, frame, request_id)
            .await
            .map(|page| page.to_typed().expect("a history page"))
    }

    /// Reads the session's retained output in one of the owner's windows.
    async fn page_in(&self, window: &mut LocalClient) -> Result<HistoryPageResult, ProtocolError> {
        let request_id = next_request();
        let frame = ControlFrame::Request(self.page(request_id));
        answer(window, frame, request_id)
            .await
            .map(|page| page.to_typed().expect("a history page"))
    }

    /// Reports, as a managed root shell's hooks do, that `command` started at `started_at_ms`, and
    /// returns once the worker has recorded it.
    async fn report_command(&mut self, command: &str, started_at_ms: u64) {
        let session_id = self.session_id;
        let (bridge, _) = self.bridge.as_mut().expect("a managed session");
        within(
            "the command's report",
            bridge.send_event(BridgeEvent::CommandBlock(Box::new(
                RootCommandBlockParams {
                    session_id,
                    prompt_generation: PromptGeneration::new(2),
                    command: command.to_owned(),
                    started_at_ms: TimestampMs::new(started_at_ms),
                    duration_ms: Nullable::null(),
                    exit_status: Nullable::null(),
                    cwd: "/tmp/project".to_owned(),
                    cwd_revision: CwdRevision::new(1),
                },
            ))),
        )
        .await
        .expect("reports the command");
        within("the worker's record of the command", async {
            loop {
                if let ToBridge::EventResult { result, .. } =
                    bridge.recv().await.expect("the worker answers")
                    && let EventOutcome::CommandBlockRecorded(_) = *result
                {
                    return;
                }
            }
        })
        .await;
    }

    /// A read of the session's metadata and current state.
    fn session_read(&self, request_id: RequestId) -> Request {
        Request {
            request_id,
            method: Method::SessionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&SessionReadParams {
                session_id: self.session_id,
            })
            .expect("encodes"),
        }
    }

    /// Forwards a session read for `actor`, with the history scope the daemon decided it under
    /// when one travels with it.
    async fn read_for(
        &self,
        daemon: &mut LocalClient,
        actor: &ActorEnvelope,
        history: Option<HistoryScope>,
    ) -> SessionReadResult {
        let request_id = next_request();
        let frame = forwarded_read(actor, self.session_read(request_id), history);
        answer(daemon, frame, request_id)
            .await
            .expect("the session is read")
            .to_typed()
            .expect("a session read")
    }

    /// Reads the session in one of the owner's windows.
    async fn read_in(&self, window: &mut LocalClient) -> SessionReadResult {
        let request_id = next_request();
        let frame = ControlFrame::Request(self.session_read(request_id));
        answer(window, frame, request_id)
            .await
            .expect("the session is read")
            .to_typed()
            .expect("a session read")
    }

    /// Forwards a request for the input lease for `actor`'s attachment.
    async fn acquire_for(
        &self,
        daemon: &mut LocalClient,
        actor: &ActorEnvelope,
        rights: &[ActionRight],
        attachment_id: AttachmentId,
    ) {
        self.forward(
            daemon,
            actor,
            rights,
            Method::InputAcquire,
            &InputAcquireParams {
                session_id: self.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("the lease is granted");
        assert_eq!(self.lease_holder(), Some(attachment_id));
    }

    /// Whether this session still has the attachment.
    fn attached(&self, attachment_id: AttachmentId) -> bool {
        self.runtime
            .session()
            .attachments()
            .iter()
            .any(|summary| summary.attachment_id == attachment_id)
    }

    /// The attachment that holds the input lease, if one does.
    fn lease_holder(&self) -> Option<AttachmentId> {
        self.runtime.session().lease().holder.as_ref().copied()
    }

    /// Announces an authority revision on the daemon's authority connection, and returns once this
    /// worker has installed it.
    ///
    /// A worker inside a dispatch transition answers that the revision is still pending for it, and
    /// the daemon announces it again. So does this.
    async fn revise(&self, authority: &mut LocalClient, revision: u64) {
        let notice = AuthorityRevisionNotice {
            environment_id: self.environment_id,
            revision: AuthorityRevision::new(revision),
            evidence_from: 0,
        };
        let started = tokio::time::Instant::now();
        loop {
            match within(
                "the worker's acknowledgement",
                authority.announce_revision(notice),
            )
            .await
            {
                Ok(acknowledged) => {
                    assert_eq!(acknowledged.revision.get(), revision);
                    return;
                }
                Err(kr_ipc::IpcError::IdentityUnavailable { detail, .. })
                    if detail.starts_with(ErrorCode::ResourceUnavailable.as_str())
                        && started.elapsed() < LIVENESS_DEADLINE =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(error) => panic!("the worker installs revision {revision}: {error}"),
            }
        }
    }

    /// Records an undispatched intent of `actor` in the session's journal, and returns its action.
    ///
    /// It is written into the journal directly because who may take it back is the question here,
    /// and an intent accepted and never dispatched is the state a cancellation reaches.
    fn intend(&self, actor: &str, number: u8) -> ActionId {
        let action_id = ActionId::new(Uuid::from_bytes([number; 16]));
        let now_ms = kr_ipc::now_ms();
        let mut session = self.runtime.session();
        session
            .journal_mut()
            .expect("a journal")
            .accept(&Submission {
                actor_id: ActorId::new(actor).expect("an actor"),
                action_id,
                method: Method::AgentApprovalRespond.into(),
                method_version: MethodVersion::V1,
                payload_digest: Digest256::from_bytes([number; 32]),
                subject_digest: Digest256::from_bytes([number.wrapping_add(128); 32]),
                intent: vec![0xa0],
                accepted_deadline_ms: Some(TimestampMs::new(now_ms.get() + 120_000)),
                now_ms,
            })
            .expect("the intent is recorded");
        action_id
    }

    /// What the session's journal records about one of `actor`'s actions now.
    fn receipt(&self, actor: &str, action_id: ActionId) -> Receipt {
        let session = self.runtime.session();
        session
            .journal()
            .expect("a journal")
            .read(ActorId::new(actor).expect("an actor"), action_id)
            .expect("reads")
            .expect("a receipt")
    }

    fn close(&self) {
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        if let Some((_, serving)) = self.bridge.as_ref() {
            serving.abort();
        }
    }
}

async fn wired(script: &str) -> Wired {
    wired_in(script, ShellMode::NativeCompat).await
}

/// A managed session, whose root shell's bridge this test plays.
///
/// What the shell's private hooks report reaches the worker over that bridge, so a test that needs
/// a command block reports one there, exactly as a managed root shell would.
async fn managed() -> Wired {
    wired_in("exec cat", ShellMode::Managed).await
}

async fn wired_in(script: &str, shell_mode: ShellMode) -> Wired {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(script),
        shell_mode,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
    };
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");

    // A managed session's bridge endpoint is in its own owner-only runtime directory, on the
    // internal disk, and it is bound before the shell starts.
    let bridge_endpoint = (shell_mode == ShellMode::Managed).then(|| {
        HostEndpoint::open_for_session(
            environment.runtime_root(),
            environment.runtime_dir(),
            session_id,
        )
        .expect("binds the bridge")
    });
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    if bridge_endpoint.is_some() {
        session.install_fence(FenceDriver::new(
            session_id,
            LeaseView::unheld(InputLeaseEpoch::new(0)),
            Arc::new(SystemContinuousClock::new()),
        ));
    }
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let bridge = match bridge_endpoint {
        Some(host_endpoint) => Some(bridged(&runtime, host_endpoint, session_id, process).await),
        None => None,
    };
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
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Wired {
        _temp: temp,
        _service: service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        controller: Arc::new(controller),
        boot,
        bridge,
    }
}

/// Registers this test as the managed session's root shell, and returns its side of the bridge.
///
/// The reference bridge runs in this process, so this process is the root shell the worker expects
/// on the endpoint. The integration's hooks are then reported live, which is when a managed root
/// shell starts reporting what its commands do.
async fn bridged(
    runtime: &Arc<SessionRuntime>,
    host_endpoint: HostEndpoint,
    session_id: SessionId,
    process: kr_protocol::identity::ProcessStartIdentity,
) -> (ScriptedBridge, tokio::task::JoinHandle<()>) {
    let address = host_endpoint.address().clone();
    let secret = host_endpoint.secret().clone();
    let expectation = WorkerExpectation {
        session_id,
        root_process: process.clone(),
        supported_editor_abis: vec!["zle-5.9".to_owned()],
        supported_integration_versions: vec!["1".to_owned()],
        launched_package: None,
        already_registered: false,
        gesture: EofGesture::default(),
    };
    let serving = tokio::spawn(
        kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(runtime),
            host_endpoint,
            expectation,
        )
        .serve(),
    );
    let shell = ReferenceShell::new(ShellKind::Zsh, "/bin/cat", "5.9", "zle-5.9");
    let hello = qualified_hello(&shell, session_id, &address, process, &secret).expect("a hello");
    let (mut bridge, outcome) = within(
        "the bridge's registration",
        ScriptedBridge::connect(&address, &hello),
    )
    .await
    .expect("connects");
    assert!(
        matches!(outcome, HandshakeOutcome::Accepted(_)),
        "a qualified root shell registers: {outcome:?}"
    );
    within(
        "the hooks' report",
        bridge.send_event(BridgeEvent::HooksActivated(HooksActivated {
            session_id,
            prompt_generation: PromptGeneration::new(1),
        })),
    )
    .await
    .expect("reports the hooks live");
    (bridge, serving)
}

// ---------------------------------------------------------------------------------------------
// Who the local owner is
// ---------------------------------------------------------------------------------------------

/// The one question every other test here asks the worker: the local ingress, and no grant.
///
/// The daemon vouches for both, and neither decides it alone. A caller heard on a local socket can
/// act under a grant, and a caller that reached the host any other way is held to a grant even
/// when it names none.
#[test]
fn the_local_owner_is_the_local_ingress_holding_no_grant() {
    assert!(Caller::local(ActorId::new("local:501").expect("an actor")).is_local_owner());
    for ingress in ActorIngress::ALL.iter().copied() {
        for grant_id in [
            Nullable::null(),
            Nullable::some(GrantId::new(Uuid::from_bytes([7; 16]))),
        ] {
            let under_a_grant = grant_id.is_present();
            let caller = Caller::forwarded(
                &ActorEnvelope {
                    ingress,
                    grant_id,
                    ..the_owner_forwarded()
                },
                &CanonicalSet::new(),
            );
            assert_eq!(
                caller.is_local_owner(),
                ingress == ActorIngress::LocalIpc && !under_a_grant,
                "{ingress:?}, under a grant: {under_a_grant}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.50: the screen an attachment is drawn
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.50: a caller the daemon heard on its local socket, acting under a grant, is drawn the
/// screen that is showing and never the buffer behind it.
///
/// Section 10's live-screen exception is the most of the screen a grant is drawn, and the socket
/// the daemon heard the caller on does not change what the caller holds, which is a grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_under_a_grant_is_drawn_the_live_screen_alone() {
    let wired = wired(TWO_BUFFERS).await;
    common::produced(&wired.runtime, b"kr-the-application-screen\r\n").await;

    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let drawn = wired.drawn_for(&mut proxy, &local_under_a_grant(1)).await;
    assert!(
        !carries(&drawn, BEHIND),
        "a caller under a grant is drawn nothing of the buffer that is not showing: {}",
        printable(&drawn)
    );

    drop(proxy);
    wired.close();
}

/// KR-REQ-10.50: the local owner is drawn the whole screen on either socket, and a paired device
/// the screen that is showing, as each always was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_is_drawn_the_whole_screen_and_a_device_the_live_screen() {
    let wired = wired(TWO_BUFFERS).await;
    common::produced(&wired.runtime, b"kr-the-application-screen\r\n").await;

    // The owner in one of its own windows. It holds no grant to be narrowed by, so it is drawn the
    // buffer behind the application as well as the one in front.
    let mut window = wired.window().await;
    let drawn = wired.drawn_in(&mut window).await;
    assert!(
        carries(&drawn, BEHIND),
        "the owner is drawn the buffer that is not showing too: {}",
        printable(&drawn)
    );

    // The same owner as the daemon forwards it. Another socket, the same caller.
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let drawn = wired.drawn_for(&mut proxy, &the_owner_forwarded()).await;
    assert!(
        carries(&drawn, BEHIND),
        "the owner the daemon forwards is drawn the buffer that is not showing too: {}",
        printable(&drawn)
    );

    // A paired device is drawn the screen that is showing, and nothing behind it.
    let mut phone = wired.daemon(ControllerConnectionRole::Proxy).await;
    let drawn = wired.drawn_for(&mut phone, &device(1)).await;
    assert!(
        !carries(&drawn, BEHIND),
        "a device is drawn nothing of the buffer that is not showing: {}",
        printable(&drawn)
    );

    drop((window, proxy, phone));
    wired.close();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.49: who is served the session's retained output
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.49: a caller the daemon heard on its local socket, acting under a grant, is refused the
/// session's retained output, and so is a paired device.
///
/// A history page is a byte range and a grant's history scope is a moment in time, so nothing on
/// this path can narrow one to the other, and a host that cannot narrow content to a grant refuses
/// it rather than serving more than the grant allows. The daemon already refuses a paired device
/// this read; the worker holds every caller but the local owner to the same rule, whichever socket
/// it came in on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_under_a_grant_is_refused_the_retained_history() {
    let wired = wired(TWO_BUFFERS).await;
    common::produced(&wired.runtime, b"kr-the-application-screen\r\n").await;

    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let refused = wired
        .page_for(&mut proxy, &local_under_a_grant(1))
        .await
        .expect_err("a caller under a grant is not served the retained output");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("retained history"),
        "the refusal says what it withheld: {refused:?}"
    );

    // A paired device the daemon forwarded anyway is refused here in the same words.
    let mut phone = wired.daemon(ControllerConnectionRole::Proxy).await;
    let refused = wired
        .page_for(&mut phone, &device(1))
        .await
        .expect_err("a device is not served the retained output");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("retained history"), "{refused:?}");

    drop((proxy, phone));
    wired.close();
}

/// KR-REQ-10.49: the local owner reads the session's retained output on either socket, as it
/// always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_reads_the_retained_history_on_either_socket() {
    let wired = wired(TWO_BUFFERS).await;
    common::produced(&wired.runtime, b"kr-the-application-screen\r\n").await;

    // In one of its own windows, it reads everything the application wrote, the line the buffer
    // behind the application holds included.
    let mut window = wired.window().await;
    let page = wired
        .page_in(&mut window)
        .await
        .expect("the owner reads the retained output");
    assert!(
        carries(page.bytes.as_slice(), BEHIND),
        "{}",
        printable(page.bytes.as_slice())
    );

    // And as the daemon forwards it.
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let page = wired
        .page_for(&mut proxy, &the_owner_forwarded())
        .await
        .expect("the owner the daemon forwards reads the retained output");
    assert!(
        carries(page.bytes.as_slice(), BEHIND),
        "{}",
        printable(page.bytes.as_slice())
    );

    drop((window, proxy));
    wired.close();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.49: the last command a session read carries
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.49: a caller the daemon heard on its local socket, acting under a grant, is given a
/// session's last command only when a history scope came with the read and reaches back to when
/// the command started, and so is a paired device.
///
/// The command block is a command line and the directory it ran in: what a person typed, and
/// where. That is retained history, which the shared filter decides by the moment it was produced,
/// and a caller with no scope to decide it by is given none of it. The rest of the read is
/// metadata and is served either way. The daemon narrows a paired device's own read by the same
/// rule before it answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_under_a_grant_reads_the_last_command_only_inside_its_scope() {
    let mut wired = managed().await;
    let started_at_ms = kr_ipc::now_ms().get();
    wired.report_command("cargo test", started_at_ms).await;

    let caller = local_under_a_grant(1);
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    // No scope came with the read, so nothing here can place the command inside the grant.
    let read = wired.read_for(&mut proxy, &caller, None).await;
    assert!(
        read.last_command_block.0.is_none(),
        "a caller under a grant with no scope is given no command: {read:?}"
    );
    assert_eq!(
        read.session.session_id, wired.session_id,
        "and the rest of the read is served"
    );
    // A scope whose history begins after the command started, and one that retains no history at
    // all: the live screen it includes is not a command line.
    for (history, what) in [
        (
            reaching(Some(started_at_ms + 1)),
            "begins after the command",
        ),
        (reaching(None), "retains no history"),
    ] {
        let read = wired.read_for(&mut proxy, &caller, Some(history)).await;
        assert!(
            read.last_command_block.0.is_none(),
            "a scope that {what} is given no command: {read:?}"
        );
    }
    // A scope that reaches back to when the command started is given it.
    let read = wired
        .read_for(&mut proxy, &caller, Some(reaching(Some(started_at_ms))))
        .await;
    assert_eq!(
        read.last_command_block.0.map(|block| block.command),
        Some("cargo test".to_owned())
    );

    // A paired device the daemon forwarded with no scope is given no command either.
    let mut phone = wired.daemon(ControllerConnectionRole::Proxy).await;
    let read = wired.read_for(&mut phone, &device(1), None).await;
    assert!(read.last_command_block.0.is_none(), "{read:?}");

    drop((proxy, phone));
    wired.close();
}

/// KR-REQ-10.49: the local owner reads the last command on either socket, as it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_reads_the_last_command_on_either_socket() {
    let mut wired = managed().await;
    wired
        .report_command("cargo test", kr_ipc::now_ms().get())
        .await;

    // In one of its own windows.
    let mut window = wired.window().await;
    let read = wired.read_in(&mut window).await;
    assert_eq!(
        read.last_command_block.0.map(|block| block.command),
        Some("cargo test".to_owned())
    );

    // And as the daemon forwards it.
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let read = wired
        .read_for(&mut proxy, &the_owner_forwarded(), None)
        .await;
    assert_eq!(
        read.last_command_block.0.map(|block| block.command),
        Some("cargo test".to_owned())
    );

    drop((window, proxy));
    wired.close();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.41: whose attachment a caller may detach
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.41: a caller the daemon heard on its local socket, acting under a grant, detaches the
/// attachments its own connection made and nothing else.
///
/// An attachment identifier is not permission. Detaching another window's attachment is something
/// the owner does on purpose; a caller under a grant is somebody else, whichever socket it came in
/// on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_under_a_grant_detaches_only_what_its_own_connection_made() {
    let wired = wired("sleep 120").await;
    let mut window = wired.window().await;
    let owners = wired
        .attach_in(&mut window, &[AttachmentCapability::ObserveTerminal])
        .await
        .attachment
        .attachment_id;

    let caller = local_under_a_grant(1);
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let refused = wired
        .forward(
            &mut proxy,
            &caller,
            &[ActionRight::SessionView],
            Method::SessionDetach,
            &detaching(owners),
        )
        .await
        .expect_err("a caller under a grant cannot detach the owner's window");
    assert_eq!(
        refused.code,
        ErrorCode::AmbiguousAttachment,
        "the refusal names the attachment: {refused:?}"
    );
    assert!(
        wired.attached(owners),
        "and the owner's window is still attached"
    );

    // Its own attachment it may detach.
    let its_own = wired
        .attach_for(
            &mut proxy,
            &caller,
            &[ActionRight::SessionView],
            &[AttachmentCapability::ObserveTerminal],
        )
        .await
        .attachment
        .attachment_id;
    wired
        .forward(
            &mut proxy,
            &caller,
            &[ActionRight::SessionView],
            Method::SessionDetach,
            &detaching(its_own),
        )
        .await
        .expect("a caller detaches what its own connection made");
    assert!(!wired.attached(its_own));

    drop((window, proxy));
    wired.close();
}

/// KR-REQ-10.41: the local owner detaches another window's attachment on either socket, and a
/// paired device does not, as each always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_detaches_another_windows_attachment_and_a_device_does_not() {
    let wired = wired("sleep 120").await;
    let mut window = wired.window().await;
    let first = wired
        .attach_in(&mut window, &[AttachmentCapability::ObserveTerminal])
        .await
        .attachment
        .attachment_id;
    let second = wired
        .attach_in(&mut window, &[AttachmentCapability::ObserveTerminal])
        .await
        .attachment
        .attachment_id;

    // A paired device is refused another connection's attachment.
    let mut phone = wired.daemon(ControllerConnectionRole::Proxy).await;
    let refused = wired
        .forward(
            &mut phone,
            &device(1),
            &[ActionRight::SessionView],
            Method::SessionDetach,
            &detaching(first),
        )
        .await
        .expect_err("a device cannot detach the owner's window");
    assert_eq!(refused.code, ErrorCode::AmbiguousAttachment, "{refused:?}");
    assert!(wired.attached(first));

    // The owner as the daemon forwards it detaches another window's attachment.
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    wired
        .forward(
            &mut proxy,
            &the_owner_forwarded(),
            &[],
            Method::SessionDetach,
            &detaching(first),
        )
        .await
        .expect("the owner the daemon forwards detaches another window's attachment");
    assert!(!wired.attached(first));

    // And so does the owner in another of its own windows.
    let mut other_window = wired.window().await;
    within(
        "the detach",
        other_window.mutate(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &detaching(second),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner detaches another window's attachment");
    assert!(!wired.attached(second));

    drop((window, phone, proxy, other_window));
    wired.close();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.45: whose input lease an authority revision fences
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.45: an authority revision takes the input lease from a caller the daemon heard on its
/// local socket, acting under a grant.
///
/// A revision replaces the authority a grant carries, and the lease is what lets its holder's
/// keystrokes reach the application, so the lease goes with the authority. Which socket the grant
/// was presented on is no part of that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_takes_the_lease_from_a_local_caller_under_a_grant() {
    let wired = wired("sleep 120").await;
    let mut authority = wired.daemon(ControllerConnectionRole::Authority).await;

    let caller = local_under_a_grant(1);
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let attachment_id = wired
        .attach_for(
            &mut proxy,
            &caller,
            WATCH_AND_TYPE,
            &[
                AttachmentCapability::ObserveTerminal,
                AttachmentCapability::Input,
            ],
        )
        .await
        .attachment
        .attachment_id;
    wired
        .acquire_for(&mut proxy, &caller, WATCH_AND_TYPE, attachment_id)
        .await;

    wired.revise(&mut authority, 2).await;
    assert_eq!(
        wired.lease_holder(),
        None,
        "the revision took the lease from the grant it replaced"
    );

    drop((authority, proxy));
    wired.close();
}

/// KR-REQ-10.45: an authority revision takes a paired device's lease and leaves the local owner's
/// on either socket, as it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_takes_a_devices_lease_and_leaves_the_local_owners() {
    let wired = wired("sleep 120").await;
    let mut authority = wired.daemon(ControllerConnectionRole::Authority).await;
    let observe_and_type = [
        AttachmentCapability::ObserveTerminal,
        AttachmentCapability::Input,
    ];

    // A paired device's lease goes with the authority its grant carried.
    let mut phone = wired.daemon(ControllerConnectionRole::Proxy).await;
    let phones = wired
        .attach_for(&mut phone, &device(1), WATCH_AND_TYPE, &observe_and_type)
        .await
        .attachment
        .attachment_id;
    wired
        .acquire_for(&mut phone, &device(1), WATCH_AND_TYPE, phones)
        .await;
    wired.revise(&mut authority, 2).await;
    assert_eq!(wired.lease_holder(), None, "the device's lease went");

    // The owner's stays, in one of its own windows. No revision replaces the operating-system
    // identity it rests on.
    let mut window = wired.window().await;
    let owners = wired
        .attach_in(&mut window, &observe_and_type)
        .await
        .attachment
        .attachment_id;
    common::take_the_keys(&mut window, wired.environment_id, wired.session_id, owners).await;
    assert_eq!(wired.lease_holder(), Some(owners));
    wired.revise(&mut authority, 3).await;
    assert_eq!(
        wired.lease_holder(),
        Some(owners),
        "the owner's lease stays"
    );

    // And as the daemon forwards it.
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let forwarded = wired
        .attach_for(&mut proxy, &the_owner_forwarded(), &[], &observe_and_type)
        .await
        .attachment
        .attachment_id;
    wired
        .acquire_for(&mut proxy, &the_owner_forwarded(), &[], forwarded)
        .await;
    wired.revise(&mut authority, 4).await;
    assert_eq!(
        wired.lease_holder(),
        Some(forwarded),
        "the lease of the owner the daemon forwards stays"
    );

    drop((authority, phone, window, proxy));
    wired.close();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.46: whose intent a caller may cancel
// ---------------------------------------------------------------------------------------------

/// KR-REQ-23.46: a caller the daemon heard on its local socket, acting under a grant, cancels its
/// own undispatched intent and not another actor's.
///
/// Section 23 reaches another actor's intent only under host-owner authority, and at a worker that
/// is the operating-system user its listener authenticated. The daemon checks `host.manage` before
/// it forwards a cancellation of another actor's intent, so the grant here carries it: what the
/// worker decides is who the caller is, and a caller under a grant is not that user whichever
/// socket it came in on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_caller_under_a_grant_cancels_its_own_intent_and_no_other() {
    let wired = wired("sleep 120").await;
    let anothers = wired.intend(ANOTHER_ACTOR, 1);
    let its_own = wired.intend(UNDER_A_GRANT, 2);

    let caller = local_under_a_grant(1);
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    let refused = wired
        .forward(
            &mut proxy,
            &caller,
            &[ActionRight::HostManage],
            Method::ActionCancel,
            &cancelling(anothers),
        )
        .await
        .expect_err("a caller under a grant cannot cancel another actor's intent");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_eq!(
        wired.receipt(ANOTHER_ACTOR, anothers).state,
        ReceiptState::Accepted,
        "and that intent is still pending"
    );

    // Its own intent it may take back.
    wired
        .forward(
            &mut proxy,
            &caller,
            &[ActionRight::HostManage],
            Method::ActionCancel,
            &cancelling(its_own),
        )
        .await
        .expect("a caller cancels its own undispatched intent");
    cancelled(&wired.receipt(UNDER_A_GRANT, its_own));

    drop(proxy);
    wired.close();
}

/// KR-REQ-23.46: the local owner cancels another actor's intent on either socket, and a paired
/// device does not, whatever its grant carries, as each always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_cancels_another_actors_intent_and_a_device_does_not() {
    let wired = wired("sleep 120").await;
    let first = wired.intend(ANOTHER_ACTOR, 1);
    let second = wired.intend(ANOTHER_ACTOR, 2);

    // A paired device is refused another actor's intent.
    let mut phone = wired.daemon(ControllerConnectionRole::Proxy).await;
    let refused = wired
        .forward(
            &mut phone,
            &device(1),
            &[ActionRight::HostManage],
            Method::ActionCancel,
            &cancelling(first),
        )
        .await
        .expect_err("a device cannot cancel another actor's intent");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_eq!(
        wired.receipt(ANOTHER_ACTOR, first).state,
        ReceiptState::Accepted
    );

    // The owner as the daemon forwards it cancels another actor's intent.
    let mut proxy = wired.daemon(ControllerConnectionRole::Proxy).await;
    wired
        .forward(
            &mut proxy,
            &the_owner_forwarded(),
            &[],
            Method::ActionCancel,
            &cancelling(first),
        )
        .await
        .expect("the owner the daemon forwards cancels another actor's intent");
    cancelled(&wired.receipt(ANOTHER_ACTOR, first));

    // And so does the owner in one of its own windows.
    let mut window = wired.window().await;
    within(
        "the cancellation",
        window.mutate(
            Method::ActionCancel,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &cancelling(second),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner cancels another actor's intent");
    cancelled(&wired.receipt(ANOTHER_ACTOR, second));

    drop((phone, proxy, window));
    wired.close();
}
