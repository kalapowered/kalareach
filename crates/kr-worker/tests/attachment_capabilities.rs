//! What an attachment is granted, against the grant the device holds.
//!
//! Requirement rows: KR-REQ-08.68 and KR-REQ-23.35 for the paired-device ingress, and KR-REQ-10.41
//! for the rule those two rest on. Section 8 says an attachment's granted capabilities are the
//! requested ones intersected with the actor's rights; section 10 says capabilities describe
//! feasibility and never authority, so asking for one is not holding it. The worker is where an
//! attachment is admitted, so the intersection is made here, out of the rights the host checked
//! the request against.
//!
//! The four grants are the four default session roles of section 25, written as the rights they
//! compile to: a role is a way of choosing rights, and the host decides from the rights alone.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActorId, BuildId, ConnectionId, ControllerGeneration, DeviceId, GrantId, RequestId,
    SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64, Uuid};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The four default session roles of section 25, as the rights they compile to.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];
const REVIEWER: &[ActionRight] = &[ActionRight::SessionView, ActionRight::FilesRead];
const CONTROLLER: &[ActionRight] = &[
    ActionRight::SessionView,
    ActionRight::FilesRead,
    ActionRight::TerminalInput,
    ActionRight::TerminalGeometry,
    ActionRight::AgentPrompt,
    ActionRight::AgentCancel,
    ActionRight::AgentApprovalRespond,
    ActionRight::QuestionRespond,
];
const OWNER: &[ActionRight] = &[
    ActionRight::SessionView,
    ActionRight::FilesRead,
    ActionRight::TerminalInput,
    ActionRight::TerminalGeometry,
    ActionRight::TerminalGeometryTransfer,
    ActionRight::TerminalPalette,
    ActionRight::AgentPrompt,
    ActionRight::AgentCancel,
    ActionRight::AgentApprovalRespond,
    ActionRight::QuestionRespond,
    ActionRight::SessionRename,
    ActionRight::SessionClose,
    ActionRight::SessionShare,
];

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn rights(of: &[ActionRight]) -> CanonicalSet<ActionRight> {
    of.iter().copied().collect()
}

/// A terminal attachment asking for every capability there is.
fn asking_for_everything(session_id: SessionId) -> SessionAttachParams {
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: AttachmentCapability::ALL.iter().copied().collect(),
    }
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

    /// Connects as the control daemon and proves the generation this worker accepts.
    async fn daemon(&self) -> LocalClient {
        let mut daemon = LocalClient::connect(&self.endpoint, LocalClientKind::Controller, build())
            .await
            .expect("connects as the daemon");
        let identity = Arc::clone(&self.controller);
        let boot = self.boot.clone();
        daemon
            .present_generation(move |nonce| {
                identity
                    .generation_token(ControllerGeneration::new(1), &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await
            .expect("the worker accepts the generation");
        daemon
    }

    /// Forwards one attach for a paired device acting under `grant_rights`.
    async fn attach_as_device(
        &self,
        daemon: &mut LocalClient,
        request_id: u64,
        grant_rights: &CanonicalSet<ActionRight>,
    ) -> SessionAttachResult {
        self.forward_as_device(
            daemon,
            request_id,
            grant_rights,
            Method::SessionAttach,
            &ParamsValue::from_typed(&asking_for_everything(self.session_id)).expect("encodes"),
        )
        .await
        .expect("the attach is admitted")
        .to_typed()
        .expect("an attachment")
    }

    /// Forwards one mutation for a paired device acting under `grant_rights`.
    async fn forward_as_device(
        &self,
        daemon: &mut LocalClient,
        request_id: u64,
        grant_rights: &CanonicalSet<ActionRight>,
        method: Method,
        params: &ParamsValue,
    ) -> std::result::Result<ParamsValue, kr_protocol::error::ProtocolError> {
        let envelope = ActorEnvelope {
            actor_id: ActorId::new("device:a-test-phone").expect("an actor"),
            ingress: ActorIngress::PairedDevice,
            device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([9; 16]))),
            grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([8; 16]))),
            grant_revision: Nullable::some(kr_protocol::ids::AuthorityRevision::new(1)),
            controller_generation: ControllerGeneration::new(1),
            connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
        };
        let mutation = MutationRequest {
            request_id: RequestId::new(request_id),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            target: self.target(),
            params: params.clone(),
            grant_id: Nullable::null(),
            expected: ParamsValue::from_typed(&std::collections::BTreeMap::<String, u64>::new())
                .expect("encodes"),
            action_window_id: kr_protocol::ids::ActionWindowId::new("forwarded")
                .expect("a window identifier"),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
        };
        daemon
            .forward(
                &mutation,
                &envelope,
                grant_rights,
                U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000),
            )
            .await
            .expect("the forward reaches the worker")
    }
}

async fn wired(script: &str) -> Wired {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), script.to_owned()],
            cwd: "/".to_owned(),
            environment: vec![
                ("TERM".to_owned(), "xterm-256color".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("PS1".to_owned(), String::new()),
            ],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
    };
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
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");

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
    }
}

/// KR-REQ-08.68, KR-REQ-23.35: every capability against the four grants a person issues.
///
/// Each device asks for all four capabilities. What it receives is the intersection with its own
/// rights: observation for a viewer and a reviewer, everything for a controller and an owner. The
/// request is identical in all four cases, so the only thing deciding the answer is the grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_devices_attachment_is_what_it_asked_for_intersected_with_its_grant() {
    let wired = wired("sleep 120").await;
    let mut daemon = wired.daemon().await;
    let observation: CanonicalSet<AttachmentCapability> = [
        AttachmentCapability::ObserveTerminal,
        AttachmentCapability::ObserveSemantic,
    ]
    .into_iter()
    .collect();
    let everything: CanonicalSet<AttachmentCapability> =
        AttachmentCapability::ALL.iter().copied().collect();

    for (request_id, role, name, expected) in [
        (1, VIEWER, "viewer", &observation),
        (2, REVIEWER, "reviewer", &observation),
        (3, CONTROLLER, "controller", &everything),
        (4, OWNER, "owner", &everything),
    ] {
        let attached = wired
            .attach_as_device(&mut daemon, request_id, &rights(role))
            .await;
        assert_eq!(
            &attached.attachment.granted, expected,
            "a {name} grant receives what its rights carry, not what it asked for"
        );
    }

    drop(daemon);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-10.41: an attachment identifier is never permission on its own.
///
/// A grant that carries nothing at all asks for everything and receives nothing. The attachment
/// still exists, because section 8 separates observing a session from owning its size and holding
/// its input: what it cannot do is act.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_grant_carries_nothing_receives_an_attachment_that_can_do_nothing() {
    let wired = wired("sleep 120").await;
    let mut daemon = wired.daemon().await;

    let attached = wired
        .attach_as_device(&mut daemon, 1, &CanonicalSet::new())
        .await;
    assert!(
        attached.attachment.granted.is_empty(),
        "asking is not holding: {:?}",
        attached.attachment.granted
    );

    // And the worker refuses the operations the capability would have carried. The attachment
    // identifier is the only thing this request has, which is section 10's point: it is not
    // permission.
    let refused = wired
        .forward_as_device(
            &mut daemon,
            2,
            &CanonicalSet::new(),
            Method::InputAcquire,
            &ParamsValue::from_typed(&kr_protocol::input::InputAcquireParams {
                session_id: wired.session_id,
                attachment_id: attached.attachment.attachment_id,
                expected_epoch: Nullable::null(),
            })
            .expect("encodes"),
        )
        .await
        .expect_err("an attachment without the input capability holds no lease");
    assert!(
        refused
            .message
            .contains(AttachmentCapability::Input.as_str()),
        "the refusal names the capability the attachment does not hold: {refused:?}"
    );
    assert!(
        !wired.runtime.session().lease().holder.is_present(),
        "and the lease is still unheld"
    );

    drop(daemon);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}

/// KR-REQ-08.68: the local owner is unchanged.
///
/// A caller on the worker's own socket holds no grant: its peer credentials already proved it is
/// this user, and there is nothing to narrow it by. It receives exactly what it asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_attachment_receives_exactly_what_it_asked_for() {
    let wired = wired("sleep 120").await;
    let mut local = LocalClient::connect(&wired.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let params = asking_for_everything(wired.session_id);
    let attached: SessionAttachResult = local
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            wired.target(),
            &params,
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach is admitted")
        .to_typed()
        .expect("an attachment");
    assert_eq!(
        attached.attachment.granted, params.requested,
        "a local owner attachment is not narrowed by a grant it does not hold"
    );

    drop(local);
    wired
        .runtime
        .close(ClosureReason::CloseRequested)
        .1
        .release();
}
