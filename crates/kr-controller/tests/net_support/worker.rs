//! A worker in this process, on a host tree a daemon of it adopts.
//!
//! The worker is the product's own: a session service over a real terminal, its question ledger,
//! its broker and its admission of every caller, serving a real local endpoint with its journal and
//! its spool. It is recorded the way a daemon records a worker it adopts, a registry row and a
//! published descriptor, so a daemon started afterwards reaches it at its start. A suite that needs
//! an agent registers one on the worker's broker with a transport of its own, which is the only
//! thing a test supplies in place of an upstream.

use std::sync::Arc;

use kr_controller::registry::{LaunchPhase, Registry, WorkerRecord};
use kr_controller::service::Clocks;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::broker::{
    ActionProvenance, BrokerGrant, BrokerGrants, InstanceCapabilityIdentity,
    InstanceCapabilityRecord, InstanceCapabilityState, InstanceEvidenceSource,
    InstanceInvalidation, IntegrationMode,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, AuthorityRevision, BrokerBindingId, BuildId,
    CapabilityId, CapabilityRevision, ConnectionId, ControllerGeneration, EnvironmentId, PluginId,
    PublisherId, SessionEpoch, SessionId, UpstreamRequestId,
};
use kr_protocol::method::Method;
use kr_protocol::question::{Question, QuestionCreateParams, QuestionKind};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_protocol::worker::WorkerDescriptor;
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, PendingTransmission, TransportHandle,
    UpstreamBody, UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

use super::Host;

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn now() -> TimestampMs {
    kr_ipc::now_ms()
}

/// A worker for one session, in this process, on an environment tree a daemon of it serves.
pub struct Worker {
    pub service: Arc<WorkerService>,
    pub session_id: SessionId,
    _runtime: Arc<SessionRuntime>,
}

impl Worker {
    /// Starts a worker for one session and records it the way a daemon records one it adopts: a
    /// registry row and a published descriptor. A daemon started afterwards reaches it at its
    /// start. No daemon may be running on the tree while this runs.
    pub async fn start(tree: &kr_ipc::testing::TempHost, display: u64) -> Self {
        Self::start_as(tree, display, false, "exec cat").await
    }

    /// As [`Self::start`], for a session whose application is `script`, a POSIX shell script.
    pub async fn start_running(
        tree: &kr_ipc::testing::TempHost,
        display: u64,
        script: &str,
    ) -> Self {
        Self::start_as(tree, display, false, script).await
    }

    /// As [`Self::start`], for a session the registry also holds an open reservation of, as it does
    /// for every session a daemon creates. What a share or an offer of a session tells a device
    /// depends on that: a session with no reservation is not one the host can tell a device about.
    pub async fn start_reserved(tree: &kr_ipc::testing::TempHost, display: u64) -> Self {
        Self::start_as(tree, display, true, "exec cat").await
    }

    async fn start_as(
        tree: &kr_ipc::testing::TempHost,
        display: u64,
        reserved: bool,
        script: &str,
    ) -> Self {
        let environment = tree.environment();
        let environment_id = tree.environment_id();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let controller_key = {
            let store = open_store_in(&environment.secrets_dir()).expect("a secret store");
            *ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                .expect("the daemon's identity")
                .public_key()
        };
        let (session_id, display_number) = if reserved {
            let mut registry = Registry::open(environment.registry_database(), environment_id)
                .expect("the registry");
            let admitted = registry
                .reserve(
                    &kr_protocol::ids::ActorId::new("local:501").expect("an actor"),
                    kr_ipc::new_uuid(),
                    Digest256::from_bytes([0x5e; 32]),
                    &[0xa0],
                    now(),
                )
                .expect("the session is reserved");
            registry
                .set_phase(admitted.reservation.reservation_id, LaunchPhase::Live)
                .expect("the session is live");
            assert_eq!(
                admitted.reservation.display_number,
                DisplayNumber::new(display),
                "sessions are reserved in the order their workers start"
            );
            (
                admitted.reservation.session_id,
                admitted.reservation.display_number,
            )
        } else {
            (
                SessionId::new(kr_ipc::new_uuid()),
                DisplayNumber::new(display),
            )
        };
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
        let journal_path = environment.journal_database(session_id);
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent).expect("the journal directory");
        }
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number,
            shell: kr_worker::testing::posix_script(script),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(journal_path.clone()),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the shell");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
        let endpoint = environment
            .worker_endpoint(display_number)
            .expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let public_key = *identity.public_key();
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                identity,
                endpoint.clone(),
                ServiceBinding {
                    environment_id,
                    boot_identity: boot.clone(),
                    controller_public_key: controller_key,
                    controller_generation: ControllerGeneration::new(1),
                    journal_path: Some(journal_path),
                    build_id: build(),
                },
            )
            .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        let mut registry =
            Registry::open(environment.registry_database(), environment_id).expect("the registry");
        registry
            .adopt_worker(
                &WorkerRecord {
                    session_id,
                    display_number,
                    public_key,
                    process_identity: process.clone(),
                    endpoint: endpoint.as_text(),
                    profile: WorkerProfile::HeadlessUser,
                    state: SessionState::Live,
                    acknowledged_revision: AuthorityRevision::new(0),
                },
                // A headless worker is bound to no desktop.
                Some(&kr_protocol::identity::DesktopBinding::none()),
            )
            .expect("the worker is recorded");
        drop(registry);
        kr_ipc::descriptor::publish(
            &environment,
            &WorkerDescriptor {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number,
                boot_identity: boot,
                process_start_identity: process,
                protocol_version: PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: public_key,
                worker_profile: WorkerProfile::HeadlessUser,
                published_at_ms: now(),
            },
        )
        .expect("the worker's descriptor is published");
        Self {
            service,
            session_id,
            _runtime: runtime,
        }
    }

    /// The session's runtime, for a suite that stops the journal's next commit.
    pub fn runtime(&self) -> &Arc<SessionRuntime> {
        &self._runtime
    }

    /// How many attachments the session holds now.
    pub fn attachments(&self) -> usize {
        self._runtime.session().attachments().len()
    }

    /// Detaches every attachment the session holds, as the session does for one it ends, so that
    /// each attachment's subscriber is told it was detached.
    pub fn detach_attachments(&self) {
        let mut session = self._runtime.session();
        for attachment in session.attachments() {
            session
                .detach(attachment.attachment_id)
                .expect("the attachment is held");
        }
    }

    /// The action target of this session.
    pub fn target(&self, environment_id: EnvironmentId) -> ActionTarget {
        ActionTarget {
            environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Asks a question from inside the session, as a verified source bound to it does.
    pub fn ask(&self, request: &str) -> Question {
        self.service
            .questions()
            .create(
                &kr_worker::questions::VerifiedSource {
                    process: kr_ipc::identity::current_process_start_identity()
                        .expect("a process identity"),
                    executable: Some("/bin/agent".to_owned()),
                    session_member: true,
                    ancestry: true,
                    launch_channel: true,
                    connection_id: ConnectionId::new(kr_ipc::new_uuid()),
                },
                &QuestionCreateParams {
                    session_id: self.session_id,
                    request_id: request.to_owned(),
                    agent_name: Nullable::some("an agent".to_owned()),
                    context: "the release is tagged".to_owned(),
                    question: format!("Publish the release ({request})?"),
                    kind: QuestionKind::Confirm,
                    choices: Vec::new(),
                    requested_expiry_ms: Nullable::null(),
                    wait_ms: Nullable::null(),
                },
                kr_worker::questions::Now {
                    utc_ms: kr_ipc::now_ms(),
                    boot_ms: kr_ipc::clock::boot_elapsed_ms(),
                },
            )
            .expect("a verified source asks")
            .0
            .question
    }

    /// What the worker's ledger holds of a question, whatever any caller was shown.
    pub fn held(&self, question: &Question) -> Question {
        self.service
            .questions()
            .question(question.question_id)
            .expect("the question is in the ledger")
    }
}

/// An upstream that records the prompts it is given and answers each as applied.
///
/// It is the one thing a suite supplies in place of an agent's own upstream: the broker admits,
/// records and dispatches the operation as it does in the product, and this transport is what it
/// hands the operation to.
#[derive(Debug, Default)]
pub struct Upstream {
    prompts: std::sync::Mutex<Vec<String>>,
}

impl Upstream {
    /// The text of every prompt the broker handed over, in order.
    pub fn prompts(&self) -> Vec<String> {
        self.prompts
            .lock()
            .expect("the record is not poisoned")
            .clone()
    }
}

impl UpstreamDispatch for Upstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        if let UpstreamBody::Prompt { text, .. } = &request.body {
            self.prompts
                .lock()
                .expect("the record is not poisoned")
                .push(text.clone().unwrap_or_default());
        }
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: Some(UpstreamRequestId::new("upstream-1").expect("valid")),
            turn_id: request.turn_id.clone(),
            provenance: ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

impl Worker {
    /// Registers an agent on this worker's broker, able to take a prompt, with `upstream` as the
    /// transport its operations leave on. The instance is the one the page finds in the session's
    /// snapshot.
    pub fn register_agent(&self, upstream: Arc<Upstream>) -> ApplicationInstanceId {
        self.register_agent_on(upstream)
    }

    /// As [`Self::register_agent`], with any upstream a test gives.
    pub fn register_agent_on(&self, upstream: Arc<dyn UpstreamDispatch>) -> ApplicationInstanceId {
        let instance = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
        let broker = self.service.broker();
        let process = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
        broker
            .register_instance(
                instance,
                IntegrationMode::Gateway,
                None,
                Some(ManagedProcess::new(
                    instance,
                    process.clone(),
                    TransportHandle {
                        transport: BrokerTransport::PrivateSocket,
                        application_instance_id: instance,
                        executable_digest: Digest256::from_bytes([3; 32]),
                        process,
                    },
                    Credential::from_bytes([9; 32]),
                    TimestampMs::new(1),
                )),
            )
            .expect("the instance is registered");
        broker
            .bind_descriptor(
                BrokerBindingId::new(Uuid::from_bytes([9; 16])),
                instance,
                PluginId::new("kalareach.codex").expect("valid"),
                PublisherId::new("kalareach").expect("valid"),
                Digest256::from_bytes([5; 32]),
                BrokerGrants::granted([BrokerGrant::UpstreamAction]),
                None,
                TimestampMs::new(1),
            )
            .expect("the binding is recorded");
        broker
            .record_capability(InstanceCapabilityRecord {
                capability_id: CapabilityId::new("agent.prompt").expect("valid"),
                capability_version: "1".to_owned(),
                application_instance_id: instance,
                identity: InstanceCapabilityIdentity::default(),
                revision: CapabilityRevision::new(1),
                state: InstanceCapabilityState::QualifiedAvailable,
                source: InstanceEvidenceSource::HostProbe,
                invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
                disabled_reason: Nullable::null(),
                observed_at: TimestampMs::new(1),
            })
            .expect("the capability is recorded");
        broker
            .bind_dispatch(instance, upstream)
            .expect("the transport is bound");
        // The session learns of the instance as a launch announces it, which is where a view
        // finds it.
        self._runtime
            .session()
            .announce_instance(kr_protocol::projection::AgentInstanceSummary {
                application_instance_id: instance,
                plugin_id: Nullable::null(),
                profile_id: Nullable::null(),
                mode: IntegrationMode::Gateway,
                bypass: Nullable::null(),
                started_at: TimestampMs::new(1),
                ended_at: Nullable::null(),
                refusal: Nullable::null(),
            });
        instance
    }

    /// Has the registered agent ask for one approval a decoder has given meaning to, with
    /// `upstream` as the transport an answer would leave on, and returns the pending resource it
    /// became.
    ///
    /// This is the native half of an approval: the qualified table, the authenticated connection,
    /// the transport that carries an answer out, and one request offering a single decision,
    /// `allow`.
    pub fn offer_approval(
        &self,
        instance: ApplicationInstanceId,
        upstream: Arc<dyn UpstreamDispatch>,
    ) -> kr_protocol::ids::PendingResourceId {
        use kr_protocol::gateway::{
            DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, RichMethodEntry,
            RichMethodTable, RichOperation,
        };
        use kr_protocol::ids::{GatewayConnectionId, MethodTableVersion, UpstreamMethod};

        let broker = self.service.broker();
        let plugin = PluginId::new("kalareach.codex").expect("valid");
        let publisher = PublisherId::new("kalareach").expect("valid");
        let digest = Digest256::from_bytes([5; 32]);
        let permission = UpstreamMethod::new("session/request_permission").expect("valid");
        broker
            .bind_descriptor(
                BrokerBindingId::new(Uuid::from_bytes([9; 16])),
                instance,
                plugin.clone(),
                publisher.clone(),
                digest,
                BrokerGrants::granted([
                    BrokerGrant::UpstreamAction,
                    BrokerGrant::ApprovalInterpreter,
                ]),
                Some(kr_protocol::broker::DecodingTrust {
                    plugin_id: plugin.clone(),
                    publisher_id: publisher.clone(),
                    package_digest: digest,
                    methods: [permission.clone()].into_iter().collect(),
                    schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
                    max_decisions: kr_protocol::scalars::U64::new(4),
                    may_encode_response: true,
                    granted_at: TimestampMs::new(1),
                }),
                TimestampMs::new(1),
            )
            .expect("the binding carries the interpreter grant");
        broker
            .record_capability(InstanceCapabilityRecord {
                capability_id: CapabilityId::new("agent.approval").expect("valid"),
                capability_version: "1".to_owned(),
                application_instance_id: instance,
                identity: InstanceCapabilityIdentity::default(),
                revision: CapabilityRevision::new(1),
                state: InstanceCapabilityState::QualifiedAvailable,
                source: InstanceEvidenceSource::HostProbe,
                invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
                disabled_reason: Nullable::null(),
                observed_at: TimestampMs::new(1),
            })
            .expect("the evidence is recorded");
        let mut table = DeclarativeTable {
            plugin_id: plugin.clone(),
            publisher_id: publisher.clone(),
            table_version: MethodTableVersion::new(1),
            upstream_protocol_version: "1".to_owned(),
            digest: Digest256::from_bytes([1; 32]),
            framing: NativeFraming::JsonLines,
            request_id_field: "id".to_owned(),
            response_id_field: "id".to_owned(),
            method_field: "method".to_owned(),
            params_field: "params".to_owned(),
            result_field: "result".to_owned(),
            error_field: "error".to_owned(),
            entries: vec![DeclarativeEntry {
                method: permission.clone(),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::some("option_id".to_owned()),
                reverse: Nullable::null(),
            }],
        };
        table.digest = table.canonical_digest().expect("encodable");
        broker
            .pin_table(
                instance,
                kr_worker::broker::PackageIdentity {
                    plugin_id: plugin.clone(),
                    publisher_id: publisher,
                    package_digest: digest,
                },
                table,
                RichMethodTable {
                    table_version: MethodTableVersion::new(1),
                    upstream_protocol_version: "1".to_owned(),
                    entries: vec![RichMethodEntry {
                        method: UpstreamMethod::new("session/cancel").expect("valid"),
                        class: NativeMethodClass::Mutation,
                        required_right: kr_protocol::rights::ActionRight::AgentCancel,
                        operation: Nullable::some(RichOperation::TurnCancel),
                        provenance: ActionProvenance::UpstreamTypedRpc,
                    }],
                },
            )
            .expect("the installed tables are pinned");
        broker
            .open_native_connection(
                instance,
                &[9; 32],
                &ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900),
                &plugin,
                "1",
            )
            .expect("the native connection is authenticated");
        broker.bind_connection_dispatch(GatewayConnectionId::new(1), upstream);
        let opaque = broker
            .forward_native(
                GatewayConnectionId::new(1),
                br#"{"id":11,"method":"session/request_permission"}"#,
                TimestampMs::new(2),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response");
        broker
            .interpret(
                BrokerBindingId::new(Uuid::from_bytes([9; 16])),
                opaque.resource_id,
                kr_protocol::broker::DecodedProjection {
                    schema_version: "kr-approval/1".to_owned(),
                    summary: "the agent wants to write a file".to_owned(),
                    decisions: vec![kr_protocol::broker::OfferedDecision {
                        option_id: "allow".to_owned(),
                        label: "Allow".to_owned(),
                    }],
                },
                None,
                TimestampMs::new(3),
            )
            .expect("interpreted")
            .resource_id
    }

    /// The binding revision a registered agent is at.
    pub const BINDING: AgentBindingRevision = AgentBindingRevision::new(1);
}

/// How long a test waits for the daemon to reach a worker.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// A daemon on the network that has adopted workers in this process, and the keys of the
/// environment's owner.
pub struct Adopted {
    pub host: Host,
    pub owner: DeviceKeys,
    pub workers: Vec<Worker>,
}

impl Adopted {
    /// Starts a daemon on a fresh environment, bootstraps its owner, stops it, starts `sessions`
    /// workers on the tree and starts the daemon again, which adopts them.
    pub async fn start(sessions: u64) -> Self {
        Self::start_on(sessions, None, Clocks::system(), false).await
    }

    /// As [`Self::start`], with each session also reserved and open in the daemon's registry.
    pub async fn start_reserved(sessions: u64) -> Self {
        Self::start_on(sessions, None, Clocks::system(), true).await
    }

    /// As [`Self::start`], for a host whose configuration is `document`.
    pub async fn start_with_document(
        sessions: u64,
        document: &kr_protocol::hostinfo::configuration::ConfigurationDocument,
    ) -> Self {
        Self::start_on(sessions, Some(document), Clocks::system(), false).await
    }

    /// As [`Self::start`], on the clocks a suite moves by hand.
    pub async fn start_on_clocks(sessions: u64, clocks: Clocks) -> Self {
        Self::start_on(sessions, None, clocks, false).await
    }

    async fn start_on(
        sessions: u64,
        document: Option<&kr_protocol::hostinfo::configuration::ConfigurationDocument>,
        clocks: Clocks,
        reserved: bool,
    ) -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = match document {
            Some(document) => Host::start_with_document_clocks(&owner, document, clocks).await,
            None => Host::start_on_clocks(&owner, clocks).await,
        };
        let stopped = host.shut_down().await;
        let mut workers = Vec::new();
        for display in 1..=sessions {
            workers.push(if reserved {
                Worker::start_reserved(stopped.tree(), display).await
            } else {
                Worker::start(stopped.tree(), display).await
            });
        }
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let adopted = Self {
            host,
            owner,
            workers,
        };
        for worker in &adopted.workers {
            adopted.until_adopted(worker).await;
        }
        adopted
    }

    /// The environment the daemon serves.
    pub fn environment_id(&self) -> EnvironmentId {
        self.host.environment_id
    }

    /// Waits until the daemon serves the worker's session.
    pub async fn until_adopted(&self, worker: &Worker) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let read = client
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams {
                        session_id: worker.session_id,
                    },
                )
                .await
                .expect("the call reaches the daemon");
            if read.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon never reached the worker: {read:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Stops the daemon.
    pub async fn stop(self) {
        self.host.stop().await;
    }
}

/// Offers `session_id` to the device `record` names, as the person at this machine does, under
/// `selection`, and leaves the invitation for the device to redeem.
pub async fn offer(
    host: &Host,
    session_id: SessionId,
    record: &kr_controller::service::net::devices::DeviceRecord,
    selection: kr_protocol::sharing::RoleSelection,
) -> kr_protocol::sharing::GrantCreateResult {
    host.client()
        .await
        .mutate(
            Method::GrantCreate,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            super::on_the_session(host, session_id),
            &kr_protocol::sharing::GrantCreateParams {
                session_id,
                recipient_device_id: record.device_id,
                parent_grant_id: Nullable::null(),
                accepted_notices: kr_protocol::sharing::AuthorityNotice::for_actions(
                    &selection.actions(),
                ),
                selection,
                lifetime_ms: Nullable::null(),
                owner_confirmation: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the share is written")
        .to_typed()
        .expect("decodes")
}

/// Shares `session_id` with the device `record` names, as the person at this machine does, under
/// `selection`, and has that device redeem it. Returns the grant.
pub async fn share(
    host: &Host,
    session_id: SessionId,
    device: &super::Device,
    record: &kr_controller::service::net::devices::DeviceRecord,
    selection: kr_protocol::sharing::RoleSelection,
) -> kr_protocol::grant::Grant {
    let created = offer(host, session_id, record, selection).await;
    let connection = super::RawDevice::connect(host, device, record).await;
    connection
        .mutate(
            Method::GrantRedeem,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            super::on_the_host(host),
            &kr_protocol::sharing::GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            },
        )
        .await
        .expect("the share is redeemed");
    connection.close();
    created.grant
}

/// Withdraws a grant, as the person at this machine does.
pub async fn revoke(host: &Host, grant_id: kr_protocol::ids::GrantId) {
    host.client()
        .await
        .mutate(
            Method::GrantRevoke,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            super::on_the_host(host),
            &kr_protocol::sharing::GrantRevokeParams { grant_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the grant is revoked");
}

/// Types `text` into the terminal of `session_id` as a device that is paired with the host and may
/// type does. The connection that typed is returned with the device: the attachment lives as long as
/// the connection does, and the screen keeps what was typed after it is gone.
pub async fn type_into(
    host: &Host,
    owner: &DeviceKeys,
    session_id: SessionId,
    text: &str,
) -> (kr_client::session::Session, super::Device) {
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    };
    use kr_protocol::envelope::ParamsValue;
    use kr_protocol::input::{InputAcquireParams, InputAcquireResult, InputWriteParams};
    use kr_protocol::scalars::DurationMs;

    let typist = super::Device::create().await;
    let record = super::pair_with(
        host,
        &typist,
        owner,
        super::proposal(&[
            kr_protocol::rights::ActionRight::SessionView,
            kr_protocol::rights::ActionRight::TerminalInput,
        ]),
    )
    .await;
    let session = super::connect(host, &typist, &record).await;
    let on_the_session = || ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let attached: SessionAttachResult = session
        .mutate(
            Method::SessionAttach,
            on_the_session(),
            None,
            &ParamsValue::empty(),
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Semantic,
                claim_geometry: false,
                dimensions: Nullable::null(),
                terminal_profile_id: Nullable::null(),
                requested: [
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Input,
                ]
                .into_iter()
                .collect(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the attach is settled")
        .to_typed()
        .expect("an attachment");
    let attachment_id = attached.attachment.attachment_id;
    let acquired: InputAcquireResult = session
        .mutate(
            Method::InputAcquire,
            on_the_session(),
            None,
            &ParamsValue::empty(),
            &InputAcquireParams {
                session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the lease is settled")
        .to_typed()
        .expect("a lease");
    session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id,
            epoch: acquired.lease.epoch,
            sequence: kr_protocol::ids::InputSequence::new(0),
            bytes: kr_protocol::scalars::Bytes::new(text.as_bytes().to_vec()),
        })
        .await
        .expect("the input is accepted");
    (session, typist)
}

/// An upstream that takes every prompt and answers it only once it is released, so a prompt stays
/// in flight for as long as a test needs it to.
#[derive(Debug, Default)]
pub struct HeldUpstream {
    prompts: std::sync::Mutex<Vec<String>>,
    released: Arc<tokio::sync::Notify>,
    open: Arc<std::sync::atomic::AtomicBool>,
}

impl HeldUpstream {
    /// The text of every prompt the broker handed over, in order.
    pub fn prompts(&self) -> Vec<String> {
        self.prompts
            .lock()
            .expect("the record is not poisoned")
            .clone()
    }

    /// Answers every prompt held, and every one that follows.
    pub fn release(&self) {
        self.open.store(true, std::sync::atomic::Ordering::SeqCst);
        self.released.notify_waiters();
    }
}

impl UpstreamDispatch for HeldUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        if let UpstreamBody::Prompt { text, .. } = &request.body {
            self.prompts
                .lock()
                .expect("the record is not poisoned")
                .push(text.clone().unwrap_or_default());
        }
        let outcome = UpstreamOutcome {
            upstream_request_id: Some(UpstreamRequestId::new("upstream-1").expect("valid")),
            turn_id: request.turn_id.clone(),
            provenance: ActionProvenance::UpstreamTypedRpc,
        };
        let released = Arc::clone(&self.released);
        let open = Arc::clone(&self.open);
        Ok(PendingTransmission::carried(async move {
            loop {
                let waiting = released.notified();
                tokio::pin!(waiting);
                waiting.as_mut().enable();
                if open.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                waiting.await;
            }
            Ok(outcome)
        }))
    }
}
