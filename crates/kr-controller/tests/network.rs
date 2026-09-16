//! The whole network path, with real processes and a real connection.
//!
//! A control daemon on the network, a worker it started, a real shell in a real pseudo-terminal,
//! and a device that pairs over iroh and then does what a device does: attaches, subscribes to the
//! session's output from a cursor, takes the input lease, types, loses its connection, reconnects
//! and resumes from where its content had reached. Then the two things that must hold when
//! authority changes underneath it: a revoked device is fenced before it is served again, and the
//! remote path ending takes neither the worker nor a local attachment with it.
//!
//! Every path here is on the internal disk, and the worker is copied there before it is started. A
//! process a service manager launches is its own identity to the operating system, and one that
//! reaches a removable volume asks the person sitting at the machine for permission; a test suite
//! must never do that.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::cursors::{Restoration, RestorationStep};
use kr_client::ipc::IpcTransport;
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::net::{self, Network, NetworkSetup};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, open_store};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_pairing::confirm::{HostEnrolment, sign_confirmation};
use kr_pairing::direct::{CandidateIdentity, redeem_proof};
use kr_pairing::grants::GrantKind;
use kr_pairing::host::OwnerContext;
use kr_protocol::actor::ActorIngress;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, DeviceId, DeviceKeyRevision, EnvironmentId, SessionId,
    StreamId,
};
use kr_protocol::input::{
    InputAcquireParams, InputAcquireResult, InputWriteParams, InputWriteResult,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ConfirmationChannel, DeviceName, DevicePlatform, DirectQrPayload, ProposedGrant, QrPayload,
    SensitiveAction,
};
use kr_protocol::preauth::{
    PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::recovery::{EventStream, EventsSubscribeResult, OutputEvent};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64};
use kr_protocol::session::{
    Presentation, SessionCloseParams, SessionCreateParams, SessionCreateResult, SessionReadParams,
    SessionReadResult, SessionState, ShellMode,
};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, LocalIdentity};
use kr_transport::scheduler::SendLimits;

/// How long a test waits for something the machine has to do before it calls it a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// A host tree on the internal disk, with the worker beside it.
struct Host {
    temp: kr_ipc::testing::TempHost,
    worker: PathBuf,
    environment_id: EnvironmentId,
}

impl Host {
    /// Builds a host, or returns `None` when the worker this suite launches is not built.
    ///
    /// The suite starts a real worker process, and the only place a test can look for it is beside
    /// its own binary. A target directory that holds the test but not the worker is a partial
    /// build rather than a failure of anything this suite checks, so it says so and stops.
    fn create() -> Option<Self> {
        let worker_build = worker_program()?;
        let temp = kr_ipc::testing::TempHost::create();
        let environment_id = temp.environment_id();
        let worker = temp.root().join("kr-worker");
        std::fs::copy(&worker_build, &worker).expect("copies the worker");
        Some(Self {
            temp,
            worker,
            environment_id,
        })
    }

    fn paths(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.temp.environment()
    }

    /// Starts the daemon and puts it on the network with the endpoint configuration given.
    async fn start(&self, endpoint: EndpointConfig, owner: &DeviceKeys) -> RunningDaemon {
        let environment = self.paths();
        let environment_id = self.environment_id;
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store(CONTROLLER_SECRET_SERVICE, &secrets).expect("a secret store");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(DetachedSupervisor::new()),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
        })
        .await
        .expect("the daemon starts");
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
            .expect("binds the client endpoint");
        let serving = vec![
            tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(Arc::clone(&controller).serve_clients(clients)),
        ];
        // The network is registered here rather than from the environment, because a test must not
        // reach the machine's own credential store: its keys live in memory and go with the test.
        let network = net::register(
            &controller,
            NetworkSetup {
                settings: kr_controller::service::net::config::NetworkSettings {
                    endpoint,
                    ..kr_controller::service::net::config::NetworkSettings::default()
                },
                secrets: Arc::new(MemoryStore::new()),
                owner_signer: Some(*owner.authorisation.public()),
                enrolment: HostEnrolment::Enrolled,
            },
        )
        .await
        .expect("the daemon joins the network");
        RunningDaemon {
            controller,
            network,
            serving,
        }
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self.paths().controller_endpoint().expect("an endpoint"),
            LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("connects to the daemon")
    }
}

/// Returns the worker binary beside this test's own, when the build produced one.
fn worker_program() -> Option<PathBuf> {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let worker = directory.join(if cfg!(windows) {
        "kr-worker.exe"
    } else {
        "kr-worker"
    });
    if worker.is_file() {
        Some(worker)
    } else {
        eprintln!(
            "the network suite needs the worker binary at {}; build it and run this again",
            worker.display()
        );
        None
    }
}

struct RunningDaemon {
    controller: Arc<Controller>,
    network: Network,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

impl RunningDaemon {
    async fn stop(self) {
        for task in &self.serving {
            task.abort();
        }
        for task in self.serving {
            let _ = task.await;
        }
        self.network.shutdown().await;
        drop(self.controller);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn loopback() -> EndpointConfig {
    EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    }
}

/// A shell that stays open, so its output is observable and it does not exit.
fn create_params(environment_id: EnvironmentId, cwd: &Path) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some("/bin/sh".to_owned()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(cwd.display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: vec![
            kr_protocol::session::EnvironmentVariable {
                name: "PATH".to_owned(),
                value: "/usr/bin:/bin".to_owned(),
            },
            kr_protocol::session::EnvironmentVariable {
                name: "PS1".to_owned(),
                value: String::new(),
            },
        ],
    }
}

async fn create(client: &mut LocalClient, host: &Host) -> SessionCreateResult {
    client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.temp.root()),
        )
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the create failed: {error}"))
}

/// What a device the host has never seen looks like.
struct Device {
    keys: DeviceKeys,
    endpoint: Endpoint,
    identity: Arc<LocalIdentity>,
}

impl Device {
    async fn create(config: &EndpointConfig) -> Self {
        let keys = DeviceKeys::generate().expect("device keys");
        let endpoint = kr_transport::endpoint::bind_dialer(config, &keys.transport)
            .await
            .expect("a dialling endpoint");
        // The identity a device presents before it is paired carries the identifier it will be
        // given; the host assigns the record's own identity when it commits the pairing, and the
        // device learns it from the status.
        let device_id = DeviceId::new(kr_ipc::new_uuid());
        let identity = Arc::new(LocalIdentity::new(
            device_id,
            DeviceKeyRevision::new(1),
            *keys.transport.public(),
            keys.authorisation.clone(),
            build(),
        ));
        Self {
            keys,
            endpoint,
            identity,
        }
    }

    fn candidate_identity(&self) -> CandidateIdentity {
        CandidateIdentity {
            keys: self.keys.public_keys(),
            device_key_revision: DeviceKeyRevision::new(1),
            device_name: DeviceName::new("A test phone").expect("a name"),
            platform: DevicePlatform::Android,
            endpoint_id: *self.keys.transport.public(),
        }
    }

    /// Returns the identity this device presents once the host has given it a record.
    fn paired_identity(&self, device_id: DeviceId) -> Arc<LocalIdentity> {
        Arc::new(LocalIdentity::new(
            device_id,
            DeviceKeyRevision::new(1),
            *self.keys.transport.public(),
            self.keys.authorisation.clone(),
            build(),
        ))
    }
}

fn proposal() -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [
            ActionRight::SessionView,
            ActionRight::TerminalInput,
            ActionRight::SessionCreate,
            ActionRight::SessionClose,
        ]
        .into_iter()
        .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: true,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        // A session invitation expires: persistent access is what owner pairing is for.
        expiry: GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(
                kr_ipc::now_ms().get().saturating_add(24 * 60 * 60 * 1000),
            ),
        },
        organisation: Nullable::null(),
    }
}

fn owner_context() -> OwnerContext {
    OwnerContext {
        actor_id: kr_protocol::ids::ActorId::new("owner:test").expect("a principal"),
        ingress: ActorIngress::LocalIpc,
    }
}

/// Runs a complete direct pairing, and returns the record the host committed.
///
/// The owner half is the test's: issuing an invitation and approving a candidate each need a fresh
/// owner confirmation, and producing one is a user-presence ceremony rather than something a
/// daemon decides for itself. What the daemon owns is the challenge, the ledger that makes it
/// single use, and the record the approval commits.
async fn pair(daemon: &RunningDaemon, device: &Device, owner: &DeviceKeys) -> DeviceRecord {
    let pairing = daemon.network.pairing().expect("this host accepts pairing");
    let owner_context = owner_context();
    // One proposal, used for the challenge and for the invitation. The owner approves an exact
    // proposal, digest and all, so a second one built a millisecond later is a different thing.
    let proposal = proposal();
    let rights: BTreeSet<ActionRight> = proposal.actions.iter().copied().collect();

    // The owner authorises the invitation, naming the rights it proposes.
    let request = pairing
        .request_confirmation(
            SensitiveAction::IssueInvitation,
            kr_pairing::confirm::action_digest(&proposal).expect("a digest"),
            None,
            rights.clone(),
        )
        .expect("a challenge");
    let proof = sign_confirmation(
        &owner.authorisation,
        &request,
        ConfirmationChannel::OwnerDevicePresence,
    )
    .expect("a proof");
    let payload = pairing
        .issue_direct(
            proposal.clone(),
            GrantKind::SessionInvitation,
            &owner_context,
            &pairing.approval(&owner_context, &request, &proof),
        )
        .expect("an invitation");
    let QrPayload::Direct(payload) = payload else {
        panic!("a direct invitation produces a direct payload");
    };
    let payload: DirectQrPayload = *payload;

    // The candidate scans it and redeems it over the pre-authorisation surface, which is the only
    // thing an unpaired endpoint reaches.
    let host_addr = host_addr(daemon, &payload);
    let connection = device
        .endpoint
        .connect(host_addr, kr_protocol::hello::ALPN)
        .await
        .expect("the candidate reaches the host");
    let mut candidate = handshake::connect_unpaired(&connection, &device.identity)
        .await
        .expect("an unpaired connection");
    let challenge: PairRedeemResult = candidate
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Challenge {
                invitation_id: payload.invitation_id,
            },
        )
        .await
        .expect("the host issues a challenge");
    let PairRedeemResult::Challenge(challenge) = challenge else {
        panic!("the first redemption step answers with a challenge");
    };
    let live_host = HostPeer(*challenge.endpoint_id.as_bytes());
    let (redeem, _transcript) = redeem_proof(
        &payload,
        &challenge,
        &device.keys.authorisation,
        &device.candidate_identity(),
        &live_host,
    )
    .expect("a redemption proof");
    let locked: PairRedeemResult = candidate
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Direct(Box::new(redeem)),
        )
        .await
        .expect("the host accepts the redemption");
    let PairRedeemResult::Locked {
        verification_value, ..
    } = locked
    else {
        panic!("a redemption locks the invitation");
    };
    assert_eq!(verification_value.len(), 8);

    // The owner approves exactly what both devices displayed.
    let (approved, client_keys, host_value) = pairing.awaiting_approval().expect("a candidate");
    assert_eq!(
        host_value, verification_value,
        "both devices show one value"
    );
    let request = pairing
        .request_confirmation(
            SensitiveAction::ConfirmDevice,
            approved.action_digest(),
            Some(client_keys),
            rights,
        )
        .expect("a challenge");
    let proof = sign_confirmation(
        &owner.authorisation,
        &request,
        ConfirmationChannel::OwnerDevicePresence,
    )
    .expect("a proof");
    let identities = net::pairing::fresh_identities(
        pairing.identity().device_id,
        daemon
            .controller
            .authority_revision()
            .await
            .expect("the revision"),
    )
    .expect("fresh identities");
    let record = pairing
        .confirm(
            &pairing.approval(&owner_context, &request, &proof),
            &approved,
            &identities,
        )
        .expect("the pairing commits");

    // And the candidate learns it happened through the surface it is already on.
    let status: PairStatusResult = candidate
        .call(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: payload.invitation_id,
            },
        )
        .await
        .expect("the host answers the candidate");
    assert!(
        matches!(
            status.status,
            kr_protocol::pairing::PairStatus::Committed { device_id, .. }
                if device_id == record.device_id
        ),
        "the candidate is told which device it became: {:?}",
        status.status
    );
    connection.close(0u32.into(), b"paired");
    record
}

/// The host as the candidate sees it: the endpoint identity the invitation pinned.
#[derive(Debug)]
struct HostPeer([u8; 32]);

impl kr_pairing::platform::LivePeer for HostPeer {
    fn live_endpoint(&self) -> kr_pairing::Result<kr_protocol::scalars::EndpointKey> {
        Ok(kr_protocol::scalars::EndpointKey::from_bytes(self.0))
    }

    fn arrived_in_early_data(&self) -> bool {
        false
    }
}

/// Returns where a device dials the host, from the invitation and this endpoint's own addresses.
fn host_addr(daemon: &RunningDaemon, payload: &DirectQrPayload) -> EndpointAddr {
    let endpoint_id = iroh::PublicKey::from_bytes(payload.endpoint_id.as_bytes())
        .expect("the invitation pins a usable endpoint identity");
    let mut addr = EndpointAddr::new(endpoint_id);
    if let Some(relay) = daemon
        .network
        .network_config()
        .expect("a network configuration")
        .relay_urls
        .first()
        .and_then(|hint| hint.as_str().parse::<iroh::RelayUrl>().ok())
    {
        addr = addr.with_relay_url(relay);
    }
    for socket in daemon.network.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/// Connects a paired device and starts one session over it.
async fn connect(daemon: &RunningDaemon, device: &Device, record: &DeviceRecord) -> Session {
    let host_record = PairedPeer {
        device_id: daemon
            .network
            .pairing()
            .expect("pairing")
            .identity()
            .device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: daemon
            .network
            .pairing()
            .expect("pairing")
            .identity()
            .keys
            .authorisation,
        endpoint_id: daemon.network.endpoint_id(),
    };
    let mut addr = EndpointAddr::new(
        iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
            .expect("a usable endpoint identity"),
    );
    for socket in daemon.network.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    let transport = NetworkTransport::connect(
        &device.endpoint,
        addr,
        &device.paired_identity(record.device_id),
        &host_record,
        SendLimits::default(),
    )
    .await
    .expect("the paired device connects");
    Session::start(Arc::new(transport)).expect("a session")
}

fn output_stream() -> StreamId {
    StreamId::new("session.output").expect("a stream identifier")
}

/// Attaches, subscribes from a cursor and returns the attachment and the subscription.
async fn attach(
    session: &Session,
    environment_id: EnvironmentId,
    session_id: SessionId,
) -> (AttachmentId, EventsSubscribeResult) {
    let attached: SessionAttachResult = session
        .mutate(
            Method::SessionAttach,
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
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

    // Section 8's order: subscribe from the cursor first, then install what it returns.
    let mut restoration = Restoration::start(output_stream(), &session.cursors().await);
    let params = restoration
        .subscribe_params(session_id, attachment_id, &[EventStream::Output])
        .expect("the stream is waiting to subscribe");
    let subscribed = session
        .subscribe_events(&params)
        .await
        .expect("the subscription succeeds");
    restoration.subscribed().expect("the order is kept");
    session
        .installed_snapshot(&output_stream(), kr_protocol::ids::EventSequence::new(0))
        .await;
    session
        .applied_content(&output_stream(), subscribed.from_cursor)
        .await;
    restoration.installed().expect("the order is kept");
    assert_eq!(restoration.step(), RestorationStep::Live);
    (attachment_id, subscribed)
}

/// Takes the input lease, types `text`, and waits for it to come back as output.
async fn type_and_observe(
    session: &Session,
    environment_id: EnvironmentId,
    session_id: SessionId,
    attachment_id: AttachmentId,
    text: &str,
) -> String {
    let acquired: InputAcquireResult = session
        .mutate(
            Method::InputAcquire,
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
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
    let mut events = session.events();
    let written: InputWriteResult = session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id,
            epoch: acquired.lease.epoch,
            // A lease starts its ordered stream at zero, and a reconnect starts a new one.
            sequence: kr_protocol::ids::InputSequence::new(0),
            bytes: kr_protocol::scalars::Bytes::new(text.as_bytes().to_vec()),
        })
        .await
        .expect("the input is accepted");
    assert!(
        written.forwarded_bytes.get() > 0,
        "the bytes reached the application"
    );

    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut seen = String::new();
    while tokio::time::Instant::now() < deadline {
        let Ok(Ok(notification)) =
            tokio::time::timeout(Duration::from_secs(5), events.recv()).await
        else {
            continue;
        };
        if notification.event_type.as_str() != "session.output" {
            continue;
        }
        let event: OutputEvent = notification.payload.to_typed().expect("an output event");
        seen.push_str(&String::from_utf8_lossy(event.bytes.as_slice()));
        session
            .applied_content(
                &output_stream(),
                U64::new(event.cursor.get() + event.bytes.len() as u64),
            )
            .await;
        session
            .applied(&output_stream(), notification.sequence)
            .await;
        if seen.contains("kalareach") {
            return seen;
        }
    }
    panic!("the session's output never carried what was typed: {seen:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_attaches_subscribes_types_and_resumes_from_its_cursor() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;

    let device = Device::create(&loopback()).await;
    let record = pair(&daemon, &device, &owner).await;
    let session = connect(&daemon, &device, &record).await;

    // A controller-served read over the network, before anything is attached.
    let read: SessionReadResult = session
        .read(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the device reads the session");
    assert_eq!(read.session.state, SessionState::Live);

    let (attachment_id, subscribed) = attach(&session, host.environment_id, session_id).await;
    assert!(
        subscribed.gap.as_ref().is_none(),
        "a fresh subscription has no gap in its history"
    );
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attachment_id,
        "echo kalareach\n",
    )
    .await;
    assert!(seen.contains("kalareach"));

    // The control stream is lost. What the client carries across is the content position, not the
    // previous connection's event sequences.
    let carried = kr_client::reconnect::ClientState::from_session(&session, None).await;
    let resumed_from = carried
        .cursors
        .applied_cursor(&output_stream())
        .expect("the client holds a position");
    assert!(resumed_from.get() > 0);
    session.close();
    drop(session);

    let session = connect(&daemon, &device, &record).await;
    let session = {
        session.close();
        // A reconnect resumes the cursors it carried.
        let transport = NetworkTransport::connect(
            &device.endpoint,
            {
                let mut addr = EndpointAddr::new(
                    iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
                        .expect("a usable endpoint identity"),
                );
                for socket in daemon.network.bound_sockets() {
                    addr = addr.with_ip_addr(socket);
                }
                addr
            },
            &device.paired_identity(record.device_id),
            &host_paired_record(&daemon),
            SendLimits::default(),
        )
        .await
        .expect("the device reconnects");
        Session::resume(Arc::new(transport), carried.cursors).expect("a resumed session")
    };
    let restoration = Restoration::start(output_stream(), &session.cursors().await);
    assert_eq!(
        restoration.step(),
        RestorationStep::SubscribeFrom(resumed_from),
        "the reconnect subscribes from the cursor it carried"
    );
    let (_attachment_id, resumed) = attach(&session, host.environment_id, session_id).await;
    assert!(
        resumed.from_cursor.get() >= resumed_from.get() || resumed.gap.as_ref().is_some(),
        "a resumed subscription starts at the cursor or says what it cannot replay"
    );

    session.close();
    let _ = local
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionCloseParams { session_id },
        )
        .await;
    daemon.stop().await;
}

fn host_paired_record(daemon: &RunningDaemon) -> PairedPeer {
    let pairing = daemon.network.pairing().expect("pairing");
    PairedPeer {
        device_id: pairing.identity().device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: pairing.identity().keys.authorisation,
        endpoint_id: daemon.network.endpoint_id(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_device_is_fenced_before_it_is_served_again() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;

    let device = Device::create(&loopback()).await;
    let record = pair(&daemon, &device, &owner).await;
    let session = connect(&daemon, &device, &record).await;
    let (_attachment_id, _subscribed) = attach(&session, host.environment_id, session_id).await;

    // The device is revoked while its connection is authorised and its subscription is running.
    daemon
        .network
        .revoke_device(record.device_id)
        .await
        .expect("the revocation is recorded");

    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err("a revoked device is refused");
    assert_eq!(
        refused.code(),
        ErrorCode::PermissionDenied,
        "the fence is on the dispatch path, not merely recorded"
    );

    // And it cannot come back: its record is withdrawn, so a fresh connection is not authorised.
    let again = NetworkTransport::connect(
        &device.endpoint,
        {
            let mut addr = EndpointAddr::new(
                iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
                    .expect("a usable endpoint identity"),
            );
            for socket in daemon.network.bound_sockets() {
                addr = addr.with_ip_addr(socket);
            }
            addr
        },
        &device.paired_identity(record.device_id),
        &host_paired_record(&daemon),
        SendLimits::default(),
    )
    .await;
    assert!(
        again.is_err(),
        "a revoked device's endpoint has no paired record to authorise"
    );

    session.close();
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_session_runs_over_a_local_socket_and_over_the_network() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;

    // The same session type over the local socket. There is no device proof: the host stamped the
    // freshness context from the caller it authenticated through peer credentials.
    let ipc = IpcTransport::connect(
        &host.paths().controller_endpoint().expect("an endpoint"),
        build(),
    )
    .await
    .expect("the local client connects");
    assert_eq!(
        ipc.context().role,
        kr_protocol::local::LocalRole::Controller,
        "the host says which of its processes answered"
    );
    assert_eq!(
        ipc.context().environment_id,
        host.environment_id,
        "and which environment it belongs to"
    );
    let over_socket = Session::start(ipc.shared()).expect("a session over the socket");
    let read: SessionReadResult = over_socket
        .read(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the local client reads the session");
    assert_eq!(read.session.session_id, session_id);

    // And over iroh, against the same daemon, with nothing above the transport changed.
    let device = Device::create(&loopback()).await;
    let record = pair(&daemon, &device, &owner).await;
    let over_network = connect(&daemon, &device, &record).await;
    let remote: SessionReadResult = over_network
        .read(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the paired device reads the session");
    assert_eq!(
        remote.session.session_id, read.session.session_id,
        "one session, read the same way over both transports"
    );

    over_socket.close();
    over_network.close();
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_remote_path_ending_takes_neither_the_worker_nor_a_local_attachment() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;
    let worker_endpoint = kr_ipc::paths::Endpoint::from_path(
        created
            .endpoint
            .as_ref()
            .cloned()
            .expect("a live session names its worker"),
    )
    .expect("a worker endpoint");

    // A local attachment on the worker's own endpoint, which is what `kr attach` holds.
    let mut attached_locally =
        LocalClient::connect(&worker_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("the local client reaches the worker");
    let local_attachment: SessionAttachResult = attached_locally
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Semantic,
                claim_geometry: false,
                dimensions: Nullable::null(),
                terminal_profile_id: Nullable::null(),
                requested: [AttachmentCapability::ObserveTerminal]
                    .into_iter()
                    .collect(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local attachment is admitted")
        .to_typed()
        .expect("an attachment");

    let device = Device::create(&loopback()).await;
    let record = pair(&daemon, &device, &owner).await;
    let session = connect(&daemon, &device, &record).await;
    let (_attachment_id, _subscribed) = attach(&session, host.environment_id, session_id).await;

    // The remote path goes: the device's endpoint is closed, which is every route it had.
    device.endpoint.close().await;
    drop(session);

    // The worker is unaffected, and so is the attachment that was never remote.
    let still_live: SessionReadResult = attached_locally
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the worker")
        .expect("the worker answers")
        .to_typed()
        .expect("decodes");
    assert_eq!(still_live.session.state, SessionState::Live);
    assert!(
        still_live.session.attachment_count.get() >= 1,
        "the local attachment survived the remote path ending"
    );
    let _ = local_attachment;

    daemon.stop().await;
}

/// A relay server running in this process, with the trust anchor a client needs for it.
///
/// `iroh::test_utils::run_relay_server` discards the certificate it generated, and an endpoint that
/// cannot verify the relay's HTTPS certificate never reaches it. This spawns the same server and
/// keeps the certificate, which is also how a self-hosted deployment with a private authority
/// works: the certificate is pinned as an extra trust anchor beside the public ones.
struct LocalRelay {
    url: iroh::RelayUrl,
    ca_roots: Vec<Vec<u8>>,
    server: Option<iroh_relay::server::Server>,
}

impl LocalRelay {
    async fn spawn() -> Self {
        use std::net::Ipv4Addr;

        use iroh_relay::server::{
            CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig,
            TlsConfig,
        };

        let (certs, server_config) =
            iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let tls = TlsConfig::new(
            (Ipv4Addr::LOCALHOST, 0),
            CertConfig::Manual { server_config },
        );
        let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.tls = Some(tls);
        relay.key_cache_capacity = Some(1024);

        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));

        let server = Server::spawn(config).await.expect("a relay server");
        let url: iroh::RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
            .parse()
            .expect("a relay URL");
        Self {
            url,
            ca_roots: certs.into_iter().map(|cert| cert.to_vec()).collect(),
            server: Some(server),
        }
    }

    fn config(&self) -> EndpointConfig {
        EndpointConfig {
            relay_urls: vec![self.url.clone()],
            relay_ca_roots: self.ca_roots.clone(),
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            ..EndpointConfig::default()
        }
    }

    /// Takes the relay away, which is what a lease that ran out of reserved bytes does to a path.
    async fn shut_down(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await.expect("the relay stops");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_and_attaches_through_a_relay_and_losing_it_leaves_the_session() {
    let Some(host) = Host::create() else {
        return;
    };
    let mut relay = LocalRelay::spawn().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(relay.config(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;
    let worker_endpoint = kr_ipc::paths::Endpoint::from_path(
        created
            .endpoint
            .as_ref()
            .cloned()
            .expect("a live session names its worker"),
    )
    .expect("a worker endpoint");

    // A local attachment, which is what `kr attach` holds and what must not depend on the network.
    let mut attached_locally =
        LocalClient::connect(&worker_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("the local client reaches the worker");
    let _local_attachment: SessionAttachResult = attached_locally
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Semantic,
                claim_geometry: false,
                dimensions: Nullable::null(),
                terminal_profile_id: Nullable::null(),
                requested: [AttachmentCapability::ObserveTerminal]
                    .into_iter()
                    .collect(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local attachment is admitted")
        .to_typed()
        .expect("an attachment");

    // The device knows the relay and nothing else about where the host is, so the relay is how it
    // reaches it. The pairing and the attachment then run over that path.
    let device = Device::create(&relay.config()).await;
    let record = pair(&daemon, &device, &owner).await;
    let mut addr = EndpointAddr::new(
        iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
            .expect("a usable endpoint identity"),
    );
    addr = addr.with_relay_url(relay.url.clone());
    let transport = NetworkTransport::connect(
        &device.endpoint,
        addr,
        &device.paired_identity(record.device_id),
        &host_paired_record(&daemon),
        SendLimits::default(),
    )
    .await
    .expect("the paired device connects over the relay");
    let session = Session::start(Arc::new(transport)).expect("a session");
    let (attachment_id, _subscribed) = attach(&session, host.environment_id, session_id).await;
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attachment_id,
        "echo kalareach\n",
    )
    .await;
    assert!(seen.contains("kalareach"), "the relay carried the session");

    // The relay path goes, which is what a lease that has run out of reserved bytes does to it.
    // The remote path ends with it; the worker and the local attachment do not.
    relay.shut_down().await;
    device.endpoint.close().await;
    drop(session);

    let still_live: SessionReadResult = attached_locally
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the worker")
        .expect("the worker answers")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        still_live.session.state,
        SessionState::Live,
        "losing the relay path did not end the session"
    );
    assert!(
        still_live.session.attachment_count.get() >= 1,
        "and the local attachment is still attached"
    );

    daemon.stop().await;
}
