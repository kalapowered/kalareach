//! A control daemon on the network and a device that really pairs with it.
//!
//! What this gives a suite is the pair of doors: the environment's owner on a local socket, and a
//! paired device on an authorised iroh connection, both speaking to the same daemon. It starts no
//! worker, so it serves the methods the daemon answers itself and nothing more; a suite that needs
//! a session needs a worker process and belongs with the suites `scripts/end-to-end.sh` runs.
//!
//! Everything here is on the internal disk: the environment is a temporary host tree and the
//! repositories a project test builds live in a temporary directory beside it.

#![allow(dead_code)]

pub mod pairing;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::net::{self, Network, NetworkSetup};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_pairing::direct::CandidateIdentity;
use kr_protocol::error::ProtocolError;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{BuildId, DeviceId, DeviceKeyRevision, EnvironmentId};
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::pairing::{DeviceName, DevicePlatform, ProposedGrant};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::LocalIdentity;
use kr_transport::scheduler::SendLimits;

/// A supervisor that starts nothing. These suites create no sessions.
#[derive(Debug)]
pub struct RefusingSupervisor;

impl WorkerSupervisor for RefusingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// The build identity every party in these suites presents.
#[must_use]
pub fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// An endpoint bound to the loopback interface, so nothing leaves this machine.
#[must_use]
pub fn loopback() -> EndpointConfig {
    EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    }
}

/// One daemon, its local endpoint and its network, with a temporary environment of its own.
pub struct Host {
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    network: Network,
    pub environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    work: tempfile::TempDir,
    /// The owner device the host was bootstrapped with.
    pub owner: Option<DeviceRecord>,
    /// That device's own endpoint and keys, for a suite that connects it.
    pub owner_device: Option<Device>,
}

impl Host {
    /// Starts a daemon on a fresh environment and puts it on the loopback network.
    pub async fn start(owner: &DeviceKeys) -> Self {
        let mut host = Self::start_unowned().await;
        // The first owner is established the way a person establishes it: from this host's own
        // account, through the initial bootstrap, pairing the owner's device with a personal
        // owner grant. Every later confirmation in the suite is that device's.
        let (device, record) = bootstrap_owner(&host, owner).await;
        host.owner = Some(record);
        host.owner_device = Some(device);
        host
    }

    /// Starts a daemon on a fresh environment, on the network, with no owner yet.
    pub async fn start_unowned() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(RefusingSupervisor),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the client endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        // The endpoint configuration is this suite's own, so the network is registered here rather
        // than from the environment. The device keys live in memory and go with it.
        let network = net::register(
            &controller,
            NetworkSetup {
                settings: kr_controller::service::net::config::NetworkSettings {
                    endpoint: loopback(),
                    ..kr_controller::service::net::config::NetworkSettings::default()
                },
                secrets: Arc::new(MemoryStore::new()),
            },
        )
        .await
        .expect("the daemon joins the network");
        Self {
            temp,
            controller,
            network,
            environment_id,
            endpoint,
            clients,
            work: tempfile::TempDir::new().expect("a working directory on the internal disk"),
            owner: None,
            owner_device: None,
        }
    }

    /// The daemon's registry database, for a suite that holds a row as an earlier host wrote it.
    pub fn registry_database(&self) -> PathBuf {
        self.temp.environment().registry_database()
    }

    /// Connects one local client on the daemon's own socket.
    pub async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the control endpoint")
    }

    /// Returns the directory a project test builds its repositories in.
    #[must_use]
    pub fn work(&self) -> &Path {
        self.work.path()
    }

    /// Returns the environment tree this daemon owns.
    #[must_use]
    pub const fn tree(&self) -> &kr_ipc::testing::TempHost {
        &self.temp
    }

    /// Returns the daemon's network, for a suite that reads its records or its pairing service.
    #[must_use]
    pub const fn network(&self) -> &Network {
        &self.network
    }

    /// Returns the daemon itself, for a suite that asks it something directly.
    #[must_use]
    pub const fn controller(&self) -> &Arc<Controller> {
        &self.controller
    }

    /// Stops the daemon and its network the way its process ending would.
    pub async fn stop(self) {
        self.clients.abort();
        let _ = self.clients.await;
        self.network.shutdown().await;
        drop(self.controller);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A device with keys of its own and an endpoint to dial from.
pub struct Device {
    keys: DeviceKeys,
    endpoint: Endpoint,
    identity: Arc<LocalIdentity>,
}

impl Device {
    /// The device's own keys, for a suite that signs as the device.
    pub const fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    /// Creates a device that has not been paired with anything.
    pub async fn create() -> Self {
        Self::with_keys(DeviceKeys::generate().expect("device keys")).await
    }

    /// Creates an unpaired device holding `keys`.
    pub async fn with_keys(keys: DeviceKeys) -> Self {
        let endpoint = kr_transport::endpoint::bind_dialer(&loopback(), &keys.transport)
            .await
            .expect("a dialling endpoint");
        // The identity a device presents before it is paired carries the identifier it will be
        // given; the host assigns the record's own identity when it commits the pairing.
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

    /// Returns this device as a candidate for an invitation.
    #[must_use]
    pub fn candidate(&self) -> pairing::Candidate<'_> {
        pairing::Candidate {
            endpoint: &self.endpoint,
            identity: &self.identity,
            keys: &self.keys,
            declared: self.candidate_identity(),
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

/// A grant carrying exactly the rights named, over every environment and session.
#[must_use]
pub fn proposal(actions: &[ActionRight]) -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: kr_protocol::scalars::Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: actions.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: kr_protocol::scalars::Nullable::null(),
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
        organisation: kr_protocol::scalars::Nullable::null(),
    }
}

/// Establishes a host's first owner: pairs `owner` as a device with a personal owner grant, through
/// the initial bootstrap, over the host's own local socket.
///
/// The bootstrap's confirmations come from a key made for the ceremony, which is what the command
/// line does at an interactive terminal; the daemon cannot see that terminal, and the key proves
/// only that the same caller answered both challenges.
pub async fn bootstrap_owner(host: &Host, owner: &DeviceKeys) -> (Device, DeviceRecord) {
    let device = Device::with_keys(owner.clone()).await;
    let ceremony = DeviceKeys::generate().expect("a ceremony key");
    let signer = pairing::Signer::Bootstrap(&ceremony.authorisation);
    let mut client = host.client().await;
    let proposal = kr_pairing::grants::personal_owner_grant();
    let invited = pairing::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &proposal,
        &signer,
    )
    .await
    .expect("the host issues its first owner's invitation");
    let (connection, _candidate, _value) = pairing::redeem(&device.candidate(), &invited).await;
    let confirmed = pairing::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the first owner is confirmed");
    assert!(
        confirmed.event.first_owner,
        "the bootstrap establishes the first owner"
    );
    connection.close(0u32.into(), b"paired");
    let record = host
        .network
        .devices()
        .record_for_device(confirmed.device_id)
        .expect("readable")
        .expect("the owner device's record");
    (device, record)
}

/// Runs a complete direct pairing under an exact proposed grant, and returns the committed record.
///
/// The owner half is the owner device's: issuing an invitation and approving a candidate each
/// need a fresh owner confirmation, which that device signs after its own ceremony. The owner's
/// local client relays the proofs; the daemon checks them against the paired owner device.
pub async fn pair_with(
    host: &Host,
    device: &Device,
    owner: &DeviceKeys,
    proposal: ProposedGrant,
) -> DeviceRecord {
    let signer = pairing::Signer::OwnerDevice(owner);
    let mut client = host.client().await;
    let invited = pairing::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal,
        &signer,
    )
    .await
    .expect("an invitation");
    let (connection, mut candidate, verification_value) =
        pairing::redeem(&device.candidate(), &invited).await;
    let status = pairing::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    let shown = status
        .owner
        .0
        .and_then(|view| view.candidate.0)
        .expect("a candidate the owner is shown");
    assert_eq!(
        shown.verification_value, verification_value,
        "both devices show one value"
    );
    let confirmed = pairing::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the pairing commits");

    // And the candidate learns it happened through the surface it is already on.
    let status: PairStatusResult = candidate
        .call(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        )
        .await
        .expect("the host answers the candidate");
    assert!(
        matches!(
            status.status,
            kr_protocol::pairing::PairStatus::Committed { device_id, .. }
                if device_id == confirmed.device_id
        ),
        "the candidate is told which device it became: {:?}",
        status.status
    );
    connection.close(0u32.into(), b"paired");
    host.network
        .devices()
        .record_for_device(confirmed.device_id)
        .expect("readable")
        .expect("the device's record")
}

/// Connects a paired device to the host it was paired with.
pub async fn connect(host: &Host, device: &Device, record: &DeviceRecord) -> Session {
    let pairing = host.network.pairing();
    let host_record = PairedPeer {
        device_id: pairing.identity().device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: pairing.identity().keys.authorisation,
        endpoint_id: host.network.endpoint_id(),
    };
    let mut addr = EndpointAddr::new(
        iroh::PublicKey::from_bytes(host.network.endpoint_id().as_bytes())
            .expect("a usable endpoint identity"),
    );
    for socket in host.network.bound_sockets() {
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

/// A paired device that sends its own frames.
///
/// A client library allocates an action identity for every mutation, which is exactly right for a
/// client and no use at all to a suite that has to submit *the same* action twice. This connects
/// the same authorised transport and puts the frames on it directly.
pub struct RawDevice {
    transport: NetworkTransport,
    action_window_id: kr_protocol::ids::ActionWindowId,
    next_request: std::sync::atomic::AtomicU64,
}

impl RawDevice {
    /// Connects a paired device and claims the receive side of its control stream.
    pub async fn connect(host: &Host, device: &Device, record: &DeviceRecord) -> Self {
        let pairing = host.network.pairing();
        let host_record = PairedPeer {
            device_id: pairing.identity().device_id,
            device_key_revision: DeviceKeyRevision::new(1),
            authorisation: pairing.identity().keys.authorisation,
            endpoint_id: host.network.endpoint_id(),
        };
        let mut addr = EndpointAddr::new(
            iroh::PublicKey::from_bytes(host.network.endpoint_id().as_bytes())
                .expect("a usable endpoint identity"),
        );
        for socket in host.network.bound_sockets() {
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
        let action_window_id = {
            use kr_client::transport::ControlTransport as _;
            transport.initial_action_window().action_window_id.clone()
        };
        Self {
            transport,
            action_window_id,
            next_request: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Submits one mutation under the action identity given, and returns what the host answered.
    pub async fn mutate<P: serde::Serialize + ?Sized>(
        &self,
        method: Method,
        action_id: kr_protocol::ids::ActionId,
        target: kr_protocol::envelope::ActionTarget,
        params: &P,
    ) -> std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError> {
        self.mutate_in(
            self.action_window_id.clone(),
            method,
            action_id,
            target,
            params,
        )
        .await
    }

    /// The action window this connection was given.
    pub fn action_window_id(&self) -> kr_protocol::ids::ActionWindowId {
        self.action_window_id.clone()
    }

    /// Submits one mutation under the action identity and the action window given, which is how a
    /// device presents an action again on a later connection.
    pub async fn mutate_in<P: serde::Serialize + ?Sized>(
        &self,
        action_window_id: kr_protocol::ids::ActionWindowId,
        method: Method,
        action_id: kr_protocol::ids::ActionId,
        target: kr_protocol::envelope::ActionTarget,
        params: &P,
    ) -> std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError> {
        use kr_client::transport::ControlTransport as _;
        use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue};

        let request_id = kr_protocol::ids::RequestId::new(
            self.next_request
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let frame = ControlFrame::Mutation(Box::new(MutationRequest {
            request_id,
            method: method.into(),
            method_version: method.entry().version,
            action_id,
            grant_id: kr_protocol::scalars::Nullable::null(),
            target,
            expected: ParamsValue::empty(),
            action_window_id,
            requested_ttl_ms: kr_protocol::scalars::DurationMs::new(120_000),
            params: ParamsValue::from_typed(params).expect("the parameters encode"),
        }));
        self.transport
            .send(&frame)
            .await
            .expect("the frame is sent");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let frame = tokio::time::timeout_at(deadline, self.transport.recv())
                .await
                .expect("the host answers in time")
                .expect("the control stream is open")
                .expect("the host does not close the stream");
            if let ControlFrame::Response(response) = frame
                && response.request_id == request_id
            {
                return match response.outcome {
                    Outcome::Ok(value) => Ok(value),
                    Outcome::Error(error) => Err(error),
                };
            }
        }
    }

    /// Sends one read, and returns what the host answered.
    pub async fn read<P: serde::Serialize + ?Sized>(
        &self,
        method: Method,
        params: &P,
    ) -> std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError> {
        use kr_client::transport::ControlTransport as _;
        use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};

        let request_id = kr_protocol::ids::RequestId::new(
            self.next_request
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let frame = ControlFrame::Request(Request {
            request_id,
            method: method.into(),
            method_version: method.entry().version,
            params: ParamsValue::from_typed(params).expect("the parameters encode"),
        });
        self.transport
            .send(&frame)
            .await
            .expect("the frame is sent");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let frame = tokio::time::timeout_at(deadline, self.transport.recv())
                .await
                .expect("the host answers in time")
                .expect("the control stream is open")
                .expect("the host does not close the stream");
            if let ControlFrame::Response(response) = frame
                && response.request_id == request_id
            {
                return match response.outcome {
                    Outcome::Ok(value) => Ok(value),
                    Outcome::Error(error) => Err(error),
                };
            }
        }
    }

    /// Claims the receive side, which exactly one reader may hold.
    pub fn claim(&self) {
        use kr_client::transport::ControlTransport as _;
        self.transport.claim_receiver().expect("the only reader");
    }

    /// Ends the connection.
    pub fn close(&self) {
        use kr_client::transport::ControlTransport as _;
        self.transport.close();
    }
}

/// Pairs one device under the rights named and connects it, in one step.
pub async fn paired_device(
    host: &Host,
    owner: &DeviceKeys,
    actions: &[ActionRight],
) -> (Device, Session) {
    let device = Device::create().await;
    let record = pair_with(host, &device, owner, proposal(actions)).await;
    let session = connect(host, &device, &record).await;
    (device, session)
}

/// Returns the refusal a call answered with.
///
/// # Panics
///
/// Panics when the call succeeded.
#[must_use]
pub fn refusal<T>(outcome: std::result::Result<T, ProtocolError>) -> ProtocolError {
    match outcome {
        Ok(_) => panic!("this call is refused"),
        Err(error) => error,
    }
}
