//! The whole network path, with real processes and a real connection.
//!
//! A control daemon on the network, a worker it started, a real shell in a real pseudo-terminal,
//! and a device that pairs over iroh and then does what a device does: attaches, subscribes to the
//! session's output from a cursor, takes the input lease, types, loses its connection, reconnects
//! and resumes from where its content had reached. Then the two things that must hold when
//! authority changes underneath it: a revoked device is fenced before it is served again, and the
//! remote path ending takes neither the worker nor a local attachment with it.
//!
//! Every path here is on the internal disk: the worker is copied there before it is started, and
//! the host gives it a working directory of its own there rather than letting it inherit this
//! process's. A process a service manager launches is its own identity to the operating system,
//! and one that reaches a removable volume asks the person sitting at the machine for permission;
//! a test suite must never do that, so every create checks what the kernel actually gave the
//! process it started.
//!
//! The session this drives is a POSIX shell in a Unix pseudo-terminal, signalled by process group
//! and read from the process table, so the suite is a Unix suite. The Windows equivalents of the
//! same paths are qualified against a Windows console in the worker's Windows module.

#![cfg(unix)]

#[allow(dead_code)]
#[path = "net_support/pairing.rs"]
mod pairing_calls;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::cursors::{Restoration, RestorationStep};
use kr_client::ipc::IpcTransport;
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_controller::registry::Registry;
use kr_controller::service::net::devices::DeviceRecord;
use kr_controller::service::net::{self, Network, NetworkSetup};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_pairing::direct::CandidateIdentity;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::hostinfo::configuration::Change;
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, DeviceId, DeviceKeyRevision, EnvironmentId, SessionId,
    StreamId,
};
use kr_protocol::input::{
    InputAcquireParams, InputAcquireResult, InputWriteParams, InputWriteResult,
};
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::pairing::{DeviceName, DevicePlatform, ProposedGrant};
use kr_protocol::preauth::{PairStatusParams, PairStatusResult};
use kr_protocol::recovery::{EventStream, EventsSubscribeResult, OutputEvent};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64, Uuid};
use kr_protocol::session::{
    Presentation, SessionCloseParams, SessionCreateParams, SessionCreateResult, SessionReadParams,
    SessionReadResult, SessionState, ShellMode,
};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::LocalIdentity;
use kr_transport::scheduler::SendLimits;

mod teardown;

/// How long a test waits for something the machine has to do before it calls it a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// What the shell prints when it has actually run what was typed.
///
/// The command's own text does not contain it, so a terminal that merely echoed the keystrokes
/// cannot satisfy an assertion about it: what passes is the shell having executed the command.
const MARKER: &str = "kalareach-ran";

/// The command that produces it.
const MARKER_COMMAND: &str = "printf 'kala%s-ran\n' reach\n";

/// What a second command prints, and the command that prints it.
///
/// The resume below is only worth checking from a position the session actually reached, and a
/// client that has applied nothing but the *first* chunk of a stream holds position zero honestly.
/// So something is produced, waited for and applied before the position that travels is taken: the
/// first command's bytes are then behind the second command's chunk, and the cursor the client
/// carries is a resume rather than a restart.
///
/// What this replaced was an accident of the host. On the machine this suite was written on,
/// `/bin/sh` printed a diagnostic of its own before any device subscribed, so the subscription
/// opened above zero and every later chunk began above zero with it; on the build box the same
/// `/bin/sh` printed nothing, the subscription opened at zero, and the one chunk that carried the
/// marker began there too. Whatever a host's shell says at startup, the position below is now one
/// this test put there.
const SECOND_MARKER: &str = "kalareach-again";

/// The command that produces it.
const SECOND_MARKER_COMMAND: &str = "printf 'kala%s-again\n' reach\n";

/// A host tree on the internal disk, with the worker beside it.
struct Host {
    /// The host tree, which ends every worker its daemon started before it goes, and is kept
    /// instead when one of them cannot be established as ended.
    temp: teardown::Tree,
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
        let temp = teardown::Tree::create();
        let environment_id = temp.environment_id();
        let worker = temp.root().join("kr-worker");
        // Started once here, where nothing is timed, so the operating system's check of a new
        // executable is not paid inside a create's rendezvous.
        kr_ipc::testing::place_and_start_once(&worker_build, &worker, &["--version"]);
        Some(Self {
            temp,
            worker,
            environment_id,
        })
    }

    fn paths(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.tree().environment()
    }

    fn tree(&self) -> &kr_ipc::testing::TempHost {
        &self.temp
    }

    /// Starts the daemon and puts it on the network with the endpoint configuration given.
    async fn start(&self, endpoint: EndpointConfig, owner: &DeviceKeys) -> RunningDaemon {
        // The owner device dials from an endpoint configured like the host's own.
        let endpoint_for_owner = endpoint.clone();
        let environment = self.paths();
        let environment_id = self.environment_id;
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: self.temp.supervisor(Box::new(DetachedSupervisor::new())),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
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
        // The network is registered here rather than from the environment, because this test gives
        // the endpoint a configuration of its own. Its device keys live in memory and go with it.
        let network = net::register(
            &controller,
            NetworkSetup {
                settings: kr_controller::service::net::config::NetworkSettings {
                    endpoint,
                    ..kr_controller::service::net::config::NetworkSettings::default()
                },
                secrets: Arc::new(MemoryStore::new()),
                rendezvous: None,
            },
        )
        .await
        .expect("the daemon joins the network");
        let daemon = RunningDaemon {
            controller,
            network,
            serving,
        };
        bootstrap_owner(&daemon, &endpoint_for_owner, owner).await;
        daemon
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

/// Returns the worker binary beside this test's own.
///
/// # Panics
///
/// Panics when the build has not produced one. A suite that skipped instead would report a pass
/// for something it never ran, which is worse than a failure: this is why every test here is
/// `#[ignore]`d and run by `scripts/end-to-end.sh`, which builds the worker first.
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
    assert!(
        worker.is_file(),
        "this suite launches a worker process and there is none at {}; build it with \
         `cargo build -p kr-worker` or run `scripts/end-to-end.sh`, which does",
        worker.display()
    );
    Some(worker)
}

struct RunningDaemon {
    controller: Arc<Controller>,
    network: Network,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

impl RunningDaemon {
    /// Returns the environment this daemon serves.
    fn environment_id(&self) -> EnvironmentId {
        self.controller.paths().environment_id()
    }

    /// Connects the owner's own client on this daemon's local socket.
    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self
                .controller
                .paths()
                .controller_endpoint()
                .expect("an endpoint"),
            LocalClientKind::Cli,
            build(),
        )
        .await
        .expect("connects to the daemon")
    }

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
        palette: Nullable::null(),
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
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

async fn create(client: &mut LocalClient, host: &Host) -> SessionCreateResult {
    let created: SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host.environment_id, host.tree().root()),
        )
        .await
        .expect("the call reaches the daemon")
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the create failed: {error}"));
    runs_where_the_host_put_it(host, created.session.session_id);
    created
}

/// Returns the working directory the operating system gave a running process.
///
/// Read from the process table rather than from anything this test arranged: what is being checked
/// is what the process actually got, and a launch that quietly inherited a directory looks exactly
/// like one that was given the right one until the kernel is asked. `None` means this platform has
/// no way to ask; a platform that has one and refuses to answer is a failure, not a skip.
fn working_directory_of(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(
            std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|error| {
                panic!("the working directory of process {pid} could not be read: {error}")
            }),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-a", "-d", "cwd", "-p", &pid.to_string(), "-Fn"])
            .output()
            .unwrap_or_else(|error| panic!("the process table could not be read: {error}"));
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| line.strip_prefix('n').map(PathBuf::from))
                .unwrap_or_else(|| {
                    panic!("the process table named no working directory for process {pid}")
                }),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Asserts that the worker this host started runs in the directory the host gave it.
///
/// A worker is deliberately not a child of the process that asked for it, so it inherits nothing
/// worth having: a directory inherited from the daemon belongs to whoever started the daemon, and
/// on this machine that is a build tree on a removable volume. A process holding one open is a
/// volume the person at the machine cannot eject and, on macOS, a permission prompt for every
/// rebuilt binary.
fn runs_where_the_host_put_it(host: &Host, session_id: SessionId) {
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let worker = registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("the created session has a worker record");
    let pid = u32::try_from(worker.process_identity.pid.get()).expect("a process identifier");
    let expected = std::fs::canonicalize(host.paths().worker_dir(session_id))
        .expect("the worker's own directory exists");
    // Checked whatever the process table can be asked: the directory the host configured and the
    // binary it started are both outside the workspace, which may be on a removable volume.
    let workspace = workspace_root();
    assert!(
        !expected.starts_with(&workspace),
        "no process this suite starts has a working directory inside the workspace: {}",
        expected.display()
    );
    assert!(
        !host.worker.starts_with(&workspace),
        "and the binary it started is not inside it either: {}",
        host.worker.display()
    );
    let Some(actual) = working_directory_of(pid) else {
        // Nothing to compare against rather than a comparison that failed. Saying so is better
        // than a pass that checked nothing.
        eprintln!(
            "skipped: this platform does not report another process's working directory here"
        );
        return;
    };
    assert_eq!(
        std::fs::canonicalize(&actual).unwrap_or(actual),
        expected,
        "the worker runs in the directory the host configured"
    );
}

/// Returns the workspace this test was built from.
fn workspace_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `<workspace>/crates/<crate>`.
    root.pop();
    root.pop();
    std::fs::canonicalize(&root).unwrap_or(root)
}

/// What a device the host has never seen looks like.
struct Device {
    keys: DeviceKeys,
    endpoint: Endpoint,
    identity: Arc<LocalIdentity>,
}

impl Device {
    async fn create(config: &EndpointConfig) -> Self {
        Self::with_keys(config, DeviceKeys::generate().expect("device keys")).await
    }

    /// Creates an unpaired device holding `keys`.
    async fn with_keys(config: &EndpointConfig, keys: DeviceKeys) -> Self {
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

    /// Returns this device as a candidate for an invitation.
    fn candidate(&self) -> pairing_calls::Candidate<'_> {
        pairing_calls::Candidate {
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

/// Pairs `owner` as the host's first owner device, through the initial bootstrap.
///
/// The owner's own client does it over the host's local socket, as a person's first pairing does;
/// every later confirmation in these suites is that owner device's.
async fn bootstrap_owner(daemon: &RunningDaemon, config: &EndpointConfig, owner: &DeviceKeys) {
    let device = Device::with_keys(config, owner.clone()).await;
    let ceremony = DeviceKeys::generate().expect("a ceremony key");
    let signer = pairing_calls::Signer::Bootstrap(&ceremony.authorisation);
    let mut client = daemon.client().await;
    let environment = daemon.environment_id();
    let invited = pairing_calls::invite_direct(
        environment,
        &mut client,
        InviteGrantKind::PersonalOwner,
        &kr_pairing::grants::personal_owner_grant(),
        &signer,
    )
    .await
    .expect("the host issues its first owner's invitation");
    let (connection, _candidate, _value) =
        pairing_calls::redeem(&device.candidate(), &invited).await;
    let confirmed =
        pairing_calls::confirm_candidate(environment, &mut client, invited.invitation_id, &signer)
            .await
            .expect("the first owner is confirmed");
    assert!(confirmed.event.first_owner);
    connection.close(0u32.into(), b"paired");
}

/// Runs a complete direct pairing, and returns the record the host committed.
///
/// The owner half is the owner device's: issuing an invitation and approving a candidate each
/// need a fresh owner confirmation, which that device signs after its own ceremony and the owner's
/// local client relays. The daemon checks each against the paired owner device and spends it once.
async fn pair(daemon: &RunningDaemon, device: &Device, owner: &DeviceKeys) -> DeviceRecord {
    pair_with(daemon, device, owner, proposal()).await
}

/// Runs a complete direct pairing under an exact proposed grant.
async fn pair_with(
    daemon: &RunningDaemon,
    device: &Device,
    owner: &DeviceKeys,
    proposal: ProposedGrant,
) -> DeviceRecord {
    let mut client = daemon.client().await;
    let invited = invite(daemon, &mut client, owner, &proposal).await;
    redeem(daemon, &mut client, device, owner, &invited).await
}

/// Issues a direct invitation under an exact proposed grant, on the owner device's confirmation.
async fn invite(
    daemon: &RunningDaemon,
    client: &mut LocalClient,
    owner: &DeviceKeys,
    proposal: &ProposedGrant,
) -> kr_protocol::invitation::PairInviteResult {
    pairing_calls::invite_direct(
        daemon.environment_id(),
        client,
        InviteGrantKind::SessionInvitation,
        proposal,
        &pairing_calls::Signer::OwnerDevice(owner),
    )
    .await
    .expect("an invitation")
}

/// Redeems a direct invitation as the candidate that scanned it, and has the owner device approve
/// the candidate, and returns the record the host committed.
async fn redeem(
    daemon: &RunningDaemon,
    client: &mut LocalClient,
    device: &Device,
    owner: &DeviceKeys,
    invited: &kr_protocol::invitation::PairInviteResult,
) -> DeviceRecord {
    let signer = pairing_calls::Signer::OwnerDevice(owner);
    let environment = daemon.environment_id();
    let (connection, mut candidate, verification_value) =
        pairing_calls::redeem(&device.candidate(), invited).await;
    assert_eq!(verification_value.len(), 8);

    // The owner approves exactly what both devices displayed.
    let status = pairing_calls::owner_status(client, invited.invitation_id)
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
    let confirmed =
        pairing_calls::confirm_candidate(environment, client, invited.invitation_id, &signer)
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
    daemon
        .network
        .devices()
        .record_for_device(confirmed.device_id)
        .expect("readable")
        .expect("the device's record")
}

/// Connects a paired device and starts one session over it.
async fn connect(daemon: &RunningDaemon, device: &Device, record: &DeviceRecord) -> Session {
    let host_record = PairedPeer {
        device_id: daemon.network.pairing().identity().device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: daemon.network.pairing().identity().keys.authorisation,
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

/// What one device holds on a session: the attachment it watches with, and the one it types on.
struct Attached {
    /// The attachment whose output this device follows, and whose cursor it carries.
    watching: AttachmentId,
    /// The attachment that takes the input lease.
    typing: AttachmentId,
    /// What the subscription on `watching` returned.
    subscribed: EventsSubscribeResult,
}

/// Attaches twice, subscribes the watching attachment from a cursor, and returns both.
///
/// Watching and typing are separate attachments because the two are sent different kinds of
/// chunk, and they count differently. A projected attachment is sent a rendering of the screen at
/// the cursor it names, so that cursor is the position applying the chunk reaches. The holder of
/// the input lease is *additionally* sent the application's own replies, which are a span of the
/// stream and carry the position their bytes begin at. Keeping the roles apart is what makes every
/// chunk this test applies one whose own cursor is the position it reached, which is what the
/// restoration later resumes from.
async fn attach(
    session: &Session,
    environment_id: EnvironmentId,
    session_id: SessionId,
) -> Attached {
    let watching = attach_one(
        session,
        environment_id,
        session_id,
        &[AttachmentCapability::ObserveTerminal],
    )
    .await;
    let typing = attach_one(
        session,
        environment_id,
        session_id,
        &[
            AttachmentCapability::ObserveTerminal,
            AttachmentCapability::Input,
        ],
    )
    .await;

    // Section 8's order: subscribe from the cursor first, then install what it returns. The
    // subscription is opened before the events it queues are read, and the events themselves are
    // what the restoration installs, so nothing here pretends to have installed a snapshot it was
    // never given.
    let mut restoration = Restoration::start(output_stream(), &session.cursors().await);
    let params = restoration
        .subscribe_params(session_id, watching, &[EventStream::Output])
        .expect("the stream is waiting to subscribe");
    let subscribed = session
        .subscribe_events(&params)
        .await
        .expect("the subscription succeeds");
    restoration.subscribed().expect("the order is kept");
    Attached {
        watching,
        typing,
        subscribed,
    }
}

/// Attaches once with the capabilities asked for.
async fn attach_one(
    session: &Session,
    environment_id: EnvironmentId,
    session_id: SessionId,
    requested: &[AttachmentCapability],
) -> AttachmentId {
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
                requested: requested.iter().copied().collect(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the attach is settled")
        .to_typed()
        .expect("an attachment");
    attached.attachment.attachment_id
}

/// Reads the session's output until `wanted` appears, applying everything it takes as it goes.
///
/// This is what installing a restoration and following the stream looks like from a client: every
/// event is folded into the client's state and its content position moves with it, so the position
/// a later reconnect resumes from is one a consumer actually reached.
async fn observe(
    session: &Session,
    events: &mut tokio::sync::broadcast::Receiver<kr_protocol::envelope::Notification>,
    wanted: &str,
) -> String {
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
        // The event's own cursor, never a position derived from how many bytes it carried. One
        // event type carries two things: a span of the stream, whose cursor is where its bytes
        // begin, and a rendering of the canonical screen, whose cursor is the state it describes.
        // A length added to the first would be right and added to the second would claim a
        // position the session never produced, so this test adds it to neither and holds the
        // start of the last chunk it applied. That is a position it has certainly reached, and
        // what a reconnect from it is given is the screen as it stands at the host's cursor, not
        // those bytes over again.
        session
            .applied_content(&output_stream(), event.cursor)
            .await;
        session
            .applied(&output_stream(), notification.sequence)
            .await;
        if seen.contains(wanted) {
            return seen;
        }
    }
    panic!("the session's output never carried {wanted:?}: {seen:?}");
}

/// Reads the session's output until `wanted` appears, applying none of it.
///
/// Being handed bytes and having consumed them are two different things, and only the second moves
/// the content position a reconnect resumes from. A test that has to know the session produced
/// something, and must still be a client that never applied it, waits here: the events are read
/// off the connection and nothing is folded into the client's state.
async fn received_without_applying(
    events: &mut tokio::sync::broadcast::Receiver<kr_protocol::envelope::Notification>,
    wanted: &str,
) -> String {
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
        if seen.contains(wanted) {
            return seen;
        }
    }
    panic!("the session's output never carried {wanted:?}: {seen:?}");
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
    observe(session, &mut events, MARKER).await
}

/// Closes a session and waits for the daemon to record that its worker has gone.
///
/// A worker is deliberately not a child of whatever created it, so a test that only asked for a
/// close and walked away would leave a process running until the machine was restarted. The
/// acceptance says `closing`; this waits for the record.
async fn close_session(client: &mut LocalClient, host: &Host, session_id: SessionId) {
    let _ = client
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
        .await
        .expect("the call reaches the daemon");
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while tokio::time::Instant::now() < deadline {
        let listed: kr_protocol::session::SessionListResult = client
            .request(
                Method::SessionList,
                &kr_protocol::session::SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the list succeeds")
            .to_typed()
            .expect("decodes");
        if listed.sessions.iter().any(|summary| {
            summary.session_id == session_id && summary.state == SessionState::Closed
        }) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the session did not finish closing");
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
/// KR-REQ-17.12: direct iroh connections and local pairing need no KalaReach account. Neither the
/// host nor the device configures an account, a relay, discovery or any managed service, and the
/// device still pairs by the host's invitation and runs a live session over direct iroh.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_attaches_subscribes_types_and_resumes_from_its_cursor() {
    // KR-REQ-01.07: a device pairs with the host and uses a live session over iroh with no
    // KalaReach account configured, and no relay, discovery or managed service either: both
    // endpoints are loopback iroh endpoints and nothing else.
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

    let attached = attach(&session, host.environment_id, session_id).await;
    assert!(
        attached.subscribed.gap.as_ref().is_none(),
        "a fresh subscription has no gap in its history"
    );
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attached.typing,
        MARKER_COMMAND,
    )
    .await;
    assert!(seen.contains(MARKER));

    // A second command, waited for like the first, on the lease the first one took. It is what
    // puts the first command's bytes behind the position the client carries below, whatever this
    // host's shell printed before any of this started.
    let mut events = session.events();
    session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id: attached.typing,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(1),
            sequence: kr_protocol::ids::InputSequence::new(1),
            bytes: kr_protocol::scalars::Bytes::new(SECOND_MARKER_COMMAND.as_bytes().to_vec()),
        })
        .await
        .expect("the second command is accepted");
    let seen = observe(&session, &mut events, SECOND_MARKER).await;
    assert!(seen.contains(SECOND_MARKER));

    // Something is typed that the device will *not* apply, and then its connection is lost. What
    // matters below is that the device never applied it, so the restoration has to bring it.
    let away = "printf 'while%s-away\n' -it\n";
    session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id: attached.typing,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(1),
            sequence: kr_protocol::ids::InputSequence::new(2),
            bytes: kr_protocol::scalars::Bytes::new(away.as_bytes().to_vec()),
        })
        .await
        .expect("the third batch is accepted");

    // The session is left to produce it, and this connection is given it without applying any of
    // it: being handed bytes is not the same as having consumed them, and what travels across a
    // reconnect is the position a consumer reached. So the position the device carries is still
    // the second command's, and everything below rests on content this test has watched arrive
    // rather than on the session having produced it by some moment after the connection went.
    let produced = received_without_applying(&mut events, "while-it-away").await;
    assert!(
        produced.contains("while-it-away"),
        "the session produced what was typed and not waited for: {produced:?}"
    );

    // The control stream is lost. What the client carries across is the content position, not the
    // previous connection's event sequences.
    let carried = kr_client::reconnect::ClientState::from_session(&session, None).await;
    session.close();
    drop(session);

    // A local caller reads the retained history on the worker's own endpoint and finds what was
    // typed but never waited for. That is what makes the restoration on the next connection worth
    // checking — the content exists, at a position past the one the device carried, and the device
    // has not applied it.
    let mut on_worker = LocalClient::connect(
        &kr_ipc::paths::Endpoint::from_path(
            created
                .endpoint
                .as_ref()
                .cloned()
                .expect("a live session names its worker"),
        )
        .expect("a worker endpoint"),
        LocalClientKind::Cli,
        build(),
    )
    .await
    .expect("the local client reaches the worker");
    // Page by page, each carrying on from where the last one ended, so what comes back is the
    // history once rather than the same range as many times as it was asked for.
    let mut from_cursor = U64::ZERO;
    let mut retained = String::new();
    loop {
        let page: kr_protocol::recovery::HistoryPageResult = on_worker
            .request(
                Method::HistoryPage,
                &kr_protocol::recovery::HistoryPageParams {
                    session_id,
                    from_cursor,
                    max_bytes: U64::new(256 * 1024),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the page is served")
            .to_typed()
            .expect("decodes");
        if page.bytes.as_slice().is_empty() {
            break;
        }
        retained.push_str(&String::from_utf8_lossy(page.bytes.as_slice()));
        from_cursor = page.next_cursor;
    }
    assert!(
        retained.contains("while-it-away"),
        "the retained history holds what the device never applied: {retained:?}"
    );

    let resumed_from = carried
        .cursors
        .applied_cursor(&output_stream())
        .expect("the client holds a position");
    assert!(
        resumed_from.get() > 0,
        "the position that travels is one the session reached, not the start of its stream"
    );
    assert_eq!(
        carried.cursors.received(&output_stream()),
        None,
        "the previous connection's event sequences do not travel"
    );

    // A reconnect resumes the cursors it carried, and the subscription it opens is asked to start
    // from exactly them.
    let transport = NetworkTransport::connect(
        &device.endpoint,
        host_addr_of(&daemon),
        &device.paired_identity(record.device_id),
        &host_paired_record(&daemon),
        SendLimits::default(),
    )
    .await
    .expect("the device reconnects");
    let session = Session::resume(Arc::new(transport), carried.cursors).expect("a resumed session");
    let restoration = Restoration::start(output_stream(), &session.cursors().await);
    assert_eq!(
        restoration.step(),
        RestorationStep::SubscribeFrom(resumed_from),
        "the reconnect subscribes from the cursor it carried"
    );
    let mut events = session.events();
    let resumed = attach(&session, host.environment_id, session_id)
        .await
        .subscribed;
    assert!(
        resumed.from_cursor.get() >= resumed_from.get(),
        "a resumed subscription starts no earlier than the position the client held"
    );
    // And the screen it is drawn carries content this client never applied. That is the
    // restoration, and it is what it can claim: the client asked from the position it held and was
    // given the screen as it stands at the host's cursor, rather than the bytes from that position
    // over again. Whether the session produced that content before this connection went or after
    // is the machine's business and this test does not depend on which.
    let restored = observe(&session, &mut events, "while-it-away").await;
    assert!(
        restored.contains("while-it-away"),
        "the restoration carries content this client never applied: {restored:?}"
    );
    drop(on_worker);

    session.close();
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// Returns the address a device dials this host at, from the endpoint's own bound sockets.
fn host_addr_of(daemon: &RunningDaemon) -> EndpointAddr {
    let mut addr = EndpointAddr::new(
        iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
            .expect("a usable endpoint identity"),
    );
    for socket in daemon.network.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

fn host_paired_record(daemon: &RunningDaemon) -> PairedPeer {
    let pairing = daemon.network.pairing();
    PairedPeer {
        device_id: pairing.identity().device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: pairing.identity().keys.authorisation,
        endpoint_id: daemon.network.endpoint_id(),
    }
}

// Ignored by default like the rest of this suite: the host fixture needs the worker binary that
// `scripts/end-to-end.sh` builds, and that script runs the suite with `--include-ignored`.
/// KR-REQ-17.45: a host's current direct addresses reach a device through the pairing exchange
/// rather than through any lookup. Neither the host nor the device selects a relay or a discovery
/// service. The invitation the host issues carries exactly the addresses its endpoint is bound to
/// now, and a device that knows nothing but the invitation dials the host there and pairs.
#[ignore = "starts a control daemon; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_invitation_carries_the_hosts_current_direct_addresses() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;

    let proposed = proposal();
    let mut client = daemon.client().await;
    let invited = invite(&daemon, &mut client, &owner, &proposed).await;
    let payload = pairing_calls::direct_payload(&invited);
    let bound: BTreeSet<String> = daemon
        .network
        .bound_sockets()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(!bound.is_empty(), "the host is bound to direct addresses");
    let hinted: BTreeSet<String> = payload
        .network_config
        .direct_addresses
        .iter()
        .map(|hint| hint.as_str().to_owned())
        .collect();
    assert_eq!(
        hinted, bound,
        "the invitation carries the addresses the host is bound to now"
    );
    let selected = &payload.network_config;
    assert!(
        selected.relay_urls.is_empty()
            && selected.pkarr_publisher_url.as_ref().is_none()
            && selected.pkarr_resolver_url.as_ref().is_none()
            && selected.dns_origin.as_ref().is_none(),
        "and nothing a device could look the host up in"
    );

    // The device dials the host at the invitation's hints and nowhere else, and the pairing
    // completes over that path.
    let device = Device::create(&loopback()).await;
    let record = redeem(&daemon, &mut client, &device, &owner, &invited).await;
    assert!(
        daemon
            .network
            .devices()
            .record_for_device(record.device_id)
            .expect("reads the device records")
            .is_some(),
        "the host recorded the device it paired with"
    );

    daemon.stop().await;
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
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
    let _attached = attach(&session, host.environment_id, session_id).await;

    // The device is revoked while its connection is authorised and its subscription is running.
    daemon
        .network
        .revoke_device(record.device_id)
        .await
        .expect("the revocation is recorded");

    // The fence is not a recorded state the next request happens to notice: withdrawing the
    // registration takes the connection's write boundary with it and ends the connection, so there
    // is no further read and no further dispatch on it at all.
    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err("a revoked device is refused");
    assert_eq!(
        refused.code(),
        ErrorCode::ResourceUnavailable,
        "the connection a revoked device held is ended rather than answered"
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
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// The rights paired devices keep when the owner withholds viewing, as the document writes them.
fn without_viewing() -> Vec<String> {
    [
        ActionRight::TerminalInput,
        ActionRight::SessionCreate,
        ActionRight::SessionClose,
    ]
    .iter()
    .map(|right| right.as_str().to_owned())
    .collect()
}

/// A device subscribed under a rights ceiling that went into force while an effect after it failed.
///
/// The accepted document withholds viewing. A wider ceiling goes into force through an edit whose
/// profile change cannot be applied, so the document this host last finished accepting is still
/// the one that withholds viewing, and a device connects and subscribes under the wider ceiling.
/// Then the fault clears.
struct SubscribedUnderAFailedWidening {
    local: LocalClient,
    session_id: SessionId,
    device: Device,
    record: DeviceRecord,
    session: Session,
}

async fn subscribed_under_a_failed_widening(
    host: &Host,
    daemon: &RunningDaemon,
    owner: &DeviceKeys,
) -> SubscribedUnderAFailedWidening {
    let mut local = host.client().await;
    let created = create(&mut local, host).await;
    let session_id = created.session.session_id;
    let device = Device::create(&loopback()).await;
    let record = pair(daemon, &device, owner).await;

    daemon
        .controller
        .apply_configuration(&Change::GrantRights(Some(without_viewing())))
        .await
        .expect("the owner withholds viewing from every paired device");

    // The capability revision is stored in a file, and a directory in its place is a write this
    // host cannot make. A profile change owes that write, so an edit carrying one is written and
    // is not in force.
    let blocked = host
        .paths()
        .state_dir()
        .join(kr_controller::service::CAPABILITY_REVISION_FILE);
    std::fs::create_dir(&blocked).expect("something in the place the revision is written to");
    let profile = match daemon.controller.default_profile().await {
        kr_protocol::identity::WorkerProfile::HeadlessUser => {
            kr_protocol::identity::WorkerProfile::DesktopBound
        }
        _ => kr_protocol::identity::WorkerProfile::HeadlessUser,
    };
    daemon
        .controller
        .apply_configuration(&Change::WorkerProfile(profile))
        .await
        .expect_err("the evidence taken under the old profile cannot be replaced");
    // The ceiling widens while that effect is still owed. The wider ceiling decides requests from
    // here on; the document this host finished accepting is still the one that withholds viewing.
    let mut with_viewing = without_viewing();
    with_viewing.push(ActionRight::SessionView.as_str().to_owned());
    let failed = daemon
        .controller
        .apply_configuration(&Change::GrantRights(Some(with_viewing)))
        .await
        .expect_err("the profile's effect still fails");
    assert!(
        failed.to_string().contains("is not in force"),
        "the caller is told the edit is not in force: {failed}"
    );

    // A device connects under the wider ceiling, and its subscription runs.
    let session = connect(daemon, &device, &record).await;
    let attached = attach(&session, host.environment_id, session_id).await;
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attached.typing,
        MARKER_COMMAND,
    )
    .await;
    assert!(seen.contains(MARKER));

    std::fs::remove_dir(&blocked).expect("the fault is cleared");
    SubscribedUnderAFailedWidening {
        local,
        session_id,
        device,
        record,
        session,
    }
}

/// Asserts that a device's connection has been ended rather than answered.
async fn ended(session: &Session, session_id: SessionId, why: &str) {
    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err(why);
    assert_eq!(
        refused.code(),
        ErrorCode::ResourceUnavailable,
        "{why}: the connection is ended rather than answered: {refused}"
    );
}

/// KR-REQ-26.15: a narrowing is measured against the rights ceiling in force, not only against
/// the document this host last finished accepting.
///
/// The two part after an edit whose ceiling went into force while an effect after it failed.
/// Narrowing back to exactly what the accepted document said still withdraws viewing from the
/// device that subscribed under the wider ceiling, so its connection and subscription are fenced
/// before the narrowing is acknowledged.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_narrowing_after_a_failed_widening_fences_the_subscription_the_widening_admitted() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let widened = subscribed_under_a_failed_widening(&host, &daemon, &owner).await;
    let session_id = widened.session_id;

    let applied = daemon
        .controller
        .apply_configuration(&Change::GrantRights(Some(without_viewing())))
        .await
        .expect("the narrowing is acknowledged");
    assert!(
        applied.fences_dispatch,
        "withdrawing what the ceiling in force allowed owes a fence"
    );
    assert!(applied.barrier_holds);
    // Acknowledged means fenced.
    ended(
        &widened.session,
        session_id,
        "the connection admitted under the wider ceiling is fenced",
    )
    .await;
    widened.session.close();

    // A new connection is decided under the narrow ceiling.
    let session = connect(&daemon, &widened.device, &widened.record).await;
    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err("viewing is withheld");
    assert!(
        refused
            .to_string()
            .contains("this host's configuration removes session.view"),
        "{refused}"
    );
    session.close();

    // The fence withdrew the owner's connection as well, like every connection admitted under
    // the revision it replaced, so the owner closes the session on a new one.
    drop(widened.local);
    let mut local = host.client().await;
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// KR-REQ-26.15: a fence a narrowing owed and could not raise stays owed until one is raised.
///
/// The narrowing comes while the registry refuses the revision's write, so its debt is written and
/// the ceiling narrows, the revision cannot advance, and the edit is not acknowledged. Once the
/// write is taken again, the same document read again moves nothing, against the document
/// accepted or against the ceiling in force, and the fence it owes is raised all the same: the
/// revision advances and the subscription admitted under the wider ceiling ends.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_a_narrowing_could_not_raise_is_raised_by_the_next_reading() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let widened = subscribed_under_a_failed_widening(&host, &daemon, &owner).await;
    let session_id = widened.session_id;
    let before = daemon
        .controller
        .authority_revision()
        .await
        .expect("the revision in force");

    // The registry refuses the revision's write, as a full disk would. Every other write goes on,
    // the ceiling's debt among them, so the ceiling narrows and only its fence cannot be raised.
    // Locking the whole registry instead would stop the debt, and with it the ceiling, first.
    let blocker = rusqlite::Connection::open(host.paths().registry_database())
        .expect("a second connection to this environment's registry");
    blocker
        .execute_batch(
            "CREATE TRIGGER refuse_revision BEFORE UPDATE OF authority_revision ON environment
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the revision's write is refused");
    let unfenced = daemon
        .controller
        .apply_configuration(&Change::GrantRights(Some(without_viewing())))
        .await
        .expect_err("a narrowing whose fence cannot be raised is not acknowledged");
    assert!(
        unfenced
            .to_string()
            .contains("dispatch could not be fenced"),
        "{unfenced}"
    );

    blocker
        .execute_batch("DROP TRIGGER refuse_revision;")
        .expect("the revision's write is taken again");
    drop(blocker);
    let effective = daemon.controller.effective_configuration().await;
    assert!(
        effective.not_in_force.0.is_none(),
        "the next reading raised the fence: {:?}",
        effective.not_in_force
    );
    let after = daemon
        .controller
        .authority_revision()
        .await
        .expect("the revision in force");
    assert!(after > before, "the revision advanced once it could");
    ended(
        &widened.session,
        session_id,
        "the connection admitted under the wider ceiling is fenced",
    )
    .await;
    widened.session.close();

    drop(widened.local);
    let mut local = host.client().await;
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// A grant this host's clock floor has passed has expired, whatever the deadline its connection
/// anchored still says.
///
/// Another decision on this host read a wall clock past the grant's expiry, and the floor moved
/// with it. The next request the device makes finds the grant expired: the connection is ended
/// with its subscription, the expiry is written down, and the device cannot come back on another
/// connection.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_the_clock_floor_expired_ends_the_subscription_and_stays_expired() {
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
    let GrantExpiry::At { expires_at_ms } = record.grant.expiry else {
        panic!("a session invitation expires");
    };

    let session = connect(&daemon, &device, &record).await;
    let attached = attach(&session, host.environment_id, session_id).await;
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attached.typing,
        MARKER_COMMAND,
    )
    .await;
    assert!(seen.contains(MARKER));

    // The deadline this connection anchored when it was admitted is still a day away.
    daemon
        .controller
        .update_policy(|policy| policy.observe_utc(expires_at_ms.get() + 1))
        .expect("the floor moves past the grant's expiry");

    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err("the grant has expired by the floor");
    assert_eq!(
        refused.code(),
        ErrorCode::ResourceUnavailable,
        "the connection and its subscription are ended rather than answered: {refused}"
    );
    let stored = daemon
        .controller
        .devices()
        .devices()
        .expect("reads the devices")
        .into_iter()
        .find(|stored| stored.device_id == record.device_id)
        .expect("the device's record");
    assert!(
        stored.expired_at_ms.is_some(),
        "the expiry is written where a later connection is admitted from: {stored:?}"
    );
    let again = NetworkTransport::connect(
        &device.endpoint,
        host_addr_of(&daemon),
        &device.paired_identity(record.device_id),
        &host_paired_record(&daemon),
        SendLimits::default(),
    )
    .await;
    assert!(
        again.is_err(),
        "an expired device's endpoint has no paired record to authorise"
    );

    session.close();
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// What the shell prints every fifth of a second once `TICKING_COMMAND` runs.
const TICK: &str = "kalareach-tick";

/// A loop in the shell's foreground, so its output keeps arriving and closing the session ends it.
/// Printed through a format string, so the echo of the command itself does not match `TICK`.
const TICKING_COMMAND: &str = "while :; do printf 'kala%s-tick\\n' reach; sleep 0.2; done\n";

/// A subscription is decided again before each batch this host writes to it, so a bounded
/// offline policy that lapses stops the output of one that is running.
///
/// The connection ends and the grant is left as it was: no expiry is written, the device connects
/// again, and the request it makes there is refused and told why.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lapsed_offline_bound_stops_a_running_subscription_and_leaves_the_grant() {
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
    let attached = attach(&session, host.environment_id, session_id).await;
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attached.typing,
        MARKER_COMMAND,
    )
    .await;
    assert!(seen.contains(MARKER));
    let mut events = session.events();
    session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id: attached.typing,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(1),
            sequence: kr_protocol::ids::InputSequence::new(1),
            bytes: kr_protocol::scalars::Bytes::new(TICKING_COMMAND.as_bytes().to_vec()),
        })
        .await
        .expect("the loop is typed");
    received_without_applying(&mut events, TICK).await;

    // The owner chooses a bounded offline policy with no synchronisation to measure from, so
    // personal remote access is outside its bound at once.
    daemon
        .controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: DurationMs::new(60_000),
                last_synchronised_at_ms: Nullable::null(),
            }));
        })
        .expect("the owner's choice is recorded");

    // The next batch the loop prints is not written, and the connection goes with it. Until
    // then a request on it is refused and told why.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let refused = session
            .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
            .await
            .expect_err("nothing is served outside the offline bound");
        if refused.code() == ErrorCode::ResourceUnavailable {
            break;
        }
        assert!(
            refused
                .to_string()
                .contains("offline-validity policy has lapsed"),
            "{refused}"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the running subscription's output was never stopped"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    session.close();

    // Nothing about the grant ended.
    let stored = daemon
        .controller
        .devices()
        .devices()
        .expect("reads the devices")
        .into_iter()
        .find(|stored| stored.device_id == record.device_id)
        .expect("the device's record");
    assert!(
        stored.is_paired(),
        "no expiry and no revocation is written for a lapsed bound: {stored:?}"
    );
    let session = connect(&daemon, &device, &record).await;
    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err("still outside the bound");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        refused
            .to_string()
            .contains("offline-validity policy has lapsed"),
        "the device is told why: {refused}"
    );
    session.close();

    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
/// KR-REQ-05.02: a paired device reaches a session over the network through the control daemon,
/// and reads the same session a local client reads through the daemon's local endpoint.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
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
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
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
    let _attached = attach(&session, host.environment_id, session_id).await;

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
    let attachments: kr_protocol::recovery::EventsSnapshotResult = attached_locally
        .request(
            Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams {
                session_id,
                agent_resources_from: kr_protocol::scalars::Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the worker answers")
        .to_typed()
        .expect("decodes");
    assert!(
        attachments
            .attachments
            .iter()
            .any(|summary| summary.attachment_id == local_attachment.attachment.attachment_id),
        "the local attachment, by identity, survived the remote path ending"
    );

    drop(attached_locally);
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// What a relay says when it turns an endpoint away because the allowance is spent: the kind token a
/// managed relay starts that refusal with, then the words for a person.
const ALLOWANCE_SPENT: &str = "allowance_spent: the relay allowance for this period is used up";

/// What a metered relay may still forward, and what it did once it could not.
#[derive(Debug)]
struct Allowance {
    /// The count of forwarded bytes at which the allowance is spent.
    limit: AtomicU64,
    /// Set once the allowance is spent. From then on the relay admits nobody.
    spent: AtomicBool,
    /// Every endpoint the relay admitted, which is what it closes when the allowance is spent.
    admitted: std::sync::Mutex<Vec<iroh::EndpointId>>,
    /// Every endpoint it turned away because the allowance was spent.
    refused: std::sync::Mutex<Vec<iroh::EndpointId>>,
}

/// The relay's admission check, which answers from the allowance.
#[derive(Debug, Clone)]
struct AllowanceGate(Arc<Allowance>);

impl iroh_relay::server::AccessControl for AllowanceGate {
    async fn on_connect(
        &self,
        request: &iroh_relay::server::ClientRequest,
    ) -> iroh_relay::server::Access {
        let endpoint = request.endpoint_id();
        if self.0.spent.load(Ordering::SeqCst) {
            self.0
                .refused
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(endpoint);
            return iroh_relay::server::Access::Deny {
                reason: Some(ALLOWANCE_SPENT.to_owned()),
            };
        }
        self.0
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(endpoint);
        iroh_relay::server::Access::Allow
    }
}

/// Counts what the relay forwards, and spends the allowance when the count reaches it.
///
/// Spending it is the relay's own act, as a managed relay's is: it closes every connection it
/// admitted, and the gate turns away whoever comes back. The server goes on running throughout.
async fn meter(
    allowance: Arc<Allowance>,
    forwarded: Arc<iroh_relay::server::Metrics>,
    service: iroh_relay::server::RelayService,
) {
    loop {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if forwarded.bytes_sent.get() < allowance.limit.load(Ordering::SeqCst) {
            continue;
        }
        allowance.spent.store(true, Ordering::SeqCst);
        let admitted = allowance
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for endpoint in admitted {
            service.clients().disconnect(endpoint, None);
        }
        return;
    }
}

/// A relay server running in this process, with the trust anchor a client needs for it.
///
/// `iroh::test_utils::run_relay_server` discards the certificate it generated, and an endpoint that
/// cannot verify the relay's HTTPS certificate never reaches it. This spawns the same server and
/// keeps the certificate, which is also how a self-hosted deployment with a private authority
/// works: the certificate is pinned as an extra trust anchor beside the public ones.
///
/// It meters what it forwards, as a managed relay does. It forwards without limit until a test
/// gives it an allowance, and once what it has forwarded reaches that allowance it closes every
/// connection it admitted and refuses, with its reason, every endpoint that comes back.
struct LocalRelay {
    url: iroh::RelayUrl,
    ca_roots: Vec<Vec<u8>>,
    server: Option<iroh_relay::server::Server>,
    allowance: Arc<Allowance>,
    metering: tokio::task::AbortHandle,
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
        let allowance = Arc::new(Allowance {
            limit: AtomicU64::new(u64::MAX),
            spent: AtomicBool::new(false),
            admitted: std::sync::Mutex::new(Vec::new()),
            refused: std::sync::Mutex::new(Vec::new()),
        });
        let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.tls = Some(tls);
        relay.key_cache_capacity = Some(1024);
        relay.access = Arc::new(AllowanceGate(Arc::clone(&allowance)));

        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));

        let server = Server::spawn(config).await.expect("a relay server");
        let url: iroh::RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
            .parse()
            .expect("a relay URL");
        let metering = tokio::spawn(meter(
            Arc::clone(&allowance),
            Arc::clone(&server.metrics().server),
            server.relay_service().expect("the server relays").clone(),
        ))
        .abort_handle();
        Self {
            url,
            ca_roots: certs.into_iter().map(|cert| cert.to_vec()).collect(),
            server: Some(server),
            allowance,
            metering,
        }
    }

    /// Leaves the relay `bytes` more to forward than it has forwarded so far.
    fn allow_only(&self, bytes: u64) {
        let forwarded = self
            .server
            .as_ref()
            .expect("the relay is running")
            .metrics()
            .server
            .bytes_sent
            .get();
        self.allowance
            .limit
            .store(forwarded.saturating_add(bytes), Ordering::SeqCst);
    }

    /// The endpoints the relay turned away because the allowance was spent.
    fn refused(&self) -> Vec<iroh::EndpointId> {
        self.allowance
            .refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn config(&self) -> EndpointConfig {
        EndpointConfig {
            relay_urls: vec![self.url.clone()],
            relay_ca_roots: self.ca_roots.clone(),
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            ..EndpointConfig::default()
        }
    }

    /// The same selection, with no direct path at all.
    ///
    /// Two loopback endpoints reach each other directly whatever addresses they were given, so an
    /// endpoint that must use the relay has to have nothing else: this removes its IP transports.
    /// It is what makes stopping the relay the end of the path rather than a detail.
    fn relay_only_config(&self) -> EndpointConfig {
        EndpointConfig {
            relay_only: true,
            ..self.config()
        }
    }

    /// Takes the relay away, which is what a lease that ran out of reserved bytes does to a path.
    async fn shut_down(&mut self) {
        self.metering.abort();
        if let Some(server) = self.server.take() {
            server.shutdown().await.expect("the relay stops");
        }
    }
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        self.metering.abort();
    }
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_pairs_and_attaches_through_a_relay_and_losing_it_leaves_the_session() {
    let Some(host) = Host::create() else {
        return;
    };
    let mut relay = LocalRelay::spawn().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    // Neither endpoint has a direct path: two loopback endpoints reach each other directly
    // whatever addresses they were given, so the relay is the only path only if there is no other
    // transport on either side.
    let daemon = host.start(relay.relay_only_config(), &owner).await;
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

    // The device has no direct path at all: every packet it sends goes through the relay. The
    // pairing and the attachment therefore run over that path and nothing else.
    let device = Device::create(&relay.relay_only_config()).await;
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
    let attached = attach(&session, host.environment_id, session_id).await;
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attached.typing,
        MARKER_COMMAND,
    )
    .await;
    assert!(seen.contains(MARKER), "the relay carried the session");

    // The relay path goes. Neither endpoint has any other transport, so the relay *is* the path:
    // the server is stopped and the device's endpoint closed, which is the closing of the relay
    // path that section 17's quota disconnect is simulated by. What a real quota disconnect adds
    // is *when* the device notices — section 23's thirty-second inactivity threshold rather than
    // an immediate local close — and that is a property of the transport rather than of what this
    // checks, which is the other half: the remote path ending takes neither the worker nor the
    // local attachment with it.
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
    let attachments: kr_protocol::recovery::EventsSnapshotResult = attached_locally
        .request(
            Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams {
                session_id,
                agent_resources_from: kr_protocol::scalars::Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the worker answers")
        .to_typed()
        .expect("decodes");
    assert!(
        attachments
            .attachments
            .iter()
            .any(|summary| summary.attachment_id == local_attachment.attachment.attachment_id),
        "the local attachment, by identity, is still attached"
    );

    drop(attached_locally);
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// What is left of a metered relay's allowance when the next command starts.
const ALLOWANCE_LEFT: u64 = 32 * 1024;

/// The file the spending command waits for, named relative to the directory the session's shell
/// starts in: the host tree's root, which `create` gives every session as its working directory.
const SPENDING_BARRIER: &str = "spend-the-allowance";

/// A command that waits until the barrier file exists and then prints several times what is left
/// of the allowance.
fn spending_command() -> String {
    format!(
        "while [ ! -e {SPENDING_BARRIER} ]; do sleep 0.05; done; \
         yes kalareach-spends-the-allowance | head -n 20000\n"
    )
}

/// How long the host may take to see a connection that went quiet as ended.
///
/// Section 23's thirty-second inactivity threshold, and room on either side of it.
const DISCONNECT_PATIENCE: Duration = Duration::from_secs(90);

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
/// KR-REQ-17.50: the terminal worker stays alive after a relay quota disconnect. A device reaches a
/// session through a relay that meters what it forwards, and the session's own output spends the
/// relay's allowance. The relay, still running, closes the path and turns the device away when it
/// comes back, telling it why. The host sees the connection end and lets go of what it held for
/// the device, and through all of it the worker process keeps running, the session stays live and
/// the local attachment stays attached.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_quota_disconnect_leaves_the_terminal_worker_running() {
    use iroh::Watcher as _;

    let Some(host) = Host::create() else {
        return;
    };
    let relay = LocalRelay::spawn().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    // Neither endpoint has a direct path, so the relay is the whole of the remote path and its
    // allowance is the path's allowance.
    let daemon = host.start(relay.relay_only_config(), &owner).await;
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

    let device = Device::create(&relay.relay_only_config()).await;
    let record = pair(&daemon, &device, &owner).await;
    let addr = EndpointAddr::new(
        iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
            .expect("a usable endpoint identity"),
    )
    .with_relay_url(relay.url.clone());
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
    let attached = attach(&session, host.environment_id, session_id).await;
    let seen = type_and_observe(
        &session,
        host.environment_id,
        session_id,
        attached.typing,
        MARKER_COMMAND,
    )
    .await;
    assert!(seen.contains(MARKER), "the relay carried the session");

    // The command that spends the allowance waits at a barrier. The allowance is only limited once
    // the device holds the command's acknowledgement, because output that spent it sooner could
    // end the path before the acknowledgement came back. Then what is left of the allowance is less
    // than the command prints, and the barrier is released, so the session's own output spends it.
    let barrier = host.tree().root().join(SPENDING_BARRIER);
    session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id: attached.typing,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(1),
            sequence: kr_protocol::ids::InputSequence::new(1),
            bytes: kr_protocol::scalars::Bytes::new(spending_command().into_bytes()),
        })
        .await
        .expect("the command is accepted");
    relay.allow_only(ALLOWANCE_LEFT);
    std::fs::write(&barrier, b"").expect("the barrier is released");

    // The relay refuses. It closes the path and turns the device away when it comes back, and the
    // device learns the relay's own reason from the relay. A relay that had stopped would have
    // said nothing at all: this one is running and answering.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut statuses = device.endpoint.home_relay_status();
    while !statuses
        .get()
        .iter()
        .any(|status| status.auth_denied_reason() == Some(ALLOWANCE_SPENT))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the relay never refused the device for its allowance: {:?}",
            statuses.get()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        relay.refused().contains(&device.endpoint.id()),
        "the relay turned the device away because the allowance is spent"
    );
    assert!(relay.server.is_some(), "the relay is still running");

    // The host sees the connection end: nothing arrives on it any more, and at the inactivity
    // threshold it is over. The host then lets go of both attachments it held for the device,
    // which is the disconnect complete on the host's side.
    let deadline = tokio::time::Instant::now() + DISCONNECT_PATIENCE;
    loop {
        let snapshot: kr_protocol::recovery::EventsSnapshotResult = attached_locally
            .request(
                Method::EventsSnapshot,
                &kr_protocol::recovery::EventsSnapshotParams {
                    session_id,
                    agent_resources_from: kr_protocol::scalars::Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker answers")
            .to_typed()
            .expect("decodes");
        let held: BTreeSet<AttachmentId> = snapshot
            .attachments
            .iter()
            .map(|summary| summary.attachment_id)
            .collect();
        if !held.contains(&attached.watching) && !held.contains(&attached.typing) {
            assert!(
                held.contains(&local_attachment.attachment.attachment_id),
                "the local attachment, by identity, is still attached"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the host never let go of what it held for the device"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // The worker process that runs the terminal is still running, and the session is still live.
    let registry = Registry::open(host.paths().registry_database(), host.environment_id)
        .expect("opens the registry");
    let worker = registry
        .workers()
        .expect("reads the worker records")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("the session still has its worker");
    assert!(
        matches!(
            kr_ipc::identity::process_state(&worker.process_identity),
            kr_ipc::identity::ProcessState::Running
        ),
        "the worker process is still running"
    );
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
        "a relay quota disconnect did not end the session"
    );

    drop(session);
    drop(attached_locally);
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

// Ignored by default like the rest of this suite: the host fixture needs the worker binary that
// `scripts/end-to-end.sh` builds, and that script runs the suite with `--include-ignored`.
/// KR-REQ-17.40: an exhausted relay is reported as the reason a new connection fails, and it takes
/// nothing that does not need it. A host and two paired devices, one with a direct path and one
/// whose only path is the relay; then the relay's allowance is spent, and the relay closes what it
/// admitted and turns away whoever comes back. The connection already established on its direct
/// path carries on, and a new connection made with the direct addresses the invitation carried
/// succeeds. A new connection that needs the relay fails at once, as the relay's refusal: its code
/// is an exhausted allowance, it names the relay on the route and carries what the relay said, and
/// it offers what may still work, rather than looking like a host that went away.
#[ignore = "starts a control daemon; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exhausted_relay_is_the_reported_reason_a_new_connection_fails() {
    let Some(host) = Host::create() else {
        return;
    };
    let relay = LocalRelay::spawn().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    // The host has its direct path and the relay.
    let daemon = host.start(relay.config(), &owner).await;
    let host_id = iroh::PublicKey::from_bytes(daemon.network.endpoint_id().as_bytes())
        .expect("a usable endpoint identity");

    // A device with a direct path, paired by an invitation whose direct addresses it keeps, and
    // connected on its direct path.
    let direct = Device::create(&relay.config()).await;
    let proposed = proposal();
    let mut client = daemon.client().await;
    let invited = invite(&daemon, &mut client, &owner, &proposed).await;
    let hints: Vec<std::net::SocketAddr> = pairing_calls::direct_payload(&invited)
        .network_config
        .direct_addresses
        .iter()
        .map(|hint| hint.as_str().parse().expect("a socket address"))
        .collect();
    assert!(!hints.is_empty(), "the invitation carries direct addresses");
    let direct_record = redeem(&daemon, &mut client, &direct, &owner, &invited).await;
    let established = connect(&daemon, &direct, &direct_record).await;

    // A device whose only path is the relay, paired over it while the allowance lasts.
    let relayed = Device::create(&relay.relay_only_config()).await;
    let relayed_record = pair(&daemon, &relayed, &owner).await;

    // The allowance is spent from here on, and the relay closes what it admitted.
    relay.allow_only(0);
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !relay.refused().contains(&relayed.endpoint.id()) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the relay never turned the relayed device away"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Already-established direct paths are unaffected.
    let listed: kr_protocol::session::SessionListResult = established
        .read(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await
        .expect("the established direct connection still answers");
    assert!(listed.sessions.is_empty());

    // A new connection made with the direct addresses the invitation carried succeeds.
    let mut by_hints = EndpointAddr::new(host_id);
    for hint in &hints {
        by_hints = by_hints.with_ip_addr(*hint);
    }
    let again = NetworkTransport::connect(
        &direct.endpoint,
        by_hints,
        &direct.paired_identity(direct_record.device_id),
        &host_paired_record(&daemon),
        SendLimits::default(),
    )
    .await
    .expect("a new connection by the invitation's direct addresses");
    drop(again);

    // A new connection that needs the relay fails, at once, and the failure says why.
    let started = tokio::time::Instant::now();
    let refused = NetworkTransport::connect(
        &relayed.endpoint,
        EndpointAddr::new(host_id).with_relay_url(relay.url.clone()),
        &relayed.paired_identity(relayed_record.device_id),
        &host_paired_record(&daemon),
        SendLimits::default(),
    )
    .await
    .expect_err("nothing reaches the host through a relay that refuses");
    let took = started.elapsed();
    let report = refused.to_string().to_lowercase();
    assert!(
        report.contains("relay")
            && ["allowance", "exhaust", "quota", "capacity"]
                .iter()
                .any(|word| report.contains(word)),
        "the failure says the relay's allowance is spent, rather than looking like a host that \
         went away: {refused}"
    );
    let kr_client::ClientError::Transport(kr_transport::TransportError::RelayRefused(refusal)) =
        &refused
    else {
        panic!("the failure is the relay's refusal: {refused}");
    };
    assert_eq!(refusal.relay, relay.url, "the relay on the route refused");
    assert_eq!(
        refusal.kind,
        kr_transport::error::RelayRefusalKind::AllowanceSpent
    );
    assert_eq!(
        refusal.reason, "the relay allowance for this period is used up",
        "what the relay said reaches the device"
    );
    assert_eq!(
        refusal.alternatives,
        [
            kr_transport::error::RouteAlternative::AnotherRelay,
            kr_transport::error::RouteAlternative::RestoredAllowance,
        ],
        "a device whose only path is the relay is offered what a relay-only device can use"
    );
    assert_eq!(refused.code(), ErrorCode::QuotaExceeded);
    assert!(
        took < Duration::from_secs(10),
        "a device with nothing but the refusing relay is told well before the attempt's \
         30-second deadline: it took {took:?}"
    );

    drop(established);
    daemon.stop().await;
}

/// A grant that sees one session and may type in it, and claims nothing else.
fn viewer_proposal(session_selector: SessionSelector) -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector,
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: true,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(
                kr_ipc::now_ms().get().saturating_add(24 * 60 * 60 * 1000),
            ),
        },
        organisation: Nullable::null(),
    }
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_devices_grant_bounds_what_it_can_reach() {
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

    // A local attachment, which the remote device must not be able to reach.
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
    let record = pair_with(
        &daemon,
        &device,
        &owner,
        viewer_proposal(SessionSelector::Any),
    )
    .await;
    let session = connect(&daemon, &device, &record).await;

    // The grant carries no terminal.geometry, so a request that *claims* geometry is refused
    // before it reaches the worker. The condition on that right is the request's own.
    let claimed = session
        .mutate(
            Method::SessionAttach,
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &ParamsValue::empty(),
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: true,
                dimensions: Nullable::some(kr_protocol::session::Dimensions {
                    rows: kr_protocol::scalars::U64::new(40),
                    columns: kr_protocol::scalars::U64::new(120),
                }),
                terminal_profile_id: Nullable::null(),
                requested: [
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Geometry,
                ]
                .into_iter()
                .collect(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a grant with no geometry right claims no geometry");
    assert_eq!(claimed.code(), ErrorCode::PermissionDenied);

    // Retained history is not something this host can narrow to a grant's lower bound, so it is
    // refused rather than served in full.
    let history = session
        .history_page(&kr_protocol::recovery::HistoryPageParams {
            session_id,
            from_cursor: U64::ZERO,
            max_bytes: U64::new(4_096),
        })
        .await
        .expect_err("retained history is refused");
    assert_eq!(history.code(), ErrorCode::PermissionDenied);

    // An attachment identifier is not permission: the device may detach its own and nothing else.
    let attached = attach(&session, host.environment_id, session_id).await;
    let stolen = session
        .mutate(
            Method::SessionDetach,
            ActionTarget {
                environment_id: host.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &ParamsValue::empty(),
            &kr_protocol::attachment::SessionDetachParams {
                attachment_id: Nullable::some(local_attachment.attachment.attachment_id),
                line_token: Nullable::null(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a device detaches its own attachment and nothing else");
    assert_eq!(
        stolen.code(),
        ErrorCode::AmbiguousAttachment,
        "the refusal names the attachment rather than the session: {stolen}"
    );
    assert!(
        session
            .mutate(
                Method::SessionDetach,
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(session_id),
                    session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                None,
                &ParamsValue::empty(),
                &kr_protocol::attachment::SessionDetachParams {
                    attachment_id: Nullable::some(attached.watching),
                    line_token: Nullable::null(),
                },
                DurationMs::new(120_000),
            )
            .await
            .is_ok(),
        "and its own it may detach"
    );

    session.close();
    drop(attached_locally);
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listing_names_only_the_sessions_a_grant_admits() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;

    // A grant for a session that is not this one. A listing names no session, so nothing about the
    // request says which sessions it may see; the answer is what has to be narrowed.
    let elsewhere = SessionSelector::These {
        session_ids: [SessionId::new(Uuid::from_bytes([0xab; 16]))]
            .into_iter()
            .collect(),
    };
    let device = Device::create(&loopback()).await;
    let record = pair_with(&daemon, &device, &owner, viewer_proposal(elsewhere)).await;
    let session = connect(&daemon, &device, &record).await;

    let listed: kr_protocol::session::SessionListResult = session
        .read(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await
        .expect("the listing is served");
    assert!(
        listed.sessions.is_empty(),
        "a device is told about the sessions its grant admits and no others: {:?}",
        listed
            .sessions
            .iter()
            .map(|summary| summary.session_id)
            .collect::<Vec<_>>()
    );
    // And a session it names directly is refused rather than narrowed away.
    let refused = session
        .read::<_, SessionReadResult>(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect_err("a session outside the grant is refused");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);

    session.close();
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// KR-REQ-23.25, KR-REQ-23.34, in part, and KR-REQ-26.44 for the host reads.
///
/// Two doors. A session's answers are the same on both once the grant admits the subject: the
/// grant decides what a device may ask about, and a second filter on one path and not the other
/// would make the two ingresses disagree about what the same method means. The host's own
/// metadata is the one thing each door reads differently, on purpose: the owner at their own
/// machine is told whose account the environment belongs to and where its directories are, and a
/// paired device reads the same answer with every account name, local path and platform message
/// held to its class and its length.
///
/// What this demonstrates is both halves: parity for the session reads, and the reduced form of
/// `host.info` and `environment.list` for the device. The two callers are what they are: the
/// environment's owner on one side and a paired device on the other, because no actor reaches this
/// host through both doors.
// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_method_answers_both_ingresses_alike_once_the_grant_admits_the_subject() {
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;

    // A grant whose selector admits every session, so nothing is narrowed away and any difference
    // between the two answers is a difference the ingress made.
    let device = Device::create(&loopback()).await;
    let record = pair_with(
        &daemon,
        &device,
        &owner,
        viewer_proposal(SessionSelector::Any),
    )
    .await;
    let session = connect(&daemon, &device, &record).await;

    let locally: kr_protocol::hostinfo::HostInfoResult = local
        .request(Method::HostInfo, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.info succeeds")
        .to_typed()
        .expect("decodes");
    let remotely: kr_protocol::hostinfo::HostInfoResult = session
        .read(Method::HostInfo, &())
        .await
        .expect("host.info is served to the device");
    // The same host, its counters and its identifiers; the boot's bytes and whatever the platform
    // said about a sleep assertion stay with the owner.
    assert_eq!(
        (
            remotely.environment_id,
            remotely.generation,
            remotely.protocol_version,
            remotely.session_limit,
            remotely.default_worker_profile,
        ),
        (
            locally.environment_id,
            locally.generation,
            locally.protocol_version,
            locally.session_limit,
            locally.default_worker_profile,
        ),
        "host.info names the same host on both ingresses"
    );
    assert_eq!(
        remotely.boot_identity.source, locally.boot_identity.source,
        "the device is told which facility the boot identity comes from"
    );
    assert!(
        remotely.boot_identity.value.is_empty(),
        "and none of its value"
    );
    assert!(
        remotely
            .power
            .holder
            .as_ref()
            .is_none_or(|holder| holder.starts_with("[name withheld, ")),
        "{:?}",
        remotely.power
    );

    let locally: kr_protocol::hostinfo::EnvironmentListResult = local
        .request(Method::EnvironmentList, &())
        .await
        .expect("the call reaches the daemon")
        .expect("environment.list succeeds")
        .to_typed()
        .expect("decodes");
    let remotely: kr_protocol::hostinfo::EnvironmentListResult = session
        .read(Method::EnvironmentList, &())
        .await
        .expect("environment.list is served to the device");
    // The owner is told the account and the directories; the device is told which environment
    // this is, what it runs on and how busy it is, and nothing that names the account or a path.
    let (owner, device) = (&locally.environments[0], &remotely.environments[0]);
    assert_eq!(locally.environments.len(), remotely.environments.len());
    assert_eq!(
        (
            device.environment_id,
            device.os.as_str(),
            device.arch.as_str(),
            device.live_sessions,
        ),
        (
            owner.environment_id,
            owner.os.as_str(),
            owner.arch.as_str(),
            owner.live_sessions,
        ),
    );
    assert!(owner.runtime_directory.starts_with('/'), "{owner:?}");
    assert_eq!(
        device.os_user,
        format!("[name withheld, {} bytes]", owner.os_user.len())
    );
    assert_eq!(
        device.runtime_directory,
        format!("[path withheld, {} bytes]", owner.runtime_directory.len())
    );
    assert_eq!(
        device.state_directory,
        format!("[path withheld, {} bytes]", owner.state_directory.len())
    );
    assert_eq!(
        device.label,
        format!(
            "environment {} on {}",
            kr_protocol::hostinfo::configuration::short_prefix(owner.environment_id),
            owner.os
        ),
        "the device's label is the environment's prefix and platform, and names no account"
    );

    let locally: SessionReadResult = local
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the daemon")
        .expect("session.read succeeds")
        .to_typed()
        .expect("decodes");
    let remotely: SessionReadResult = session
        .read(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("session.read is served to the device");
    assert_eq!(
        locally, remotely,
        "a session the grant admits reads the same on both ingresses"
    );

    let parameters = kr_protocol::session::SessionListParams {
        environment_id: Nullable::null(),
        include_closed: true,
    };
    let locally: kr_protocol::session::SessionListResult = local
        .request(Method::SessionList, &parameters)
        .await
        .expect("the call reaches the daemon")
        .expect("session.list succeeds")
        .to_typed()
        .expect("decodes");
    let remotely: kr_protocol::session::SessionListResult = session
        .read(Method::SessionList, &parameters)
        .await
        .expect("session.list is served to the device");
    assert_eq!(
        locally, remotely,
        "a listing a selector admits whole is the same listing on both ingresses"
    );
    assert!(
        locally
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id),
        "and it is the listing that names this session, not an empty one"
    );

    session.close();
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// A loopback address where a managed service in an outage would be: every connection is accepted
/// and nothing is ever answered.
///
/// The thread that holds the listener and every connection it accepted is stopped and joined when
/// this goes out of scope, so the sockets close with the test that opened them.
struct ServiceInOutage {
    address: std::net::SocketAddr,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServiceInOutage {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        listener
            .set_nonblocking(true)
            .expect("a listener that can be stopped");
        let address = listener.local_addr().expect("its address");
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = std::thread::spawn({
            let accepted = Arc::clone(&accepted);
            let stop = Arc::clone(&stop);
            move || {
                let mut held = Vec::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((connection, _)) => {
                            accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            held.push(connection);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
                drop(held);
            }
        });
        Self {
            address,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    /// How many connections the host has opened to this service so far.
    fn reached(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for ServiceInOutage {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// KR-REQ-26.46: a control-plane outage does not stop local terminal use. The host is configured
/// with a relay and a discovery service that accept connections and never answer, and on that host
/// a session is still created on the local socket, a terminal on this machine still attaches to it,
/// and what it types still runs and comes back.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_control_plane_outage_leaves_local_terminal_use_working() {
    let Some(host) = Host::create() else {
        return;
    };
    let service = ServiceInOutage::start();
    let outage = service.address;
    let config = EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        relay_urls: vec![format!("https://{outage}").parse().expect("a relay URL")],
        discovery: kr_transport::config::DiscoveryConfig {
            pkarr_publisher_url: Some(format!("http://{outage}/pkarr").parse().expect("a URL")),
            pkarr_resolver_url: Some(format!("http://{outage}/pkarr").parse().expect("a URL")),
            ..kr_transport::config::DiscoveryConfig::default()
        },
        ..EndpointConfig::default()
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(config, &owner).await;
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

    // A terminal on this machine attaches on the worker's own endpoint, takes the keys and types.
    let mut terminal = LocalClient::connect(&worker_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("the local terminal reaches the worker");
    let target = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let attached: SessionAttachResult = terminal
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(created.session.dimensions),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: [
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Input,
                ]
                .into_iter()
                .collect(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local terminal attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    let lease: kr_protocol::input::InputAcquireResult = terminal
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &kr_protocol::input::InputAcquireParams {
                session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local terminal takes the keys")
        .to_typed()
        .expect("decodes");
    let _: EventsSubscribeResult = terminal
        .request(
            Method::EventsSubscribe,
            &kr_protocol::recovery::EventsSubscribeParams {
                session_id,
                attachment_id,
                streams: [EventStream::Output].into_iter().collect(),
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local terminal subscribes")
        .to_typed()
        .expect("decodes");
    let _: kr_protocol::input::InputWriteResult = terminal
        .request(
            Method::InputWrite,
            &kr_protocol::input::InputWriteParams {
                session_id,
                attachment_id,
                epoch: lease.lease.epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: kr_protocol::scalars::Bytes::new(
                    b"printf 'kr-%s\\n' local-use-in-an-outage\n".to_vec(),
                ),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the worker takes the line")
        .to_typed()
        .expect("decodes");
    let mut seen = String::new();
    let started = tokio::time::Instant::now();
    while !seen.contains("kr-local-use-in-an-outage") {
        let remaining = (started + Duration::from_secs(120))
            .saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, terminal.recv()).await {
            Ok(Ok(kr_protocol::envelope::ControlFrame::Notification(notification)))
                if notification.event_type.as_str() == "session.output" =>
            {
                if let Ok(event) = notification.payload.to_typed::<OutputEvent>() {
                    seen.push_str(&String::from_utf8_lossy(event.bytes.as_slice()));
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!("the local terminal's connection ended ({error}): {seen:?}"),
            Err(_) => panic!(
                "waited {:?} for the typed line's output during the outage: {seen:?}",
                started.elapsed()
            ),
        }
    }

    // The outage was real: the host did try its control plane, which answered nothing. The host
    // reaches for it in the background, so this waits for the first attempt rather than racing it.
    let started = tokio::time::Instant::now();
    while service.reached() == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the host never tried the relay or the discovery service it was configured with"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    drop(terminal);
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}

/// Where the question half finds the worker it asks, and what it asks about.
const QUESTION_ENDPOINT: &str = "KR_QUESTION_TEST_ENDPOINT";
const QUESTION_ENVIRONMENT: &str = "KR_QUESTION_TEST_ENVIRONMENT";
const QUESTION_SESSION: &str = "KR_QUESTION_TEST_SESSION";

/// The name of the question half, as the test harness selects it.
const QUESTION_HALF: &str = "ask_a_question_from_inside_the_session";

/// The application half of the question test: typed into the test's session, it asks one question
/// of that session's worker as an application running inside the session, and then stays alive,
/// as an agent waiting for its answer does. It does nothing unless the question test started it.
#[test]
#[ignore = "the application half of the question test, run only inside that test's own session"]
fn ask_a_question_from_inside_the_session() {
    let (Some(endpoint), Ok(environment_id), Ok(session_id)) = (
        std::env::var_os(QUESTION_ENDPOINT),
        std::env::var(QUESTION_ENVIRONMENT),
        std::env::var(QUESTION_SESSION),
    ) else {
        return;
    };
    let environment_id: EnvironmentId = environment_id.parse().expect("an environment");
    let session_id: SessionId = session_id.parse().expect("a session");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            let endpoint = kr_ipc::paths::Endpoint::from_path(PathBuf::from(endpoint))
                .expect("the worker's endpoint");
            let mut worker = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("the application reaches its session's worker");
            let created: kr_protocol::question::QuestionCreateResult = worker
                .mutate(
                    Method::QuestionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget {
                        environment_id,
                        session_id: Nullable::some(session_id),
                        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                        application_instance_id: Nullable::null(),
                        agent_binding_revision: Nullable::null(),
                    },
                    &kr_protocol::question::QuestionCreateParams {
                        session_id,
                        request_id: "push-anyway".to_owned(),
                        agent_name: Nullable::some("kr-test-agent".to_owned()),
                        context: "The build finished with two failing tests.".to_owned(),
                        question: "Push the branch anyway?".to_owned(),
                        kind: kr_protocol::question::QuestionKind::Confirm,
                        choices: Vec::new(),
                        requested_expiry_ms: Nullable::null(),
                        wait_ms: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the worker")
                .expect("the worker creates the question")
                .to_typed()
                .expect("decodes");
            println!("kr-asked-{}", created.question.question_id);
            // The application stays alive for as long as its question should: the session's close
            // ends it.
            tokio::time::sleep(Duration::from_secs(600)).await;
        });
}

/// A grant a pairing proposes: these rights, over these sessions.
fn proposing(actions: &[ActionRight], session_selector: SessionSelector) -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector,
        actions: actions.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(
                kr_ipc::now_ms().get().saturating_add(24 * 60 * 60 * 1000),
            ),
        },
        organisation: Nullable::null(),
    }
}

/// Asks, as the device `session` belongs to, to close the session, and returns why that was
/// refused.
async fn refused_close(
    session: &Session,
    target: ActionTarget,
    session_id: SessionId,
) -> ErrorCode {
    session
        .mutate(
            Method::SessionClose,
            target,
            None,
            &ParamsValue::empty(),
            &SessionCloseParams { session_id },
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a grant without session.close does not close the session")
        .code()
}

/// Everything the host holds that says what anybody may do: every paired device's record with the
/// grant it holds, every grant the host has shared, resolved ones included, and the authority
/// revision in force.
async fn authority(
    daemon: &RunningDaemon,
    local: &mut LocalClient,
) -> (
    Vec<DeviceRecord>,
    kr_protocol::sharing::GrantListResult,
    kr_protocol::ids::AuthorityRevision,
) {
    let devices = daemon
        .network
        .devices()
        .devices()
        .expect("the device records read");
    let shared: kr_protocol::sharing::GrantListResult = local
        .request(
            Method::GrantList,
            &kr_protocol::sharing::GrantListParams {
                session_id: Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the grants list")
        .to_typed()
        .expect("decodes");
    let revision = daemon
        .controller
        .authority_revision()
        .await
        .expect("the revision");
    (devices, shared, revision)
}

/// KR-REQ-11.60, KR-REQ-11.64: a question an application inside a session asked is answered
/// from a paired device only with `question.respond` for that session. A device that may view but
/// not respond is refused, and so is one that may respond to another session; one that may respond
/// to this session answers, and the answer it stores names that device, the principal the device
/// acts under, the time and the revision it answered. The yes changes no grant: every grant the
/// host holds reads back exactly as it did before the answer, and the device that answered still
/// cannot close the session, which its grant never allowed.
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_question_is_answered_only_with_the_respond_right_for_its_session_and_enlarges_no_grant()
{
    let Some(host) = Host::create() else {
        return;
    };
    let owner = DeviceKeys::generate().expect("owner keys");
    let daemon = host.start(loopback(), &owner).await;
    let mut local = host.client().await;
    let created = create(&mut local, &host).await;
    let session_id = created.session.session_id;
    let endpoint_path = created
        .endpoint
        .as_ref()
        .cloned()
        .expect("a live session names its worker");
    let worker_endpoint =
        kr_ipc::paths::Endpoint::from_path(endpoint_path.clone()).expect("a worker endpoint");
    let target = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };

    // The application is this test's own executable, copied into the host's tree and typed into
    // the session's shell, so the worker sees it as a process inside the session.
    let application = host.tree().root().join("kr-question-application");
    std::fs::copy(
        std::env::current_exe().expect("this test's own executable"),
        &application,
    )
    .expect("copies the application half");
    let mut terminal = LocalClient::connect(&worker_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("a local terminal reaches the worker");
    let attached: SessionAttachResult = terminal
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(created.session.dimensions),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: [
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Input,
                ]
                .into_iter()
                .collect(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local terminal attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    let lease: InputAcquireResult = terminal
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &InputAcquireParams {
                session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the local terminal takes the keys")
        .to_typed()
        .expect("decodes");
    let line = format!(
        "{QUESTION_ENDPOINT}='{endpoint_path}' {QUESTION_ENVIRONMENT}='{}' \
         {QUESTION_SESSION}='{session_id}' '{}' --exact {QUESTION_HALF} --include-ignored \
         --nocapture --test-threads 1\n",
        host.environment_id,
        application.display()
    );
    let _: InputWriteResult = terminal
        .request(
            Method::InputWrite,
            &InputWriteParams {
                session_id,
                attachment_id,
                epoch: lease.lease.epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: kr_protocol::scalars::Bytes::new(line.into_bytes()),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the worker takes the line")
        .to_typed()
        .expect("decodes");

    // The question the application asked, as the session's worker holds it.
    let mut reader = LocalClient::connect(&worker_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("a local reader reaches the worker");
    let started = tokio::time::Instant::now();
    let asked = loop {
        let read: kr_protocol::question::QuestionReadResult = reader
            .request(
                Method::QuestionRead,
                &kr_protocol::question::QuestionReadParams {
                    session_id,
                    question_id: Nullable::null(),
                    include_resolved: true,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the questions read")
            .to_typed()
            .expect("decodes");
        if let Some(question) = read.questions.into_iter().next() {
            break question;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the application inside the session never asked its question"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(asked.state, kr_protocol::question::QuestionState::Pending);
    let answer = kr_protocol::question::QuestionAnswerParams {
        session_id,
        question_id: asked.question_id,
        expected_revision: asked.revision,
        answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
    };

    // Three devices: one that may view, one that may respond to another session, and one that may
    // respond to this one.
    let viewer = Device::create(&loopback()).await;
    let viewer_record = pair_with(
        &daemon,
        &viewer,
        &owner,
        proposing(&[ActionRight::SessionView], SessionSelector::Any),
    )
    .await;
    let elsewhere = Device::create(&loopback()).await;
    let elsewhere_record = pair_with(
        &daemon,
        &elsewhere,
        &owner,
        proposing(
            &[ActionRight::SessionView, ActionRight::QuestionRespond],
            SessionSelector::These {
                session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
            },
        ),
    )
    .await;
    let responder = Device::create(&loopback()).await;
    let responder_record = pair_with(
        &daemon,
        &responder,
        &owner,
        proposing(
            &[ActionRight::SessionView, ActionRight::QuestionRespond],
            SessionSelector::These {
                session_ids: [session_id].into_iter().collect(),
            },
        ),
    )
    .await;
    let before = authority(&daemon, &mut local).await;
    // The owner's own device, paired when the host was set up, is on record beside the three.
    assert_eq!(before.0.len(), 4, "each pairing wrote its device and grant");
    let responder_grant = before
        .0
        .iter()
        .find(|record| record.device_id == responder_record.device_id)
        .map(|record| {
            record
                .grant
                .actions
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        })
        .expect("the responder's grant");
    assert_eq!(
        responder_grant,
        BTreeSet::from([ActionRight::SessionView, ActionRight::QuestionRespond])
    );

    // Without `question.respond`, and with it for another session: refused, and nothing changes.
    for (device, record) in [(&viewer, &viewer_record), (&elsewhere, &elsewhere_record)] {
        let session = connect(&daemon, device, record).await;
        let refused = session
            .mutate(
                Method::QuestionAnswer,
                target.clone(),
                None,
                &ParamsValue::empty(),
                &answer,
                DurationMs::new(120_000),
            )
            .await
            .expect_err("an answer without the right for this session is refused");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
        session.close();
    }

    // The device that may respond to this session cannot close it, before the answer.
    let session = connect(&daemon, &responder, &responder_record).await;
    assert_eq!(
        refused_close(&session, target.clone(), session_id).await,
        ErrorCode::PermissionDenied
    );

    // It answers yes.
    let resolved: kr_protocol::question::QuestionResolveResult = session
        .mutate(
            Method::QuestionAnswer,
            target.clone(),
            None,
            &ParamsValue::empty(),
            &answer,
            DurationMs::new(120_000),
        )
        .await
        .expect("the responder answers")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        resolved.question.state,
        kr_protocol::question::QuestionState::Answered
    );
    let record = resolved
        .question
        .answer
        .as_ref()
        .expect("the answer is recorded");
    assert_eq!(
        record.answer,
        kr_protocol::question::QuestionAnswer::Decision { decided: true }
    );
    assert_eq!(
        record.actor_id,
        kr_transport::listener::device_principal(&responder_record.device_id),
        "the answer names the principal the answering device acts under"
    );
    assert_eq!(record.device_id.as_ref(), Some(&responder_record.device_id));
    assert_eq!(record.question_revision, asked.revision);
    assert!(
        record.answered_at_ms.get() >= asked.created_at_ms.get(),
        "the answer carries the time it was given"
    );

    // The yes enlarged nothing: every grant reads back as it did, and the responder still cannot
    // close the session.
    let after = authority(&daemon, &mut local).await;
    assert_eq!(after.0, before.0, "an answer changed a device's grant");
    assert_eq!(
        after.1, before.1,
        "an answer issued or changed a shared grant"
    );
    assert_eq!(after.2, before.2, "an answer moved the authority revision");
    assert_eq!(
        refused_close(&session, target.clone(), session_id).await,
        ErrorCode::PermissionDenied
    );

    session.close();
    drop(reader);
    drop(terminal);
    close_session(&mut local, &host, session_id).await;
    daemon.stop().await;
}
