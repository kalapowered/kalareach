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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_client::cursors::{Restoration, RestorationStep};
use kr_client::ipc::IpcTransport;
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_controller::registry::{LaunchPhase, Registry};
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
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64, Uuid};
use kr_protocol::session::{
    Presentation, SessionCloseParams, SessionCreateParams, SessionCreateResult, SessionReadParams,
    SessionReadResult, SessionState, ShellMode,
};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, LocalIdentity};
use kr_transport::scheduler::SendLimits;

/// How long a test waits for something the machine has to do before it calls it a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the fixture waits for a worker it signalled to go, before it stops it outright.
const STRAY_PATIENCE: Duration = Duration::from_secs(5);

/// What the shell prints when it has actually run what was typed.
///
/// The command's own text does not contain it, so a terminal that merely echoed the keystrokes
/// cannot satisfy an assertion about it: what passes is the shell having executed the command.
const MARKER: &str = "kalareach-ran";

/// The command that produces it.
const MARKER_COMMAND: &str = "printf 'kala%s-ran\n' reach\n";

/// A host tree on the internal disk, with the worker beside it.
struct Host {
    /// The tree, held in an option so cleanup can keep it rather than remove it.
    ///
    /// Removing it is the ordinary end. A worker this fixture started and could not confirm had
    /// exited is the other one: the tree stays, because a live worker reading a directory that had
    /// been removed underneath it is a worse state to leave the machine in than a directory the
    /// operator has to remove.
    temp: Option<kr_ipc::testing::TempHost>,
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
            temp: Some(temp),
            worker,
            environment_id,
        })
    }

    fn paths(&self) -> kr_ipc::paths::EnvironmentPaths {
        self.tree().environment()
    }

    fn tree(&self) -> &kr_ipc::testing::TempHost {
        self.temp.as_ref().expect("the host tree is still held")
    }

    /// Ends every worker this host started that is still running, and waits for it to go.
    ///
    /// A worker is deliberately not a child of whatever created it, so a test that panicked before
    /// it could close its session would leave one running until the machine was restarted. Two
    /// records find them. The worker table holds the workers that reported themselves ready; the
    /// launch records hold the process identity of everything that was started, which is the only
    /// thing that can find a worker whose ready report failed or stalled - and losing that report
    /// is something a worker survives on purpose.
    ///
    /// A process is signalled only when the kernel agrees it is still the process that identity
    /// names, so a reused identifier is never signalled. Then this waits: the host's tree goes
    /// when it returns, and a worker still inside it would be reading a directory that had been
    /// removed.
    fn end_stray_workers(&self) -> Vec<String> {
        let Ok(registry) = Registry::open(self.paths().registry_database(), self.environment_id)
        else {
            // The records cannot be read, so what this host started cannot be established. The
            // tree stays: it is the only thing that could still be found by hand.
            return vec!["this host's records could not be read".to_owned()];
        };
        let mut started: Vec<(kr_protocol::identity::ProcessStartIdentity, String)> = Vec::new();
        let mut unreadable = Vec::new();
        match registry.workers() {
            Ok(workers) => started.extend(workers.into_iter().map(|worker| {
                (
                    worker.process_identity,
                    format!("session {}", worker.session_id),
                )
            })),
            Err(error) => unreadable.push(format!("the worker records could not be read: {error}")),
        }
        // Every phase in which something may be running. `Reserved` has nothing started yet, and
        // `Failed` and `Closed` are the phases that say the process is gone.
        for phase in [
            LaunchPhase::Spawned,
            LaunchPhase::Claimed,
            LaunchPhase::Live,
            LaunchPhase::Fenced,
        ] {
            match registry.reservations_in(phase) {
                Ok(reservations) => {
                    started.extend(reservations.into_iter().filter_map(|reservation| {
                        reservation.launcher_identity.map(|identity| {
                            (
                                identity,
                                format!("the launch for session {}", reservation.session_id),
                            )
                        })
                    }))
                }
                Err(error) => unreadable.push(format!(
                    "the {phase:?} launch records could not be read: {error}"
                )),
            }
        }
        started.sort_by_key(|(identity, _)| identity.pid.get());
        started.dedup_by_key(|(identity, _)| identity.pid.get());

        // Every identity this host started is followed until the kernel says it has ended, whether
        // the request to stop reached it or not. A signal that failed, and a query the operating
        // system refused, both establish nothing: treating either as death is what would remove a
        // tree from under a live worker.
        let mut signalled = unreadable;
        let mut following = Vec::new();
        for (identity, what) in started {
            if matches!(
                kr_ipc::identity::process_state(&identity),
                kr_ipc::identity::ProcessState::Ended
            ) {
                continue;
            }
            eprintln!("ending a worker this test started and did not close: {what}");
            Self::signal(&identity, rustix::process::Signal::TERM);
            following.push((identity, what));
        }
        // Nothing is released until the kernel says every one of them has ended.
        let deadline = std::time::Instant::now() + STRAY_PATIENCE;
        let insist_at = deadline - STRAY_PATIENCE / 2;
        let mut insisted = false;
        while !following.is_empty() {
            following.retain(|(identity, _)| {
                !matches!(
                    kr_ipc::identity::process_state(identity),
                    kr_ipc::identity::ProcessState::Ended
                )
            });
            let now = std::time::Instant::now();
            if following.is_empty() || now >= deadline {
                break;
            }
            // A worker that will not stop for the request is stopped outright. Leaving it running
            // while its tree is removed is worse than ending it abruptly. The identity is checked
            // again first, inside `signal`: by now the identifier may belong to somebody else.
            if !insisted && now >= insist_at {
                for (identity, _) in &following {
                    Self::signal(identity, rustix::process::Signal::KILL);
                }
                insisted = true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        signalled.extend(following.into_iter().map(|(_, what)| what));
        signalled
    }

    /// Signals one process, and only while the kernel agrees it is the one that identity names.
    ///
    /// A process identifier is reused. Checking the start identity immediately before the signal
    /// is what keeps this from ending somebody else's process, and it is checked again before an
    /// escalation for the same reason.
    fn signal(
        identity: &kr_protocol::identity::ProcessStartIdentity,
        signal: rustix::process::Signal,
    ) {
        if !matches!(
            kr_ipc::identity::process_state(identity),
            kr_ipc::identity::ProcessState::Running
        ) {
            return;
        }
        let Ok(raw) = i32::try_from(identity.pid.get()) else {
            return;
        };
        let Some(pid) = rustix::process::Pid::from_raw(raw) else {
            return;
        };
        let _ = rustix::process::kill_process(pid, signal);
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
                let store = open_store_in(&secrets).expect("a secret store");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(DetachedSupervisor::new()),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
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

impl Drop for Host {
    fn drop(&mut self) {
        // The successful paths close their sessions and wait for the record. This is the failing
        // path: unwinding cannot await, so what it can do is end the processes this host started,
        // and establish that they have ended, before its tree goes.
        let unresolved = self.end_stray_workers();
        if unresolved.is_empty() {
            return;
        }
        // Not established as ended. The tree is kept, and where it is is printed, because the
        // alternative is removing the directories a live worker is reading.
        let kept = self.temp.take().map(|temp| {
            let root = temp.root().to_path_buf();
            std::mem::forget(temp);
            root
        });
        for what in unresolved {
            eprintln!("could not establish that a worker this test started has ended: {what}");
        }
        if let Some(root) = kept {
            eprintln!("the host tree has been kept at {}", root.display());
        }
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
    pair_with(daemon, device, owner, proposal()).await
}

/// Runs a complete direct pairing under an exact proposed grant.
async fn pair_with(
    daemon: &RunningDaemon,
    device: &Device,
    owner: &DeviceKeys,
    proposal: ProposedGrant,
) -> DeviceRecord {
    let pairing = daemon.network.pairing().expect("this host accepts pairing");
    let owner_context = owner_context();
    // One proposal, used for the challenge and for the invitation. The owner approves an exact
    // proposal, digest and all, so a second one built a millisecond later is a different thing.
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
            daemon
                .network
                .network_config()
                .expect("the host's selected configuration"),
            &pairing.approval(&owner_context, &request, &proof),
        )
        .expect("an invitation");
    let QrPayload::Direct(payload) = payload else {
        panic!("a direct invitation produces a direct payload");
    };
    let payload: DirectQrPayload = *payload;

    // The candidate scans it and redeems it over the pre-authorisation surface, which is the only
    // thing an unpaired endpoint reaches.
    let host_addr = host_addr(&payload);
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

/// Returns where a candidate dials the host, from the invitation alone.
///
/// A candidate has the QR and nothing else, so this is built from the QR: the endpoint identity it
/// pins, the relay it names and the address hints it carries. A test that reached into the daemon
/// for the address instead would be proving that the *test* knows where the host is.
fn host_addr(payload: &DirectQrPayload) -> EndpointAddr {
    let endpoint_id = iroh::PublicKey::from_bytes(payload.endpoint_id.as_bytes())
        .expect("the invitation pins a usable endpoint identity");
    let mut addr = EndpointAddr::new(endpoint_id);
    if let Some(relay) = payload
        .network_config
        .relay_urls
        .first()
        .and_then(|hint| hint.as_str().parse::<iroh::RelayUrl>().ok())
    {
        addr = addr.with_relay_url(relay);
    }
    for hint in &payload.network_config.direct_addresses {
        if let Ok(socket) = hint.as_str().parse::<std::net::SocketAddr>() {
            addr = addr.with_ip_addr(socket);
        }
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
        // The event's own cursor, never a position derived from how many bytes it carried. Every
        // chunk this attachment receives is a rendering of the screen at the cursor it names -
        // which is what attaching separately to watch and to type buys - so the cursor *is* the
        // position applying the chunk reaches, and adding the rendering's length would claim a
        // position the session never produced.
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
#[ignore = "launches a worker process; run through scripts/end-to-end.sh"]
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

    // Something is typed that the device will *not* wait for, and then its connection is lost.
    // What the session produces next happens while the device is away, which is what makes the
    // restoration on the next connection worth checking.
    let away = "printf 'while%s-away\n' -it\n";
    session
        .write_input(&InputWriteParams {
            session_id,
            attachment_id: attached.typing,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(1),
            sequence: kr_protocol::ids::InputSequence::new(1),
            bytes: kr_protocol::scalars::Bytes::new(away.as_bytes().to_vec()),
        })
        .await
        .expect("the second batch is accepted");

    // The control stream is lost. What the client carries across is the content position, not the
    // previous connection's event sequences.
    let carried = kr_client::reconnect::ClientState::from_session(&session, None).await;
    session.close();
    drop(session);

    // While the device is away, the session goes on producing: a local caller reads the retained
    // history on the worker's own endpoint and finds what was typed but never waited for. That is
    // what makes the restoration on the next connection worth checking — the content exists, and
    // the device has not seen it.
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
    let produced = tokio::time::Instant::now() + PATIENCE;
    let mut retained = String::new();
    while tokio::time::Instant::now() < produced {
        let page: kr_protocol::recovery::HistoryPageResult = on_worker
            .request(
                Method::HistoryPage,
                &kr_protocol::recovery::HistoryPageParams {
                    session_id,
                    from_cursor: U64::ZERO,
                    max_bytes: U64::new(256 * 1024),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the page is served")
            .to_typed()
            .expect("decodes");
        retained.push_str(&String::from_utf8_lossy(page.bytes.as_slice()));
        if retained.contains("while-it-away") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        retained.contains("while-it-away"),
        "the session produced it while the device was away: {retained:?}"
    );

    let resumed_from = carried
        .cursors
        .applied_cursor(&output_stream())
        .expect("the client holds a position");
    assert!(resumed_from.get() > 0);
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
    // And the screen it is drawn carries what the session produced while it was away. That is the
    // restoration: the client asked from its own cursor and was given the state at it.
    let restored = observe(&session, &mut events, "while-it-away").await;
    assert!(
        restored.contains("while-it-away"),
        "the restoration carries what happened while the device was away: {restored:?}"
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
    let pairing = daemon.network.pairing().expect("pairing");
    PairedPeer {
        device_id: pairing.identity().device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: pairing.identity().keys.authorisation,
        endpoint_id: daemon.network.endpoint_id(),
    }
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

// Ignored by default: this suite starts real processes, and the binary it launches is built by
// `scripts/end-to-end.sh`, which runs it with `--include-ignored`. A suite that skipped itself
// silently when that binary was absent would report a pass for something it never ran.
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
            &kr_protocol::recovery::EventsSnapshotParams { session_id },
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
        if let Some(server) = self.server.take() {
            server.shutdown().await.expect("the relay stops");
        }
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
            &kr_protocol::recovery::EventsSnapshotParams { session_id },
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
                attachment_id: local_attachment.attachment.attachment_id,
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
                    attachment_id: attached.watching,
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

/// KR-REQ-23.25, KR-REQ-23.34, in part.
///
/// One answer, two doors. What the host does to a method's result before it leaves belongs to the
/// method, not to the ingress the request arrived on: the grant decides what a device may ask
/// about, and once it has admitted the subject the device is given the answer the owner's own
/// socket is given. A second filter on one path and not the other would make the two ingresses
/// disagree about what the same method means.
///
/// What this demonstrates is that parity, for the four reads this daemon answers itself. It is not
/// evidence about diagnostic redaction or about `session.describe`'s own filtering, and the two
/// callers are what they are: the environment's owner on one side and a paired device on the
/// other, because no actor reaches this host through both doors.
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
    assert_eq!(
        locally, remotely,
        "host.info is the same answer on both ingresses"
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
    assert_eq!(
        locally, remotely,
        "environment.list is the same answer on both ingresses"
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
