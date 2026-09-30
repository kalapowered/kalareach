//! The catalogue's admissions and the workers this daemon hosts.
//!
//! A real daemon launches real workers here, through the platform's own supervisor, and hands each
//! its plugin admissions: the first snapshot with its specification, and every later one as a
//! round on its authority connection. What these tests watch is the member set the catalogue's
//! reclaim asks: a worker is pending until it answers a round at the current admission revision,
//! it leaves when its session closes or its process is known to have ended, and a worker the host
//! stopped trusting is never sent a round. `plugin.list` counts only from reports its own refresh
//! received, so its counts are known exactly when every member answered at the revision it
//! renders.
//!
//! A worker that cannot answer is one this test has stopped with a signal, after checking that the
//! process is still the one the daemon started; it is resumed before the test lets go of it.
//! Everything a launched process opens is on the internal disk, under the test's own tree.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::identity::ProcessState;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, Enrolment, InstallationGrant, RepositoryId, RepositoryKind,
};
use kr_protocol::admission::{LiveRelease, ReleaseOrigin};
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActionId, BuildId, EnvironmentId, PluginId, PublisherId, SessionEpoch, SessionId,
};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{Presentation, SessionCreateParams, SessionCreateResult, ShellMode};
use kr_protocol::worker::ReservationId;

mod teardown;

/// The catalogue's own builder of signed generations, for a release whose manifest names another
/// platform. This suite uses one of its helpers.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// How long a test waits for something the daemon does on its own: a round after a worker is
/// recorded, the pass a change asks for, a closure. Generous, because a loaded machine is slow and
/// none of these is timed by the product itself.
const PATIENCE: Duration = Duration::from_secs(40);

/// The variable that makes a placed copy of this binary a program a person starts in a session:
/// it sleeps for as many seconds as it names.
const STAND_IN: &str = "KR_BINDING_STAND_IN";

/// The variable that names a file the stand-in writes its process identifier to once it runs.
const STAND_IN_RUNNING: &str = "KR_BINDING_STAND_IN_RUNNING";

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        if let Some(running) = std::env::var_os(STAND_IN_RUNNING) {
            std::fs::write(running, std::process::id().to_string()).expect("says it is running");
        }
        std::thread::sleep(Duration::from_secs(seconds.parse().unwrap_or(60)));
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// The package the development catalogue publishes and every test here installs and enables.
fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("an identifier")
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/catalogue/development")
}

/// Returns the worker binary beside this test's own.
fn worker_beside_this_test() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let worker = directory.join("kr-worker");
    assert!(
        worker.is_file(),
        "this test starts worker processes and there is none at {}; build it with \
         `cargo build -p kr-worker`, or run the whole workspace's tests, which build it",
        worker.display()
    );
    worker
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination");
    let mut stack = vec![from.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("readable").flatten() {
            let source = entry.path();
            if source.is_dir() {
                stack.push(source);
                continue;
            }
            let relative = source.strip_prefix(from).expect("inside the tree");
            let destination = to.join(relative);
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
            std::fs::copy(&source, &destination).expect("copyable");
        }
    }
}

fn directory_url(path: &Path) -> url::Url {
    url::Url::from_directory_path(std::fs::canonicalize(path).expect("an existing directory"))
        .expect("an absolute path")
}

/// One worker the daemon asked the supervisor for.
#[derive(Clone, Debug)]
struct Launched {
    reservation_id: ReservationId,
    session_id: SessionId,
    process: Option<ProcessStartIdentity>,
}

/// The tree's own supervisor, recording what it started.
#[derive(Debug)]
struct Recording {
    inner: Box<dyn WorkerSupervisor>,
    launched: Arc<Mutex<Vec<Launched>>>,
}

impl WorkerSupervisor for Recording {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let outcome = self.inner.start(launch);
        let process = match &outcome {
            LaunchOutcome::Started(identity) => Some(identity.clone()),
            _ => None,
        };
        self.launched
            .lock()
            .expect("the record is not poisoned")
            .push(Launched {
                reservation_id: launch.reservation_id,
                session_id: launch.session_id,
                process,
            });
        outcome
    }

    fn describe(&self) -> &'static str {
        "the platform's supervisor, recording what it starts"
    }
}

/// A daemon hosting real workers, with the example package installed and enabled.
struct Hosted {
    controller: Option<Arc<Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    worker: PathBuf,
    launched: Arc<Mutex<Vec<Launched>>>,
    /// The example package's installed release.
    example: LiveRelease,
    _repository: tempfile::TempDir,
    /// Last, so it goes last: it ends every worker the daemon started.
    tree: teardown::Tree,
}

impl Hosted {
    async fn start() -> Self {
        Self::start_from(&fixture(), true).await
    }

    /// A daemon whose repository publishes what `source` holds, with the example package installed
    /// and enabled from it. Where `workers` is false there is no worker program, for a test that
    /// starts no session.
    async fn start_from(source: &Path, workers: bool) -> Self {
        let tree = teardown::Tree::create();
        let worker = tree.root().join("kr-worker");
        if workers {
            // On the internal disk, and started once here, where nothing is timed.
            kr_ipc::testing::place_and_start_once(
                &worker_beside_this_test(),
                &worker,
                &["--version"],
            );
        }
        let repository = tempfile::tempdir().expect("a directory on the internal disk");
        let published = repository.path().join("development");
        copy_tree(source, &published);
        let example = install_the_example(&tree, &published).await;
        let environment = tree.environment();
        let mut hosted = Self {
            controller: None,
            serving: Vec::new(),
            endpoint: environment.controller_endpoint().expect("an endpoint"),
            environment_id: tree.environment_id(),
            worker,
            launched: Arc::default(),
            example,
            _repository: repository,
            tree,
        };
        hosted.run().await;
        hosted
    }

    /// Starts the daemon on the tree, serving its clients and its workers' rendezvous.
    async fn run(&mut self) {
        let environment = self.tree.environment();
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
            supervisor: Box::new(Recording {
                inner: self.tree.supervisor(kr_controller::supervision::detect()),
                launched: Arc::clone(&self.launched),
            }),
            worker_program: self.worker.clone(),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let listener = Listener::bind(&self.endpoint).expect("binds the endpoint");
        self.serving.push(tokio::spawn(
            Arc::clone(&controller).serve_clients(listener),
        ));
        let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
            .expect("binds the rendezvous");
        self.serving.push(tokio::spawn(
            Arc::clone(&controller).serve_rendezvous(rendezvous),
        ));
        self.controller = Some(controller);
    }

    /// Stops the daemon and starts another on the same tree, the way a restart of the host does:
    /// every durable record stays, nothing held in memory does, and the workers go on running.
    async fn restart(&mut self) {
        for serving in self.serving.drain(..) {
            serving.abort();
            let _ = serving.await;
        }
        let controller = self.controller.take().expect("a daemon");
        let deadline = tokio::time::Instant::now() + PATIENCE;
        while Arc::strong_count(&controller) > 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the stopped daemon is still held in {} places",
                Arc::strong_count(&controller) - 1
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(controller);
        self.run().await;
    }

    fn controller(&self) -> &Arc<Controller> {
        self.controller.as_ref().expect("a daemon")
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects")
    }

    fn target(&self, session: Option<(SessionId, SessionEpoch)>) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::from(session.map(|(session_id, _)| session_id)),
            session_epoch: Nullable::from(session.map(|(_, epoch)| epoch)),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Creates a session with a real worker, and returns it once it is live.
    async fn session(&self) -> SessionCreateResult {
        self.client()
            .await
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &SessionCreateParams {
                    environment_id: self.environment_id,
                    presentation: Presentation::Invisible,
                    shell: Nullable::some("/bin/sh".to_owned()),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some(self.tree.root().display().to_string()),
                    dimensions: Nullable::null(),
                    worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    environment_snapshot: Vec::new(),
                    palette: Nullable::null(),
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("the session is created")
            .to_typed()
            .expect("decodes")
    }

    async fn close(&self, created: &SessionCreateResult) {
        let session = &created.session;
        let _: kr_protocol::session::SessionCloseResult = self
            .client()
            .await
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(Some((session.session_id, session.session_epoch))),
                &kr_protocol::session::SessionCloseParams {
                    session_id: session.session_id,
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("closes")
            .to_typed()
            .expect("decodes");
    }

    /// Returns true while `session_id` is listed among the sessions that are not closed.
    async fn listed(&self, session_id: SessionId) -> bool {
        let listed: kr_protocol::session::SessionListResult = self
            .client()
            .await
            .request(
                Method::SessionList,
                &kr_protocol::session::SessionListParams {
                    environment_id: Nullable::some(self.environment_id),
                    include_closed: false,
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("lists")
            .to_typed()
            .expect("decodes");
        listed
            .sessions
            .iter()
            .any(|session| session.session_id == session_id)
    }

    /// Makes one change that raises the admission revision, through the daemon's own endpoint.
    async fn change(&self, method: Method) {
        let params = wire::PluginEnableParams {
            environment_id: self.environment_id,
            plugin_id: plugin(),
        };
        self.client()
            .await
            .mutate(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &params,
            )
            .await
            .expect("reaches the daemon")
            .expect("the change commits");
    }

    /// Removes the example package, and returns how many live bindings the removal counted.
    async fn remove(&self) -> Nullable<U64> {
        let removed: wire::PluginRemoveResult = self
            .client()
            .await
            .mutate(
                Method::PluginRemove,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(None),
                &wire::PluginRemoveParams {
                    environment_id: self.environment_id,
                    plugin_id: plugin(),
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("removed")
            .to_typed()
            .expect("decodes");
        removed.affected_bindings
    }

    /// The example package as `plugin.list` reports it now.
    async fn summary(&self) -> wire::PluginSummary {
        let listed: wire::PluginListResult = self
            .client()
            .await
            .request(
                Method::PluginList,
                &wire::PluginListParams {
                    environment_id: self.environment_id,
                },
            )
            .await
            .expect("reaches the daemon")
            .expect("listed")
            .to_typed()
            .expect("decodes");
        listed
            .plugins
            .into_iter()
            .find(|summary| summary.plugin_id == plugin())
            .expect("the example package is installed")
    }

    /// The example package's live bindings as `plugin.list` counts them now: known only when every
    /// worker answered its refresh at the revision the answer renders.
    async fn counted(&self) -> Nullable<U64> {
        self.summary().await.live_bindings
    }

    /// The directory of the example package's copy in the catalogue's store.
    fn package_copy(&self) -> PathBuf {
        self.tree
            .environment()
            .state_dir()
            .join("catalogue/repositories")
            .join(&self.example.origin.enrolment_key)
            .join("packages")
            .join(
                kr_plugin_sdk::digest::PayloadDigest::from_bytes(
                    *self.example.package_digest.as_bytes(),
                )
                .to_string(),
            )
    }

    /// Asks `plugin.list` until it counts `wanted` live bindings, or until the patience runs out,
    /// and returns the last count.
    async fn counted_as(&self, wanted: u64) -> Nullable<U64> {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let counted = self.counted().await;
            if counted == Nullable::some(U64::new(wanted))
                || tokio::time::Instant::now() >= deadline
            {
                return counted;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Types `line` into a session's terminal as a person at an attached terminal does: an
    /// attachment that may type, on the session's own worker, the input lease, and the bytes.
    /// Returns the connection, which holds the attachment.
    async fn type_into(&self, created: &SessionCreateResult, line: &str) -> LocalClient {
        let session = &created.session;
        let endpoint = self
            .tree
            .environment()
            .worker_endpoint(session.display_number)
            .expect("the worker's endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the session's worker");
        let target = self.target(Some((session.session_id, session.session_epoch)));
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &kr_protocol::attachment::SessionAttachParams {
                    session_id: session.session_id,
                    mode: kr_protocol::attachment::AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the attachment is accepted")
            .to_typed()
            .expect("decodes");
        let acquired: kr_protocol::input::InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::input::InputAcquireParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the lease is acquired")
            .to_typed()
            .expect("decodes");
        client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    epoch: acquired.lease.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(0),
                    bytes: kr_protocol::scalars::Bytes::new(line.as_bytes().to_vec()),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("the line reaches the terminal");
        client
    }

    /// The members a reclaim that needs room would wait for now.
    async fn pending(&self) -> Vec<String> {
        self.controller()
            .pending_admissions()
            .await
            .expect("the admission revision is readable")
    }

    /// Asks `plugin.list` until its counts are known, or until the patience runs out.
    async fn counted_once_known(&self) -> Nullable<U64> {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let counted = self.counted().await;
            if counted.is_present() || tokio::time::Instant::now() >= deadline {
                return counted;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// The worker the daemon launched for `session_id`, once the supervisor has reported it.
    async fn launched_for(&self, session_id: Option<SessionId>) -> Launched {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let found = self
                .launched
                .lock()
                .expect("the record is not poisoned")
                .iter()
                .find(|launched| session_id.is_none_or(|wanted| launched.session_id == wanted))
                .cloned();
            if let Some(launched) = found {
                return launched;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the supervisor started nothing for {session_id:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Claims `launched`'s reservation a second time, from this test's own process, which the
    /// launcher did not start: the daemon refuses the claim and fences the reservation.
    async fn claim_again(&self, launched: &Launched) {
        let identity = WorkerIdentity::generate(
            launched.session_id,
            SessionEpoch::V1,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
            kr_ipc::identity::current_process_start_identity().expect("this process"),
            PROTOCOL_VERSION,
        )
        .expect("a session key");
        let rendezvous = self
            .tree
            .environment()
            .rendezvous_endpoint()
            .expect("an endpoint");
        let connection = Connection::connect(&rendezvous).await.expect("connects");
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: build(),
                client: LocalClientKind::Worker,
                capabilities: kr_protocol::scalars::CanonicalSet::new(),
                max_receive: kr_protocol::hello::ReceiveLimits::default(),
            }))
            .await
            .expect("the hello is written");
        let acknowledged: ControlFrame = reader.read_message().await.expect("acknowledged");
        assert!(matches!(acknowledged, ControlFrame::HelloAck(_)));
        writer
            .write_message(&ControlFrame::Rendezvous(
                identity
                    .rendezvous(launched.reservation_id)
                    .expect("a signed claim"),
            ))
            .await
            .expect("the claim is written");
        let answer = tokio::time::timeout(PATIENCE, reader.read_message::<ControlFrame>())
            .await
            .expect("the daemon answers or ends the connection");
        assert!(
            !matches!(answer, Ok(ControlFrame::LaunchSpec(_))),
            "a claim from a process the launcher did not start is refused"
        );
    }
}

/// Enrols the published development catalogue, synchronises it, and installs and enables its
/// example package, as the owner acting directly, before any daemon opens the catalogue, and
/// returns the release installed, as a worker reports a binding of it.
async fn install_the_example(tree: &teardown::Tree, published: &Path) -> LiveRelease {
    let environment = tree.environment();
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&published.join("metadata")),
                directory_url(&published.join("targets")),
                std::fs::read(published.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&plugin(), &version)
        .expect("the example package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            tree.environment_id(),
            &plugin(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(tree.environment_id(), &plugin(), true)
        .await
        .expect("enabled");
    let installation = catalogue
        .installations()
        .expect("readable")
        .into_iter()
        .find(|installation| installation.plugin_id == plugin())
        .expect("the example package is installed");
    LiveRelease {
        plugin_id: installation.plugin_id,
        publisher_id: PublisherId::new(installation.publisher_id.as_str()).expect("a publisher"),
        version: installation.version.to_string(),
        package_digest: kr_protocol::scalars::Digest256::from_bytes(
            *installation.package_digest.as_bytes(),
        ),
        origin: ReleaseOrigin {
            repository_id: installation.repository.to_string(),
            enrolment_key: installation.enrolment.as_str().to_owned(),
        },
    }
}

/// Sends `signal` to a worker the daemon started, after checking that the process is still that
/// worker.
fn signal(process: &ProcessStartIdentity, signal: rustix::process::Signal) {
    assert_eq!(
        kr_ipc::identity::process_state(process),
        ProcessState::Running,
        "the process is still the worker the daemon started"
    );
    let pid = rustix::process::Pid::from_raw(i32::try_from(process.pid.get()).expect("a pid"))
        .expect("a process");
    rustix::process::kill_process(pid, signal).expect("signalled");
}

/// A worker stopped by this test, resumed when this is dropped however the test ends, so the tree
/// can ask it to close.
struct Stopped(ProcessStartIdentity);

impl Stopped {
    fn stop(process: &ProcessStartIdentity) -> Self {
        signal(process, rustix::process::Signal::STOP);
        Self(process.clone())
    }
}

impl Drop for Stopped {
    fn drop(&mut self) {
        if kr_ipc::identity::process_state(&self.0) == ProcessState::Running
            && let Ok(pid) = i32::try_from(self.0.pid.get())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::CONT);
        }
    }
}

/// Ends a worker the daemon started, and waits until the kernel says it has ended.
async fn end(process: &ProcessStartIdentity) {
    signal(process, rustix::process::Signal::KILL);
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while kr_ipc::identity::process_state(process) != ProcessState::Ended {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker did not end"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// KR-REQ-23.29: `plugin.list` and `plugin.remove` count live bindings from the hosted workers' own
/// answers.
///
/// A worker is a member from its claim, and once it is recorded a round reconciles it: the next
/// `plugin.list` counts its bindings, none yet, and a removal counts what its refresh found.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_recorded_worker_is_reconciled_and_counted_from_its_answer() {
    let hosted = Hosted::start().await;
    let _session = hosted.session().await;
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "a recorded worker answers a round and is counted"
    );
    assert!(
        hosted.pending().await.is_empty(),
        "a reconciled worker holds no reclaim"
    );
    assert_eq!(
        hosted.remove().await,
        Nullable::some(U64::new(0)),
        "a removal counts the bindings its refresh found"
    );
}

/// KR-REQ-23.29: after `plugin.disable`, `plugin.list` counts nothing and `plugin.remove` counts
/// nothing while a hosted worker has not answered at the new admission revision.
///
/// A change leaves a worker pending until it answers at the new revision. A refresh whose caller
/// goes away part way through a round, as a paired device's read does when its connection drops,
/// leaves that round to finish on its own: once the worker answers again the member is reconciled.
/// A removal while it cannot answer counts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_worker_is_pending_after_a_change_until_it_answers_at_the_new_revision() {
    let hosted = Hosted::start().await;
    let created = hosted.session().await;
    let worker = hosted
        .launched_for(Some(created.session.session_id))
        .await
        .process
        .expect("started");
    assert!(hosted.counted_once_known().await.is_present());

    assert!(hosted.pending().await.is_empty());
    let member = format!("session {}", created.session.session_id);

    let stopped = Stopped::stop(&worker);
    hosted.change(Method::PluginDisable).await;
    assert_eq!(
        hosted.pending().await,
        vec![member.clone()],
        "a worker reconciled at the revision before a change is pending at the new one"
    );
    // Each read's refresh stops waiting at its bound with the round still out.
    for _ in 0..2 {
        assert_eq!(
            hosted.counted().await,
            Nullable::null(),
            "a worker that has not answered at the new revision is not counted"
        );
        assert_eq!(hosted.pending().await, vec![member.clone()]);
    }

    // Once no round is out, a refresh sends one, and its caller goes away part way through it.
    let session_id = created.session.session_id;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while hosted.controller().admission_round_out(session_id) {
        assert!(tokio::time::Instant::now() < deadline, "the round ends");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let gone = tokio::time::timeout(
        Duration::from_millis(500),
        hosted.controller().refresh_admissions(),
    )
    .await;
    assert!(gone.is_err(), "the refresh's caller went away part way");
    assert!(
        hosted.controller().admission_round_out(session_id),
        "the refresh's round is still out on its own"
    );
    drop(stopped);
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "the worker answers at the new revision and is reconciled"
    );
    assert!(hosted.pending().await.is_empty());

    let stopped = Stopped::stop(&worker);
    assert_eq!(
        hosted.remove().await,
        Nullable::null(),
        "a removal whose refresh a worker did not answer counts nothing"
    );
    drop(stopped);
}

/// KR-REQ-23.29: `plugin.list` counts bindings from the workers whose sessions are live.
///
/// A session that closes takes its worker out of the member set: the workers left answer, and the
/// counts are known again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_closed_session_takes_its_worker_out_of_the_member_set() {
    let hosted = Hosted::start().await;
    let first = hosted.session().await;
    let _second = hosted.session().await;
    let worker = hosted
        .launched_for(Some(first.session.session_id))
        .await
        .process
        .expect("started");
    assert!(hosted.counted_once_known().await.is_present());
    hosted.close(&first).await;
    // The closure is written once the worker has ended: counted only after that, so the closed
    // session's worker cannot be the one answering.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while kr_ipc::identity::process_state(&worker) != ProcessState::Ended
        || hosted.listed(first.session.session_id).await
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the closed session's worker ends and its session is closed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "the closed session's worker is no longer asked, and the one left answers"
    );
}

/// KR-REQ-23.29: a worker this host stopped trusting keeps `plugin.list`'s count unknown until its
/// process has ended.
///
/// A second claim that lands after a worker's claim is committed and before its specification is
/// made fences the member the first claim added: the worker it launched, holding its first
/// snapshot, is never sent a round and keeps the counts unknown until its process has ended, and
/// then it leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_worker_fenced_between_its_claim_and_its_specification_leaves_once_its_process_ends() {
    let hosted = Hosted::start().await;
    let (arrived, release) = hosted.controller().pause_rendezvous_after_claim();
    let client = hosted.client().await;
    let environment_id = hosted.environment_id;
    let target = hosted.target(None);
    let creating = tokio::spawn(async move {
        let mut client = client;
        client
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &SessionCreateParams {
                    environment_id,
                    presentation: Presentation::Invisible,
                    shell: Nullable::some("/bin/sh".to_owned()),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some("/".to_owned()),
                    dimensions: Nullable::null(),
                    worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                    environment_snapshot: Vec::new(),
                    palette: Nullable::null(),
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                },
            )
            .await
    });
    tokio::time::timeout(PATIENCE, arrived)
        .await
        .expect("the worker's claim is committed in time")
        .expect("the rendezvous arrived");
    let launched = hosted.launched_for(None).await;
    hosted.claim_again(&launched).await;
    release.send(()).expect("the rendezvous goes on");
    let _ = tokio::time::timeout(PATIENCE, creating).await;
    let worker = launched.process.expect("started");
    let member = format!("session {}", launched.session_id);

    for _ in 0..2 {
        assert_eq!(
            hosted.counted().await,
            Nullable::null(),
            "a fenced worker keeps the counts unknown while its process runs"
        );
        assert_eq!(hosted.pending().await, vec![member.clone()]);
    }
    end(&worker).await;
    // A change asks for a pass, which asks the kernel about the fenced member.
    hosted.change(Method::PluginDisable).await;
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "a fenced member leaves once its process has ended"
    );
    assert!(hosted.pending().await.is_empty());
}

/// KR-REQ-23.29: the binding count stays unknown across a daemon restart while an untrusted worker
/// runs.
///
/// A daemon that restarts seeds its member set from the registry before it serves anything: a
/// worker the host stopped trusting is a member again, pending and never sent a round, until its
/// process has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_12_a_fenced_worker_is_a_member_again_after_a_restart_until_its_process_ends() {
    let mut hosted = Hosted::start().await;
    let created = hosted.session().await;
    let launched = hosted.launched_for(Some(created.session.session_id)).await;
    let worker = launched.process.clone().expect("started");
    assert!(hosted.counted_once_known().await.is_present());
    hosted.claim_again(&launched).await;
    let member = format!("session {}", launched.session_id);
    assert_eq!(hosted.counted().await, Nullable::null(), "fenced, pending");
    assert_eq!(hosted.pending().await, vec![member.clone()]);

    hosted.restart().await;
    for _ in 0..2 {
        assert_eq!(
            hosted.counted().await,
            Nullable::null(),
            "the restarted daemon holds the fenced worker pending"
        );
        assert_eq!(hosted.pending().await, vec![member.clone()]);
    }
    end(&worker).await;
    hosted.change(Method::PluginDisable).await;
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "it leaves once its process has ended"
    );
    assert!(hosted.pending().await.is_empty());
}

/// KR-REQ-23.29: an installation past the owner's package limit is left out of the admissions new
/// bindings use, by the limit's name, and the hosted worker answers at the new revision.
///
/// A configuration that lowers a package limit below an admitted package moves the admissions with
/// no catalogue change: the admission revision rises, the package is left out by the limit's name,
/// and the hosted worker is reconciled again at the new revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lowered_package_limit_moves_the_admissions_to_a_new_revision() {
    use kr_protocol::hostinfo::configuration::{Change, ConfiguredEnrolmentBudgets};
    let hosted = Hosted::start().await;
    let _session = hosted.session().await;
    assert!(hosted.counted_once_known().await.is_present());
    let snapshot = || async {
        hosted
            .controller()
            .catalogue()
            .snapshot_within(&[], tokio::time::Instant::now() + PATIENCE)
            .await
            .expect("computed")
    };
    let before = snapshot().await;
    assert!(
        before
            .packages
            .iter()
            .any(|package| package.plugin_id == plugin())
    );
    let names_the_package = |warnings: &[String]| {
        warnings
            .iter()
            .any(|warning| warning.contains(plugin().as_str()))
    };
    assert!(
        !names_the_package(&hosted.controller().catalogue_warnings().await),
        "an admitted package is nothing the doctor warns about"
    );

    hosted
        .controller()
        .apply_configuration(&Change::Enrolment(ConfiguredEnrolmentBudgets {
            package_bytes: Nullable::some(1),
            ..ConfiguredEnrolmentBudgets::default()
        }))
        .await
        .expect("the owner's limit");
    let after = snapshot().await;
    assert!(
        after.revision > before.revision,
        "{} {}",
        after.revision,
        before.revision
    );
    assert!(after.packages.is_empty(), "{:?}", after.packages);
    assert!(
        after
            .left_out
            .iter()
            .any(|left| left.plugin_id == plugin() && left.detail.contains("package_bytes")),
        "{:?}",
        after.left_out
    );
    let warnings = hosted.controller().catalogue_warnings().await;
    assert!(
        warnings.iter().any(|warning| warning.contains(plugin().as_str())
            && warning.contains("package_bytes")),
        "the doctor names the package it cannot admit and the limit it is past: {warnings:?}"
    );
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "the worker answers at the new revision"
    );
    assert!(hosted.pending().await.is_empty());

    // Disabled as well, the package is the owner's decision twice over and nothing to warn about.
    hosted
        .controller()
        .apply_configuration(&Change::Enrolment(ConfiguredEnrolmentBudgets::default()))
        .await
        .expect("the limit back as it was");
    hosted.change(Method::PluginDisable).await;
    assert!(
        !names_the_package(&hosted.controller().catalogue_warnings().await),
        "a disabled package is nothing the doctor warns about"
    );
}

/// A lowered package limit whose admission revision cannot be raised does not come into force:
/// the acceptance says so, and the budgets and the admissions stay as they were. Another acceptance
/// of the same configuration, once the store answers, raises the revision and leaves the package
/// out by the limit's name.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_package_limit_whose_revision_cannot_be_raised_stays_out_of_force_until_an_acceptance_raises_it()
 {
    use kr_protocol::hostinfo::configuration::{Change, ConfiguredEnrolmentBudgets};
    let hosted = Hosted::start().await;
    let catalogue = hosted.controller().catalogue();
    let snapshot = || async {
        catalogue
            .snapshot_within(&[], tokio::time::Instant::now() + PATIENCE)
            .await
            .expect("computed")
    };
    let admitted = |snapshot: &kr_controller::catalogue::admissions::Snapshot| {
        snapshot
            .packages
            .iter()
            .any(|package| package.plugin_id == plugin())
    };
    let before = snapshot().await;
    assert!(admitted(&before));
    let in_force = catalogue.budgets_in_force();
    let lowered = Change::Enrolment(ConfiguredEnrolmentBudgets {
        package_bytes: Nullable::some(1),
        ..ConfiguredEnrolmentBudgets::default()
    });

    catalogue.fail_next_revision_raise();
    let refused = hosted
        .controller()
        .apply_configuration(&lowered)
        .await
        .expect_err("the acceptance says the budgets are not in force");
    assert!(
        refused.to_string().contains("enrolment budgets"),
        "{refused}"
    );
    assert_eq!(catalogue.budgets_in_force(), in_force, "nothing moved");
    let during = snapshot().await;
    assert_eq!(during.revision, before.revision);
    assert!(admitted(&during), "the admissions are as they were");

    hosted
        .controller()
        .apply_configuration(&lowered)
        .await
        .expect("the same configuration accepted again");
    assert_eq!(catalogue.budgets_in_force().package_bytes, 1);
    let after = snapshot().await;
    assert!(after.revision > before.revision);
    assert!(!admitted(&after));
    assert!(
        after
            .left_out
            .iter()
            .any(|left| left.plugin_id == plugin() && left.detail.contains("package_bytes")),
        "{:?}",
        after.left_out
    );
}

/// The budgets and their admission revision move in one step with every read of the catalogue: an
/// acceptance that lowers a package limit while a read holds the catalogue puts nothing in force
/// until that read is done, so no snapshot pairs the old revision with the new limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lowered_package_limit_comes_into_force_with_its_revision_in_one_step() {
    use kr_controller::catalogue::TestingPoint;
    use kr_protocol::hostinfo::configuration::{Change, ConfiguredEnrolmentBudgets};
    let hosted = Hosted::start().await;
    let catalogue = hosted.controller().catalogue();
    let before = catalogue
        .snapshot_within(&[], tokio::time::Instant::now() + PATIENCE)
        .await
        .expect("computed");
    let in_force = catalogue.budgets_in_force();

    // A read that holds the catalogue until the test lets it go: the first one to reach it, which
    // may be the cadence's own. Every later read, the rounds the acceptance asks for among them,
    // goes through.
    let (held, holding) = std::sync::mpsc::channel::<()>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (held, released) = (Mutex::new(held), Mutex::new(released));
    let first = std::sync::atomic::AtomicBool::new(true);
    catalogue.at_testing_point(move |point| {
        if point == TestingPoint::Records && first.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = held.lock().expect("the channel").send(());
            let _ = released.lock().expect("the channel").recv_timeout(PATIENCE);
        }
    });
    let reading = {
        let controller = Arc::clone(hosted.controller());
        tokio::spawn(async move {
            controller
                .catalogue()
                .installed_within(tokio::time::Instant::now() + PATIENCE)
                .await
                .map(|_| ())
        })
    };
    tokio::task::spawn_blocking(move || holding.recv_timeout(PATIENCE))
        .await
        .expect("the wait ends")
        .expect("the read holds the catalogue");

    let accepting = {
        let controller = Arc::clone(hosted.controller());
        tokio::spawn(async move {
            controller
                .apply_configuration(&Change::Enrolment(ConfiguredEnrolmentBudgets {
                    package_bytes: Nullable::some(1),
                    ..ConfiguredEnrolmentBudgets::default()
                }))
                .await
                .map(|_| ())
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        catalogue.budgets_in_force(),
        in_force,
        "nothing is put in force while a read holds the catalogue"
    );
    assert!(!accepting.is_finished());

    release.send(()).expect("the read goes on");
    reading
        .await
        .expect("the read ends")
        .expect("the read answers");
    accepting
        .await
        .expect("the acceptance ends")
        .expect("the limit is in force");
    assert_eq!(catalogue.budgets_in_force().package_bytes, 1);
    let after = catalogue
        .snapshot_within(&[], tokio::time::Instant::now() + PATIENCE)
        .await
        .expect("computed");
    assert!(after.revision > before.revision);
    assert!(
        after
            .packages
            .iter()
            .all(|package| package.plugin_id != plugin())
    );
}

/// KR-REQ-23.29: `plugin.list` counts the binding of a program a worker adopted while it runs, and
/// none once it has exited.
///
/// A worker reconciled with an empty report adopts a program a person started in its session,
/// with no change to the catalogue: the program is the one the example package recognises, which
/// has no connector table, so it is adopted by the package's match rule alone and bound. The next
/// `plugin.list` counts that binding, and once the program has exited the next one counts none.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_program_adopted_with_no_catalogue_change_is_counted_while_it_runs() {
    let hosted = Hosted::start().await;
    let created = hosted.session().await;
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "reconciled with an empty report"
    );

    // The program the example package recognises, placed on the internal disk and started once
    // where nothing is timed.
    let program = hosted.tree.root().join("example-agent");
    kr_ipc::testing::place_and_start_once(
        &std::env::current_exe().expect("this test's own binary"),
        &program,
        &["--exact", "the_stand_in_program", "--test-threads", "1"],
    );
    let running = hosted.tree.root().join("stand-in-running");
    let _typing = hosted
        .type_into(
            &created,
            &format!(
                "{STAND_IN}=60 {STAND_IN_RUNNING}='{}' '{}' --exact the_stand_in_program \
                 --test-threads 1\n",
                running.display(),
                program.display()
            ),
        )
        .await;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let pid = loop {
        if let Ok(said) = std::fs::read_to_string(&running)
            && let Ok(pid) = said.trim().parse::<u32>()
        {
            break pid;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the program the line started runs"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let started = kr_ipc::identity::process_start_identity(pid).expect("the program is identified");

    assert_eq!(
        hosted.counted_as(1).await,
        Nullable::some(U64::new(1)),
        "the adopted program's binding is counted"
    );
    end(&started).await;
    assert_eq!(
        hosted.counted_as(0).await,
        Nullable::some(U64::new(0)),
        "and once it has exited, none is"
    );
}

/// KR-REQ-23.29: a `plugin.disable` ends the package's bindings: the host asks again until the
/// worker reports the binding closed.
///
/// A binding due to end closes at the first snapshot after every request it admitted settles, and
/// only a round brings a snapshot. A worker answers the round of a disabling with its binding
/// ending while such a request is open; the release is still installed, and the worker is
/// reconciled, so the cadence asks it again, with no `plugin.list` and no other change, until an
/// answer omits the binding.
///
/// The worker here holds no request: the test makes its accepted report list a binding of the
/// example release due to end, as the answer given while a request was open does, and the
/// worker's own next answer is the one given after that request settled. That the worker closes
/// the binding at that snapshot is the worker's own tests' to show.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_cadence_asks_a_worker_reporting_a_binding_due_to_end_again_until_it_closes() {
    let hosted = Hosted::start().await;
    let created = hosted.session().await;
    let session_id = created.session.session_id;
    assert!(hosted.counted_once_known().await.is_present());
    hosted.change(Method::PluginDisable).await;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !hosted.pending().await.is_empty() || hosted.controller().admission_round_out(session_id)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the worker answers at the disabling's revision"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        hosted
            .controller()
            .report_ending_binding(session_id, hosted.example.clone()),
        "the worker has an accepted report"
    );
    assert_eq!(
        hosted.controller().reported_releases(),
        vec![(hosted.example.clone(), true)]
    );
    assert!(
        hosted.pending().await.is_empty(),
        "a report listing an installed release leaves the worker reconciled"
    );

    hosted.controller().ask_for_admissions_pass();
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !hosted.controller().reported_releases().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the cadence asks the worker again, and its answer omits the binding"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hosted.pending().await.is_empty());
}

/// Why `plugin.list` says the admissions leave the example package out, where it says they do.
fn left_out(summary: &wire::PluginSummary) -> (wire::PluginLeftOutReason, String) {
    match &summary.admission.0 {
        Some(wire::PluginAdmission::LeftOut { reason, detail }) => (*reason, detail.clone()),
        other => panic!("the admissions leave it out, not {other:?}"),
    }
}

/// KR-REQ-23.29: `plugin.list` says whether new bindings may use each installation, and why not.
///
/// `plugin.list` says whether the admissions in force let new bindings use each installation,
/// and why not where they do not, by kind and in words that name the package: admitted, then
/// disabled, then past a package limit the owner set, and, once a file of the store's copy is
/// gone, not whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn plugin_list_says_why_the_admissions_leave_an_installation_out() {
    use kr_protocol::hostinfo::configuration::{Change, ConfiguredEnrolmentBudgets};
    let admitted = Nullable::some(wire::PluginAdmission::Admitted);
    let mut hosted = Hosted::start_from(&fixture(), false).await;
    assert_eq!(hosted.summary().await.admission, admitted);

    hosted.change(Method::PluginDisable).await;
    let (reason, detail) = left_out(&hosted.summary().await);
    assert_eq!(reason, wire::PluginLeftOutReason::Disabled);
    assert!(
        detail.contains(plugin().as_str()) && detail.contains("disabled"),
        "{detail}"
    );
    hosted.change(Method::PluginEnable).await;
    assert_eq!(hosted.summary().await.admission, admitted);

    hosted
        .controller()
        .apply_configuration(&Change::Enrolment(ConfiguredEnrolmentBudgets {
            package_bytes: Nullable::some(1),
            ..ConfiguredEnrolmentBudgets::default()
        }))
        .await
        .expect("the owner's limit");
    let (reason, detail) = left_out(&hosted.summary().await);
    assert_eq!(reason, wire::PluginLeftOutReason::PastALimit);
    assert!(
        detail.contains(plugin().as_str()) && detail.contains("package_bytes"),
        "{detail}"
    );
    hosted
        .controller()
        .apply_configuration(&Change::Enrolment(ConfiguredEnrolmentBudgets::default()))
        .await
        .expect("the limit lifted");
    assert_eq!(hosted.summary().await.admission, admitted);

    // The store's copy is read when the admissions are next computed, which a daemon that starts
    // again does.
    std::fs::remove_file(hosted.package_copy().join("README.md")).expect("a file of the copy");
    hosted.restart().await;
    let (reason, detail) = left_out(&hosted.summary().await);
    assert_eq!(reason, wire::PluginLeftOutReason::Incomplete);
    assert!(
        detail.contains(plugin().as_str()) && detail.contains("README.md"),
        "{detail}"
    );
}

/// KR-REQ-23.29: the environment check: an installation for another platform is left out of what
/// new bindings on this host may use.
///
/// An installation whose own manifest names only another platform is listed as one this host
/// does not support.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn plugin_list_names_an_installation_this_host_does_not_support() {
    use kr_plugin_sdk::matching::{Architecture, OperatingSystem, PlatformSupport};
    let home = tempfile::tempdir().expect("a directory on the internal disk");
    let elsewhere = if kr_plugin_catalogue::this_host().os == Some(OperatingSystem::MacOs) {
        PlatformSupport {
            os: OperatingSystem::Linux,
            architectures: vec![Architecture::X86_64],
        }
    } else {
        PlatformSupport {
            os: OperatingSystem::MacOs,
            architectures: vec![Architecture::Aarch64],
        }
    };
    let generation = generations::Generation::build(
        home.path(),
        generations::GenerationSpec {
            platforms: Some(vec![elsewhere]),
            ..generations::GenerationSpec::default()
        },
    )
    .await;
    let hosted = Hosted::start_from(&generation.directory(), false).await;
    let (reason, detail) = left_out(&hosted.summary().await);
    assert_eq!(reason, wire::PluginLeftOutReason::Unsupported);
    assert!(
        detail.contains(plugin().as_str()) && detail.contains("operating system"),
        "{detail}"
    );
}

/// Writes the host's configuration document naming `policy`, at the revision after the one on
/// disk, as a person editing their own file does.
fn name_the_policy(hosted: &Hosted, policy: kr_protocol::admission::RevocationPolicy) {
    let path = kr_worker::config::document_path(&hosted.tree.environment());
    let mut document: serde_json::Value = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).expect("a document this host wrote"),
        Err(_) => serde_json::to_value(
            kr_protocol::hostinfo::configuration::ConfigurationDocument::empty(),
        )
        .expect("an empty document"),
    };
    let revision = document["revision"].as_u64().expect("a revision") + 1;
    document["revision"] = serde_json::json!(revision);
    document["ceilings"]["disable_policy"] = serde_json::to_value(policy).expect("a policy");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the state directory");
    }
    kr_ipc::paths::write_owner_only_file(
        &path,
        serde_json::to_string(&document).expect("JSON").as_bytes(),
    )
    .expect("the document");
}

/// KR-REQ-25.22: no snapshot a restarted daemon computes for a worker that outlived the last one
/// carries the policy the catalogue recorded before the restart rather than the one this host's
/// configuration decides. The cadence that sends the first round starts before the document is
/// accepted, so the policy is put in force when the catalogue opens; the configuration suite holds
/// that ordering by construction, and this case shows it with a real worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_worker_that_outlives_a_restart_is_first_sent_the_policy_the_configuration_decides() {
    use kr_protocol::admission::RevocationPolicy;
    let mut hosted = Hosted::start().await;
    let _session = hosted.session().await;
    assert!(hosted.counted_once_known().await.is_present());
    assert_eq!(
        hosted.controller().catalogue().policies_carried(),
        [RevocationPolicy::WarnOnly],
        "control: the worker was handed warn only before the document named anything"
    );

    // The document is edited while no daemon reads it: the restart is what meets it.
    name_the_policy(&hosted, RevocationPolicy::DisableAtOnce);
    hosted.restart().await;
    assert!(hosted.counted_once_known().await.is_present());
    let carried = hosted.controller().catalogue().policies_carried();
    assert!(!carried.is_empty(), "the worker was sent a round");
    assert!(
        carried
            .iter()
            .all(|policy| *policy == RevocationPolicy::DisableAtOnce),
        "no snapshot the restarted daemon computed carried the policy before it: {carried:?}"
    );
}

/// KR-REQ-25.22: a policy that moves sends every worker a round at once, as a package limit does,
/// without waiting for the cadence. The worker cannot answer here, so the round stays out, and
/// that is what shows it was sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_policy_that_moves_sends_every_worker_a_round_at_once() {
    use kr_protocol::admission::RevocationPolicy;
    let hosted = Hosted::start().await;
    let created = hosted.session().await;
    let session_id = created.session.session_id;
    let worker = hosted
        .launched_for(Some(session_id))
        .await
        .process
        .expect("started");
    assert!(hosted.counted_once_known().await.is_present());
    assert!(hosted.pending().await.is_empty());

    let stopped = Stopped::stop(&worker);
    name_the_policy(&hosted, RevocationPolicy::DisableAtNextAdmission);
    drop(hosted.controller().effective_configuration().await);
    assert_eq!(
        hosted.pending().await,
        vec![format!("session {session_id}")],
        "the worker is pending at the revision the policy moved"
    );
    // The cadence's own pass is thirty seconds away from any point in this test's first seconds,
    // so a round out before it is the one the change asked for.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !hosted.controller().admission_round_out(session_id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no round was sent when the policy moved"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(stopped);
    assert_eq!(
        hosted.counted_once_known().await,
        Nullable::some(U64::new(0)),
        "the worker answers at the new revision"
    );
    assert!(hosted.pending().await.is_empty());
    assert_eq!(
        hosted.controller().catalogue().policies_carried().last(),
        Some(&RevocationPolicy::DisableAtNextAdmission)
    );
}
