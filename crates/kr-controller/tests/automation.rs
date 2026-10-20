//! The "Automation" method group through the real control daemon.
//!
//! Requirement rows exercised here: KR-REQ-23.52 (the five methods under the daemon's own
//! admission, each naming the exact definition revision), KR-REQ-18.04 (a workflow node that is a
//! real host action, carried out and bound to the run that asked for it), KR-REQ-19.04 (a
//! revoked grant runs nothing, and the grant is this host's rather than the request's) and
//! KR-REQ-25.19 (a redelivered trigger produces one run, not two).
//!
//! These run the real endpoint, the real handshake, the real envelope checks and real
//! repositories built with installed Git. The daemon starts on an environment under the
//! platform's temporary directory, which is on the internal disk, and its secrets go to a file
//! store rather than to the operator's login keychain.

#![cfg(not(windows))]

mod organisation_support;
mod teardown;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::grants::GrantRecord;
use kr_controller::service::{Clocks, Controller, ControllerSetup, WallClock};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::automation::{
    NodeStatus, WorkflowActionKind, WorkflowDeadlines, WorkflowDefinition, WorkflowEnableParams,
    WorkflowEnableResult, WorkflowInstallParams, WorkflowInstallResult, WorkflowNode,
    WorkflowPauseParams, WorkflowPauseResult, WorkflowReadParams, WorkflowReadResult,
    WorkflowResourceScope, WorkflowRunParams, WorkflowRunResult, WorkflowRunStatus,
    WorkflowTrigger,
};
use kr_protocol::changeset::{
    ChangesetCaptureParams, ChangesetReadParams, ChangesetReadResult, FileGrant, TestedSource,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    ActionId, AuthorityRevision, BuildId, EnvironmentId, GrantId, WorkflowId, WorkspaceId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, DestinationParent, DestinationRequest, InclusionChoice, InclusionPolicy,
    ProjectAdoptParams, ProjectAdoptResult, WorkspaceCreateParams, WorkspaceCreateResult,
    WorkspaceKind,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, U64, Uuid};

/// A supervisor that starts nothing. These tests create no sessions.
#[derive(Debug)]
struct RefusingSupervisor;

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

struct Host {
    /// The host tree. Whatever workers its daemon started are ended before it goes.
    _temp: teardown::Tree,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    /// The rendezvous of a daemon that starts workers.
    _rendezvous: Option<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    work: tempfile::TempDir,
}

impl Host {
    fn work(&self) -> &Path {
        self.work.path()
    }

    /// Writes one live grant into this daemon's own grant store.
    ///
    /// A definition names a grant and the host reads it from here, so a test that installs one
    /// puts the grant in first, exactly as a person sharing a session would have. It carries the
    /// authority revision the host is at, as a grant the host issued now would.
    fn issue(&self, grant_id: GrantId, rights: &[ActionRight]) -> Grant {
        let device_id = kr_protocol::ids::DeviceId::new(self.environment_id.get());
        let grant = Grant {
            grant_id,
            parent_grant_id: Nullable::null(),
            issuer_device_id: device_id,
            recipient_device_id: device_id,
            authority_revision: self.controller.policy().authority_revision(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: rights.iter().copied().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        };
        self.controller
            .sharing()
            .grants()
            .issue(
                &GrantRecord {
                    grant: grant.clone(),
                    session_id: None,
                    issued_at_ms: 1_000,
                    activated_at_ms: Some(1_000),
                    revoked_at_ms: None,
                    revoked_by_parent: None,
                },
                || Ok(()),
            )
            .expect("the grant is written");
        grant
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    host_on(Clocks::system()).await
}

/// A daemon on the clocks the test gives it.
async fn host_on(clocks: Clocks) -> Host {
    let temp = teardown::Tree::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let controller = start_daemon(&environment, environment_id, clocks)
        .await
        .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Host {
        _temp: temp,
        controller,
        environment_id,
        endpoint,
        clients,
        _rendezvous: None,
        work: tempfile::TempDir::new().expect("a working directory on the internal disk"),
    }
}

/// The program `name` built beside this test, which the workspace's own test run builds.
fn beside_this_test(name: &str) -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let program = directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        program.is_file(),
        "this test starts {name} and there is none at {}; build it with `cargo build -p {name}`, \
         or run the whole workspace's tests, which build it",
        program.display()
    );
    program
}

/// A daemon whose sessions are real: the worker program is the one built beside this test, placed
/// on the internal disk and started by the platform's own supervisor, and the daemon serves the
/// rendezvous its workers connect to.
async fn working_host() -> Host {
    working_host_through(|supervisor| supervisor).await
}

/// A supervisor that waits at the door of a launch until the test lets it through, and counts the
/// launches that have reached the door and the workers the platform then started.
#[derive(Debug)]
struct AtTheDoor {
    inner: Box<dyn WorkerSupervisor>,
    open: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    arrived: Arc<std::sync::atomic::AtomicUsize>,
    started: Arc<std::sync::atomic::AtomicUsize>,
}

impl WorkerSupervisor for AtTheDoor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.arrived
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (lock, wake) = &*self.open;
        let mut open = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*open {
            open = wake
                .wait(open)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(open);
        let outcome = self.inner.start(launch);
        if matches!(outcome, LaunchOutcome::Started(_)) {
            self.started
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        outcome
    }

    fn describe(&self) -> &'static str {
        self.inner.describe()
    }
}

/// [`working_host`] with the supervisor wrapped by `wrap`, which sits between the daemon and the
/// tree's own.
async fn working_host_through(
    wrap: impl FnOnce(Box<dyn WorkerSupervisor>) -> Box<dyn WorkerSupervisor>,
) -> Host {
    let temp = teardown::Tree::create();
    let worker = temp.root().join("kr-worker");
    kr_ipc::testing::place_and_start_once(&beside_this_test("kr-worker"), &worker, &["--version"]);
    working_host_on(temp, wrap).await
}

/// A daemon with real sessions on a tree that already holds its worker program.
async fn working_host_on(
    temp: teardown::Tree,
    wrap: impl FnOnce(Box<dyn WorkerSupervisor>) -> Box<dyn WorkerSupervisor>,
) -> Host {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let worker = temp.root().join("kr-worker");
    let supervisor = wrap(temp.supervisor(kr_controller::supervision::detect()));
    let controller = start_daemon_with(
        &environment,
        environment_id,
        Clocks::system(),
        supervisor,
        worker,
    )
    .await
    .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
        .expect("binds the rendezvous");
    let rendezvous = tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
    Host {
        _temp: temp,
        controller,
        environment_id,
        endpoint,
        clients,
        _rendezvous: Some(rendezvous),
        work: tempfile::TempDir::new().expect("a working directory on the internal disk"),
    }
}

/// A daemon that runs on a runtime of its own, so that ending the runtime ends every task the
/// daemon has begun, as the end of its process would, while the workers it started go on.
struct Apart {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Apart {
    /// Ends the daemon's runtime and waits for it to be gone.
    fn end(mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the daemon's runtime ended");
        }
    }
}

/// [`working_host`] whose daemon runs apart.
async fn working_host_apart() -> (Host, Apart) {
    let temp = teardown::Tree::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let worker = temp.root().join("kr-worker");
    kr_ipc::testing::place_and_start_once(&beside_this_test("kr-worker"), &worker, &["--version"]);
    let supervisor = temp.supervisor(kr_controller::supervision::detect());
    let (ready_sender, ready) = std::sync::mpsc::channel();
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn({
        let environment = environment.clone();
        move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("a runtime for the daemon");
            let started = runtime.block_on(async {
                let controller = start_daemon_with(
                    &environment,
                    environment_id,
                    Clocks::system(),
                    supervisor,
                    worker,
                )
                .await
                .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
                let endpoint = environment.controller_endpoint().expect("an endpoint");
                let clients = tokio::spawn(
                    Arc::clone(&controller)
                        .serve_clients(Listener::bind(&endpoint).expect("binds the endpoint")),
                );
                let rendezvous = tokio::spawn(
                    Arc::clone(&controller).serve_rendezvous(
                        Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
                            .expect("binds the rendezvous"),
                    ),
                );
                (controller, endpoint, clients, rendezvous)
            });
            ready_sender.send(started).expect("the test is waiting");
            // Until the test lets go, and then the runtime goes with every task it holds.
            let _ = stopped.recv();
            drop(runtime);
        }
    });
    let (controller, endpoint, clients, rendezvous) = ready.recv().expect("the daemon started");
    (
        Host {
            _temp: temp,
            controller,
            environment_id,
            endpoint,
            clients,
            _rendezvous: Some(rendezvous),
            work: tempfile::TempDir::new().expect("a working directory on the internal disk"),
        },
        Apart {
            stop: Some(stop),
            thread: Some(thread),
        },
    )
}

/// Ends the daemon that runs apart and starts another on the same tree, as a restart does: the
/// workers it started go on running, and the new daemon finds them.
async fn restarted(host: Host, apart: Apart) -> Host {
    let Host {
        _temp, controller, ..
    } = host;
    drop(controller);
    apart.end();
    working_host_on(_temp, |supervisor| supervisor).await
}

/// Starts a daemon on an environment and on `clocks`, waiting out one that is still letting go of
/// the environment ([`kr_controller::testing::taken_over`]).
async fn start_daemon(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    clocks: Clocks,
) -> kr_controller::error::Result<Arc<Controller>> {
    start_daemon_with(
        environment,
        environment_id,
        clocks,
        Box::new(RefusingSupervisor),
        PathBuf::from("/nonexistent/kr-worker"),
    )
    .await
}

/// Starts a daemon on an environment, on `clocks`, launching workers through `supervisor`.
async fn start_daemon_with(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    clocks: Clocks,
    supervisor: Box<dyn WorkerSupervisor>,
    worker_program: PathBuf,
) -> kr_controller::error::Result<Arc<Controller>> {
    let supervisor = std::sync::Mutex::new(Some(supervisor));
    kr_controller::testing::taken_over(|| {
        let secrets = environment.secrets_dir();
        kr_controller::testing::with_git_read_bound(
            kr_controller::testing::HUNG_GIT_READ,
            Controller::start_on_clocks(
                ControllerSetup {
                    paths: environment.clone(),
                    environment_id,
                    identity: Box::new(move || {
                        let store = open_store_in(&secrets)
                            .expect("a secret store for the test environment");
                        Ok(
                            ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                                .expect("an identity"),
                        )
                    }),
                    secret_store: StoreSelection::File,
                    boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                    supervisor: supervisor
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                        .unwrap_or_else(|| Box::new(RefusingSupervisor)),
                    worker_program: worker_program.clone(),
                    build_id: build(),
                    release: "0".to_owned(),
                    shell_packages: None,
                    terminal: Box::new(kr_controller::supervision::NoTerminal),
                },
                clocks.clone(),
            ),
        )
    })
    .await
}

async fn client(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint")
}

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

fn failure(outcome: std::result::Result<ParamsValue, ProtocolError>) -> ProtocolError {
    outcome.expect_err("this call is refused")
}

/// Runs installed Git directly, to build a repository for the daemon to find.
fn git_raw<I: IntoIterator<Item = S>, S: AsRef<std::ffi::OsStr>>(directory: &Path, arguments: I) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .arg("-c")
        .arg("user.name=KalaReach Fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("LC_ALL", "C")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "the fixture could not be built: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A repository with one commit and one later edit.
fn repository(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir_all(&path).expect("a directory for the repository");
    git_raw(&path, ["init", "--initial-branch=main"]);
    std::fs::write(path.join("README.md"), "a repository\n").expect("a tracked file");
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "the first commit"]);
    std::fs::write(path.join("README.md"), "changed after the commit\n").expect("a dirty file");
    path
}

fn include_everything() -> InclusionPolicy {
    InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    }
}

fn workflow_id(value: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([value; 16]))
}

fn grant_id(value: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([value; 16]))
}

/// A one-node definition, with the node the caller gave it.
fn definition(
    id: WorkflowId,
    grant: GrantId,
    name: &str,
    node: WorkflowNode,
) -> WorkflowDefinition {
    WorkflowDefinition {
        workflow_id: id,
        revision: U64::new(1),
        name: name.to_owned(),
        description: Nullable::null(),
        trigger: WorkflowTrigger {
            event_type: "manual".to_owned(),
        },
        resource_scope: WorkflowResourceScope::default(),
        nodes: vec![node],
        edges: Vec::new(),
        deadlines: WorkflowDeadlines::default(),
        grant_reference: grant,
        enabled: false,
        explicit_recurrence: false,
    }
}

/// The complete parameters of a test node: a suite, and the version its result binds to.
fn tests_params() -> String {
    serde_json::to_string(&kr_protocol::automation::RunTestsParams {
        suite: "unit".to_owned(),
        version: kr_protocol::changeset::VersionRef {
            change_set_id: kr_protocol::ids::ChangeSetId::new(Uuid::from_bytes([0x5d; 16])),
            version: kr_protocol::ids::ChangeSetVersion::new(1),
        },
    })
    .expect("a test node's typed parameters")
}

/// The parameters of a capture node: the change-set method's own typed parameters.
fn capture_node(workspace_id: WorkspaceId) -> WorkflowNode {
    let params = ChangesetCaptureParams {
        workspace_id,
        change_set_id: Nullable::null(),
        label: "the workflow's reading".to_owned(),
        policy: include_everything(),
        grant: FileGrant::default(),
        quiescence_declared: false,
        required_consistency: Nullable::null(),
        pin: false,
        session_id: Nullable::null(),
        workflow_run_id: Nullable::null(),
        note: "captured by an automation run".to_owned(),
    };
    WorkflowNode {
        node_id: "capture".to_owned(),
        action_kind: WorkflowActionKind::CaptureChangeset,
        action_params: serde_json::to_string(&params).expect("the node's typed parameters"),
        declared_environment: Nullable::null(),
    }
}

async fn install(
    control: &mut LocalClient,
    host: &Host,
    document: &WorkflowDefinition,
) -> WorkflowInstallResult {
    typed(
        &control
            .mutate(
                Method::WorkflowInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowInstallParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    definition: document.clone(),
                    grant_reference: document.grant_reference,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.install succeeds"),
    )
}

async fn enable(
    control: &mut LocalClient,
    host: &Host,
    document: &WorkflowDefinition,
) -> WorkflowEnableResult {
    typed(
        &control
            .mutate(
                Method::WorkflowEnable,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowEnableParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.enable succeeds"),
    )
}

async fn start(
    control: &mut LocalClient,
    host: &Host,
    document: &WorkflowDefinition,
    event_id: &str,
) -> std::result::Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            Method::WorkflowRun,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &WorkflowRunParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                event_id: event_id.to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
}

/// KR-REQ-23.52, KR-REQ-18.04 and KR-REQ-25.19: the five methods reach the service through the
/// daemon's own admission path, the run carries out a real host action, and the version it
/// produces names the run that asked for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automation_run_captures_a_change_set_and_the_version_names_the_run() {
    let host = host().await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    an_automation_run_captures_a_change_set_in(&mut control, &host, workspace).await;
    host.clients.abort();
}

/// Adopts a repository with an edit in it, built under `work`, and returns the workspace over it.
async fn adopted_workspace(
    control: &mut LocalClient,
    environment_id: EnvironmentId,
    work: &Path,
) -> WorkspaceId {
    let _source = repository(work, "source");

    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &ProjectAdoptParams {
                    destination: DestinationRequest {
                        environment_id,
                        parent: DestinationParent::Host {
                            path: work.display().to_string(),
                        },
                        name: "source".to_owned(),
                    },
                    label: "source".to_owned(),
                    flow: AdoptionFlow::ExistingCheckout,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.adopt succeeds"),
    );
    let created: WorkspaceCreateResult = typed(
        &control
            .mutate(
                Method::WorkspaceCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &WorkspaceCreateParams {
                    project_repository_id: adopted.project.project_repository_id,
                    label: "the user's own tree".to_owned(),
                    kind: WorkspaceKind::SharedExisting,
                    isolation: Nullable::null(),
                    policy: include_everything(),
                    base_revision: Nullable::null(),
                    base_change_set_id: Nullable::null(),
                    destination: Nullable::null(),
                    preview_only: false,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workspace.create succeeds"),
    );
    created
        .workspace
        .0
        .expect("a creation returns the workspace")
        .workspace_id
}

async fn an_automation_run_captures_a_change_set_in(
    control: &mut LocalClient,
    host: &Host,
    workspace: WorkspaceId,
) {
    host.issue(grant_id(1), &[ActionRight::ChangesetCreate]);
    let document = definition(
        workflow_id(1),
        grant_id(1),
        "capture-on-trigger",
        capture_node(workspace),
    );

    let installed = install(control, host, &document).await;
    assert_eq!(installed.revision.get(), 1);

    // A revision installs disabled, whatever the document said, because enabling is its own
    // authorised method.
    let refused = failure(start(control, host, &document, "evt-before-enable").await);
    assert_eq!(refused.code, ErrorCode::PluginDisabled, "{refused:?}");

    let enabled = enable(control, host, &document).await;
    assert!(enabled.enabled);

    let run: WorkflowRunResult = typed(
        &start(control, host, &document, "evt-1")
            .await
            .expect("workflow.run succeeds"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    assert_eq!(run.depth.get(), 1, "an external trigger starts a chain");

    // The same event again is one trigger arriving twice, and it produces no second run.
    let repeat = failure(start(control, host, &document, "evt-1").await);
    assert_eq!(repeat.code, ErrorCode::IdConflict, "{repeat:?}");

    // `workflow.read` answers about the revision it was asked about, with the run and its receipt.
    let read: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::some(run.run_id),
                    causal_root_id: Nullable::some(run.causal_root_id),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    assert_eq!(read.definitions.len(), 1);
    assert_eq!(read.runs.len(), 1, "one trigger, one run");
    assert_eq!(read.node_receipts.len(), 1);
    assert_eq!(read.node_receipts[0].status, NodeStatus::Success);
    assert!(
        read.remaining_causal_budget.0.is_some(),
        "the chain this run belongs to has a budget"
    );

    // The capture really happened, and the version it produced names the run that asked for it.
    let captured = read.node_receipts[0]
        .output
        .0
        .as_ref()
        .expect("the receipt carries what the action produced");
    assert_eq!(
        captured.action_kind(),
        WorkflowActionKind::CaptureChangeset,
        "{captured:?}"
    );

    let change_sets: ChangesetReadResult = typed(
        &control
            .request(
                Method::ChangesetRead,
                &ChangesetReadParams {
                    change_set_id: first_change_set(captured),
                    version: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.read succeeds"),
    );
    assert_eq!(
        change_sets.version.provenance.workflow_run_id.0,
        Some(run.run_id),
        "the version records the run that captured it"
    );
    assert_eq!(change_sets.version.provenance.method, "changeset.capture");
    // The workflow asked for a reservation and was refused one, so the version says it was read
    // file by file from a live tree and claims no quiesced or point-in-time tree.
    assert_eq!(
        change_sets.version.consistency,
        kr_protocol::changeset::SourceConsistency::PerFileCapture
    );
    assert!(
        change_sets
            .version
            .consistency_detail
            .contains("could not be reserved"),
        "{}",
        change_sets.version.consistency_detail
    );

    // A second workflow materialises the exact version the first one captured. Its node's
    // parameters are `changeset.materialize`'s own, so what installs is what runs.
    host.issue(grant_id(10), &[ActionRight::WorkspaceManage]);
    let materialise_params = kr_protocol::changeset::ChangesetMaterializeParams {
        change_set_id: change_sets.version.change_set_id,
        version: change_sets.version.version,
        purpose: kr_protocol::changeset::MaterialisationPurpose::Test,
        label: "the run's own copy".to_owned(),
    };
    let materialise_document = definition(
        workflow_id(10),
        grant_id(10),
        "materialise-for-tests",
        WorkflowNode {
            node_id: "materialise".to_owned(),
            action_kind: WorkflowActionKind::MaterializeChangeset,
            action_params: serde_json::to_string(&materialise_params)
                .expect("the node's typed parameters"),
            declared_environment: Nullable::null(),
        },
    );
    install(control, host, &materialise_document).await;
    enable(control, host, &materialise_document).await;
    let materialised: WorkflowRunResult = typed(
        &start(control, host, &materialise_document, "evt-materialise")
            .await
            .expect("the materialisation run succeeds"),
    );
    assert_eq!(
        materialised.status,
        WorkflowRunStatus::Completed,
        "{materialised:?}"
    );

    // A definition scoped to another workspace cannot read this one's work through a version
    // identifier. The version names the workspace it was captured from, and the host compares the
    // two where the effect would begin: the run pauses and nothing is materialised.
    host.issue(grant_id(11), &[ActionRight::WorkspaceManage]);
    let mut elsewhere = definition(
        workflow_id(11),
        grant_id(11),
        "materialise-from-elsewhere",
        WorkflowNode {
            node_id: "materialise".to_owned(),
            action_kind: WorkflowActionKind::MaterializeChangeset,
            action_params: serde_json::to_string(&materialise_params)
                .expect("the node's typed parameters"),
            declared_environment: Nullable::null(),
        },
    );
    elsewhere.resource_scope = WorkflowResourceScope {
        workspace_id: Nullable::some(WorkspaceId::new(Uuid::from_bytes([0x5c; 16]))),
        ..WorkflowResourceScope::default()
    };
    install(control, host, &elsewhere).await;
    enable(control, host, &elsewhere).await;
    let refused = failure(start(control, host, &elsewhere, "evt-elsewhere").await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("workspace"), "{refused:?}");
    let read_elsewhere: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(elsewhere.workflow_id),
                    revision: Nullable::some(elsewhere.revision),
                    run_id: Nullable::null(),
                    causal_root_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    assert_eq!(read_elsewhere.runs[0].status, WorkflowRunStatus::Paused);

    // `workflow.pause` stops the revision, and a later trigger is refused for that reason.
    let paused: WorkflowPauseResult = typed(
        &control
            .mutate(
                Method::WorkflowPause,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowPauseParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    reason: Nullable::some("the person stopped it".to_owned()),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.pause succeeds"),
    );
    assert!(paused.paused);
    let after_pause = failure(start(control, host, &document, "evt-2").await);
    assert_eq!(
        after_pause.code,
        ErrorCode::PluginDisabled,
        "{after_pause:?}"
    );
}

/// Reads the change-set identifier out of what the capture node produced.
fn first_change_set(output: &kr_protocol::automation::NodeOutput) -> kr_protocol::ids::ChangeSetId {
    match output {
        kr_protocol::automation::NodeOutput::CaptureChangeset { version } => version.change_set_id,
        other => panic!("a capture produces a captured version, not {other:?}"),
    }
}

/// KR-REQ-19.04: the grant a definition names is this host's, and a revoked one runs nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_grant_runs_no_workflow() {
    let host = host().await;
    let mut control = client(&host).await;

    host.issue(grant_id(2), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(2),
        grant_id(2),
        "tests-on-completion",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    host.controller
        .sharing()
        .grants()
        .revoke(grant_id(2), 2_000, || Ok(()))
        .expect("the grant is withdrawn");

    let refused = failure(start(&mut control, &host, &document, "evt-1").await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("revoked"), "{refused:?}");

    host.clients.abort();
}

/// The complete parameters of a review node: the reviewer, the version it reads and what it is
/// asked.
fn review_params() -> String {
    serde_json::to_string(&kr_protocol::automation::RequestReviewParams {
        reviewer_id: kr_protocol::ids::PluginId::new("kalareach/reviewer").expect("a plugin"),
        version: kr_protocol::changeset::VersionRef {
            change_set_id: kr_protocol::ids::ChangeSetId::new(Uuid::from_bytes([0x5d; 16])),
            version: kr_protocol::ids::ChangeSetVersion::new(1),
        },
        workspace: WorkspaceKind::Isolated,
        instructions: kr_protocol::agent::PromptText::new("review this").expect("a prompt"),
    })
    .expect("a review node's typed parameters")
}

/// A node whose kind this host cannot carry out fails. It never reports success for work nobody
/// did, and it never reports an outcome nobody can establish either: nothing was dispatched, and
/// nothing was made on the way to refusing it, no session and no materialisation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_this_host_cannot_carry_out_fails_rather_than_succeeding() {
    let host = host().await;
    let mut control = client(&host).await;

    host.issue(
        grant_id(3),
        &[ActionRight::AgentPrompt, ActionRight::SessionView],
    );
    let document = definition(
        workflow_id(3),
        grant_id(3),
        "review-on-completion",
        WorkflowNode {
            node_id: "review".to_owned(),
            action_kind: WorkflowActionKind::RequestReview,
            action_params: review_params(),
            declared_environment: Nullable::null(),
        },
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-1")
            .await
            .expect("the run is admitted"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Failed, "{run:?}");

    let read: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::some(run.run_id),
                    causal_root_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    assert_eq!(read.node_receipts[0].status, NodeStatus::Failed);
    assert!(
        read.node_receipts[0].output.0.is_none(),
        "a refused dispatch produced no output"
    );

    host.clients.abort();
}

/// A replayed mutation is answered from what the first attempt came to, not performed again.
///
/// Section 23 gives these four methods `ACTION` idempotency. Without a record of what an action
/// identifier already did, a replayed enable would undo a pause decided after it, and a replayed
/// run would be a second run under a different event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_mutation_is_answered_from_its_record() {
    let host = host().await;
    let mut control = client(&host).await;

    host.issue(grant_id(4), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(4),
        grant_id(4),
        "replayed",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    install(&mut control, &host, &document).await;

    // One enable, submitted twice under one action identifier, with a pause in between.
    let enable_action = ActionId::new(kr_ipc::new_uuid());
    let enable_params = WorkflowEnableParams {
        workflow_id: document.workflow_id,
        revision: document.revision,
    };
    let first: WorkflowEnableResult = typed(
        &control
            .mutate(
                Method::WorkflowEnable,
                enable_action,
                ActionTarget::environment(host.environment_id),
                &enable_params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.enable succeeds"),
    );
    assert!(first.enabled);

    control
        .mutate(
            Method::WorkflowPause,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &WorkflowPauseParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                reason: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("workflow.pause succeeds");

    // The replay returns the first result and changes nothing: the revision stays paused.
    let replayed: WorkflowEnableResult = typed(
        &control
            .mutate(
                Method::WorkflowEnable,
                enable_action,
                ActionTarget::environment(host.environment_id),
                &enable_params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the replay is answered from its record"),
    );
    assert_eq!(replayed, first);
    let refused = failure(start(&mut control, &host, &document, "evt-1").await);
    assert_eq!(
        refused.code,
        ErrorCode::PluginDisabled,
        "a replayed enable did not undo the pause: {refused:?}"
    );

    // The same identifier carrying something else is a reused identifier, not a repeat.
    let reused = failure(
        control
            .mutate(
                Method::WorkflowEnable,
                enable_action,
                ActionTarget::environment(host.environment_id),
                &WorkflowEnableParams {
                    workflow_id: document.workflow_id,
                    revision: U64::new(2),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(reused.code, ErrorCode::IdConflict, "{reused:?}");

    host.clients.abort();
}

/// A caller that lost its reply and asks again over a new connection is answered from the record.
///
/// The retry is the original mutation, window and all, and the new connection holds a newer
/// window. The record is read before any freshness is considered, so the caller gets its own
/// result, and the run is not started a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_over_a_new_connection_is_answered_from_its_record() {
    let host = host().await;
    let mut control = client(&host).await;

    host.issue(grant_id(5), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(5),
        grant_id(5),
        "asked twice",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let original = control
        .compose(
            Method::WorkflowRun,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &WorkflowRunParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                event_id: "evt-once".to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
            },
        )
        .await
        .expect("the mutation is composed");
    let first: WorkflowRunResult = typed(
        &control
            .repeat(&original)
            .await
            .expect("the call reaches the daemon")
            .expect("the run is admitted"),
    );
    drop(control);

    let mut again = client(&host).await;
    let answered: WorkflowRunResult = typed(
        &again
            .repeat(&original)
            .await
            .expect("the call reaches the daemon")
            .expect("the repeat is answered from its record"),
    );
    assert_eq!(answered.run_id, first.run_id, "one action, one run");
    assert_eq!(answered.status, first.status);

    let read: WorkflowReadResult = typed(
        &again
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::null(),
                    causal_root_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    assert_eq!(read.runs.len(), 1, "the repeat started nothing");

    host.clients.abort();
}

/// A grant stands only as this host's policy leaves it. One that claims an authority revision this
/// host never issued is refused before anything is installed, although its own record says active.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_the_host_policy_refuses_installs_no_workflow() {
    let host = host().await;
    let mut control = client(&host).await;

    let mut grant = host.issue(grant_id(6), &COMMAND_RIGHTS);
    grant.authority_revision = AuthorityRevision::new(1_000_000);
    let unissued = grant_id(7);
    host.controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: Grant {
                    grant_id: unissued,
                    ..grant
                },
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");
    let document = definition(
        workflow_id(6),
        unissued,
        "under a revision nobody issued",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    let refused = failure(
        control
            .mutate(
                Method::WorkflowInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowInstallParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    definition: document.clone(),
                    grant_reference: document.grant_reference,
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("revision"), "{refused:?}");

    host.clients.abort();
}

/// Reads the runs of one workflow until one appears, and fails when none has within ten seconds.
///
/// One deadline covers the whole wait, each read included, so a daemon that takes a request and
/// never answers ends the wait at the deadline too.
async fn first_run_of(
    control: &mut LocalClient,
    document: &WorkflowDefinition,
) -> kr_protocol::automation::WorkflowRunSummary {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let appeared = tokio::time::timeout_at(deadline, async {
        loop {
            let read: WorkflowReadResult = typed(
                &control
                    .request(
                        Method::WorkflowRead,
                        &WorkflowReadParams {
                            workflow_id: Nullable::some(document.workflow_id),
                            revision: Nullable::some(document.revision),
                            run_id: Nullable::null(),
                            causal_root_id: Nullable::null(),
                        },
                    )
                    .await
                    .expect("the call reaches the daemon")
                    .expect("workflow.read succeeds"),
            );
            if let Some(run) = read.runs.into_iter().next() {
                return run;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    appeared.unwrap_or_else(|_| {
        panic!(
            "the daemon started no run of workflow {} within ten seconds",
            document.workflow_id
        )
    })
}

/// KR-REQ-25.15: a workflow triggered by another's node descends from that node, and the daemon,
/// not the caller, says so.
///
/// The capture succeeds and commits the event its action kind fixes. The daemon's dispatcher reads
/// it and starts the workflow whose trigger names that event, with the chain's root, one more level
/// of depth and the capture node as its parent, all taken from the journal's own record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_triggered_workflow_descends_from_the_node_that_triggered_it() {
    let host = host().await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;

    host.issue(grant_id(8), &[ActionRight::ChangesetCreate]);
    let capturing = definition(
        workflow_id(8),
        grant_id(8),
        "capture-on-demand",
        capture_node(workspace),
    );
    host.issue(grant_id(9), &COMMAND_RIGHTS);
    let mut tests = definition(
        workflow_id(9),
        grant_id(9),
        "tests-after-capture",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    tests.trigger = WorkflowTrigger {
        event_type: "changeset.captured".to_owned(),
    };
    for document in [&capturing, &tests] {
        install(&mut control, &host, document).await;
        enable(&mut control, &host, document).await;
    }

    let captured: WorkflowRunResult = typed(
        &start(&mut control, &host, &capturing, "evt-capture")
            .await
            .expect("the capture runs"),
    );
    assert_eq!(
        captured.status,
        WorkflowRunStatus::Completed,
        "{captured:?}"
    );

    let descendant = first_run_of(&mut control, &tests).await;
    assert_eq!(descendant.causal_root_id, captured.causal_root_id);
    assert_eq!(descendant.depth.get(), 2);
    assert_eq!(descendant.parent_run_id.0, Some(captured.run_id));
    assert_eq!(descendant.parent_node_id.0.as_deref(), Some("capture"));

    host.clients.abort();
}

/// A materialisation is performed only for a version whose scope was checked. One that cannot be
/// read, a version that does not exist yet among them, is refused where the effect would begin,
/// because it could be captured from anywhere before the materialisation read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_materialisation_whose_version_cannot_be_checked_is_refused() {
    let host = host().await;
    let mut control = client(&host).await;

    host.issue(grant_id(12), &[ActionRight::WorkspaceManage]);
    let unchecked = kr_protocol::changeset::ChangesetMaterializeParams {
        change_set_id: kr_protocol::ids::ChangeSetId::new(Uuid::from_bytes([0x6d; 16])),
        version: kr_protocol::ids::ChangeSetVersion::new(1),
        purpose: kr_protocol::changeset::MaterialisationPurpose::Test,
        label: "a version nobody captured".to_owned(),
    };
    let document = definition(
        workflow_id(12),
        grant_id(12),
        "materialise-the-unknown",
        WorkflowNode {
            node_id: "materialise".to_owned(),
            action_kind: WorkflowActionKind::MaterializeChangeset,
            action_params: serde_json::to_string(&unchecked).expect("typed parameters"),
            declared_environment: Nullable::null(),
        },
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;
    let refused = failure(start(&mut control, &host, &document, "evt-unknown").await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("could not be checked"),
        "{refused:?}"
    );

    host.clients.abort();
}

/// The clock floor rises with automation's own decisions. A workflow runs unattended, so nothing
/// else may advance the floor between two of its dispatches, and a clock wound back after a grant
/// was refused as expired must not make it stand again.
#[test]
fn a_clock_wound_back_does_not_revive_a_grant_a_dispatch_refused() {
    use kr_controller::grants::{HostPolicy, standing_at_dispatch};
    use kr_protocol::actor::ActorIngress;

    let environment_id = EnvironmentId::new(Uuid::from_bytes([0x3e; 16]));
    let device_id = kr_protocol::ids::DeviceId::new(Uuid::from_bytes([0x3f; 16]));
    let record = GrantRecord {
        grant: Grant {
            grant_id: grant_id(13),
            parent_grant_id: Nullable::null(),
            issuer_device_id: device_id,
            recipient_device_id: device_id,
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: COMMAND_RIGHTS.into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::At {
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(200),
            },
            organisation: Nullable::null(),
        },
        session_id: None,
        issued_at_ms: 100,
        activated_at_ms: Some(100),
        revoked_at_ms: None,
        revoked_by_parent: None,
    };
    let mut policy = HostPolicy::personal(AuthorityRevision::new(1));

    standing_at_dispatch(
        &record,
        &mut policy,
        environment_id,
        ActorIngress::LocalIpc,
        150,
        kr_transport::clock::ContinuousClock::now(&kr_transport::clock::ManualClock::new()),
    )
    .expect("the grant stands before it expires");
    standing_at_dispatch(
        &record,
        &mut policy,
        environment_id,
        ActorIngress::LocalIpc,
        201,
        kr_transport::clock::ContinuousClock::now(&kr_transport::clock::ManualClock::new()),
    )
    .expect_err("the grant has expired");
    assert_eq!(policy.utc_floor_ms(), 201, "the refusal raised the floor");
    standing_at_dispatch(
        &record,
        &mut policy,
        environment_id,
        ActorIngress::LocalIpc,
        199,
        kr_transport::clock::ContinuousClock::now(&kr_transport::clock::ManualClock::new()),
    )
    .expect_err("a clock wound back does not revive it");
}

/// A decision stands on the clock floor in memory, so a floor that could not be written down stops
/// every dispatch until it is: on the next decision too, however many come in between and whatever
/// the clock reads meanwhile. A decision taken on it instead would be one a restart could revive,
/// because the floor on disk would still be the old one.
#[tokio::test(flavor = "multi_thread")]
async fn a_clock_floor_that_could_not_be_written_down_stays_owed_until_it_is() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;

    let host = host().await;
    let now = kr_ipc::now_ms().get();
    let expires = now + 3_600_000;
    let device_id = kr_protocol::ids::DeviceId::new(host.environment_id.get());
    let grant = Grant {
        grant_id: grant_id(15),
        parent_grant_id: Nullable::null(),
        issuer_device_id: device_id,
        recipient_device_id: device_id,
        authority_revision: host.controller.policy().authority_revision(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::AutomationManage].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(expires),
        },
        organisation: Nullable::null(),
    };
    host.controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: grant.clone(),
                session_id: None,
                issued_at_ms: now,
                activated_at_ms: Some(now),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");
    let grants = HostGrants::for_daemon(&host.controller);
    grants
        .grant(grant.grant_id, now)
        .expect("the grant stands before it expires");

    // From here every write of the host's policy fails, as it would on a full disk.
    let registry = rusqlite::Connection::open(host._temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    for reading in [expires + 1, expires + 1, expires - 1, now] {
        let error = grants
            .grant(grant.grant_id, reading)
            .expect_err("nothing is decided on a floor that is not written down");
        assert!(
            matches!(error, AutomationError::AuthorityUnavailable(_)),
            "at {reading}: {error}"
        );
    }

    // Once the floor can be written down, the refusal stands, and it stands on disk.
    registry
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the fault is cleared");
    let error = grants
        .grant(grant.grant_id, expires - 1)
        .expect_err("the grant expired at the floor this host decided from");
    assert!(
        matches!(error, AutomationError::PermissionDenied(_)),
        "{error}"
    );
    let stored = host
        .controller
        .sharing()
        .grants()
        .stored_policy()
        .expect("reads the policy")
        .expect("the host has a policy");
    assert!(stored.utc_floor_ms.get() > expires, "{stored:?}");
}

/// An admission that always stands, for work written to a journal outside any daemon.
fn standing() -> kr_automation::Result<()> {
    Ok(())
}

/// Leaves one settled node's event in an environment's workflow journal with nothing dispatched
/// for it yet, as a daemon that stopped between the two would. Returns the event's position.
async fn trigger_left_pending(state_dir: &Path, environment_id: EnvironmentId) -> u64 {
    std::fs::create_dir_all(state_dir).expect("the state directory");
    let grant = grant_id(17);
    let device_id = kr_protocol::ids::DeviceId::new(environment_id.get());
    let table = kr_automation::GrantTable::new();
    table.insert(Grant {
        grant_id: grant,
        parent_grant_id: Nullable::null(),
        issuer_device_id: device_id,
        recipient_device_id: device_id,
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: ActionRight::ALL.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    });
    let service = kr_automation::AutomationService::open(
        state_dir,
        kr_automation::Host {
            environment_id,
            runner: Arc::new(kr_automation::MockActionRunner::new()),
            authority: Arc::new(table),
            clock: Arc::new(kr_automation::SystemClock),
            ceilings: Arc::new(kr_automation::FixedCeilings {
                sessions: 128,
                managed_spend: 0,
            }),
        },
    )
    .expect("the journal opens");
    let document = definition(
        workflow_id(41),
        grant,
        "producer",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    let key = |method: Method| kr_automation::ActionKey {
        actor_id: "local:test".to_owned(),
        action_id: kr_ipc::new_uuid().to_string(),
        method: method.as_str().to_owned(),
        digest: kr_ipc::new_uuid().as_bytes().to_vec(),
    };
    let submitted = |key| kr_automation::Submitted {
        key,
        admission: &standing,
        caller_grant: None,
    };
    let now = kr_ipc::now_ms().get();
    let installing = key(Method::WorkflowInstall);
    service
        .install(
            &WorkflowInstallParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                definition: document.clone(),
                grant_reference: grant,
            },
            &submitted(&installing),
            now,
        )
        .expect("installs");
    let enabling = key(Method::WorkflowEnable);
    service
        .enable(
            &WorkflowEnableParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
            },
            &submitted(&enabling),
            now,
        )
        .expect("enables");
    let running = key(Method::WorkflowRun);
    service
        .run(
            &WorkflowRunParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                event_id: "evt-left".to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
            },
            &submitted(&running),
            now,
        )
        .await
        .expect("the run completes");
    service
        .store()
        .events_after(0, &[kr_automation::store::EVENT_NODE_SETTLED], 16)
        .expect("the journal's events")
        .last()
        .expect("the settled node's event")
        .sequence
}

/// Where the trigger dispatcher of an environment's journal has read to.
fn dispatched_to(journal: &kr_automation::WorkflowStore) -> Option<u64> {
    journal
        .consumer_position(kr_automation::TRIGGER_CONSUMER)
        .expect("the journal reads")
}

/// Opening the automation module recovers its journal and executes nothing: only starting it
/// does. A trigger a stopped daemon left pending is dispatched once the module is started, and
/// not while it is only open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_automation_module_dispatches_nothing_until_it_is_started() {
    let host = host().await;
    let elsewhere = kr_ipc::testing::TempHost::create();
    let paths = elsewhere.environment();
    let pending = trigger_left_pending(paths.state_dir(), host.environment_id).await;

    let module = kr_controller::automation::AutomationModule::open(
        &paths,
        host.environment_id,
        Arc::clone(host.controller.changesets().service()),
    )
    .await
    .expect("the module opens");
    module.bind(Arc::downgrade(&host.controller));
    // Longer than the dispatcher's own interval: a module that dispatched on opening would have
    // read past the pending event by now.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    assert_eq!(
        dispatched_to(module.journal()),
        None,
        "an open module dispatches nothing"
    );
    assert_eq!(
        module.dispatch_passes(),
        0,
        "an open module makes no pass over the journal"
    );

    module.start();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    // The pass counts when it ends, which is after it has read the event, so both are waited for.
    while dispatched_to(module.journal()).is_none_or(|position| position < pending)
        || module.dispatch_passes() == 0
    {
        assert!(
            std::time::Instant::now() < deadline,
            "a started module dispatches the trigger a stopped daemon left"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    drop(module);
    host.clients.abort();
}

/// Writes one configuration document where this host reads it.
fn write_configuration(
    environment: &kr_ipc::paths::EnvironmentPaths,
    document: &kr_protocol::hostinfo::configuration::ConfigurationDocument,
) {
    let path = kr_worker::config::document_path(environment);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the state directory");
    }
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(document).as_bytes(),
    )
    .expect("the document");
}

/// A configuration document that narrows the rights a grant may carry to `rights`, which withdraws
/// authority and owes a fence.
fn narrowing_document(
    rights: &[ActionRight],
) -> kr_protocol::hostinfo::configuration::ConfigurationDocument {
    let mut narrowed = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    narrowed.revision = 1;
    narrowed.ceilings.grant_rights = Nullable::some(
        rights
            .iter()
            .map(|right| right.as_str().to_owned())
            .collect(),
    );
    narrowed
}

/// Makes this environment's registry refuse the revision advance a fence needs, as a full disk or
/// a damaged file would, until the returned connection drops the trigger.
fn refuse_fences(environment: &kr_ipc::paths::EnvironmentPaths) -> rusqlite::Connection {
    let registry =
        rusqlite::Connection::open(environment.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_fence BEFORE UPDATE OF authority_revision ON environment
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    registry
}

/// Waits until `condition` holds, and fails when it does not within a liveness bound: what the
/// wait measures is whether the condition is ever met, and one that is met costs what it costs.
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "waited 60 s for {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// A start that does not pass its configuration gate executes nothing a stopped daemon left
/// behind. The document it has to put into force withdraws authority and owes a fence, the
/// registry cannot raise it, and the start fails; the trigger left pending in the journal is
/// still pending afterwards.
///
/// The first start's daemon has to be gone, its dispatcher included, before the trigger is left
/// pending. Dropping the daemon aborts the dispatcher's task, but a pass it had already handed to a
/// blocking thread goes on to its end, holding the service, and reads the journal when a loaded
/// machine gets to it: after the trigger was left pending it would dispatch it, and the failed
/// start would be blamed. The service is the dispatcher's own, so the test waits for the last
/// holder of it to let go. The failed start is then held to the same rule: it runs on a runtime of
/// its own, which is ended before it is judged, and not after a length of time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_fails_at_its_configuration_gate_dispatches_nothing() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // A first start makes the registry and the journal; then the daemon stops.
    let first = start_daemon(&environment, environment_id, Clocks::system())
        .await
        .unwrap_or_else(|error| panic!("the first start: {error}"));
    let dispatcher = Arc::downgrade(first.automation().service());
    drop(first);
    until(
        "the first daemon's dispatcher to let go of the service",
        || dispatcher.strong_count() == 0,
    )
    .await;
    let pending = trigger_left_pending(environment.state_dir(), environment_id).await;
    let registry = refuse_fences(&environment);
    write_configuration(
        &environment,
        &narrowing_document(&[ActionRight::SessionView]),
    );

    // The start runs on a runtime of its own, and the runtime is dropped before the journal is
    // read: dropping one ends every task it holds and waits for every pass it handed to a blocking
    // thread. Nothing the failed start began is left running then, whichever kind of work it was,
    // and a pass that had read the pending event is in the journal by then. What this cannot tell
    // is a dispatcher that was ended before its first read from one that was never started, so it
    // holds the start to what it can see: it is refused, and the event is still where it was left.
    let refused = {
        let environment = environment.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a runtime for the start");
            let outcome = runtime
                .block_on(async {
                    start_daemon(&environment, environment_id, Clocks::system())
                        .await
                        .map(drop)
                })
                .map_err(|error| error.to_string());
            drop(runtime);
            outcome
        })
        .join()
        .expect("the start's thread ended")
    };
    let Err(refused) = refused else {
        panic!("the start does not pass its configuration gate");
    };
    assert!(refused.contains("could not be put into force"), "{refused}");
    // The first start's dispatcher registered and read nothing; the event left since is where it
    // was left.
    let journal =
        kr_automation::WorkflowStore::open(environment.state_dir()).expect("the journal opens");
    let position = dispatched_to(&journal);
    assert!(
        position.is_none_or(|position| position < pending),
        "nothing was dispatched, so the event at {pending} is still pending: {position:?}"
    );
    registry
        .execute_batch("DROP TRIGGER refuse_fence;")
        .expect("the fault is cleared");
}

/// A withdrawal whose fence could not be raised stops a workflow mutation that was admitted just
/// before it. The install passes the daemon's first check, waits for the journal, and meanwhile
/// the registry refuses the fence a narrowed configuration owes; asked again inside the journal's
/// transaction, the admission refuses, and nothing is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_owed_after_admission_stops_the_workflow_write() {
    let host = host().await;
    let environment = host._temp.environment();
    // Everything the workflow needs, and everything the narrowed configuration below still allows,
    // so the fence is the only thing that can refuse it.
    let needed = [ActionRight::AutomationManage, ActionRight::TerminalInput];
    let grant = host.issue(grant_id(18), &needed);
    let document = definition(
        workflow_id(42),
        grant.grant_id,
        "admitted before the fence",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    let mut control = client(&host).await;

    // Another writer holds the workflow journal's write lock. Reads go on, so the install is
    // answered no retained record, passes the daemon's first check, and waits for the journal's
    // transaction.
    let journal = rusqlite::Connection::open(
        environment
            .state_dir()
            .join(kr_automation::store::WORKFLOW_DB_NAME),
    )
    .expect("opens the journal");
    journal
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the journal");
    let installing = document.clone();
    let environment_id = host.environment_id;
    let pending = tokio::spawn(async move {
        control
            .mutate(
                Method::WorkflowInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &WorkflowInstallParams {
                    workflow_id: installing.workflow_id,
                    revision: installing.revision,
                    definition: installing.clone(),
                    grant_reference: installing.grant_reference,
                },
            )
            .await
            .expect("the call reaches the daemon")
    });
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // The configuration narrows the grants' rights, and the fence that owes cannot be raised.
    let registry = refuse_fences(&environment);
    write_configuration(&environment, &narrowing_document(&needed));
    let effective = host.controller.effective_configuration().await;
    assert!(
        effective
            .not_in_force
            .as_ref()
            .is_some_and(|problem| problem.as_str().contains("dispatch could not be fenced")),
        "{:?}",
        effective.not_in_force
    );

    journal
        .execute_batch("COMMIT")
        .expect("the other writer finishes");
    let refusal = pending
        .await
        .expect("the install answers")
        .expect_err("the fence stops the install");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    assert!(
        refusal.message.contains("could not be raised"),
        "{refusal:?}"
    );
    assert!(
        host.controller
            .automation()
            .service()
            .store()
            .list_definitions(None)
            .expect("the journal reads")
            .is_empty(),
        "nothing was installed"
    );
    registry
        .execute_batch("DROP TRIGGER refuse_fence;")
        .expect("the fault is cleared");
    host.clients.abort();
}

mod net_support;

/// Runs one automation mutation as a paired device and returns what the daemon answered.
async fn device_mutation<P: serde::Serialize + ?Sized>(
    session: &kr_client::session::Session,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> std::result::Result<ParamsValue, ProtocolError> {
    match session
        .mutate(
            method,
            ActionTarget::environment(environment_id),
            None,
            &ParamsValue::empty(),
            params,
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
    {
        Ok(settled) => Ok(settled
            .result()
            .cloned()
            .expect("an automation mutation answers with its result")),
        Err(kr_client::error::ClientError::Host(refusal)) => Err(refusal),
        Err(other) => panic!("the call did not reach the daemon: {other}"),
    }
}

/// KR-REQ-23.52 and KR-REQ-19.04 at the paired-device ingress.
///
/// The registry is walked for the automation group, and every ingress it lists for a method is
/// one this daemon serves: each method is called here from a paired device over the network, and
/// the owner's own socket serves all five in the tests above. A device reaches only the workflows
/// that act under the grant it holds, so a workflow cannot give it rights its grant does not carry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_automation_group_is_served_at_every_ingress_the_registry_lists() {
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::method::{MethodGroup, REGISTRY};

    let listed: Vec<_> = REGISTRY
        .iter()
        .filter(|entry| entry.method.group() == MethodGroup::Automation)
        .collect();
    assert_eq!(listed.len(), 5, "the group's five methods");
    for entry in &listed {
        for ingress in entry.ingress {
            assert!(
                matches!(ingress, ActorIngress::LocalIpc | ActorIngress::PairedDevice),
                "{} lists an ingress this daemon does not serve: {ingress:?}",
                entry.name
            );
        }
        assert!(
            entry.ingress.contains(&ActorIngress::PairedDevice),
            "{} is served to a paired device and says so",
            entry.name
        );
    }

    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[
            ActionRight::AutomationManage,
            ActionRight::TerminalInput,
            ActionRight::SessionCreate,
            ActionRight::SessionClose,
            ActionRight::WorkspaceManage,
        ]),
    )
    .await;
    let session = net_support::connect(&host, &device, &record).await;
    let own_grant = record.grant.grant_id;

    // A workflow under the device's own grant: every method answers the device.
    let document = definition(
        workflow_id(20),
        own_grant,
        "a device's own",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    let mut served = std::collections::BTreeSet::new();
    let installed: WorkflowInstallResult = typed(
        &device_mutation(
            &session,
            host.environment_id,
            Method::WorkflowInstall,
            &WorkflowInstallParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                definition: document.clone(),
                grant_reference: document.grant_reference,
            },
        )
        .await
        .expect("a device installs under its own grant"),
    );
    assert_eq!(installed.revision.get(), 1);
    served.insert(Method::WorkflowInstall);
    device_mutation(
        &session,
        host.environment_id,
        Method::WorkflowEnable,
        &WorkflowEnableParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
        },
    )
    .await
    .expect("a device enables its own workflow");
    served.insert(Method::WorkflowEnable);
    let run: WorkflowRunResult = typed(
        &device_mutation(
            &session,
            host.environment_id,
            Method::WorkflowRun,
            &WorkflowRunParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                event_id: "evt-device".to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
            },
        )
        .await
        .expect("a device runs its own workflow"),
    );
    // Nothing on this host carries out a test run, so the node fails; the run itself was served.
    assert_eq!(run.status, WorkflowRunStatus::Failed, "{run:?}");
    served.insert(Method::WorkflowRun);
    device_mutation(
        &session,
        host.environment_id,
        Method::WorkflowPause,
        &WorkflowPauseParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
            reason: Nullable::null(),
        },
    )
    .await
    .expect("a device pauses its own workflow");
    served.insert(Method::WorkflowPause);
    let read: WorkflowReadResult = session
        .read(Method::WorkflowRead, &WorkflowReadParams::default())
        .await
        .expect("a device reads its workflows");
    assert_eq!(read.definitions.len(), 1);
    assert!(read.definitions[0].paused, "the read shows the pause");
    served.insert(Method::WorkflowRead);
    assert_eq!(
        served,
        listed.iter().map(|entry| entry.method).collect(),
        "every method the registry lists for a paired device was served to one"
    );

    // A workflow under the owner's grant is not the device's: it cannot install one under that
    // grant, and it neither sees nor runs the owner's.
    let host_device = kr_protocol::ids::DeviceId::new(host.environment_id.get());
    let owners = grant_id(31);
    host.controller()
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: Grant {
                    grant_id: owners,
                    parent_grant_id: Nullable::null(),
                    issuer_device_id: host_device,
                    recipient_device_id: host_device,
                    authority_revision: host.controller().policy().authority_revision(),
                    environment_selector: EnvironmentSelector::Any,
                    session_selector: SessionSelector::Any,
                    actions: COMMAND_RIGHTS.into_iter().collect(),
                    history: HistoryScope {
                        lower_bound_ms: Nullable::null(),
                        include_live_screen: false,
                        named_questions: CanonicalSet::new(),
                        named_approvals: CanonicalSet::new(),
                    },
                    expiry: GrantExpiry::Never,
                    organisation: Nullable::null(),
                },
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the owner's grant is written");
    let borrowed = definition(
        workflow_id(21),
        owners,
        "borrowing the owner's grant",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: tests_params(),
            declared_environment: Nullable::null(),
        },
    );
    let refused = device_mutation(
        &session,
        host.environment_id,
        Method::WorkflowInstall,
        &WorkflowInstallParams {
            workflow_id: borrowed.workflow_id,
            revision: borrowed.revision,
            definition: borrowed.clone(),
            grant_reference: borrowed.grant_reference,
        },
    )
    .await
    .expect_err("a device cannot install under a grant it does not hold");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    let mut control = host.client().await;
    typed::<WorkflowInstallResult>(
        &control
            .mutate(
                Method::WorkflowInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowInstallParams {
                    workflow_id: borrowed.workflow_id,
                    revision: borrowed.revision,
                    definition: borrowed.clone(),
                    grant_reference: borrowed.grant_reference,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the owner installs under the owner's grant"),
    );
    let read: WorkflowReadResult = session
        .read(Method::WorkflowRead, &WorkflowReadParams::default())
        .await
        .expect("a device reads its workflows");
    assert_eq!(
        read.definitions.len(),
        1,
        "the owner's workflow is not the device's to see"
    );
    let refused = device_mutation(
        &session,
        host.environment_id,
        Method::WorkflowEnable,
        &WorkflowEnableParams {
            workflow_id: borrowed.workflow_id,
            revision: borrowed.revision,
        },
    )
    .await
    .expect_err("a device cannot enable the owner's workflow");
    // Answered as a revision that is not installed, naming no grant.
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(refused.message.contains("not found"), "{refused:?}");
    assert!(
        !refused.message.contains(&owners.to_string()),
        "{refused:?}"
    );

    // A revoked device's grant runs nothing, whoever asks: the pairing record is where its
    // revocation is written, and the workflow's grant is read from there before anything runs.
    host.controller()
        .devices()
        .revoke(record.device_id, kr_ipc::now_ms())
        .expect("the device is revoked");
    let enable_again = WorkflowEnableParams {
        workflow_id: document.workflow_id,
        revision: document.revision,
    };
    typed::<WorkflowEnableResult>(
        &control
            .mutate(
                Method::WorkflowEnable,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &enable_again,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the owner enables the device's workflow again"),
    );
    let refused = failure(
        control
            .mutate(
                Method::WorkflowRun,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowRunParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    event_id: "evt-after-revocation".to_owned(),
                    event_type: "manual".to_owned(),
                    event_payload: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("revoked"), "{refused:?}");

    host.stop().await;
}

/// KR-REQ-19.04 and KR-REQ-18.04 at the paired-device ingress: a workflow under a device's own
/// grant carries out the change-set node that grant allows, and the version it writes names the
/// run that asked for it. The write is held under the device's grant inside the change-set
/// service's own transaction, so the workflow reaches no further than the grant does while the
/// write prepares.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_under_a_paired_devices_grant_captures_under_that_grant() {
    let owner = kr_crypto::keys::DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::AutomationManage, ActionRight::ChangesetCreate]),
    )
    .await;
    let session = net_support::connect(&host, &device, &record).await;
    let own_grant = record.grant.grant_id;

    // The owner adopts the workspace the device's workflow reads.
    let mut control = host.client().await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;

    let document = definition(
        workflow_id(40),
        own_grant,
        "a device's capture",
        capture_node(workspace),
    );
    device_mutation(
        &session,
        host.environment_id,
        Method::WorkflowInstall,
        &WorkflowInstallParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
            definition: document.clone(),
            grant_reference: document.grant_reference,
        },
    )
    .await
    .expect("a device installs a capture under its own grant");
    device_mutation(
        &session,
        host.environment_id,
        Method::WorkflowEnable,
        &WorkflowEnableParams {
            workflow_id: document.workflow_id,
            revision: document.revision,
        },
    )
    .await
    .expect("a device enables its own workflow");
    let run: WorkflowRunResult = typed(
        &device_mutation(
            &session,
            host.environment_id,
            Method::WorkflowRun,
            &WorkflowRunParams {
                workflow_id: document.workflow_id,
                revision: document.revision,
                event_id: "evt-device-capture".to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
            },
        )
        .await
        .expect("a device runs its own capture"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");

    let read: WorkflowReadResult = session
        .read(
            Method::WorkflowRead,
            &WorkflowReadParams {
                workflow_id: Nullable::some(document.workflow_id),
                revision: Nullable::some(document.revision),
                run_id: Nullable::some(run.run_id),
                causal_root_id: Nullable::null(),
            },
        )
        .await
        .expect("a device reads its own run");
    assert_eq!(read.node_receipts.len(), 1);
    assert_eq!(read.node_receipts[0].status, NodeStatus::Success);
    let captured = read.node_receipts[0]
        .output
        .0
        .as_ref()
        .expect("the receipt carries what the capture produced");
    let version: ChangesetReadResult = typed(
        &control
            .request(
                Method::ChangesetRead,
                &ChangesetReadParams {
                    change_set_id: first_change_set(captured),
                    version: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.read succeeds"),
    );
    assert_eq!(
        version.version.provenance.workflow_run_id.0,
        Some(run.run_id),
        "the version records the device's run"
    );

    host.stop().await;
}

/// The versions the environment's change-set store holds, read from the store itself.
fn versions_in(environment: &kr_ipc::paths::EnvironmentPaths) -> i64 {
    let store = rusqlite::Connection::open(
        environment
            .state_dir()
            .join(kr_changeset::store::CHANGESETS_DIRECTORY)
            .join(kr_changeset::store::STORE_FILE_NAME),
    )
    .expect("opens the change-set store");
    store
        .query_row("SELECT COUNT(*) FROM versions", [], |row| row.get(0))
        .expect("counts the versions")
}

/// KR-REQ-19.04: a grant withdrawn while a node's change-set write waits for the change-set store
/// stops the write. The node passed every check before its effect began; the grant is asked again
/// inside the store's own transaction, under the daemon's hold, so the capture writes nothing once
/// the grant is gone, and the node pauses on the refusal rather than failing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_withdrawn_while_the_change_set_write_waits_writes_nothing() {
    let host = host().await;
    let environment = host._temp.environment();
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    host.issue(grant_id(19), &[ActionRight::ChangesetCreate]);
    let document = definition(
        workflow_id(19),
        grant_id(19),
        "a capture that waits for the store",
        capture_node(workspace),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;
    assert_eq!(versions_in(&environment), 0);

    // Another writer holds the change-set store's write lock. The run passes every check the
    // engine and the runner make, reads the working tree, and then waits for the store.
    let store = rusqlite::Connection::open(
        environment
            .state_dir()
            .join(kr_changeset::store::CHANGESETS_DIRECTORY)
            .join(kr_changeset::store::STORE_FILE_NAME),
    )
    .expect("opens the change-set store");
    store
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the store");
    let running = {
        let host_environment = host.environment_id;
        let endpoint = host.endpoint.clone();
        let document = document.clone();
        tokio::spawn(async move {
            let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects to the control endpoint");
            control
                .mutate(
                    Method::WorkflowRun,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(host_environment),
                    &WorkflowRunParams {
                        workflow_id: document.workflow_id,
                        revision: document.revision,
                        event_id: "evt-while-busy".to_owned(),
                        event_type: "manual".to_owned(),
                        event_payload: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the daemon")
        })
    };
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // The grant is withdrawn while the write waits, and then the store is free again.
    host.controller
        .sharing()
        .grants()
        .revoke(grant_id(19), kr_ipc::now_ms().get(), || Ok(()))
        .expect("the grant is withdrawn");
    store
        .execute_batch("COMMIT")
        .expect("the other writer finishes");

    let refused = running
        .await
        .expect("the run answers")
        .expect_err("the withdrawn grant stops the write");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("revoked"), "{refused:?}");
    assert_eq!(versions_in(&environment), 0, "nothing was captured");
    let read: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::null(),
                    causal_root_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    assert_eq!(read.runs.len(), 1);
    assert_eq!(read.runs[0].status, WorkflowRunStatus::Paused);

    host.clients.abort();
}

/// A device other than this host, which a grant issued to it reaches the host over the network.
fn another_device() -> kr_protocol::ids::DeviceId {
    kr_protocol::ids::DeviceId::new(Uuid::from_bytes([0x7d; 16]))
}

/// Writes a grant carrying `rights` to `recipient`, running out at `expiry`, into this daemon's
/// grant store.
fn issue_grant(
    host: &Host,
    grant_id: GrantId,
    recipient: kr_protocol::ids::DeviceId,
    rights: &[ActionRight],
    expiry: GrantExpiry,
) -> Grant {
    let issuer = kr_protocol::ids::DeviceId::new(host.environment_id.get());
    let grant = Grant {
        grant_id,
        parent_grant_id: Nullable::null(),
        issuer_device_id: issuer,
        recipient_device_id: recipient,
        authority_revision: host.controller.policy().authority_revision(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: rights.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry,
        organisation: Nullable::null(),
    };
    host.controller
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: grant.clone(),
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");
    grant
}

/// The bounded offline validity holds a workflow's grant on the continuous clock it was anchored
/// on, as it holds a device's own request. The daemon runs on clocks this test moves by hand: the
/// continuous clock runs past the bound while the wall clock is wound back, and a decision taken
/// then is refused all the same, although UTC, through the host's floor, is still inside the
/// bound. Nothing here reads the machine's clocks and nothing sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_grant_is_held_to_the_offline_bound_on_the_continuous_clock() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;
    use std::sync::atomic::{AtomicU64, Ordering};

    const T: u64 = 1_767_225_600_000;
    let continuous = kr_transport::clock::ManualClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let host = host_on(Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn({
            let wall = Arc::clone(&wall);
            move || wall.load(Ordering::SeqCst)
        }),
    })
    .await;
    host.controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(200),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(T)),
            }));
        })
        .expect("the owner chooses an offline bound of a fifth of a second");
    let grant = issue_grant(
        &host,
        grant_id(21),
        another_device(),
        &[ActionRight::ChangesetCreate],
        GrantExpiry::Never,
    );
    let grants = HostGrants::for_daemon(&host.controller);
    grants.grant(grant.grant_id, T).expect("inside the bound");
    // The bound is an end the grant stands on, and a command that starts later than the node
    // asks is held to it.
    let (_, ends_in) = grants
        .grant_standing(grant.grant_id, T)
        .expect("inside the bound");
    assert!(
        ends_in.is_some_and(|ends_in| ends_in <= std::time::Duration::from_millis(201)
            && ends_in >= std::time::Duration::from_millis(200)),
        "the bound is the end of a window of two hundred milliseconds: {ends_in:?}"
    );

    // The control: a hundred milliseconds on both clocks, still inside the bound.
    continuous.advance(std::time::Duration::from_millis(100));
    wall.store(T + 100, Ordering::SeqCst);
    grants
        .grant(grant.grant_id, T + 100)
        .expect("inside the bound a hundred milliseconds on");
    let (_, ends_in) = grants
        .grant_standing(grant.grant_id, T + 100)
        .expect("inside the bound a hundred milliseconds on");
    assert!(
        ends_in.is_some_and(|ends_in| ends_in <= std::time::Duration::from_millis(101)
            && ends_in >= std::time::Duration::from_millis(100)),
        "a hundred milliseconds of the window are left: {ends_in:?}"
    );

    // Two hundred more on the continuous clock, and the wall clock wound back five seconds. The
    // host's floor holds UTC at T + 100, inside the bound, so only the continuous clock can refuse.
    continuous.advance(std::time::Duration::from_millis(200));
    wall.store(T - 5_000, Ordering::SeqCst);
    let refused = grants
        .grant(grant.grant_id, T - 5_000)
        .expect_err("the bound ran out on the continuous clock");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("offline")),
        "{refused}"
    );

    host.clients.abort();
}

/// A continuous clock a test moves by hand, which says when one thread has read it.
///
/// A decision takes the caller's moment on the continuous clock before it waits for anything. A
/// test that moves the clock after that reading, and lets storage go only then, has the decision
/// wait out the time it moved: whichever step of the decision the thread had reached by then, the
/// time between its first reading and its last is the time the decision waited.
#[derive(Clone, Debug)]
struct WatchedClock {
    clock: kr_transport::clock::ManualClock,
    watched: Arc<std::sync::Mutex<Option<std::thread::ThreadId>>>,
    read: Arc<tokio::sync::Notify>,
}

impl WatchedClock {
    fn new() -> Self {
        Self {
            clock: kr_transport::clock::ManualClock::new(),
            watched: Arc::new(std::sync::Mutex::new(None)),
            read: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Has the calling thread's readings of this clock reported.
    fn watch_this_thread(&self) {
        *self.watched.lock().expect("the watched thread") = Some(std::thread::current().id());
    }

    /// Waits until the watched thread has read the clock.
    ///
    /// The wait turns on that reading and on nothing else; the bound only ends a test that would
    /// hang.
    async fn until_read(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(60), self.read.notified())
            .await
            .expect("the decision read the continuous clock");
    }

    fn advance(&self, by: std::time::Duration) {
        self.clock.advance(by);
    }
}

impl kr_transport::clock::ContinuousClock for WatchedClock {
    fn now(&self) -> kr_transport::clock::ContinuousInstant {
        // The reading is taken before the test is told of it, so a test that moves the clock on
        // being told moves it after this reading and not before.
        let at = self.clock.now();
        if *self.watched.lock().expect("the watched thread") == Some(std::thread::current().id()) {
            self.read.notify_one();
        }
        at
    }
}

/// A deadline that passes while a workflow's decision waits for storage is decided after the wait.
/// A refusal left its clock floor owed, and storage is held while the next decision writes it. The
/// offline bound runs out during that wait, so the decision that follows it is a refusal rather
/// than the permission the clock gave before the wait. The daemon runs on clocks this test moves
/// by hand: the continuous clock moves once the decision has taken its reading and before storage
/// is let go, so the machine's speed bears on no step but one. The daemon's write waits at most
/// five seconds for storage, and the test lets storage go within one wake of moving the clock.
/// Nothing here reads the machine's clocks and nothing sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_that_passes_while_the_floor_is_written_is_decided_after_the_write() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;
    use std::sync::atomic::{AtomicU64, Ordering};

    const T: u64 = 1_767_225_600_000;
    let continuous = WatchedClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let host = host_on(Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn({
            let wall = Arc::clone(&wall);
            move || wall.load(Ordering::SeqCst)
        }),
    })
    .await;
    let environment = host._temp.environment();
    host.controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(400),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(T)),
            }));
        })
        .expect("the owner chooses an offline bound of 400 milliseconds");
    let lasting = issue_grant(
        &host,
        grant_id(23),
        another_device(),
        &[ActionRight::ChangesetCreate],
        GrantExpiry::Never,
    );
    let expired = issue_grant(
        &host,
        grant_id(24),
        another_device(),
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(T - 1),
        },
    );
    let grants = Arc::new(HostGrants::for_daemon(&host.controller));
    grants.grant(lasting.grant_id, T).expect("inside the bound");

    // A grant that has already run out is refused while the host's policy cannot be written, so
    // the floor that refusal stood on is owed.
    let registry =
        rusqlite::Connection::open(environment.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let owed = grants
        .grant(expired.grant_id, T + 50)
        .expect_err("an expired grant is refused");
    assert!(
        matches!(owed, AutomationError::AuthorityUnavailable(_)),
        "{owed}"
    );

    // Storage can take the write again, but another writer holds it while the next decision is
    // taken, for longer than the bound has left: the decision has read the clock, and the time
    // that passes before storage is let go is time it waited.
    registry
        .execute_batch("DROP TRIGGER refuse_policy; BEGIN IMMEDIATE;")
        .expect("storage is held");
    let deciding = {
        let grants = Arc::clone(&grants);
        let continuous = continuous.clone();
        std::thread::spawn(move || {
            continuous.watch_this_thread();
            grants.grant(lasting.grant_id, T)
        })
    };
    continuous.until_read().await;
    continuous.advance(std::time::Duration::from_millis(600));
    registry
        .execute_batch("ROLLBACK;")
        .expect("storage is free");
    let refused = deciding
        .join()
        .expect("the decision returns")
        .expect_err("the bound ran out while the decision waited for storage");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("offline")),
        "{refused}"
    );

    host.clients.abort();
}

/// A grant that expires while a workflow's decision waits for storage is refused after the wait.
/// The owner's own grant is held to no offline bound, so its expiry in UTC is the only deadline:
/// the decision is taken at the caller's reading advanced by the time the write took, not at the
/// reading the caller took before it.
///
/// The daemon runs on clocks this test moves by hand: the continuous clock moves once the decision
/// has taken its reading and before storage is let go, so the machine's speed bears on no step but
/// one. The daemon's write waits at most five seconds for storage; a decision refused because that
/// wait ran out (the store was held longer than the test meant, on a machine too busy to let it go)
/// was not decided after a write, and is made again on a host of its own, so that nothing an
/// earlier attempt left behind bears on the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_expires_while_the_floor_is_written_is_refused_after_the_write() {
    use kr_automation::AutomationError;

    for _ in 0..5 {
        match an_expiring_grant_is_decided_while_the_floor_is_written().await {
            Err(AutomationError::AuthorityUnavailable(detail))
                if detail == kr_controller::grants::FLOOR_UNRECORDED => {}
            decided => {
                let refused =
                    decided.expect_err("the grant expired while the decision waited for storage");
                assert!(
                    matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("expired")),
                    "{refused}"
                );
                return;
            }
        }
    }
    panic!("the daemon's wait for storage ran out in every attempt");
}

/// One attempt: a host on clocks the test moves, a floor owed its record, and the decision of a
/// grant that expires during the wait for storage.
async fn an_expiring_grant_is_decided_while_the_floor_is_written() -> kr_automation::Result<Grant> {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;
    use std::sync::atomic::{AtomicU64, Ordering};

    const T: u64 = 1_767_225_600_000;
    let continuous = WatchedClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let host = host_on(Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn({
            let wall = Arc::clone(&wall);
            move || wall.load(Ordering::SeqCst)
        }),
    })
    .await;
    let environment = host._temp.environment();
    let here = kr_protocol::ids::DeviceId::new(host.environment_id.get());
    let expiring = issue_grant(
        &host,
        grant_id(25),
        here,
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(T + 300),
        },
    );
    let expired = issue_grant(
        &host,
        grant_id(26),
        here,
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(T - 1),
        },
    );
    let grants = Arc::new(HostGrants::for_daemon(&host.controller));

    // A grant that has already run out is refused while the host's policy cannot be written, so
    // the floor that refusal stood on is owed.
    let registry =
        rusqlite::Connection::open(environment.registry_database()).expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
             WHEN NEW.key = 'policy'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let owed = grants
        .grant(expired.grant_id, T + 50)
        .expect_err("an expired grant is refused");
    assert!(
        matches!(owed, AutomationError::AuthorityUnavailable(_)),
        "{owed}"
    );

    // The next decision waits for storage past the moment the first grant expires.
    registry
        .execute_batch("DROP TRIGGER refuse_policy; BEGIN IMMEDIATE;")
        .expect("storage is held");
    let deciding = {
        let grants = Arc::clone(&grants);
        let continuous = continuous.clone();
        std::thread::spawn(move || {
            continuous.watch_this_thread();
            grants.grant(expiring.grant_id, T)
        })
    };
    continuous.until_read().await;
    continuous.advance(std::time::Duration::from_millis(600));
    registry
        .execute_batch("ROLLBACK;")
        .expect("storage is free");
    let decided = deciding.join().expect("the decision returns");

    host.clients.abort();
    decided
}

/// A workflow's grant is decided as a device's request is: narrowed to the rights this host's
/// configuration allows a grant to carry. A node that needs a right the configuration removed is
/// refused, whatever the grant was issued with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_grant_is_narrowed_by_the_configured_rights_ceiling() {
    let host = host().await;
    let environment = host._temp.environment();
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    host.issue(
        grant_id(22),
        &[ActionRight::ChangesetCreate, ActionRight::TerminalInput],
    );
    let document = definition(
        workflow_id(22),
        grant_id(22),
        "a capture the configuration no longer allows",
        capture_node(workspace),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    // The configuration allows grants terminal input and no longer the change-set right.
    write_configuration(
        &environment,
        &narrowing_document(&[ActionRight::AutomationManage, ActionRight::TerminalInput]),
    );
    let effective = host.controller.effective_configuration().await;
    assert!(
        effective.not_in_force.0.is_none(),
        "{:?}",
        effective.not_in_force
    );

    let mut control = client(&host).await;
    let refused = failure(start(&mut control, &host, &document, "evt-narrowed").await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("changeset.create"), "{refused:?}");

    host.clients.abort();
}

/// A capture node that requires a quiesced capture fails, and says why this host cannot hold its
/// workspace still: here, the user's own checkout, which the user's own tools write. Nothing is
/// captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capture_that_requires_a_quiesced_tree_fails_and_names_why() {
    let host = host().await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    host.issue(grant_id(24), &[ActionRight::ChangesetCreate]);
    let mut node = capture_node(workspace);
    let mut params: ChangesetCaptureParams =
        serde_json::from_str(&node.action_params).expect("the node's parameters");
    params.required_consistency =
        Nullable::some(kr_protocol::changeset::SourceConsistency::QuiescedCapture);
    node.action_params = serde_json::to_string(&params).expect("the node's parameters");
    let document = definition(
        workflow_id(24),
        grant_id(24),
        "a capture that needs a quiesced tree",
        node,
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-quiesced")
            .await
            .expect("workflow.run answers"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Failed, "{run:?}");
    let read: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::some(run.run_id),
                    causal_root_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    assert_eq!(read.node_receipts.len(), 1);
    assert_eq!(read.node_receipts[0].status, NodeStatus::Failed);
    assert!(
        read.node_receipts[0].output.0.is_none(),
        "nothing was captured"
    );
    // The journal keeps why.
    let journal = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::store::WORKFLOW_DB_NAME),
    )
    .expect("opens the workflow journal");
    let why: String = journal
        .query_row(
            "SELECT error_json FROM node_receipts WHERE run_id = ?1",
            [run.run_id.to_string()],
            |row| row.get(0),
        )
        .expect("the failed node's reason");
    assert!(
        why.contains("requires a quiesced capture") && why.contains("shared existing checkout"),
        "{why}"
    );

    host.clients.abort();
}

/// Puts a configured session number in force on this host.
async fn admit_sessions(host: &Host, revision: u64, sessions: u64) {
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = revision;
    document.ceilings.session_limit = Nullable::some(sessions);
    write_configuration(&host._temp.environment(), &document);
    let effective = host.controller.effective_configuration().await;
    assert!(
        effective.not_in_force.0.is_none(),
        "{:?}",
        effective.not_in_force
    );
}

/// Reads the budget of the chain `run` belongs to.
async fn chain_budget(
    control: &mut LocalClient,
    document: &WorkflowDefinition,
    run: &WorkflowRunResult,
) -> kr_protocol::automation::CausalBudgetSummary {
    let read: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::some(run.run_id),
                    causal_root_id: Nullable::some(run.causal_root_id),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    read.remaining_causal_budget
        .0
        .expect("the chain this run belongs to has a budget")
}

/// A new chain may create no more sessions than the lower of ten and the session number this host
/// admits when the chain begins, and spend no managed allowance, because this host gives a
/// workflow none. A number the host admits later changes the ceiling of chains that begin later
/// and of no chain already begun.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_chain_inherits_the_session_number_the_host_admits_when_it_begins() {
    let host = host().await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    host.issue(grant_id(23), &[ActionRight::ChangesetCreate]);
    let document = definition(
        workflow_id(23),
        grant_id(23),
        "a capture whose chain inherits the host's session number",
        capture_node(workspace),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    admit_sessions(&host, 1, 3).await;
    let mut control = client(&host).await;
    let narrow: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-three-sessions")
            .await
            .expect("workflow.run succeeds"),
    );
    assert_eq!(narrow.status, WorkflowRunStatus::Completed, "{narrow:?}");
    let budget = chain_budget(&mut control, &document, &narrow).await;
    assert_eq!(budget.max_sessions.get(), 3, "the host admits three");
    assert_eq!(budget.max_managed_spend.get(), 0, "this host gives none");
    assert_eq!(budget.managed_spend.get(), 0, "a capture spends none");

    admit_sessions(&host, 2, 64).await;
    let mut control = client(&host).await;
    let wide: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-sixty-four-sessions")
            .await
            .expect("workflow.run succeeds"),
    );
    assert_eq!(wide.status, WorkflowRunStatus::Completed, "{wide:?}");
    assert_ne!(wide.causal_root_id, narrow.causal_root_id, "a second chain");
    let budget = chain_budget(&mut control, &document, &wide).await;
    assert_eq!(
        budget.max_sessions.get(),
        10,
        "ten, when the host admits more"
    );
    let kept = chain_budget(&mut control, &document, &narrow).await;
    assert_eq!(
        kept.max_sessions.get(),
        3,
        "a chain already begun keeps the ceiling it inherited"
    );

    host.clients.abort();
}

// ---- KR-ACC-032 across a real daemon process restart --------------------------------------------

/// A daemon this test started as a process of its own, ended when the test lets go of it.
#[cfg(unix)]
struct DaemonProcess(Option<std::process::Child>);

#[cfg(unix)]
impl DaemonProcess {
    /// Starts the placed daemon on this test's own directories, with no worker program.
    ///
    /// The copy was placed by a process of its own, so no child another test starts holds it open
    /// for writing, and the first start is the only one.
    fn start(program: &Path, temp: &kr_ipc::testing::TempHost) -> Self {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(temp.root().join("daemon.log"))
            .expect("opens the daemon's log");
        let child = std::process::Command::new(program)
            .current_dir(temp.root())
            .arg("--runtime-dir")
            .arg(temp.root().join("r"))
            .arg("--state-dir")
            .arg(temp.root().join("s"))
            .arg("--worker")
            .arg(temp.root().join("no-such-worker"))
            .arg("--secret-store")
            .arg("file")
            .env(
                kr_controller::testing::GIT_READ_BOUND_VARIABLE,
                kr_controller::testing::HUNG_GIT_READ
                    .as_millis()
                    .to_string(),
            )
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .unwrap_or_else(|error| panic!("the daemon starts: {error:?}"));
        Self(Some(child))
    }

    /// Ends it now, as a crash or a power cut would, without giving it a chance to tidy up.
    fn kill(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(unix)]
impl Drop for DaemonProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Waits for a daemon process to answer on its control endpoint.
///
/// One deadline covers the whole wait, each connection and its hello included, so a daemon that
/// takes the connection and never answers ends the wait at the deadline like one that is not there.
#[cfg(unix)]
async fn answering(
    endpoint: &kr_ipc::paths::Endpoint,
    temp: &kr_ipc::testing::TempHost,
) -> LocalClient {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    let answered = tokio::time::timeout_at(deadline, async {
        loop {
            if let Ok(client) = LocalClient::connect(endpoint, LocalClientKind::Cli, build()).await
            {
                return client;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    answered.unwrap_or_else(|_| {
        panic!(
            "the daemon did not answer within two minutes, and its log says: {}",
            std::fs::read_to_string(temp.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        )
    })
}

/// Writes one live grant into the registry of a daemon running as a process, as a person sharing
/// work would have had it written.
#[cfg(unix)]
fn grant_in_registry(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    grant_id: GrantId,
    rights: &[ActionRight],
) {
    let device_id = kr_protocol::ids::DeviceId::new(environment_id.get());
    // The revision the host is at, as a grant it issued now would carry.
    let registry = rusqlite::Connection::open_with_flags(
        environment.registry_database(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    let revision: i64 = registry
        .query_row("SELECT authority_revision FROM environment", [], |row| {
            row.get(0)
        })
        .expect("the host's authority revision");
    drop(registry);
    let record = GrantRecord {
        grant: Grant {
            grant_id,
            parent_grant_id: Nullable::null(),
            issuer_device_id: device_id,
            recipient_device_id: device_id,
            authority_revision: AuthorityRevision::new(
                u64::try_from(revision).expect("a revision"),
            ),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: rights.iter().copied().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        },
        session_id: None,
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    };
    // The daemon writes the same database, so a write that meets its lock waits and tries again.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let written =
            kr_controller::grants::store::GrantDirectory::open(environment.registry_database())
                .and_then(|directory| directory.issue(&record, || Ok(())));
        match written {
            Ok(()) => return,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("the grant is written: {error}"),
        }
    }
}

/// How far one chain has got, read from the workflow journal: the runs of it that completed, and
/// the nodes of it whose action is under way. `None` when the journal could not be read just now.
#[cfg(unix)]
fn chain_progress(journal: &Path, root: kr_protocol::ids::CausalRootId) -> Option<(i64, i64)> {
    let connection =
        rusqlite::Connection::open_with_flags(journal, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let completed = connection
        .query_row(
            "SELECT COUNT(*) FROM workflow_runs WHERE causal_root_id = ?1 AND status = ?2",
            rusqlite::params![root.to_string(), WorkflowRunStatus::Completed.as_str()],
            |row| row.get(0),
        )
        .ok()?;
    let under_way = connection
        .query_row(
            "SELECT COUNT(*) FROM node_receipts n JOIN workflow_runs r ON n.run_id = r.run_id
             WHERE r.causal_root_id = ?1 AND n.status = ?2",
            rusqlite::params![root.to_string(), NodeStatus::Running.as_str()],
            |row| row.get(0),
        )
        .ok()?;
    Some((completed, under_way))
}

/// A gate on the workflow journal that holds every chain at a set number of runs, for as long as
/// the test keeps it.
///
/// The gate is a trigger on the journal that refuses to record a chain's next run once the chain
/// has `runs` of them. The host takes a refused write for a journal it could not write, which says
/// nothing about the trigger that asked for the run: nothing of that admission is kept, the event
/// that asked for it stays unread, and the process that reads the journal next decides it again.
/// A daemon running the chain therefore stops between two of its actions once `runs` runs have
/// completed, however fast or slow the machine is, and nothing of the chain is under way while it
/// is held. A run killed between two actions is taken up by the next daemon; one killed during an
/// action is not known to have happened, which would end the chain rather than test its budget.
#[cfg(unix)]
struct ChainGate {
    journal: PathBuf,
}

#[cfg(unix)]
impl ChainGate {
    /// The trigger's name in the journal.
    const TRIGGER: &str = "kr_test_chain_gate";

    /// Puts the gate on `journal`, holding each chain at `runs` runs.
    fn hold(journal: &Path, runs: i64) -> Self {
        let connection = rusqlite::Connection::open(journal).expect("opens the workflow journal");
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER {trigger} BEFORE INSERT ON workflow_runs
                 WHEN (SELECT COUNT(*) FROM workflow_runs
                       WHERE causal_root_id = NEW.causal_root_id) >= {runs}
                 BEGIN SELECT RAISE(ABORT, 'the chain is held at its gate'); END;",
                trigger = Self::TRIGGER
            ))
            .expect("the gate is put on the journal");
        Self {
            journal: journal.to_path_buf(),
        }
    }

    /// Takes the gate off again, for a daemon that is not running, so the next one to start goes
    /// on with the chain.
    fn lift(self) {
        let connection =
            rusqlite::Connection::open(&self.journal).expect("opens the workflow journal");
        connection
            .execute_batch(&format!("DROP TRIGGER {};", Self::TRIGGER))
            .expect("the gate is taken off the journal");
    }
}

/// Waits until the chain stands at the gate: exactly `runs` of its runs completed and no action of
/// it under way, which the gate keeps true until it is lifted. Returns the runs completed.
#[cfg(unix)]
async fn held_at_the_gate(journal: &Path, root: kr_protocol::ids::CausalRootId, runs: i64) -> i64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let progress = chain_progress(journal, root);
        if progress == Some((runs, 0)) {
            return runs;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the chain stood at its gate of {runs} runs, with nothing under way, within two \
             minutes: {progress:?} (completed, under way)"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// KR-ACC-032 and KR-REQ-24.10 across a real restart of the daemon's process, not a reopened
/// service. Two workflows, each a single node and neither cyclic on its own, trigger one another:
/// a capture's success triggers a materialisation of a version, and a materialisation's success
/// triggers a capture. The chain they make starts under one root the host mints. The daemon's
/// process is killed part way through the chain, where a gate on the journal holds it after its
/// third run with nothing under way, and a new process on the same state goes on with the same
/// chain and the same budget, whose count the first process had spent part of, until the depth
/// ceiling refuses the next descendant: one chain, one budget, exhausted once, with one attention
/// item. Where the restart comes is the gate's to say, not the machine's speed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutually_triggering_workflows_exhaust_one_budget_across_a_daemon_process_restart() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let program = temp.root().join("kr-controller");
    kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-controller")), &program);
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let work = tempfile::TempDir::new().expect("a working directory on the internal disk");
    let journal = environment
        .state_dir()
        .join(kr_automation::store::WORKFLOW_DB_NAME);

    let mut first = DaemonProcess::start(&program, &temp);
    let mut control = answering(&endpoint, &temp).await;
    let grant = grant_id(40);
    grant_in_registry(
        &environment,
        environment_id,
        grant,
        &[ActionRight::ChangesetCreate, ActionRight::WorkspaceManage],
    );
    let workspace = adopted_workspace(&mut control, environment_id, work.path()).await;

    // The version every materialisation in the chain copies, captured directly rather than by a
    // workflow, so it triggers nothing.
    let seed_params: ChangesetCaptureParams =
        serde_json::from_str(&capture_node(workspace).action_params).expect("the parameters");
    let seed: kr_protocol::changeset::ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &seed_params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.capture succeeds"),
    );

    let mut captures = definition(
        workflow_id(40),
        grant,
        "capture after a materialisation",
        capture_node(workspace),
    );
    captures.trigger.event_type = "changeset.materialized".to_owned();
    captures.explicit_recurrence = true;
    let mut materialises = definition(
        workflow_id(41),
        grant,
        "materialise after a capture",
        WorkflowNode {
            node_id: "materialise".to_owned(),
            action_kind: WorkflowActionKind::MaterializeChangeset,
            action_params: serde_json::to_string(
                &kr_protocol::changeset::ChangesetMaterializeParams {
                    change_set_id: seed.version.change_set_id,
                    version: seed.version.version,
                    purpose: kr_protocol::changeset::MaterialisationPurpose::Test,
                    label: "the chain's copy".to_owned(),
                },
            )
            .expect("the parameters"),
            declared_environment: Nullable::null(),
        },
    );
    materialises.trigger.event_type = "changeset.captured".to_owned();
    materialises.explicit_recurrence = true;
    for document in [&captures, &materialises] {
        typed::<WorkflowInstallResult>(
            &control
                .mutate(
                    Method::WorkflowInstall,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment_id),
                    &WorkflowInstallParams {
                        workflow_id: document.workflow_id,
                        revision: document.revision,
                        definition: document.clone(),
                        grant_reference: document.grant_reference,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("workflow.install succeeds"),
        );
        typed::<WorkflowEnableResult>(
            &control
                .mutate(
                    Method::WorkflowEnable,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment_id),
                    &WorkflowEnableParams {
                        workflow_id: document.workflow_id,
                        revision: document.revision,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("workflow.enable succeeds"),
        );
    }

    // The gate goes on before the chain begins, so the chain stops after its third run however
    // quickly the first process gets there.
    let gate = ChainGate::hold(&journal, 3);

    // The external trigger: the host mints the root.
    let root_run: WorkflowRunResult = typed(
        &control
            .mutate(
                Method::WorkflowRun,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &WorkflowRunParams {
                    workflow_id: captures.workflow_id,
                    revision: captures.revision,
                    event_id: "evt-acc-032".to_owned(),
                    event_type: "manual".to_owned(),
                    event_payload: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.run succeeds"),
    );
    assert_eq!(
        root_run.status,
        WorkflowRunStatus::Completed,
        "{root_run:?}"
    );
    let root = root_run.causal_root_id;

    // The first process goes on with the chain on its own until the gate holds it, and is killed
    // there. The gate comes off only once that process has gone, so it never admits the next run.
    drop(control);
    let before = held_at_the_gate(&journal, root, 3).await;
    first.kill();
    gate.lift();
    let depth_limit =
        i64::try_from(kr_protocol::automation::DEFAULT_CAUSAL_DEPTH_LIMIT).expect("a small limit");
    assert!(
        before < depth_limit,
        "the restart came part way through the chain: {before} runs before it"
    );

    // A new process on the same state goes on with the same chain.
    let _second = DaemonProcess::start(&program, &temp);
    let mut control = answering(&endpoint, &temp).await;
    // One deadline for the whole wait, each read included.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut last = None;
    let exhausted = tokio::time::timeout_at(deadline, async {
        loop {
            let read: WorkflowReadResult = typed(
                &control
                    .request(
                        Method::WorkflowRead,
                        &WorkflowReadParams {
                            workflow_id: Nullable::null(),
                            revision: Nullable::null(),
                            run_id: Nullable::null(),
                            causal_root_id: Nullable::some(root),
                        },
                    )
                    .await
                    .expect("the call reaches the daemon")
                    .expect("workflow.read succeeds"),
            );
            if read
                .remaining_causal_budget
                .0
                .as_ref()
                .is_some_and(|budget| budget.exhausted)
            {
                return read;
            }
            last = Some(read);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    let read = exhausted.unwrap_or_else(|_| {
        panic!("the chain exhausted its budget within two minutes of the restart: {last:?}")
    });

    let budget = read.remaining_causal_budget.0.expect("the chain's budget");
    assert!(budget.paused, "{budget:?}");
    let chain: Vec<&kr_protocol::automation::WorkflowRunSummary> = read
        .runs
        .iter()
        .filter(|run| run.causal_root_id == root)
        .collect();
    let mut depths: Vec<u64> = chain.iter().map(|run| run.depth.get()).collect();
    depths.sort_unstable();
    let limit = kr_protocol::automation::DEFAULT_CAUSAL_DEPTH_LIMIT;
    assert_eq!(
        depths,
        (1..=limit).collect::<Vec<_>>(),
        "one run at every depth to the ceiling and none past it"
    );
    assert!(
        chain
            .iter()
            .all(|run| run.status == WorkflowRunStatus::Completed),
        "{chain:?}"
    );
    assert_eq!(
        budget.total_runs.get(),
        limit,
        "the second process spent the budget the first one had begun"
    );
    assert!(
        i64::try_from(limit).expect("a small limit") > before,
        "the second process ran part of the chain"
    );

    // One attention item for the exhausted chain, with one deadline for the whole wait.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let raised = tokio::time::timeout_at(deadline, async {
        loop {
            let inbox: kr_protocol::attention::AttentionReadResult = typed(
                &control
                    .request(
                        Method::AttentionRead,
                        &kr_protocol::attention::AttentionReadParams {
                            session_id: Nullable::null(),
                            include_acknowledged: true,
                            max_items: U64::new(50),
                            after: Nullable::null(),
                        },
                    )
                    .await
                    .expect("the call reaches the daemon")
                    .expect("attention.read succeeds"),
            );
            if !inbox.items.is_empty() {
                return inbox.items;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the exhausted chain raised its attention item within a minute"));
    assert_eq!(raised.len(), 1, "{raised:?}");
}

/// Rule C for a workflow: a stored grant is anchored once in this boot and decided on both of its
/// deadlines before every node. With UTC moved past one grant's expiry while its continuous
/// deadline is still ahead, the next node under it is refused; with the continuous clock past
/// another grant's anchor while UTC is still before its expiry, so is the next node under that
/// one. No authority revision moves: nothing left the controller. The control: before either
/// deadline, both grants stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_under_a_stored_grant_stops_when_either_deadline_passes() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;
    use std::sync::atomic::{AtomicU64, Ordering};

    const T: u64 = 1_767_225_600_000;
    let continuous = kr_transport::clock::ManualClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let host = host_on(Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn({
            let wall = Arc::clone(&wall);
            move || wall.load(Ordering::SeqCst)
        }),
    })
    .await;
    let revision = host.controller.policy().authority_revision();
    let by_utc = issue_grant(
        &host,
        grant_id(27),
        another_device(),
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(T + 60_000),
        },
    );
    let by_continuous = issue_grant(
        &host,
        grant_id(28),
        another_device(),
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(T + 120_000),
        },
    );
    let grants = HostGrants::for_daemon(&host.controller);
    grants
        .grant(by_utc.grant_id, T)
        .expect("the control: before either deadline");
    grants
        .grant(by_continuous.grant_id, T)
        .expect("the control: before either deadline");
    // A grant that expires is an end it stands on: a command that starts later than the node asks
    // is held to the earlier of that and its own wait.
    let (_, ends_in) = grants
        .grant_standing(by_continuous.grant_id, T)
        .expect("before the deadline");
    assert_eq!(ends_in, Some(std::time::Duration::from_secs(120)));
    let (_, ends_in) = grants
        .grant_standing(by_utc.grant_id, T)
        .expect("before the deadline");
    assert_eq!(ends_in, Some(std::time::Duration::from_secs(60)));

    // UTC runs past the first grant's expiry while the continuous clock moves one second.
    continuous.advance(std::time::Duration::from_secs(1));
    wall.store(T + 61_000, Ordering::SeqCst);
    let refused = grants
        .grant(by_utc.grant_id, T + 61_000)
        .expect_err("the first grant ran out in UTC");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("expired")),
        "{refused}"
    );
    grants
        .grant(by_continuous.grant_id, T + 61_000)
        .expect("the second grant stands");

    // The continuous clock runs past the second grant's anchor while UTC stays before its expiry.
    continuous.advance(std::time::Duration::from_secs(120));
    let refused = grants
        .grant(by_continuous.grant_id, T + 62_000)
        .expect_err("the second grant ran out on the continuous clock");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("expired")),
        "{refused}"
    );
    assert_eq!(
        host.controller.policy().authority_revision(),
        revision,
        "no lapse moves the revision"
    );

    host.clients.abort();
}

/// KR-REQ-23.52: the owner installs a workflow whose execution grant is a member device's
/// organisation grant. It is refused while that device is bound to no member, installed once the
/// device binds on a live lease, and its node is decided while the lease lasts and refused after
/// it. The control: the member's grant does not reach workflow.install itself, since no role
/// ceiling carries automation.manage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_managed_workflow_runs_under_a_members_organisation_grant_while_its_lease_lasts() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;
    use kr_controller::grants::organisation::LeasePresentation;
    use organisation_support::{LEASE_MS, Organisation, T, member, reading};
    use std::sync::atomic::{AtomicU64, Ordering};

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    let continuous = kr_transport::clock::ManualClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let host = host_on(Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn({
            let wall = Arc::clone(&wall);
            move || wall.load(Ordering::SeqCst)
        }),
    })
    .await;
    let mut control = client(&host).await;
    let mut organisation = Organisation::new(0x51, T - 2 * DAY_MS);
    organisation.rotate(T - DAY_MS);
    let revision = host.controller.policy().authority_revision();
    host.controller
        .update_policy(|policy| organisation.enrol(policy, T))
        .expect("the enrolment is written down");

    let member_device = another_device();
    let grant = Grant {
        grant_id: grant_id(29),
        parent_grant_id: Nullable::null(),
        issuer_device_id: kr_protocol::ids::DeviceId::new(host.environment_id.get()),
        recipient_device_id: member_device,
        authority_revision: revision,
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::some(kr_protocol::grant::OrganisationRequirement {
            organisation_id: organisation.organisation_id,
            policy_revision: revision,
        }),
    };
    let record = GrantRecord {
        grant: grant.clone(),
        session_id: None,
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    };
    host.controller
        .sharing()
        .grants()
        .issue(&record, || Ok(()))
        .expect("the grant is written");
    let document = definition(
        workflow_id(29),
        grant.grant_id,
        "under a member's organisation grant",
        WorkflowNode {
            node_id: "notice".to_owned(),
            action_kind: WorkflowActionKind::AttentionNotice,
            action_params: serde_json::to_string(&kr_protocol::automation::AttentionNoticeParams {
                summary: "a notice".to_owned(),
            })
            .expect("a notice node's typed parameters"),
            declared_environment: Nullable::null(),
        },
    );
    let installing = WorkflowInstallParams {
        workflow_id: document.workflow_id,
        revision: document.revision,
        definition: document.clone(),
        grant_reference: document.grant_reference,
    };

    // The member's device is bound to nobody, so no lease answers for the grant.
    let refused = failure(
        control
            .mutate(
                Method::WorkflowInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &installing,
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    // The device binds on a live lease, and the owner installs the workflow.
    let key = organisation_support::device();
    let lease = organisation.lease(
        2,
        &member("ada"),
        *key.public(),
        T,
        &[ActionRight::SessionView],
    );
    host.controller
        .update_policy(|policy| {
            policy.install_lease(LeasePresentation {
                lease: &lease,
                device_id: member_device,
                proven_key: key.public(),
                reading: Some(reading(T)),
                now: kr_transport::clock::ContinuousClock::now(&continuous),
                generation: host.controller.generation(),
            })
        })
        .expect("the lease is written down")
        .expect("the lease installs and binds the device");
    install(&mut control, &host, &document).await;

    // A node that runs a command needs the right to create a session beside the right to type,
    // and the member's grant carries neither (nor does any role ceiling), so no node of that kind
    // is installed under it.
    let command = definition(
        workflow_id(28),
        grant.grant_id,
        "a command under a member's grant",
        command_node(&host, "command", "true"),
    );
    let refused = failure(
        control
            .mutate(
                Method::WorkflowInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkflowInstallParams {
                    workflow_id: command.workflow_id,
                    revision: command.revision,
                    definition: command.clone(),
                    grant_reference: command.grant_reference,
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    // Its node is decided while the lease lasts.
    let grants = HostGrants::for_daemon(&host.controller);
    let held = grants
        .grant(grant.grant_id, T + 60_000)
        .expect("the member's lease answers");
    kr_automation::authority::check_node(&held, &document, &document.nodes[0], host.environment_id)
        .expect("the node is inside the grant");
    // The lease is an end the grant stands on: a command that starts later than the node asks is
    // held to it.
    let (_, first) = grants
        .grant_standing(grant.grant_id, T + 60_000)
        .expect("the member's lease answers");
    let first = first.expect("a lease is an end");
    assert!(
        first <= std::time::Duration::from_millis(LEASE_MS) && !first.is_zero(),
        "the lease ends within its own lifetime: {first:?}"
    );

    // The control: the member's grant does not reach workflow.install itself.
    let managing = Grant {
        actions: [ActionRight::AutomationManage, ActionRight::SessionView]
            .into_iter()
            .collect(),
        ..grant.clone()
    };
    let asked = kr_controller::grants::decide(
        &managing,
        &GrantRecord {
            grant: managing.clone(),
            ..record.clone()
        },
        &mut host.controller.policy(),
        kr_controller::grants::AccessRequest {
            method: Method::WorkflowInstall,
            ingress: kr_protocol::actor::ActorIngress::PairedDevice,
            environment_id: host.environment_id,
            session_id: None,
            claims_geometry: false,
            own_subject: None,
            now_ms: T + 60_000,
            continuous_now: kr_transport::clock::ContinuousClock::now(&continuous),
        },
    );
    assert_eq!(
        asked,
        Err(kr_controller::grants::Refusal::MissingRight {
            right: ActionRight::AutomationManage
        }),
        "no role ceiling carries automation.manage"
    );

    // The end moves with the continuous clock: a second before it, a second is left.
    continuous.advance(first - std::time::Duration::from_secs(1));
    let (_, ends_in) = grants
        .grant_standing(grant.grant_id, T + 60_000)
        .expect("the lease has a second left");
    assert!(
        ends_in.is_some_and(|ends_in| ends_in >= std::time::Duration::from_secs(1)
            && ends_in <= std::time::Duration::from_millis(1_001)),
        "a second of the lease is left: {ends_in:?}"
    );

    // Once the lease has ended, the node is refused.
    continuous.advance(
        std::time::Duration::from_millis(LEASE_MS) - (first - std::time::Duration::from_secs(1)),
    );
    wall.store(T + LEASE_MS, Ordering::SeqCst);
    let refused = grants
        .grant(grant.grant_id, T + LEASE_MS)
        .expect_err("the lease has ended");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("lease")),
        "{refused}"
    );

    host.clients.abort();
}

/// A workflow grant's end on the continuous clock is answered as an expiry only once its tombstone
/// is on disk. The store refuses every tombstone, the grant's anchor runs out while UTC is still
/// before its expiry, and authority is unavailable rather than refused. The control: once the store
/// takes the tombstone, the grant is refused as expired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_grant_whose_end_could_not_be_written_is_not_answered_as_expired() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;
    use std::sync::atomic::{AtomicU64, Ordering};

    const T: u64 = 1_767_225_600_000;
    let continuous = kr_transport::clock::ManualClock::new();
    let wall = Arc::new(AtomicU64::new(T));
    let host = host_on(Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn({
            let wall = Arc::clone(&wall);
            move || wall.load(Ordering::SeqCst)
        }),
    })
    .await;
    let grant = issue_grant(
        &host,
        grant_id(30),
        another_device(),
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(T + 60_000),
        },
    );
    let grants = HostGrants::for_daemon(&host.controller);
    grants
        .grant(grant.grant_id, T)
        .expect("anchored in this boot, a minute from its end");

    let registry = rusqlite::Connection::open(host._temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_tombstones BEFORE UPDATE OF expired_at_ms ON grants
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    continuous.advance(std::time::Duration::from_secs(61));
    let refused = grants
        .grant(grant.grant_id, T)
        .expect_err("the grant ran out on the continuous clock");
    assert!(
        matches!(refused, AutomationError::AuthorityUnavailable(_)),
        "not answered as an expiry while its end is not on disk: {refused}"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_tombstones;")
        .expect("the fault is cleared");
    let refused = grants
        .grant(grant.grant_id, T)
        .expect_err("the grant stays run out");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("expired")),
        "{refused}"
    );

    host.clients.abort();
}

/// The rights a node that runs a command needs: it types into a shell account, creates its
/// session, closes it when it settles, and (for a test run) writes a version out.
const COMMAND_RIGHTS: [ActionRight; 4] = [
    ActionRight::TerminalInput,
    ActionRight::SessionCreate,
    ActionRight::SessionClose,
    ActionRight::WorkspaceManage,
];

/// A `shell_command` node that runs `command` in this host's own environment.
fn command_node(host: &Host, node_id: &str, command: &str) -> WorkflowNode {
    WorkflowNode {
        node_id: node_id.to_owned(),
        action_kind: WorkflowActionKind::ShellCommand,
        action_params: serde_json::to_string(&kr_protocol::automation::ShellCommandParams {
            command: command.to_owned(),
        })
        .expect("a command node's typed parameters"),
        declared_environment: Nullable::some(host.environment_id),
    }
}

/// A `create_session` node asking for an invisible session in this host's own environment, running
/// the shell it names or, when it names none, the account's own.
fn create_session_node(host: &Host, shell: Option<&str>) -> WorkflowNode {
    let params = kr_protocol::session::SessionCreateParams {
        environment_id: host.environment_id,
        presentation: kr_protocol::session::Presentation::Invisible,
        shell: Nullable(shell.map(str::to_owned)),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        cwd: Nullable::some(host.work().display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    };
    WorkflowNode {
        node_id: "session".to_owned(),
        action_kind: WorkflowActionKind::CreateSession,
        action_params: serde_json::to_string(&params).expect("a create node's typed parameters"),
        declared_environment: Nullable::null(),
    }
}

/// The node receipts of one run.
async fn receipts_of(
    control: &mut LocalClient,
    document: &WorkflowDefinition,
    run_id: kr_protocol::ids::WorkflowRunId,
) -> Vec<kr_protocol::automation::NodeReceiptSummary> {
    let read: WorkflowReadResult = typed(
        &control
            .request(
                Method::WorkflowRead,
                &WorkflowReadParams {
                    workflow_id: Nullable::some(document.workflow_id),
                    revision: Nullable::some(document.revision),
                    run_id: Nullable::some(run_id),
                    causal_root_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workflow.read succeeds"),
    );
    read.node_receipts
}

/// Every session the daemon lists, closed ones included.
async fn all_sessions(control: &mut LocalClient) -> Vec<kr_protocol::session::SessionSummary> {
    let listed: kr_protocol::session::SessionListResult = typed(
        &control
            .request(
                Method::SessionList,
                &kr_protocol::session::SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("session.list succeeds"),
    );
    listed.sessions
}

/// A session, once it has closed.
async fn closed_session(
    control: &mut LocalClient,
    session_id: kr_protocol::ids::SessionId,
) -> kr_protocol::session::SessionSummary {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(session) = all_sessions(control)
            .await
            .into_iter()
            .find(|session| session.session_id == session_id && session.closure.0.is_some())
        {
            return session;
        }
        assert!(
            std::time::Instant::now() < until,
            "session {session_id} has not closed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// The rows of the resource ledger that are still owed their release.
fn owed_rows(host: &Host) -> i64 {
    let ledger = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::resources::RESOURCES_DB_NAME),
    )
    .expect("opens the resource ledger");
    ledger
        .query_row(
            "SELECT COUNT(*) FROM owned WHERE state = 'open'",
            [],
            |row| row.get(0),
        )
        .expect("counts the open rows")
}

/// The statuses the journal holds for the nodes of every run, as it holds them now.
fn node_statuses(host: &Host) -> Vec<String> {
    let journal = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::store::WORKFLOW_DB_NAME),
    )
    .expect("opens the journal");
    let mut statement = journal
        .prepare("SELECT status FROM node_receipts ORDER BY rowid")
        .expect("prepares");
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("reads")
        .collect::<std::result::Result<_, _>>()
        .expect("rows")
}

/// The run the journal holds, when it holds one.
fn only_run(host: &Host) -> kr_protocol::ids::WorkflowRunId {
    let journal = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::store::WORKFLOW_DB_NAME),
    )
    .expect("opens the journal");
    let run: String = journal
        .query_row("SELECT run_id FROM workflow_runs", [], |row| row.get(0))
        .expect("one run");
    kr_protocol::ids::WorkflowRunId::new(run.parse::<Uuid>().expect("a run identifier"))
}

/// The phases of the reservations the sessions of one grant's workflows made.
fn reservation_phases(host: &Host, grant: GrantId) -> Vec<String> {
    let registry = rusqlite::Connection::open(host._temp.environment().registry_database())
        .expect("opens the registry");
    let mut statement = registry
        .prepare("SELECT phase FROM reservations WHERE actor_id = ?1 ORDER BY created_at_ms")
        .expect("prepares");
    statement
        .query_map(
            [kr_automation::resources::session_principal(grant)],
            |row| row.get::<_, String>(0),
        )
        .expect("reads")
        .collect::<std::result::Result<_, _>>()
        .expect("rows")
}

/// Whether a worker's claim was committed on each reservation of the grant's sessions, oldest
/// first.
fn reservation_claims(host: &Host, grant: GrantId) -> Vec<bool> {
    let registry = rusqlite::Connection::open(host._temp.environment().registry_database())
        .expect("opens the registry");
    let mut statement = registry
        .prepare(
            "SELECT claimed_key IS NOT NULL FROM reservations WHERE actor_id = ?1 \
             ORDER BY created_at_ms",
        )
        .expect("prepares");
    statement
        .query_map(
            [kr_automation::resources::session_principal(grant)],
            |row| row.get::<_, bool>(0),
        )
        .expect("reads")
        .collect::<std::result::Result<_, _>>()
        .expect("rows")
}

/// The first live session whose root is a command, once there is one.
async fn live_command_session(control: &mut LocalClient) -> kr_protocol::session::SessionSummary {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(session) = all_sessions(control).await.into_iter().find(|session| {
            session.closure.0.is_none()
                && session.root == Some(kr_protocol::session::SessionRoot::Command)
        }) {
            return session;
        }
        assert!(
            std::time::Instant::now() < until,
            "no session whose root is a command came up"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// A host whose launches wait at the supervisor's door until the test lets them through.
struct Door {
    open: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    arrived: Arc<std::sync::atomic::AtomicUsize>,
    started: Arc<std::sync::atomic::AtomicUsize>,
}

impl Door {
    fn shut() -> Self {
        Self {
            open: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            arrived: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            started: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    async fn host(&self) -> Host {
        let (open, arrived, started) = (
            Arc::clone(&self.open),
            Arc::clone(&self.arrived),
            Arc::clone(&self.started),
        );
        working_host_through(move |inner| {
            Box::new(AtTheDoor {
                inner,
                open,
                arrived,
                started,
            })
        })
        .await
    }

    /// How many launches have reached the door.
    fn launches(&self) -> usize {
        self.arrived.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many workers the platform started once the door was open.
    fn workers_started(&self) -> usize {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn until_a_launch_arrives(&self) {
        until("a launch to reach the door", || {
            self.arrived.load(std::sync::atomic::Ordering::SeqCst) > 0
        })
        .await;
    }

    fn let_through(&self) {
        let (lock, wake) = &*self.open;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
    }
}

/// KR-REQ-25.14 and KR-REQ-18.04: a `shell_command` node runs its command as the root of a session
/// of its own and reports how that root ended, as the host observed it. A command that exits zero
/// succeeds and names its session; one that exits with a status fails and says which; and the
/// session of each closed with that status, labelled as a command's, with nothing left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_shell_command_node_reports_how_its_command_ended() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(21), &COMMAND_RIGHTS);

    let mut ended = Vec::new();
    for (number, command) in [(22_u8, "exit 0"), (23, "exit 3")] {
        let document = definition(
            workflow_id(number),
            grant_id(21),
            "a command",
            command_node(&host, "command", command),
        );
        install(&mut control, &host, &document).await;
        enable(&mut control, &host, &document).await;
        let run: WorkflowRunResult = typed(
            &start(&mut control, &host, &document, "evt-1")
                .await
                .expect("the run is admitted"),
        );
        let receipts = receipts_of(&mut control, &document, run.run_id).await;
        ended.push((run.status, receipts));
    }

    let (status, receipts) = &ended[0];
    assert_eq!(*status, WorkflowRunStatus::Completed);
    assert_eq!(receipts[0].status, NodeStatus::Success);
    let Some(kr_protocol::automation::NodeOutput::ShellCommand { session_id }) =
        receipts[0].output.0.clone()
    else {
        panic!("a command that succeeded names its session: {receipts:?}");
    };
    let session = closed_session(&mut control, session_id).await;
    let closure = session.closure.0.expect("a closed session has its closure");
    assert_eq!(
        closure.reason,
        kr_protocol::session::ClosureReason::RootExit
    );
    assert_eq!(closure.root_exit_code.0, Some(U64::new(0)));

    let (status, receipts) = &ended[1];
    assert_eq!(*status, WorkflowRunStatus::Failed);
    assert_eq!(receipts[0].status, NodeStatus::Failed);
    assert!(receipts[0].output.0.is_none());
    let sessions = all_sessions(&mut control).await;
    assert_eq!(sessions.len(), 2, "one session for each command");
    let failed = sessions
        .iter()
        .find(|session| session.session_id != session_id)
        .expect("the second command's session");
    let closure = failed.closure.0.clone().expect("it closed");
    assert_eq!(closure.root_exit_code.0, Some(U64::new(3)));

    until("what each dispatch owned to be released", || {
        owed_rows(&host) == 0
    })
    .await;
    let scratch = host
        ._temp
        .environment()
        .state_dir()
        .join("workflow-scratch");
    assert!(
        std::fs::read_dir(&scratch).map_or(true, |mut entries| entries.next().is_none()),
        "the directories the commands ran in are gone"
    );
    host.clients.abort();
}

/// KR-REQ-25.15: a `create_session` node creates a session through the daemon's own create path
/// and leaves it running; the session is the node's output and nothing closes it afterwards. A
/// workflow triggered by the node's event descends from it: the daemon, not the caller, says which
/// run and node produced the trigger, one level deeper in the same chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_create_session_node_creates_a_session_that_outlives_its_node() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(24), &[ActionRight::SessionCreate]);
    host.issue(grant_id(34), &[ActionRight::SessionView]);
    let document = definition(
        workflow_id(24),
        grant_id(24),
        "a session",
        create_session_node(&host, None),
    );
    let mut follower = definition(
        workflow_id(34),
        grant_id(34),
        "after a session",
        WorkflowNode {
            node_id: "notice".to_owned(),
            action_kind: WorkflowActionKind::AttentionNotice,
            action_params: serde_json::to_string(&kr_protocol::automation::AttentionNoticeParams {
                summary: "a session was created".to_owned(),
            })
            .expect("a notice node's typed parameters"),
            declared_environment: Nullable::null(),
        },
    );
    follower.trigger = WorkflowTrigger {
        event_type: "session.created".to_owned(),
    };
    for document in [&document, &follower] {
        install(&mut control, &host, document).await;
        enable(&mut control, &host, document).await;
    }

    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-1")
            .await
            .expect("the run is admitted"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    let receipts = receipts_of(&mut control, &document, run.run_id).await;
    let Some(kr_protocol::automation::NodeOutput::CreateSession { session_id }) =
        receipts[0].output.0.clone()
    else {
        panic!("the node names the session it created: {receipts:?}");
    };

    // The session is there, running, and a node's end did not close it.
    let sessions = all_sessions(&mut control).await;
    let session = sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .expect("the session is listed");
    assert!(session.closure.0.is_none(), "{session:?}");
    assert_eq!(session.root, None, "an ordinary session's root is a shell");
    assert_eq!(owed_rows(&host), 0, "the node owns nothing to release");

    let descendant = first_run_of(&mut control, &follower).await;
    assert_eq!(descendant.causal_root_id, run.causal_root_id);
    assert_eq!(descendant.depth.get(), 2);
    assert_eq!(descendant.parent_run_id.0, Some(run.run_id));
    assert_eq!(descendant.parent_node_id.0.as_deref(), Some("session"));
    host.clients.abort();
}

/// KR-REQ-25.14 and KR-REQ-25.19: a command that outlives the node's wait is asked to stop, and
/// its session is closed; nothing is claimed about what it did.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_command_that_outlives_its_wait_is_stopped() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(25), &COMMAND_RIGHTS);
    let mut document = definition(
        workflow_id(25),
        grant_id(25),
        "a long command",
        command_node(&host, "long", "sleep 120"),
    );
    // Long enough for the worker to start under load, and far shorter than the command.
    document.deadlines = WorkflowDeadlines {
        run_deadline_ms: U64::new(120_000),
        action_wait_ms: U64::new(15_000),
    };
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;
    // The run blocks until the node's wait ends, so the live session is read from another
    // connection while the command runs.
    let watcher = {
        let endpoint = host.endpoint.clone();
        tokio::spawn(async move {
            let mut other = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects to the control endpoint");
            live_command_session(&mut other).await
        })
    };
    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-1")
            .await
            .expect("the run is admitted"),
    );
    let live = watcher.await.expect("the watcher answers");
    assert_eq!(
        live.root,
        Some(kr_protocol::session::SessionRoot::Command),
        "a live session whose root is a command says so"
    );
    let receipts = receipts_of(&mut control, &document, run.run_id).await;
    assert_eq!(receipts[0].status, NodeStatus::Cancelled, "{receipts:?}");

    let sessions = all_sessions(&mut control).await;
    assert_eq!(sessions.len(), 1);
    let closed = closed_session(&mut control, sessions[0].session_id).await;
    assert_eq!(
        closed.root,
        Some(kr_protocol::session::SessionRoot::Command),
        "a command's session says its root was a command after it has closed"
    );
    assert_eq!(
        closed.closure.0.expect("closed").reason,
        kr_protocol::session::ClosureReason::CloseRequested,
        "the session was closed because the node was asked to stop"
    );
    until(
        "what the dispatch owned to be released once the closure was recorded",
        || owed_rows(&host) == 0,
    )
    .await;
    host.clients.abort();
}

/// KR-REQ-25.19: a run cancelled by request while its command runs stops the command and closes
/// its session, and nothing is paused: the run exceeded no limit, so the workflow stays enabled
/// and no attention item is owed. What the dispatch owned is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_run_cancelled_while_its_command_runs_stops_it_and_pauses_nothing() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(35), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(35),
        grant_id(35),
        "a long command",
        command_node(&host, "long", "sleep 120"),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;
    let running = run_from_another_task(&host, &document, "evt-cancelled");
    let live = live_command_session(&mut control).await;

    host.controller
        .automation()
        .journal()
        .cancel_run(
            only_run(&host),
            "run cancelled by request",
            kr_ipc::now_ms().get(),
        )
        .expect("the run is cancelled");

    let answered: WorkflowRunResult = typed(
        &running
            .await
            .expect("the run answers")
            .expect("the cancelled run is answered"),
    );
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    let closed = closed_session(&mut control, live.session_id).await;
    assert_eq!(
        closed.closure.0.expect("closed").reason,
        kr_protocol::session::ClosureReason::CloseRequested,
        "the command's session was closed because its run was cancelled"
    );
    assert_eq!(node_statuses(&host), [NodeStatus::Cancelled.as_str()]);
    assert!(
        !host
            .controller
            .automation()
            .journal()
            .is_paused(document.workflow_id, 1)
            .expect("reads"),
        "a cancellation is no limit exceeded"
    );
    until("what the dispatch owned to be released", || {
        owed_rows(&host) == 0
    })
    .await;
    host.clients.abort();
}

/// KR-REQ-25.14: the directory a command ran in is removed only while it is the one that was made.
/// A directory put at its path in the meantime is not this host's to remove, and the row is
/// released all the same. The control is the case above it, where the directory is the one made
/// and is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_directory_put_in_place_of_a_commands_own_is_left_alone() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(36), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(36),
        grant_id(36),
        "a long command",
        command_node(&host, "long", "sleep 120"),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;
    let running = run_from_another_task(&host, &document, "evt-replaced");
    let live = live_command_session(&mut control).await;

    let scratch = host
        ._temp
        .environment()
        .state_dir()
        .join("workflow-scratch");
    let made = std::fs::read_dir(&scratch)
        .expect("the directories commands run in")
        .next()
        .expect("the command's directory")
        .expect("it is readable")
        .path();
    let moved = scratch.join("moved-away");
    std::fs::rename(&made, &moved).expect("the command's directory is moved");
    std::fs::create_dir(&made).expect("another directory is put in its place");
    std::fs::write(made.join("precious"), b"not the command's").expect("a file in it");

    host.controller
        .automation()
        .journal()
        .cancel_run(
            only_run(&host),
            "run cancelled by request",
            kr_ipc::now_ms().get(),
        )
        .expect("the run is cancelled");
    let _ = running.await;
    let _ = closed_session(&mut control, live.session_id).await;
    until("what the dispatch owned to be released", || {
        owed_rows(&host) == 0
    })
    .await;
    assert!(
        made.join("precious").exists(),
        "a directory that is not the one the command ran in is not removed"
    );
    host.clients.abort();
}

/// KR-REQ-25.14: a command declared for a workspace runs in the tree the project service recorded
/// for it and nowhere else. A tree that was moved aside, with another directory put at its path,
/// is refused where the command would start, the node pauses, and nothing runs in the other
/// directory. The control is the same node before the directory is replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_command_runs_only_in_the_workspace_that_was_recorded() {
    let host = working_host().await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    let tree = host.work().join("source");
    host.issue(grant_id(37), &COMMAND_RIGHTS);
    let mut document = definition(
        workflow_id(37),
        grant_id(37),
        "a command in a workspace",
        command_node(&host, "command", "touch ran-here"),
    );
    document.resource_scope = WorkflowResourceScope {
        environment_id: Nullable::null(),
        workspace_id: Nullable::some(workspace),
        session_id: Nullable::null(),
    };
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-in-place")
            .await
            .expect("the run is admitted"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    assert!(
        tree.join("ran-here").exists(),
        "the command ran in the tree"
    );
    std::fs::remove_file(tree.join("ran-here")).expect("the mark is removed");

    std::fs::rename(&tree, host.work().join("moved-away")).expect("the tree is moved aside");
    std::fs::create_dir(&tree).expect("another directory is put at its path");
    let refused = failure(start(&mut control, &host, &document, "evt-replaced").await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        !tree.join("ran-here").exists(),
        "nothing ran in a directory that is not the recorded tree"
    );
    assert_eq!(
        node_statuses(&host),
        [NodeStatus::Success.as_str(), NodeStatus::Paused.as_str()]
    );
    assert_eq!(
        all_sessions(&mut control).await.len(),
        1,
        "no second session"
    );
    until("the refused node to leave nothing owed", || {
        owed_rows(&host) == 0
    })
    .await;
    host.clients.abort();
}

/// Runs `document` from another task, so the test can act while the node is between its checks and
/// its effect, and answers what the run came to.
fn run_from_another_task(
    host: &Host,
    document: &WorkflowDefinition,
    event: &str,
) -> tokio::task::JoinHandle<std::result::Result<ParamsValue, ProtocolError>> {
    let environment_id = host.environment_id;
    let endpoint = host.endpoint.clone();
    let document = document.clone();
    let event = event.to_owned();
    tokio::spawn(async move {
        let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the control endpoint");
        control
            .mutate(
                Method::WorkflowRun,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &WorkflowRunParams {
                    workflow_id: document.workflow_id,
                    revision: document.revision,
                    event_id: event,
                    event_type: "manual".to_owned(),
                    event_payload: Nullable::null(),
                },
            )
            .await
            .unwrap_or_else(|error| {
                Err(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    format!("the daemon did not answer: {error}"),
                ))
            })
    })
}

/// Holds the registry's write lock, as another writer would, so that a create that has passed
/// every check the engine and the runner make waits for it.
fn hold_the_registry(host: &Host) -> rusqlite::Connection {
    let registry = rusqlite::Connection::open(host._temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the registry");
    registry
}

/// KR-REQ-25.14 and KR-REQ-19.04: the moment the engine stops waiting for a node is asked where
/// the node's session comes into being, and not only before the runner is called. The create waits
/// for the registry, as it does behind another writer, until the node's wait has ended; when it
/// reaches its launch it is refused there, its reservation fails, and nothing is left counting
/// against the session limit. No session is made for a `create_session` node, and no command runs
/// for a `shell_command` node. The control is the same node with the registry free, which makes
/// its session (the cases above).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_wait_that_ends_before_the_session_comes_into_being_makes_no_session() {
    // The door is open: it only counts the launches that reach the supervisor.
    let door = Door::shut();
    door.let_through();
    let host = door.host().await;
    let mut control = client(&host).await;
    let marker = host.work().join("a-command-ran");
    for (number, grant, node) in [
        (
            30_u8,
            vec![ActionRight::SessionCreate],
            create_session_node(&host, None),
        ),
        (
            31,
            COMMAND_RIGHTS.to_vec(),
            command_node(&host, "command", &format!("touch {}", marker.display())),
        ),
    ] {
        host.issue(grant_id(number), &grant);
        let mut document = definition(workflow_id(number), grant_id(number), "a node", node);
        document.deadlines = WorkflowDeadlines {
            run_deadline_ms: U64::new(60_000),
            action_wait_ms: U64::new(1_500),
        };
        install(&mut control, &host, &document).await;
        enable(&mut control, &host, &document).await;

        // Another writer holds the registry. The run passes every check the engine and the runner
        // make, and the create waits for it until the node's wait has ended.
        let settled_before = node_statuses(&host).len();
        let registry = hold_the_registry(&host);
        let running = run_from_another_task(&host, &document, "evt-too-late");
        // A node that has not begun is `pending` and one waiting for its action is `running`: the
        // wait has ended once the engine has settled the node, and only then is the registry freed.
        until("the engine to stop waiting for the node", || {
            node_statuses(&host).len() > settled_before
                && node_statuses(&host).last().is_some_and(|status| {
                    status != NodeStatus::Pending.as_str() && status != NodeStatus::Running.as_str()
                })
        })
        .await;
        registry
            .execute_batch("COMMIT")
            .expect("the other writer finishes");
        let run: WorkflowRunResult = typed(
            &running
                .await
                .expect("the run answers")
                .expect("the run is answered"),
        );
        assert_eq!(run.status, WorkflowRunStatus::Cancelled, "{run:?}");

        // The create reaches its launch once the registry is free, is refused there, and leaves
        // a reservation that failed and nothing else.
        until("the refused create to have failed its reservation", || {
            reservation_phases(&host, grant_id(number)) == ["failed"]
        })
        .await;
        assert_eq!(
            node_statuses(&host).last().map(String::as_str),
            Some(NodeStatus::Cancelled.as_str())
        );
        let receipts = receipts_of(&mut control, &document, run.run_id).await;
        assert!(
            !receipts.is_empty() && receipts.iter().all(|receipt| receipt.output.0.is_none()),
            "the node produced nothing: {receipts:?}"
        );
    }
    let sessions = all_sessions(&mut control).await;
    assert!(
        sessions.iter().all(|session| session.closure.0.is_some()),
        "no session is live for either node: {sessions:?}"
    );
    assert_eq!(
        door.launches(),
        0,
        "the refusal was the launch transition's: no worker was asked for"
    );
    assert!(!marker.exists(), "the command never ran");
    until("what the command's dispatch owned to be released", || {
        owed_rows(&host) == 0
    })
    .await;
    host.clients.abort();
}

/// A grant is withdrawn while a node's launch waits at the supervisor's door, after the launch
/// transition admitted it. The worker is started, connects and is refused its claim; the node
/// pauses on the refusal, its reservation fails, and what it would have started never starts.
async fn a_grant_withdrawn_at_the_door_starts_nothing(
    number: u8,
    rights: &[ActionRight],
    node: impl FnOnce(&Host, &Path) -> WorkflowNode,
) {
    let door = Door::shut();
    let host = door.host().await;
    let mut control = client(&host).await;
    let marker = host.work().join("a-command-ran");
    host.issue(grant_id(number), rights);
    let document = definition(
        workflow_id(number),
        grant_id(number),
        "a node",
        node(&host, &marker),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let running = run_from_another_task(&host, &document, "evt-at-the-door");
    door.until_a_launch_arrives().await;
    host.controller
        .sharing()
        .grants()
        .revoke(grant_id(number), kr_ipc::now_ms().get(), || Ok(()))
        .expect("the grant is withdrawn");
    door.let_through();

    let refused = running
        .await
        .expect("the run answers")
        .expect_err("the withdrawn grant stops the node");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_eq!(node_statuses(&host), [NodeStatus::Paused.as_str()]);
    until("the refused launch to have failed its reservation", || {
        reservation_phases(&host, grant_id(number)) == ["failed"]
    })
    .await;
    assert!(!marker.exists(), "the command never ran");
    assert!(
        all_sessions(&mut control)
            .await
            .iter()
            .all(|session| session.closure.0.is_some()),
        "no session is live"
    );
    host.clients.abort();
}

/// KR-REQ-19.04 and KR-REQ-25.14: the command is released to start at the worker's claim, which
/// comes after the launch transition, so the grant is asked there as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_grant_withdrawn_before_the_worker_claims_its_launch_runs_no_command() {
    a_grant_withdrawn_at_the_door_starts_nothing(32, &COMMAND_RIGHTS, |host, marker| {
        command_node(host, "command", &format!("touch {}", marker.display()))
    })
    .await;
}

/// KR-REQ-19.04 and KR-REQ-25.14: a session that names the shell it runs starts a program the
/// definition chose, and is held to its grant at the claim as a command is.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_grant_withdrawn_before_the_worker_claims_its_launch_starts_no_named_shell() {
    a_grant_withdrawn_at_the_door_starts_nothing(
        38,
        &[ActionRight::SessionCreate, ActionRight::TerminalInput],
        |host, _| create_session_node(host, Some("/bin/sh")),
    )
    .await;
}

/// A node's launch has passed the launch transition and waits at the supervisor's door; the node's
/// wait ends there, and the door opens afterwards. The engine's request to stop is asked of a node
/// whose admission has passed, and the worker's claim, which comes after it, is refused: no program
/// starts and no session is made. What the node settles as is the runner's answer to the request.
async fn a_wait_that_ends_at_the_door_makes_no_session(
    number: u8,
    rights: &[ActionRight],
    node: impl FnOnce(&Host, &Path) -> WorkflowNode,
    settles: NodeStatus,
) {
    let door = Door::shut();
    let host = door.host().await;
    let mut control = client(&host).await;
    let marker = host.work().join("a-command-ran");
    host.issue(grant_id(number), rights);
    let mut document = definition(
        workflow_id(number),
        grant_id(number),
        "a node",
        node(&host, &marker),
    );
    // Long enough for the launch to reach the door under load; the node's wait ends there.
    document.deadlines = WorkflowDeadlines {
        run_deadline_ms: U64::new(60_000),
        action_wait_ms: U64::new(4_000),
    };
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let running = run_from_another_task(&host, &document, "evt-at-the-door");
    door.until_a_launch_arrives().await;
    until("the engine to stop waiting for the node", || {
        node_statuses(&host).last().is_some_and(|status| {
            status != NodeStatus::Pending.as_str() && status != NodeStatus::Running.as_str()
        })
    })
    .await;
    door.let_through();
    let run: WorkflowRunResult = typed(
        &running
            .await
            .expect("the run answers")
            .expect("the run is answered"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Cancelled, "{run:?}");
    assert_eq!(
        node_statuses(&host),
        [settles.as_str()],
        "what the node settles as is the runner's answer to the request to stop"
    );
    until("the refused launch to have failed its reservation", || {
        reservation_phases(&host, grant_id(number)) == ["failed"]
    })
    .await;
    // The platform started a worker and the reservation failed with no claim committed, so the
    // worker was not admitted and then reported failed, and the launch did not fail before it
    // started.
    assert_eq!(door.workers_started(), 1, "a worker was started");
    assert_eq!(
        reservation_claims(&host, grant_id(number)),
        [false],
        "no claim of the worker was committed"
    );
    assert!(!marker.exists(), "the command never ran");
    assert!(
        all_sessions(&mut control)
            .await
            .iter()
            .all(|session| session.closure.0.is_some()),
        "no session is live"
    );
    host.clients.abort();
}

/// KR-REQ-25.14 and KR-REQ-25.19: a `create_session` node whose admission passed cannot be
/// stopped, so its wait ending at the door leaves it unknown, and the claim that follows makes no
/// session. The control is the case below, a command, which is stopped and so settles cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_wait_that_ends_at_the_door_leaves_a_created_session_unknown_and_makes_none() {
    a_wait_that_ends_at_the_door_makes_no_session(
        39,
        &[ActionRight::SessionCreate],
        |host, _| create_session_node(host, None),
        NodeStatus::Unknown,
    )
    .await;
}

/// KR-REQ-25.14 and KR-REQ-25.19: a command whose launch waits at the door when its node's wait
/// ends is stopped, settles cancelled, and never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_wait_that_ends_at_the_door_cancels_a_command_that_never_runs() {
    a_wait_that_ends_at_the_door_makes_no_session(
        40,
        &COMMAND_RIGHTS,
        |host, marker| command_node(host, "command", &format!("touch {}", marker.display())),
        NodeStatus::Cancelled,
    )
    .await;
}

/// KR-REQ-25.19: a `create_session` node whose session passed its admission cannot be stopped. The
/// worker's claim is committed, the node's wait ends while the rendezvous waits there, and the
/// node settles unknown; the session comes into being once the rendezvous goes on, and stays:
/// nothing closes a session a node created.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_created_session_is_kept_when_its_node_is_asked_to_stop_after_its_admission() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(33), &[ActionRight::SessionCreate]);
    let mut document = definition(
        workflow_id(33),
        grant_id(33),
        "a session",
        create_session_node(&host, None),
    );
    // Long enough for the worker to claim its launch under load, and short enough to end while the
    // rendezvous is held.
    document.deadlines = WorkflowDeadlines {
        run_deadline_ms: U64::new(120_000),
        action_wait_ms: U64::new(15_000),
    };
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let (claimed, resume) = host.controller.pause_rendezvous_after_claim();
    let running = run_from_another_task(&host, &document, "evt-held");
    tokio::time::timeout(std::time::Duration::from_secs(60), claimed)
        .await
        .expect("the worker claimed its launch")
        .expect("the worker's claim was committed");
    until("the node's wait to end", || {
        node_statuses(&host) == [NodeStatus::Unknown.as_str()]
    })
    .await;
    resume.send(()).expect("the rendezvous goes on");
    let _ = running.await;

    let until_live = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let session = loop {
        let sessions = all_sessions(&mut control).await;
        if let Some(session) = sessions.into_iter().find(|session| {
            session.closure.0.is_none() && session.state == kr_protocol::session::SessionState::Live
        }) {
            break session;
        }
        assert!(
            std::time::Instant::now() < until_live,
            "the session came into being"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert_eq!(session.root, None);
    assert_eq!(owed_rows(&host), 0, "the node owns nothing to release");
    host.clients.abort();
}

/// A daemon with real sessions whose configuration document names `suites` (a name, its command,
/// and the output paths it declares), started before anything else is done.
async fn working_host_with_suites(suites: &[(&str, &str, &[&str])]) -> Host {
    let temp = teardown::Tree::create();
    let worker = temp.root().join("kr-worker");
    kr_ipc::testing::place_and_start_once(&beside_this_test("kr-worker"), &worker, &["--version"]);
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.automation.test_suites = kr_protocol::scalars::Nullable::some(
        suites
            .iter()
            .map(|(name, command, outputs)| {
                (
                    (*name).to_owned(),
                    kr_protocol::hostinfo::configuration::TestSuite {
                        command: (*command).to_owned(),
                        outputs: outputs.iter().map(|path| (*path).to_owned()).collect(),
                    },
                )
            })
            .collect(),
    );
    write_configuration(&temp.environment(), &document);
    working_host_on(temp, |supervisor| supervisor).await
}

/// Captures the workspace into a version, through a workflow run, and returns the version.
async fn captured(
    control: &mut LocalClient,
    host: &Host,
    workspace: WorkspaceId,
    number: u8,
) -> kr_protocol::changeset::VersionRef {
    host.issue(grant_id(number), &[ActionRight::ChangesetCreate]);
    let document = definition(
        workflow_id(number),
        grant_id(number),
        "a capture",
        capture_node(workspace),
    );
    install(control, host, &document).await;
    enable(control, host, &document).await;
    let run: WorkflowRunResult = typed(
        &start(control, host, &document, "evt-capture")
            .await
            .expect("the capture runs"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    match receipts_of(control, &document, run.run_id).await[0]
        .output
        .0
        .clone()
    {
        Some(kr_protocol::automation::NodeOutput::CaptureChangeset { version }) => version,
        other => panic!("a capture names its version, not {other:?}"),
    }
}

/// Runs a `run_tests` node for `suite` against `version`, and answers the run, its node and the
/// version as the daemon reads it afterwards.
async fn tests_run(
    control: &mut LocalClient,
    host: &Host,
    number: u8,
    suite: &str,
    version: kr_protocol::changeset::VersionRef,
) -> (
    WorkflowRunResult,
    kr_protocol::automation::NodeReceiptSummary,
    kr_protocol::changeset::ChangesetReadResult,
) {
    tests_run_within(control, host, number, suite, version, None).await
}

/// [`tests_run`] with the deadlines the definition names, where it names any.
async fn tests_run_within(
    control: &mut LocalClient,
    host: &Host,
    number: u8,
    suite: &str,
    version: kr_protocol::changeset::VersionRef,
    deadlines: Option<WorkflowDeadlines>,
) -> (
    WorkflowRunResult,
    kr_protocol::automation::NodeReceiptSummary,
    kr_protocol::changeset::ChangesetReadResult,
) {
    host.issue(grant_id(number), &COMMAND_RIGHTS);
    let mut document = definition(
        workflow_id(number),
        grant_id(number),
        "tests",
        WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: serde_json::to_string(&kr_protocol::automation::RunTestsParams {
                suite: suite.to_owned(),
                version,
            })
            .expect("a test node's typed parameters"),
            declared_environment: Nullable::some(host.environment_id),
        },
    );
    if let Some(deadlines) = deadlines {
        document.deadlines = deadlines;
    }
    install(control, host, &document).await;
    enable(control, host, &document).await;
    let run: WorkflowRunResult = typed(
        &start(control, host, &document, "evt-tests")
            .await
            .expect("the run is admitted"),
    );
    let receipt = receipts_of(control, &document, run.run_id).await.remove(0);
    until("what the tests owned to be released", || {
        owed_rows(host) == 0
    })
    .await;
    (run, receipt, version_as_read(control, version).await)
}

/// A version as `changeset.read` answers for it: its results and the evidence against it.
async fn version_as_read(
    control: &mut LocalClient,
    version: kr_protocol::changeset::VersionRef,
) -> kr_protocol::changeset::ChangesetReadResult {
    typed(
        &control
            .request(
                Method::ChangesetRead,
                &kr_protocol::changeset::ChangesetReadParams {
                    change_set_id: version.change_set_id,
                    version: Nullable::some(version.version),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.read succeeds"),
    )
}

/// KR-REQ-25.20 and KR-REQ-25.14: a suite that passes against a version succeeds, and the host
/// records what it observed: the session the suite ran in, its exit status, and that the copy it
/// ran in still held exactly the version. The edit a person makes in the main workspace after the
/// capture changes neither the version nor its copy, and a capture after it is a later version; the
/// evidence stays against the earlier one. The copy is released once the session has closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_suite_that_passes_against_a_version_is_recorded_as_the_host_observed_it() {
    let host = working_host_with_suites(&[(
        "passes",
        "grep -q 'changed after the commit' README.md",
        &[],
    )])
    .await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    let version = captured(&mut control, &host, workspace, 60).await;

    // The person goes on working: the copy the suite runs in is the version, not the tree.
    std::fs::write(
        host.work().join("source/README.md"),
        "edited after the capture\n",
    )
    .expect("an edit in the main workspace");

    let (run, receipt, read) = tests_run(&mut control, &host, 61, "passes", version).await;
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    assert_eq!(receipt.status, NodeStatus::Success, "{receipt:?}");
    assert_eq!(
        receipt.output.0,
        Some(kr_protocol::automation::NodeOutput::RunTests {
            suite: "passes".to_owned(),
            version,
        })
    );
    assert_eq!(read.results.len(), 1, "{read:?}");
    let result = &read.results[0];
    assert_eq!(result.tested_source, TestedSource::UnmodifiedVersion);
    assert_eq!(result.tested_version.0, Some(version));
    assert_eq!(result.receipt.exit_status.0, Some(U64::new(0)));
    assert!(
        result.receipt.detail.contains(&run.run_id.to_string())
            && result.receipt.detail.contains("session"),
        "the result names the session, the run and the node it was observed in: {result:?}"
    );
    let command = "grep -q 'changed after the commit' README.md";
    assert!(
        result.profile.contains(&kr_changeset::objects::hex_of(
            kr_changeset::objects::digest_of(command.as_bytes())
        )),
        "the result names the command that ran by its digest: {}",
        result.profile
    );
    assert!(
        !result.profile.contains("grep"),
        "and never by its text: {}",
        result.profile
    );
    assert!(
        read.evidence.iter().any(|evidence| evidence.kind
            == kr_protocol::changeset::EvidenceKind::TestResult
            && evidence.detail.contains("exited with status 0")),
        "{:?}",
        read.evidence
    );
    assert!(
        read.materialisations
            .iter()
            .all(|copy| copy.released_at_ms.0.is_some()),
        "the copy was released: {:?}",
        read.materialisations
    );

    // The edit is a later version, and the evidence stays against the version the suite ran on.
    host.issue(grant_id(62), &[ActionRight::ChangesetCreate]);
    let later = definition(
        workflow_id(62),
        grant_id(62),
        "a later capture",
        capture_node(workspace),
    );
    install(&mut control, &host, &later).await;
    enable(&mut control, &host, &later).await;
    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &later, "evt-later")
            .await
            .expect("the later capture runs"),
    );
    let Some(kr_protocol::automation::NodeOutput::CaptureChangeset { version: second }) =
        receipts_of(&mut control, &later, run.run_id).await[0]
            .output
            .0
            .clone()
    else {
        panic!("the later capture names its version");
    };
    assert_ne!(
        second, version,
        "an edit after the capture makes a later version"
    );
    assert!(
        version_as_read(&mut control, second)
            .await
            .evidence
            .iter()
            .all(|evidence| evidence.kind != kr_protocol::changeset::EvidenceKind::TestResult),
        "the tests are evidence about the version they ran on and not the later one"
    );
    host.clients.abort();
}

/// KR-REQ-25.20: a suite that fails is a failed node with its status, and the host records the
/// status it observed. A caller's word that tests passed is nowhere in the path. A suite the
/// configuration does not name fails the node before anything is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_suite_that_fails_is_recorded_with_the_status_the_host_observed() {
    let host =
        working_host_with_suites(&[("fails", "exit 3", &[]), ("killed", "kill -KILL $$", &[])])
            .await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    let version = captured(&mut control, &host, workspace, 63).await;

    let (run, receipt, read) = tests_run(&mut control, &host, 64, "fails", version).await;
    assert_eq!(run.status, WorkflowRunStatus::Failed, "{run:?}");
    assert_eq!(receipt.status, NodeStatus::Failed, "{receipt:?}");
    assert_eq!(read.results.len(), 1, "{read:?}");
    assert_eq!(read.results[0].receipt.exit_status.0, Some(U64::new(3)));
    assert!(
        read.evidence.iter().any(|evidence| evidence.kind
            == kr_protocol::changeset::EvidenceKind::TestResult
            && evidence.detail.contains("exited with status 3")
            && !evidence.detail.contains("passed")),
        "{:?}",
        read.evidence
    );

    // A suite a signal ended is a failed node, whatever the copy holds, and the result says that
    // something stopped it and that it had no status.
    let (run, receipt, read) = tests_run(&mut control, &host, 69, "killed", version).await;
    assert_eq!(run.status, WorkflowRunStatus::Failed, "{run:?}");
    assert_eq!(receipt.status, NodeStatus::Failed, "{receipt:?}");
    let killed = read
        .results
        .iter()
        .find(|result| result.command == "killed")
        .expect("the signal is recorded as the host observed it");
    assert!(killed.receipt.stopped && killed.receipt.exit_status.0.is_none());
    assert!(
        read.evidence
            .iter()
            .any(|evidence| evidence.detail.contains("was ended by signal")),
        "{:?}",
        read.evidence
    );

    let sessions_before = all_sessions(&mut control).await.len();
    let (run, receipt, read) = tests_run(&mut control, &host, 65, "no-such-suite", version).await;
    assert_eq!(run.status, WorkflowRunStatus::Failed, "{run:?}");
    assert_eq!(receipt.status, NodeStatus::Failed, "{receipt:?}");
    assert_eq!(read.results.len(), 2, "no further result: {read:?}");
    assert_eq!(
        all_sessions(&mut control).await.len(),
        sessions_before,
        "a suite the configuration does not name makes no session"
    );
    host.clients.abort();
}

/// KR-REQ-25.20 and KR-REQ-25.19: a suite that outlives the node's wait is asked to stop and its
/// session is closed, and a suite that was stopped has no result to record: nothing is recorded
/// against the version, the node is cancelled, and the copy it ran in is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_suite_that_outlives_its_wait_is_stopped_and_records_no_result() {
    let host = working_host_with_suites(&[("long", "sleep 120", &[])]).await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    let version = captured(&mut control, &host, workspace, 70).await;

    let (_, receipt, read) = tests_run_within(
        &mut control,
        &host,
        71,
        "long",
        version,
        Some(WorkflowDeadlines {
            run_deadline_ms: U64::new(120_000),
            action_wait_ms: U64::new(15_000),
        }),
    )
    .await;
    assert_eq!(receipt.status, NodeStatus::Cancelled, "{receipt:?}");
    // The suite had started: its session was closed because its node was asked to stop.
    let sessions = all_sessions(&mut control).await;
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    let closed = closed_session(&mut control, sessions[0].session_id).await;
    assert_eq!(
        closed.closure.0.expect("closed").reason,
        kr_protocol::session::ClosureReason::CloseRequested
    );
    assert!(
        read.results.is_empty(),
        "a suite that was stopped attests nothing: {read:?}"
    );
    assert!(
        read.evidence
            .iter()
            .all(|evidence| evidence.kind != kr_protocol::changeset::EvidenceKind::TestResult),
        "{:?}",
        read.evidence
    );
    assert!(
        read.materialisations
            .iter()
            .all(|copy| copy.released_at_ms.0.is_some()),
        "the copy was released: {:?}",
        read.materialisations
    );
    host.clients.abort();
}

/// KR-REQ-25.20: a suite that writes where it declares output attests the version it ran on, with
/// the output as a reference; one that writes anywhere else has changed the source, so its pass
/// attests nothing and the node is left unknown with the version the copy held recorded beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_suite_that_writes_only_its_declared_output_still_attests_the_version() {
    let host = working_host_with_suites(&[
        (
            "builds",
            "mkdir -p build/out && echo built > build/out/artefact",
            &["build/out"],
        ),
        (
            "strays",
            "mkdir -p build/out && echo built > build/out/artefact && echo stray > stray.txt",
            &["build/out"],
        ),
    ])
    .await;
    let mut control = client(&host).await;
    let workspace = adopted_workspace(&mut control, host.environment_id, host.work()).await;
    let version = captured(&mut control, &host, workspace, 66).await;

    let (run, receipt, read) = tests_run(&mut control, &host, 67, "builds", version).await;
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    assert_eq!(receipt.status, NodeStatus::Success, "{receipt:?}");
    assert_eq!(
        read.results[0].tested_source,
        TestedSource::UnmodifiedVersion
    );
    assert!(
        read.results[0]
            .outputs
            .iter()
            .any(|output| output.label == "build/out" && output.kind == "directory listing"),
        "{:?}",
        read.results[0].outputs
    );

    let (_, receipt, read) = tests_run(&mut control, &host, 68, "strays", version).await;
    assert_eq!(receipt.status, NodeStatus::Unknown, "{receipt:?}");
    let result = read
        .results
        .iter()
        .find(|result| result.tested_source == TestedSource::Indeterminate)
        .expect("the second run is recorded as indeterminate");
    assert!(result.derived_output_version.0.is_some());
    assert_eq!(result.tested_version.0, None, "it attests no version");
    host.clients.abort();
}

/// KR-REQ-25.14 and KR-REQ-24.10: a command that is running when the daemon stops is
/// not forgotten. The node it belonged to settles unknown, nothing runs it again, and the new
/// daemon's sweep finds what the dispatch wrote down, closes the session, removes the directory the
/// command ran in and releases the row, without waiting for the run to end. A `create_session`
/// node's session, which no sweep owns, is there after the restart as it was before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_command_a_stopped_daemon_left_running_is_closed_and_released_by_the_next_one() {
    let (host, apart) = working_host_apart().await;
    let mut control = client(&host).await;
    host.issue(grant_id(26), &COMMAND_RIGHTS);
    host.issue(grant_id(27), &[ActionRight::SessionCreate]);

    // A session a node created and left running.
    let created = definition(
        workflow_id(27),
        grant_id(27),
        "a session",
        create_session_node(&host, None),
    );
    install(&mut control, &host, &created).await;
    enable(&mut control, &host, &created).await;
    let made: WorkflowRunResult = typed(
        &start(&mut control, &host, &created, "evt-session")
            .await
            .expect("the run is admitted"),
    );
    let Some(kr_protocol::automation::NodeOutput::CreateSession { session_id: kept }) =
        receipts_of(&mut control, &created, made.run_id).await[0]
            .output
            .0
            .clone()
    else {
        panic!("the node names its session");
    };

    // A command that runs far longer than this test.
    let long = definition(
        workflow_id(26),
        grant_id(26),
        "a long command",
        command_node(&host, "long", "sleep 600"),
    );
    install(&mut control, &host, &long).await;
    enable(&mut control, &host, &long).await;
    let running = run_from_another_task(&host, &long, "evt-long");
    let command_session = {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let live = all_sessions(&mut control).await;
            if let Some(session) = live.into_iter().find(|session| {
                session.root == Some(kr_protocol::session::SessionRoot::Command)
                    && session.closure.0.is_none()
            }) {
                break session.session_id;
            }
            assert!(std::time::Instant::now() < until, "the command's session");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    };
    assert_eq!(owed_rows(&host), 1, "the dispatch wrote down what it owns");
    // The dispatch wrote down its session's worker. A dispatch that ended before it had is the
    // same row without the worker, and the next daemon's sweep takes the worker from the registry,
    // which keeps the process the launcher started.
    let ledger = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::resources::RESOURCES_DB_NAME),
    )
    .expect("opens the resource ledger");
    let worker_of_the_row = || -> Option<String> {
        ledger
            .query_row("SELECT worker_process FROM owned", [], |row| row.get(0))
            .expect("reads the row")
    };
    assert!(
        worker_of_the_row().is_some(),
        "the dispatch wrote its session's worker down"
    );
    let boot: Option<String> = ledger
        .query_row("SELECT boot FROM owned", [], |row| row.get(0))
        .expect("reads the row");
    assert!(
        boot.is_some(),
        "the dispatch wrote the boot it began in down"
    );
    ledger
        .execute("UPDATE owned SET worker_process = NULL", [])
        .expect("the row loses its worker");
    drop(control);

    let host = restarted(host, apart).await;
    running.abort();
    let mut control = client(&host).await;
    let closed = closed_session(&mut control, command_session).await;
    assert_eq!(
        closed.closure.0.expect("closed").reason,
        kr_protocol::session::ClosureReason::CloseRequested,
        "the sweep of the next daemon closed it"
    );
    until("the sweep to release what the command owned", || {
        owed_rows(&host) == 0
    })
    .await;
    assert!(
        worker_of_the_row().is_some(),
        "the sweep took the worker from the registry before it released the row"
    );
    let scratch = host
        ._temp
        .environment()
        .state_dir()
        .join("workflow-scratch");
    assert!(
        std::fs::read_dir(&scratch).map_or(true, |mut entries| entries.next().is_none()),
        "the directory the command ran in is gone"
    );
    let sessions = all_sessions(&mut control).await;
    let still = sessions
        .iter()
        .find(|session| session.session_id == kept)
        .expect("the created session is listed");
    assert!(
        still.closure.0.is_none(),
        "a session a create_session node made is not any sweep's to close: {still:?}"
    );
    host.clients.abort();
}

/// KR-REQ-19.04 and KR-REQ-25.14: a session a workflow starts is held to its grant's own end where
/// its process is created, whatever the node's wait still allows. The grant ends while the worker's
/// rendezvous is held after its claim, which the grant still stood at, and the worker, going on,
/// creates no process: a command leaves no mark, a shell a `create_session` node names starts none,
/// and the reservation fails. The control is a grant with no end, whose command starts through the
/// same hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_session_does_not_start_after_its_grants_end_though_its_wait_has_time_left() {
    let host = working_host().await;
    let mut control = client(&host).await;
    let local = kr_protocol::ids::DeviceId::new(host.environment_id.get());
    for (number, ends, shell) in [(50_u8, true, false), (51, false, false), (55, true, true)] {
        let ends_at = kr_ipc::now_ms().get() + 20_000;
        issue_grant(
            &host,
            grant_id(number),
            local,
            &COMMAND_RIGHTS,
            if ends {
                GrantExpiry::At {
                    expires_at_ms: kr_protocol::scalars::TimestampMs::new(ends_at),
                }
            } else {
                GrantExpiry::Never
            },
        );
        let marker = host.work().join(format!("a-command-ran-{number}"));
        let node = if shell {
            create_session_node(&host, Some("/bin/sh"))
        } else {
            command_node(&host, "command", &format!("touch {}", marker.display()))
        };
        let mut document = definition(workflow_id(number), grant_id(number), "a node", node);
        document.deadlines = WorkflowDeadlines {
            run_deadline_ms: U64::new(600_000),
            action_wait_ms: U64::new(300_000),
        };
        install(&mut control, &host, &document).await;
        enable(&mut control, &host, &document).await;

        let (claimed, resume) = host.controller.pause_rendezvous_after_claim();
        let running = run_from_another_task(&host, &document, "evt-grant-end");
        tokio::time::timeout(std::time::Duration::from_secs(60), claimed)
            .await
            .expect("the worker claimed its launch")
            .expect("the worker's claim was committed");
        if ends {
            until("the grant's end to pass", || {
                kr_ipc::now_ms().get() > ends_at
            })
            .await;
        }
        resume.send(()).expect("the rendezvous goes on");
        let _ = running.await;

        if ends {
            until("the refused start to have failed its reservation", || {
                reservation_phases(&host, grant_id(number)) == ["failed"]
            })
            .await;
            let settled = node_statuses(&host);
            assert_eq!(
                settled.last().map(String::as_str),
                Some(NodeStatus::Paused.as_str()),
                "the worker's refusal to start pauses the node: {settled:?}"
            );
            assert!(
                !marker.exists(),
                "no process was created after the grant's end"
            );
            assert!(
                all_sessions(&mut control)
                    .await
                    .iter()
                    .all(|session| session.closure.0.is_some()),
                "no session is live"
            );
        } else {
            let sessions = all_sessions(&mut control).await;
            let session = sessions
                .iter()
                .max_by_key(|session| session.display_number.get())
                .expect("the command's session");
            let closed = closed_session(&mut control, session.session_id).await;
            assert_eq!(
                closed.closure.0.expect("closed").reason,
                kr_protocol::session::ClosureReason::RootExit
            );
            assert!(marker.exists(), "a grant with no end let the command run");
        }
    }
    until("what each dispatch owned to be released", || {
        owed_rows(&host) == 0
    })
    .await;
    host.clients.abort();
}

/// A run is cancelled while a node's launch waits at the supervisor's door, after the launch
/// transition admitted it. The worker starts, connects and is refused its claim: the node's session
/// is never made, the reservation fails, and what it would have started never starts.
async fn a_run_cancelled_at_the_door_starts_nothing(
    number: u8,
    rights: &[ActionRight],
    node: impl FnOnce(&Host, &Path) -> WorkflowNode,
) {
    let door = Door::shut();
    let host = door.host().await;
    let mut control = client(&host).await;
    let marker = host.work().join("a-command-ran");
    host.issue(grant_id(number), rights);
    let document = definition(
        workflow_id(number),
        grant_id(number),
        "a node",
        node(&host, &marker),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let running = run_from_another_task(&host, &document, "evt-cancelled-at-the-door");
    door.until_a_launch_arrives().await;
    host.controller
        .automation()
        .journal()
        .cancel_run(
            only_run(&host),
            "run cancelled by request",
            kr_ipc::now_ms().get(),
        )
        .expect("the run is cancelled");
    let answered: WorkflowRunResult = typed(
        &running
            .await
            .expect("the run answers")
            .expect("the cancelled run is answered"),
    );
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    door.let_through();

    until("the refused claim to have failed the reservation", || {
        reservation_phases(&host, grant_id(number)) == ["failed"]
    })
    .await;
    assert!(!marker.exists(), "the command never ran");
    assert!(
        all_sessions(&mut control)
            .await
            .iter()
            .all(|session| session.closure.0.is_some()),
        "no session is live"
    );
    until("what the node owned to be released", || {
        owed_rows(&host) == 0
    })
    .await;
    host.clients.abort();
}

/// KR-REQ-25.19: the command of a node whose run was cancelled before its worker's claim never
/// starts. The control is every case that lets a command's launch through the door uncancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_run_cancelled_before_the_worker_claims_its_launch_runs_no_command() {
    a_run_cancelled_at_the_door_starts_nothing(52, &COMMAND_RIGHTS, |host, marker| {
        command_node(host, "command", &format!("touch {}", marker.display()))
    })
    .await;
}

/// KR-REQ-25.19: a `create_session` node whose run was cancelled after its launch transition and
/// before its worker's claim makes no session: the claim is refused, and the node is left unknown
/// because its session had passed its first admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_run_cancelled_before_the_worker_claims_its_launch_creates_no_session() {
    a_run_cancelled_at_the_door_starts_nothing(
        53,
        &[ActionRight::SessionCreate, ActionRight::TerminalInput],
        |host, _| create_session_node(host, Some("/bin/sh")),
    )
    .await;
}

/// The rows of the resource ledger that were released.
fn released_rows(host: &Host) -> i64 {
    let ledger = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::resources::RESOURCES_DB_NAME),
    )
    .expect("opens the resource ledger");
    ledger
        .query_row(
            "SELECT COUNT(*) FROM owned WHERE state = 'released'",
            [],
            |row| row.get(0),
        )
        .expect("counts the released rows")
}

/// KR-REQ-25.19: a run cancelled while its node waits to write down what it will own is not a
/// dispatch that is dropped half way. The engine stops waiting for the node, the node's task goes
/// on once the ledger is free, writes its row, finds it was asked to stop, makes no session and
/// releases the row: nothing stays owed and the command never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_run_cancelled_while_its_node_writes_down_what_it_owns_leaves_nothing_owed() {
    let host = working_host().await;
    let mut control = client(&host).await;
    let marker = host.work().join("a-command-ran");
    host.issue(grant_id(54), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(54),
        grant_id(54),
        "a command",
        command_node(&host, "command", &format!("touch {}", marker.display())),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    // Another writer holds the ledger, so the node's row waits for it.
    let ledger = rusqlite::Connection::open(
        host._temp
            .environment()
            .state_dir()
            .join(kr_automation::resources::RESOURCES_DB_NAME),
    )
    .expect("opens the resource ledger");
    ledger
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the ledger");
    let running = run_from_another_task(&host, &document, "evt-cancelled-at-the-ledger");
    until("the node to be running", || {
        node_statuses(&host) == [NodeStatus::Running.as_str()]
    })
    .await;
    host.controller
        .automation()
        .journal()
        .cancel_run(
            only_run(&host),
            "run cancelled by request",
            kr_ipc::now_ms().get(),
        )
        .expect("the run is cancelled");
    let answered: WorkflowRunResult = typed(
        &running
            .await
            .expect("the run answers")
            .expect("the cancelled run is answered"),
    );
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    ledger
        .execute_batch("COMMIT")
        .expect("the other writer finishes");

    until(
        "the node's task to have written its row and released it",
        || released_rows(&host) == 1,
    )
    .await;
    assert_eq!(owed_rows(&host), 0, "nothing stays owed");
    assert!(!marker.exists(), "the command never ran");
    assert!(
        all_sessions(&mut control)
            .await
            .iter()
            .all(|session| session.closure.0.is_some()),
        "no session is live"
    );
    host.clients.abort();
}

/// KR-REQ-25.14 and KR-REQ-25.19: a close that finds no worker to ask is asked again. A worker
/// that was claimed and then reported itself after its create had given up (the node settled
/// unknown) is not in the directory while the sweep first looks; the sweep must not take that look
/// for a close, and must close the session once the worker has reported. The command runs far
/// longer than the case, so only a close ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_session_whose_worker_reports_after_its_node_gave_up_is_closed_by_the_sweep() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(56), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(56),
        grant_id(56),
        "a long command",
        command_node(&host, "long", "sleep 600"),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;

    let (claimed, resume) = host.controller.pause_rendezvous_after_claim();
    let running = run_from_another_task(&host, &document, "evt-late-worker");
    tokio::time::timeout(std::time::Duration::from_secs(60), claimed)
        .await
        .expect("the worker claimed its launch")
        .expect("the worker's claim was committed");
    // The create gives up on a worker that does not report, and the node settles unknown.
    until("the dispatch to give up waiting for the worker", || {
        node_statuses(&host) == [NodeStatus::Unknown.as_str()]
    })
    .await;
    // The sweep looks while the worker has not reported: nobody is in the directory to ask.
    let looked = host.controller.automation().sweep_passes();
    until("the sweep to look twice after the node settled", || {
        host.controller.automation().sweep_passes() >= looked + 2
    })
    .await;
    let session_id = all_sessions(&mut control)
        .await
        .first()
        .expect("the session the node left")
        .session_id;
    resume.send(()).expect("the worker goes on and reports");
    let _ = running.await;

    let closed = closed_session(&mut control, session_id).await;
    assert_eq!(
        closed.closure.0.expect("closed").reason,
        kr_protocol::session::ClosureReason::CloseRequested,
        "the sweep closed it once the worker had reported"
    );
    until("the sweep to release what the command owned", || {
        owed_rows(&host) == 0
    })
    .await;
    host.clients.abort();
}

/// KR-REQ-25.14: a tree the removal will not take does not keep its row owed. A command that
/// leaves a chain of directories deeper than the removal holds handles for ends normally; its
/// node succeeds, the row is released, and the tree stays where it is, to be looked at.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_tree_the_removal_will_not_take_leaves_its_row_released() {
    let host = working_host().await;
    let mut control = client(&host).await;
    host.issue(grant_id(57), &COMMAND_RIGHTS);
    let document = definition(
        workflow_id(57),
        grant_id(57),
        "a deep tree",
        command_node(
            &host,
            "deep",
            &format!("mkdir -p {}", vec!["a"; 140].join("/")),
        ),
    );
    install(&mut control, &host, &document).await;
    enable(&mut control, &host, &document).await;
    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-deep")
            .await
            .expect("the run is admitted"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");

    until("the row to be released although its tree stays", || {
        released_rows(&host) == 1
    })
    .await;
    assert_eq!(owed_rows(&host), 0, "nothing is owed");
    let scratch = host
        ._temp
        .environment()
        .state_dir()
        .join("workflow-scratch");
    assert!(
        std::fs::read_dir(&scratch).is_ok_and(|mut entries| entries.next().is_some()),
        "the tree the removal would not take is still there"
    );
    host.clients.abort();
}
