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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::grants::GrantRecord;
use kr_controller::service::{Controller, ControllerSetup};
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
    ChangesetCaptureParams, ChangesetReadParams, ChangesetReadResult, FileGrant,
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
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
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
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let controller = start_daemon(&environment, environment_id)
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
        work: tempfile::TempDir::new().expect("a working directory on the internal disk"),
    }
}

/// Starts a daemon on an environment, waiting out one that is still letting go of it.
async fn start_daemon(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
) -> kr_controller::error::Result<Arc<Controller>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let secrets = environment.secrets_dir();
        let attempt = Controller::start(ControllerSetup {
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
        .await;
        match attempt {
            Err(kr_controller::error::ControllerError::AlreadyRunning { .. })
                if std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            answered => return answered,
        }
    }
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

    host.issue(grant_id(2), &[ActionRight::TerminalInput]);
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

/// A node whose kind this host cannot carry out fails. It never reports success for work nobody
/// did, and it never reports an outcome nobody can establish either: nothing was dispatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_this_host_cannot_carry_out_fails_rather_than_succeeding() {
    let host = host().await;
    let mut control = client(&host).await;

    host.issue(grant_id(3), &[ActionRight::TerminalInput]);
    let document = definition(
        workflow_id(3),
        grant_id(3),
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

    host.issue(grant_id(4), &[ActionRight::TerminalInput]);
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

    host.issue(grant_id(5), &[ActionRight::TerminalInput]);
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

    let mut grant = host.issue(grant_id(6), &[ActionRight::TerminalInput]);
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

/// Reads the runs of one workflow until one appears or ten seconds have passed.
async fn first_run_of(
    control: &mut LocalClient,
    document: &WorkflowDefinition,
) -> Option<kr_protocol::automation::WorkflowRunSummary> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
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
            return Some(run);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
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
    host.issue(grant_id(9), &[ActionRight::TerminalInput]);
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

    let descendant = first_run_of(&mut control, &tests)
        .await
        .expect("the daemon started the triggered workflow");
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
            actions: [ActionRight::TerminalInput].into_iter().collect(),
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
    )
    .expect("the grant stands before it expires");
    standing_at_dispatch(
        &record,
        &mut policy,
        environment_id,
        ActorIngress::LocalIpc,
        201,
    )
    .expect_err("the grant has expired");
    assert_eq!(policy.utc_floor_ms(), 201, "the refusal raised the floor");
    standing_at_dispatch(
        &record,
        &mut policy,
        environment_id,
        ActorIngress::LocalIpc,
        199,
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

    module.start();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while dispatched_to(module.journal()).is_none_or(|position| position < pending) {
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

/// A start that does not pass its configuration gate executes nothing a stopped daemon left
/// behind. The document it has to put into force withdraws authority and owes a fence, the
/// registry cannot raise it, and the start fails; the trigger left pending in the journal is
/// still pending afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_fails_at_its_configuration_gate_dispatches_nothing() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // A first start makes the registry and the journal; then the daemon stops.
    drop(
        start_daemon(&environment, environment_id)
            .await
            .unwrap_or_else(|error| panic!("the first start: {error}")),
    );
    let pending = trigger_left_pending(environment.state_dir(), environment_id).await;
    let registry = refuse_fences(&environment);
    write_configuration(
        &environment,
        &narrowing_document(&[ActionRight::SessionView]),
    );

    let Err(refused) = start_daemon(&environment, environment_id).await else {
        panic!("the start does not pass its configuration gate");
    };
    assert!(
        refused.to_string().contains("could not be put into force"),
        "{refused}"
    );
    // The dispatcher of a daemon that had started executing would have read the pending event
    // by now; give a dispatcher left behind the time it would need.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
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
        net_support::proposal(&[ActionRight::AutomationManage, ActionRight::TerminalInput]),
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
                    actions: [ActionRight::TerminalInput].into_iter().collect(),
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
/// on, as it holds a device's own request. A decision taken after the wall clock was wound back
/// reads UTC inside the bound again, and is refused all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workflow_grant_is_held_to_the_offline_bound_on_the_continuous_clock() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;

    let host = host().await;
    let synchronised = kr_ipc::now_ms().get();
    host.controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(200),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(
                    synchronised,
                )),
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
    grants
        .grant(grant.grant_id, synchronised)
        .expect("inside the bound");

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // The wall clock has been wound back five seconds. With the floor this host holds, UTC is
    // still inside the bound.
    let refused = grants
        .grant(grant.grant_id, synchronised - 5_000)
        .expect_err("the bound ran out on the continuous clock");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("offline")),
        "{refused}"
    );

    host.clients.abort();
}

/// A deadline that passes while a workflow's decision waits for storage is decided after the wait.
/// A refusal left its clock floor owed, and storage is held while the next decision writes it. The
/// offline bound runs out during that wait, so the decision that follows it is a refusal rather
/// than the permission the clock gave before the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_that_passes_while_the_floor_is_written_is_decided_after_the_write() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;

    let host = host().await;
    let environment = host._temp.environment();
    let synchronised = kr_ipc::now_ms().get();
    host.controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(400),
                last_synchronised_at_ms: Nullable::some(kr_protocol::scalars::TimestampMs::new(
                    synchronised,
                )),
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
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(synchronised - 1),
        },
    );
    let grants = Arc::new(HostGrants::for_daemon(&host.controller));
    grants
        .grant(lasting.grant_id, kr_ipc::now_ms().get())
        .expect("inside the bound");

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
        .grant(expired.grant_id, kr_ipc::now_ms().get() + 50)
        .expect_err("an expired grant is refused");
    assert!(
        matches!(owed, AutomationError::AuthorityUnavailable(_)),
        "{owed}"
    );

    // Storage can take the write again, but another writer holds it while the next decision is
    // taken, for longer than the bound has left.
    registry
        .execute_batch("DROP TRIGGER refuse_policy; BEGIN IMMEDIATE;")
        .expect("storage is held");
    let deciding = {
        let grants = Arc::clone(&grants);
        let reading = kr_ipc::now_ms().get();
        std::thread::spawn(move || grants.grant(lasting.grant_id, reading))
    };
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_expires_while_the_floor_is_written_is_refused_after_the_write() {
    use kr_automation::{AuthoritySource, AutomationError};
    use kr_controller::automation::HostGrants;

    let host = host().await;
    let environment = host._temp.environment();
    let here = kr_protocol::ids::DeviceId::new(host.environment_id.get());
    let now = kr_ipc::now_ms().get();
    let expiring = issue_grant(
        &host,
        grant_id(25),
        here,
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(now + 300),
        },
    );
    let expired = issue_grant(
        &host,
        grant_id(26),
        here,
        &[ActionRight::ChangesetCreate],
        GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(now - 1),
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
        .grant(expired.grant_id, kr_ipc::now_ms().get() + 50)
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
        let reading = kr_ipc::now_ms().get();
        std::thread::spawn(move || grants.grant(expiring.grant_id, reading))
    };
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    registry
        .execute_batch("ROLLBACK;")
        .expect("storage is free");
    let refused = deciding
        .join()
        .expect("the decision returns")
        .expect_err("the grant expired while the decision waited for storage");
    assert!(
        matches!(&refused, AutomationError::PermissionDenied(detail) if detail.contains("expired")),
        "{refused}"
    );

    host.clients.abort();
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
