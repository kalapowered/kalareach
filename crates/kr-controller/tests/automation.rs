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
    NodeStatus, WorkflowDeadlines, WorkflowDefinition, WorkflowEnableParams, WorkflowEnableResult,
    WorkflowInstallParams, WorkflowInstallResult, WorkflowNode, WorkflowPauseParams,
    WorkflowPauseResult, WorkflowReadParams, WorkflowReadResult, WorkflowResourceScope,
    WorkflowRunParams, WorkflowRunResult, WorkflowRunStatus, WorkflowTrigger,
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

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
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

    fn destination(&self, name: &str) -> DestinationRequest {
        DestinationRequest {
            environment_id: self.environment_id,
            parent: DestinationParent::Host {
                path: self.work().display().to_string(),
            },
            name: name.to_owned(),
        }
    }

    /// Writes one live grant into this daemon's own grant store.
    ///
    /// A definition names a grant and the host reads it from here, so a test that installs one
    /// puts the grant in first, exactly as a person sharing a session would have.
    fn issue(&self, grant_id: GrantId, rights: &[ActionRight]) -> Grant {
        let device_id = kr_protocol::ids::DeviceId::new(self.environment_id.get());
        let grant = Grant {
            grant_id,
            parent_grant_id: Nullable::null(),
            issuer_device_id: device_id,
            recipient_device_id: device_id,
            authority_revision: AuthorityRevision::new(1),
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
            .issue(&GrantRecord {
                grant: grant.clone(),
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            })
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let controller = loop {
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
            Ok(controller) => break controller,
            Err(error) if std::time::Instant::now() < deadline => {
                assert!(
                    matches!(
                        error,
                        kr_controller::error::ControllerError::AlreadyRunning { .. }
                    ),
                    "the daemon starts: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(error) => panic!("the daemon starts: {error}"),
        }
    };
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

async fn client(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the control endpoint")
}

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(value: &ParamsValue) -> T {
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
            criteria: Nullable::null(),
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
        action_kind: "capture_changeset".to_owned(),
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
                causal_parent: Nullable::null(),
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
    let _source = repository(host.work(), "source");

    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectAdoptParams {
                    destination: host.destination("source"),
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
                ActionTarget::environment(host.environment_id),
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
    let workspace = created
        .workspace
        .0
        .expect("a creation returns the workspace")
        .workspace_id;

    host.issue(grant_id(1), &[ActionRight::ChangesetCreate]);
    let document = definition(
        workflow_id(1),
        grant_id(1),
        "capture-on-trigger",
        capture_node(workspace),
    );

    let installed = install(&mut control, &host, &document).await;
    assert_eq!(installed.revision.get(), 1);

    // A revision installs disabled, whatever the document said, because enabling is its own
    // authorised method.
    let refused = failure(start(&mut control, &host, &document, "evt-before-enable").await);
    assert_eq!(refused.code, ErrorCode::PluginDisabled, "{refused:?}");

    let enabled = enable(&mut control, &host, &document).await;
    assert!(enabled.enabled);

    let run: WorkflowRunResult = typed(
        &start(&mut control, &host, &document, "evt-1")
            .await
            .expect("workflow.run succeeds"),
    );
    assert_eq!(run.status, WorkflowRunStatus::Completed, "{run:?}");
    assert_eq!(run.depth.get(), 1, "an external trigger starts a chain");

    // The same event again is one trigger arriving twice, and it produces no second run.
    let repeat = failure(start(&mut control, &host, &document, "evt-1").await);
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
    assert!(captured.contains("captured change set"), "{captured}");

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
    let after_pause = failure(start(&mut control, &host, &document, "evt-2").await);
    assert_eq!(
        after_pause.code,
        ErrorCode::PluginDisabled,
        "{after_pause:?}"
    );

    host.clients.abort();
}

/// Reads the change-set identifier out of what the capture node reported.
fn first_change_set(output: &str) -> kr_protocol::ids::ChangeSetId {
    let identifier = output
        .split_whitespace()
        .nth(3)
        .expect("the receipt names the change set");
    kr_protocol::ids::ChangeSetId::new(identifier.parse::<Uuid>().expect("a change-set identifier"))
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
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "unit"}"#.to_owned(),
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
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "unit"}"#.to_owned(),
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
