//! The project and workspace methods through the real control daemon.
//!
//! Requirement rows closed here: KR-REQ-14.17 (selecting, creating and cloning repositories
//! through the daemon's own admission path), KR-REQ-14.18 (an idempotent creation and a crash
//! reconciled against the create token), KR-REQ-14.20 (the explicit workspace choice and its
//! inclusion preview), KR-REQ-23.42 and KR-REQ-23.43 (the ten methods under the daemon's
//! authority) and KR-REQ-24.08 (a workspace and its pins surviving the daemon's death).
//!
//! These run the real endpoint, the real handshake, the real envelope checks, real repositories
//! built with installed Git, and — for the kill test — a separate `kr-controller` process copied
//! to the internal disk and ended with a signal where it stands.

mod net_support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, CloneSource, DestinationRequest, InclusionChoice, InclusionClass,
    InclusionPolicy, IsolationMechanism, OperationState, ProjectAdoptParams, ProjectAdoptResult,
    ProjectCloneParams, ProjectCloneResult, ProjectInitParams, ProjectInitResult,
    ProjectListParams, ProjectListResult, ProjectOperationCancelParams,
    ProjectOperationCancelResult, ProjectReadParams, ProjectReadResult, RemoteSpecification,
    RemoteTransport, RetentionPolicy, WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind,
    WorkspaceListParams, WorkspaceListResult, WorkspaceReadParams, WorkspaceReadResult,
    WorkspaceRemoveParams, WorkspaceRemoveResult, WorkspaceState,
};
use kr_protocol::scalars::{Nullable, U64};
use net_support::pairing as calls;

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
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    /// Where the repositories live. Shared, so it outlives a daemon a test replaces.
    work: Arc<tempfile::TempDir>,
}

impl Host {
    /// Ends this daemon the way its process ending would end it.
    ///
    /// Returns the environment and the working directory, so a replacement daemon opens the same
    /// state and finds the same repositories.
    async fn stop(self) -> (kr_ipc::testing::TempHost, Arc<tempfile::TempDir>) {
        self.clients.abort();
        let _ = self.clients.await;
        drop(self.controller);
        (self.temp, self.work)
    }

    fn work(&self) -> &Path {
        self.work.path()
    }

    fn destination(&self, name: &str) -> DestinationRequest {
        DestinationRequest {
            environment_id: self.environment_id,
            parent: kr_protocol::project::DestinationParent::Host {
                path: self.work().display().to_string(),
            },
            name: name.to_owned(),
        }
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host() -> Host {
    host_on(
        kr_ipc::testing::TempHost::create(),
        Arc::new(tempfile::TempDir::new().expect("a working directory on the internal disk")),
    )
    .await
}

async fn host_on(temp: kr_ipc::testing::TempHost, work: Arc<tempfile::TempDir>) -> Host {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // A replacement daemon on the same environment has to wait for the one it replaces to release
    // the singleton lock. The previous daemon's per-connection tasks hold a reference to it, so
    // the release is not instantaneous even after the accept loop is stopped.
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
        temp,
        controller,
        environment_id,
        endpoint,
        clients,
        work,
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

/// A repository with one commit, a dirty file and an untracked one.
fn repository(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir_all(&path).expect("a directory for the repository");
    git_raw(&path, ["init", "--initial-branch=main"]);
    std::fs::write(path.join("README.md"), "a repository\n").expect("a tracked file");
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "the first commit"]);
    std::fs::write(path.join("README.md"), "changed after the commit\n").expect("a dirty file");
    std::fs::write(path.join("notes.txt"), "the user's own untracked file\n")
        .expect("an untracked file");
    path
}

/// KR-REQ-14.17, 14.20, 23.42 and 23.43: the ten methods reach the service through the daemon's
/// own admission path, and each one does what its row says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_project_and_workspace_method_runs_end_to_end_through_the_daemon() {
    let host = host().await;
    let mut control = client(&host).await;
    let source = repository(host.work(), "source");

    // Nothing to begin with, and a list is a scoped read.
    let listed: ProjectListResult = typed(
        &control
            .request(
                Method::ProjectList,
                &ProjectListParams {
                    environment_id: host.environment_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.list succeeds"),
    );
    assert!(listed.projects.is_empty());

    // `project.init` at an absent destination.
    let initialised: ProjectInitResult = typed(
        &control
            .mutate(
                Method::ProjectInit,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectInitParams {
                    destination: host.destination("fresh"),
                    label: "fresh".to_owned(),
                    initial_branch: Nullable::some("main".to_owned()),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.init succeeds"),
    );
    assert_eq!(initialised.operation.state, OperationState::Completed);
    assert!(host.work().join("fresh/.git").is_dir());

    // `project.clone` from a local path.
    let cloned: ProjectCloneResult = typed(
        &control
            .mutate(
                Method::ProjectClone,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectCloneParams {
                    destination: host.destination("cloned"),
                    label: "cloned".to_owned(),
                    source: CloneSource::Remote {
                        remote: RemoteSpecification {
                            remote_name: "origin".to_owned(),
                            transport: RemoteTransport::LocalPath,
                            url: source.display().to_string(),
                            provider: String::new(),
                            credential_broker: String::new(),
                        },
                    },
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.clone succeeds"),
    );
    assert_eq!(cloned.operation.state, OperationState::Completed);
    assert!(host.work().join("cloned/README.md").is_file());

    // `project.adopt` of the checkout the fixture built.
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
    let project = adopted.project.project_repository_id;

    // Three repositories, and `project.read` names one with its operation.
    let listed: ProjectListResult = typed(
        &control
            .request(
                Method::ProjectList,
                &ProjectListParams {
                    environment_id: host.environment_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.list succeeds"),
    );
    assert_eq!(listed.projects.len(), 3);
    let read: ProjectReadResult = typed(
        &control
            .request(
                Method::ProjectRead,
                &ProjectReadParams {
                    project_repository_id: project,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.read succeeds"),
    );
    assert_eq!(read.project.label, "source");
    assert!(read.workspaces.is_empty());

    // `workspace.create` as a preview first: what a reviewer would see, with nothing created.
    let preview_params = WorkspaceCreateParams {
        project_repository_id: project,
        label: "review".to_owned(),
        kind: WorkspaceKind::Isolated,
        isolation: Nullable::some(IsolationMechanism::GitWorktree),
        policy: InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Exclude,
            submodules: InclusionChoice::Exclude,
            binary_files: InclusionChoice::Exclude,
            generated_artefacts: InclusionChoice::Exclude,
        },
        base_revision: Nullable::null(),
        base_change_set_id: Nullable::null(),
        destination: Nullable::some(host.destination("review")),
        preview_only: true,
    };
    let previewed: WorkspaceCreateResult = typed(
        &control
            .mutate(
                Method::WorkspaceCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &preview_params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the preview succeeds"),
    );
    assert!(previewed.workspace.0.is_none());
    let dirty = previewed
        .preview
        .counts
        .iter()
        .find(|count| count.class == InclusionClass::DirtyFile)
        .expect("the preview counts dirty files");
    assert_eq!(dirty.total, U64::new(1));
    assert_eq!(dirty.included, U64::new(1));
    let untracked = previewed
        .preview
        .counts
        .iter()
        .find(|count| count.class == InclusionClass::UntrackedFile)
        .expect("the preview counts untracked files");
    assert_eq!(untracked.total, U64::new(1));
    assert_eq!(untracked.included, U64::new(0));
    assert_absent(&host.work().join("review"), "the preview created nothing");

    // Then the creation itself.
    let created: WorkspaceCreateResult = typed(
        &control
            .mutate(
                Method::WorkspaceCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkspaceCreateParams {
                    preview_only: false,
                    ..preview_params
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workspace.create succeeds"),
    );
    let workspace = created
        .workspace
        .0
        .expect("a creation returns the workspace");
    assert_eq!(workspace.state, WorkspaceState::Ready);
    // The dirty file came across and the untracked one did not, and the source keeps both.
    assert_eq!(
        std::fs::read_to_string(host.work().join("review/README.md")).expect("it is there"),
        "changed after the commit\n"
    );
    assert_absent(
        &host.work().join("review/notes.txt"),
        "the excluded file did not arrive",
    );
    assert_eq!(
        std::fs::read_to_string(source.join("notes.txt")).expect("the original is untouched"),
        "the user's own untracked file\n"
    );

    // `workspace.list` and `workspace.read` are reads that delete nothing.
    let listed: WorkspaceListResult = typed(
        &control
            .request(
                Method::WorkspaceList,
                &WorkspaceListParams {
                    environment_id: host.environment_id,
                    project_repository_id: Nullable::some(project),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workspace.list succeeds"),
    );
    assert_eq!(listed.workspaces.len(), 1);
    let read: WorkspaceReadResult = typed(
        &control
            .request(
                Method::WorkspaceRead,
                &WorkspaceReadParams {
                    workspace_id: workspace.workspace_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workspace.read succeeds"),
    );
    assert_eq!(read.workspace.workspace_id, workspace.workspace_id);
    assert!(host.work().join("review/README.md").is_file());

    // A session bound to it refuses the removal, and its ending admits it.
    host.controller
        .project()
        .service()
        .bind_session(
            workspace.workspace_id,
            SessionId::new(kr_ipc::new_uuid()),
            true,
        )
        .expect("the session binds");
    let refusal = failure(
        control
            .mutate(
                Method::WorkspaceRemove,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &WorkspaceRemoveParams {
                    workspace_id: workspace.workspace_id,
                    retention: RetentionPolicy::RemoveRetained,
                    through_location_id: Nullable(None),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::ResourceUnavailable);
    assert!(host.work().join("review/README.md").is_file());

    // `project.operation.cancel` of finished work undoes nothing and reports its staging paths.
    let cancelled: ProjectOperationCancelResult = typed(
        &control
            .mutate(
                Method::ProjectOperationCancel,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectOperationCancelParams {
                    operation_action_id: cloned.operation.action_id,
                    through_location_id: Nullable(None),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.operation.cancel succeeds"),
    );
    assert_eq!(cancelled.operation.state, OperationState::Completed);
    assert_eq!(cancelled.stopped_processes, U64::new(0));
    assert_eq!(cancelled.operation.removed_staging_paths.len(), 1);
    assert!(host.work().join("cloned/README.md").is_file());

    let _ = host.stop().await;
}

/// KR-REQ-23.42 and 23.43: a project mutation acts on a repository rather than on a session, and
/// the daemon refuses an envelope that says otherwise before anything runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_refuses_a_project_envelope_that_names_a_session_or_another_environment() {
    let host = host().await;
    let mut control = client(&host).await;
    let refusal = failure(
        control
            .mutate(
                Method::ProjectInit,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(SessionId::new(kr_ipc::new_uuid())),
                    session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::new(1)),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &ProjectInitParams {
                    destination: host.destination("never"),
                    label: "never".to_owned(),
                    initial_branch: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::InvalidArgument);
    let refusal = failure(
        control
            .mutate(
                Method::ProjectInit,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectInitParams {
                    destination: DestinationRequest {
                        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
                        parent: kr_protocol::project::DestinationParent::Host {
                            path: host.work().display().to_string(),
                        },
                        name: "never".to_owned(),
                    },
                    label: "never".to_owned(),
                    initial_branch: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::InvalidArgument);
    assert_absent(
        &host.work().join("never"),
        "a refused creation makes nothing",
    );
    let _ = host.stop().await;
}

/// KR-REQ-14.18: a lost reply is answered from the retained record rather than by cloning twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_creation_action_is_answered_from_the_record() {
    let host = host().await;
    let mut control = client(&host).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let params = ProjectInitParams {
        destination: host.destination("once"),
        label: "once".to_owned(),
        initial_branch: Nullable::null(),
    };
    let first: ProjectInitResult = typed(
        &control
            .mutate(
                Method::ProjectInit,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.init succeeds"),
    );
    // The same action again, which is what a retry after a lost reply is.
    let second: ProjectInitResult = typed(
        &control
            .mutate(
                Method::ProjectInit,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the repeat is answered from the record"),
    );
    assert_eq!(
        first.project.project_repository_id,
        second.project.project_repository_id
    );
    let listed: ProjectListResult = typed(
        &control
            .request(
                Method::ProjectList,
                &ProjectListParams {
                    environment_id: host.environment_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.list succeeds"),
    );
    assert_eq!(listed.projects.len(), 1, "one action, one repository");
    let _ = host.stop().await;
}

/// KR-REQ-14.19: a failure a caller's own text produced is answered, and retained, with none of
/// that text in it. The retry reads the retained record back, which is the copy that would outlive
/// the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retained_failure_carries_none_of_what_the_caller_sent() {
    let host = host().await;
    let mut control = client(&host).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let carrying = "https://user:RETAINEDSECRET@b.invalid/x";
    let params = ProjectInitParams {
        destination: host.destination("retained"),
        label: "retained".to_owned(),
        // A branch name a caller can send and this host refuses: it holds a colon.
        initial_branch: Nullable(Some(carrying.to_owned())),
    };
    let refusal = failure(
        control
            .mutate(
                Method::ProjectInit,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert!(
        !refusal.message.contains("RETAINEDSECRET"),
        "the answer carries none of it: {}",
        refusal.message
    );
    // The same action again. A retry is answered from the retained record rather than run twice,
    // so this is the copy of the message the journal kept.
    let repeated = failure(
        control
            .mutate(
                Method::ProjectInit,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert!(
        !repeated.message.contains("RETAINEDSECRET"),
        "and neither does the record it was retained as: {}",
        repeated.message
    );
    assert!(
        repeated.message.contains("does-not-repeat"),
        "which says what was taken out: {}",
        repeated.message
    );
    assert_eq!(
        repeated.message, refusal.message,
        "and the journal holds the same message the caller was answered with"
    );
    assert!(
        refusal.message.contains("is not a branch name"),
        "which still says what was wrong: {}",
        refusal.message
    );
    let _ = host.stop().await;
}

/// KR-REQ-24.08: a workspace, its policy and its pins survive the daemon's death, and cleanup
/// still respects them afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_workspace_and_its_pins_survive_a_replacement_daemon() {
    let host = host().await;
    let mut control = client(&host).await;
    let source = repository(host.work(), "durable");
    let work = host.work().to_owned();
    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectAdoptParams {
                    destination: host.destination("durable"),
                    label: "durable".to_owned(),
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
                    label: "pinned".to_owned(),
                    kind: WorkspaceKind::Isolated,
                    isolation: Nullable::some(IsolationMechanism::GitWorktree),
                    policy: InclusionPolicy::base_only(),
                    base_revision: Nullable::null(),
                    base_change_set_id: Nullable::null(),
                    destination: Nullable::some(host.destination("pinned")),
                    preview_only: false,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workspace.create succeeds"),
    );
    let workspace = created.workspace.0.expect("it exists");
    host.controller
        .project()
        .service()
        .retain(
            workspace.workspace_id,
            &kr_project::store::RetainedRow {
                kind: kr_protocol::project::RetainedKind::PinnedChangeSet,
                detail: "version 4 is pinned".to_owned(),
                change_set_id: Some(kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid())),
            },
        )
        .expect("the pin is recorded");
    drop(control);
    let (temp, work_dir) = host.stop().await;

    // A replacement daemon on the same environment and the same repositories.
    let replacement = host_on(temp, work_dir).await;
    let mut control = client(&replacement).await;
    let read: WorkspaceReadResult = typed(
        &control
            .request(
                Method::WorkspaceRead,
                &WorkspaceReadParams {
                    workspace_id: workspace.workspace_id,
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("workspace.read succeeds"),
    );
    assert_eq!(read.workspace.base_revision, workspace.base_revision);
    assert_eq!(read.workspace.policy, workspace.policy);
    assert_eq!(
        read.workspace.filesystem_identity,
        workspace.filesystem_identity
    );
    assert_eq!(read.workspace.retained.len(), 1);
    // And the pin still keeps the workspace: the policy that cannot lose work removes nothing.
    let answer: WorkspaceRemoveResult = typed(
        &control
            .mutate(
                Method::WorkspaceRemove,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(replacement.environment_id),
                &WorkspaceRemoveParams {
                    workspace_id: workspace.workspace_id,
                    retention: RetentionPolicy::KeepEverything,
                    through_location_id: Nullable(None),
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("workspace.remove is answered"),
    );
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    assert!(!answer.working_files_removed);
    assert!(work.join("pinned/README.md").is_file(), "a pin keeps it");
    assert!(source.join("notes.txt").is_file(), "so does the source");
    drop(control);
    let _ = replacement.stop().await;
}

/// KR-REQ-14.20 and 14.24 together: the two services this daemon hosts use one authority model, so
/// a verified download publishes into a workspace's own directory the same way it publishes into
/// any other destination the user chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_verified_download_publishes_into_a_workspace_this_daemon_created() {
    let host = host().await;
    let mut control = client(&host).await;
    repository(host.work(), "delivered");
    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectAdoptParams {
                    destination: host.destination("delivered"),
                    label: "delivered".to_owned(),
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
                    label: "delivery".to_owned(),
                    kind: WorkspaceKind::Isolated,
                    isolation: Nullable::some(IsolationMechanism::GitWorktree),
                    policy: InclusionPolicy::base_only(),
                    base_revision: Nullable::null(),
                    base_change_set_id: Nullable::null(),
                    destination: Nullable::some(host.destination("delivery")),
                    preview_only: false,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("workspace.create succeeds"),
    );
    let workspace = created.workspace.0.expect("it exists");

    // One file through the transfer service the same daemon hosts.
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a valid principal");
    let bytes: Vec<u8> = (0..4096_u32).map(|index| (index % 251) as u8).collect();
    let content_digest = kr_protocol::scalars::Digest256::from_bytes(kr_cbor::sha256(&bytes));
    let transfer = host.controller.transfer().service();
    let begun = transfer
        .upload_begin(
            &actor,
            &kr_protocol::transfer::UploadBeginParams {
                environment_id: host.environment_id,
                session_id: Nullable::null(),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: content_digest,
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "review-notes.bin".to_owned(),
            },
            None,
        )
        .expect("upload.begin succeeds");
    transfer
        .upload_chunk(
            &actor,
            &kr_protocol::transfer::UploadChunkParams {
                transfer_id: begun.transfer_id,
                chunk: kr_protocol::transfer::ChunkDescriptor {
                    index: U64::new(0),
                    byte_len: U64::new(bytes.len() as u64),
                    digest: content_digest,
                },
                bytes: kr_protocol::scalars::Bytes::new(bytes.clone()),
            },
            None,
        )
        .expect("upload.chunk succeeds");
    transfer
        .upload_finish(
            &actor,
            &kr_protocol::transfer::UploadFinishParams {
                transfer_id: begun.transfer_id,
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: content_digest,
            },
            None,
        )
        .expect("upload.finish succeeds");

    // A verified download of that attachment, which is the snapshot the publication resumes.
    let snapshot = transfer
        .download_begin(
            &actor,
            &kr_protocol::transfer::DownloadBeginParams {
                environment_id: host.environment_id,
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(kr_protocol::transfer::DownloadSource::Attachment {
                    transfer_id: begun.transfer_id,
                }),
                device_id: Nullable::null(),
            },
        )
        .expect("download.begin succeeds");

    // The workspace's own directory is the destination, authorised the same way every other
    // destination is: an open directory handle rather than a path the caller resolves again.
    let destination = kr_transfer::AuthorisedDirectory::open_root(
        host.environment_id,
        Path::new(&workspace.display_path),
    )
    .expect("the workspace's directory opens as an authority");
    let published = kr_transfer::publish_transfer(
        transfer,
        &actor,
        &destination,
        &kr_protocol::transfer::DownloadPlacement {
            transfer_id: snapshot.transfer_id,
            destination_name: "review-notes.bin".to_owned(),
            byte_len: snapshot.byte_len,
            content_digest: snapshot.content_digest,
            allow_overwrite: false,
        },
    )
    .expect("the download publishes into the workspace");
    assert_eq!(published, bytes.len() as u64);
    assert_eq!(
        std::fs::read(Path::new(&workspace.display_path).join("review-notes.bin"))
            .expect("the file is in the workspace"),
        bytes
    );
    // And the repository's own tree did not receive it: a workspace is its own object.
    assert_absent(
        &host.work().join("delivered/review-notes.bin"),
        "the repository's own tree did not receive it",
    );
    drop(control);
    let _ = host.stop().await;
}

/// KR-REQ-14.18 and 14.19: a daemon killed part way through a clone is replaced, the destination
/// is untouched, the staged content is named for the owner rather than removed by a daemon that
/// holds nothing reaching it, and the operation is reconciled against the create token rather than
/// retried as another clone.
///
/// The remote is a listener on this machine's loopback address that accepts the connection and
/// never answers, so the clone is still running when the daemon is ended. Nothing leaves the
/// machine and no name outside this test's own directories is touched.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_killed_mid_clone_is_replaced_and_the_destination_is_untouched() {
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    let environment_id = host.environment_id();
    let program = host.root().join("kr-controller");
    kr_ipc::testing::place_program(
        std::path::Path::new(env!("CARGO_BIN_EXE_kr-controller")),
        &program,
    );
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let work = tempfile::TempDir::new().expect("a working directory on the internal disk");
    let journal =
        kr_project::ProjectService::root_of(&environment).join(kr_project::store::STORE_FILE_NAME);

    // A remote that accepts and holds. The thread ends when this test drops the listener.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("its address").port();
    let held = std::thread::spawn(move || {
        let accepted = listener.accept();
        std::thread::sleep(std::time::Duration::from_secs(20));
        drop(accepted);
    });

    let action = ActionId::new(kr_ipc::new_uuid());
    let params = ProjectCloneParams {
        destination: DestinationRequest {
            environment_id,
            parent: kr_protocol::project::DestinationParent::Host {
                path: work.path().display().to_string(),
            },
            name: "hanging".to_owned(),
        },
        label: "hanging".to_owned(),
        source: CloneSource::Remote {
            remote: RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::Https,
                url: format!("https://127.0.0.1:{port}/repository.git"),
                provider: String::new(),
                credential_broker: kr_project::credential::OS_SECRET_STORE.to_owned(),
            },
        },
    };

    let log = host.root().join("daemon.log");
    let mut first = start_daemon(&program, &host);
    wait_for_daemon(&endpoint, &log).await;
    {
        let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the daemon this test started");
        // The reply never arrives, because the clone is still reaching the remote when the daemon
        // is ended. The daemon runs the effect on a task a dropped connection cannot cancel.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            control.mutate(
                Method::ProjectClone,
                action,
                ActionTarget::environment(environment_id),
                &params,
            ),
        )
        .await;
        assert!(
            outcome.is_err(),
            "the clone is still running when the daemon is ended, and instead it answered \
             {outcome:?}; the daemon's own log says: {}",
            std::fs::read_to_string(&log).unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
    }
    // The operation row exists before anything is on disk, which is what makes the create token
    // the thing a replacement reconciles against.
    wait_for_operation(&journal).await;

    // The daemon dies where it stands.
    first.stop();

    let mut second = start_daemon(&program, &host);
    wait_for_daemon(&endpoint, &log).await;
    let mut control = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the replacement");

    // The replacement settled it from its journal: the destination was never written, and the
    // staged content an earlier daemon left is where it was, because the replacement holds nothing
    // that reaches it and a recorded path is not authority. Nothing was retried as another clone.
    assert_absent(&work.path().join("hanging"), "the destination is untouched");
    let leftovers: Vec<String> = names_in(work.path())
        .into_iter()
        .filter(|name| name.starts_with(kr_project::operation::STAGING_PREFIX))
        .collect();
    assert_eq!(
        leftovers.len(),
        1,
        "the staged content an earlier daemon left is kept for the owner: {leftovers:?}"
    );
    let listed: ProjectListResult = typed(
        &control
            .request(Method::ProjectList, &ProjectListParams { environment_id })
            .await
            .expect("the call reaches the replacement")
            .expect("project.list succeeds"),
    );
    assert!(
        listed.projects.is_empty(),
        "no repository was recorded for a clone that never published"
    );

    // The operation is closed under its own create token, and its record names what was left.
    let cancelled: ProjectOperationCancelResult = typed(
        &control
            .mutate(
                Method::ProjectOperationCancel,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &ProjectOperationCancelParams {
                    operation_action_id: action,
                    through_location_id: Nullable(None),
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("the operation is readable through its create token"),
    );
    assert_eq!(cancelled.operation.state, OperationState::Failed);
    assert_eq!(cancelled.operation.retained_staging_paths.len(), 1);
    assert!(
        cancelled.operation.retained_staging_paths[0].ends_with(&leftovers[0]),
        "the path named is the one left: {:?}",
        cancelled.operation.retained_staging_paths
    );
    assert_eq!(cancelled.operation.removed_staging_paths.len(), 0);

    // And the same action identifier again clones nothing. Over a replacement daemon it is a
    // reused identifier rather than a retry, because the payload digest covers the action window
    // and this connection holds a new one; either way nothing is cloned a second time.
    let refusal = failure(
        control
            .mutate(
                Method::ProjectClone,
                action,
                ActionTarget::environment(environment_id),
                &params,
            )
            .await
            .expect("the call reaches the replacement"),
    );
    assert_eq!(refusal.code, ErrorCode::IdConflict);
    assert_absent(&work.path().join("hanging"), "the repeat cloned nothing");
    let listed: ProjectListResult = typed(
        &control
            .request(Method::ProjectList, &ProjectListParams { environment_id })
            .await
            .expect("the call reaches the replacement")
            .expect("project.list succeeds"),
    );
    assert!(listed.projects.is_empty(), "and recorded nothing");

    drop(control);
    second.stop();
    let _ = held.join();
    keys_are_this_test_s(&environment, environment_id, &log);
}

/// Waits for the project journal to hold one operation row.
#[cfg(unix)]
async fn wait_for_operation(journal: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(connection) = rusqlite::Connection::open(journal)
            && let Ok(count) =
                connection
                    .query_row::<i64, _, _>("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            && count > 0
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon wrote no operation row within thirty seconds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// A daemon this test started, ended when it goes out of scope however that happens.
#[cfg(unix)]
struct Daemon(Option<std::process::Child>);

#[cfg(unix)]
impl Daemon {
    /// Ends it now, without giving it a chance to tidy up.
    fn stop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        if let Ok(pid) = i32::try_from(child.id())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        let _ = child.wait();
    }
}

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Asserts the daemon kept its device keys where this test told it to.
///
/// A daemon started with `--secret-store file` writes them into this environment's own `secrets`
/// directory, which goes when the temporary host does. That is what keeps a test run out of the
/// person's own credential store, and this is the check that says it happened rather than the flag
/// on the command line saying it was asked for. The daemon's own log is checked too, because the
/// line it prints is what a run's evidence rests on when nobody is reading the directory.
#[cfg(unix)]
fn keys_are_this_test_s(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    log: &Path,
) {
    let scope = environment_id.to_string();
    for purpose in kr_protocol::pairing::KeyPurpose::ALL {
        let name = kr_crypto::store::SecretName::device_key(&scope, purpose)
            .expect("a name this store takes");
        let path = name
            .as_str()
            .split('/')
            .fold(environment.secrets_dir(), |path, part| path.join(part));
        assert!(
            path.is_file(),
            "the daemon's {purpose:?} key is not at {}, so it went to a store this test does not own",
            path.display()
        );
    }
    // The daemon names the directory as it resolved it, which is not always how this test spells
    // it: a daemon given relative directories resolves them against the working directory the
    // kernel reports, and on macOS that has already followed the link at `/var`. So the two names
    // are compared as directories rather than as text.
    // The suffix is removed rather than split on, because a directory's own name may contain the
    // text the suffix starts with.
    let said = std::fs::read_to_string(log).unwrap_or_default();
    let named = said
        .lines()
        .find_map(|line| {
            line.strip_prefix("kr-controller: keys in the 0700 fallback directory at ")
        })
        .and_then(|rest| {
            rest.strip_suffix(" (protected only by OS account isolation and disk encryption)")
        })
        .unwrap_or_else(|| {
            panic!("the daemon's log does not say where its keys went; it says: {said}")
        });
    assert_eq!(
        std::fs::canonicalize(named).expect("the directory the daemon named"),
        std::fs::canonicalize(environment.secrets_dir()).expect("this test's secrets directory"),
        "the daemon named a directory other than this test's own"
    );
}

/// Fails the test unless nothing at all is at the path, and says what it found instead.
///
/// `Path::exists` answers false when the platform would not say, and it follows a link, so an
/// assertion that something was never created has to ask about the name itself.
fn assert_absent(path: &Path, what: &str) {
    match std::fs::symlink_metadata(path) {
        Ok(found) => panic!(
            "{what}: {} still holds {:?}",
            path.display(),
            found.file_type()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "{what}: whether {} is there could not be established: {error}",
            path.display()
        ),
    }
}

/// Returns the names one directory holds, sorted, failing the test on anything it could not read.
///
/// A listing that turns a failure into an empty list says "there is nothing here" when it means
/// "I could not look", and an assertion built on it then passes for the wrong reason.
#[cfg(unix)]
fn names_in(directory: &Path) -> Vec<String> {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", directory.display()));
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "an entry of {} could not be read: {error}",
                directory.display()
            )
        });
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names
}

/// Starts the copied daemon on this test's own directories, with no worker program.
#[cfg(unix)]
fn start_daemon(program: &Path, host: &kr_ipc::testing::TempHost) -> Daemon {
    let logs = host.root().join("daemon.log");
    // A bounded retry, for one race and nothing else. The tests in this binary run in threads of
    // one process, and a child one of them forks inherits a copy of every descriptor open at that
    // moment - including the one another test's copy of this daemon is being written through. Linux
    // refuses to execute a file any process still holds open for writing, with ETXTBSY, and the
    // window closes as soon as that child reaches its own exec. Nothing about the daemon or the
    // copy is wrong when that happens, and the window closes in milliseconds, so it is waited out
    // rather than prevented. Preventing it is possible - coordinate every write of an executable
    // against every launch in the binary, or run these tests one at a time - and both cost far
    // more than the wait does.
    const ATTEMPTS: usize = 100;
    const BETWEEN: std::time::Duration = std::time::Duration::from_millis(10);

    let mut attempted = 0;
    loop {
        attempted += 1;
        // Reopened for each attempt, because the handles go to the child rather than staying here.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&logs)
            .expect("opens the daemon's log");
        let started = std::process::Command::new(program)
            // The daemon starts in a directory on the internal disk rather than inheriting this
            // test's own, which is inside the checkout. A copied binary is a new program as far as
            // the operating system's privacy rules are concerned, and a new program whose working
            // directory is on a removable volume is one the system stops to ask the user about.
            .current_dir(host.root())
            .arg("--runtime-dir")
            .arg(host.root().join("r"))
            .arg("--state-dir")
            .arg(host.root().join("s"))
            .arg("--worker")
            .arg(host.root().join("no-such-worker"))
            // Its device keys belong to this run: they go in this environment's own secrets
            // directory and leave with the temporary host, rather than into the person's
            // credential store.
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn();
        match started {
            Ok(child) => return Daemon(Some(child)),
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && attempted < ATTEMPTS =>
            {
                std::thread::sleep(BETWEEN);
            }
            Err(error) => {
                panic!("the daemon starts, after {attempted} attempts: {error:?}");
            }
        }
    }
}

/// Waits for a daemon to answer on its control endpoint.
#[cfg(unix)]
async fn wait_for_daemon(endpoint: &kr_ipc::paths::Endpoint, log: &Path) {
    // Generous, because this suite runs beside every other one in the workspace: a daemon that is
    // still starting is not a daemon that failed, and a failure shows in its own log.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        if LocalClient::connect(endpoint, LocalClientKind::Cli, build())
            .await
            .is_ok()
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not answer on {} within two minutes, and its log says: {}",
            endpoint.as_text(),
            std::fs::read_to_string(log).unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// KR-REQ-23.44 and section 9: the admission this daemon accepted a project mutation under is
/// asked again inside the service's own transaction, which is the last moment before the effect.
///
/// The two earlier answers cover the waiting this daemon can see: the registry's lock, a blocking
/// task to be scheduled, a retained record to be looked for. What they cannot cover is the
/// service's own preparation — a destination resolved and probed, a repository opened, the
/// journal's lock taken — and a revocation completing in there has to reach an action that then
/// does not begin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_withdrawn_during_a_creation_is_refused_inside_the_services_transaction() {
    let temp = kr_ipc::testing::TempHost::create();
    let work = tempfile::TempDir::new().expect("a working directory on the internal disk");
    let checkout = repository(work.path(), "adopted");
    let module = kr_controller::project::ProjectModule::open(&temp.environment())
        .await
        .expect("the project service opens");
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a valid principal");
    let params = ProjectAdoptParams {
        destination: DestinationRequest {
            environment_id: temp.environment_id(),
            parent: kr_protocol::project::DestinationParent::Host {
                path: work.path().display().to_string(),
            },
            name: "adopted".to_owned(),
        },
        label: "adopted".to_owned(),
        flow: AdoptionFlow::ExistingCheckout,
    };
    let mutation = kr_protocol::envelope::MutationRequest {
        request_id: kr_protocol::ids::RequestId::new(1),
        method: Method::ProjectAdopt.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: kr_protocol::ids::ActionWindowId::new("window-1".to_owned())
            .expect("a valid window identifier"),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(30_000),
        params: ParamsValue::from_typed(&params).expect("encodes"),
    };
    // The grant stands when this daemon asks before the service acts, and is gone by the time the
    // service's transaction asks.
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let admission = {
        let asked = Arc::clone(&asked);
        move || {
            if asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "the authority this action was admitted under was withdrawn",
                ))
            }
        }
    };
    let refusal = module
        .write(&actor, &mutation, Method::ProjectAdopt, admission, None)
        .await
        .expect_err("the adoption does not begin");
    assert_eq!(
        asked.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "asked before the service acts, and again inside its transaction"
    );
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(
        refusal.message.contains("withdrawn"),
        "the caller is told what lapsed: {}",
        refusal.message
    );
    // The checkout is untouched and nothing was recorded against it.
    assert!(checkout.join(".git").is_dir());
    let listed: ProjectListResult = typed(
        &module
            .read(&kr_protocol::envelope::Request {
                request_id: kr_protocol::ids::RequestId::new(2),
                method: Method::ProjectList.into(),
                method_version: kr_protocol::method::MethodVersion::V1,
                params: ParamsValue::from_typed(&ProjectListParams {
                    environment_id: temp.environment_id(),
                })
                .expect("encodes"),
            })
            .await
            .expect("the listing reads"),
    );
    assert!(
        listed.projects.is_empty(),
        "no repository was adopted: {listed:?}"
    );
}

// ----- the owner's authorised locations ----------------------------------------------------------

/// A daemon on the loopback network with an owner device, whose confirmations the project service
/// takes for its location decisions.
struct Owned {
    host: Host,
    network: kr_controller::service::net::Network,
    /// This host's owner as the project service reaches it: the daemon's own pairing service, whose
    /// ledger the daemon's sweep keeps.
    owner: Arc<kr_controller::project::HostOwner>,
    /// The owner device, when this daemon paired it rather than finding it on record.
    owner_device: Option<kr_protocol::ids::DeviceId>,
}

impl Owned {
    async fn stop(self) -> (kr_ipc::testing::TempHost, Arc<tempfile::TempDir>) {
        self.network.shutdown().await;
        self.host.stop().await
    }
}

/// The owner device every location test confirms as.
fn owner_keys() -> kr_crypto::keys::DeviceKeys {
    kr_crypto::keys::DeviceKeys::generate().expect("owner keys")
}

async fn owned(owner: &kr_crypto::keys::DeviceKeys) -> Owned {
    owned_on(
        kr_ipc::testing::TempHost::create(),
        Arc::new(tempfile::TempDir::new().expect("a working directory on the internal disk")),
        owner,
    )
    .await
}

/// Starts a daemon on the network, and pairs `owner` as its first owner device unless the host
/// already has an owner, as a replacement daemon on the same tree does.
async fn owned_on(
    temp: kr_ipc::testing::TempHost,
    work: Arc<tempfile::TempDir>,
    owner: &kr_crypto::keys::DeviceKeys,
) -> Owned {
    let (host, network) = networked_on(temp, work).await;
    let unowned = network
        .pairing()
        .owner()
        .enrolment()
        .expect("the owner record reads")
        == kr_pairing::confirm::HostEnrolment::InitialBootstrap;
    let owner_device = if unowned {
        Some(pair_first_owner(&host, owner).await)
    } else {
        None
    };
    let lent = Arc::new(kr_controller::project::HostOwner::new(Arc::clone(
        network.pairing(),
    )));
    Owned {
        host,
        network,
        owner: lent,
        owner_device,
    }
}

/// Starts a daemon and puts it on the loopback network, which lends its project service this
/// host's owner devices.
async fn networked_on(
    temp: kr_ipc::testing::TempHost,
    work: Arc<tempfile::TempDir>,
) -> (Host, kr_controller::service::net::Network) {
    use kr_controller::service::net::{self, NetworkSetup, config::NetworkSettings};

    let host = host_on(temp, work).await;
    let network = net::register(
        &host.controller,
        NetworkSetup {
            settings: NetworkSettings {
                endpoint: kr_transport::config::EndpointConfig {
                    bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
                    ..kr_transport::config::EndpointConfig::default()
                },
                ..NetworkSettings::default()
            },
            secrets: Arc::new(kr_crypto::store::MemoryStore::new()),
            rendezvous: None,
        },
    )
    .await
    .expect("the daemon joins the loopback network");
    (host, network)
}

/// Pairs `owner` as the host's first owner device, the way a person does: the host's own account
/// issues a personal owner invitation through the terminal bootstrap, the device redeems it over
/// its own connection, and the owner confirms the device it was shown.
async fn pair_first_owner(
    host: &Host,
    owner: &kr_crypto::keys::DeviceKeys,
) -> kr_protocol::ids::DeviceId {
    let device = net_support::Device::with_keys(owner.clone()).await;
    let ceremony = kr_crypto::keys::DeviceKeys::generate().expect("a ceremony key");
    let signer = calls::Signer::Bootstrap(&ceremony.authorisation);
    let mut control = client(host).await;
    let invited = calls::invite_direct(
        host.environment_id,
        &mut control,
        kr_protocol::invitation::InviteGrantKind::PersonalOwner,
        &kr_pairing::grants::personal_owner_grant(),
        &signer,
    )
    .await
    .expect("the first owner's invitation");
    let (connection, _candidate, _value) = calls::redeem(&device.candidate(), &invited).await;
    let confirmed = calls::confirm_candidate(
        host.environment_id,
        &mut control,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the first owner device is paired");
    connection.close(0u32.into(), b"paired");
    confirmed.device_id
}

/// The owner device's proof for one challenge, after its own ceremony.
fn signed(
    owner: &kr_crypto::keys::DeviceKeys,
    request: &kr_protocol::pairing::OwnerConfirmationRequest,
) -> kr_protocol::pairing::OwnerConfirmationProof {
    signed_on(
        owner,
        request,
        kr_protocol::pairing::ConfirmationChannel::OwnerDevicePresence,
    )
}

/// A proof for one challenge signed with `keys`, as it arrives on `channel`.
fn signed_on(
    keys: &kr_crypto::keys::DeviceKeys,
    request: &kr_protocol::pairing::OwnerConfirmationRequest,
    channel: kr_protocol::pairing::ConfirmationChannel,
) -> kr_protocol::pairing::OwnerConfirmationProof {
    kr_pairing::confirm::sign_confirmation(&keys.authorisation, request, channel)
        .expect("the proof is signed")
}

fn location_params(
    environment_id: EnvironmentId,
    path: &Path,
    purpose: kr_protocol::project::LocationPurpose,
) -> kr_protocol::project::ProjectLocationAuthoriseParams {
    kr_protocol::project::ProjectLocationAuthoriseParams {
        location_id: Nullable::null(),
        environment_id,
        grant_id: Nullable::null(),
        purpose,
        label: "the owner's own".to_owned(),
        path: path.display().to_string(),
        owner_confirmation: Nullable::null(),
    }
}

fn proven(
    params: &kr_protocol::project::ProjectLocationAuthoriseParams,
    proof: kr_protocol::pairing::OwnerConfirmationProof,
) -> kr_protocol::project::ProjectLocationAuthoriseParams {
    kr_protocol::project::ProjectLocationAuthoriseParams {
        owner_confirmation: Nullable(Some(proof)),
        ..params.clone()
    }
}

async fn submit<P: serde::Serialize + ?Sized>(
    control: &mut LocalClient,
    environment_id: EnvironmentId,
    method: Method,
    action: ActionId,
    params: &P,
) -> std::result::Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            method,
            action,
            ActionTarget::environment(environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
}

/// Builds a mutation once, so that it can be sent again exactly as it was first sent.
///
/// An exact duplicate is the original request, the action window included: the same identifier
/// under another connection's window is another payload, and is refused as a reused identifier.
async fn composed<P: serde::Serialize + ?Sized>(
    control: &mut LocalClient,
    environment_id: EnvironmentId,
    method: Method,
    action: ActionId,
    params: &P,
) -> kr_protocol::envelope::MutationRequest {
    control
        .compose(
            method,
            action,
            ActionTarget::environment(environment_id),
            params,
        )
        .await
        .expect("the mutation is composed")
}

/// Submits an authorisation's first submission, expecting the challenge.
async fn challenged(
    control: &mut LocalClient,
    environment_id: EnvironmentId,
    action: ActionId,
    params: &kr_protocol::project::ProjectLocationAuthoriseParams,
) -> kr_protocol::pairing::OwnerConfirmationRequest {
    let answered: kr_protocol::project::ProjectLocationAuthoriseResult = typed(
        &submit(
            control,
            environment_id,
            Method::ProjectLocationAuthorise,
            action,
            params,
        )
        .await
        .expect("the first submission is answered"),
    );
    match answered.outcome {
        kr_protocol::project::LocationAuthorisation::ConfirmationRequired { request } => request,
        kr_protocol::project::LocationAuthorisation::Authorised { .. } => {
            panic!("an authorisation with no proof authorises nothing")
        }
    }
}

fn authorised_location(value: &ParamsValue) -> kr_protocol::project::AuthorisedLocation {
    let answered: kr_protocol::project::ProjectLocationAuthoriseResult = typed(value);
    match answered.outcome {
        kr_protocol::project::LocationAuthorisation::Authorised { location } => location,
        kr_protocol::project::LocationAuthorisation::ConfirmationRequired { .. } => {
            panic!("a submission carrying its proof is not answered with another challenge")
        }
    }
}

async fn locations(
    control: &mut LocalClient,
    environment_id: EnvironmentId,
) -> Vec<kr_protocol::project::AuthorisedLocation> {
    let listed: kr_protocol::project::ProjectLocationListResult = typed(
        &control
            .request(
                Method::ProjectLocationList,
                &kr_protocol::project::ProjectLocationListParams {
                    environment_id,
                    grant_id: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.location.list succeeds"),
    );
    listed.locations
}

/// KR-REQ-23.42, 23.43 and the specification's sensitive owner confirmation: a location is
/// authorised under the owner's fresh confirmation of exactly it, and under nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorise_requires_exact_fresh_owner_confirmation() {
    use kr_protocol::project::LocationPurpose;

    let owner = owner_keys();
    let stranger = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    let mut control = client(host).await;
    let root = host.work().join("projects");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let params = location_params(host.environment_id, &root, LocationPurpose::Destination);
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, host.environment_id, action, &params).await;
    assert_eq!(
        request.action,
        kr_protocol::pairing::SensitiveAction::EnlargeGrant
    );
    assert_eq!(
        request.host_device_id,
        kr_protocol::ids::DeviceId::new(host.environment_id.get())
    );
    assert!(
        locations(&mut control, host.environment_id)
            .await
            .is_empty(),
        "nothing is authorised before the owner confirms"
    );

    // A signature that is not an owner device's.
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&stranger, &request)),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    // The owner's signature over a challenge altered after it was issued: more rights than the
    // owner was shown.
    let mut widened = request.clone();
    widened.destination_rights = [
        kr_protocol::rights::ActionRight::ProjectCreate,
        kr_protocol::rights::ActionRight::WorkspaceManage,
        kr_protocol::rights::ActionRight::HostManage,
    ]
    .into_iter()
    .collect();
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &widened)),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    // The owner's own proof, for this action's request but another path.
    let elsewhere = host.work().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("another directory");
    let other_params = location_params(
        host.environment_id,
        &elsewhere,
        LocationPurpose::Destination,
    );
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&other_params, signed(&owner, &request)),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    assert!(
        locations(&mut control, host.environment_id)
            .await
            .is_empty(),
        "no refusal authorised anything"
    );

    // The owner's proof of exactly this.
    let location = authorised_location(
        &submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &request)),
        )
        .await
        .expect("the owner's confirmation authorises it"),
    );
    assert_eq!(location.path, root.display().to_string());
    assert_eq!(location.state, kr_protocol::project::LocationState::Active);
    // Spent: the same proof under another action is a confirmation of nothing there.
    let replayed = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            ActionId::new(kr_ipc::new_uuid()),
            &proven(&params, signed(&owner, &request)),
        )
        .await,
    );
    assert_eq!(replayed.code, ErrorCode::OwnerConfirmationRequired);
    assert_eq!(
        locations(&mut control, host.environment_id).await,
        vec![location]
    );
    drop(control);
    let _ = owned.stop().await;
}

/// A daemon that is not on the network has no owner device to confirm anything, so it authorises
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_enrolled_owner_authorises_no_location() {
    let host = host().await;
    let mut control = client(&host).await;
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            ActionId::new(kr_ipc::new_uuid()),
            &location_params(
                host.environment_id,
                host.work(),
                kr_protocol::project::LocationPurpose::Source,
            ),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::HostNotConfigured);
    drop(control);
    let _ = host.stop().await;
}

/// A daemon on the network whose first owner has not been paired has no owner device to confirm a
/// location decision, so it issues no challenge and authorises nothing. The terminal bootstrap
/// establishes the first owner and confirms nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_owner_device_authorises_no_location() {
    let (host, network) = networked_on(
        kr_ipc::testing::TempHost::create(),
        Arc::new(tempfile::TempDir::new().expect("a working directory on the internal disk")),
    )
    .await;
    let mut control = client(&host).await;
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            ActionId::new(kr_ipc::new_uuid()),
            &location_params(
                host.environment_id,
                host.work(),
                kr_protocol::project::LocationPurpose::Source,
            ),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::HostNotConfigured);
    assert!(
        locations(&mut control, host.environment_id)
            .await
            .is_empty()
    );
    drop(control);
    network.shutdown().await;
    let _ = host.stop().await;
}

/// KR-REQ-10.05: a location decision is confirmed by this host's owner devices, the owner every
/// other sensitive action here is confirmed by, and by nothing else.
///
/// Its challenge is listed to the owner with what it approves. A key that is not an owner device's,
/// the owner device's own key on a channel that is not its ceremony, and the owner device once it
/// is revoked confirm nothing; the owner device's proof authorises the location, and the
/// acceptance record holds that proof being spent. Without an owner device no challenge is issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_location_is_confirmed_by_an_owner_device_and_by_nothing_else() {
    use kr_protocol::confirmation::{ConfirmationDisplay, DescribedAction};
    use kr_protocol::pairing::{ConfirmationChannel, SensitiveAction};
    use kr_protocol::project::{LocationPurpose, LocationState};

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    let environment_id = host.environment_id;
    let mut control = client(host).await;
    let root = host.work().join("projects");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let params = location_params(environment_id, &root, LocationPurpose::Destination);
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, environment_id, action, &params).await;

    // Listed to the owner, and so to its owner devices, with what it approves.
    let pending = calls::pending(&mut control)
        .await
        .expect("the owner reads what is outstanding");
    let listed = pending
        .pending
        .iter()
        .find(|pending| pending.request == request)
        .expect("the challenge is listed");
    assert_eq!(
        listed.display,
        ConfirmationDisplay::Described(DescribedAction {
            action: SensitiveAction::EnlargeGrant,
            action_digest: request.action_digest,
            destination_keys: Nullable::null(),
            destination_rights: request.destination_rights.clone(),
        })
    );

    // Not an owner device's key, and not the owner device's ceremony.
    for proof in [
        signed(&owner_keys(), &request),
        signed_on(
            &owner,
            &request,
            ConfirmationChannel::EnrolledPresenceSigner,
        ),
        signed_on(
            &owner,
            &request,
            ConfirmationChannel::LocalBootstrapTerminal,
        ),
    ] {
        let refusal = failure(
            submit(
                &mut control,
                environment_id,
                Method::ProjectLocationAuthorise,
                action,
                &proven(&params, proof),
            )
            .await,
        );
        assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    }
    // The owner device's own proof.
    let location = authorised_location(
        &submit(
            &mut control,
            environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &request)),
        )
        .await
        .expect("the owner device confirms it"),
    );
    assert_eq!(location.state, LocationState::Active);
    let acceptance = owned
        .network
        .pairing()
        .rows()
        .acceptance(request.confirmation_id)
        .expect("readable")
        .expect("the acceptance record");
    assert_eq!(acceptance.channel, "owner_device_presence");
    assert!(acceptance.consumed_at_ms.is_some(), "spent, on record");

    // A challenge the owner device was given, and then the device revoked.
    let elsewhere = host.work().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("another directory");
    let other_params = location_params(environment_id, &elsewhere, LocationPurpose::Source);
    let second = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, environment_id, second, &other_params).await;
    submit(
        &mut control,
        environment_id,
        Method::DeviceRevoke,
        ActionId::new(kr_ipc::new_uuid()),
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: owned
                .owner_device
                .expect("the owner device this daemon paired"),
        },
    )
    .await
    .expect("revoked");
    // A revocation withdraws every registration, the owner's own socket included.
    drop(control);
    let mut control = client(host).await;
    let refusal = failure(
        submit(
            &mut control,
            environment_id,
            Method::ProjectLocationAuthorise,
            second,
            &proven(&other_params, signed(&owner, &request)),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    let refusal = failure(
        submit(
            &mut control,
            environment_id,
            Method::ProjectLocationAuthorise,
            ActionId::new(kr_ipc::new_uuid()),
            &other_params,
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::HostNotConfigured);
    assert_eq!(
        locations(&mut control, environment_id).await,
        vec![location]
    );
    drop(control);
    let _ = owned.stop().await;
}

/// Section 9's receipt: a confirmed authorisation's exact retry is answered from its record, over
/// the connection it was sent on and over another, and the same identifier with another payload is
/// a different request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exact_confirmation_retry_returns_its_receipt() {
    use kr_protocol::project::LocationPurpose;

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    let mut control = client(host).await;
    let params = location_params(host.environment_id, host.work(), LocationPurpose::Source);
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, host.environment_id, action, &params).await;
    let confirmed = composed(
        &mut control,
        host.environment_id,
        Method::ProjectLocationAuthorise,
        action,
        &proven(&params, signed(&owner, &request)),
    )
    .await;
    let first = authorised_location(
        &control
            .repeat(&confirmed)
            .await
            .expect("the call reaches the daemon")
            .expect("it is authorised"),
    );
    let same = authorised_location(
        &control
            .repeat(&confirmed)
            .await
            .expect("the call reaches the daemon")
            .expect("the retry is answered from the record"),
    );
    let mut again = client(host).await;
    let elsewhere = authorised_location(
        &again
            .repeat(&confirmed)
            .await
            .expect("the call reaches the daemon")
            .expect("the retry over another connection is answered from the record"),
    );
    assert_eq!(first, same, "one action, one receipt");
    assert_eq!(first, elsewhere, "whichever connection asks");
    assert_eq!(locations(&mut control, host.environment_id).await.len(), 1);
    // The unconfirmed payload under the same identifier, and the confirmed one under another
    // connection's window, are both other requests.
    for different in [
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &params,
        )
        .await,
        submit(
            &mut again,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &request)),
        )
        .await,
    ] {
        assert_eq!(failure(different).code, ErrorCode::IdConflict);
    }
    drop((control, again));
    let _ = owned.stop().await;
}

/// Two copies of one confirmed submission arrive together. One performs it; the other waits for
/// that transition and is given its answer, rather than meeting a challenge the first one spent.
///
/// The daemon answers one connection's requests in order and admits a first submission only under
/// the window of the connection it arrived on, so two exact copies of one submission meet nowhere
/// but in the service. They are driven there directly, under this daemon's own owner and its real
/// ceremony: a challenge this host issued, the owner device's signature over it, and a ledger that
/// spends it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_confirmation_submissions_overlap_before_the_claim() {
    use kr_project::policy::OwnerAuthority as _;
    use kr_protocol::project::{
        LocationAuthorisation, LocationPurpose, ProjectLocationAuthoriseResult,
    };

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    // The daemon's own owner, over its own pairing service, whose ledger its sweep keeps: the
    // service has one owner, and another's challenges would be ones that ledger does not know.
    let authority = Arc::clone(&owned.owner);
    let service = Arc::clone(host.controller.project().service());
    let actor = kr_protocol::ids::ActorId::new("local:owner").expect("a principal");
    let params = location_params(
        host.environment_id,
        host.work(),
        LocationPurpose::Destination,
    );
    let action_id = kr_ipc::new_uuid();
    let unproven = kr_project::store::Action {
        actor_id: actor.clone(),
        action_id,
        method: Method::ProjectLocationAuthorise.as_str().to_owned(),
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([1; 32]),
    };
    let first = service
        .project_location_authorise(&actor, &params, Some(&unproven), Some(authority.as_ref()))
        .expect("the challenge is issued");
    let LocationAuthorisation::ConfirmationRequired { request } = first.outcome else {
        panic!("the first submission is answered with its challenge");
    };
    let confirmed = proven(&params, signed(&owner, &request));
    let submission = kr_project::store::Action {
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([2; 32]),
        ..unproven
    };
    let start = Arc::new(std::sync::Barrier::new(2));
    let copies: Vec<_> = (0..2)
        .map(|_| {
            let service = Arc::clone(&service);
            let authority = Arc::clone(&authority);
            let actor = actor.clone();
            let confirmed = confirmed.clone();
            let submission = submission.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                service.project_location_authorise(
                    &actor,
                    &confirmed,
                    Some(&submission),
                    Some(authority.as_ref() as &dyn kr_project::policy::OwnerAuthority),
                )
            })
        })
        .collect();
    let answers: Vec<ProjectLocationAuthoriseResult> = copies
        .into_iter()
        .map(|copy| {
            copy.join()
                .expect("the copy runs")
                .expect("each copy is answered with the location, not a spent challenge")
        })
        .collect();
    assert_eq!(
        answers[0], answers[1],
        "both copies are given the one answer"
    );
    let LocationAuthorisation::Authorised { location } = &answers[0].outcome else {
        panic!("the confirmed submission authorises");
    };
    let mut control = client(host).await;
    assert_eq!(
        locations(&mut control, host.environment_id).await,
        vec![location.clone()]
    );
    // The challenge was spent exactly once: the ledger holds it no more, and the owner's proof
    // answers nothing now.
    assert!(!authority.outstanding(&request));
    let spent = authority
        .verify(
            &kr_project::policy::Enlargement {
                action_digest: request.action_digest,
                rights: request.destination_rights.clone(),
            },
            &signed(&owner, &request),
        )
        .expect_err("a spent challenge verifies nothing");
    assert_eq!(spent.code, ErrorCode::OwnerConfirmationRequired);
    drop(control);
    let _ = owned.stop().await;
}

/// A reauthorisation whose challenge is spent and whose effect then fails keeps that failure as
/// the action's answer, so a repeat learns it without a second ceremony, and the failure enlarged
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failure_after_the_challenge_is_consumed_retains_its_error() {
    use kr_protocol::project::{LocationPurpose, LocationState, ProjectLocationWithdrawParams};

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let mut control = client(&owned.host).await;
    let environment_id = owned.host.environment_id;
    let params = location_params(environment_id, owned.host.work(), LocationPurpose::Source);
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, environment_id, action, &params).await;
    let location = authorised_location(
        &submit(
            &mut control,
            environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &request)),
        )
        .await
        .expect("it is authorised"),
    );
    drop(control);

    // A replacement daemon holds no handle: the location is dormant until the owner acts again.
    let (temp, work) = owned.stop().await;
    let owned = owned_on(temp, work, &owner).await;
    let mut control = client(&owned.host).await;
    let listed = locations(&mut control, environment_id).await;
    assert_eq!(listed[0].state, LocationState::Dormant);
    let again = kr_protocol::project::ProjectLocationAuthoriseParams {
        location_id: Nullable(Some(location.location_id)),
        ..params.clone()
    };
    let reauthorise = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, environment_id, reauthorise, &again).await;
    // The owner withdraws it before confirming the reauthorisation.
    submit(
        &mut control,
        environment_id,
        Method::ProjectLocationWithdraw,
        ActionId::new(kr_ipc::new_uuid()),
        &ProjectLocationWithdrawParams {
            location_id: location.location_id,
        },
    )
    .await
    .expect("the withdrawal is performed");
    let confirmed = proven(&again, signed(&owner, &request));
    let refusal = failure(
        submit(
            &mut control,
            environment_id,
            Method::ProjectLocationAuthorise,
            reauthorise,
            &confirmed,
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    let repeated = failure(
        submit(
            &mut control,
            environment_id,
            Method::ProjectLocationAuthorise,
            reauthorise,
            &confirmed,
        )
        .await,
    );
    assert_eq!(repeated, refusal, "the kept failure answers the repeat");
    let listed = locations(&mut control, environment_id).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].state,
        LocationState::Withdrawn,
        "the spent confirmation revived nothing"
    );
    drop(control);
    let _ = owned.stop().await;
}

/// An owner location names no grant, so its challenge names no recipient device and carries both
/// rights; a grant this host did not issue to a paired device has no location at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_location_confirmation_is_bound_to_a_null_grant() {
    use kr_protocol::project::LocationPurpose;
    use kr_protocol::rights::ActionRight;

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    let mut control = client(host).await;
    let params = location_params(host.environment_id, host.work(), LocationPurpose::Source);
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(&mut control, host.environment_id, action, &params).await;
    assert!(
        request.destination_keys.0.is_none(),
        "no device is its recipient"
    );
    assert_eq!(
        request.destination_rights,
        [ActionRight::ProjectCreate, ActionRight::WorkspaceManage]
            .into_iter()
            .collect(),
        "both rights, unintersected"
    );
    // The owner signing a challenge that claims a recipient is not signing this one.
    let mut addressed = request.clone();
    addressed.destination_keys = Nullable(Some(owner.public_keys()));
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &addressed)),
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    let location = authorised_location(
        &submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(&params, signed(&owner, &request)),
        )
        .await
        .expect("the owner's own location is authorised"),
    );
    assert!(location.grant_id.0.is_none());
    // A grant no paired device holds is refused before any challenge is issued.
    let unissued = kr_protocol::project::ProjectLocationAuthoriseParams {
        grant_id: Nullable(Some(kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()))),
        ..params
    };
    let refusal = failure(
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAuthorise,
            ActionId::new(kr_ipc::new_uuid()),
            &unissued,
        )
        .await,
    );
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    drop(control);
    let _ = owned.stop().await;
}

/// Asks for a binding's challenge and returns the submission that carries the owner's proof.
async fn binding(
    control: &mut LocalClient,
    owner: &kr_crypto::keys::DeviceKeys,
    environment_id: EnvironmentId,
    action: ActionId,
    params: &kr_protocol::project::ProjectLocationAttachParams,
) -> std::result::Result<kr_protocol::project::ProjectLocationAttachParams, ProtocolError> {
    let first: kr_protocol::project::ProjectLocationAttachResult = typed(
        &submit(
            control,
            environment_id,
            Method::ProjectLocationAttach,
            action,
            params,
        )
        .await?,
    );
    let kr_protocol::project::LocationAttachment::ConfirmationRequired { request } = first.outcome
    else {
        panic!("a binding's first submission is answered with its challenge");
    };
    Ok(kr_protocol::project::ProjectLocationAttachParams {
        owner_confirmation: Nullable(Some(signed(owner, &request))),
        ..params.clone()
    })
}

/// Authorises one location through the daemon.
async fn authorise(
    control: &mut LocalClient,
    owner: &kr_crypto::keys::DeviceKeys,
    params: &kr_protocol::project::ProjectLocationAuthoriseParams,
) -> kr_protocol::project::AuthorisedLocation {
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenged(control, params.environment_id, action, params).await;
    authorised_location(
        &submit(
            control,
            params.environment_id,
            Method::ProjectLocationAuthorise,
            action,
            &proven(params, signed(owner, &request)),
        )
        .await
        .expect("the owner's confirmation authorises it"),
    )
}

async fn initialised(
    control: &mut LocalClient,
    host: &Host,
    name: &str,
) -> kr_protocol::ids::ProjectRepositoryId {
    let created: ProjectInitResult = typed(
        &submit(
            control,
            host.environment_id,
            Method::ProjectInit,
            ActionId::new(kr_ipc::new_uuid()),
            &ProjectInitParams {
                destination: host.destination(name),
                label: name.to_owned(),
                initial_branch: Nullable(Some("main".to_owned())),
            },
        )
        .await
        .expect("the repository is created"),
    );
    created.project.project_repository_id
}

fn attach_params(
    project: kr_protocol::ids::ProjectRepositoryId,
    location: kr_protocol::ids::ProjectLocationId,
) -> kr_protocol::project::ProjectLocationAttachParams {
    kr_protocol::project::ProjectLocationAttachParams {
        project_repository_id: project,
        location_id: Nullable(Some(location)),
        owner_confirmation: Nullable::null(),
    }
}

/// A binding is proved through the location's held handle, confirmed by the owner, and retried
/// from its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachment_completes_and_its_retry_returns_the_receipt() {
    use kr_protocol::project::{LocationAttachment, LocationPurpose, ProjectLocationAttachResult};

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    let mut control = client(host).await;
    let project = initialised(&mut control, host, "bound").await;
    let location = authorise(
        &mut control,
        &owner,
        &location_params(host.environment_id, host.work(), LocationPurpose::Source),
    )
    .await;
    let params = attach_params(project, location.location_id);
    let action = ActionId::new(kr_ipc::new_uuid());
    let confirmed = binding(&mut control, &owner, host.environment_id, action, &params)
        .await
        .expect("the challenge is issued");
    let confirmed = composed(
        &mut control,
        host.environment_id,
        Method::ProjectLocationAttach,
        action,
        &confirmed,
    )
    .await;
    let answer: ProjectLocationAttachResult = typed(
        &control
            .repeat(&confirmed)
            .await
            .expect("the call reaches the daemon")
            .expect("the binding is confirmed"),
    );
    let LocationAttachment::Bound {
        project: summary,
        source,
    } = &answer.outcome
    else {
        panic!("a confirmed binding is bound");
    };
    assert_eq!(summary.project_repository_id, project);
    let source = source.0.as_ref().expect("the binding names its location");
    assert_eq!(source.location_id, location.location_id);
    assert_eq!(source.relative_path, "bound");
    // The confirmed submission again, from another connection: the receipt, not a second binding.
    let mut again = client(host).await;
    let retried: ProjectLocationAttachResult = typed(
        &again
            .repeat(&confirmed)
            .await
            .expect("the call reaches the daemon")
            .expect("the retry is answered from the record"),
    );
    assert_eq!(retried, answer);
    drop((control, again));
    let _ = owned.stop().await;
}

/// A proof is for the binding it was issued for: another repository, another location or another
/// action's challenge is refused, and the binding each challenge was issued for still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attachment_proof_for_another_repository_or_location_is_refused() {
    use kr_protocol::project::LocationPurpose;

    let owner = owner_keys();
    let owned = owned(&owner).await;
    let host = &owned.host;
    let mut control = client(host).await;
    let first = initialised(&mut control, host, "first").await;
    let second = initialised(&mut control, host, "second").await;
    let location = authorise(
        &mut control,
        &owner,
        &location_params(host.environment_id, host.work(), LocationPurpose::Source),
    )
    .await;
    let other_location = authorise(
        &mut control,
        &owner,
        &location_params(host.environment_id, host.work(), LocationPurpose::Source),
    )
    .await;
    let first_action = ActionId::new(kr_ipc::new_uuid());
    let second_action = ActionId::new(kr_ipc::new_uuid());
    let first_confirmed = binding(
        &mut control,
        &owner,
        host.environment_id,
        first_action,
        &attach_params(first, location.location_id),
    )
    .await
    .expect("the first binding's challenge");
    let second_confirmed = binding(
        &mut control,
        &owner,
        host.environment_id,
        second_action,
        &attach_params(second, location.location_id),
    )
    .await
    .expect("the second binding's challenge");
    let first_proof = first_confirmed.owner_confirmation.clone();

    for (action, params, what) in [
        (
            second_action,
            kr_protocol::project::ProjectLocationAttachParams {
                owner_confirmation: first_proof.clone(),
                ..attach_params(second, location.location_id)
            },
            "the first repository's proof for the second repository",
        ),
        (
            first_action,
            kr_protocol::project::ProjectLocationAttachParams {
                owner_confirmation: first_proof.clone(),
                ..attach_params(first, other_location.location_id)
            },
            "the first binding's proof for another location",
        ),
        (
            ActionId::new(kr_ipc::new_uuid()),
            first_confirmed.clone(),
            "the first binding's proof under an action that was never challenged",
        ),
    ] {
        let refusal = failure(
            submit(
                &mut control,
                host.environment_id,
                Method::ProjectLocationAttach,
                action,
                &params,
            )
            .await,
        );
        assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired, "{what}");
    }
    // Nothing was spent by those refusals, and each binding is still the owner's to confirm.
    for (action, confirmed) in [
        (first_action, first_confirmed),
        (second_action, second_confirmed),
    ] {
        submit(
            &mut control,
            host.environment_id,
            Method::ProjectLocationAttach,
            action,
            &confirmed,
        )
        .await
        .expect("the binding its challenge was issued for is confirmed");
    }
    drop(control);
    let _ = owned.stop().await;
}
