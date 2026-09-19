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
    AdoptionFlow, DestinationRequest, InclusionChoice, InclusionClass, InclusionPolicy,
    IsolationMechanism, OperationState, ProjectAdoptParams, ProjectAdoptResult, ProjectCloneParams,
    ProjectCloneResult, ProjectInitParams, ProjectInitResult, ProjectListParams, ProjectListResult,
    ProjectOperationCancelParams, ProjectOperationCancelResult, ProjectReadParams,
    ProjectReadResult, RemoteSpecification, RemoteTransport, RetentionPolicy,
    WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind, WorkspaceListParams,
    WorkspaceListResult, WorkspaceReadParams, WorkspaceReadResult, WorkspaceRemoveParams,
    WorkspaceRemoveResult, WorkspaceState,
};
use kr_protocol::scalars::{Nullable, U64};

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
            parent_path: self.work().display().to_string(),
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
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: RemoteTransport::LocalPath,
                        url: source.display().to_string(),
                        provider: String::new(),
                        credential_broker: String::new(),
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
                        parent_path: host.work().display().to_string(),
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
/// is untouched, the staged content is gone, and the operation is reconciled against the create
/// token rather than retried as another clone.
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
    std::fs::copy(env!("CARGO_BIN_EXE_kr-controller"), &program).expect("copies the daemon");
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
            parent_path: work.path().display().to_string(),
            name: "hanging".to_owned(),
        },
        label: "hanging".to_owned(),
        remote: RemoteSpecification {
            remote_name: "origin".to_owned(),
            transport: RemoteTransport::Https,
            url: format!("https://127.0.0.1:{port}/repository.git"),
            provider: String::new(),
            credential_broker: kr_project::credential::OS_SECRET_STORE.to_owned(),
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

    // The replacement resolved it: the destination was never written and the staged content is
    // gone. Nothing was retried as another clone.
    assert_absent(&work.path().join("hanging"), "the destination is untouched");
    let leftovers: Vec<String> = names_in(work.path())
        .into_iter()
        .filter(|name| name.starts_with(kr_project::operation::STAGING_PREFIX))
        .collect();
    assert_eq!(
        leftovers,
        Vec::<String>::new(),
        "the staged content an earlier daemon left is removed"
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

    // The operation is closed under its own create token, and its record says so.
    let cancelled: ProjectOperationCancelResult = typed(
        &control
            .mutate(
                Method::ProjectOperationCancel,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(environment_id),
                &ProjectOperationCancelParams {
                    operation_action_id: action,
                },
            )
            .await
            .expect("the call reaches the replacement")
            .expect("the operation is readable through its create token"),
    );
    assert_eq!(cancelled.operation.state, OperationState::Failed);
    assert_eq!(
        cancelled.operation.retained_staging_paths,
        Vec::<String>::new()
    );
    assert_eq!(cancelled.operation.removed_staging_paths.len(), 1);

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
    let said = std::fs::read_to_string(log).unwrap_or_default();
    let expected = format!(
        "kr-controller: keys in the 0700 fallback directory at {}",
        environment.secrets_dir().display()
    );
    assert!(
        said.contains(&expected),
        "the daemon's log does not say where its keys went; it says: {said}"
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
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logs)
        .expect("opens the daemon's log");
    std::process::Command::new(program)
        // The daemon starts in a directory on the internal disk rather than inheriting this test's
        // own, which is inside the checkout. A copied binary is a new program as far as the
        // operating system's privacy rules are concerned, and a new program whose working directory
        // is on a removable volume is one the system stops to ask the user about.
        .current_dir(host.root())
        .arg("--runtime-dir")
        .arg(host.root().join("r"))
        .arg("--state-dir")
        .arg(host.root().join("s"))
        .arg("--worker")
        .arg(host.root().join("no-such-worker"))
        // Its device keys belong to this run: they go in this environment's own secrets directory
        // and leave with the temporary host, rather than into the person's credential store.
        .arg("--secret-store")
        .arg("file")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().expect("duplicates the log"))
        .stderr(log)
        .spawn()
        .map(|child| Daemon(Some(child)))
        .expect("starts the daemon")
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
