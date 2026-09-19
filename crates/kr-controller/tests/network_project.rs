//! The project and workspace methods over the network path.
//!
//! Requirement rows closed here: KR-REQ-23.42 and KR-REQ-23.43 for the paired-device ingress. The
//! registry admits a device to all ten methods; until now the network dispatcher refused the reads
//! as unsupported and sent the mutations to the worker proxy, which wants a session a project
//! mutation does not name. What these suites demonstrate is that the two doors now answer alike:
//! every method runs over both, the results of the reads are identical, the refusals the daemon
//! decides are identical, and the grant is what a device is additionally held to.
//!
//! No worker is started here. A project acts on a repository rather than on a session, so the
//! daemon answers all ten itself; the repositories are real ones built with installed Git in a
//! temporary directory on the internal disk.

mod net_support;

use std::path::{Path, PathBuf};

use kr_client::error::ClientError;
use kr_client::session::Session;
use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, DestinationRequest, InclusionChoice, InclusionPolicy, IsolationMechanism,
    OperationState, ProjectAdoptParams, ProjectAdoptResult, ProjectCloneParams, ProjectCloneResult,
    ProjectInitParams, ProjectInitResult, ProjectListParams, ProjectListResult,
    ProjectOperationCancelParams, ProjectOperationCancelResult, ProjectReadParams,
    ProjectReadResult, RemoteSpecification, RemoteTransport, RetentionPolicy,
    WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind, WorkspaceListParams,
    WorkspaceListResult, WorkspaceReadParams, WorkspaceReadResult, WorkspaceRemoveParams,
    WorkspaceRemoveResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable};
use net_support::Host;

/// The rights a device needs to reach every project and workspace method.
const PROJECT_RIGHTS: &[ActionRight] = &[
    ActionRight::SessionView,
    ActionRight::ProjectCreate,
    ActionRight::WorkspaceManage,
];

/// How long a mutation asks for. A clone reaches the filesystem and a materialisation copies it.
const LIFETIME: DurationMs = DurationMs::new(120_000);

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

fn destination(host: &Host, name: &str) -> DestinationRequest {
    DestinationRequest {
        environment_id: host.environment_id,
        parent_path: host.work().display().to_string(),
        name: name.to_owned(),
    }
}

/// Runs one read on the owner's own socket.
async fn locally<P, R>(control: &mut LocalClient, method: Method, params: &P) -> R
where
    P: serde::Serialize + ?Sized,
    R: serde::de::DeserializeOwned + serde::Serialize,
{
    typed(
        &control
            .request(method, params)
            .await
            .expect("the call reaches the daemon")
            .unwrap_or_else(|error| panic!("{} succeeds locally: {error}", method.as_str())),
    )
}

/// Runs one mutation on the owner's own socket, and returns whatever the daemon answered.
async fn local_mutation<P>(
    control: &mut LocalClient,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> std::result::Result<ParamsValue, ProtocolError>
where
    P: serde::Serialize + ?Sized,
{
    control
        .mutate(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
}

/// Runs one mutation over the network, and returns whatever the daemon answered.
async fn remote_mutation<P>(
    session: &Session,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> std::result::Result<ParamsValue, ClientError>
where
    P: serde::Serialize + ?Sized,
{
    session
        .mutate(
            method,
            ActionTarget::environment(environment_id),
            None,
            &ParamsValue::empty(),
            params,
            LIFETIME,
        )
        .await
        .map(|settled| {
            settled
                .result()
                .cloned()
                .expect("a project mutation answers with its result")
        })
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

/// A repository with one commit and a dirty file.
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

fn workspace_params(
    host: &Host,
    project: kr_protocol::ids::ProjectRepositoryId,
    name: &str,
) -> WorkspaceCreateParams {
    WorkspaceCreateParams {
        project_repository_id: project,
        label: name.to_owned(),
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
        destination: Nullable::some(destination(host, name)),
        preview_only: false,
    }
}

/// KR-REQ-23.42 and KR-REQ-23.43: every project and workspace method runs over both ingresses.
///
/// Each mutation is performed once from each door, against a destination of its own, and each read
/// is asked on both doors for the same subject and the two answers compared. A mutation cannot be
/// run twice against the same destination and still be the same request, so what the mutations
/// demonstrate is that the device reaches the service and gets the service's own result; what the
/// reads demonstrate is that the answer itself does not depend on which door asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_project_and_workspace_method_answers_a_paired_device_and_the_owner_alike() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, PROJECT_RIGHTS).await;
    let source = repository(host.work(), "source");

    // `project.init`, from each door.
    let locally_made: ProjectInitResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectInit,
            &ProjectInitParams {
                destination: destination(&host, "fresh-owner"),
                label: "fresh-owner".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect("project.init succeeds locally"),
    );
    let remotely_made: ProjectInitResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectInit,
            &ProjectInitParams {
                destination: destination(&host, "fresh-device"),
                label: "fresh-device".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect("project.init succeeds for a paired device"),
    );
    assert_eq!(locally_made.operation.state, OperationState::Completed);
    assert_eq!(remotely_made.operation.state, OperationState::Completed);
    assert!(host.work().join("fresh-device/.git").is_dir());

    // `project.clone`, from each door.
    let remote = |name: &str| ProjectCloneParams {
        destination: destination(&host, name),
        label: name.to_owned(),
        remote: RemoteSpecification {
            remote_name: "origin".to_owned(),
            transport: RemoteTransport::LocalPath,
            url: source.display().to_string(),
            provider: String::new(),
            credential_broker: String::new(),
        },
    };
    let locally_cloned: ProjectCloneResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectClone,
            &remote("cloned-owner"),
        )
        .await
        .expect("project.clone succeeds locally"),
    );
    let remotely_cloned: ProjectCloneResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectClone,
            &remote("cloned-device"),
        )
        .await
        .expect("project.clone succeeds for a paired device"),
    );
    assert_eq!(locally_cloned.operation.state, OperationState::Completed);
    assert_eq!(remotely_cloned.operation.state, OperationState::Completed);
    assert!(host.work().join("cloned-device/README.md").is_file());

    // `project.adopt`: the device adopts the checkout the fixture built.
    let adopted: ProjectAdoptResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectAdopt,
            &ProjectAdoptParams {
                destination: destination(&host, "source"),
                label: "source".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
        )
        .await
        .expect("project.adopt succeeds for a paired device"),
    );
    let project = adopted.project.project_repository_id;
    let owner_adopted: ProjectAdoptResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectAdopt,
            &ProjectAdoptParams {
                destination: destination(&host, "cloned-owner"),
                label: "cloned-owner-adopted".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
        )
        .await
        .expect("project.adopt succeeds locally"),
    );
    assert_ne!(owner_adopted.project.project_repository_id, project);

    // The two reads of the repository surface, asked on both doors for the same subject.
    let list_params = ProjectListParams {
        environment_id: host.environment_id,
    };
    let owner_list: ProjectListResult =
        locally(&mut control, Method::ProjectList, &list_params).await;
    let device_list: ProjectListResult = session
        .read(Method::ProjectList, &list_params)
        .await
        .expect("project.list is served to the device");
    assert_eq!(
        owner_list, device_list,
        "project.list is the same answer on both ingresses"
    );
    assert_eq!(owner_list.projects.len(), 6);

    let read_params = ProjectReadParams {
        project_repository_id: project,
    };
    let owner_read: ProjectReadResult =
        locally(&mut control, Method::ProjectRead, &read_params).await;
    let device_read: ProjectReadResult = session
        .read(Method::ProjectRead, &read_params)
        .await
        .expect("project.read is served to the device");
    assert_eq!(
        owner_read, device_read,
        "project.read is the same answer on both ingresses"
    );
    assert_eq!(device_read.project.label, "source");

    // `workspace.create`, from each door, each into a directory of its own.
    let device_created: WorkspaceCreateResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::WorkspaceCreate,
            &workspace_params(&host, project, "review-device"),
        )
        .await
        .expect("workspace.create succeeds for a paired device"),
    );
    let device_workspace = device_created
        .workspace
        .0
        .expect("a creation returns the workspace");
    let owner_created: WorkspaceCreateResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceCreate,
            &workspace_params(&host, project, "review-owner"),
        )
        .await
        .expect("workspace.create succeeds locally"),
    );
    // The dirty file came across, which is what the inclusion policy asked for.
    assert_eq!(
        std::fs::read_to_string(host.work().join("review-device/README.md"))
            .expect("the workspace is there"),
        "changed after the commit\n"
    );

    // The two workspace reads, asked on both doors for the same subject.
    let list_params = WorkspaceListParams {
        environment_id: host.environment_id,
        project_repository_id: Nullable::some(project),
    };
    let owner_list: WorkspaceListResult =
        locally(&mut control, Method::WorkspaceList, &list_params).await;
    let device_list: WorkspaceListResult = session
        .read(Method::WorkspaceList, &list_params)
        .await
        .expect("workspace.list is served to the device");
    assert_eq!(
        owner_list, device_list,
        "workspace.list is the same answer on both ingresses"
    );
    assert_eq!(owner_list.workspaces.len(), 2);

    let read_params = WorkspaceReadParams {
        workspace_id: device_workspace.workspace_id,
    };
    let owner_read: WorkspaceReadResult =
        locally(&mut control, Method::WorkspaceRead, &read_params).await;
    let device_read: WorkspaceReadResult = session
        .read(Method::WorkspaceRead, &read_params)
        .await
        .expect("workspace.read is served to the device");
    assert_eq!(
        owner_read, device_read,
        "workspace.read is the same answer on both ingresses"
    );

    // `project.operation.cancel` of work that has finished: it undoes nothing and says so.
    let device_cancelled: ProjectOperationCancelResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectOperationCancel,
            &ProjectOperationCancelParams {
                operation_action_id: remotely_cloned.operation.action_id,
            },
        )
        .await
        .expect("project.operation.cancel succeeds for a paired device"),
    );
    let owner_cancelled: ProjectOperationCancelResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectOperationCancel,
            &ProjectOperationCancelParams {
                operation_action_id: locally_cloned.operation.action_id,
            },
        )
        .await
        .expect("project.operation.cancel succeeds locally"),
    );
    assert_eq!(device_cancelled.operation.state, OperationState::Completed);
    assert_eq!(owner_cancelled.operation.state, OperationState::Completed);
    assert!(host.work().join("cloned-device/README.md").is_file());

    // `workspace.remove`, from each door.
    let device_removed: WorkspaceRemoveResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::WorkspaceRemove,
            &WorkspaceRemoveParams {
                workspace_id: device_workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
        )
        .await
        .expect("workspace.remove succeeds for a paired device"),
    );
    assert_eq!(
        device_removed.workspace.workspace_id, device_workspace.workspace_id,
        "the removal names the workspace it removed"
    );
    let owner_removed: WorkspaceRemoveResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceRemove,
            &WorkspaceRemoveParams {
                workspace_id: owner_created
                    .workspace
                    .0
                    .expect("a creation returns the workspace")
                    .workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
        )
        .await
        .expect("workspace.remove succeeds locally"),
    );
    assert_eq!(
        owner_removed.working_files_removed, device_removed.working_files_removed,
        "the same removal leaves the same state on both ingresses"
    );
    assert!(
        device_removed.working_files_removed,
        "an isolated workspace's own working files go with it"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42 and KR-REQ-23.43: the grant is what a device is additionally held to.
///
/// The registry admits a paired device to all ten methods. Which of them it may actually perform
/// is the grant's answer: `project.create` for the three creations, `workspace.manage` for the
/// creation and the removal of a working copy. A grant that carries neither still reads, because
/// the reads require no right of their own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_only_the_project_methods_its_grant_carries() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;

    // The owner builds a repository and a workspace for the device to be refused.
    let source = repository(host.work(), "source");
    let adopted: ProjectAdoptResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectAdopt,
            &ProjectAdoptParams {
                destination: destination(&host, "source"),
                label: "source".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
        )
        .await
        .expect("project.adopt succeeds locally"),
    );
    let project = adopted.project.project_repository_id;
    assert!(source.join(".git").is_dir());
    let created: WorkspaceCreateResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceCreate,
            &workspace_params(&host, project, "review"),
        )
        .await
        .expect("workspace.create succeeds locally"),
    );
    let workspace = created
        .workspace
        .0
        .expect("a creation returns the workspace");

    // The three creations need `project.create`.
    for (method, params) in [
        (
            Method::ProjectInit,
            ParamsValue::from_typed(&ProjectInitParams {
                destination: destination(&host, "never"),
                label: "never".to_owned(),
                initial_branch: Nullable::null(),
            })
            .expect("encodes"),
        ),
        (
            Method::ProjectClone,
            ParamsValue::from_typed(&ProjectCloneParams {
                destination: destination(&host, "never"),
                label: "never".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            })
            .expect("encodes"),
        ),
        (
            Method::ProjectAdopt,
            ParamsValue::from_typed(&ProjectAdoptParams {
                destination: destination(&host, "never"),
                label: "never".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            })
            .expect("encodes"),
        ),
    ] {
        let refused = remote_mutation(&session, host.environment_id, method, &params)
            .await
            .expect_err("a grant without project.create reaches no creation");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert!(
            refused
                .to_string()
                .contains(ActionRight::ProjectCreate.as_str()),
            "the refusal names the right the grant lacks: {refused}"
        );
    }
    assert!(
        !host.work().join("never").exists(),
        "a refused creation created nothing"
    );

    // The creation and the removal of a working copy need `workspace.manage`.
    for (method, params) in [
        (
            Method::WorkspaceCreate,
            ParamsValue::from_typed(&workspace_params(&host, project, "never")).expect("encodes"),
        ),
        (
            Method::WorkspaceRemove,
            ParamsValue::from_typed(&WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            })
            .expect("encodes"),
        ),
    ] {
        let refused = remote_mutation(&session, host.environment_id, method, &params)
            .await
            .expect_err("a grant without workspace.manage reaches neither");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);
        assert!(
            refused
                .to_string()
                .contains(ActionRight::WorkspaceManage.as_str()),
            "the refusal names the right the grant lacks: {refused}"
        );
    }
    assert!(
        host.work().join("review/README.md").is_file(),
        "a refused removal removed nothing"
    );

    // And the reads, which need no right of their own, are served.
    let listed: ProjectListResult = session
        .read(
            Method::ProjectList,
            &ProjectListParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .expect("project.list is served to the device");
    assert_eq!(listed.projects.len(), 1);
    let read: WorkspaceReadResult = session
        .read(
            Method::WorkspaceRead,
            &WorkspaceReadParams {
                workspace_id: workspace.workspace_id,
            },
        )
        .await
        .expect("workspace.read is served to the device");
    assert_eq!(read.workspace.workspace_id, workspace.workspace_id);

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42: a project acts on a repository, and the envelope check says so on both doors.
///
/// The subject check is the daemon's own, not the ingress's: a target naming a session would
/// produce a receipt against something the effect never touched, and parameters naming another
/// environment would act somewhere the target did not name. Both doors refuse both, with the same
/// code and the same sentence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_envelope_naming_a_session_or_another_environment_is_refused_on_both_ingresses() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, PROJECT_RIGHTS).await;

    let params = ProjectInitParams {
        destination: destination(&host, "never"),
        label: "never".to_owned(),
        initial_branch: Nullable::null(),
    };
    let names_a_session = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(SessionId::new(kr_ipc::new_uuid())),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::new(1)),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let locally_refused = control
        .mutate(
            Method::ProjectInit,
            ActionId::new(kr_ipc::new_uuid()),
            names_a_session.clone(),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("a project mutation does not act on a session");
    let remotely_refused = session
        .mutate(
            Method::ProjectInit,
            names_a_session,
            None,
            &ParamsValue::empty(),
            &params,
            LIFETIME,
        )
        .await
        .expect_err("a project mutation does not act on a session");
    assert_eq!(locally_refused.code, ErrorCode::InvalidArgument);
    assert_eq!(remotely_refused.code(), ErrorCode::InvalidArgument);
    assert!(
        remotely_refused
            .to_string()
            .contains(&locally_refused.message),
        "both doors give the same sentence: {} against {remotely_refused}",
        locally_refused.message
    );

    // Parameters naming another environment than the target does.
    let elsewhere = ProjectInitParams {
        destination: DestinationRequest {
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            parent_path: host.work().display().to_string(),
            name: "never".to_owned(),
        },
        label: "never".to_owned(),
        initial_branch: Nullable::null(),
    };
    let locally_refused = control
        .mutate(
            Method::ProjectInit,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &elsewhere,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("the target and the parameters have to agree");
    let remotely_refused = remote_mutation(
        &session,
        host.environment_id,
        Method::ProjectInit,
        &elsewhere,
    )
    .await
    .expect_err("the target and the parameters have to agree");
    assert_eq!(locally_refused.code, ErrorCode::InvalidArgument);
    assert_eq!(remotely_refused.code(), ErrorCode::InvalidArgument);
    assert!(
        remotely_refused
            .to_string()
            .contains(&locally_refused.message),
        "both doors give the same sentence: {} against {remotely_refused}",
        locally_refused.message
    );
    assert!(
        !host.work().join("never").exists(),
        "neither refusal created anything"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42: a device's repeated project mutation is answered from its own record.
///
/// A device whose reply was lost submits the same action again. Section 9 makes that one
/// operation: the service's retained record answers it, nothing is performed twice, and an
/// identifier reused with a different payload is refused outright rather than acted on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_project_mutation_from_a_device_is_answered_rather_than_performed_again() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(PROJECT_RIGHTS),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    let params = ProjectInitParams {
        destination: destination(&host, "once"),
        label: "once".to_owned(),
        initial_branch: Nullable::some("main".to_owned()),
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
    let first: ProjectInitResult = typed(
        &raw.mutate(Method::ProjectInit, action_id, target.clone(), &params)
            .await
            .expect("project.init succeeds for a paired device"),
    );
    let again: ProjectInitResult = typed(
        &raw.mutate(Method::ProjectInit, action_id, target.clone(), &params)
            .await
            .expect("the repeat is answered"),
    );
    assert_eq!(
        first.project.project_repository_id, again.project.project_repository_id,
        "the repeat is answered from the record the first submission wrote"
    );

    // The same identifier with a different payload is a different action, and section 9 refuses it.
    let conflicting = raw
        .mutate(
            Method::ProjectInit,
            action_id,
            target,
            &ProjectInitParams {
                destination: destination(&host, "twice"),
                label: "twice".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect_err("a reused identifier carrying another request is refused");
    assert_eq!(conflicting.code, ErrorCode::IdConflict);
    assert!(
        !host.work().join("twice").exists(),
        "and nothing was created under it"
    );

    raw.close();
    host.stop().await;
}

/// KR-REQ-23.42: a device recovers its own project result under the authority the subject needs.
///
/// Section 23 has present view authority over the subject decide whether a retained result goes
/// back. The subject of a repository mutation is a repository, not a session, so a grant that
/// carries `project.create` and nothing else performs the action and is given its own result back
/// on a repeat. Demanding `session.view` for that would ask for authority over something the
/// answer is not about, and it would leave a device that lost its reply unable to recover it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_without_session_view_still_recovers_its_own_project_result() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::ProjectCreate]),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    let params = ProjectInitParams {
        destination: destination(&host, "alone"),
        label: "alone".to_owned(),
        initial_branch: Nullable::some("main".to_owned()),
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
    let first: ProjectInitResult = typed(
        &raw.mutate(Method::ProjectInit, action_id, target.clone(), &params)
            .await
            .expect("project.init succeeds under project.create alone"),
    );
    let again: ProjectInitResult = typed(
        &raw.mutate(Method::ProjectInit, action_id, target.clone(), &params)
            .await
            .expect("the repeat is answered rather than refused"),
    );
    assert_eq!(
        first.project.project_repository_id,
        again.project.project_repository_id
    );

    // And a reused identifier carrying another request is still refused, rather than being lost
    // behind a refusal about authority.
    let conflicting = raw
        .mutate(
            Method::ProjectInit,
            action_id,
            target,
            &ProjectInitParams {
                destination: destination(&host, "second"),
                label: "second".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect_err("a reused identifier carrying another request is refused");
    assert_eq!(conflicting.code, ErrorCode::IdConflict);

    raw.close();
    host.stop().await;
}

/// KR-REQ-23.42: what `action.read` says about an action that belongs to this host.
///
/// A receipt lives in the journal of the session an action was performed on, and a repository
/// mutation belongs to no session. What such an action leaves is kept by the service, which is not
/// a receipt in the shape this method answers with, so the request is refused and the refusal says
/// how the outcome is obtained instead. An action nothing recorded reads differently, because it
/// means something different.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_read_says_how_to_obtain_an_outcome_this_host_owns() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(PROJECT_RIGHTS),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &record).await;
    raw.claim();
    let session = net_support::connect(&host, &device, &record).await;

    let action_id = ActionId::new(kr_ipc::new_uuid());
    let _: ProjectInitResult = typed(
        &raw.mutate(
            Method::ProjectInit,
            action_id,
            ActionTarget::environment(host.environment_id),
            &ProjectInitParams {
                destination: destination(&host, "recorded"),
                label: "recorded".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect("project.init succeeds"),
    );

    let refused = session
        .read::<_, kr_protocol::receipt::ActionReadResult>(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams { action_id },
        )
        .await
        .expect_err("this host keeps no receipt for an action of its own");
    assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    assert!(
        refused.to_string().contains("submit the action again"),
        "the refusal says how the outcome is obtained: {refused}"
    );

    // An action nothing recorded reads differently, because it means something different.
    let unknown = session
        .read::<_, kr_protocol::receipt::ActionReadResult>(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id: ActionId::new(kr_ipc::new_uuid()),
            },
        )
        .await
        .expect_err("nothing recorded it");
    assert!(
        unknown.to_string().contains("no receipt for action"),
        "an action nobody recorded says so: {unknown}"
    );

    session.close();
    raw.close();
    host.stop().await;
}
