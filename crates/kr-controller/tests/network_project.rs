//! The project and workspace methods over the network path.
//!
//! What these demonstrate, towards KR-REQ-23.42 and KR-REQ-23.43 for the paired-device ingress.
//! The registry admits a device to all ten methods; until now the network dispatcher refused the
//! reads as unsupported and sent the mutations to the worker proxy, which wants a session a
//! project mutation does not name.
//!
//! Five of the ten now answer a device differently on purpose: `project.init`, `project.clone`,
//! `project.adopt`, `workspace.create` and `workspace.remove` name a destination or a source this
//! host cannot check a device's authority over, so they are refused to one and the owner's own
//! path is untouched. What is shown to be identical on both doors is the four reads, for the same
//! subject, and the refusals the daemon decides about an envelope. On top of those, the grant is
//! what a device is additionally held to, and a device that submits its own action again is given
//! the answer its first submission produced rather than the answer performing it now would give.
//!
//! What these do not show is the rest of those rows: the destination and source authority sections
//! 14 and 23 ask for, which this host does not yet establish and which is why the five are
//! refused, and recovery through `action.read`, which is refused for an action this host owns.
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

/// KR-REQ-23.42 and KR-REQ-23.43: every method a device may reach answers it and the owner alike.
///
/// The owner runs all ten. A device runs the four reads and the cancellation, which is everything
/// this host serves it while it cannot check a device's authority over a destination or a source;
/// the other five are the next test. Each read is asked on both doors for the same subject and the
/// two answers compared, because the answer must not depend on which door asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_project_method_a_device_may_reach_answers_it_and_the_owner_alike() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, PROJECT_RIGHTS).await;
    let source = repository(host.work(), "source");

    // The owner performs the five creations and the two workspace mutations.
    let initialised: ProjectInitResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectInit,
            &ProjectInitParams {
                destination: destination(&host, "fresh"),
                label: "fresh".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect("project.init succeeds locally"),
    );
    assert_eq!(initialised.operation.state, OperationState::Completed);
    let cloned: ProjectCloneResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectClone,
            &ProjectCloneParams {
                destination: destination(&host, "cloned"),
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
        .expect("project.clone succeeds locally"),
    );
    assert_eq!(cloned.operation.state, OperationState::Completed);
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
    assert_eq!(
        std::fs::read_to_string(host.work().join("review/README.md"))
            .expect("the workspace is there"),
        "changed after the commit\n"
    );

    // The four reads, on both doors, for the same subject.
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
    assert_eq!(owner_list.projects.len(), 3);

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
    assert_eq!(owner_list.workspaces.len(), 1);

    let read_params = WorkspaceReadParams {
        workspace_id: workspace.workspace_id,
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

    // `project.operation.cancel` reaches a device, and section 23 puts it under the resource
    // owner's authority: the operation is the resource, and one the owner started is not the
    // device's to stop. So the device reaches the method and is refused the owner's work.
    let refused = remote_mutation(
        &session,
        host.environment_id,
        Method::ProjectOperationCancel,
        &ProjectOperationCancelParams {
            operation_action_id: cloned.operation.action_id,
        },
    )
    .await
    .expect_err("an operation another actor started is not this device's to stop");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    let cancelled: ProjectOperationCancelResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectOperationCancel,
            &ProjectOperationCancelParams {
                operation_action_id: cloned.operation.action_id,
            },
        )
        .await
        .expect("the owner cancels its own finished work"),
    );
    assert_eq!(cancelled.operation.state, OperationState::Completed);

    // And the owner removes the working copy it made.
    let removed: WorkspaceRemoveResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceRemove,
            &WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
        )
        .await
        .expect("workspace.remove succeeds locally"),
    );
    assert!(removed.working_files_removed);

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42 and KR-REQ-23.43: what a device is refused while its destination is unauthorised.
///
/// A device with an unbounded grant is refused the five mutations whose destination it cannot authorise.
///
/// Section 14 asks for an authorised destination handle and section 23 for a destination policy
/// and for source and destination grants. An unbounded grant (`EnvironmentSelector::Any`) cannot
/// authorise a host-local path, so these five are refused by name with PermissionDenied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_unbounded_grant_is_refused_the_five_whose_destination_it_cannot_authorise() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, PROJECT_RIGHTS).await;
    let source = repository(host.work(), "source");

    // The owner builds a repository and a workspace, so the two workspace mutations name real
    // subjects and the refusal is about the authority rather than about the subject.
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

    for (method, params, expected_resource) in [
        (
            Method::ProjectInit,
            ParamsValue::from_typed(&ProjectInitParams {
                destination: destination(&host, "never"),
                label: "never".to_owned(),
                initial_branch: Nullable::null(),
            })
            .expect("encodes"),
            "the directory it creates a repository in",
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
            "the directory it creates a repository in",
        ),
        (
            Method::ProjectAdopt,
            ParamsValue::from_typed(&ProjectAdoptParams {
                destination: destination(&host, "never"),
                label: "never".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            })
            .expect("encodes"),
            "the directory it creates a repository in",
        ),
        (
            Method::WorkspaceCreate,
            ParamsValue::from_typed(&workspace_params(&host, project, "never")).expect("encodes"),
            "the repository it takes a working copy from",
        ),
        (
            Method::WorkspaceRemove,
            ParamsValue::from_typed(&WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            })
            .expect("encodes"),
            "the working copy it removes",
        ),
    ] {
        let refused = remote_mutation(&session, host.environment_id, method, &params)
            .await
            .unwrap_err();
        assert_eq!(
            refused.code(),
            ErrorCode::PermissionDenied,
            "{} is refused to an unbounded device",
            method.as_str()
        );
        let message = refused.to_string();
        assert!(
            message.contains(method.as_str())
                && message.contains(expected_resource)
                && message.contains("unbounded grant cannot authorise a host-local path"),
            "the refusal names the method and why: {refused}"
        );
    }
    assert!(
        !host.work().join("never").exists(),
        "a refused creation created nothing"
    );
    assert!(
        host.work().join("review/README.md").is_file(),
        "and a refused removal removed nothing"
    );

    // The owner's own path is unchanged: it still creates and removes.
    let initialised: ProjectInitResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectInit,
            &ProjectInitParams {
                destination: destination(&host, "fresh"),
                label: "fresh".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            },
        )
        .await
        .expect("project.init succeeds locally"),
    );
    assert_eq!(initialised.operation.state, OperationState::Completed);
    let removed: WorkspaceRemoveResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceRemove,
            &WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
        )
        .await
        .expect("workspace.remove succeeds locally"),
    );
    assert!(removed.working_files_removed);

    // And the device still reads.
    let listed: ProjectListResult = session
        .read(
            Method::ProjectList,
            &ProjectListParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .expect("project.list is served to the device");
    assert_eq!(listed.projects.len(), 2);

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42 and KR-REQ-23.43: A device with a bounded grant can perform the five project mutations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_bounded_grant_can_perform_the_five_project_mutations() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let mut proposal = net_support::proposal(PROJECT_RIGHTS);
    proposal.environment_selector = kr_protocol::grant::EnvironmentSelector::These {
        environment_ids: [host.environment_id].into_iter().collect(),
    };
    let record = net_support::pair_with(&host, &device, &owner, proposal).await;
    let session = net_support::connect(&host, &device, &record).await;
    let source = repository(host.work(), "source");

    // 1. project.adopt
    let adopted: ProjectAdoptResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectAdopt,
            &ParamsValue::from_typed(&ProjectAdoptParams {
                destination: destination(&host, "source"),
                label: "source".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            })
            .expect("encodes"),
        )
        .await
        .expect("project.adopt succeeds for bounded device"),
    );
    let project = adopted.project.project_repository_id;

    // 2. project.init
    let initialised: ProjectInitResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectInit,
            &ParamsValue::from_typed(&ProjectInitParams {
                destination: destination(&host, "fresh"),
                label: "fresh".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            })
            .expect("encodes"),
        )
        .await
        .expect("project.init succeeds for bounded device"),
    );
    assert_eq!(initialised.operation.state, OperationState::Completed);

    // 3. project.clone
    let cloned: ProjectCloneResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::ProjectClone,
            &ParamsValue::from_typed(&ProjectCloneParams {
                destination: destination(&host, "cloned"),
                label: "cloned".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            })
            .expect("encodes"),
        )
        .await
        .expect("project.clone succeeds for bounded device"),
    );
    assert_eq!(cloned.operation.state, OperationState::Completed);

    // 4. workspace.create
    let created: WorkspaceCreateResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::WorkspaceCreate,
            &ParamsValue::from_typed(&workspace_params(&host, project, "review")).expect("encodes"),
        )
        .await
        .expect("workspace.create succeeds for bounded device"),
    );
    let workspace = created
        .workspace
        .0
        .expect("a creation returns the workspace");

    // 5. workspace.remove
    let removed: WorkspaceRemoveResult = typed(
        &remote_mutation(
            &session,
            host.environment_id,
            Method::WorkspaceRemove,
            &ParamsValue::from_typed(&WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            })
            .expect("encodes"),
        )
        .await
        .expect("workspace.remove succeeds for bounded device"),
    );
    assert!(removed.working_files_removed);

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42 and KR-REQ-23.43: A device with a grant for another environment or session sees narrowed lists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_unadmitted_environment_or_session_sees_narrowed_lists() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let _source = repository(host.work(), "source");

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
        .expect("project.adopt succeeds"),
    );
    let project = adopted.project.project_repository_id;

    let created: WorkspaceCreateResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceCreate,
            &workspace_params(&host, project, "review"),
        )
        .await
        .expect("workspace.create succeeds"),
    );
    let workspace = created.workspace.0.expect("workspace");

    let admitted_session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16]));
    host.controller()
        .project()
        .service()
        .bind_session(workspace.workspace_id, admitted_session, true)
        .expect("binds session");

    // Grant bounded to a different environment and a different session
    let other_env = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([99; 16]));
    let other_session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([98; 16]));
    let device = net_support::Device::create().await;
    let mut proposal = net_support::proposal(PROJECT_RIGHTS);
    proposal.environment_selector = kr_protocol::grant::EnvironmentSelector::These {
        environment_ids: [other_env].into_iter().collect(),
    };
    proposal.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [other_session].into_iter().collect(),
    };
    let record = net_support::pair_with(&host, &device, &owner, proposal).await;
    let session = net_support::connect(&host, &device, &record).await;

    // The device asking for an unadmitted environment is refused PermissionDenied
    let refused_plist = session
        .read::<_, ProjectListResult>(
            Method::ProjectList,
            &ProjectListParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused_plist.code(), ErrorCode::PermissionDenied);
    assert!(
        refused_plist
            .to_string()
            .contains("does not cover this environment")
    );

    let refused_wlist = session
        .read::<_, WorkspaceListResult>(
            Method::WorkspaceList,
            &WorkspaceListParams {
                environment_id: host.environment_id,
                project_repository_id: Nullable::null(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused_wlist.code(), ErrorCode::PermissionDenied);
    assert!(
        refused_wlist
            .to_string()
            .contains("does not cover this environment")
    );

    // A read of one subject is refused for the same reason the listing is narrowed. Otherwise a
    // narrowed listing would only hide an identifier that the read then answered for, and a
    // device that learned one another way would reach the whole record.
    let refused_pread = session
        .read::<_, kr_protocol::project::ProjectReadResult>(
            Method::ProjectRead,
            &kr_protocol::project::ProjectReadParams {
                project_repository_id: project,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused_pread.code(), ErrorCode::PermissionDenied);
    assert!(
        refused_pread
            .to_string()
            .contains("does not cover this environment"),
        "{refused_pread}"
    );
    let refused_wread = session
        .read::<_, WorkspaceReadResult>(
            Method::WorkspaceRead,
            &kr_protocol::project::WorkspaceReadParams {
                workspace_id: workspace.workspace_id,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused_wread.code(), ErrorCode::PermissionDenied);
    assert!(
        refused_wread
            .to_string()
            .contains("does not cover this environment"),
        "{refused_wread}"
    );

    session.close();
    host.stop().await;
}

/// A grant that covers the environment reads one working copy, and sees only the sessions its own
/// selector admits bound to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_of_one_working_copy_carries_only_the_sessions_the_grant_admits() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let _source = repository(host.work(), "bound");
    let adopted: ProjectAdoptResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::ProjectAdopt,
            &ProjectAdoptParams {
                destination: destination(&host, "bound"),
                label: "bound".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
        )
        .await
        .expect("project.adopt succeeds"),
    );
    let project = adopted.project.project_repository_id;
    let created: WorkspaceCreateResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceCreate,
            &workspace_params(&host, project, "bound-tree"),
        )
        .await
        .expect("workspace.create succeeds"),
    );
    let workspace = created.workspace.0.expect("workspace");
    let admitted_session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([11; 16]));
    let hidden_session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([12; 16]));
    for session_id in [admitted_session, hidden_session] {
        host.controller()
            .project()
            .service()
            .bind_session(workspace.workspace_id, session_id, true)
            .expect("binds session");
    }

    let device = net_support::Device::create().await;
    let mut proposal = net_support::proposal(PROJECT_RIGHTS);
    proposal.environment_selector = kr_protocol::grant::EnvironmentSelector::These {
        environment_ids: [host.environment_id].into_iter().collect(),
    };
    proposal.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [admitted_session].into_iter().collect(),
    };
    let record = net_support::pair_with(&host, &device, &owner, proposal).await;
    let session = net_support::connect(&host, &device, &record).await;

    let read: WorkspaceReadResult = session
        .read(
            Method::WorkspaceRead,
            &kr_protocol::project::WorkspaceReadParams {
                workspace_id: workspace.workspace_id,
            },
        )
        .await
        .expect("a working copy in an admitted environment reads");
    assert_eq!(
        read.workspace.bound_sessions,
        vec![admitted_session],
        "a read carries only the sessions the grant admits"
    );
    let project_read: kr_protocol::project::ProjectReadResult = session
        .read(
            Method::ProjectRead,
            &kr_protocol::project::ProjectReadParams {
                project_repository_id: project,
            },
        )
        .await
        .expect("the repository reads");
    assert!(
        project_read
            .workspaces
            .iter()
            .all(|summary| summary.bound_sessions == vec![admitted_session]),
        "and so does the repository's own read: {:?}",
        project_read.workspaces
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42 and KR-REQ-23.43: A device with an admitted environment but unadmitted session sees the workspace but narrowed bound sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_admitted_environment_and_unadmitted_session_sees_narrowed_bound_sessions() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let _source = repository(host.work(), "source");

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
        .expect("project.adopt succeeds"),
    );
    let project = adopted.project.project_repository_id;

    let created: WorkspaceCreateResult = typed(
        &local_mutation(
            &mut control,
            host.environment_id,
            Method::WorkspaceCreate,
            &workspace_params(&host, project, "review"),
        )
        .await
        .expect("workspace.create succeeds"),
    );
    let workspace = created.workspace.0.expect("workspace");

    let bound_session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16]));
    host.controller()
        .project()
        .service()
        .bind_session(workspace.workspace_id, bound_session, true)
        .expect("binds session");

    // Grant admitting host.environment_id but a different session
    let other_session = SessionId::new(kr_protocol::scalars::Uuid::from_bytes([98; 16]));
    let device = net_support::Device::create().await;
    let mut proposal = net_support::proposal(PROJECT_RIGHTS);
    proposal.environment_selector = kr_protocol::grant::EnvironmentSelector::These {
        environment_ids: [host.environment_id].into_iter().collect(),
    };
    proposal.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [other_session].into_iter().collect(),
    };
    let record = net_support::pair_with(&host, &device, &owner, proposal).await;
    let session = net_support::connect(&host, &device, &record).await;

    let list: ProjectListResult = session
        .read(
            Method::ProjectList,
            &ProjectListParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .expect("reads");
    assert_eq!(list.projects.len(), 1);

    let ws_list: WorkspaceListResult = session
        .read(
            Method::WorkspaceList,
            &WorkspaceListParams {
                environment_id: host.environment_id,
                project_repository_id: Nullable::null(),
            },
        )
        .await
        .expect("reads");
    assert_eq!(ws_list.workspaces.len(), 1);
    assert!(
        ws_list.workspaces[0].bound_sessions.is_empty(),
        "unadmitted bound session is narrowed away"
    );

    session.close();
    host.stop().await;
}

/// A grant without session.view cannot list projects or workspaces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_without_session_view_is_refused_project_and_workspace_lists() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::ProjectCreate]).await;

    let refused_plist = session
        .read::<_, ProjectListResult>(
            Method::ProjectList,
            &ProjectListParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused_plist.code(), ErrorCode::PermissionDenied);
    assert!(
        refused_plist
            .to_string()
            .contains(ActionRight::SessionView.as_str())
    );

    let refused_wlist = session
        .read::<_, WorkspaceListResult>(
            Method::WorkspaceList,
            &WorkspaceListParams {
                environment_id: host.environment_id,
                project_repository_id: Nullable::null(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused_wlist.code(), ErrorCode::PermissionDenied);
    assert!(
        refused_wlist
            .to_string()
            .contains(ActionRight::SessionView.as_str())
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
/// operation: the service's retained record answers it and nothing is performed twice, and an
/// identifier reused with a different payload is refused outright rather than acted on.
///
/// The action is `project.operation.cancel`, which is the one project mutation a device reaches:
/// the five that name their own destination are refused before the service sees them. It is
/// submitted against an operation that does not exist yet, so the service refuses it, and a
/// refusal is retained exactly as a result is. The owner then *creates* that operation, so
/// performing the same request now would give a different answer — section 23 puts the method
/// under the resource owner's authority and the operation is the owner's. The retry therefore
/// distinguishes the record from what performing it now would say: the record still says the
/// operation was unknown, and a fresh submission of the same request says it belongs to somebody
/// else.
///
/// What this establishes is that the caller is given its own first answer. It does not establish
/// that the service was not entered again, because the service records the first outcome and
/// hands that record back whatever a second entry produced; what keeps a second entry from
/// happening is the retained lookup that returns before the action, and this suite does not count
/// entries. A cancellation of an operation another actor owns has no effect to observe either
/// way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_project_mutation_from_a_device_is_answered_rather_than_performed_again() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
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

    // The operation this cancellation names does not exist yet.
    let operation_id = ActionId::new(kr_ipc::new_uuid());
    let params = ProjectOperationCancelParams {
        operation_action_id: operation_id,
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
    let first = raw
        .mutate(
            Method::ProjectOperationCancel,
            action_id,
            target.clone(),
            &params,
        )
        .await
        .expect_err("no operation carries that identifier");
    assert_ne!(first.code, ErrorCode::PermissionDenied);

    // The owner now performs the action that identifier names, so the operation exists and is the
    // owner's. Anything executed from here on gets a different answer.
    let initialised: ProjectInitResult = typed(
        &control
            .mutate(
                Method::ProjectInit,
                operation_id,
                target.clone(),
                &ProjectInitParams {
                    destination: destination(&host, "fresh"),
                    label: "fresh".to_owned(),
                    initial_branch: Nullable::some("main".to_owned()),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.init succeeds locally"),
    );
    assert_eq!(initialised.operation.action_id, operation_id);

    // A fresh submission of the same request, under an identifier of its own, is executed and
    // says what executing it now says.
    let fresh = raw
        .mutate(
            Method::ProjectOperationCancel,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &params,
        )
        .await
        .expect_err("an operation the owner started is not this device's to stop");
    assert_eq!(fresh.code, ErrorCode::PermissionDenied);
    assert_ne!(
        fresh.code, first.code,
        "the answer to executing this request has changed, which is what makes the retry a test"
    );

    // And the retry under the original identifier is the record, not another execution.
    let again = raw
        .mutate(
            Method::ProjectOperationCancel,
            action_id,
            target.clone(),
            &params,
        )
        .await
        .expect_err("the repeat is answered from the record the first submission wrote");
    assert_eq!(again.code, first.code);
    assert_eq!(again.message, first.message);

    // The same identifier with a different payload is a different action, and section 9 refuses it.
    let conflicting = raw
        .mutate(
            Method::ProjectOperationCancel,
            action_id,
            target,
            &ProjectOperationCancelParams {
                operation_action_id: ActionId::new(kr_ipc::new_uuid()),
            },
        )
        .await
        .expect_err("a reused identifier carrying another request is refused");
    assert_eq!(conflicting.code, ErrorCode::IdConflict);

    raw.close();
    host.stop().await;
}

/// KR-REQ-23.42: a device recovers its own project outcome under the authority the subject needs.
///
/// Section 23 has present view authority over the subject decide whether a retained result goes
/// back. The subject of a repository mutation is a repository or an operation, not a session, so a
/// grant that carries no `session.view` at all is given its own outcome back on a repeat.
/// Demanding `session.view` for that would ask for authority over something the answer is not
/// about, and would leave a device that lost its reply unable to recover it. The operation is
/// created between the two submissions for the reason the test above gives: it makes the record
/// and another execution say different things.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_without_session_view_still_recovers_its_own_project_outcome() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
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

    let operation_id = ActionId::new(kr_ipc::new_uuid());
    let params = ProjectOperationCancelParams {
        operation_action_id: operation_id,
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
    let first = raw
        .mutate(
            Method::ProjectOperationCancel,
            action_id,
            target.clone(),
            &params,
        )
        .await
        .expect_err("no operation carries that identifier");
    let _: ProjectInitResult = typed(
        &control
            .mutate(
                Method::ProjectInit,
                operation_id,
                target.clone(),
                &ProjectInitParams {
                    destination: destination(&host, "fresh"),
                    label: "fresh".to_owned(),
                    initial_branch: Nullable::some("main".to_owned()),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("project.init succeeds locally"),
    );
    let again = raw
        .mutate(Method::ProjectOperationCancel, action_id, target, &params)
        .await
        .expect_err("the repeat is answered rather than refused for an unrelated right");
    assert_eq!(first.code, again.code);
    assert_eq!(first.message, again.message);
    assert_ne!(
        again.code,
        ErrorCode::PermissionDenied,
        "the repeat is this action's own answer, neither a refusal about session.view nor the \
         answer executing it now would give: {again:?}"
    );

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
    let _ = raw
        .mutate(
            Method::ProjectOperationCancel,
            action_id,
            ActionTarget::environment(host.environment_id),
            &ProjectOperationCancelParams {
                operation_action_id: ActionId::new(kr_ipc::new_uuid()),
            },
        )
        .await
        .expect_err("no such operation, and the outcome is recorded under this identifier");

    let refused = session
        .read::<_, kr_protocol::receipt::ActionReadResult>(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            },
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
                session_id: None,
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
