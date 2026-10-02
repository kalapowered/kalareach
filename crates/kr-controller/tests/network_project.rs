//! The project and workspace methods over the network path.
//!
//! What these demonstrate, towards KR-REQ-23.42 and KR-REQ-23.43 for the paired-device ingress.
//! The registry admits a device to all ten methods, and the grant is what it is additionally held
//! to.
//!
//! `project.init`, `project.clone`, `project.adopt`, `workspace.create` and `workspace.remove`
//! each run the Git program, and one rule decides all five at the door: a host that has proved it
//! confines what that program reads (on Linux, inside one boundary the project service builds for
//! a caller bounded by a grant) serves them to a device, inside the locations the owner authorised
//! for the device's grant and nowhere else; any other host refuses them with one sentence. The
//! owner's own path is untouched. The four reads answer a device and the owner alike for the same
//! subject, narrowed to what the grant admits, and a device that submits its own action again is
//! given the answer its first submission produced rather than the answer performing it now would
//! give.
//!
//! The tests that need a host that proves the boundary say so by name when theirs does not, and
//! count as not run there. The refusals run on every host, holding the daemon as one that did not
//! prove it.
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
    AdoptionFlow, CloneSource, DestinationRequest, InclusionChoice, InclusionPolicy,
    IsolationMechanism, OperationState, ProjectAdoptParams, ProjectAdoptResult, ProjectCloneParams,
    ProjectCloneResult, ProjectInitParams, ProjectInitResult, ProjectListParams, ProjectListResult,
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

/// The whole of what a device is told when it asks for a repository operation on a host that
/// cannot confine what the Git program reads.
///
/// Compared in full rather than by substring: an addition to this message would be a disclosure,
/// and a change to its final clause would be a change of posture. Only the check before dispatch
/// produces it, so a test that sees exactly this has established that nothing was dispatched.
const REFUSAL: &str = "this host cannot confine what the Git program reads to the directories \
                       the owner authorised, so it does not run that program for a paired device";

/// Holds the host as one that did not prove Git's reads confined, which is the state of every host
/// but a Linux one that proved it: the five repository operations are refused at the door.
fn as_unqualified(host: &Host) {
    host.controller()
        .hold_qualification_for_tests(kr_project::service::Qualification::refused(
            kr_project::service::Refusal::Invocation,
            "a host this test holds as one that did not qualify",
        ));
}

/// The message a refusal carried, without the code the client renders in front of it.
fn said(error: &ClientError) -> String {
    let rendered = error.to_string();
    rendered
        .split_once(": ")
        .map_or(rendered.clone(), |(_, message)| message.to_owned())
}

/// How long a mutation asks for. A clone reaches the filesystem and a materialisation copies it.
const LIFETIME: DurationMs = DurationMs::new(120_000);

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

fn destination(host: &Host, name: &str) -> DestinationRequest {
    DestinationRequest {
        environment_id: host.environment_id,
        parent: kr_protocol::project::DestinationParent::Host {
            path: host.work().display().to_string(),
        },
        name: name.to_owned(),
    }
}

/// Runs one read on the owner's own socket.
async fn locally<P, R>(control: &mut LocalClient, method: Method, params: &P) -> R
where
    P: serde::Serialize + ?Sized,
    R: kr_protocol::wire::WireMessage,
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
            through_location_id: Nullable(None),
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
                through_location_id: Nullable(None),
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
                through_location_id: Nullable(None),
            },
        )
        .await
        .expect("workspace.remove succeeds locally"),
    );
    assert!(removed.working_files_removed);

    session.close();
    host.stop().await;
}

/// KR-REQ-23.42 and KR-REQ-23.43: an unbounded grant is refused by the same rule, and the owner is
/// unaffected.
///
/// The companion to the bounded case: what a grant bounds makes no difference, because the rule is
/// about running the Git program rather than about what the grant names. The second half is the one
/// that matters most here — the owner's own creation and removal still work while the device's are
/// refused, which is the posture this product has always had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbounded_grant_is_refused_by_the_same_rule_and_the_owner_is_unaffected() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    as_unqualified(&host);
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
                source: CloneSource::Remote {
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: RemoteTransport::LocalPath,
                        url: source.display().to_string(),
                        provider: String::new(),
                        credential_broker: String::new(),
                    },
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
        (
            Method::WorkspaceCreate,
            ParamsValue::from_typed(&workspace_params(&host, project, "never")).expect("encodes"),
        ),
        (
            Method::WorkspaceRemove,
            ParamsValue::from_typed(&WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
                through_location_id: Nullable(None),
            })
            .expect("encodes"),
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
        assert_eq!(
            said(&refused),
            REFUSAL,
            "the refusal gives the one reason and no other"
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
                through_location_id: Nullable(None),
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

/// KR-REQ-23.42 and KR-REQ-23.43: a device is refused every repository operation on a host that
/// cannot confine what Git reads, by one rule.
///
/// The five operations each run the Git program. A host bounds every name **it** resolves to an
/// opened directory handle, and bounds what Git reaches once Git is running only where it has
/// proved it can. A host that has not does not start that program for a paired device, whatever
/// the device's grant says, and a grant that names `project.create` or `workspace.manage` still
/// reaches no repository operation there.
///
/// The refusal carries one sentence, and the assertion is on that exact sentence rather than on the
/// code alone: only the door produces it, so a test that sees it has established that nothing was
/// dispatched, rather than that some later filesystem or Git step happened to fail. What the owner
/// can see afterwards says the same thing from the other side: no repository, no working copy and
/// no directory appeared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_refused_all_five_repository_methods() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    as_unqualified(&host);
    let mut control = host.client().await;
    let device = net_support::Device::create().await;
    let mut proposal = net_support::proposal(PROJECT_RIGHTS);
    // The widest grant this host issues for these rights, bounded to this environment: if even
    // this reaches nothing, no narrower grant does.
    proposal.environment_selector = kr_protocol::grant::EnvironmentSelector::These {
        environment_ids: [host.environment_id].into_iter().collect(),
    };
    let record = net_support::pair_with(&host, &device, &owner, proposal).await;
    let session = net_support::connect(&host, &device, &record).await;
    let source = repository(host.work(), "source");

    // The owner adopts a repository and takes a working copy of it, so the two workspace methods
    // name subjects that really exist: the refusal is about the operation, not about the subject.
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
        .expect("the owner adopts its own checkout"),
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
        .expect("the owner takes a working copy"),
    );
    let workspace = created
        .workspace
        .0
        .expect("a creation returns the workspace")
        .workspace_id;

    let refusals: Vec<(Method, ParamsValue)> = vec![
        (
            Method::ProjectInit,
            ParamsValue::from_typed(&ProjectInitParams {
                destination: destination(&host, "fresh"),
                label: "fresh".to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            })
            .expect("encodes"),
        ),
        (
            Method::ProjectClone,
            ParamsValue::from_typed(&ProjectCloneParams {
                destination: destination(&host, "cloned"),
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
            })
            .expect("encodes"),
        ),
        (
            Method::ProjectAdopt,
            ParamsValue::from_typed(&ProjectAdoptParams {
                destination: destination(&host, "second"),
                label: "second".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            })
            .expect("encodes"),
        ),
        (
            Method::WorkspaceCreate,
            ParamsValue::from_typed(&workspace_params(&host, project, "device")).expect("encodes"),
        ),
        (
            Method::WorkspaceRemove,
            ParamsValue::from_typed(&WorkspaceRemoveParams {
                workspace_id: workspace,
                retention: RetentionPolicy::RemoveRetained,
                through_location_id: Nullable(None),
            })
            .expect("encodes"),
        ),
    ];

    for (method, params) in refusals {
        let error = remote_mutation(&session, host.environment_id, method, &params)
            .await
            .expect_err("a device reaches no repository operation");
        assert_eq!(
            error.code(),
            ErrorCode::PermissionDenied,
            "{} is refused as an authority failure",
            method.as_str()
        );
        assert_eq!(
            said(&error),
            REFUSAL,
            "{} is refused by the one rule rather than by a later failure",
            method.as_str()
        );
    }

    // Nothing was dispatched, so nothing exists: the owner still sees exactly what it made.
    let listed: ProjectListResult = locally(
        &mut control,
        Method::ProjectList,
        &ProjectListParams {
            environment_id: host.environment_id,
        },
    )
    .await;
    assert_eq!(listed.projects.len(), 1);
    assert_eq!(
        listed.projects[0].project_repository_id, project,
        "and it is the one the owner adopted, not a replacement"
    );
    for name in ["fresh", "cloned", "second", "device"] {
        assert!(
            !host.work().join(name).exists(),
            "{name} is a destination a refused request named, so nothing made it"
        );
    }
    let workspaces: WorkspaceListResult = locally(
        &mut control,
        Method::WorkspaceList,
        &WorkspaceListParams {
            environment_id: host.environment_id,
            project_repository_id: Nullable::null(),
        },
    )
    .await;
    assert_eq!(
        workspaces.workspaces.len(),
        1,
        "the owner's working copy is still there, so the removal never began"
    );
    assert_eq!(
        workspaces.workspaces[0].workspace_id, workspace,
        "and it is the same working copy, by identity"
    );
    assert!(
        host.work().join("review/README.md").is_file(),
        "whose files a refused removal left alone"
    );

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
                source: CloneSource::Remote {
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: RemoteTransport::LocalPath,
                        url: source.display().to_string(),
                        provider: String::new(),
                        credential_broker: String::new(),
                    },
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
                through_location_id: Nullable(None),
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
            parent: kr_protocol::project::DestinationParent::Host {
                path: host.work().display().to_string(),
            },
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
        through_location_id: Nullable(None),
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
                through_location_id: Nullable(None),
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
        through_location_id: Nullable(None),
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

/// KR-REQ-23.42: a device names no location to reconcile an operation through.
///
/// Naming one is the owner's route to an operation no handle reaches any more, and it reaches any
/// operation in the environment. The network door tells the project service which grant the
/// device holds, so the request is refused as a bounded caller's before the operation it names is
/// even looked for; a door that told the service nothing would have it answer that no such
/// operation exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_refused_the_owners_reconciliation_route() {
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

    let refusal = raw
        .mutate(
            Method::ProjectOperationCancel,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &ProjectOperationCancelParams {
                operation_action_id: ActionId::new(kr_ipc::new_uuid()),
                through_location_id: Nullable(Some(kr_protocol::ids::ProjectLocationId::new(
                    kr_ipc::new_uuid(),
                ))),
            },
        )
        .await
        .expect_err("a device names no location");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(
        refusal.message.contains("bounded by grant"),
        "the refusal is the one a bounded caller is given: {}",
        refusal.message
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
                through_location_id: Nullable(None),
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

/// The grant a device needs to read and materialise a recorded version.
const VERSION_RIGHTS: &[ActionRight] = &[
    ActionRight::SessionView,
    ActionRight::FilesRead,
    ActionRight::WorkspaceManage,
];

/// A host whose owner has captured one version of a repository's working tree, and one more for a
/// session, with the identifiers a device names them by.
struct Recorded {
    host: Host,
    owner: DeviceKeys,
    control: LocalClient,
    workspace: kr_protocol::ids::WorkspaceId,
    /// The version captured for no session.
    plain: kr_protocol::changeset::VersionRef,
    /// The version captured for `session`.
    for_a_session: kr_protocol::changeset::VersionRef,
    session: SessionId,
    /// When the later of the two was captured.
    captured_at_ms: kr_protocol::scalars::TimestampMs,
}

impl Recorded {
    async fn start() -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let mut control = host.client().await;
        repository(host.work(), "recorded");
        let adopted: ProjectAdoptResult = typed(
            &local_mutation(
                &mut control,
                host.environment_id,
                Method::ProjectAdopt,
                &ProjectAdoptParams {
                    destination: destination(&host, "recorded"),
                    label: "recorded".to_owned(),
                    flow: AdoptionFlow::ExistingCheckout,
                },
            )
            .await
            .expect("the owner adopts the repository"),
        );
        let created: WorkspaceCreateResult = typed(
            &local_mutation(
                &mut control,
                host.environment_id,
                Method::WorkspaceCreate,
                &WorkspaceCreateParams {
                    kind: WorkspaceKind::SharedExisting,
                    isolation: Nullable::null(),
                    destination: Nullable::null(),
                    // A shared working copy is the user's own tree, in which every class stays.
                    policy: InclusionPolicy {
                        dirty_files: InclusionChoice::Include,
                        untracked_files: InclusionChoice::Include,
                        submodules: InclusionChoice::Include,
                        binary_files: InclusionChoice::Include,
                        generated_artefacts: InclusionChoice::Include,
                    },
                    ..workspace_params(&host, adopted.project.project_repository_id, "the tree")
                },
            )
            .await
            .expect("the owner takes the working copy"),
        );
        let workspace = created
            .workspace
            .0
            .expect("a creation returns the workspace")
            .workspace_id;
        let session = SessionId::new(kr_ipc::new_uuid());
        let capture = |session: Option<SessionId>, label: &str| {
            kr_protocol::changeset::ChangesetCaptureParams {
                workspace_id: workspace,
                change_set_id: Nullable::null(),
                label: label.to_owned(),
                policy: InclusionPolicy {
                    dirty_files: InclusionChoice::Include,
                    untracked_files: InclusionChoice::Include,
                    submodules: InclusionChoice::Exclude,
                    binary_files: InclusionChoice::Exclude,
                    generated_artefacts: InclusionChoice::Exclude,
                },
                grant: kr_protocol::changeset::FileGrant {
                    included_paths: Vec::new(),
                    excluded_paths: Vec::new(),
                    secret_rules_applied: true,
                },
                quiescence_declared: false,
                required_consistency: Nullable::null(),
                pin: true,
                session_id: Nullable(session),
                workflow_run_id: Nullable::null(),
                note: String::new(),
            }
        };
        let mut captured = Vec::new();
        for (session, label) in [(None, "plain"), (Some(session), "for a session")] {
            let result: kr_protocol::changeset::ChangesetCaptureResult = typed(
                &local_mutation(
                    &mut control,
                    host.environment_id,
                    Method::ChangesetCapture,
                    &capture(session, label),
                )
                .await
                .expect("the owner captures a version"),
            );
            captured.push(result.version);
        }
        let named = |version: &kr_protocol::changeset::ChangeSetVersionRecord| {
            kr_protocol::changeset::VersionRef {
                change_set_id: version.change_set_id,
                version: version.version,
            }
        };
        Self {
            plain: named(&captured[0]),
            for_a_session: named(&captured[1]),
            captured_at_ms: captured[1].captured_at_ms,
            host,
            owner,
            control,
            workspace,
            session,
        }
    }

    /// Pairs a device whose grant is the version rights, adjusted by `adjust`, and connects it.
    async fn paired(
        &self,
        adjust: impl FnOnce(&mut kr_protocol::pairing::ProposedGrant),
    ) -> (
        net_support::Device,
        kr_controller::service::net::devices::DeviceRecord,
        Session,
    ) {
        let mut proposal = net_support::proposal(VERSION_RIGHTS);
        // History reaches back to the start of the host's life unless a test says otherwise.
        proposal.history.lower_bound_ms = Nullable::some(kr_protocol::scalars::TimestampMs::new(1));
        adjust(&mut proposal);
        let device = net_support::Device::create().await;
        let record = net_support::pair_with(&self.host, &device, &self.owner, proposal).await;
        let session = net_support::connect(&self.host, &device, &record).await;
        (device, record, session)
    }

    /// The same, for a test that wants only the connection and keeps the device.
    async fn device(
        &self,
        adjust: impl FnOnce(&mut kr_protocol::pairing::ProposedGrant),
    ) -> (net_support::Device, Session) {
        let (device, _record, session) = self.paired(adjust).await;
        (device, session)
    }

    async fn stop(self) {
        self.host.stop().await;
    }
}

fn read_of(version: kr_protocol::changeset::VersionRef) -> kr_protocol::changeset::DiffReadParams {
    kr_protocol::changeset::DiffReadParams {
        workspace_id: Nullable::null(),
        change_set_id: Nullable::some(version.change_set_id),
        version: Nullable::some(version.version),
    }
}

fn materialise_of(
    version: kr_protocol::changeset::VersionRef,
) -> kr_protocol::changeset::ChangesetMaterializeParams {
    kr_protocol::changeset::ChangesetMaterializeParams {
        change_set_id: version.change_set_id,
        version: version.version,
        purpose: kr_protocol::changeset::MaterialisationPurpose::Review,
        label: "a device's own copy".to_owned(),
    }
}

/// What a device asking to read and to materialise `version` is told, as a refusal or as the
/// answer, for each of the two.
async fn read_and_materialise(
    session: &Session,
    env: EnvironmentId,
    version: kr_protocol::changeset::VersionRef,
) -> (
    std::result::Result<kr_protocol::changeset::DiffReadResult, ClientError>,
    std::result::Result<kr_protocol::changeset::ChangesetMaterializeResult, ClientError>,
) {
    let read = session
        .read::<_, kr_protocol::changeset::DiffReadResult>(Method::DiffRead, &read_of(version))
        .await;
    let materialised = remote_mutation(
        session,
        env,
        Method::ChangesetMaterialize,
        &materialise_of(version),
    )
    .await
    .map(|answer| typed::<kr_protocol::changeset::ChangesetMaterializeResult>(&answer));
    (read, materialised)
}

/// KR-REQ-23.44: a device reads a recorded version and has it written out, and is never told where
/// on this host the directory is.
///
/// Both run no Git and read no working tree: the diff is answered from the version's stored
/// manifest and the materialisation is written from the stored content into a directory of the
/// change-set service's own. The answer to the materialisation, a repeat of it, and what
/// `changeset.read` lists carry the form a device is shown. The control is the owner's own answer
/// over its own socket, which names the directory it wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_a_recorded_version_and_has_it_written_out_without_the_host_path() {
    let mut recorded = Recorded::start().await;
    let env = recorded.host.environment_id;
    let (device, record, session) = recorded.paired(|_| {}).await;
    let (read, materialised) = read_and_materialise(&session, env, recorded.plain).await;
    let read = read.expect("a recorded version's diff is served to a device inside its grant");
    assert_eq!(read.source_version.0, Some(recorded.plain));
    assert!(
        read.tracked.iter().any(|entry| entry.path == "README.md"),
        "the diff names what the version captured"
    );
    let materialised = materialised.expect("the version is written out for the device");
    let shown = materialised.materialisation.directory_path.clone();
    assert!(
        shown.starts_with("[path withheld, ") && !shown.contains('/'),
        "a device is shown the form and not the path: {shown}"
    );

    // The owner's own answer names the directory, and the files are there: the directory is real,
    // and what the device was not told is where it is.
    let owners: kr_protocol::changeset::ChangesetReadResult = locally(
        &mut recorded.control,
        Method::ChangesetRead,
        &kr_protocol::changeset::ChangesetReadParams {
            change_set_id: recorded.plain.change_set_id,
            version: Nullable::some(recorded.plain.version),
        },
    )
    .await;
    assert_eq!(owners.materialisations.len(), 1);
    let real = PathBuf::from(&owners.materialisations[0].directory_path);
    assert!(real.is_absolute() && real.join("README.md").is_file());
    assert_eq!(
        owners.materialisations[0].materialisation_id,
        materialised.materialisation.materialisation_id,
        "the device names the materialisation by its identity"
    );

    // `changeset.read` lists the materialisation to the device in the same form.
    let listed: kr_protocol::changeset::ChangesetReadResult = session
        .read(
            Method::ChangesetRead,
            &kr_protocol::changeset::ChangesetReadParams {
                change_set_id: recorded.plain.change_set_id,
                version: Nullable::some(recorded.plain.version),
            },
        )
        .await
        .expect("changeset.read is served to a device");
    assert_eq!(listed.materialisations.len(), 1);
    assert_eq!(listed.materialisations[0].directory_path, shown);
    assert!(
        !format!("{listed:?}").contains(&real.display().to_string()),
        "no part of the answer names the directory"
    );

    // A repeat under the same action is answered from the record, in the same form.
    let raw = net_support::RawDevice::connect(&recorded.host, &device, &record).await;
    raw.claim();
    let action = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(env);
    let params = materialise_of(recorded.plain);
    let first: kr_protocol::changeset::ChangesetMaterializeResult = typed(
        &raw.mutate(
            Method::ChangesetMaterialize,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("a second materialisation of the version"),
    );
    let again: kr_protocol::changeset::ChangesetMaterializeResult = typed(
        &raw.mutate(Method::ChangesetMaterialize, action, target, &params)
            .await
            .expect("the repeat is answered from the record"),
    );
    assert_eq!(again, first, "the record answers the repeat");
    assert!(
        again
            .materialisation
            .directory_path
            .starts_with("[path withheld, "),
        "and in the form a device is shown: {}",
        again.materialisation.directory_path
    );
    assert_ne!(
        first.materialisation.materialisation_id, materialised.materialisation.materialisation_id,
        "the repeat did not make a third directory"
    );
    raw.close();
    session.close();
    recorded.stop().await;
}

/// KR-REQ-23.44: the version a device names has to be inside its grant, and a version it does not
/// reach is refused the way one that does not exist is.
///
/// Each case is one grant against the same two recorded versions, asked for the diff and for the
/// materialisation, beside a control: the same request under a grant that reaches the version.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_refused_a_recorded_version_its_grant_does_not_reach() {
    use kr_protocol::grant::{EnvironmentSelector, SessionSelector};

    let recorded = Recorded::start().await;
    let env = recorded.host.environment_id;
    let elsewhere = EnvironmentId::new(kr_ipc::new_uuid());
    let another = SessionId::new(kr_ipc::new_uuid());
    let beyond = kr_protocol::scalars::TimestampMs::new(recorded.captured_at_ms.get() + 3_600_000);
    let does_not_reach = "does not reach change set";

    // The environment: a grant that selects another one reaches neither, and one that selects this
    // one reaches both.
    let (_a, outside) = recorded
        .device(|grant| {
            grant.environment_selector = EnvironmentSelector::These {
                environment_ids: [elsewhere].into_iter().collect(),
            };
        })
        .await;
    let (read, materialised) = read_and_materialise(&outside, env, recorded.plain).await;
    // The door holds every request to the environments the grant selects before any version is
    // looked at, so a grant that selects none of this host's reaches neither.
    for refusal in [read.err(), materialised.err()] {
        let refusal = refusal.expect("a grant that does not select this environment");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
        assert!(
            said(&refusal).contains("does not cover this environment"),
            "{refusal}"
        );
    }
    let (_b, inside) = recorded
        .device(|grant| {
            grant.environment_selector = EnvironmentSelector::These {
                environment_ids: [env].into_iter().collect(),
            };
        })
        .await;
    let (read, materialised) = read_and_materialise(&inside, env, recorded.plain).await;
    read.expect("the grant that selects the environment reaches the diff");
    materialised.expect("and the materialisation");

    // An identifier no change set has is refused in the same words, so a device learns nothing
    // about which exist.
    let unknown = kr_protocol::changeset::VersionRef {
        change_set_id: kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid()),
        version: recorded.plain.version,
    };
    let (read, materialised) = read_and_materialise(&inside, env, unknown).await;
    for refusal in [read.err(), materialised.err()] {
        let refusal = refusal.expect("a version that is not there");
        assert!(said(&refusal).contains(does_not_reach), "{refusal}");
    }

    // The history: a grant that reaches back only to a moment after the capture reaches neither,
    // and one with no lower bound retains none.
    let (_c, later) = recorded
        .device(|grant| grant.history.lower_bound_ms = Nullable::some(beyond))
        .await;
    let (read, materialised) = read_and_materialise(&later, env, recorded.for_a_session).await;
    for refusal in [read.err(), materialised.err()] {
        let refusal = refusal.expect("a version captured before the grant reaches back to");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
        assert!(
            said(&refusal).contains("captured before the moment"),
            "{refusal}"
        );
    }
    let (_d, none) = recorded
        .device(|grant| grant.history.lower_bound_ms = Nullable::null())
        .await;
    let (read, materialised) = read_and_materialise(&none, env, recorded.plain).await;
    for refusal in [read.err(), materialised.err()] {
        let refusal = refusal.expect("a grant with no history");
        assert!(said(&refusal).contains("retains no history"), "{refusal}");
    }

    // The session: a grant that names sessions reaches a version captured for one of them and no
    // other, and a version that records none is out of scope for it. A grant over any session
    // reaches both, which is the control.
    let (_e, other) = recorded
        .device(|grant| {
            grant.session_selector = SessionSelector::These {
                session_ids: [another].into_iter().collect(),
            };
        })
        .await;
    let (_f, named) = recorded
        .device(|grant| {
            grant.session_selector = SessionSelector::These {
                session_ids: [recorded.session].into_iter().collect(),
            };
        })
        .await;
    let (_g, no_session) = recorded
        .device(|grant| grant.session_selector = SessionSelector::None)
        .await;
    for (device, version, reached, why) in [
        (
            &other,
            recorded.for_a_session,
            false,
            "another session's version",
        ),
        (
            &named,
            recorded.for_a_session,
            true,
            "the named session's version",
        ),
        (
            &named,
            recorded.plain,
            false,
            "a version that records no session",
        ),
        (
            &no_session,
            recorded.for_a_session,
            false,
            "a grant that names no session",
        ),
    ] {
        let (read, materialised) = read_and_materialise(device, env, version).await;
        // `changeset.read` of the same version is held to the same scope.
        let listed = device
            .read::<_, kr_protocol::changeset::ChangesetReadResult>(
                Method::ChangesetRead,
                &kr_protocol::changeset::ChangesetReadParams {
                    change_set_id: version.change_set_id,
                    version: Nullable::some(version.version),
                },
            )
            .await;
        if reached {
            read.unwrap_or_else(|error| panic!("{why}: the diff: {error}"));
            materialised.unwrap_or_else(|error| panic!("{why}: the materialisation: {error}"));
            listed.unwrap_or_else(|error| panic!("{why}: the change set: {error}"));
        } else {
            for refusal in [read.err(), materialised.err(), listed.err()] {
                let refusal = refusal.unwrap_or_else(|| panic!("{why} is out of scope"));
                assert_eq!(refusal.code(), ErrorCode::PermissionDenied, "{why}");
                assert!(said(&refusal).contains(does_not_reach), "{why}: {refusal}");
            }
        }
    }
    // Nothing the refused requests asked for was written out: only the control cases did.
    let owners: kr_protocol::changeset::ChangesetReadResult = {
        let mut control = recorded.host.client().await;
        locally(
            &mut control,
            Method::ChangesetRead,
            &kr_protocol::changeset::ChangesetReadParams {
                change_set_id: recorded.plain.change_set_id,
                version: Nullable::some(recorded.plain.version),
            },
        )
        .await
    };
    assert_eq!(
        owners.materialisations.len(),
        1,
        "the one version a device reached was written out once, and no refused request wrote any"
    );
    recorded.stop().await;
}

/// KR-REQ-23.44: capture, apply, revert and the diff of a working copy are refused to a device,
/// each by name and for the reason that is so: each reads or writes a working tree by running the
/// Git program, outside the boundary that confines what that program reads for a device's
/// repository operations. The refusal comes before the subject is looked up, so a device learns
/// nothing about which working copies exist. The control is the same host serving a recorded
/// version, which runs no Git.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_refused_what_runs_git_on_a_working_tree_with_the_reason() {
    let recorded = Recorded::start().await;
    let env = recorded.host.environment_id;
    let (_device, session) = recorded
        .device(|grant| {
            grant.actions.insert(ActionRight::ChangesetCreate);
            grant.actions.insert(ActionRight::FilesApplyDiff);
        })
        .await;
    let unknown = kr_protocol::ids::WorkspaceId::new(kr_ipc::new_uuid());
    let capture = kr_protocol::changeset::ChangesetCaptureParams {
        workspace_id: unknown,
        change_set_id: Nullable::null(),
        label: "a capture this host does not run for a device".to_owned(),
        policy: InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Exclude,
            submodules: InclusionChoice::Exclude,
            binary_files: InclusionChoice::Exclude,
            generated_artefacts: InclusionChoice::Exclude,
        },
        grant: kr_protocol::changeset::FileGrant {
            included_paths: Vec::new(),
            excluded_paths: Vec::new(),
            secret_rules_applied: true,
        },
        quiescence_declared: false,
        required_consistency: Nullable::null(),
        pin: false,
        session_id: Nullable::null(),
        workflow_run_id: Nullable::null(),
        note: String::new(),
    };
    let apply = kr_protocol::changeset::DiffApplyParams {
        change_set_id: recorded.plain.change_set_id,
        version: recorded.plain.version,
        destination: kr_protocol::changeset::DestinationClass::Proposal,
        workspace_id: Nullable::null(),
        expected_reference: Nullable::null(),
        affected: Vec::new(),
        paths: Vec::new(),
        preflight_only: true,
        acknowledged_limitations: Vec::new(),
    };
    let mut refused = Vec::new();
    refused.push((
        Method::ChangesetCapture,
        remote_mutation(&session, env, Method::ChangesetCapture, &capture).await,
    ));
    for method in [Method::DiffApply, Method::DiffRevert] {
        refused.push((method, remote_mutation(&session, env, method, &apply).await));
    }
    for (method, outcome) in refused {
        let refusal = outcome.expect_err("a method that runs Git on a working tree");
        assert_eq!(
            refusal.code(),
            ErrorCode::PermissionDenied,
            "{}",
            method.as_str()
        );
        let message = said(&refusal);
        assert!(
            message.contains(method.as_str())
                && message.contains("is not served to a paired device")
                && message
                    .contains("by running the Git program, outside the boundary that confines"),
            "the refusal names the method and the reason it is so: {message}"
        );
        assert!(
            !message.contains("cannot yet") && !message.contains("no workspace"),
            "it is not the old reason, and nothing looked the subject up: {message}"
        );
    }
    let working_copy = session
        .read::<_, kr_protocol::changeset::DiffReadResult>(
            Method::DiffRead,
            &kr_protocol::changeset::DiffReadParams {
                workspace_id: Nullable::some(recorded.workspace),
                change_set_id: Nullable::null(),
                version: Nullable::null(),
            },
        )
        .await
        .expect_err("a working copy's diff runs Git on its working tree");
    assert_eq!(working_copy.code(), ErrorCode::PermissionDenied);
    assert!(
        said(&working_copy).contains("diff.read is not served to a paired device")
            && said(&working_copy).contains("by running the Git program, outside the boundary"),
        "{working_copy}"
    );
    // The control: the same session reads the recorded version, which runs none.
    session
        .read::<_, kr_protocol::changeset::DiffReadResult>(
            Method::DiffRead,
            &read_of(recorded.plain),
        )
        .await
        .expect("a recorded version's diff runs no Git");
    session.close();
    recorded.stop().await;
}

/// KR-REQ-23.44 and section 9: a materialisation asked for by a device whose registration was
/// withdrawn is not performed, and the same request is performed once the device is admitted again.
///
/// The withdrawal here comes before the request, so what this holds is the door: the connection is
/// gone and nothing is dispatched. What holds the authority in force while the store commits the
/// effect is the change-set module's own hold, which this door hands the connection's admission to
/// and which `tests/changeset.rs` withdraws authority inside, through the owner's door.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_materialisation_asked_for_by_a_device_whose_authority_has_gone_is_not_performed() {
    let recorded = Recorded::start().await;
    let env = recorded.host.environment_id;
    let mut proposal = net_support::proposal(VERSION_RIGHTS);
    proposal.history.lower_bound_ms = Nullable::some(kr_protocol::scalars::TimestampMs::new(1));
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(&recorded.host, &device, &recorded.owner, proposal).await;
    let session = net_support::connect(&recorded.host, &device, &record).await;
    // The environment's authority is withdrawn, and every registration admitted under it goes
    // with it, this device's connection included.
    recorded
        .host
        .controller()
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let refusal = remote_mutation(
        &session,
        env,
        Method::ChangesetMaterialize,
        &materialise_of(recorded.plain),
    )
    .await
    .expect_err("a registration that was withdrawn writes nothing");
    // The withdrawal closed the device's connection, so what the device is told is that it ended.
    let _ = refusal;
    // The owner's own connection went with the rest, so it reads on a new one.
    let mut owners_own = recorded.host.client().await;
    let owners: kr_protocol::changeset::ChangesetReadResult = locally(
        &mut owners_own,
        Method::ChangesetRead,
        &kr_protocol::changeset::ChangesetReadParams {
            change_set_id: recorded.plain.change_set_id,
            version: Nullable::some(recorded.plain.version),
        },
    )
    .await;
    assert!(
        owners.materialisations.is_empty(),
        "nothing was written out under the withdrawn authority"
    );
    // The control: the device is admitted again on a new connection, and the same request writes
    // the version out.
    let again = net_support::connect(&recorded.host, &device, &record).await;
    remote_mutation(
        &again,
        env,
        Method::ChangesetMaterialize,
        &materialise_of(recorded.plain),
    )
    .await
    .expect("the device admitted again has the version written out");
    again.close();
    session.close();
    recorded.stop().await;
}

/// The owner's four location methods are the owner's alone. A paired device that asks for any of
/// them is told the method is not available, in the words an unlisted method gets, before its
/// parameters are read, whatever rights its grant carries; the registry says the same for every
/// other ingress that is not the local one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_methods_reject_every_nonlocal_ingress() {
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::authority::AuthorityDecision;
    use kr_protocol::project::{
        LocationPurpose, ProjectLocationAttachParams, ProjectLocationAuthoriseParams,
        ProjectLocationListParams, ProjectLocationListResult, ProjectLocationWithdrawParams,
    };

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let mut rights = PROJECT_RIGHTS.to_vec();
    rights.push(ActionRight::HostManage);
    let (_device, session) = net_support::paired_device(&host, &owner, &rights).await;
    let location = kr_protocol::ids::ProjectLocationId::new(kr_ipc::new_uuid());
    const NOT_AVAILABLE: &str = "the method is not available";

    let listed = session
        .read::<_, ProjectLocationListResult>(
            Method::ProjectLocationList,
            &ProjectLocationListParams {
                environment_id: host.environment_id,
                grant_id: Nullable::null(),
            },
        )
        .await
        .expect_err("a device lists no location");
    assert_eq!(listed.code(), ErrorCode::PermissionDenied);
    assert_eq!(said(&listed), NOT_AVAILABLE);
    let writes: Vec<(Method, ParamsValue)> = vec![
        (
            Method::ProjectLocationAuthorise,
            ParamsValue::from_typed(&ProjectLocationAuthoriseParams {
                location_id: Nullable::null(),
                environment_id: host.environment_id,
                grant_id: Nullable::null(),
                purpose: LocationPurpose::Source,
                label: "a device's own".to_owned(),
                path: host.work().display().to_string(),
                owner_confirmation: Nullable::null(),
            })
            .expect("encodes"),
        ),
        (
            Method::ProjectLocationWithdraw,
            ParamsValue::from_typed(&ProjectLocationWithdrawParams {
                location_id: location,
            })
            .expect("encodes"),
        ),
        (
            Method::ProjectLocationAttach,
            ParamsValue::from_typed(&ProjectLocationAttachParams {
                project_repository_id: kr_protocol::ids::ProjectRepositoryId::new(
                    kr_ipc::new_uuid(),
                ),
                location_id: Nullable::some(location),
                owner_confirmation: Nullable::null(),
            })
            .expect("encodes"),
        ),
        // Parameters that are not the method's at all are refused the same way, because the
        // refusal comes before anything reads them.
        (
            Method::ProjectLocationAuthorise,
            ParamsValue::from_typed(&"not the parameters of anything").expect("encodes"),
        ),
    ];
    for (method, params) in writes {
        let error = remote_mutation(&session, host.environment_id, method, &params)
            .await
            .expect_err("a device reaches no owner method");
        assert_eq!(
            error.code(),
            ErrorCode::PermissionDenied,
            "{}",
            method.as_str()
        );
        assert_eq!(said(&error), NOT_AVAILABLE, "{}", method.as_str());
    }
    for method in [
        Method::ProjectLocationList,
        Method::ProjectLocationAuthorise,
        Method::ProjectLocationWithdraw,
        Method::ProjectLocationAttach,
    ] {
        for ingress in [ActorIngress::PairedDevice, ActorIngress::Workflow] {
            assert!(
                !matches!(
                    kr_protocol::method::decide(method.as_str(), method.entry().version, ingress),
                    AuthorityDecision::Listed(_)
                ),
                "{} is not listed for {ingress:?}",
                method.as_str()
            );
        }
    }
    // The owner's own door is the one that serves them.
    let owners: ProjectLocationListResult = locally(
        &mut control,
        Method::ProjectLocationList,
        &ProjectLocationListParams {
            environment_id: host.environment_id,
            grant_id: Nullable::null(),
        },
    )
    .await;
    assert!(owners.locations.is_empty());
    session.close();
    host.stop().await;
}

// ----- a device's location -------------------------------------------------------------------

/// The parameters of an authorisation of `path` for `purpose`, for the grant a device holds.
fn location_for(
    host: &Host,
    path: &Path,
    purpose: kr_protocol::project::LocationPurpose,
    grant: Option<kr_protocol::ids::GrantId>,
) -> kr_protocol::project::ProjectLocationAuthoriseParams {
    kr_protocol::project::ProjectLocationAuthoriseParams {
        location_id: Nullable::null(),
        environment_id: host.environment_id,
        grant_id: Nullable(grant),
        purpose,
        label: "a place the owner chose".to_owned(),
        path: path.display().to_string(),
        owner_confirmation: Nullable::null(),
    }
}

/// The owner's proof for one challenge, after its own ceremony.
fn signed_by(
    owner: &DeviceKeys,
    request: &kr_protocol::pairing::OwnerConfirmationRequest,
) -> kr_protocol::pairing::OwnerConfirmationProof {
    kr_pairing::confirm::sign_confirmation(
        &owner.authorisation,
        request,
        kr_protocol::pairing::ConfirmationChannel::OwnerDevicePresence,
    )
    .expect("the proof is signed")
}

/// Submits the first half of an authorisation on the owner's own socket, and returns the
/// challenge it was answered with.
async fn challenge_of(
    control: &mut LocalClient,
    host: &Host,
    action: ActionId,
    params: &kr_protocol::project::ProjectLocationAuthoriseParams,
) -> std::result::Result<kr_protocol::pairing::OwnerConfirmationRequest, ProtocolError> {
    let answered: kr_protocol::project::ProjectLocationAuthoriseResult = typed(
        &control
            .mutate(
                Method::ProjectLocationAuthorise,
                action,
                ActionTarget::environment(host.environment_id),
                params,
            )
            .await
            .expect("the call reaches the daemon")?,
    );
    match answered.outcome {
        kr_protocol::project::LocationAuthorisation::ConfirmationRequired { request } => {
            Ok(request)
        }
        kr_protocol::project::LocationAuthorisation::Authorised { .. } => {
            panic!("an authorisation with no proof authorises nothing")
        }
    }
}

/// Submits the second half, carrying `proof`.
async fn authorised_with(
    control: &mut LocalClient,
    host: &Host,
    action: ActionId,
    params: &kr_protocol::project::ProjectLocationAuthoriseParams,
    proof: kr_protocol::pairing::OwnerConfirmationProof,
) -> std::result::Result<kr_protocol::project::AuthorisedLocation, ProtocolError> {
    let proven = kr_protocol::project::ProjectLocationAuthoriseParams {
        owner_confirmation: Nullable(Some(proof)),
        ..params.clone()
    };
    let answered: kr_protocol::project::ProjectLocationAuthoriseResult = typed(
        &control
            .mutate(
                Method::ProjectLocationAuthorise,
                action,
                ActionTarget::environment(host.environment_id),
                &proven,
            )
            .await
            .expect("the call reaches the daemon")?,
    );
    match answered.outcome {
        kr_protocol::project::LocationAuthorisation::Authorised { location } => Ok(location),
        kr_protocol::project::LocationAuthorisation::ConfirmationRequired { .. } => {
            panic!("a submission carrying its proof is not answered with another challenge")
        }
    }
}

/// KR-REQ-23.42 and KR-REQ-23.43, and the specification's sensitive owner confirmation: the
/// owner's confirmation of a device's location is bound to that device's four public keys.
///
/// The challenge names all four keys the host holds for the device that holds the grant, a proof
/// for a challenge naming another device's keys authorises nothing, and the confirmation then
/// authorises the location for that grant. The control is the owner's own location, whose
/// challenge names no device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owners_confirmation_of_a_devices_location_names_that_devices_four_keys() {
    use kr_protocol::project::LocationPurpose;

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let first = net_support::Device::create().await;
    let held =
        net_support::pair_with(&host, &first, &owner, net_support::proposal(PROJECT_RIGHTS)).await;
    let second = net_support::Device::create().await;
    let _other = net_support::pair_with(
        &host,
        &second,
        &owner,
        net_support::proposal(PROJECT_RIGHTS),
    )
    .await;
    let grant = held.grant.grant_id;
    let root = host.work().join("devices");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let params = location_for(&host, &root, LocationPurpose::Source, Some(grant));

    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenge_of(&mut control, &host, action, &params)
        .await
        .expect("a device's location is given a challenge");
    assert_eq!(
        request.action,
        kr_protocol::pairing::SensitiveAction::EnlargeGrant
    );
    assert_eq!(
        request.destination_keys.0,
        Some(first.keys().public_keys()),
        "the challenge names the device that holds the grant by all four of its keys"
    );
    assert_eq!(request.destination_keys.0, held.public_keys());

    // A challenge that names another device's keys is not this one, and its proof is refused
    // without spending this one.
    let mut elsewhere = request.clone();
    elsewhere.destination_keys = Nullable(Some(second.keys().public_keys()));
    let refusal = authorised_with(
        &mut control,
        &host,
        action,
        &params,
        signed_by(&owner, &elsewhere),
    )
    .await
    .expect_err("a confirmation naming another device's keys authorises nothing");
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);

    let location = authorised_with(
        &mut control,
        &host,
        action,
        &params,
        signed_by(&owner, &request),
    )
    .await
    .expect("the confirmation for this device authorises its location");
    assert_eq!(location.grant_id.0, Some(grant));

    // The control: the owner's own location names no device, and is as it always was.
    let own = location_for(&host, host.work(), LocationPurpose::Source, None);
    let own_request = challenge_of(&mut control, &host, ActionId::new(kr_ipc::new_uuid()), &own)
        .await
        .expect("the owner's own location is given a challenge");
    assert!(own_request.destination_keys.0.is_none());

    host.stop().await;
}

/// The same binding at the owner's own seam: a challenge issued for one device's grant does not
/// verify as the confirmation of another device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_issued_for_one_devices_location_does_not_verify_for_anothers() {
    use kr_project::policy::{Enlargement, OwnerAuthority as _};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let first = net_support::Device::create().await;
    let held =
        net_support::pair_with(&host, &first, &owner, net_support::proposal(PROJECT_RIGHTS)).await;
    let second = net_support::Device::create().await;
    let other = net_support::pair_with(
        &host,
        &second,
        &owner,
        net_support::proposal(PROJECT_RIGHTS),
    )
    .await;
    let authority =
        kr_controller::project::HostOwner::new(std::sync::Arc::clone(host.network().pairing()));
    let rights: kr_protocol::scalars::CanonicalSet<ActionRight> =
        [ActionRight::ProjectCreate, ActionRight::WorkspaceManage]
            .into_iter()
            .collect();
    let enlargement = |grant| Enlargement {
        action_digest: kr_protocol::scalars::Digest256::from_bytes([0x5a; 32]),
        rights: rights.clone(),
        destination: Some(grant),
    };
    let request = authority
        .challenge(&enlargement(held.grant.grant_id))
        .expect("a challenge for the first device's location");
    assert_eq!(request.destination_keys.0, held.public_keys());
    let proof = signed_by(&owner, &request);
    authority
        .verify(&enlargement(held.grant.grant_id), &proof)
        .expect("it verifies for the device it names");
    let refusal = authority
        .verify(&enlargement(other.grant.grant_id), &proof)
        .expect_err("it does not verify for another device's location");
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    // And the owner's own enlargement is not this device's: the same digest and rights with no
    // destination are a different confirmation.
    let own = Enlargement {
        destination: None,
        ..enlargement(held.grant.grant_id)
    };
    let refusal = authority
        .verify(&own, &proof)
        .expect_err("a challenge naming a device is not the owner's own location's");
    assert_eq!(refusal.code, ErrorCode::OwnerConfirmationRequired);
    // Spent once, for the device it names.
    authority
        .consume(&enlargement(other.grant.grant_id), &proof)
        .expect_err("it is not spent for another device's location");
    authority
        .consume(&enlargement(held.grant.grant_id), &proof)
        .expect("it is spent for the device it names");
    host.stop().await;
}

/// A device that has not declared all four keys cannot be named in a confirmation, and the owner
/// is told to have it declare them first. Once it has, the same request is given its challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_has_not_declared_its_keys_is_refused_a_confirmation_until_it_does() {
    use kr_protocol::project::LocationPurpose;
    use kr_protocol::sharing::{
        DEVICE_KEYS_DOMAIN, DeviceKeysCompleteParams, DeviceKeysDeclaration,
    };

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
    // The row as a host that kept two of the device's keys wrote it.
    let connection = rusqlite::Connection::open(host.registry_database()).expect("the registry");
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("a timeout");
    assert_eq!(
        connection
            .execute(
                "UPDATE network_devices
                    SET stored_envelope_key = NULL, notification_preview = NULL
                  WHERE device_id = ?1",
                rusqlite::params![record.device_id.get().as_bytes().as_slice()],
            )
            .expect("the row is written"),
        1
    );
    let session = net_support::connect(&host, &device, &record).await;
    let root = host.work().join("devices");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let params = location_for(
        &host,
        &root,
        LocationPurpose::Source,
        Some(record.grant.grant_id),
    );
    let refusal = challenge_of(
        &mut control,
        &host,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect_err("a device with two keys on record cannot be named");
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(
        refusal
            .message
            .contains("has not declared all four of its public keys")
            && refusal.message.contains("device.keys.complete"),
        "{}",
        refusal.message
    );

    // The control: the device declares its own keys, signed by the key its pairing recorded, and
    // the same request is given its challenge.
    let keys = device.keys().public_keys();
    let declaration = DeviceKeysCompleteParams {
        keys,
        signature: kr_crypto::sign::sign_object(
            &device.keys().authorisation,
            DEVICE_KEYS_DOMAIN,
            &DeviceKeysDeclaration {
                device_id: record.device_id,
                keys,
            },
        )
        .expect("a signature"),
    };
    session
        .mutate(
            Method::DeviceKeysComplete,
            ActionTarget::environment(host.environment_id),
            None,
            &ParamsValue::empty(),
            &declaration,
            LIFETIME,
        )
        .await
        .expect("the device declares its own keys");
    let request = challenge_of(
        &mut control,
        &host,
        ActionId::new(kr_ipc::new_uuid()),
        &params,
    )
    .await
    .expect("with its keys declared the device is named");
    assert_eq!(request.destination_keys.0, Some(keys));
    session.close();
    host.stop().await;
}

// ----- the five repository operations on a host that proves Git's reads confined -------------

/// Starts a host, or returns none and says so when it does not prove Git's reads confined: the
/// test that asked for one is not run there.
async fn qualified_host(owner: &DeviceKeys, test: &str) -> Option<Host> {
    let host = Host::start(owner).await;
    let proved = host.controller().qualification();
    if proved.qualifies() {
        return Some(host);
    }
    println!(
        "not exercised: {test} needs a host that proves Git's reads confined, and this one does \
         not ({:?}: {})",
        proved.refusal(),
        proved.detail()
    );
    host.stop().await;
    None
}

/// Authorises `path` for `purpose` as the owner does, for the device that holds `grant`.
async fn authorise_for(
    control: &mut LocalClient,
    host: &Host,
    owner: &DeviceKeys,
    path: &Path,
    purpose: kr_protocol::project::LocationPurpose,
    grant: kr_protocol::ids::GrantId,
) -> kr_protocol::project::AuthorisedLocation {
    let params = location_for(host, path, purpose, Some(grant));
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenge_of(control, host, action, &params)
        .await
        .expect("the device's location is given a challenge");
    authorised_with(control, host, action, &params, signed_by(owner, &request))
        .await
        .expect("the owner's confirmation authorises the device's location")
}

/// Binds a repository to a source location as the owner does, and returns the challenge's
/// destination: the keys of the device the location is for.
async fn bind_for(
    control: &mut LocalClient,
    host: &Host,
    owner: &DeviceKeys,
    project: kr_protocol::ids::ProjectRepositoryId,
    location: kr_protocol::ids::ProjectLocationId,
) -> Option<kr_protocol::pairing::DevicePublicKeys> {
    use kr_protocol::project::{
        LocationAttachment, ProjectLocationAttachParams, ProjectLocationAttachResult,
    };

    let params = ProjectLocationAttachParams {
        project_repository_id: project,
        location_id: Nullable::some(location),
        owner_confirmation: Nullable::null(),
    };
    let action = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);
    let first: ProjectLocationAttachResult = typed(
        &control
            .mutate(
                Method::ProjectLocationAttach,
                action,
                target.clone(),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("a binding's first submission is answered"),
    );
    let LocationAttachment::ConfirmationRequired { request } = first.outcome else {
        panic!("a binding's first submission is answered with its challenge");
    };
    let named = request.destination_keys.0;
    let proven = ProjectLocationAttachParams {
        owner_confirmation: Nullable::some(signed_by(owner, &request)),
        ..params
    };
    let second: ProjectLocationAttachResult = typed(
        &control
            .mutate(Method::ProjectLocationAttach, action, target, &proven)
            .await
            .expect("the call reaches the daemon")
            .expect("the owner's confirmation binds the repository"),
    );
    assert!(
        matches!(second.outcome, LocationAttachment::Bound { .. }),
        "the repository is bound"
    );
    named
}

/// A host that proves Git's reads confined, a paired device, the two locations the owner
/// authorised for its grant over one directory, and the owner's own repository in that directory,
/// bound to the source location.
struct Granted {
    host: Host,
    control: LocalClient,
    /// The device's own endpoint, which has to live as long as its connection does.
    _device: net_support::Device,
    session: Session,
    owner: DeviceKeys,
    record: kr_controller::service::net::devices::DeviceRecord,
    /// The directory both locations are over.
    root: PathBuf,
    source: kr_protocol::project::AuthorisedLocation,
    destination: kr_protocol::project::AuthorisedLocation,
    project: kr_protocol::ids::ProjectRepositoryId,
}

impl Granted {
    /// Sets the scene, or returns none and says so on a host that does not qualify.
    async fn on_a_qualified_host(test: &str) -> Option<Self> {
        use kr_protocol::project::LocationPurpose;

        let owner = DeviceKeys::generate().expect("owner keys");
        let host = qualified_host(&owner, test).await?;
        let mut control = host.client().await;
        let device = net_support::Device::create().await;
        let record = net_support::pair_with(
            &host,
            &device,
            &owner,
            net_support::proposal(PROJECT_RIGHTS),
        )
        .await;
        let session = net_support::connect(&host, &device, &record).await;
        let grant = record.grant.grant_id;
        let root = host.work().join("granted");
        std::fs::create_dir(&root).expect("a directory to authorise");
        repository(&root, "src");
        // A directory wanted as a destination and as a source is authorised twice.
        let source = authorise_for(
            &mut control,
            &host,
            &owner,
            &root,
            LocationPurpose::Source,
            grant,
        )
        .await;
        let destination = authorise_for(
            &mut control,
            &host,
            &owner,
            &root,
            LocationPurpose::Destination,
            grant,
        )
        .await;
        let adopted: ProjectAdoptResult = typed(
            &local_mutation(
                &mut control,
                host.environment_id,
                Method::ProjectAdopt,
                &ProjectAdoptParams {
                    destination: DestinationRequest {
                        environment_id: host.environment_id,
                        parent: kr_protocol::project::DestinationParent::Host {
                            path: root.display().to_string(),
                        },
                        name: "src".to_owned(),
                    },
                    label: "src".to_owned(),
                    flow: AdoptionFlow::ExistingCheckout,
                },
            )
            .await
            .expect("the owner adopts the repository in the directory"),
        );
        let project = adopted.project.project_repository_id;
        let named = bind_for(&mut control, &host, &owner, project, source.location_id).await;
        assert_eq!(
            named,
            record.public_keys(),
            "binding a repository to the device's location names that device's four keys"
        );
        Some(Self {
            host,
            control,
            _device: device,
            session,
            owner,
            record,
            root,
            source,
            destination,
            project,
        })
    }

    /// A clone into the destination location, from `source`.
    fn clone_into(&self, name: &str, source: CloneSource) -> ProjectCloneParams {
        ProjectCloneParams {
            destination: self.in_destination(name),
            label: name.to_owned(),
            source,
        }
    }

    /// A name beneath the destination location.
    fn in_destination(&self, name: &str) -> DestinationRequest {
        DestinationRequest {
            environment_id: self.host.environment_id,
            parent: kr_protocol::project::DestinationParent::Location {
                location_id: self.destination.location_id,
            },
            name: name.to_owned(),
        }
    }

    /// A clone from the repository the owner bound to the source location.
    fn clone_of_src(&self, name: &str) -> ProjectCloneParams {
        self.clone_into(
            name,
            CloneSource::Location {
                location_id: self.source.location_id,
                relative_path: "src".to_owned(),
            },
        )
    }

    /// A working copy of `project`, made beneath the destination location.
    fn working_copy(
        &self,
        project: kr_protocol::ids::ProjectRepositoryId,
        name: &str,
    ) -> WorkspaceCreateParams {
        WorkspaceCreateParams {
            isolation: Nullable::some(IsolationMechanism::IndependentClone),
            destination: Nullable::some(self.in_destination(name)),
            ..workspace_params(&self.host, project, name)
        }
    }

    /// What the device was told, when it asked for `method` and was refused.
    async fn refused<P: serde::Serialize + ?Sized>(
        &self,
        method: Method,
        params: &P,
    ) -> ClientError {
        remote_mutation(&self.session, self.host.environment_id, method, params)
            .await
            .expect_err("the device is refused")
    }

    async fn stop(self) {
        self.session.close();
        self.host.stop().await;
    }
}

/// KR-REQ-23.42 and KR-REQ-23.43: on a host that proves Git's reads confined, a device clones,
/// makes a working copy and removes it, inside the locations the owner authorised for its grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_clones_makes_a_working_copy_and_removes_it_inside_its_granted_location() {
    let Some(granted) = Granted::on_a_qualified_host(
        "a_device_clones_makes_a_working_copy_and_removes_it_inside_its_granted_location",
    )
    .await
    else {
        return;
    };
    let env = granted.host.environment_id;

    // A clone, from the source location into the destination location.
    let cloned: ProjectCloneResult = typed(
        &remote_mutation(
            &granted.session,
            env,
            Method::ProjectClone,
            &granted.clone_of_src("clone"),
        )
        .await
        .expect("the device clones inside its granted location"),
    );
    assert_eq!(cloned.operation.state, OperationState::Completed);
    assert_eq!(
        std::fs::read_to_string(granted.root.join("clone/README.md")).expect("the clone's file"),
        "a repository\n",
        "the clone holds what was committed"
    );

    // A working copy of the owner's repository, made through the source location it is bound to
    // and carrying the file the owner changed since the commit.
    let created: WorkspaceCreateResult = typed(
        &remote_mutation(
            &granted.session,
            env,
            Method::WorkspaceCreate,
            &granted.working_copy(granted.project, "review"),
        )
        .await
        .expect("the device makes a working copy inside its granted location"),
    );
    let workspace = created
        .workspace
        .0
        .expect("a creation returns the workspace");
    assert_eq!(
        std::fs::read_to_string(granted.root.join("review/README.md")).expect("the working copy"),
        "changed after the commit\n",
        "the working copy carries the owner's dirty file"
    );

    // And the removal, which takes the working copy's files with it.
    let removed: WorkspaceRemoveResult = typed(
        &remote_mutation(
            &granted.session,
            env,
            Method::WorkspaceRemove,
            &WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
                through_location_id: Nullable::null(),
            },
        )
        .await
        .expect("the device removes the working copy it made"),
    );
    assert!(removed.working_files_removed);
    assert!(
        !granted.root.join("review").exists(),
        "the working copy's directory is gone"
    );
    assert!(
        granted.root.join("src/README.md").is_file() && granted.root.join("clone/.git").is_dir(),
        "and nothing else was removed"
    );
    granted.stop().await;
}

/// KR-REQ-23.42: what a device names has to be reached through a location the owner authorised for
/// its own grant. A path of its own, the owner's location, a name that leaves the location and a
/// remote are each refused, and nothing is created.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_nothing_outside_the_locations_the_owner_authorised_for_it() {
    use kr_protocol::project::{DestinationParent, LocationPurpose};

    let Some(mut granted) = Granted::on_a_qualified_host(
        "a_device_reaches_nothing_outside_the_locations_the_owner_authorised_for_it",
    )
    .await
    else {
        return;
    };
    let outside = granted.host.work().join("outside");
    std::fs::create_dir(&outside).expect("a directory outside the locations");
    repository(&outside, "elsewhere");

    // A path of its own, which only the owner's own socket names.
    let by_path = ProjectCloneParams {
        destination: DestinationRequest {
            environment_id: granted.host.environment_id,
            parent: DestinationParent::Host {
                path: outside.display().to_string(),
            },
            name: "taken".to_owned(),
        },
        label: "taken".to_owned(),
        source: CloneSource::Location {
            location_id: granted.source.location_id,
            relative_path: "src".to_owned(),
        },
    };
    let refused = granted.refused(Method::ProjectClone, &by_path).await;
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        said(&refused).contains("names a location for a destination"),
        "{refused}"
    );
    assert!(!outside.join("taken").exists());

    // The owner's own location is the owner's, though it covers the same directory: the device is
    // told the location admits the owner and not its grant.
    let owners = authorise_owner_location(
        &mut granted.control,
        &granted.host,
        &granted.owner,
        &outside,
        LocationPurpose::Destination,
    )
    .await;
    let into_owners = ProjectCloneParams {
        destination: DestinationRequest {
            environment_id: granted.host.environment_id,
            parent: DestinationParent::Location {
                location_id: owners.location_id,
            },
            name: "taken".to_owned(),
        },
        ..granted.clone_of_src("taken")
    };
    let refused = granted.refused(Method::ProjectClone, &into_owners).await;
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(said(&refused).contains("admits the owner"), "{refused}");
    assert!(!outside.join("taken").exists());

    // A source that is the owner's own location, and a name that leaves the location.
    let from_owners = granted.clone_into(
        "taken",
        CloneSource::Location {
            location_id: owners.location_id,
            relative_path: "elsewhere".to_owned(),
        },
    );
    let refused = granted.refused(Method::ProjectClone, &from_owners).await;
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    for leaving in ["../outside/elsewhere", "/etc"] {
        let leaves = granted.clone_into(
            "taken",
            CloneSource::Location {
                location_id: granted.source.location_id,
                relative_path: leaving.to_owned(),
            },
        );
        let refused = granted.refused(Method::ProjectClone, &leaves).await;
        assert!(
            matches!(
                refused.code(),
                ErrorCode::InvalidArgument | ErrorCode::PermissionDenied
            ),
            "{leaving}: {refused}"
        );
    }
    assert!(!granted.root.join("taken").exists());

    // A remote stays refused for a device, whatever the host proves: no location says which
    // providers this host may reach for it.
    let remote = granted.clone_into(
        "remote",
        CloneSource::Remote {
            remote: RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::LocalPath,
                url: outside.join("elsewhere").display().to_string(),
                provider: String::new(),
                credential_broker: String::new(),
            },
        },
    );
    let refused = granted.refused(Method::ProjectClone, &remote).await;
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused}");
    assert!(
        said(&refused).contains("does not clone a remote"),
        "{refused}"
    );
    assert!(!granted.root.join("remote").exists());

    // The control: the same clone, into the device's own destination from its own source.
    let cloned: ProjectCloneResult = typed(
        &remote_mutation(
            &granted.session,
            granted.host.environment_id,
            Method::ProjectClone,
            &granted.clone_of_src("taken"),
        )
        .await
        .expect("the same clone through the device's own locations"),
    );
    assert_eq!(cloned.operation.state, OperationState::Completed);
    granted.stop().await;
}

/// Authorises `path` as the owner's own location, which names no grant.
async fn authorise_owner_location(
    control: &mut LocalClient,
    host: &Host,
    owner: &DeviceKeys,
    path: &Path,
    purpose: kr_protocol::project::LocationPurpose,
) -> kr_protocol::project::AuthorisedLocation {
    let params = location_for(host, path, purpose, None);
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = challenge_of(control, host, action, &params)
        .await
        .expect("the owner's own location is given a challenge");
    authorised_with(control, host, action, &params, signed_by(owner, &request))
        .await
        .expect("the owner's own location is authorised")
}

/// KR-REQ-23.42 and KR-REQ-14.06: what a device can influence through repository content is read
/// by nothing outside the location.
///
/// The owner's repository in the location can borrow another repository's objects through an
/// alternates file and can include a configuration file through a link inside the location, and a
/// device clones from it. The alternates name is refused before Git starts, and the link is
/// refused where Git opens its target: the kernel denies a read of the file the link leads to,
/// outside every directory the invocation was lent. Neither refusal repeats what the outside file
/// holds. The control is the same repository with the link leading to a file inside the location,
/// which is read and cloned from.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_nothing_outside_its_location_through_repository_content() {
    let Some(granted) = Granted::on_a_qualified_host(
        "a_device_reads_nothing_outside_its_location_through_repository_content",
    )
    .await
    else {
        return;
    };
    let outside = granted.host.work().join("outside");
    std::fs::create_dir(&outside).expect("a directory outside the location");
    let secret = outside.join("secret.config");
    std::fs::write(&secret, "[secret]\n\tvalue = held-outside-the-location\n")
        .expect("a file outside the location");

    // A repository that borrows the objects of one outside the location.
    let other = repository(&outside, "other");
    let borrowing = repository(&granted.root, "borrowing");
    std::fs::write(
        borrowing.join(".git/objects/info/alternates"),
        format!("{}\n", other.join(".git/objects").display()),
    )
    .expect("an alternates file");
    let refused = granted
        .refused(
            Method::ProjectClone,
            &granted.clone_into(
                "from-borrowing",
                CloneSource::Location {
                    location_id: granted.source.location_id,
                    relative_path: "borrowing".to_owned(),
                },
            ),
        )
        .await;
    assert!(
        said(&refused).contains("objects/info/alternates"),
        "the refusal names the alternates file: {refused}"
    );
    assert!(!granted.root.join("from-borrowing").exists());

    // A repository whose configuration includes a file through a link inside the location.
    let linked = repository(&granted.root, "linked");
    let link = linked.join("included.config");
    std::os::unix::fs::symlink(&secret, &link).expect("a link inside the location");
    git_raw(
        &linked,
        [
            std::ffi::OsStr::new("config"),
            std::ffi::OsStr::new("--local"),
            std::ffi::OsStr::new("include.path"),
            link.as_os_str(),
        ],
    );
    let from_linked = granted.clone_into(
        "from-linked",
        CloneSource::Location {
            location_id: granted.source.location_id,
            relative_path: "linked".to_owned(),
        },
    );
    let refused = granted.refused(Method::ProjectClone, &from_linked).await;
    assert!(
        !said(&refused).contains("held-outside-the-location"),
        "nothing of the file the link leads to is repeated: {refused}"
    );
    assert!(!granted.root.join("from-linked").exists());

    // The control: the same repository and the same include, with the link leading to a file
    // inside the repository. The file is read, and the clone is made.
    // Inside the repository the device is lent, which is all the clone may read.
    let inside = linked.join("inside.config");
    std::fs::write(&inside, "[secret]\n\tvalue = held-inside-the-location\n")
        .expect("a file inside the location");
    std::fs::remove_file(&link).expect("the link is replaced");
    std::os::unix::fs::symlink(&inside, &link).expect("a link to a file inside the location");
    let cloned: ProjectCloneResult = typed(
        &remote_mutation(
            &granted.session,
            granted.host.environment_id,
            Method::ProjectClone,
            &from_linked,
        )
        .await
        .expect("with the link leading inside the location the clone is made"),
    );
    assert_eq!(cloned.operation.state, OperationState::Completed);
    granted.stop().await;
}

/// KR-REQ-23.42 and section 9: a grant withdrawn before the write stops each of the five
/// operations, and one still standing lets the same operation through.
///
/// The daemon asks the admission a mutation was accepted under once before the service acts and
/// again inside the transaction that begins the effect. Each operation is run with an admission
/// that answers yes the first time and says the grant was withdrawn the second, and then with one
/// that always says yes, on a name of its own: the first leaves nothing behind, the second makes
/// what was asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_withdrawn_before_the_write_stops_each_of_the_five_operations() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let Some(mut granted) = Granted::on_a_qualified_host(
        "a_grant_withdrawn_before_the_write_stops_each_of_the_five_operations",
    )
    .await
    else {
        return;
    };
    let env = granted.host.environment_id;
    let actor = granted.record.principal();
    let grant = granted.record.grant.grant_id;
    repository(&granted.root, "adopt-withdrawn");
    repository(&granted.root, "adopt-standing");
    // A working copy for the removals to name, made by the device before anything is withdrawn.
    let mut working_copies = Vec::new();
    for name in ["remove-withdrawn", "remove-standing"] {
        let created: WorkspaceCreateResult = typed(
            &remote_mutation(
                &granted.session,
                env,
                Method::WorkspaceCreate,
                &granted.working_copy(granted.project, name),
            )
            .await
            .expect("the device makes a working copy"),
        );
        working_copies.push(created.workspace.0.expect("a working copy").workspace_id);
    }

    // Each case is one operation under a name of its own, which is its label and the directory it
    // makes, run with the grant withdrawn before the write or standing throughout.
    let init = |name: &str| {
        ParamsValue::from_typed(&ProjectInitParams {
            destination: granted.in_destination(name),
            label: name.to_owned(),
            initial_branch: Nullable::null(),
        })
        .expect("encodes")
    };
    let adopt = |name: &str| {
        ParamsValue::from_typed(&ProjectAdoptParams {
            destination: granted.in_destination(name),
            label: name.to_owned(),
            flow: AdoptionFlow::ExistingCheckout,
        })
        .expect("encodes")
    };
    let remove = |workspace_id| {
        ParamsValue::from_typed(&WorkspaceRemoveParams {
            workspace_id,
            retention: RetentionPolicy::RemoveRetained,
            through_location_id: Nullable::null(),
        })
        .expect("encodes")
    };
    let cases: Vec<(Method, ParamsValue, &str, bool)> = vec![
        (
            Method::ProjectInit,
            init("init-withdrawn"),
            "init-withdrawn",
            false,
        ),
        (
            Method::ProjectInit,
            init("init-standing"),
            "init-standing",
            true,
        ),
        (
            Method::ProjectClone,
            ParamsValue::from_typed(&granted.clone_of_src("clone-withdrawn")).expect("encodes"),
            "clone-withdrawn",
            false,
        ),
        (
            Method::ProjectClone,
            ParamsValue::from_typed(&granted.clone_of_src("clone-standing")).expect("encodes"),
            "clone-standing",
            true,
        ),
        (
            Method::ProjectAdopt,
            adopt("adopt-withdrawn"),
            "adopt-withdrawn",
            false,
        ),
        (
            Method::ProjectAdopt,
            adopt("adopt-standing"),
            "adopt-standing",
            true,
        ),
        (
            Method::WorkspaceCreate,
            ParamsValue::from_typed(&granted.working_copy(granted.project, "create-withdrawn"))
                .expect("encodes"),
            "create-withdrawn",
            false,
        ),
        (
            Method::WorkspaceCreate,
            ParamsValue::from_typed(&granted.working_copy(granted.project, "create-standing"))
                .expect("encodes"),
            "create-standing",
            true,
        ),
        (
            Method::WorkspaceRemove,
            remove(working_copies[0]),
            "remove-withdrawn",
            false,
        ),
        (
            Method::WorkspaceRemove,
            remove(working_copies[1]),
            "remove-standing",
            true,
        ),
    ];
    for (method, params, name, standing) in cases {
        let mutation = granted
            .control
            .compose(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(env),
                &params,
            )
            .await
            .expect("the mutation is composed");
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let admission = {
            let asked = std::sync::Arc::clone(&asked);
            move || {
                if standing || asked.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(())
                } else {
                    Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "the authority this action was admitted under was withdrawn",
                    ))
                }
            }
        };
        let outcome = granted
            .host
            .controller()
            .project()
            .write(&actor, &mutation, method, admission, Some(grant))
            .await;
        if standing {
            outcome.unwrap_or_else(|error| {
                panic!(
                    "{} for {name} with the grant standing: {error:?}",
                    method.as_str()
                )
            });
        } else {
            let refusal = outcome.expect_err("the grant was withdrawn before the write");
            assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{name}");
            assert!(refusal.message.contains("withdrawn"), "{name}: {refusal:?}");
        }
        let exists = granted.root.join(name).exists();
        if method == Method::WorkspaceRemove {
            assert_eq!(
                exists, !standing,
                "{name}: a removal under a standing grant takes the working copy, and one under a \
                 withdrawn grant leaves it"
            );
        } else {
            assert_eq!(
                labelled(&mut granted.control, env, name).await,
                standing,
                "{} for {name}: what the owner can see afterwards",
                method.as_str()
            );
            // An adoption names a checkout that was there before it.
            if method != Method::ProjectAdopt {
                assert_eq!(exists, standing, "{name}: the directory");
            }
        }
    }
    granted.stop().await;
}

/// Whether the owner sees a repository or a working copy by this label.
async fn labelled(control: &mut LocalClient, env: EnvironmentId, label: &str) -> bool {
    let projects: ProjectListResult = locally(
        control,
        Method::ProjectList,
        &ProjectListParams {
            environment_id: env,
        },
    )
    .await;
    let workspaces: WorkspaceListResult = locally(
        control,
        Method::WorkspaceList,
        &WorkspaceListParams {
            environment_id: env,
            project_repository_id: Nullable::null(),
        },
    )
    .await;
    projects
        .projects
        .iter()
        .any(|project| project.label == label)
        || workspaces
            .workspaces
            .iter()
            .any(|workspace| workspace.label == label)
}

/// Tells the run of the test below inside a mount namespace where the location is.
const INSIDE_A_NAMESPACE: &str = "KR_CONTROLLER_DEVICE_LOCATION_INSIDE_A_MOUNT_NAMESPACE";

/// What the run inside the namespace says when it asserted the refusal, and when this host's
/// daemon did not prove the boundary there and so asserted nothing.
const INNER_ASSERTED: &str = "the mount refusal was asserted inside the namespace";
const INNER_NOT_EXERCISED: &str = "the mount refusal was not exercised inside the namespace";

/// Runs one clone as a device, from the repository `src` beneath `root`, into `into` beneath it.
///
/// Both locations are the owner's, authorised for the device's grant over `root`. Returns none,
/// and says so, on a host that does not prove Git's reads confined.
async fn a_device_clones_from_a_repository_in(
    root: &Path,
    into: &str,
    test: &str,
) -> Option<std::result::Result<ParamsValue, ClientError>> {
    use kr_protocol::project::{DestinationParent, LocationPurpose};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = qualified_host(&owner, test).await?;
    let mut control = host.client().await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(PROJECT_RIGHTS),
    )
    .await;
    let session = net_support::connect(&host, &device, &record).await;
    let grant = record.grant.grant_id;
    let source = authorise_for(
        &mut control,
        &host,
        &owner,
        root,
        LocationPurpose::Source,
        grant,
    )
    .await;
    let destination = authorise_for(
        &mut control,
        &host,
        &owner,
        root,
        LocationPurpose::Destination,
        grant,
    )
    .await;
    let outcome = remote_mutation(
        &session,
        host.environment_id,
        Method::ProjectClone,
        &ProjectCloneParams {
            destination: DestinationRequest {
                environment_id: host.environment_id,
                parent: DestinationParent::Location {
                    location_id: destination.location_id,
                },
                name: into.to_owned(),
            },
            label: into.to_owned(),
            source: CloneSource::Location {
                location_id: source.location_id,
                relative_path: "src".to_owned(),
            },
        },
    )
    .await;
    session.close();
    host.stop().await;
    Some(outcome)
}

/// KR-REQ-23.42: a filesystem mounted beneath a directory a device's operation is granted refuses
/// the operation, with the reason, before Git starts.
///
/// No account here can mount anything where the daemon runs, so the test runs itself again inside
/// a namespace that bubblewrap makes, with a filesystem mounted beneath the repository the device
/// clones from, and asserts the refusal there. The control is the same clone from the same
/// repository outside the namespace, where nothing is mounted beneath it, which is made. A host
/// that does not prove Git's reads confined, or whose bubblewrap cannot make a namespace, does not
/// exercise it and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_filesystem_mounted_beneath_a_granted_directory_refuses_a_devices_clone_with_its_reason()
{
    let test =
        "a_filesystem_mounted_beneath_a_granted_directory_refuses_a_devices_clone_with_its_reason";
    if let Some(root) = std::env::var_os(INSIDE_A_NAMESPACE) {
        let root = PathBuf::from(root);
        let table = std::fs::read_to_string("/proc/self/mountinfo").expect("the mount table");
        let mounted = root.join("src/mounted");
        assert!(
            table
                .lines()
                .filter_map(|line| line.split(' ').nth(4))
                .any(|point| Path::new(point) == mounted),
            "a filesystem is mounted beneath the repository in here"
        );
        let Some(outcome) = a_device_clones_from_a_repository_in(&root, "inside", test).await
        else {
            // The run outside says so by name: a run that asserted nothing is not a pass.
            println!("{INNER_NOT_EXERCISED}");
            return;
        };
        let refusal = outcome.expect_err("a clone from a repository with a mount beneath it");
        let said = said(&refusal);
        assert!(
            said.contains(&format!("a filesystem is mounted at {}", mounted.display())),
            "the refusal names the mount point: {said}"
        );
        assert!(!root.join("inside").exists(), "nothing was cloned");
        println!("{INNER_ASSERTED}");
        return;
    }
    let Some(bwrap) = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .map(Path::new)
        .find(|candidate| candidate.is_file())
    else {
        println!("not exercised: {test} needs bubblewrap, and this host has none");
        return;
    };
    let makes_one = std::process::Command::new(bwrap)
        .args(["--unshare-user", "--dev-bind", "/", "/", "--", "/bin/true"])
        .status()
        .is_ok_and(|status| status.success());
    if !makes_one {
        println!("not exercised: {test} needs a namespace, and bubblewrap cannot make one here");
        return;
    }
    let work = tempfile::TempDir::new().expect("a directory on the internal disk");
    let root = work.path().join("granted");
    std::fs::create_dir(&root).expect("a directory to authorise");
    repository(&root, "src");
    std::fs::create_dir(root.join("src/mounted")).expect("a directory to mount over");
    // The control: nothing is mounted beneath the repository here, and the clone is made.
    let Some(control) = a_device_clones_from_a_repository_in(&root, "outside", test).await else {
        return;
    };
    let cloned: ProjectCloneResult = typed(&control.expect("the clone is made where no mount is"));
    assert_eq!(cloned.operation.state, OperationState::Completed);
    assert!(root.join("outside/README.md").is_file());
    let output = std::process::Command::new(bwrap)
        .args(["--unshare-user", "--dev-bind", "/", "/", "--tmpfs"])
        .arg(root.join("src/mounted"))
        .arg("--setenv")
        .arg(INSIDE_A_NAMESPACE)
        .arg(&root)
        .arg("--")
        .arg(std::env::current_exe().expect("this test's own program"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .output()
        .expect("the namespace starts");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && report.contains("1 passed"),
        "the run inside the namespace passed: {report}"
    );
    if report.contains(INNER_NOT_EXERCISED) {
        println!(
            "not exercised: {test} asserted nothing, because this host's daemon did not prove Git's reads confined inside the namespace"
        );
        return;
    }
    assert!(
        report.contains(INNER_ASSERTED),
        "the run inside the namespace asserted the refusal: {report}"
    );
}

/// KR-REQ-23.42: `host.doctor` says whether this host serves a paired device repository
/// operations, on the terms the door applies, and reports what it shows of the mount residual
/// where the platform confines Git's reads at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_doctor_says_whether_a_paired_device_is_served_repository_operations() {
    use kr_project::service::Refusal;
    use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};

    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, PROJECT_RIGHTS).await;
    let doctor: HostDoctorResult = locally(&mut control, Method::HostDoctor, &()).await;
    let proved = host.controller().qualification();
    let status = |result: &HostDoctorResult, id: &str| {
        result
            .checks
            .iter()
            .find(|check| check.id() == id)
            .map(|check| (check.status, check.detail().to_owned()))
    };
    let (served, detail) = status(&doctor, "device-repositories")
        .expect("the doctor reports whether a paired device is served repository operations");
    assert_eq!(
        served,
        match proved.refusal() {
            None => DoctorStatus::Ok,
            Some(Refusal::Platform) => DoctorStatus::NotApplicable,
            Some(_) => DoctorStatus::Warning,
        },
        "the report says what the door reads: {detail}"
    );
    let mounts = status(&doctor, "device-repository-mounts");
    if proved.refusal() == Some(Refusal::Platform) {
        assert!(
            mounts.is_none(),
            "a platform that confines nothing reports nothing about mounts"
        );
    } else {
        let (_, mounts) = mounts.expect("a platform that confines Git's reads reports its mounts");
        assert!(
            mounts.contains("does not close it"),
            "the report says the narrowing is not a closure: {mounts}"
        );
    }
    // A device is told the same, in the export form, and no path or library name is in it.
    let seen: HostDoctorResult = session
        .read(Method::HostDoctor, &())
        .await
        .expect("host.doctor is served to a device");
    assert_eq!(
        status(&seen, "device-repositories").map(|(status, _)| status),
        Some(served)
    );
    session.close();
    host.stop().await;
}

/// KR-REQ-23.42: the door reads the last proof the daemon made, and `host.doctor` makes another and
/// holds it. A host held as one that did not qualify refuses the five operations with one
/// sentence; the doctor proves it again and the same request is past the door, where the project
/// service decides it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_door_follows_the_last_proof_and_the_doctor_proves_again() {
    use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};

    let owner = DeviceKeys::generate().expect("owner keys");
    let Some(host) = qualified_host(
        &owner,
        "the_door_follows_the_last_proof_and_the_doctor_proves_again",
    )
    .await
    else {
        return;
    };
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, PROJECT_RIGHTS).await;
    let init = ProjectInitParams {
        destination: destination(&host, "door"),
        label: "door".to_owned(),
        initial_branch: Nullable::null(),
    };
    as_unqualified(&host);
    let refused = remote_mutation(&session, host.environment_id, Method::ProjectInit, &init)
        .await
        .expect_err("a host held as one that did not qualify refuses the operation");
    assert_eq!(said(&refused), REFUSAL);

    let doctor: HostDoctorResult = locally(&mut control, Method::HostDoctor, &()).await;
    let proved = doctor
        .checks
        .iter()
        .find(|check| check.id() == "device-repositories")
        .expect("the doctor reports it");
    assert_eq!(proved.status, DoctorStatus::Ok);
    assert!(host.controller().qualification().qualifies());
    let past = remote_mutation(&session, host.environment_id, Method::ProjectInit, &init)
        .await
        .expect_err("past the door, the project service refuses a path the device names");
    assert_eq!(past.code(), ErrorCode::PermissionDenied);
    assert_ne!(said(&past), REFUSAL, "and says so in its own words: {past}");
    assert!(!host.work().join("door").exists());
    session.close();
    host.stop().await;
}
