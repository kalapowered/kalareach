//! The "Changes and diffs" method group through the real control daemon.
//!
//! Requirement rows closed here: KR-REQ-23.44 (the six methods under the daemon's own authority,
//! with the rights and the version checks section 23 names), KR-REQ-14.31 and KR-ACC-031 (an
//! immutable version delivered exactly while the source keeps changing), KR-REQ-14.26 (a preflight
//! conflict returns `DRAFT_CONFLICT` with no writes) and KR-REQ-14.34 (an independent
//! materialisation of an exact version).
//!
//! These run the real endpoint, the real handshake, the real envelope checks and real repositories
//! built with installed Git. The daemon starts on an environment under the platform's temporary
//! directory, which is on the internal disk, and its secrets go to a file store rather than to the
//! operator's login keychain.

#![cfg(not(windows))]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::changeset::{
    ApplyOutcomeClass, ChangesetCaptureParams, ChangesetCaptureResult, ChangesetMaterializeParams,
    ChangesetMaterializeResult, ChangesetReadParams, ChangesetReadResult, DestinationClass,
    DiffApplyParams, DiffApplyResult, DiffReadParams, DiffReadResult, FileGrant,
    MaterialisationPurpose, PathClass, SourceConsistency,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, DestinationRequest, InclusionChoice, InclusionPolicy, ProjectAdoptParams,
    ProjectAdoptResult, WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind,
};
use kr_protocol::scalars::Nullable;

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

/// A repository with one commit, a dirty file, an untracked one and a secret.
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
    std::fs::write(path.join(".env"), "API_TOKEN=nobody-should-capture-this\n")
        .expect("a secret the user keeps in the tree");
    path
}

/// The parameters one capture of a workspace carries.
fn capture_params(
    workspace_id: kr_protocol::ids::WorkspaceId,
    change_set_id: Nullable<kr_protocol::ids::ChangeSetId>,
    note: &str,
) -> ChangesetCaptureParams {
    ChangesetCaptureParams {
        workspace_id,
        change_set_id,
        label: "the work".to_owned(),
        policy: include_everything(),
        grant: FileGrant::default(),
        quiescence_declared: false,
        required_consistency: Nullable::null(),
        pin: false,
        session_id: Nullable::null(),
        workflow_run_id: Nullable::null(),
        note: note.to_owned(),
    }
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

/// KR-REQ-23.44, KR-REQ-14.31, KR-REQ-14.34 and KR-ACC-031: the six methods reach the service
/// through the daemon's own admission path, and each one does what its row says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_change_set_method_runs_end_to_end_through_the_daemon() {
    let host = host().await;
    let mut control = client(&host).await;
    let source = repository(host.work(), "source");

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

    // `diff.read` is a read: identity, base, head and both content revisions.
    let read: DiffReadResult = typed(
        &control
            .request(
                Method::DiffRead,
                &DiffReadParams {
                    workspace_id: Nullable::some(workspace),
                    change_set_id: Nullable::null(),
                    version: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("diff.read succeeds"),
    );
    assert_eq!(read.workspace_id, workspace);
    assert!(!read.base_revision.is_empty());
    assert!(
        read.tracked
            .iter()
            .any(|entry| entry.path == "README.md" && entry.class == PathClass::DirtyFile)
    );

    // `changeset.capture` produces an immutable version, and the secret never enters it.
    let captured: ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ChangesetCaptureParams {
                    workspace_id: workspace,
                    change_set_id: Nullable::null(),
                    label: "the work".to_owned(),
                    policy: include_everything(),
                    grant: FileGrant::default(),
                    quiescence_declared: false,
                    required_consistency: Nullable::null(),
                    pin: true,
                    session_id: Nullable::null(),
                    workflow_run_id: Nullable::null(),
                    note: "captured through the daemon".to_owned(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.capture succeeds"),
    );
    assert_eq!(captured.version.version.get(), 1);
    assert!(captured.pinned);
    assert!(
        captured
            .version
            .changes
            .iter()
            .all(|entry| entry.path != ".env"),
        "the secret is not in the version"
    );
    assert!(
        captured
            .version
            .exclusions
            .iter()
            .any(|entry| entry.path == ".env"),
        "and it is named as left out"
    );
    let change_set = captured.version.change_set_id;

    // KR-ACC-031: the agent keeps working, and the captured version is unmoved.
    std::fs::write(source.join("README.md"), "the agent has moved on\n").expect("a later edit");
    let reread: ChangesetReadResult = typed(
        &control
            .request(
                Method::ChangesetRead,
                &ChangesetReadParams {
                    change_set_id: change_set,
                    version: Nullable::some(captured.version.version),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.read succeeds"),
    );
    assert_eq!(
        reread.version.content_digest,
        captured.version.content_digest
    );

    // The daemon has nowhere to reserve a workspace from yet, so a caller that requires the
    // quiesced class is told so rather than served a weaker class under that name.
    let err = control
        .mutate(
            Method::ChangesetCapture,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &ChangesetCaptureParams {
                workspace_id: workspace,
                change_set_id: Nullable::null(),
                label: "requiring quiesced".to_owned(),
                policy: include_everything(),
                grant: FileGrant::default(),
                quiescence_declared: false,
                required_consistency: Nullable::some(SourceConsistency::QuiescedCapture),
                pin: true,
                session_id: Nullable::null(),
                workflow_run_id: Nullable::null(),
                note: "requiring quiesced capture without reservation".to_owned(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("requiring quiesced capture without reservation must fail");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(
        err.message.contains("nowhere to reserve this workspace"),
        "the refusal says what is missing: {}",
        err.message
    );

    // A second capture is a second version, and both are visible.
    let second: ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ChangesetCaptureParams {
                    workspace_id: workspace,
                    change_set_id: Nullable::some(change_set),
                    label: "the work".to_owned(),
                    policy: include_everything(),
                    grant: FileGrant::default(),
                    quiescence_declared: false,
                    required_consistency: Nullable::null(),
                    pin: false,
                    session_id: Nullable::null(),
                    workflow_run_id: Nullable::null(),
                    note: String::new(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the second capture succeeds"),
    );
    assert_eq!(second.version.version.get(), 2);
    assert_ne!(
        second.version.content_digest,
        captured.version.content_digest
    );
    let listed: ChangesetReadResult = typed(
        &control
            .request(
                Method::ChangesetRead,
                &ChangesetReadParams {
                    change_set_id: change_set,
                    version: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.read succeeds"),
    );
    assert_eq!(listed.version.version.get(), 2, "no version is the latest");
    assert_eq!(listed.versions.len(), 2);

    // `changeset.materialize` writes the exact version somewhere of this host's own.
    let materialised: ChangesetMaterializeResult = typed(
        &control
            .mutate(
                Method::ChangesetMaterialize,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ChangesetMaterializeParams {
                    change_set_id: change_set,
                    version: captured.version.version,
                    purpose: MaterialisationPurpose::Review,
                    label: "the reviewer's copy".to_owned(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.materialize succeeds"),
    );
    let directory = Path::new(&materialised.materialisation.directory_path);
    assert_eq!(
        std::fs::read(directory.join("README.md")).expect("the file is there"),
        b"changed after the commit\n",
        "version one's content, not the tree's"
    );
    assert!(
        !directory.join(".env").exists(),
        "the secret is in no materialisation either"
    );
    assert!(!materialised.limitations.is_empty());

    // `diff.apply` to a proposal writes to no working tree.
    let applied: DiffApplyResult = typed(
        &control
            .mutate(
                Method::DiffApply,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &DiffApplyParams {
                    change_set_id: change_set,
                    version: captured.version.version,
                    destination: DestinationClass::Proposal,
                    workspace_id: Nullable::some(workspace),
                    expected_reference: Nullable::null(),
                    affected: vec![kr_protocol::changeset::AffectedVersion {
                        path: "README.md".to_owned(),
                        expected_worktree_digest: Nullable::some(kr_changeset::objects::digest_of(
                            b"the agent has moved on\n",
                        )),
                        expected_index_object_id: Nullable::null(),
                        expected_index_mode: Nullable::null(),
                        check_index: false,
                    }],
                    paths: vec!["README.md".to_owned()],
                    preflight_only: false,
                    acknowledged_limitations: Vec::new(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("diff.apply succeeds"),
    );
    assert_eq!(applied.outcome, Nullable::some(ApplyOutcomeClass::Applied));
    assert!(applied.proposal_version.0.is_some());
    assert_eq!(
        std::fs::read(source.join("README.md")).expect("the tree is there"),
        b"the agent has moved on\n",
        "a proposal writes to no working tree"
    );

    // KR-REQ-14.26: a preflight conflict is DRAFT_CONFLICT.
    let refusal = failure(
        control
            .mutate(
                Method::DiffApply,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &DiffApplyParams {
                    change_set_id: change_set,
                    version: captured.version.version,
                    destination: DestinationClass::Proposal,
                    workspace_id: Nullable::some(workspace),
                    expected_reference: Nullable::null(),
                    affected: vec![kr_protocol::changeset::AffectedVersion {
                        path: "README.md".to_owned(),
                        expected_worktree_digest: Nullable::some(kr_changeset::objects::digest_of(
                            b"something else entirely\n",
                        )),
                        expected_index_object_id: Nullable::null(),
                        expected_index_mode: Nullable::null(),
                        check_index: false,
                    }],
                    paths: vec!["README.md".to_owned()],
                    preflight_only: false,
                    acknowledged_limitations: Vec::new(),
                },
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::DraftConflict);

    // The pin the capture recorded is one the project service holds, so a workspace removal has to
    // account for it.
    let retained = host
        .controller
        .project()
        .service()
        .retained(workspace)
        .expect("the project service holds the pin");
    assert!(
        retained.iter().any(|item| {
            item.kind == kr_protocol::project::RetainedKind::PinnedChangeSet
                && item.change_set_id == Some(change_set)
        }),
        "the pin names the change set"
    );

    host.clients.abort();
    let _ = host.clients.await;
}

/// KR-REQ-23.44: a repeat of one capture action is answered from its own record rather than
/// captured twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_capture_action_is_answered_from_its_record() {
    let host = host().await;
    let mut control = client(&host).await;
    let source = repository(host.work(), "repeated");

    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectAdoptParams {
                    destination: host.destination("repeated"),
                    label: "repeated".to_owned(),
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
    let params = ChangesetCaptureParams {
        workspace_id: workspace,
        change_set_id: Nullable::null(),
        label: "the work".to_owned(),
        policy: include_everything(),
        grant: FileGrant::default(),
        quiescence_declared: false,
        required_consistency: Nullable::null(),
        pin: false,
        session_id: Nullable::null(),
        workflow_run_id: Nullable::null(),
        note: String::new(),
    };
    let action = ActionId::new(kr_ipc::new_uuid());
    let first: ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the capture succeeds"),
    );
    // The tree moves on, and the repeat still answers with the version the first call made.
    std::fs::write(source.join("README.md"), "moved on again\n").expect("a later edit");
    let repeated: ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the repeat succeeds"),
    );
    assert_eq!(repeated.version.version, first.version.version);
    assert_eq!(
        repeated.version.content_digest,
        first.version.content_digest
    );
    let listed: ChangesetReadResult = typed(
        &control
            .request(
                Method::ChangesetRead,
                &ChangesetReadParams {
                    change_set_id: first.version.change_set_id,
                    version: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.read succeeds"),
    );
    assert_eq!(
        listed.versions.len(),
        1,
        "one action captured one version, however many times it was sent"
    );

    host.clients.abort();
    let _ = host.clients.await;
}

/// KR-REQ-14.26 and 23.44: a preflight conflict through the daemon leaves **no KR writes**,
/// including no action record, so the caller can ask again with what it now knows is there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_preflight_conflict_through_the_daemon_records_nothing() {
    let host = host().await;
    let mut control = client(&host).await;
    let source = repository(host.work(), "conflicting");

    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectAdoptParams {
                    destination: host.destination("conflicting"),
                    label: "conflicting".to_owned(),
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
    let captured: ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ChangesetCaptureParams {
                    workspace_id: workspace,
                    change_set_id: Nullable::null(),
                    label: "the work".to_owned(),
                    policy: include_everything(),
                    grant: FileGrant::default(),
                    quiescence_declared: false,
                    required_consistency: Nullable::null(),
                    pin: false,
                    session_id: Nullable::null(),
                    workflow_run_id: Nullable::null(),
                    note: String::new(),
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.capture succeeds"),
    );

    let action = ActionId::new(kr_ipc::new_uuid());
    let params = DiffApplyParams {
        change_set_id: captured.version.change_set_id,
        version: captured.version.version,
        destination: DestinationClass::Proposal,
        workspace_id: Nullable::some(workspace),
        expected_reference: Nullable::null(),
        affected: vec![kr_protocol::changeset::AffectedVersion {
            path: "README.md".to_owned(),
            expected_worktree_digest: Nullable::some(kr_changeset::objects::digest_of(
                b"something that is not there\n",
            )),
            expected_index_object_id: Nullable::null(),
            expected_index_mode: Nullable::null(),
            check_index: false,
        }],
        paths: vec!["README.md".to_owned()],
        preflight_only: false,
        acknowledged_limitations: Vec::new(),
    };
    let refusal = failure(
        control
            .mutate(
                Method::DiffApply,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::DraftConflict);
    // Nothing of that request is in the journal: the same action identifier with a request that
    // now matches the tree goes through rather than being answered from a record of the refusal.
    let digest = kr_changeset::objects::digest_of(b"changed after the commit\n");
    let second = DiffApplyParams {
        affected: vec![kr_protocol::changeset::AffectedVersion {
            path: "README.md".to_owned(),
            expected_worktree_digest: Nullable::some(digest),
            expected_index_object_id: Nullable::null(),
            expected_index_mode: Nullable::null(),
            check_index: false,
        }],
        ..params
    };
    let applied: DiffApplyResult = typed(
        &control
            .mutate(
                Method::DiffApply,
                action,
                ActionTarget::environment(host.environment_id),
                &second,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the apply succeeds once the request matches the tree"),
    );
    assert_eq!(applied.outcome, Nullable::some(ApplyOutcomeClass::Applied));
    assert_eq!(
        std::fs::read(source.join("README.md")).expect("the tree is there"),
        b"changed after the commit\n",
        "a proposal writes to no working tree"
    );

    host.clients.abort();
    let _ = host.clients.await;
}

/// KR-REQ-23.44: a change-set mutation whose authority has gone leaves nothing behind.
///
/// The daemon's answer to "is this still admitted?" travels into the change-set store, which asks
/// it inside the transaction that records the claim every effect of this service follows. So a
/// first attempt whose authority ran out writes no claim row, and the very same action can still
/// be performed once the authority holds.
#[tokio::test]
async fn a_change_set_mutation_whose_authority_has_gone_writes_nothing() {
    let host = host().await;
    let mut control = client(&host).await;
    repository(host.work(), "admission");

    let adopted: ProjectAdoptResult = typed(
        &control
            .mutate(
                Method::ProjectAdopt,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &ProjectAdoptParams {
                    destination: host.destination("admission"),
                    label: "admission".to_owned(),
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
                    label: "the tree".to_owned(),
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

    // One capture, offered twice under one action identifier: first under an authority that has
    // gone, then under one that holds. The identifier is what makes the second attempt the **same**
    // action rather than a new one.
    let action = ActionId::new(kr_ipc::new_uuid());
    let params = capture_params(workspace, Nullable::null(), "a capture nothing admits");

    // The environment's authority is withdrawn before it is offered. Every registration admitted
    // under it goes with it, this connection's included.
    host.controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let refusal = failure(
        control
            .mutate(
                Method::ChangesetCapture,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(refusal.code, ErrorCode::PermissionDenied);
    assert!(
        refusal.message.contains("withdrawn"),
        "the daemon's own sentence reaches the caller: {}",
        refusal.message
    );

    // Nothing was claimed and nothing was captured. A fresh connection is admitted again, because
    // what was withdrawn was the registration rather than the person's right to use this host,
    // and the very same action performs cleanly on it.
    let mut admitted = client(&host).await;
    let captured: ChangesetCaptureResult = typed(
        &admitted
            .mutate(
                Method::ChangesetCapture,
                action,
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the same action runs once its authority holds"),
    );
    assert_eq!(captured.version.version.get(), 1);

    host.clients.abort();
}

/// KR-REQ-23.44 through the daemon's own dispatch: authority withdrawn between the claim and the
/// effect stops the effect, and the answer is the daemon's own.
///
/// The mutation arrives on a real connection and is served by the daemon's ordinary path, so the
/// admission the change-set store asks is the one the daemon builds for it: the connection's
/// registration, the authority revision it was admitted under, and the deadline this host
/// accepted. The environment's authority is revoked the instant the apply's claim is taken, which
/// is the interval a claim cannot cover, and nothing of the apply is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authority_revoked_after_the_claim_stops_the_effect_through_the_daemon() {
    let host = host().await;
    let mut control = client(&host).await;
    repository(host.work(), "source");
    repository(host.work(), "destination");

    let mut workspaces = Vec::new();
    for name in ["source", "destination"] {
        let adopted: ProjectAdoptResult = typed(
            &control
                .mutate(
                    Method::ProjectAdopt,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(host.environment_id),
                    &ProjectAdoptParams {
                        destination: host.destination(name),
                        label: name.to_owned(),
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
                        label: name.to_owned(),
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
        workspaces.push(
            created
                .workspace
                .0
                .expect("a creation returns the workspace")
                .workspace_id,
        );
    }
    let captured: ChangesetCaptureResult = typed(
        &control
            .mutate(
                Method::ChangesetCapture,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &capture_params(workspaces[0], Nullable::null(), "the work to apply"),
            )
            .await
            .expect("the call reaches the daemon")
            .expect("changeset.capture succeeds"),
    );

    // The instant the apply's claim is taken, the environment's authority is revoked: the
    // daemon's own revocation, which withdraws every registration admitted under it.
    let controller = Arc::clone(&host.controller);
    host.controller
        .changesets()
        .service()
        .inject(Some(kr_changeset::apply::Fault {
            after_paths: usize::MAX,
            act: None,
            before_rename: None,
            after_claim: Some(Arc::new(move || {
                tokio::runtime::Handle::current().block_on(async {
                    controller
                        .revoke_authority()
                        .await
                        .expect("the revocation is recorded");
                });
            })),
            refuse_staging_record: false,
            stop: false,
            detail: String::new(),
        }));
    let outcome = control
        .mutate(
            Method::DiffApply,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &DiffApplyParams {
                change_set_id: captured.version.change_set_id,
                version: captured.version.version,
                destination: DestinationClass::SharedExisting,
                workspace_id: Nullable::some(workspaces[1]),
                expected_reference: Nullable::null(),
                // What the destination holds now, which is what the fixture wrote into it.
                affected: vec![kr_protocol::changeset::AffectedVersion {
                    path: "README.md".to_owned(),
                    expected_worktree_digest: Nullable::some(kr_changeset::objects::digest_of(
                        b"changed after the commit\n",
                    )),
                    expected_index_object_id: Nullable::null(),
                    expected_index_mode: Nullable::null(),
                    check_index: false,
                }],
                paths: vec!["README.md".to_owned()],
                preflight_only: false,
                acknowledged_limitations: kr_changeset::apply::limitations(
                    DestinationClass::SharedExisting,
                ),
            },
        )
        .await
        .expect("the call reaches the daemon");
    host.controller.changesets().service().inject(None);

    let refusal = failure(outcome);
    assert_eq!(
        refusal.code,
        ErrorCode::PermissionDenied,
        "the refusal is the admission's: {}",
        refusal.message
    );
    assert!(
        refusal.message.contains("withdrawn"),
        "the daemon's own sentence reaches the caller: {}",
        refusal.message
    );
    // Nothing of the destination was touched: the claim was taken, and the reading this apply
    // takes of its destination is the first thing the store refuses.
    assert_eq!(
        std::fs::read(host.work().join("destination").join("README.md"))
            .expect("the destination's own file"),
        b"changed after the commit\n",
        "the destination is exactly as it was"
    );

    host.clients.abort();
}
