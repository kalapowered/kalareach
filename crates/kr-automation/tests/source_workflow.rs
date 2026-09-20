//! Tests for source-workflow verification: completion -> tests -> reviewer flow,
//! quiescence reservations (T-029 Residual 2), and evidence binding on immutable
//! changeset versions without race conditions (T-029 Residual 3).

use std::sync::Arc;

use kr_attention::event::EventKind;
use kr_automation::{QuiescenceManager, SourceWorkflowCoordinator};
use kr_changeset::ChangeSetService;
use kr_changeset::capture::CaptureRequest;
use kr_changeset::service::CaptureOrder;
use kr_ipc::testing::TempHost;
use kr_project::ProjectService;
use kr_protocol::changeset::{EvidenceKind, FileGrant, Provenance, VersionRef};
use kr_protocol::ids::{ActorId, SessionId, WorkspaceId};
use kr_protocol::project::{
    AdoptionFlow, DestinationParent, DestinationRequest, InclusionChoice, InclusionPolicy,
    ProjectAdoptParams, WorkspaceCreateParams, WorkspaceKind,
};
use kr_protocol::scalars::{Nullable, Uuid};

fn test_workspace_id(v: u8) -> WorkspaceId {
    WorkspaceId::new(Uuid::from_bytes([v; 16]))
}

fn test_session_id(v: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([v; 16]))
}

fn test_action(method: &str) -> kr_project::store::Action {
    kr_project::store::Action {
        actor_id: ActorId::new("local:test").unwrap(),
        action_id: Uuid::from_bytes(uuid::Uuid::new_v4().into_bytes()),
        method: method.to_owned(),
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
    }
}

fn dummy_provenance() -> Provenance {
    Provenance {
        actor_id: ActorId::new("local:test").unwrap(),
        method: "changeset.capture".to_owned(),
        session_id: Nullable::null(),
        workflow_run_id: Nullable::null(),
        derived_from: Nullable::null(),
        derivation: String::new(),
        note: "source workflow test".to_owned(),
    }
}

#[test]
fn quiescence_reservation_enforces_exclusive_hold() {
    let mgr = QuiescenceManager::new();
    let ws = test_workspace_id(1);

    // Initial reservation succeeds
    let res1 = mgr.reserve(ws, 5000, 1000).unwrap();
    assert_eq!(res1.workspace_id, ws);
    assert!(res1.active);
    assert_eq!(res1.expires_at_ms, 6000);

    // Workspace is quiesced
    assert!(mgr.is_quiesced(ws, 2000));

    // Overlapping reservation attempt while res1 is active fails
    let err = mgr.reserve(ws, 5000, 2000).unwrap_err();
    assert!(err.to_string().contains("already reserved for quiescence"));

    // Release res1
    assert!(mgr.release(ws, res1.reservation_id));
    assert!(!mgr.is_quiesced(ws, 2000));

    // Now reservation succeeds again
    let res2 = mgr.reserve(ws, 5000, 3000).unwrap();
    assert!(res2.active);
}

#[test]
fn quiescence_reservation_expires_automatically() {
    let mgr = QuiescenceManager::new();
    let ws = test_workspace_id(2);

    let res = mgr.reserve(ws, 1000, 1000).unwrap();
    assert_eq!(res.expires_at_ms, 2000);

    // Active before 2000 ms
    assert!(mgr.is_quiesced(ws, 1500));

    // Expired at 2000 ms
    assert!(!mgr.is_quiesced(ws, 2000));
    assert!(!mgr.is_quiesced(ws, 2500));

    // After expiry, a new reservation succeeds without manual release
    let res2 = mgr.reserve(ws, 2000, 2100).unwrap();
    assert!(res2.active);
}

fn git_raw<I, S>(directory: &std::path::Path, arguments: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let arguments: Vec<std::ffi::OsString> = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .arg("-c")
        .arg("user.name=KalaReach Fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .arg("-c")
        .arg("init.defaultBranch=main")
        .arg("-c")
        .arg("core.autocrlf=false")
        .args(&arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn source_workflow_binds_evidence_to_exact_immutable_version() {
    let host = TempHost::create();
    let project =
        Arc::new(ProjectService::open(&host.environment()).expect("project service opens"));
    let changesets = ChangeSetService::open(&host.environment(), Arc::clone(&project))
        .expect("changeset service opens");

    let work_dir = tempfile::TempDir::new().expect("temp work dir");
    let repo_dir = work_dir.path().join("repo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    git_raw(&repo_dir, ["init", "--initial-branch=main"]);
    std::fs::write(repo_dir.join("file.txt"), "hello world\n").unwrap();
    git_raw(&repo_dir, ["add", "file.txt"]);
    git_raw(&repo_dir, ["commit", "-m", "initial"]);

    let actor = ActorId::new("local:test").unwrap();
    let adopted = project
        .project_adopt(
            &actor,
            &ProjectAdoptParams {
                destination: DestinationRequest {
                    environment_id: host.environment_id(),
                    parent: DestinationParent::Host {
                        path: work_dir.path().display().to_string(),
                    },
                    name: "repo".to_owned(),
                },
                label: "repo".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&test_action("project.adopt:repo")),
        )
        .unwrap()
        .project
        .project_repository_id;

    let policy = InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    };

    let ws = project
        .workspace_create(
            &actor,
            &WorkspaceCreateParams {
                project_repository_id: adopted,
                label: "work".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy,
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: false,
            },
            Some(&test_action("workspace.create:work")),
        )
        .unwrap()
        .workspace
        .0
        .unwrap()
        .workspace_id;

    // Change file in repo and capture version 1
    std::fs::write(repo_dir.join("file.txt"), "hello world modified\n").unwrap();

    let grant = FileGrant::default();
    let order1 = CaptureOrder {
        workspace_id: ws,
        change_set_id: None,
        label: "initial-change",
        request: CaptureRequest {
            policy: &policy,
            grant: &grant,
            quiescence_declared: true,
            required_consistency: None,
        },
        pin: false,
        provenance: dummy_provenance(),
    };

    let (record1, _) = changesets.capture(&order1).unwrap();
    let version1 = VersionRef {
        change_set_id: record1.change_set_id,
        version: record1.version,
    };

    let coordinator = SourceWorkflowCoordinator::new(Arc::new(QuiescenceManager::new()));
    let test_session = test_session_id(1);

    // 1. Bind test evidence to version 1
    coordinator
        .bind_test_evidence(
            &changesets,
            version1,
            true,
            "unit-tests",
            test_session,
            1000,
        )
        .unwrap();

    // Verify evidence in changeset service
    let ev1 = changesets
        .evidence(version1.change_set_id, version1.version)
        .unwrap();
    assert_eq!(ev1.len(), 1);
    assert_eq!(ev1[0].kind, EvidenceKind::TestResult);
    assert!(ev1[0].detail.contains("passed: true"));

    // 2. Bind reviewer evidence to version 1
    let review_session = test_session_id(2);
    let event = coordinator
        .bind_reviewer_evidence(
            &changesets,
            version1,
            "claude-code",
            "LGTM",
            review_session,
            2000,
        )
        .unwrap();

    // Verify turn completed attention event
    assert!(matches!(event.kind, EventKind::TurnCompleted { .. }));

    // Verify both evidence records exist on version 1
    let ev2 = changesets
        .evidence(version1.change_set_id, version1.version)
        .unwrap();
    assert_eq!(ev2.len(), 2);
    assert!(
        ev2.iter()
            .any(|e| e.kind == EvidenceKind::TestResult && e.detail.contains("passed: true"))
    );
    assert!(
        ev2.iter()
            .any(|e| e.kind == EvidenceKind::ReviewAcknowledgement && e.detail.contains("LGTM"))
    );

    // 3. Mutate workspace further and capture version 2
    std::fs::write(repo_dir.join("file.txt"), "hello world further modified\n").unwrap();
    let order2 = CaptureOrder {
        workspace_id: ws,
        change_set_id: Some(version1.change_set_id),
        label: "second-change",
        request: CaptureRequest {
            policy: &policy,
            grant: &grant,
            quiescence_declared: false,
            required_consistency: None,
        },
        pin: false,
        provenance: dummy_provenance(),
    };
    let (record2, _) = changesets.capture(&order2).unwrap();
    assert_eq!(record2.version.get(), 2);

    // Version 2 has NO evidence yet
    let ev_v2 = changesets
        .evidence(record2.change_set_id, record2.version)
        .unwrap();
    assert_eq!(ev_v2.len(), 0);

    // Version 1 still has its 2 immutable evidence records!
    let ev_v1_again = changesets
        .evidence(version1.change_set_id, version1.version)
        .unwrap();
    assert_eq!(ev_v1_again.len(), 2);
}
