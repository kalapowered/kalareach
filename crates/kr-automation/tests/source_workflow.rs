//! Tests for the source workflow's pieces: the completion to tests to reviewer flow, exclusive
//! quiescence reservations on a workspace, and evidence recorded against one immutable change-set
//! version that later edits cannot change.

use std::sync::Arc;

use kr_attention::event::{EventCursor, EventKind};
use kr_attention::store::{Claimant, Liveness};
use kr_attention::time::BootMark;
use kr_attention::{Attention, HostReading, Outcome};
use kr_automation::{QuiescenceManager, ReviewerTurn, SourceWorkflowCoordinator};
use kr_changeset::ChangeSetService;
use kr_changeset::capture::CaptureRequest;
use kr_changeset::service::CaptureOrder;
use kr_ipc::testing::TempHost;
use kr_project::ProjectService;
use kr_protocol::attention::{AttentionRule, AttentionSource, ReviewSubject};
use kr_protocol::changeset::{EvidenceKind, FileGrant, Provenance, VersionRef};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ActorId, AgentTurnId, SessionId, WorkspaceId};
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

/// A repository adopted as a shared workspace, with a local change captured as version 1.
struct Adopted {
    _host: TempHost,
    _work: tempfile::TempDir,
    repo_dir: std::path::PathBuf,
    changesets: ChangeSetService,
    workspace_id: WorkspaceId,
    policy: InclusionPolicy,
    version: VersionRef,
}

fn adopted_with_one_version() -> Adopted {
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
            quiescence: None,
        },
        pin: false,
        provenance: dummy_provenance(),
        admitted: None,
    };

    let (record1, _) = changesets.capture(&order1).unwrap();
    let version = VersionRef {
        change_set_id: record1.change_set_id,
        version: record1.version,
    };
    Adopted {
        _host: host,
        _work: work_dir,
        repo_dir,
        changesets,
        workspace_id: ws,
        policy,
        version,
    }
}

#[test]
fn source_workflow_binds_evidence_to_exact_immutable_version() {
    let Adopted {
        _host,
        _work,
        repo_dir,
        changesets,
        workspace_id: ws,
        policy,
        version: version1,
    } = adopted_with_one_version();
    let grant = FileGrant::default();

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
    let reviewed = reviewer_turn(review_session, "turn-review-1", 5);
    let event = coordinator
        .bind_reviewer_evidence(
            &changesets,
            version1,
            "claude-code",
            "LGTM",
            &reviewed,
            2000,
        )
        .unwrap();

    // The attention event is the reviewer turn's own completion, where its session recorded it.
    assert_eq!(event.cursor, reviewed.cursor);
    assert!(matches!(
        &event.kind,
        EventKind::TurnCompleted { session_id, turn_id, version, change_set, .. }
            if *session_id == review_session
                && *turn_id == reviewed.turn_id
                && *version == reviewed.result_version
                && *change_set == Some((version1.change_set_id, version1.version.get()))
    ));

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
            quiescence: None,
        },
        pin: false,
        provenance: dummy_provenance(),
        admitted: None,
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

/// A reviewer turn's first result, whose completion sits at `sequence` in its session's semantic
/// events.
fn reviewer_turn(session_id: SessionId, turn: &str, sequence: u64) -> ReviewerTurn {
    ReviewerTurn {
        session_id,
        turn_id: AgentTurnId::new(turn.to_owned()).expect("a turn identifier"),
        result_version: 1,
        cursor: EventCursor::new(AttentionSource::Semantic, sequence),
    }
}

fn reading(now_ms: u64) -> HostReading {
    HostReading::new(BootMark::of(b"source-workflow-test"), now_ms, now_ms, true)
}

/// Review results become review-ready items, one per reviewer turn. Each review's event is that
/// turn's own completion at its own position, so a second review is new work rather than a replay
/// of the first, and the same review reported again raises nothing further. A position that is
/// not a record of the session's semantic events is refused.
#[test]
fn each_review_is_its_own_item_and_a_repeat_is_not_another() {
    let adopted = adopted_with_one_version();
    let (changesets, version) = (&adopted.changesets, adopted.version);
    let coordinator = SourceWorkflowCoordinator::new(Arc::new(QuiescenceManager::new()));
    let unknown = |_: &ProcessStartIdentity| Liveness::Unknown;
    let mut attention = Attention::in_memory(
        reading(1_000),
        &Claimant::new(
            ProcessStartIdentity::new(1, ProcessStartSource::LinuxProcStat, 1_001),
            &unknown,
        ),
    )
    .expect("an attention state");

    let first = reviewer_turn(test_session_id(3), "turn-a", 4);
    let second = reviewer_turn(test_session_id(3), "turn-b", 9);
    let mut raised = 0;
    for (turn, outcome) in [(&first, "needs work"), (&second, "LGTM")] {
        let event = coordinator
            .bind_reviewer_evidence(changesets, version, "reviewer", outcome, turn, 2_000)
            .expect("the review is recorded");
        raised += attention
            .apply(&event, reading(2_000))
            .expect("applies")
            .iter()
            .filter(|outcome| matches!(outcome, Outcome::Raised { .. }))
            .count();
    }
    assert_eq!(raised, 2, "two reviews are two items");
    let engine = attention.engine().expect("the engine");
    assert_eq!(
        engine
            .items()
            .filter(|item| item.rule == AttentionRule::ReviewReady)
            .count(),
        2
    );
    assert_eq!(
        engine.consumed(kr_attention::Origin::Environment, AttentionSource::Semantic),
        Some(9)
    );

    // The first review reported again is the same turn at the same position.
    let again = coordinator
        .bind_reviewer_evidence(changesets, version, "reviewer", "needs work", &first, 3_000)
        .expect("the review is recorded");
    assert!(
        attention
            .apply(&again, reading(3_000))
            .expect("applies")
            .is_empty()
    );
    assert_eq!(attention.engine().expect("the engine").items().count(), 2);

    // A turn's completion is a record of its session's semantic events.
    for cursor in [
        EventCursor::new(AttentionSource::Receipts, 4),
        EventCursor::new(AttentionSource::Semantic, 0),
    ] {
        let refused = coordinator
            .bind_reviewer_evidence(
                changesets,
                version,
                "reviewer",
                "LGTM",
                &ReviewerTurn {
                    cursor,
                    ..first.clone()
                },
                3_000,
            )
            .expect_err("not a semantic record");
        assert!(refused.to_string().contains("semantic"), "{refused}");
    }
}

/// A turn that runs again produces a later result, and that result is review work of its own even
/// though the change-set version it reviewed has not moved. The event carries the turn result's
/// version, so the attention state takes the second result as the turn moving on rather than as a
/// late copy of the first.
#[test]
fn a_later_result_of_the_same_reviewer_turn_is_new_review_work() {
    let adopted = adopted_with_one_version();
    let (changesets, version) = (&adopted.changesets, adopted.version);
    let coordinator = SourceWorkflowCoordinator::new(Arc::new(QuiescenceManager::new()));
    let unknown = |_: &ProcessStartIdentity| Liveness::Unknown;
    let mut attention = Attention::in_memory(
        reading(1_000),
        &Claimant::new(
            ProcessStartIdentity::new(1, ProcessStartSource::LinuxProcStat, 1_001),
            &unknown,
        ),
    )
    .expect("an attention state");

    let first = reviewer_turn(test_session_id(4), "turn-rerun", 1);
    let event = coordinator
        .bind_reviewer_evidence(changesets, version, "reviewer", "needs work", &first, 2_000)
        .expect("the first result is recorded");
    attention.apply(&event, reading(2_000)).expect("applies");

    let rerun = ReviewerTurn {
        result_version: 2,
        cursor: EventCursor::new(AttentionSource::Semantic, 2),
        ..first.clone()
    };
    let event = coordinator
        .bind_reviewer_evidence(changesets, version, "reviewer", "LGTM", &rerun, 3_000)
        .expect("the later result is recorded");
    let outcomes = attention.apply(&event, reading(3_000)).expect("applies");
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Repeated { occurrences: 2, .. })),
        "the later result reaches the item as the turn's second result: {outcomes:?}"
    );
    assert!(
        attention.gaps().expect("the gaps").is_empty(),
        "the two results are consecutive records of the session's events"
    );
    let subject = ReviewSubject::CompletedTurn {
        session_id: first.session_id,
        turn_id: first.turn_id.clone(),
    };
    assert_eq!(
        attention
            .reviews()
            .expect("the review state")
            .version_of(&subject),
        Some(2),
        "the review state holds the turn at its later result"
    );
}
