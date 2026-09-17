//! Workspaces: the explicit choice, the inclusion preview, what a creation copies, and what a
//! removal may take.
//!
//! KR-REQ-14.20, 14.21, 14.22, 23.43, 24.08.

#![cfg(feature = "git-fixtures")]

mod support;

use kr_project::store::{RetainedRow, WorkspaceRow};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ChangeSetId, ProjectRepositoryId, SessionId};
use kr_protocol::project::{
    AdoptionFlow, InclusionChoice, InclusionClass, InclusionPolicy, IsolationMechanism,
    ProjectAdoptParams, RetainedKind, RetentionPolicy, WorkspaceCreateParams, WorkspaceKind,
    WorkspaceListParams, WorkspaceReadParams, WorkspaceRemoveParams, WorkspaceState,
};
use kr_protocol::scalars::{Nullable, Uuid};

use support::{
    Fixture, action, actor, destination, include_everything, ordinary_repository, write,
    write_bytes,
};

/// Builds a repository with one of each class of uncommitted work in it and adopts it.
fn adopted_with_changes(fixture: &Fixture, name: &str) -> ProjectRepositoryId {
    let path = ordinary_repository(fixture.work(), name);
    // A tracked file with an uncommitted change, an untracked one, an ignored one, and a binary
    // one that is untracked.
    write(&path, "README.md", "changed after the commit\n");
    write(&path, "notes.txt", "untracked and the user's own\n");
    write(&path, ".gitignore", "generated/\n");
    write(&path, "generated/output.txt", "a build product\n");
    write_bytes(&path, "image.bin", &[0_u8, 1, 2, 3, 0, 5]);
    fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), name),
                label: name.to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 1)),
        )
        .expect("the checkout is adopted")
        .project
        .project_repository_id
}

fn count(preview: &kr_protocol::project::InclusionPreview, class: InclusionClass) -> (u64, u64) {
    let row = preview
        .counts
        .iter()
        .find(|count| count.class == class)
        .unwrap_or_else(|| panic!("the preview counts {}", class.as_str()));
    (row.total.get(), row.included.get())
}

#[test]
fn a_preview_names_what_a_reviewer_would_see_and_creates_nothing() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "previewed");
    let before: Vec<String> = std::fs::read_dir(fixture.work())
        .expect("the parent is readable")
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    let result = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "review".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy {
                    dirty_files: InclusionChoice::Include,
                    untracked_files: InclusionChoice::Include,
                    submodules: InclusionChoice::Exclude,
                    binary_files: InclusionChoice::Exclude,
                    generated_artefacts: InclusionChoice::Exclude,
                },
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "review",
                ))),
                preview_only: true,
            },
            Some(&action("workspace.create", 2)),
        )
        .expect("the preview is taken");
    assert!(
        result.workspace.0.is_none(),
        "a preview creates no workspace"
    );
    let preview = &result.preview;
    assert_eq!(preview.project_repository_id, project);
    assert_eq!(preview.kind, WorkspaceKind::Isolated);
    // Every class is counted exactly, and the inclusion follows the policy.
    assert_eq!(count(preview, InclusionClass::DirtyFile), (1, 1));
    // The untracked files are `notes.txt`, `.gitignore` and the binary `image.bin`.
    let (untracked_total, untracked_included) = count(preview, InclusionClass::UntrackedFile);
    assert_eq!(untracked_total, 3);
    assert_eq!(
        untracked_included, 2,
        "the binary untracked file is excluded by the binary rule"
    );
    assert_eq!(count(preview, InclusionClass::GeneratedArtefact), (1, 0));
    assert_eq!(count(preview, InclusionClass::BinaryFile), (1, 0));
    // The sample names the paths and says which are binary.
    let binary: Vec<&str> = preview
        .entries
        .iter()
        .filter(|entry| entry.binary)
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(binary, vec!["image.bin"]);
    assert!(
        preview
            .entries
            .iter()
            .any(|entry| entry.path == "notes.txt" && entry.included)
    );
    assert!(
        preview
            .entries
            .iter()
            .any(|entry| entry.path == "generated/output.txt" && !entry.included)
    );
    // And the limitations are stated rather than left to be discovered.
    assert!(
        preview
            .limitations
            .iter()
            .any(|line| line.contains("not a security sandbox"))
    );
    // Nothing was created.
    let after: Vec<String> = std::fs::read_dir(fixture.work())
        .expect("the parent is readable")
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    assert_eq!(before.len(), after.len());
    assert!(
        fixture
            .service()
            .workspace_list(&WorkspaceListParams {
                environment_id: fixture.environment_id(),
                project_repository_id: Nullable(None),
            })
            .expect("the listing reads")
            .workspaces
            .is_empty()
    );
}

#[test]
fn an_isolated_workspace_copies_what_the_policy_includes_and_the_source_keeps_everything() {
    // KR-REQ-14.21: never clean, stash or discard untracked files to start a reviewer.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "source");
    let source = fixture.work().join("source");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "review".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy {
                    dirty_files: InclusionChoice::Include,
                    untracked_files: InclusionChoice::Exclude,
                    submodules: InclusionChoice::Exclude,
                    binary_files: InclusionChoice::Exclude,
                    generated_artefacts: InclusionChoice::Exclude,
                },
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "review",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 3)),
        )
        .expect("the workspace is created");
    let workspace = created
        .workspace
        .0
        .as_ref()
        .expect("a creation returns the workspace");
    assert_eq!(workspace.state, WorkspaceState::Ready);
    assert_eq!(workspace.kind, WorkspaceKind::Isolated);
    assert_eq!(workspace.isolation.0, Some(IsolationMechanism::GitWorktree));
    let review = fixture.work().join("review");
    // The dirty tracked file came across with the user's own content.
    assert_eq!(
        std::fs::read_to_string(review.join("README.md")).expect("it is there"),
        "changed after the commit\n"
    );
    // The excluded classes did not.
    assert!(!review.join("notes.txt").exists());
    assert!(!review.join("generated/output.txt").exists());
    assert!(!review.join("image.bin").exists());
    // And the source tree still holds every one of them, byte for byte. Nothing was cleaned,
    // stashed or discarded to start a reviewer.
    assert_eq!(
        std::fs::read_to_string(source.join("README.md")).expect("it is there"),
        "changed after the commit\n"
    );
    assert_eq!(
        std::fs::read_to_string(source.join("notes.txt")).expect("it is there"),
        "untracked and the user's own\n"
    );
    assert_eq!(
        std::fs::read_to_string(source.join("generated/output.txt")).expect("it is there"),
        "a build product\n"
    );
    assert_eq!(
        std::fs::read(source.join("image.bin")).expect("it is there"),
        vec![0_u8, 1, 2, 3, 0, 5]
    );
    // The workspace is its own object, so a record of the repository's tree does not cover it.
    let read = fixture
        .service()
        .workspace_read(&WorkspaceReadParams {
            workspace_id: workspace.workspace_id,
        })
        .expect("the workspace reads");
    assert_ne!(
        read.workspace.filesystem_identity,
        fixture
            .service()
            .project_read(&kr_protocol::project::ProjectReadParams {
                project_repository_id: project,
            })
            .expect("the repository reads")
            .project
            .filesystem_identity
    );
    // What was copied in is uncommitted work the workspace now holds, so a removal accounts for it.
    assert!(
        read.workspace
            .retained
            .iter()
            .any(|item| item.kind == RetainedKind::DirtyContent),
        "the copied work is retained: {:?}",
        read.workspace.retained
    );
}

#[test]
fn an_independent_clone_has_its_own_object_store() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "shared-source");
    fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "independent".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::IndependentClone)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "independent",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 4)),
        )
        .expect("the workspace is created");
    let clone = fixture.work().join("independent");
    assert!(clone.join(".git/objects").is_dir());
    assert!(
        !clone.join(".git/objects/info/alternates").exists(),
        "an independent clone shares no object store"
    );
    // The base alone: nothing uncommitted was copied in.
    assert_eq!(
        std::fs::read_to_string(clone.join("README.md")).expect("it is there"),
        "a repository\n"
    );
    assert!(!clone.join("notes.txt").exists());
}

#[test]
fn a_shared_workspace_is_the_users_own_tree_and_nothing_is_relocated() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "in-place");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "in place".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: false,
            },
            Some(&action("workspace.create", 5)),
        )
        .expect("a shared workspace is the repository's own tree");
    let workspace = created.workspace.0.expect("it exists");
    assert_eq!(workspace.kind, WorkspaceKind::SharedExisting);
    // A shared workspace's tree is the repository's own, so its path is the repository's.
    let project_path = fixture
        .service()
        .project_read(&kr_protocol::project::ProjectReadParams {
            project_repository_id: project,
        })
        .expect("the repository reads")
        .project
        .display_path;
    assert_eq!(workspace.display_path, project_path);
    // Every one of the user's files is where it was.
    let source = fixture.work().join("in-place");
    assert!(source.join("notes.txt").is_file());
    assert!(source.join("generated/output.txt").is_file());
    // A reviewer of a shared workspace sees the tree as it is, so the preview includes everything.
    for class in InclusionClass::EVERY {
        let (total, included) = count(&created.preview, *class);
        assert_eq!(total, included, "{} is included as it is", class.as_str());
    }
    // A shared workspace takes no exclusion: asking for one is asking for an isolated workspace.
    let refusal = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "in place".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: true,
            },
            Some(&action("workspace.create", 6)),
        )
        .expect_err("a shared workspace keeps the user's state in place");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
}

#[test]
fn a_read_never_deletes() {
    // KR-REQ-23.43: view and read never imply deletion.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "kept");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "kept".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "kept-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 7)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let tree = fixture.work().join("kept-tree");
    for _ in 0..3 {
        let listed = fixture
            .service()
            .workspace_list(&WorkspaceListParams {
                environment_id: fixture.environment_id(),
                project_repository_id: Nullable(Some(project)),
            })
            .expect("the listing reads");
        assert_eq!(listed.workspaces.len(), 1);
        let read = fixture
            .service()
            .workspace_read(&WorkspaceReadParams { workspace_id })
            .expect("the workspace reads");
        assert_eq!(read.workspace.state, WorkspaceState::Ready);
        assert!(tree.join("README.md").is_file(), "the tree is still there");
    }
}

#[test]
fn a_removal_is_refused_while_a_bound_session_is_live() {
    // KR-REQ-14.22: cleanup happens after every bound session and run has finished, and neither
    // session closure nor marking a review complete deletes the workspace.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "bound");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "bound".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "bound-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 8)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let session = SessionId::new(Uuid::from_bytes([9; 16]));
    fixture
        .service()
        .bind_session(workspace_id, session, true)
        .expect("the session binds");
    let refusal = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 10)),
        )
        .expect_err("a live bound session refuses a removal");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    assert!(
        refusal
            .to_string()
            .contains("after every bound session and run has finished")
    );
    let tree = fixture.work().join("bound-tree");
    assert!(tree.join("README.md").is_file(), "nothing was removed");
    // The session ending is what makes the removal possible, and it is recorded rather than
    // performing the removal itself.
    fixture
        .service()
        .bind_session(workspace_id, session, false)
        .expect("the session ends");
    assert!(tree.join("README.md").is_file(), "closure deletes nothing");
    let removed = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 11)),
        )
        .expect("the removal is admitted once nothing is bound");
    assert!(removed.working_files_removed);
    assert_eq!(removed.workspace.state, WorkspaceState::Removed);
    assert!(!tree.exists());
    // The repository's own tree is untouched.
    assert!(fixture.work().join("bound/README.md").is_file());
}

#[test]
fn a_removal_keeps_dirty_content_a_pin_and_review_evidence_until_the_user_approves() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "retaining");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "retaining".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy {
                    dirty_files: InclusionChoice::Include,
                    untracked_files: InclusionChoice::Exclude,
                    submodules: InclusionChoice::Exclude,
                    binary_files: InclusionChoice::Exclude,
                    generated_artefacts: InclusionChoice::Exclude,
                },
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "retaining-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 12)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let change_set = ChangeSetId::new(Uuid::from_bytes([13; 16]));
    for item in [
        RetainedRow {
            kind: RetainedKind::PinnedChangeSet,
            detail: "version 3 is pinned".to_owned(),
            change_set_id: Some(change_set),
        },
        RetainedRow {
            kind: RetainedKind::ReviewEvidence,
            detail: "a review acknowledged version 3".to_owned(),
            change_set_id: Some(change_set),
        },
    ] {
        fixture
            .service()
            .retain(workspace_id, &item)
            .expect("the workspace records what it holds");
    }
    let tree = fixture.work().join("retaining-tree");

    // The policy that cannot lose work removes nothing while anything is held, and says what.
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::KeepEverything,
            },
            Some(&action("workspace.remove", 14)),
        )
        .expect("the removal is answered rather than refused");
    assert!(!answer.working_files_removed);
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    let kinds: Vec<RetainedKind> = answer.retained.iter().map(|item| item.kind).collect();
    assert!(kinds.contains(&RetainedKind::DirtyContent));
    assert!(kinds.contains(&RetainedKind::PinnedChangeSet));
    assert!(kinds.contains(&RetainedKind::ReviewEvidence));
    assert!(tree.join("README.md").is_file(), "nothing was removed");

    // Keeping the evidence removes the working files and leaves the record waiting.
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::KeepRetainedEvidence,
            },
            Some(&action("workspace.remove", 15)),
        )
        .expect("the working files go and the evidence stays");
    assert!(answer.working_files_removed);
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    assert_eq!(answer.retained.len(), 3);
    assert!(!tree.exists());

    // The user's approval is the policy that names what it removes.
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 16)),
        )
        .expect("the approval removes what was held");
    assert_eq!(answer.workspace.state, WorkspaceState::Removed);
    assert!(answer.retained.is_empty());
    // And the record survives, so a later read says what happened rather than nothing.
    let read = fixture
        .service()
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the record is still there");
    assert_eq!(read.workspace.state, WorkspaceState::Removed);
}

#[test]
fn a_shared_workspaces_removal_never_touches_the_users_tree() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "never-deleted");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "in place".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: false,
            },
            Some(&action("workspace.create", 17)),
        )
        .expect("the selection is made");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 18)),
        )
        .expect("the selection is removed");
    assert_eq!(answer.workspace.state, WorkspaceState::Removed);
    assert!(
        !answer.working_files_removed,
        "a shared workspace is the user's own tree, and removing the selection removes no file"
    );
    let source = fixture.work().join("never-deleted");
    assert!(source.join("README.md").is_file());
    assert!(source.join("notes.txt").is_file());
    assert!(source.join(".git").is_dir());
}

#[test]
fn a_workspace_record_its_pins_and_its_partial_progress_survive_the_daemons_death() {
    // KR-REQ-24.08: immutable versions and partial progress survive controller death, and cleanup
    // respects pins.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "durable");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "durable".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "durable-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 19)),
        )
        .expect("the workspace is created");
    let workspace = created.workspace.0.expect("it exists");
    let change_set = ChangeSetId::new(Uuid::from_bytes([20; 16]));
    fixture
        .service()
        .retain(
            workspace.workspace_id,
            &RetainedRow {
                kind: RetainedKind::PinnedChangeSet,
                detail: "version 4 is pinned".to_owned(),
                change_set_id: Some(change_set),
            },
        )
        .expect("the pin is recorded");
    let session = SessionId::new(Uuid::from_bytes([21; 16]));
    fixture
        .service()
        .bind_session(workspace.workspace_id, session, true)
        .expect("a session binds");

    // The daemon goes. A replacement opens the same environment and finds everything.
    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert_eq!(recovery.materialisations_unfinished, 0);
    let read = replacement
        .workspace_read(&WorkspaceReadParams {
            workspace_id: workspace.workspace_id,
        })
        .expect("the record survived");
    assert_eq!(read.workspace.base_revision, workspace.base_revision);
    assert_eq!(read.workspace.policy, workspace.policy);
    assert_eq!(
        read.workspace.filesystem_identity,
        workspace.filesystem_identity
    );
    assert_eq!(read.workspace.bound_sessions, vec![session]);
    assert!(
        read.workspace
            .retained
            .iter()
            .any(|item| item.change_set_id.0 == Some(change_set)),
        "the pin survived: {:?}",
        read.workspace.retained
    );
    // And cleanup still respects the pin and the session.
    let refusal = replacement
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 22)),
        )
        .expect_err("the bound session still refuses it");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    replacement
        .bind_session(workspace.workspace_id, session, false)
        .expect("the session ends");
    let answer = replacement
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id: workspace.workspace_id,
                retention: RetentionPolicy::KeepEverything,
            },
            Some(&action("workspace.remove", 23)),
        )
        .expect("the removal is answered");
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    assert!(
        fixture.work().join("durable-tree/README.md").is_file(),
        "a pin keeps the workspace"
    );
}

#[test]
fn a_workspace_names_a_revision_this_repository_holds() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "revisions");
    for (revision, expected) in [
        ("HEAD", None),
        ("main", None),
        ("does-not-exist", Some(ErrorCode::InvalidArgument)),
        ("--upload-pack=sh", Some(ErrorCode::InvalidArgument)),
    ] {
        let outcome = fixture.service().workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "revision".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(Some(revision.to_owned())),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "revision-tree",
                ))),
                preview_only: true,
            },
            None,
        );
        match expected {
            None => {
                let result = outcome.unwrap_or_else(|error| {
                    panic!("{revision} is a revision this repository holds: {error}")
                });
                assert_eq!(result.preview.base_revision.len(), 40);
            }
            Some(code) => {
                assert_eq!(
                    outcome
                        .expect_err("a revision this repository does not hold is refused")
                        .code(),
                    code,
                    "{revision}"
                );
            }
        }
    }
    // A change-set version is resolved by the change-set service, which names the revision with it.
    let refusal = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "version".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(Some(ChangeSetId::new(Uuid::from_bytes([24; 16])))),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "version-tree",
                ))),
                preview_only: true,
            },
            None,
        )
        .expect_err("a change-set version alone is not a revision this service resolves");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(refusal.to_string().contains("change-set service"));
}

#[test]
fn an_isolated_workspaces_destination_is_created_rather_than_merged_into() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "taken");
    std::fs::create_dir(fixture.work().join("occupied")).expect("something is already there");
    let refusal = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "occupied".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "occupied",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 25)),
        )
        .expect_err("an existing destination is not merged into");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(
        refusal
            .to_string()
            .contains("created rather than merged into")
    );
}

#[test]
fn a_workspace_row_holds_every_field_a_replacement_needs() {
    // The row is what survives, so every field a replacement reads has to be in it. This is the
    // shape rather than the behaviour, so it costs no repository.
    let row = WorkspaceRow {
        workspace_id: kr_protocol::ids::WorkspaceId::new(Uuid::from_bytes([1; 16])),
        project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
        label: "review".to_owned(),
        kind: WorkspaceKind::Isolated,
        isolation: Some(IsolationMechanism::GitWorktree),
        policy: InclusionPolicy::base_only(),
        state: WorkspaceState::Ready,
        base_revision: "a".repeat(40),
        base_change_set_id: Some(ChangeSetId::new(Uuid::from_bytes([4; 16]))),
        identity: Some(kr_transfer::ObjectIdentity {
            device: 1,
            file_id: 2,
        }),
        display_path: "/tmp/review".to_owned(),
        retention: Some(RetentionPolicy::KeepEverything),
        created_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        removed_at_ms: None,
    };
    assert_eq!(row.base_revision.len(), 40);
    assert_eq!(row.policy, InclusionPolicy::base_only());
}
