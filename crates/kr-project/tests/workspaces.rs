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
        .filter(|entry| entry.content == kr_protocol::project::ContentClass::Binary)
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
    let repository_identity = fixture
        .service()
        .project_read(&kr_protocol::project::ProjectReadParams {
            project_repository_id: project,
        })
        .expect("the repository reads")
        .project
        .filesystem_identity;
    assert_ne!(
        read.workspace
            .filesystem_identity
            .0
            .expect("a ready workspace has one"),
        repository_identity
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

    // The user's approval is the policy that names what it removes. There is no third policy that
    // removes the working files while claiming to keep the dirty content in them.
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
    assert!(answer.working_files_removed);
    assert!(!tree.exists());
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
        staging_name: None,
        staging_identity: None,
        detail: None,
        retention: Some(RetentionPolicy::KeepEverything),
        created_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        removed_at_ms: None,
    };
    assert_eq!(row.base_revision.len(), 40);
    assert_eq!(row.policy, InclusionPolicy::base_only());
}

#[test]
fn a_shorter_dirty_file_keeps_none_of_the_bases_bytes() {
    // The checkout puts the base's content at the name, so a copy that wrote over it would leave
    // the base's tail behind whenever the user's file is shorter.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "truncating");
    write(&path, "long.txt", "abcdefghijklmnop\n");
    write(&path, "empty.txt", "not empty yet\n");
    support::git_raw(&path, ["add", "-A"]);
    support::git_raw(&path, ["commit", "-m", "the long versions"]);
    write(&path, "long.txt", "x\n");
    write(&path, "empty.txt", "");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "truncating"),
                label: "truncating".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 30)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "review".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "shorter",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 31)),
        )
        .expect("the workspace is created");
    let tree = fixture.work().join("shorter");
    assert_eq!(
        std::fs::read_to_string(tree.join("long.txt")).expect("it is there"),
        "x\n",
        "the workspace holds the user's file and nothing of the base's"
    );
    assert_eq!(
        std::fs::read_to_string(tree.join("empty.txt")).expect("it is there"),
        "",
        "an emptied file arrives empty rather than unchanged"
    );
}

#[test]
fn a_deletion_the_user_has_is_carried_by_removing_the_path() {
    // A copy is not the only way to carry an inclusion. The user deleted a tracked file, and the
    // checkout put the base's copy back, so carrying that change means removing it again.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "deleting");
    std::fs::remove_file(path.join("README.md")).expect("the user deletes a tracked file");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "deleting"),
                label: "deleting".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 32)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "review".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "deleted",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 33)),
        )
        .expect("the workspace is created");
    // The preview names the change as a deletion rather than as a file to copy.
    assert!(
        created
            .preview
            .entries
            .iter()
            .any(|entry| entry.path == "README.md"
                && entry.change == kr_protocol::project::ChangeKind::Deleted),
        "the preview names the deletion: {:?}",
        created.preview.entries
    );
    assert!(
        !fixture.work().join("deleted/README.md").exists(),
        "the workspace holds the deletion rather than the base's copy"
    );
    // And the source still has its own state: the file the user deleted is still deleted there,
    // and nothing else was touched.
    assert!(!fixture.work().join("deleting/README.md").exists());
    assert!(fixture.work().join("deleting/src/lib.rs").is_file());
}

#[cfg(unix)]
#[test]
fn a_path_this_host_cannot_read_is_excluded_by_an_exclusion_and_named_by_an_inclusion() {
    // An unread path is not a text path. A symbolic link is refused by the authority model, so it
    // is the case this host can reach without waiting for twenty thousand files.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "unreadable");
    std::os::unix::fs::symlink("src/lib.rs", path.join("link.rs")).expect("a symbolic link");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "unreadable"),
                label: "unreadable".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 34)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    // An exclusion of binary files leaves it out, because what this host could not read might be
    // binary and excluding it is the direction that honours the request.
    let excluded = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "excluded".to_owned(),
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
                    "excluded",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 35)),
        )
        .expect("the workspace is created");
    let link = excluded
        .preview
        .entries
        .iter()
        .find(|entry| entry.path == "link.rs")
        .expect("the preview names the link");
    assert_eq!(link.content, kr_protocol::project::ContentClass::Unknown);
    assert!(!link.included, "what this host could not read is left out");
    assert!(excluded.preview.unknown_content.get() >= 1);
    assert!(!fixture.work().join("excluded/link.rs").exists());

    // An inclusion of binary files takes it, and the result names it as one this host could not
    // carry rather than pretending the workspace holds it.
    let included = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "included".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "included",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 36)),
        )
        .expect("the workspace is created");
    assert!(
        included.unapplied.iter().any(|path| path == "link.rs"),
        "the result names what it could not carry: {:?}",
        included.unapplied
    );
    // And the link is still in the source tree.
    assert!(fixture.work().join("unreadable/link.rs").exists());
}

#[test]
fn a_live_automation_run_refuses_a_removal_as_a_live_session_does() {
    // Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
    // between two sessions or after its last one ended.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "run-bound");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "run".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "run-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 37)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let run = kr_protocol::ids::WorkflowRunId::new(Uuid::from_bytes([38; 16]));
    fixture
        .service()
        .bind_run(workspace_id, run, true)
        .expect("the run binds");
    let refusal = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 39)),
        )
        .expect_err("a live run refuses a removal");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    assert!(
        refusal
            .to_string()
            .contains("automation runs bound to this workspace")
    );
    assert!(fixture.work().join("run-tree/README.md").is_file());
    // A read says which run holds it.
    let read = fixture
        .service()
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace reads");
    assert_eq!(read.workspace.bound_runs, vec![run]);
    // And the run ending is what admits the removal.
    fixture
        .service()
        .bind_run(workspace_id, run, false)
        .expect("the run ends");
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 40)),
        )
        .expect("the removal is admitted once nothing holds it");
    assert_eq!(answer.workspace.state, WorkspaceState::Removed);
    assert!(!fixture.work().join("run-tree").exists());
}

#[test]
fn work_added_after_a_workspace_was_created_still_keeps_it() {
    // An empty retention table does not establish a clean tree. The tree is measured before a
    // removal decides anything.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "later-work");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "later".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "later-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 41)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    // Nothing uncommitted was copied in, so the workspace holds nothing yet.
    let read = fixture
        .service()
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace reads");
    assert!(read.workspace.retained.is_empty());
    // Somebody then works in it.
    let tree = fixture.work().join("later-tree");
    write(&tree, "README.md", "edited inside the workspace\n");
    write(&tree, "new-note.txt", "written inside the workspace\n");
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::KeepEverything,
            },
            Some(&action("workspace.remove", 42)),
        )
        .expect("the removal is answered");
    assert!(!answer.working_files_removed);
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    assert!(
        answer
            .retained
            .iter()
            .any(|item| item.kind == RetainedKind::DirtyContent),
        "the work added after the creation keeps it: {:?}",
        answer.retained
    );
    assert_eq!(
        std::fs::read_to_string(tree.join("new-note.txt")).expect("it is still there"),
        "written inside the workspace\n"
    );
}

#[test]
fn nothing_new_may_hold_a_workspace_once_its_removal_has_begun() {
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "reserved");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "reserved".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "reserved-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 43)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 44)),
        )
        .expect("the removal runs");
    // A session or a run that arrived after the removal would be a live holder of a tree that is
    // already gone, so neither is accepted.
    let refusal = fixture
        .service()
        .bind_session(
            workspace_id,
            SessionId::new(Uuid::from_bytes([45; 16])),
            true,
        )
        .expect_err("a removed workspace takes no new holder");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    let refusal = fixture
        .service()
        .bind_run(
            workspace_id,
            kr_protocol::ids::WorkflowRunId::new(Uuid::from_bytes([46; 16])),
            true,
        )
        .expect_err("a removed workspace takes no new run either");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
}

#[test]
fn a_removal_this_host_cannot_prove_it_owns_is_refused() {
    // A materialisation that never recorded the tree's identity leaves a row with none. Removing
    // whatever is at that path would be removing whatever is there.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "unproven");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "unproven".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "unproven-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 47)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    // The state a materialisation that failed before it created the tree leaves behind.
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE workspaces SET tree_device = NULL, tree_file_id = NULL WHERE workspace_id = ?1",
            rusqlite::params![workspace_id.get().as_bytes().to_vec()],
        )
        .expect("the identity is cleared");
    drop(journal);
    let replacement = fixture.reopen();
    let read = replacement
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace reads");
    assert!(
        read.workspace.filesystem_identity.0.is_none(),
        "an absent identity is reported as absent rather than as zero"
    );
    let refusal = replacement
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 48)),
        )
        .expect_err("this host does not remove a directory it cannot prove is its");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);
    assert!(
        refusal
            .to_string()
            .contains("recorded no filesystem identity")
    );
    assert!(fixture.work().join("unproven-tree/README.md").is_file());
}

#[cfg(unix)]
#[test]
fn an_included_executable_arrives_executable_and_a_failed_copy_leaves_the_base_in_place() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "executable");
    write(&path, "run.sh", "#!/bin/sh\necho base\n");
    std::fs::create_dir_all(path.join("blocked")).expect("a directory in the base");
    write(&path.join("blocked"), "inner.txt", "the base's content\n");
    std::fs::set_permissions(path.join("run.sh"), std::fs::Permissions::from_mode(0o755))
        .expect("the script is executable");
    support::git_raw(&path, ["add", "-A"]);
    support::git_raw(&path, ["commit", "-m", "the base"]);
    // The user's own versions. Where the base has a directory, the user has a plain file: a copy
    // cannot replace one with the other, so this is the path the inclusion has to report rather
    // than write over.
    write(&path, "run.sh", "#!/bin/sh\necho mine\n");
    std::fs::set_permissions(path.join("run.sh"), std::fs::Permissions::from_mode(0o755))
        .expect("the user's script is executable too");
    std::fs::remove_dir_all(path.join("blocked")).expect("the user removed the directory");
    write(&path, "blocked", "the user's content\n");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "executable"),
                label: "executable".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 50)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "modes".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "modes",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 51)),
        )
        .expect("the workspace is created");
    assert!(created.workspace.0.is_some());
    let tree = fixture.work().join("modes");
    assert_eq!(
        std::fs::read_to_string(tree.join("run.sh")).expect("it is there"),
        "#!/bin/sh\necho mine\n"
    );
    let mode = std::fs::metadata(tree.join("run.sh"))
        .expect("its metadata")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o111,
        0o111,
        "an included executable keeps its executable bit"
    );
    // The copy that could not land is named, and what the base put there is still there.
    assert!(
        created.unapplied.iter().any(|path| path == "blocked"),
        "the path this host could not carry is named: {:?}",
        created.unapplied
    );
    assert!(
        tree.join("blocked").is_dir(),
        "a copy that could not land does not write over what is at the name"
    );
    // And nothing of this host's own is left behind in the user's workspace.
    let strays: Vec<String> = std::fs::read_dir(&tree)
        .expect("the workspace lists")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".kr-copy-"))
        .collect();
    assert!(strays.is_empty(), "no copy in progress is left: {strays:?}");
}

#[test]
fn a_workspace_this_host_cannot_inspect_is_kept_rather_than_removed() {
    // An incomplete inspection keeps work. A tree this host could not read is not a tree it found
    // empty, so `keep_everything` keeps it and says why.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "uninspectable");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "uninspectable".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "uninspectable-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 52)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let tree = fixture.work().join("uninspectable-tree");
    // The gitfile a linked worktree uses, replaced by something Git cannot read: the directory is
    // still there and its identity still matches, but its status cannot be taken.
    std::fs::write(tree.join(".git"), "not a gitfile\n").expect("the gitfile is broken");
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::KeepEverything,
            },
            Some(&action("workspace.remove", 53)),
        )
        .expect("the removal is answered");
    assert!(!answer.working_files_removed);
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    assert!(
        answer.retained.iter().any(|item| item
            .detail
            .contains("could not read what this workspace holds")),
        "the host says it could not inspect the tree: {:?}",
        answer.retained
    );
    assert!(tree.join("README.md").is_file(), "nothing was removed");
}

#[test]
fn nothing_new_is_recorded_against_a_workspace_once_its_removal_has_begun() {
    // A pin added between the removal's decision and its deletion would be a pin the removal never
    // saw, so a workspace whose removal has begun takes nothing new either.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "sealed");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "sealed".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "sealed-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 54)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    // A pin before the removal keeps it, and is visible to the decision.
    fixture
        .service()
        .retain(
            workspace_id,
            &RetainedRow {
                kind: RetainedKind::PinnedChangeSet,
                detail: "version 9 is pinned".to_owned(),
                change_set_id: Some(ChangeSetId::new(Uuid::from_bytes([55; 16]))),
            },
        )
        .expect("the pin is recorded");
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::KeepEverything,
            },
            Some(&action("workspace.remove", 56)),
        )
        .expect("the removal is answered");
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    // And a pin that arrives afterwards is refused rather than recorded against a workspace whose
    // removal has begun.
    let refusal = fixture
        .service()
        .retain(
            workspace_id,
            &RetainedRow {
                kind: RetainedKind::ReviewEvidence,
                detail: "a review that arrived too late".to_owned(),
                change_set_id: None,
            },
        )
        .expect_err("nothing new is recorded against it");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
}

#[test]
fn a_staged_deletion_is_carried_like_an_unstaged_one() {
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "staged-delete");
    // `git rm` stages the deletion, so the status reports `D.` rather than `.D`.
    support::git_raw(&path, ["rm", "--quiet", "README.md"]);
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "staged-delete"),
                label: "staged".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 57)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "staged".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "staged-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 58)),
        )
        .expect("the workspace is created");
    assert!(
        created
            .preview
            .entries
            .iter()
            .any(|entry| entry.path == "README.md"
                && entry.change == kr_protocol::project::ChangeKind::Deleted),
        "a staged deletion is a deletion: {:?}",
        created.preview.entries
    );
    assert!(
        !fixture.work().join("staged-tree/README.md").exists(),
        "the workspace holds the deletion rather than the base's copy"
    );
}

#[test]
fn a_workspace_holding_a_populated_submodule_is_kept_rather_than_removed() {
    // The status a removal reads asks Git to ignore submodules, because looking inside one would
    // run under a configuration this host has not audited. So an empty status is an empty status
    // of the tree *outside* its submodules, and work inside one is work this host has not read.
    let fixture = Fixture::create();
    let planted = support::planted_submodule(fixture.work(), "submodule-holder");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "submodule-holder",
                ),
                label: "holder".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 60)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "holder".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: false,
            },
            Some(&action("workspace.create", 61)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    assert!(
        planted.parent.join("vendor/child").is_dir(),
        "the submodule's own tree is populated"
    );
    let answer = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::KeepEverything,
            },
            Some(&action("workspace.remove", 62)),
        )
        .expect("the removal is answered");
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    assert!(
        answer
            .retained
            .iter()
            .any(|item| item.detail.contains("does not look inside")),
        "the host says the submodule is work it has not read: {:?}",
        answer.retained
    );
    assert!(
        planted.parent.join("vendor/child/a.txt").is_file(),
        "nothing inside the submodule was touched"
    );
    // And no marker inside the submodule ran while the removal measured what the workspace holds.
    assert!(
        !planted.sentinels.exists()
            || std::fs::read_dir(&planted.sentinels)
                .is_ok_and(|mut entries| entries.next().is_none()),
        "no planted helper ran"
    );
}

#[test]
fn a_recovered_workspace_creation_answers_from_the_journal_rather_than_unknown() {
    // A daemon can die between calling a workspace ready and recording the result. The workspace
    // is sitting there, so a repeat of the action is answered from the journal: the summary and
    // what the inclusion could not carry are durable, and the preview says it is not a measurement
    // this host still holds.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "recovered");
    let submitted = action("workspace.create", 63);
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "recovered".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "recovered-tree",
                ))),
                preview_only: false,
            },
            Some(&submitted),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    // The state a daemon that died before recording the result leaves: the workspace is ready and
    // the claim is open.
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE actions SET result = NULL, error_code = NULL, error_detail = NULL
              WHERE action_id = ?1",
            rusqlite::params![submitted.action_id.as_bytes().to_vec()],
        )
        .expect("the claim is open again");
    drop(journal);
    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert_eq!(recovery.claims_settled, 1);
    let repeated = replacement
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "recovered".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "recovered-tree",
                ))),
                preview_only: false,
            },
            Some(&submitted),
        )
        .expect("the repeat is answered from the journal");
    assert_eq!(
        repeated.workspace.0.expect("the workspace").workspace_id,
        workspace_id
    );
    assert!(
        !repeated.preview.counts_complete,
        "a rebuilt preview does not claim to be a measurement"
    );
    assert!(
        repeated
            .preview
            .limitations
            .iter()
            .any(|line| line.contains("rebuilt from the journal")),
        "and says so: {:?}",
        repeated.preview.limitations
    );
}

#[test]
fn a_staging_name_a_workspace_recorded_is_swept_only_while_it_holds_that_object() {
    // A workspace row names the private sibling an independent clone was staged in. A recorded
    // name is not authority to remove whatever holds it later, so the sweep removes the object
    // whose identity the row holds and leaves a replacement alone.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "sibling");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "sibling".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::IndependentClone)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "sibling-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 64)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    // A directory the user put at a name this host once used, recorded on the row with the
    // identity of something else.
    let replaced = fixture.work().join(".kr-project-replaced");
    std::fs::create_dir_all(replaced.join("mine")).expect("the user's own directory");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE workspaces SET staging_name = ?2, staging_device = ?3, staging_file_id = ?4
              WHERE workspace_id = ?1",
            rusqlite::params![
                workspace_id.get().as_bytes().to_vec(),
                ".kr-project-replaced",
                1_i64,
                1_i64,
            ],
        )
        .expect("the name and a different identity are recorded");
    drop(journal);
    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    assert!(
        replaced.join("mine").is_dir(),
        "a directory whose identity is not the recorded one is left alone"
    );
    // And once the row holds that object's own identity, the sweep takes it.
    let identity = std::fs::metadata(&replaced).expect("its metadata");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE workspaces SET staging_name = ?2, staging_device = ?3, staging_file_id = ?4
              WHERE workspace_id = ?1",
            rusqlite::params![
                workspace_id.get().as_bytes().to_vec(),
                ".kr-project-replaced",
                std::os::unix::fs::MetadataExt::dev(&identity) as i64,
                std::os::unix::fs::MetadataExt::ino(&identity) as i64,
            ],
        )
        .expect("the recorded identity is that object's own");
    drop(journal);
    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs again");
    assert!(
        !replaced.exists(),
        "the sibling whose identity the row holds is removed"
    );
}
