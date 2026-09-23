//! Workspaces: the explicit choice, the inclusion preview, what a creation copies, and what a
//! removal may take.
//!
//! KR-REQ-14.20, 14.21, 14.22, 23.43, 24.08.
//!
//! Every test here asks the project service to run Git. On Windows it runs none: an application
//! container cannot keep a repository from being executed from and cannot bound which ports a
//! remote operation reaches, so the service refuses there rather than claiming a boundary it does
//! not have. These tests therefore describe the platforms where Git runs; the refusal itself is in
//! `tests/boundary.rs`.

#![cfg(not(windows))]
#![cfg(feature = "git-fixtures")]

mod support;

use kr_project::store::{Performed, RetainedRow, WorkspaceRow};
use kr_protocol::error::{ErrorCode, ProtocolError};
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
    let before = support::names_in(fixture.work());
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
    assert_eq!(before, support::names_in(fixture.work()));
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
    for excluded in ["notes.txt", "generated/output.txt", "image.bin"] {
        support::assert_absent(
            &review.join(excluded),
            "the excluded classes did not arrive",
        );
    }
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
    support::assert_absent(
        &clone.join(".git/objects/info/alternates"),
        "an independent clone shares no object store",
    );
    // The base alone: nothing uncommitted was copied in.
    assert_eq!(
        std::fs::read_to_string(clone.join("README.md")).expect("it is there"),
        "a repository\n"
    );
    support::assert_absent(
        &clone.join("notes.txt"),
        "nothing uncommitted was copied in",
    );
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
    support::assert_absent(&tree, "the working files are gone");
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
    support::assert_absent(&tree, "the working files are gone");
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
fn a_pin_recorded_while_a_deletion_reads_the_pins_lands_after_that_reading_not_inside_it() {
    // KR-REQ-14.36: retention accounts for every pin before a version is deleted. The pin is in
    // this store and the version is in the change-set store, so a deletion that read the pins and
    // then removed the version would leave a window: a pin recorded in between would be a pin the
    // deletion never saw. `with_pins` closes it by holding this journal across the caller's own
    // transaction, and the pin's own path takes the same lock.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "pinned");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "pinned".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "pinned-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 61)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let change_set = ChangeSetId::new(Uuid::from_bytes([62; 16]));
    let item = RetainedRow {
        kind: RetainedKind::PinnedChangeSet,
        detail: "version 1 is pinned against this workspace".to_owned(),
        change_set_id: Some(change_set),
    };
    let service = fixture.service();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let (recorded, landed) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|threads| {
        threads.spawn(move || {
            wait.recv().expect("the reading has begun");
            service
                .retain(workspace_id, &item)
                .expect("the pin is recorded");
            recorded.send(()).expect("the reading is still waiting");
        });
        let decided = service
            .with_pins(change_set, |pinned| {
                assert!(pinned.is_empty(), "nothing holds it yet: {pinned:?}");
                // The other thread now asks to record one. It cannot, because this reading holds
                // the journal, so the decision this closure is making stays true while it is made.
                go.send(()).expect("the recorder is waiting");
                assert!(
                    landed
                        .recv_timeout(std::time::Duration::from_millis(250))
                        .is_err(),
                    "a pin recorded while the pins are being read waits for the reading"
                );
                "deleted"
            })
            .expect("the pins read");
        assert_eq!(decided, "deleted");
        landed
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("and lands once the reading has finished");
    });
    let after = service.pins(change_set).expect("the pins read again");
    assert_eq!(
        after.len(),
        1,
        "the pin that waited is recorded, not lost: {after:?}"
    );
    assert_eq!(after[0].workspace_id, workspace_id);
    assert_eq!(after[0].change_set_id, change_set);

    // The other half of the protocol: a pin whose version is gone is not recorded at all. The
    // caller's question is asked inside the same hold the deletion's reading takes, so a version
    // deleted after the question cannot be pinned by this write.
    let gone = ChangeSetId::new(Uuid::from_bytes([67; 16]));
    let refusal = service
        .retain_pin(
            workspace_id,
            &RetainedRow {
                kind: RetainedKind::PinnedChangeSet,
                detail: "a version this host no longer holds".to_owned(),
                change_set_id: Some(gone),
            },
            || false,
        )
        .expect_err("a pin against a version that is gone is refused");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(
        service.pins(gone).expect("the pins read").is_empty(),
        "and nothing was written"
    );
    service
        .retain_pin(
            workspace_id,
            &RetainedRow {
                kind: RetainedKind::PinnedChangeSet,
                detail: "a version this host holds".to_owned(),
                change_set_id: Some(gone),
            },
            || true,
        )
        .expect("a pin against a version that is there is recorded");
    assert_eq!(service.pins(gone).expect("the pins read").len(), 1);
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
        located: None,
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
    support::assert_absent(
        &fixture.work().join("deleted/README.md"),
        "the workspace holds the deletion rather than the base's copy",
    );
    // And the source still has its own state: the file the user deleted is still deleted there,
    // and nothing else was touched.
    support::assert_absent(
        &fixture.work().join("deleting/README.md"),
        "the source still holds the deletion the user made",
    );
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
    support::assert_absent(
        &fixture.work().join("excluded/link.rs"),
        "what this host could not read is left out",
    );

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
    // And the link is still in the source tree. The name is what matters, not what it points at,
    // so this asks about the name itself.
    assert!(
        std::fs::symlink_metadata(fixture.work().join("unreadable/link.rs")).is_ok(),
        "the link the inclusion could not carry is still where the user left it"
    );
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
    support::assert_absent(
        &fixture.work().join("run-tree"),
        "the working files are gone once nothing holds the workspace",
    );
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
    let strays: Vec<String> = support::names_in(&tree)
        .into_iter()
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
    support::assert_absent(
        &fixture.work().join("staged-tree/README.md"),
        "the workspace holds the deletion rather than the base's copy",
    );
}

#[test]
fn a_workspace_holding_a_populated_submodule_is_kept_rather_than_removed() {
    // The status a removal reads asks Git to ignore submodules, because looking inside one would
    // run under a configuration this host has not audited. So an empty status is an empty status
    // of the tree *outside* its submodules, and work inside one is work this host has not read.
    //
    // The reason it records names two pieces of text this host did not write: the workspace's own
    // path and the submodule's path out of the index. They carry a marker each, so a message that
    // repeats either one is caught wherever it surfaces — the answer, a later read, and the repeat
    // of the action, which is answered from the journal's own copy.
    const TREE: &str = "access_token=HOLDERSECRET";
    const NESTED: &str = "vendor/access_token=NESTEDSECRET";
    let fixture = Fixture::create();
    let planted = support::planted_submodule(fixture.work(), TREE, NESTED);
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), TREE),
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
        planted.parent.join(NESTED).is_dir(),
        "the submodule's own tree is populated"
    );
    let removal = action("workspace.remove", 62);
    let params = WorkspaceRemoveParams {
        workspace_id,
        retention: RetentionPolicy::KeepEverything,
    };
    let answer = fixture
        .service()
        .workspace_remove(&params, Some(&removal))
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
    // Every diagnostic in the first answer, in the read that follows it, and in the repeat of the
    // action. Each of those is a *successful* reply: none of them crosses the error boundary, and
    // the last is the journal's own copy rather than a message composed again.
    let read = fixture
        .service()
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace reads");
    let repeated = fixture
        .service()
        .workspace_remove(&params, Some(&removal))
        .expect("the repeat is answered from the journal");
    let mut reasons: Vec<String> = Vec::new();
    for summary in [&answer.workspace, &read.workspace, &repeated.workspace] {
        reasons.extend(summary.detail.0.clone());
        reasons.extend(summary.retained.iter().map(|item| item.detail.clone()));
    }
    for item in answer.retained.iter().chain(repeated.retained.iter()) {
        reasons.push(item.detail.clone());
    }
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("does not look inside")),
        "the reason is in all three: {reasons:?}"
    );
    for reason in &reasons {
        assert!(
            !reason.contains("HOLDERSECRET"),
            "no reason repeats the workspace's own path: {reason}"
        );
        assert!(
            !reason.contains("NESTEDSECRET"),
            "and none repeats the submodule's path out of the index: {reason}"
        );
    }
    // The path the caller named is still answered with, because that is the value the request
    // asked about rather than something this host is explaining.
    assert!(
        read.workspace.display_path.contains(TREE),
        "a display path is data: {}",
        read.workspace.display_path
    );
    assert!(
        planted.parent.join(NESTED).join("a.txt").is_file(),
        "nothing inside the submodule was touched"
    );
    // And no marker inside the submodule ran while the removal measured what the workspace holds.
    assert!(
        planted.escaped().is_empty(),
        "no planted helper ran: {:?}",
        planted.escaped()
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
fn a_staging_name_a_workspace_recorded_is_named_by_recovery_and_never_removed() {
    // A workspace row names the private sibling an independent clone was staged in. Recovery
    // holds nothing that reaches it, and a recorded name is not authority, so it removes neither
    // a replacement at that name nor the object whose identity the row holds. The workspace says
    // why the name is still there.
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
    // A directory at a name this host once used, as private as one this host makes, recorded on
    // the row with the identity of something else.
    let replaced = fixture.work().join(".kr-project-replaced");
    support::staging_directory(&replaced);
    std::fs::create_dir(replaced.join("mine")).expect("something in it");
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
    // And once the row holds that object's own identity, recovery still removes nothing.
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
        replaced.join("mine").is_dir(),
        "the sibling whose identity the row holds is left for the owner as well"
    );
    let read = replacement
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace reads");
    assert!(
        read.workspace
            .detail
            .0
            .as_deref()
            .is_some_and(|detail| detail.contains("no location reaches it")),
        "and the workspace says why: {:?}",
        read.workspace.detail
    );
}

#[test]
fn an_inclusion_records_every_path_it_will_attempt_before_it_attempts_any() {
    // A crash inside the first batch would otherwise leave paths this host had copied with no
    // record at all. So every path the inclusion will attempt is written as `planned` first, and
    // each outcome replaces its row: a path with no row is a path nothing accounts for.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "planned");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "planned".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "planned-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 65)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    let mut statement = journal
        .prepare("SELECT path, outcome FROM workspace_progress WHERE workspace_id = ?1")
        .expect("the progress reads");
    let rows: Vec<(String, String)> = statement
        .query_map(
            rusqlite::params![workspace_id.get().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the rows map")
        .map(|row| row.expect("a row"))
        .collect();
    assert!(
        !rows.is_empty(),
        "an inclusion of a tree with uncommitted work journalled something"
    );
    assert!(
        rows.iter().all(|(_, outcome)| outcome != "planned"),
        "a finished inclusion leaves nothing unresolved: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|(path, outcome)| path == "README.md" && outcome == "carried"),
        "and says what became of each path: {rows:?}"
    );
    // Every path the copy carried is a path the creation reported, and nothing it could not carry
    // is missing from `unapplied`.
    let unapplied: Vec<&String> = rows
        .iter()
        .filter(|(_, outcome)| outcome == "unapplied" || outcome == "leftover")
        .map(|(path, _)| path)
        .collect();
    for path in unapplied {
        assert!(
            created.unapplied.contains(path),
            "{path} is journalled as unapplied and named in the reply: {:?}",
            created.unapplied
        );
    }
}

#[test]
fn a_workspace_staging_directory_recovery_cannot_reach_is_named_with_the_reason() {
    use std::os::unix::fs::MetadataExt as _;

    // Recovery keeps the name of a workspace's staging directory for the owner and says, on the
    // workspace, why it is still there.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "stopping");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "stopping".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::IndependentClone)),
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "stopping-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 66)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let staged = fixture.work().join(".kr-project-stopping");
    support::staging_directory(&staged);
    let identity = std::fs::metadata(&staged).expect("its metadata");
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
                ".kr-project-stopping",
                identity.dev() as i64,
                identity.ino() as i64,
            ],
        )
        .expect("the name and its identity are recorded");
    drop(journal);

    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    assert!(
        staged.join("tree").is_dir(),
        "the directory is left where it is"
    );
    let read = replacement
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace reads");
    let detail = read
        .workspace
        .detail
        .0
        .expect("the workspace says why its staging directory is still there");
    assert!(
        detail.contains("a staging directory is still there")
            && detail.contains("no location reaches it"),
        "and why: {detail}"
    );
}

#[test]
fn a_staging_name_with_no_recorded_identity_is_never_removed() {
    // A daemon can die after creating a staging sibling and before recording which object it
    // created. A name alone is not authority to remove anything, so the sweep leaves it and a
    // person decides.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "unproven-sibling");
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
                    "unproven-sibling-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 66)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let unproven = fixture.work().join(".kr-project-unproven");
    std::fs::create_dir_all(unproven.join("tree")).expect("a sibling with no recorded identity");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE workspaces SET staging_name = ?2, staging_device = NULL,
                    staging_file_id = NULL
              WHERE workspace_id = ?1",
            rusqlite::params![
                workspace_id.get().as_bytes().to_vec(),
                ".kr-project-unproven",
            ],
        )
        .expect("the name is recorded and the identity is not");
    drop(journal);
    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    assert!(
        unproven.join("tree").is_dir(),
        "a name with no identity beside it is not this host's to remove"
    );
}

#[cfg(unix)]
#[test]
fn a_link_the_policy_includes_is_named_rather_than_copied() {
    // A symbolic link, a socket and a device are not file content, and this host carries file
    // content. One inside a wholly ignored directory the policy includes is therefore a path the
    // workspace does not hold as the policy asked, and the creation names it.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "linked");
    write(&path, ".gitignore", "generated/\n");
    support::git_raw(&path, ["add", "-A"]);
    support::git_raw(&path, ["commit", "-m", "the base"]);
    std::fs::create_dir_all(path.join("generated")).expect("an ignored directory");
    write(&path.join("generated"), "real.txt", "a real file\n");
    std::os::unix::fs::symlink("real.txt", path.join("generated/link.txt"))
        .expect("a link beside it");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "linked"),
                label: "linked".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 67)),
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
                label: "linked".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "linked-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 68)),
        )
        .expect("the workspace is created");
    assert!(
        created
            .unapplied
            .iter()
            .any(|path| path == "generated/link.txt"),
        "the link is named: {:?}",
        created.unapplied
    );
    assert!(
        !created.preview.counts_complete,
        "and the counts say they do not cover it"
    );
    assert!(
        created
            .preview
            .limitations
            .iter()
            .any(|line| line.contains("symbolic link")),
        "the preview says what it could not carry: {:?}",
        created.preview.limitations
    );
    let tree = fixture.work().join("linked-tree");
    assert!(
        std::fs::read_to_string(tree.join("generated/real.txt")).is_ok(),
        "the file beside it is carried"
    );
    support::assert_absent(
        &tree.join("generated/link.txt"),
        "and nothing is put where the link was",
    );
    // The path is journalled with the rest, so a recovered answer names it too.
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    let recorded: String = journal
        .query_row(
            "SELECT outcome FROM workspace_progress WHERE path = ?1",
            rusqlite::params!["generated/link.txt"],
            |row| row.get(0),
        )
        .expect("the link has a row");
    assert_eq!(recorded, "unapplied");
}

#[test]
fn a_users_file_at_the_name_a_copy_would_use_is_never_removed() {
    // The name a copy writes under follows from the destination's path, which makes it
    // recoverable. It does not make it this host's: a repository can hold a tracked file at that
    // name, and nothing tells it apart from a copy an earlier daemon left. So the copy is never
    // written over it and the path is reported instead.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "collided");
    let occupied = kr_project::workspace::temporary_name(
        &kr_transfer::RelativeName::parse("notes.txt").expect("a name"),
    );
    write(&path, "notes.txt", "the base's notes\n");
    write(&path, &occupied, "the user's own file at that name\n");
    support::git_raw(&path, ["add", "-A"]);
    support::git_raw(&path, ["commit", "-m", "the base"]);
    write(&path, "notes.txt", "the user's notes\n");
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "collided"),
                label: "collided".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 69)),
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
                label: "collided".to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "collided-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 70)),
        )
        .expect("the workspace is created");
    let tree = fixture.work().join("collided-tree");
    assert_eq!(
        std::fs::read_to_string(tree.join(&occupied)).expect("the user's file is there"),
        "the user's own file at that name\n",
        "a file at the name a copy would use is not removed to make room for it"
    );
    assert!(
        created.unapplied.iter().any(|path| path == "notes.txt"),
        "and the path that could not be carried is named: {:?}",
        created.unapplied
    );
    assert_eq!(
        std::fs::read_to_string(tree.join("notes.txt")).expect("the base's version"),
        "the base's notes\n",
        "so the workspace holds the base's version rather than half of either"
    );
}

#[test]
fn a_successful_answer_an_earlier_build_recorded_is_protected_before_a_repeat_returns_it() {
    // An action's row keeps the whole successful reply, so a repeat of the action is answered from
    // it rather than performed again. A build before the rule composed the reasons inside that
    // reply without it, and rewriting the reason *columns* does not reach the reply: it is one
    // value, encoded. So the reply goes through the rule where it is read, and the upgrade rewrites
    // what the file holds.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "replayed");
    let created = fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: "replayed".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: false,
            },
            Some(&action("workspace.create", 71)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let pin = ChangeSetId::new(Uuid::from_bytes([72; 16]));
    fixture
        .service()
        .retain(
            workspace_id,
            &RetainedRow {
                kind: RetainedKind::PinnedChangeSet,
                detail: "version 4 is pinned".to_owned(),
                change_set_id: Some(pin),
            },
        )
        .expect("the pin is recorded");
    let submitted = action("workspace.remove", 73);
    let params = WorkspaceRemoveParams {
        workspace_id,
        retention: RetentionPolicy::KeepEverything,
    };
    let answer = fixture
        .service()
        .workspace_remove(&params, Some(&submitted))
        .expect("the removal is answered");
    assert_eq!(answer.workspace.state, WorkspaceState::RemovalPending);
    let journal_path = kr_project::ProjectService::root_of(&fixture.host().environment())
        .join(kr_project::store::STORE_FILE_NAME);
    let recorded: Vec<u8> = {
        let journal = rusqlite::Connection::open(&journal_path).expect("the journal opens");
        journal
            .query_row(
                "SELECT result FROM actions WHERE action_id = ?1",
                rusqlite::params![submitted.action_id.as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("the recorded answer reads")
    };
    // The answer as a build before the rule would have recorded it: the same reply, with the
    // reasons composed out of what the caller named.
    let mut earlier: kr_protocol::project::WorkspaceRemoveResult =
        kr_cbor::from_canonical_slice(&recorded, &kr_cbor::Limits::DEFAULT)
            .expect("the recorded answer decodes");
    earlier.workspace.detail = Nullable(Some(
        "the tree at /w/access_token=REPLAYSECRET was kept".to_owned(),
    ));
    earlier.retained.push(kr_protocol::project::RetainedItem {
        kind: RetainedKind::DirtyContent,
        detail: "/w/access_token=REPLAYSECRET holds uncommitted work".to_owned(),
        change_set_id: Nullable(None),
    });
    let unprotected = kr_cbor::to_canonical_vec(&earlier).expect("it encodes");
    assert!(
        String::from_utf8_lossy(&unprotected).contains("REPLAYSECRET"),
        "the stand-in for an earlier build's answer holds what this host would not repeat"
    );
    let write_earlier_answer = || {
        let journal = rusqlite::Connection::open(&journal_path).expect("the journal opens");
        journal
            .execute(
                "UPDATE actions SET result = ?1 WHERE action_id = ?2",
                rusqlite::params![unprotected.clone(), submitted.action_id.as_bytes().to_vec()],
            )
            .expect("an earlier build's answer is written");
    };
    write_earlier_answer();

    // The repeat is answered from that row, and what it returns holds none of it.
    let repeated = fixture
        .service()
        .workspace_remove(&params, Some(&submitted))
        .expect("the repeat is answered from the journal");
    let shown = format!("{repeated:?}");
    assert!(
        !shown.contains("REPLAYSECRET"),
        "a recorded answer is put through the rule before it is returned: {shown}"
    );
    // And it is still the answer to that action: the same workspace, the same pin, the same
    // decision about the working files.
    assert_eq!(repeated.workspace.workspace_id, workspace_id);
    assert_eq!(repeated.workspace.state, answer.workspace.state);
    assert_eq!(repeated.working_files_removed, answer.working_files_removed);
    assert!(
        repeated
            .workspace
            .retained
            .iter()
            .any(|item| item.change_set_id == Nullable(Some(pin))),
        "the pin the workspace holds is still named: {:?}",
        repeated.workspace.retained
    );

    // A replacement daemon rewrites the file itself, so the bytes stop holding it too.
    write_earlier_answer();
    {
        let journal = rusqlite::Connection::open(&journal_path).expect("the journal opens");
        journal
            .execute("UPDATE schema_version SET version = 3", [])
            .expect("the version an earlier build recorded");
    }
    let replacement = fixture.reopen();
    let stored: Vec<u8> = {
        let journal = rusqlite::Connection::open(&journal_path).expect("the journal opens");
        journal
            .query_row(
                "SELECT result FROM actions WHERE action_id = ?1",
                rusqlite::params![submitted.action_id.as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("the recorded answer reads")
    };
    assert!(
        !String::from_utf8_lossy(&stored).contains("REPLAYSECRET"),
        "the upgrade rewrites what the file holds"
    );
    let repeated = replacement
        .workspace_remove(&params, Some(&submitted))
        .expect("the repeat is answered again");
    assert_eq!(repeated.workspace.workspace_id, workspace_id);
    assert!(!format!("{repeated:?}").contains("REPLAYSECRET"));
}

#[cfg(unix)]
#[test]
fn a_filesystem_refusal_repeats_no_part_of_what_the_caller_named() {
    // A creation whose destination the host cannot make: the name is the caller's, the failure is
    // the filesystem's, and the message names both. A Rust caller gets that refusal itself rather
    // than the wire's copy of it, so the rule has to reach it there too.
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "refused");
    let parent = fixture.work().join("read-only-parent");
    std::fs::create_dir_all(&parent).expect("a parent directory");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555))
        .expect("a parent nothing may be created in");
    let params = WorkspaceCreateParams {
        project_repository_id: project,
        label: "refused".to_owned(),
        kind: WorkspaceKind::Isolated,
        isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
        policy: InclusionPolicy::base_only(),
        base_revision: Nullable(None),
        base_change_set_id: Nullable(None),
        destination: Nullable(Some(destination(
            fixture.environment_id(),
            &parent,
            "access_token=TREESECRET",
        ))),
        preview_only: false,
    };
    let refusal = fixture
        .service()
        .workspace_create(&actor(), &params, Some(&action("workspace.create", 74)))
        .expect_err("nothing can be created there");
    let said = refusal.to_string();
    assert!(
        !said.contains("TREESECRET"),
        "a refusal repeats no part of the name the caller chose: {said}"
    );
    assert!(
        said.contains("could not be created"),
        "and the host's own words survive, because the name is replaced before the sentence is \
         built: {said}"
    );
    // The journal's copy is the caller's copy: a direct call and a replay say the same thing.
    let recorded = fixture
        .service()
        .workspace_list(&WorkspaceListParams {
            environment_id: fixture.environment_id(),
            project_repository_id: Nullable(Some(project)),
        })
        .expect("the workspaces read")
        .workspaces
        .into_iter()
        .find(|workspace| workspace.label == "refused")
        .expect("the row the creation began");
    let kept = recorded.detail.0.expect("the reason is recorded");
    assert!(
        !kept.contains("TREESECRET"),
        "the journal's copy too: {kept}"
    );
    assert_eq!(kept, said, "and it is the same message");
    // And the repeat of that action is answered with it, under the same code.
    let repeated = fixture
        .service()
        .workspace_create(&actor(), &params, Some(&action("workspace.create", 74)))
        .expect_err("the action is answered from the journal");
    assert_eq!(repeated.to_string(), said);
    assert_eq!(repeated.code(), refusal.code());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
        .expect("the parent is left removable");
}

#[test]
fn a_grant_withdrawn_while_a_workspace_prepares_leaves_no_row_and_no_tree() {
    // KR-REQ-23.44: the workspace row is written before the tree is materialised, so that
    // transaction is where the workspace begins. Opening the repository, reading its head and
    // surveying what the policy would copy all happen before it, and a revocation that completes
    // in there reaches a workspace that is then not created at all.
    let fixture = Fixture::create();
    let project = adopted_with_changes(&fixture, "revoked");
    let claimed = action("workspace.create", 63);
    let withdrawn = || {
        Err(ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the authority this action was admitted under was withdrawn",
        ))
    };
    let params = WorkspaceCreateParams {
        project_repository_id: project,
        label: "revoked".to_owned(),
        kind: WorkspaceKind::Isolated,
        isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
        policy: InclusionPolicy::base_only(),
        base_revision: Nullable(None),
        base_change_set_id: Nullable(None),
        destination: Nullable(Some(destination(
            fixture.environment_id(),
            fixture.work(),
            "revoked-tree",
        ))),
        preview_only: false,
    };
    let refusal = fixture
        .service()
        .workspace_create(
            &actor(),
            &params,
            Performed::from(Some(&claimed)).admitted(&withdrawn),
        )
        .expect_err("a workspace whose grant went is not materialised");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        refusal.to_string().contains("withdrawn"),
        "the refusal is the daemon's own words: {refusal}"
    );
    assert!(
        !fixture.work().join("revoked-tree").exists(),
        "no working tree was materialised"
    );
    assert!(
        fixture
            .service()
            .workspace_list(&WorkspaceListParams {
                environment_id: fixture.environment_id(),
                project_repository_id: Nullable(None),
            })
            .expect("the listing reads")
            .workspaces
            .is_empty(),
        "and no workspace row was written"
    );
    // The action was not claimed either, so the same identifier under a grant that stands is
    // performed rather than answered from a claim nothing settled.
    let created = fixture
        .service()
        .workspace_create(&actor(), &params, Some(&claimed))
        .expect("the same action under a grant that stands is performed");
    assert_eq!(
        created.workspace.0.expect("it exists").state,
        WorkspaceState::Ready
    );
}

#[test]
fn a_grant_withdrawn_before_a_removal_reserves_leaves_the_workspace_and_its_tree_alone() {
    // The reservation, the holder count and the state change are one transaction, and it is the
    // first thing a removal does. The admission is asked inside it, so a removal whose grant went
    // while it queued takes no reservation: the workspace is not moved to `removal_pending`, and a
    // later removal is not refused for a reservation this one never gave up.
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
                policy: InclusionPolicy::base_only(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "kept-tree",
                ))),
                preview_only: false,
            },
            Some(&action("workspace.create", 64)),
        )
        .expect("the workspace is created");
    let workspace_id = created.workspace.0.expect("it exists").workspace_id;
    let expired = || {
        Err(ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the deadline this action was admitted under passed before its effect was committed",
        ))
    };
    let claimed = action("workspace.remove", 65);
    let refusal = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Performed::from(Some(&claimed)).admitted(&expired),
        )
        .expect_err("a removal whose window closed does not reserve the workspace");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(refusal.to_string().contains("deadline"), "{refusal}");
    assert!(
        fixture.work().join("kept-tree").join("README.md").is_file(),
        "the working tree is untouched"
    );
    let read = fixture
        .service()
        .workspace_read(&WorkspaceReadParams { workspace_id })
        .expect("the workspace is still there");
    assert_eq!(
        read.workspace.state,
        WorkspaceState::Ready,
        "and it was never moved to removal_pending"
    );
    // No reservation was taken, so the next removal is not refused for one nothing released.
    let removed = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 66)),
        )
        .expect("a removal under a grant that stands is performed");
    assert!(removed.working_files_removed);
}
