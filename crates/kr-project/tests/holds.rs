//! Holds: which workspaces a capture can hold still, what holding one keeps the host's own
//! writers from doing, and which sessions stand in the way.
//!
//! KR-REQ-14.32 (a quiesced capture rests on a reservation that every writer this host
//! coordinates respects) and KR-REQ-25.20 (the writers consult the quiescence authority).
//!
//! Every test here asks the project service to run Git, which it does not do on Windows; the
//! registry's own cases, which need no repository, are in `src/holds.rs` and run there.

#![cfg(not(windows))]

mod support;

use kr_project::ProjectService;
use kr_project::holds::{Hold, Refusal, SessionPlace};
use kr_project::operation::STAGING_PREFIX;
use kr_project::store::Performed;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ProjectRepositoryId, SessionId, WorkspaceId};
use kr_protocol::project::{
    AdoptionFlow, IsolationMechanism, LocationPurpose, ProjectAdoptParams, ProjectInitParams,
    ProjectOperationCancelParams, RetentionPolicy, WorkspaceCreateParams, WorkspaceKind,
    WorkspaceRemoveParams,
};
use kr_protocol::scalars::{Nullable, Uuid};

use support::{
    Fixture, action, actor, destination, include_everything, ordinary_repository, write,
};

fn adopt(fixture: &Fixture, name: &str, seed: u8) -> ProjectRepositoryId {
    ordinary_repository(fixture.work(), name);
    fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), name),
                label: name.to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", seed)),
        )
        .expect("the checkout is adopted")
        .project
        .project_repository_id
}

fn create(
    fixture: &Fixture,
    project: ProjectRepositoryId,
    kind: WorkspaceKind,
    isolation: Option<IsolationMechanism>,
    parent: &std::path::Path,
    name: &str,
    seed: u8,
) -> Result<WorkspaceId, kr_project::ProjectError> {
    fixture
        .service()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: name.to_owned(),
                kind,
                isolation: Nullable(isolation),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(
                    (kind == WorkspaceKind::Isolated)
                        .then(|| destination(fixture.environment_id(), parent, name)),
                ),
                preview_only: false,
            },
            Some(&action("workspace.create", seed)),
        )
        .map(|created| {
            created
                .workspace
                .0
                .expect("a creation returns the workspace")
                .workspace_id
        })
}

fn worktree(fixture: &Fixture, project: ProjectRepositoryId, name: &str, seed: u8) -> WorkspaceId {
    create(
        fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::GitWorktree),
        fixture.work(),
        name,
        seed,
    )
    .expect("the worktree is made")
}

fn clone(fixture: &Fixture, project: ProjectRepositoryId, name: &str, seed: u8) -> WorkspaceId {
    create(
        fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::IndependentClone),
        fixture.work(),
        name,
        seed,
    )
    .expect("the clone is made")
}

fn shared(fixture: &Fixture, project: ProjectRepositoryId, seed: u8) -> WorkspaceId {
    create(
        fixture,
        project,
        WorkspaceKind::SharedExisting,
        None,
        fixture.work(),
        "shared",
        seed,
    )
    .expect("the checkout is selected")
}

fn remove(
    fixture: &Fixture,
    workspace_id: WorkspaceId,
    seed: u8,
) -> Result<(), kr_project::ProjectError> {
    fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id,
                retention: RetentionPolicy::RemoveRetained,
                through_location_id: Nullable(None),
            },
            Some(&action("workspace.remove", seed)),
        )
        .map(|_| ())
}

/// Asks to hold a workspace the way a capture does, with the identities it opens.
fn hold(service: &ProjectService, workspace_id: WorkspaceId) -> Result<Hold, Refusal> {
    let opened = service
        .open_workspace_repository(workspace_id)
        .expect("the workspace opens");
    let identity = opened.identity();
    service
        .hold_workspace(workspace_id, identity.work_tree, identity.git_dir)
        .expect("the records can be read")
}

fn session(number: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([number; 16]))
}

/// KR-REQ-14.32: a worktree and a clone this host made can be held, and the user's own checkout
/// cannot, nor can a workspace whose recorded tree is not the one the capture opened.
#[test]
fn a_workspace_this_host_made_can_be_held_and_the_users_own_checkout_cannot() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let checkout = shared(&fixture, project, 2);
    let linked = worktree(&fixture, project, "linked", 3);
    let independent = clone(&fixture, project, "independent", 4);
    let service = fixture.service();

    assert!(hold(service, linked).is_ok(), "a linked worktree is held");
    assert!(
        hold(service, independent).is_ok(),
        "and so is an independent clone"
    );
    assert_eq!(
        hold(service, checkout).expect_err("the user's own tools write it"),
        Refusal::SharedCheckout
    );

    // What the capture opened is the tree the records name, or nothing is held: a Git directory
    // that is another repository's is not this workspace's.
    let other = service
        .open_workspace_repository(independent)
        .expect("the clone opens")
        .identity();
    let refused = service
        .hold_workspace(
            linked,
            service
                .open_workspace_repository(linked)
                .expect("the worktree opens")
                .identity()
                .work_tree,
            other.git_dir,
        )
        .expect("the records can be read");
    assert_eq!(
        refused.expect_err("another repository's Git directory"),
        Refusal::TreeMoved
    );
}

/// KR-REQ-14.32: while a hold stands the host's own writers of its repository are turned away
/// with `RESOURCE_UNAVAILABLE`, a worktree's sibling and the selection of the user's checkout
/// among them, and a hold on a clone, which is another repository, turns away none of them. The
/// hold's own workspace is not removed under it. Each succeeds, under a new action, when the hold
/// is gone.
#[test]
fn a_hold_turns_away_the_workspace_operations_of_its_repository_until_it_ends() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let checkout = shared(&fixture, project, 2);
    let linked = worktree(&fixture, project, "linked", 3);
    let sibling = worktree(&fixture, project, "sibling", 4);
    let independent = clone(&fixture, project, "independent", 5);
    let service = fixture.service();

    let held = hold(service, linked).expect("the worktree is held");
    let refused = create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::GitWorktree),
        fixture.work(),
        "another",
        6,
    )
    .expect_err("a worktree writes the held repository's administration");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    for (workspace, seed) in [(linked, 7), (sibling, 8), (checkout, 9)] {
        let refused = remove(&fixture, workspace, seed)
            .expect_err("its repository is held, and a removal prunes it");
        assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    }
    let refused = create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::IndependentClone),
        &fixture.work().join("linked"),
        "inside",
        10,
    )
    .expect_err("a new directory inside the held tree");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(!fixture.work().join("another").exists());
    assert!(fixture.work().join("linked").is_dir());
    assert!(!fixture.work().join("linked/inside").exists());

    drop(held);
    // The clone is another repository, and it is not the one held.
    let clone_held = hold(service, independent).expect("the clone is held");
    create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::GitWorktree),
        fixture.work(),
        "control",
        12,
    )
    .expect("a hold on a clone does not reach the source repository");
    let refused =
        remove(&fixture, independent, 13).expect_err("a clone is not removed under its own hold");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    drop(clone_held);

    // Released, the same operations go ahead.
    create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::GitWorktree),
        fixture.work(),
        "another",
        14,
    )
    .expect("the worktree is made once nothing holds the repository");
    remove(&fixture, linked, 15).expect("and removed");
    remove(&fixture, independent, 16).expect("and so is the clone");
}

/// KR-REQ-14.32: a project service turns a new repository away from the directory of a tree that
/// is held, and makes it elsewhere.
#[test]
fn a_hold_turns_away_a_new_repository_made_inside_its_tree() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    let service = fixture.service();
    let init = |parent: &std::path::Path, name: &str, seed: u8| {
        service.project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), parent, name),
                label: name.to_owned(),
                initial_branch: Nullable(Some("main".to_owned())),
            },
            Some(&action("project.init", seed)),
        )
    };
    let held = hold(service, linked).expect("the worktree is held");
    let refused = init(&fixture.work().join("linked"), "inside", 3)
        .expect_err("a directory in a held tree is written");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    init(fixture.work(), "elsewhere", 4).expect("a directory outside every tree is not");
    drop(held);
    init(&fixture.work().join("linked"), "inside", 5).expect("and inside, once nothing holds it");
}

/// An operation that has ended and left a staging directory in `parent` that its row proves it
/// made, and the request that cleans it up through a location over `parent`.
fn leave_staging_in(
    fixture: &Fixture,
    parent: &std::path::Path,
    seed: u8,
) -> (ProjectOperationCancelParams, std::path::PathBuf, String) {
    use std::os::unix::fs::MetadataExt as _;

    let service = fixture.service();
    let made = service
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), parent, "made"),
                label: "made".to_owned(),
                initial_branch: Nullable(Some("main".to_owned())),
            },
            Some(&action("project.init", seed)),
        )
        .expect("a repository is made in the directory");
    let name = format!("{STAGING_PREFIX}left");
    let leftover = parent.join(&name);
    support::staging_directory(&leftover);
    let metadata = std::fs::metadata(&leftover).expect("the staging directory has an identity");
    let journal = rusqlite::Connection::open(
        ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET staging_name = ?2, staging_device = ?3, staging_file_id = ?4
              WHERE action_id = ?1",
            rusqlite::params![
                made.operation.action_id.get().as_bytes().to_vec(),
                name,
                metadata.dev() as i64,
                metadata.ino() as i64,
            ],
        )
        .expect("the row names the staging directory it left");
    drop(journal);
    let owner = support::TestOwner::default();
    let location = support::authorise_location(
        fixture.service(),
        &owner,
        parent,
        LocationPurpose::Destination,
        seed + 1,
    );
    (
        ProjectOperationCancelParams {
            operation_action_id: made.operation.action_id,
            through_location_id: Nullable(Some(location)),
        },
        leftover,
        name,
    )
}

/// KR-REQ-14.32: the cleanup of a staging directory that an ended operation left inside a held
/// tree is turned away with `RESOURCE_UNAVAILABLE`, claims nothing and removes nothing, and the
/// same request removes the directory once the hold has ended.
#[test]
fn a_hold_turns_away_the_cleanup_of_a_staging_directory_inside_its_tree() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    let service = fixture.service();
    let (reconcile, leftover, name) = leave_staging_in(&fixture, &fixture.work().join("linked"), 3);

    let held = hold(service, linked).expect("the worktree is held");
    let refused = service
        .project_operation_cancel(&actor(), &reconcile, Performed::default())
        .expect_err("the cleanup writes beside the entries of a held tree");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(leftover.join("tree").is_dir(), "nothing was removed");
    drop(held);

    let reconciled = service
        .project_operation_cancel(&actor(), &reconcile, Performed::default())
        .expect("the same request goes ahead once nothing holds the tree");
    assert!(
        reconciled
            .operation
            .removed_staging_paths
            .iter()
            .any(|path| path.ends_with(&name)),
        "{:?}",
        reconciled.operation.removed_staging_paths
    );
    support::assert_absent(&leftover, "the staging directory the cleanup took away");
}

/// KR-REQ-14.32: the cleanup removes a staging directory with everything in it, so a tree a
/// capture holds inside the directory turns it away even though the directory is beside no held
/// tree, and the directory is removed once the hold has ended.
#[test]
fn a_hold_on_a_tree_inside_a_staging_directory_turns_away_its_cleanup() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let service = fixture.service();
    let (reconcile, leftover, _) = leave_staging_in(&fixture, fixture.work(), 3);
    let inside = create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::IndependentClone),
        &leftover,
        "held",
        5,
    )
    .expect("a clone inside the staging directory");

    let held = hold(service, inside).expect("the clone is held");
    let refused = service
        .project_operation_cancel(&actor(), &reconcile, Performed::default())
        .expect_err("the cleanup would remove the held tree with the directory");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(leftover.join("held").is_dir(), "nothing was removed");
    drop(held);

    service
        .project_operation_cancel(&actor(), &reconcile, Performed::default())
        .expect("the same request goes ahead once nothing holds the tree");
    support::assert_absent(&leftover, "the staging directory the cleanup took away");
}

/// KR-REQ-14.32: the cleanup removes a staging directory with everything in it, so it is turned
/// away when the project's own checkout, which holds the Git directory a held worktree depends on,
/// is inside the directory, though the worktree itself is elsewhere; the directory is removed once
/// the hold has ended.
#[test]
fn a_hold_turns_away_the_cleanup_of_a_directory_that_holds_the_repositorys_checkout() {
    let fixture = Fixture::create();
    let service = fixture.service();
    let (reconcile, leftover, _) = leave_staging_in(&fixture, fixture.work(), 3);
    ordinary_repository(&leftover, "source");
    let project = service
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), &leftover, "source"),
                label: "source".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 5)),
        )
        .expect("a checkout inside the staging directory is adopted")
        .project
        .project_repository_id;
    let outside = worktree(&fixture, project, "outside", 6);

    let held = hold(service, outside).expect("the worktree outside the directory is held");
    let refused = service
        .project_operation_cancel(&actor(), &reconcile, Performed::default())
        .expect_err("the cleanup would remove the Git directory the held worktree depends on");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(leftover.join("source/.git").is_dir(), "nothing was removed");
    drop(held);

    service
        .project_operation_cancel(&actor(), &reconcile, Performed::default())
        .expect("the same request goes ahead once nothing holds the repository");
    support::assert_absent(&leftover, "the staging directory the cleanup took away");
}

/// KR-REQ-14.32: a live session blocks a hold on a tree of its repository wherever in the
/// repository it started, including in the user's own checkout when that is only a project and
/// no workspace has been selected on it, and a session that started where no tree is recorded
/// blocks nothing. The session is found by the directory it started in: a subdirectory, a
/// name that does not exist yet, a file, a name under a file, and a link all stand for the
/// directory they are in.
#[test]
fn a_session_in_any_tree_of_the_repository_blocks_a_hold_on_another_tree() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    let service = fixture.service();
    let source = fixture.work().join("source");
    let elsewhere = fixture.work().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("a directory outside every tree");
    std::fs::write(elsewhere.join("note.txt"), b"a file\n").expect("a file outside every tree");
    std::os::unix::fs::symlink(&source, fixture.work().join("alias")).expect("a link");

    let starts = |directory: Option<&str>| service.session_place(directory);
    let named = |path: std::path::PathBuf| path.display().to_string();

    for (what, place) in [
        ("the checkout itself", starts(Some(&named(source.clone())))),
        ("a subdirectory", starts(Some(&named(source.join("src"))))),
        (
            "a name that does not exist yet",
            starts(Some(&named(source.join("not/yet/made")))),
        ),
        ("a file", starts(Some(&named(source.join("src/lib.rs"))))),
        (
            "a link to the checkout",
            starts(Some(&named(fixture.work().join("alias/src")))),
        ),
        ("a path that is not absolute", starts(Some("src"))),
    ] {
        let registration = service
            .holds()
            .begin_session(session(1), place)
            .expect("nothing is held");
        assert_eq!(
            hold(service, linked).expect_err(what),
            Refusal::SessionsBound(1),
            "{what}"
        );
        drop(registration);
        assert!(hold(service, linked).is_ok(), "{what}: the session ended");
    }

    for (what, place) in [
        (
            "a name under a file outside every tree",
            starts(Some(&named(elsewhere.join("note.txt/inside")))),
        ),
        (
            "a directory outside every tree",
            starts(Some(&named(elsewhere))),
        ),
        ("the worker's own default, the root", starts(None)),
    ] {
        let _registration = service
            .holds()
            .begin_session(session(2), place)
            .expect("nothing is held");
        assert!(hold(service, linked).is_ok(), "{what} blocks nothing");
    }
}

/// KR-REQ-14.32: a session counts against a tree that became known after the session began.
/// A terminal opened in a repository the host does not yet know is in the repository when the
/// host adopts it and makes a worktree of it.
#[test]
fn a_session_that_began_before_its_tree_was_known_still_blocks_the_hold() {
    let fixture = Fixture::create();
    ordinary_repository(fixture.work(), "later");
    let service = fixture.service();
    let place = service.session_place(Some(&fixture.work().join("later").display().to_string()));
    assert!(matches!(place, SessionPlace::Chain(_)));
    let registration = service
        .holds()
        .begin_session(session(1), place)
        .expect("nothing is held");

    let project = adopt_existing(&fixture, "later", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    assert_eq!(
        hold(service, linked).expect_err("the session started in the adopted checkout"),
        Refusal::SessionsBound(1)
    );
    drop(registration);
    assert!(hold(service, linked).is_ok());
}

/// Takes the right to search a directory away until it is dropped, and says whether that kept
/// this account out: an account that ignores directory modes (root) is not kept out.
struct Unsearchable {
    directory: std::path::PathBuf,
}

impl Unsearchable {
    /// Makes `directory` readable and writable but not searchable, and returns it with whether
    /// `through` can no longer be reached.
    fn make(directory: &std::path::Path, through: &std::path::Path) -> (Self, bool) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o600))
            .expect("the directory's mode is changed");
        let held = Self {
            directory: directory.to_owned(),
        };
        let kept_out = std::fs::metadata(through).is_err();
        (held, kept_out)
    }
}

impl Drop for Unsearchable {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;

        let _ = std::fs::set_permissions(&self.directory, std::fs::Permissions::from_mode(0o700));
    }
}

/// KR-REQ-14.32: a start directory that cannot be looked at is not a missing name. The host may
/// not search the directory above it, so it cannot say where a session started there: the
/// session counts against every hold and a writer there writes anywhere, and neither is placed
/// in the directory that does open, which sits outside every tree this host records. The same
/// path stands for the directory it is in once that directory can be searched.
#[test]
fn a_directory_that_cannot_be_looked_at_is_placed_nowhere_and_not_at_the_one_above_it() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    let service = fixture.service();
    let locked = fixture.work().join("locked");
    let inside = locked.join("inside");
    std::fs::create_dir_all(&inside).expect("a directory outside every tree");
    let named = |path: &std::path::Path| path.display().to_string();

    let control = service.session_place(Some(&named(&inside)));
    assert!(
        matches!(control, SessionPlace::Chain(_)),
        "a directory that can be searched is placed"
    );
    assert!(!service.footprint_inside(&inside).anywhere);

    let (_held, kept_out) = Unsearchable::make(&locked, &inside);
    if !kept_out {
        eprintln!("skipped: this account is not kept out of a directory by its mode");
        return;
    }
    let place = service.session_place(Some(&named(&inside)));
    assert_eq!(place, SessionPlace::Unknown, "it is not placed above");
    assert!(
        service.footprint_inside(&inside).anywhere,
        "and a writer there writes anywhere"
    );
    let _registration = service
        .holds()
        .begin_session(session(1), place)
        .expect("nothing is held");
    assert_eq!(
        hold(service, linked).expect_err("a session that cannot be placed is in the way"),
        Refusal::SessionsBound(1)
    );
}

/// KR-REQ-14.32: a hold is not granted while a tree this host records for the repository cannot be
/// looked at. The directories above every such tree are what a removal of the directory holding
/// it meets, and those of the nearest directory that does open are not its own.
#[test]
fn a_recorded_tree_that_cannot_be_looked_at_keeps_a_hold_from_being_granted() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    let guarded = fixture.work().join("guarded");
    std::fs::create_dir(&guarded).expect("a directory to hold a second tree");
    create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::GitWorktree),
        &guarded,
        "second",
        3,
    )
    .expect("the second worktree is made");
    let service = fixture.service();
    assert!(
        hold(service, linked).is_ok(),
        "the repository is held while every tree it has can be looked at"
    );

    let (_held, kept_out) = Unsearchable::make(&guarded, &guarded.join("second"));
    if !kept_out {
        eprintln!("skipped: this account is not kept out of a directory by its mode");
        return;
    }
    assert_eq!(
        hold(service, linked).expect_err("a tree of the repository cannot be looked at"),
        Refusal::TreeUnreadable
    );
}

fn adopt_existing(fixture: &Fixture, name: &str, seed: u8) -> ProjectRepositoryId {
    fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), name),
                label: name.to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", seed)),
        )
        .expect("the checkout is adopted")
        .project
        .project_repository_id
}

/// KR-REQ-14.32: a session unknown to the registry blocks every hold, and a removal that takes a
/// tree takes the clone recorded inside it, so the clone's hold turns the removal away.
#[test]
fn a_removal_is_turned_away_by_a_hold_on_a_clone_inside_the_tree_it_removes() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let outer = worktree(&fixture, project, "outer", 2);
    let inner = create(
        &fixture,
        project,
        WorkspaceKind::Isolated,
        Some(IsolationMechanism::IndependentClone),
        &fixture.work().join("outer"),
        "inner",
        3,
    )
    .expect("a clone inside the worktree's tree");
    write(
        &fixture.work().join("outer"),
        "touched.txt",
        "after the clone\n",
    );
    let service = fixture.service();

    let held = hold(service, inner).expect("the clone is held");
    let refused = remove(&fixture, outer, 4)
        .expect_err("removing the outer tree removes the held clone with it");
    assert_eq!(refused.code(), ErrorCode::ResourceUnavailable);
    assert!(fixture.work().join("outer/inner").is_dir());
    drop(held);
    remove(&fixture, outer, 5).expect("nothing holds the clone now");
    assert!(!fixture.work().join("outer").exists());
}
