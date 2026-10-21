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
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ProjectRepositoryId, SessionId, WorkspaceId};
use kr_protocol::project::{
    AdoptionFlow, IsolationMechanism, ProjectAdoptParams, ProjectInitParams, RetentionPolicy,
    WorkspaceCreateParams, WorkspaceKind, WorkspaceRemoveParams,
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

/// KR-REQ-14.32: a live session blocks a hold on a tree of its repository wherever in the
/// repository it started, including in the user's own checkout when that is only a project and
/// no workspace has been selected on it, and a session that started where no tree is recorded
/// blocks nothing. The session is found by the directory it started in: a subdirectory, a
/// name that does not exist yet, a file, and a link all stand for the tree they are in.
#[test]
fn a_session_in_any_tree_of_the_repository_blocks_a_hold_on_another_tree() {
    let fixture = Fixture::create();
    let project = adopt(&fixture, "source", 1);
    let linked = worktree(&fixture, project, "linked", 2);
    let service = fixture.service();
    let source = fixture.work().join("source");
    let elsewhere = fixture.work().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("a directory outside every tree");
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
