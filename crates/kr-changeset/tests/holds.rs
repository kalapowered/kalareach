//! The project service's own quiescence authority: what a capture under it is, what it keeps the
//! host's writers from doing while it reads, and what its comparison afterwards catches.
//!
//! KR-REQ-14.32 (the consistency class is recorded; a concurrent change is retried or rejected;
//! a quiesced capture rests on a reservation that held) and KR-REQ-25.20 (the writers consult
//! the quiescence authority).
//!
//! Every test here asks the project service to run Git, which it does not do on Windows.

#![cfg(not(windows))]

mod support;

use std::sync::{Arc, Mutex};

use kr_changeset::apply::{self, ApplyOrder};
use kr_changeset::capture::{
    ProjectQuiescence, QuiescenceAuthority, QuiescenceLease, QuiescenceSubject,
};
use kr_protocol::changeset::{DestinationClass, FileGrant, SourceConsistency, VersionRef};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ProjectRepositoryId, SessionId, WorkspaceId};
use kr_protocol::project::{IsolationMechanism, WorkspaceCreateParams, WorkspaceKind};
use kr_protocol::scalars::{Nullable, Uuid};

use support::{
    Fixture, action, actor, destination, expectations, include_everything, ordinary_repository,
    read_bytes, write,
};

/// An isolated worktree of a project, in the fixture's working directory.
fn worktree(fixture: &Fixture, project: ProjectRepositoryId, name: &str) -> WorkspaceId {
    fixture
        .project()
        .workspace_create(
            &actor(),
            &WorkspaceCreateParams {
                project_repository_id: project,
                label: name.to_owned(),
                kind: WorkspaceKind::Isolated,
                isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                policy: include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(Some(destination(
                    fixture.environment_id(),
                    fixture.work(),
                    name,
                ))),
                preview_only: false,
            },
            Some(&action(&format!("workspace.create:{name}"))),
        )
        .expect("the worktree is made")
        .workspace
        .0
        .expect("a creation returns one")
        .workspace_id
}

fn session(number: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([number; 16]))
}

/// The authority a host builds from its project service, with something a test does the moment a
/// grant is made: the interval a capture then reads across.
struct Probing<'a> {
    inner: ProjectQuiescence<'a>,
    probe: Box<dyn Fn() + Send + Sync + 'a>,
}

impl std::fmt::Debug for Probing<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Probing")
    }
}

impl QuiescenceAuthority for Probing<'_> {
    fn reserve(
        &self,
        subject: QuiescenceSubject,
    ) -> kr_changeset::Result<Option<Box<dyn QuiescenceLease + '_>>> {
        let lease = self.inner.reserve(subject)?;
        if lease.is_some() {
            (self.probe)();
        }
        Ok(lease)
    }
}

/// A repository with a checkout the user owns, a workspace selected on it, a worktree of it the
/// host made, and a version to apply.
struct Scene {
    fixture: Fixture,
    project: ProjectRepositoryId,
    shared: WorkspaceId,
    isolated: WorkspaceId,
    version: VersionRef,
    checkout: std::path::PathBuf,
    tree: std::path::PathBuf,
}

fn scene() -> Scene {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source-tree");
    write(&source, "README.md", "the change\n");
    write(&source, "src/lib.rs", "pub fn answer() -> u32 { 44 }\n");
    let source_workspace = fixture.workspace("source-tree");
    let record = fixture.capture(source_workspace, &include_everything());

    let checkout = ordinary_repository(fixture.work(), "checkout");
    let project = fixture.adopt("checkout");
    let shared = fixture.shared_workspace(project, "checkout");
    let isolated = worktree(&fixture, project, "tree");
    Scene {
        project,
        shared,
        isolated,
        version: VersionRef {
            change_set_id: record.change_set_id,
            version: record.version,
        },
        tree: fixture.work().join("tree"),
        checkout,
        fixture,
    }
}

fn order<'a>(
    scene: &Scene,
    workspace: WorkspaceId,
    affected: &'a [kr_protocol::changeset::AffectedVersion],
    limitations: &'a [String],
) -> ApplyOrder<'a> {
    support::apply_order(
        scene.version,
        DestinationClass::SharedExisting,
        workspace,
        affected,
        limitations,
    )
}

/// KR-REQ-14.32 and KR-REQ-25.20: a direct apply, into the user's checkout or into the held
/// worktree itself, is turned away while a capture holds the repository, writes nothing and
/// claims nothing, so the same action asked again after the hold is applied once.
#[test]
fn a_direct_apply_is_turned_away_while_a_capture_holds_the_repository_and_claims_nothing() {
    let scene = scene();
    let service = scene.fixture.service();
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let into_checkout = expectations(&scene.checkout, &["README.md", "src/lib.rs"]);
    let into_tree = expectations(&scene.tree, &["README.md", "src/lib.rs"]);
    let checkout_order = order(&scene, scene.shared, &into_checkout, &limitations);
    let tree_order = order(&scene, scene.isolated, &into_tree, &limitations);

    let project = scene.fixture.project();
    let opened = project
        .open_workspace_repository(scene.isolated)
        .expect("the worktree opens")
        .identity();
    let hold = project
        .hold_workspace(scene.isolated, opened.work_tree, opened.git_dir)
        .expect("the records read")
        .expect("the worktree is held");
    for (what, refused) in [
        ("into the user's checkout", &checkout_order),
        ("into the held worktree", &tree_order),
    ] {
        let error = apply::apply(service, refused).expect_err(what);
        assert_eq!(error.code(), ErrorCode::ResourceUnavailable, "{what}");
    }
    assert_eq!(
        read_bytes(&scene.checkout, "README.md"),
        b"a repository\n",
        "nothing was written"
    );
    assert_eq!(read_bytes(&scene.tree, "README.md"), b"a repository\n");

    drop(hold);
    let applied = apply::apply(service, &checkout_order)
        .expect("the same action is applied once nothing holds the repository");
    assert_eq!(
        applied.outcome,
        Nullable(Some(kr_protocol::changeset::ApplyOutcomeClass::Applied)),
        "{}",
        applied.detail
    );
    assert_eq!(read_bytes(&scene.checkout, "README.md"), b"the change\n");
}

/// KR-REQ-14.32: a hold is turned away by a direct apply that is already writing, and a
/// capture that required the quiesced class is then refused, not served a weaker one.
#[test]
fn a_hold_is_turned_away_while_a_direct_apply_is_writing() {
    let scene = scene();
    let service = scene.fixture.service();
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let affected = expectations(&scene.checkout, &["README.md", "src/lib.rs"]);
    let writing = order(&scene, scene.shared, &affected, &limitations);

    let project = Arc::clone(scene.fixture.project());
    let opened = project
        .open_workspace_repository(scene.isolated)
        .expect("the worktree opens")
        .identity();
    let isolated = scene.isolated;
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let record = Arc::clone(&seen);
    service.inject(Some(apply::Fault {
        after_paths: 1,
        act: Some(Arc::new(move || {
            let outcome = project
                .hold_workspace(isolated, opened.work_tree, opened.git_dir)
                .expect("the records read");
            *record.lock().expect("the lock") = Some(match outcome {
                Ok(_) => "granted".to_owned(),
                Err(refusal) => refusal.to_string(),
            });
        })),
        before_rename: None,
        after_claim: None,
        refuse_staging_record: false,
        stop: false,
        detail: String::new(),
    }));
    let applied = apply::apply(service, &writing).expect("the apply runs");
    assert_eq!(
        applied.outcome,
        Nullable(Some(kr_protocol::changeset::ApplyOutcomeClass::Applied))
    );
    let seen = seen.lock().expect("the lock").clone();
    assert!(
        seen.as_deref()
            .is_some_and(|said| said.contains("is at work in its repository")),
        "a hold asked for while an apply was writing was refused for that: {seen:?}"
    );
}

/// KR-REQ-14.32 and KR-REQ-25.20: a capture under the project service's authority, with the
/// host's writers asked to write at the moment the grant is made, is a quiesced capture; every
/// one of them was turned away, and the version says what was kept off and what was not. The
/// writers go ahead afterwards.
#[test]
fn a_capture_under_the_projects_authority_is_quiesced_and_the_hosts_writers_are_turned_away() {
    let scene = scene();
    let project = Arc::clone(scene.fixture.project());
    let service = scene.fixture.service();
    let limitations = apply::limitations(DestinationClass::SharedExisting);
    let affected = expectations(&scene.checkout, &["README.md", "src/lib.rs"]);
    let refused: Arc<Mutex<Vec<(&'static str, ErrorCode)>>> = Arc::default();

    let authority = Probing {
        inner: ProjectQuiescence::new(&project),
        probe: Box::new({
            let refused = Arc::clone(&refused);
            let project = Arc::clone(&project);
            let apply_affected = affected.clone();
            let apply_limitations = limitations.clone();
            let version = scene.version;
            let shared = scene.shared;
            let service_for_apply = scene.fixture.service();
            let work = scene.fixture.work().to_path_buf();
            let environment_id = scene.fixture.environment_id();
            let source_project = scene.project;
            move || {
                let mut seen = refused.lock().expect("the lock");
                let apply_order = support::apply_order(
                    version,
                    DestinationClass::SharedExisting,
                    shared,
                    &apply_affected,
                    &apply_limitations,
                );
                if let Err(error) = apply::apply(service_for_apply, &apply_order) {
                    seen.push(("diff.apply", error.code()));
                }
                if let Err(error) = project.workspace_create(
                    &actor(),
                    &WorkspaceCreateParams {
                        project_repository_id: source_project,
                        label: "probe".to_owned(),
                        kind: WorkspaceKind::Isolated,
                        isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
                        policy: include_everything(),
                        base_revision: Nullable(None),
                        base_change_set_id: Nullable(None),
                        destination: Nullable(Some(destination(environment_id, &work, "probe"))),
                        preview_only: false,
                    },
                    Some(&action("workspace.create:probe")),
                ) {
                    seen.push(("workspace.create", error.code()));
                }
                if let Err(error) = project
                    .holds()
                    .begin_session(session(7), kr_project::holds::SessionPlace::Unknown)
                {
                    seen.push(("a session", error.code()));
                }
                if let Err(error) = project
                    .writer_in_directory("an agent-tool installation", &work.join("checkout"))
                {
                    seen.push(("an installation", error.code()));
                }
            }
        }),
    };
    let record = scene
        .fixture
        .capture_with_authority(
            scene.isolated,
            &include_everything(),
            &FileGrant::default(),
            None,
            Some(SourceConsistency::QuiescedCapture),
            Some(&authority),
        )
        .expect("the capture runs");

    assert_eq!(record.consistency, SourceConsistency::QuiescedCapture);
    assert!(record.policy.quiescence_held);
    let refused = refused.lock().expect("the lock").clone();
    assert_eq!(
        refused,
        vec![
            ("diff.apply", ErrorCode::ResourceUnavailable),
            ("workspace.create", ErrorCode::ResourceUnavailable),
            ("a session", ErrorCode::ResourceUnavailable),
            ("an installation", ErrorCode::ResourceUnavailable),
        ],
        "every writer asked while the grant stood was turned away"
    );
    assert!(
        record
            .consistency_detail
            .contains("no diff apply, workspace creation or removal")
            && record
                .consistency_detail
                .contains("does not exclude an editor or a program"),
        "the version says what was kept off and what was not: {}",
        record.consistency_detail
    );

    // The grant is back, and the writers go ahead.
    let applied = apply::apply(
        service,
        &order(&scene, scene.shared, &affected, &limitations),
    )
    .expect("the apply runs");
    assert_eq!(
        applied.outcome,
        Nullable(Some(kr_protocol::changeset::ApplyOutcomeClass::Applied)),
        "{}",
        applied.detail
    );
}

/// KR-REQ-14.32: a file that was already modified, written again after this host read it while it
/// read another, contradicts the reservation: the class is the weaker one, and a request that
/// required the quiesced class is refused. So does a path that was gone when it was read and is
/// back by the end.
#[test]
fn a_file_written_after_its_own_read_makes_the_capture_per_file_and_a_required_class_is_refused() {
    for required in [None, Some(SourceConsistency::QuiescedCapture)] {
        let scene = scene();
        write(&scene.tree, "README.md", "modified in the worktree\n");
        write(&scene.tree, "src/lib.rs", "pub fn answer() -> u32 { 43 }\n");
        write(&scene.tree, "zzz.txt", "present at the status\n");
        write(&scene.tree, "zzzz.txt", "the last file read\n");
        let project = Arc::clone(scene.fixture.project());
        let authority = ProjectQuiescence::new(&project);

        let tree = scene.tree.clone();
        kr_changeset::capture::interpose_working_tree_reads(Some(Arc::new(
            move |read: &str, attempt: u32| {
                if attempt > 0 {
                    return;
                }
                match read {
                    // README.md was read first. Written again with another length while the next
                    // file is read, and one later path is taken away before its turn.
                    "src/lib.rs" => {
                        std::fs::write(tree.join("README.md"), "modified again, and longer\n")
                            .expect("the fixture writes");
                        std::fs::remove_file(tree.join("zzz.txt")).expect("the fixture removes");
                    }
                    // And the path that was gone when it was read is back before the end.
                    "zzzz.txt" => {
                        std::fs::write(tree.join("zzz.txt"), "back again\n")
                            .expect("the fixture writes");
                    }
                    _ => {}
                }
            },
        )));
        let outcome = scene.fixture.capture_with_authority(
            scene.isolated,
            &include_everything(),
            &FileGrant::default(),
            None,
            required,
            Some(&authority),
        );
        kr_changeset::capture::interpose_working_tree_reads(None);

        match required {
            None => {
                let record = outcome.expect("the capture runs");
                assert_eq!(
                    record.consistency,
                    SourceConsistency::PerFileCapture,
                    "{}",
                    record.consistency_detail
                );
                assert!(!record.policy.quiescence_held);
                assert!(
                    record.consistency_detail.contains(
                        "although a reservation was supposed to be holding the tree still"
                    ),
                    "{}",
                    record.consistency_detail
                );
            }
            Some(_) => {
                let error = outcome.expect_err("a required class is refused, not served weaker");
                assert_eq!(error.code(), ErrorCode::InvalidArgument);
                assert!(
                    error.to_string().contains("requires a quiesced_capture"),
                    "{error}"
                );
            }
        }
    }
}

/// KR-REQ-14.32: the user's own checkout, a workspace a live session started in a tree of, and a
/// workspace a writer is at work in are each not held, and say why; the capture is the per-file
/// class, or is refused when it required the quiesced one.
#[test]
fn a_shared_checkout_a_live_session_and_a_writer_at_work_each_leave_the_capture_per_file() {
    use kr_project::holds::Refusal;
    let scene = scene();
    let project = Arc::clone(scene.fixture.project());
    let ask = |workspace: WorkspaceId, required: Option<SourceConsistency>| {
        let authority = ProjectQuiescence::new(&project);
        let outcome = scene.fixture.capture_with_authority(
            workspace,
            &include_everything(),
            &FileGrant::default(),
            None,
            required,
            Some(&authority),
        );
        (outcome, authority.refusal())
    };

    let (outcome, refusal) = ask(scene.shared, None);
    let record = outcome.expect("the capture runs");
    assert_eq!(record.consistency, SourceConsistency::PerFileCapture);
    assert!(record.consistency_detail.contains("could not be reserved"));
    assert_eq!(refusal, Some(Refusal::SharedCheckout));

    // A session started in the user's checkout, which is a tree of the worktree's repository.
    let place = project.session_place(Some(&scene.checkout.display().to_string()));
    let registration = project
        .holds()
        .begin_session(session(1), place)
        .expect("nothing is held");
    let (outcome, refusal) = ask(scene.isolated, Some(SourceConsistency::QuiescedCapture));
    outcome.expect_err("the quiesced class is required and a session is alive");
    assert_eq!(refusal, Some(Refusal::SessionsBound(1)));
    drop(registration);
    let (outcome, refusal) = ask(scene.isolated, Some(SourceConsistency::QuiescedCapture));
    assert_eq!(
        outcome.expect("nothing is in the way now").consistency,
        SourceConsistency::QuiescedCapture
    );
    assert_eq!(refusal, None);

    // A writer of the repository that is at work.
    let writer = project
        .writer_in_directory("a test writer", &scene.tree)
        .expect("nothing is held");
    let (outcome, refusal) = ask(scene.isolated, None);
    assert_eq!(
        outcome.expect("the capture runs").consistency,
        SourceConsistency::PerFileCapture
    );
    assert_eq!(refusal, Some(Refusal::WriterAtWork("a test writer")));
    drop(writer);
}
