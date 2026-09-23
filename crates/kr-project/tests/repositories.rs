//! Project repositories: identity, authorised destinations, staged publication, the credential
//! rule and the reconciliation of an interrupted publish.
//!
//! KR-REQ-06.09, 14.06, 14.17, 14.18, 14.19, 23.42.
//!
//! Every test here asks the project service to run Git. On Windows it runs none: an application
//! container cannot keep a repository from being executed from and cannot bound which ports a
//! remote operation reaches, so the service refuses there rather than claiming a boundary it does
//! not have. These tests therefore describe the platforms where Git runs; the refusal itself is in
//! `tests/boundary.rs`.

#![cfg(not(windows))]
#![cfg(feature = "git-fixtures")]

mod support;

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kr_project::git::{Cancellation, GitRequest};
use kr_project::identity::OpenedRepository;
use kr_project::operation::STAGING_PREFIX;
use kr_project::store::Performed;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::project::{
    AdoptionFlow, DestinationState, OperationState, ProjectAdoptParams, ProjectCloneParams,
    ProjectInitParams, ProjectListParams, ProjectOperationCancelParams, ProjectOrigin,
    ProjectReadParams, ProjectState, RemoteSpecification, RemoteTransport,
};
use kr_protocol::scalars::Nullable;

use support::{
    Fixture, action, actor, destination, installed_broker, named_broker, ordinary_repository,
};

#[test]
fn an_initialised_repository_is_published_from_a_private_sibling_and_nothing_is_left_behind() {
    let fixture = Fixture::create();
    let result = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "fresh"),
                label: "fresh".to_owned(),
                initial_branch: Nullable(Some("main".to_owned())),
            },
            Some(&action("project.init", 1)),
        )
        .expect("an absent destination is initialised");
    assert_eq!(result.project.origin, ProjectOrigin::Initialised);
    assert_eq!(result.project.state, ProjectState::Ready);
    assert_eq!(result.operation.state, OperationState::Completed);
    assert_eq!(result.operation.destination_state, DestinationState::Absent);
    // The content was staged in a private sibling and the publication removed it.
    assert_eq!(
        result.operation.retained_staging_paths,
        Vec::<String>::new()
    );
    assert_eq!(result.operation.removed_staging_paths.len(), 1);
    let staged = &result.operation.removed_staging_paths[0];
    assert!(
        Path::new(staged)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with(STAGING_PREFIX)),
        "the staging path is a private sibling of the destination: {staged}"
    );
    support::assert_absent(Path::new(staged), "the sibling is gone");
    // The published repository is a repository, and the parent holds nothing else.
    assert!(fixture.work().join("fresh/.git").is_dir());
    assert_eq!(support::names_in(fixture.work()), vec!["fresh".to_owned()]);
    // And the record's identity is the object rather than the path.
    let read = fixture
        .service()
        .project_read(&ProjectReadParams {
            project_repository_id: result.project.project_repository_id,
        })
        .expect("the record reads back");
    assert_eq!(
        read.project.filesystem_identity,
        result.project.filesystem_identity
    );
    assert!(read.workspaces.is_empty());
    assert_eq!(
        read.operation.0.map(|operation| operation.state),
        Some(OperationState::Completed)
    );
    // A scoped list names it once.
    let listed = fixture
        .service()
        .project_list(&ProjectListParams {
            environment_id: fixture.environment_id(),
        })
        .expect("the environment lists its repositories");
    assert_eq!(listed.projects.len(), 1);
    assert_eq!(
        listed.projects[0].project_repository_id,
        result.project.project_repository_id
    );
}

#[test]
fn an_existing_destination_is_refused_unless_the_adoption_flow_is_chosen() {
    let fixture = Fixture::create();
    let existing = ordinary_repository(fixture.work(), "existing");
    // An initialisation into it is refused, and the refusal names the flow that would work.
    let refusal = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "existing"),
                label: "existing".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&action("project.init", 2)),
        )
        .expect_err("an existing destination is refused");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(
        refusal.to_string().contains("existing-checkout flow"),
        "the refusal names the flow: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("nothing is ever merged into an existing destination"),
        "the refusal says nothing is merged into it: {refusal}"
    );
    // So is a clone, and nothing was written into the destination by either.
    let before = std::fs::read_to_string(existing.join("README.md")).expect("the file is there");
    let refusal = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "existing"),
                label: "existing".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: existing.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&action("project.clone", 3)),
        )
        .expect_err("a clone is never merged into an existing destination");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        std::fs::read_to_string(existing.join("README.md")).expect("the file is still there"),
        before
    );
    // An empty directory is existing too, so it is refused for the same reason.
    std::fs::create_dir(fixture.work().join("empty")).expect("an empty directory");
    let refusal = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "empty"),
                label: "empty".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&action("project.init", 4)),
        )
        .expect_err("an existing empty directory is still an existing destination");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    // The explicit flow is what admits it, and it changes nothing inside.
    let adopted = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "existing"),
                label: "existing".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 5)),
        )
        .expect("the explicit flow admits it");
    assert_eq!(adopted.project.origin, ProjectOrigin::Adopted);
    assert_eq!(
        adopted.operation.destination_state,
        DestinationState::NonEmptyDirectory
    );
    assert_eq!(
        adopted.operation.removed_staging_paths,
        Vec::<String>::new(),
        "an adoption stages nothing"
    );
    assert_eq!(
        std::fs::read_to_string(existing.join("README.md")).expect("the file is still there"),
        before
    );
    // And an adoption of a directory with no checkout in it is refused.
    let refusal = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "empty"),
                label: "empty".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 6)),
        )
        .expect_err("there is nothing to adopt");
    assert!(refusal.to_string().contains("no checkout to adopt"));
}

#[test]
fn two_copies_of_one_creation_action_produce_one_repository() {
    let fixture = Fixture::create();
    let submitted = action("project.init", 7);
    let first = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "once"),
                label: "once".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&submitted),
        )
        .expect("the first copy creates it");
    // The same action again, which is what a retry after a lost reply is. It is answered from the
    // record rather than performed, so the destination is not refused for existing and no second
    // repository appears.
    let second = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "once"),
                label: "once".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&submitted),
        )
        .expect("the second copy is answered from the record");
    assert_eq!(
        first.project.project_repository_id,
        second.project.project_repository_id
    );
    assert_eq!(
        fixture
            .service()
            .project_list(&ProjectListParams {
                environment_id: fixture.environment_id(),
            })
            .expect("the listing reads")
            .projects
            .len(),
        1
    );
    // A different request under the same identifier is a conflict rather than a second attempt.
    let mut reused = submitted.clone();
    reused.payload_digest = kr_protocol::scalars::Digest256::from_bytes([99; 32]);
    let refusal = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "twice"),
                label: "twice".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&reused),
        )
        .expect_err("one identifier is one request");
    assert_eq!(refusal.code(), ErrorCode::IdConflict);
}

#[test]
fn a_clone_names_the_remote_the_provider_and_the_broker_and_stores_no_credential() {
    let fixture = Fixture::with_brokers(installed_broker());
    let source = ordinary_repository(fixture.work(), "source");
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "clone"),
                label: "clone".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "upstream".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&action("project.clone", 8)),
        )
        .expect("a local path is cloned");
    let remote = cloned
        .project
        .remote
        .0
        .as_ref()
        .expect("the record names the remote it came from");
    assert_eq!(remote.remote_name, "upstream");
    assert_eq!(remote.transport, RemoteTransport::LocalPath);
    // A local path reaches no network, so it names no provider and no broker.
    assert_eq!(remote.provider, String::new());
    assert_eq!(remote.credential_broker, String::new());
    // The repository stored exactly the URL this host passed, under the name it was given.
    let stored = support::git_raw(
        &fixture.work().join("clone"),
        ["config", "--get", "remote.upstream.url"],
    );
    assert_eq!(stored.trim(), source.display().to_string());
    // A local clone that shared the source's objects would not be a separate repository.
    support::assert_absent(
        &fixture.work().join("clone/.git/objects/info/alternates"),
        "the clone has its own object store",
    );
    // The commit came across.
    assert!(fixture.work().join("clone/README.md").is_file());
}

#[test]
fn a_credential_in_a_url_is_refused_before_anything_is_staged() {
    let fixture = Fixture::with_brokers(named_broker());
    for url in [
        "https://user:secret@example.invalid/x.git",
        "ssh://git:secret@example.invalid/x.git",
    ] {
        let refusal = fixture
            .service()
            .project_clone(
                &actor(),
                &ProjectCloneParams {
                    destination: destination(fixture.environment_id(), fixture.work(), "never"),
                    label: "never".to_owned(),
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: if url.starts_with("https") {
                            RemoteTransport::Https
                        } else {
                            RemoteTransport::Ssh
                        },
                        url: url.to_owned(),
                        provider: String::new(),
                        credential_broker: "os-secret-store".to_owned(),
                    },
                },
                Some(&action("project.clone", 9)),
            )
            .expect_err("a credential in a URL is refused");
        assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
        assert!(
            !refusal.to_string().contains("secret"),
            "the refusal does not repeat the credential: {refusal}"
        );
    }
    // Nothing was created and nothing was staged: the parent is empty.
    assert_eq!(support::names_in(fixture.work()), Vec::<String>::new());
}

#[test]
fn a_transport_this_host_does_not_use_is_refused_by_name() {
    let fixture = Fixture::with_brokers(named_broker());
    for (url, named) in [
        ("git://example.invalid/x.git", RemoteTransport::Https),
        ("ext::sh -c 'echo planted'", RemoteTransport::Https),
        ("file:///tmp/x", RemoteTransport::LocalPath),
        ("http://example.invalid/x.git", RemoteTransport::Https),
    ] {
        let refusal = fixture
            .service()
            .project_clone(
                &actor(),
                &ProjectCloneParams {
                    destination: destination(fixture.environment_id(), fixture.work(), "never"),
                    label: "never".to_owned(),
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: named,
                        url: url.to_owned(),
                        provider: String::new(),
                        credential_broker: "os-secret-store".to_owned(),
                    },
                },
                Some(&action("project.clone", 10)),
            )
            .expect_err("a transport this host does not use is refused");
        assert_eq!(refusal.code(), ErrorCode::RepositoryUntrusted);
    }
    // An unapproved broker is refused too, so a caller cannot name its own credential program.
    let refusal = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "never"),
                label: "never".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::Https,
                    url: "https://example.invalid/x.git".to_owned(),
                    provider: String::new(),
                    credential_broker: "/tmp/my-own-helper".to_owned(),
                },
            },
            Some(&action("project.clone", 11)),
        )
        .expect_err("a broker this host does not have is refused");
    assert!(
        refusal
            .to_string()
            .contains("not an approved credential broker"),
        "the refusal says why: {refusal}"
    );
}

#[test]
fn a_rename_of_the_checkout_keeps_the_grant_and_a_replacement_at_its_path_does_not() {
    // Section 14 paragraph 5: identity is the stable filesystem identity, so a rename does not
    // extend a grant and a different repository at the old path is not the one that was granted.
    let fixture = Fixture::create();
    let created = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "first"),
                label: "first".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&action("project.init", 12)),
        )
        .expect("it is created");
    let first = fixture.work().join("first");
    let recorded = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &first,
    )
    .expect("it opens")
    .identity();

    // A rename of the checkout. The object is the same, so the recorded identity still names it.
    let moved = fixture.work().join("moved");
    std::fs::rename(&first, &moved).expect("the checkout is renamed");
    OpenedRepository::open_recorded(
        fixture.service().profile(),
        fixture.environment_id(),
        &moved,
        recorded,
    )
    .expect("a rename of the checkout keeps the identity that was recorded");

    // A different repository at the old path is a different object, so nothing is served from the
    // record: the grant did not extend to whatever now holds the name.
    ordinary_repository(fixture.work(), "first");
    let refusal = OpenedRepository::open_recorded(
        fixture.service().profile(),
        fixture.environment_id(),
        &first,
        recorded,
    )
    .expect_err("a replacement at the recorded path is refused");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);
    assert!(
        refusal
            .to_string()
            .contains("the object rather than the path"),
        "the refusal says why: {refusal}"
    );
    // The service's own record names the old path, so a workspace of it is refused for the same
    // reason rather than being made against the replacement.
    let refusal = fixture
        .service()
        .workspace_create(
            &actor(),
            &kr_protocol::project::WorkspaceCreateParams {
                project_repository_id: created.project.project_repository_id,
                label: "review".to_owned(),
                kind: kr_protocol::project::WorkspaceKind::SharedExisting,
                isolation: Nullable(None),
                policy: support::include_everything(),
                base_revision: Nullable(None),
                base_change_set_id: Nullable(None),
                destination: Nullable(None),
                preview_only: true,
            },
            Some(&action("workspace.create", 13)),
        )
        .expect_err("the record names an object that is no longer at its path");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);
}

#[test]
fn an_added_worktree_is_its_own_object_and_a_record_of_one_tree_never_covers_another() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "shared");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &source,
    )
    .expect("it opens");
    let recorded = repository.identity();
    // A linked worktree, added with plain Git the way a user would.
    let added = fixture.work().join("linked");
    support::git_raw(
        &source,
        [
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("--detach"),
            added.as_os_str(),
            OsStr::new("HEAD"),
        ],
    );
    let worktree = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &added,
    )
    .expect("the worktree opens");
    // The repository is the same object, which is what makes both worktrees one repository.
    assert_eq!(worktree.identity().git_dir, recorded.git_dir);
    // The working tree is a different object, so a record made against the first does not cover
    // the second: adding a worktree extends no grant.
    assert_ne!(worktree.identity().work_tree, recorded.work_tree);
    let refusal = OpenedRepository::open_recorded(
        fixture.service().profile(),
        fixture.environment_id(),
        &added,
        recorded,
    )
    .expect_err("a record of one working tree does not cover another");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);
    assert!(
        refusal
            .to_string()
            .contains("a record of one never covers another"),
        "the refusal says why: {refusal}"
    );
}

#[test]
fn an_interrupted_publication_is_settled_unknown_by_a_recovery_that_reaches_nothing() {
    // The operation row's key is the caller's action identifier, and the staged object's identity
    // is recorded before the rename. What a replacement daemon cannot do is look: it holds no
    // descriptor from before the restart, a recorded path is not authority, and a location is
    // dormant until the owner authorises it again. So it neither finishes the publication nor
    // starts another clone. It settles the operation as unknown under its create token and names
    // the staging directory, with the reason, for the owner.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source");
    let submitted = action("project.clone", 14);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "published"),
                label: "published".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");

    // Now put the journal back into the state a daemon that died between the two commits leaves:
    // the rename landed, the row still says `publishing`, and the repository row was never
    // written. A replacement resolves it from the recorded identity.
    let identity = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &fixture.work().join("published"),
    )
    .expect("the published repository opens")
    .identity()
    .work_tree;
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'publishing', ended_at_ms = NULL,
                    staged_device = ?2, staged_file_id = ?3 WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                identity.device as i64,
                identity.file_id as i64,
            ],
        )
        .expect("the row moves back to publishing");
    journal
        .execute(
            "DELETE FROM projects WHERE project_repository_id = ?1",
            rusqlite::params![
                cloned
                    .project
                    .project_repository_id
                    .get()
                    .as_bytes()
                    .to_vec()
            ],
        )
        .expect("the repository row was never written");
    journal
        .execute(
            "UPDATE actions SET result = NULL, error_code = NULL, error_detail = NULL
              WHERE action_id = ?1",
            rusqlite::params![submitted.action_id.as_bytes().to_vec()],
        )
        .expect("the claim is open again");
    // And the staging sibling the dying daemon had not got round to removing, with its own
    // identity on the row: finishing the publication has to take it away, and the identity it
    // checks is the sibling's rather than the published tree's.
    let name: String = journal
        .query_row(
            "SELECT staging_name FROM operations WHERE action_id = ?1",
            rusqlite::params![cloned.operation.action_id.get().as_bytes().to_vec()],
            |row| row.get(0),
        )
        .expect("the row names its sibling");
    let sibling = fixture.work().join(&name);
    support::staging_directory(&sibling);
    let sibling_identity = std::fs::metadata(&sibling).expect("its metadata");
    journal
        .execute(
            "UPDATE operations SET staging_device = ?2, staging_file_id = ?3
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                std::os::unix::fs::MetadataExt::dev(&sibling_identity) as i64,
                std::os::unix::fs::MetadataExt::ino(&sibling_identity) as i64,
            ],
        )
        .expect("the sibling's own identity is recorded");
    // The live run recorded the sibling as a path still there when it made it, and a daemon that
    // died before its cleanup never recorded it removed.
    journal
        .execute(
            "UPDATE operation_paths SET removed = 0, detail = NULL WHERE action_id = ?1",
            rusqlite::params![cloned.operation.action_id.get().as_bytes().to_vec()],
        )
        .expect("the sibling is recorded as still there");
    drop(journal);

    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert_eq!(recovery.unresolved, 1);
    assert!(
        sibling.join("tree").is_dir(),
        "the staging directory is not removed, because nothing this daemon holds reaches it"
    );
    assert!(
        fixture.work().join("published/.git").is_dir(),
        "and what was published is not touched"
    );
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert_eq!(operation.state, OperationState::Unknown);
    assert!(
        operation
            .retained_staging_paths
            .iter()
            .any(|path| path.ends_with(&name)),
        "the staging directory is named as still there: {:?}",
        operation.retained_staging_paths
    );
    let detail = operation.detail.0.expect("the record says why");
    assert!(
        detail.contains("cannot say whether the publication landed")
            && detail.contains("no location reaches it"),
        "and why nothing was looked at: {detail}"
    );
    // A repeat of the same action is told what this host established, which is that it cannot
    // say, rather than being cloned again.
    let refusal = replacement
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "published"),
                label: "published".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect_err("the repeat is answered from the unknown outcome");
    assert_eq!(refusal.code(), ErrorCode::OutcomeUnknown);
}

#[test]
fn an_operation_that_never_published_is_closed_and_its_staging_named_without_being_looked_at() {
    // An operation that never recorded the object it staged published nothing, which is a fact
    // the journal holds, so recovery closes it as failed without looking at anything. Its staging
    // directory is named as still there, with the reason, for the owner to reconcile through a
    // location: recovery reaches no directory, and a recorded name is not authority.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source");
    let submitted = action("project.clone", 15);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "never"),
                label: "never".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");
    // Put the row back into `staging` with no recorded identity, which is where a daemon that died
    // mid-clone leaves it, and put a staging directory back beside the destination.
    let staging = fixture.work().join(format!("{STAGING_PREFIX}abandoned"));
    support::staging_directory(&staging);
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    // The row carries the sibling's own identity as well as its name, because that is what a
    // daemon records when it creates one and what makes the cleanup a removal of this host's own
    // directory rather than of whatever holds the name.
    let abandoned = std::fs::metadata(&staging).expect("its metadata");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                    staged_file_id = NULL, staging_name = ?2, staging_device = ?3,
                    staging_file_id = ?4
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                format!("{STAGING_PREFIX}abandoned"),
                std::os::unix::fs::MetadataExt::dev(&abandoned) as i64,
                std::os::unix::fs::MetadataExt::ino(&abandoned) as i64,
            ],
        )
        .expect("the row moves back to staging");
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
    assert_eq!(recovery.unresolved, 1);
    assert!(
        staging.join("tree").is_dir(),
        "the abandoned staging directory is left for the owner"
    );
    // The published repository is untouched: nothing here removes a destination.
    assert!(fixture.work().join("never/.git").is_dir());
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert_eq!(operation.state, OperationState::Failed);
    assert!(
        operation
            .retained_staging_paths
            .iter()
            .any(|path| path.ends_with("abandoned")),
        "and named as still there: {:?}",
        operation.retained_staging_paths
    );
    // And the same row with *no* recorded identity: the daemon died before it could say which
    // object it had created, so the name alone authorises nothing.
    let unproven = fixture.work().join(format!("{STAGING_PREFIX}unproven"));
    std::fs::create_dir_all(unproven.join("tree")).expect("a sibling with no recorded identity");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                    staged_file_id = NULL, staging_name = ?2, staging_device = NULL,
                    staging_file_id = NULL
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                format!("{STAGING_PREFIX}unproven"),
            ],
        )
        .expect("the name is recorded and the identity is not");
    drop(journal);
    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs again");
    assert!(unproven.join("tree").is_dir(), "it is still there");
    // And what the recovery reports is that path, because a figure that counted it as cleaned up
    // would be saying something this host did not do.
    assert_eq!(recovery.unresolved, 1);
    assert!(
        recovery
            .retained_paths
            .iter()
            .any(|path| path.ends_with("unproven")),
        "the path a person can find is named: {:?}",
        recovery.retained_paths
    );
    // And a name whose directory is not there at all: the daemon died between recording the name
    // and creating the sibling. Recovery cannot tell that from a directory it could not look at,
    // because it looks at nothing, so the name is reported like every other: as a path the owner
    // should look at, with the reason this host did not.
    let absent = format!("{STAGING_PREFIX}absent");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                    staged_file_id = NULL, staging_name = ?2, staging_device = NULL,
                    staging_file_id = NULL
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                absent.clone(),
            ],
        )
        .expect("the row names a sibling that was never created");
    // The live run recorded the name it created as a path that is still there, which is what a
    // daemon that died between the two writes leaves. Recovery has to take that record away.
    journal
        .execute(
            "INSERT INTO operation_paths (action_id, path, removed) VALUES (?1, ?2, 0)
             ON CONFLICT (action_id, path) DO UPDATE SET removed = 0",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                fixture.work().join(&absent).display().to_string(),
            ],
        )
        .expect("the path is recorded as one that is still there");
    drop(journal);
    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs once more");
    assert_eq!(
        recovery.unresolved, 1,
        "a name recovery did not look at is an unresolved path, not a cleanup"
    );
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert!(
        operation
            .retained_staging_paths
            .iter()
            .any(|path| path.ends_with(&absent)),
        "the path is named for the owner to look at: {:?}",
        operation.retained_staging_paths
    );
    assert!(
        !operation
            .removed_staging_paths
            .iter()
            .any(|path| path.ends_with(&absent)),
        "and nothing claims it was removed: {:?}",
        operation.removed_staging_paths
    );
    // And a record that says this host *did* remove a directory is history rather than occupancy:
    // a cleanup removed it and the operation never closed. Naming what recovery could not look at
    // must not take that away.
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL WHERE action_id = ?1",
            rusqlite::params![cloned.operation.action_id.get().as_bytes().to_vec()],
        )
        .expect("the row is unfinished again");
    journal
        .execute(
            "INSERT INTO operation_paths (action_id, path, removed) VALUES (?1, ?2, 1)
             ON CONFLICT (action_id, path) DO UPDATE SET removed = 1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                fixture.work().join(&absent).display().to_string(),
            ],
        )
        .expect("an earlier cleanup's removal is recorded");
    drop(journal);
    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs again");
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert!(
        operation
            .removed_staging_paths
            .iter()
            .any(|path| path.ends_with(&absent)),
        "a removal this host did make is still on the record: {:?}",
        operation.removed_staging_paths
    );
    assert!(
        operation
            .detail
            .0
            .as_deref()
            .is_some_and(|detail| detail.contains("a new operation needs a new action identifier")),
        "the record says what to do next: {:?}",
        operation.detail.0
    );
    // A repeat of the same action is owed that failure rather than a second clone.
    let refusal = replacement
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "never"),
                label: "never".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect_err("the repeat is answered with the retained failure");
    assert_eq!(refusal.code(), ErrorCode::OutcomeUnknown);
}

#[test]
fn a_cancellation_ends_the_subprocess_this_host_started() {
    // The one thing a cancellation has to do is stop the child. The endpoint is a listener on this
    // machine's loopback address that accepts the connection and never answers, so the invocation
    // blocks until something stops it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("its address").port();
    let held = std::thread::spawn(move || {
        // Accept and hold: the connection stays open and nothing is written to it. The wait is
        // bounded, because whether the invocation reached the connection before its owner stopped
        // it is a matter of how busy the machine is, and a thread waiting for a connection that is
        // never coming would hold this test open for ever rather than failing it.
        listener
            .set_nonblocking(true)
            .expect("the listener can be polled");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match listener.accept() {
                Ok(accepted) => {
                    std::thread::sleep(Duration::from_secs(5));
                    drop(accepted);
                    break;
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
        drop(listener);
    });

    let fixture = Fixture::with_brokers(installed_broker());
    let profile = fixture.service().profile().clone();
    let cancel = Arc::new(Cancellation::default());
    let watched = Arc::clone(&cancel);
    let work = fixture.work().to_owned();
    let url = format!("https://127.0.0.1:{port}/repository.git");
    let (finished, waiting) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let arguments: [&OsStr; 4] = [
            OsStr::new("clone"),
            OsStr::new("--template="),
            OsStr::new(&url),
            OsStr::new("tree"),
        ];
        let outcome = profile.run(
            &GitRequest::write(&work, &arguments)
                .with_transport(kr_project::git::RemoteAccess {
                    transport: RemoteTransport::Https,
                    credential_helper: None,
                    ssh_command: None,
                    ssh_program: None,
                    port: Some(port),
                    remote_name: Some("origin"),
                })
                .with_deadline(Duration::from_secs(120))
                .with_cancellation(watched),
        );
        let _ = finished.send(outcome.err().map(|error| error.code()));
    });

    // Give the invocation long enough to reach the connection, then stop it.
    std::thread::sleep(Duration::from_millis(500));
    cancel.request();
    let answer = waiting
        .recv_timeout(Duration::from_secs(60))
        .expect("the cancellation ends the invocation");
    assert_eq!(
        answer,
        Some(ErrorCode::ResourceUnavailable),
        "the invocation reports that its owner stopped it"
    );
    assert!(
        cancel.stopped() >= 1,
        "the cancellation counted the subprocess it stopped"
    );
    let _ = held.join();
}

#[test]
fn a_cancellation_reaches_only_authorised_owned_work() {
    let fixture = Fixture::create();
    let created = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "owned"),
                label: "owned".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&action("project.init", 16)),
        )
        .expect("it is created");
    // Another actor's operation is not this caller's to stop.
    let stranger = kr_protocol::ids::ActorId::new("local:stranger").expect("a valid principal");
    let refusal = fixture
        .service()
        .project_operation_cancel(
            &stranger,
            &ProjectOperationCancelParams {
                operation_action_id: created.operation.action_id,
            },
        )
        .expect_err("a cancellation reaches only authorised owned work");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    // The owner's cancellation of work that has already finished undoes nothing and says so, with
    // the staging paths the operation accounted for.
    let answered = fixture
        .service()
        .project_operation_cancel(
            &actor(),
            &ProjectOperationCancelParams {
                operation_action_id: created.operation.action_id,
            },
        )
        .expect("the owner's cancellation is answered from the record");
    assert_eq!(answered.operation.state, OperationState::Completed);
    assert_eq!(answered.stopped_processes.get(), 0);
    assert_eq!(answered.operation.removed_staging_paths.len(), 1);
    assert!(fixture.work().join("owned/.git").is_dir());
    // And an operation this host has no record of is not something to cancel.
    let refusal = fixture
        .service()
        .project_operation_cancel(
            &actor(),
            &ProjectOperationCancelParams {
                operation_action_id: kr_protocol::ids::ActionId::new(
                    kr_protocol::scalars::Uuid::from_bytes([200; 16]),
                ),
            },
        )
        .expect_err("there is no such operation");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
}

#[test]
fn a_destination_is_one_name_inside_a_directory_this_host_holds_a_handle_to() {
    let fixture = Fixture::create();
    for (parent, name, why) in [
        (fixture.work().display().to_string(), "a/b", "a separator"),
        (
            fixture.work().display().to_string(),
            "..",
            "a traversal segment",
        ),
        (fixture.work().display().to_string(), "", "an empty name"),
        ("relative/parent".to_owned(), "x", "a relative parent"),
    ] {
        let refusal = fixture
            .service()
            .project_init(
                &actor(),
                &ProjectInitParams {
                    destination: kr_protocol::project::DestinationRequest {
                        environment_id: fixture.environment_id(),
                        parent_path: parent,
                        name: name.to_owned(),
                    },
                    label: "refused".to_owned(),
                    initial_branch: Nullable(None),
                },
                Some(&action("project.init", 17)),
            )
            .expect_err("a destination is one name inside a directory");
        assert_eq!(refusal.code(), ErrorCode::InvalidArgument, "{why}");
    }
    // And a destination in another environment is not this service's to create.
    let refusal = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: kr_protocol::project::DestinationRequest {
                    environment_id: kr_protocol::ids::EnvironmentId::new(
                        kr_protocol::scalars::Uuid::from_bytes([7; 16]),
                    ),
                    parent_path: fixture.work().display().to_string(),
                    name: "elsewhere".to_owned(),
                },
                label: "elsewhere".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&action("project.init", 18)),
        )
        .expect_err("another environment's destination is not this service's");
    assert_eq!(refusal.code(), ErrorCode::EnvironmentUnavailable);
}

#[test]
fn rows_without_a_location_take_no_filesystem_effect() {
    // A row that records no location was written for a request that named none, or by an earlier
    // build, and earlier builds wrote such rows for paired devices as well as for the owner. It is
    // evidence of no authority, so recovery takes no filesystem effect for it whoever its actor
    // was: what it left is named for the owner, who reconciles it through a location.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source");
    let mut left = Vec::new();
    for (seed, principal, name) in [
        (50_u8, "device:phone", "left-by-a-device"),
        (51_u8, "local:test", "left-by-the-owner"),
    ] {
        let submitted = action("project.clone", seed);
        let cloned = fixture
            .service()
            .project_clone(
                &actor(),
                &ProjectCloneParams {
                    destination: destination(fixture.environment_id(), fixture.work(), name),
                    label: name.to_owned(),
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: RemoteTransport::LocalPath,
                        url: source.display().to_string(),
                        provider: String::new(),
                        credential_broker: String::new(),
                    },
                },
                Some(&submitted),
            )
            .expect("the clone completes");
        // What a daemon that died mid-clone leaves, under the actor the row names.
        let staging_name = format!("{STAGING_PREFIX}{name}");
        let staging = fixture.work().join(&staging_name);
        support::staging_directory(&staging);
        let identity = std::fs::metadata(&staging).expect("its metadata");
        let journal = rusqlite::Connection::open(
            kr_project::ProjectService::root_of(&fixture.host().environment())
                .join(kr_project::store::STORE_FILE_NAME),
        )
        .expect("the journal opens");
        journal
            .execute(
                "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                        staged_file_id = NULL, staging_name = ?2, staging_device = ?3,
                        staging_file_id = ?4, actor_id = ?5
                  WHERE action_id = ?1",
                rusqlite::params![
                    cloned.operation.action_id.get().as_bytes().to_vec(),
                    staging_name,
                    std::os::unix::fs::MetadataExt::dev(&identity) as i64,
                    std::os::unix::fs::MetadataExt::ino(&identity) as i64,
                    principal,
                ],
            )
            .expect("the row is left mid-clone");
        drop(journal);
        left.push((cloned.operation.action_id, staging));
    }

    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert_eq!(recovery.unresolved, 2);
    for (action_id, staging) in left {
        assert!(
            staging.join("tree").is_dir(),
            "{}: nothing is removed for a row with no location",
            staging.display()
        );
        let operation = replacement
            .read_operation(action_id)
            .expect("the operation reads");
        assert_eq!(operation.state, OperationState::Failed);
        assert!(
            operation
                .retained_staging_paths
                .iter()
                .any(|path| Path::new(path) == staging),
            "the directory is named: {:?}",
            operation.retained_staging_paths
        );
        assert!(
            operation
                .detail
                .0
                .as_deref()
                .is_some_and(|detail| detail.contains("no location reaches it")),
            "with the reason: {:?}",
            operation.detail
        );
    }
}

#[test]
fn recovery_removes_no_staging_directory_and_names_each_one_it_recorded() {
    // A sibling is named on the row before it exists, so what recovery reports is a name this host
    // recorded, and it removes none of them: it holds nothing that reaches a directory. A
    // repository a user happened to call `.kr-project-something` is not named at all.
    let fixture = Fixture::create();
    let decoy = ordinary_repository(fixture.work(), &format!("{STAGING_PREFIX}a-users-own"));
    let source = ordinary_repository(fixture.work(), "source");
    let submitted = action("project.clone", 20);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "swept"),
                label: "swept".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");
    // A sibling this host recorded and did not get to remove, which is what a daemon that died
    // between the publication and the cleanup leaves.
    let recorded = fixture.work().join(format!("{STAGING_PREFIX}recorded"));
    support::staging_directory(&recorded);
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    // The service records the sibling's own identity with its name, because a recorded name is
    // not authority to remove whatever now holds it. The row a dying daemon would have left holds
    // both, so the fixture writes both.
    let recorded_identity = std::fs::metadata(&recorded).expect("the directory's metadata");
    journal
        .execute(
            "UPDATE operations SET staging_name = ?2, staging_device = ?3, staging_file_id = ?4
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                format!("{STAGING_PREFIX}recorded"),
                std::os::unix::fs::MetadataExt::dev(&recorded_identity) as i64,
                std::os::unix::fs::MetadataExt::ino(&recorded_identity) as i64,
            ],
        )
        .expect("the name and the identity are recorded");
    drop(journal);

    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    assert!(
        recorded.join("tree").is_dir(),
        "the recorded sibling is left for the owner"
    );
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert!(
        operation
            .retained_staging_paths
            .iter()
            .any(|path| path.ends_with(&format!("{STAGING_PREFIX}recorded"))),
        "and named as still there: {:?}",
        operation.retained_staging_paths
    );
    assert!(
        !operation
            .retained_staging_paths
            .iter()
            .any(|path| path.ends_with("a-users-own")),
        "a name this host did not record is not named"
    );
    // And the user's own repository, whose name merely looks like one of this host's, is untouched.
    assert!(
        decoy.join(".git").is_dir(),
        "a repository this host did not create is not this host's to delete"
    );
    assert!(decoy.join("README.md").is_file());
    assert!(fixture.work().join("swept/.git").is_dir());
}

#[test]
fn a_staging_directory_recovery_cannot_reach_is_named_with_the_reason_on_every_read() {
    use std::os::unix::fs::MetadataExt as _;

    // Recovery reaches no staging directory, so one an ended operation left is named as still
    // there, with the reason, on the operation's own read and on its repository's. The publication
    // it followed stands.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source");
    let submitted = action("project.clone", 21);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "kept"),
                label: "kept".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");
    // A sibling this host recorded and did not get to remove.
    let recorded = fixture.work().join(format!("{STAGING_PREFIX}stuck"));
    support::staging_directory(&recorded);
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    let recorded_identity = std::fs::metadata(&recorded).expect("the directory's metadata");
    journal
        .execute(
            "UPDATE operations SET staging_name = ?2, staging_device = ?3, staging_file_id = ?4
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                format!("{STAGING_PREFIX}stuck"),
                recorded_identity.dev() as i64,
                recorded_identity.ino() as i64,
            ],
        )
        .expect("the name and the identity are recorded");
    drop(journal);

    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    assert!(
        recorded.join("tree").is_dir(),
        "the directory is left where it is"
    );
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert_eq!(
        operation.state,
        OperationState::Completed,
        "a staging directory left behind does not undo the publication"
    );
    assert!(
        operation
            .retained_staging_paths
            .iter()
            .any(|path| path.ends_with(&format!("{STAGING_PREFIX}stuck"))),
        "the path is one that is still there: {:?}",
        operation.retained_staging_paths
    );
    let detail = operation
        .detail
        .0
        .expect("the record says why the path is still there");
    assert!(
        detail.contains(&format!(
            "the staging directory {} is still there",
            recorded.display()
        )) && detail.contains("no location reaches it"),
        "and why: {detail}"
    );
    // The repository's own read says the same about the operation that made it.
    let read = replacement
        .project_read(&ProjectReadParams {
            project_repository_id: cloned.project.project_repository_id,
        })
        .expect("the repository reads");
    let named = read
        .operation
        .0
        .expect("the repository's read names the operation that made it");
    assert!(
        named
            .detail
            .0
            .as_deref()
            .is_some_and(|detail| detail.contains("no location reaches it")),
        "and says why its staging directory is still there: {named:?}"
    );
}

#[test]
fn a_recorded_staging_name_whose_object_was_replaced_is_left_alone() {
    // A recorded name is not authority to remove whatever now holds it. The row carries the
    // sibling's own identity, and a different directory at that name is not the one to remove.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source");
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "replaced"),
                label: "replaced".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&action("project.clone", 23)),
        )
        .expect("the clone completes");
    let name = format!("{STAGING_PREFIX}substituted");
    let substituted = fixture.work().join(&name);
    std::fs::create_dir_all(substituted.join("somebody-elses-work"))
        .expect("a directory at the name");
    // The row names that name and an identity that is not what is there.
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET staging_name = ?2, staging_device = ?3, staging_file_id = ?4
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                name,
                1_i64,
                1_i64,
            ],
        )
        .expect("the name and a different identity are recorded");
    drop(journal);
    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    assert!(
        substituted.join("somebody-elses-work").is_dir(),
        "a different object at a recorded name is not the one to remove"
    );
}

#[test]
fn recovery_settles_a_claim_an_earlier_daemon_left_open() {
    // A claim is opened with the state it changes and filled in when the effect settles, so a
    // daemon that died between the two leaves one open. An open claim is not an answer: a repeat
    // of the action would be told the outcome is unknown for ever.
    let fixture = Fixture::create();
    let submitted = action("project.init", 21);
    let created = fixture
        .service()
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "claimed"),
                label: "claimed".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&submitted),
        )
        .expect("it is created");
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
    // The claim named a completed operation, so the durable state answers it: the repeat gets the
    // repository that was created rather than being told the outcome is unknown for ever.
    let repeated = replacement
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "claimed"),
                label: "claimed".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&submitted),
        )
        .expect("the repeat is answered from the settled record");
    assert_eq!(
        repeated.project.project_repository_id,
        created.project.project_repository_id
    );
    assert_eq!(repeated.operation.state, OperationState::Completed);
    // And a second recovery has nothing left to settle.
    assert_eq!(
        replacement
            .recover()
            .expect("recovery runs again")
            .claims_settled,
        0
    );
}

#[test]
fn a_publication_recovery_cannot_examine_is_recorded_as_unknown_and_answered_from_that() {
    // Whether the rename landed is a question only the filesystem answers, and recovery holds
    // nothing that reaches it. The operation says unknown, and a repeat is told the same.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "source");
    let submitted = action("project.clone", 24);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "undecided"),
                label: "undecided".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");
    // The state a daemon that died in the middle of a publication leaves: the row is `publishing`
    // with a witness of an object neither name holds, and the claim is open.
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'publishing', ended_at_ms = NULL,
                    staged_device = 1, staged_file_id = 1, staged_created_at_ms = 1,
                    staging_name = NULL WHERE action_id = ?1",
            rusqlite::params![cloned.operation.action_id.get().as_bytes().to_vec()],
        )
        .expect("the row moves back to publishing");
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
    // Nothing recovery holds reaches either name, so the operation is recorded as unknown and its
    // claim is settled from that state: no later recovery would reach them either.
    assert_eq!(recovery.unresolved, 1);
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert_eq!(operation.state, OperationState::Unknown);
    let refusal = replacement
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "undecided"),
                label: "undecided".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect_err("the repeat is answered with what this host could establish");
    assert_eq!(refusal.code(), ErrorCode::OutcomeUnknown);
}

#[test]
fn a_destination_a_caller_named_does_not_reach_the_journal() {
    // A destination's own name is text a caller sent, and a failure about it is written into the
    // operation row, into the claim and into every later answer. So the journal holds what the
    // caller was told rather than what the caller sent.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "journal-source");
    let carrying = "access_token=JOURNALSECRET";
    let submitted = action("project.clone", 80);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), carrying),
                label: "journal".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");
    // The state a daemon that died before it recorded a witness leaves. Recovery closes the
    // operation with a reason that names the destination.
    let journal_path = kr_project::ProjectService::root_of(&fixture.host().environment())
        .join(kr_project::store::STORE_FILE_NAME);
    let journal = rusqlite::Connection::open(&journal_path).expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                    staged_file_id = NULL, detail = NULL WHERE action_id = ?1",
            rusqlite::params![cloned.operation.action_id.get().as_bytes().to_vec()],
        )
        .expect("the row moves back to staging");
    journal
        .execute(
            "UPDATE actions SET result = NULL, error_code = NULL, error_detail = NULL
              WHERE action_id = ?1",
            rusqlite::params![submitted.action_id.as_bytes().to_vec()],
        )
        .expect("the claim is open again");
    drop(journal);
    let replacement = fixture.reopen();
    replacement.recover().expect("recovery runs");
    // Every place that reason is kept, and the answer a repeat of the action gets.
    let journal = rusqlite::Connection::open(&journal_path).expect("the journal opens again");
    let kept: Vec<String> = [
        "SELECT detail FROM operations",
        "SELECT error_detail FROM actions",
    ]
    .iter()
    .flat_map(|query| {
        let mut statement = journal.prepare(query).expect("the column reads");
        let rows: Vec<String> = statement
            .query_map([], |row| {
                Ok(row.get::<_, Option<String>>(0)?.unwrap_or_default())
            })
            .expect("the rows map")
            .map(|row| row.expect("a row"))
            .collect();
        rows
    })
    .collect();
    assert!(
        kept.iter().any(|text| text.contains("does-not-repeat")),
        "the reason was written and something was taken out of it: {kept:?}"
    );
    for text in &kept {
        assert!(
            !text.contains("JOURNALSECRET"),
            "nothing the caller sent is in the journal: {text}"
        );
    }
    let refusal = replacement
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), carrying),
                label: "journal".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&submitted),
        )
        .expect_err("the repeat is answered from the record")
        .to_string();
    assert!(
        !refusal.contains("JOURNALSECRET"),
        "nor in what a repeat is told: {refusal}"
    );
}

#[test]
fn an_https_clone_with_no_credential_helper_is_attempted_rather_than_refused() {
    // Git ships a credential helper for the platform's secret store on some hosts and not on
    // others, and an ordinary Linux installation has none. A host that refused an https remote
    // there would put every one of them out of reach, a public repository included. So the attempt
    // goes ahead carrying no credential, and what this test establishes is exactly that: the remote
    // passed validation and the host attempted to start Git for it, rather than refusing the broker
    // before anything ran. What became of the attempt after that is Git's, and this does not read
    // it.
    // What the profile still guarantees is that no credential of the user's is used: the helper
    // list is empty and no prompt can be answered.
    let fixture = Fixture::with_brokers(support::broker_without_a_credential_helper());
    // A port nothing is listening on, so the attempt ends at once and nothing leaves this machine.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = closed.local_addr().expect("its address").port();
    drop(closed);
    let refusal = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "unauthenticated",
                ),
                label: "unauthenticated".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::Https,
                    url: format!("https://127.0.0.1:{port}/repository.git"),
                    provider: String::new(),
                    credential_broker: "os-secret-store".to_owned(),
                },
            },
            Some(&action("project.clone", 41)),
        )
        .expect_err("nothing is listening at that port, so the attempt fails");
    assert_eq!(
        refusal.code(),
        ErrorCode::UpstreamUnavailable,
        "the attempt got as far as Git rather than being refused for its broker: {refusal}"
    );
    assert!(
        refusal.to_string().contains("no credential was available"),
        "and it says what the attempt carried, because Git's own words are not repeated: {refusal}"
    );
    // The code above is every Git failure's, a process that would not start included, so it says
    // the attempt reached Git and no more than that. The rest is what was left behind: the
    // destination was never made, and the private sibling the attempt staged into was taken away
    // as the attempt failed, through the handle the attempt held, rather than left for a
    // recovery that reaches no directory.
    support::assert_absent(
        &fixture.work().join("unauthenticated"),
        "a clone that failed published nothing",
    );
    assert_eq!(
        support::names_in(fixture.work())
            .into_iter()
            .filter(|name| name.starts_with(STAGING_PREFIX))
            .collect::<Vec<String>>(),
        Vec::<String>::new(),
        "and the sibling it staged into is gone"
    );
}

#[test]
fn a_grant_withdrawn_while_a_creation_prepares_reaches_an_operation_that_never_begins() {
    // KR-REQ-23.44, section 9: the admission is revalidated immediately before the effect. The
    // daemon answers it once when it accepts the mutation and once before the service acts, and
    // everything after that still waits: the destination is resolved and probed, and the journal's
    // lock is taken. A revocation completing in there has to reach an operation that does not then
    // begin, so the service asks the admission once more inside the transaction that writes the
    // operation row -- the row that is the create token, before anything exists on disk.
    let fixture = Fixture::create();
    let service = fixture.service();
    let environment_id = fixture.environment_id();
    let claimed = action("project.init", 90);
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let refusal = std::thread::scope(|threads| {
        // Something else asking this journal a question, so that where the admission is asked can
        // be observed rather than assumed.
        threads.spawn(move || {
            wait.recv().expect("the admission has been asked");
            service
                .project_list(&ProjectListParams { environment_id })
                .expect("the listing reads");
            done.send(()).expect("the creation is still waiting");
        });
        let withdrawn = || {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            go.send(()).expect("the reader is waiting");
            assert!(
                finished.recv_timeout(Duration::from_millis(250)).is_err(),
                "the admission is asked inside the transaction, with the journal held"
            );
            Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the authority this action was admitted under was withdrawn",
            ))
        };
        let refusal = service
            .project_init(
                &actor(),
                &ProjectInitParams {
                    destination: destination(fixture.environment_id(), fixture.work(), "withdrawn"),
                    label: "withdrawn".to_owned(),
                    initial_branch: Nullable(None),
                },
                Performed::from(Some(&claimed)).admitted(&withdrawn),
            )
            .expect_err("a creation whose grant went does not begin");
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("and the journal is free again once the transaction has rolled back");
        refusal
    });
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        refusal.to_string().contains("withdrawn"),
        "the refusal is the daemon's own words: {refusal}"
    );
    support::assert_absent(
        &fixture.work().join("withdrawn"),
        "nothing was created for an operation that never began",
    );
    assert_eq!(
        support::names_in(fixture.work()),
        Vec::<String>::new(),
        "and no private sibling was staged either"
    );
    // Nothing was written, so nothing has to be reconciled: the operation row is not there and the
    // action is not claimed. A repeat under the same identifier is a fresh request rather than a
    // retry of something half performed.
    let unknown = service
        .read_operation(kr_protocol::ids::ActionId::new(claimed.action_id))
        .expect_err("no operation row was written");
    assert_eq!(unknown.code(), ErrorCode::ResourceUnavailable);
    let created = service
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "withdrawn"),
                label: "withdrawn".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&claimed),
        )
        .expect("the same action under a grant that stands is performed");
    assert_eq!(created.operation.state, OperationState::Completed);
}

#[test]
fn an_expiry_landing_while_a_clone_prepares_reaches_an_operation_that_never_begins() {
    // The other lapse section 9 names: the accepted deadline passes while the service prepares.
    // The answer a caller gets says which of the two happened, because the daemon decides it and
    // the service carries its words rather than composing a refusal of its own.
    let fixture = Fixture::with_brokers(named_broker());
    let source = ordinary_repository(fixture.work(), "origin");
    let expired = || {
        Err(ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the deadline this action was admitted under passed before its effect was committed",
        ))
    };
    let claimed = action("project.clone", 91);
    let refusal = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "expired"),
                label: "expired".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: "local".to_owned(),
                    credential_broker: String::new(),
                },
            },
            Performed::from(Some(&claimed)).admitted(&expired),
        )
        .expect_err("a clone whose window closed does not begin");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        refusal.to_string().contains("deadline"),
        "an expiry is told apart from a revocation by what it says: {refusal}"
    );
    support::assert_absent(
        &fixture.work().join("expired"),
        "nothing was cloned for an operation that never began",
    );
    assert_eq!(
        support::names_in(fixture.work()),
        vec!["origin".to_owned()],
        "and no private sibling was staged either"
    );
}
