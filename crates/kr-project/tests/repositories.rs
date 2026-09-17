//! Project repositories: identity, authorised destinations, staged publication, the credential
//! rule and the reconciliation of an interrupted publish.
//!
//! KR-REQ-06.09, 14.06, 14.17, 14.18, 14.19, 23.42.

#![cfg(feature = "git-fixtures")]

mod support;

use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kr_project::git::{Cancellation, GitRequest};
use kr_project::identity::OpenedRepository;
use kr_project::operation::STAGING_PREFIX;
use kr_protocol::error::ErrorCode;
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
    assert!(!Path::new(staged).exists(), "the sibling is gone");
    // The published repository is a repository, and the parent holds nothing else.
    assert!(fixture.work().join("fresh/.git").is_dir());
    let mut entries: Vec<String> = std::fs::read_dir(fixture.work())
        .expect("the parent is readable")
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    entries.sort();
    assert_eq!(entries, vec!["fresh".to_owned()]);
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
    assert!(
        !fixture
            .work()
            .join("clone/.git/objects/info/alternates")
            .exists(),
        "the clone has its own object store"
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
    let entries: Vec<String> = std::fs::read_dir(fixture.work())
        .expect("the parent is readable")
        .filter_map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    assert_eq!(entries, Vec::<String>::new());
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
fn an_interrupted_publication_is_reconciled_against_the_create_token() {
    // The operation row's key is the caller's action identifier, and the staged object's identity
    // is recorded before the rename. So a replacement daemon asks which name holds that object
    // rather than starting another clone.
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
    drop(journal);

    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert_eq!(recovery.publications_completed, 1);
    assert_eq!(recovery.unresolved, 0);
    let read = replacement
        .project_read(&ProjectReadParams {
            project_repository_id: cloned.project.project_repository_id,
        })
        .expect("the repository the publication landed as is there");
    assert_eq!(read.project.state, ProjectState::Ready);
    assert_eq!(
        read.operation.0.map(|operation| operation.state),
        Some(OperationState::Completed)
    );
    // A repeat of the same action is answered from the record the recovery settled, so the caller
    // that never saw a reply is owed the outcome rather than another clone.
    let repeated = replacement
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
        .expect("the repeat is answered from the record");
    assert_eq!(
        repeated.project.project_repository_id,
        cloned.project.project_repository_id
    );
}

#[test]
fn an_operation_that_never_published_leaves_the_destination_untouched_and_is_closed() {
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
    std::fs::create_dir_all(staging.join("tree")).expect("an abandoned staging directory");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                    staged_file_id = NULL, staging_name = ?2 WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                format!("{STAGING_PREFIX}abandoned"),
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
    assert_eq!(recovery.staging_removed, 1);
    assert!(!staging.exists(), "the abandoned staging directory is gone");
    // The published repository is untouched: nothing here removes a destination.
    assert!(fixture.work().join("never/.git").is_dir());
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert_eq!(operation.state, OperationState::Failed);
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
        // Accept and hold: the connection stays open and nothing is written to it.
        let accepted = listener.accept();
        std::thread::sleep(Duration::from_secs(5));
        drop(accepted);
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
                .with_transport(RemoteTransport::Https, None, None)
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
fn recovery_removes_the_staging_directories_it_recorded_and_nothing_else() {
    // A sibling is named on the row before it exists, so what recovery removes is a name this
    // host recorded. A repository a user happened to call `.kr-project-something` is not one.
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
    std::fs::create_dir_all(recorded.join("tree")).expect("a recorded staging directory");
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET staging_name = ?2 WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                format!("{STAGING_PREFIX}recorded"),
            ],
        )
        .expect("the name is recorded");
    drop(journal);

    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert!(recovery.staging_removed >= 1);
    assert!(!recorded.exists(), "the recorded sibling is removed");
    // And the user's own repository, whose name merely looks like one of this host's, is untouched.
    assert!(
        decoy.join(".git").is_dir(),
        "a repository this host did not create is not this host's to delete"
    );
    assert!(decoy.join("README.md").is_file());
    assert!(fixture.work().join("swept/.git").is_dir());
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
    // A repeat now gets a definite answer that names what the action acted on, rather than being
    // told for ever that the outcome is unknown.
    let refusal = replacement
        .project_init(
            &actor(),
            &ProjectInitParams {
                destination: destination(fixture.environment_id(), fixture.work(), "claimed"),
                label: "claimed".to_owned(),
                initial_branch: Nullable(None),
            },
            Some(&submitted),
        )
        .expect_err("the repeat is answered from the settled record");
    assert_eq!(refusal.code(), ErrorCode::OutcomeUnknown);
    assert!(
        refusal
            .to_string()
            .contains(&created.operation.action_id.to_string()),
        "the answer names what the action acted on: {refusal}"
    );
    // And a second recovery has nothing left to settle.
    assert_eq!(
        replacement
            .recover()
            .expect("recovery runs again")
            .claims_settled,
        0
    );
}
