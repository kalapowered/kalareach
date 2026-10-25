//! Review work from captured change sets, through a real daemon.
//!
//! Requirement rows exercised here: KR-REQ-14.35 (a review acknowledgement binds the version it was
//! made against, a later version is new review work, and promotion stays a separate authorised
//! action) and KR-REQ-25.04 (what changed since the last visit, and a review that changes no Git
//! state).
//!
//! A change set is captured through `changeset.capture` by a client of the daemon, for a session
//! the daemon holds: a worker it adopted at its start, which is the product's own worker over a
//! real terminal. The repositories are built with installed Git. What each test reads is what the
//! attention group answers (`review.read`, `visit.changed`) and what Git itself reports.
//!
//! Nothing here waits for a measured delay. A test waits for a condition, and the daemon announces
//! each finished pass over the change-set store, so a wait ends when the pass that settles the
//! question has finished.

#![cfg(not(windows))]

mod net_support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_crypto::keys::DeviceKeys;
use kr_ipc::client::LocalClient;
use kr_protocol::attention::{
    ReviewAcknowledgeParams, ReviewAcknowledgeResult, ReviewReadParams, ReviewReadResult,
    ReviewState, ReviewSubject, SemanticChangeKind, VisitAcknowledgeParams, VisitAcknowledgeResult,
    VisitChangedParams, VisitChangedResult,
};
use kr_protocol::changeset::{
    AffectedVersion, ChangesetCaptureParams, ChangesetCaptureResult, DestinationClass,
    DiffApplyParams, DiffApplyResult, FileGrant, VersionRef,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::ids::{ActionId, ChangeSetId, ChangeSetVersion, SessionId, WorkspaceId};
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, DestinationParent, DestinationRequest, InclusionChoice, InclusionPolicy,
    ProjectAdoptParams, ProjectAdoptResult, WorkspaceCreateParams, WorkspaceCreateResult,
    WorkspaceKind,
};
use kr_protocol::scalars::{Nullable, U64};

use net_support::Host;
use net_support::worker::Worker;

/// How long a condition is waited for before the test gives up on it. A bound for a machine under
/// load, never a figure a test depends on.
const PATIENCE: Duration = Duration::from_secs(120);

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// Runs installed Git directly and returns what it printed.
fn git_out<I: IntoIterator<Item = S>, S: AsRef<std::ffi::OsStr>>(
    directory: &Path,
    arguments: I,
) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .arg("-c")
        .arg("user.name=KalaReach Fixture")
        .arg("-c")
        .arg("user.email=fixture@example.invalid")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("LC_ALL", "C")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "Git refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A repository with one commit, a dirty file, an untracked one and a secret.
fn repository(parent: &Path, name: &str, readme: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir_all(&path).expect("a directory for the repository");
    git_out(&path, ["init", "--initial-branch=main"]);
    std::fs::write(path.join("README.md"), "a repository\n").expect("a tracked file");
    git_out(&path, ["add", "-A"]);
    git_out(&path, ["commit", "-m", "the first commit"]);
    std::fs::write(path.join("README.md"), readme).expect("a dirty file");
    std::fs::write(path.join("notes.txt"), "an untracked file\n").expect("an untracked file");
    path
}

/// Everything Git reports about a repository, and the bytes of every file in its working tree.
#[derive(Debug, PartialEq, Eq)]
struct GitState {
    head: String,
    references: String,
    index: String,
    status: String,
    files: BTreeMap<String, Vec<u8>>,
}

fn git_state(path: &Path) -> GitState {
    fn walk(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(directory).expect("a directory reads") {
            let entry = entry.expect("an entry");
            let path = entry.path();
            if entry.file_name() == ".git" {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .expect("below the root")
                        .display()
                        .to_string(),
                    std::fs::read(&path).expect("a file reads"),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(path, path, &mut files);
    GitState {
        head: git_out(path, ["rev-parse", "HEAD"]),
        references: git_out(path, ["for-each-ref", "--format=%(refname) %(objectname)"]),
        index: git_out(path, ["ls-files", "--stage"]),
        status: git_out(
            path,
            [
                "--no-optional-locks",
                "status",
                "--porcelain=v2",
                "--untracked-files=all",
            ],
        ),
        files,
    }
}

fn include_everything() -> InclusionPolicy {
    InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    }
}

async fn local_mutation<P: serde::Serialize + ?Sized>(
    control: &mut LocalClient,
    host: &Host,
    method: Method,
    params: &P,
) -> ParamsValue {
    control
        .mutate(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
        .unwrap_or_else(|error| panic!("{} is served: {error:?}", method.as_str()))
}

/// Adopts the repository `name` under the host's work directory and selects the user's own tree
/// as a workspace.
async fn workspace_over(
    control: &mut LocalClient,
    host: &Host,
    work: &Path,
    name: &str,
) -> WorkspaceId {
    let adopted: ProjectAdoptResult = typed(
        &local_mutation(
            control,
            host,
            Method::ProjectAdopt,
            &ProjectAdoptParams {
                destination: DestinationRequest {
                    environment_id: host.environment_id,
                    parent: DestinationParent::Host {
                        path: work.display().to_string(),
                    },
                    name: name.to_owned(),
                },
                label: name.to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
        )
        .await,
    );
    let created: WorkspaceCreateResult = typed(
        &local_mutation(
            control,
            host,
            Method::WorkspaceCreate,
            &WorkspaceCreateParams {
                project_repository_id: adopted.project.project_repository_id,
                label: name.to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: Nullable::null(),
                policy: include_everything(),
                base_revision: Nullable::null(),
                base_change_set_id: Nullable::null(),
                destination: Nullable::null(),
                preview_only: false,
            },
        )
        .await,
    );
    created
        .workspace
        .0
        .expect("a creation returns the workspace")
        .workspace_id
}

/// A daemon that holds one session, with a repository it has adopted and a workspace over it.
///
/// The repositories live in a directory of the rig's own, so they outlast a restart of the daemon.
struct Rig {
    host: Host,
    worker: Worker,
    control: LocalClient,
    work: tempfile::TempDir,
    source: PathBuf,
    workspace: WorkspaceId,
}

impl Rig {
    async fn start() -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        // The session's worker is started on the tree while no daemon runs on it, and the daemon
        // that starts next adopts it, as a daemon that restarted adopts the workers it left.
        let stopped = host.shut_down().await;
        let worker = Worker::start(stopped.tree(), 1).await;
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let mut control = host.client().await;
        let work = tempfile::TempDir::new().expect("a working directory on the internal disk");
        let source = repository(work.path(), "source", "changed after the commit\n");
        let workspace = workspace_over(&mut control, &host, work.path(), "source").await;
        Self {
            host,
            worker,
            control,
            work,
            source,
            workspace,
        }
    }

    /// Stops the daemon, lets `between` change what it left on the tree, and starts another that
    /// finds the worker still running.
    async fn restarted(self, between: impl FnOnce(&kr_ipc::testing::TempHost)) -> Self {
        let Self {
            host,
            worker,
            control,
            work,
            source,
            workspace,
        } = self;
        drop(control);
        let stopped = host.shut_down().await;
        between(stopped.tree());
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let control = host.client().await;
        Self {
            host,
            worker,
            control,
            work,
            source,
            workspace,
        }
    }

    /// The session the daemon holds.
    fn session(&self) -> SessionId {
        self.worker.session_id
    }

    /// Captures the workspace into a change set, or into a new one, recorded for `session`.
    async fn capture(
        &mut self,
        change_set_id: Option<ChangeSetId>,
        session: Option<SessionId>,
    ) -> ChangesetCaptureResult {
        let params = ChangesetCaptureParams {
            workspace_id: self.workspace,
            change_set_id: Nullable(change_set_id),
            label: "the work".to_owned(),
            policy: include_everything(),
            grant: FileGrant::default(),
            quiescence_declared: false,
            required_consistency: Nullable::null(),
            pin: false,
            session_id: Nullable(session),
            workflow_run_id: Nullable::null(),
            note: String::new(),
        };
        typed(
            &local_mutation(
                &mut self.control,
                &self.host,
                Method::ChangesetCapture,
                &params,
            )
            .await,
        )
    }

    /// Makes one pass over the change-set store now and waits for it.
    async fn settle(&self) -> Result<(), kr_protocol::error::ProtocolError> {
        let controller = self.host.controller();
        let held = controller.held_sessions();
        controller
            .attention()
            .take_change_sets(controller.changesets().service(), held.as_ref())
            .await
    }

    async fn reviews(&mut self) -> Vec<ReviewState> {
        let read: ReviewReadResult = typed(
            &self
                .control
                .request(
                    Method::ReviewRead,
                    &ReviewReadParams {
                        session_id: Nullable::some(self.session()),
                        subject: Nullable::null(),
                        max_reviews: U64::new(50),
                        after: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("review state reads"),
        );
        read.reviews
    }

    /// Every session's review state, as the owner reads it.
    async fn every_review(&mut self) -> Vec<ReviewState> {
        let read: ReviewReadResult = typed(
            &self
                .control
                .request(
                    Method::ReviewRead,
                    &ReviewReadParams {
                        session_id: Nullable::null(),
                        subject: Nullable::null(),
                        max_reviews: U64::new(50),
                        after: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("review state reads"),
        );
        read.reviews
    }

    /// What changed in one session since the owner's last visit.
    async fn changes_of(&mut self, session_id: SessionId) -> VisitChangedResult {
        typed(
            &self
                .control
                .request(
                    Method::VisitChanged,
                    &VisitChangedParams {
                        session_id,
                        max_changes: U64::new(50),
                        summarise: false,
                    },
                )
                .await
                .expect("the call reaches the daemon")
                .expect("the changed view is served"),
        )
    }

    /// Reads the review state until `done` says it is what the test waits for, each time a pass
    /// over the change-set store has finished.
    async fn reviews_when(&mut self, done: impl Fn(&[ReviewState]) -> bool) -> Vec<ReviewState> {
        let mut passes = self.host.controller().attention().change_set_passes();
        tokio::time::timeout(PATIENCE, async {
            loop {
                let reviews = self.reviews().await;
                if done(&reviews) {
                    return reviews;
                }
                passes.changed().await.expect("the daemon is running");
            }
        })
        .await
        .expect("the review state came to what the test waits for")
    }

    async fn changes(&mut self) -> VisitChangedResult {
        let session_id = self.session();
        self.changes_of(session_id).await
    }

    async fn acknowledge_review(&mut self, subject: &ReviewSubject, version: u64) {
        let session_id = self.session();
        let _: ReviewAcknowledgeResult = typed(
            &local_mutation(
                &mut self.control,
                &self.host,
                Method::ReviewAcknowledge,
                &ReviewAcknowledgeParams {
                    session_id,
                    subject: subject.clone(),
                    version: U64::new(version),
                },
            )
            .await,
        );
    }

    async fn acknowledge_visit(&mut self, cursor: U64) {
        let session_id = self.session();
        let _: VisitAcknowledgeResult = typed(
            &local_mutation(
                &mut self.control,
                &self.host,
                Method::VisitAcknowledge,
                &VisitAcknowledgeParams {
                    session_id,
                    acknowledged_cursor: cursor,
                    views: Vec::new(),
                },
            )
            .await,
        );
    }

    fn subject(&self, change_set_id: ChangeSetId) -> ReviewSubject {
        ReviewSubject::ChangeSet {
            session_id: self.session(),
            change_set_id,
        }
    }
}

fn state_of<'a>(reviews: &'a [ReviewState], subject: &ReviewSubject) -> Option<&'a ReviewState> {
    reviews.iter().find(|state| state.subject == *subject)
}

/// KR-REQ-14.35: a change set captured for a session the daemon holds is review work for that
/// session, reached by the daemon's own pass over the change-set store when the version is
/// recorded, with nothing calling the attention store. A version recorded for a session the daemon
/// does not hold, and one recorded for none, are not review work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_captured_for_a_held_session_is_review_work() {
    let mut rig = Rig::start().await;
    let session = rig.session();
    assert!(
        rig.reviews().await.is_empty(),
        "nothing was captured, so nothing is waiting for review"
    );

    let captured = rig.capture(None, Some(session)).await;
    let subject = rig.subject(captured.version.change_set_id);
    let reviews = rig
        .reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;
    let state = state_of(&reviews, &subject).expect("the change set is a review subject");
    assert_eq!(state.current_version, U64::new(1));
    assert!(state.outstanding, "nobody has reviewed it");
    assert_eq!(state.acknowledged_version, Nullable::null());

    // The controls: a session the daemon does not hold and a capture for none. The pass is made
    // after each capture has been recorded, so a subject that was going to appear has. The owner
    // reads every session's review state, and the invented session's log of changes.
    let unheld = SessionId::new(kr_ipc::new_uuid());
    let _ = rig.capture(None, Some(unheld)).await;
    let _ = rig.capture(None, None).await;
    rig.settle().await.expect("the pass runs");
    assert_eq!(
        rig.every_review().await.len(),
        1,
        "a session this daemon does not hold, and no session, raise nothing"
    );
    assert!(
        rig.changes_of(unheld).await.changes.is_empty(),
        "and the session this daemon does not hold has no change to visit"
    );
    rig.host.stop().await;
}

/// KR-REQ-14.35 and KR-REQ-25.04: a captured version is a change in its session's visit log, and a
/// review acknowledgement binds the version it was made against: a version captured after it is
/// new review work and one more change since the visit, and a pass made twice records one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_version_is_new_review_work_and_one_more_change_since_the_visit() {
    let mut rig = Rig::start().await;
    let session = rig.session();
    let first = rig.capture(None, Some(session)).await;
    let change_set_id = first.version.change_set_id;
    let subject = rig.subject(change_set_id);
    rig.reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;
    rig.settle()
        .await
        .expect("a second pass over the same version");

    let changed = rig.changes().await;
    assert_eq!(
        changed.changes.len(),
        1,
        "one capture is one change, however many passes read it"
    );
    assert_eq!(
        changed.changes[0].kind,
        SemanticChangeKind::ChangeSetCaptured
    );
    assert!(
        changed.changes[0]
            .summary
            .0
            .as_deref()
            .is_some_and(|text| text.contains(&change_set_id.to_string())),
        "the change names the change set in the host's own words"
    );

    rig.acknowledge_review(&subject, 1).await;
    rig.acknowledge_visit(changed.to_cursor).await;
    assert!(rig.changes().await.changes.is_empty(), "the visit saw it");
    assert!(
        !state_of(&rig.reviews().await, &subject)
            .expect("held")
            .outstanding
    );

    let second = rig.capture(Some(change_set_id), Some(session)).await;
    assert_eq!(second.version.version, ChangeSetVersion::new(2));
    let reviews = rig
        .reviews_when(|reviews| {
            state_of(reviews, &subject).is_some_and(|state| state.current_version == U64::new(2))
        })
        .await;
    let state = state_of(&reviews, &subject).expect("held");
    assert_eq!(state.acknowledged_version, Nullable::some(U64::new(1)));
    assert!(
        state.outstanding,
        "an acknowledgement of version 1 does not cover version 2"
    );
    assert_eq!(
        rig.changes().await.changes.len(),
        1,
        "exactly the one capture since the visit"
    );

    rig.acknowledge_review(&subject, 2).await;
    assert!(
        !state_of(&rig.reviews().await, &subject)
            .expect("held")
            .outstanding
    );
    rig.host.stop().await;
}

/// KR-REQ-25.04 and KR-REQ-14.35: acknowledging a review, and visiting, change no Git state of the
/// repository the version was captured from, and promoting the version is a separate action. The
/// control: the same reading of Git, taken before and after an authorised apply of that version to
/// another working copy, reports the difference, so the reading can see what the claim denies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_review_changes_no_git_state_and_an_authorised_apply_does() {
    let mut rig = Rig::start().await;
    let session = rig.session();
    let destination = repository(rig.work.path(), "destination", "another readme\n");
    let destination_workspace =
        workspace_over(&mut rig.control, &rig.host, rig.work.path(), "destination").await;

    let captured = rig.capture(None, Some(session)).await;
    let subject = rig.subject(captured.version.change_set_id);
    rig.reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;

    let source_before = git_state(&rig.source);
    let destination_before = git_state(&destination);
    let changed = rig.changes().await;
    rig.acknowledge_review(&subject, 1).await;
    rig.acknowledge_visit(changed.to_cursor).await;
    let _ = rig.reviews().await;
    assert_eq!(
        git_state(&rig.source),
        source_before,
        "the repository the version came from is as it was"
    );
    assert_eq!(
        git_state(&destination),
        destination_before,
        "and so is every other working copy"
    );

    let applied: DiffApplyResult = typed(
        &local_mutation(
            &mut rig.control,
            &rig.host,
            Method::DiffApply,
            &DiffApplyParams {
                change_set_id: captured.version.change_set_id,
                version: captured.version.version,
                destination: DestinationClass::SharedExisting,
                workspace_id: Nullable::some(destination_workspace),
                expected_reference: Nullable::null(),
                affected: vec![AffectedVersion {
                    path: "README.md".to_owned(),
                    expected_worktree_digest: Nullable::some(kr_changeset::objects::digest_of(
                        b"another readme\n",
                    )),
                    expected_index_object_id: Nullable::null(),
                    expected_index_mode: Nullable::null(),
                    check_index: false,
                }],
                paths: vec!["README.md".to_owned()],
                preflight_only: false,
                acknowledged_limitations: kr_changeset::apply::limitations(
                    DestinationClass::SharedExisting,
                ),
            },
        )
        .await,
    );
    assert_eq!(
        applied.outcome,
        Nullable::some(kr_protocol::changeset::ApplyOutcomeClass::Applied)
    );
    assert_ne!(
        git_state(&destination),
        destination_before,
        "promotion is an action of its own, and the reading sees what it does"
    );
    rig.host.stop().await;
}

/// KR-REQ-14.35: a version derived from a modified materialisation of a reviewed version is new
/// review work: an acknowledgement of the version it came from does not cover it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_derived_version_is_new_review_work() {
    use kr_changeset::{binding, materialise};

    let mut rig = Rig::start().await;
    let session = rig.session();
    let captured = rig.capture(None, Some(session)).await;
    let change_set_id = captured.version.change_set_id;
    let subject = rig.subject(change_set_id);
    rig.reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;
    rig.acknowledge_review(&subject, 1).await;

    // A test run changes its own copy of the version, and the host records what the copy held.
    let service = rig.host.controller().changesets().service().clone();
    let reference = VersionRef {
        change_set_id,
        version: captured.version.version,
    };
    let made = materialise::materialise(
        &service,
        reference,
        kr_protocol::changeset::MaterialisationPurpose::Test,
        "the test copy",
        None,
    )
    .expect("the version is materialised");
    std::fs::write(
        Path::new(&made.directory_path).join("README.md"),
        b"what the test run left\n",
    )
    .expect("the run edits its copy");
    let ended = kr_ipc::now_ms();
    let outputs = materialise::Outputs::none();
    let bound = binding::bind_run(&service, made.materialisation_id, &outputs);
    let result = materialise::record_result(
        &service,
        made.materialisation_id,
        &materialise::RunReport {
            command: "cargo test".to_owned(),
            profile: "the project's test profile".to_owned(),
            tool: kr_protocol::changeset::ToolIdentity {
                name: "cargo".to_owned(),
                version: "1.97.1".to_owned(),
            },
            receipt: kr_protocol::changeset::ExecutionReceipt {
                started_at_ms: kr_protocol::scalars::TimestampMs::new(
                    ended.get().saturating_sub(60_000),
                ),
                ended_at_ms: ended,
                exit_status: Nullable::some(U64::new(0)),
                stopped: false,
                detail: "every test passed".to_owned(),
            },
            outputs: Vec::new(),
        },
        &outputs,
        &bound,
    )
    .expect("the result is recorded");
    let derived = result
        .derived_output_version
        .0
        .expect("a changed copy records the version it held");
    assert_eq!(derived.change_set_id, change_set_id);

    let reviews = rig
        .reviews_when(|reviews| {
            state_of(reviews, &subject)
                .is_some_and(|state| state.current_version == U64::new(derived.version.get()))
        })
        .await;
    let state = state_of(&reviews, &subject).expect("held");
    assert_eq!(state.acknowledged_version, Nullable::some(U64::new(1)));
    assert!(state.outstanding);
    rig.host.stop().await;
}

/// Refuses the attention store's writes of the environment's own semantic source, as a store whose
/// disk is full does.
fn the_attention_store_refuses_the_semantic_source(host: &Host) {
    let store =
        rusqlite::Connection::open(host.attention_database()).expect("opens the attention store");
    store
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    store
        .execute_batch(
            "CREATE TRIGGER refuse_semantic_insert BEFORE INSERT ON attention_consumed
             WHEN NEW.source = 'semantic'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;
             CREATE TRIGGER refuse_semantic_update BEFORE UPDATE ON attention_consumed
             WHEN NEW.source = 'semantic'
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
}

fn the_attention_store_takes_the_semantic_source(host: &Host) {
    let store =
        rusqlite::Connection::open(host.attention_database()).expect("opens the attention store");
    store
        .busy_timeout(Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    store
        .execute_batch(
            "DROP TRIGGER refuse_semantic_insert;
             DROP TRIGGER refuse_semantic_update;",
        )
        .expect("the fault is lifted");
}

/// KR-REQ-14.35: a version the attention store refused to take is not lost. It is review work once
/// the store takes it, by the daemon's own retry and without another capture.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_the_attention_store_refused_is_offered_again() {
    let mut rig = Rig::start().await;
    let session = rig.session();
    the_attention_store_refuses_the_semantic_source(&rig.host);
    let captured = rig.capture(None, Some(session)).await;
    let subject = rig.subject(captured.version.change_set_id);
    rig.settle()
        .await
        .expect_err("the store refuses the version");
    assert!(
        state_of(&rig.reviews().await, &subject).is_none(),
        "a refused write did not happen"
    );

    the_attention_store_takes_the_semantic_source(&rig.host);
    rig.reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;
    assert_eq!(
        rig.changes().await.changes.len(),
        1,
        "and it is one change in the visit log"
    );
    rig.host.stop().await;
}

/// KR-REQ-14.35: a daemon that starts over an attention store older than the change-set store finds
/// the review work the store lacks: the pass at its start reads every change set again, and it is
/// one change in the visit log, not two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_over_an_older_attention_store_finds_the_review_work_it_lacks() {
    let mut rig = Rig::start().await;
    let session = rig.session();
    let earlier = tempfile::tempdir().expect("a directory for the earlier copy");
    let earlier_copy = earlier.path().join("attention.sqlite3");
    // The attention store as it stands before anything was captured.
    rig = rig
        .restarted(|tree| {
            std::fs::copy(
                tree.environment().state_dir().join("attention.sqlite3"),
                &earlier_copy,
            )
            .expect("the earlier copy");
        })
        .await;
    let captured = rig.capture(None, Some(session)).await;
    let subject = rig.subject(captured.version.change_set_id);
    rig.reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;

    // The daemon stops, the attention store is put back as it was, and the daemon starts again.
    rig = rig
        .restarted(|tree| {
            let environment = tree.environment();
            let state = environment.state_dir();
            for suffix in ["-wal", "-shm"] {
                let sidecar = state.join(format!("attention.sqlite3{suffix}"));
                if sidecar.exists() {
                    std::fs::remove_file(&sidecar).expect("the sidecar goes");
                }
            }
            std::fs::copy(&earlier_copy, state.join("attention.sqlite3"))
                .expect("the earlier copy is put back");
        })
        .await;
    rig.reviews_when(|reviews| state_of(reviews, &subject).is_some())
        .await;
    assert_eq!(
        rig.changes().await.changes.len(),
        1,
        "the capture is one change in the visit log again, not two"
    );
    rig.host.stop().await;
}
