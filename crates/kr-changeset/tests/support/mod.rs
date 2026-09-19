//! What the change-set tests build their repositories and services out of.
//!
//! Everything lives on the internal disk: the host tree, the repositories, both journals and every
//! materialisation. A repository is built with plain installed Git rather than through the
//! restricted profile, because the profile refuses the subcommands a fixture needs (`add`,
//! `commit`) and that refusal is one of the things the project service exists for.

// Each test binary compiles this module on its own and uses the part of it it needs.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use kr_changeset::ChangeSetService;
use kr_changeset::capture::CaptureRequest;
use kr_changeset::service::CaptureOrder;
use kr_ipc::testing::TempHost;
use kr_project::ProjectService;
use kr_protocol::changeset::{
    ChangeSetVersionRecord, FileGrant, Provenance, SourceConsistency, VersionRef,
};
use kr_protocol::ids::{ActorId, ProjectRepositoryId, WorkspaceId};
use kr_protocol::project::{
    AdoptionFlow, DestinationRequest, InclusionChoice, InclusionPolicy, ProjectAdoptParams,
    WorkspaceCreateParams, WorkspaceKind,
};
use kr_protocol::scalars::Nullable;

/// A host tree with both services open on it.
pub struct Fixture {
    host: TempHost,
    project: Arc<ProjectService>,
    changesets: ChangeSetService,
    work: tempfile::TempDir,
}

impl Fixture {
    /// Opens a fresh host and both services.
    #[must_use]
    pub fn create() -> Self {
        Self::with_interposition(None)
    }

    /// Opens a fresh host whose Git invocations run something first.
    ///
    /// The seam fires immediately before each Git child, which is where a test that has to change
    /// the working tree *while a capture is reading it* has to act: the capture reads the index
    /// and the status, reads the content, and reads both again, and the interposition is the only
    /// place a test can get between them.
    #[must_use]
    pub fn with_interposition(interposition: Option<kr_project::git::Interposition>) -> Self {
        let host = TempHost::create();
        let mut service =
            ProjectService::open(&host.environment()).expect("the project service opens");
        if let Some(interposition) = interposition {
            service.interpose(interposition);
        }
        let project = Arc::new(service);
        let changesets = ChangeSetService::open(&host.environment(), Arc::clone(&project))
            .expect("the change-set service opens");
        let work = tempfile::TempDir::new().expect("a working directory on the internal disk");
        Self {
            host,
            project,
            changesets,
            work,
        }
    }

    /// Returns the change-set service.
    #[must_use]
    pub const fn service(&self) -> &ChangeSetService {
        &self.changesets
    }

    /// Returns the project service.
    #[must_use]
    pub const fn project(&self) -> &Arc<ProjectService> {
        &self.project
    }

    /// Reopens the change-set service on the same environment, the way a replacement daemon does.
    #[must_use]
    pub fn reopen(&self) -> ChangeSetService {
        ChangeSetService::open(&self.host.environment(), Arc::clone(&self.project))
            .expect("a replacement change-set service opens")
    }

    /// Returns the directory repositories are built in.
    #[must_use]
    pub fn work(&self) -> &Path {
        self.work.path()
    }

    /// Returns the environment this host owns.
    #[must_use]
    pub fn environment_id(&self) -> kr_protocol::ids::EnvironmentId {
        self.host.environment_id()
    }

    /// Adopts a repository at `name` and selects the user's own working tree as a workspace.
    #[must_use]
    pub fn workspace(&self, name: &str) -> WorkspaceId {
        let project = self.adopt(name);
        self.shared_workspace(project, name)
    }

    /// Adopts the checkout at `name`.
    #[must_use]
    pub fn adopt(&self, name: &str) -> ProjectRepositoryId {
        self.project
            .project_adopt(
                &actor(),
                &ProjectAdoptParams {
                    destination: destination(self.environment_id(), self.work(), name),
                    label: name.to_owned(),
                    flow: AdoptionFlow::ExistingCheckout,
                },
                Some(&action(&format!("project.adopt:{name}"))),
            )
            .expect("the checkout is adopted")
            .project
            .project_repository_id
    }

    /// Selects the user's own working tree as a workspace.
    #[must_use]
    pub fn shared_workspace(&self, project: ProjectRepositoryId, name: &str) -> WorkspaceId {
        self.project
            .workspace_create(
                &actor(),
                &WorkspaceCreateParams {
                    project_repository_id: project,
                    label: name.to_owned(),
                    kind: WorkspaceKind::SharedExisting,
                    isolation: Nullable(None),
                    policy: include_everything(),
                    base_revision: Nullable(None),
                    base_change_set_id: Nullable(None),
                    destination: Nullable(None),
                    preview_only: false,
                },
                Some(&action(&format!("workspace.create:{name}"))),
            )
            .expect("the workspace is created")
            .workspace
            .0
            .expect("a creation returns one")
            .workspace_id
    }

    /// Captures one version of a workspace under a policy.
    ///
    /// # Panics
    ///
    /// Panics when the capture fails.
    #[must_use]
    pub fn capture(
        &self,
        workspace_id: WorkspaceId,
        policy: &InclusionPolicy,
    ) -> ChangeSetVersionRecord {
        self.capture_with(workspace_id, policy, &FileGrant::default(), None, None)
            .expect("the capture succeeds")
    }

    /// Captures one version with a quiescence declaration.
    ///
    /// # Errors
    ///
    /// Returns whatever the capture returns.
    pub fn capture_declaring_quiescence(
        &self,
        workspace_id: WorkspaceId,
    ) -> kr_changeset::Result<ChangeSetVersionRecord> {
        let policy = include_everything();
        let grant = FileGrant::default();
        let order = CaptureOrder {
            workspace_id,
            change_set_id: None,
            label: "the work",
            request: CaptureRequest {
                policy: &policy,
                grant: &grant,
                quiescence_declared: true,
                required_consistency: None,
            },
            pin: false,
            provenance: provenance(),
        };
        self.changesets.capture(&order).map(|(record, _)| record)
    }

    /// Captures one version, with every knob the tests turn.
    ///
    /// # Errors
    ///
    /// Returns whatever the capture returns.
    pub fn capture_with(
        &self,
        workspace_id: WorkspaceId,
        policy: &InclusionPolicy,
        grant: &FileGrant,
        change_set_id: Option<kr_protocol::ids::ChangeSetId>,
        required: Option<SourceConsistency>,
    ) -> kr_changeset::Result<ChangeSetVersionRecord> {
        let order = CaptureOrder {
            workspace_id,
            change_set_id,
            label: "the work",
            request: CaptureRequest {
                policy,
                grant,
                quiescence_declared: false,
                required_consistency: required,
            },
            pin: false,
            provenance: provenance(),
        };
        self.changesets.capture(&order).map(|(record, _)| record)
    }
}

/// The order one apply is performed under, with everything a test usually leaves alone.
///
/// # Panics
///
/// Panics when the version cannot be read.
#[must_use]
pub fn apply_order<'a>(
    version: VersionRef,
    destination: kr_protocol::changeset::DestinationClass,
    workspace_id: WorkspaceId,
    affected: &'a [kr_protocol::changeset::AffectedVersion],
    acknowledged: &'a [String],
) -> kr_changeset::apply::ApplyOrder<'a> {
    kr_changeset::apply::ApplyOrder {
        action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        version,
        destination,
        workspace_id: Some(workspace_id),
        expected_reference: None,
        affected,
        paths: &[],
        preflight_only: false,
        acknowledged_limitations: acknowledged,
        revert: false,
        provenance: provenance(),
    }
}

/// What the request expects each path to hold, read from the destination's own files.
///
/// A path that is not there is expected to be absent, which is what a request that adds a file
/// says.
#[must_use]
pub fn expectations(root: &Path, paths: &[&str]) -> Vec<kr_protocol::changeset::AffectedVersion> {
    paths
        .iter()
        .map(|path| kr_protocol::changeset::AffectedVersion {
            path: (*path).to_owned(),
            expected_worktree_digest: Nullable(
                std::fs::read(root.join(path))
                    .ok()
                    .map(|bytes| kr_changeset::objects::digest_of(&bytes)),
            ),
            expected_index_object_id: Nullable(None),
            check_index: false,
        })
        .collect()
}

/// The digest of one file in one tree.
///
/// # Panics
///
/// Panics when the file cannot be read.
#[must_use]
pub fn digest_of_file(root: &Path, relative: &str) -> kr_protocol::scalars::Digest256 {
    kr_changeset::objects::digest_of(&read_bytes(root, relative))
}

/// The provenance every test's capture carries.
#[must_use]
pub fn provenance() -> Provenance {
    Provenance {
        actor_id: actor(),
        method: "changeset.capture".to_owned(),
        session_id: Nullable(None),
        workflow_run_id: Nullable(None),
        derived_from: Nullable(None),
        derivation: String::new(),
        note: "a test".to_owned(),
    }
}

/// The version one record names.
#[must_use]
pub const fn reference(record: &ChangeSetVersionRecord) -> VersionRef {
    VersionRef {
        change_set_id: record.change_set_id,
        version: record.version,
    }
}

/// The principal every test acts as.
#[must_use]
pub fn actor() -> ActorId {
    ActorId::new("local:test").expect("a valid principal")
}

/// One action, named by what it does so two of them never collide.
#[must_use]
pub fn action(method: &str) -> kr_project::store::Action {
    kr_project::store::Action {
        actor_id: actor(),
        action_id: kr_ipc::new_uuid(),
        method: method.to_owned(),
        payload_digest: kr_changeset::objects::digest_of(method.as_bytes()),
    }
}

/// A destination a project method names.
#[must_use]
pub fn destination(
    environment_id: kr_protocol::ids::EnvironmentId,
    parent: &Path,
    name: &str,
) -> DestinationRequest {
    DestinationRequest {
        environment_id,
        parent_path: parent.display().to_string(),
        name: name.to_owned(),
    }
}

/// The policy that captures everything uncommitted.
#[must_use]
pub const fn include_everything() -> InclusionPolicy {
    InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    }
}

/// Runs installed Git directly, for building a fixture.
///
/// # Panics
///
/// Panics when the invocation fails, which in a test means the fixture could not be built.
pub fn git_raw<I, S>(directory: &Path, arguments: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments: Vec<std::ffi::OsString> = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    let output = Command::new("git")
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
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "git {arguments:?} in {} failed: {}",
        directory.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Builds an ordinary repository with one commit.
///
/// # Panics
///
/// Panics when the repository cannot be built.
pub fn ordinary_repository(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir_all(&path).expect("a directory for the repository");
    git_raw(&path, ["init", "--initial-branch=main"]);
    write(&path, "README.md", "a repository\n");
    write(&path, "src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "the first commit"]);
    path
}

/// Writes one file, creating the directories above it.
///
/// # Panics
///
/// Panics when the file cannot be written.
pub fn write(root: &Path, relative: &str, contents: &str) {
    write_bytes(root, relative, contents.as_bytes());
}

/// Writes one file of bytes, creating the directories above it.
///
/// # Panics
///
/// Panics when the file cannot be written.
pub fn write_bytes(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the directories above the file");
    }
    std::fs::write(&path, contents).expect("the file is written");
}

/// Reads one file's bytes.
///
/// # Panics
///
/// Panics when the file cannot be read.
#[must_use]
pub fn read_bytes(root: &Path, relative: &str) -> Vec<u8> {
    std::fs::read(root.join(relative))
        .unwrap_or_else(|error| panic!("{relative} could not be read: {error}"))
}

/// Returns true when one file is executable.
#[cfg(unix)]
#[must_use]
pub fn is_executable(root: &Path, relative: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(root.join(relative))
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Makes one file executable.
#[cfg(unix)]
pub fn make_executable(root: &Path, relative: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = root.join(relative);
    let mut permissions = std::fs::metadata(&path)
        .expect("the file is there")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("the mode is set");
}

/// Returns the captured path with this name, or fails the test.
///
/// # Panics
///
/// Panics when the record does not name the path.
#[must_use]
pub fn change<'a>(
    record: &'a ChangeSetVersionRecord,
    path: &str,
) -> &'a kr_protocol::changeset::CapturedPath {
    record
        .changes
        .iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| {
            panic!(
                "the version names {path} as a change; it names {:?}",
                record
                    .changes
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

/// Returns the exclusion for one path, or fails the test.
///
/// # Panics
///
/// Panics when the record does not exclude the path.
#[must_use]
pub fn exclusion<'a>(
    record: &'a ChangeSetVersionRecord,
    path: &str,
) -> &'a kr_protocol::changeset::Exclusion {
    record
        .exclusions
        .iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| {
            panic!(
                "the version excludes {path}; it excludes {:?}",
                record
                    .exclusions
                    .iter()
                    .map(|entry| entry.path.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

/// Fails the test unless nothing at all is at the path, and says what it found instead.
///
/// `Path::exists` answers false when the platform will not say and follows a link, so an
/// assertion that something was removed has to ask about the name itself.
///
/// # Panics
///
/// Panics when something is at the path, and when the platform will not say whether anything is.
pub fn assert_absent(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(found) => panic!("{} still holds {:?}", path.display(), found.file_type()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "whether {} is there could not be established: {error}",
            path.display()
        ),
    }
}
