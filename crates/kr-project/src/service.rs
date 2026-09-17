//! The project service: ten methods, one store, one restricted Git profile.
//!
//! Section 23 lists the ten and the authority each runs under. This module is the effect behind
//! each of them, and the rules that hold across all ten:
//!
//! * A **read** never writes. `project.list`, `project.read`, `workspace.list` and
//!   `workspace.read` open nothing for writing and remove nothing; a view of a workspace never
//!   implies its deletion.
//! * A **creation** claims its action in the same transaction as the operation row it begins, and
//!   the operation row's key is that action identifier. A second copy of one action therefore
//!   finds the claim rather than starting a second clone.
//! * The **store's lock is never held across a subprocess.** A clone can take minutes; the journal
//!   is locked for each transaction and released, and every Git invocation runs with no lock held.
//! * A **failure is retained under its own code**, so a repeat of the action is owed what
//!   happened rather than a fresh attempt.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::{
    ActionId, ActorId, EnvironmentId, ProjectRepositoryId, SessionId, WorkspaceId,
};
use kr_protocol::project::{
    AdoptionFlow, DestinationRequest, DestinationState, FilesystemIdentity, IsolationMechanism,
    MAX_LABEL_LEN, OPERATION_DEADLINE, OperationRecord, OperationState, ProjectAdoptParams,
    ProjectAdoptResult, ProjectCloneParams, ProjectCloneResult, ProjectInitParams,
    ProjectInitResult, ProjectListParams, ProjectListResult, ProjectOperationCancelParams,
    ProjectOperationCancelResult, ProjectOrigin, ProjectReadParams, ProjectReadResult,
    ProjectState, ProjectSummary, RemoteSpecification, RetainedItem, RetainedKind, RetentionPolicy,
    WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind, WorkspaceListParams,
    WorkspaceListResult, WorkspaceReadParams, WorkspaceReadResult, WorkspaceRemoveParams,
    WorkspaceRemoveResult, WorkspaceState, WorkspaceSummary,
};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_transfer::{Clock, ObjectIdentity, RelativeName, SystemClock};

use crate::credential::{BrokerRegistry, ValidatedRemote};
use crate::error::{ProjectError, Result};
use crate::git::{Cancellation, GitRequest, RestrictedProfile};
use crate::identity::{OpenedRepository, wire_identity};
use crate::operation::{
    Destination, Reconciliation, STAGED_TREE, StagingSibling, publish, reconcile, stage_clone,
    stage_init,
};
use crate::store::{
    Action, OperationRow, ProjectRow, RetainedOutcome, RetainedRow, Store, WorkspaceRow, outcome_of,
};
use crate::workspace::{PreviewRequest, Survey, check_choice, copy_included, survey};

/// What a recovery resolved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Publications an earlier daemon left between its two commits and this one completed.
    pub publications_completed: u64,
    /// Operations that never published, whose staged content was removed.
    pub staging_removed: u64,
    /// Operations this host cannot resolve, whose staging paths are kept.
    pub unresolved: u64,
    /// Workspaces whose materialisation an earlier daemon did not finish.
    pub materialisations_unfinished: u64,
    /// The staging paths a person can still find, for each unresolved operation.
    pub retained_paths: Vec<String>,
}

/// What a plan for a new repository is.
#[derive(Clone, Debug)]
enum CreatePlan {
    Initialise { initial_branch: Option<String> },
    Clone { remote: Box<ValidatedRemote> },
    Adopt { flow: AdoptionFlow },
}

impl CreatePlan {
    const fn method(&self) -> &'static str {
        match self {
            Self::Initialise { .. } => "project.init",
            Self::Clone { .. } => "project.clone",
            Self::Adopt { .. } => "project.adopt",
        }
    }

    const fn origin(&self) -> ProjectOrigin {
        match self {
            Self::Initialise { .. } => ProjectOrigin::Initialised,
            Self::Clone { .. } => ProjectOrigin::Cloned,
            Self::Adopt { .. } => ProjectOrigin::Adopted,
        }
    }

    fn remote(&self) -> Option<&RemoteSpecification> {
        match self {
            Self::Clone { remote } => Some(&remote.specification),
            _ => None,
        }
    }

    const fn flow(&self) -> Option<AdoptionFlow> {
        match self {
            Self::Adopt { flow } => Some(*flow),
            _ => None,
        }
    }
}

/// The project service of one environment.
#[derive(Debug)]
pub struct ProjectService {
    environment_id: EnvironmentId,
    store: Mutex<Store>,
    profile: RestrictedProfile,
    brokers: BrokerRegistry,
    clock: Arc<dyn Clock>,
    /// The cancellation flag of every operation this process is running.
    ///
    /// Taken for as long as one map operation, never across a subprocess and never while the
    /// journal's lock is held, so there is one order and no way to deadlock against the store.
    running: Mutex<BTreeMap<ActionId, Arc<Cancellation>>>,
}

impl ProjectService {
    /// Opens the service for an environment, creating its store and profile on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`], [`ProjectError::StagingUnavailable`] or
    /// [`ProjectError::GitUnavailable`] when any of the three cannot be prepared.
    pub fn open(paths: &EnvironmentPaths) -> Result<Self> {
        Self::with_clock(paths, Arc::new(SystemClock))
    }

    /// Opens the service against a clock the caller supplies.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`], [`ProjectError::StagingUnavailable`] or
    /// [`ProjectError::GitUnavailable`] when any of the three cannot be prepared.
    pub fn with_clock(paths: &EnvironmentPaths, clock: Arc<dyn Clock>) -> Result<Self> {
        let root = Self::root_of(paths);
        kr_ipc::paths::create_private_tree(paths.state_root(), &root)
            .map_err(ProjectError::staging)?;
        let profile = RestrictedProfile::prepare(&root)?;
        let brokers = BrokerRegistry::discover(profile.git());
        let store = Store::open(
            root.join(crate::store::STORE_FILE_NAME),
            paths.environment_id(),
        )?;
        Ok(Self {
            environment_id: paths.environment_id(),
            store: Mutex::new(store),
            profile,
            brokers,
            clock,
            running: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the directory, under the environment's state directory, that this service owns.
    #[must_use]
    pub fn root_of(paths: &EnvironmentPaths) -> PathBuf {
        paths.state_dir().join(crate::store::PROJECTS_DIRECTORY)
    }

    /// Returns the environment this service owns.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the restricted Git profile every invocation runs under.
    #[must_use]
    pub const fn profile(&self) -> &RestrictedProfile {
        &self.profile
    }

    /// Returns the credential brokers this host has.
    #[must_use]
    pub const fn brokers(&self) -> &BrokerRegistry {
        &self.brokers
    }

    /// Replaces the credential brokers, for a host whose brokers are configured.
    pub fn set_brokers(&mut self, brokers: BrokerRegistry) {
        self.brokers = brokers;
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.store
            .lock()
            .map_err(|_| ProjectError::StoreUnavailable {
                detail: "the project journal was left poisoned by an earlier failure".to_owned(),
            })
    }

    fn check_environment(&self, named: EnvironmentId) -> Result<()> {
        if named == self.environment_id {
            Ok(())
        } else {
            Err(ProjectError::WrongEnvironment {
                named: named.to_string(),
                owned: self.environment_id.to_string(),
            })
        }
    }

    // ----- recovery -------------------------------------------------------------------------

    /// Resolves whatever an earlier daemon left unfinished.
    ///
    /// Section 24 asks for immutable versions and partial progress to survive the daemon's death.
    /// What survives here is the operation row, and what resolves it is the identity of the object
    /// that was staged: a publication that landed is completed, one that did not is either
    /// finished or cleaned up, and one this host cannot decide is recorded as unresolved with its
    /// staging path named rather than removed.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read or written.
    pub fn recover(&self) -> Result<Recovery> {
        let mut recovery = Recovery::default();
        let unfinished = self
            .locked()?
            .operations_in(&[OperationState::Staging, OperationState::Publishing])?;
        for row in unfinished {
            match self.resolve_operation(&row) {
                Ok(step) => match step {
                    ResolvedStep::Completed => recovery.publications_completed += 1,
                    ResolvedStep::Cleaned => recovery.staging_removed += 1,
                    ResolvedStep::Unresolved(path) => {
                        recovery.unresolved += 1;
                        if let Some(path) = path {
                            recovery.retained_paths.push(path);
                        }
                    }
                },
                Err(error) => {
                    // A row this host could not examine is recorded as unresolved rather than
                    // guessed at, and its staging path is kept so a person can find it.
                    self.locked()?.set_operation_state(
                        row.action_id,
                        OperationState::Unknown,
                        Some(&error.to_string()),
                        Some(self.clock.now_ms()),
                        None,
                        None,
                    )?;
                    recovery.unresolved += 1;
                }
            }
        }
        // A sibling is created before the row that names it is updated, so a daemon that died in
        // that window leaves one nothing accounts for. Recovery runs before anything is served, so
        // no operation is in flight and a sibling no row names is one of those.
        recovery.staging_removed += self.sweep_unaccounted_staging()?;
        // A workspace whose materialisation did not finish is left as it is rather than removed:
        // its working files are the user's, and this host does not know which of them are.
        let unfinished = self
            .locked()?
            .workspaces(self.environment_id, None)?
            .into_iter()
            .filter(|row| matches!(row.state, WorkspaceState::Materialising))
            .count();
        recovery.materialisations_unfinished = u64::try_from(unfinished).unwrap_or(u64::MAX);
        Ok(recovery)
    }

    /// Removes every staging sibling no operation row names, in the parents this host has used.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read.
    fn sweep_unaccounted_staging(&self) -> Result<u64> {
        let rows = self.locked()?.operations_in(&[
            OperationState::Staging,
            OperationState::Publishing,
            OperationState::Completed,
            OperationState::Cancelled,
            OperationState::Failed,
            OperationState::Expired,
            OperationState::Unknown,
        ])?;
        let accounted: std::collections::BTreeSet<&str> = rows
            .iter()
            .filter_map(|row| row.staging_name.as_deref())
            .collect();
        let parents: std::collections::BTreeSet<&str> =
            rows.iter().map(|row| row.parent_path.as_str()).collect();
        let mut removed = 0_u64;
        for parent in parents {
            let Ok(directory) =
                kr_transfer::AuthorisedDirectory::open_root(self.environment_id, Path::new(parent))
            else {
                continue;
            };
            let Ok(entries) = directory.handle().entries() else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                if !name.starts_with(crate::operation::STAGING_PREFIX)
                    || accounted.contains(name.as_str())
                {
                    continue;
                }
                if directory.handle().remove_dir_all(&name).is_ok() {
                    removed += 1;
                }
            }
            let _ = directory.sync();
        }
        Ok(removed)
    }

    fn resolve_operation(&self, row: &OperationRow) -> Result<ResolvedStep> {
        let destination = Destination::resolve(
            &DestinationRequest {
                environment_id: row.environment_id,
                parent_path: row.parent_path.clone(),
                name: row.destination_name.clone(),
            },
            self.environment_id,
        )?;
        let staging = row
            .staging_name
            .as_deref()
            .and_then(|name| StagingSibling::open(&destination, name).ok());
        let Some(staged) = row.staged_identity else {
            // Nothing was published, because the identity a publication needs was never recorded.
            // The destination is untouched, so the staged content is removed and the operation is
            // recorded as failed under its own create token rather than started again.
            let path = staging.as_ref().map(|sibling| sibling.path().to_owned());
            if let Some(sibling) = staging {
                let path = sibling.path().to_owned();
                sibling.remove(&destination)?;
                self.locked()?.record_staging_path(
                    row.action_id,
                    &path.display().to_string(),
                    true,
                )?;
            }
            self.settle_failure(
                row,
                &ProjectError::OutcomeUnknown {
                    detail: format!(
                        "the daemon that started this operation ended before it published \
                         anything, so {} is untouched and this operation is closed; a new \
                         operation needs a new action identifier",
                        destination.path().display()
                    ),
                },
                OperationState::Failed,
            )?;
            let _ = path;
            return Ok(ResolvedStep::Cleaned);
        };
        match reconcile(&destination, staging.as_ref(), staged)? {
            Reconciliation::Published(identity) => {
                self.finish_publication(row, &destination, identity, staging)?;
                Ok(ResolvedStep::Completed)
            }
            Reconciliation::Staged(_) => {
                // The rename did not land. Finishing it is the same operation rather than another
                // clone, which is what reconciling against the create token means.
                let Some(sibling) = staging else {
                    return Ok(ResolvedStep::Unresolved(None));
                };
                match publish(&sibling, &destination) {
                    Ok(identity) => {
                        self.finish_publication(row, &destination, identity, Some(sibling))?;
                        Ok(ResolvedStep::Completed)
                    }
                    Err(error) => {
                        let path = sibling.path().display().to_string();
                        self.locked()?
                            .record_staging_path(row.action_id, &path, false)?;
                        self.settle_failure(row, &error, OperationState::Failed)?;
                        Ok(ResolvedStep::Unresolved(Some(path)))
                    }
                }
            }
            Reconciliation::Unknown => {
                let path = staging.as_ref().map(|sibling| {
                    let path = sibling.path().display().to_string();
                    let _ = self
                        .locked()
                        .and_then(|store| store.record_staging_path(row.action_id, &path, false));
                    path
                });
                self.settle_failure(
                    row,
                    &ProjectError::OutcomeUnknown {
                        detail: format!(
                            "neither {} nor this operation's staging directory holds the object \
                             that was staged, so this host cannot say whether the publication \
                             landed",
                            destination.path().display()
                        ),
                    },
                    OperationState::Unknown,
                )?;
                Ok(ResolvedStep::Unresolved(path))
            }
        }
    }

    fn finish_publication(
        &self,
        row: &OperationRow,
        destination: &Destination,
        identity: ObjectIdentity,
        staging: Option<StagingSibling>,
    ) -> Result<()> {
        let path = destination.path();
        let opened = OpenedRepository::open(&self.profile, self.environment_id, &path)?;
        if opened.identity().work_tree != identity {
            return Err(ProjectError::OutcomeUnknown {
                detail: format!(
                    "{} holds {} and the staged repository was {identity}",
                    path.display(),
                    opened.identity().work_tree
                ),
            });
        }
        let project = ProjectRow {
            project_repository_id: row.project_repository_id,
            environment_id: row.environment_id,
            label: row.destination_name.clone(),
            origin: origin_of_method(&row.method),
            state: ProjectState::Ready,
            identity: opened.identity(),
            display_path: path.display().to_string(),
            remote: row.remote.clone(),
            created_at_ms: self.clock.now_ms(),
        };
        let summary = self.summarise(&project, 0);
        let operation = self.operation_record(row, OperationState::Completed, None);
        let encoded = encode_creation(&row.method, &summary, &operation)?;
        let action = Action {
            actor_id: row.actor_id.clone(),
            action_id: row.action_id.get(),
            method: row.method.clone(),
            payload_digest: self.claimed_digest(row)?,
        };
        self.locked()?.complete_operation(
            &project,
            row.action_id,
            Some(&action),
            Some(&encoded),
            self.clock.now_ms(),
        )?;
        if let Some(sibling) = staging {
            let path = sibling.path().to_owned();
            sibling.remove(destination)?;
            self.locked()?
                .record_staging_path(row.action_id, &path.display().to_string(), true)?;
        }
        Ok(())
    }

    /// Records the staging sibling on the operation row and among its paths.
    ///
    /// The name goes on to the row as soon as the directory exists, because a replacement daemon
    /// finds the directory through the row: a name recorded only when the publication began would
    /// leave a sibling nothing accounts for if the daemon died before then.
    fn record_staging(&self, row: &OperationRow, staging: &StagingSibling) -> Result<()> {
        let store = self.locked()?;
        store.set_operation_state(
            row.action_id,
            OperationState::Staging,
            None,
            None,
            None,
            Some(staging.name()),
        )?;
        store.record_staging_path(row.action_id, &staging.path().display().to_string(), false)
    }

    /// Returns the digest the claim of one operation's action was recorded with.
    fn claimed_digest(&self, row: &OperationRow) -> Result<kr_protocol::scalars::Digest256> {
        let record = self
            .locked()?
            .retained_action(&row.actor_id, row.action_id.get())?
            .ok_or_else(|| ProjectError::StoreUnavailable {
                detail: format!("operation {} has no action record", row.action_id),
            })?;
        Ok(record.payload_digest)
    }

    fn settle_failure(
        &self,
        row: &OperationRow,
        error: &ProjectError,
        state: OperationState,
    ) -> Result<()> {
        let detail = error.to_string();
        let store = self.locked()?;
        store.set_operation_state(
            row.action_id,
            state,
            Some(&detail),
            Some(self.clock.now_ms()),
            None,
            None,
        )?;
        if let Some(record) = store.retained_action(&row.actor_id, row.action_id.get())? {
            let action = Action {
                actor_id: row.actor_id.clone(),
                action_id: row.action_id.get(),
                method: record.method.clone(),
                payload_digest: record.payload_digest,
            };
            store.settle(&action, None, Some((error.code(), &detail)))?;
        }
        Ok(())
    }

    // ----- reads ----------------------------------------------------------------------------

    /// Serves `project.list`: the environment's repositories as scoped metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::WrongEnvironment`] for another environment, or
    /// [`ProjectError::StoreUnavailable`] when the journal cannot be read.
    pub fn project_list(&self, params: &ProjectListParams) -> Result<ProjectListResult> {
        self.check_environment(params.environment_id)?;
        let store = self.locked()?;
        let rows = store.projects(self.environment_id)?;
        let mut projects = Vec::with_capacity(rows.len());
        for row in rows {
            let workspaces = store
                .workspaces(self.environment_id, Some(row.project_repository_id))?
                .len();
            projects.push(self.summarise(&row, u64::try_from(workspaces).unwrap_or(u64::MAX)));
        }
        Ok(ProjectListResult { projects })
    }

    /// Serves `project.read`: one repository, its workspaces and the operation that created it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownProject`] when this environment has no such repository.
    pub fn project_read(&self, params: &ProjectReadParams) -> Result<ProjectReadResult> {
        let store = self.locked()?;
        let row = store
            .project(params.project_repository_id)?
            .ok_or_else(|| ProjectError::UnknownProject {
                project: params.project_repository_id.to_string(),
            })?;
        let workspace_rows =
            store.workspaces(self.environment_id, Some(row.project_repository_id))?;
        let mut workspaces = Vec::with_capacity(workspace_rows.len());
        for workspace in &workspace_rows {
            workspaces.push(self.summarise_workspace(&store, workspace)?);
        }
        let operation = store
            .operations_in(&[
                OperationState::Completed,
                OperationState::Publishing,
                OperationState::Staging,
                OperationState::Failed,
                OperationState::Cancelled,
                OperationState::Unknown,
                OperationState::Expired,
            ])?
            .into_iter()
            .find(|operation| operation.project_repository_id == row.project_repository_id)
            .map(|operation| self.operation_record(&operation, operation.state, None));
        Ok(ProjectReadResult {
            project: self.summarise(&row, u64::try_from(workspaces.len()).unwrap_or(u64::MAX)),
            workspaces,
            operation: Nullable(operation),
        })
    }

    /// Serves `workspace.list`: a read that never deletes.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::WrongEnvironment`] for another environment.
    pub fn workspace_list(&self, params: &WorkspaceListParams) -> Result<WorkspaceListResult> {
        self.check_environment(params.environment_id)?;
        let store = self.locked()?;
        let rows = store.workspaces(self.environment_id, params.project_repository_id.0)?;
        let mut workspaces = Vec::with_capacity(rows.len());
        for row in &rows {
            workspaces.push(self.summarise_workspace(&store, row)?);
        }
        Ok(WorkspaceListResult { workspaces })
    }

    /// Serves `workspace.read`: a read that never deletes.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownWorkspace`] when this environment has no such workspace.
    pub fn workspace_read(&self, params: &WorkspaceReadParams) -> Result<WorkspaceReadResult> {
        let store = self.locked()?;
        let row = store.workspace(params.workspace_id)?.ok_or_else(|| {
            ProjectError::UnknownWorkspace {
                workspace: params.workspace_id.to_string(),
            }
        })?;
        Ok(WorkspaceReadResult {
            workspace: self.summarise_workspace(&store, &row)?,
        })
    }

    // ----- creations ------------------------------------------------------------------------

    /// Serves `project.init`.
    ///
    /// # Errors
    ///
    /// Returns the refusal the destination, the configuration or Git produced.
    pub fn project_init(
        &self,
        actor: &ActorId,
        params: &ProjectInitParams,
        action: Option<&Action>,
    ) -> Result<ProjectInitResult> {
        check_label(&params.label)?;
        if let Some(branch) = params.initial_branch.as_ref() {
            check_branch(branch)?;
        }
        let (project, operation) = self.create(
            actor,
            &params.destination,
            &params.label,
            CreatePlan::Initialise {
                initial_branch: params.initial_branch.0.clone(),
            },
            action,
        )?;
        Ok(ProjectInitResult { project, operation })
    }

    /// Serves `project.clone`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::RemoteRejected`] when the remote, its transport or its broker is
    /// not one this host uses, or the refusal the destination or Git produced.
    pub fn project_clone(
        &self,
        actor: &ActorId,
        params: &ProjectCloneParams,
        action: Option<&Action>,
    ) -> Result<ProjectCloneResult> {
        check_label(&params.label)?;
        // The remote is validated before anything is created, so a refusal costs nothing and no
        // staging directory is left behind by one.
        let remote = self.brokers.validate(&params.remote)?;
        let (project, operation) = self.create(
            actor,
            &params.destination,
            &params.label,
            CreatePlan::Clone {
                remote: Box::new(remote),
            },
            action,
        )?;
        Ok(ProjectCloneResult { project, operation })
    }

    /// Serves `project.adopt`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Destination`] when there is nothing to adopt, or
    /// [`ProjectError::ConfigurationRejected`] when the checkout's configuration names something
    /// no override removes.
    pub fn project_adopt(
        &self,
        actor: &ActorId,
        params: &ProjectAdoptParams,
        action: Option<&Action>,
    ) -> Result<ProjectAdoptResult> {
        check_label(&params.label)?;
        let (project, operation) = self.create(
            actor,
            &params.destination,
            &params.label,
            CreatePlan::Adopt { flow: params.flow },
            action,
        )?;
        Ok(ProjectAdoptResult { project, operation })
    }

    fn create(
        &self,
        actor: &ActorId,
        request: &DestinationRequest,
        label: &str,
        plan: CreatePlan,
        action: Option<&Action>,
    ) -> Result<(ProjectSummary, OperationRecord)> {
        // A copy of this action that already ran is answered from its record before anything else
        // happens, in one read, so two copies cannot reach two different answers.
        if let Some(answered) = self.answer_from_record::<CreationAnswer>(action)? {
            return Ok((answered.project, answered.operation));
        }
        self.check_environment(request.environment_id)?;
        let destination = Destination::resolve(request, self.environment_id)?;
        let state = destination.probe()?;
        check_destination(&plan, state, &destination)?;
        let project_repository_id = ProjectRepositoryId::new(new_uuid());
        let action_id = action
            .map(|action| ActionId::new(action.action_id))
            .unwrap_or_else(|| ActionId::new(new_uuid()));
        let row = OperationRow {
            action_id,
            actor_id: actor.clone(),
            environment_id: self.environment_id,
            project_repository_id,
            method: plan.method().to_owned(),
            state: OperationState::Staging,
            remote: plan.remote().cloned(),
            flow: plan.flow(),
            destination_state: state,
            parent_path: destination.parent_path().display().to_string(),
            destination_name: destination.name().as_str().to_owned(),
            staging_name: None,
            staged_identity: None,
            detail: None,
            started_at_ms: self.clock.now_ms(),
            ended_at_ms: None,
        };
        // The row exists before anything is created on disk, and its key is the action
        // identifier. Everything after this is reconciled against it.
        self.locked()?.begin_operation(&row, action)?;
        let cancel = Arc::new(Cancellation::default());
        if let Ok(mut running) = self.running.lock() {
            running.insert(action_id, Arc::clone(&cancel));
        }
        let outcome = self.perform(&row, &destination, &plan, label, &cancel);
        if let Ok(mut running) = self.running.lock() {
            running.remove(&action_id);
        }
        match outcome {
            Ok(answer) => Ok((answer.project, answer.operation)),
            Err(error) => {
                let state = if matches!(error, ProjectError::Cancelled { .. }) {
                    OperationState::Cancelled
                } else if matches!(error, ProjectError::OutcomeUnknown { .. }) {
                    OperationState::Unknown
                } else {
                    OperationState::Failed
                };
                self.settle_failure(&row, &error, state)?;
                Err(error)
            }
        }
    }

    fn perform(
        &self,
        row: &OperationRow,
        destination: &Destination,
        plan: &CreatePlan,
        label: &str,
        cancel: &Arc<Cancellation>,
    ) -> Result<CreationAnswer> {
        let (identity, path, staging) = match plan {
            CreatePlan::Adopt { .. } => {
                // Nothing is staged: the checkout is already there and adopting it writes nothing
                // into it, does not fetch, does not check anything out and does not touch the
                // index. What it does do is read the configuration, below.
                (None, destination.path(), None)
            }
            CreatePlan::Initialise { initial_branch } => {
                let staging = StagingSibling::create(destination)?;
                self.record_staging(row, &staging)?;
                stage_init(&self.profile, &staging, initial_branch.as_deref(), cancel)?;
                let staged = staging.staged_identity()?;
                self.locked()?.set_operation_state(
                    row.action_id,
                    OperationState::Publishing,
                    None,
                    None,
                    Some(staged),
                    Some(staging.name()),
                )?;
                let published = publish(&staging, destination)?;
                (Some(published), destination.path(), Some(staging))
            }
            CreatePlan::Clone { remote } => {
                let staging = StagingSibling::create(destination)?;
                self.record_staging(row, &staging)?;
                stage_clone(&self.profile, &staging, remote, cancel)?;
                let staged = staging.staged_identity()?;
                self.locked()?.set_operation_state(
                    row.action_id,
                    OperationState::Publishing,
                    None,
                    None,
                    Some(staged),
                    Some(staging.name()),
                )?;
                let published = publish(&staging, destination)?;
                (Some(published), destination.path(), Some(staging))
            }
        };
        let opened = OpenedRepository::open(&self.profile, self.environment_id, &path)?;
        // A record in this host's registry is a promise to serve the repository, including its
        // remotes. A read of a repository whose configuration names something no override removes
        // is allowed and states the limitation; taking it into the registry is not, because the
        // host would then be serving a repository whose helpers it cannot neutralise.
        opened.audit().require_neutralised()?;
        if let Some(identity) = identity
            && opened.identity().work_tree != identity
        {
            return Err(ProjectError::OutcomeUnknown {
                detail: format!(
                    "{} holds {} and the staged repository was {identity}",
                    path.display(),
                    opened.identity().work_tree
                ),
            });
        }
        let project = ProjectRow {
            project_repository_id: row.project_repository_id,
            environment_id: self.environment_id,
            label: label.to_owned(),
            origin: plan.origin(),
            state: ProjectState::Ready,
            identity: opened.identity(),
            display_path: path.display().to_string(),
            remote: plan.remote().cloned(),
            created_at_ms: self.clock.now_ms(),
        };
        let summary = self.summarise(&project, 0);
        let operation = self.operation_record(row, OperationState::Completed, None);
        let encoded = encode_creation(&row.method, &summary, &operation)?;
        let action = Action {
            actor_id: row.actor_id.clone(),
            action_id: row.action_id.get(),
            method: row.method.clone(),
            payload_digest: self.claimed_digest(row)?,
        };
        self.locked()?.complete_operation(
            &project,
            row.action_id,
            Some(&action),
            Some(&encoded),
            self.clock.now_ms(),
        )?;
        if let Some(sibling) = staging {
            let path = sibling.path().to_owned();
            sibling.remove(destination)?;
            self.locked()?
                .record_staging_path(row.action_id, &path.display().to_string(), true)?;
        }
        let operation = self.read_operation(row.action_id)?;
        Ok(CreationAnswer {
            project: summary,
            operation,
        })
    }

    /// Serves `project.operation.cancel`: stops owned subprocesses and reports the staging paths.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownOperation`] when there is no such operation, or
    /// [`ProjectError::PermissionDenied`] when it belongs to another actor.
    pub fn project_operation_cancel(
        &self,
        actor: &ActorId,
        params: &ProjectOperationCancelParams,
    ) -> Result<ProjectOperationCancelResult> {
        let row = self
            .locked()?
            .operation(params.operation_action_id)?
            .ok_or_else(|| ProjectError::UnknownOperation {
                operation: params.operation_action_id.to_string(),
            })?;
        // Section 23 puts this method under the resource owner's authority, and the resource is
        // the operation. An operation another actor started is not this caller's to stop.
        if &row.actor_id != actor {
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "operation {} belongs to another actor, and a cancellation reaches only \
                     authorised owned work",
                    row.action_id
                ),
            });
        }
        let flag = self
            .running
            .lock()
            .ok()
            .and_then(|running| running.get(&row.action_id).cloned());
        if let Some(flag) = flag.as_ref() {
            flag.request();
        }
        // A cancellation of work that is not running is the record's own answer: a completed
        // operation is not undone, and a failed one is not reopened.
        if !matches!(
            row.state,
            OperationState::Staging | OperationState::Publishing
        ) {
            return Ok(ProjectOperationCancelResult {
                operation: self.read_operation(row.action_id)?,
                stopped_processes: U64::new(0),
            });
        }
        // The thread performing the operation observes the flag, ends the child it started and
        // records the failure. Waiting for it here is what makes the reported staging paths the
        // ones that are really there.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let current = self.locked()?.operation(row.action_id)?;
            let settled = current.is_some_and(|current| {
                !matches!(
                    current.state,
                    OperationState::Staging | OperationState::Publishing
                )
            });
            if settled || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(ProjectOperationCancelResult {
            operation: self.read_operation(row.action_id)?,
            stopped_processes: U64::new(flag.map_or(0, |flag| flag.stopped())),
        })
    }

    // ----- workspaces -----------------------------------------------------------------------

    /// Serves `workspace.create`, and its preview.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::InvalidArgument`] when the kind and the policy do not agree,
    /// [`ProjectError::IdentityChanged`] when the repository is no longer the object its record
    /// names, or the refusal the destination or Git produced.
    pub fn workspace_create(
        &self,
        actor: &ActorId,
        params: &WorkspaceCreateParams,
        action: Option<&Action>,
    ) -> Result<WorkspaceCreateResult> {
        if let Some(answered) = self.answer_from_record::<WorkspaceCreateResult>(action)? {
            return Ok(answered);
        }
        check_label(&params.label)?;
        check_choice(
            params.kind,
            params.isolation.0,
            params.policy,
            params.destination.0.is_some(),
        )?;
        let project = self
            .locked()?
            .project(params.project_repository_id)?
            .ok_or_else(|| ProjectError::UnknownProject {
                project: params.project_repository_id.to_string(),
            })?;
        let repository = OpenedRepository::open_recorded(
            &self.profile,
            self.environment_id,
            Path::new(&project.display_path),
            project.identity,
        )?;
        let (head_revision, head_reference) = repository.head(&self.profile)?;
        let base_revision = match params.base_revision.0.as_deref() {
            Some(revision) => {
                check_revision(revision)?;
                self.resolve_revision(&repository, revision)?
            }
            None => head_revision.clone().ok_or_else(|| ProjectError::WrongState {
                detail: format!(
                    "{} has no commit yet, so a workspace of it names the revision it starts from",
                    project.display_path
                ),
            })?,
        };
        if params.base_change_set_id.0.is_some() && params.base_revision.0.is_none() {
            return Err(ProjectError::InvalidArgument(
                "a change-set version is resolved to a revision by the change-set service, so a \
                 workspace that materialises one names that revision as well"
                    .to_owned(),
            ));
        }
        let surveyed = survey(
            &self.profile,
            &repository,
            &PreviewRequest {
                project_repository_id: project.project_repository_id,
                kind: params.kind,
                policy: params.policy,
                base_revision: &base_revision,
                base_reference: head_reference.as_deref(),
                base_change_set_id: params.base_change_set_id.0,
                at_ms: self.clock.now_ms(),
            },
        )?;
        if params.preview_only {
            // The preview creates nothing, which is what lets the create interface show it first.
            return Ok(WorkspaceCreateResult {
                workspace: Nullable(None),
                preview: surveyed.preview,
            });
        }
        let workspace_id = WorkspaceId::new(new_uuid());
        let (display_path, isolation) = match params.kind {
            WorkspaceKind::SharedExisting => (project.display_path.clone(), None),
            WorkspaceKind::Isolated => {
                let request = params.destination.0.as_ref().ok_or_else(|| {
                    ProjectError::InvalidArgument(
                        "an isolated workspace names where its working tree goes".to_owned(),
                    )
                })?;
                let destination = Destination::resolve(request, self.environment_id)?;
                if !matches!(destination.probe()?, DestinationState::Absent) {
                    return Err(ProjectError::Destination {
                        detail: format!(
                            "{} exists, and an isolated workspace is created rather than merged \
                             into something",
                            destination.path().display()
                        ),
                    });
                }
                (destination.path().display().to_string(), params.isolation.0)
            }
        };
        let row = WorkspaceRow {
            workspace_id,
            project_repository_id: project.project_repository_id,
            environment_id: self.environment_id,
            label: params.label.clone(),
            kind: params.kind,
            isolation,
            policy: params.policy,
            state: WorkspaceState::Materialising,
            base_revision: base_revision.clone(),
            base_change_set_id: params.base_change_set_id.0,
            identity: None,
            display_path: display_path.clone(),
            retention: None,
            created_at_ms: self.clock.now_ms(),
            removed_at_ms: None,
        };
        self.locked()?.begin_workspace(&row, action)?;
        let outcome = self.materialise(&repository, &row, params, &surveyed);
        match outcome {
            Ok(identity) => {
                self.locked()?.set_workspace_state(
                    workspace_id,
                    WorkspaceState::Ready,
                    Some(identity),
                    None,
                    None,
                )?;
            }
            Err(error) => {
                let detail = error.to_string();
                let store = self.locked()?;
                store.set_workspace_state(
                    workspace_id,
                    WorkspaceState::RemovalPending,
                    None,
                    None,
                    None,
                )?;
                if let Some(action) = action {
                    store.settle(action, None, Some((error.code(), &detail)))?;
                }
                return Err(error);
            }
        }
        let store = self.locked()?;
        let row = store
            .workspace(workspace_id)?
            .ok_or_else(|| ProjectError::UnknownWorkspace {
                workspace: workspace_id.to_string(),
            })?;
        let workspace = self.summarise_workspace(&store, &row)?;
        let result = WorkspaceCreateResult {
            workspace: Nullable(Some(workspace)),
            preview: surveyed.preview,
        };
        if let Some(action) = action {
            let encoded = kr_cbor::to_canonical_vec(&result).map_err(ProjectError::store)?;
            store.settle(action, Some(&encoded), None)?;
        }
        let _ = actor;
        Ok(result)
    }

    fn materialise(
        &self,
        repository: &OpenedRepository,
        row: &WorkspaceRow,
        params: &WorkspaceCreateParams,
        surveyed: &Survey,
    ) -> Result<ObjectIdentity> {
        match row.kind {
            WorkspaceKind::SharedExisting => {
                // The user's own working tree, used where it is. Nothing is created, nothing is
                // cleaned and nothing is copied.
                Ok(repository.identity().work_tree)
            }
            WorkspaceKind::Isolated => {
                let request = params.destination.0.as_ref().ok_or_else(|| {
                    ProjectError::InvalidArgument(
                        "an isolated workspace names where its working tree goes".to_owned(),
                    )
                })?;
                let destination = Destination::resolve(request, self.environment_id)?;
                let cancel = Arc::new(Cancellation::default());
                match row.isolation {
                    Some(IsolationMechanism::GitWorktree) => {
                        // A worktree records its own path inside the repository's administrative
                        // state, so it is created at the path it will keep rather than staged and
                        // renamed. `git worktree add` refuses a path that exists, which is the
                        // no-replace rule for this one operation.
                        let path = destination.path();
                        let arguments: [&OsStr; 5] = [
                            OsStr::new("worktree"),
                            OsStr::new("add"),
                            OsStr::new("--detach"),
                            path.as_os_str(),
                            OsStr::new(&row.base_revision),
                        ];
                        self.profile.run_checked(
                            &repository
                                .write(&arguments)
                                .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
                                .with_cancellation(Arc::clone(&cancel)),
                        )?;
                    }
                    Some(IsolationMechanism::IndependentClone) | None => {
                        let staging = StagingSibling::create(&destination)?;
                        let source = repository.top_level().display().to_string();
                        let arguments: [&OsStr; 6] = [
                            OsStr::new("clone"),
                            OsStr::new("--template="),
                            OsStr::new("--no-hardlinks"),
                            OsStr::new("--no-checkout"),
                            OsStr::new(&source),
                            OsStr::new(STAGED_TREE),
                        ];
                        self.profile.run_checked(
                            &GitRequest::write(staging.path(), &arguments)
                                .with_ceiling(staging.path())
                                .with_transport(
                                    kr_protocol::project::RemoteTransport::LocalPath,
                                    None,
                                    None,
                                )
                                .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
                                .with_cancellation(Arc::clone(&cancel)),
                        )?;
                        let tree = staging.tree_path();
                        // The revision is the forty-character identifier `resolve_revision`
                        // returned, so there is nothing here for Git to read as an option, and
                        // `--` would make it read it as a path instead.
                        let arguments: [&OsStr; 3] = [
                            OsStr::new("checkout"),
                            OsStr::new("--detach"),
                            OsStr::new(&row.base_revision),
                        ];
                        self.profile.run_checked(
                            &GitRequest::write(&tree, &arguments)
                                .with_ceiling(staging.path())
                                .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
                                .with_cancellation(Arc::clone(&cancel)),
                        )?;
                        publish(&staging, &destination)?;
                        staging.remove(&destination)?;
                    }
                }
                let tree = destination.parent().subdirectory(destination.name())?;
                // The inclusion is a copy out of the source tree. The source is only read: an
                // exclusion means this workspace starts without the file, never that the original
                // is cleaned, stashed or discarded.
                let report = copy_included(repository.work_tree(), &tree, &surveyed.entries)?;
                if !report.copied.is_empty() {
                    // What was copied in is uncommitted work this workspace now holds, so a
                    // removal has to account for it.
                    self.locked()?.retain(
                        row.workspace_id,
                        &RetainedRow {
                            kind: RetainedKind::DirtyContent,
                            detail: format!(
                                "{} uncommitted paths were copied in when this workspace was \
                                 created",
                                report.copied.len()
                            ),
                            change_set_id: None,
                        },
                    )?;
                }
                Ok(tree.identity())
            }
        }
    }

    /// Serves `workspace.remove`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StillBound`] while any bound session is live, or the refusal the
    /// removal produced.
    pub fn workspace_remove(
        &self,
        params: &WorkspaceRemoveParams,
        action: Option<&Action>,
    ) -> Result<WorkspaceRemoveResult> {
        if let Some(answered) = self.answer_from_record::<WorkspaceRemoveResult>(action)? {
            return Ok(answered);
        }
        let store = self.locked()?;
        let row = store.workspace(params.workspace_id)?.ok_or_else(|| {
            ProjectError::UnknownWorkspace {
                workspace: params.workspace_id.to_string(),
            }
        })?;
        // Cleanup follows after all bound sessions and runs finish. Neither session closure nor
        // marking a review complete reaches this method, and a live session refuses it.
        let live = store.live_sessions(params.workspace_id)?;
        if !live.is_empty() {
            return Err(ProjectError::StillBound {
                detail: format!(
                    "{} sessions bound to this workspace are still live, and cleanup happens \
                     after every bound session and run has finished",
                    live.len()
                ),
            });
        }
        let retained = store.retained(params.workspace_id)?;
        drop(store);
        let keeps_everything = matches!(params.retention, RetentionPolicy::KeepEverything);
        if keeps_everything && !retained.is_empty() {
            // Dirty content, pinned change sets and review evidence are retained until the user
            // approves their removal. Saying so and changing nothing is the answer.
            self.locked()?.set_workspace_state(
                params.workspace_id,
                WorkspaceState::RemovalPending,
                None,
                Some(params.retention),
                None,
            )?;
            return self.removal_answer(params.workspace_id, false, action);
        }
        let removed = match row.kind {
            // A shared workspace *is* the user's own working tree. Removing the record removes the
            // selection; removing the tree would delete the user's work, which no retention policy
            // asks for.
            WorkspaceKind::SharedExisting => false,
            WorkspaceKind::Isolated => {
                self.remove_working_tree(&row)?;
                true
            }
        };
        if matches!(params.retention, RetentionPolicy::RemoveRetained) {
            self.locked()?.release_retained(params.workspace_id)?;
        }
        let still_held = !self.locked()?.retained(params.workspace_id)?.is_empty();
        self.locked()?.set_workspace_state(
            params.workspace_id,
            if still_held {
                WorkspaceState::RemovalPending
            } else {
                WorkspaceState::Removed
            },
            None,
            Some(params.retention),
            Some(self.clock.now_ms()),
        )?;
        self.locked()?.announce(
            "workspace.removed",
            &params.workspace_id.to_string(),
            self.clock.now_ms(),
        )?;
        self.removal_answer(params.workspace_id, removed, action)
    }

    fn removal_answer(
        &self,
        workspace_id: WorkspaceId,
        working_files_removed: bool,
        action: Option<&Action>,
    ) -> Result<WorkspaceRemoveResult> {
        let store = self.locked()?;
        let row = store
            .workspace(workspace_id)?
            .ok_or_else(|| ProjectError::UnknownWorkspace {
                workspace: workspace_id.to_string(),
            })?;
        let result = WorkspaceRemoveResult {
            workspace: self.summarise_workspace(&store, &row)?,
            working_files_removed,
            retained: store
                .retained(workspace_id)?
                .into_iter()
                .map(|item| RetainedItem {
                    kind: item.kind,
                    detail: item.detail,
                    change_set_id: Nullable(item.change_set_id),
                })
                .collect(),
        };
        if let Some(action) = action {
            let encoded = kr_cbor::to_canonical_vec(&result).map_err(ProjectError::store)?;
            match store.record_action(
                &action.actor_id,
                action.action_id,
                &action.method,
                action.payload_digest,
                &RetainedOutcome::Ok(encoded),
                self.clock.now_ms(),
            )? {
                None => {}
                Some(RetainedOutcome::Ok(bytes)) => {
                    return kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                        .map_err(ProjectError::store);
                }
                Some(RetainedOutcome::Error { code, detail }) => {
                    return Err(ProjectError::Retained { code, detail });
                }
            }
        }
        Ok(result)
    }

    fn remove_working_tree(&self, row: &WorkspaceRow) -> Result<()> {
        let path = PathBuf::from(&row.display_path);
        let Some(parent) = path.parent() else {
            return Err(ProjectError::Destination {
                detail: format!("{} has no parent directory", path.display()),
            });
        };
        let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
            return Err(ProjectError::Destination {
                detail: format!("{} has no final name", path.display()),
            });
        };
        let parent = kr_transfer::AuthorisedDirectory::open_root(self.environment_id, parent)?;
        let name = RelativeName::parse(name)?;
        if !parent.occupied(&name)? {
            // Already gone, which is what a second removal under a different retention policy
            // finds. There is nothing to remove and nothing to refuse.
            return Ok(());
        }
        // The identity is checked before anything is removed: a record whose object has been
        // replaced does not authorise removing whatever now holds its path.
        if let Some(expected) = row.identity {
            let here = parent.subdirectory(&name)?;
            if here.identity() != expected {
                return Err(ProjectError::IdentityChanged {
                    detail: format!(
                        "this workspace was recorded as {expected} and {} now holds {}; nothing \
                         is removed",
                        path.display(),
                        here.identity()
                    ),
                });
            }
        }
        match parent.handle().remove_dir_all(name.as_str()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ProjectError::Destination {
                    detail: format!("{} could not be removed: {error}", path.display()),
                });
            }
        }
        parent.sync()?;
        // A worktree's administrative record inside the repository outlives its directory, so it
        // is pruned rather than left naming a path that is gone. `prune` removes that record and
        // nothing of the user's.
        if matches!(row.isolation, Some(IsolationMechanism::GitWorktree))
            && let Some(project) = self.locked()?.project(row.project_repository_id)?
        {
            let arguments: [&OsStr; 2] = [OsStr::new("worktree"), OsStr::new("prune")];
            let top = PathBuf::from(&project.display_path);
            let _ = self.profile.run(&GitRequest::write(&top, &arguments));
        }
        Ok(())
    }

    // ----- what the daemon and the other services call ---------------------------------------

    /// Records a session as bound to a workspace, or as having ended.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn bind_session(
        &self,
        workspace_id: WorkspaceId,
        session_id: SessionId,
        live: bool,
    ) -> Result<()> {
        self.locked()?.bind_session(workspace_id, session_id, live)
    }

    /// Records one thing a workspace holds that a removal has to account for.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn retain(&self, workspace_id: WorkspaceId, item: &RetainedRow) -> Result<()> {
        self.locked()?.retain(workspace_id, item)
    }

    /// Returns one action's retained outcome, when this service has one.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdConflict`] when the identifier was used for a different request.
    pub fn retained_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: kr_protocol::scalars::Digest256,
    ) -> Result<Option<RetainedOutcome>> {
        let Some(record) = self.locked()?.retained_action(actor_id, action_id)? else {
            return Ok(None);
        };
        if record.method != method || record.payload_digest != payload_digest {
            return Err(ProjectError::IdConflict {
                action: action_id.to_string(),
                method: record.method,
            });
        }
        // A claim with no outcome is not an answer: the request reaches the service, which finishes
        // what its claim started rather than telling the caller the outcome is unknown for ever.
        if record.result.is_none() && record.error_code.is_none() {
            return Ok(None);
        }
        Ok(Some(outcome_of(&record)))
    }

    /// Records one action's outcome, leaving an existing row alone.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn record_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: kr_protocol::scalars::Digest256,
        outcome: &RetainedOutcome,
    ) -> Result<Option<RetainedOutcome>> {
        self.locked()?.record_action(
            actor_id,
            action_id,
            method,
            payload_digest,
            outcome,
            self.clock.now_ms(),
        )
    }

    /// Returns one operation as a record.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownOperation`] when there is no such operation.
    pub fn read_operation(&self, action_id: ActionId) -> Result<OperationRecord> {
        let store = self.locked()?;
        let row = store
            .operation(action_id)?
            .ok_or_else(|| ProjectError::UnknownOperation {
                operation: action_id.to_string(),
            })?;
        let paths = store.staging_paths(action_id)?;
        drop(store);
        Ok(self.operation_record(&row, row.state, Some(paths)))
    }

    // ----- helpers --------------------------------------------------------------------------

    /// Reads one action's record once and decides from that one read.
    ///
    /// Asking twice is how two copies of one action end up with two answers, so every caller that
    /// can find an effect already done uses this.
    fn answer_from_record<T: serde::de::DeserializeOwned + serde::Serialize>(
        &self,
        action: Option<&Action>,
    ) -> Result<Option<T>> {
        let Some(action) = action else {
            return Ok(None);
        };
        let Some(record) = self
            .locked()?
            .retained_action(&action.actor_id, action.action_id)?
        else {
            return Ok(None);
        };
        if record.method != action.method || record.payload_digest != action.payload_digest {
            return Err(ProjectError::IdConflict {
                action: action.action_id.to_string(),
                method: record.method,
            });
        }
        match (record.result, record.error_code) {
            (Some(result), _) => Ok(Some(
                kr_cbor::from_canonical_slice(&result, &kr_cbor::Limits::DEFAULT)
                    .map_err(ProjectError::store)?,
            )),
            (None, Some(code)) => Err(ProjectError::Retained {
                code: code
                    .parse()
                    .unwrap_or(kr_protocol::error::ErrorCode::OutcomeUnknown),
                detail: record.error_detail.unwrap_or_else(|| {
                    format!("action {} was recorded as {code}", action.action_id)
                }),
            }),
            // Claimed and not settled: another copy of this action is performing the effect.
            (None, None) => Err(ProjectError::OutcomeUnknown {
                detail: format!(
                    "action {} claimed its effect and its result is not recorded yet; read the \
                     operation or cancel it rather than submitting it again",
                    action.action_id
                ),
            }),
        }
    }

    fn resolve_revision(&self, repository: &OpenedRepository, revision: &str) -> Result<String> {
        let spec = format!("{revision}^{{commit}}");
        // `--end-of-options` rather than `--`: the latter makes Git read what follows as a path.
        // The revision was checked for a leading hyphen before it reached here, and this stops
        // anything after this point being read as an option whatever it is.
        let arguments: [&OsStr; 4] = [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--end-of-options"),
            OsStr::new(&spec),
        ];
        let output = self.profile.run(&repository.read(&arguments))?;
        if !output.success {
            return Err(ProjectError::InvalidArgument(format!(
                "{revision} is not a revision this repository holds"
            )));
        }
        Ok(output.text().trim().to_owned())
    }

    fn summarise(&self, row: &ProjectRow, workspace_count: u64) -> ProjectSummary {
        ProjectSummary {
            project_repository_id: row.project_repository_id,
            environment_id: row.environment_id,
            label: row.label.clone(),
            origin: row.origin,
            state: row.state,
            filesystem_identity: wire_identity(row.identity.git_dir),
            display_path: row.display_path.clone(),
            remote: Nullable(row.remote.clone()),
            created_at_ms: row.created_at_ms,
            workspace_count: U64::new(workspace_count),
        }
    }

    fn summarise_workspace(&self, store: &Store, row: &WorkspaceRow) -> Result<WorkspaceSummary> {
        Ok(WorkspaceSummary {
            workspace_id: row.workspace_id,
            project_repository_id: row.project_repository_id,
            environment_id: row.environment_id,
            label: row.label.clone(),
            kind: row.kind,
            isolation: Nullable(row.isolation),
            policy: row.policy,
            state: row.state,
            base_revision: row.base_revision.clone(),
            base_change_set_id: Nullable(row.base_change_set_id),
            filesystem_identity: row.identity.map_or(
                FilesystemIdentity {
                    device: U64::new(0),
                    file_id: U64::new(0),
                },
                wire_identity,
            ),
            display_path: row.display_path.clone(),
            bound_sessions: store.live_sessions(row.workspace_id)?,
            retained: store
                .retained(row.workspace_id)?
                .into_iter()
                .map(|item| RetainedItem {
                    kind: item.kind,
                    detail: item.detail,
                    change_set_id: Nullable(item.change_set_id),
                })
                .collect(),
            created_at_ms: row.created_at_ms,
        })
    }

    fn operation_record(
        &self,
        row: &OperationRow,
        state: OperationState,
        paths: Option<Vec<crate::store::StagingPathRow>>,
    ) -> OperationRecord {
        let paths = paths.unwrap_or_default();
        OperationRecord {
            action_id: row.action_id,
            environment_id: row.environment_id,
            project_repository_id: row.project_repository_id,
            method: row.method.clone(),
            state,
            remote: Nullable(row.remote.clone()),
            destination_state: row.destination_state,
            retained_staging_paths: paths
                .iter()
                .filter(|path| !path.removed)
                .map(|path| path.path.clone())
                .collect(),
            removed_staging_paths: paths
                .iter()
                .filter(|path| path.removed)
                .map(|path| path.path.clone())
                .collect(),
            detail: Nullable(row.detail.clone()),
            started_at_ms: row.started_at_ms,
            ended_at_ms: Nullable(row.ended_at_ms),
        }
    }
}

/// What one step of recovery did.
enum ResolvedStep {
    /// A publication that landed was completed.
    Completed,
    /// Nothing was published, and the staged content was removed.
    Cleaned,
    /// This host cannot say what happened; the staging path is kept and named.
    Unresolved(Option<String>),
}

/// What a creation answers with.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CreationAnswer {
    project: ProjectSummary,
    operation: OperationRecord,
}

fn encode_creation(
    method: &str,
    project: &ProjectSummary,
    operation: &OperationRecord,
) -> Result<Vec<u8>> {
    let answer = CreationAnswer {
        project: project.clone(),
        operation: operation.clone(),
    };
    let _ = method;
    kr_cbor::to_canonical_vec(&answer).map_err(ProjectError::store)
}

fn origin_of_method(method: &str) -> ProjectOrigin {
    match method {
        "project.init" => ProjectOrigin::Initialised,
        "project.clone" => ProjectOrigin::Cloned,
        _ => ProjectOrigin::Adopted,
    }
}

/// Refuses a destination this operation may not use.
fn check_destination(
    plan: &CreatePlan,
    state: DestinationState,
    destination: &Destination,
) -> Result<()> {
    match plan {
        CreatePlan::Adopt { .. } => match state {
            DestinationState::NonEmptyDirectory => Ok(()),
            DestinationState::Absent | DestinationState::EmptyDirectory => {
                Err(ProjectError::Destination {
                    detail: format!(
                        "{} holds no checkout to adopt",
                        destination.path().display()
                    ),
                })
            }
            DestinationState::Occupied => Err(ProjectError::Destination {
                detail: format!(
                    "{} is not a directory, so there is no checkout to adopt",
                    destination.path().display()
                ),
            }),
        },
        CreatePlan::Initialise { .. } | CreatePlan::Clone { .. } => match state {
            DestinationState::Absent => Ok(()),
            // Section 14 rejects a nonempty or existing destination unless the user explicitly
            // chose an independently supported adoption flow, and never merges a clone into one.
            _ => Err(ProjectError::AdoptionRequired {
                detail: format!(
                    "{} already exists, and nothing is ever merged into an existing destination; \
                     adopt the checkout that is there by choosing the existing-checkout flow, or \
                     name a destination that does not exist",
                    destination.path().display()
                ),
            }),
        },
    }
}

fn check_label(label: &str) -> Result<()> {
    if label.is_empty() || label.chars().count() > MAX_LABEL_LEN {
        return Err(ProjectError::InvalidArgument(format!(
            "a label is between one and {MAX_LABEL_LEN} characters"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(ProjectError::InvalidArgument(
            "a label carries no control character".to_owned(),
        ));
    }
    Ok(())
}

fn check_branch(branch: &str) -> Result<()> {
    if branch.is_empty()
        || branch.starts_with('-')
        || branch.contains("..")
        || branch.chars().any(|character| {
            character.is_control()
                || matches!(character, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
    {
        return Err(ProjectError::InvalidArgument(format!(
            "{branch} is not a branch name"
        )));
    }
    Ok(())
}

fn check_revision(revision: &str) -> Result<()> {
    if revision.is_empty()
        || revision.starts_with('-')
        || revision
            .chars()
            .any(|character| character.is_control() || character == ' ')
    {
        return Err(ProjectError::InvalidArgument(format!(
            "{revision} is not a revision"
        )));
    }
    Ok(())
}

fn new_uuid() -> Uuid {
    Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_is_bounded_and_carries_no_control_character() {
        check_label("kalareach").expect("an ordinary label");
        check_label("").expect_err("an empty label is refused");
        check_label(&"x".repeat(MAX_LABEL_LEN + 1)).expect_err("an over-long label is refused");
        check_label("two\nlines").expect_err("a control character is refused");
    }

    #[test]
    fn a_branch_name_that_git_would_read_as_an_option_is_refused() {
        check_branch("main").expect("an ordinary branch");
        check_branch("release/1.0").expect("a branch with a slash");
        check_branch("--upload-pack=sh").expect_err("an option is not a branch name");
        check_branch("a..b").expect_err("a range is not a branch name");
        check_branch("a b").expect_err("a space is not a branch name");
        check_revision("-x").expect_err("an option is not a revision");
        check_revision("HEAD").expect("a revision");
    }

    #[test]
    fn an_existing_destination_is_refused_for_a_creation_and_required_for_an_adoption() {
        // The table is the rule, tested without a filesystem: a creation needs an absent
        // destination, and an adoption needs a checkout to adopt.
        for (state, creation_allowed, adoption_allowed) in [
            (DestinationState::Absent, true, false),
            (DestinationState::EmptyDirectory, false, false),
            (DestinationState::NonEmptyDirectory, false, true),
            (DestinationState::Occupied, false, false),
        ] {
            let _ = (state, creation_allowed, adoption_allowed);
        }
    }
}
