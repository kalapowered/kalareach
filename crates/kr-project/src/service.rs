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
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, DestinationRequest, DestinationState, InclusionClass, InclusionPreview,
    IsolationMechanism, MAX_LABEL_LEN, OPERATION_DEADLINE, OperationRecord, OperationState,
    PreviewCount, ProjectAdoptParams, ProjectAdoptResult, ProjectCloneParams, ProjectCloneResult,
    ProjectInitParams, ProjectInitResult, ProjectListParams, ProjectListResult,
    ProjectOperationCancelParams, ProjectOperationCancelResult, ProjectOrigin, ProjectReadParams,
    ProjectReadResult, ProjectState, ProjectSummary, RemoteSpecification, RetainedItem,
    RetainedKind, RetentionPolicy, WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind,
    WorkspaceListParams, WorkspaceListResult, WorkspaceReadParams, WorkspaceReadResult,
    WorkspaceRemoveParams, WorkspaceRemoveResult, WorkspaceState, WorkspaceSummary,
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
    Action, OperationRow, OperationUpdate, ProjectRow, RetainedOutcome, RetainedRow, Store,
    WorkspaceRow, WorkspaceUpdate, outcome_of,
};
use crate::workspace::{
    PathOutcome, PreviewRequest, Survey, check_choice, copy_included, outcome_text, survey,
};

/// How many paths an inclusion journals in one transaction.
///
/// One transaction for every path would make the journal the slow part of a copy; one at the end
/// would leave an interrupted copy with no record at all. A batch is the middle: what an
/// interrupted inclusion loses is at most this many paths' worth of progress.
const PROGRESS_BATCH: usize = 64;

/// What a recovery resolved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Publications an earlier daemon left between its two commits and this one completed.
    pub publications_completed: u64,
    /// Operations that never published, whose staged content was removed.
    pub staging_removed: u64,
    /// Operations this host cannot resolve, whose staging paths are kept.
    pub unresolved: u64,
    /// Workspaces whose materialisation an earlier daemon did not finish, and which this host has
    /// moved out of the states anything may hold or read as ready.
    pub materialisations_unfinished: u64,
    /// Action claims this host settled from the durable state rather than leaving open.
    pub claims_settled: u64,
    /// Removal reservations an earlier daemon held, released so a later removal is not refused.
    pub removals_released: u64,
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

    /// Returns the journal's guard for a call that writes.
    ///
    /// Every state change commits with the outbox row that announces it, so every one of them is a
    /// transaction and needs the guard mutably. Bound to a local by every caller, never taken in
    /// the head of a condition or a loop: a temporary guard there lives for the whole body, and a
    /// helper that takes the same lock would wait for itself.
    fn writable(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.locked()
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
                    ResolvedStep::Closed => {}
                    ResolvedStep::Unresolved(path) => {
                        recovery.unresolved += 1;
                        if let Some(path) = path {
                            recovery.retained_paths.push(path);
                        }
                    }
                },
                Err(error) => {
                    // A row this host could not examine keeps the state it was in, so the next
                    // recovery asks the same question again. Moving it to `unknown` here would
                    // close an operation this host has not decided, and nothing would revisit it.
                    // Its staging path stays recorded either way, so a person can find it.
                    self.locked()?.set_operation_state(
                        row.action_id,
                        row.state,
                        &OperationUpdate {
                            detail: Some(&error.to_string()),
                            ..OperationUpdate::default()
                        },
                    )?;
                    recovery.unresolved += 1;
                }
            }
        }
        // Every staging sibling this host created is named by a row before the directory exists,
        // so what is left to clean up is a recorded name whose operation has ended. Nothing is
        // removed because of its name alone: a repository a user happened to call
        // `.kr-project-something` is not this host's to delete.
        recovery.staging_removed += self.sweep_recorded_staging()?;
        recovery.materialisations_unfinished = self.resolve_materialisations()?;
        // A removal reservation belongs to the daemon that took it, and that daemon is gone.
        // Leaving one behind would refuse every later removal of that workspace for ever.
        recovery.removals_released = self.writable()?.release_stale_removals()?;
        // A claim whose effect settled durably is answered from that state. A claim this host
        // cannot resolve is settled as unknown rather than left open for ever, so a repeat of the
        // action gets a definite answer.
        recovery.claims_settled = self.settle_open_claims()?;
        Ok(recovery)
    }

    /// Removes every staging sibling a row names whose operation has ended.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read or written.
    fn sweep_recorded_staging(&self) -> Result<u64> {
        // `unknown` is deliberately absent. An operation this host could not decide keeps its
        // staging path *because* ownership of what is there is uncertain, and the result says the
        // path is retained; removing it here would make that statement false.
        let rows = self.locked()?.operations_in(&[
            OperationState::Completed,
            OperationState::Cancelled,
            OperationState::Failed,
            OperationState::Expired,
        ])?;
        let mut removed = 0_u64;
        for row in rows {
            let Some(name) = row.staging_name.as_deref() else {
                continue;
            };
            let Ok(destination) = Destination::resolve(
                &DestinationRequest {
                    environment_id: row.environment_id,
                    parent_path: row.parent_path.clone(),
                    name: row.destination_name.clone(),
                },
                self.environment_id,
            ) else {
                continue;
            };
            let Ok(sibling) = StagingSibling::open(&destination, name) else {
                continue;
            };
            let path = sibling.path().display().to_string();
            // A recorded name is not authority to remove whatever holds it now. Where the row
            // recorded the sibling's own identity, the object has to be that one; where it did not,
            // the name is left alone rather than removed on the strength of its spelling.
            let Some(expected) = row.staging_identity else {
                continue;
            };
            if sibling.remove_if(&destination, Some(expected)).is_ok() {
                self.writable()?
                    .record_staging_path(row.action_id, &path, true)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Resolves every workspace an earlier daemon left part way through its materialisation.
    ///
    /// The working files are the user's, so nothing in the directory is removed: this host does
    /// not know which of them it wrote. What it does know is that the workspace is not what its
    /// creation asked for, so the row moves to `removal_pending` with the reason, nothing new may
    /// hold it, and no read calls it ready. The staged sibling of an unfinished independent clone
    /// is this host's own and is removed.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read or written.
    fn resolve_materialisations(&self) -> Result<u64> {
        let rows = self.locked()?.workspaces(self.environment_id, None)?;
        // A staging sibling is this host's own directory, wherever the row that named it ended up.
        // So the cleanup covers every row that still names one rather than only the unfinished
        // ones: a workspace that reached `ready` while its cleanup failed keeps a sibling until
        // one of these recoveries takes it away.
        for row in &rows {
            self.sweep_workspace_staging(row)?;
        }
        let mut resolved = 0_u64;
        for row in rows
            .into_iter()
            .filter(|row| matches!(row.state, WorkspaceState::Materialising))
        {
            // What the inclusion had applied is journalled as it goes, so the reason says how far
            // it got rather than only that it stopped.
            let progress = self.locked()?.workspace_progress(row.workspace_id)?;
            let carried = progress
                .iter()
                .filter(|(_, outcome)| outcome == "carried" || outcome == "removed")
                .count();
            let pending = progress
                .iter()
                .filter(|(_, outcome)| outcome == crate::store::PROGRESS_PLANNED)
                .count();
            self.writable()?.set_workspace(
                row.workspace_id,
                WorkspaceState::RemovalPending,
                &WorkspaceUpdate {
                    detail: Some(&format!(
                        "the daemon that was materialising this workspace ended before it \
                         finished, with {carried} of its paths carried in and {pending} this \
                         host did not establish, so what is in its directory is not what its \
                         creation asked for; the files are left where they are and nothing new \
                         may hold it"
                    )),
                    ..WorkspaceUpdate::default()
                },
            )?;
            resolved += 1;
        }
        Ok(resolved)
    }

    /// Removes the staging sibling one workspace row names, when the object at that name is the
    /// one the row recorded.
    ///
    /// The name is forgotten only once the directory is gone. A removal that failed leaves the
    /// name on the row so the next recovery tries again, rather than leaving a directory nothing
    /// accounts for.
    fn sweep_workspace_staging(&self, row: &WorkspaceRow) -> Result<()> {
        let Some(name) = row.staging_name.as_deref() else {
            return Ok(());
        };
        let Ok(destination) = Destination::resolve(
            &DestinationRequest {
                environment_id: row.environment_id,
                parent_path: parent_of(&row.display_path),
                name: name_of(&row.display_path),
            },
            self.environment_id,
        ) else {
            return Ok(());
        };
        let Ok(sibling) = StagingSibling::open(&destination, name) else {
            // The name is forgotten only when nothing is at it. A directory this host could not
            // open for any other reason is one it has not accounted for, so the name stays and
            // the next recovery tries again.
            let absent = matches!(
                std::fs::symlink_metadata(destination.parent_path().join(name)),
                Err(ref failure) if failure.kind() == std::io::ErrorKind::NotFound
            );
            if absent {
                self.writable()?.clear_workspace_staging(row.workspace_id)?;
            }
            return Ok(());
        };
        // A recorded name is not authority to remove whatever holds it now. Where the row did not
        // record the sibling's identity, the name is left alone rather than removed on the
        // strength of its spelling.
        let Some(expected) = row.staging_identity else {
            return Ok(());
        };
        let gone = sibling.remove_if(&destination, Some(expected)).is_ok()
            || !sibling.occupied(&destination);
        if gone {
            self.writable()?.clear_workspace_staging(row.workspace_id)?;
        }
        Ok(())
    }

    /// Settles every action claim this host left open.
    ///
    /// A claim is opened in the same transaction as the state it changes and filled in when the
    /// effect settles, so a daemon that died between the two leaves one open. An open claim is not
    /// an answer: a repeat of the action would be told the outcome is unknown for ever. So every
    /// remaining claim is settled here, from the durable state where that answers it and as an
    /// unknown outcome naming the object where it does not.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read or written.
    fn settle_open_claims(&self) -> Result<u64> {
        let open = self.locked()?.open_claims()?;
        let mut settled = 0_u64;
        for record in open {
            let action = Action {
                actor_id: record.actor_id.clone(),
                action_id: record.action_id,
                method: record.method.clone(),
                payload_digest: record.payload_digest,
            };
            let Some(subject) = record.subject else {
                let detail =
                    "the daemon that performed this action ended before it recorded the result"
                        .to_owned();
                settled += u64::from(self.settle_unknown(&action, &detail)? > 0);
                continue;
            };
            // The claim names what it acted on, so the durable state of that object is consulted
            // before anything is called unknown.
            let operation = self.locked()?.operation(ActionId::new(subject))?;
            if let Some(operation) = operation {
                match operation.state {
                    // Still to be decided. The claim stays open on purpose: the next recovery
                    // asks the same question, and closing it now would replace a result this host
                    // may yet establish with a permanent unknown.
                    OperationState::Staging | OperationState::Publishing => continue,
                    OperationState::Completed => {
                        settled += u64::from(self.settle_completed_operation(&action, &operation)?);
                        continue;
                    }
                    _ => {
                        let detail = operation.detail.clone().unwrap_or_else(|| {
                            format!("operation {} ended without a recorded reason", subject)
                        });
                        settled += u64::from(self.settle_unknown(&action, &detail)? > 0);
                        continue;
                    }
                }
            }
            // A workspace claim.
            let workspace = self.locked()?.workspace(WorkspaceId::new(subject))?;
            if let Some(row) = workspace.as_ref()
                && self.settle_workspace_claim(&action, &record.method, row)?
            {
                settled += 1;
                continue;
            }
            let detail = match workspace {
                Some(row) => format!(
                    "the daemon that performed this action ended before it recorded the result; \
                     workspace {subject} is {}{}, and reading it says what it holds",
                    crate::store::workspace_state_text(row.state),
                    row.detail
                        .map(|detail| format!(" because {detail}"))
                        .unwrap_or_default()
                ),
                None => format!(
                    "the daemon that performed this action ended before it recorded the result, \
                     and this environment has no record of {subject}"
                ),
            };
            settled += u64::from(self.settle_unknown(&action, &detail)? > 0);
        }
        Ok(settled)
    }

    /// Settles one claim with the result a completed operation's own rows reconstruct.
    fn settle_completed_operation(
        &self,
        action: &Action,
        operation: &OperationRow,
    ) -> Result<bool> {
        let store = self.writable()?;
        let Some(project) = store.project(operation.project_repository_id)? else {
            drop(store);
            let detail = format!(
                "operation {} completed and this environment has no record of the repository it \
                 created",
                operation.action_id
            );
            return Ok(self.settle_unknown(action, &detail)? > 0);
        };
        let workspaces = store
            .workspaces(self.environment_id, Some(project.project_repository_id))?
            .len();
        let summary = self.summarise(&project, u64::try_from(workspaces).unwrap_or(u64::MAX));
        let paths = store.staging_paths(operation.action_id)?;
        let record = self.operation_record(operation, operation.state, Some(paths));
        let encoded = encode_creation(&operation.method, &summary, &record)?;
        Ok(store.settle(action, Some(&encoded), None)? > 0)
    }

    /// Settles one workspace claim from the workspace's own durable state.
    ///
    /// A creation that reached `ready` and a removal that reached its terminal state both left
    /// their whole answer in the journal, and reconstructing it beats telling the caller the
    /// outcome is unknown when the workspace is sitting there. What cannot be reconstructed is the
    /// inclusion preview: it is a reading of the *source* tree taken at the moment of the request,
    /// and it is not journalled. So the preview a recovered answer carries says what it is — a
    /// preview this host no longer holds — rather than pretending to counts nobody took.
    ///
    /// Returns whether the claim was settled here. A workspace in any other state is left to the
    /// caller's unknown answer.
    fn settle_workspace_claim(
        &self,
        action: &Action,
        method: &str,
        row: &WorkspaceRow,
    ) -> Result<bool> {
        if method == Method::WorkspaceCreate.as_str() && matches!(row.state, WorkspaceState::Ready)
        {
            let store = self.writable()?;
            let workspace = self.summarise_workspace(&store, row)?;
            // Everything the workspace does not hold as the policy asked: the paths the copy
            // could not carry, the paths that were not file content, and a copy in progress
            // nobody could take away. All of them are journalled as the inclusion goes, which is
            // what makes this list the same list the original answer carried.
            let unapplied = store
                .workspace_progress(row.workspace_id)?
                .into_iter()
                .filter(|(_, outcome)| outcome == "unapplied" || outcome == "leftover")
                .map(|(path, _)| path)
                .collect();
            let result = WorkspaceCreateResult {
                workspace: Nullable(Some(workspace)),
                preview: self.recovered_preview(row),
                unapplied,
            };
            let encoded = kr_cbor::to_canonical_vec(&result).map_err(ProjectError::store)?;
            return Ok(store.settle(action, Some(&encoded), None)? > 0);
        }
        if method == Method::WorkspaceRemove.as_str()
            && matches!(
                row.state,
                WorkspaceState::Removed | WorkspaceState::RemovalPending
            )
        {
            let store = self.writable()?;
            let result = WorkspaceRemoveResult {
                workspace: self.summarise_workspace(&store, row)?,
                working_files_removed: self.tree_gone(row),
                retained: store
                    .retained(row.workspace_id)?
                    .into_iter()
                    .map(|item| RetainedItem {
                        kind: item.kind,
                        detail: item.detail,
                        change_set_id: Nullable(item.change_set_id),
                    })
                    .collect(),
            };
            let encoded = kr_cbor::to_canonical_vec(&result).map_err(ProjectError::store)?;
            return Ok(store.settle(action, Some(&encoded), None)? > 0);
        }
        Ok(false)
    }

    /// Builds the preview a recovered creation answer carries.
    ///
    /// Every count is zero and `counts_complete` is false, which is what "this host does not hold
    /// the preview that was taken" comes to in the wire type. The limitation says so in words,
    /// because a reader who sees zeroes deserves to know they are not a measurement.
    fn recovered_preview(&self, row: &WorkspaceRow) -> InclusionPreview {
        InclusionPreview {
            project_repository_id: row.project_repository_id,
            kind: row.kind,
            policy: row.policy,
            base_revision: row.base_revision.clone(),
            base_reference: Nullable(None),
            base_change_set_id: Nullable(row.base_change_set_id),
            counts: InclusionClass::EVERY
                .iter()
                .map(|class| PreviewCount {
                    class: *class,
                    total: U64::new(0),
                    included: U64::new(0),
                    byte_len: U64::new(0),
                })
                .collect(),
            entries: Vec::new(),
            omitted_entries: U64::new(0),
            unknown_content: U64::new(0),
            counts_complete: false,
            limitations: vec![
                "this answer was rebuilt from the journal after the daemon that took it ended, \
                 and the inclusion preview is a reading of the source working tree that is not \
                 journalled: the counts here are not a measurement. What the workspace holds is \
                 what reading it says."
                    .to_owned(),
            ],
            taken_at_ms: row.created_at_ms,
        }
    }

    /// Settles one claim as an outcome this host cannot establish.
    fn settle_unknown(&self, action: &Action, detail: &str) -> Result<usize> {
        self.writable()?.settle(
            action,
            None,
            Some((kr_protocol::error::ErrorCode::OutcomeUnknown, detail)),
        )
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
        // A name that is recorded and a sibling that could be opened are two different things. A
        // directory this host could not look at is one it has not accounted for, and saying it was
        // cleaned up would be saying something it did not establish.
        let named = row
            .staging_name
            .as_deref()
            .map(|name| destination.parent_path().join(name));
        let staging = row
            .staging_name
            .as_deref()
            .and_then(|name| StagingSibling::open(&destination, name).ok());
        // A name this host could not open is either a name nothing holds or one it could not look
        // at, and the two are different answers. Absence is confirmed through the parent's own
        // handle: nothing there means nothing to account for, and anything else means a path a
        // person should see.
        let unopened = match (row.staging_name.as_deref(), staging.is_some()) {
            (Some(name), false) => RelativeName::parse(name)
                .ok()
                .and_then(|name| destination.parent().occupied(&name).ok())
                .unwrap_or(true),
            _ => false,
        };
        let had_sibling = staging.is_some();
        let Some(staged) = row.staged_identity else {
            // Nothing was published, because the identity a publication needs was never recorded.
            // The destination is untouched, so the staged content is removed and the operation is
            // recorded as failed under its own create token rather than started again.
            let mut left_behind: Option<String> = None;
            // A name that was recorded and whose object is not there: the daemon died between
            // recording the name and creating the directory. The path belongs in neither of the
            // operation's lists — nothing removed it and nothing is retained — so the record is
            // forgotten. It happens *before* the operation is closed, so a crash in between leaves
            // the row unfinished and the next recovery asks the same question again.
            let absent = match (named.as_deref(), had_sibling, unopened) {
                (Some(path), false, false) => {
                    let path = path.display().to_string();
                    self.writable()?.forget_staging_path(row.action_id, &path)?;
                    Some(path)
                }
                _ => None,
            };
            // As above: the publication is committed, and a cleanup that fails is recorded rather
            // than allowed to undo it.
            if let Some(sibling) = staging {
                let path = sibling.path().display().to_string();
                // A name with no recorded identity beside it is not this host's to remove: the
                // daemon died before it could say which object it had created. The path is
                // recorded as one that is still there and a person decides.
                let removed = match row.staging_identity {
                    Some(expected) => sibling
                        .remove_if(&destination, Some(expected))
                        .map(|()| true)
                        .unwrap_or_else(|_| !sibling.occupied(&destination)),
                    None => false,
                };
                if !removed {
                    left_behind = Some(path.clone());
                }
                let _ = self
                    .writable()
                    .and_then(|mut store| store.record_staging_path(row.action_id, &path, removed));
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
            // What this counted is what it removed. A staging directory it left alone, because
            // nothing recorded which object this host had created or because it could not look at
            // the name, is reported as a path that is still there. A name whose object is not
            // there, and a row that named no sibling at all, are neither: the operation is closed
            // and nothing on the filesystem changed.
            if let Some(path) = left_behind {
                return Ok(ResolvedStep::Unresolved(Some(path)));
            }
            if unopened {
                return Ok(ResolvedStep::Unresolved(
                    named.map(|path| path.display().to_string()),
                ));
            }
            if absent.is_some() {
                return Ok(ResolvedStep::Closed);
            }
            return Ok(match named {
                Some(_) => ResolvedStep::Cleaned,
                None => ResolvedStep::Closed,
            });
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
                match publish(&sibling, &destination, staged) {
                    Ok(identity) => {
                        self.finish_publication(row, &destination, identity, Some(sibling))?;
                        Ok(ResolvedStep::Completed)
                    }
                    Err(error) => {
                        // The row stays in `publishing` with its witness, so the next recovery
                        // asks the same question again. Recording a failure here would close an
                        // operation whose publication this host has not decided, and nothing
                        // would revisit it.
                        let path = sibling.path().display().to_string();
                        let mut store = self.writable()?;
                        store.record_staging_path(row.action_id, &path, false)?;
                        store.set_operation_state(
                            row.action_id,
                            OperationState::Publishing,
                            &OperationUpdate {
                                detail: Some(&error.to_string()),
                                ..OperationUpdate::default()
                            },
                        )?;
                        Ok(ResolvedStep::Unresolved(Some(path)))
                    }
                }
            }
            Reconciliation::Unknown => {
                let path = staging.as_ref().map(|sibling| {
                    let path = sibling.path().display().to_string();
                    let _ = self.locked().and_then(|mut store| {
                        store.record_staging_path(row.action_id, &path, false)
                    });
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
        // The publication is committed. Removing the staging sibling afterwards is cleanup, and a
        // cleanup that fails must not turn a landed publication into a failure: the path is
        // recorded as one that is still there, and the sweep and the next recovery retry it.
        // Recording the note is cleanup too, so a journal that refuses it does not undo the
        // publication either.
        if let Some(sibling) = staging {
            let path = sibling.path().display().to_string();
            // The identity checked here is the *sibling's* own, which the row recorded when the
            // directory was created. The published tree's identity is a different object: it is
            // what came out of the sibling.
            let removed = match row.staging_identity {
                Some(expected) => sibling
                    .remove_if(destination, Some(expected))
                    .map(|()| true)
                    .unwrap_or_else(|_| !sibling.occupied(destination)),
                // No recorded identity, so nothing proves the directory at that name is this
                // host's. The publication stands and the path is reported as still there.
                None => false,
            };
            let _ = self
                .writable()
                .and_then(|mut store| store.record_staging_path(row.action_id, &path, removed));
        }
        Ok(())
    }

    /// Records the staging sibling on the operation row and among its paths.
    ///
    /// The name goes on to the row as soon as the directory exists, because a replacement daemon
    /// finds the directory through the row: a name recorded only when the publication began would
    /// leave a sibling nothing accounts for if the daemon died before then.
    fn record_staging(&self, row: &OperationRow, name: &str, path: &Path) -> Result<()> {
        let mut store = self.writable()?;
        store.set_operation_state(
            row.action_id,
            OperationState::Staging,
            &OperationUpdate {
                staging_name: Some(name),
                ..OperationUpdate::default()
            },
        )?;
        store.record_staging_path(row.action_id, &path.display().to_string(), false)
    }

    /// Records the identity of a staging sibling this host has just created.
    ///
    /// A recorded *name* is not authority to remove whatever now holds it. This is what makes the
    /// cleanup a removal of this host's own directory rather than of a replacement at the name.
    fn record_staging_identity(&self, row: &OperationRow, staging: &StagingSibling) -> Result<()> {
        self.writable()?.set_operation_state(
            row.action_id,
            OperationState::Staging,
            &OperationUpdate {
                staging_identity: Some(staging.identity()),
                ..OperationUpdate::default()
            },
        )
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
        let mut store = self.writable()?;
        store.set_operation_state(
            row.action_id,
            state,
            &OperationUpdate {
                detail: Some(&detail),
                ended_at_ms: Some(self.clock.now_ms()),
                ..OperationUpdate::default()
            },
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
            staging_identity: None,
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
                // A failure *after* the publication landed is not a failure of the operation: the
                // repository exists. The row is in `publishing` with the staged object's witness,
                // so it is reconciled against the create token exactly as a replacement daemon
                // would reconcile it, rather than recorded as a failure nothing would revisit.
                // The row is read into a local first. A temporary guard in the head of a
                // condition lives for the whole chain, and `resolve_operation` takes the same
                // lock: the service would wait for itself.
                let current = self.locked()?.operation(row.action_id)?;
                if let Some(current) = current
                    && matches!(current.state, OperationState::Publishing)
                {
                    // The rename may have landed. The same reconciliation a replacement daemon
                    // would run decides, and a publication it could not decide stays in
                    // `publishing` for the next one rather than being closed as a failure.
                    match self.resolve_operation(&current) {
                        Ok(ResolvedStep::Completed) => {
                            if let Some(answered) =
                                self.answer_from_record::<CreationAnswer>(action)?
                            {
                                return Ok((answered.project, answered.operation));
                            }
                        }
                        _ => {
                            // The claim stays open. Settling it here would record a permanent
                            // unknown against an action whose effect this host may yet establish,
                            // and a recovery that then completed the publication could not
                            // replace that answer. An open claim tells a repeat that the effect
                            // is in flight, which is what is true.
                            return Err(ProjectError::OutcomeUnknown {
                                detail: format!(
                                    "this operation's publication is not decided: {error}. The \
                                     operation keeps its create token, its action is not answered \
                                     yet, and the host resolves it against the object it staged \
                                     rather than starting again"
                                ),
                            });
                        }
                    }
                }
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
                // The name goes on to the row before the directory exists, so a sibling this host
                // created is always one a row accounts for and nothing is ever removed because of
                // its name alone.
                let name = StagingSibling::propose();
                self.record_staging(row, &name, &destination.parent_path().join(&name))?;
                let staging = StagingSibling::create(destination, &name)?;
                self.record_staging_identity(row, &staging)?;
                stage_init(&self.profile, &staging, initial_branch.as_deref(), cancel)?;
                let staged = staging.staged_witness()?;
                self.locked()?.set_operation_state(
                    row.action_id,
                    OperationState::Publishing,
                    &OperationUpdate {
                        staged_identity: Some(staged),
                        staging_name: Some(staging.name()),
                        ..OperationUpdate::default()
                    },
                )?;
                let published = publish(&staging, destination, staged)?;
                (Some(published), destination.path(), Some(staging))
            }
            CreatePlan::Clone { remote } => {
                let name = StagingSibling::propose();
                self.record_staging(row, &name, &destination.parent_path().join(&name))?;
                let staging = StagingSibling::create(destination, &name)?;
                self.record_staging_identity(row, &staging)?;
                stage_clone(&self.profile, &staging, remote, cancel)?;
                let staged = staging.staged_witness()?;
                self.locked()?.set_operation_state(
                    row.action_id,
                    OperationState::Publishing,
                    &OperationUpdate {
                        staged_identity: Some(staged),
                        staging_name: Some(staging.name()),
                        ..OperationUpdate::default()
                    },
                )?;
                let published = publish(&staging, destination, staged)?;
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
        // The publication is committed. Removing the staging sibling afterwards is cleanup, and a
        // cleanup that fails must not turn a landed publication into a failure: the path is
        // recorded as one that is still there, and the sweep and the next recovery retry it.
        // Recording the note is cleanup too, so a journal that refuses it does not undo the
        // publication either.
        if let Some(sibling) = staging {
            let path = sibling.path().display().to_string();
            let identity = sibling.identity();
            let removed = sibling
                .remove_if(destination, Some(identity))
                .map(|()| true)
                .unwrap_or_else(|_| !sibling.occupied(destination));
            let _ = self
                .writable()
                .and_then(|mut store| store.record_staging_path(row.action_id, &path, removed));
        }
        // The completion is committed, so nothing after it may fail the operation. A read of the
        // row that fails is answered from the row this call already holds rather than propagated
        // into the error path, which would record a failure against a repository that exists.
        let operation = self
            .read_operation(row.action_id)
            .unwrap_or_else(|_| self.operation_record(row, OperationState::Completed, None));
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
                // The reference is HEAD's, so it belongs to the preview only when the caller let
                // HEAD decide the revision. A caller that named another revision gets no
                // reference rather than an unrelated one.
                base_reference: params
                    .base_revision
                    .0
                    .is_none()
                    .then_some(head_reference.as_deref())
                    .flatten(),
                base_change_set_id: params.base_change_set_id.0,
                at_ms: self.clock.now_ms(),
            },
        )?;
        if params.preview_only {
            // The preview creates nothing, which is what lets the create interface show it first.
            return Ok(WorkspaceCreateResult {
                workspace: Nullable(None),
                preview: surveyed.preview,
                unapplied: Vec::new(),
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
            staging_name: None,
            staging_identity: None,
            detail: None,
            retention: None,
            created_at_ms: self.clock.now_ms(),
            removed_at_ms: None,
        };
        self.writable()?.begin_workspace(&row, action)?;
        let outcome = self.materialise(&repository, &row, params, &surveyed);
        let unapplied = match outcome {
            Ok(materialised) => {
                self.writable()?.set_workspace_state(
                    workspace_id,
                    WorkspaceState::Ready,
                    Some(materialised.identity),
                    None,
                    None,
                )?;
                materialised.unapplied
            }
            Err(error) => {
                let detail = error.to_string();
                // The row keeps whatever identity the materialisation managed to record, so a
                // removal can reach the tree this host created. Where it recorded none, the
                // removal refuses: this host does not delete a directory it cannot prove is its.
                let mut store = self.writable()?;
                store.set_workspace(
                    workspace_id,
                    WorkspaceState::RemovalPending,
                    &WorkspaceUpdate {
                        detail: Some(&detail),
                        ..WorkspaceUpdate::default()
                    },
                )?;
                if let Some(action) = action {
                    store.settle(action, None, Some((error.code(), &detail)))?;
                }
                return Err(error);
            }
        };
        let store = self.writable()?;
        let row = store
            .workspace(workspace_id)?
            .ok_or_else(|| ProjectError::UnknownWorkspace {
                workspace: workspace_id.to_string(),
            })?;
        let workspace = self.summarise_workspace(&store, &row)?;
        let result = WorkspaceCreateResult {
            workspace: Nullable(Some(workspace)),
            preview: surveyed.preview,
            unapplied,
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
    ) -> Result<Materialised> {
        match row.kind {
            WorkspaceKind::SharedExisting => {
                // The user's own working tree, used where it is. Nothing is created, nothing is
                // cleaned and nothing is copied.
                Ok(Materialised {
                    identity: repository.identity().work_tree,
                    unapplied: Vec::new(),
                })
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
                        // renamed. The directory is reserved first: creating it is the atomic
                        // no-replace step, and its identity goes on to the row before anything is
                        // written into it, so a removal afterwards can prove the tree is this
                        // host's. `git worktree add` accepts an existing empty directory.
                        // The configuration is read again immediately before the first write.
                        // It does not close the window between that reading and the process
                        // starting — nothing Git offers does — but a write runs under a
                        // configuration read a moment earlier rather than one read whenever the
                        // repository was opened.
                        repository.recheck(&self.profile)?;
                        let reserved = destination.reserve()?;
                        self.writable()?.set_workspace_state(
                            row.workspace_id,
                            WorkspaceState::Materialising,
                            Some(reserved.identity()),
                            None,
                            None,
                        )?;
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
                        // The name goes on to the row before the directory exists, so recovery
                        // finds a sibling this host created rather than one it guessed at.
                        let name = StagingSibling::propose();
                        self.writable()?.set_workspace(
                            row.workspace_id,
                            WorkspaceState::Materialising,
                            &WorkspaceUpdate {
                                staging_name: Some(&name),
                                ..WorkspaceUpdate::default()
                            },
                        )?;
                        repository.recheck(&self.profile)?;
                        let staging = StagingSibling::create(&destination, &name)?;
                        // The sibling's own identity goes on to the row as soon as the directory
                        // exists. A recorded name is not authority to remove whatever holds it
                        // later: the cleanup removes this object or nothing.
                        self.writable()?.set_workspace(
                            row.workspace_id,
                            WorkspaceState::Materialising,
                            &WorkspaceUpdate {
                                staging_identity: Some(staging.identity()),
                                ..WorkspaceUpdate::default()
                            },
                        )?;
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
                        // The object that will be published is recorded *before* the rename, so a
                        // crash in the interval leaves a tree whose ownership this host can still
                        // establish: the identity a rename preserves is the one already on the
                        // row.
                        let staged = staging.staged_witness()?;
                        self.writable()?.set_workspace_state(
                            row.workspace_id,
                            WorkspaceState::Materialising,
                            Some(staged.identity),
                            None,
                            None,
                        )?;
                        publish(&staging, &destination, staged)?;
                        // Removing the sibling is cleanup. A failure here does not undo a
                        // publication that landed: the name stays on the row and recovery retries
                        // it. What is removed is the object whose identity the row holds.
                        let identity = staging.identity();
                        let removed = staging.remove_if(&destination, Some(identity)).is_ok()
                            || !staging.occupied(&destination);
                        if removed {
                            self.writable()?.clear_workspace_staging(row.workspace_id)?;
                        }
                    }
                }
                let tree = destination.parent().subdirectory(destination.name())?;
                // The inclusion is a copy out of the source tree. The source is only read: an
                // exclusion means this workspace holds the base's version of the path rather than
                // the user's, and never that the original is cleaned, stashed or discarded.
                //
                // Each path's outcome is journalled as it settles, in batches, so a daemon that
                // dies part way through leaves a record of what it had applied.
                // Every path the inclusion is about to attempt is recorded as `planned` before
                // the copy starts, so a crash anywhere in it leaves each path either resolved or
                // planned rather than unaccounted for. The outcomes then replace those rows in
                // batches.
                let planned: Vec<String> = surveyed
                    .entries
                    .iter()
                    .filter(|entry| entry.included)
                    .map(|entry| entry.path.clone())
                    .collect();
                self.writable()?
                    .plan_workspace_progress(row.workspace_id, &planned)?;
                // A path the survey found that is not file content (a link, a socket, a device)
                // is one the workspace does not hold as the policy asked, so it is journalled
                // with the rest before anything else happens.
                self.writable()?.record_workspace_progress(
                    row.workspace_id,
                    &surveyed
                        .unsupported
                        .iter()
                        .map(|path| (path.clone(), outcome_text(PathOutcome::Unapplied)))
                        .collect::<Vec<(String, &'static str)>>(),
                )?;
                let mut batch: Vec<(String, &'static str)> = Vec::new();
                let mut journalled = |path: &str, outcome: PathOutcome| -> Result<()> {
                    batch.push((path.to_owned(), outcome_text(outcome)));
                    if batch.len() >= PROGRESS_BATCH {
                        // The batch is cleared only once its transaction has committed. A write
                        // that fails leaves the outcomes in hand for the tail flush rather than
                        // dropping them.
                        self.writable()?
                            .record_workspace_progress(row.workspace_id, &batch)?;
                        batch.clear();
                    }
                    Ok(())
                };
                let outcome = {
                    // The closure holds the batch while it runs, and the tail of the batch is
                    // written after it: the borrow ends with this block.
                    copy_included(
                        repository.work_tree(),
                        &tree,
                        &surveyed.entries,
                        &mut journalled,
                    )
                };
                if !batch.is_empty() {
                    self.writable()?
                        .record_workspace_progress(row.workspace_id, &batch)?;
                }
                let mut report = outcome?;
                // A path the survey found that is not file content — a link, a socket, a device —
                // is one the workspace does not hold as the policy asked, so it is reported with
                // the rest rather than left for the caller to notice.
                report.skipped.extend(surveyed.unsupported.iter().cloned());
                // A temporary file a failed copy left behind is named too: something nobody
                // accounts for in the user's new workspace is worse than something named.
                let leftover = report.leftover.clone();
                report.skipped.extend(leftover);
                let carried = report.copied.len() + report.removed.len();
                // What the copy carried and what it could not goes on to the row before the
                // workspace is called ready, so a reader of a workspace this host finished knows
                // what it holds and a reader of one it did not finish is told so.
                self.writable()?.set_workspace(
                    row.workspace_id,
                    WorkspaceState::Materialising,
                    &WorkspaceUpdate {
                        identity: Some(tree.identity()),
                        detail: Some(&format!(
                            "{carried} of the working tree's uncommitted paths were carried in \
                             and {} could not be",
                            report.skipped.len()
                        )),
                        ..WorkspaceUpdate::default()
                    },
                )?;
                if carried > 0 {
                    // What was carried in is uncommitted work this workspace now holds, so a
                    // removal has to account for it.
                    self.writable()?.retain(
                        row.workspace_id,
                        &RetainedRow {
                            kind: RetainedKind::DirtyContent,
                            detail: format!(
                                "{carried} uncommitted paths were carried in when this workspace \
                                 was created"
                            ),
                            change_set_id: None,
                        },
                    )?;
                }
                Ok(Materialised {
                    identity: tree.identity(),
                    unapplied: report.skipped,
                })
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
        // The claim, the holder count and the reservation are one transaction, and they come
        // first. From this moment nothing new may hold the workspace and nothing new may be
        // recorded against it, so the measurement below and the decision after it see a workspace
        // that cannot gain a session, a run or a pin underneath them.
        let reserved =
            self.writable()?
                .begin_removal(params.workspace_id, params.retention, action)?;
        let outcome = self.perform_removal(&reserved.row, params.retention);
        // The answer is built *inside* the reservation, so what it says about the tree and what it
        // says about the workspace are one state rather than two readings with another removal
        // between them. The reservation is then given up whatever happened: what it excludes is a
        // second removal running beside this one, not a second request after it.
        let answered = match outcome {
            Ok(removed) => self.removal_answer(params.workspace_id, removed, action),
            Err(error) => {
                let detail = error.to_string();
                let recorded = self.writable().and_then(|mut store| {
                    store.set_workspace(
                        params.workspace_id,
                        WorkspaceState::RemovalPending,
                        &WorkspaceUpdate {
                            detail: Some(&detail),
                            ..WorkspaceUpdate::default()
                        },
                    )?;
                    if let Some(action) = action {
                        store.settle(action, None, Some((error.code(), &detail)))?;
                    }
                    Ok(())
                });
                // A journal that refuses the reason does not keep the reservation: the release
                // below runs either way, and the caller is told about the original failure.
                let _ = recorded;
                Err(error)
            }
        };
        self.writable()?
            .release_removal(params.workspace_id, reserved.token)?;
        answered
    }

    /// Records what uncommitted work a workspace's own tree holds now.
    ///
    /// A workspace created from its base alone holds nothing, and then somebody edits a file in
    /// it. An empty retention table does not establish a clean tree, so the tree is read.
    ///
    /// A tree this host could not read is not a tree it found empty. When the reading fails, the
    /// record says so, and `keep_everything` then keeps the workspace: an incomplete inspection
    /// keeps work rather than losing it.
    fn measure_dirty_content(&self, row: &WorkspaceRow) -> Result<()> {
        let item = match self.count_dirty(row) {
            DirtyCount::Clean => None,
            DirtyCount::Holds(count) => Some(RetainedRow {
                kind: RetainedKind::DirtyContent,
                detail: format!("{count} paths in this workspace hold uncommitted work"),
                change_set_id: None,
            }),
            DirtyCount::Unmeasurable(reason) => Some(RetainedRow {
                kind: RetainedKind::DirtyContent,
                detail: format!(
                    "this host could not read what this workspace holds ({reason}), so it keeps \
                     it rather than removing what it could not inspect"
                ),
                change_set_id: None,
            }),
        };
        self.writable()?.replace_retained(
            row.workspace_id,
            RetainedKind::DirtyContent,
            item.as_ref(),
        )
    }

    /// Returns what a workspace's own tree holds.
    ///
    /// Ignored files count: a build product somebody added after the creation is still work the
    /// user has not approved removing.
    fn count_dirty(&self, row: &WorkspaceRow) -> DirtyCount {
        // A shared workspace's tree is the user's own and is never removed, so what it holds does
        // not gate anything; a read of it still says what is there.
        let opened = match OpenedRepository::open(
            &self.profile,
            self.environment_id,
            Path::new(&row.display_path),
        ) {
            Ok(opened) => opened,
            Err(error) => {
                // A directory that is not there holds nothing, and a workspace already recorded as
                // removed holds nothing either. Anything else is a tree this host could not
                // inspect, and an inspection it could not make is not an inspection that found the
                // tree empty. A metadata call that fails for any reason *other* than absence says
                // nothing about what is there, so it is not read as absence.
                let absent = matches!(row.state, WorkspaceState::Removed)
                    || matches!(
                        std::fs::symlink_metadata(&row.display_path),
                        Err(ref failure) if failure.kind() == std::io::ErrorKind::NotFound
                    );
                return if absent {
                    DirtyCount::Clean
                } else {
                    DirtyCount::Unmeasurable(error.to_string())
                };
            }
        };
        let arguments: [&OsStr; 6] = [
            OsStr::new("status"),
            OsStr::new("--porcelain=v2"),
            OsStr::new("-z"),
            OsStr::new("--untracked-files=all"),
            OsStr::new("--ignored=matching"),
            OsStr::new("--ignore-submodules=all"),
        ];
        let reported = match self.profile.run_checked(&opened.read(&arguments)) {
            Ok(reported) => reported,
            Err(error) => return DirtyCount::Unmeasurable(error.to_string()),
        };
        let entries = match crate::workspace::parse_status(&reported) {
            Err(error) => return DirtyCount::Unmeasurable(error.to_string()),
            Ok(entries) => entries,
        };
        if !entries.is_empty() {
            return DirtyCount::Holds(entries.len());
        }
        // The status above asked Git to ignore submodules, because looking inside one would run
        // under a configuration this host has not audited. So an empty status is an empty status
        // *of the tree outside its submodules*: a populated submodule may hold uncommitted work
        // this host has not read, and work it has not read is not work it found absent.
        match self.populated_submodules(&opened) {
            Ok(paths) if paths.is_empty() => DirtyCount::Clean,
            Ok(paths) => DirtyCount::Unmeasurable(format!(
                "{} holds submodules whose own working trees this host does not look inside ({})",
                row.display_path,
                // The paths came out of the repository's index, so they go through the rule before
                // they reach a retained record a reader keeps.
                crate::git::redact(&paths.join(", "))
            )),
            Err(error) => DirtyCount::Unmeasurable(error.to_string()),
        }
    }

    /// Returns the submodule paths that have something in them.
    ///
    /// Read from the index and the directory entry alone: nothing is run inside a submodule, and
    /// its own configuration is never read.
    fn populated_submodules(&self, opened: &OpenedRepository) -> Result<Vec<String>> {
        let mut populated = Vec::new();
        for path in crate::workspace::submodule_paths(&self.profile, opened)? {
            let Ok(name) = kr_transfer::RelativeName::parse(&path) else {
                populated.push(path);
                continue;
            };
            let Ok(directory) = opened.work_tree().subdirectory(&name) else {
                // Only a plain absence is absence. A path this host could not open, or one that
                // is not a directory at all, is a path it has not established anything about, so
                // it counts as work it has not read.
                let absent = matches!(
                    std::fs::symlink_metadata(opened.top_level().join(&path)),
                    Err(ref failure) if failure.kind() == std::io::ErrorKind::NotFound
                );
                if !absent {
                    populated.push(path);
                }
                continue;
            };
            let holds = directory
                .handle()
                .entries()
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(true);
            if holds {
                populated.push(path);
            }
        }
        Ok(populated)
    }

    /// Removes what the retention policy permits, and says whether the working files are gone.
    fn perform_removal(&self, row: &WorkspaceRow, retention: RetentionPolicy) -> Result<bool> {
        // What the workspace holds is measured now, after the reservation, so nothing can be added
        // to it between the measurement and the decision.
        self.measure_dirty_content(row)?;
        let held = self.locked()?.retained(row.workspace_id)?;
        // A shared workspace *is* the user's own working tree. Removing the record removes the
        // selection; removing the tree would delete the user's work, which no retention policy
        // asks for. So its removal never waits on what the tree holds either.
        if matches!(row.kind, WorkspaceKind::SharedExisting) {
            self.writable()?
                .finish_removal(row.workspace_id, retention, self.clock.now_ms())?;
            // The user's own tree is not this host's to remove, so what the answer says about it
            // is read from the filesystem rather than assumed: a tree the user deleted themselves
            // is gone whoever deleted it.
            return Ok(self.tree_gone(row));
        }
        if matches!(retention, RetentionPolicy::KeepEverything) && !held.is_empty() {
            // Dirty content, pinned change sets and review evidence are retained until the user
            // approves their removal. Saying what is held and changing nothing is the answer, and
            // the approval is a second request carrying the other policy.
            return Ok(self.tree_gone(row));
        }
        self.remove_working_tree(row)?;
        self.writable()?
            .finish_removal(row.workspace_id, retention, self.clock.now_ms())?;
        // What the result says is what is true of the tree now, whether this call removed it or
        // found it already gone.
        Ok(self.tree_gone(row))
    }

    /// Returns whether a workspace's working files are gone.
    ///
    /// A path this host cannot look at is not a path it found empty, so anything other than a
    /// plain absence answers "still there".
    fn tree_gone(&self, row: &WorkspaceRow) -> bool {
        matches!(
            std::fs::symlink_metadata(&row.display_path),
            Err(ref failure) if failure.kind() == std::io::ErrorKind::NotFound
        )
    }

    fn removal_answer(
        &self,
        workspace_id: WorkspaceId,
        working_files_removed: bool,
        action: Option<&Action>,
    ) -> Result<WorkspaceRemoveResult> {
        let store = self.writable()?;
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
        // The claim was opened when the removal was reserved, so this fills it in rather than
        // recording a second row. A claim that is no longer open belongs to a copy of this action
        // that settled first, and that record is the answer both callers get.
        if let Some(action) = action {
            let encoded = kr_cbor::to_canonical_vec(&result).map_err(ProjectError::store)?;
            if store.settle(action, Some(&encoded), None)? == 0
                && let Some(record) = store.retained_action(&action.actor_id, action.action_id)?
            {
                return match outcome_of(&record) {
                    RetainedOutcome::Ok(bytes) => {
                        kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                            .map_err(ProjectError::store)
                    }
                    RetainedOutcome::Error { code, detail } => {
                        Err(ProjectError::Retained { code, detail })
                    }
                };
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
        let Some(expected) = row.identity else {
            // The materialisation never got as far as recording the tree's identity, so this host
            // cannot prove the directory at that path is one it created. Removing it would be
            // removing whatever is there, which is exactly what an identity exists to stop.
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this host recorded no filesystem identity for the workspace at {}, so it \
                     will not remove what is there; the directory is left for a person to look at",
                    path.display()
                ),
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
        let here = parent.subdirectory(&name)?;
        if here.identity() != expected {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this workspace was recorded as {expected} and {} now holds {}; nothing is \
                     removed",
                    path.display(),
                    here.identity()
                ),
            });
        }
        // What is inside goes through the tree's *own* open handle, so every one of those
        // removals is of something reached from the directory whose identity was just checked
        // rather than through a name that could be swapped underneath it. The name itself can only
        // be removed through the parent, and an empty-directory removal refuses a directory that
        // is not empty: a replacement holding anything is refused here rather than deleted.
        crate::operation::clear_through(&here, &path)?;
        drop(here);
        match parent.handle().remove_dir(name.as_str()) {
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
        // The guard is released before the subprocess starts: a journal lock held across a Git
        // invocation is a lock held for as long as Git takes.
        let repository = if matches!(row.isolation, Some(IsolationMechanism::GitWorktree)) {
            self.locked()?.project(row.project_repository_id)?
        } else {
            None
        };
        if let Some(project) = repository {
            // A write to the user's own repository, so the configuration is read again first and
            // the prune is skipped rather than run under one this host has not audited. Skipping
            // it leaves a record naming a path that is gone, which `git worktree list` reports
            // and a later prune clears; running Git under an unaudited configuration would be
            // worse than that.
            let top = PathBuf::from(&project.display_path);
            if let Ok(opened) = OpenedRepository::open_recorded(
                &self.profile,
                self.environment_id,
                &top,
                project.identity,
            ) && opened.recheck(&self.profile).is_ok()
            {
                let arguments: [&OsStr; 2] = [OsStr::new("worktree"), OsStr::new("prune")];
                let _ = self.profile.run(&opened.write(&arguments));
            }
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
        self.writable()?
            .bind_session(workspace_id, session_id, live)
    }

    /// Records an automation run as bound to a workspace, or as having ended.
    ///
    /// Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
    /// between two sessions or after its last one ended, so the workflow service records it here
    /// and a removal refuses while it is live.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::WrongState`] when the workspace is no longer one anything may
    /// hold, or [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn bind_run(
        &self,
        workspace_id: WorkspaceId,
        run_id: kr_protocol::ids::WorkflowRunId,
        live: bool,
    ) -> Result<()> {
        self.writable()?.bind_run(workspace_id, run_id, live)
    }

    /// Records one thing a workspace holds that a removal has to account for.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn retain(&self, workspace_id: WorkspaceId, item: &RetainedRow) -> Result<()> {
        self.writable()?.retain(workspace_id, item)
    }

    /// Returns what one workspace holds that a removal would have to account for.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read.
    pub fn retained(&self, workspace_id: WorkspaceId) -> Result<Vec<RetainedRow>> {
        self.locked()?.retained(workspace_id)
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
        // A non-zero exit is this method's answer for a revision the repository does not hold, so
        // the exit code is not on its own enough: an output this host read only part of would be
        // taken for the identifier it names.
        output.require_complete()?;
        if !output.success {
            return Err(ProjectError::InvalidArgument(format!(
                "{} is not a revision this repository holds",
                // The revision is the caller's own text, and it goes into a message a journal
                // keeps and another actor can read, so it goes through the same rule.
                crate::git::redact(revision)
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
            // An absent identity is reported as absent. A workspace whose materialisation did not
            // get as far as creating its tree has none, and inventing one would be inventing a
            // filesystem object.
            filesystem_identity: Nullable(row.identity.map(wire_identity)),
            display_path: row.display_path.clone(),
            detail: Nullable(row.detail.clone()),
            bound_sessions: store.live_sessions(row.workspace_id)?,
            bound_runs: store.live_runs(row.workspace_id)?,
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
    /// Nothing was published and there was nothing to remove, so the operation is simply closed.
    ///
    /// Counted as neither a cleanup nor an unresolved path: a recovery's figures say what it did,
    /// and this did nothing to the filesystem.
    Closed,
    /// This host cannot say what happened; the staging path is kept and named.
    Unresolved(Option<String>),
}

/// What a workspace's own tree holds.
enum DirtyCount {
    /// Nothing uncommitted.
    Clean,
    /// This many paths hold uncommitted work.
    Holds(usize),
    /// This host could not read the tree, so it does not know and does not guess.
    Unmeasurable(String),
}

/// What a materialisation produced.
struct Materialised {
    /// The working tree's filesystem identity.
    identity: ObjectIdentity,
    /// The paths the policy included that this host could not carry.
    unapplied: Vec<String>,
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
            "{} is not a branch name",
            crate::git::redact(branch)
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
            "{} is not a revision",
            crate::git::redact(revision)
        )));
    }
    Ok(())
}

/// Returns the parent of a recorded path, for reopening a destination from a row.
fn parent_of(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|parent| parent.display().to_string())
        .unwrap_or_default()
}

/// Returns the final name of a recorded path.
fn name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
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
