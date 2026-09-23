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
    ActionId, ActorId, ChangeSetId, EnvironmentId, ProjectLocationId, ProjectRepositoryId,
    SessionId, WorkspaceId,
};
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, CloneSource, DestinationRequest, DestinationState, InclusionClass,
    InclusionPreview, IsolationMechanism, LocationPurpose, MAX_LABEL_LEN, OPERATION_DEADLINE,
    OperationRecord, OperationState, PreviewCount, ProjectAdoptParams, ProjectAdoptResult,
    ProjectCloneParams, ProjectCloneResult, ProjectInitParams, ProjectInitResult,
    ProjectListParams, ProjectListResult, ProjectOperationCancelParams,
    ProjectOperationCancelResult, ProjectOrigin, ProjectReadParams, ProjectReadResult,
    ProjectState, ProjectSummary, RemoteSpecification, RemoteTransport, RetainedItem, RetainedKind,
    RetentionPolicy, WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind,
    WorkspaceListParams, WorkspaceListResult, WorkspaceReadParams, WorkspaceReadResult,
    WorkspaceRemoveParams, WorkspaceRemoveResult, WorkspaceState, WorkspaceSummary,
};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_transfer::{Clock, ObjectIdentity, RelativeName, SystemClock};

use crate::credential::{BrokerRegistry, ValidatedRemote};
use crate::error::{ProjectError, Result};
use crate::git::ReadAdmission;
use crate::git::{Cancellation, GitRequest, RestrictedProfile};
use crate::identity::{OpenedRepository, wire_identity};
use crate::operation::{
    Cleanup, Destination, Reconciliation, STAGED_TREE, STAGING_PREFIX, StagedWitness,
    StagingSibling, publish, reconcile, remove_staging_directory, stage_clone, stage_init,
};
use crate::policy::{Admitting, HeldLocation, LocationUse};
use crate::store::{
    Action, LocatedName, OperationRow, OperationUpdate, Performed, PinnedRow, ProjectRow,
    RecordedAuthority, RetainedOutcome, RetainedRow, Store, WorkspaceRow, WorkspaceUpdate,
    outcome_of,
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
///
/// Recovery takes no filesystem effect. It runs when the daemon starts, and a starting daemon holds
/// nothing that reaches a directory: no descriptor survives a restart, a recorded path is display
/// rather than authority, and a location the owner authorised is dormant until the owner
/// authorises it again. So what an earlier daemon left is settled from the journal, every staging
/// path is named as still there with the reason, and the owner reconciles it through a location.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Operations an earlier daemon left staging or publishing, settled from the journal with their
    /// staging paths named.
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

/// A source location an operation reads through, and the use it was admitted for.
type SourceReach = (Arc<HeldLocation>, LocationUse);

/// What a plan for a new repository is.
#[derive(Clone, Debug)]
enum CreatePlan {
    Initialise {
        initial_branch: Option<String>,
    },
    Clone {
        remote: Box<ValidatedRemote>,
        /// The source location the repository was found through, and the use it was admitted
        /// for, when the source was not a remote.
        through: Option<SourceReach>,
    },
    Adopt {
        flow: AdoptionFlow,
    },
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
            Self::Clone { remote, .. } => Some(&remote.specification),
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
    pub(crate) environment_id: EnvironmentId,
    store: Mutex<Store>,
    profile: RestrictedProfile,
    brokers: BrokerRegistry,
    pub(crate) clock: Arc<dyn Clock>,
    /// The owner's active locations and the handles held for them.
    pub(crate) policy: crate::policy::LocationPolicy,
    /// The challenges issued for a location decision and not yet answered.
    pub(crate) challenges: crate::policy::Challenges,
    /// One confirmation transition at a time for each actor and action.
    pub(crate) transitions: crate::policy::Transitions,
    /// The cancellation flag of every operation this process is running.
    ///
    /// Taken for as long as one map operation, never across a subprocess and never while the
    /// journal's lock is held, so there is one order and no way to deadlock against the store.
    running: Mutex<BTreeMap<ActionId, Arc<Cancellation>>>,
    /// What a test runs immediately before a reconciliation reads or removes anything beneath its
    /// location.
    #[cfg(feature = "git-fixtures")]
    reconciling: Option<Hook>,
}

/// Something a test runs at one point of the service's own work.
#[cfg(feature = "git-fixtures")]
struct Hook(Arc<dyn Fn() + Send + Sync>);

#[cfg(feature = "git-fixtures")]
impl std::fmt::Debug for Hook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hook")
    }
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
        let profile = RestrictedProfile::prepare(&root, paths.environment_id())?;
        let brokers = BrokerRegistry::discover(profile.git());
        let mut store = Store::open(
            root.join(crate::store::STORE_FILE_NAME),
            paths.environment_id(),
        )?;
        // No descriptor survives the process that opened it, so every location this environment
        // held active is dormant from here until the owner authorises it again.
        crate::policy::load_dormant(&mut store, clock.now_ms())?;
        Ok(Self {
            environment_id: paths.environment_id(),
            store: Mutex::new(store),
            profile,
            brokers,
            clock,
            policy: crate::policy::LocationPolicy::default(),
            challenges: crate::policy::Challenges::default(),
            transitions: crate::policy::Transitions::default(),
            running: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "git-fixtures")]
            reconciling: None,
        })
    }

    /// Runs something between the reading of a repository's configuration and the start of a Git
    /// child.
    ///
    /// Compiled with the fixtures, so that the tests which prove what the boundary holds can act in
    /// the window it exists for. Nothing in the service sets it.
    #[cfg(feature = "git-fixtures")]
    pub fn interpose(&mut self, interposition: crate::git::Interposition) {
        self.profile.interpose(interposition);
    }

    /// Runs something immediately before a reconciliation reads or removes anything beneath its
    /// location: a running operation's, between the question it asks first and the read that asks
    /// it again, and the owner's, between the claim of its action and the removal.
    ///
    /// Compiled with the fixtures, so that a test can act in windows where no Git child runs for
    /// an interposition to act beside. Nothing in the service sets it.
    #[cfg(feature = "git-fixtures")]
    pub fn before_reconciling(&mut self, act: Arc<dyn Fn() + Send + Sync>) {
        self.reconciling = Some(Hook(act));
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

    pub(crate) fn locked(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.store
            .lock()
            .map_err(|_| ProjectError::StoreUnavailable {
                detail: "the project journal was left poisoned by an earlier failure"
                    .to_owned()
                    .into(),
            })
    }

    /// Returns the journal's guard for a call that writes.
    ///
    /// Every state change commits with the outbox row that announces it, so every one of them is a
    /// transaction and needs the guard mutably. Bound to a local by every caller, never taken in
    /// the head of a condition or a loop: a temporary guard there lives for the whole body, and a
    /// helper that takes the same lock would wait for itself.
    pub(crate) fn writable(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.locked()
    }

    pub(crate) fn check_environment(&self, named: EnvironmentId) -> Result<()> {
        if named == self.environment_id {
            Ok(())
        } else {
            Err(ProjectError::WrongEnvironment {
                named: named.to_string().into(),
                owned: self.environment_id.to_string().into(),
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
            match self.resolve_operation(&row, None) {
                Ok(step) => match step {
                    ResolvedStep::Completed | ResolvedStep::Cleaned | ResolvedStep::Closed => {}
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
        // so what an ended operation left is a recorded name. Recovery reaches none of them, so
        // each is named as still there with the reason, unless a cleanup recorded it removed.
        self.note_recorded_staging()?;
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

    /// Names every staging sibling an ended operation left, and why it is still there.
    ///
    /// Recovery removes none of them: it holds nothing that reaches the directory, and a recorded
    /// name and path are not authority. A path an earlier cleanup recorded as removed stays
    /// recorded as removed, because that one is gone.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read or written.
    fn note_recorded_staging(&self) -> Result<()> {
        // `unknown` is here as well: an operation this host could not decide keeps its staging
        // path because ownership of what is there is uncertain, and the reason says so.
        let rows = self.locked()?.operations_in(&[
            OperationState::Completed,
            OperationState::Cancelled,
            OperationState::Failed,
            OperationState::Expired,
            OperationState::Unknown,
        ])?;
        for row in rows {
            let Some(name) = row.staging_name.as_deref() else {
                continue;
            };
            let path = Path::new(&row.parent_path).join(name);
            self.writable()?.note_kept_staging_path(
                row.action_id,
                &path.display().to_string(),
                &unreachable_reason(row.authority.destination_location_id),
            )?;
        }
        Ok(())
    }

    /// Resolves every workspace an earlier daemon left part way through its materialisation.
    ///
    /// The working files are the user's, so nothing in the directory is removed: this host does
    /// not know which of them it wrote. What it does know is that the workspace is not what its
    /// creation asked for, so the row moves to `removal_pending` with the reason, nothing new may
    /// hold it, and no read calls it ready. The staged sibling of an unfinished independent clone
    /// is named as still there, with the reason, for the owner to reconcile.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read or written.
    fn resolve_materialisations(&self) -> Result<u64> {
        let rows = self.locked()?.workspaces(self.environment_id, None)?;
        // A staging sibling is this host's own directory, wherever the row that named it ended up,
        // so every row that still names one says why it is still there: a workspace that reached
        // `ready` while its cleanup failed keeps its sibling until the owner reconciles it.
        for row in &rows {
            self.note_workspace_staging(row)?;
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

    /// Says why the staging sibling one workspace row names is still there.
    ///
    /// Recovery removes nothing, so the name stays on the row and the row says why: the sibling
    /// is reached through the workspace's location or through nothing, and a starting daemon holds
    /// no location.
    fn note_workspace_staging(&self, row: &WorkspaceRow) -> Result<()> {
        if row.staging_name.is_none() {
            return Ok(());
        }
        self.writable()?.note_kept_workspace_staging(
            row.workspace_id,
            &unreachable_reason(row.located.as_ref().map(|named| named.location_id)),
        )
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
            // A reconciliation's claim names the operation it reconciled, and its answer is not
            // that operation's: what it removed is on the operation's own record, and what the
            // daemon that ended was answering with is not something the journal holds.
            if record.method == Method::ProjectOperationCancel.as_str() {
                let detail = format!(
                    "the daemon that performed this reconciliation ended before it recorded the \
                     result; reading operation {subject} says which of its staging paths are \
                     still there"
                );
                settled += u64::from(self.settle_unknown(&action, &detail)? > 0);
                continue;
            }
            // The claim names what it acted on, so the durable state of that object is consulted
            // before anything is called unknown.
            let operation = self.locked()?.operation(ActionId::new(subject))?;
            if let Some(operation) = operation {
                match operation.state {
                    // Recovery settles these from the journal before it comes here, so one that
                    // is still here is one whose settlement could not be written. Its claim stays
                    // open, and the next recovery settles both the same way.
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
                // Rebuilt from the journal, because recovery looks at nothing: an isolated
                // workspace is recorded as removed only after this host removed its tree, and
                // nothing else is a removal this host can vouch for without looking.
                working_files_removed: matches!(row.state, WorkspaceState::Removed)
                    && matches!(row.kind, WorkspaceKind::Isolated),
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

    /// Reconciles one operation that was staging or publishing against its create token.
    ///
    /// `destination` is the handle the running operation holds, when it is still running. A
    /// reconciliation reaches the filesystem through a handle this process already holds and
    /// through nothing else, so recovery, which holds none, settles the operation from the journal
    /// and names its staging path instead of looking at it.
    fn resolve_operation(
        &self,
        row: &OperationRow,
        destination: Option<&Destination>,
    ) -> Result<ResolvedStep> {
        let Some(destination) = destination else {
            return self.settle_unreachable(row);
        };
        // The running operation holds its destination, and asks its location first: one that no
        // longer admits this operation reaches nothing, so the operation is settled the way a
        // recovery settles one, with no filesystem effect.
        if destination.admit().is_err() {
            return self.settle_unreachable(row);
        }
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
            .and_then(|name| StagingSibling::open(destination, name).ok());
        // A name this host could not open is either a name nothing holds or one it could not look
        // at, and the two are different answers. Absence is confirmed through the parent's own
        // handle: nothing there means nothing to account for, and anything else means a path a
        // person should see.
        let unopened = match (row.staging_name.as_deref(), staging.is_some()) {
            (Some(name), false) => RelativeName::parse(name)
                .ok()
                .and_then(|name| destination.occupied(&name).ok())
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
                let cleanup = row
                    .staging_identity
                    .map(|expected| self.remove_staging(sibling, destination, expected));
                let removed = cleanup.as_ref().is_some_and(Cleanup::gone);
                if !removed {
                    left_behind = Some(path.clone());
                }
                let why = cleanup.as_ref().and_then(Cleanup::why);
                let _ = self.writable().and_then(|mut store| {
                    store.record_staging_path(row.action_id, &path, removed, why)
                });
            }
            self.settle_failure(
                row,
                &ProjectError::OutcomeUnknown {
                    detail: format!(
                        "the daemon that started this operation ended before it published \
                         anything, so {} is untouched and this operation is closed; a new \
                         operation needs a new action identifier",
                        // The fragment, not the sentence: a path put through the rule leaves the
                        // rest of the explanation legible, and replacing the whole reason at the
                        // journal's write would take away the part that says what to do next.
                        crate::git::redact(&destination.path().display().to_string())
                    )
                    .into(),
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
        // A test can act here, between the question above and the read that asks it again.
        #[cfg(feature = "git-fixtures")]
        if let Some(hook) = &self.reconciling {
            (hook.0)();
        }
        let reconciled = match reconcile(destination, staging.as_ref(), staged) {
            Ok(reconciled) => reconciled,
            // The location went between the question above and this read, which asks it again: the
            // operation is settled the way a recovery settles one, with no filesystem effect.
            Err(_) if destination.admit().is_err() => return self.settle_unreachable(row),
            Err(error) => return Err(error),
        };
        match reconciled {
            Reconciliation::Published(identity) => {
                self.finish_publication(row, destination, identity, staging)?;
                Ok(ResolvedStep::Completed)
            }
            Reconciliation::Staged(_) => {
                // The rename did not land. Finishing it is the same operation rather than another
                // clone, which is what reconciling against the create token means.
                let Some(sibling) = staging else {
                    return Ok(ResolvedStep::Unresolved(None));
                };
                match publish(&sibling, destination, staged) {
                    Ok(identity) => {
                        self.finish_publication(row, destination, identity, Some(sibling))?;
                        Ok(ResolvedStep::Completed)
                    }
                    Err(error) => {
                        self.settle_failed_publication(row, destination, sibling, staged, &error)
                    }
                }
            }
            Reconciliation::Unknown => self.settle_undecided(row, destination, staging.as_ref()),
        }
    }

    /// Settles an operation whose publication failed, by asking again which name holds the object
    /// it staged.
    ///
    /// A rename that fails moves nothing, and one that meets a name something else took replaces
    /// nothing, so the object still in the staging directory proves that nothing was published:
    /// the operation failed, with the rename's refusal as its answer, and its staging directory is
    /// taken away through the handle this operation holds, or kept and named with the reason. The
    /// object at the destination means the rename landed after all, which is completed; the object
    /// at neither name is an outcome this host cannot establish.
    fn settle_failed_publication(
        &self,
        row: &OperationRow,
        destination: &Destination,
        sibling: StagingSibling,
        staged: StagedWitness,
        error: &ProjectError,
    ) -> Result<ResolvedStep> {
        let reconciled = match reconcile(destination, Some(&sibling), staged) {
            Ok(reconciled) => reconciled,
            Err(_) if destination.admit().is_err() => return self.settle_unreachable(row),
            Err(failure) => return Err(failure),
        };
        match reconciled {
            Reconciliation::Published(identity) => {
                self.finish_publication(row, destination, identity, Some(sibling))?;
                Ok(ResolvedStep::Completed)
            }
            Reconciliation::Staged(_) => {
                let path = sibling.path().display().to_string();
                // Removed as the directory this operation recorded creating, which nothing but
                // the recorded identity proves.
                let cleanup = row
                    .staging_identity
                    .map(|expected| self.remove_staging(sibling, destination, expected));
                let removed = cleanup.as_ref().is_some_and(Cleanup::gone);
                let why = cleanup.as_ref().and_then(Cleanup::why);
                let _ = self.writable().and_then(|mut store| {
                    store.record_staging_path(row.action_id, &path, removed, why)
                });
                self.settle_failure(row, error, OperationState::Failed)?;
                Ok(if removed {
                    ResolvedStep::Cleaned
                } else {
                    ResolvedStep::Unresolved(Some(path))
                })
            }
            Reconciliation::Unknown => self.settle_undecided(row, destination, Some(&sibling)),
        }
    }

    /// Settles an operation whose staged object neither name holds, as an outcome this host cannot
    /// establish, and names the staging directory as still there.
    fn settle_undecided(
        &self,
        row: &OperationRow,
        destination: &Destination,
        staging: Option<&StagingSibling>,
    ) -> Result<ResolvedStep> {
        let path = staging.map(|sibling| {
            let path = sibling.path().display().to_string();
            let _ = self
                .locked()
                .and_then(|mut store| store.record_staging_path(row.action_id, &path, false, None));
            path
        });
        self.settle_failure(
            row,
            &ProjectError::OutcomeUnknown {
                detail: format!(
                    "neither {} nor this operation's staging directory holds the object that was \
                     staged, so this host cannot say whether the publication landed",
                    crate::git::redact(&destination.path().display().to_string())
                )
                .into(),
            },
            OperationState::Unknown,
        )?;
        Ok(ResolvedStep::Unresolved(path))
    }

    /// Settles an operation no handle reaches, taking no filesystem effect: one a recovery finds,
    /// or a running one whose location no longer admits it.
    ///
    /// What the journal says decides. An operation that never recorded the object it staged
    /// published nothing, so it is closed as failed; one that did may have published, and this
    /// host cannot say, so its outcome is unknown. Either way its create token is kept, and its
    /// staging path is named as still there, with the reason, rather than removed or looked at.
    fn settle_unreachable(&self, row: &OperationRow) -> Result<ResolvedStep> {
        let why = unreachable_reason(row.authority.destination_location_id);
        let destination = crate::git::redact(
            &Path::new(&row.parent_path)
                .join(&row.destination_name)
                .display()
                .to_string(),
        );
        let named = row
            .staging_name
            .as_deref()
            .map(|name| Path::new(&row.parent_path).join(name).display().to_string());
        if let Some(path) = named.as_deref() {
            self.writable()?
                .note_kept_staging_path(row.action_id, path, &why)?;
        }
        if row.staged_identity.is_none() {
            self.settle_failure(
                row,
                &ProjectError::OutcomeUnknown {
                    detail: format!(
                        "the daemon that started this operation ended before it published \
                         anything, so {destination} is untouched and this operation is closed; a \
                         new operation needs a new action identifier"
                    )
                    .into(),
                },
                OperationState::Failed,
            )?;
            return Ok(named.map_or(ResolvedStep::Closed, |path| {
                ResolvedStep::Unresolved(Some(path))
            }));
        }
        self.settle_failure(
            row,
            &ProjectError::OutcomeUnknown {
                detail: format!(
                    "this operation was publishing to {destination}, and this host holds nothing \
                     that reaches it now, so it cannot say whether the publication landed: {why}"
                )
                .into(),
            },
            OperationState::Unknown,
        )?;
        Ok(ResolvedStep::Unresolved(named))
    }

    fn finish_publication(
        &self,
        row: &OperationRow,
        destination: &Destination,
        identity: ObjectIdentity,
        staging: Option<StagingSibling>,
    ) -> Result<()> {
        let path = destination.path();
        let opened = self.open_at(destination, destination.admission())?;
        if opened.identity().work_tree != identity {
            return Err(ProjectError::OutcomeUnknown {
                detail: format!(
                    "{} holds {} and the staged repository was {identity}",
                    crate::git::redact(&path.display().to_string()),
                    opened.identity().work_tree
                )
                .into(),
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
            created_through: created_through(destination),
            source: None,
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
        // recorded as one that is still there, with the reason, for the owner. Recording the note
        // is cleanup too, so a journal that refuses it does not undo the publication either.
        if let Some(sibling) = staging {
            let path = sibling.path().display().to_string();
            // The identity checked here is the *sibling's* own, which the row recorded when the
            // directory was created. The published tree's identity is a different object: it is
            // what came out of the sibling.
            // No recorded identity, so nothing proves the directory at that name is this host's:
            // the publication stands and the path is reported as still there.
            let cleanup = row
                .staging_identity
                .map(|expected| self.remove_staging(sibling, destination, expected));
            let removed = cleanup.as_ref().is_some_and(Cleanup::gone);
            let why = cleanup.as_ref().and_then(Cleanup::why);
            let _ = self.writable().and_then(|mut store| {
                store.record_staging_path(row.action_id, &path, removed, why)
            });
        }
        Ok(())
    }

    /// Returns a completed creation's answer from its rows, for an operation no action carries.
    fn completed_answer(&self, row: &OperationRow) -> Result<(ProjectSummary, OperationRecord)> {
        let project = self
            .locked()?
            .project(row.project_repository_id)?
            .ok_or_else(|| ProjectError::UnknownProject {
                project: row.project_repository_id.to_string().into(),
            })?;
        Ok((
            self.summarise(&project, 0),
            self.read_operation(row.action_id)?,
        ))
    }

    /// Resolves where a clone's content comes from.
    ///
    /// A remote is validated under the credential policy, and only a caller who holds no grant
    /// may name one: a location says nothing about which providers this host may reach for a
    /// caller. A location is admitted as a source for this caller in this environment, the
    /// repository is found beneath it by a descent from its handle, and its configuration is
    /// audited, all before anything is created. A registered repository is reached through the
    /// source location it is bound to, and only as the object its record names; one bound to no
    /// location is reached through nothing. The remote a local source records is written by this
    /// host after the resolution and is for a person to read.
    fn resolve_source(
        &self,
        source: &CloneSource,
        admitting: Admitting,
    ) -> Result<(ValidatedRemote, Option<SourceReach>)> {
        let (location_id, relative, expected) = match source {
            CloneSource::Remote { remote } => {
                if let Admitting::Caller(Some(grant)) = admitting {
                    return Err(ProjectError::PermissionDenied {
                        detail: format!(
                            "project.clone: a caller bounded by grant {grant} does not clone a \
                             remote, because no location says which providers this host may \
                             reach for it"
                        )
                        .into(),
                    });
                }
                return Ok((self.brokers.validate(remote)?, None));
            }
            CloneSource::Location {
                location_id,
                relative_path,
            } => (*location_id, RelativeName::parse(relative_path)?, None),
            CloneSource::Registered {
                project_repository_id,
            } => {
                let project = self
                    .locked()?
                    .project(*project_repository_id)?
                    .ok_or_else(|| ProjectError::UnknownProject {
                        project: project_repository_id.to_string().into(),
                    })?;
                let Some(bound) = project.source else {
                    return Err(ProjectError::PermissionDenied {
                        detail: format!(
                            "repository {project_repository_id} is bound to no source location, \
                             so no location reaches it; the owner binds it to one first"
                        )
                        .into(),
                    });
                };
                (
                    bound.location_id,
                    RelativeName::parse(&bound.relative_path)?,
                    Some(project.identity),
                )
            }
        };
        let wanted = LocationUse {
            purpose: LocationPurpose::Source,
            environment_id: self.environment_id,
            admitting,
        };
        let held = self.locations().admit(location_id, &wanted)?;
        let admission = self
            .locations()
            .read_admission(vec![(Arc::clone(&held), wanted)]);
        let opened = self.open_through(&held, &relative, admission)?;
        if let Some(expected) = expected {
            opened.require_identity(expected)?;
        }
        let remote = self.brokers.validate(&RemoteSpecification {
            remote_name: "origin".to_owned(),
            transport: RemoteTransport::LocalPath,
            url: opened.top_level().display().to_string(),
            provider: String::new(),
            credential_broker: String::new(),
        })?;
        Ok((remote, Some((held, wanted))))
    }

    /// Finds the repository whose working tree is `relative` beneath a location, and opens it
    /// through that location: discovered by a descent from its handle, audited, and asking
    /// `admission` before every invocation against it.
    fn open_through(
        &self,
        location: &HeldLocation,
        relative: &RelativeName,
        admission: Option<ReadAdmission>,
    ) -> Result<OpenedRepository> {
        let shown = location.handle().host_path(relative).display().to_string();
        let found = crate::discovery::discover_through(
            location.handle(),
            relative,
            &shown,
            admission.as_ref(),
        )?;
        OpenedRepository::discovered(
            &self.profile,
            found,
            (location.handle().try_clone()?, relative.clone()),
            admission,
        )
    }

    /// Opens the repository at a destination: through its location when it has one, and as it
    /// always was when the owner named a path.
    fn open_at(
        &self,
        destination: &Destination,
        admission: Option<&ReadAdmission>,
    ) -> Result<OpenedRepository> {
        match destination.location() {
            Some(held) => self.open_through(held, destination.name(), admission.cloned()),
            None => OpenedRepository::open(&self.profile, self.environment_id, &destination.path()),
        }
    }

    /// Makes one operation's staging sibling and records it: the name before the directory exists,
    /// so a sibling this host created is always one a row accounts for, and the identity as soon
    /// as it does, so its cleanup removes that directory and nothing that later holds its name.
    fn begin_staging(
        &self,
        row: &OperationRow,
        destination: &Destination,
    ) -> Result<StagingSibling> {
        let name = StagingSibling::propose();
        self.record_staging(row, &name, &destination.parent_path().join(&name))?;
        let staging = StagingSibling::create(destination, &name)?;
        if let Err(error) = self.record_staging_identity(row, &staging) {
            self.clean_up_staging(row, destination, staging);
            return Err(error);
        }
        Ok(staging)
    }

    /// Runs one operation's staging work and records the object it staged, which is the step
    /// that begins the publication.
    ///
    /// Until that record is written nothing has been published, so a failure here, a
    /// cancellation included, leaves the staging sibling holding only what this operation put in
    /// it. It is taken away at once, through the handle this operation has held since it made the
    /// directory: recovery reaches no directory, so a sibling left for it would stay until the
    /// owner reconciled it.
    fn stage(
        &self,
        row: &OperationRow,
        destination: &Destination,
        staging: StagingSibling,
        work: impl FnOnce(&StagingSibling) -> Result<()>,
    ) -> Result<(StagingSibling, StagedWitness)> {
        let staged = work(&staging).and_then(|()| {
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
            Ok(staged)
        });
        match staged {
            Ok(staged) => Ok((staging, staged)),
            Err(error) => {
                self.clean_up_staging(row, destination, staging);
                Err(error)
            }
        }
    }

    /// Takes one operation's staging sibling away through the handle it holds, and records what
    /// that left: removed, gone, or still there with the reason.
    ///
    /// Recording the note is cleanup too, so a journal that refuses it changes nothing else.
    fn clean_up_staging(
        &self,
        row: &OperationRow,
        destination: &Destination,
        staging: StagingSibling,
    ) {
        let path = staging.path().display().to_string();
        let identity = staging.identity();
        let cleanup = self.remove_staging(staging, destination, identity);
        let _ = self.writable().and_then(|mut store| {
            store.record_staging_path(row.action_id, &path, cleanup.gone(), cleanup.why())
        });
    }

    /// Removes one staging sibling through its destination's handle, unless the destination's
    /// location no longer admits this operation.
    ///
    /// A withdrawal ends this host's reach through a location for every later effect, not only for
    /// reads, so a sibling in a withdrawn location is kept and named with the reason, and the owner
    /// reconciles it. A destination the owner named by path has no location to ask.
    fn remove_staging(
        &self,
        sibling: StagingSibling,
        destination: &Destination,
        expected: ObjectIdentity,
    ) -> Cleanup {
        if let Err(refusal) = destination.admit() {
            return Cleanup::Kept(format!(
                "{refusal}; nothing is removed through it, and the owner reconciles this path"
            ));
        }
        sibling.clean_up(destination, expected)
    }

    /// Takes one workspace's staging sibling away through the handle it holds, and records what
    /// that left: the name forgotten once the directory is gone, or kept with the reason.
    ///
    /// Recording the note is cleanup too, so a journal that refuses it changes nothing else.
    fn clean_up_workspace_staging(
        &self,
        workspace_id: WorkspaceId,
        destination: &Destination,
        staging: StagingSibling,
    ) {
        let identity = staging.identity();
        let _ = match self.remove_staging(staging, destination, identity).why() {
            None => self
                .writable()
                .and_then(|mut store| store.clear_workspace_staging(workspace_id)),
            Some(why) => self
                .writable()
                .and_then(|mut store| store.keep_workspace_staging(workspace_id, why)),
        };
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
        store.record_staging_path(row.action_id, &path.display().to_string(), false, None)
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
                detail: format!("operation {} has no action record", row.action_id).into(),
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
                project: params.project_repository_id.to_string().into(),
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
            .find(|operation| operation.project_repository_id == row.project_repository_id);
        // With its staging paths, as a read of the operation itself gives them: a path that is
        // still there, and why, is part of what the repository's own read says about it.
        let operation = match operation {
            Some(operation) => {
                let paths = store.staging_paths(operation.action_id)?;
                Some(self.operation_record(&operation, operation.state, Some(paths)))
            }
            None => None,
        };
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
                workspace: params.workspace_id.to_string().into(),
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
    pub fn project_init<'a>(
        &self,
        actor: &ActorId,
        params: &ProjectInitParams,
        performed: impl Into<Performed<'a>>,
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
            performed.into(),
        )?;
        Ok(ProjectInitResult { project, operation })
    }

    /// Serves `project.clone`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::RemoteRejected`] when the remote, its transport or its broker is
    /// not one this host uses, or the refusal the destination or Git produced.
    pub fn project_clone<'a>(
        &self,
        actor: &ActorId,
        params: &ProjectCloneParams,
        performed: impl Into<Performed<'a>>,
    ) -> Result<ProjectCloneResult> {
        let performed = performed.into();
        // A copy of this action that already ran is answered before its source is looked for
        // again: the source location may have gone since, and the answer has not.
        if let Some(answered) = self.answer_from_record::<CreationAnswer>(performed.action())? {
            return Ok(ProjectCloneResult {
                project: answered.project,
                operation: answered.operation,
            });
        }
        check_label(&params.label)?;
        // The source is resolved before anything is created, so a refusal costs nothing and no
        // staging directory is left behind by one.
        let (remote, through) =
            self.resolve_source(&params.source, Admitting::Caller(performed.grant()))?;
        let (project, operation) = self.create(
            actor,
            &params.destination,
            &params.label,
            CreatePlan::Clone {
                remote: Box::new(remote),
                through,
            },
            performed,
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
    pub fn project_adopt<'a>(
        &self,
        actor: &ActorId,
        params: &ProjectAdoptParams,
        performed: impl Into<Performed<'a>>,
    ) -> Result<ProjectAdoptResult> {
        check_label(&params.label)?;
        let (project, operation) = self.create(
            actor,
            &params.destination,
            &params.label,
            CreatePlan::Adopt { flow: params.flow },
            performed.into(),
        )?;
        Ok(ProjectAdoptResult { project, operation })
    }

    fn create(
        &self,
        actor: &ActorId,
        request: &DestinationRequest,
        label: &str,
        plan: CreatePlan,
        performed: Performed<'_>,
    ) -> Result<(ProjectSummary, OperationRecord)> {
        // A copy of this action that already ran is answered from its record before anything else
        // happens, in one read, so two copies cannot reach two different answers.
        if let Some(answered) = self.answer_from_record::<CreationAnswer>(performed.action())? {
            return Ok((answered.project, answered.operation));
        }
        self.check_environment(request.environment_id)?;
        let admitting = Admitting::Caller(performed.grant());
        let destination =
            Destination::resolve(request, self.environment_id, self.locations(), admitting)?;
        // Every location this request reaches a name through, asked again inside the transaction
        // that begins the effect and before every read after it.
        let mut reach = Vec::new();
        if let Some(held) = destination.location() {
            reach.push((
                Arc::clone(held),
                LocationUse {
                    purpose: LocationPurpose::Destination,
                    environment_id: self.environment_id,
                    admitting,
                },
            ));
        }
        if let CreatePlan::Clone {
            through: Some(source),
            ..
        } = &plan
        {
            reach.push(source.clone());
        }
        let source_location_id = match &plan {
            CreatePlan::Clone {
                through: Some((held, _)),
                ..
            } => Some(held.location_id()),
            _ => None,
        };
        let admission = self.locations().read_admission(reach);
        // The probe asks the destination's location first, as every read beneath it does.
        let state = destination.probe()?;
        check_destination(&plan, state, &destination)?;
        let project_repository_id = ProjectRepositoryId::new(new_uuid());
        let action_id = performed
            .action()
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
            authority: RecordedAuthority {
                grant_id: performed.grant(),
                destination_location_id: destination.location().map(|held| held.location_id()),
                source_location_id,
            },
            started_at_ms: self.clock.now_ms(),
            ended_at_ms: None,
        };
        // The row exists before anything is created on disk, and its key is the action
        // identifier. Everything after this is reconciled against it. The admission this mutation
        // carries is asked inside that transaction, so an operation whose grant went, or whose
        // location was withdrawn, while its destination was being resolved does not begin.
        self.locked()?
            .begin_operation(&row, performed.reaching(admission.as_ref()))?;
        let cancel = Arc::new(Cancellation::default());
        if let Ok(mut running) = self.running.lock() {
            running.insert(action_id, Arc::clone(&cancel));
        }
        let outcome = self.perform(
            &row,
            &destination,
            &plan,
            label,
            &cancel,
            admission.as_ref(),
        );
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
                    // The rename may have landed. The reconciliation decides which name holds the
                    // object that was staged, and what it settles it records against the action:
                    // the caller is given that record rather than a second answer. A rename that
                    // met a name something else took is settled there as the failure it is.
                    match self.resolve_operation(&current, Some(&destination)) {
                        Ok(step) => {
                            if let Some(answered) =
                                self.answer_from_record::<CreationAnswer>(performed.action())?
                            {
                                return Ok((answered.project, answered.operation));
                            }
                            // No action carries this operation, so its rows say what it settled.
                            return match step {
                                ResolvedStep::Completed => self.completed_answer(&current),
                                _ => Err(error),
                            };
                        }
                        Err(_) => {
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
                                )
                                .into(),
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
        admission: Option<&ReadAdmission>,
    ) -> Result<CreationAnswer> {
        let (identity, path, staging) = match plan {
            CreatePlan::Adopt { .. } => {
                // Nothing is staged: the checkout is already there and adopting it writes nothing
                // into it, does not fetch, does not check anything out and does not touch the
                // index. What it does do is read the configuration, below.
                (None, destination.path(), None)
            }
            CreatePlan::Initialise { initial_branch } => {
                let staging = self.begin_staging(row, destination)?;
                let (staging, staged) = self.stage(row, destination, staging, |staging| {
                    stage_init(
                        &self.profile,
                        staging,
                        initial_branch.as_deref(),
                        cancel,
                        admission,
                    )
                })?;
                let published = publish(&staging, destination, staged)?;
                (Some(published), destination.path(), Some(staging))
            }
            CreatePlan::Clone { remote, .. } => {
                let staging = self.begin_staging(row, destination)?;
                // A failed attempt that carried no credential says so beside whatever Git said,
                // because what Git says is not repeated: a person on a host whose Git ships no
                // credential helper would otherwise have nothing to go on. It is context rather
                // than a cause. An attempt that succeeded needed no credential, and says nothing.
                let (staging, staged) = self.stage(row, destination, staging, |staging| {
                    stage_clone(&self.profile, staging, remote, cancel, admission)
                        .map_err(|error| unauthenticated_fetch(error, remote))
                })?;
                let published = publish(&staging, destination, staged)?;
                (Some(published), destination.path(), Some(staging))
            }
        };
        let opened = self.open_at(destination, admission)?;
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
                    crate::git::redact(&path.display().to_string()),
                    opened.identity().work_tree
                )
                .into(),
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
            created_through: created_through(destination),
            source: None,
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
        // recorded as one that is still there, with the reason, for the owner. Recording the note
        // is cleanup too, so a journal that refuses it does not undo the publication either.
        if let Some(sibling) = staging {
            self.clean_up_staging(row, destination, sibling);
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

    /// Serves `project.operation.cancel`: stops owned subprocesses and reports the staging paths,
    /// and is the owner's route to reconciling an operation no handle reaches any more.
    ///
    /// Its actor rule has two halves. Without a location, a cancellation reaches only the caller's
    /// own operations, whoever the caller is. A location may be named only by a caller that holds
    /// no grant, which is the owner on this machine's own socket; naming one reaches any operation
    /// in this environment, whoever started it, because it is how the owner reaches an operation a
    /// device or an earlier build left. The operation is cancelled if it is still running, and once
    /// it has ended the staging directory it recorded is taken away through the location's handle
    /// when the object there is the one this host recorded creating, or kept and named with the
    /// reason. What the operation's outcome was, and what its action was answered with, stay.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownOperation`] when there is no such operation,
    /// [`ProjectError::PermissionDenied`] when it belongs to another actor and no location is
    /// named, when a caller bounded by a grant names one, or when the location does not admit the
    /// owner's reconciliation or does not contain the operation's staging directory, and
    /// [`ProjectError::WrongState`] when a named location meets an operation that has not ended.
    pub fn project_operation_cancel<'a>(
        &self,
        actor: &ActorId,
        params: &ProjectOperationCancelParams,
        performed: impl Into<Performed<'a>>,
    ) -> Result<ProjectOperationCancelResult> {
        let performed = performed.into();
        // A copy of this action that already settled is answered from its record, and one still
        // in flight is told so, before anything is looked at again.
        if let Some(answered) =
            self.answer_from_record::<ProjectOperationCancelResult>(performed.action())?
        {
            return Ok(answered);
        }
        let through = params.through_location_id.0;
        if let (Some(grant), Some(_)) = (performed.grant(), through) {
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "a caller bounded by grant {grant} names no location to reconcile an operation \
                     through; only the owner reconciles through one"
                )
                .into(),
            });
        }
        let row = self
            .locked()?
            .operation(params.operation_action_id)?
            .ok_or_else(|| ProjectError::UnknownOperation {
                operation: params.operation_action_id.to_string().into(),
            })?;
        // Section 23 puts this method under the resource owner's authority, and the resource is
        // the operation. An operation another actor started is not this caller's to stop, unless
        // the caller is the owner naming a location to reconcile it through.
        if through.is_none() && &row.actor_id != actor {
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "operation {} belongs to another actor, and a cancellation reaches only \
                     authorised owned work",
                    row.action_id
                )
                .into(),
            });
        }
        // A named location is admitted, and has to contain the directory the operation worked in,
        // before anything is done: one that cannot serve the reconciliation refuses the whole
        // request with no effect.
        if let Some(location_id) = through {
            self.recorded_reach(
                location_id,
                &Path::new(&row.parent_path).join(&row.destination_name),
                "the operation's destination",
            )?;
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
        // operation is not undone, and a failed one is not reopened. For work that is running,
        // the thread performing it observes the flag, ends the child it started and records the
        // failure. Waiting for it here is what makes the reported staging paths the ones that are
        // really there.
        if matches!(
            row.state,
            OperationState::Staging | OperationState::Publishing
        ) {
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
        }
        let stopped = flag.map_or(0, |flag| flag.stopped());
        if let Some(location_id) = through {
            return self.reconcile_staging(row.action_id, location_id, performed, stopped);
        }
        Ok(ProjectOperationCancelResult {
            operation: self.read_operation(row.action_id)?,
            stopped_processes: U64::new(stopped),
        })
    }

    /// Takes away, through a location the owner named, the staging directory an ended operation
    /// recorded, records what that left, and answers with the operation's record.
    ///
    /// Only what the row's recorded identity proves this host created goes: a directory whose
    /// identity is not the recorded one, or one that recorded none, is kept and named with the
    /// reason, and so is one a removal could not finish. A directory a cleanup already recorded as
    /// removed is not looked for again. Nothing about the operation's outcome changes.
    ///
    /// Before anything is removed, the request's own admission and the location's are asked, and
    /// the action is claimed with the operation as its subject, in one transaction. The answer then
    /// settles that claim, so a copy of the action finds it rather than removing anything itself.
    fn reconcile_staging(
        &self,
        operation: ActionId,
        location_id: ProjectLocationId,
        performed: Performed<'_>,
        stopped: u64,
    ) -> Result<ProjectOperationCancelResult> {
        let row =
            self.locked()?
                .operation(operation)?
                .ok_or_else(|| ProjectError::UnknownOperation {
                    operation: operation.to_string().into(),
                })?;
        if matches!(
            row.state,
            OperationState::Staging | OperationState::Publishing
        ) {
            return Err(ProjectError::WrongState {
                detail: format!(
                    "operation {operation} has not ended, so the staging directory it recorded may \
                     still be in use and is not reconciled; ask again once it has ended"
                )
                .into(),
            });
        }
        let answer = || -> Result<ProjectOperationCancelResult> {
            Ok(ProjectOperationCancelResult {
                operation: self.read_operation(operation)?,
                stopped_processes: U64::new(stopped),
            })
        };
        let Some(name) = row.staging_name.as_deref() else {
            return answer();
        };
        let shown = Path::new(&row.parent_path).join(name);
        let path = shown.display().to_string();
        let removed = self
            .locked()?
            .staging_paths(operation)?
            .into_iter()
            .any(|recorded| recorded.path == path && recorded.removed);
        if removed {
            return answer();
        }
        let reach = self.recorded_reach(location_id, &shown, "the staging directory")?;
        // The guard is released at the end of this statement: answering from the record below
        // takes the same lock.
        let begun = self
            .writable()?
            .begin_reconciliation(operation, performed.reaching(reach.admission.as_ref()));
        match begun {
            Ok(()) => {}
            // Another copy of this action claimed first: its record is the answer, or says that
            // its effect is still in flight.
            Err(ProjectError::OutcomeUnknown { .. }) if performed.action().is_some() => {
                if let Some(answered) =
                    self.answer_from_record::<ProjectOperationCancelResult>(performed.action())?
                {
                    return Ok(answered);
                }
                return Err(ProjectError::OutcomeUnknown {
                    detail: format!(
                        "another copy of this action is reconciling operation {operation}"
                    )
                    .into(),
                });
            }
            Err(error) => return Err(error),
        }
        // A test can act here, between the claim and the removal.
        #[cfg(feature = "git-fixtures")]
        if let Some(hook) = &self.reconciling {
            (hook.0)();
        }
        let cleanup = self.remove_recorded_staging(&reach, row.staging_identity, &shown);
        let outcome = self
            .writable()
            .and_then(|mut store| {
                store.record_staging_path(operation, &path, cleanup.gone(), cleanup.why())
            })
            .and_then(|()| answer());
        // The claim is settled with what the caller is told. A journal that refuses even that
        // leaves the claim open, which a repeat is told about and a restart settles.
        if let Some(action) = performed.action() {
            let _ = self.writable().and_then(|store| match &outcome {
                Ok(answered) => {
                    let encoded =
                        kr_cbor::to_canonical_vec(answered).map_err(ProjectError::store)?;
                    store.settle(action, Some(&encoded), None)
                }
                Err(error) => store.settle(action, None, Some((error.code(), &error.to_string()))),
            });
        }
        outcome
    }

    /// Admits a location for the owner's reconciliation: an active destination of the owner's in
    /// this environment.
    fn owner_destination(
        &self,
        location_id: ProjectLocationId,
    ) -> Result<(Arc<HeldLocation>, LocationUse)> {
        let wanted = LocationUse {
            purpose: LocationPurpose::Destination,
            environment_id: self.environment_id,
            admitting: Admitting::Caller(None),
        };
        Ok((self.locations().admit(location_id, &wanted)?, wanted))
    }

    /// Reaches a path an earlier operation or workspace recorded, through a location the owner
    /// names that contains it.
    ///
    /// The path's name beneath the location is taken from the two recorded paths, and it is
    /// resolved from the held handle, with the location asked first, before every read and every
    /// effect: what decides is the object that descent reaches and the identity the row recorded
    /// for it, never the path.
    fn recorded_reach(
        &self,
        location_id: ProjectLocationId,
        recorded: &Path,
        subject: &str,
    ) -> Result<TreeReach> {
        let (held, wanted) = self.owner_destination(location_id)?;
        let relative = crate::policy::relative_beneath(
            &held.row().path,
            &recorded.display().to_string(),
            subject,
        )?;
        let admission = self
            .locations()
            .read_admission(vec![(Arc::clone(&held), wanted)]);
        Ok(TreeReach {
            through: Some((held, relative)),
            admission,
        })
    }

    /// Removes a staging directory an earlier operation or workspace recorded, through the
    /// location that reaches it, and says what that left.
    ///
    /// One effect through the location, asked for once before it starts. The directory has to be
    /// one this host names its staging directories by, it has to be the object whose identity the
    /// row recorded, and it has to be one only this account can change; anything else is kept and
    /// named with the reason. A name nothing holds is gone, whoever freed it.
    fn remove_recorded_staging(
        &self,
        reach: &TreeReach,
        expected: Option<ObjectIdentity>,
        shown: &Path,
    ) -> Cleanup {
        let Some((held, relative)) = &reach.through else {
            return Cleanup::Kept(unreachable_reason(None));
        };
        if let Some(admission) = &reach.admission
            && let Err(refusal) = admission.admit()
        {
            return Cleanup::Kept(format!("{refusal}; nothing is removed through it"));
        }
        let (above, leaf) = match split_last(relative) {
            Ok(split) => split,
            Err(refusal) => return Cleanup::Kept(refusal.to_string()),
        };
        if !leaf.as_str().starts_with(STAGING_PREFIX) {
            return Cleanup::Kept(format!(
                "{} is not a name this host gives a staging directory, so it is not removed",
                crate::git::redact(leaf.as_str())
            ));
        }
        let parent = match above {
            None => held.handle().try_clone(),
            Some(above) => held.handle().subdirectory(&above),
        };
        let parent = match parent {
            Ok(parent) => parent,
            Err(kr_transfer::Escape::NotFound { .. }) => return Cleanup::Absent,
            Err(refusal) => return Cleanup::Kept(ProjectError::from(refusal).to_string()),
        };
        let directory = match parent.subdirectory(&leaf) {
            Ok(directory) => directory,
            Err(kr_transfer::Escape::NotFound { .. }) => return Cleanup::Absent,
            Err(refusal) => return Cleanup::Kept(ProjectError::from(refusal).to_string()),
        };
        let Some(expected) = expected else {
            return Cleanup::Kept(
                "this host recorded no identity for it, so nothing proves it is the directory this \
                 host created, and it is not removed"
                    .to_owned(),
            );
        };
        match remove_staging_directory(&parent, &leaf, directory, expected, shown) {
            Ok(()) => Cleanup::Removed,
            Err(refusal) => Cleanup::Kept(refusal.to_string()),
        }
    }

    // ----- workspaces -----------------------------------------------------------------------

    /// Serves `workspace.create`, and its preview.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::InvalidArgument`] when the kind and the policy do not agree,
    /// [`ProjectError::IdentityChanged`] when the repository is no longer the object its record
    /// names, or the refusal the destination or Git produced.
    pub fn workspace_create<'a>(
        &self,
        actor: &ActorId,
        params: &WorkspaceCreateParams,
        performed: impl Into<Performed<'a>>,
    ) -> Result<WorkspaceCreateResult> {
        let performed = performed.into();
        if let Some(answered) =
            self.answer_from_record::<WorkspaceCreateResult>(performed.action())?
        {
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
                project: params.project_repository_id.to_string().into(),
            })?;
        let admitting = Admitting::Caller(performed.grant());
        // Where an isolated workspace's tree goes, resolved once, here.
        let destination = match (params.kind, params.destination.0.as_ref()) {
            (WorkspaceKind::Isolated, Some(request)) => Some(Destination::resolve(
                request,
                self.environment_id,
                self.locations(),
                admitting,
            )?),
            (WorkspaceKind::Isolated, None) => {
                return Err(ProjectError::InvalidArgument(
                    "an isolated workspace names where its working tree goes"
                        .to_owned()
                        .into(),
                ));
            }
            (WorkspaceKind::SharedExisting, _) => None,
        };
        // Every location this request reaches a name through, asked again inside the transaction
        // that begins the effect and before every read after it.
        let mut reach = Vec::new();
        let repository = match destination.as_ref().and_then(Destination::location) {
            // A workspace made through a location reads its repository through the source
            // location the repository is bound to, and through nothing else.
            Some(held) => {
                if matches!(params.isolation.0, Some(IsolationMechanism::GitWorktree)) {
                    return Err(ProjectError::PermissionDenied {
                        detail: "a linked worktree writes its path into the repository it shares, \
                                 which no location reaches; a workspace made through a location \
                                 is an independent clone"
                            .to_owned()
                            .into(),
                    });
                }
                reach.push((
                    Arc::clone(held),
                    LocationUse {
                        purpose: LocationPurpose::Destination,
                        environment_id: self.environment_id,
                        admitting,
                    },
                ));
                let Some(bound) = project.source.clone() else {
                    return Err(ProjectError::PermissionDenied {
                        detail: format!(
                            "repository {} is bound to no source location, so no location \
                             reaches it; the owner binds it to one first",
                            project.project_repository_id
                        )
                        .into(),
                    });
                };
                let wanted = LocationUse {
                    purpose: LocationPurpose::Source,
                    environment_id: self.environment_id,
                    admitting,
                };
                let source = self.locations().admit(bound.location_id, &wanted)?;
                reach.push((Arc::clone(&source), wanted));
                let opened = self.open_through(
                    &source,
                    &RelativeName::parse(&bound.relative_path)?,
                    self.locations().read_admission(reach.clone()),
                )?;
                opened.require_identity(project.identity)?;
                opened
            }
            None => OpenedRepository::open_recorded(
                &self.profile,
                self.environment_id,
                Path::new(&project.display_path),
                project.identity,
            )?,
        };
        let admission = self.locations().read_admission(reach);
        let (head_revision, head_reference) = repository.head(&self.profile)?;
        let base_revision =
            match params.base_revision.0.as_deref() {
                Some(revision) => {
                    check_revision(revision)?;
                    self.resolve_revision(&repository, revision)?
                }
                None => head_revision.clone().ok_or_else(|| {
                    ProjectError::WrongState {
                detail: format!(
                    "{} has no commit yet, so a workspace of it names the revision it starts from",
                    project.display_path
                ).into(),
            }
                })?,
            };
        if params.base_change_set_id.0.is_some() && params.base_revision.0.is_none() {
            return Err(ProjectError::InvalidArgument(
                "a change-set version is resolved to a revision by the change-set service, so a \
                 workspace that materialises one names that revision as well"
                    .to_owned()
                    .into(),
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
        let (display_path, isolation) = match destination.as_ref() {
            None => (project.display_path.clone(), None),
            Some(destination) => {
                if !matches!(destination.probe()?, DestinationState::Absent) {
                    return Err(ProjectError::Destination {
                        detail: format!(
                            "{} exists, and an isolated workspace is created rather than merged \
                             into something",
                            crate::git::redact(&destination.path().display().to_string())
                        )
                        .into(),
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
            located: destination.as_ref().and_then(created_through),
            retention: None,
            created_at_ms: self.clock.now_ms(),
            removed_at_ms: None,
        };
        // The row exists before the tree is materialised, and the admission this mutation carries
        // is asked inside that transaction: a workspace whose grant went, or whose location was
        // withdrawn, while its repository was being opened and surveyed is not materialised.
        self.writable()?
            .begin_workspace(&row, performed.reaching(admission.as_ref()))?;
        let outcome = self.materialise(
            &repository,
            &row,
            destination.as_ref(),
            &surveyed,
            admission.as_ref(),
        );
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
                if let Some(action) = performed.action() {
                    store.settle(action, None, Some((error.code(), &detail)))?;
                }
                return Err(error);
            }
        };
        let store = self.writable()?;
        let row = store
            .workspace(workspace_id)?
            .ok_or_else(|| ProjectError::UnknownWorkspace {
                workspace: workspace_id.to_string().into(),
            })?;
        let workspace = self.summarise_workspace(&store, &row)?;
        let result = WorkspaceCreateResult {
            workspace: Nullable(Some(workspace)),
            preview: surveyed.preview,
            unapplied,
        };
        if let Some(action) = performed.action() {
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
        destination: Option<&Destination>,
        surveyed: &Survey,
        admission: Option<&ReadAdmission>,
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
                let destination = destination.ok_or_else(|| {
                    ProjectError::InvalidArgument(
                        "an isolated workspace names where its working tree goes"
                            .to_owned()
                            .into(),
                    )
                })?;
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
                                // The directory this host reserved a moment ago, which is where
                                // the worktree goes. Nothing else outside the repository is
                                // writable, so a `core.worktree` or an argument naming somewhere
                                // else is refused by the boundary rather than noticed afterwards.
                                .writing(&[(reserved.display_path(), reserved.identity())])
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
                        let staging = StagingSibling::create(destination, &name)?;
                        let materialised = (|| -> Result<()> {
                            // The sibling's own identity goes on to the row as soon as the
                            // directory exists. A recorded name is not authority to remove
                            // whatever holds it later: the cleanup removes this object or nothing.
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
                                    // Named by path for Git, and required to be the directory
                                    // this host created.
                                    .expecting(staging.identity())
                                    .with_ceiling(staging.path())
                                    // The repository this clone copies, which is not one of the
                                    // directories the operation owns.
                                    .reading(&[repository.top_level()])
                                    .with_transport(crate::git::RemoteAccess::local())
                                    .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
                                    .with_cancellation(Arc::clone(&cancel))
                                    .admitted(admission.cloned()),
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
                                    // The tree the clone made, found through the staging
                                    // directory's handle rather than by its path, by a read
                                    // that asks the destination's location first.
                                    .expecting(staging.staged_identity()?)
                                    .with_ceiling(staging.path())
                                    .with_deadline(Duration::from_millis(OPERATION_DEADLINE.get()))
                                    .with_cancellation(Arc::clone(&cancel))
                                    .admitted(admission.cloned()),
                            )?;
                            // The object that will be published is recorded *before* the rename,
                            // so a crash in the interval leaves a tree whose ownership this host
                            // can still establish: the identity a rename preserves is the one
                            // already on the row.
                            let staged = staging.staged_witness()?;
                            self.writable()?.set_workspace_state(
                                row.workspace_id,
                                WorkspaceState::Materialising,
                                Some(staged.identity),
                                None,
                                None,
                            )?;
                            publish(&staging, destination, staged)?;
                            Ok(())
                        })();
                        if let Err(error) = materialised {
                            // A creation that failed before its tree was published, or while it was
                            // being published, leaves the sibling holding only what this creation
                            // put there. It goes at once, through the handle this creation has held
                            // since it made it, because recovery reaches no directory.
                            self.clean_up_workspace_staging(row.workspace_id, destination, staging);
                            return Err(error);
                        }
                        // Removing the sibling is cleanup, and a failure here does not undo a
                        // publication that landed: the name stays on the row with the reason.
                        // What is removed is the object whose identity the row holds.
                        self.clean_up_workspace_staging(row.workspace_id, destination, staging);
                    }
                }
                // The new tree, opened through the destination once its location admits it.
                let tree = destination.opened()?;
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
                        admission,
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
    pub fn workspace_remove<'a>(
        &self,
        params: &WorkspaceRemoveParams,
        performed: impl Into<Performed<'a>>,
    ) -> Result<WorkspaceRemoveResult> {
        let performed = performed.into();
        if let Some(answered) =
            self.answer_from_record::<WorkspaceRemoveResult>(performed.action())?
        {
            return Ok(answered);
        }
        // Naming a location to remove a workspace through is the owner's route, and only the owner
        // takes it: withdrawal stays withdrawn for every device.
        if let (Some(grant), Some(_)) = (performed.grant(), params.through_location_id.0) {
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "a caller bounded by grant {grant} names no location to remove a workspace \
                     through; only the owner removes one through a location it names"
                )
                .into(),
            });
        }
        let recorded = self.locked()?.workspace(params.workspace_id)?;
        let reach = match params.through_location_id.0 {
            // The owner's route to a workspace whose location was withdrawn, or that recorded
            // none: a location of the owner's that contains the tree, admitted before anything is
            // reserved. The tree is found beneath it by name and removed only while it is the
            // object this host recorded creating.
            Some(location_id) => {
                let row = recorded
                    .as_ref()
                    .ok_or_else(|| ProjectError::UnknownWorkspace {
                        workspace: params.workspace_id.to_string().into(),
                    })?;
                self.recorded_reach(location_id, Path::new(&row.display_path), "the workspace")?
            }
            None => {
                // A workspace made through no location is reached through none, whatever
                // authority a caller holds over the repository it is a copy of: only the owner
                // reaches it, by the path it was made at.
                if let Some(grant) = performed.grant()
                    && recorded.as_ref().is_some_and(|row| row.located.is_none())
                {
                    return Err(ProjectError::PermissionDenied {
                        detail: format!(
                            "workspace {} was made through no location, so a caller bounded by \
                             grant {grant} reaches it through none",
                            params.workspace_id
                        )
                        .into(),
                    });
                }
                // A workspace created through a location is reached through that location,
                // admitted for this caller, and through nothing else; a location that is dormant
                // or withdrawn refuses the removal here, before anything is reserved.
                self.tree_reach(
                    recorded.as_ref().and_then(|row| row.located.as_ref()),
                    Admitting::Caller(performed.grant()),
                )?
            }
        };
        // The claim, the holder count and the reservation are one transaction, and they come
        // first. From this moment nothing new may hold the workspace and nothing new may be
        // recorded against it, so the measurement below and the decision after it see a workspace
        // that cannot gain a session, a run or a pin underneath them.
        let reserved = self.writable()?.begin_removal(
            params.workspace_id,
            params.retention,
            performed.reaching(reach.admission.as_ref()),
        )?;
        let outcome = self.perform_removal(&reserved.row, params.retention, &reach);
        // The answer is built *inside* the reservation, so what it says about the tree and what it
        // says about the workspace are one state rather than two readings with another removal
        // between them. The reservation is then given up whatever happened: what it excludes is a
        // second removal running beside this one, not a second request after it.
        let answered = match outcome {
            Ok(removed) => self.removal_answer(params.workspace_id, removed, performed.action()),
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
                    if let Some(action) = performed.action() {
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
    fn measure_dirty_content(&self, row: &WorkspaceRow, reach: &TreeReach) -> Result<()> {
        let item = match self.count_dirty(row, reach) {
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
    fn count_dirty(&self, row: &WorkspaceRow, reach: &TreeReach) -> DirtyCount {
        // A shared workspace's tree is the user's own and is never removed, so what it holds does
        // not gate anything; a read of it still says what is there.
        let opened = match &reach.through {
            Some((held, name)) => self.open_through(held, name, reach.admission.clone()),
            None => OpenedRepository::open(
                &self.profile,
                self.environment_id,
                Path::new(&row.display_path),
            ),
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(error) => {
                // A directory that is not there holds nothing, and a workspace already recorded as
                // removed holds nothing either. Anything else is a tree this host could not
                // inspect, and an inspection it could not make is not an inspection that found the
                // tree empty. A metadata call that fails for any reason *other* than absence says
                // nothing about what is there, so it is not read as absence.
                let absent =
                    matches!(row.state, WorkspaceState::Removed) || self.tree_gone(row, reach);
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
                // Both the workspace's own path and the paths out of the index are text this host
                // did not choose, and this reason is kept and read back in a successful answer.
                crate::git::redact(&row.display_path),
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
        let paths = crate::workspace::submodule_paths(&self.profile, opened)?;
        // The directories are looked at through the working tree's handle, which is a read through
        // the repository's location when it was reached through one, so that location is asked
        // first, once, for this read.
        if let Some(admission) = opened.admission() {
            admission.admit()?;
        }
        for path in paths {
            let Ok(name) = kr_transfer::RelativeName::parse(&path) else {
                populated.push(path);
                continue;
            };
            let Ok(directory) = opened.work_tree().subdirectory(&name) else {
                // Only a plain absence is absence. A path this host could not open, or one that
                // is not a directory at all, is a path it has not established anything about, so
                // it counts as work it has not read. Absence is asked of the same handle, never
                // of a path.
                let absent = matches!(
                    opened.work_tree().probe(&name),
                    Err(kr_transfer::Escape::NotFound { .. })
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
    fn perform_removal(
        &self,
        row: &WorkspaceRow,
        retention: RetentionPolicy,
        reach: &TreeReach,
    ) -> Result<bool> {
        // What the workspace holds is measured now, after the reservation, so nothing can be added
        // to it between the measurement and the decision.
        self.measure_dirty_content(row, reach)?;
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
            return Ok(self.tree_gone(row, reach));
        }
        if matches!(retention, RetentionPolicy::KeepEverything) && !held.is_empty() {
            // Dirty content, pinned change sets and review evidence are retained until the user
            // approves their removal. Saying what is held and changing nothing is the answer, and
            // the approval is a second request carrying the other policy.
            return Ok(self.tree_gone(row, reach));
        }
        // A staging directory the workspace recorded is this host's own and beside the tree. A
        // removal that reaches the tree through a location takes it away through the same
        // handle when its recorded identity proves it, or keeps it and says why.
        if row.staging_name.is_some() && reach.through.is_some() {
            self.remove_workspace_staging(row, reach);
        }
        self.remove_working_tree(row, reach)?;
        self.writable()?
            .finish_removal(row.workspace_id, retention, self.clock.now_ms())?;
        // What the result says is what is true of the tree now, whether this call removed it or
        // found it already gone.
        Ok(self.tree_gone(row, reach))
    }

    /// Takes away the staging directory a workspace recorded, beside its tree, through the
    /// location the removal reaches the tree through, and records what that left: the name
    /// forgotten once the directory is gone, or kept with the reason.
    ///
    /// Recording the note is cleanup too, so a journal that refuses it changes nothing else.
    fn remove_workspace_staging(&self, row: &WorkspaceRow, reach: &TreeReach) {
        let Some(name) = row.staging_name.as_deref() else {
            return;
        };
        let shown = PathBuf::from(workspace_staging_path(row));
        let cleanup = match reach.beside(name) {
            Ok(beside) => self.remove_recorded_staging(&beside, row.staging_identity, &shown),
            Err(refusal) => Cleanup::Kept(refusal.to_string()),
        };
        let _ = match cleanup.why() {
            None => self
                .writable()
                .and_then(|mut store| store.clear_workspace_staging(row.workspace_id)),
            Some(why) => self
                .writable()
                .and_then(|mut store| store.keep_workspace_staging(row.workspace_id, why)),
        };
    }

    /// Returns how a removal reaches a workspace's tree.
    ///
    /// A workspace created through a location is reached through that location, admitted for this
    /// caller as a destination, with an admission every read of the removal asks again. One that
    /// recorded no location is reached as the owner always has.
    fn tree_reach(&self, located: Option<&LocatedName>, admitting: Admitting) -> Result<TreeReach> {
        let Some(located) = located else {
            return Ok(TreeReach {
                through: None,
                admission: None,
            });
        };
        let wanted = LocationUse {
            purpose: LocationPurpose::Destination,
            environment_id: self.environment_id,
            admitting,
        };
        let held = self.locations().admit(located.location_id, &wanted)?;
        let admission = self
            .locations()
            .read_admission(vec![(Arc::clone(&held), wanted)]);
        Ok(TreeReach {
            through: Some((held, RelativeName::parse(&located.relative_path)?)),
            admission,
        })
    }

    /// Returns whether a workspace's working files are gone.
    ///
    /// A path this host cannot look at is not a path it found empty, so anything other than a
    /// plain absence answers "still there". A tree reached through a location is asked about
    /// through that location's handle.
    fn tree_gone(&self, row: &WorkspaceRow, reach: &TreeReach) -> bool {
        match &reach.through {
            Some((held, name)) => {
                reach
                    .admission
                    .as_ref()
                    .is_none_or(|admission| admission.admit().is_ok())
                    && matches!(
                        held.handle().probe(name),
                        Err(kr_transfer::Escape::NotFound { .. })
                    )
            }
            None => matches!(
                std::fs::symlink_metadata(&row.display_path),
                Err(ref failure) if failure.kind() == std::io::ErrorKind::NotFound
            ),
        }
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
                workspace: workspace_id.to_string().into(),
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
                    RetainedOutcome::Error { code, detail } => Err(ProjectError::Retained {
                        code,
                        detail: detail.into(),
                    }),
                };
            }
        }
        Ok(result)
    }

    fn remove_working_tree(&self, row: &WorkspaceRow, reach: &TreeReach) -> Result<()> {
        let path = PathBuf::from(&row.display_path);
        let Some(parent) = path.parent() else {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} has no parent directory",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        };
        let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
            return Err(ProjectError::Destination {
                detail: format!(
                    "{} has no final name",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        };
        let (parent, name) = match &reach.through {
            // Through the location, and asked for immediately before it starts. The tree's name
            // beneath the location can have several components, and a removal takes one entry
            // out of the directory that holds it, so that directory is found first.
            Some((held, relative)) => {
                if let Some(admission) = &reach.admission {
                    admission.admit()?;
                }
                let (above, leaf) = split_last(relative)?;
                let parent = match above {
                    None => held.handle().try_clone()?,
                    Some(above) => match held.handle().subdirectory(&above) {
                        Ok(parent) => parent,
                        // The directory the tree was in is not there, so neither is the tree.
                        Err(kr_transfer::Escape::NotFound { .. }) => return Ok(()),
                        Err(refusal) => return Err(refusal.into()),
                    },
                };
                (parent, leaf)
            }
            None => (
                kr_transfer::AuthorisedDirectory::open_root(self.environment_id, parent)?,
                RelativeName::parse(name)?,
            ),
        };
        if !parent.occupied(&name)? {
            // Already gone, which is what a second removal under a different retention policy
            // finds, and so is a tree a materialisation that failed early never made. There is
            // nothing to remove and nothing to refuse: an identity is what authorises removing an
            // object, and an absence needs no authority.
            return Ok(());
        }
        let Some(expected) = row.identity else {
            // The materialisation never got as far as recording the tree's identity, so this host
            // cannot prove the directory at that path is one it created. Removing it would be
            // removing whatever is there, which is exactly what an identity exists to stop.
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this host recorded no filesystem identity for the workspace at {}, so it \
                     will not remove what is there; the directory is left for a person to look at",
                    crate::git::redact(&path.display().to_string())
                )
                .into(),
            });
        };
        // The identity is checked before anything is removed: a record whose object has been
        // replaced does not authorise removing whatever now holds its path.
        let here = parent.subdirectory(&name)?;
        if here.identity() != expected {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "this workspace was recorded as {expected} and {} now holds {}; nothing is \
                     removed",
                    crate::git::redact(&path.display().to_string()),
                    here.identity()
                )
                .into(),
            });
        }
        // The tree goes through the handle whose identity was just checked and through handles
        // the removal opens beneath it, never through a path, so no name in the tree can be
        // swapped underneath it. The tree's own name goes last, only while it still holds this
        // directory and only once it is empty: a replacement at it is refused rather than
        // emptied. A removal that stops says where, and what it removed stays removed.
        parent
            .remove_tree(&name, here)
            .map_err(|refusal| ProjectError::Destination {
                detail: format!(
                    "{} was not removed: {}",
                    crate::git::redact(&path.display().to_string()),
                    crate::git::redact(&refusal.to_string())
                )
                .into(),
            })?;
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

    /// Records a pin under a check the caller makes inside this journal's hold.
    ///
    /// The other half of [`Self::with_pins`], and the reason the two together are a protocol
    /// rather than two readings. A deletion reads the pins with this journal held and removes the
    /// version inside that hold. A pin written without the same hold could be recorded against a
    /// version the deletion has already taken away, because this journal knows nothing about
    /// versions and cannot tell. Here the caller's own question — is the version still there —
    /// and the write of the pin happen inside one hold, and the deletion's reading takes the same
    /// lock, so the two cannot be interleaved.
    ///
    /// `still_there` answers false for a version that is gone **and** for a store the caller could
    /// not read: an unreadable store is not a version this host found, and refusing the pin is the
    /// answer that loses nothing.
    ///
    /// **The lock order is this journal first, the caller's store inside it**, which is
    /// [`Self::with_pins`]'s order. Nothing is awaited inside `still_there`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::WrongState`] when `still_there` answers false, and whatever
    /// [`Self::retain`] returns otherwise.
    pub fn retain_pin(
        &self,
        workspace_id: WorkspaceId,
        item: &RetainedRow,
        still_there: impl FnOnce() -> bool,
    ) -> Result<()> {
        let mut store = self.writable()?;
        if !still_there() {
            return Err(ProjectError::WrongState {
                detail: "the version this pin names is not one this host holds, so nothing is \
                         pinned against the workspace"
                    .to_owned()
                    .into(),
            });
        }
        store.retain(workspace_id, item)
    }

    /// Returns every pin held against one change set, in this whole environment.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read. A journal this
    /// host could not read is never an absence of pins.
    pub fn pins(&self, change_set_id: ChangeSetId) -> Result<Vec<PinnedRow>> {
        self.locked()?.pins(change_set_id)
    }

    /// Reads every pin held against one change set and keeps the journal shut while a caller acts
    /// on them.
    ///
    /// The change-set store counts what holds a version and removes it in one transaction, so
    /// nothing recorded in between is lost. A pin is not in that store, and reading the pins and
    /// then removing the version would leave a window between the two: a pin recorded in there
    /// would be a pin the removal never saw. Here the reading and the caller's own transaction
    /// happen inside one hold on this journal, and [`Self::retain`] takes that same lock, so a pin
    /// is either recorded before the reading, where it is counted, or after the caller's
    /// transaction has finished.
    ///
    /// What that establishes is exclusion, and it is worth saying what it does not: this journal
    /// knows nothing about versions, so a pin recorded after a version was deleted is still
    /// recorded. A caller that must not record one against a version that is gone checks that for
    /// itself, inside a hold on this journal, so that its check and its write cannot be separated
    /// either.
    ///
    /// **The lock order is this journal first, the caller's store inside it.** A caller that
    /// already holds its own store's lock does not call this: the pin's own path takes them the
    /// other way round, and two callers taking one pair of locks in two orders wait for each
    /// other. Nothing is awaited inside `act`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be read.
    pub fn with_pins<T>(
        &self,
        change_set_id: ChangeSetId,
        act: impl FnOnce(&[PinnedRow]) -> T,
    ) -> Result<T> {
        let store = self.locked()?;
        let pinned = store.pins(change_set_id)?;
        Ok(act(&pinned))
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
                action: action_id.to_string().into(),
                method: record.method.into(),
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
                operation: action_id.to_string().into(),
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
    pub(crate) fn answer_from_record<T: serde::de::DeserializeOwned + serde::Serialize>(
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
                action: action.action_id.to_string().into(),
                method: record.method.into(),
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
                detail: record
                    .error_detail
                    .unwrap_or_else(|| {
                        format!("action {} was recorded as {code}", action.action_id)
                    })
                    .into(),
            }),
            // Claimed and not settled: another copy of this action is performing the effect.
            (None, None) => Err(ProjectError::OutcomeUnknown {
                detail: format!(
                    "action {} claimed its effect and its result is not recorded yet; read the \
                     operation or cancel it rather than submitting it again",
                    action.action_id
                )
                .into(),
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
            return Err(ProjectError::InvalidArgument(
                format!(
                    "{} is not a revision this repository holds",
                    // The revision is the caller's own text, and it goes into a message a journal
                    // keeps and another actor can read, so it goes through the same rule.
                    crate::git::redact(revision)
                )
                .into(),
            ));
        }
        Ok(output.text().trim().to_owned())
    }

    pub(crate) fn summarise(&self, row: &ProjectRow, workspace_count: u64) -> ProjectSummary {
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
            detail: Nullable(with_staging_notes(
                row.detail.clone(),
                store
                    .workspace_staging_detail(row.workspace_id)?
                    .map(|why| (workspace_staging_path(row), why)),
            )),
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
            detail: Nullable(with_staging_notes(
                row.detail.clone(),
                paths
                    .iter()
                    .filter(|path| !path.removed)
                    .filter_map(|path| path.why.clone().map(|why| (path.path.clone(), why))),
            )),
            started_at_ms: row.started_at_ms,
            ended_at_ms: Nullable(row.ended_at_ms),
        }
    }
}

/// Returns the location a repository was created through, and its name beneath it, when the
/// destination was a location. This is provenance, never source authority.
fn created_through(destination: &Destination) -> Option<LocatedName> {
    destination.location().map(|held| LocatedName {
        location_id: held.location_id(),
        relative_path: destination.name().as_str().to_owned(),
    })
}

/// Why recovery reaches nothing a row names.
fn unreachable_reason(location: Option<ProjectLocationId>) -> String {
    match location {
        None => "no location reaches it, because none was recorded for it and a recorded path is \
                 not authority; the owner reconciles it through a location that contains it"
            .to_owned(),
        Some(location) => format!(
            "location {location} holds no directory now: it was withdrawn, or this host has not \
             held it since it last started, and a recorded path is not authority; the owner \
             reconciles it through a location that contains it"
        ),
    }
}

/// Puts why a staging directory is still there beside the reason a record already carries.
///
/// A cleanup that stopped part way is not a reason the operation or the workspace ended where it
/// did, and it does not turn a publication that landed into a failure. It is still something a
/// person has to be able to read, with where the removal stopped and what went before it did, so
/// it travels in the same field, after the reason.
fn with_staging_notes(
    detail: Option<String>,
    kept: impl IntoIterator<Item = (String, String)>,
) -> Option<String> {
    let notes = kept.into_iter().map(|(path, why)| {
        format!(
            "the staging directory {} is still there: {why}",
            crate::git::redact(&path)
        )
    });
    let parts: Vec<String> = detail.into_iter().chain(notes).collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// Returns where a workspace's staging sibling is, from what the row recorded, for a person to
/// read. Composed from the recorded strings alone: nothing is looked up to say it.
fn workspace_staging_path(row: &WorkspaceRow) -> String {
    let name = row.staging_name.as_deref().unwrap_or_default();
    Path::new(&row.display_path).parent().map_or_else(
        || name.to_owned(),
        |parent| parent.join(name).display().to_string(),
    )
}

/// How a removal reaches a workspace's tree.
struct TreeReach {
    /// The location the tree is reached through, admitted, and the tree's name beneath it: the
    /// location the workspace was created through, or one the owner named that contains it. None
    /// for a workspace that recorded no location and was named no location.
    through: Option<(Arc<HeldLocation>, RelativeName)>,
    /// What every read of the removal asks before it starts, when there is a location.
    admission: Option<ReadAdmission>,
}

impl TreeReach {
    /// Returns the reach of another entry of the directory the tree is in, through the same
    /// location and asking the same question.
    fn beside(&self, name: &str) -> Result<Self> {
        let Some((held, tree)) = &self.through else {
            return Ok(Self {
                through: None,
                admission: None,
            });
        };
        let relative = match split_last(tree)?.0 {
            None => RelativeName::parse(name)?,
            Some(above) => RelativeName::parse(&format!("{}/{name}", above.as_str()))?,
        };
        Ok(Self {
            through: Some((Arc::clone(held), relative)),
            admission: self.admission.clone(),
        })
    }
}

/// Splits a relative name into the name of the directory above its last component, when it has
/// one, and that last component.
fn split_last(name: &RelativeName) -> Result<(Option<RelativeName>, RelativeName)> {
    let components = name.components();
    let Some((last, above)) = components.split_last() else {
        return Err(ProjectError::InvalidArgument(
            "a relative name has at least one component"
                .to_owned()
                .into(),
        ));
    };
    let above = if above.is_empty() {
        None
    } else {
        Some(RelativeName::parse(&above.join("/"))?)
    };
    Ok((above, RelativeName::parse(last)?))
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

/// Says that the attempt carried no credential, where that is so.
///
/// The broker a caller named is approved and lends no credential helper on this host, so nothing in
/// the attempt could have authenticated. This is context rather than a diagnosis: it says what was
/// available, not that the absence is why the attempt failed, because Git's own words are not
/// repeated and this host cannot tell a refused authentication from a remote that was never
/// reached.
fn unauthenticated_fetch(error: ProjectError, remote: &ValidatedRemote) -> ProjectError {
    if !remote.unauthenticated() || !matches!(error, ProjectError::GitFailed { .. }) {
        return error;
    }
    ProjectError::GitFailed {
        detail: format!(
            "{error}; the approved broker {} lends no credential helper on this host, so no \
             credential was available for this attempt",
            crate::git::redact(&remote.specification.credential_broker)
        )
        .into(),
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
                        crate::git::redact(&destination.path().display().to_string())
                    )
                    .into(),
                })
            }
            DestinationState::Occupied => Err(ProjectError::Destination {
                detail: format!(
                    "{} is not a directory, so there is no checkout to adopt",
                    crate::git::redact(&destination.path().display().to_string())
                )
                .into(),
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
                    crate::git::redact(&destination.path().display().to_string())
                )
                .into(),
            }),
        },
    }
}

pub(crate) fn check_label(label: &str) -> Result<()> {
    if label.is_empty() || label.chars().count() > MAX_LABEL_LEN {
        return Err(ProjectError::InvalidArgument(
            format!("a label is between one and {MAX_LABEL_LEN} characters").into(),
        ));
    }
    if label.chars().any(char::is_control) {
        return Err(ProjectError::InvalidArgument(
            "a label carries no control character".to_owned().into(),
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
        return Err(ProjectError::InvalidArgument(
            format!("{} is not a branch name", crate::git::redact(branch)).into(),
        ));
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
        return Err(ProjectError::InvalidArgument(
            format!("{} is not a revision", crate::git::redact(revision)).into(),
        ));
    }
    Ok(())
}

pub(crate) fn new_uuid() -> Uuid {
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
        // The table is the rule: a creation needs a destination that is not there at all, and an
        // adoption needs a checkout to adopt. Section 14 refuses a nonempty *or existing*
        // destination for a creation, so an empty directory is refused too, and the refusal names
        // the flow that would take it.
        let directory = tempfile::TempDir::new().expect("a directory on the internal disk");
        let destination = Destination::resolve(
            &DestinationRequest {
                environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
                parent: kr_protocol::project::DestinationParent::Host {
                    path: directory.path().display().to_string(),
                },
                name: "where".to_owned(),
            },
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            &crate::policy::LocationPolicy::default(),
            Admitting::Caller(None),
        )
        .expect("the destination resolves");
        let creation = CreatePlan::Initialise {
            initial_branch: None,
        };
        let adoption = CreatePlan::Adopt {
            flow: AdoptionFlow::ExistingCheckout,
        };
        for (state, creation_allowed, adoption_allowed) in [
            (DestinationState::Absent, true, false),
            (DestinationState::EmptyDirectory, false, false),
            (DestinationState::NonEmptyDirectory, false, true),
            (DestinationState::Occupied, false, false),
        ] {
            let created = check_destination(&creation, state, &destination);
            assert_eq!(
                created.is_ok(),
                creation_allowed,
                "a creation at {state:?}: {created:?}"
            );
            if let Err(refusal) = created {
                assert_eq!(
                    refusal.code(),
                    kr_protocol::error::ErrorCode::InvalidArgument
                );
                assert!(
                    refusal.to_string().contains("flow"),
                    "a creation's refusal names the flow that would take it: {refusal}"
                );
            }
            let adopted = check_destination(&adoption, state, &destination);
            assert_eq!(
                adopted.is_ok(),
                adoption_allowed,
                "an adoption at {state:?}: {adopted:?}"
            );
            if let Err(refusal) = adopted {
                assert_eq!(
                    refusal.code(),
                    kr_protocol::error::ErrorCode::InvalidArgument
                );
                assert!(
                    refusal.to_string().contains("adopt"),
                    "an adoption's refusal says there is nothing to adopt: {refusal}"
                );
            }
        }
    }
}
