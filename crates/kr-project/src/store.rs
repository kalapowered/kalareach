//! `projects.sqlite`: the project journal.
//!
//! Write-ahead logging with full synchronisation, forward-only migrations, and every state change
//! committed together with the outbox row that announces it. What the order of the writes buys is
//! the recovery section 24 asks for: immutable workspace versions and partial progress survive the
//! daemon's death, and cleanup respects pins.
//!
//! * An **operation** row exists before anything is created on disk, and its primary key is the
//!   action identifier the caller submitted. That row *is* the create token: a crash or an
//!   ambiguous publish is reconciled against it rather than retried as another clone.
//! * Publication is two commits with the staged object's filesystem identity between them. The row
//!   moves to `publishing` naming the staging directory, the destination name and that identity;
//!   then the directory is renamed; then the row moves to `completed` and the repository row is
//!   written. A daemon that dies in the middle resolves it by asking which name holds *that
//!   object*.
//! * A **workspace** row is written before its working tree is materialised and moves to `ready`
//!   only when the tree exists, so a partly materialised workspace is a row in `materialising`
//!   rather than a workspace that looks usable.
//! * A **retained** row is what stops a removal: dirty content, a pinned change set and review
//!   evidence each get one, and a removal that finds any of them leaves the workspace in
//!   `removal_pending` until the user approves.
//! * An **action** row claims a mutation in the same transaction as its effect, so two copies of
//!   one action agree about what happened. It is the de-duplication record rather than an object
//!   whose transitions a consumer replays, so it carries no outbox row of its own: what a consumer
//!   replays is the state the claim was opened beside.

use std::path::Path;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, ActorId, ChangeSetId, EnvironmentId, ProjectRepositoryId, SessionId, WorkflowRunId,
    WorkspaceId,
};
use kr_protocol::project::{
    AdoptionFlow, DestinationState, InclusionChoice, InclusionPolicy, IsolationMechanism,
    OperationState, ProjectOrigin, ProjectState, RemoteSpecification, RemoteTransport,
    RetainedKind, RetentionPolicy, WorkspaceKind, WorkspaceState,
};
use kr_protocol::scalars::{Digest256, TimestampMs, U64, Uuid};
use rusqlite::{Connection, OptionalExtension as _, Transaction, params};

use kr_transfer::ObjectIdentity;

use crate::error::{ProjectError, Result};
use crate::identity::RepositoryIdentity;
use crate::operation::StagedWitness;

/// The schema version this build reads.
pub const SCHEMA_VERSION: i64 = 4;

/// What an inclusion records for a path whose outcome it has not established.
pub const PROGRESS_PLANNED: &str = "planned";

/// The directory, under the environment's state directory, that the project service owns.
pub const PROJECTS_DIRECTORY: &str = "projects";

/// The project store's filename inside that directory.
pub const STORE_FILE_NAME: &str = "projects.sqlite";

/// One recorded repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectRow {
    /// Its environment-local identity.
    pub project_repository_id: ProjectRepositoryId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The label the user gave it.
    pub label: String,
    /// How it came to be known here.
    pub origin: ProjectOrigin,
    /// What state the record is in.
    pub state: ProjectState,
    /// The stable filesystem identity of its repository and of the working tree it was recorded
    /// against.
    pub identity: RepositoryIdentity,
    /// The path it was created or adopted at, for a person to read.
    pub display_path: String,
    /// The remote it was cloned from, when it has one.
    pub remote: Option<RemoteSpecification>,
    /// When the record was written.
    pub created_at_ms: TimestampMs,
}

/// What one operation state change records beside the state.
///
/// Every field is optional and an absent one leaves what the row holds alone, so one call carries
/// whichever of them the caller has learned.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationUpdate<'a> {
    /// Why it is in the state it is in.
    pub detail: Option<&'a str>,
    /// When it ended.
    pub ended_at_ms: Option<TimestampMs>,
    /// What this host recorded about the object it staged, before the publication.
    pub staged_identity: Option<StagedWitness>,
    /// The private sibling the content is staged in.
    pub staging_name: Option<&'a str>,
    /// That sibling's own filesystem identity.
    pub staging_identity: Option<ObjectIdentity>,
}

/// What one workspace state change records beside the state.
///
/// Every field is optional and an absent one leaves what the row holds alone, so one call carries
/// whichever of them the caller has learned.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkspaceUpdate<'a> {
    /// The working tree's filesystem identity, once there is one.
    pub identity: Option<ObjectIdentity>,
    /// The retention policy a removal was requested under.
    pub retention: Option<RetentionPolicy>,
    /// When it was removed.
    pub removed_at_ms: Option<TimestampMs>,
    /// The private sibling an independent clone is staged in.
    pub staging_name: Option<&'a str>,
    /// The filesystem identity of that sibling, once the directory exists.
    pub staging_identity: Option<ObjectIdentity>,
    /// Why it is in the state it is in.
    pub detail: Option<&'a str>,
}

/// A workspace reserved for removal, and the token that reservation is held under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// The workspace as it was inside the reserving transaction.
    pub row: WorkspaceRow,
    /// What the reservation is held under, so only its holder releases it.
    pub token: Uuid,
}

/// One recorded workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRow {
    /// Its identity.
    pub workspace_id: WorkspaceId,
    /// The repository it is a working copy of.
    pub project_repository_id: ProjectRepositoryId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The label the user gave it.
    pub label: String,
    /// Which kind it is.
    pub kind: WorkspaceKind,
    /// How an isolated workspace is separated.
    pub isolation: Option<IsolationMechanism>,
    /// The inclusion policy it was created under.
    pub policy: InclusionPolicy,
    /// What state it is in.
    pub state: WorkspaceState,
    /// The revision it started from.
    pub base_revision: String,
    /// The change-set version it materialised, when it named one.
    pub base_change_set_id: Option<ChangeSetId>,
    /// The stable filesystem identity of its working tree.
    pub identity: Option<ObjectIdentity>,
    /// The path its working tree is at.
    pub display_path: String,
    /// The private sibling an independent clone was staged in, while one existed.
    pub staging_name: Option<String>,
    /// That sibling's own filesystem identity, so a cleanup removes the directory this host
    /// created rather than whatever holds the name now.
    pub staging_identity: Option<ObjectIdentity>,
    /// Why it is in the state it is in, when it ended up there for a reason.
    pub detail: Option<String>,
    /// The retention policy a removal was requested under, when one was.
    pub retention: Option<RetentionPolicy>,
    /// When it was created.
    pub created_at_ms: TimestampMs,
    /// When it was removed, once it was.
    pub removed_at_ms: Option<TimestampMs>,
}

/// One recorded repository operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRow {
    /// The action that started it, which is the create token.
    pub action_id: ActionId,
    /// The actor that submitted it. Only that actor may cancel it.
    pub actor_id: ActorId,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The repository it creates.
    pub project_repository_id: ProjectRepositoryId,
    /// Which method started it.
    pub method: String,
    /// What state it is in.
    pub state: OperationState,
    /// The remote it reaches, when it reaches one.
    pub remote: Option<RemoteSpecification>,
    /// The adoption flow the caller chose, when it chose one.
    pub flow: Option<AdoptionFlow>,
    /// The destination's state when the operation was admitted.
    pub destination_state: DestinationState,
    /// The parent directory the destination is in.
    pub parent_path: String,
    /// The single name inside it.
    pub destination_name: String,
    /// The private sibling the content was staged in, when one was made.
    pub staging_name: Option<String>,
    /// That sibling's own filesystem identity, recorded when it was created.
    ///
    /// A recorded name is not authority to remove whatever now holds it. The identity is what
    /// makes the cleanup a removal of this host's own directory rather than of a replacement.
    pub staging_identity: Option<ObjectIdentity>,
    /// What this host recorded about the object it staged, before the publication.
    ///
    /// This is what makes an interrupted publication resolvable: the question is not whether a
    /// name exists but which name holds *this object*.
    pub staged_identity: Option<StagedWitness>,
    /// Why it ended, when it ended for a reason.
    pub detail: Option<String>,
    /// When it started.
    pub started_at_ms: TimestampMs,
    /// When it ended, once it has.
    pub ended_at_ms: Option<TimestampMs>,
}

/// One thing a workspace holds that its removal has to account for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedRow {
    /// What kind of thing it is.
    pub kind: RetainedKind,
    /// What it is, in the host's own words.
    pub detail: String,
    /// The change set it belongs to, when it belongs to one.
    pub change_set_id: Option<ChangeSetId>,
}

/// One staging path an operation left behind or removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingPathRow {
    /// The path.
    pub path: String,
    /// True when this host removed it.
    pub removed: bool,
}

/// The action one mutation is performed under.
///
/// A mutation whose idempotency is its action identifier commits this together with the state it
/// changes, in one transaction. A second attempt at the same action therefore finds the first
/// already recorded and changes nothing, whether it arrives after the reply was lost or beside it
/// on another connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The actor performing it.
    pub actor_id: ActorId,
    /// The durable operation identity.
    pub action_id: Uuid,
    /// The method being performed.
    pub method: String,
    /// The digest of the payload it was submitted with.
    pub payload_digest: Digest256,
}

/// One retained mutation outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedOutcome {
    /// The mutation succeeded, and this is the canonically encoded result it returned.
    Ok(Vec<u8>),
    /// The mutation failed, and this is the error it returned.
    Error {
        /// The stable protocol code.
        code: ErrorCode,
        /// The message.
        detail: String,
    },
}

/// One row of the action table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedAction {
    /// The actor.
    pub actor_id: ActorId,
    /// The action identifier.
    pub action_id: Uuid,
    /// The method it was performed under.
    pub method: String,
    /// The payload digest it was submitted with.
    pub payload_digest: Digest256,
    /// The operation it claimed, for an effect whose result comes later.
    pub subject: Option<Uuid>,
    /// The encoded result, once there is one.
    pub result: Option<Vec<u8>>,
    /// The failure code, when it failed.
    pub error_code: Option<String>,
    /// The failure message, when it failed.
    pub error_detail: Option<String>,
    /// When the row was written.
    pub recorded_at_ms: TimestampMs,
}

/// The project journal of one environment.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    environment_id: EnvironmentId,
}

impl Store {
    /// Opens the store for an environment, creating it on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>, environment_id: EnvironmentId) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(ProjectError::store)?;
        Self::prepare(connection, environment_id)
    }

    /// Opens a store that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the database cannot be created.
    pub fn in_memory(environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare(
            Connection::open_in_memory().map_err(ProjectError::store)?,
            environment_id,
        )
    }

    fn prepare(connection: Connection, environment_id: EnvironmentId) -> Result<Self> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ProjectError::store)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ProjectError::store)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(ProjectError::store)?;
        let mut store = Self {
            connection,
            environment_id,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        // One transaction for the whole upgrade, because section 24 asks for a transactional
        // migration: the tables this build needs, the columns an earlier shape did not have, and
        // the version that describes them all land together or none of them does. A store is
        // never left saying it is at a version whose shape it does not have, and a store this
        // build refuses is left exactly as it was found.
        let transaction = self.connection.transaction().map_err(ProjectError::store)?;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS projects (
                     project_repository_id BLOB PRIMARY KEY,
                     environment_id        BLOB NOT NULL,
                     label                 TEXT NOT NULL,
                     origin                TEXT NOT NULL,
                     state                 TEXT NOT NULL,
                     git_dir_device        INTEGER NOT NULL,
                     git_dir_file_id       INTEGER NOT NULL,
                     work_tree_device      INTEGER NOT NULL,
                     work_tree_file_id     INTEGER NOT NULL,
                     display_path          TEXT NOT NULL,
                     remote_name           TEXT,
                     remote_transport      TEXT,
                     remote_url            TEXT,
                     remote_provider       TEXT,
                     remote_broker         TEXT,
                     created_at_ms         INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS workspaces (
                     workspace_id          BLOB PRIMARY KEY,
                     project_repository_id BLOB NOT NULL,
                     environment_id        BLOB NOT NULL,
                     label                 TEXT NOT NULL,
                     kind                  TEXT NOT NULL,
                     isolation             TEXT,
                     dirty_files           TEXT NOT NULL,
                     untracked_files       TEXT NOT NULL,
                     submodules            TEXT NOT NULL,
                     binary_files          TEXT NOT NULL,
                     generated_artefacts   TEXT NOT NULL,
                     state                 TEXT NOT NULL,
                     base_revision         TEXT NOT NULL,
                     base_change_set_id    BLOB,
                     tree_device           INTEGER,
                     tree_file_id          INTEGER,
                     display_path          TEXT NOT NULL,
                     staging_name          TEXT,
                     staging_device        INTEGER,
                     staging_file_id       INTEGER,
                     removal_action        BLOB,
                     detail                TEXT,
                     retention             TEXT,
                     created_at_ms         INTEGER NOT NULL,
                     removed_at_ms         INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS workspace_progress (
                     workspace_id BLOB NOT NULL,
                     path         TEXT NOT NULL,
                     outcome      TEXT NOT NULL,
                     PRIMARY KEY (workspace_id, path)
                 );
                 CREATE TABLE IF NOT EXISTS workspace_sessions (
                     workspace_id BLOB NOT NULL,
                     session_id   BLOB NOT NULL,
                     live         INTEGER NOT NULL DEFAULT 1,
                     PRIMARY KEY (workspace_id, session_id)
                 );
                 CREATE TABLE IF NOT EXISTS workspace_runs (
                     workspace_id BLOB NOT NULL,
                     run_id       BLOB NOT NULL,
                     live         INTEGER NOT NULL DEFAULT 1,
                     PRIMARY KEY (workspace_id, run_id)
                 );
                 CREATE TABLE IF NOT EXISTS workspace_retained (
                     workspace_id  BLOB NOT NULL,
                     kind          TEXT NOT NULL,
                     detail        TEXT NOT NULL,
                     change_set_id BLOB,
                     PRIMARY KEY (workspace_id, kind, detail)
                 );
                 CREATE TABLE IF NOT EXISTS operations (
                     action_id             BLOB PRIMARY KEY,
                     actor_id              TEXT NOT NULL,
                     environment_id        BLOB NOT NULL,
                     project_repository_id BLOB NOT NULL,
                     method                TEXT NOT NULL,
                     state                 TEXT NOT NULL,
                     remote_name           TEXT,
                     remote_transport      TEXT,
                     remote_url            TEXT,
                     remote_provider       TEXT,
                     remote_broker         TEXT,
                     flow                  TEXT,
                     destination_state     TEXT NOT NULL,
                     parent_path           TEXT NOT NULL,
                     destination_name      TEXT NOT NULL,
                     staging_name          TEXT,
                     staging_device        INTEGER,
                     staging_file_id       INTEGER,
                     staged_device         INTEGER,
                     staged_file_id        INTEGER,
                     staged_created_at_ms  INTEGER,
                     detail                TEXT,
                     started_at_ms         INTEGER NOT NULL,
                     ended_at_ms           INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS operation_paths (
                     action_id BLOB NOT NULL,
                     path      TEXT NOT NULL,
                     removed   INTEGER NOT NULL,
                     PRIMARY KEY (action_id, path)
                 );
                 CREATE TABLE IF NOT EXISTS actions (
                     actor_id       TEXT NOT NULL,
                     action_id      BLOB NOT NULL,
                     method         TEXT NOT NULL,
                     payload_digest BLOB NOT NULL,
                     subject        BLOB,
                     result         BLOB,
                     error_code     TEXT,
                     error_detail   TEXT,
                     recorded_at_ms INTEGER NOT NULL,
                     PRIMARY KEY (actor_id, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind           TEXT NOT NULL,
                     subject        TEXT NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS cursors (
                     consumer TEXT PRIMARY KEY,
                     sequence INTEGER NOT NULL
                 );",
            )
            .map_err(ProjectError::store)?;
        let recorded: Option<i64> = transaction
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .map_err(ProjectError::store)?;
        match recorded {
            None => {
                transaction
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ProjectError::store)?;
            }
            Some(version) if version == SCHEMA_VERSION => {}
            // Forward only. `CREATE TABLE IF NOT EXISTS` leaves a table that already exists
            // exactly as it was, so a store written by an earlier build has the tables and not
            // the columns added since: each one is added here and the version is moved on.
            //
            // The version says which *build* wrote the store, not which columns it has, and one
            // earlier build moved a store to version 2 while adding only some of them. So the
            // step runs for every version below the current one and adds whatever is missing,
            // rather than trusting a version number to describe a shape.
            //
            // Version 4 is the version this host started putting a reason through the rule at the
            // write. A store at 3 has the right columns and the wrong contents, which is why the
            // version moves on for a change that adds no column at all.
            Some(version) if version < SCHEMA_VERSION => {
                add_missing_columns(&transaction)?;
                protect_recorded_reasons(&transaction)?;
                transaction
                    .execute(
                        "UPDATE schema_version SET version = ?1",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ProjectError::store)?;
            }
            Some(version) => {
                // The transaction is dropped without committing, so a store this build cannot
                // read is left exactly as it was: nothing this migration would have created is
                // there afterwards.
                return Err(ProjectError::StoreUnavailable {
                    detail: format!(
                        "this project store is at schema version {version}; this build reads \
                         {SCHEMA_VERSION}"
                    ),
                });
            }
        }
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns the environment this store belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Begins a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the transaction cannot be started.
    pub fn transaction(&mut self) -> Result<Transaction<'_>> {
        self.connection.transaction().map_err(ProjectError::store)
    }

    // ----- operations -----------------------------------------------------------------------

    /// Writes an operation row and claims its action, in one transaction.
    ///
    /// The row exists before anything is created on disk, and its key is the action identifier, so
    /// a crash afterwards is reconciled against this row rather than retried as another clone.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails, or
    /// [`ProjectError::IdConflict`] when the action was already used for another request.
    pub fn begin_operation(&mut self, row: &OperationRow, action: Option<&Action>) -> Result<()> {
        let transaction = self.transaction()?;
        // The claim comes first, because the operation's own key is the action identifier: a
        // second copy of one action would otherwise be refused for a unique-key collision rather
        // than told that its action is already claimed.
        if let Some(action) = action {
            claim_action(&transaction, action, Some(row.action_id.get()))?;
        }
        insert_operation(&transaction, row)?;
        announce(
            &transaction,
            "project.operation.began",
            &row.action_id.to_string(),
            row.started_at_ms,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Moves an operation to a new state, recording what is known about it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn set_operation_state(
        &mut self,
        action_id: ActionId,
        state: OperationState,
        update: &OperationUpdate<'_>,
    ) -> Result<()> {
        let OperationUpdate {
            detail,
            ended_at_ms,
            staged_identity,
            staging_name,
            staging_identity,
        } = *update;
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                "UPDATE operations
                    SET state = ?2,
                        detail = COALESCE(?3, detail),
                        ended_at_ms = COALESCE(?4, ended_at_ms),
                        staged_device = COALESCE(?5, staged_device),
                        staged_file_id = COALESCE(?6, staged_file_id),
                        staged_created_at_ms = COALESCE(?7, staged_created_at_ms),
                        staging_name = COALESCE(?8, staging_name),
                        staging_device = COALESCE(?9, staging_device),
                        staging_file_id = COALESCE(?10, staging_file_id)
                  WHERE action_id = ?1",
                params![
                    action_id.get().as_bytes().to_vec(),
                    operation_state_text(state),
                    // A reason is free text a caller reads back, so it goes through the rule at
                    // the write, as every other retained diagnostic does.
                    detail.map(crate::git::redact),
                    ended_at_ms.map(|stamp| i64_of(stamp.get())),
                    staged_identity.map(|staged| i64_of(staged.identity.device)),
                    staged_identity.map(|staged| i64_of(staged.identity.file_id)),
                    staged_identity
                        .and_then(|staged| staged.created_at_ms)
                        .map(i64_of),
                    staging_name,
                    staging_identity.map(|identity| i64_of(identity.device)),
                    staging_identity.map(|identity| i64_of(identity.file_id)),
                ],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            &format!("project.operation.{}", operation_state_text(state)),
            &action_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns one operation.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the row cannot be read.
    pub fn operation(&self, action_id: ActionId) -> Result<Option<OperationRow>> {
        self.connection
            .query_row(
                &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE action_id = ?1"),
                params![action_id.get().as_bytes().to_vec()],
                read_operation,
            )
            .optional()
            .map_err(ProjectError::store)
    }

    /// Returns every operation in one of the named states.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn operations_in(&self, states: &[OperationState]) -> Result<Vec<OperationRow>> {
        let mut rows = Vec::new();
        for state in states {
            let mut statement = self
                .connection
                .prepare(&format!(
                    "SELECT {OPERATION_COLUMNS} FROM operations WHERE state = ?1 \
                     ORDER BY started_at_ms"
                ))
                .map_err(ProjectError::store)?;
            let mapped = statement
                .query_map(params![operation_state_text(*state)], read_operation)
                .map_err(ProjectError::store)?;
            for row in mapped {
                rows.push(row.map_err(ProjectError::store)?);
            }
        }
        Ok(rows)
    }

    /// Forgets one staging path, because nothing is there.
    ///
    /// A path this host neither removed nor left behind belongs in neither list: reporting it as
    /// removed would claim a removal that never happened, and reporting it as retained would name
    /// a directory a person cannot find.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn forget_staging_path(&mut self, action_id: ActionId, path: &str) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                // A row that says this host removed the directory is history rather than
                // occupancy: an earlier recovery removed it and the operation never closed. That
                // record stays, and only a stale "still there" row goes.
                "DELETE FROM operation_paths
                  WHERE action_id = ?1 AND path = ?2 AND removed = 0",
                params![action_id.get().as_bytes().to_vec(), path],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            "project.operation.staging_absent",
            &action_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Records one staging path and whether it is still there.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn record_staging_path(
        &mut self,
        action_id: ActionId,
        path: &str,
        removed: bool,
    ) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                "INSERT INTO operation_paths (action_id, path, removed) VALUES (?1, ?2, ?3)
                 ON CONFLICT (action_id, path) DO UPDATE SET removed = ?3",
                params![action_id.get().as_bytes().to_vec(), path, removed],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            if removed {
                "project.operation.staging_removed"
            } else {
                "project.operation.staging_retained"
            },
            &action_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns the staging paths one operation accounts for.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn staging_paths(&self, action_id: ActionId) -> Result<Vec<StagingPathRow>> {
        let mut statement = self
            .connection
            .prepare("SELECT path, removed FROM operation_paths WHERE action_id = ?1 ORDER BY path")
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![action_id.get().as_bytes().to_vec()], |row| {
                Ok(StagingPathRow {
                    path: row.get(0)?,
                    removed: row.get(1)?,
                })
            })
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(ProjectError::store)?);
        }
        Ok(rows)
    }

    // ----- repositories ---------------------------------------------------------------------

    /// Publishes a repository: the row, the operation's completion and the claim's result, in one
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn complete_operation(
        &mut self,
        project: &ProjectRow,
        action_id: ActionId,
        action: Option<&Action>,
        result: Option<&[u8]>,
        at_ms: TimestampMs,
    ) -> Result<()> {
        let transaction = self.transaction()?;
        insert_project(&transaction, project)?;
        transaction
            .execute(
                "UPDATE operations SET state = ?2, ended_at_ms = ?3 WHERE action_id = ?1",
                params![
                    action_id.get().as_bytes().to_vec(),
                    operation_state_text(OperationState::Completed),
                    i64_of(at_ms.get()),
                ],
            )
            .map_err(ProjectError::store)?;
        if let (Some(action), Some(result)) = (action, result) {
            settle_claim(&transaction, action, Some(result), None)?;
        }
        announce(
            &transaction,
            "project.created",
            &project.project_repository_id.to_string(),
            at_ms,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns one repository.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the row cannot be read.
    pub fn project(&self, id: ProjectRepositoryId) -> Result<Option<ProjectRow>> {
        self.connection
            .query_row(
                &format!("SELECT {PROJECT_COLUMNS} FROM projects WHERE project_repository_id = ?1"),
                params![id.get().as_bytes().to_vec()],
                read_project,
            )
            .optional()
            .map_err(ProjectError::store)
    }

    /// Returns every repository of one environment, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn projects(&self, environment_id: EnvironmentId) -> Result<Vec<ProjectRow>> {
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT {PROJECT_COLUMNS} FROM projects WHERE environment_id = ?1 \
                 ORDER BY created_at_ms, project_repository_id"
            ))
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(
                params![environment_id.get().as_bytes().to_vec()],
                read_project,
            )
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(ProjectError::store)?);
        }
        Ok(rows)
    }

    /// Moves a repository record to a new state.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn set_project_state(
        &mut self,
        id: ProjectRepositoryId,
        state: ProjectState,
    ) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                "UPDATE projects SET state = ?2 WHERE project_repository_id = ?1",
                params![id.get().as_bytes().to_vec(), project_state_text(state)],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            &format!("project.{}", project_state_text(state)),
            &id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    // ----- workspaces -----------------------------------------------------------------------

    /// Writes a workspace row and claims its action, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails, or
    /// [`ProjectError::IdConflict`] when the action was already used for another request.
    pub fn begin_workspace(&mut self, row: &WorkspaceRow, action: Option<&Action>) -> Result<()> {
        let transaction = self.transaction()?;
        if let Some(action) = action {
            claim_action(&transaction, action, Some(row.workspace_id.get()))?;
        }
        insert_workspace(&transaction, row)?;
        announce(
            &transaction,
            "workspace.created",
            &row.workspace_id.to_string(),
            row.created_at_ms,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Moves a workspace to a new state, recording what a removal decided.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn set_workspace_state(
        &mut self,
        id: WorkspaceId,
        state: WorkspaceState,
        identity: Option<ObjectIdentity>,
        retention: Option<RetentionPolicy>,
        removed_at_ms: Option<TimestampMs>,
    ) -> Result<()> {
        self.set_workspace(
            id,
            state,
            &WorkspaceUpdate {
                identity,
                retention,
                removed_at_ms,
                staging_name: None,
                staging_identity: None,
                detail: None,
            },
        )
    }

    /// Moves a workspace to a new state, recording everything a later read needs.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn set_workspace(
        &mut self,
        id: WorkspaceId,
        state: WorkspaceState,
        update: &WorkspaceUpdate<'_>,
    ) -> Result<()> {
        let WorkspaceUpdate {
            identity,
            retention,
            removed_at_ms,
            staging_name,
            staging_identity,
            detail,
        } = *update;
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                "UPDATE workspaces
                    SET state = ?2,
                        tree_device = COALESCE(?3, tree_device),
                        tree_file_id = COALESCE(?4, tree_file_id),
                        retention = COALESCE(?5, retention),
                        removed_at_ms = COALESCE(?6, removed_at_ms),
                        staging_name = COALESCE(?7, staging_name),
                        staging_device = COALESCE(?8, staging_device),
                        staging_file_id = COALESCE(?9, staging_file_id),
                        detail = COALESCE(?10, detail)
                  WHERE workspace_id = ?1",
                params![
                    id.get().as_bytes().to_vec(),
                    workspace_state_text(state),
                    identity.map(|identity| i64_of(identity.device)),
                    identity.map(|identity| i64_of(identity.file_id)),
                    retention.map(retention_text),
                    removed_at_ms.map(|stamp| i64_of(stamp.get())),
                    staging_name,
                    staging_identity.map(|identity| i64_of(identity.device)),
                    staging_identity.map(|identity| i64_of(identity.file_id)),
                    detail.map(crate::git::redact),
                ],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            &format!("workspace.{}", workspace_state_text(state)),
            &id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Reserves a workspace for removal, in one transaction with everything the decision needs.
    ///
    /// The check and the reservation have to be one step. Otherwise a session or a run bound
    /// between them would be a live holder of a tree that is already going, and two copies of one
    /// removal action would both delete before either was told it lost.
    ///
    /// What this does, atomically: claims the action, refuses a workspace nothing may remove yet,
    /// refuses one a live session or run still holds, moves it to `removal_pending`, and returns
    /// the row and what it holds as they were inside that transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownWorkspace`] when there is no such workspace,
    /// [`ProjectError::WrongState`] while it is being materialised or while another removal of it
    /// is in progress, [`ProjectError::StillBound`] while a session or a run holds it, or
    /// [`ProjectError::IdConflict`] when the action was used for another request.
    pub fn begin_removal(
        &mut self,
        workspace_id: WorkspaceId,
        retention: RetentionPolicy,
        action: Option<&Action>,
    ) -> Result<Reservation> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        if let Some(action) = action {
            claim_action(&transaction, action, Some(workspace_id.get()))?;
        }
        let row = transaction
            .query_row(
                &format!("SELECT {WORKSPACE_COLUMNS} FROM workspaces WHERE workspace_id = ?1"),
                params![workspace_id.get().as_bytes().to_vec()],
                read_workspace,
            )
            .optional()
            .map_err(ProjectError::store)?
            .ok_or_else(|| ProjectError::UnknownWorkspace {
                workspace: workspace_id.to_string(),
            })?;
        if matches!(row.state, WorkspaceState::Materialising) {
            return Err(ProjectError::WrongState {
                detail: format!(
                    "workspace {workspace_id} is still being materialised, so what is in its \
                     directory is not yet something this host can account for"
                ),
            });
        }
        // One removal at a time. `removal_pending` is a state a workspace *rests* in — it holds
        // work the user has not approved removing — so the state alone cannot say whether a
        // removal is running. This does: while one holds the reservation, a second is refused
        // rather than allowed to measure a tree the first is deleting underneath it.
        let held: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT removal_action FROM workspaces WHERE workspace_id = ?1",
                params![workspace_id.get().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .map_err(ProjectError::store)?;
        // The token is this host's own, always, and never the action identifier: two actors may
        // submit the same identifier, and the claim above is what tells those two apart. A
        // reservation is one call's hold on one workspace, so it is one identifier per call.
        let token = fresh_uuid();
        if let Some(held) = held.as_deref().and_then(uuid_of)
            && held != token
        {
            return Err(ProjectError::WrongState {
                detail: format!(
                    "a removal of workspace {workspace_id} is already in progress; read the \
                     workspace for what it holds rather than removing it twice"
                ),
            });
        }
        let sessions: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM workspace_sessions WHERE workspace_id = ?1 AND live = 1",
                params![workspace_id.get().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .map_err(ProjectError::store)?;
        let runs: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM workspace_runs WHERE workspace_id = ?1 AND live = 1",
                params![workspace_id.get().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .map_err(ProjectError::store)?;
        if sessions > 0 || runs > 0 {
            return Err(ProjectError::StillBound {
                detail: format!(
                    "{sessions} sessions and {runs} automation runs bound to this workspace are \
                     still live, and cleanup happens after every bound session and run has finished"
                ),
            });
        }
        transaction
            .execute(
                "UPDATE workspaces SET state = ?2, retention = ?3, removal_action = ?4
                  WHERE workspace_id = ?1",
                params![
                    workspace_id.get().as_bytes().to_vec(),
                    workspace_state_text(WorkspaceState::RemovalPending),
                    retention_text(retention),
                    token.as_bytes().to_vec(),
                ],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            "workspace.removal_pending",
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)?;
        Ok(Reservation { row, token })
    }

    /// Releases a removal reservation without changing what the workspace holds.
    ///
    /// What a removal that failed leaves behind is a workspace nothing is removing, so the next
    /// request can be served. The token is checked: a release only ever gives up this caller's own
    /// reservation.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn release_removal(&mut self, workspace_id: WorkspaceId, token: Uuid) -> Result<()> {
        self.connection
            .execute(
                "UPDATE workspaces SET removal_action = NULL
                  WHERE workspace_id = ?1 AND removal_action = ?2",
                params![
                    workspace_id.get().as_bytes().to_vec(),
                    token.as_bytes().to_vec()
                ],
            )
            .map(|_| ())
            .map_err(ProjectError::store)
    }

    /// Releases every removal reservation, because the daemon that held them is gone.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn release_stale_removals(&mut self) -> Result<u64> {
        let changed = self
            .connection
            .execute(
                "UPDATE workspaces SET removal_action = NULL WHERE removal_action IS NOT NULL",
                [],
            )
            .map_err(ProjectError::store)?;
        Ok(u64::try_from(changed).unwrap_or(0))
    }

    /// Records what became of one batch of paths an inclusion was asked to carry.
    ///
    /// Written as the copy runs rather than at the end of it, so a daemon that dies part way
    /// through leaves a record of the paths it had applied.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn record_workspace_progress(
        &mut self,
        workspace_id: WorkspaceId,
        applied: &[(String, &'static str)],
    ) -> Result<()> {
        if applied.is_empty() {
            return Ok(());
        }
        self.write_progress(workspace_id, applied)
    }

    /// Records every path an inclusion is about to attempt, as `planned`.
    ///
    /// Written before the copy starts, in one transaction. What it buys is that a crash anywhere
    /// in the copy leaves every path either resolved or `planned`: a path with no row at all
    /// would be a path nothing accounts for, which is the thing a replacement daemon cannot
    /// report. `planned` means this host did not establish what became of that path, not that it
    /// was not copied: a copy that landed and whose flush this host never saw leaves the row as
    /// it was.
    ///
    /// The transaction is as large as the inclusion, which is bounded by what a working tree's
    /// status can report rather than by a constant. That is one transaction of inserts against a
    /// local database, taken before any file is touched, which is cheaper than the copy it
    /// precedes.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn plan_workspace_progress(
        &mut self,
        workspace_id: WorkspaceId,
        paths: &[String],
    ) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let planned: Vec<(String, &'static str)> = paths
            .iter()
            .map(|path| (path.clone(), PROGRESS_PLANNED))
            .collect();
        self.write_progress(workspace_id, &planned)
    }

    fn write_progress(
        &mut self,
        workspace_id: WorkspaceId,
        applied: &[(String, &'static str)],
    ) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        for (path, outcome) in applied {
            transaction
                .execute(
                    "INSERT INTO workspace_progress (workspace_id, path, outcome)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (workspace_id, path) DO UPDATE SET outcome = excluded.outcome",
                    params![workspace_id.get().as_bytes().to_vec(), path, outcome],
                )
                .map_err(ProjectError::store)?;
        }
        announce(
            &transaction,
            "workspace.progress",
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns what an inclusion recorded for each path it accounted for, in path order.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn workspace_progress(&self, workspace_id: WorkspaceId) -> Result<Vec<(String, String)>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT path, outcome FROM workspace_progress WHERE workspace_id = ?1
                  ORDER BY path",
            )
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![workspace_id.get().as_bytes().to_vec()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(ProjectError::store)?);
        }
        Ok(rows)
    }

    /// Finishes a removal in one transaction: re-reads what is held, releases it where the policy
    /// approves, and sets the terminal state.
    ///
    /// The re-read is the point. The decision to delete was taken from a list read earlier, and a
    /// pin added since then is a pin the decision never saw: the state it lands in has to be
    /// decided from what is held *now*.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn finish_removal(
        &mut self,
        workspace_id: WorkspaceId,
        retention: RetentionPolicy,
        removed_at_ms: TimestampMs,
    ) -> Result<Vec<RetainedRow>> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        if matches!(retention, RetentionPolicy::RemoveRetained) {
            transaction
                .execute(
                    "DELETE FROM workspace_retained WHERE workspace_id = ?1",
                    params![workspace_id.get().as_bytes().to_vec()],
                )
                .map_err(ProjectError::store)?;
        }
        let mut statement = transaction
            .prepare(
                "SELECT kind, detail, change_set_id FROM workspace_retained
                  WHERE workspace_id = ?1 ORDER BY kind, detail",
            )
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![workspace_id.get().as_bytes().to_vec()], |row| {
                let kind: String = row.get(0)?;
                let change_set: Option<Vec<u8>> = row.get(2)?;
                Ok(RetainedRow {
                    kind: retained_kind_of(&kind),
                    detail: detail_column(row, 1)?,
                    change_set_id: change_set
                        .as_deref()
                        .and_then(uuid_of)
                        .map(ChangeSetId::new),
                })
            })
            .map_err(ProjectError::store)?;
        let mut held = Vec::new();
        for item in mapped {
            held.push(item.map_err(ProjectError::store)?);
        }
        drop(statement);
        let state = if held.is_empty() {
            WorkspaceState::Removed
        } else {
            WorkspaceState::RemovalPending
        };
        transaction
            .execute(
                "UPDATE workspaces SET state = ?2, retention = ?3, removed_at_ms = ?4,
                        removal_action = NULL
                  WHERE workspace_id = ?1",
                params![
                    workspace_id.get().as_bytes().to_vec(),
                    workspace_state_text(state),
                    retention_text(retention),
                    i64_of(removed_at_ms.get()),
                ],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            &format!("workspace.{}", workspace_state_text(state)),
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)?;
        Ok(held)
    }

    /// Forgets a workspace's staging name, once the sibling it named is gone.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn clear_workspace_staging(&mut self, id: WorkspaceId) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                "UPDATE workspaces
                    SET staging_name = NULL, staging_device = NULL, staging_file_id = NULL
                  WHERE workspace_id = ?1",
                params![id.get().as_bytes().to_vec()],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            "workspace.staging_removed",
            &id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns one workspace.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the row cannot be read.
    pub fn workspace(&self, id: WorkspaceId) -> Result<Option<WorkspaceRow>> {
        self.connection
            .query_row(
                &format!("SELECT {WORKSPACE_COLUMNS} FROM workspaces WHERE workspace_id = ?1"),
                params![id.get().as_bytes().to_vec()],
                read_workspace,
            )
            .optional()
            .map_err(ProjectError::store)
    }

    /// Returns the workspaces of one environment, or of one repository inside it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn workspaces(
        &self,
        environment_id: EnvironmentId,
        project: Option<ProjectRepositoryId>,
    ) -> Result<Vec<WorkspaceRow>> {
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT {WORKSPACE_COLUMNS} FROM workspaces
                  WHERE environment_id = ?1
                    AND (?2 IS NULL OR project_repository_id = ?2)
                  ORDER BY created_at_ms, workspace_id"
            ))
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(
                params![
                    environment_id.get().as_bytes().to_vec(),
                    project.map(|id| id.get().as_bytes().to_vec()),
                ],
                read_workspace,
            )
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(ProjectError::store)?);
        }
        Ok(rows)
    }

    /// Binds a session to a workspace, or records that it has ended.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn bind_session(
        &mut self,
        workspace_id: WorkspaceId,
        session_id: SessionId,
        live: bool,
    ) -> Result<()> {
        self.bind(
            workspace_id,
            "workspace_sessions",
            "session_id",
            session_id.get().as_bytes(),
            live,
        )
    }

    /// Records an automation run as bound to a workspace, or as having ended.
    ///
    /// Section 14 makes cleanup wait for every bound session *and run*. A run can hold a workspace
    /// between two sessions or after its last one ended, so it is its own binding.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails, or
    /// [`ProjectError::WrongState`] when the workspace is no longer one anything may hold.
    pub fn bind_run(
        &mut self,
        workspace_id: WorkspaceId,
        run_id: WorkflowRunId,
        live: bool,
    ) -> Result<()> {
        self.bind(
            workspace_id,
            "workspace_runs",
            "run_id",
            run_id.get().as_bytes(),
            live,
        )
    }

    fn bind(
        &mut self,
        workspace_id: WorkspaceId,
        table: &str,
        column: &str,
        holder: &[u8],
        live: bool,
    ) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        // A workspace whose removal has begun takes no new holder. Otherwise a binding that
        // arrived between the removal's check and its deletion would be a live session or run
        // holding a tree that is already going.
        let state: Option<String> = transaction
            .query_row(
                "SELECT state FROM workspaces WHERE workspace_id = ?1",
                params![workspace_id.get().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ProjectError::store)?;
        let state = state.as_deref().map(workspace_state_of);
        if live
            && !matches!(
                state,
                Some(WorkspaceState::Ready | WorkspaceState::Materialising)
            )
        {
            return Err(ProjectError::WrongState {
                detail: format!(
                    "workspace {workspace_id} is {}, so nothing new may hold it",
                    state.map_or("not a workspace this environment has", workspace_state_text)
                ),
            });
        }
        transaction
            .execute(
                &format!(
                    "INSERT INTO {table} (workspace_id, {column}, live) VALUES (?1, ?2, ?3)
                     ON CONFLICT (workspace_id, {column}) DO UPDATE SET live = ?3"
                ),
                params![
                    workspace_id.get().as_bytes().to_vec(),
                    holder.to_vec(),
                    live
                ],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            if live {
                "workspace.bound"
            } else {
                "workspace.released"
            },
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns the automation runs bound to a workspace that are still live.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn live_runs(&self, workspace_id: WorkspaceId) -> Result<Vec<WorkflowRunId>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT run_id FROM workspace_runs
                  WHERE workspace_id = ?1 AND live = 1 ORDER BY run_id",
            )
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![workspace_id.get().as_bytes().to_vec()], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(uuid_of(&bytes).map(WorkflowRunId::new))
            })
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            if let Some(run) = row.map_err(ProjectError::store)? {
                rows.push(run);
            }
        }
        Ok(rows)
    }

    /// Returns the sessions bound to a workspace that are still live.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn live_sessions(&self, workspace_id: WorkspaceId) -> Result<Vec<SessionId>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT session_id FROM workspace_sessions
                  WHERE workspace_id = ?1 AND live = 1 ORDER BY session_id",
            )
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![workspace_id.get().as_bytes().to_vec()], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(uuid_of(&bytes).map(SessionId::new))
            })
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            if let Some(session) = row.map_err(ProjectError::store)? {
                rows.push(session);
            }
        }
        Ok(rows)
    }

    /// Records one thing a workspace holds that a removal has to account for.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn retain(&mut self, workspace_id: WorkspaceId, item: &RetainedRow) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        // A workspace whose removal has begun takes nothing new, for the same reason it takes no
        // new holder: a pin added between the removal's decision and its deletion would be a pin
        // the removal never saw. The host's own measurement uses `replace_retained`, which is part
        // of the removal rather than a caller of it.
        let state: Option<String> = transaction
            .query_row(
                "SELECT state FROM workspaces WHERE workspace_id = ?1",
                params![workspace_id.get().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ProjectError::store)?;
        let state = state.as_deref().map(workspace_state_of);
        if !matches!(
            state,
            Some(WorkspaceState::Ready | WorkspaceState::Materialising)
        ) {
            return Err(ProjectError::WrongState {
                detail: format!(
                    "workspace {workspace_id} is {}, so nothing new is recorded against it",
                    state.map_or("not a workspace this environment has", workspace_state_text)
                ),
            });
        }
        transaction
            .execute(
                "INSERT INTO workspace_retained (workspace_id, kind, detail, change_set_id)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (workspace_id, kind, detail) DO UPDATE SET change_set_id = ?4",
                params![
                    workspace_id.get().as_bytes().to_vec(),
                    retained_kind_text(item.kind),
                    // What is held is read back in a *successful* answer as well as a failure, so
                    // it goes through the rule at the write like any other retained diagnostic.
                    crate::git::redact(&item.detail),
                    item.change_set_id.map(|id| id.get().as_bytes().to_vec()),
                ],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            "workspace.retained",
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Replaces the rows of one retained kind with what the host has just measured.
    ///
    /// The uncommitted work a workspace holds is a fact about its tree rather than a record
    /// somebody wrote, so it is measured before a removal decides anything and the row is replaced
    /// rather than added to.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn replace_retained(
        &mut self,
        workspace_id: WorkspaceId,
        kind: RetainedKind,
        item: Option<&RetainedRow>,
    ) -> Result<()> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        transaction
            .execute(
                "DELETE FROM workspace_retained WHERE workspace_id = ?1 AND kind = ?2",
                params![
                    workspace_id.get().as_bytes().to_vec(),
                    retained_kind_text(kind)
                ],
            )
            .map_err(ProjectError::store)?;
        if let Some(item) = item {
            transaction
                .execute(
                    "INSERT INTO workspace_retained (workspace_id, kind, detail, change_set_id)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        workspace_id.get().as_bytes().to_vec(),
                        retained_kind_text(item.kind),
                        crate::git::redact(&item.detail),
                        item.change_set_id.map(|id| id.get().as_bytes().to_vec()),
                    ],
                )
                .map_err(ProjectError::store)?;
        }
        announce(
            &transaction,
            "workspace.retained",
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)
    }

    /// Returns everything a workspace holds that a removal has to account for.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn retained(&self, workspace_id: WorkspaceId) -> Result<Vec<RetainedRow>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT kind, detail, change_set_id FROM workspace_retained
                  WHERE workspace_id = ?1 ORDER BY kind, detail",
            )
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![workspace_id.get().as_bytes().to_vec()], |row| {
                let kind: String = row.get(0)?;
                let change_set: Option<Vec<u8>> = row.get(2)?;
                Ok(RetainedRow {
                    kind: retained_kind_of(&kind),
                    detail: detail_column(row, 1)?,
                    change_set_id: change_set
                        .as_deref()
                        .and_then(uuid_of)
                        .map(ChangeSetId::new),
                })
            })
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(ProjectError::store)?);
        }
        Ok(rows)
    }

    /// Removes everything a workspace held, once the user approved it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn release_retained(&mut self, workspace_id: WorkspaceId) -> Result<usize> {
        let now = kr_ipc::now_ms();
        let transaction = self.transaction()?;
        let released = transaction
            .execute(
                "DELETE FROM workspace_retained WHERE workspace_id = ?1",
                params![workspace_id.get().as_bytes().to_vec()],
            )
            .map_err(ProjectError::store)?;
        announce(
            &transaction,
            "workspace.released",
            &workspace_id.to_string(),
            now,
        )?;
        transaction.commit().map_err(ProjectError::store)?;
        Ok(released)
    }

    // ----- actions --------------------------------------------------------------------------

    /// Returns one action's record.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the row cannot be read.
    pub fn retained_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
    ) -> Result<Option<RetainedAction>> {
        self.connection
            .query_row(
                "SELECT actor_id, action_id, method, payload_digest, subject, result, error_code,
                        error_detail, recorded_at_ms
                   FROM actions WHERE actor_id = ?1 AND action_id = ?2",
                params![actor_id.as_str(), action_id.as_bytes().to_vec()],
                |row| {
                    let action: Vec<u8> = row.get(1)?;
                    let digest: Vec<u8> = row.get(3)?;
                    let subject: Option<Vec<u8>> = row.get(4)?;
                    Ok(RetainedAction {
                        actor_id: actor_column(row, 0)?,
                        action_id: uuid_of(&action).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
                        method: row.get(2)?,
                        payload_digest: digest_of(&digest),
                        subject: subject.as_deref().and_then(uuid_of),
                        result: row.get(5)?,
                        error_code: row.get(6)?,
                        error_detail: optional_detail_column(row, 7)?,
                        recorded_at_ms: TimestampMs::new(u64_of(row.get::<_, i64>(8)?)),
                    })
                },
            )
            .optional()
            .map_err(ProjectError::store)
    }

    /// Records one action's outcome, leaving an existing row alone.
    ///
    /// Returns the record that was already there, when another copy of the action recorded first.
    /// That record is the answer both callers get: one action, one receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails, or
    /// [`ProjectError::IdConflict`] when the identifier was used for a different request.
    pub fn record_action(
        &self,
        actor_id: &ActorId,
        action_id: Uuid,
        method: &str,
        payload_digest: Digest256,
        outcome: &RetainedOutcome,
        at_ms: TimestampMs,
    ) -> Result<Option<RetainedOutcome>> {
        let (result, code, detail) = match outcome {
            RetainedOutcome::Ok(result) => (Some(result.clone()), None, None),
            RetainedOutcome::Error { code, detail } => (
                None,
                Some(code.as_str().to_owned()),
                // A retained failure is read back by whoever repeats the action, and it is kept,
                // so the rule is applied here as well as where the message was composed. Two bars
                // rather than one, because fourteen reviews each found one producer that had been
                // missed and the journal is the place a miss is permanent.
                Some(crate::git::redact(detail)),
            ),
        };
        let inserted = self
            .connection
            .execute(
                "INSERT INTO actions (actor_id, action_id, method, payload_digest, subject,
                                      result, error_code, error_detail, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8)
                 ON CONFLICT (actor_id, action_id) DO NOTHING",
                params![
                    actor_id.as_str(),
                    action_id.as_bytes().to_vec(),
                    method,
                    payload_digest.as_bytes().to_vec(),
                    result,
                    code,
                    detail,
                    i64_of(at_ms.get()),
                ],
            )
            .map_err(ProjectError::store)?;
        if inserted == 1 {
            return Ok(None);
        }
        let existing = self.retained_action(actor_id, action_id)?.ok_or_else(|| {
            ProjectError::StoreUnavailable {
                detail: "an action row that conflicted could not be read back".to_owned(),
            }
        })?;
        if existing.method != method || existing.payload_digest != payload_digest {
            return Err(ProjectError::IdConflict {
                action: action_id.to_string(),
                method: existing.method,
            });
        }
        Ok(Some(outcome_of(&existing)))
    }

    /// Fills in the result of a claim whose effect has since settled.
    ///
    /// The update names the actor, the identifier, the method and the digest, so a completion
    /// cannot fill a different request's claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn settle(
        &self,
        action: &Action,
        result: Option<&[u8]>,
        failure: Option<(ErrorCode, &str)>,
    ) -> Result<usize> {
        settle_claim_on(&self.connection, action, result, failure)
    }

    /// Returns the actions this store has claimed and not settled.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the rows cannot be read.
    pub fn open_claims(&self) -> Result<Vec<RetainedAction>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT actor_id, action_id, method, payload_digest, subject, result, error_code,
                        error_detail, recorded_at_ms
                   FROM actions
                  WHERE result IS NULL AND error_code IS NULL
                  ORDER BY recorded_at_ms",
            )
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map([], |row| {
                let action: Vec<u8> = row.get(1)?;
                let digest: Vec<u8> = row.get(3)?;
                let subject: Option<Vec<u8>> = row.get(4)?;
                Ok(RetainedAction {
                    actor_id: actor_column(row, 0)?,
                    action_id: uuid_of(&action).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
                    method: row.get(2)?,
                    payload_digest: digest_of(&digest),
                    subject: subject.as_deref().and_then(uuid_of),
                    result: row.get(5)?,
                    error_code: row.get(6)?,
                    error_detail: optional_detail_column(row, 7)?,
                    recorded_at_ms: TimestampMs::new(u64_of(row.get::<_, i64>(8)?)),
                })
            })
            .map_err(ProjectError::store)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row.map_err(ProjectError::store)?);
        }
        Ok(rows)
    }

    /// Records one event in the outbox.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the write fails.
    pub fn announce(&self, kind: &str, subject: &str, at_ms: TimestampMs) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO events (kind, subject, recorded_at_ms) VALUES (?1, ?2, ?3)",
                params![kind, subject, i64_of(at_ms.get())],
            )
            .map_err(ProjectError::store)?;
        Ok(())
    }

    /// Returns how many events the outbox holds.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the count cannot be read.
    pub fn event_count(&self) -> Result<u64> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(ProjectError::store)?;
        Ok(u64_of(count))
    }
}

/// Returns what one action's record says its outcome was.
#[must_use]
pub fn outcome_of(record: &RetainedAction) -> RetainedOutcome {
    match (&record.result, &record.error_code) {
        (Some(result), _) => RetainedOutcome::Ok(result.clone()),
        (None, Some(code)) => RetainedOutcome::Error {
            code: code.parse().unwrap_or(ErrorCode::OutcomeUnknown),
            detail: record
                .error_detail
                .clone()
                .unwrap_or_else(|| format!("action {} was recorded as {code}", record.action_id)),
        },
        (None, None) => RetainedOutcome::Error {
            code: ErrorCode::OutcomeUnknown,
            detail: format!(
                "action {} claimed its effect and its result is not recorded yet",
                record.action_id
            ),
        },
    }
}

/// Claims one action inside a transaction that also writes the state it changes.
///
/// # Errors
///
/// Returns [`ProjectError::IdConflict`] when the identifier was used for a different request, or
/// [`ProjectError::StoreUnavailable`] when the write fails.
pub fn claim_action(
    transaction: &Transaction<'_>,
    action: &Action,
    subject: Option<Uuid>,
) -> Result<()> {
    let inserted = transaction
        .execute(
            "INSERT INTO actions (actor_id, action_id, method, payload_digest, subject,
                                  result, error_code, error_detail, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, ?6)
             ON CONFLICT (actor_id, action_id) DO NOTHING",
            params![
                action.actor_id.as_str(),
                action.action_id.as_bytes().to_vec(),
                action.method,
                action.payload_digest.as_bytes().to_vec(),
                subject.map(|id| id.as_bytes().to_vec()),
                i64_of(kr_ipc::now_ms().get()),
            ],
        )
        .map_err(ProjectError::store)?;
    if inserted == 1 {
        return Ok(());
    }
    let existing: (String, Vec<u8>) = transaction
        .query_row(
            "SELECT method, payload_digest FROM actions WHERE actor_id = ?1 AND action_id = ?2",
            params![
                action.actor_id.as_str(),
                action.action_id.as_bytes().to_vec()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(ProjectError::store)?;
    if existing.0 != action.method || digest_of(&existing.1) != action.payload_digest {
        return Err(ProjectError::IdConflict {
            action: action.action_id.to_string(),
            method: existing.0,
        });
    }
    // Another copy of this action claimed first. The caller reads the claim's record and answers
    // from it rather than performing the effect a second time.
    Err(ProjectError::OutcomeUnknown {
        detail: format!(
            "action {} is already claimed by another copy of this request",
            action.action_id
        ),
    })
}

/// Fills in a claim's result inside a transaction.
fn settle_claim(
    transaction: &Transaction<'_>,
    action: &Action,
    result: Option<&[u8]>,
    failure: Option<(ErrorCode, &str)>,
) -> Result<usize> {
    settle_claim_on(transaction, action, result, failure)
}

/// Fills in a claim's result.
///
/// The update names the actor, the identifier, the method and the digest, and requires the claim
/// to be open, so a completion cannot fill a different request's claim or overwrite a settled one.
fn settle_claim_on(
    connection: &Connection,
    action: &Action,
    result: Option<&[u8]>,
    failure: Option<(ErrorCode, &str)>,
) -> Result<usize> {
    connection
        .execute(
            "UPDATE actions
                SET result = ?5, error_code = ?6, error_detail = ?7
              WHERE actor_id = ?1
                AND action_id = ?2
                AND method = ?3
                AND payload_digest = ?4
                AND result IS NULL
                AND error_code IS NULL",
            params![
                action.actor_id.as_str(),
                action.action_id.as_bytes().to_vec(),
                action.method,
                action.payload_digest.as_bytes().to_vec(),
                result.map(<[u8]>::to_vec),
                failure.map(|(code, _)| code.as_str().to_owned()),
                // A settled failure is read back by whoever repeats the action, and it is kept, so
                // the rule is applied at the write. The rule leaves its own output alone, so a
                // message whose untrusted part was already replaced where it was composed comes
                // through here unchanged, and what the journal keeps is what the caller was told.
                failure.map(|(_, detail)| crate::git::redact(detail)),
            ],
        )
        .map_err(ProjectError::store)
}

/// Writes one event in the outbox of a transaction.
fn announce(
    transaction: &Transaction<'_>,
    kind: &str,
    subject: &str,
    at_ms: TimestampMs,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO events (kind, subject, recorded_at_ms) VALUES (?1, ?2, ?3)",
            params![kind, subject, i64_of(at_ms.get())],
        )
        .map_err(ProjectError::store)?;
    Ok(())
}

/// The columns an operation row is read from.
const OPERATION_COLUMNS: &str = "action_id, actor_id, environment_id, project_repository_id, \
     method, state, remote_name, remote_transport, remote_url, remote_provider, remote_broker, \
     flow, destination_state, parent_path, destination_name, staging_name, staging_device, \
     staging_file_id, staged_device, staged_file_id, staged_created_at_ms, detail, \
     started_at_ms, ended_at_ms";

/// The columns a repository row is read from.
const PROJECT_COLUMNS: &str = "project_repository_id, environment_id, label, origin, state, \
     git_dir_device, git_dir_file_id, work_tree_device, work_tree_file_id, display_path, \
     remote_name, remote_transport, remote_url, remote_provider, remote_broker, created_at_ms";

/// Adds the columns a store written by an earlier build does not have.
///
/// Every one of them is nullable and means "not recorded", which is what an older row holds
/// anyway: a staging directory an earlier build created has no recorded identity, and the cleanup
/// leaves such a name alone rather than deleting whatever now holds it.
fn protect_recorded_reasons(transaction: &Transaction<'_>) -> Result<()> {
    // A store written before the rule existed holds whatever that build composed. Reading one
    // applies the rule on the way out, so nothing unprotected reaches a caller either way; this
    // rewrites the columns as well, so the file itself stops holding it. Both, because a reader
    // outside this build reads the file rather than going through this code.
    //
    // The rule leaves its own output alone, so this is safe to run over a store that has already
    // been through it. What it does *not* rewrite is `actions.result`: that is the canonical
    // encoding of a typed answer rather than prose, and rewriting it would mean decoding every
    // method's result type here. No build of this service has been released, so the only stores
    // that can hold one are development journals, and the handoff records that.
    for (table, column) in [
        ("operations", "detail"),
        ("workspaces", "detail"),
        ("workspace_retained", "detail"),
        ("actions", "error_detail"),
    ] {
        let mut statement = transaction
            .prepare(&format!(
                "SELECT rowid, {column} FROM {table} WHERE {column} IS NOT NULL"
            ))
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(ProjectError::store)?;
        let mut rewritten: Vec<(i64, String)> = Vec::new();
        for row in mapped {
            let (rowid, detail) = row.map_err(ProjectError::store)?;
            let protected = crate::git::redact(&detail);
            if protected != detail {
                rewritten.push((rowid, protected));
            }
        }
        drop(statement);
        for (rowid, protected) in rewritten {
            transaction
                .execute(
                    &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
                    params![protected, rowid],
                )
                .map_err(ProjectError::store)?;
        }
    }
    Ok(())
}

fn add_missing_columns(transaction: &Transaction<'_>) -> Result<()> {
    // Every nullable column this build reads that some earlier shape of this schema did not have.
    // The list is the whole of them rather than the ones added last: a store written by *any*
    // earlier build has to be readable, and a column that is already there costs one
    // `pragma_table_info` to find out.
    const ADDED: &[(&str, &str, &str)] = &[
        ("operations", "staging_device", "INTEGER"),
        ("operations", "staging_file_id", "INTEGER"),
        ("operations", "staged_created_at_ms", "INTEGER"),
        ("workspaces", "staging_name", "TEXT"),
        ("workspaces", "staging_device", "INTEGER"),
        ("workspaces", "staging_file_id", "INTEGER"),
        ("workspaces", "removal_action", "BLOB"),
        ("workspaces", "detail", "TEXT"),
    ];
    for (table, column, kind) in ADDED {
        let present: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                params![table, column],
                |row| row.get(0),
            )
            .map_err(ProjectError::store)?;
        if present == 0 {
            transaction
                .execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"))
                .map_err(ProjectError::store)?;
        }
    }
    Ok(())
}

/// The columns a workspace row is read from.
const WORKSPACE_COLUMNS: &str = "workspace_id, project_repository_id, environment_id, label, \
     kind, isolation, dirty_files, untracked_files, submodules, binary_files, \
     generated_artefacts, state, base_revision, base_change_set_id, tree_device, tree_file_id, \
     display_path, staging_name, detail, retention, created_at_ms, removed_at_ms, \
     staging_device, staging_file_id";

fn insert_operation(transaction: &Transaction<'_>, row: &OperationRow) -> Result<()> {
    let remote = row.remote.as_ref();
    transaction
        .execute(
            "INSERT INTO operations (action_id, actor_id, environment_id, project_repository_id,
                                     method, state, remote_name, remote_transport, remote_url,
                                     remote_provider, remote_broker, flow, destination_state,
                                     parent_path, destination_name, staging_name, staging_device,
                                     staging_file_id, staged_device, staged_file_id,
                                     staged_created_at_ms, detail, started_at_ms, ended_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
            params![
                row.action_id.get().as_bytes().to_vec(),
                row.actor_id.as_str(),
                row.environment_id.get().as_bytes().to_vec(),
                row.project_repository_id.get().as_bytes().to_vec(),
                row.method,
                operation_state_text(row.state),
                remote.map(|remote| remote.remote_name.clone()),
                remote.map(|remote| transport_text(remote.transport).to_owned()),
                remote.map(|remote| remote.url.clone()),
                remote.map(|remote| remote.provider.clone()),
                remote.map(|remote| remote.credential_broker.clone()),
                row.flow.map(adoption_flow_text),
                destination_state_text(row.destination_state),
                row.parent_path,
                row.destination_name,
                row.staging_name,
                row.staging_identity.map(|identity| i64_of(identity.device)),
                row.staging_identity
                    .map(|identity| i64_of(identity.file_id)),
                row.staged_identity
                    .map(|staged| i64_of(staged.identity.device)),
                row.staged_identity
                    .map(|staged| i64_of(staged.identity.file_id)),
                row.staged_identity
                    .and_then(|staged| staged.created_at_ms)
                    .map(i64_of),
                row.detail.as_deref().map(crate::git::redact),
                i64_of(row.started_at_ms.get()),
                row.ended_at_ms.map(|stamp| i64_of(stamp.get())),
            ],
        )
        .map_err(ProjectError::store)?;
    Ok(())
}

fn read_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRow> {
    let action: Vec<u8> = row.get(0)?;
    let environment: Vec<u8> = row.get(2)?;
    let project: Vec<u8> = row.get(3)?;
    let state: String = row.get(5)?;
    let transport: Option<String> = row.get(7)?;
    let flow: Option<String> = row.get(11)?;
    let destination_state: String = row.get(12)?;
    let staging_device: Option<i64> = row.get(16)?;
    let staging_file_id: Option<i64> = row.get(17)?;
    let device: Option<i64> = row.get(18)?;
    let file_id: Option<i64> = row.get(19)?;
    let created_at_ms: Option<i64> = row.get(20)?;
    let remote = match (row.get::<_, Option<String>>(6)?, transport) {
        (Some(name), Some(transport)) => Some(RemoteSpecification {
            remote_name: name,
            transport: transport_of(&transport),
            url: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
            provider: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
            credential_broker: row.get::<_, Option<String>>(10)?.unwrap_or_default(),
        }),
        _ => None,
    };
    Ok(OperationRow {
        action_id: ActionId::new(uuid_of(&action).unwrap_or_else(|| Uuid::from_bytes([0; 16]))),
        actor_id: actor_column(row, 1)?,
        environment_id: EnvironmentId::new(
            uuid_of(&environment).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        project_repository_id: ProjectRepositoryId::new(
            uuid_of(&project).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        method: row.get(4)?,
        state: operation_state_of(&state),
        remote,
        flow: flow.as_deref().map(adoption_flow_of),
        destination_state: destination_state_of(&destination_state),
        parent_path: row.get(13)?,
        destination_name: row.get(14)?,
        staging_name: row.get(15)?,
        staging_identity: match (staging_device, staging_file_id) {
            (Some(device), Some(file_id)) => Some(ObjectIdentity {
                device: u64_of(device),
                file_id: u64_of(file_id),
            }),
            _ => None,
        },
        staged_identity: match (device, file_id) {
            (Some(device), Some(file_id)) => Some(StagedWitness {
                identity: ObjectIdentity {
                    device: u64_of(device),
                    file_id: u64_of(file_id),
                },
                created_at_ms: created_at_ms.map(u64_of),
            }),
            _ => None,
        },
        detail: optional_detail_column(row, 21)?,
        started_at_ms: TimestampMs::new(u64_of(row.get::<_, i64>(22)?)),
        ended_at_ms: row
            .get::<_, Option<i64>>(23)?
            .map(|stamp| TimestampMs::new(u64_of(stamp))),
    })
}

fn insert_project(transaction: &Transaction<'_>, row: &ProjectRow) -> Result<()> {
    let remote = row.remote.as_ref();
    transaction
        .execute(
            "INSERT INTO projects (project_repository_id, environment_id, label, origin, state,
                                   git_dir_device, git_dir_file_id, work_tree_device,
                                   work_tree_file_id, display_path, remote_name, remote_transport,
                                   remote_url, remote_provider, remote_broker, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                row.project_repository_id.get().as_bytes().to_vec(),
                row.environment_id.get().as_bytes().to_vec(),
                row.label,
                origin_text(row.origin),
                project_state_text(row.state),
                i64_of(row.identity.git_dir.device),
                i64_of(row.identity.git_dir.file_id),
                i64_of(row.identity.work_tree.device),
                i64_of(row.identity.work_tree.file_id),
                row.display_path,
                remote.map(|remote| remote.remote_name.clone()),
                remote.map(|remote| transport_text(remote.transport).to_owned()),
                remote.map(|remote| remote.url.clone()),
                remote.map(|remote| remote.provider.clone()),
                remote.map(|remote| remote.credential_broker.clone()),
                i64_of(row.created_at_ms.get()),
            ],
        )
        .map_err(ProjectError::store)?;
    Ok(())
}

fn read_project(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRow> {
    let project: Vec<u8> = row.get(0)?;
    let environment: Vec<u8> = row.get(1)?;
    let origin: String = row.get(3)?;
    let state: String = row.get(4)?;
    let transport: Option<String> = row.get(11)?;
    let remote = match (row.get::<_, Option<String>>(10)?, transport) {
        (Some(name), Some(transport)) => Some(RemoteSpecification {
            remote_name: name,
            transport: transport_of(&transport),
            url: row.get::<_, Option<String>>(12)?.unwrap_or_default(),
            provider: row.get::<_, Option<String>>(13)?.unwrap_or_default(),
            credential_broker: row.get::<_, Option<String>>(14)?.unwrap_or_default(),
        }),
        _ => None,
    };
    Ok(ProjectRow {
        project_repository_id: ProjectRepositoryId::new(
            uuid_of(&project).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        environment_id: EnvironmentId::new(
            uuid_of(&environment).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        label: row.get(2)?,
        origin: origin_of(&origin),
        state: project_state_of(&state),
        identity: RepositoryIdentity {
            git_dir: ObjectIdentity {
                device: u64_of(row.get::<_, i64>(5)?),
                file_id: u64_of(row.get::<_, i64>(6)?),
            },
            work_tree: ObjectIdentity {
                device: u64_of(row.get::<_, i64>(7)?),
                file_id: u64_of(row.get::<_, i64>(8)?),
            },
        },
        display_path: row.get(9)?,
        remote,
        created_at_ms: TimestampMs::new(u64_of(row.get::<_, i64>(15)?)),
    })
}

fn insert_workspace(transaction: &Transaction<'_>, row: &WorkspaceRow) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO workspaces (workspace_id, project_repository_id, environment_id, label,
                                     kind, isolation, dirty_files, untracked_files, submodules,
                                     binary_files, generated_artefacts, state, base_revision,
                                     base_change_set_id, tree_device, tree_file_id, display_path,
                                     staging_name, detail, retention, created_at_ms, removed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18, ?19, ?20, ?21, ?22)",
            params![
                row.workspace_id.get().as_bytes().to_vec(),
                row.project_repository_id.get().as_bytes().to_vec(),
                row.environment_id.get().as_bytes().to_vec(),
                row.label,
                workspace_kind_text(row.kind),
                row.isolation.map(isolation_text),
                choice_text(row.policy.dirty_files),
                choice_text(row.policy.untracked_files),
                choice_text(row.policy.submodules),
                choice_text(row.policy.binary_files),
                choice_text(row.policy.generated_artefacts),
                workspace_state_text(row.state),
                row.base_revision,
                row.base_change_set_id
                    .map(|id| id.get().as_bytes().to_vec()),
                row.identity.map(|id| i64_of(id.device)),
                row.identity.map(|id| i64_of(id.file_id)),
                row.display_path,
                row.staging_name,
                row.detail.as_deref().map(crate::git::redact),
                row.retention.map(retention_text),
                i64_of(row.created_at_ms.get()),
                row.removed_at_ms.map(|stamp| i64_of(stamp.get())),
            ],
        )
        .map_err(ProjectError::store)?;
    Ok(())
}

fn read_workspace(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceRow> {
    let workspace: Vec<u8> = row.get(0)?;
    let project: Vec<u8> = row.get(1)?;
    let environment: Vec<u8> = row.get(2)?;
    let kind: String = row.get(4)?;
    let isolation: Option<String> = row.get(5)?;
    let state: String = row.get(11)?;
    let change_set: Option<Vec<u8>> = row.get(13)?;
    let device: Option<i64> = row.get(14)?;
    let file_id: Option<i64> = row.get(15)?;
    let retention: Option<String> = row.get(19)?;
    let staging_device: Option<i64> = row.get(22)?;
    let staging_file_id: Option<i64> = row.get(23)?;
    Ok(WorkspaceRow {
        workspace_id: WorkspaceId::new(
            uuid_of(&workspace).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        project_repository_id: ProjectRepositoryId::new(
            uuid_of(&project).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        environment_id: EnvironmentId::new(
            uuid_of(&environment).unwrap_or_else(|| Uuid::from_bytes([0; 16])),
        ),
        label: row.get(3)?,
        kind: workspace_kind_of(&kind),
        isolation: isolation.as_deref().map(isolation_of),
        policy: InclusionPolicy {
            dirty_files: choice_of(&row.get::<_, String>(6)?),
            untracked_files: choice_of(&row.get::<_, String>(7)?),
            submodules: choice_of(&row.get::<_, String>(8)?),
            binary_files: choice_of(&row.get::<_, String>(9)?),
            generated_artefacts: choice_of(&row.get::<_, String>(10)?),
        },
        state: workspace_state_of(&state),
        base_revision: row.get(12)?,
        base_change_set_id: change_set
            .as_deref()
            .and_then(uuid_of)
            .map(ChangeSetId::new),
        identity: match (device, file_id) {
            (Some(device), Some(file_id)) => Some(ObjectIdentity {
                device: u64_of(device),
                file_id: u64_of(file_id),
            }),
            _ => None,
        },
        display_path: row.get(16)?,
        staging_name: row.get(17)?,
        staging_identity: match (staging_device, staging_file_id) {
            (Some(device), Some(file_id)) => Some(ObjectIdentity {
                device: u64_of(device),
                file_id: u64_of(file_id),
            }),
            _ => None,
        },
        detail: optional_detail_column(row, 18)?,
        retention: retention.as_deref().map(retention_of),
        created_at_ms: TimestampMs::new(u64_of(row.get::<_, i64>(20)?)),
        removed_at_ms: row
            .get::<_, Option<i64>>(21)?
            .map(|stamp| TimestampMs::new(u64_of(stamp))),
    })
}

/// Reads one free-text reason out of a stored row, through the rule.
///
/// The rule leaves its own output alone, so a reason written under it comes back exactly as it was
/// written and the caller and the journal hold the same message. What this is *for* is a reason a
/// build before the rule existed wrote: the column holds whatever that build composed, and reading
/// it is the last place this host can put it through the rule before it reaches anybody.
fn detail_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
    Ok(crate::git::redact(&row.get::<_, String>(index)?))
}

/// Reads one optional free-text reason out of a stored row, through the rule.
fn optional_detail_column(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<String>> {
    Ok(row
        .get::<_, Option<String>>(index)?
        .map(|detail| crate::git::redact(&detail)))
}

/// Reads a principal out of a stored row, reporting a row this build cannot read.
fn actor_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<ActorId> {
    let text: String = row.get(index)?;
    ActorId::new(text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })
}

/// Returns an identifier nothing else holds.
fn fresh_uuid() -> Uuid {
    Uuid::from_bytes(*uuid::Uuid::new_v4().as_bytes())
}

/// Reads a 16-byte identifier out of a stored blob.
fn uuid_of(bytes: &[u8]) -> Option<Uuid> {
    <[u8; 16]>::try_from(bytes).ok().map(Uuid::from_bytes)
}

/// Reads a 32-byte digest out of a stored blob.
fn digest_of(bytes: &[u8]) -> Digest256 {
    Digest256::from_bytes(<[u8; 32]>::try_from(bytes).unwrap_or([0; 32]))
}

/// Stores an unsigned 64-bit value in SQLite's signed integer column.
///
/// A filesystem identity and a timestamp are both unsigned, and SQLite's integer is signed, so the
/// bits are kept rather than the value clamped: what is read back is what was written.
const fn i64_of(value: u64) -> i64 {
    value as i64
}

/// Reads back what [`i64_of`] wrote.
const fn u64_of(value: i64) -> u64 {
    value as u64
}

macro_rules! text_enum {
    ($to:ident, $from:ident, $type:ty, $fallback:expr, $($variant:ident => $text:literal),+ $(,)?) => {
        /// Returns the stored text of one value.
        #[must_use]
        pub const fn $to(value: $type) -> &'static str {
            match value {
                $(<$type>::$variant => $text),+
            }
        }

        /// Returns the value one stored text names.
        #[must_use]
        pub fn $from(text: &str) -> $type {
            match text {
                $($text => <$type>::$variant,)+
                _ => $fallback,
            }
        }
    };
}

text_enum!(
    origin_text,
    origin_of,
    ProjectOrigin,
    ProjectOrigin::Adopted,
    Initialised => "initialised",
    Cloned => "cloned",
    Adopted => "adopted",
);

text_enum!(
    project_state_text,
    project_state_of,
    ProjectState,
    ProjectState::Detached,
    Ready => "ready",
    Creating => "creating",
    Detached => "detached",
);

text_enum!(
    operation_state_text,
    operation_state_of,
    OperationState,
    OperationState::Unknown,
    Staging => "staging",
    Publishing => "publishing",
    Completed => "completed",
    Cancelled => "cancelled",
    Failed => "failed",
    Expired => "expired",
    Unknown => "unknown",
);

text_enum!(
    destination_state_text,
    destination_state_of,
    DestinationState,
    DestinationState::Occupied,
    Absent => "absent",
    EmptyDirectory => "empty_directory",
    NonEmptyDirectory => "non_empty_directory",
    Occupied => "occupied",
);

text_enum!(
    transport_text,
    transport_of,
    RemoteTransport,
    RemoteTransport::LocalPath,
    Https => "https",
    Ssh => "ssh",
    LocalPath => "local_path",
);

text_enum!(
    adoption_flow_text,
    adoption_flow_of,
    AdoptionFlow,
    AdoptionFlow::ExistingCheckout,
    ExistingCheckout => "existing_checkout",
);

text_enum!(
    workspace_kind_text,
    workspace_kind_of,
    WorkspaceKind,
    WorkspaceKind::SharedExisting,
    SharedExisting => "shared_existing",
    Isolated => "isolated",
);

text_enum!(
    isolation_text,
    isolation_of,
    IsolationMechanism,
    IsolationMechanism::IndependentClone,
    GitWorktree => "git_worktree",
    IndependentClone => "independent_clone",
);

text_enum!(
    workspace_state_text,
    workspace_state_of,
    WorkspaceState,
    WorkspaceState::RemovalPending,
    Ready => "ready",
    Materialising => "materialising",
    RemovalPending => "removal_pending",
    Removed => "removed",
);

text_enum!(
    retention_text,
    retention_of,
    RetentionPolicy,
    RetentionPolicy::KeepEverything,
    KeepEverything => "keep_everything",
    RemoveRetained => "remove_retained",
);

text_enum!(
    retained_kind_text,
    retained_kind_of,
    RetainedKind,
    RetainedKind::DirtyContent,
    DirtyContent => "dirty_content",
    PinnedChangeSet => "pinned_change_set",
    ReviewEvidence => "review_evidence",
);

text_enum!(
    choice_text,
    choice_of,
    InclusionChoice,
    InclusionChoice::Exclude,
    Include => "include",
    Exclude => "exclude",
);

/// Returns the wire form of a counter, for a caller building a summary.
#[must_use]
pub const fn count(value: u64) -> U64 {
    U64::new(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([7; 16]))
    }

    fn operation(action: u8, project: u8) -> OperationRow {
        OperationRow {
            action_id: ActionId::new(Uuid::from_bytes([action; 16])),
            actor_id: ActorId::new("local:501").expect("a valid principal"),
            environment_id: environment(),
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([project; 16])),
            method: "project.clone".to_owned(),
            state: OperationState::Staging,
            remote: Some(RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::Https,
                url: "https://example.invalid/x.git".to_owned(),
                provider: "example.invalid".to_owned(),
                credential_broker: "os-secret-store".to_owned(),
            }),
            flow: None,
            destination_state: DestinationState::Absent,
            parent_path: "/tmp/parent".to_owned(),
            destination_name: "x".to_owned(),
            staging_name: Some(".kr-project-0123".to_owned()),
            staging_identity: None,
            staged_identity: None,
            detail: None,
            started_at_ms: TimestampMs::new(1_000),
            ended_at_ms: None,
        }
    }

    fn action(id: u8, method: &str) -> Action {
        Action {
            actor_id: ActorId::new("local:501").expect("a valid principal"),
            action_id: Uuid::from_bytes([id; 16]),
            method: method.to_owned(),
            payload_digest: Digest256::from_bytes([id; 32]),
        }
    }

    #[test]
    fn an_operation_row_survives_a_round_trip_with_every_field_it_carries() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        let row = operation(1, 2);
        store
            .begin_operation(&row, Some(&action(1, "project.clone")))
            .expect("the row and its claim commit together");
        let read = store
            .operation(row.action_id)
            .expect("it reads")
            .expect("it is there");
        assert_eq!(read, row);
        // The row is the create token, and it exists before anything is on disk.
        assert_eq!(read.state, OperationState::Staging);
        // The state change and the identity that resolves a publication are recorded together.
        let staged = StagedWitness {
            identity: ObjectIdentity {
                device: 16_777_234,
                file_id: 98_765,
            },
            created_at_ms: Some(1_700_000_000_000),
        };
        store
            .set_operation_state(
                row.action_id,
                OperationState::Publishing,
                &OperationUpdate {
                    staged_identity: Some(staged),
                    ..OperationUpdate::default()
                },
            )
            .expect("the state moves");
        let read = store
            .operation(row.action_id)
            .expect("it reads")
            .expect("it is there");
        assert_eq!(read.state, OperationState::Publishing);
        assert_eq!(read.staged_identity, Some(staged));
        assert_eq!(
            store
                .operations_in(&[OperationState::Publishing])
                .expect("the listing reads")
                .len(),
            1
        );
    }

    #[test]
    fn a_second_copy_of_one_action_does_not_claim_it_twice() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        store
            .begin_operation(&operation(3, 4), Some(&action(3, "project.clone")))
            .expect("the first copy claims it");
        // A second copy of the same action finds the claim and is told the outcome is not settled
        // rather than starting a second clone.
        let refusal = store
            .begin_operation(&operation(3, 5), Some(&action(3, "project.clone")))
            .expect_err("the second copy does not claim it");
        assert_eq!(refusal.code(), ErrorCode::OutcomeUnknown);
        // And the first copy's row is the only one.
        assert_eq!(
            store
                .operations_in(&[OperationState::Staging])
                .expect("the listing reads")
                .len(),
            1
        );
    }

    #[test]
    fn one_identifier_used_for_two_different_requests_is_a_conflict() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        store
            .begin_operation(&operation(5, 6), Some(&action(5, "project.clone")))
            .expect("the first request claims it");
        let mut different = action(5, "project.init");
        different.payload_digest = Digest256::from_bytes([9; 32]);
        let refusal = store
            .begin_operation(&operation(5, 7), Some(&different))
            .expect_err("a different request under the same identifier is a conflict");
        assert_eq!(refusal.code(), ErrorCode::IdConflict);
    }

    #[test]
    fn a_claim_is_settled_only_by_the_request_that_made_it() {
        let store = Store::in_memory(environment()).expect("a store opens");
        let claimed = action(8, "project.clone");
        {
            let mut store = Store::in_memory(environment()).expect("a second store opens");
            store
                .begin_operation(&operation(8, 9), Some(&claimed))
                .expect("it claims");
            // Another method's result never fills this claim.
            let other = Action {
                method: "project.init".to_owned(),
                ..claimed.clone()
            };
            assert_eq!(
                store.settle(&other, Some(b"wrong"), None).expect("it runs"),
                0
            );
            assert_eq!(
                store
                    .settle(&claimed, Some(b"right"), None)
                    .expect("it runs"),
                1
            );
            let record = store
                .retained_action(&claimed.actor_id, claimed.action_id)
                .expect("it reads")
                .expect("it is there");
            assert_eq!(record.result.as_deref(), Some(b"right".as_slice()));
            // A settled claim is not settled again.
            assert_eq!(
                store
                    .settle(&claimed, Some(b"again"), None)
                    .expect("it runs"),
                0
            );
        }
        assert!(
            store.open_claims().expect("it reads").is_empty(),
            "a fresh store has no claims"
        );
    }

    #[test]
    fn a_workspace_keeps_its_policy_its_sessions_and_everything_it_holds() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        let workspace_id = WorkspaceId::new(Uuid::from_bytes([11; 16]));
        let row = WorkspaceRow {
            workspace_id,
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            environment_id: environment(),
            label: "review".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Some(IsolationMechanism::GitWorktree),
            policy: InclusionPolicy {
                dirty_files: InclusionChoice::Include,
                untracked_files: InclusionChoice::Exclude,
                submodules: InclusionChoice::Exclude,
                binary_files: InclusionChoice::Exclude,
                generated_artefacts: InclusionChoice::Exclude,
            },
            state: WorkspaceState::Materialising,
            base_revision: "a".repeat(40),
            base_change_set_id: Some(ChangeSetId::new(Uuid::from_bytes([12; 16]))),
            identity: None,
            display_path: "/tmp/review".to_owned(),
            staging_name: None,
            staging_identity: None,
            detail: None,
            retention: None,
            created_at_ms: TimestampMs::new(2_000),
            removed_at_ms: None,
        };
        store
            .begin_workspace(&row, Some(&action(13, "workspace.create")))
            .expect("the row and its claim commit together");
        let read = store
            .workspace(workspace_id)
            .expect("it reads")
            .expect("it is there");
        assert_eq!(read, row);
        let tree = ObjectIdentity {
            device: 1,
            file_id: 2,
        };
        store
            .set_workspace_state(workspace_id, WorkspaceState::Ready, Some(tree), None, None)
            .expect("the state moves");
        let read = store
            .workspace(workspace_id)
            .expect("it reads")
            .expect("it is there");
        assert_eq!(read.state, WorkspaceState::Ready);
        assert_eq!(read.identity, Some(tree));
        // A bound session is what refuses a removal, and its end is recorded rather than deleted.
        let session = SessionId::new(Uuid::from_bytes([14; 16]));
        store
            .bind_session(workspace_id, session, true)
            .expect("it binds");
        assert_eq!(
            store.live_sessions(workspace_id).expect("it reads"),
            vec![session]
        );
        store
            .bind_session(workspace_id, session, false)
            .expect("it ends");
        assert!(
            store
                .live_sessions(workspace_id)
                .expect("it reads")
                .is_empty()
        );
        // Dirty content, a pin and review evidence are three rows and a removal accounts for all.
        for item in [
            RetainedRow {
                kind: RetainedKind::DirtyContent,
                detail: "two modified files".to_owned(),
                change_set_id: None,
            },
            RetainedRow {
                kind: RetainedKind::PinnedChangeSet,
                detail: "version 3".to_owned(),
                change_set_id: Some(ChangeSetId::new(Uuid::from_bytes([12; 16]))),
            },
            RetainedRow {
                kind: RetainedKind::ReviewEvidence,
                detail: "a review acknowledged version 3".to_owned(),
                change_set_id: Some(ChangeSetId::new(Uuid::from_bytes([12; 16]))),
            },
        ] {
            store.retain(workspace_id, &item).expect("it retains");
        }
        assert_eq!(store.retained(workspace_id).expect("it reads").len(), 3);
        assert_eq!(store.release_retained(workspace_id).expect("it runs"), 3);
        assert!(store.retained(workspace_id).expect("it reads").is_empty());
    }

    #[test]
    fn a_store_from_a_later_build_is_refused_rather_than_read() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        store
            .connection
            .execute(
                "UPDATE schema_version SET version = ?1",
                params![SCHEMA_VERSION + 1],
            )
            .expect("the version moves");
        let refusal = store.migrate().expect_err("a later schema is refused");
        assert_eq!(refusal.code(), ErrorCode::StorageUnavailable);
    }

    #[test]
    fn every_state_change_commits_with_the_event_that_announces_it() {
        // Section 24 asks every authoritative producer to commit a state transition and its
        // outbox row in the same local transaction. So every call that changes state is checked
        // here, not only the one that begins an operation: a change a consumer cannot replay is a
        // change that happened as far as this host is concerned and never happened as far as
        // anything downstream is.
        let mut store = Store::in_memory(environment()).expect("a store opens");
        let mut expected = 0_u64;
        let mut announced = |store: &Store, what: &str| {
            expected += 1;
            assert_eq!(
                store.event_count().expect("the outbox reads"),
                expected,
                "{what} commits with the event that announces it"
            );
        };
        assert_eq!(store.event_count().expect("it reads"), 0);

        let row = operation(20, 21);
        store
            .begin_operation(&row, Some(&action(20, "project.clone")))
            .expect("it begins");
        announced(&store, "beginning an operation");

        store
            .set_operation_state(
                row.action_id,
                OperationState::Publishing,
                &OperationUpdate {
                    ..OperationUpdate::default()
                },
            )
            .expect("the state moves");
        announced(&store, "moving an operation");

        let project = ProjectRepositoryId::new(Uuid::from_bytes([21; 16]));
        store
            .set_project_state(project, ProjectState::Detached)
            .expect("the state moves");
        announced(&store, "moving a repository");

        let workspace_id = WorkspaceId::new(Uuid::from_bytes([30; 16]));
        let workspace = WorkspaceRow {
            workspace_id,
            project_repository_id: project,
            environment_id: environment(),
            label: "review".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Some(IsolationMechanism::GitWorktree),
            policy: InclusionPolicy::base_only(),
            state: WorkspaceState::Materialising,
            base_revision: "a".repeat(40),
            base_change_set_id: None,
            identity: None,
            display_path: "/tmp/review".to_owned(),
            staging_name: None,
            staging_identity: None,
            detail: None,
            retention: None,
            created_at_ms: TimestampMs::new(3_000),
            removed_at_ms: None,
        };
        store
            .begin_workspace(&workspace, Some(&action(31, "workspace.create")))
            .expect("it begins");
        announced(&store, "beginning a workspace");

        store
            .set_workspace_state(workspace_id, WorkspaceState::Ready, None, None, None)
            .expect("the state moves");
        announced(&store, "moving a workspace");

        let session = SessionId::new(Uuid::from_bytes([32; 16]));
        store
            .bind_session(workspace_id, session, true)
            .expect("it binds");
        announced(&store, "binding a session");

        let run = WorkflowRunId::new(Uuid::from_bytes([33; 16]));
        store.bind_run(workspace_id, run, true).expect("it binds");
        announced(&store, "binding a run");

        store
            .retain(
                workspace_id,
                &RetainedRow {
                    kind: RetainedKind::PinnedChangeSet,
                    detail: "version 1".to_owned(),
                    change_set_id: None,
                },
            )
            .expect("it retains");
        announced(&store, "retaining something");

        store
            .replace_retained(workspace_id, RetainedKind::DirtyContent, None)
            .expect("it replaces");
        announced(&store, "replacing what is retained");

        store.release_retained(workspace_id).expect("it releases");
        announced(&store, "releasing what is retained");

        store
            .bind_session(workspace_id, session, false)
            .expect("the session ends");
        announced(&store, "releasing a session");

        store
            .bind_run(workspace_id, run, false)
            .expect("the run ends");
        announced(&store, "releasing a run");

        store
            .begin_removal(
                workspace_id,
                RetentionPolicy::RemoveRetained,
                Some(&action(34, "workspace.remove")),
            )
            .expect("the removal is reserved");
        announced(&store, "reserving a removal");

        store
            .complete_operation(
                &ProjectRow {
                    project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([35; 16])),
                    environment_id: environment(),
                    label: "done".to_owned(),
                    origin: ProjectOrigin::Cloned,
                    state: ProjectState::Ready,
                    identity: RepositoryIdentity {
                        git_dir: ObjectIdentity {
                            device: 1,
                            file_id: 2,
                        },
                        work_tree: ObjectIdentity {
                            device: 1,
                            file_id: 3,
                        },
                    },
                    display_path: "/tmp/done".to_owned(),
                    remote: None,
                    created_at_ms: TimestampMs::new(4_000),
                },
                row.action_id,
                None,
                None,
                TimestampMs::new(4_000),
            )
            .expect("it completes");
        announced(&store, "completing an operation");
    }

    #[test]
    fn a_workspace_whose_removal_has_begun_takes_no_new_holder() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        let workspace_id = WorkspaceId::new(Uuid::from_bytes([40; 16]));
        let workspace = WorkspaceRow {
            workspace_id,
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            environment_id: environment(),
            label: "reserved".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Some(IsolationMechanism::GitWorktree),
            policy: InclusionPolicy::base_only(),
            state: WorkspaceState::Ready,
            base_revision: "a".repeat(40),
            base_change_set_id: None,
            identity: None,
            display_path: "/tmp/reserved".to_owned(),
            staging_name: None,
            staging_identity: None,
            detail: None,
            retention: None,
            created_at_ms: TimestampMs::new(1),
            removed_at_ms: None,
        };
        store.begin_workspace(&workspace, None).expect("it begins");
        // The reservation, the checks and the claim are one transaction, so a holder that arrives
        // afterwards finds a workspace nothing new may hold.
        let reserved = store
            .begin_removal(workspace_id, RetentionPolicy::KeepEverything, None)
            .expect("the removal is reserved");
        let refusal = store
            .bind_session(
                workspace_id,
                SessionId::new(Uuid::from_bytes([41; 16])),
                true,
            )
            .expect_err("a reserved workspace takes no new session");
        assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
        // While that reservation is held, another removal is refused rather than allowed to
        // measure a tree the first one is deleting underneath it.
        let refusal = store
            .begin_removal(
                workspace_id,
                RetentionPolicy::KeepEverything,
                Some(&action(41, "workspace.remove")),
            )
            .expect_err("a second removal does not begin beside the first");
        assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
        store
            .release_removal(workspace_id, reserved.token)
            .expect("the reservation is released");
        // And a second copy of one removal action does not reserve it twice.
        store
            .begin_removal(
                workspace_id,
                RetentionPolicy::KeepEverything,
                Some(&action(42, "workspace.remove")),
            )
            .expect("the first copy claims it");
        let refusal = store
            .begin_removal(
                workspace_id,
                RetentionPolicy::KeepEverything,
                Some(&action(42, "workspace.remove")),
            )
            .expect_err("the second copy does not");
        assert_eq!(refusal.code(), ErrorCode::OutcomeUnknown);
    }

    #[test]
    fn every_path_an_inclusion_will_attempt_is_recorded_before_any_of_them_settles() {
        // What makes an interrupted inclusion reportable is the order: the paths go in as
        // `planned` first, and each outcome replaces its own row. So a journal read part way
        // through says which paths this host had not established anything about.
        let mut store = Store::in_memory(environment()).expect("a store opens");
        let workspace_id = WorkspaceId::new(Uuid::from_bytes([70; 16]));
        let paths = vec!["a.txt".to_owned(), "b/c.txt".to_owned(), "d.bin".to_owned()];
        store
            .plan_workspace_progress(workspace_id, &paths)
            .expect("the plan is written");
        let planned = store
            .workspace_progress(workspace_id)
            .expect("the progress reads");
        assert_eq!(planned.len(), 3);
        assert!(
            planned
                .iter()
                .all(|(_, outcome)| outcome == PROGRESS_PLANNED),
            "every path starts unresolved: {planned:?}"
        );
        // One path settles, which is what a daemon that died after the first batch leaves.
        store
            .record_workspace_progress(workspace_id, &[("a.txt".to_owned(), "carried")])
            .expect("one outcome is written");
        let mixed = store
            .workspace_progress(workspace_id)
            .expect("the progress reads again");
        assert_eq!(
            mixed.len(),
            3,
            "an outcome replaces a row rather than adding one"
        );
        assert_eq!(
            mixed
                .iter()
                .filter(|(_, outcome)| outcome == PROGRESS_PLANNED)
                .count(),
            2,
            "and the rest are still unresolved: {mixed:?}"
        );
    }

    #[test]
    fn a_store_written_by_an_earlier_build_gains_the_columns_it_is_missing() {
        // The tables are created only when they are absent, so a store an earlier build wrote has
        // the tables and not the columns added since. Opening it has to add them: a replacement
        // daemon that cannot read its own journal cannot recover anything. And the version says
        // which build wrote the store rather than which columns it has, so the step runs for
        // every version below the current one and adds whatever is missing.
        const EARLIEST: &str = "
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (1);
            CREATE TABLE operations (
                action_id             BLOB PRIMARY KEY,
                actor_id              TEXT NOT NULL,
                environment_id        BLOB NOT NULL,
                project_repository_id BLOB NOT NULL,
                method                TEXT NOT NULL,
                state                 TEXT NOT NULL,
                remote_name           TEXT,
                remote_transport      TEXT,
                remote_url            TEXT,
                remote_provider       TEXT,
                remote_broker         TEXT,
                flow                  TEXT,
                destination_state     TEXT NOT NULL,
                parent_path           TEXT NOT NULL,
                destination_name      TEXT NOT NULL,
                staging_name          TEXT,
                staged_device         INTEGER,
                staged_file_id        INTEGER,
                detail                TEXT,
                started_at_ms         INTEGER NOT NULL,
                ended_at_ms           INTEGER
            );
            CREATE TABLE workspaces (
                workspace_id          BLOB PRIMARY KEY,
                project_repository_id BLOB NOT NULL,
                environment_id        BLOB NOT NULL,
                label                 TEXT NOT NULL,
                kind                  TEXT NOT NULL,
                isolation             TEXT,
                dirty_files           TEXT NOT NULL,
                untracked_files       TEXT NOT NULL,
                submodules            TEXT NOT NULL,
                binary_files          TEXT NOT NULL,
                generated_artefacts   TEXT NOT NULL,
                state                 TEXT NOT NULL,
                base_revision         TEXT NOT NULL,
                base_change_set_id    BLOB,
                tree_device           INTEGER,
                tree_file_id          INTEGER,
                display_path          TEXT NOT NULL,
                retention             TEXT,
                created_at_ms         INTEGER NOT NULL,
                removed_at_ms         INTEGER
            );";
        let directory = tempfile::tempdir().expect("a directory");
        // The earliest shape of version 1, which had neither of the workspace columns this build
        // reads nor the staged instant.
        let earliest = directory.path().join("earliest.sqlite");
        let first = Connection::open(&earliest).expect("the earliest store opens");
        first
            .execute_batch(EARLIEST)
            .expect("the earliest shape is written");
        drop(first);
        let store = Store::open(&earliest, environment()).expect("this build opens it");
        assert!(store.operations_in(&[OperationState::Staging]).is_ok());
        assert!(store.workspaces(environment(), None).is_ok());
        let version: i64 = store
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("the version reads");
        assert_eq!(version, SCHEMA_VERSION);
        drop(store);
        // A store an earlier build wrote whose columns are all there and whose reasons are not
        // protected. The version moves on, and the reasons are rewritten.
        let unprotected = directory.path().join("unprotected.sqlite");
        let earlier = Connection::open(&unprotected).expect("the earlier store opens");
        earlier
            .execute_batch(EARLIEST)
            .expect("the earliest shape is written for it");
        earlier
            .execute_batch(
                "INSERT INTO operations (action_id, actor_id, environment_id,
                                         project_repository_id, method, state, destination_state,
                                         parent_path, destination_name, detail, started_at_ms)
                 VALUES (x'01', 'a', x'02', x'03', 'project.clone', 'failed', 'absent', '/p',
                         'access_token=STOREDSECRET',
                         'so /p/access_token=STOREDSECRET is untouched', 1);
                 UPDATE schema_version SET version = 3;",
            )
            .expect("an unprotected reason is written");
        drop(earlier);
        let store = Store::open(&unprotected, environment()).expect("this build opens it");
        let kept: String = store
            .connection
            .query_row("SELECT detail FROM operations", [], |row| row.get(0))
            .expect("the reason reads");
        assert!(
            !kept.contains("STOREDSECRET"),
            "an earlier build's reason is rewritten in the file: {kept}"
        );
        assert!(kept.contains("does-not-repeat"), "{kept}");
        // The whole reason goes, because a build that did not put the path through the rule left
        // nothing to tell the path from the sentence around it. A reason *this* build composes
        // keeps its words, because the fragment is replaced before the sentence is built, and
        // `the_rule_leaves_its_own_output_alone` is where that is asserted.
        drop(store);
        // The shape a *partial* migration left: an earlier build moved a store to version 2 while
        // adding only some of the columns, so the version number does not describe the shape.
        let partial = directory.path().join("partial.sqlite");
        let half = Connection::open(&partial).expect("the partial store opens");
        half.execute_batch(EARLIEST)
            .expect("the earliest shape is written again");
        half.execute_batch(
            "ALTER TABLE operations ADD COLUMN staging_device INTEGER;
             ALTER TABLE operations ADD COLUMN staging_file_id INTEGER;
             ALTER TABLE workspaces ADD COLUMN staging_device INTEGER;
             ALTER TABLE workspaces ADD COLUMN staging_file_id INTEGER;
             ALTER TABLE workspaces ADD COLUMN removal_action BLOB;
             UPDATE schema_version SET version = 2;",
        )
        .expect("the partial migration is written");
        drop(half);
        let store = Store::open(&partial, environment()).expect("this build repairs it");
        assert!(store.operations_in(&[OperationState::Publishing]).is_ok());
        assert!(store.workspaces(environment(), None).is_ok());
        let version: i64 = store
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("the version reads");
        assert_eq!(version, SCHEMA_VERSION);
        drop(store);
        // And a store from a *later* build is refused rather than half read. What it leaves behind
        // is what it found: the whole migration is one transaction, so the tables this build would
        // have created are not there either.
        let later = directory.path().join("later.sqlite");
        let ahead = Connection::open(&later).expect("the later store opens");
        ahead
            .execute_batch(EARLIEST)
            .expect("the earliest shape is written once more");
        ahead
            .execute(
                "UPDATE schema_version SET version = ?1",
                params![SCHEMA_VERSION + 1],
            )
            .expect("a later version is written");
        drop(ahead);
        let refusal = Store::open(&later, environment()).expect_err("a later store is refused");
        assert_eq!(refusal.code(), ErrorCode::StorageUnavailable);
        let refused = Connection::open(&later).expect("the refused store opens");
        let tables: i64 = refused
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type = 'table' AND name IN ('workspace_progress', 'workspace_runs')",
                [],
                |row| row.get(0),
            )
            .expect("the table list reads");
        assert_eq!(
            tables, 0,
            "a store this build refuses is left exactly as it was found"
        );
    }

    #[test]
    fn a_live_run_and_a_live_session_each_refuse_a_removal() {
        let mut store = Store::in_memory(environment()).expect("a store opens");
        let workspace_id = WorkspaceId::new(Uuid::from_bytes([50; 16]));
        let workspace = WorkspaceRow {
            workspace_id,
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            environment_id: environment(),
            label: "held".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Some(IsolationMechanism::GitWorktree),
            policy: InclusionPolicy::base_only(),
            state: WorkspaceState::Ready,
            base_revision: "a".repeat(40),
            base_change_set_id: None,
            identity: None,
            display_path: "/tmp/held".to_owned(),
            staging_name: None,
            staging_identity: None,
            detail: None,
            retention: None,
            created_at_ms: TimestampMs::new(1),
            removed_at_ms: None,
        };
        store.begin_workspace(&workspace, None).expect("it begins");
        let run = WorkflowRunId::new(Uuid::from_bytes([51; 16]));
        store.bind_run(workspace_id, run, true).expect("it binds");
        let refusal = store
            .begin_removal(workspace_id, RetentionPolicy::KeepEverything, None)
            .expect_err("a live run refuses it");
        assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
        assert_eq!(store.live_runs(workspace_id).expect("it reads"), vec![run]);
        store.bind_run(workspace_id, run, false).expect("it ends");
        assert!(store.live_runs(workspace_id).expect("it reads").is_empty());
        store
            .begin_removal(workspace_id, RetentionPolicy::KeepEverything, None)
            .expect("nothing holds it now");
    }
}
