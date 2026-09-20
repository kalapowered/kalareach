//! The workflow journal: environment store for definitions, runs, node receipts, and causal budgets.
//!
//! Section 24 and Lead Ruling D-114.12 state:
//! - The workflow journal is this crate's own SQLite store under the environment's runtime directory,
//!   opened and owned by the crate.
//! - Commits the trigger, run, and budget reservation together with an outbox record in one
//!   local transaction.
//! - Deduplicates triggers by `(workflow_id, definition_revision, event_id)`.
//! - Budgets survive restart and reboot.
//! - Only undispatched and still-authorised steps resume after restart; unknown predecessors pause.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::automation::{
    NodeReceiptSummary, NodeStatus, WorkflowDefinition, WorkflowDefinitionSummary,
    WorkflowRunStatus, WorkflowRunSummary,
};
use kr_protocol::ids::{ActionId, CausalRootId, GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::budget::CausalBudget;
use crate::causal::CausalContext;
use crate::error::{AutomationError, Result};

/// Default file name for the workflow journal database.
pub const WORKFLOW_DB_NAME: &str = "workflows.db";

/// The schema version this build reads and writes.
pub const WORKFLOW_SCHEMA_VERSION: u32 = 1;

/// The columns [`WorkflowStore::parse_run_record`] expects, in order.
const RUN_RECORD_QUERY: &str = "SELECT run_id, workflow_id, revision, causal_root_id, generation,
            depth, parent_run_id, parent_node_id
     FROM workflow_runs WHERE run_id = ?1";

/// Reads an identifier the journal wrote, reporting a corrupt row rather than panicking on it.
fn parse_stored_uuid(value: &str) -> rusqlite::Result<kr_protocol::scalars::Uuid> {
    crate::parse_uuid(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// Durable record of a workflow run, and the host's only source of causal ancestry.
#[derive(Debug, Clone)]
pub struct StoredRunRecord {
    /// The unique identifier of the run.
    pub run_id: WorkflowRunId,
    /// The workflow definition identifier.
    pub workflow_id: WorkflowId,
    /// The workflow revision number.
    pub revision: u64,
    /// The causal root identifier.
    pub causal_root_id: CausalRootId,
    /// The causal budget generation the run belongs to.
    pub generation: u64,
    /// The causal depth in the tree.
    pub depth: u64,
    /// Optional parent run identifier.
    pub parent_run_id: Option<WorkflowRunId>,
    /// Optional parent node identifier.
    pub parent_node_id: Option<String>,
}

/// The event type of the attention record an exhausted causal chain leaves in the outbox.
pub const ATTENTION_CAUSAL_LIMIT: &str = "attention.causal_limit";
/// The event type of the attention record a workflow paused by its own limits leaves.
pub const ATTENTION_WORKFLOW_PAUSED: &str = "attention.workflow_paused";
/// The event type that ends the condition [`ATTENTION_WORKFLOW_PAUSED`] raised.
pub const ATTENTION_WORKFLOW_RESUMED: &str = "attention.workflow_resumed";

/// What an attention record is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionSubject {
    /// A causal chain whose budget ran out.
    CausalRoot(CausalRootId),
    /// A workflow paused because one of its own limits was breached.
    Workflow(WorkflowId),
}

impl std::fmt::Display for AttentionSubject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CausalRoot(root) => write!(formatter, "automation.causal_budget.{root}"),
            Self::Workflow(workflow) => write!(formatter, "automation.workflow.{workflow}"),
        }
    }
}

/// An installed definition together with the operational state the journal keeps beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledDefinition {
    /// The document as it was installed. It never changes.
    pub definition: WorkflowDefinition,
    /// Whether the revision has been enabled.
    pub enabled: bool,
    /// Whether the revision has been paused, by request or by a breached limit.
    pub paused: bool,
}

/// One undelivered attention record from the workflow journal's outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionOutboxRecord {
    /// Whether the record raises a condition or ends one.
    pub ends_condition: bool,
    /// The outbox row.
    ///
    /// It is also the delivery cursor: a redelivery of the same row carries the same sequence,
    /// so an attention engine that already consumed it counts nothing twice.
    pub outbox_id: i64,
    /// What the record is about.
    pub subject: AttentionSubject,
    /// Which limit was reached.
    pub reason: String,
    /// When the record was committed.
    pub created_at_ms: u64,
}

/// Reads back the subject an attention record was written with.
fn parse_attention_subject(value: &str) -> Option<AttentionSubject> {
    if let Some(root) = value.strip_prefix("automation.causal_budget.") {
        return crate::parse_uuid(root)
            .ok()
            .map(|id| AttentionSubject::CausalRoot(CausalRootId::new(id)));
    }
    let workflow = value.strip_prefix("automation.workflow.")?;
    crate::parse_uuid(workflow)
        .ok()
        .map(|id| AttentionSubject::Workflow(WorkflowId::new(id)))
}

/// Writes one attention record into the journal's outbox, inside the caller's transaction.
fn record_attention_tx(
    tx: &rusqlite::Transaction<'_>,
    event_type: &str,
    subject: &AttentionSubject,
    reason: &str,
    now_ms: u64,
) -> Result<()> {
    let payload = serde_json::json!({ "subject": subject.to_string(), "reason": reason });
    tx.execute(
        "INSERT INTO outbox_events (event_type, payload_json, created_at_ms)
         VALUES (?1, ?2, ?3)",
        params![event_type, payload.to_string(), now_ms as i64],
    )?;
    Ok(())
}

/// The persistent workflow journal.
pub struct WorkflowStore {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl std::fmt::Debug for WorkflowStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkflowStore")
            .field("path", &self.path)
            .finish()
    }
}

impl WorkflowStore {
    /// Opens the workflow journal database in the specified directory.
    pub fn open(runtime_dir: impl AsRef<Path>) -> Result<Self> {
        let path = runtime_dir.as_ref().join(WORKFLOW_DB_NAME);
        let conn = Connection::open(&path)?;
        let store = Self {
            conn: Mutex::new(conn),
            path,
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Opens an in-memory workflow journal for tests.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
            path: PathBuf::from(":memory:"),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Creates this journal's schema, or refuses a journal written to a different one.
    ///
    /// A journal carries the schema version it was written with. Reading one written to another
    /// version with statements meant for this one would fail later, somewhere unhelpful, so the
    /// refusal happens here and says what it found.
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let empty: bool = conn.query_row(
            "SELECT COUNT(*) = 0 FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )?;

        if !empty && found != WORKFLOW_SCHEMA_VERSION {
            return Err(AutomationError::InvalidArgument(format!(
                "the workflow journal at {} was written to schema version {found}, and this build reads version {WORKFLOW_SCHEMA_VERSION}",
                self.path.display()
            )));
        }

        conn.execute_batch(
            "
            BEGIN IMMEDIATE;

            CREATE TABLE IF NOT EXISTS workflow_definitions (
                workflow_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                definition_json TEXT NOT NULL,
                grant_reference TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                paused INTEGER NOT NULL,
                installed_at_ms INTEGER NOT NULL,
                PRIMARY KEY (workflow_id, revision)
            );

            CREATE TABLE IF NOT EXISTS causal_budgets (
                causal_root_id TEXT PRIMARY KEY,
                generation INTEGER NOT NULL DEFAULT 0,
                depth INTEGER NOT NULL,
                max_depth INTEGER NOT NULL,
                total_runs INTEGER NOT NULL,
                max_runs INTEGER NOT NULL,
                total_actions INTEGER NOT NULL,
                max_actions INTEGER NOT NULL,
                created_sessions INTEGER NOT NULL,
                max_sessions INTEGER NOT NULL,
                started_at_ms INTEGER NOT NULL,
                max_lifetime_ms INTEGER NOT NULL,
                paused INTEGER NOT NULL,
                exhausted INTEGER NOT NULL,
                attention_emitted INTEGER NOT NULL,
                rearmed_at_ms INTEGER
            );

            CREATE TABLE IF NOT EXISTS workflow_runs (
                run_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                trigger_event_id TEXT NOT NULL,
                causal_root_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                depth INTEGER NOT NULL,
                parent_run_id TEXT,
                parent_node_id TEXT,
                status TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER,
                deadline_ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS workflow_runs_by_root
                ON workflow_runs (causal_root_id);

            CREATE TABLE IF NOT EXISTS trigger_dedup (
                workflow_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                PRIMARY KEY (workflow_id, revision, event_id)
            );

            CREATE TABLE IF NOT EXISTS node_receipts (
                run_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                causal_parent TEXT,
                status TEXT NOT NULL,
                output_json TEXT,
                error_json TEXT,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER,
                PRIMARY KEY (run_id, node_id)
            );

            CREATE TABLE IF NOT EXISTS outbox_events (
                outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                settled_at_ms INTEGER
            );

            CREATE TABLE IF NOT EXISTS consumed_cursors (
                source_name TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL
            );

            PRAGMA user_version = 1;

            COMMIT;
            ",
        )?;
        Ok(())
    }

    /// Installs a workflow definition revision.
    ///
    /// An installed revision is immutable: a second insert of the same number is refused. It
    /// starts disabled and unpaused, because enabling a revision is its own authorised method.
    pub fn save_definition(
        &self,
        definition: &WorkflowDefinition,
        installed_at_ms: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let def_json = serde_json::to_string(definition)?;
        conn.execute(
            "INSERT INTO workflow_definitions (
                workflow_id, revision, name, description, definition_json,
                grant_reference, enabled, paused, installed_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7)",
            params![
                definition.workflow_id.to_string(),
                definition.revision.get() as i64,
                definition.name,
                definition.description.as_ref(),
                def_json,
                definition.grant_reference.to_string(),
                installed_at_ms as i64,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(err, _)
                if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY =>
            {
                AutomationError::AlreadyInstalled {
                    workflow_id: definition.workflow_id,
                    revision: definition.revision.get(),
                }
            }
            other => AutomationError::DatabaseError(other),
        })?;
        Ok(())
    }

    /// Loads the latest revision of a workflow definition with its operational state.
    pub fn get_latest_definition(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<InstalledDefinition>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT definition_json, enabled, paused FROM workflow_definitions
             WHERE workflow_id = ?1
             ORDER BY revision DESC LIMIT 1",
        )?;
        let found = stmt
            .query_row(params![workflow_id.to_string()], Self::parse_installed)
            .optional()?;
        found.transpose()
    }

    /// Loads an exact revision of a workflow definition with its operational state.
    ///
    /// The document is what was installed and never changes. Whether it is enabled, and whether
    /// it is paused, are the journal's and are read from their own columns, so an enable or a
    /// pause after installation is what decides whether the revision runs.
    pub fn get_definition(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
    ) -> Result<Option<InstalledDefinition>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT definition_json, enabled, paused FROM workflow_definitions
             WHERE workflow_id = ?1 AND revision = ?2",
        )?;
        let found = stmt
            .query_row(
                params![workflow_id.to_string(), revision as i64],
                Self::parse_installed,
            )
            .optional()?;
        found.transpose()
    }

    fn parse_installed(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<InstalledDefinition>> {
        let json: String = row.get(0)?;
        let enabled: i64 = row.get(1)?;
        let paused: i64 = row.get(2)?;
        Ok(serde_json::from_str(&json)
            .map(|definition| InstalledDefinition {
                definition,
                enabled: enabled != 0,
                paused: paused != 0,
            })
            .map_err(AutomationError::JsonError))
    }

    /// Sets the enabled state of an installed definition revision.
    pub fn set_enabled(&self, workflow_id: WorkflowId, revision: u64, enabled: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE workflow_definitions SET enabled = ?1
             WHERE workflow_id = ?2 AND revision = ?3",
            params![
                if enabled { 1 } else { 0 },
                workflow_id.to_string(),
                revision as i64,
            ],
        )?;
        if updated == 0 {
            return Err(AutomationError::WorkflowNotFound(workflow_id));
        }
        Ok(())
    }

    /// Sets the paused state of an installed definition revision.
    pub fn set_paused(&self, workflow_id: WorkflowId, revision: u64, paused: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE workflow_definitions SET paused = ?1
             WHERE workflow_id = ?2 AND revision = ?3",
            params![
                if paused { 1 } else { 0 },
                workflow_id.to_string(),
                revision as i64,
            ],
        )?;
        if updated == 0 {
            return Err(AutomationError::WorkflowNotFound(workflow_id));
        }
        Ok(())
    }

    /// Reads all definitions matching criteria.
    pub fn list_definitions(
        &self,
        workflow_id: Option<WorkflowId>,
    ) -> Result<Vec<WorkflowDefinitionSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut result = Vec::new();

        let query = if workflow_id.is_some() {
            "SELECT workflow_id, revision, name, description, grant_reference, enabled, installed_at_ms
             FROM workflow_definitions WHERE workflow_id = ?1 ORDER BY revision ASC"
        } else {
            "SELECT workflow_id, revision, name, description, grant_reference, enabled, installed_at_ms
             FROM workflow_definitions ORDER BY workflow_id, revision ASC"
        };

        let mut stmt = conn.prepare(query)?;
        let rows = if let Some(id) = workflow_id {
            stmt.query_map(params![id.to_string()], Self::parse_def_summary)?
        } else {
            stmt.query_map([], Self::parse_def_summary)?
        };

        for r in rows {
            result.push(r?);
        }
        Ok(result)
    }

    fn parse_def_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkflowDefinitionSummary> {
        let wf_str: String = row.get(0)?;
        let rev: i64 = row.get(1)?;
        let name: String = row.get(2)?;
        let desc: Option<String> = row.get(3)?;
        let grant_str: String = row.get(4)?;
        let enabled: i64 = row.get(5)?;
        let installed: i64 = row.get(6)?;

        let workflow_id = WorkflowId::new(parse_stored_uuid(&wf_str)?);
        let grant_reference = GrantId::new(parse_stored_uuid(&grant_str)?);

        Ok(WorkflowDefinitionSummary {
            workflow_id,
            revision: U64::new(rev as u64),
            name,
            description: Nullable::from(desc),
            grant_reference,
            enabled: enabled != 0,
            installed_at_ms: TimestampMs::new(installed as u64),
        })
    }

    /// Loads or creates a causal budget for a causal root.
    pub fn get_or_create_budget(&self, root_id: CausalRootId, now_ms: u64) -> Result<CausalBudget> {
        let conn = self.conn.lock().unwrap();
        if let Some(budget) = Self::load_budget_tx(&conn, root_id)? {
            Ok(budget)
        } else {
            let budget = CausalBudget::new(root_id, now_ms);
            Self::save_budget_tx(&conn, &budget)?;
            Ok(budget)
        }
    }

    /// Loads an existing causal budget if present.
    pub fn get_budget(&self, root_id: CausalRootId) -> Result<Option<CausalBudget>> {
        let conn = self.conn.lock().unwrap();
        Self::load_budget_tx(&conn, root_id)
    }

    /// Saves a causal budget.
    pub fn save_budget(&self, budget: &CausalBudget) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        Self::save_budget_tx(&conn, budget)
    }

    fn load_budget_tx(conn: &Connection, root_id: CausalRootId) -> Result<Option<CausalBudget>> {
        let mut stmt = conn.prepare(
            "SELECT generation, depth, max_depth, total_runs, max_runs, total_actions, max_actions,
                    created_sessions, max_sessions, started_at_ms, max_lifetime_ms,
                    paused, exhausted, attention_emitted, rearmed_at_ms
             FROM causal_budgets WHERE causal_root_id = ?1",
        )?;
        let mut rows = stmt.query(params![root_id.to_string()])?;
        if let Some(row) = rows.next()? {
            Ok(Some(CausalBudget {
                causal_root_id: root_id,
                generation: row.get::<_, i64>(0)? as u64,
                depth: row.get::<_, i64>(1)? as u64,
                max_depth: row.get::<_, i64>(2)? as u64,
                total_runs: row.get::<_, i64>(3)? as u64,
                max_runs: row.get::<_, i64>(4)? as u64,
                total_actions: row.get::<_, i64>(5)? as u64,
                max_actions: row.get::<_, i64>(6)? as u64,
                created_sessions: row.get::<_, i64>(7)? as u64,
                max_sessions: row.get::<_, i64>(8)? as u64,
                started_at_ms: row.get::<_, i64>(9)? as u64,
                max_lifetime_ms: row.get::<_, i64>(10)? as u64,
                paused: row.get::<_, i64>(11)? != 0,
                exhausted: row.get::<_, i64>(12)? != 0,
                attention_emitted: row.get::<_, i64>(13)? != 0,
                rearmed_at_ms: row.get::<_, Option<i64>>(14)?.map(|v| v as u64),
            }))
        } else {
            Ok(None)
        }
    }

    fn save_budget_tx(conn: &Connection, budget: &CausalBudget) -> Result<()> {
        conn.execute(
            "INSERT INTO causal_budgets (
                causal_root_id, generation, depth, max_depth, total_runs, max_runs,
                total_actions, max_actions, created_sessions, max_sessions,
                started_at_ms, max_lifetime_ms, paused, exhausted,
                attention_emitted, rearmed_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(causal_root_id) DO UPDATE SET
                generation = excluded.generation,
                depth = excluded.depth,
                total_runs = excluded.total_runs,
                total_actions = excluded.total_actions,
                created_sessions = excluded.created_sessions,
                started_at_ms = excluded.started_at_ms,
                paused = excluded.paused,
                exhausted = excluded.exhausted,
                attention_emitted = excluded.attention_emitted,
                rearmed_at_ms = excluded.rearmed_at_ms",
            params![
                budget.causal_root_id.to_string(),
                budget.generation as i64,
                budget.depth as i64,
                budget.max_depth as i64,
                budget.total_runs as i64,
                budget.max_runs as i64,
                budget.total_actions as i64,
                budget.max_actions as i64,
                budget.created_sessions as i64,
                budget.max_sessions as i64,
                budget.started_at_ms as i64,
                budget.max_lifetime_ms as i64,
                if budget.paused { 1 } else { 0 },
                if budget.exhausted { 1 } else { 0 },
                if budget.attention_emitted { 1 } else { 0 },
                budget.rearmed_at_ms.map(|v| v as i64),
            ],
        )?;
        Ok(())
    }

    /// Reserves one action of the causal budget, in one transaction with its refusal.
    ///
    /// The load, the ceiling check, the reservation and any exhaustion commit together, so two
    /// concurrent dispatches cannot both read the last free action and both take it.
    pub fn reserve_budget_action(
        &self,
        root_id: CausalRootId,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.reserve_in_budget(root_id, generation, now_ms, |budget| {
            budget.reserve_action(now_ms)
        })
    }

    /// Reserves one created session of the causal budget, in one transaction with its refusal.
    pub fn reserve_budget_session(
        &self,
        root_id: CausalRootId,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.reserve_in_budget(root_id, generation, now_ms, |budget| {
            budget.reserve_session(now_ms)
        })
    }

    /// Runs one reservation against the durable budget inside a single transaction.
    fn reserve_in_budget(
        &self,
        root_id: CausalRootId,
        generation: u64,
        now_ms: u64,
        reserve: impl FnOnce(&mut CausalBudget) -> Result<()>,
    ) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let mut budget = Self::load_budget_tx(&tx, root_id)?
            .unwrap_or_else(|| CausalBudget::new(root_id, now_ms));

        budget.check_generation(generation)?;

        let was_emitted = budget.attention_emitted;
        let outcome = reserve(&mut budget);
        Self::save_budget_tx(&tx, &budget)?;
        if let Err(err) = &outcome
            && budget.attention_emitted
            && !was_emitted
        {
            Self::record_exhaustion_tx(&tx, root_id, &err.to_string(), now_ms)?;
        }
        tx.commit()?;
        outcome
    }

    /// Records the one attention item an exhausted chain owes.
    ///
    /// The caller has already flipped the budget's `attention_emitted` flag inside the same
    /// transaction, so a chain that stays exhausted never queues a second item.
    fn record_exhaustion_tx(
        tx: &rusqlite::Transaction<'_>,
        root_id: CausalRootId,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        record_attention_tx(
            tx,
            ATTENTION_CAUSAL_LIMIT,
            &AttentionSubject::CausalRoot(root_id),
            reason,
            now_ms,
        )
    }

    /// Clears a pause and records the recovery the attention item it raised is waiting for.
    ///
    /// The item an exceedance raised stays in the inbox, climbing its ladder, until something
    /// says the condition ended. Clearing the pause is that something, and the record commits
    /// with it. A revision that was not paused records nothing.
    pub fn resume_workflow(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        now_ms: u64,
    ) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let resumed = tx.execute(
            "UPDATE workflow_definitions SET paused = 0
             WHERE workflow_id = ?1 AND revision = ?2 AND paused = 1",
            params![workflow_id.to_string(), revision as i64],
        )?;
        if resumed > 0 {
            record_attention_tx(
                &tx,
                ATTENTION_WORKFLOW_RESUMED,
                &AttentionSubject::Workflow(workflow_id),
                "the workflow was enabled again",
                now_ms,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Pauses a workflow revision and records the attention item the pause owes, together.
    ///
    /// Section 17 ¶8 asks for both when one of a workflow's own limits is breached. A revision
    /// that is already paused records nothing further, so a workflow being hammered produces one
    /// item rather than one per refusal.
    pub fn pause_workflow_on_breach(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let paused = tx.execute(
            "UPDATE workflow_definitions SET paused = 1
             WHERE workflow_id = ?1 AND revision = ?2 AND paused = 0",
            params![workflow_id.to_string(), revision as i64],
        )?;
        if paused > 0 {
            record_attention_tx(
                &tx,
                ATTENTION_WORKFLOW_PAUSED,
                &AttentionSubject::Workflow(workflow_id),
                reason,
                now_ms,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Rearms the budget under an authorised administrative request.
    pub fn rearm_budget(&self, root_id: CausalRootId, now_ms: u64) -> Result<CausalBudget> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let mut budget = Self::load_budget_tx(&tx, root_id)?
            .ok_or_else(|| AutomationError::InvalidArgument("causal root not found".to_owned()))?;

        budget.rearm(now_ms);
        Self::save_budget_tx(&tx, &budget)?;
        tx.commit()?;
        Ok(budget)
    }

    /// Retrieves the durable run record the host verifies causal ancestry against.
    pub fn get_run_record(&self, run_id: WorkflowRunId) -> Result<Option<StoredRunRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(RUN_RECORD_QUERY)?;
        let record = stmt
            .query_row(params![run_id.to_string()], Self::parse_run_record)
            .optional()?;
        Ok(record)
    }

    /// Claims a node for dispatch, if the journal still has it waiting for one.
    ///
    /// The read of the status and the move to running are one statement, so a cancellation that
    /// lands between them cannot be lost: either it got there first and this returns false, or
    /// it finds the node already running and leaves it alone.
    pub fn claim_node_for_dispatch(&self, run_id: WorkflowRunId, node_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let claimed = conn.execute(
            "UPDATE node_receipts SET status = ?1
             WHERE run_id = ?2 AND node_id = ?3 AND status = ?4",
            params![
                NodeStatus::Running.as_str(),
                run_id.to_string(),
                node_id,
                NodeStatus::Pending.as_str(),
            ],
        )?;
        Ok(claimed > 0)
    }

    /// Reports whether a workflow revision is currently paused.
    pub fn is_paused(&self, workflow_id: WorkflowId, revision: u64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let paused: Option<i64> = conn
            .query_row(
                "SELECT paused FROM workflow_definitions WHERE workflow_id = ?1 AND revision = ?2",
                params![workflow_id.to_string(), revision as i64],
                |row| row.get(0),
            )
            .optional()?;
        Ok(paused.unwrap_or(0) != 0)
    }

    /// Reports whether this trigger has already been recorded for this revision.
    pub fn trigger_is_recorded(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        event_id: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM trigger_dedup
                 WHERE workflow_id = ?1 AND revision = ?2 AND event_id = ?3",
                params![workflow_id.to_string(), revision as i64, event_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Reads one node's recorded status.
    pub fn node_status(&self, run_id: WorkflowRunId, node_id: &str) -> Result<Option<NodeStatus>> {
        let conn = self.conn.lock().unwrap();
        let status: Option<String> = conn
            .query_row(
                "SELECT status FROM node_receipts WHERE run_id = ?1 AND node_id = ?2",
                params![run_id.to_string(), node_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(status.and_then(|value| NodeStatus::from_wire(&value)))
    }

    /// Checks whether a node of a run has a receipt, which is what makes it a usable parent.
    pub fn node_receipt_exists(&self, run_id: WorkflowRunId, node_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT 1 FROM node_receipts WHERE run_id = ?1 AND node_id = ?2")?;
        let mut rows = stmt.query(params![run_id.to_string(), node_id])?;
        Ok(rows.next()?.is_some())
    }

    /// Lists durable run records sharing a causal root.
    pub fn list_runs_by_root(&self, root_id: CausalRootId) -> Result<Vec<StoredRunRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT run_id, workflow_id, revision, causal_root_id, generation, depth,
                    parent_run_id, parent_node_id
             FROM workflow_runs WHERE causal_root_id = ?1 ORDER BY depth ASC",
        )?;
        let rows = stmt.query_map(params![root_id.to_string()], Self::parse_run_record)?;

        let mut result = Vec::new();
        for r in rows {
            result.push(r?);
        }
        Ok(result)
    }

    fn parse_run_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRunRecord> {
        let run_id_str: String = row.get(0)?;
        let wf_id_str: String = row.get(1)?;
        let rev: i64 = row.get(2)?;
        let root_str: String = row.get(3)?;
        let generation: i64 = row.get(4)?;
        let depth: i64 = row.get(5)?;
        let parent_run_str: Option<String> = row.get(6)?;
        let parent_node_id: Option<String> = row.get(7)?;

        Ok(StoredRunRecord {
            run_id: WorkflowRunId::new(parse_stored_uuid(&run_id_str)?),
            workflow_id: WorkflowId::new(parse_stored_uuid(&wf_id_str)?),
            revision: rev as u64,
            causal_root_id: CausalRootId::new(parse_stored_uuid(&root_str)?),
            generation: generation as u64,
            depth: depth as u64,
            parent_run_id: parent_run_str
                .map(|s| parse_stored_uuid(&s).map(WorkflowRunId::new))
                .transpose()?,
            parent_node_id,
        })
    }

    /// Commits a trigger, run, and budget reservation together with outbox in one atomic local transaction.
    ///
    /// Deduplicates by `(workflow_id, definition_revision, event_id)`.
    pub fn commit_trigger_and_run(
        &self,
        run_id: WorkflowRunId,
        definition: &WorkflowDefinition,
        event_id: &str,
        causal_ctx: &CausalContext,
        now_ms: u64,
    ) -> Result<CausalBudget> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let wf_id_str = definition.workflow_id.to_string();
        let rev = definition.revision.get() as i64;

        // 1. Check deduplication
        let existing: Option<String> = tx
            .query_row(
                "SELECT run_id FROM trigger_dedup WHERE workflow_id = ?1 AND revision = ?2 AND event_id = ?3",
                params![wf_id_str, rev, event_id],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Err(AutomationError::DuplicateTrigger {
                workflow_id: definition.workflow_id,
                revision: definition.revision.get(),
                event_id: event_id.to_owned(),
            });
        }

        // 2. Load or create causal budget
        let mut budget = Self::load_budget_tx(&tx, causal_ctx.root_id)?
            .unwrap_or_else(|| CausalBudget::new(causal_ctx.root_id, now_ms));

        // 3. Check generation and reserve the run
        budget.check_generation(causal_ctx.generation)?;
        let was_emitted = budget.attention_emitted;
        if let Err(err) = budget.reserve_run(causal_ctx.depth, now_ms) {
            // The pause, the refusal and the attention record land together.
            Self::save_budget_tx(&tx, &budget)?;
            if budget.attention_emitted && !was_emitted {
                Self::record_exhaustion_tx(&tx, causal_ctx.root_id, &err.to_string(), now_ms)?;
            }
            tx.commit()?;
            return Err(err);
        }

        // 4. Save updated budget
        Self::save_budget_tx(&tx, &budget)?;

        // 5. Insert run record
        let parent_run_id = causal_ctx
            .parent
            .as_ref()
            .map(|p| p.parent_run_id.to_string());
        let parent_node_id = causal_ctx.parent.as_ref().map(|p| p.parent_node_id.clone());
        let deadline_ms = now_ms.saturating_add(definition.deadlines.run_deadline_ms.get());

        tx.execute(
            "INSERT INTO workflow_runs (
                run_id, workflow_id, revision, trigger_event_id, causal_root_id, generation,
                depth, parent_run_id, parent_node_id, status, started_at_ms, deadline_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                run_id.to_string(),
                wf_id_str,
                rev,
                event_id,
                causal_ctx.root_id.to_string(),
                causal_ctx.generation as i64,
                causal_ctx.depth as i64,
                parent_run_id,
                parent_node_id,
                WorkflowRunStatus::Pending.as_str(),
                now_ms as i64,
                deadline_ms as i64,
            ],
        )?;

        // 6. Record deduplication
        tx.execute(
            "INSERT INTO trigger_dedup (workflow_id, revision, event_id, run_id, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![wf_id_str, rev, event_id, run_id.to_string(), now_ms as i64],
        )?;

        // 7. Initialise all nodes as Pending
        for node in &definition.nodes {
            let action_id = ActionId::new(crate::new_uuid());
            tx.execute(
                "INSERT INTO node_receipts (
                    run_id, node_id, action_id, causal_parent, status, started_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run_id.to_string(),
                    node.node_id,
                    action_id.to_string(),
                    parent_node_id,
                    NodeStatus::Pending.as_str(),
                    now_ms as i64,
                ],
            )?;
        }

        tx.commit()?;
        Ok(budget)
    }

    /// Updates a workflow run's status.
    pub fn update_run_status(
        &self,
        run_id: WorkflowRunId,
        status: WorkflowRunStatus,
        ended_at_ms: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE workflow_runs SET status = ?1, ended_at_ms = ?2 WHERE run_id = ?3",
            params![
                status.as_str(),
                ended_at_ms.map(|v| v as i64),
                run_id.to_string()
            ],
        )?;
        Ok(())
    }

    /// Updates an action node's receipt and outcome.
    pub fn update_node_receipt(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        status: NodeStatus,
        output: Option<&str>,
        error: Option<&str>,
        ended_at_ms: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE node_receipts SET status = ?1, output_json = ?2, error_json = ?3, ended_at_ms = ?4
             WHERE run_id = ?5 AND node_id = ?6",
            params![
                status.as_str(),
                output,
                error,
                ended_at_ms.map(|v| v as i64),
                run_id.to_string(),
                node_id,
            ],
        )?;
        Ok(())
    }

    /// Reads run summaries.
    pub fn list_runs(&self, workflow_id: Option<WorkflowId>) -> Result<Vec<WorkflowRunSummary>> {
        let conn = self.conn.lock().unwrap();
        let query = if workflow_id.is_some() {
            "SELECT run_id, workflow_id, revision, causal_root_id, depth, status,
                    trigger_event_id, started_at_ms, ended_at_ms
             FROM workflow_runs WHERE workflow_id = ?1 ORDER BY started_at_ms DESC"
        } else {
            "SELECT run_id, workflow_id, revision, causal_root_id, depth, status,
                    trigger_event_id, started_at_ms, ended_at_ms
             FROM workflow_runs ORDER BY started_at_ms DESC"
        };

        let mut stmt = conn.prepare(query)?;
        let rows = if let Some(id) = workflow_id {
            stmt.query_map(params![id.to_string()], Self::parse_run_summary)?
        } else {
            stmt.query_map([], Self::parse_run_summary)?
        };

        let mut result = Vec::new();
        for r in rows {
            result.push(r?);
        }
        Ok(result)
    }

    fn parse_run_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkflowRunSummary> {
        let run_id_str: String = row.get(0)?;
        let wf_id_str: String = row.get(1)?;
        let rev: i64 = row.get(2)?;
        let root_str: String = row.get(3)?;
        let depth: i64 = row.get(4)?;
        let status_str: String = row.get(5)?;
        let trigger_id: String = row.get(6)?;
        let started: i64 = row.get(7)?;
        let ended: Option<i64> = row.get(8)?;

        Ok(WorkflowRunSummary {
            run_id: WorkflowRunId::new(parse_stored_uuid(&run_id_str)?),
            workflow_id: WorkflowId::new(parse_stored_uuid(&wf_id_str)?),
            revision: U64::new(rev as u64),
            causal_root_id: CausalRootId::new(parse_stored_uuid(&root_str)?),
            depth: U64::new(depth as u64),
            status: WorkflowRunStatus::from_wire(&status_str).unwrap_or(WorkflowRunStatus::Pending),
            trigger_event_id: trigger_id,
            started_at_ms: TimestampMs::new(started as u64),
            ended_at_ms: Nullable::from(ended.map(|v| TimestampMs::new(v as u64))),
        })
    }

    /// Reads node receipts for a run.
    pub fn list_node_receipts(&self, run_id: WorkflowRunId) -> Result<Vec<NodeReceiptSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT node_id, action_id, causal_parent, status, output_json, started_at_ms, ended_at_ms
             FROM node_receipts WHERE run_id = ?1",
        )?;
        let rows = stmt.query_map(params![run_id.to_string()], |row| {
            let node_id: String = row.get(0)?;
            let action_str: String = row.get(1)?;
            let causal_parent: Option<String> = row.get(2)?;
            let status_str: String = row.get(3)?;
            let output: Option<String> = row.get(4)?;
            let started: i64 = row.get(5)?;
            let ended: Option<i64> = row.get(6)?;

            Ok(NodeReceiptSummary {
                run_id,
                node_id,
                action_id: ActionId::new(parse_stored_uuid(&action_str)?),
                causal_parent: Nullable::from(causal_parent),
                status: NodeStatus::from_wire(&status_str).unwrap_or(NodeStatus::Pending),
                output: Nullable::from(output),
                started_at_ms: TimestampMs::new(started as u64),
                ended_at_ms: Nullable::from(ended.map(|v| TimestampMs::new(v as u64))),
            })
        })?;

        let mut result = Vec::new();
        for r in rows {
            result.push(r?);
        }
        Ok(result)
    }

    /// Reads the attention records the journal has committed but not yet delivered.
    ///
    /// The rows outlive a restart, so a host that stopped between a pause and its delivery still
    /// raises the item when it comes back.
    pub fn pending_attention(&self) -> Result<Vec<AttentionOutboxRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT outbox_id, event_type, payload_json, created_at_ms FROM outbox_events
             WHERE settled_at_ms IS NULL ORDER BY outbox_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let outbox_id: i64 = row.get(0)?;
            let event_type: String = row.get(1)?;
            let payload: String = row.get(2)?;
            let created_at_ms: i64 = row.get(3)?;
            Ok((outbox_id, event_type, payload, created_at_ms))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (outbox_id, event_type, payload, created_at_ms) = row?;
            let value: serde_json::Value = serde_json::from_str(&payload)?;
            let subject = value
                .get("subject")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    AutomationError::InvalidArgument(format!(
                        "attention record {outbox_id} names no subject"
                    ))
                })?;
            result.push(AttentionOutboxRecord {
                ends_condition: event_type == ATTENTION_WORKFLOW_RESUMED,
                outbox_id,
                subject: parse_attention_subject(subject).ok_or_else(|| {
                    AutomationError::InvalidArgument(format!(
                        "attention record {outbox_id} names an unreadable subject: {subject}"
                    ))
                })?,
                reason: value
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                created_at_ms: created_at_ms as u64,
            });
        }
        Ok(result)
    }

    /// Marks attention records as delivered.
    pub fn settle_attention(&self, outbox_ids: &[i64], now_ms: u64) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for id in outbox_ids {
            tx.execute(
                "UPDATE outbox_events SET settled_at_ms = ?1 WHERE outbox_id = ?2",
                params![now_ms as i64, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::create_workflow_definition;
    use kr_protocol::scalars::Uuid;

    fn test_wf_id(v: u8) -> WorkflowId {
        WorkflowId::new(Uuid::from_bytes([v; 16]))
    }

    fn test_grant_id(v: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([v; 16]))
    }

    #[test]
    fn store_persists_definitions_and_survives() {
        let store = WorkflowStore::in_memory().unwrap();
        let wf_id = test_wf_id(1);
        let grant_id = test_grant_id(1);

        let def = create_workflow_definition(wf_id, 1, "test-wf", grant_id, vec![], vec![]);
        store.save_definition(&def, 1000).unwrap();

        let loaded = store.get_definition(wf_id, 1).unwrap().unwrap();
        assert_eq!(loaded.definition.name, "test-wf");
        assert_eq!(loaded.definition.revision.get(), 1);
    }

    #[test]
    fn trigger_deduplication_prevents_duplicate_runs() {
        let store = WorkflowStore::in_memory().unwrap();
        let wf_id = test_wf_id(1);
        let grant_id = test_grant_id(1);
        let def = create_workflow_definition(wf_id, 1, "dedup-wf", grant_id, vec![], vec![]);
        store.save_definition(&def, 1000).unwrap();

        let causal = CausalContext::new_root();
        let run1 = WorkflowRunId::new(Uuid::from_bytes([10; 16]));

        // First trigger succeeds
        store
            .commit_trigger_and_run(run1, &def, "evt-123", &causal, 1000)
            .unwrap();

        // Second trigger with same (wf, rev, event_id) fails with DuplicateTrigger
        let run2 = WorkflowRunId::new(Uuid::from_bytes([11; 16]));
        let err = store
            .commit_trigger_and_run(run2, &def, "evt-123", &causal, 1000)
            .unwrap_err();
        assert!(matches!(err, AutomationError::DuplicateTrigger { .. }));
    }
}
