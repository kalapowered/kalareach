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

    /// Initialises database schema.
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
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
                depth INTEGER NOT NULL,
                parent_run_id TEXT,
                parent_node_id TEXT,
                status TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER,
                deadline_ms INTEGER NOT NULL
            );

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
            ",
        )?;
        Ok(())
    }

    /// Installs or updates a workflow definition.
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
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
            ON CONFLICT(workflow_id, revision) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                definition_json = excluded.definition_json,
                grant_reference = excluded.grant_reference,
                enabled = excluded.enabled",
            params![
                definition.workflow_id.to_string(),
                definition.revision.get() as i64,
                definition.name,
                definition.description.as_ref(),
                def_json,
                definition.grant_reference.to_string(),
                if definition.enabled { 1 } else { 0 },
                installed_at_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// Loads the latest revision of a workflow definition.
    pub fn get_latest_definition(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<WorkflowDefinition>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT definition_json FROM workflow_definitions
             WHERE workflow_id = ?1
             ORDER BY revision DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![workflow_id.to_string()])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let def: WorkflowDefinition = serde_json::from_str(&json)?;
            Ok(Some(def))
        } else {
            Ok(None)
        }
    }

    /// Loads an exact revision of a workflow definition.
    pub fn get_definition(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
    ) -> Result<Option<WorkflowDefinition>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT definition_json FROM workflow_definitions
             WHERE workflow_id = ?1 AND revision = ?2",
        )?;
        let mut rows = stmt.query(params![workflow_id.to_string(), revision as i64])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let def: WorkflowDefinition = serde_json::from_str(&json)?;
            Ok(Some(def))
        } else {
            Ok(None)
        }
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

        let workflow_id = WorkflowId::new(crate::parse_uuid(&wf_str).unwrap());
        let grant_reference = GrantId::new(crate::parse_uuid(&grant_str).unwrap());

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
    pub fn get_or_create_budget(
        &self,
        root_id: CausalRootId,
        now_ms: u64,
    ) -> Result<CausalBudget> {
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
            "SELECT depth, max_depth, total_runs, max_runs, total_actions, max_actions,
                    created_sessions, max_sessions, started_at_ms, max_lifetime_ms,
                    paused, exhausted, attention_emitted, rearmed_at_ms
             FROM causal_budgets WHERE causal_root_id = ?1",
        )?;
        let mut rows = stmt.query(params![root_id.to_string()])?;
        if let Some(row) = rows.next()? {
            Ok(Some(CausalBudget {
                causal_root_id: root_id,
                depth: row.get::<_, i64>(0)? as u64,
                max_depth: row.get::<_, i64>(1)? as u64,
                total_runs: row.get::<_, i64>(2)? as u64,
                max_runs: row.get::<_, i64>(3)? as u64,
                total_actions: row.get::<_, i64>(4)? as u64,
                max_actions: row.get::<_, i64>(5)? as u64,
                created_sessions: row.get::<_, i64>(6)? as u64,
                max_sessions: row.get::<_, i64>(7)? as u64,
                started_at_ms: row.get::<_, i64>(8)? as u64,
                max_lifetime_ms: row.get::<_, i64>(9)? as u64,
                paused: row.get::<_, i64>(10)? != 0,
                exhausted: row.get::<_, i64>(11)? != 0,
                attention_emitted: row.get::<_, i64>(12)? != 0,
                rearmed_at_ms: row.get::<_, Option<i64>>(13)?.map(|v| v as u64),
            }))
        } else {
            Ok(None)
        }
    }

    fn save_budget_tx(conn: &Connection, budget: &CausalBudget) -> Result<()> {
        conn.execute(
            "INSERT INTO causal_budgets (
                causal_root_id, depth, max_depth, total_runs, max_runs,
                total_actions, max_actions, created_sessions, max_sessions,
                started_at_ms, max_lifetime_ms, paused, exhausted,
                attention_emitted, rearmed_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            ON CONFLICT(causal_root_id) DO UPDATE SET
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
        let tx = conn.transaction()?;

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

        if let Some(_existing_run) = existing {
            return Err(AutomationError::DuplicateTrigger {
                workflow_id: definition.workflow_id,
                revision: definition.revision.get(),
                event_id: event_id.to_owned(),
            });
        }

        // 2. Load or create causal budget
        let mut budget = if let Some(b) = Self::load_budget_tx(&tx, causal_ctx.root_id)? {
            b
        } else {
            CausalBudget::new(causal_ctx.root_id, now_ms)
        };

        // 3. Reserve run
        let reservation_result = budget.reserve_run(causal_ctx.depth, now_ms);
        if let Err(err) = reservation_result {
            // Save exhausted state and outbox event if emitted
            Self::save_budget_tx(&tx, &budget)?;
            if budget.attention_emitted {
                let payload = serde_json::json!({
                    "causal_root_id": budget.causal_root_id.to_string(),
                    "reason": err.to_string(),
                });
                tx.execute(
                    "INSERT INTO outbox_events (event_type, payload_json, created_at_ms)
                     VALUES (?1, ?2, ?3)",
                    params!["attention.causal_limit", payload.to_string(), now_ms as i64],
                )?;
            }
            tx.commit()?;
            return Err(err);
        }

        // 4. Save updated budget
        Self::save_budget_tx(&tx, &budget)?;

        // 5. Insert run record
        let parent_run_id = causal_ctx.parent.as_ref().map(|p| p.parent_run_id.to_string());
        let parent_node_id = causal_ctx.parent.as_ref().map(|p| p.parent_node_id.clone());
        let deadline_ms = now_ms.saturating_add(definition.deadlines.run_deadline_ms.get());

        tx.execute(
            "INSERT INTO workflow_runs (
                run_id, workflow_id, revision, trigger_event_id, causal_root_id,
                depth, parent_run_id, parent_node_id, status, started_at_ms, deadline_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                run_id.to_string(),
                wf_id_str,
                rev,
                event_id,
                causal_ctx.root_id.to_string(),
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
            params![status.as_str(), ended_at_ms.map(|v| v as i64), run_id.to_string()],
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
            run_id: WorkflowRunId::new(crate::parse_uuid(&run_id_str).unwrap()),
            workflow_id: WorkflowId::new(crate::parse_uuid(&wf_id_str).unwrap()),
            revision: U64::new(rev as u64),
            causal_root_id: CausalRootId::new(crate::parse_uuid(&root_str).unwrap()),
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
                action_id: ActionId::new(crate::parse_uuid(&action_str).unwrap()),
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

    /// Takes all pending outbox events.
    pub fn take_outbox_events(&self) -> Result<Vec<(i64, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT outbox_id, event_type, payload_json FROM outbox_events
             WHERE settled_at_ms IS NULL ORDER BY outbox_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        let mut result = Vec::new();
        for r in rows {
            result.push(r?);
        }
        Ok(result)
    }

    /// Settles outbox events.
    pub fn settle_outbox_events(&self, outbox_ids: &[i64], now_ms: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for id in outbox_ids {
            conn.execute(
                "UPDATE outbox_events SET settled_at_ms = ?1 WHERE outbox_id = ?2",
                params![now_ms as i64, id],
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;
    use crate::definition::create_workflow_definition;

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
        assert_eq!(loaded.name, "test-wf");
        assert_eq!(loaded.revision.get(), 1);
    }

    #[test]
    fn trigger_deduplication_prevents_duplicate_runs() {
        let store = WorkflowStore::in_memory().unwrap();
        let wf_id = test_wf_id(1);
        let grant_id = test_grant_id(1);
        let def = create_workflow_definition(wf_id, 1, "dedup-wf", grant_id, vec![], vec![]);
        store.save_definition(&def, 1000).unwrap();

        let causal = CausalContext::new_root(wf_id);
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
