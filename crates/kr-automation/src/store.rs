//! The workflow journal: the environment store for definitions, runs, node receipts, causal
//! budgets, the action record and the attention outbox.
//!
//! Section 24 makes this journal the authoritative owner of workflow definitions, runs, node
//! receipts and causal budgets:
//! - It is this crate's own SQLite store in the environment's state directory, opened and owned by
//!   the crate. The state directory rather than the runtime one, because a causal budget has to
//!   survive a reboot and a runtime directory does not.
//! - The trigger, the run, its budget reservation and the action that asked for them commit
//!   together in one local transaction.
//! - Triggers are deduplicated by `(workflow_id, definition_revision, event_id)`.
//! - Budgets survive restart and reboot.
//!
//! # One transaction per action
//!
//! Every mutation a caller submits is an action, and everything the journal does for it happens
//! in one transaction ([`WorkflowStore::act`]):
//!
//! 1. The record an earlier submission of the same action left is looked for. When there is one,
//!    it is the answer, and nothing else happens.
//! 2. The admission the caller was accepted under is asked again, immediately before the first
//!    write. [`Journal`] asks it itself, so no write can happen without it.
//! 3. The effect is written.
//! 4. What the action came to is written beside it.
//!
//! There is therefore no moment at which an effect exists without its record. A repeat is always
//! answered from the record rather than performed again, and there is no half-finished claim for a
//! later attempt to take over or to report as still running.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::automation::{
    NodeReceiptSummary, NodeStatus, WorkflowDefinition, WorkflowDefinitionSummary,
    WorkflowRunStatus, WorkflowRunSummary,
};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActionId, CausalRootId, GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::budget::CausalBudget;
use crate::causal::CausalContext;
use crate::error::{AutomationError, Result};

/// Default file name for the workflow journal database.
pub const WORKFLOW_DB_NAME: &str = "workflows.db";

/// The schema version this build reads and writes.
///
/// It covers the rows as well as the tables. Versions 1 and 2 were written only by builds that
/// never reached an installed product, so no installed journal holds either, and a journal at one
/// of them is refused by name rather than read as if its rows said what this build expects.
pub const WORKFLOW_SCHEMA_VERSION: u32 = 3;

/// The columns [`Journal::parse_run_record`] expects, in order.
const RUN_RECORD_COLUMNS: &str = "run_id, workflow_id, revision, causal_root_id, generation, depth,
            parent_run_id, parent_node_id";

/// The columns [`Journal::parse_run_summary`] expects, in order.
const RUN_SUMMARY_COLUMNS: &str = "run_id, workflow_id, revision, causal_root_id, depth, status,
            trigger_event_id, started_at_ms, ended_at_ms";

/// Reads an identifier the journal wrote, reporting a corrupt row rather than panicking on it.
fn parse_stored_uuid(value: &str) -> rusqlite::Result<kr_protocol::scalars::Uuid> {
    crate::parse_uuid(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// A count or an instant as the journal stores it.
fn stored(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
    /// A workflow revision paused because one of its own limits was breached.
    ///
    /// The revision is part of the identity: two revisions of one workflow can be paused for
    /// different reasons, and enabling one must not clear the other's item.
    Workflow {
        /// The workflow.
        workflow_id: WorkflowId,
        /// The revision that was paused.
        revision: u64,
    },
}

impl std::fmt::Display for AttentionSubject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CausalRoot(root) => write!(formatter, "automation.causal_budget.{root}"),
            Self::Workflow {
                workflow_id,
                revision,
            } => write!(formatter, "automation.workflow.{workflow_id}.{revision}"),
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

/// One action a caller submitted, as the journal keys it.
///
/// The actor and the identifier together name the action. The method and the digest of everything
/// it carried are what tell a repeat of it from a different action under a reused identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionKey {
    /// The verified actor that submitted it.
    pub actor_id: String,
    /// The identifier the caller gave it.
    pub action_id: String,
    /// The method it named.
    pub method: String,
    /// The digest of everything it carried.
    pub digest: Vec<u8>,
}

/// What one action came to, as the journal recorded it in the transaction that performed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionRecord {
    /// It was performed, and this is the result it produced, encoded as JSON.
    Done {
        /// The result.
        result: String,
    },
    /// It started this run.
    ///
    /// What the run has come to since is the run's own record, read when the question is asked,
    /// so a repeat is told where the run stands now rather than where it stood when it began.
    Started {
        /// The run it started.
        run_id: WorkflowRunId,
    },
    /// It was refused, under this code.
    Refused {
        /// The stable error code the refusal carried.
        code: String,
        /// What the refusal said.
        detail: String,
    },
}

impl ActionRecord {
    /// The record of an action that produced `result`.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::JsonError`] when the result cannot be encoded.
    pub fn done<T: serde::Serialize>(result: &T) -> Result<Self> {
        Ok(Self::Done {
            result: serde_json::to_string(result)?,
        })
    }
}

/// What a submission of one action came to.
#[derive(Debug)]
pub enum Acted<T> {
    /// This submission performed it, and this is what the effect handed back.
    Performed(T),
    /// An earlier submission of the same action did, and this is what the journal recorded.
    Answered(ActionRecord),
}

/// One submission of an action: its key, and the admission it was accepted under.
///
/// The admission is asked inside the journal's transaction, immediately before the first thing
/// the action writes. A caller whose admission cannot lapse, a test among them, passes one that
/// always answers yes.
#[derive(Clone, Copy)]
pub struct Submitted<'a> {
    /// The action.
    pub key: &'a ActionKey,
    /// Whether the admission the action was accepted under still stands.
    pub admission: &'a (dyn Fn() -> Result<()> + Send + Sync),
}

impl std::fmt::Debug for Submitted<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Submitted")
            .field("key", self.key)
            .finish_non_exhaustive()
    }
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
    let (workflow, revision) = value
        .strip_prefix("automation.workflow.")?
        .rsplit_once('.')?;
    Some(AttentionSubject::Workflow {
        workflow_id: WorkflowId::new(crate::parse_uuid(workflow).ok()?),
        revision: revision.parse().ok()?,
    })
}

/// The journal's operations, over one connection its caller has locked.
///
/// Every statement this store runs is written once, here. [`WorkflowStore`] decides where the
/// transaction boundaries are; an action's [`Journal`] also carries the admission the action was
/// accepted under, and every write asks it first.
pub struct Journal<'c> {
    conn: &'c Connection,
    admission: Option<&'c (dyn Fn() -> Result<()> + Send + Sync)>,
    admitted: Cell<bool>,
}

impl std::fmt::Debug for Journal<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Journal")
            .field("admitted", &self.admitted.get())
            .finish_non_exhaustive()
    }
}

impl<'c> Journal<'c> {
    const fn unguarded(conn: &'c Connection) -> Self {
        Self {
            conn,
            admission: None,
            admitted: Cell::new(false),
        }
    }

    /// Asks the admission this action was accepted under, once, before its first write.
    ///
    /// Every write below calls this first, which is what makes it impossible for an action to
    /// write anything under an admission that lapsed while it waited for this journal.
    ///
    /// # Errors
    ///
    /// Returns whatever the admission refused with.
    pub fn admit(&self) -> Result<()> {
        if self.admitted.get() {
            return Ok(());
        }
        if let Some(admission) = self.admission {
            admission()?;
        }
        self.admitted.set(true);
        Ok(())
    }

    /// Loads the latest revision of a workflow definition with its operational state.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn latest_definition(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<InstalledDefinition>> {
        let found = self
            .conn
            .query_row(
                "SELECT definition_json, enabled, paused FROM workflow_definitions
                 WHERE workflow_id = ?1
                 ORDER BY revision DESC LIMIT 1",
                params![workflow_id.to_string()],
                Self::parse_installed,
            )
            .optional()?;
        found.transpose()
    }

    /// Loads an exact revision of a workflow definition with its operational state.
    ///
    /// The document is what was installed and never changes. Whether it is enabled, and whether
    /// it is paused, are the journal's and are read from their own columns, so an enable or a
    /// pause after installation is what decides whether the revision runs.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn definition(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
    ) -> Result<Option<InstalledDefinition>> {
        let found = self
            .conn
            .query_row(
                "SELECT definition_json, enabled, paused FROM workflow_definitions
                 WHERE workflow_id = ?1 AND revision = ?2",
                params![workflow_id.to_string(), stored(revision)],
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

    /// Installs a workflow definition revision.
    ///
    /// An installed revision is immutable: a second insert of the same number is refused. It
    /// starts disabled and unpaused, because enabling a revision is its own authorised method.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::AlreadyInstalled`] for a revision that exists, and whatever the
    /// admission refused with.
    pub fn save_definition(
        &self,
        definition: &WorkflowDefinition,
        installed_at_ms: u64,
    ) -> Result<()> {
        self.admit()?;
        let def_json = serde_json::to_string(definition)?;
        self.conn
            .execute(
                "INSERT INTO workflow_definitions (
                    workflow_id, revision, name, description, definition_json,
                    grant_reference, enabled, paused, installed_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7)",
                params![
                    definition.workflow_id.to_string(),
                    stored(definition.revision.get()),
                    definition.name,
                    definition.description.as_ref(),
                    def_json,
                    definition.grant_reference.to_string(),
                    stored(installed_at_ms),
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

    /// Sets the enabled state of an installed definition revision.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::WorkflowNotFound`] when the revision is not installed.
    pub fn set_enabled(&self, workflow_id: WorkflowId, revision: u64, enabled: bool) -> Result<()> {
        self.admit()?;
        let updated = self.conn.execute(
            "UPDATE workflow_definitions SET enabled = ?1
             WHERE workflow_id = ?2 AND revision = ?3",
            params![
                i64::from(enabled),
                workflow_id.to_string(),
                stored(revision)
            ],
        )?;
        if updated == 0 {
            return Err(AutomationError::WorkflowNotFound(workflow_id));
        }
        Ok(())
    }

    /// Sets the paused state of an installed definition revision.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::WorkflowNotFound`] when the revision is not installed.
    pub fn set_paused(&self, workflow_id: WorkflowId, revision: u64, paused: bool) -> Result<()> {
        self.admit()?;
        let updated = self.conn.execute(
            "UPDATE workflow_definitions SET paused = ?1
             WHERE workflow_id = ?2 AND revision = ?3",
            params![i64::from(paused), workflow_id.to_string(), stored(revision)],
        )?;
        if updated == 0 {
            return Err(AutomationError::WorkflowNotFound(workflow_id));
        }
        Ok(())
    }

    /// Clears a pause and records the recovery the attention item it raised is waiting for.
    ///
    /// The item an exceedance raised stays in the inbox, climbing its ladder, until something
    /// says the condition ended. Clearing the pause is that something, and the record is written
    /// with it. A revision that was not paused records nothing.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn resume_workflow(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.admit()?;
        let resumed = self.conn.execute(
            "UPDATE workflow_definitions SET paused = 0
             WHERE workflow_id = ?1 AND revision = ?2 AND paused = 1",
            params![workflow_id.to_string(), stored(revision)],
        )?;
        if resumed > 0 {
            self.record_attention(
                ATTENTION_WORKFLOW_RESUMED,
                &AttentionSubject::Workflow {
                    workflow_id,
                    revision,
                },
                "the workflow revision was enabled again",
                now_ms,
            )?;
        }
        Ok(())
    }

    /// Pauses a workflow revision and records the attention item the pause owes, together.
    ///
    /// Section 17 ¶8 asks for both when one of a workflow's own limits is breached. A revision
    /// that is already paused records nothing further, so a workflow being hammered produces one
    /// item rather than one per refusal.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn pause_workflow_on_breach(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        self.admit()?;
        let paused = self.conn.execute(
            "UPDATE workflow_definitions SET paused = 1
             WHERE workflow_id = ?1 AND revision = ?2 AND paused = 0",
            params![workflow_id.to_string(), stored(revision)],
        )?;
        if paused > 0 {
            self.record_attention(
                ATTENTION_WORKFLOW_PAUSED,
                &AttentionSubject::Workflow {
                    workflow_id,
                    revision,
                },
                reason,
                now_ms,
            )?;
        }
        Ok(())
    }

    /// Reports whether a workflow revision is currently paused.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn is_paused(&self, workflow_id: WorkflowId, revision: u64) -> Result<bool> {
        let paused: Option<i64> = self
            .conn
            .query_row(
                "SELECT paused FROM workflow_definitions WHERE workflow_id = ?1 AND revision = ?2",
                params![workflow_id.to_string(), stored(revision)],
                |row| row.get(0),
            )
            .optional()?;
        Ok(paused.unwrap_or(0) != 0)
    }

    /// Reports whether this trigger has already been recorded for this revision.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn trigger_is_recorded(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        event_id: &str,
    ) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM trigger_dedup
                 WHERE workflow_id = ?1 AND revision = ?2 AND event_id = ?3",
                params![workflow_id.to_string(), stored(revision), event_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Retrieves the durable run record the host verifies causal ancestry against.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn run_record(&self, run_id: WorkflowRunId) -> Result<Option<StoredRunRecord>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {RUN_RECORD_COLUMNS} FROM workflow_runs WHERE run_id = ?1"),
                params![run_id.to_string()],
                Self::parse_run_record,
            )
            .optional()?)
    }

    /// Reads one run's summary, as it stands now.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn run_summary(&self, run_id: WorkflowRunId) -> Result<Option<WorkflowRunSummary>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {RUN_SUMMARY_COLUMNS} FROM workflow_runs WHERE run_id = ?1"),
                params![run_id.to_string()],
                Self::parse_run_summary,
            )
            .optional()?)
    }

    /// Checks whether a node of a run has a receipt, which is what makes it a usable parent.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn node_receipt_exists(&self, run_id: WorkflowRunId, node_id: &str) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM node_receipts WHERE run_id = ?1 AND node_id = ?2",
                params![run_id.to_string(), node_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Lists durable run records sharing a causal root.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn runs_by_root(&self, root_id: CausalRootId) -> Result<Vec<StoredRunRecord>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {RUN_RECORD_COLUMNS} FROM workflow_runs WHERE causal_root_id = ?1
             ORDER BY depth ASC"
        ))?;
        let rows = stmt.query_map(params![root_id.to_string()], Self::parse_run_record)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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

    /// Commits a trigger, its run, the run's node receipts and the chain's reservation together.
    ///
    /// Deduplicates by `(workflow_id, definition_revision, event_id)`. A refusal from the budget
    /// writes the exhausted budget and the one attention item it owes, and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::DuplicateTrigger`] for a trigger already recorded, the budget's
    /// `CAUSAL_LIMIT` refusal, and whatever the admission refused with.
    pub fn commit_trigger_and_run(
        &self,
        run_id: WorkflowRunId,
        definition: &WorkflowDefinition,
        event_id: &str,
        causal_ctx: &CausalContext,
        now_ms: u64,
    ) -> Result<CausalBudget> {
        let wf_id_str = definition.workflow_id.to_string();
        let rev = stored(definition.revision.get());

        if self.trigger_is_recorded(definition.workflow_id, definition.revision.get(), event_id)? {
            return Err(AutomationError::DuplicateTrigger {
                workflow_id: definition.workflow_id,
                revision: definition.revision.get(),
                event_id: event_id.to_owned(),
            });
        }

        self.admit()?;
        let mut budget = self
            .load_budget(causal_ctx.root_id)?
            .unwrap_or_else(|| CausalBudget::new(causal_ctx.root_id, now_ms));
        budget.check_generation(causal_ctx.generation)?;
        let was_emitted = budget.attention_emitted;
        if let Err(err) = budget.reserve_run(causal_ctx.depth, now_ms) {
            // The pause, the refusal and the attention record land together.
            self.save_budget(&budget)?;
            if budget.attention_emitted && !was_emitted {
                self.record_exhaustion(causal_ctx.root_id, &err.to_string(), now_ms)?;
            }
            return Err(err);
        }
        self.save_budget(&budget)?;

        let parent_run_id = causal_ctx
            .parent
            .as_ref()
            .map(|p| p.parent_run_id.to_string());
        let parent_node_id = causal_ctx.parent.as_ref().map(|p| p.parent_node_id.clone());
        let deadline_ms = now_ms.saturating_add(definition.deadlines.run_deadline_ms.get());

        self.conn.execute(
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
                stored(causal_ctx.generation),
                stored(causal_ctx.depth),
                parent_run_id,
                parent_node_id,
                WorkflowRunStatus::Pending.as_str(),
                stored(now_ms),
                stored(deadline_ms),
            ],
        )?;

        self.conn.execute(
            "INSERT INTO trigger_dedup (workflow_id, revision, event_id, run_id, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![wf_id_str, rev, event_id, run_id.to_string(), stored(now_ms)],
        )?;

        for node in &definition.nodes {
            let action_id = ActionId::new(crate::new_uuid());
            self.conn.execute(
                "INSERT INTO node_receipts (
                    run_id, node_id, action_id, causal_parent, status, started_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run_id.to_string(),
                    node.node_id,
                    action_id.to_string(),
                    parent_node_id,
                    NodeStatus::Pending.as_str(),
                    stored(now_ms),
                ],
            )?;
        }

        Ok(budget)
    }

    fn load_budget(&self, root_id: CausalRootId) -> Result<Option<CausalBudget>> {
        let found = self
            .conn
            .query_row(
                "SELECT generation, depth, max_depth, total_runs, max_runs, total_actions,
                        max_actions, created_sessions, max_sessions, started_at_ms,
                        max_lifetime_ms, paused, exhausted, attention_emitted, rearmed_at_ms
                 FROM causal_budgets WHERE causal_root_id = ?1",
                params![root_id.to_string()],
                |row| {
                    Ok(CausalBudget {
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
                    })
                },
            )
            .optional()?;
        Ok(found)
    }

    fn save_budget(&self, budget: &CausalBudget) -> Result<()> {
        self.conn.execute(
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
                stored(budget.generation),
                stored(budget.depth),
                stored(budget.max_depth),
                stored(budget.total_runs),
                stored(budget.max_runs),
                stored(budget.total_actions),
                stored(budget.max_actions),
                stored(budget.created_sessions),
                stored(budget.max_sessions),
                stored(budget.started_at_ms),
                stored(budget.max_lifetime_ms),
                i64::from(budget.paused),
                i64::from(budget.exhausted),
                i64::from(budget.attention_emitted),
                budget.rearmed_at_ms.map(stored),
            ],
        )?;
        Ok(())
    }

    /// Runs one reservation against the durable budget.
    ///
    /// The load, the ceiling check, the reservation and any exhaustion are written together, so
    /// two concurrent dispatches cannot both read the last free action and both take it.
    fn reserve_in_budget(
        &self,
        root_id: CausalRootId,
        generation: u64,
        now_ms: u64,
        reserve: impl FnOnce(&mut CausalBudget) -> Result<()>,
    ) -> Result<()> {
        let mut budget = self
            .load_budget(root_id)?
            .unwrap_or_else(|| CausalBudget::new(root_id, now_ms));
        budget.check_generation(generation)?;
        let was_emitted = budget.attention_emitted;
        let outcome = reserve(&mut budget);
        self.save_budget(&budget)?;
        if let Err(err) = &outcome
            && budget.attention_emitted
            && !was_emitted
        {
            self.record_exhaustion(root_id, &err.to_string(), now_ms)?;
        }
        outcome
    }

    /// Records the one attention item an exhausted chain owes.
    ///
    /// The caller has already flipped the budget's `attention_emitted` flag inside the same
    /// transaction, so a chain that stays exhausted never queues a second item.
    fn record_exhaustion(&self, root_id: CausalRootId, reason: &str, now_ms: u64) -> Result<()> {
        self.record_attention(
            ATTENTION_CAUSAL_LIMIT,
            &AttentionSubject::CausalRoot(root_id),
            reason,
            now_ms,
        )
    }

    /// Writes one attention record into the journal's outbox.
    fn record_attention(
        &self,
        event_type: &str,
        subject: &AttentionSubject,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        let payload = serde_json::json!({ "subject": subject.to_string(), "reason": reason });
        self.conn.execute(
            "INSERT INTO outbox_events (event_type, payload_json, created_at_ms)
             VALUES (?1, ?2, ?3)",
            params![event_type, payload.to_string(), stored(now_ms)],
        )?;
        Ok(())
    }

    /// Reads what the journal recorded about one action, when it recorded anything.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::ActionIdentifierReused`] when the identifier was spent on a
    /// different method or a different payload: that is another action under a reused identifier,
    /// and it is refused rather than answered with somebody else's result.
    pub fn action_record(&self, key: &ActionKey) -> Result<Option<ActionRecord>> {
        type Row = (
            String,
            Vec<u8>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let held: Option<Row> = self
            .conn
            .query_row(
                "SELECT method, payload_digest, result_json, run_id, error_code, error_detail
                 FROM action_records WHERE actor_id = ?1 AND action_id = ?2",
                params![key.actor_id, key.action_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((method, digest, result, run_id, code, detail)) = held else {
            return Ok(None);
        };
        if method != key.method || digest != key.digest {
            return Err(AutomationError::ActionIdentifierReused {
                action_id: key.action_id.clone(),
            });
        }
        let record = match (result, run_id, code) {
            (Some(result), None, None) => ActionRecord::Done { result },
            (None, Some(run_id), None) => ActionRecord::Started {
                run_id: WorkflowRunId::new(parse_stored_uuid(&run_id)?),
            },
            (None, None, Some(code)) => ActionRecord::Refused {
                code,
                detail: detail.unwrap_or_default(),
            },
            _ => {
                return Err(AutomationError::InvalidArgument(format!(
                    "the record of action {} says more than one thing about how it ended",
                    key.action_id
                )));
            }
        };
        Ok(Some(record))
    }

    /// Writes what one action came to.
    fn record_action(&self, key: &ActionKey, record: &ActionRecord, now_ms: u64) -> Result<()> {
        let (result, run_id, code, detail) = match record {
            ActionRecord::Done { result } => (Some(result.as_str()), None, None, None),
            ActionRecord::Started { run_id } => (None, Some(run_id.to_string()), None, None),
            ActionRecord::Refused { code, detail } => {
                (None, None, Some(code.as_str()), Some(detail.as_str()))
            }
        };
        self.conn.execute(
            "INSERT INTO action_records (
                actor_id, action_id, method, payload_digest, result_json, run_id, error_code,
                error_detail, recorded_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                key.actor_id,
                key.action_id,
                key.method,
                key.digest,
                result,
                run_id,
                code,
                detail,
                stored(now_ms),
            ],
        )?;
        Ok(())
    }
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
    /// Opens the workflow journal in the environment's state directory.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the journal cannot be opened, and a refusal naming the
    /// version when it was written to a schema this build does not read.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let path = state_dir.as_ref().join(WORKFLOW_DB_NAME);
        let conn = Connection::open(&path)?;
        let store = Self {
            conn: Mutex::new(conn),
            path,
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Opens an in-memory workflow journal for tests.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the schema cannot be created.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
            path: PathBuf::from(":memory:"),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `body` over the journal outside any transaction.
    fn read<T>(&self, body: impl FnOnce(&Journal<'_>) -> Result<T>) -> Result<T> {
        let conn = self.lock();
        body(&Journal::unguarded(&conn))
    }

    /// Runs `body` inside one immediate transaction, committing only when it succeeds.
    ///
    /// `Immediate`, so the write lock is taken before the first read: every read-then-write here
    /// decides on what it read, and a second writer must not change it in between.
    fn write<T>(&self, body: impl FnOnce(&Journal<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let value = body(&Journal::unguarded(&tx))?;
        tx.commit()?;
        Ok(value)
    }

    /// Creates this journal's schema, or refuses a journal written to a different one.
    ///
    /// A journal carries the schema version it was written with. Reading one written to another
    /// version with statements meant for this one would fail later, somewhere unhelpful, so the
    /// refusal happens here and says what it found.
    fn init_schema(&self) -> Result<()> {
        let mut conn = self.lock();
        // The version is read, the decision is made and the schema is written under one write
        // lock, so two processes opening a new journal at the same time cannot have one of them
        // see the other's half-written state and refuse the journal it is about to share.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let empty: bool = tx.query_row(
            "SELECT COUNT(*) = 0 FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )?;

        if !empty && found != WORKFLOW_SCHEMA_VERSION {
            return Err(AutomationError::InvalidArgument(format!(
                "the workflow journal at {} was written to schema version {found}, and this build \
                 reads version {WORKFLOW_SCHEMA_VERSION}",
                self.path.display()
            )));
        }

        tx.execute_batch(
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

            -- One row per action, written in the transaction that performed it. Exactly one of
            -- the three outcome columns is set: there is no row for an action still under way.
            CREATE TABLE IF NOT EXISTS action_records (
                actor_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                method TEXT NOT NULL,
                payload_digest BLOB NOT NULL,
                result_json TEXT,
                run_id TEXT,
                error_code TEXT,
                error_detail TEXT,
                recorded_at_ms INTEGER NOT NULL,
                PRIMARY KEY (actor_id, action_id),
                CHECK ((result_json IS NOT NULL) + (run_id IS NOT NULL)
                       + (error_code IS NOT NULL) = 1)
            );
            ",
        )?;
        tx.pragma_update(None, "user_version", WORKFLOW_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    /// Performs one action, or answers it from what an earlier submission of it recorded.
    ///
    /// Everything happens in one immediate transaction. The record is looked for first; when an
    /// earlier submission left one, it is returned and nothing is written. Otherwise `effect` runs
    /// with a [`Journal`] that asks the submission's admission before its first write, and what it
    /// returns is recorded beside everything it wrote:
    ///
    /// - `Ok((record, value))` commits the effect with `record`, and `value` comes back to the
    ///   caller as [`Acted::Performed`].
    /// - A refusal the host decided about the action itself commits whatever `effect` wrote in
    ///   deciding it (the pause a breached limit owes, the exhausted budget and its one attention
    ///   item) together with the refusal, so a repeat is refused the same way.
    /// - Anything else says nothing about the action: a journal that could not be written, a
    ///   grant store that could not be read, an admission that lapsed before the first write. The
    ///   transaction is abandoned with everything in it, and no record is left, so a later
    ///   submission is decided afresh.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::ActionIdentifierReused`] for an identifier spent on another
    /// action, and whatever `effect` returned.
    pub fn act<T>(
        &self,
        submitted: &Submitted<'_>,
        now_ms: u64,
        effect: impl FnOnce(&Journal<'_>) -> Result<(ActionRecord, T)>,
    ) -> Result<Acted<T>> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let journal = Journal {
            conn: &tx,
            admission: Some(submitted.admission),
            admitted: Cell::new(false),
        };
        if let Some(record) = journal.action_record(submitted.key)? {
            return Ok(Acted::Answered(record));
        }
        match effect(&journal) {
            Ok((record, value)) => {
                journal.record_action(submitted.key, &record, now_ms)?;
                tx.commit()?;
                Ok(Acted::Performed(value))
            }
            Err(error) if error.is_decided() => {
                let refusal = ProtocolError::from(&error);
                journal.record_action(
                    submitted.key,
                    &ActionRecord::Refused {
                        code: refusal.code.as_str().to_owned(),
                        detail: refusal.message,
                    },
                    now_ms,
                )?;
                tx.commit()?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Reads what the journal recorded about one action, without performing anything.
    ///
    /// This is what answers a repeat before its freshness is considered: a retry after a lost
    /// reply carries the window it was first admitted under, and refusing it for that would deny a
    /// caller its own completed result.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::ActionIdentifierReused`] for an identifier spent on another
    /// action, and a storage error when the row cannot be read.
    pub fn recorded_action(&self, key: &ActionKey) -> Result<Option<ActionRecord>> {
        self.read(|journal| journal.action_record(key))
    }

    /// Installs a workflow definition revision.
    ///
    /// # Errors
    ///
    /// As [`Journal::save_definition`].
    pub fn save_definition(
        &self,
        definition: &WorkflowDefinition,
        installed_at_ms: u64,
    ) -> Result<()> {
        self.read(|journal| journal.save_definition(definition, installed_at_ms))
    }

    /// Loads the latest revision of a workflow definition with its operational state.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn get_latest_definition(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<Option<InstalledDefinition>> {
        self.read(|journal| journal.latest_definition(workflow_id))
    }

    /// Loads an exact revision of a workflow definition with its operational state.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn get_definition(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
    ) -> Result<Option<InstalledDefinition>> {
        self.read(|journal| journal.definition(workflow_id, revision))
    }

    /// Sets the enabled state of an installed definition revision.
    ///
    /// # Errors
    ///
    /// As [`Journal::set_enabled`].
    pub fn set_enabled(&self, workflow_id: WorkflowId, revision: u64, enabled: bool) -> Result<()> {
        self.read(|journal| journal.set_enabled(workflow_id, revision, enabled))
    }

    /// Sets the paused state of an installed definition revision.
    ///
    /// # Errors
    ///
    /// As [`Journal::set_paused`].
    pub fn set_paused(&self, workflow_id: WorkflowId, revision: u64, paused: bool) -> Result<()> {
        self.read(|journal| journal.set_paused(workflow_id, revision, paused))
    }

    /// Reads all definitions matching criteria.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn list_definitions(
        &self,
        workflow_id: Option<WorkflowId>,
    ) -> Result<Vec<WorkflowDefinitionSummary>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT workflow_id, revision, name, description, grant_reference, enabled,
                    installed_at_ms
             FROM workflow_definitions
             WHERE ?1 IS NULL OR workflow_id = ?1
             ORDER BY workflow_id, revision ASC",
        )?;
        let rows = stmt.query_map(
            params![workflow_id.map(|id| id.to_string())],
            Self::parse_def_summary,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn parse_def_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkflowDefinitionSummary> {
        let wf_str: String = row.get(0)?;
        let rev: i64 = row.get(1)?;
        let name: String = row.get(2)?;
        let desc: Option<String> = row.get(3)?;
        let grant_str: String = row.get(4)?;
        let enabled: i64 = row.get(5)?;
        let installed: i64 = row.get(6)?;

        Ok(WorkflowDefinitionSummary {
            workflow_id: WorkflowId::new(parse_stored_uuid(&wf_str)?),
            revision: U64::new(rev as u64),
            name,
            description: Nullable::from(desc),
            grant_reference: GrantId::new(parse_stored_uuid(&grant_str)?),
            enabled: enabled != 0,
            installed_at_ms: TimestampMs::new(installed as u64),
        })
    }

    /// Loads or creates a causal budget for a causal root.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read or written.
    pub fn get_or_create_budget(&self, root_id: CausalRootId, now_ms: u64) -> Result<CausalBudget> {
        self.write(|journal| {
            if let Some(budget) = journal.load_budget(root_id)? {
                return Ok(budget);
            }
            let budget = CausalBudget::new(root_id, now_ms);
            journal.save_budget(&budget)?;
            Ok(budget)
        })
    }

    /// Loads an existing causal budget if present.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn get_budget(&self, root_id: CausalRootId) -> Result<Option<CausalBudget>> {
        self.read(|journal| journal.load_budget(root_id))
    }

    /// Saves a causal budget.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn save_budget(&self, budget: &CausalBudget) -> Result<()> {
        self.read(|journal| journal.save_budget(budget))
    }

    /// Reserves one action of the causal budget, in one transaction with its refusal.
    ///
    /// # Errors
    ///
    /// Returns the budget's `CAUSAL_LIMIT` refusal, or a stale generation.
    pub fn reserve_budget_action(
        &self,
        root_id: CausalRootId,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.write(|journal| {
            Ok(
                journal.reserve_in_budget(root_id, generation, now_ms, |budget| {
                    budget.reserve_action(now_ms)
                }),
            )
        })?
    }

    /// Reserves one created session of the causal budget, in one transaction with its refusal.
    ///
    /// # Errors
    ///
    /// Returns the budget's `CAUSAL_LIMIT` refusal, or a stale generation.
    pub fn reserve_budget_session(
        &self,
        root_id: CausalRootId,
        generation: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.write(|journal| {
            Ok(
                journal.reserve_in_budget(root_id, generation, now_ms, |budget| {
                    budget.reserve_session(now_ms)
                }),
            )
        })?
    }

    /// Clears a pause and records the recovery its attention item is waiting for, together.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn resume_workflow(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.write(|journal| journal.resume_workflow(workflow_id, revision, now_ms))
    }

    /// Pauses a workflow revision and records the attention item the pause owes, together.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn pause_workflow_on_breach(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        self.write(|journal| {
            journal.pause_workflow_on_breach(workflow_id, revision, reason, now_ms)
        })
    }

    /// Rearms the budget under an authorised administrative request.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::InvalidArgument`] for a root this journal holds no budget for.
    pub fn rearm_budget(&self, root_id: CausalRootId, now_ms: u64) -> Result<CausalBudget> {
        self.write(|journal| {
            let mut budget = journal.load_budget(root_id)?.ok_or_else(|| {
                AutomationError::InvalidArgument("causal root not found".to_owned())
            })?;
            budget.rearm(now_ms);
            journal.save_budget(&budget)?;
            Ok(budget)
        })
    }

    /// Retrieves the durable run record the host verifies causal ancestry against.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn get_run_record(&self, run_id: WorkflowRunId) -> Result<Option<StoredRunRecord>> {
        self.read(|journal| journal.run_record(run_id))
    }

    /// Claims a node for dispatch, if the journal still has it waiting for one.
    ///
    /// The read of the status and the move to running are one statement, so a cancellation that
    /// lands between them cannot be lost: either it got there first and this returns false, or
    /// it finds the node already running and leaves it alone.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn claim_node_for_dispatch(&self, run_id: WorkflowRunId, node_id: &str) -> Result<bool> {
        let conn = self.lock();
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

    /// Pauses one node and its run because the host refused to dispatch it, in one transaction.
    ///
    /// Cancellation is terminal and a refusal never undoes it. A node that has already settled,
    /// a cancelled node among them, keeps the status it settled with, and a run that was
    /// cancelled stays cancelled: the host stopped asking, which is a different thing from the
    /// host refusing to go on.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn pause_on_refusal(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<()> {
        self.write(|journal| {
            journal.conn.execute(
                "UPDATE node_receipts SET status = ?1, error_json = ?2, ended_at_ms = ?3
                 WHERE run_id = ?4 AND node_id = ?5 AND status IN (?6, ?7)",
                params![
                    NodeStatus::Paused.as_str(),
                    reason,
                    stored(now_ms),
                    run_id.to_string(),
                    node_id,
                    NodeStatus::Pending.as_str(),
                    NodeStatus::Running.as_str(),
                ],
            )?;
            journal.conn.execute(
                "UPDATE workflow_runs SET status = ?1, ended_at_ms = ?2
                 WHERE run_id = ?3 AND status <> ?4",
                params![
                    WorkflowRunStatus::Paused.as_str(),
                    stored(now_ms),
                    run_id.to_string(),
                    WorkflowRunStatus::Cancelled.as_str(),
                ],
            )?;
            Ok(())
        })
    }

    /// Reports whether a workflow revision is currently paused.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn is_paused(&self, workflow_id: WorkflowId, revision: u64) -> Result<bool> {
        self.read(|journal| journal.is_paused(workflow_id, revision))
    }

    /// Reports whether this trigger has already been recorded for this revision.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn trigger_is_recorded(
        &self,
        workflow_id: WorkflowId,
        revision: u64,
        event_id: &str,
    ) -> Result<bool> {
        self.read(|journal| journal.trigger_is_recorded(workflow_id, revision, event_id))
    }

    /// Reads one node's recorded status.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn node_status(&self, run_id: WorkflowRunId, node_id: &str) -> Result<Option<NodeStatus>> {
        let conn = self.lock();
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
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn node_receipt_exists(&self, run_id: WorkflowRunId, node_id: &str) -> Result<bool> {
        self.read(|journal| journal.node_receipt_exists(run_id, node_id))
    }

    /// Lists durable run records sharing a causal root.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn list_runs_by_root(&self, root_id: CausalRootId) -> Result<Vec<StoredRunRecord>> {
        self.read(|journal| journal.runs_by_root(root_id))
    }

    /// Commits a trigger, run, and budget reservation together in one local transaction.
    ///
    /// # Errors
    ///
    /// As [`Journal::commit_trigger_and_run`].
    pub fn commit_trigger_and_run(
        &self,
        run_id: WorkflowRunId,
        definition: &WorkflowDefinition,
        event_id: &str,
        causal_ctx: &CausalContext,
        now_ms: u64,
    ) -> Result<CausalBudget> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let outcome = Journal::unguarded(&tx)
            .commit_trigger_and_run(run_id, definition, event_id, causal_ctx, now_ms);
        // A budget refusal writes the exhaustion it owes; every other refusal wrote nothing.
        if outcome.is_ok() || matches!(outcome, Err(AutomationError::CausalLimitExhausted { .. })) {
            tx.commit()?;
        }
        outcome
    }

    /// Updates a workflow run's status.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn update_run_status(
        &self,
        run_id: WorkflowRunId,
        status: WorkflowRunStatus,
        ended_at_ms: Option<u64>,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE workflow_runs SET status = ?1, ended_at_ms = ?2 WHERE run_id = ?3",
            params![status.as_str(), ended_at_ms.map(stored), run_id.to_string()],
        )?;
        Ok(())
    }

    /// Updates an action node's receipt and outcome.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn update_node_receipt(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        status: NodeStatus,
        output: Option<&str>,
        error: Option<&str>,
        ended_at_ms: Option<u64>,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE node_receipts SET status = ?1, output_json = ?2, error_json = ?3,
                    ended_at_ms = ?4
             WHERE run_id = ?5 AND node_id = ?6",
            params![
                status.as_str(),
                output,
                error,
                ended_at_ms.map(stored),
                run_id.to_string(),
                node_id,
            ],
        )?;
        Ok(())
    }

    /// Reads run summaries.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn list_runs(&self, workflow_id: Option<WorkflowId>) -> Result<Vec<WorkflowRunSummary>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {RUN_SUMMARY_COLUMNS} FROM workflow_runs
             WHERE ?1 IS NULL OR workflow_id = ?1
             ORDER BY started_at_ms DESC"
        ))?;
        let rows = stmt.query_map(
            params![workflow_id.map(|id| id.to_string())],
            Journal::parse_run_summary,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Reads one run's summary, as it stands now.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn run_summary(&self, run_id: WorkflowRunId) -> Result<Option<WorkflowRunSummary>> {
        self.read(|journal| journal.run_summary(run_id))
    }

    /// Reads node receipts for a run.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn list_node_receipts(&self, run_id: WorkflowRunId) -> Result<Vec<NodeReceiptSummary>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT node_id, action_id, causal_parent, status, output_json, started_at_ms,
                    ended_at_ms
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
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Reads the attention records the journal has committed but not yet delivered.
    ///
    /// The rows outlive a restart, so a host that stopped between a pause and its delivery still
    /// raises the item when it comes back.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read, and a refusal naming the row when one
    /// cannot be understood.
    pub fn pending_attention(&self) -> Result<Vec<AttentionOutboxRecord>> {
        let conn = self.lock();
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
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn settle_attention(&self, outbox_ids: &[i64], now_ms: u64) -> Result<()> {
        self.write(|journal| {
            for id in outbox_ids {
                journal.conn.execute(
                    "UPDATE outbox_events SET settled_at_ms = ?1 WHERE outbox_id = ?2",
                    params![stored(now_ms), id],
                )?;
            }
            Ok(())
        })
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

    fn key(action: &str, method: &str) -> ActionKey {
        ActionKey {
            actor_id: "tester".to_owned(),
            action_id: action.to_owned(),
            method: method.to_owned(),
            digest: vec![1, 2, 3],
        }
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

        store
            .commit_trigger_and_run(run1, &def, "evt-123", &causal, 1000)
            .unwrap();

        let run2 = WorkflowRunId::new(Uuid::from_bytes([11; 16]));
        let err = store
            .commit_trigger_and_run(run2, &def, "evt-123", &causal, 1000)
            .unwrap_err();
        assert!(matches!(err, AutomationError::DuplicateTrigger { .. }));
    }

    /// An effect and its record are one transaction: an action that was performed always has
    /// its record, and a submission whose admission lapsed leaves neither.
    #[test]
    fn an_action_and_its_record_commit_together_or_not_at_all() {
        let store = WorkflowStore::in_memory().unwrap();
        let def = create_workflow_definition(
            test_wf_id(2),
            1,
            "recorded",
            test_grant_id(2),
            vec![],
            vec![],
        );

        let refuse = || -> Result<()> {
            Err(AutomationError::Lapsed {
                code: kr_protocol::error::ErrorCode::PermissionDenied,
                detail: "the admission was withdrawn".to_owned(),
            })
        };
        let installing = key("a-1", "workflow.install");
        let error = store
            .act(
                &Submitted {
                    key: &installing,
                    admission: &refuse,
                },
                1_000,
                |journal| {
                    journal.save_definition(&def, 1_000)?;
                    Ok((ActionRecord::done(&"installed")?, ()))
                },
            )
            .expect_err("a lapsed admission writes nothing");
        assert!(matches!(error, AutomationError::Lapsed { .. }), "{error}");
        assert!(store.get_definition(test_wf_id(2), 1).unwrap().is_none());
        assert!(store.recorded_action(&installing).unwrap().is_none());

        let admit = || Ok(());
        let acted = store
            .act(
                &Submitted {
                    key: &installing,
                    admission: &admit,
                },
                1_000,
                |journal| {
                    journal.save_definition(&def, 1_000)?;
                    Ok((ActionRecord::done(&"installed")?, ()))
                },
            )
            .unwrap();
        assert!(matches!(acted, Acted::Performed(())));
        assert!(store.get_definition(test_wf_id(2), 1).unwrap().is_some());

        // The repeat is answered from the record, and its effect is never run.
        let repeated = store
            .act(
                &Submitted {
                    key: &installing,
                    admission: &admit,
                },
                1_001,
                |_| -> Result<(ActionRecord, ())> {
                    panic!("a recorded action is not performed a second time")
                },
            )
            .unwrap();
        assert!(matches!(
            repeated,
            Acted::Answered(ActionRecord::Done { .. })
        ));

        // The same identifier carrying something else is another action.
        let mut reused = installing.clone();
        reused.digest = vec![9];
        let error = store
            .act(
                &Submitted {
                    key: &reused,
                    admission: &admit,
                },
                1_002,
                |_| -> Result<(ActionRecord, ())> {
                    panic!("a reused identifier performs nothing")
                },
            )
            .expect_err("a reused identifier is refused");
        assert!(
            matches!(error, AutomationError::ActionIdentifierReused { .. }),
            "{error}"
        );
    }

    /// A refusal the host decided is recorded with whatever it wrote in deciding it, so a repeat is
    /// refused the same way and the effect of the refusal is not lost.
    #[test]
    fn a_decided_refusal_is_recorded_with_its_own_effect() {
        let store = WorkflowStore::in_memory().unwrap();
        let def = create_workflow_definition(
            test_wf_id(3),
            1,
            "refused",
            test_grant_id(3),
            vec![],
            vec![],
        );
        store.save_definition(&def, 1_000).unwrap();

        let admit = || Ok(());
        let breaching = key("a-2", "workflow.run");
        let error = store
            .act(
                &Submitted {
                    key: &breaching,
                    admission: &admit,
                },
                1_000,
                |journal| -> Result<(ActionRecord, ())> {
                    journal.pause_workflow_on_breach(test_wf_id(3), 1, "too many", 1_000)?;
                    Err(AutomationError::RateLimitExceeded {
                        reason: "too many".to_owned(),
                    })
                },
            )
            .expect_err("the breach is refused");
        assert!(matches!(error, AutomationError::RateLimitExceeded { .. }));
        assert!(
            store.is_paused(test_wf_id(3), 1).unwrap(),
            "the pause was kept"
        );
        assert!(matches!(
            store.recorded_action(&breaching).unwrap(),
            Some(ActionRecord::Refused { code, .. }) if code == "RATE_LIMITED"
        ));
    }
}
