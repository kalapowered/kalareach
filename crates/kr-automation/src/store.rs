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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::automation::{
    NodeOutput, NodeReceiptSummary, NodeStatus, WorkflowDefinition, WorkflowDefinitionSummary,
    WorkflowRunStatus, WorkflowRunSummary,
};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActionId, CausalRootId, GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::admission::Placement;
use crate::budget::{CausalBudget, Inherited};
use crate::causal::CausalContext;
use crate::error::{AutomationError, Result};

/// Default file name for the workflow journal database.
pub const WORKFLOW_DB_NAME: &str = "workflows.db";

/// The schema version this build reads and writes.
///
/// It covers the rows as well as the tables, the stored events, definitions and node outputs among
/// them. Versions 1 to 5 were written only by builds that never reached an installed product, so no
/// installed journal holds any of them, and a journal at one of them is refused by name rather than
/// read as if its rows said what this build expects. Version 5 stores each node's output as its
/// kind's typed output rather than as text. Version 6 keeps the admissions the host-wide and
/// per-grant rates count, a run that waits for a slot as pending, and the ceilings a chain
/// inherited.
pub const WORKFLOW_SCHEMA_VERSION: u32 = 6;

/// The columns [`Journal::parse_run_record`] expects, in order.
const RUN_RECORD_COLUMNS: &str = "run_id, workflow_id, revision, causal_root_id, generation, depth,
            parent_run_id, parent_node_id";

/// The columns [`Journal::parse_run_summary`] expects, in order.
const RUN_SUMMARY_COLUMNS: &str = "run_id, workflow_id, revision, causal_root_id, depth, status,
            trigger_event_id, started_at_ms, ended_at_ms, parent_run_id, parent_node_id";

/// Reads an identifier the journal wrote, reporting a corrupt row rather than panicking on it.
fn parse_stored_uuid(value: &str) -> rusqlite::Result<kr_protocol::scalars::Uuid> {
    crate::parse_uuid(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

/// Splits an outcome into the part a transaction commits and the part that abandons it.
///
/// A refusal the host decided commits with whatever deciding it wrote, such as an exhausted budget
/// and the one attention event it owes, and comes back to the caller after the commit. Anything
/// else, a journal that could not write that event among them, abandons the transaction, so the
/// budget is never left marked as having raised an item that was not written.
fn decided(outcome: Result<()>) -> Result<Result<()>> {
    match outcome {
        Ok(()) => Ok(Ok(())),
        Err(error) if error.is_decided() => Ok(Err(error)),
        Err(error) => Err(error),
    }
}

/// A count or an instant as the journal stores it.
fn stored(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A definition revision as the journal keys it, or `None` for a number no revision can have.
///
/// A revision is stored exactly or not at all. Saturating it, as a count may be, would make every
/// number past the largest one the store holds name the revision stored there.
fn revision_key(revision: u64) -> Option<i64> {
    i64::try_from(revision).ok()
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
/// The event type of an accepted trigger and the run it started.
pub const EVENT_RUN_ADMITTED: &str = "workflow.run_admitted";
/// The event type of a dispatched node's settled outcome.
pub const EVENT_NODE_SETTLED: &str = "workflow.node_settled";
/// The event type of a run that stopped: completed, failed, paused or cancelled.
pub const EVENT_RUN_SETTLED: &str = "workflow.run_settled";

/// The event types that raise an attention item or end one.
pub const ATTENTION_EVENTS: &[&str] = &[
    ATTENTION_CAUSAL_LIMIT,
    ATTENTION_WORKFLOW_PAUSED,
    ATTENTION_WORKFLOW_RESUMED,
];

/// The name the attention consumer registers under.
pub const ATTENTION_CONSUMER: &str = "attention";

/// The subsystem every event of this journal's stream comes from.
pub const EVENT_SOURCE: &str = "automation";

/// The content class of every event of this journal's stream: identifiers and states, never
/// anything a node, a terminal or a model produced.
pub const EVENT_CONTENT: &str = "identifiers";

/// The actor an event names when the host's own transition caused it rather than a caller's action.
pub const HOST_ACTOR: &str = "host";

/// A run's place in its causal chain, as an event carries it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventChain {
    /// The chain's root.
    pub causal_root_id: CausalRootId,
    /// The budget generation the run belongs to.
    pub generation: u64,
    /// The run's depth in the chain.
    pub depth: u64,
    /// The run whose node triggered this one, when it descends from another.
    pub parent_run_id: Option<WorkflowRunId>,
    /// That node.
    pub parent_node_id: Option<String>,
}

impl EventChain {
    /// The chain a recorded run belongs to.
    #[must_use]
    pub fn of(run: &StoredRunRecord) -> Self {
        Self {
            causal_root_id: run.causal_root_id,
            generation: run.generation,
            depth: run.depth,
            parent_run_id: run.parent_run_id,
            parent_node_id: run.parent_node_id.clone(),
        }
    }
}

/// What one event in the journal's stream says happened.
///
/// The shape is part of the journal's contract with its consumers: an event, once committed, is
/// never rewritten, and a consumer reads it as it was written. Each variant carries the
/// identifiers a consumer needs to act on it without reading anything else, the causal chain among
/// them. Nothing a node produced is copied in: an output, a terminal's text or a model's words stay
/// where they are, and a consumer that needs them reads them under its own authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalEventKind {
    /// A causal chain ran out of budget and was paused. It owes one attention item.
    CausalLimit {
        /// The chain.
        causal_root_id: CausalRootId,
        /// Which ceiling was reached.
        reason: String,
    },
    /// A workflow revision was paused because one of its own limits was breached. It owes one
    /// attention item.
    WorkflowPaused {
        /// The workflow.
        workflow_id: WorkflowId,
        /// The revision that was paused.
        revision: u64,
        /// Which limit was breached.
        reason: String,
    },
    /// The pause a breached limit caused was cleared, which ends that item's condition.
    WorkflowResumed {
        /// The workflow.
        workflow_id: WorkflowId,
        /// The revision that was enabled again.
        revision: u64,
    },
    /// A trigger was accepted: its run, the run's receipts and the chain's reservation were
    /// recorded, and the run will dispatch its first node.
    RunAdmitted {
        /// The run.
        run_id: WorkflowRunId,
        /// The run's workflow.
        workflow_id: WorkflowId,
        /// The run's revision.
        revision: u64,
        /// The identifier of the trigger that started it.
        trigger_event_id: String,
        /// The run's place in its chain.
        chain: EventChain,
    },
    /// A dispatched node's outcome became the journal's record.
    NodeSettled {
        /// The run the node belongs to.
        run_id: WorkflowRunId,
        /// The run's workflow.
        workflow_id: WorkflowId,
        /// The run's revision.
        revision: u64,
        /// The node.
        node_id: String,
        /// The action identifier the journal gave the node when the run was recorded.
        action_id: ActionId,
        /// What the node came to.
        status: NodeStatus,
        /// The event a successful node produces, which is what a derived trigger names.
        produced: Option<String>,
        /// The run's place in its chain.
        chain: EventChain,
    },
    /// A run stopped: it completed, failed, paused or was cancelled.
    RunSettled {
        /// The run.
        run_id: WorkflowRunId,
        /// The run's workflow.
        workflow_id: WorkflowId,
        /// The run's revision.
        revision: u64,
        /// Where it stopped.
        status: WorkflowRunStatus,
        /// The run's place in its chain.
        chain: EventChain,
    },
}

impl JournalEventKind {
    /// The event's type, as the stream's type column holds it.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::CausalLimit { .. } => ATTENTION_CAUSAL_LIMIT,
            Self::WorkflowPaused { .. } => ATTENTION_WORKFLOW_PAUSED,
            Self::WorkflowResumed { .. } => ATTENTION_WORKFLOW_RESUMED,
            Self::RunAdmitted { .. } => EVENT_RUN_ADMITTED,
            Self::NodeSettled { .. } => EVENT_NODE_SETTLED,
            Self::RunSettled { .. } => EVENT_RUN_SETTLED,
        }
    }
}

/// An event as the stream stores it: what happened, and the envelope every event carries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEvent {
    source: String,
    actor: String,
    content: String,
    event: JournalEventKind,
}

/// One event of the journal's stream, as a consumer reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEvent {
    /// The event's row number: its position in the stream, which never changes, and the position
    /// a consumer records once it has acted on it.
    pub sequence: u64,
    /// When it was committed.
    pub recorded_at_ms: u64,
    /// The subsystem it comes from, [`EVENT_SOURCE`].
    pub source: String,
    /// The verified actor whose action caused it, or [`HOST_ACTOR`] for the host's own
    /// transitions.
    pub actor: String,
    /// Its content class, [`EVENT_CONTENT`].
    pub content: String,
    /// What happened.
    pub kind: JournalEventKind,
}

/// A dispatched node's outcome, as the engine hands it to the journal.
#[derive(Debug, Clone, Copy)]
pub struct NodeSettlement<'a> {
    /// The run.
    pub run_id: WorkflowRunId,
    /// The node.
    pub node_id: &'a str,
    /// What it came to.
    pub status: NodeStatus,
    /// What the action produced, when it succeeded.
    pub output: Option<&'a NodeOutput>,
    /// Why it did not, when it did not.
    pub error: Option<&'a str>,
    /// The event a success produces.
    pub produced: Option<&'a str>,
    /// When the outcome arrived.
    pub at_ms: u64,
}

/// A limit one run exceeded, and what the host did about the action it was waiting for.
#[derive(Debug, Clone, Copy)]
pub struct Breach<'a> {
    /// The run.
    pub run_id: WorkflowRunId,
    /// The limit it exceeded, which is why it stops.
    pub reason: &'a str,
    /// The node whose action outlived the limit, when the host was waiting for one.
    pub outlived: Option<Outlived<'a>>,
    /// When the host found the limit exceeded.
    pub at_ms: u64,
}

/// A node whose action outlived a limit, as it settles.
#[derive(Debug, Clone, Copy)]
pub struct Outlived<'a> {
    /// The node.
    pub node_id: &'a str,
    /// Cancelled when its action was asked to stop, unknown when an action of its kind cannot be.
    pub status: NodeStatus,
    /// What the host did, in words.
    pub detail: &'a str,
}

/// The nodes still waiting that depend, directly or through other nodes that have not run, on an
/// outcome that is not known. They wait for review rather than being stopped: whether they should
/// have run is exactly what is not known.
fn awaiting_review(
    definition: &WorkflowDefinition,
    statuses: &HashMap<String, NodeStatus>,
) -> Vec<String> {
    let mut reached: HashSet<&str> = HashSet::new();
    let mut frontier: Vec<&str> = statuses
        .iter()
        .filter(|(_, status)| **status == NodeStatus::Unknown)
        .map(|(node_id, _)| node_id.as_str())
        .collect();
    while let Some(from) = frontier.pop() {
        for edge in definition
            .edges
            .iter()
            .filter(|edge| edge.from_node == from)
        {
            let to = edge.to_node.as_str();
            let unsettled = matches!(
                statuses.get(to),
                Some(NodeStatus::Pending | NodeStatus::Paused)
            );
            if unsettled && reached.insert(to) {
                frontier.push(to);
            }
        }
    }
    let mut waiting: Vec<String> = reached
        .into_iter()
        .filter(|node_id| statuses.get(*node_id) == Some(&NodeStatus::Pending))
        .map(str::to_owned)
        .collect();
    waiting.sort();
    waiting
}

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
    /// The grant the caller who installed it was held to, when a paired device installed it.
    ///
    /// A revision a paired device installed is triggered only by runs under that same grant, so a
    /// device cannot subscribe to another grant's events, join that grant's causal chains or learn
    /// about their runs. `None` is a revision the host's owner installed.
    pub installed_under: Option<GrantId>,
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
    /// The grant the caller holds, when it reached this host as a paired device.
    ///
    /// Such a submission reaches only workflows that act under that grant: a device may not
    /// install, enable, pause or run a workflow under authority it does not hold, which would give
    /// it rights through a workflow that its own grant does not carry. `None` is the host's owner at
    /// this machine, who may act on every workflow.
    pub caller_grant: Option<GrantId>,
}

impl std::fmt::Debug for Submitted<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Submitted")
            .field("key", self.key)
            .finish_non_exhaustive()
    }
}

/// One attention record from the journal's stream, as the attention consumer reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionOutboxRecord {
    /// Whether the record raises a condition or ends one.
    pub ends_condition: bool,
    /// The record's position in the stream.
    ///
    /// It is also the delivery cursor: a redelivery of the same record carries the same sequence,
    /// so an attention state that already consumed it counts nothing twice.
    pub sequence: u64,
    /// What the record is about.
    pub subject: AttentionSubject,
    /// Which limit was reached.
    pub reason: String,
    /// When the record was committed.
    pub created_at_ms: u64,
}

impl AttentionOutboxRecord {
    /// The attention record an event carries, when it carries one.
    #[must_use]
    pub fn of(event: &JournalEvent) -> Option<Self> {
        let (subject, reason, ends_condition) = match &event.kind {
            JournalEventKind::CausalLimit {
                causal_root_id,
                reason,
            } => (
                AttentionSubject::CausalRoot(*causal_root_id),
                reason.clone(),
                false,
            ),
            JournalEventKind::WorkflowPaused {
                workflow_id,
                revision,
                reason,
            } => (
                AttentionSubject::Workflow {
                    workflow_id: *workflow_id,
                    revision: *revision,
                },
                reason.clone(),
                false,
            ),
            JournalEventKind::WorkflowResumed {
                workflow_id,
                revision,
            } => (
                AttentionSubject::Workflow {
                    workflow_id: *workflow_id,
                    revision: *revision,
                },
                "the workflow revision was enabled again".to_owned(),
                true,
            ),
            JournalEventKind::RunAdmitted { .. }
            | JournalEventKind::NodeSettled { .. }
            | JournalEventKind::RunSettled { .. } => {
                return None;
            }
        };
        Some(Self {
            ends_condition,
            sequence: event.sequence,
            subject,
            reason,
            created_at_ms: event.recorded_at_ms,
        })
    }
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
    actor: Option<&'c str>,
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
            actor: None,
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
                "SELECT definition_json, enabled, paused, installed_under FROM workflow_definitions
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
        let Some(key) = revision_key(revision) else {
            return Ok(None);
        };
        let found = self
            .conn
            .query_row(
                "SELECT definition_json, enabled, paused, installed_under FROM workflow_definitions
                 WHERE workflow_id = ?1 AND revision = ?2",
                params![workflow_id.to_string(), key],
                Self::parse_installed,
            )
            .optional()?;
        found.transpose()
    }

    fn parse_installed(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<InstalledDefinition>> {
        let json: String = row.get(0)?;
        let enabled: i64 = row.get(1)?;
        let paused: i64 = row.get(2)?;
        let installed_under: Option<String> = row.get(3)?;
        let installed_under = installed_under
            .map(|value| parse_stored_uuid(&value).map(GrantId::new))
            .transpose()?;
        Ok(serde_json::from_str(&json)
            .map(|definition| InstalledDefinition {
                definition,
                enabled: enabled != 0,
                paused: paused != 0,
                installed_under,
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
        installed_under: Option<GrantId>,
        installed_at_ms: u64,
    ) -> Result<()> {
        let Some(key) = revision_key(definition.revision.get()) else {
            return Err(AutomationError::InvalidArgument(format!(
                "a revision is at most {}",
                i64::MAX
            )));
        };
        self.admit()?;
        let def_json = serde_json::to_string(definition)?;
        self.conn
            .execute(
                "INSERT INTO workflow_definitions (
                    workflow_id, revision, name, description, definition_json,
                    grant_reference, enabled, paused, installed_at_ms, installed_under
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7, ?8)",
                params![
                    definition.workflow_id.to_string(),
                    key,
                    definition.name,
                    definition.description.as_ref(),
                    def_json,
                    definition.grant_reference.to_string(),
                    stored(installed_at_ms),
                    installed_under.map(|grant| grant.to_string()),
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
        let key = revision_key(revision).ok_or(AutomationError::WorkflowNotFound(workflow_id))?;
        self.admit()?;
        let updated = self.conn.execute(
            "UPDATE workflow_definitions SET enabled = ?1
             WHERE workflow_id = ?2 AND revision = ?3",
            params![i64::from(enabled), workflow_id.to_string(), key],
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
        let key = revision_key(revision).ok_or(AutomationError::WorkflowNotFound(workflow_id))?;
        self.admit()?;
        let updated = self.conn.execute(
            "UPDATE workflow_definitions SET paused = ?1
             WHERE workflow_id = ?2 AND revision = ?3",
            params![i64::from(paused), workflow_id.to_string(), key],
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
        let Some(key) = revision_key(revision) else {
            return Ok(());
        };
        self.admit()?;
        let resumed = self.conn.execute(
            "UPDATE workflow_definitions SET paused = 0
             WHERE workflow_id = ?1 AND revision = ?2 AND paused = 1",
            params![workflow_id.to_string(), key],
        )?;
        if resumed > 0 {
            self.record_event(
                &JournalEventKind::WorkflowResumed {
                    workflow_id,
                    revision,
                },
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
        let Some(key) = revision_key(revision) else {
            return Ok(());
        };
        self.admit()?;
        let paused = self.conn.execute(
            "UPDATE workflow_definitions SET paused = 1
             WHERE workflow_id = ?1 AND revision = ?2 AND paused = 0",
            params![workflow_id.to_string(), key],
        )?;
        if paused > 0 {
            self.record_event(
                &JournalEventKind::WorkflowPaused {
                    workflow_id,
                    revision,
                    reason: reason.to_owned(),
                },
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
        let Some(key) = revision_key(revision) else {
            return Ok(false);
        };
        let paused: Option<i64> = self
            .conn
            .query_row(
                "SELECT paused FROM workflow_definitions WHERE workflow_id = ?1 AND revision = ?2",
                params![workflow_id.to_string(), key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(paused.unwrap_or(0) != 0)
    }

    /// Lists the enabled, unpaused revisions whose trigger names `event_type`.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn definitions_triggered_by(&self, event_type: &str) -> Result<Vec<InstalledDefinition>> {
        let mut stmt = self.conn.prepare(
            "SELECT definition_json, enabled, paused, installed_under FROM workflow_definitions
             WHERE enabled = 1 AND paused = 0
             ORDER BY workflow_id, revision",
        )?;
        let rows = stmt.query_map([], Self::parse_installed)?;
        let mut matched = Vec::new();
        for row in rows {
            let installed = row??;
            if installed.definition.trigger.event_type == event_type {
                matched.push(installed);
            }
        }
        Ok(matched)
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
        let Some(key) = revision_key(revision) else {
            return Ok(false);
        };
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM trigger_dedup
                 WHERE workflow_id = ?1 AND revision = ?2 AND event_id = ?3",
                params![workflow_id.to_string(), key, event_id],
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

    /// Reads the grant a run acts under: the one its recorded revision names.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn run_grant(&self, run_id: WorkflowRunId) -> Result<Option<GrantId>> {
        let Some(run) = self.run_record(run_id)? else {
            return Ok(None);
        };
        Ok(self
            .definition(run.workflow_id, run.revision)?
            .map(|installed| installed.definition.grant_reference))
    }

    /// Reads the grant a causal chain belongs to: the one its root run acts under.
    ///
    /// A chain starts from exactly one run with no parent, the run of the external trigger the
    /// host minted the root for, and every other run in it descends from that one.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn chain_grant(&self, root_id: CausalRootId) -> Result<Option<GrantId>> {
        let root_run = self
            .conn
            .query_row(
                "SELECT run_id FROM workflow_runs
                 WHERE causal_root_id = ?1 AND parent_run_id IS NULL",
                params![root_id.to_string()],
                |row| parse_stored_uuid(&row.get::<_, String>(0)?).map(WorkflowRunId::new),
            )
            .optional()?;
        match root_run {
            Some(run_id) => self.run_grant(run_id),
            None => Ok(None),
        }
    }

    /// Counts the runs of every revision of one workflow that stand in `status`.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn runs_in(&self, workflow_id: WorkflowId, status: WorkflowRunStatus) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM workflow_runs WHERE workflow_id = ?1 AND status = ?2",
            params![workflow_id.to_string(), status.as_str()],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    /// Counts the runs admitted at or after `since_ms`, host-wide or under one grant.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn admissions_since(&self, since_ms: u64, grant: Option<GrantId>) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM run_admissions
             WHERE admitted_at_ms >= ?1 AND (?2 IS NULL OR grant_reference = ?2)",
            params![stored(since_ms), grant.map(|grant| grant.to_string())],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or_default())
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
        let parent_run: Option<String> = row.get(9)?;
        let parent_node: Option<String> = row.get(10)?;

        Ok(WorkflowRunSummary {
            run_id: WorkflowRunId::new(parse_stored_uuid(&run_id_str)?),
            workflow_id: WorkflowId::new(parse_stored_uuid(&wf_id_str)?),
            revision: U64::new(rev as u64),
            causal_root_id: CausalRootId::new(parse_stored_uuid(&root_str)?),
            depth: U64::new(depth as u64),
            status: WorkflowRunStatus::from_wire(&status_str).unwrap_or(WorkflowRunStatus::Pending),
            parent_run_id: Nullable::from(
                parent_run
                    .map(|value| parse_stored_uuid(&value).map(WorkflowRunId::new))
                    .transpose()?,
            ),
            parent_node_id: Nullable::from(parent_node),
            trigger_event_id: trigger_id,
            started_at_ms: TimestampMs::new(started as u64),
            ended_at_ms: Nullable::from(ended.map(|v| TimestampMs::new(v as u64))),
        })
    }

    /// Commits a trigger, its run, the run's node receipts, the chain's reservation and the
    /// admission the rates count, together.
    ///
    /// Deduplicates by `(workflow_id, definition_revision, event_id)`. A refusal from the budget
    /// writes the exhausted budget and the one attention item it owes, and nothing else. A run
    /// placed to start is recorded running, with its deadline; one placed in the queue is recorded
    /// pending, and its deadline is set when it is claimed. A new root's budget records what the
    /// chain inherits from its host; a descendant's reads the root's.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::DuplicateTrigger`] for a trigger already recorded, the budget's
    /// `CAUSAL_LIMIT` refusal, and whatever the admission refused with.
    #[expect(
        clippy::too_many_arguments,
        reason = "one transaction's worth of facts, each of which the caller decided"
    )]
    pub fn commit_trigger_and_run(
        &self,
        run_id: WorkflowRunId,
        definition: &WorkflowDefinition,
        event_id: &str,
        causal_ctx: &CausalContext,
        now_ms: u64,
        placement: Placement,
        inherited: Inherited,
    ) -> Result<CausalBudget> {
        let wf_id_str = definition.workflow_id.to_string();
        let rev = revision_key(definition.revision.get())
            .ok_or(AutomationError::WorkflowNotFound(definition.workflow_id))?;

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
            .unwrap_or_else(|| CausalBudget::new(causal_ctx.root_id, now_ms, inherited));
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

        let parent_run_id = causal_ctx.parent.as_ref().map(|p| p.run_id.to_string());
        let parent_node_id = causal_ctx.parent.as_ref().map(|p| p.node_id.clone());
        let (status, deadline_ms) = match placement {
            Placement::Start => (
                WorkflowRunStatus::Running,
                now_ms.saturating_add(definition.deadlines.run_deadline_ms.get()),
            ),
            // A run's deadline measures its execution, which has not begun.
            Placement::Queue => (WorkflowRunStatus::Pending, 0),
        };

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
                status.as_str(),
                stored(now_ms),
                stored(deadline_ms),
            ],
        )?;

        self.conn.execute(
            "INSERT INTO trigger_dedup (workflow_id, revision, event_id, run_id, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![wf_id_str, rev, event_id, run_id.to_string(), stored(now_ms)],
        )?;

        // What the host-wide and per-grant rates count. Kept here rather than in memory, so a
        // restart is not a way past a rate, and written only for a run that was admitted.
        self.conn.execute(
            "DELETE FROM run_admissions WHERE admitted_at_ms < ?1",
            params![stored(
                now_ms.saturating_sub(crate::admission::ADMISSION_WINDOW_MS)
            )],
        )?;
        self.conn.execute(
            "INSERT INTO run_admissions (admitted_at_ms, grant_reference) VALUES (?1, ?2)",
            params![stored(now_ms), definition.grant_reference.to_string()],
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

        self.record_event(
            &JournalEventKind::RunAdmitted {
                run_id,
                workflow_id: definition.workflow_id,
                revision: definition.revision.get(),
                trigger_event_id: event_id.to_owned(),
                chain: EventChain {
                    causal_root_id: causal_ctx.root_id,
                    generation: causal_ctx.generation,
                    depth: causal_ctx.depth,
                    parent_run_id: causal_ctx.parent.as_ref().map(|parent| parent.run_id),
                    parent_node_id: causal_ctx
                        .parent
                        .as_ref()
                        .map(|parent| parent.node_id.clone()),
                },
            },
            now_ms,
        )?;

        Ok(budget)
    }

    fn load_budget(&self, root_id: CausalRootId) -> Result<Option<CausalBudget>> {
        let found = self
            .conn
            .query_row(
                "SELECT generation, depth, max_depth, total_runs, max_runs, total_actions,
                        max_actions, created_sessions, max_sessions, started_at_ms,
                        max_lifetime_ms, paused, exhausted, attention_emitted, rearmed_at_ms,
                        managed_spend, max_managed_spend
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
                        managed_spend: row.get::<_, i64>(15)? as u64,
                        max_managed_spend: row.get::<_, i64>(16)? as u64,
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
                attention_emitted, rearmed_at_ms, managed_spend, max_managed_spend
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                      ?18)
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
                rearmed_at_ms = excluded.rearmed_at_ms,
                managed_spend = excluded.managed_spend",
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
                stored(budget.managed_spend),
                stored(budget.max_managed_spend),
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
        // A chain's budget is written with its root run, so a reservation for a chain this journal
        // holds no budget for is not one it can decide.
        let mut budget = self.load_budget(root_id)?.ok_or_else(|| {
            AutomationError::InvalidArgument(format!(
                "this journal holds no budget for causal root {root_id}"
            ))
        })?;
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
        self.record_event(
            &JournalEventKind::CausalLimit {
                causal_root_id: root_id,
                reason: reason.to_owned(),
            },
            now_ms,
        )?;
        Ok(())
    }

    /// Commits one event to the journal's stream, inside the caller's transaction.
    ///
    /// Returns the event's position in the stream.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn record_event(&self, kind: &JournalEventKind, now_ms: u64) -> Result<u64> {
        let stored_event = StoredEvent {
            source: EVENT_SOURCE.to_owned(),
            actor: self.actor.unwrap_or(HOST_ACTOR).to_owned(),
            content: EVENT_CONTENT.to_owned(),
            event: kind.clone(),
        };
        self.conn.execute(
            "INSERT INTO outbox_events (event_type, payload_json, created_at_ms)
             VALUES (?1, ?2, ?3)",
            params![
                kind.event_type(),
                serde_json::to_string(&stored_event)?,
                stored(now_ms)
            ],
        )?;
        Ok(u64::try_from(self.conn.last_insert_rowid()).unwrap_or_default())
    }

    /// Reads the events after `position` whose type is one of `event_types`, oldest first.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read, and a refusal naming the row when one
    /// cannot be understood.
    pub fn events_after(
        &self,
        position: u64,
        event_types: &[&str],
        limit: usize,
    ) -> Result<Vec<JournalEvent>> {
        if event_types.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; event_types.len()].join(", ");
        let mut stmt = self.conn.prepare(&format!(
            "SELECT outbox_id, payload_json, created_at_ms FROM outbox_events
             WHERE outbox_id > ? AND event_type IN ({placeholders})
             ORDER BY outbox_id ASC LIMIT ?"
        ))?;
        let mut values: Vec<rusqlite::types::Value> =
            vec![rusqlite::types::Value::Integer(stored(position))];
        values.extend(
            event_types
                .iter()
                .map(|kind| rusqlite::types::Value::Text((*kind).to_owned())),
        );
        values.push(rusqlite::types::Value::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));
        let rows = stmt.query_map(rusqlite::params_from_iter(values), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, payload, recorded_at_ms) = row?;
            let stored_event: StoredEvent = serde_json::from_str(&payload).map_err(|error| {
                AutomationError::InvalidArgument(format!(
                    "event {sequence} of the workflow journal cannot be read: {error}"
                ))
            })?;
            events.push(JournalEvent {
                sequence: sequence as u64,
                recorded_at_ms: recorded_at_ms as u64,
                source: stored_event.source,
                actor: stored_event.actor,
                content: stored_event.content,
                kind: stored_event.event,
            });
        }
        Ok(events)
    }

    /// Registers a consumer of the event types it reads, if it is not registered already.
    ///
    /// A new consumer starts before the oldest event the journal still holds, so it reads every
    /// retained event of its types. Returns the consumer's position.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn register_consumer(
        &self,
        consumer: &str,
        event_types: &[&str],
        now_ms: u64,
    ) -> Result<u64> {
        self.conn.execute(
            "INSERT OR IGNORE INTO event_consumers (consumer, position, registered_at_ms)
             VALUES (?1, 0, ?2)",
            params![consumer, stored(now_ms)],
        )?;
        for event_type in event_types {
            self.conn.execute(
                "INSERT OR IGNORE INTO event_subscriptions (consumer, event_type)
                 VALUES (?1, ?2)",
                params![consumer, event_type],
            )?;
        }
        Ok(self.consumer_position(consumer)?.unwrap_or_default())
    }

    /// Returns where a registered consumer has read to.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn consumer_position(&self, consumer: &str) -> Result<Option<u64>> {
        let position: Option<i64> = self
            .conn
            .query_row(
                "SELECT position FROM event_consumers WHERE consumer = ?1",
                params![consumer],
                |row| row.get(0),
            )
            .optional()?;
        Ok(position.map(|position| position as u64))
    }

    /// Records that a consumer has acted on every event up to `position`.
    ///
    /// A position only moves forward: an acknowledgement that arrives late cannot make a consumer
    /// read again what it already acted on.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written, and a refusal for a consumer that
    /// never registered.
    pub fn advance_consumer(&self, consumer: &str, position: u64) -> Result<()> {
        let updated = self.conn.execute(
            "UPDATE event_consumers SET position = MAX(position, ?2) WHERE consumer = ?1",
            params![consumer, stored(position)],
        )?;
        if updated == 0 {
            return Err(AutomationError::InvalidArgument(format!(
                "{consumer} is not a registered consumer of this journal's events"
            )));
        }
        Ok(())
    }

    /// Settles a dispatched node's outcome and commits the event that says so, together.
    ///
    /// Only a node that is still running is settled. A node cancelled while its action ran keeps
    /// its cancellation: the host stopped asking, and an answer that arrived afterwards does not
    /// make the run one that completed. Returns whether the outcome was written.
    fn settle_node(&self, settlement: &NodeSettlement<'_>) -> Result<bool> {
        let output = settlement.output.map(serde_json::to_string).transpose()?;
        let settled = self.conn.execute(
            "UPDATE node_receipts SET status = ?1, output_json = ?2, error_json = ?3,
                    ended_at_ms = ?4
             WHERE run_id = ?5 AND node_id = ?6 AND status = ?7",
            params![
                settlement.status.as_str(),
                output,
                settlement.error,
                stored(settlement.at_ms),
                settlement.run_id.to_string(),
                settlement.node_id,
                NodeStatus::Running.as_str(),
            ],
        )?;
        if settled == 0 {
            return Ok(false);
        }
        let run = self.run_record(settlement.run_id)?.ok_or_else(|| {
            AutomationError::InvalidArgument(format!(
                "node {} names run {}, which is not in the journal",
                settlement.node_id, settlement.run_id
            ))
        })?;
        let action_id: String = self.conn.query_row(
            "SELECT action_id FROM node_receipts WHERE run_id = ?1 AND node_id = ?2",
            params![settlement.run_id.to_string(), settlement.node_id],
            |row| row.get(0),
        )?;
        self.record_event(
            &JournalEventKind::NodeSettled {
                run_id: run.run_id,
                workflow_id: run.workflow_id,
                revision: run.revision,
                node_id: settlement.node_id.to_owned(),
                action_id: ActionId::new(parse_stored_uuid(&action_id)?),
                status: settlement.status,
                produced: settlement.produced.map(str::to_owned),
                chain: EventChain::of(&run),
            },
            settlement.at_ms,
        )?;
        Ok(true)
    }

    /// Reads where every node of one run stands.
    fn node_statuses(&self, run_id: WorkflowRunId) -> Result<HashMap<String, NodeStatus>> {
        let mut stmt = self
            .conn
            .prepare("SELECT node_id, status FROM node_receipts WHERE run_id = ?1")?;
        let rows = stmt.query_map(params![run_id.to_string()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut statuses = HashMap::new();
        for row in rows {
            let (node_id, status) = row?;
            let status = NodeStatus::from_wire(&status).ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {node_id} of run {run_id} holds a status this build does not know: \
                     {status}"
                ))
            })?;
            statuses.insert(node_id, status);
        }
        Ok(statuses)
    }

    /// Stops a run: every node still waiting or running is cancelled, and so is the run.
    ///
    /// A node that already settled keeps what it settled with, and a run that already finished is
    /// not reopened as a cancelled one.
    fn cancel_run(&self, run_id: WorkflowRunId, reason: &str, now_ms: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE node_receipts SET status = ?1, error_json = ?2, ended_at_ms = ?3
             WHERE run_id = ?4 AND status IN (?5, ?6)",
            params![
                NodeStatus::Cancelled.as_str(),
                reason,
                stored(now_ms),
                run_id.to_string(),
                NodeStatus::Pending.as_str(),
                NodeStatus::Running.as_str(),
            ],
        )?;
        let cancelled = self.conn.execute(
            "UPDATE workflow_runs SET status = ?1, ended_at_ms = ?2
             WHERE run_id = ?3 AND status IN (?4, ?5, ?6)",
            params![
                WorkflowRunStatus::Cancelled.as_str(),
                stored(now_ms),
                run_id.to_string(),
                WorkflowRunStatus::Pending.as_str(),
                WorkflowRunStatus::Running.as_str(),
                WorkflowRunStatus::Paused.as_str(),
            ],
        )?;
        if cancelled > 0 {
            self.record_run_settled(run_id, WorkflowRunStatus::Cancelled, now_ms)?;
        }
        Ok(())
    }

    /// Commits the event a run's new status owes, for a run whose status just changed.
    fn record_run_settled(
        &self,
        run_id: WorkflowRunId,
        status: WorkflowRunStatus,
        now_ms: u64,
    ) -> Result<()> {
        let Some(run) = self.run_record(run_id)? else {
            return Ok(());
        };
        self.record_event(
            &JournalEventKind::RunSettled {
                run_id,
                workflow_id: run.workflow_id,
                revision: run.revision,
                status,
                chain: EventChain::of(&run),
            },
            now_ms,
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
                installed_under TEXT,
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
                rearmed_at_ms INTEGER,
                managed_spend INTEGER NOT NULL,
                max_managed_spend INTEGER NOT NULL
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

            -- The journal's event stream. A row is never rewritten; its number is its position in
            -- the stream and the cursor its consumers record. A row is removed only once every
            -- consumer registered for its type has passed it.
            CREATE TABLE IF NOT EXISTS outbox_events (
                outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS outbox_events_by_type
                ON outbox_events (event_type, outbox_id);

            -- Each registered consumer and the position it has acted on.
            CREATE TABLE IF NOT EXISTS event_consumers (
                consumer TEXT PRIMARY KEY,
                position INTEGER NOT NULL,
                registered_at_ms INTEGER NOT NULL
            );

            -- The event types each consumer reads.
            CREATE TABLE IF NOT EXISTS event_subscriptions (
                consumer TEXT NOT NULL,
                event_type TEXT NOT NULL,
                PRIMARY KEY (consumer, event_type)
            );

            -- One row per admitted run, for the host-wide and per-grant rates, kept for as long
            -- as a rate counts it.
            CREATE TABLE IF NOT EXISTS run_admissions (
                admitted_at_ms INTEGER NOT NULL,
                grant_reference TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS run_admissions_by_time
                ON run_admissions (admitted_at_ms);

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
            actor: Some(&submitted.key.actor_id),
        };
        if let Some(record) = journal.action_record(submitted.key)? {
            return Ok(Acted::Answered(record));
        }
        match effect(&journal) {
            Ok((record, value)) => {
                // The record is a write like any other: an action whose effect wrote nothing is
                // still refused here when its admission has lapsed, and leaves no record.
                journal.admit()?;
                journal.record_action(submitted.key, &record, now_ms)?;
                tx.commit()?;
                Ok(Acted::Performed(value))
            }
            Err(error) if error.is_decided() => {
                // A refusal is recorded only under an admission that still stands. One decided
                // before the first write, a revision that is not installed among them, would
                // otherwise be retained for a submission whose admission lapsed while it waited.
                journal.admit()?;
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

    /// Installs a workflow definition revision as the host's owner would.
    ///
    /// # Errors
    ///
    /// As [`Journal::save_definition`].
    pub fn save_definition(
        &self,
        definition: &WorkflowDefinition,
        installed_at_ms: u64,
    ) -> Result<()> {
        self.read(|journal| journal.save_definition(definition, None, installed_at_ms))
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

    /// Reads the installed definitions, of one workflow or of all of them.
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
                    installed_at_ms, paused
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
        let paused: i64 = row.get(7)?;

        Ok(WorkflowDefinitionSummary {
            workflow_id: WorkflowId::new(parse_stored_uuid(&wf_str)?),
            revision: U64::new(rev as u64),
            name,
            description: Nullable::from(desc),
            grant_reference: GrantId::new(parse_stored_uuid(&grant_str)?),
            enabled: enabled != 0,
            paused: paused != 0,
            installed_at_ms: TimestampMs::new(installed as u64),
        })
    }

    /// Loads or creates a causal budget for a causal root, one a new root inherits section 25's
    /// defaults and no managed allowance into.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read or written.
    pub fn get_or_create_budget(&self, root_id: CausalRootId, now_ms: u64) -> Result<CausalBudget> {
        self.write(|journal| {
            if let Some(budget) = journal.load_budget(root_id)? {
                return Ok(budget);
            }
            let budget = CausalBudget::new(root_id, now_ms, Inherited::DEFAULTS);
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

    /// Reserves one action of the causal budget, spending `managed_spend` of the chain's managed
    /// allowance, in one transaction with its refusal.
    ///
    /// # Errors
    ///
    /// Returns the budget's `CAUSAL_LIMIT` refusal, or a stale generation.
    pub fn reserve_budget_action(
        &self,
        root_id: CausalRootId,
        generation: u64,
        managed_spend: u64,
        now_ms: u64,
    ) -> Result<()> {
        self.write(|journal| {
            decided(
                journal.reserve_in_budget(root_id, generation, now_ms, |budget| {
                    budget.reserve_action(managed_spend, now_ms)
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
            decided(
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

    /// Records what a dispatched node came to, and the event that says so, if the node is still
    /// the dispatch's to settle.
    ///
    /// Only a node that is still running is settled. A node cancelled while its action ran keeps
    /// its cancellation: the host stopped asking, and an answer that arrived afterwards does not
    /// make the run one that completed. Returns whether the outcome was written.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn settle_node(&self, settlement: &NodeSettlement<'_>) -> Result<bool> {
        self.write(|journal| journal.settle_node(settlement))
    }

    /// Pauses a node that was never dispatched, for review, if it is still waiting.
    ///
    /// Returns whether the node was paused. A node the journal has already moved on, a cancelled
    /// one among them, is left as it is.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn pause_waiting_node(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<bool> {
        let conn = self.lock();
        let paused = conn.execute(
            "UPDATE node_receipts SET status = ?1, error_json = ?2, ended_at_ms = ?3
             WHERE run_id = ?4 AND node_id = ?5 AND status = ?6",
            params![
                NodeStatus::Paused.as_str(),
                reason,
                stored(now_ms),
                run_id.to_string(),
                node_id,
                NodeStatus::Pending.as_str(),
            ],
        )?;
        Ok(paused > 0)
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
            let paused = journal.conn.execute(
                "UPDATE workflow_runs SET status = ?1, ended_at_ms = ?2
                 WHERE run_id = ?3 AND status <> ?4",
                params![
                    WorkflowRunStatus::Paused.as_str(),
                    stored(now_ms),
                    run_id.to_string(),
                    WorkflowRunStatus::Cancelled.as_str(),
                ],
            )?;
            if paused > 0 {
                journal.record_run_settled(run_id, WorkflowRunStatus::Paused, now_ms)?;
            }
            Ok(())
        })
    }

    /// Stops a run: every node still waiting or running is cancelled, and so is the run.
    ///
    /// A node that already settled keeps what it settled with, and a run that already finished is
    /// not reopened as a cancelled one. Nothing here says anything about an external side effect
    /// an already dispatched action may have had.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn cancel_run(&self, run_id: WorkflowRunId, reason: &str, now_ms: u64) -> Result<()> {
        self.write(|journal| journal.cancel_run(run_id, reason, now_ms))
    }

    /// Starts the oldest pending run of one workflow, when fewer than `running_limit` of its runs
    /// are running and its revision is enabled and unpaused, and answers it with the definition
    /// it runs.
    ///
    /// The count, the choice and the move to running are one transaction, so two callers cannot
    /// both take the last slot or both start the same run. The run's deadline starts here, because
    /// it measures the run's execution rather than its wait.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read or written.
    pub fn claim_queued_run(
        &self,
        workflow_id: WorkflowId,
        running_limit: u64,
        now_ms: u64,
    ) -> Result<Option<(StoredRunRecord, WorkflowDefinition)>> {
        self.write(|journal| {
            if journal.runs_in(workflow_id, WorkflowRunStatus::Running)? >= running_limit {
                return Ok(None);
            }
            let next = journal
                .conn
                .query_row(
                    &format!(
                        "SELECT {RUN_RECORD_COLUMNS} FROM workflow_runs r
                         WHERE r.workflow_id = ?1 AND r.status = ?2
                           AND EXISTS (
                               SELECT 1 FROM workflow_definitions d
                               WHERE d.workflow_id = r.workflow_id AND d.revision = r.revision
                                 AND d.enabled = 1 AND d.paused = 0
                           )
                         ORDER BY r.started_at_ms ASC, r.rowid ASC LIMIT 1"
                    ),
                    params![workflow_id.to_string(), WorkflowRunStatus::Pending.as_str()],
                    Journal::parse_run_record,
                )
                .optional()?;
            let Some(run) = next else {
                return Ok(None);
            };
            let Some(installed) = journal.definition(run.workflow_id, run.revision)? else {
                return Ok(None);
            };
            let deadline_ms =
                now_ms.saturating_add(installed.definition.deadlines.run_deadline_ms.get());
            journal.conn.execute(
                "UPDATE workflow_runs SET status = ?1, deadline_ms = ?2
                 WHERE run_id = ?3 AND status = ?4",
                params![
                    WorkflowRunStatus::Running.as_str(),
                    stored(deadline_ms),
                    run.run_id.to_string(),
                    WorkflowRunStatus::Pending.as_str(),
                ],
            )?;
            Ok(Some((run, installed.definition)))
        })
    }

    /// Lists the workflows that have a run waiting for a slot.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn workflows_with_queued_runs(&self) -> Result<Vec<WorkflowId>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT workflow_id FROM workflow_runs WHERE status = ?1
             ORDER BY workflow_id",
        )?;
        let rows = stmt.query_map(params![WorkflowRunStatus::Pending.as_str()], |row| {
            parse_stored_uuid(&row.get::<_, String>(0)?).map(WorkflowId::new)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Reads the moment a running run's deadline passes, on the host's clock.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn run_deadline(&self, run_id: WorkflowRunId) -> Result<Option<u64>> {
        let conn = self.lock();
        let deadline: Option<i64> = conn
            .query_row(
                "SELECT deadline_ms FROM workflow_runs WHERE run_id = ?1",
                params![run_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(deadline.map(|deadline| u64::try_from(deadline).unwrap_or_default()))
    }

    /// Stops a run that exceeded one of its workflow's limits, in one transaction.
    ///
    /// The node whose action outlived the limit, when there is one, settles as the breach says:
    /// cancelled when its action was asked to stop, unknown when it could not be. Every node still
    /// waiting that depends, directly or through other waiting nodes, on an outcome that is not
    /// known pauses for review; every other node still waiting is cancelled; the run is cancelled;
    /// and the revision pauses with the attention item the pause owes. A crash therefore finds
    /// either none of this or all of it, and never a settled node whose run dispatches on. A node
    /// or a run that already settled keeps what it settled with.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read or written.
    pub fn stop_run_on_breach(&self, breach: &Breach<'_>) -> Result<()> {
        self.write(|journal| {
            let Some(run) = journal.run_record(breach.run_id)? else {
                return Ok(());
            };
            if let Some(outlived) = &breach.outlived {
                journal.settle_node(&NodeSettlement {
                    run_id: breach.run_id,
                    node_id: outlived.node_id,
                    status: outlived.status,
                    output: None,
                    error: Some(outlived.detail),
                    produced: None,
                    at_ms: breach.at_ms,
                })?;
            }
            if let Some(installed) = journal.definition(run.workflow_id, run.revision)? {
                let statuses = journal.node_statuses(breach.run_id)?;
                let review = format!(
                    "{}: the run stopped, and this node waits for review because a node it \
                     depends on has an outcome that is not known",
                    breach.reason
                );
                for node_id in awaiting_review(&installed.definition, &statuses) {
                    journal.conn.execute(
                        "UPDATE node_receipts SET status = ?1, error_json = ?2, ended_at_ms = ?3
                         WHERE run_id = ?4 AND node_id = ?5 AND status = ?6",
                        params![
                            NodeStatus::Paused.as_str(),
                            review,
                            stored(breach.at_ms),
                            breach.run_id.to_string(),
                            node_id,
                            NodeStatus::Pending.as_str(),
                        ],
                    )?;
                }
            }
            journal.cancel_run(breach.run_id, breach.reason, breach.at_ms)?;
            journal.pause_workflow_on_breach(
                run.workflow_id,
                run.revision,
                breach.reason,
                breach.at_ms,
            )
        })
    }

    /// Records where a run ended, unless it was cancelled, which is terminal.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn finish_run(
        &self,
        run_id: WorkflowRunId,
        status: WorkflowRunStatus,
        ended_at_ms: u64,
    ) -> Result<()> {
        self.write(|journal| {
            let finished = journal.conn.execute(
                "UPDATE workflow_runs SET status = ?1, ended_at_ms = ?2
                 WHERE run_id = ?3 AND status <> ?4",
                params![
                    status.as_str(),
                    stored(ended_at_ms),
                    run_id.to_string(),
                    WorkflowRunStatus::Cancelled.as_str(),
                ],
            )?;
            if finished > 0 {
                journal.record_run_settled(run_id, status, ended_at_ms)?;
            }
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

    /// Reads the grant a run acts under.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn run_grant(&self, run_id: WorkflowRunId) -> Result<Option<GrantId>> {
        self.read(|journal| journal.run_grant(run_id))
    }

    /// Reads the grant a causal chain belongs to.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn chain_grant(&self, root_id: CausalRootId) -> Result<Option<GrantId>> {
        self.read(|journal| journal.chain_grant(root_id))
    }

    /// Commits a trigger, run, and budget reservation together in one local transaction, for a
    /// caller outside the service: the run starts at once, and a new root inherits section 25's
    /// defaults and no managed allowance.
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
        let outcome = Journal::unguarded(&tx).commit_trigger_and_run(
            run_id,
            definition,
            event_id,
            causal_ctx,
            now_ms,
            Placement::Start,
            Inherited::DEFAULTS,
        );
        // A budget refusal writes the exhaustion it owes; every other refusal wrote nothing.
        if outcome.is_ok() || matches!(outcome, Err(AutomationError::CausalLimitExhausted { .. })) {
            tx.commit()?;
        }
        outcome
    }

    /// Overwrites a run's status, whatever it was.
    ///
    /// A record-keeping operation for a caller that is restoring a known state; the engine itself
    /// moves a run only through [`Self::claim_queued_run`], [`Self::finish_run`],
    /// [`Self::pause_on_refusal`] and [`Self::cancel_run`], which respect a cancellation.
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

    /// Overwrites a node's receipt, whatever it held.
    ///
    /// A record-keeping operation, as [`Self::update_run_status`]; the engine settles a node
    /// through [`Self::settle_node`], which respects a cancellation.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be written.
    pub fn update_node_receipt(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        status: NodeStatus,
        output: Option<&NodeOutput>,
        error: Option<&str>,
        ended_at_ms: Option<u64>,
    ) -> Result<()> {
        let output = output.map(serde_json::to_string).transpose()?;
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
            // The journal wrote this output from a typed one, so one it cannot read back is a
            // corrupt row, reported as one rather than shown as something else.
            let output = output
                .map(|value| {
                    serde_json::from_str::<NodeOutput>(&value).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })
                .transpose()?;

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

    /// Lets one consumer act on the next event after its position, in one transaction with its
    /// own position moving past it.
    ///
    /// This is the consumer rule of the journal's stream for a consumer whose effects are in this
    /// journal: what it does about an event and the fact that it has done it commit together, so
    /// a host that stops at any point neither skips the event nor acts on it twice. Returns what
    /// `act` returned, or nothing when there is no event after the position. When `act` fails,
    /// nothing it wrote is kept and the position does not move.
    ///
    /// # Errors
    ///
    /// Returns a storage error, a refusal for a consumer that never registered, or what `act`
    /// returned.
    pub fn consume<T>(
        &self,
        consumer: &str,
        event_types: &[&str],
        act: impl FnOnce(&Journal<'_>, &JournalEvent) -> Result<T>,
    ) -> Result<Option<T>> {
        self.write(|journal| {
            let position = journal.consumer_position(consumer)?.ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "{consumer} is not a registered consumer of this journal's events"
                ))
            })?;
            let Some(event) = journal
                .events_after(position, event_types, 1)?
                .into_iter()
                .next()
            else {
                return Ok(None);
            };
            let value = act(journal, &event)?;
            journal.advance_consumer(consumer, event.sequence)?;
            Ok(Some(value))
        })
    }

    /// Lists the runs the journal holds as running: the ones a stopped host may have been
    /// dispatching. A run still waiting for a slot is not among them; it waits on.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read.
    pub fn running_runs(&self) -> Result<Vec<StoredRunRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!(
            "SELECT {RUN_RECORD_COLUMNS} FROM workflow_runs WHERE status = ?1
             ORDER BY started_at_ms ASC"
        ))?;
        let rows = stmt.query_map(
            params![WorkflowRunStatus::Running.as_str()],
            Journal::parse_run_record,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Settles every node of a run that was running when the host stopped as unknown.
    ///
    /// The node was claimed for dispatch, so its action may have been performed, and nothing this
    /// host holds says whether it was. Each settlement commits its event, as any other does.
    /// Returns how many nodes were settled.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read or written.
    pub fn settle_interrupted_nodes(
        &self,
        run_id: WorkflowRunId,
        reason: &str,
        now_ms: u64,
    ) -> Result<usize> {
        self.write(|journal| {
            let mut stmt = journal
                .conn
                .prepare("SELECT node_id FROM node_receipts WHERE run_id = ?1 AND status = ?2")?;
            let interrupted = stmt
                .query_map(
                    params![run_id.to_string(), NodeStatus::Running.as_str()],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            let mut settled = 0;
            for node_id in &interrupted {
                if journal.settle_node(&NodeSettlement {
                    run_id,
                    node_id,
                    status: NodeStatus::Unknown,
                    output: None,
                    error: Some(reason),
                    produced: None,
                    at_ms: now_ms,
                })? {
                    settled += 1;
                }
            }
            Ok(settled)
        })
    }

    /// Reads the attention records the attention consumer has not acknowledged yet.
    ///
    /// The records outlive a restart, and nothing removes one before the attention consumer has
    /// passed it, so a host that stopped between a pause and its delivery still raises the item
    /// when it comes back.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be read, and a refusal naming the row when one
    /// cannot be understood.
    pub fn pending_attention(&self) -> Result<Vec<AttentionOutboxRecord>> {
        self.read(|journal| {
            let position = journal
                .consumer_position(ATTENTION_CONSUMER)?
                .unwrap_or_default();
            Ok(journal
                .events_after(position, ATTENTION_EVENTS, usize::MAX)?
                .iter()
                .filter_map(AttentionOutboxRecord::of)
                .collect())
        })
    }

    /// Returns where a consumer has read to, or `None` for one that never registered.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the row cannot be read.
    pub fn consumer_position(&self, consumer: &str) -> Result<Option<u64>> {
        self.read(|journal| journal.consumer_position(consumer))
    }

    /// Registers a consumer of the event types it reads, if it is not registered already.
    ///
    /// # Errors
    ///
    /// As [`Journal::register_consumer`].
    pub fn register_consumer(
        &self,
        consumer: &str,
        event_types: &[&str],
        now_ms: u64,
    ) -> Result<u64> {
        self.write(|journal| journal.register_consumer(consumer, event_types, now_ms))
    }

    /// Reads the events after `position` whose type is one of `event_types`, oldest first.
    ///
    /// # Errors
    ///
    /// As [`Journal::events_after`].
    pub fn events_after(
        &self,
        position: u64,
        event_types: &[&str],
        limit: usize,
    ) -> Result<Vec<JournalEvent>> {
        self.read(|journal| journal.events_after(position, event_types, limit))
    }

    /// Records that a consumer has acted on every event up to `position`.
    ///
    /// # Errors
    ///
    /// As [`Journal::advance_consumer`].
    pub fn acknowledge(&self, consumer: &str, position: u64) -> Result<()> {
        self.write(|journal| journal.advance_consumer(consumer, position))
    }

    /// Removes the events every consumer that reads them has passed.
    ///
    /// The rule is the consumer contract's: an event is removed only once every consumer
    /// registered for its type has acknowledged a position at or past it, and an event of a type
    /// no consumer is registered for is never removed. So an attention record waits in the stream
    /// for the attention state that has not registered yet, however far the trigger dispatcher
    /// has read. Returns how many events were removed.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the rows cannot be written.
    pub fn prune(&self) -> Result<usize> {
        self.write(|journal| {
            Ok(journal.conn.execute(
                "DELETE FROM outbox_events
                 WHERE EXISTS (
                     SELECT 1 FROM event_subscriptions s
                     WHERE s.event_type = outbox_events.event_type
                 )
                 AND outbox_id <= (
                     SELECT MIN(c.position) FROM event_consumers c
                     JOIN event_subscriptions s ON s.consumer = c.consumer
                     WHERE s.event_type = outbox_events.event_type
                 )",
                [],
            )?)
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
                    caller_grant: None,
                },
                1_000,
                |journal| {
                    journal.save_definition(&def, None, 1_000)?;
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
                    caller_grant: None,
                },
                1_000,
                |journal| {
                    journal.save_definition(&def, None, 1_000)?;
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
                    caller_grant: None,
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
                    caller_grant: None,
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
                    caller_grant: None,
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
