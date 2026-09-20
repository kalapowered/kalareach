//! The environment automation service.
//!
//! Owns workflow definitions, runs, causal budgets, and quiescence reservations.
//! Dispatches the five methods of the `Automation` method group:
//! - `workflow.install`
//! - `workflow.enable`
//! - `workflow.pause`
//! - `workflow.run`
//! - `workflow.read`

use std::path::Path;
use std::sync::{Arc, Mutex};

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_attention::{Engine as AttentionEngine, HostReading, Outcome};
use kr_protocol::attention::AttentionSource;
use kr_protocol::automation::{
    CausalParentRef, WorkflowDefinition, WorkflowEnableParams, WorkflowEnableResult,
    WorkflowInstallParams, WorkflowInstallResult, WorkflowPauseParams, WorkflowPauseResult,
    WorkflowReadParams, WorkflowReadResult, WorkflowRunParams, WorkflowRunResult,
};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{CausalRootId, PluginId, WorkflowRunId, WorkspaceId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

use crate::admission::AdmissionController;
use crate::causal::CausalContext;
use crate::definition::validate_definition;
use crate::engine::{ActionRunner, MockActionRunner, WorkflowEngine};
use crate::error::{AutomationError, Result};
use crate::source_workflow::{QuiescenceManager, QuiescenceReservation, SourceWorkflowCoordinator};
use crate::store::WorkflowStore;
use crate::{HostClock, SystemClock};

/// The identifier an exhausted causal chain raises its attention item about.
///
/// The subject is the causal root, so the attention engine's own de-duplication gives one item
/// per chain even if delivery is attempted more than once.
fn causal_limit_subject(root: CausalRootId) -> PluginId {
    PluginId::new(format!("automation.causal_budget.{root}"))
        .unwrap_or_else(|_| PluginId::new("automation.causal_budget").expect("a static identifier"))
}

/// The central automation service of an environment.
pub struct AutomationService {
    store: Arc<WorkflowStore>,
    admission: Mutex<AdmissionController>,
    engine: Arc<WorkflowEngine>,
    source_workflow: Arc<SourceWorkflowCoordinator>,
}

impl AutomationService {
    /// Opens the automation service on the workflow journal in `runtime_dir`.
    pub fn open(
        runtime_dir: impl AsRef<Path>,
        runner: Option<Arc<dyn ActionRunner>>,
    ) -> Result<Self> {
        Self::on_store(Arc::new(WorkflowStore::open(runtime_dir)?), runner, None)
    }

    /// Opens the automation service on the workflow journal in `runtime_dir`, reading `clock`.
    pub fn open_with_clock(
        runtime_dir: impl AsRef<Path>,
        runner: Option<Arc<dyn ActionRunner>>,
        clock: Arc<dyn HostClock>,
    ) -> Result<Self> {
        Self::on_store(
            Arc::new(WorkflowStore::open(runtime_dir)?),
            runner,
            Some(clock),
        )
    }

    /// Creates an automation service whose journal lives only in memory.
    pub fn in_memory(runner: Option<Arc<dyn ActionRunner>>) -> Result<Self> {
        Self::on_store(Arc::new(WorkflowStore::in_memory()?), runner, None)
    }

    /// Creates an automation service whose journal lives only in memory, reading `clock`.
    pub fn in_memory_with_clock(
        runner: Option<Arc<dyn ActionRunner>>,
        clock: Arc<dyn HostClock>,
    ) -> Result<Self> {
        Self::on_store(Arc::new(WorkflowStore::in_memory()?), runner, Some(clock))
    }

    fn on_store(
        store: Arc<WorkflowStore>,
        runner: Option<Arc<dyn ActionRunner>>,
        clock: Option<Arc<dyn HostClock>>,
    ) -> Result<Self> {
        let action_runner = runner.unwrap_or_else(|| Arc::new(MockActionRunner::new()));
        let clock = clock.unwrap_or_else(|| Arc::new(SystemClock));
        let engine = Arc::new(WorkflowEngine::with_clock(
            Arc::clone(&store),
            action_runner,
            clock,
        ));
        let quiescence = Arc::new(QuiescenceManager::new());

        Ok(Self {
            store,
            admission: Mutex::new(AdmissionController::new()),
            engine,
            source_workflow: Arc::new(SourceWorkflowCoordinator::new(quiescence)),
        })
    }

    /// Accessor for the store.
    #[must_use]
    pub fn store(&self) -> &Arc<WorkflowStore> {
        &self.store
    }

    /// Accessor for the source workflow coordinator.
    #[must_use]
    pub fn source_workflow(&self) -> &Arc<SourceWorkflowCoordinator> {
        &self.source_workflow
    }

    /// Installs a versioned workflow definition (`workflow.install`).
    ///
    /// Validates graph acyclicity, registered action kinds, absence of template code,
    /// and required broad shell grant for shell command nodes.
    pub fn install(
        &self,
        params: &WorkflowInstallParams,
        grant: Option<&Grant>,
        now_ms: u64,
    ) -> Result<WorkflowInstallResult> {
        // Validate definition
        validate_definition(&params.definition, grant)?;

        // The request and the document it carries must name the same workflow, the same
        // revision and the same grant. Anything else lets one revision be installed under
        // another's number, and every later reference names a revision by number.
        if params.definition.workflow_id != params.workflow_id {
            return Err(AutomationError::InvalidArgument(
                "the definition names a different workflow from the request".to_owned(),
            ));
        }
        if params.definition.revision != params.revision {
            return Err(AutomationError::RevisionMismatch {
                workflow_id: params.workflow_id,
                expected: params.revision.get(),
                found: params.definition.revision.get(),
            });
        }
        if params.definition.grant_reference != params.grant_reference {
            return Err(AutomationError::InvalidArgument(
                "the definition names a different grant from the request".to_owned(),
            ));
        }

        // A revision number only ever moves forward, and an installed revision is immutable:
        // the journal refuses a second insert of one that exists.
        if let Some(existing) = self.store.get_latest_definition(params.workflow_id)?
            && params.revision.get() <= existing.revision.get()
        {
            return Err(AutomationError::RevisionMismatch {
                workflow_id: params.workflow_id,
                expected: existing.revision.get() + 1,
                found: params.revision.get(),
            });
        }

        self.store.save_definition(&params.definition, now_ms)?;

        Ok(WorkflowInstallResult {
            workflow_id: params.workflow_id,
            revision: params.revision,
            installed_at_ms: TimestampMs::new(now_ms),
        })
    }

    /// Enables an installed workflow revision (`workflow.enable`).
    pub fn enable(
        &self,
        params: &WorkflowEnableParams,
        _now_ms: u64,
    ) -> Result<WorkflowEnableResult> {
        let def = self
            .store
            .get_definition(params.workflow_id, params.revision.get())?
            .ok_or(AutomationError::WorkflowNotFound(params.workflow_id))?;

        if def.revision != params.revision {
            return Err(AutomationError::RevisionMismatch {
                workflow_id: params.workflow_id,
                expected: params.revision.get(),
                found: def.revision.get(),
            });
        }

        self.store
            .set_enabled(params.workflow_id, params.revision.get(), true)?;

        Ok(WorkflowEnableResult {
            workflow_id: params.workflow_id,
            revision: params.revision,
            enabled: true,
        })
    }

    /// Pauses an installed workflow revision (`workflow.pause`).
    pub fn pause(&self, params: &WorkflowPauseParams, _now_ms: u64) -> Result<WorkflowPauseResult> {
        let def = self
            .store
            .get_definition(params.workflow_id, params.revision.get())?
            .ok_or(AutomationError::WorkflowNotFound(params.workflow_id))?;

        if def.revision != params.revision {
            return Err(AutomationError::RevisionMismatch {
                workflow_id: params.workflow_id,
                expected: params.revision.get(),
                found: def.revision.get(),
            });
        }

        self.store
            .set_paused(params.workflow_id, params.revision.get(), true)?;

        Ok(WorkflowPauseResult {
            workflow_id: params.workflow_id,
            revision: params.revision,
            paused: true,
        })
    }

    /// Starts a workflow run (`workflow.run`).
    ///
    /// Persists the run before dispatching its first node.
    /// Deduplicates by `(workflow_id, definition_revision, event_id)`.
    /// Enforces per-workflow concurrency and per-host/grant admission rates.
    /// Tracks causal root, depth, and parent, preventing retrigger on own descendants.
    pub async fn run(
        &self,
        params: &WorkflowRunParams,
        grant: Option<&Grant>,
        now_ms: u64,
    ) -> Result<WorkflowRunResult> {
        // Load exact revision
        let def = self
            .store
            .get_definition(params.workflow_id, params.revision.get())?
            .ok_or(AutomationError::WorkflowNotFound(params.workflow_id))?;

        if !def.enabled {
            return Err(AutomationError::WorkflowDisabled(params.workflow_id));
        }

        // Verify grant requirements against current grant if provided
        if grant.is_some() {
            validate_definition(&def, grant)?;
        }

        // Establish the causal context from the host's own records.
        let causal_ctx = match params.causal_parent.0.as_ref() {
            Some(parent_ref) => self.descendant_context(&def, parent_ref)?,
            // No parent means an external trigger, including an unauthenticated callback. The
            // host mints a root for it; nothing in the request can name one, so event content
            // cannot place a trigger inside an existing chain or start a new chain of its own
            // to escape one. Host-wide admission below is what bounds it.
            None => CausalContext::new_root(),
        };

        // Per-workflow concurrency, the per-grant rate and the host-wide rate, in that order.
        self.admission
            .lock()
            .expect("the admission controller")
            .admit_run(params.workflow_id, def.grant_reference, now_ms, None, None)?;

        // The trigger, the run, its deduplication key and the chain's reservation commit
        // together, so a run is durable before its first node dispatches and a reservation is
        // never made for a run that was not recorded.
        let run_id = WorkflowRunId::new(crate::new_uuid());
        let outcome =
            self.store
                .commit_trigger_and_run(run_id, &def, &params.event_id, &causal_ctx, now_ms);

        let status = match outcome {
            Ok(_) => self.engine.execute_run(run_id, &def, &causal_ctx).await,
            Err(error) => Err(error),
        };

        self.admission
            .lock()
            .expect("the admission controller")
            .release_run(params.workflow_id);

        Ok(WorkflowRunResult {
            run_id,
            workflow_id: params.workflow_id,
            revision: params.revision,
            causal_root_id: causal_ctx.root_id,
            depth: U64::new(causal_ctx.depth),
            status: status?,
        })
    }

    /// Derives a descendant's causal context from the parent run the host has on record.
    ///
    /// The caller names a parent run and a parent node. Everything else, the root, the depth
    /// and the budget generation, is read from this host's journal, so a caller cannot mint a
    /// fresh root by claiming one, reset the depth, or rejoin a rearmed budget with a stale run.
    fn descendant_context(
        &self,
        def: &WorkflowDefinition,
        parent_ref: &CausalParentRef,
    ) -> Result<CausalContext> {
        let parent = self
            .store
            .get_run_record(parent_ref.parent_run_id)?
            .ok_or(AutomationError::ParentRunNotFound(parent_ref.parent_run_id))?;

        if !self
            .store
            .node_receipt_exists(parent.run_id, &parent_ref.parent_node_id)?
        {
            return Err(AutomationError::ParentNodeNotFound {
                run_id: parent.run_id,
                node_id: parent_ref.parent_node_id.clone(),
            });
        }

        if parent_ref.causal_root_id != parent.causal_root_id {
            return Err(AutomationError::CausalRootMismatch {
                claimed: parent_ref.causal_root_id,
                actual: parent.causal_root_id,
            });
        }

        // A definition does not retrigger on its own descendants. Only a definition that was
        // reviewed and installed with explicit recurrence may, and even then the root stays the
        // parent's: recurrence buys another turn in the chain, not a fresh budget.
        if !def.explicit_recurrence
            && self
                .store
                .list_runs_by_root(parent.causal_root_id)?
                .iter()
                .any(|run| run.workflow_id == def.workflow_id)
        {
            return Err(AutomationError::SelfRetriggerRejected {
                workflow_id: def.workflow_id,
                root: parent.causal_root_id,
            });
        }

        Ok(CausalContext::descendant_of(
            &parent,
            &parent_ref.parent_node_id,
        ))
    }

    /// Reads definitions, runs, node receipts, and remaining causal budget (`workflow.read`).
    pub fn read(&self, params: &WorkflowReadParams, now_ms: u64) -> Result<WorkflowReadResult> {
        let wf_filter = params.workflow_id.0;
        let definitions = self.store.list_definitions(wf_filter)?;
        let runs = self.store.list_runs(wf_filter)?;

        let mut node_receipts = Vec::new();
        if let Some(run_id) = params.run_id.0 {
            node_receipts = self.store.list_node_receipts(run_id)?;
        }

        let remaining_causal_budget = if let Some(root_id) = params.causal_root_id.0 {
            self.store
                .get_budget(root_id)?
                .map(|b| b.to_summary(now_ms))
                .into()
        } else {
            Nullable::null()
        };

        Ok(WorkflowReadResult {
            definitions,
            runs,
            node_receipts,
            remaining_causal_budget,
        })
    }

    /// Authorised rearm establishing a new budget for an exhausted causal chain.
    ///
    /// Requires explicit management right (`ActionRight::AutomationManage`). A replayed or late
    /// event reaches [`Self::run`] without this right and cannot rearm anything; a descendant of
    /// a run from the old generation is refused afterwards by the generation check.
    pub fn rearm(
        &self,
        causal_root_id: CausalRootId,
        has_manage_right: bool,
        now_ms: u64,
    ) -> Result<()> {
        if !has_manage_right {
            return Err(AutomationError::PermissionDenied(
                "rearm requires automation.manage right".to_owned(),
            ));
        }

        self.store.rearm_budget(causal_root_id, now_ms)?;
        Ok(())
    }

    /// Delivers the attention items the journal owes to the host's attention engine.
    ///
    /// An exhausted chain commits its attention record with the pause that caused it, and this
    /// hands that record to the engine and settles it. Both steps are idempotent: an
    /// undelivered record survives a restart, and the engine de-duplicates by causal root.
    ///
    /// Returns how many items the engine raised.
    pub fn deliver_attention(
        &self,
        attention: &mut AttentionEngine,
        reading: HostReading,
        now_ms: u64,
    ) -> Result<usize> {
        let pending = self.store.pending_attention()?;
        if pending.is_empty() {
            return Ok(0);
        }

        // The engine may be shared with other producers on this source, so the events continue
        // from the sequence it has already consumed rather than from the journal's own row
        // numbers. Exactly-once delivery comes from settling the outbox, not from the cursor.
        let mut sequence = attention
            .consumed(AttentionSource::Semantic)
            .unwrap_or_default();

        let mut raised = 0;
        let mut delivered = Vec::with_capacity(pending.len());
        for record in &pending {
            sequence += 1;
            let event = SourceEvent::new(
                EventCursor::new(AttentionSource::Semantic, sequence),
                TimestampMs::new(record.created_at_ms),
                EventKind::AdapterFailed {
                    plugin_id: causal_limit_subject(record.causal_root_id),
                    session_id: None,
                    detail: record.reason.clone(),
                },
            );
            raised += attention
                .apply(&event, reading)
                .iter()
                .filter(|outcome| matches!(outcome, Outcome::Raised { .. }))
                .count();
            delivered.push(record.outbox_id);
        }

        self.store.settle_attention(&delivered, now_ms)?;
        Ok(raised)
    }

    /// Reserves a workspace for quiesced capture (closing T-029 residual 2).
    pub fn reserve_quiescence(
        &self,
        workspace_id: WorkspaceId,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<QuiescenceReservation> {
        self.source_workflow
            .quiescence()
            .reserve(workspace_id, timeout_ms, now_ms)
    }

    /// Releases a quiescence reservation.
    pub fn release_quiescence(&self, workspace_id: WorkspaceId, reservation_id: Uuid) -> bool {
        self.source_workflow
            .quiescence()
            .release(workspace_id, reservation_id)
    }
}
