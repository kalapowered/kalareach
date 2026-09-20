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

use kr_protocol::automation::{
    WorkflowEnableParams, WorkflowEnableResult, WorkflowInstallParams, WorkflowInstallResult,
    WorkflowPauseParams, WorkflowPauseResult, WorkflowReadParams, WorkflowReadResult,
    WorkflowRunParams, WorkflowRunResult,
};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{CausalRootId, WorkflowRunId, WorkspaceId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

use crate::admission::AdmissionController;
use crate::causal::CausalContext;
use crate::definition::validate_definition;
use crate::engine::{ActionRunner, MockActionRunner, WorkflowEngine};
use crate::error::{AutomationError, Result};
use crate::source_workflow::{QuiescenceManager, QuiescenceReservation, SourceWorkflowCoordinator};
use crate::store::WorkflowStore;

/// The central automation service of an environment.
pub struct AutomationService {
    store: Arc<WorkflowStore>,
    admission: Mutex<AdmissionController>,
    engine: Arc<WorkflowEngine>,
    source_workflow: Arc<SourceWorkflowCoordinator>,
}

impl AutomationService {
    /// Opens the automation service with a database in the specified directory.
    pub fn open(
        runtime_dir: impl AsRef<Path>,
        runner: Option<Arc<dyn ActionRunner>>,
    ) -> Result<Self> {
        let store = Arc::new(WorkflowStore::open(runtime_dir)?);
        let action_runner = runner.unwrap_or_else(|| Arc::new(MockActionRunner::new()));
        let engine = Arc::new(WorkflowEngine::new(Arc::clone(&store), action_runner));
        let quiescence = Arc::new(QuiescenceManager::new());
        let source_workflow = Arc::new(SourceWorkflowCoordinator::new(quiescence));

        Ok(Self {
            store,
            admission: Mutex::new(AdmissionController::new()),
            engine,
            source_workflow,
        })
    }

    /// Creates an in-memory automation service for testing.
    pub fn in_memory(runner: Option<Arc<dyn ActionRunner>>) -> Result<Self> {
        let store = Arc::new(WorkflowStore::in_memory()?);
        let action_runner = runner.unwrap_or_else(|| Arc::new(MockActionRunner::new()));
        let engine = Arc::new(WorkflowEngine::new(Arc::clone(&store), action_runner));
        let quiescence = Arc::new(QuiescenceManager::new());
        let source_workflow = Arc::new(SourceWorkflowCoordinator::new(quiescence));

        Ok(Self {
            store,
            admission: Mutex::new(AdmissionController::new()),
            engine,
            source_workflow,
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

        if params.definition.workflow_id != params.workflow_id {
            return Err(AutomationError::InvalidArgument(
                "params.workflow_id does not match definition.workflow_id".to_owned(),
            ));
        }

        // Check revision monotonicity
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

        // Establish causal context
        let causal_ctx = match params.causal_parent.as_ref() {
            Some(parent_ref) => {
                // Descendant trigger
                let mut ctx = CausalContext::from_existing_root(
                    parent_ref.causal_root_id,
                    params.workflow_id,
                );
                ctx.depth = parent_ref.depth.get() + 1;
                ctx.parent = Some(parent_ref.clone());

                // Retrigger prevention: definition cannot retrigger on own descendants by default
                // Check if any ancestor was this workflow
                // The parent run can be queried to verify ancestor chain
                let runs = self.store.list_runs(Some(params.workflow_id))?;
                if runs
                    .iter()
                    .any(|r| r.causal_root_id == parent_ref.causal_root_id)
                {
                    return Err(AutomationError::SelfRetriggerRejected {
                        workflow_id: params.workflow_id,
                        root: parent_ref.causal_root_id,
                    });
                }
                ctx
            }
            None => {
                // New independent root
                CausalContext::new_root(params.workflow_id)
            }
        };

        // Check admission rates and concurrency
        let grant_id = def.grant_reference;
        {
            let mut adm = self.admission.lock().unwrap();
            adm.admit_run(params.workflow_id, grant_id, now_ms, None, None)?;
        }

        // Commit trigger, run, and budget reservation atomically
        let run_id = WorkflowRunId::new(crate::new_uuid());
        let _budget = match self.store.commit_trigger_and_run(
            run_id,
            &def,
            &params.event_id,
            &causal_ctx,
            now_ms,
        ) {
            Ok(b) => b,
            Err(e) => {
                // Release admission on reservation failure
                let mut adm = self.admission.lock().unwrap();
                adm.release_run(params.workflow_id);
                return Err(e);
            }
        };

        // Execute nodes
        let engine = Arc::clone(&self.engine);
        let status = engine
            .execute_run(run_id, &def, &causal_ctx, now_ms)
            .await?;

        // Release admission
        {
            let mut adm = self.admission.lock().unwrap();
            adm.release_run(params.workflow_id);
        }

        Ok(WorkflowRunResult {
            run_id,
            workflow_id: params.workflow_id,
            revision: params.revision,
            causal_root_id: causal_ctx.root_id,
            depth: U64::new(causal_ctx.depth),
            status,
        })
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
    /// Requires explicit management right (`ActionRight::AutomationManage`).
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

        let mut budget = self
            .store
            .get_budget(causal_root_id)?
            .ok_or_else(|| AutomationError::InvalidArgument("causal root not found".to_owned()))?;

        budget.rearm(now_ms);
        self.store.save_budget(&budget)?;
        Ok(())
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
