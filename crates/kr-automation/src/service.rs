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
use kr_attention::{Attention, HostReading, Outcome};
use kr_protocol::attention::AttentionSource;
use kr_protocol::automation::{
    CausalParentRef, WorkflowDefinition, WorkflowEnableParams, WorkflowEnableResult,
    WorkflowInstallParams, WorkflowInstallResult, WorkflowPauseParams, WorkflowPauseResult,
    WorkflowReadParams, WorkflowReadResult, WorkflowRunParams, WorkflowRunResult,
};
use kr_protocol::ids::{CausalRootId, PluginId, WorkflowId, WorkflowRunId, WorkspaceId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

use crate::admission::AdmissionController;
use crate::authority::{self, AuthoritySource};
use crate::causal::CausalContext;
use crate::definition::validate_definition;
use crate::engine::{ActionRunner, WorkflowEngine};
use crate::error::{AutomationError, Result};
use crate::source_workflow::{QuiescenceManager, QuiescenceReservation, SourceWorkflowCoordinator};
use crate::store::{AttentionSubject, InstalledDefinition, WorkflowStore};
use crate::{HostClock, SystemClock};

/// The identifier an attention record is raised about.
///
/// The subject is the causal root or the workflow, so the attention state's own key is one per
/// chain or one per workflow however many refusals the same condition produced.
fn attention_subject(subject: AttentionSubject) -> PluginId {
    PluginId::new(subject.to_string())
        .unwrap_or_else(|_| PluginId::new("automation").expect("a static identifier"))
}

/// Holds one run's place in the per-workflow concurrency allowance until the run ends.
///
/// The release happens on drop, so a run that returns early, fails, or has its future cancelled
/// gives its place back. A permit that only released on the success path would leak the
/// allowance a few cancellations at a time until the workflow could not run at all.
struct RunPermit<'a> {
    admission: &'a Mutex<AdmissionController>,
    workflow_id: WorkflowId,
}

impl Drop for RunPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut admission) = self.admission.lock() {
            admission.release_run(self.workflow_id);
        }
    }
}

/// The central automation service of an environment.
pub struct AutomationService {
    store: Arc<WorkflowStore>,
    admission: Mutex<AdmissionController>,
    authority: Arc<dyn AuthoritySource>,
    engine: Arc<WorkflowEngine>,
    source_workflow: Arc<SourceWorkflowCoordinator>,
}

impl AutomationService {
    /// Opens the automation service on the workflow journal in `state_dir`.
    ///
    /// `runner` is what actually carries out an action node. There is no default: a service
    /// with nothing behind its action kinds would write success receipts for work nobody did,
    /// and a later node, review or deployment would read them as proof.
    ///
    /// `authority` is where the grant a definition names is read from. There is no default here
    /// either: a service that believed whatever grant a request carried would let a caller
    /// describe authority it does not hold.
    pub fn open(
        state_dir: impl AsRef<Path>,
        runner: Arc<dyn ActionRunner>,
        authority: Arc<dyn AuthoritySource>,
    ) -> Result<Self> {
        Self::on_store(
            Arc::new(WorkflowStore::open(state_dir)?),
            runner,
            authority,
            Arc::new(SystemClock),
        )
    }

    /// Opens the automation service on the workflow journal in `state_dir`, reading `clock`.
    pub fn open_with_clock(
        state_dir: impl AsRef<Path>,
        runner: Arc<dyn ActionRunner>,
        authority: Arc<dyn AuthoritySource>,
        clock: Arc<dyn HostClock>,
    ) -> Result<Self> {
        Self::on_store(
            Arc::new(WorkflowStore::open(state_dir)?),
            runner,
            authority,
            clock,
        )
    }

    /// Creates an automation service whose journal lives only in memory, reading `clock`.
    pub fn in_memory_with_clock(
        runner: Arc<dyn ActionRunner>,
        authority: Arc<dyn AuthoritySource>,
        clock: Arc<dyn HostClock>,
    ) -> Result<Self> {
        Self::on_store(
            Arc::new(WorkflowStore::in_memory()?),
            runner,
            authority,
            clock,
        )
    }

    fn on_store(
        store: Arc<WorkflowStore>,
        runner: Arc<dyn ActionRunner>,
        authority: Arc<dyn AuthoritySource>,
        clock: Arc<dyn HostClock>,
    ) -> Result<Self> {
        let engine = Arc::new(WorkflowEngine::with_clock(
            Arc::clone(&store),
            runner,
            Arc::clone(&authority),
            clock,
        ));
        let quiescence = Arc::new(QuiescenceManager::new());

        Ok(Self {
            store,
            admission: Mutex::new(AdmissionController::new()),
            authority,
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
    /// Validates graph acyclicity, registered action kinds, absence of template code, and the
    /// grant the definition names: it is read from this host's own store, it has to admit every
    /// node's effect, and a shell node has to be covered by a broad shell grant that admits the
    /// environment it declares. A definition nobody could ever run is refused here rather than
    /// half way through its first run.
    pub fn install(
        &self,
        params: &WorkflowInstallParams,
        now_ms: u64,
    ) -> Result<WorkflowInstallResult> {
        let grant = self
            .authority
            .grant(params.definition.grant_reference, now_ms)?;
        validate_definition(&params.definition, &grant)?;
        authority::check_definition(&grant, &params.definition)?;

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
            && params.revision.get() <= existing.definition.revision.get()
        {
            return Err(AutomationError::RevisionMismatch {
                workflow_id: params.workflow_id,
                expected: existing.definition.revision.get() + 1,
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
    ///
    /// Enabling clears a pause, whether the pause came from `workflow.pause` or from a breached
    /// per-workflow limit, so the same authorised method that starts a revision is the one that
    /// restarts it.
    pub fn enable(
        &self,
        params: &WorkflowEnableParams,
        now_ms: u64,
    ) -> Result<WorkflowEnableResult> {
        self.installed(params.workflow_id, params.revision)?;
        self.store
            .set_enabled(params.workflow_id, params.revision.get(), true)?;
        self.store
            .resume_workflow(params.workflow_id, params.revision.get(), now_ms)?;

        Ok(WorkflowEnableResult {
            workflow_id: params.workflow_id,
            revision: params.revision,
            enabled: true,
        })
    }

    /// Pauses an installed workflow revision (`workflow.pause`).
    pub fn pause(&self, params: &WorkflowPauseParams, _now_ms: u64) -> Result<WorkflowPauseResult> {
        self.installed(params.workflow_id, params.revision)?;
        self.store
            .set_paused(params.workflow_id, params.revision.get(), true)?;

        Ok(WorkflowPauseResult {
            workflow_id: params.workflow_id,
            revision: params.revision,
            paused: true,
        })
    }

    /// Loads the exact revision a request names, with the journal's state for it.
    fn installed(&self, workflow_id: WorkflowId, revision: U64) -> Result<InstalledDefinition> {
        let installed = self
            .store
            .get_definition(workflow_id, revision.get())?
            .ok_or(AutomationError::WorkflowNotFound(workflow_id))?;

        if installed.definition.revision != revision {
            return Err(AutomationError::RevisionMismatch {
                workflow_id,
                expected: revision.get(),
                found: installed.definition.revision.get(),
            });
        }
        Ok(installed)
    }

    /// Starts a workflow run (`workflow.run`).
    ///
    /// Persists the run before dispatching its first node.
    /// Deduplicates by `(workflow_id, definition_revision, event_id)`.
    /// Enforces per-workflow concurrency and per-host/grant admission rates.
    /// Tracks causal root, depth, and parent, preventing retrigger on own descendants.
    pub async fn run(&self, params: &WorkflowRunParams, now_ms: u64) -> Result<WorkflowRunResult> {
        let installed = self.installed(params.workflow_id, params.revision)?;
        if !installed.enabled {
            return Err(AutomationError::WorkflowDisabled(params.workflow_id));
        }
        if installed.paused {
            return Err(AutomationError::WorkflowPaused(params.workflow_id));
        }
        let def = installed.definition;

        // The grant is read again, from this host's store, and checked against the definition as
        // installed. It can have expired, been revoked or been narrowed since the definition was
        // installed, and the engine reads it once more before each node it dispatches.
        let grant = self.authority.grant(def.grant_reference, now_ms)?;
        validate_definition(&def, &grant)?;
        authority::check_definition(&grant, &def)?;

        // Establish the causal context from the host's own records.
        let causal_ctx = match params.causal_parent.0.as_ref() {
            Some(parent_ref) => self.descendant_context(&def, parent_ref)?,
            // No parent means an external trigger, including an unauthenticated callback. The
            // host mints a root for it; nothing in the request can name one, so event content
            // cannot place a trigger inside an existing chain or start a new chain of its own
            // to escape one. Host-wide admission below is what bounds it.
            None => CausalContext::new_root(),
        };

        // A trigger this journal has already recorded is the same trigger arriving twice. It is
        // answered before admission, because a redelivery is not new load and must not be able
        // to spend an allowance or pause the workflow. The transaction below still holds the
        // line for two copies that arrive at once.
        if self.store.trigger_is_recorded(
            params.workflow_id,
            params.revision.get(),
            &params.event_id,
        )? {
            return Err(AutomationError::DuplicateTrigger {
                workflow_id: params.workflow_id,
                revision: params.revision.get(),
                event_id: params.event_id.clone(),
            });
        }

        // Per-workflow concurrency, the per-grant rate and the host-wide rate, in that order.
        // A breach pauses the revision and records the attention item that pause owes, so the
        // workflow stops rather than being refused one request at a time.
        let admitted = self
            .admission
            .lock()
            .expect("the admission controller")
            .admit_run(params.workflow_id, def.grant_reference, now_ms, None, None);
        if let Err(breach) = admitted {
            // Two copies of one event can both reach this point. The one that lost is still a
            // duplicate, not load, so the journal is asked again before the breach is allowed
            // to pause anything.
            if self.store.trigger_is_recorded(
                params.workflow_id,
                params.revision.get(),
                &params.event_id,
            )? {
                return Err(AutomationError::DuplicateTrigger {
                    workflow_id: params.workflow_id,
                    revision: params.revision.get(),
                    event_id: params.event_id.clone(),
                });
            }
            self.store.pause_workflow_on_breach(
                params.workflow_id,
                params.revision.get(),
                &breach.to_string(),
                now_ms,
            )?;
            return Err(breach);
        }
        let _permit = RunPermit {
            admission: &self.admission,
            workflow_id: params.workflow_id,
        };

        // The trigger, the run, its deduplication key and the chain's reservation commit
        // together, so a run is durable before its first node dispatches and a reservation is
        // never made for a run that was not recorded.
        let run_id = WorkflowRunId::new(crate::new_uuid());
        let outcome =
            self.store
                .commit_trigger_and_run(run_id, &def, &params.event_id, &causal_ctx, now_ms);

        let status = match outcome {
            Ok(_) => self.engine.execute_run(run_id, &def, &causal_ctx).await?,
            Err(error) => return Err(error),
        };

        Ok(WorkflowRunResult {
            run_id,
            workflow_id: params.workflow_id,
            revision: params.revision,
            causal_root_id: causal_ctx.root_id,
            depth: U64::new(causal_ctx.depth),
            status,
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
        let mut definitions = self.store.list_definitions(wf_filter)?;
        let mut runs = self.store.list_runs(wf_filter)?;

        // A request that names a revision is asking about that revision, not about every one
        // ever installed under the same workflow identifier.
        if let Some(revision) = params.revision.0 {
            definitions.retain(|definition| definition.revision == revision);
            runs.retain(|run| run.revision == revision);
        }

        let mut node_receipts = Vec::new();
        if let Some(run_id) = params.run_id.0 {
            // A run belongs to one workflow, and a reader that named another is not shown it.
            let record = self.store.get_run_record(run_id)?;
            let belongs = record.as_ref().is_some_and(|record| {
                wf_filter.is_none_or(|id| record.workflow_id == id)
                    && params
                        .revision
                        .0
                        .is_none_or(|rev| record.revision == rev.get())
            });
            if belongs {
                node_receipts = self.store.list_node_receipts(run_id)?;
            }
        }

        // A budget is answered only for a root the rest of this request actually covers, so a
        // reader asking about one workflow is not handed another chain's remaining allowance.
        let remaining_causal_budget = match params.causal_root_id.0 {
            Some(root_id)
                if runs.iter().any(|run| {
                    run.causal_root_id == root_id
                        && params.run_id.0.is_none_or(|named| run.run_id == named)
                }) =>
            {
                self.store
                    .get_budget(root_id)?
                    .map(|budget| budget.to_summary(now_ms))
                    .into()
            }
            _ => Nullable::null(),
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

    /// Delivers the attention items the journal owes to the host's attention state.
    ///
    /// The record is durable before this runs and is settled only after `attention` has written
    /// its own state, so a host that stops in between raises the item when it comes back. Each
    /// record is delivered under its own outbox row number, which never changes, so a retry
    /// after a failed settle replays a sequence the attention state has already consumed and
    /// changes nothing.
    ///
    /// `source` is the retained source the host has given this journal. It must not be shared
    /// with another producer, because the sequence numbers here are the journal's row numbers.
    ///
    /// Returns how many items were newly raised.
    pub fn deliver_attention(
        &self,
        attention: &mut Attention,
        source: AttentionSource,
        reading: HostReading,
        now_ms: u64,
    ) -> Result<usize> {
        let pending = self.store.pending_attention()?;
        if pending.is_empty() {
            return Ok(0);
        }

        let mut raised = 0;
        for record in &pending {
            let sequence = u64::try_from(record.outbox_id).map_err(|_| {
                AutomationError::InvalidArgument("an outbox row number went negative".to_owned())
            })?;
            let event = SourceEvent::new(
                EventCursor::new(source, sequence),
                TimestampMs::new(record.created_at_ms),
                if record.ends_condition {
                    EventKind::AdapterRecovered {
                        plugin_id: attention_subject(record.subject),
                    }
                } else {
                    EventKind::AdapterFailed {
                        plugin_id: attention_subject(record.subject),
                        session_id: None,
                        detail: record.reason.clone(),
                    }
                },
            );
            raised += attention
                .apply(&event, reading)?
                .iter()
                .filter(|outcome| matches!(outcome, Outcome::Raised { .. }))
                .count();
            self.store.settle_attention(&[record.outbox_id], now_ms)?;
        }

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
