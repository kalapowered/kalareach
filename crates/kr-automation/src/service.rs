//! The environment automation service.
//!
//! Owns workflow definitions, runs, causal budgets, and quiescence reservations.
//! Dispatches the five methods of the `Automation` method group:
//! - `workflow.install`
//! - `workflow.enable`
//! - `workflow.pause`
//! - `workflow.run`
//! - `workflow.read`
//!
//! The four mutations are actions. Each one is performed inside one journal transaction together
//! with the record of what it came to ([`WorkflowStore::act`]), and a repeat of an action is
//! answered from that record ([`AutomationService::answered`]) rather than performed again.
//!
//! # Where a run comes from
//!
//! A run starts in one of three ways, and in none of them does anything a caller sends decide the
//! run's place in a causal chain:
//!
//! * **An external trigger.** `workflow.run` is always one. The host mints a new causal root, and
//!   host-wide admission is what bounds how many of them there are.
//! * **A derived trigger.** A node that succeeds commits, with its outcome, an event whose type its
//!   action kind fixes. [`AutomationService::admit_triggers`] reads those events under its own
//!   cursor and starts a run of every enabled workflow whose trigger names that type. The run's
//!   root, depth, generation and parent are the journal's record of the node that produced the
//!   event, and the trigger's identifier is that node's action identifier in a namespace no
//!   external trigger may use.
//! * **Recovery.** [`AutomationService::recover`] picks up the runs a stopped host left unfinished.
//!   A node that was running when the host stopped may have been dispatched, so its outcome is
//!   unknown and its dependants pause; only nodes that were never dispatched, and whose grant
//!   still admits them, go on.

use std::path::Path;
use std::sync::{Arc, Mutex};

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_attention::{Attention, HostReading, Outcome};
use kr_protocol::attention::AttentionSource;
use kr_protocol::automation::{
    NodeStatus, WorkflowDefinition, WorkflowEnableParams, WorkflowEnableResult,
    WorkflowInstallParams, WorkflowInstallResult, WorkflowPauseParams, WorkflowPauseResult,
    WorkflowReadParams, WorkflowReadResult, WorkflowRunParams, WorkflowRunResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    CausalRootId, EnvironmentId, PluginId, WorkflowId, WorkflowRunId, WorkspaceId,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

use crate::Host;
use crate::admission::AdmissionController;
use crate::authority::{self, AuthoritySource};
use crate::causal::CausalContext;
use crate::definition::validate_definition;
use crate::engine::WorkflowEngine;
use crate::error::{AutomationError, Result};
use crate::source_workflow::{QuiescenceManager, QuiescenceReservation, SourceWorkflowCoordinator};
use crate::store::{
    ATTENTION_CONSUMER, ATTENTION_EVENTS, Acted, ActionKey, ActionRecord, AttentionSubject,
    EVENT_NODE_SETTLED, InstalledDefinition, Journal, JournalEvent, JournalEventKind,
    StoredRunRecord, Submitted, WorkflowStore,
};

/// The name the trigger dispatcher registers under as a consumer of the journal's events.
pub const TRIGGER_CONSUMER: &str = "workflow.triggers";

/// The prefix every derived trigger's identifier carries, and no external trigger's may.
///
/// A derived trigger is named by the action identifier of the node that produced it, and node
/// receipts show those identifiers before the node settles. Without a namespace of its own, a
/// caller could submit an external trigger under that identifier first and take the derived
/// trigger's place in the deduplication record, turning the expected descendant into a run with
/// a fresh root.
pub const DERIVED_TRIGGER_PREFIX: &str = "node:";

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
#[derive(Debug)]
struct RunPermit {
    admission: Arc<Mutex<AdmissionController>>,
    workflow_id: WorkflowId,
}

impl Drop for RunPermit {
    fn drop(&mut self) {
        self.admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_run(self.workflow_id);
    }
}

/// A run the journal has admitted and recorded, ready for its first node.
///
/// It holds the run's place in its workflow's concurrency allowance until it is executed and
/// dropped, so a host that admits a run and hands it to a task of its own keeps the allowance
/// honest.
#[derive(Debug)]
pub struct StartedRun {
    run_id: WorkflowRunId,
    definition: WorkflowDefinition,
    causal: CausalContext,
    _permit: RunPermit,
}

impl StartedRun {
    /// The run.
    #[must_use]
    pub const fn run_id(&self) -> WorkflowRunId {
        self.run_id
    }

    /// The chain the run belongs to.
    #[must_use]
    pub const fn causal(&self) -> &CausalContext {
        &self.causal
    }
}

/// What one derived trigger came to for one workflow whose trigger it matched.
#[derive(Debug)]
pub struct TriggerDecision {
    /// The position of the event that produced the trigger.
    pub event_sequence: u64,
    /// The workflow it matched.
    pub workflow_id: WorkflowId,
    /// The revision it matched.
    pub revision: u64,
    /// The run it started, or the refusal that stopped it.
    pub outcome: std::result::Result<WorkflowRunId, AutomationError>,
}

/// What one pass of the trigger dispatcher admitted.
///
/// A pass that stopped part way still hands back every run it committed before it stopped. Each
/// event commits on its own, so those runs are in the journal whatever happened to the next one,
/// and a host that dropped them would leave them waiting until its next restart.
#[derive(Debug, Default)]
pub struct AdmittedTriggers {
    /// Every decision the pass took, one per workflow a trigger matched.
    pub decisions: Vec<TriggerDecision>,
    /// The runs it started, for the host to execute.
    pub started: Vec<StartedRun>,
    /// Why the pass stopped before it reached the end of the stream, when it did: a grant store
    /// that could not be read or a journal that could not be written. The event it stopped at is
    /// still unread and is decided again on the next pass.
    pub stopped: Option<AutomationError>,
}

/// What an earlier submission of an action came to, as its method answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A `workflow.install` that was performed.
    Installed(WorkflowInstallResult),
    /// A `workflow.enable` that was performed.
    Enabled(WorkflowEnableResult),
    /// A `workflow.pause` that was performed.
    Paused(WorkflowPauseResult),
    /// A `workflow.run` that started a run, as that run stands now.
    Ran(WorkflowRunResult),
}

/// The central automation service of an environment.
pub struct AutomationService {
    store: Arc<WorkflowStore>,
    admission: Arc<Mutex<AdmissionController>>,
    authority: Arc<dyn AuthoritySource>,
    environment_id: EnvironmentId,
    engine: Arc<WorkflowEngine>,
    source_workflow: Arc<SourceWorkflowCoordinator>,
    events: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for AutomationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AutomationService")
            .field("store", &self.store)
            .field("environment_id", &self.environment_id)
            .finish_non_exhaustive()
    }
}

impl AutomationService {
    /// Opens the automation service on the workflow journal in `state_dir`, for `host`.
    ///
    /// # Errors
    ///
    /// Returns the journal's refusal when it cannot be opened.
    pub fn open(state_dir: impl AsRef<Path>, host: Host) -> Result<Self> {
        Ok(Self::on_store(
            Arc::new(WorkflowStore::open(state_dir)?),
            host,
        ))
    }

    /// Creates an automation service whose journal lives only in memory, for `host`.
    ///
    /// # Errors
    ///
    /// Returns the journal's refusal when its schema cannot be created.
    pub fn in_memory(host: Host) -> Result<Self> {
        Ok(Self::on_store(Arc::new(WorkflowStore::in_memory()?), host))
    }

    fn on_store(store: Arc<WorkflowStore>, host: Host) -> Self {
        let environment_id = host.environment_id;
        let authority = Arc::clone(&host.authority);
        let engine = Arc::new(WorkflowEngine::new(Arc::clone(&store), host));
        let quiescence = Arc::new(QuiescenceManager::new());

        Self {
            store,
            admission: Arc::new(Mutex::new(AdmissionController::new())),
            authority,
            environment_id,
            engine,
            source_workflow: Arc::new(SourceWorkflowCoordinator::new(quiescence)),
            events: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Accessor for the store.
    #[must_use]
    pub fn store(&self) -> &Arc<WorkflowStore> {
        &self.store
    }

    /// Accessor for the engine.
    #[must_use]
    pub fn engine(&self) -> &Arc<WorkflowEngine> {
        &self.engine
    }

    /// Accessor for the source workflow coordinator.
    #[must_use]
    pub fn source_workflow(&self) -> &Arc<SourceWorkflowCoordinator> {
        &self.source_workflow
    }

    /// Woken each time a run this service executed has stopped, which is when its nodes' events
    /// are all in the journal.
    ///
    /// A host that runs the trigger dispatcher waits on this, as well as on a timer of its own for
    /// anything a wake-up did not cover.
    #[must_use]
    pub fn events(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.events)
    }

    /// Installs a versioned workflow definition (`workflow.install`).
    ///
    /// Validates graph acyclicity, registered action kinds, absence of template code, and the
    /// grant the definition names: it is read from this host's own store, it has to admit every
    /// node's effect in the environment this host serves, and a shell node has to be covered by a
    /// broad shell grant that admits the environment it declares. A definition nobody could ever
    /// run is refused here rather than half way through its first run.
    ///
    /// The installation and the record of the action commit together, and a repeat of the action
    /// is answered from that record.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, the one an earlier submission of the same action
    /// was given, or a lapsed admission.
    pub fn install(
        &self,
        params: &WorkflowInstallParams,
        submitted: &Submitted<'_>,
        now_ms: u64,
    ) -> Result<WorkflowInstallResult> {
        let acted = self.store.act(submitted, now_ms, |journal| {
            let result = self.install_in(journal, params, now_ms)?;
            Ok((ActionRecord::done(&result)?, result))
        })?;
        performed_or_recorded(acted)
    }

    fn install_in(
        &self,
        journal: &Journal<'_>,
        params: &WorkflowInstallParams,
        now_ms: u64,
    ) -> Result<WorkflowInstallResult> {
        let grant = self
            .authority
            .grant(params.definition.grant_reference, now_ms)?;
        validate_definition(&params.definition, &grant)?;
        authority::check_definition(&grant, &params.definition, self.environment_id)?;

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
        if let Some(existing) = journal.latest_definition(params.workflow_id)?
            && params.revision.get() <= existing.definition.revision.get()
        {
            return Err(AutomationError::RevisionMismatch {
                workflow_id: params.workflow_id,
                expected: existing.definition.revision.get() + 1,
                found: params.revision.get(),
            });
        }

        journal.save_definition(&params.definition, now_ms)?;

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
    /// restarts it. The change and the record of the action commit together, so a replayed
    /// enable is answered from its record and cannot undo a pause decided after it.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, the one an earlier submission of the same action
    /// was given, or a lapsed admission.
    pub fn enable(
        &self,
        params: &WorkflowEnableParams,
        submitted: &Submitted<'_>,
        now_ms: u64,
    ) -> Result<WorkflowEnableResult> {
        let acted = self.store.act(submitted, now_ms, |journal| {
            installed(journal, params.workflow_id, params.revision)?;
            journal.set_enabled(params.workflow_id, params.revision.get(), true)?;
            journal.resume_workflow(params.workflow_id, params.revision.get(), now_ms)?;
            let result = WorkflowEnableResult {
                workflow_id: params.workflow_id,
                revision: params.revision,
                enabled: true,
            };
            Ok((ActionRecord::done(&result)?, result))
        })?;
        performed_or_recorded(acted)
    }

    /// Pauses an installed workflow revision (`workflow.pause`).
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, the one an earlier submission of the same action
    /// was given, or a lapsed admission.
    pub fn pause(
        &self,
        params: &WorkflowPauseParams,
        submitted: &Submitted<'_>,
        now_ms: u64,
    ) -> Result<WorkflowPauseResult> {
        let acted = self.store.act(submitted, now_ms, |journal| {
            installed(journal, params.workflow_id, params.revision)?;
            journal.set_paused(params.workflow_id, params.revision.get(), true)?;
            let result = WorkflowPauseResult {
                workflow_id: params.workflow_id,
                revision: params.revision,
                paused: true,
            };
            Ok((ActionRecord::done(&result)?, result))
        })?;
        performed_or_recorded(acted)
    }

    /// Starts a workflow run (`workflow.run`).
    ///
    /// The run is an external trigger: the host mints its causal root, and nothing in the
    /// request can place it inside a chain. It is admitted in one journal transaction: the record
    /// of an earlier submission of the same action is looked for, the trigger is deduplicated by
    /// `(workflow_id, definition_revision, event_id)` before anything is spent, per-workflow
    /// concurrency and the per-grant and host-wide rates are applied, and the trigger, the run,
    /// its node receipts, the chain's reservation and the record of the action commit together.
    /// The run is therefore durable before its first node dispatches, and a repeat of the action
    /// is answered with where that run stands now rather than starting a second one.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, the one an earlier submission of the same action
    /// was given, a lapsed admission, or the refusal that stopped the run.
    pub async fn run(
        &self,
        params: &WorkflowRunParams,
        submitted: &Submitted<'_>,
        now_ms: u64,
    ) -> Result<WorkflowRunResult> {
        let acted = self.store.act(submitted, now_ms, |journal| {
            let started = self.admit_run(journal, params, now_ms)?;
            Ok((
                ActionRecord::Started {
                    run_id: started.run_id,
                },
                started,
            ))
        })?;
        match acted {
            Acted::Performed(started) => self.execute(started).await,
            Acted::Answered(record) => self.ran(record),
        }
    }

    /// Executes a run the journal has admitted, and wakes whoever dispatches the triggers its
    /// nodes produced.
    ///
    /// # Errors
    ///
    /// Returns the refusal that stopped the run, which is recorded as its pause.
    pub async fn execute(&self, started: StartedRun) -> Result<WorkflowRunResult> {
        let outcome = self
            .engine
            .execute_run(started.run_id, &started.definition, &started.causal)
            .await;
        self.events.notify_one();
        Ok(WorkflowRunResult {
            run_id: started.run_id,
            workflow_id: started.definition.workflow_id,
            revision: started.definition.revision,
            causal_root_id: started.causal.root_id,
            depth: U64::new(started.causal.depth),
            status: outcome?,
        })
    }

    /// Decides one external trigger, inside the journal transaction that records it.
    fn admit_run(
        &self,
        journal: &Journal<'_>,
        params: &WorkflowRunParams,
        now_ms: u64,
    ) -> Result<StartedRun> {
        let installed = installed(journal, params.workflow_id, params.revision)?;
        if !installed.enabled {
            return Err(AutomationError::WorkflowDisabled(params.workflow_id));
        }
        if installed.paused {
            return Err(AutomationError::WorkflowPaused(params.workflow_id));
        }
        if params.event_id.starts_with(DERIVED_TRIGGER_PREFIX) {
            return Err(AutomationError::InvalidArgument(format!(
                "an external trigger cannot use an event identifier beginning with \
                 {DERIVED_TRIGGER_PREFIX}, which this host keeps for the triggers its own nodes \
                 produce"
            )));
        }
        // An external trigger, including an unauthenticated callback. The host mints its root;
        // nothing in the request can name one, so event content cannot place a trigger inside an
        // existing chain or lift one out of it. Host-wide admission is what bounds it.
        self.admit(
            journal,
            &installed.definition,
            &params.event_id,
            CausalContext::new_root(),
            now_ms,
        )
    }

    /// Admits one run of `definition` for one trigger, inside the caller's transaction.
    ///
    /// The grant is read again, from this host's store, and checked against the definition as
    /// installed: it can have expired, been revoked or been narrowed since, and the engine reads
    /// it once more before each node it dispatches. A trigger this journal has already recorded
    /// is the same trigger arriving twice; it is answered before admission, because a redelivery
    /// is not new load and must not spend an allowance or pause the workflow, and two copies of
    /// one event that arrive at once are serialised by the transaction.
    fn admit(
        &self,
        journal: &Journal<'_>,
        definition: &WorkflowDefinition,
        event_id: &str,
        causal: CausalContext,
        now_ms: u64,
    ) -> Result<StartedRun> {
        let grant = self.authority.grant(definition.grant_reference, now_ms)?;
        validate_definition(definition, &grant)?;
        authority::check_definition(&grant, definition, self.environment_id)?;

        if journal.trigger_is_recorded(
            definition.workflow_id,
            definition.revision.get(),
            event_id,
        )? {
            return Err(AutomationError::DuplicateTrigger {
                workflow_id: definition.workflow_id,
                revision: definition.revision.get(),
                event_id: event_id.to_owned(),
            });
        }

        // The admission a caller's action was accepted under, asked before the first thing the
        // run spends rather than only before the first thing it writes.
        journal.admit()?;

        // Per-workflow concurrency, the per-grant rate and the host-wide rate, in that order.
        // A breach pauses the revision and records the attention item that pause owes, so the
        // workflow stops rather than being refused one request at a time.
        let admitted = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit_run(
                definition.workflow_id,
                definition.grant_reference,
                now_ms,
                None,
                None,
            );
        if let Err(breach) = admitted {
            journal.pause_workflow_on_breach(
                definition.workflow_id,
                definition.revision.get(),
                &breach.to_string(),
                now_ms,
            )?;
            return Err(breach);
        }
        let permit = RunPermit {
            admission: Arc::clone(&self.admission),
            workflow_id: definition.workflow_id,
        };

        let run_id = WorkflowRunId::new(crate::new_uuid());
        journal.commit_trigger_and_run(run_id, definition, event_id, &causal, now_ms)?;
        Ok(StartedRun {
            run_id,
            definition: definition.clone(),
            causal,
            _permit: permit,
        })
    }

    /// Starts the runs the events its nodes produced have triggered.
    ///
    /// The dispatcher is a registered consumer of the journal's settled-node events. It reads
    /// them one at a time, and for each successful node whose action kind produces an event it
    /// admits a run of every enabled, unpaused workflow whose trigger names that event. Each
    /// descendant's root, depth, generation and parent come from the journal's record of the run
    /// that produced the event, and its trigger's identifier is the producing node's action
    /// identifier under [`DERIVED_TRIGGER_PREFIX`], a namespace no external trigger may use, so
    /// a replay of the event is the same trigger and runs once.
    ///
    /// The runs an event starts, the refusals it earned (a self-retrigger, a breached rate and the
    /// pause it owes, an exhausted chain and the one attention item it owes) and the dispatcher's
    /// position all commit in one transaction. A host that stops between two events neither loses
    /// one nor starts one twice. A grant store that cannot be read, or a journal that cannot be
    /// written, stops the pass where it is, with that event still unread; the runs the pass
    /// committed before it stopped come back all the same, with the reason in
    /// [`AdmittedTriggers::stopped`].
    #[must_use]
    pub fn admit_triggers(&self, now_ms: u64) -> AdmittedTriggers {
        let mut admitted = AdmittedTriggers::default();
        if let Err(error) =
            self.store
                .register_consumer(TRIGGER_CONSUMER, &[EVENT_NODE_SETTLED], now_ms)
        {
            admitted.stopped = Some(error);
            return admitted;
        }
        loop {
            match self
                .store
                .consume(TRIGGER_CONSUMER, &[EVENT_NODE_SETTLED], |journal, event| {
                    self.decide_trigger(journal, event, now_ms)
                }) {
                Ok(Some((mut decisions, mut started))) => {
                    admitted.decisions.append(&mut decisions);
                    admitted.started.append(&mut started);
                }
                Ok(None) => return admitted,
                Err(error) => {
                    admitted.stopped = Some(error);
                    return admitted;
                }
            }
        }
    }

    /// Admits and executes the runs pending triggers have started, one pass.
    ///
    /// A host that runs each started run on a task of its own uses [`Self::admit_triggers`] and
    /// [`Self::execute`] instead. This is the same pass, executing each run in turn.
    ///
    /// # Errors
    ///
    /// Returns the reason the pass stopped part way, after executing every run it committed
    /// before it stopped.
    pub async fn dispatch_triggers(&self, now_ms: u64) -> Result<Vec<TriggerDecision>> {
        let admitted = self.admit_triggers(now_ms);
        for started in admitted.started {
            // A run that stopped on a refusal has recorded its pause; the decision already says
            // the run was started.
            let _ = self.execute(started).await;
        }
        match admitted.stopped {
            Some(error) => Err(error),
            None => Ok(admitted.decisions),
        }
    }

    /// Decides what one settled-node event triggers.
    fn decide_trigger(
        &self,
        journal: &Journal<'_>,
        event: &JournalEvent,
        now_ms: u64,
    ) -> Result<(Vec<TriggerDecision>, Vec<StartedRun>)> {
        let JournalEventKind::NodeSettled {
            run_id,
            node_id,
            action_id,
            status: NodeStatus::Success,
            produced: Some(produced),
            ..
        } = &event.kind
        else {
            return Ok((Vec::new(), Vec::new()));
        };
        let Some(parent) = journal.run_record(*run_id)? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut decisions = Vec::new();
        let mut started = Vec::new();
        for installed in journal.definitions_triggered_by(produced)? {
            let definition = installed.definition;
            let trigger_id = format!("{DERIVED_TRIGGER_PREFIX}{action_id}");
            let outcome = descendant_context(journal, &definition, &parent, node_id)
                .and_then(|causal| self.admit(journal, &definition, &trigger_id, causal, now_ms));
            let outcome = match outcome {
                Ok(run) => {
                    let run_id = run.run_id;
                    started.push(run);
                    Ok(run_id)
                }
                Err(error) if error.is_decided() => Err(error),
                // A grant store that could not be read, or a journal that could not be written,
                // says nothing about this trigger. The event stays unread and is decided again.
                Err(error) => return Err(error),
            };
            decisions.push(TriggerDecision {
                event_sequence: event.sequence,
                workflow_id: definition.workflow_id,
                revision: definition.revision.get(),
                outcome,
            });
        }
        Ok((decisions, started))
    }

    /// Picks up the runs a stopped host left unfinished.
    ///
    /// A node that was running when the host stopped may have been dispatched, and nothing this
    /// host holds says whether its action happened, so it is settled as unknown: its dependants
    /// pause for review rather than running on a guess, and no edge fires from it. Every other
    /// node is as the journal left it, and executing the returned runs dispatches exactly the
    /// nodes that were never dispatched and whose predecessors are authoritative, each only after
    /// its grant is read again.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the journal cannot be read or written.
    pub fn recover(&self, now_ms: u64) -> Result<Vec<StartedRun>> {
        let mut resumed = Vec::new();
        for run in self.store.unfinished_runs()? {
            self.store.settle_interrupted_nodes(
                run.run_id,
                "this host stopped while the action was dispatched, so its outcome is not known",
                now_ms,
            )?;
            let Some(installed) = self.store.get_definition(run.workflow_id, run.revision)? else {
                continue;
            };
            self.admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resume_run(run.workflow_id);
            resumed.push(StartedRun {
                run_id: run.run_id,
                definition: installed.definition,
                causal: CausalContext::of_run(&run),
                _permit: RunPermit {
                    admission: Arc::clone(&self.admission),
                    workflow_id: run.workflow_id,
                },
            });
        }
        Ok(resumed)
    }

    /// Answers a repeat of a `workflow.run` action with where its run stands now.
    fn ran(&self, record: ActionRecord) -> Result<WorkflowRunResult> {
        let run_id = match record {
            ActionRecord::Started { run_id } => run_id,
            other => return recorded(other),
        };
        let run = self.store.run_summary(run_id)?.ok_or_else(|| {
            AutomationError::InvalidArgument(format!(
                "the run {run_id} this action started is not in the journal"
            ))
        })?;
        Ok(WorkflowRunResult {
            run_id: run.run_id,
            workflow_id: run.workflow_id,
            revision: run.revision,
            causal_root_id: run.causal_root_id,
            depth: run.depth,
            status: run.status,
        })
    }

    /// Answers an action from what an earlier submission of it recorded, when one did.
    ///
    /// This is what a repeat is answered from before its freshness is considered: a retry after
    /// a lost reply carries the window it was first admitted under, and refusing it for that
    /// would deny a caller its own completed result. Nothing here performs anything, and there is
    /// no state in which a submission is recorded as still under way: an action either has a
    /// record, written with its effect, or has not been performed.
    ///
    /// # Errors
    ///
    /// Returns the refusal an earlier submission was given,
    /// [`AutomationError::ActionIdentifierReused`] for an identifier spent on another action, and
    /// a storage error when the record cannot be read.
    pub fn answered(&self, key: &ActionKey) -> Result<Option<Answer>> {
        let Some(record) = self.store.recorded_action(key)? else {
            return Ok(None);
        };
        Ok(Some(match Method::from_wire(&key.method) {
            Some(Method::WorkflowInstall) => Answer::Installed(recorded(record)?),
            Some(Method::WorkflowEnable) => Answer::Enabled(recorded(record)?),
            Some(Method::WorkflowPause) => Answer::Paused(recorded(record)?),
            Some(Method::WorkflowRun) => Answer::Ran(self.ran(record)?),
            _ => {
                return Err(AutomationError::InvalidArgument(format!(
                    "{} is not an automation mutation",
                    key.method
                )));
            }
        }))
    }

    /// Reads definitions, runs, node receipts, and remaining causal budget (`workflow.read`).
    ///
    /// # Errors
    ///
    /// Returns a storage error when the journal cannot be read.
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
    /// event reaches the dispatcher without this right and cannot rearm anything; a descendant of
    /// a run from the old generation is refused afterwards by the generation check.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::PermissionDenied`] without the management right.
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

    /// Delivers the attention items the journal owes to an attention state.
    ///
    /// This is the attention consumer of the journal's event stream, under the contract the
    /// stream keeps with every consumer: it registers for the attention event types, reads them
    /// from its own position, and acknowledges each one only after `attention` has written its own
    /// state. A host that stops in between raises the item when it comes back, and each record is
    /// delivered under its own position in the stream, which never changes, so a redelivery
    /// replays a sequence the attention state has already consumed and changes nothing.
    ///
    /// `source` is the retained source the host has given this journal. It must not be shared
    /// with another producer, because the sequence numbers here are the journal's positions.
    ///
    /// Returns how many items were newly raised.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or the attention state's refusal.
    pub fn deliver_attention(
        &self,
        attention: &mut Attention,
        source: AttentionSource,
        reading: HostReading,
        now_ms: u64,
    ) -> Result<usize> {
        self.store
            .register_consumer(ATTENTION_CONSUMER, ATTENTION_EVENTS, now_ms)?;
        let mut raised = 0;
        for record in self.store.pending_attention()? {
            let event = SourceEvent::new(
                EventCursor::new(source, record.sequence),
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
            self.store
                .acknowledge(ATTENTION_CONSUMER, record.sequence)?;
        }

        Ok(raised)
    }

    /// Reserves a workspace for quiesced capture.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::PermissionDenied`] while another reservation holds it.
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

/// Loads the exact revision a request names, with the journal's state for it.
fn installed(
    journal: &Journal<'_>,
    workflow_id: WorkflowId,
    revision: U64,
) -> Result<InstalledDefinition> {
    let installed = journal
        .definition(workflow_id, revision.get())?
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

/// Derives a descendant's causal context from the journal's record of the run that produced its
/// trigger.
///
/// Everything comes from `parent`, which this journal wrote when it recorded that run: the root,
/// the depth and the budget generation. A definition does not retrigger on its own descendants.
/// Only a definition that was reviewed and installed with explicit recurrence may, and even then
/// the root stays the parent's: recurrence buys another turn in the chain, not a fresh budget.
fn descendant_context(
    journal: &Journal<'_>,
    def: &WorkflowDefinition,
    parent: &StoredRunRecord,
    node_id: &str,
) -> Result<CausalContext> {
    if !def.explicit_recurrence
        && journal
            .runs_by_root(parent.causal_root_id)?
            .iter()
            .any(|run| run.workflow_id == def.workflow_id)
    {
        return Err(AutomationError::SelfRetriggerRejected {
            workflow_id: def.workflow_id,
            root: parent.causal_root_id,
        });
    }
    Ok(CausalContext::descendant_of(parent, node_id))
}

/// What a submission came to, for a method whose record carries its whole result.
fn performed_or_recorded<T: serde::de::DeserializeOwned>(acted: Acted<T>) -> Result<T> {
    match acted {
        Acted::Performed(value) => Ok(value),
        Acted::Answered(record) => recorded(record),
    }
}

/// Reads back what an earlier submission recorded, for a method whose record carries its result.
fn recorded<T: serde::de::DeserializeOwned>(record: ActionRecord) -> Result<T> {
    match record {
        ActionRecord::Done { result } => Ok(serde_json::from_str(&result)?),
        ActionRecord::Refused { code, detail } => Err(AutomationError::Recorded {
            code: ErrorCode::from_wire(&code).unwrap_or(ErrorCode::InvalidArgument),
            detail,
        }),
        ActionRecord::Started { run_id } => Err(AutomationError::InvalidArgument(format!(
            "this action started run {run_id}, which is not what the method it names does"
        ))),
    }
}
