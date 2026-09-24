//! Causal budgets: the ceilings, exhaustion, rearm, and the chain that spans two workflows.
//!
//! The central case is KR-ACC-032: two workflows that are each individually acyclic trigger one
//! another slowly, across controller restarts, and exhaust one persistent budget rather than
//! escaping through per-run limits that reset with every run.
//!
//! Every chain here is built the only way one can be: a run started through `workflow.run` is an
//! external trigger with a root the host mints, and every descendant is started by the host's own
//! trigger dispatcher from the journal's record of the node that produced its trigger. No test
//! names a parent, because nothing a caller sends can.

use std::sync::Arc;

use kr_attention::store::{Claimant, Liveness};
use kr_attention::time::BootMark;
use kr_attention::{Attention, HostReading};
use kr_automation::{
    AttentionSubject, AutomationError, AutomationService, CausalBudget, ManualClock,
    MockActionRunner, TriggerDecision, WorkflowStore, create_workflow_definition,
};
use kr_protocol::attention::{AttentionRule, AttentionSource};
use kr_protocol::automation::{
    DEFAULT_CAUSAL_DEPTH_LIMIT, DEFAULT_CAUSAL_SESSIONS_LIMIT, WorkflowActionKind,
    WorkflowDefinition, WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams,
    WorkflowRunStatus,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{CausalRootId, GrantId, WorkflowId};
use kr_protocol::scalars::{Nullable, Uuid};

mod common;

use common::Submit;

fn test_root_id(v: u8) -> CausalRootId {
    CausalRootId::new(Uuid::from_bytes([v; 16]))
}

fn test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn test_grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

/// The grants these definitions name, as the host holds them.
///
/// A definition names a grant and the host reads it from its own store, so every suite that runs
/// one puts that grant in first. What a narrower or withdrawn grant does is its own suite's
/// subject.
fn authority() -> std::sync::Arc<kr_automation::GrantTable> {
    common::every_right(&[test_grant_id(1)])
}

/// A one-node workflow triggered by `trigger`, whose node's success produces the event its action
/// kind fixes, and which may take another turn inside a chain it already appears in.
fn recurring_workflow(
    id: u8,
    name: &str,
    trigger: &str,
    action_kind: WorkflowActionKind,
) -> WorkflowDefinition {
    let node = common::node("step", action_kind);
    let mut def = create_workflow_definition(
        test_wf_id(id),
        1,
        name,
        test_grant_id(1),
        vec![node],
        vec![],
    );
    def.trigger.event_type = trigger.to_owned();
    def.explicit_recurrence = true;
    def
}

fn install_and_enable(service: &AutomationService, def: &WorkflowDefinition, now_ms: u64) {
    service
        .submit_install(
            &WorkflowInstallParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
                definition: def.clone(),
                grant_reference: def.grant_reference,
            },
            now_ms,
        )
        .expect("the definition installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
            },
            now_ms,
        )
        .expect("the revision enables");
}

fn run_params(def: &WorkflowDefinition, event_id: &str) -> WorkflowRunParams {
    WorkflowRunParams {
        workflow_id: def.workflow_id,
        revision: def.revision,
        event_id: event_id.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
    }
}

fn open(journal: &std::path::Path, clock: &Arc<ManualClock>) -> AutomationService {
    AutomationService::open(
        journal,
        common::host(
            Arc::new(MockActionRunner::new()),
            authority(),
            Arc::clone(clock) as Arc<dyn kr_automation::HostClock>,
        ),
    )
    .expect("the journal opens")
}

fn in_memory() -> AutomationService {
    AutomationService::in_memory(common::host(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service")
}

/// The one decision a dispatch pass took, for a pass that matched one workflow.
fn only(mut decisions: Vec<TriggerDecision>) -> TriggerDecision {
    assert_eq!(decisions.len(), 1, "{decisions:?}");
    decisions.remove(0)
}

fn code(error: &AutomationError) -> ErrorCode {
    ProtocolError::from(error).code
}

fn reading(now_ms: u64) -> HostReading {
    HostReading::new(BootMark::of(b"causal-budget-test"), now_ms, now_ms, true)
}

/// What the host says when it cannot tell whether the last owner is still running.
const UNKNOWN: &dyn Fn(&ProcessStartIdentity) -> Liveness = &|_| Liveness::Unknown;

/// A durable attention state on disk, opened as this process.
fn attention_at(path: &std::path::Path, now_ms: u64) -> Attention {
    Attention::open(
        path,
        reading(now_ms),
        &Claimant::new(
            ProcessStartIdentity::new(1, ProcessStartSource::LinuxProcStat, 1_001),
            UNKNOWN,
        ),
    )
    .expect("the attention state opens")
}

/// KR-ACC-032. Two workflows trigger one another across restarts and share one budget.
///
/// Each definition is a single node with no edges, so neither is cyclic on its own and neither
/// can breach a per-run ceiling. The first finishes by producing the event the second is triggered
/// by, and the second the event that triggers the first. The chain they form between them is what
/// the budget counts. Every step runs in a fresh process against the same journal, which is what a
/// controller restart leaves behind: the budget, the pending trigger and the dispatcher's own
/// position are all read back from the journal.
#[tokio::test]
async fn mutually_triggering_workflows_exhaust_one_persistent_budget() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let clock = Arc::new(ManualClock::new(1_000));
    let tests = recurring_workflow(1, "tests", "review.completed", WorkflowActionKind::RunTests);
    let review = recurring_workflow(
        2,
        "review",
        "tests.passed",
        WorkflowActionKind::RequestReview,
    );

    // The first trigger is external, so the host mints the root.
    let root = {
        let service = open(journal.path(), &clock);
        install_and_enable(&service, &tests, 1_000);
        install_and_enable(&service, &review, 1_000);
        let first = service
            .submit_run(&run_params(&tests, "external-1"), 1_000)
            .await
            .expect("the external trigger runs");
        assert_eq!(first.depth.get(), 1);
        first.causal_root_id
    };

    // Each further step is a fresh process against the same journal, a minute later.
    let mut runs = 1_u64;
    let refusal = loop {
        let service = open(journal.path(), &clock);
        assert!(
            service
                .recover(clock_now(&clock))
                .expect("recovery")
                .is_empty(),
            "every run so far finished before its process stopped"
        );
        let now_ms = 1_000 + runs * 60_000;
        clock.set(now_ms);

        let decision = only(
            service
                .dispatch_triggers(now_ms)
                .await
                .expect("the dispatcher runs"),
        );
        match decision.outcome {
            Ok(run_id) => {
                runs += 1;
                let expected = if runs.is_multiple_of(2) {
                    &review
                } else {
                    &tests
                };
                assert_eq!(decision.workflow_id, expected.workflow_id);
                let run = service
                    .store()
                    .run_summary(run_id)
                    .expect("the journal")
                    .expect("the run");
                assert_eq!(
                    run.causal_root_id, root,
                    "every descendant stays under the root the host minted"
                );
                assert_eq!(run.depth.get(), runs);
                assert_eq!(run.status, WorkflowRunStatus::Completed);
                assert!(runs < 100, "the chain should have been stopped by now");
            }
            Err(error) => break error,
        }
    };

    assert_eq!(
        runs, DEFAULT_CAUSAL_DEPTH_LIMIT,
        "the chain ran to the depth ceiling and no further"
    );
    assert_eq!(code(&refusal), ErrorCode::CausalLimit, "{refusal}");

    // The pause survives the restart that follows it, and nothing else gets in.
    let service = open(journal.path(), &clock);
    let budget = service
        .store()
        .get_budget(root)
        .expect("the budget reads")
        .expect("the budget outlived the restart");
    assert!(budget.exhausted);
    assert!(budget.paused);
    assert!(
        service
            .dispatch_triggers(2_000_000)
            .await
            .expect("the dispatcher runs")
            .is_empty(),
        "an exhausted chain produced nothing further to trigger"
    );

    // Exactly one attention item, however many refusals the chain collected.
    let inbox = journal.path().join("attention.state");
    {
        let mut attention = attention_at(&inbox, 2_000_000);
        let raised = service
            .deliver_attention(
                &mut attention,
                AttentionSource::Semantic,
                reading(2_000_000),
                2_000_000,
            )
            .expect("the attention records deliver");
        assert_eq!(raised, 1, "an exhausted chain raises exactly one item");
        let engine = attention.engine().expect("the engine");
        assert_eq!(engine.items().count(), 1);
        assert_eq!(
            engine.items().next().expect("the item").rule,
            AttentionRule::AdapterFailed
        );
    }

    // The item is in the attention state, not in a process. Both come back after a restart,
    // and the acknowledged record is not delivered a second time.
    let after_restart = open(journal.path(), &clock);
    let mut attention = attention_at(&inbox, 2_100_000);
    assert_eq!(
        attention.engine().expect("the engine").items().count(),
        1,
        "the item outlived the process that raised it"
    );
    assert_eq!(
        after_restart
            .deliver_attention(
                &mut attention,
                AttentionSource::Semantic,
                reading(2_100_000),
                2_100_000,
            )
            .expect("nothing is owed"),
        0
    );
    assert_eq!(attention.engine().expect("the engine").items().count(), 1);
}

/// The journal's positions are not dense: a run's events sit between two attention records. The
/// attention consumer reads past them, and the attention state is told so, so it records no
/// history gap and marks nothing uncertain, whether the records arrive in one delivery or two.
#[tokio::test]
async fn run_events_between_attention_records_leave_no_history_gap() {
    let service = in_memory();
    let def = recurring_workflow(9, "one-shot", "tests.passed", WorkflowActionKind::RunTests);
    install_and_enable(&service, &def, 1_000);
    let journal = tempfile::tempdir().expect("a directory for the attention state");
    let mut attention = attention_at(&journal.path().join("attention.state"), 1_000);

    // A run commits its events, then its chain runs out of time and owes an attention record.
    let first = service
        .submit_run(&run_params(&def, "evt-first"), 1_000)
        .await
        .expect("the run completes");
    assert!(
        service
            .store()
            .reserve_budget_action(first.causal_root_id, 0, 1_000 + 3_600_001)
            .is_err(),
        "the chain is out of lifetime"
    );
    let first_alert = service.store().pending_attention().expect("the journal")[0].sequence;
    assert!(first_alert > 1, "the run's own events came first");
    assert_eq!(
        service
            .deliver_attention(
                &mut attention,
                AttentionSource::Semantic,
                reading(3_700_000),
                3_700_000,
            )
            .expect("delivers"),
        1
    );

    // Another run's events, then another chain's record.
    let second = service
        .submit_run(&run_params(&def, "evt-second"), 3_700_000)
        .await
        .expect("the run completes");
    assert!(
        service
            .store()
            .reserve_budget_action(second.causal_root_id, 0, 3_700_000 + 3_600_001)
            .is_err(),
        "the chain is out of lifetime"
    );
    let second_alert = service.store().pending_attention().expect("the journal")[0].sequence;
    assert!(
        second_alert > first_alert + 1,
        "a run's events sit between them"
    );
    assert_eq!(
        service
            .deliver_attention(
                &mut attention,
                AttentionSource::Semantic,
                reading(7_400_000),
                7_400_000,
            )
            .expect("delivers"),
        1
    );

    assert!(
        attention.gaps().expect("the gaps").is_empty(),
        "{:?}",
        attention.gaps()
    );
    let engine = attention.engine().expect("the engine");
    assert_eq!(engine.items().count(), 2);
    assert!(engine.items().all(|item| !item.uncertain));
    assert_eq!(
        engine.consumed(kr_attention::Origin::Environment, AttentionSource::Semantic),
        Some(second_alert),
        "the state stands at the last record this consumer read"
    );
}

fn clock_now(clock: &ManualClock) -> u64 {
    kr_automation::HostClock::now_ms(clock)
}

/// A workflow cannot retrigger on its own descendants unless the reviewed definition says so.
#[tokio::test]
async fn self_retrigger_is_refused_without_explicit_recurrence() {
    let service = in_memory();
    let mut def = recurring_workflow(
        3,
        "self-trigger",
        "tests.passed",
        WorkflowActionKind::RunTests,
    );
    def.explicit_recurrence = false;
    install_and_enable(&service, &def, 1_000);

    let first = service
        .submit_run(&run_params(&def, "evt-1"), 1_000)
        .await
        .expect("the first run is admitted");

    let decision = only(service.dispatch_triggers(2_000).await.expect("a pass"));
    let error = decision
        .outcome
        .expect_err("the workflow cannot retrigger on its own descendant");
    assert!(error.to_string().contains("retrigger"), "{error}");
    assert_eq!(
        service
            .store()
            .list_runs_by_root(first.causal_root_id)
            .expect("the journal")
            .len(),
        1,
        "nothing further ran under the chain"
    );
}

/// A descendant's root, depth and parent are the journal's record of the node that produced its
/// trigger, and its trigger's identifier is that node's action identifier.
#[tokio::test]
async fn a_descendant_takes_its_ancestry_from_the_node_that_produced_its_trigger() {
    let service = in_memory();
    let first = recurring_workflow(4, "first", "manual", WorkflowActionKind::RunTests);
    let second = recurring_workflow(5, "second", "tests.passed", WorkflowActionKind::RunTests);
    install_and_enable(&service, &first, 1_000);
    install_and_enable(&service, &second, 1_000);

    let root_run = service
        .submit_run(&run_params(&first, "evt-1"), 1_000)
        .await
        .expect("the first run is admitted");

    let decisions = service.dispatch_triggers(2_000).await.expect("a pass");
    let descendant = decisions
        .iter()
        .find(|decision| decision.workflow_id == second.workflow_id)
        .expect("the second workflow was triggered");
    let run_id = *descendant.outcome.as_ref().expect("the descendant started");
    let run = service
        .store()
        .run_summary(run_id)
        .expect("the journal")
        .expect("the run");

    let producing = service
        .store()
        .list_node_receipts(root_run.run_id)
        .expect("the journal");
    assert_eq!(run.causal_root_id, root_run.causal_root_id);
    assert_eq!(run.depth.get(), 2);
    assert_eq!(run.parent_run_id.0, Some(root_run.run_id));
    assert_eq!(run.parent_node_id.0.as_deref(), Some("step"));
    assert_eq!(
        run.trigger_event_id,
        format!(
            "{}{}",
            kr_automation::DERIVED_TRIGGER_PREFIX,
            producing[0].action_id
        ),
        "the trigger is named by the producing node's action identifier"
    );

    // The same event again is the same trigger: another pass starts nothing.
    assert!(
        service
            .dispatch_triggers(3_000)
            .await
            .expect("a pass")
            .iter()
            .all(|decision| decision.workflow_id != second.workflow_id
                || decision.event_sequence != descendant.event_sequence),
        "an event the dispatcher has passed is not decided again"
    );
}

/// A node that creates a session spends the chain's session allowance.
#[tokio::test]
async fn created_sessions_are_reserved_against_the_chain() {
    let clock = Arc::new(ManualClock::new(1_000));
    let journal = tempfile::tempdir().expect("a journal directory");
    let service = open(journal.path(), &clock);

    let def = recurring_workflow(
        6,
        "session-maker",
        "session.created",
        WorkflowActionKind::CreateSession,
    );
    install_and_enable(&service, &def, 1_000);

    let first = service
        .submit_run(&run_params(&def, "session-0"), 1_000)
        .await
        .expect("the first session-creating run is admitted");
    let root = first.causal_root_id;

    // Ten sessions are the whole allowance.
    for step in 1..DEFAULT_CAUSAL_SESSIONS_LIMIT {
        let decision = only(service.dispatch_triggers(1_000).await.expect("a pass"));
        decision
            .outcome
            .unwrap_or_else(|error| panic!("session {step} should be admitted: {error}"));
    }
    let budget = service
        .store()
        .get_budget(root)
        .unwrap()
        .expect("a budget exists");
    assert_eq!(budget.created_sessions, DEFAULT_CAUSAL_SESSIONS_LIMIT);

    // The eleventh run is admitted, and its node is refused the session it would create.
    let decision = only(service.dispatch_triggers(1_000).await.expect("a pass"));
    let eleventh = decision.outcome.expect("the run itself fits the chain");
    let run = service
        .store()
        .run_summary(eleventh)
        .unwrap()
        .expect("the run");
    assert_eq!(run.status, WorkflowRunStatus::Paused);
    let budget = service.store().get_budget(root).unwrap().unwrap();
    assert!(budget.exhausted, "the eleventh session exhausted the chain");
}

/// A chain that has run out of time starts nothing further.
#[tokio::test]
async fn an_expired_lifetime_stops_further_descendants() {
    let clock = Arc::new(ManualClock::new(1_000));
    let journal = tempfile::tempdir().expect("a journal directory");
    let service = open(journal.path(), &clock);

    let def = recurring_workflow(
        7,
        "long-chain",
        "tests.passed",
        WorkflowActionKind::RunTests,
    );
    install_and_enable(&service, &def, 1_000);
    service
        .submit_run(&run_params(&def, "evt-1"), 1_000)
        .await
        .expect("the first run is admitted");

    // An hour and a second after the root was created, the chain is out of lifetime.
    let expired = 1_000 + 3_600_001;
    clock.set(expired);
    let error = only(service.dispatch_triggers(expired).await.expect("a pass"))
        .outcome
        .expect_err("an expired chain admits nothing further");
    assert!(error.to_string().contains("lifetime"), "{error}");
}

/// An authorised rearm gives the chain a fresh budget; a late descendant does not get it.
#[tokio::test]
async fn rearm_is_authorised_and_refuses_late_descendants() {
    let clock = Arc::new(ManualClock::new(1_000));
    let journal = tempfile::tempdir().expect("a journal directory");
    let service = open(journal.path(), &clock);

    let def = recurring_workflow(8, "rearmed", "tests.passed", WorkflowActionKind::RunTests);
    install_and_enable(&service, &def, 1_000);

    // The first run finishes, and the trigger its node produced waits for the dispatcher.
    let first = service
        .submit_run(&run_params(&def, "evt-1"), 1_000)
        .await
        .expect("the first run is admitted");
    let root = first.causal_root_id;

    // Exhaust the chain by hand, as a breached ceiling would.
    let mut budget = service.store().get_budget(root).unwrap().unwrap();
    budget.exhaust();
    service.store().save_budget(&budget).unwrap();

    // Without the management right nothing changes.
    let refused = service.rearm(root, false, 2_000).expect_err("no right");
    assert!(
        refused.to_string().contains("automation.manage"),
        "{refused}"
    );
    assert!(service.store().get_budget(root).unwrap().unwrap().exhausted);

    service
        .rearm(root, true, 2_000)
        .expect("an authorised rearm");
    let rearmed = service.store().get_budget(root).unwrap().unwrap();
    assert!(!rearmed.exhausted);
    assert_eq!(rearmed.generation, 1);
    assert_eq!(
        rearmed.total_runs, 0,
        "the counters were reset with the flags"
    );
    assert_eq!(
        rearmed.max_runs,
        CausalBudget::new(root, 0).max_runs,
        "nobody had to raise a ceiling to make the chain usable again"
    );

    // The trigger from before the rearm belongs to the old generation.
    let late = only(service.dispatch_triggers(3_000).await.expect("a pass"))
        .outcome
        .expect_err("a late descendant cannot spend the new budget");
    assert!(
        late.to_string().contains("stale causal generation"),
        "{late}"
    );

    // A fresh external trigger is a root of its own.
    let fresh = service
        .submit_run(&run_params(&def, "evt-fresh"), 3_000)
        .await
        .expect("a fresh root runs");
    assert_ne!(fresh.causal_root_id, root);
}

/// Concurrent dispatches cannot both take the last free action of a chain.
#[test]
fn concurrent_action_reservations_do_not_oversubscribe() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let store = Arc::new(WorkflowStore::open(journal.path()).expect("the journal opens"));
    let root = test_root_id(10);

    let mut budget = CausalBudget::new(root, 1_000);
    budget.max_actions = 20;
    store.save_budget(&budget).expect("the budget saves");

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                (0..10)
                    .filter(|_| store.reserve_budget_action(root, 0, 1_000).is_ok())
                    .count()
            })
        })
        .collect();

    let granted: usize = threads
        .into_iter()
        .map(|t| t.join().expect("a thread"))
        .sum();
    assert_eq!(granted, 20, "no more than the ceiling was ever granted");

    let final_budget = store.get_budget(root).unwrap().unwrap();
    assert_eq!(final_budget.total_actions, 20);
    assert!(final_budget.exhausted);

    // However many threads were refused, the chain owes one attention item.
    let pending = store.pending_attention().expect("the outbox reads");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].subject, AttentionSubject::CausalRoot(root));
}

/// The budget itself, not a run, is what the ceilings live on.
#[test]
fn budget_enforces_each_default_ceiling() {
    let mut budget = CausalBudget::new(test_root_id(1), 1_000);
    budget.max_depth = 3;
    budget.reserve_run(1, 1_000).unwrap();
    budget.reserve_run(2, 1_010).unwrap();
    budget.reserve_run(3, 1_020).unwrap();
    let err = budget.reserve_run(4, 1_030).unwrap_err();
    assert!(err.to_string().contains("depth"));
    assert!(budget.exhausted && budget.paused);
    assert!(
        budget
            .reserve_run(1, 1_040)
            .unwrap_err()
            .to_string()
            .contains("exhausted"),
        "an exhausted chain refuses even a run it would otherwise have room for"
    );

    let mut budget = CausalBudget::new(test_root_id(2), 1_000);
    budget.max_actions = 3;
    for at in [1_001, 1_002, 1_003] {
        budget.reserve_action(at).unwrap();
    }
    assert!(
        budget
            .reserve_action(1_004)
            .unwrap_err()
            .to_string()
            .contains("actions")
    );
    let summary = budget.to_summary(1_005);
    assert!(summary.exhausted);
    assert_eq!(summary.total_actions.get(), 3);

    let mut budget = CausalBudget::new(test_root_id(3), 1_000);
    budget.max_runs = 2;
    budget.reserve_run(1, 1_001).unwrap();
    budget.reserve_run(2, 1_002).unwrap();
    assert!(
        budget
            .reserve_run(2, 1_003)
            .unwrap_err()
            .to_string()
            .contains("runs")
    );

    let mut budget = CausalBudget::new(test_root_id(4), 1_000);
    budget.max_lifetime_ms = 5_000;
    budget.reserve_run(1, 2_000).unwrap();
    assert!(
        budget
            .reserve_run(1, 7_001)
            .unwrap_err()
            .to_string()
            .contains("lifetime")
    );
}

/// A budget is the journal's, not a process's: it comes back as it was left.
#[test]
fn budget_persists_across_store_reopen() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let root = test_root_id(6);

    {
        let store = WorkflowStore::open(journal.path()).unwrap();
        store.reserve_budget_action(root, 0, 1_010).unwrap();
        store.reserve_budget_action(root, 0, 1_020).unwrap();
    }

    {
        let store = WorkflowStore::open(journal.path()).unwrap();
        let budget = store.get_budget(root).unwrap().expect("a budget exists");
        assert_eq!(budget.total_actions, 2);
        assert!(!budget.exhausted);
    }
}

/// An unauthenticated external callback starts a new chain under host-wide limits.
#[tokio::test]
async fn an_external_callback_is_a_new_external_trigger() {
    let service = in_memory();
    let def = recurring_workflow(
        9,
        "callback",
        "callback.received",
        WorkflowActionKind::RunTests,
    );
    install_and_enable(&service, &def, 1_000);

    let first = service
        .submit_run(&run_params(&def, "callback-1"), 1_000)
        .await
        .expect("the callback runs");
    let second = service
        .submit_run(&run_params(&def, "callback-2"), 1_000)
        .await
        .expect("a second callback runs");

    assert_ne!(
        first.causal_root_id, second.causal_root_id,
        "each external trigger is its own root, so one cannot spend another's budget"
    );
    assert_eq!(first.depth.get(), 1);
    assert_eq!(second.depth.get(), 1);

    // A repeat of the same event identifier is the same trigger, and runs once.
    let repeat = service
        .submit_run(&run_params(&def, "callback-1"), 1_000)
        .await
        .expect_err("a replayed callback is deduplicated");
    assert!(repeat.to_string().contains("duplicate trigger"), "{repeat}");
}
