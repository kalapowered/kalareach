//! Causal budgets: the ceilings, exhaustion, rearm, and the chain that spans two workflows.
//!
//! The central case is KR-ACC-032: two workflows that are each individually acyclic trigger one
//! another slowly, across controller restarts, and exhaust one persistent budget rather than
//! escaping through per-run limits that reset with every run.

use std::sync::Arc;

use kr_attention::store::{Claimant, Liveness};
use kr_attention::time::BootMark;
use kr_attention::{Attention, HostReading};
use kr_automation::{
    AttentionSubject, AutomationService, CausalBudget, ManualClock, MockActionRunner,
    WorkflowStore, create_workflow_definition,
};
use kr_protocol::attention::{AttentionRule, AttentionSource};
use kr_protocol::automation::{
    CausalParentRef, DEFAULT_CAUSAL_DEPTH_LIMIT, DEFAULT_CAUSAL_SESSIONS_LIMIT, WorkflowDefinition,
    WorkflowInstallParams, WorkflowNode, WorkflowRunParams, WorkflowRunStatus,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{CausalRootId, GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, U64, Uuid};

mod common;

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

/// A one-node workflow that may retrigger inside a chain it did not start.
fn recurring_workflow(id: u8, name: &str, action_kind: &str) -> WorkflowDefinition {
    let params = match action_kind {
        "create_session" => r#"{"title": "descendant"}"#,
        _ => r#"{"suite": "unit"}"#,
    };
    let node = WorkflowNode {
        node_id: "step".to_owned(),
        action_kind: action_kind.to_owned(),
        action_params: params.to_owned(),
        declared_environment: Nullable::null(),
    };
    let mut def = create_workflow_definition(
        test_wf_id(id),
        1,
        name,
        test_grant_id(1),
        vec![node],
        vec![],
    );
    def.explicit_recurrence = true;
    def
}

fn install_and_enable(service: &AutomationService, def: &WorkflowDefinition, now_ms: u64) {
    service
        .install(
            &WorkflowInstallParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
                definition: def.clone(),
                grant_reference: def.grant_reference,
            },
            now_ms,
        )
        .expect("the definition installs");
}

fn run_params(
    def: &WorkflowDefinition,
    event_id: &str,
    parent: Option<CausalParentRef>,
) -> WorkflowRunParams {
    WorkflowRunParams {
        workflow_id: def.workflow_id,
        revision: def.revision,
        event_id: event_id.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
        causal_parent: Nullable::from(parent),
    }
}

fn parent_ref(root: CausalRootId, run_id: WorkflowRunId, depth: u64) -> CausalParentRef {
    CausalParentRef {
        causal_root_id: root,
        parent_run_id: run_id,
        parent_node_id: "step".to_owned(),
        depth: U64::new(depth),
    }
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
/// can breach a per-run ceiling. The chain they form between them is what the budget counts, and
/// the budget is reloaded from the journal at every step, which is what a controller restart
/// leaves behind.
#[tokio::test]
async fn mutually_triggering_workflows_exhaust_one_persistent_budget() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let clock = Arc::new(ManualClock::new(1_000));
    let workflows = [
        recurring_workflow(1, "completion", "run_tests"),
        recurring_workflow(2, "verification", "run_tests"),
    ];

    // The first trigger is external, so the host mints the root.
    let root;
    let mut parent;
    {
        let service = AutomationService::open_with_clock(
            journal.path(),
            Arc::new(MockActionRunner::new()),
            authority(),
            clock.clone(),
        )
        .expect("the journal opens");
        for def in &workflows {
            install_and_enable(&service, def, 1_000);
            service
                .enable(
                    &kr_protocol::automation::WorkflowEnableParams {
                        workflow_id: def.workflow_id,
                        revision: def.revision,
                    },
                    1_000,
                )
                .expect("the revision enables");
        }

        let first = service
            .run(&run_params(&workflows[0], "external-1", None), 1_000)
            .await
            .expect("the external trigger runs");
        assert_eq!(first.depth.get(), 1);
        root = first.causal_root_id;
        parent = parent_ref(root, first.run_id, 1);
    }

    // Each further step is a fresh process against the same journal.
    let mut steps = 1_u64;
    let refusal = loop {
        let service = AutomationService::open_with_clock(
            journal.path(),
            Arc::new(MockActionRunner::new()),
            authority(),
            clock.clone(),
        )
        .expect("the journal reopens");

        let def = &workflows[usize::try_from(steps % 2).expect("two workflows")];
        let now_ms = 1_000 + steps * 60_000;
        clock.set(now_ms);

        match service
            .run(
                &run_params(def, &format!("chain-{steps}"), Some(parent.clone())),
                now_ms,
            )
            .await
        {
            Ok(result) => {
                assert_eq!(
                    result.causal_root_id, root,
                    "every descendant stays under the root the host minted"
                );
                assert_eq!(result.depth.get(), steps + 1);
                assert_eq!(result.status, WorkflowRunStatus::Completed);
                parent = parent_ref(root, result.run_id, result.depth.get());
                steps += 1;
                assert!(steps < 100, "the chain should have been stopped by now");
            }
            Err(error) => break error,
        }
    };

    assert_eq!(
        steps, DEFAULT_CAUSAL_DEPTH_LIMIT,
        "the chain ran to the depth ceiling and no further"
    );
    assert_eq!(
        kr_protocol::error::ProtocolError::from(refusal).code,
        kr_protocol::error::ErrorCode::CausalLimit,
    );

    // The pause survives the restart that follows it, and nothing else gets in.
    let service = AutomationService::open_with_clock(
        journal.path(),
        Arc::new(MockActionRunner::new()),
        authority(),
        clock.clone(),
    )
    .expect("the journal reopens");

    let budget = service
        .store()
        .get_budget(root)
        .expect("the budget reads")
        .expect("the budget outlived the restart");
    assert!(budget.exhausted);
    assert!(budget.paused);

    let again = service
        .run(
            &run_params(&workflows[0], "chain-after-exhaustion", Some(parent)),
            2_000_000,
        )
        .await
        .expect_err("an exhausted chain admits no further descendant");
    assert_eq!(
        kr_protocol::error::ProtocolError::from(again).code,
        kr_protocol::error::ErrorCode::CausalLimit,
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
    // and the settled record is not delivered a second time.
    let after_restart = AutomationService::open_with_clock(
        journal.path(),
        Arc::new(MockActionRunner::new()),
        authority(),
        clock.clone(),
    )
    .expect("the journal reopens");
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

/// A workflow cannot retrigger on its own descendants unless the reviewed definition says so.
#[tokio::test]
async fn self_retrigger_is_refused_without_explicit_recurrence() {
    let service = AutomationService::in_memory_with_clock(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    )
    .expect("a service");
    let mut def = recurring_workflow(3, "self-trigger", "run_tests");
    def.explicit_recurrence = false;
    install_and_enable(&service, &def, 1_000);
    service
        .enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
            },
            1_000,
        )
        .unwrap();

    let first = service
        .run(&run_params(&def, "evt-1", None), 1_000)
        .await
        .expect("the first run is admitted");

    let error = service
        .run(
            &run_params(
                &def,
                "evt-2",
                Some(parent_ref(first.causal_root_id, first.run_id, 1)),
            ),
            2_000,
        )
        .await
        .expect_err("the workflow cannot retrigger on its own descendant");
    assert!(error.to_string().contains("retrigger"), "{error}");
}

/// The root and the depth come from the host's records, not from what the request claims.
#[tokio::test]
async fn a_request_cannot_name_its_own_causal_root() {
    let service = AutomationService::in_memory_with_clock(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    )
    .expect("a service");
    let first = recurring_workflow(4, "first", "run_tests");
    let second = recurring_workflow(5, "second", "run_tests");
    for def in [&first, &second] {
        install_and_enable(&service, def, 1_000);
        service
            .enable(
                &kr_protocol::automation::WorkflowEnableParams {
                    workflow_id: def.workflow_id,
                    revision: def.revision,
                },
                1_000,
            )
            .unwrap();
    }

    let root_run = service
        .run(&run_params(&first, "evt-1", None), 1_000)
        .await
        .expect("the first run is admitted");

    // A root the parent run does not belong to is refused outright.
    let error = service
        .run(
            &run_params(
                &second,
                "evt-2",
                Some(parent_ref(test_root_id(99), root_run.run_id, 1)),
            ),
            2_000,
        )
        .await
        .expect_err("a claimed root that is not the parent's is refused");
    assert!(error.to_string().contains("causal root"), "{error}");

    // A parent run this host never recorded is refused too, so an invented ancestry cannot
    // start a chain with a depth of its choosing.
    let error = service
        .run(
            &run_params(
                &second,
                "evt-3",
                Some(parent_ref(
                    root_run.causal_root_id,
                    WorkflowRunId::new(Uuid::from_bytes([200; 16])),
                    9,
                )),
            ),
            3_000,
        )
        .await
        .expect_err("an unknown parent run is refused");
    assert!(error.to_string().contains("parent run"), "{error}");

    // A real parent with a lying depth still lands one below its parent.
    let descendant = service
        .run(
            &run_params(
                &second,
                "evt-4",
                Some(parent_ref(root_run.causal_root_id, root_run.run_id, 12)),
            ),
            4_000,
        )
        .await
        .expect("a real parent admits a descendant");
    assert_eq!(descendant.depth.get(), 2);
    assert_eq!(descendant.causal_root_id, root_run.causal_root_id);
}

/// A node that creates a session spends the chain's session allowance.
#[tokio::test]
async fn created_sessions_are_reserved_against_the_chain() {
    let clock = Arc::new(ManualClock::new(1_000));
    let journal = tempfile::tempdir().expect("a journal directory");
    let service = AutomationService::open_with_clock(
        journal.path(),
        Arc::new(MockActionRunner::new()),
        authority(),
        clock.clone(),
    )
    .expect("a service");

    let def = recurring_workflow(6, "session-maker", "create_session");
    install_and_enable(&service, &def, 1_000);
    service
        .enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
            },
            1_000,
        )
        .unwrap();

    let first = service
        .run(&run_params(&def, "session-0", None), 1_000)
        .await
        .expect("the first session-creating run is admitted");
    let root = first.causal_root_id;
    let mut parent = parent_ref(root, first.run_id, 1);

    // Ten sessions are the whole allowance, and the eleventh is refused.
    for step in 1..DEFAULT_CAUSAL_SESSIONS_LIMIT {
        let result = service
            .run(
                &run_params(&def, &format!("session-{step}"), Some(parent.clone())),
                1_000,
            )
            .await
            .unwrap_or_else(|error| panic!("session {step} should be admitted: {error}"));
        parent = parent_ref(root, result.run_id, result.depth.get());
    }

    let budget = service
        .store()
        .get_budget(root)
        .unwrap()
        .expect("a budget exists");
    assert_eq!(budget.created_sessions, DEFAULT_CAUSAL_SESSIONS_LIMIT);

    let error = service
        .run(&run_params(&def, "session-over", Some(parent)), 1_000)
        .await
        .expect_err("the eleventh session is refused");
    assert_eq!(
        kr_protocol::error::ProtocolError::from(error).code,
        kr_protocol::error::ErrorCode::CausalLimit,
    );
}

/// A chain that has run out of time stops spending, even mid-run.
#[tokio::test]
async fn an_expired_lifetime_stops_further_actions() {
    let clock = Arc::new(ManualClock::new(1_000));
    let journal = tempfile::tempdir().expect("a journal directory");
    let service = AutomationService::open_with_clock(
        journal.path(),
        Arc::new(MockActionRunner::new()),
        authority(),
        clock.clone(),
    )
    .expect("a service");

    let def = recurring_workflow(7, "long-chain", "run_tests");
    install_and_enable(&service, &def, 1_000);
    service
        .enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
            },
            1_000,
        )
        .unwrap();

    let first = service
        .run(&run_params(&def, "evt-1", None), 1_000)
        .await
        .expect("the first run is admitted");
    let parent = parent_ref(first.causal_root_id, first.run_id, 1);

    // An hour and a second after the root was created, the chain is out of lifetime.
    let expired = 1_000 + 3_600_001;
    clock.set(expired);
    let error = service
        .run(&run_params(&def, "evt-2", Some(parent)), expired)
        .await
        .expect_err("an expired chain admits nothing further");
    assert!(error.to_string().contains("lifetime"), "{error}");
}

/// An authorised rearm gives the chain a fresh budget; a late descendant does not get it.
#[tokio::test]
async fn rearm_is_authorised_and_refuses_late_descendants() {
    let clock = Arc::new(ManualClock::new(1_000));
    let journal = tempfile::tempdir().expect("a journal directory");
    let service = AutomationService::open_with_clock(
        journal.path(),
        Arc::new(MockActionRunner::new()),
        authority(),
        clock.clone(),
    )
    .expect("a service");

    let def = recurring_workflow(8, "rearmed", "run_tests");
    install_and_enable(&service, &def, 1_000);
    service
        .enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
            },
            1_000,
        )
        .unwrap();

    let first = service
        .run(&run_params(&def, "evt-1", None), 1_000)
        .await
        .expect("the first run is admitted");
    let root = first.causal_root_id;
    let stale_parent = parent_ref(root, first.run_id, 1);

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

    // A descendant of the run from before the rearm belongs to the old generation.
    let late = service
        .run(&run_params(&def, "evt-late", Some(stale_parent)), 3_000)
        .await
        .expect_err("a late descendant cannot spend the new budget");
    assert!(
        late.to_string().contains("stale causal generation"),
        "{late}"
    );

    // A fresh external trigger under the rearmed root still runs.
    let fresh = service
        .run(&run_params(&def, "evt-fresh", None), 3_000)
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
    let service = AutomationService::in_memory_with_clock(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    )
    .expect("a service");
    let def = recurring_workflow(9, "callback", "run_tests");
    install_and_enable(&service, &def, 1_000);
    service
        .enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: def.workflow_id,
                revision: def.revision,
            },
            1_000,
        )
        .unwrap();

    let first = service
        .run(&run_params(&def, "callback-1", None), 1_000)
        .await
        .expect("the callback runs");
    let second = service
        .run(&run_params(&def, "callback-2", None), 1_000)
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
        .run(&run_params(&def, "callback-1", None), 1_000)
        .await
        .expect_err("a replayed callback is deduplicated");
    assert!(repeat.to_string().contains("duplicate trigger"), "{repeat}");
}
