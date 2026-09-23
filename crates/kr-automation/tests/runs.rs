//! Tests for workflow run execution, topological sequencing, edge conditions, and unknown outcome pauses.

use std::sync::Arc;

use kr_automation::{
    ActionOutcome, MockActionRunner, WorkflowEngine, WorkflowStore, create_workflow_definition,
};
use kr_protocol::automation::{
    EdgeCondition, NodeStatus, WorkflowEdge, WorkflowNode, WorkflowRunStatus,
};
use kr_protocol::ids::{GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, Uuid};

mod common;

use common::Submit;

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
    common::every_right(&[
        test_grant_id(1),
        test_grant_id(7),
        test_grant_id(8),
        test_grant_id(9),
        test_grant_id(10),
    ])
}

fn test_run_id(v: u8) -> WorkflowRunId {
    WorkflowRunId::new(Uuid::from_bytes([v; 16]))
}

#[tokio::test]
async fn topological_execution_respects_dependencies() {
    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let runner = Arc::new(MockActionRunner::new());

    // Register success for all nodes
    runner.set_outcome(
        "step1",
        ActionOutcome::Success {
            output: "{}".to_owned(),
        },
    );
    runner.set_outcome(
        "step2",
        ActionOutcome::Success {
            output: "{}".to_owned(),
        },
    );
    runner.set_outcome(
        "step3",
        ActionOutcome::Success {
            output: "{}".to_owned(),
        },
    );

    let engine = WorkflowEngine::with_clock(
        store.clone(),
        runner,
        authority(),
        Arc::new(kr_automation::ManualClock::new(1000)),
    );

    let n1 = WorkflowNode {
        node_id: "step1".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "step2".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n3 = WorkflowNode {
        node_id: "step3".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };

    let edges = vec![
        WorkflowEdge {
            from_node: "step1".to_owned(),
            to_node: "step2".to_owned(),
            condition: EdgeCondition::Success,
        },
        WorkflowEdge {
            from_node: "step2".to_owned(),
            to_node: "step3".to_owned(),
            condition: EdgeCondition::Success,
        },
    ];

    let def = create_workflow_definition(
        test_wf_id(1),
        1,
        "topo-workflow",
        test_grant_id(1),
        vec![n1, n2, n3],
        edges,
    );
    store.save_definition(&def, 1000).unwrap();

    let run_id = test_run_id(1);
    let causal_ctx = kr_automation::CausalContext::new_root();
    store
        .commit_trigger_and_run(run_id, &def, "evt-1", &causal_ctx, 1000)
        .unwrap();

    let status = engine.execute_run(run_id, &def, &causal_ctx).await.unwrap();
    assert_eq!(status, WorkflowRunStatus::Completed);

    let receipts = store.list_node_receipts(run_id).unwrap();
    assert_eq!(receipts.len(), 3);
    for r in receipts {
        assert_eq!(r.status, NodeStatus::Success);
    }
}

#[tokio::test]
async fn edge_condition_branching_success_and_failure() {
    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let runner = Arc::new(MockActionRunner::new());

    // step1 fails
    runner.set_outcome(
        "step1",
        ActionOutcome::Failed {
            error: "tests failed".to_owned(),
        },
    );
    // on_failure succeeds
    runner.set_outcome(
        "on_failure",
        ActionOutcome::Success {
            output: "{}".to_owned(),
        },
    );
    // on_success should NOT run
    runner.set_outcome(
        "on_success",
        ActionOutcome::Success {
            output: "{}".to_owned(),
        },
    );

    let engine = WorkflowEngine::with_clock(
        store.clone(),
        runner,
        authority(),
        Arc::new(kr_automation::ManualClock::new(1000)),
    );

    let n1 = WorkflowNode {
        node_id: "step1".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n_succ = WorkflowNode {
        node_id: "on_success".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n_fail = WorkflowNode {
        node_id: "on_failure".to_owned(),
        action_kind: "attention_notice".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };

    let edges = vec![
        WorkflowEdge {
            from_node: "step1".to_owned(),
            to_node: "on_success".to_owned(),
            condition: EdgeCondition::Success,
        },
        WorkflowEdge {
            from_node: "step1".to_owned(),
            to_node: "on_failure".to_owned(),
            condition: EdgeCondition::Failure,
        },
    ];

    let def = create_workflow_definition(
        test_wf_id(2),
        1,
        "branching-workflow",
        test_grant_id(1),
        vec![n1, n_succ, n_fail],
        edges,
    );
    store.save_definition(&def, 1000).unwrap();

    let run_id = test_run_id(2);
    let causal_ctx = kr_automation::CausalContext::new_root();
    store
        .commit_trigger_and_run(run_id, &def, "evt-2", &causal_ctx, 1000)
        .unwrap();

    let status = engine.execute_run(run_id, &def, &causal_ctx).await.unwrap();
    assert_eq!(status, WorkflowRunStatus::Failed);

    let receipts = store.list_node_receipts(run_id).unwrap();
    let r_step1 = receipts.iter().find(|r| r.node_id == "step1").unwrap();
    let r_succ = receipts.iter().find(|r| r.node_id == "on_success").unwrap();
    let r_fail = receipts.iter().find(|r| r.node_id == "on_failure").unwrap();

    assert_eq!(r_step1.status, NodeStatus::Failed);
    assert_eq!(r_succ.status, NodeStatus::Pending); // never run
    assert_eq!(r_fail.status, NodeStatus::Success); // ran on failure branch
}

#[tokio::test]
async fn unknown_predecessor_outcome_pauses_dependants_for_review() {
    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let runner = Arc::new(MockActionRunner::new());

    // step1 outcome unknown (crash / lost connection / inconclusive process)
    runner.set_outcome(
        "step1",
        ActionOutcome::Unknown {
            detail: "process was terminated by SIGKILL before receipt".to_owned(),
        },
    );
    runner.set_outcome(
        "step2",
        ActionOutcome::Success {
            output: "{}".to_owned(),
        },
    );

    let engine = WorkflowEngine::with_clock(
        store.clone(),
        runner,
        authority(),
        Arc::new(kr_automation::ManualClock::new(1000)),
    );

    let n1 = WorkflowNode {
        node_id: "step1".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "step2".to_owned(),
        action_kind: "apply_diff".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };

    let edges = vec![WorkflowEdge {
        from_node: "step1".to_owned(),
        to_node: "step2".to_owned(),
        condition: EdgeCondition::Success,
    }];

    let def = create_workflow_definition(
        test_wf_id(3),
        1,
        "unknown-outcome-workflow",
        test_grant_id(1),
        vec![n1, n2],
        edges,
    );
    store.save_definition(&def, 1000).unwrap();

    let run_id = test_run_id(3);
    let causal_ctx = kr_automation::CausalContext::new_root();
    store
        .commit_trigger_and_run(run_id, &def, "evt-3", &causal_ctx, 1000)
        .unwrap();

    let status = engine.execute_run(run_id, &def, &causal_ctx).await.unwrap();
    // Run status must be Paused because step2 was paused for review
    assert_eq!(status, WorkflowRunStatus::Paused);

    let receipts = store.list_node_receipts(run_id).unwrap();
    let r1 = receipts.iter().find(|r| r.node_id == "step1").unwrap();
    let r2 = receipts.iter().find(|r| r.node_id == "step2").unwrap();

    assert_eq!(r1.status, NodeStatus::Unknown);
    // Dependant node MUST be paused for review
    assert_eq!(r2.status, NodeStatus::Paused);
}

/// A revision that was installed but never enabled does not run, and a pause stops one that was.
#[tokio::test]
async fn enable_and_pause_decide_whether_a_revision_runs() {
    use kr_automation::{AutomationService, ManualClock};
    use kr_protocol::automation::{
        WorkflowEnableParams, WorkflowInstallParams, WorkflowPauseParams, WorkflowRunParams,
    };

    let workflow_id = test_wf_id(7);
    let node = WorkflowNode {
        node_id: "step".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "gated",
        test_grant_id(7),
        vec![node],
        vec![],
    );

    let service = AutomationService::in_memory_with_clock(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    )
    .expect("a service");
    service
        .submit_install(
            &WorkflowInstallParams {
                workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: definition.grant_reference,
            },
            1_000,
        )
        .expect("the definition installs");

    let params = |event: &str| WorkflowRunParams {
        workflow_id,
        revision: definition.revision,
        event_id: event.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
        causal_parent: Nullable::null(),
    };

    // The definition document says `enabled`, and it is installed disabled all the same,
    // because enabling a revision is its own authorised method.
    assert!(definition.enabled);
    let refused = service
        .submit_run(&params("evt-1"), 1_000)
        .await
        .expect_err("an installed revision does not run until it is enabled");
    assert!(refused.to_string().contains("disabled"), "{refused}");

    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");
    service
        .submit_run(&params("evt-2"), 1_000)
        .await
        .expect("an enabled revision runs");

    service
        .submit_pause(
            &WorkflowPauseParams {
                workflow_id,
                revision: definition.revision,
                reason: kr_protocol::scalars::Nullable::some("under review".to_owned()),
            },
            1_000,
        )
        .expect("the revision pauses");
    let paused = service
        .submit_run(&params("evt-3"), 1_000)
        .await
        .expect_err("a paused revision runs nothing");
    assert!(paused.to_string().contains("paused"), "{paused}");
}

/// An uncertain answer from an action stays uncertain, whichever way the runner reports it.
#[tokio::test]
async fn an_uncertain_dispatch_pauses_dependants_rather_than_failing_them() {
    struct UncertainRunner;

    impl kr_automation::ActionRunner for UncertainRunner {
        fn execute(
            &self,
            dispatch: &kr_automation::Dispatch<'_>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
        > {
            let node_id = dispatch.node.node_id.clone();
            Box::pin(async move {
                if node_id == "step1" {
                    // The action was dispatched and the answer never came back.
                    Err(kr_automation::AutomationError::OutcomeUnknown {
                        node_id,
                        detail: "the receipt never arrived".to_owned(),
                    })
                } else {
                    Ok(ActionOutcome::Success {
                        output: "{}".to_owned(),
                    })
                }
            })
        }
    }

    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let engine = WorkflowEngine::with_clock(
        store.clone(),
        Arc::new(UncertainRunner),
        authority(),
        Arc::new(kr_automation::ManualClock::new(1000)),
    );

    let n1 = WorkflowNode {
        node_id: "step1".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "step2".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: r#"{"reviewer_id": "bob"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let edge = WorkflowEdge {
        from_node: "step1".to_owned(),
        to_node: "step2".to_owned(),
        // Even a failure edge must not fire: the host does not know there was a failure.
        condition: EdgeCondition::Failure,
    };

    let def = create_workflow_definition(
        test_wf_id(8),
        1,
        "uncertain",
        test_grant_id(8),
        vec![n1, n2],
        vec![edge],
    );
    store.save_definition(&def, 1000).unwrap();

    let run_id = test_run_id(8);
    let causal_ctx = kr_automation::CausalContext::new_root();
    store
        .commit_trigger_and_run(run_id, &def, "evt-1", &causal_ctx, 1000)
        .unwrap();

    let status = engine
        .execute_run(run_id, &def, &causal_ctx)
        .await
        .expect("the run finishes");
    assert_eq!(status, WorkflowRunStatus::Paused);

    let receipts = store.list_node_receipts(run_id).unwrap();
    let step1 = receipts.iter().find(|r| r.node_id == "step1").unwrap();
    let step2 = receipts.iter().find(|r| r.node_id == "step2").unwrap();
    assert_eq!(step1.status, NodeStatus::Unknown);
    assert_eq!(step2.status, NodeStatus::Paused);
}

/// A cancelled node is not dispatched, even when the cancellation lands mid-run.
#[tokio::test]
async fn cancellation_stops_undispatched_nodes() {
    use std::sync::Mutex;

    struct CancellingRunner {
        store: Mutex<Option<Arc<WorkflowStore>>>,
        run_id: WorkflowRunId,
    }

    impl kr_automation::ActionRunner for CancellingRunner {
        fn execute(
            &self,
            dispatch: &kr_automation::Dispatch<'_>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
        > {
            // While the first node runs, somebody cancels the run.
            if dispatch.node.node_id == "step1"
                && let Some(store) = self.store.lock().unwrap().as_ref()
            {
                let engine = WorkflowEngine::with_clock(
                    Arc::clone(store),
                    Arc::new(MockActionRunner::new()),
                    authority(),
                    Arc::new(kr_automation::ManualClock::new(1000)),
                );
                engine.cancel_run(self.run_id, 1_500).unwrap();
            }
            Box::pin(async move {
                Ok(ActionOutcome::Success {
                    output: "{}".to_owned(),
                })
            })
        }
    }

    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let run_id = test_run_id(9);
    let runner = Arc::new(CancellingRunner {
        store: Mutex::new(Some(Arc::clone(&store))),
        run_id,
    });
    let engine = WorkflowEngine::with_clock(
        Arc::clone(&store),
        runner,
        authority(),
        Arc::new(kr_automation::ManualClock::new(1000)),
    );

    let n1 = WorkflowNode {
        node_id: "step1".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "step2".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: r#"{"reviewer_id": "bob"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let edge = WorkflowEdge {
        from_node: "step1".to_owned(),
        to_node: "step2".to_owned(),
        condition: EdgeCondition::Success,
    };

    let def = create_workflow_definition(
        test_wf_id(9),
        1,
        "cancelled",
        test_grant_id(9),
        vec![n1, n2],
        vec![edge],
    );
    store.save_definition(&def, 1000).unwrap();

    let causal_ctx = kr_automation::CausalContext::new_root();
    store
        .commit_trigger_and_run(run_id, &def, "evt-1", &causal_ctx, 1000)
        .unwrap();

    engine
        .execute_run(run_id, &def, &causal_ctx)
        .await
        .expect("the run finishes");

    let status = engine
        .execute_run(run_id, &def, &causal_ctx)
        .await
        .expect("the run finishes");
    assert_eq!(
        status,
        WorkflowRunStatus::Cancelled,
        "a run with a cancelled node is a cancelled run, not a completed one"
    );

    let receipts = store.list_node_receipts(run_id).unwrap();
    let step2 = receipts.iter().find(|r| r.node_id == "step2").unwrap();
    assert_eq!(
        step2.status,
        NodeStatus::Cancelled,
        "an undispatched node stays cancelled"
    );
}

/// A workflow paused while a run is in flight dispatches nothing further.
#[tokio::test]
async fn a_pause_mid_run_stops_the_next_node() {
    use kr_automation::{AutomationService, ManualClock};
    use kr_protocol::automation::{
        WorkflowEnableParams, WorkflowInstallParams, WorkflowPauseParams, WorkflowRunParams,
    };

    let workflow_id = test_wf_id(10);
    let n1 = WorkflowNode {
        node_id: "step1".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "step2".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: r#"{"reviewer_id": "bob"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let edge = WorkflowEdge {
        from_node: "step1".to_owned(),
        to_node: "step2".to_owned(),
        condition: EdgeCondition::Success,
    };
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "paused-mid-run",
        test_grant_id(10),
        vec![n1, n2],
        vec![edge],
    );

    let service = Arc::new(
        AutomationService::in_memory_with_clock(
            Arc::new(MockActionRunner::new()),
            authority(),
            Arc::new(ManualClock::new(1_000)),
        )
        .expect("a service"),
    );
    service
        .submit_install(
            &WorkflowInstallParams {
                workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: definition.grant_reference,
            },
            1_000,
        )
        .expect("the definition installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");

    // The pause lands after the run has been admitted and before its first node dispatches.
    service
        .submit_pause(
            &WorkflowPauseParams {
                workflow_id,
                revision: definition.revision,
                reason: Nullable::some("stop it".to_owned()),
            },
            1_000,
        )
        .expect("the revision pauses");

    let refused = service
        .submit_run(
            &WorkflowRunParams {
                workflow_id,
                revision: definition.revision,
                event_id: "evt-1".to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
                causal_parent: Nullable::null(),
            },
            1_000,
        )
        .await
        .expect_err("a paused workflow runs nothing");
    assert!(refused.to_string().contains("paused"), "{refused}");
    assert!(
        service
            .store()
            .list_runs(Some(workflow_id))
            .unwrap()
            .is_empty(),
        "a refused run leaves no record behind"
    );
}
