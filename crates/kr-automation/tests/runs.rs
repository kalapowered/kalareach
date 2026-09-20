//! Tests for workflow run execution, topological sequencing, edge conditions, and unknown outcome pauses.

use std::sync::Arc;

use kr_automation::{
    ActionOutcome, MockActionRunner, WorkflowEngine, WorkflowStore,
    create_workflow_definition,
};
use kr_protocol::automation::{
    EdgeCondition, NodeStatus, WorkflowEdge, WorkflowNode, WorkflowRunStatus,
};
use kr_protocol::ids::{GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, Uuid};

fn test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn test_grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

fn test_run_id(v: u8) -> WorkflowRunId {
    WorkflowRunId::new(Uuid::from_bytes([v; 16]))
}

#[tokio::test]
async fn topological_execution_respects_dependencies() {
    let store = Arc::new(WorkflowStore::in_memory().unwrap());
    let runner = Arc::new(MockActionRunner::new());

    // Register success for all nodes
    runner.set_outcome("step1", ActionOutcome::Success { output: "{}".to_owned() });
    runner.set_outcome("step2", ActionOutcome::Success { output: "{}".to_owned() });
    runner.set_outcome("step3", ActionOutcome::Success { output: "{}".to_owned() });

    let engine = WorkflowEngine::new(store.clone(), runner);

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
    let causal_ctx = kr_automation::CausalContext::new_root(def.workflow_id);
    store
        .commit_trigger_and_run(run_id, &def, "evt-1", &causal_ctx, 1000)
        .unwrap();

    let status = engine.execute_run(run_id, &def, &causal_ctx, 1000).await.unwrap();
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
    runner.set_outcome("step1", ActionOutcome::Failed { error: "tests failed".to_owned() });
    // on_failure succeeds
    runner.set_outcome("on_failure", ActionOutcome::Success { output: "{}".to_owned() });
    // on_success should NOT run
    runner.set_outcome("on_success", ActionOutcome::Success { output: "{}".to_owned() });

    let engine = WorkflowEngine::new(store.clone(), runner);

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
    let causal_ctx = kr_automation::CausalContext::new_root(def.workflow_id);
    store
        .commit_trigger_and_run(run_id, &def, "evt-2", &causal_ctx, 1000)
        .unwrap();

    let status = engine.execute_run(run_id, &def, &causal_ctx, 1000).await.unwrap();
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
    runner.set_outcome("step2", ActionOutcome::Success { output: "{}".to_owned() });

    let engine = WorkflowEngine::new(store.clone(), runner);

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
    let causal_ctx = kr_automation::CausalContext::new_root(def.workflow_id);
    store
        .commit_trigger_and_run(run_id, &def, "evt-3", &causal_ctx, 1000)
        .unwrap();

    let status = engine.execute_run(run_id, &def, &causal_ctx, 1000).await.unwrap();
    // Run status must be Paused because step2 was paused for review
    assert_eq!(status, WorkflowRunStatus::Paused);

    let receipts = store.list_node_receipts(run_id).unwrap();
    let r1 = receipts.iter().find(|r| r.node_id == "step1").unwrap();
    let r2 = receipts.iter().find(|r| r.node_id == "step2").unwrap();

    assert_eq!(r1.status, NodeStatus::Unknown);
    // Dependant node MUST be paused for review
    assert_eq!(r2.status, NodeStatus::Paused);
}
