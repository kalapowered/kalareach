//! Tests for SQLite persistence across drop/reopen and trigger deduplication key semantics.

use kr_automation::{
    CausalContext, WorkflowStore, create_workflow_definition,
};
use kr_protocol::automation::{NodeStatus, WorkflowNode, WorkflowRunStatus};
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

#[test]
fn sqlite_persistence_survives_drop_and_reopen() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let wf_id = test_wf_id(1);
    let grant_id = test_grant_id(1);
    let run_id = test_run_id(1);

    // Phase 1: Write state and drop connection
    {
        let store = WorkflowStore::open(tmp_dir.path()).unwrap();

        let n1 = WorkflowNode {
            node_id: "step1".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "core"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };

        let def = create_workflow_definition(
            wf_id,
            1,
            "durable-wf",
            grant_id,
            vec![n1],
            vec![],
        );
        store.save_definition(&def, 1000).unwrap();

        let causal_ctx = CausalContext::new_root(wf_id);
        store
            .commit_trigger_and_run(run_id, &def, "evt-init", &causal_ctx, 1050)
            .unwrap();

        // Update node receipt and run status
        store
            .update_node_receipt(
                run_id,
                "step1",
                NodeStatus::Success,
                Some(r#"{"exit_code": 0}"#),
                None,
                Some(1100),
            )
            .unwrap();

        store
            .update_run_status(run_id, WorkflowRunStatus::Completed, Some(1105))
            .unwrap();
    }

    // Phase 2: Reopen from disk and verify exact recovery
    {
        let store = WorkflowStore::open(tmp_dir.path()).unwrap();

        // Verify definition
        let defs = store.list_definitions(Some(wf_id)).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "durable-wf");
        assert_eq!(defs[0].revision.get(), 1);

        // Verify run
        let runs = store.list_runs(Some(wf_id)).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].status, WorkflowRunStatus::Completed);
        assert_eq!(runs[0].trigger_event_id, "evt-init");

        // Verify node receipt
        let receipts = store.list_node_receipts(run_id).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].node_id, "step1");
        assert_eq!(receipts[0].status, NodeStatus::Success);
        assert_eq!(
            receipts[0].output.as_ref().map(|s| s.as_str()),
            Some(r#"{"exit_code": 0}"#)
        );

        // Verify causal budget
        let budget = store
            .get_budget(runs[0].causal_root_id)
            .unwrap()
            .expect("causal budget must exist");
        assert_eq!(budget.total_runs, 1);
    }
}

#[test]
fn deduplication_key_prevents_duplicate_runs() {
    let store = WorkflowStore::in_memory().unwrap();
    let wf_id = test_wf_id(2);
    let grant_id = test_grant_id(1);

    let def = create_workflow_definition(
        wf_id,
        1,
        "dedup-wf",
        grant_id,
        vec![],
        vec![],
    );
    store.save_definition(&def, 1000).unwrap();

    let run1 = test_run_id(10);
    let causal_ctx = CausalContext::new_root(wf_id);

    // First commit for (wf_id, rev 1, "evt-dup") succeeds
    assert!(
        store
            .commit_trigger_and_run(run1, &def, "evt-dup", &causal_ctx, 1000)
            .is_ok()
    );

    // Second commit with exact same deduplication key fails atomically
    let run2 = test_run_id(11);
    let err = store
        .commit_trigger_and_run(run2, &def, "evt-dup", &causal_ctx, 1005)
        .unwrap_err();

    assert!(err.to_string().contains("duplicate trigger"));

    // A different event ID succeeds
    let run3 = test_run_id(12);
    assert!(
        store
            .commit_trigger_and_run(run3, &def, "evt-different", &causal_ctx, 1010)
            .is_ok()
    );
}
