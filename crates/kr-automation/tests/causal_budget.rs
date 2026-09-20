//! Tests for causal budgets, depth limits, action ceilings, exhaustion, rearm, and persistence.

use kr_automation::{CausalBudget, WorkflowStore};
use kr_protocol::ids::{CausalRootId, WorkflowId};
use kr_protocol::scalars::Uuid;

fn test_root_id(v: u8) -> CausalRootId {
    CausalRootId::new(Uuid::from_bytes([v; 16]))
}

fn _test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

#[test]
fn budget_enforces_depth_limit() {
    let mut budget = CausalBudget::new(test_root_id(1), 1000);
    budget.max_depth = 3;

    // Depths 1, 2, 3 succeed
    assert!(budget.reserve_run(1, 1000).is_ok());
    assert!(budget.reserve_run(2, 1010).is_ok());
    assert!(budget.reserve_run(3, 1020).is_ok());

    // Depth 4 fails and exhausts the budget
    let err = budget.reserve_run(4, 1030).unwrap_err();
    assert!(err.to_string().contains("depth"));
    assert!(budget.exhausted);
    assert!(budget.paused);

    // Subsequent run even at depth 1 is rejected because budget is exhausted
    let err2 = budget.reserve_run(1, 1040).unwrap_err();
    assert!(err2.to_string().contains("exhausted"));
}

#[test]
fn budget_enforces_max_action_ceiling() {
    let mut budget = CausalBudget::new(test_root_id(2), 1000);
    budget.max_actions = 3;

    assert!(budget.reserve_action(1001).is_ok());
    assert!(budget.reserve_action(1002).is_ok());
    assert!(budget.reserve_action(1003).is_ok());

    // 4th action exceeds ceiling
    let err = budget.reserve_action(1004).unwrap_err();
    assert!(err.to_string().contains("actions"));
    assert!(budget.exhausted);

    // Check summary reflects exhaustion
    let summary = budget.to_summary(1005);
    assert!(summary.exhausted);
    assert_eq!(summary.total_actions.get(), 3);
    assert_eq!(summary.max_actions.get(), 3);
}

#[test]
fn budget_enforces_max_runs_ceiling() {
    let mut budget = CausalBudget::new(test_root_id(3), 1000);
    budget.max_runs = 2;

    assert!(budget.reserve_run(1, 1001).is_ok());
    assert!(budget.reserve_run(2, 1002).is_ok());

    // 3rd run exceeds limit
    let err = budget.reserve_run(2, 1003).unwrap_err();
    assert!(err.to_string().contains("runs"));
    assert!(budget.exhausted);
}

#[test]
fn budget_enforces_lifetime_limit() {
    let mut budget = CausalBudget::new(test_root_id(4), 1000);
    budget.max_lifetime_ms = 5000;

    assert!(budget.reserve_run(1, 2000).is_ok());

    // At 7000 ms, elapsed = 6000 > 5000 limit
    let err = budget.reserve_run(1, 7001).unwrap_err();
    assert!(err.to_string().contains("lifetime"));
    assert!(budget.exhausted);
}

#[test]
fn budget_rearm_clears_exhaustion() {
    let mut budget = CausalBudget::new(test_root_id(5), 1000);
    budget.max_actions = 2;

    budget.reserve_action(1001).unwrap();
    budget.reserve_action(1002).unwrap();
    assert!(budget.reserve_action(1003).is_err());
    assert!(budget.exhausted);

    // Operator rearms with higher limits
    budget.max_actions = 10;
    budget.rearm(2000);

    assert!(!budget.exhausted);
    assert!(!budget.paused);

    // Now actions can proceed again
    assert!(budget.reserve_action(2001).is_ok());
    assert_eq!(budget.total_actions, 3);
}

#[test]
fn budget_persists_across_store_reopen() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let root_id = test_root_id(6);

    {
        let store = WorkflowStore::open(tmp_dir.path()).unwrap();
        let mut budget = store.get_or_create_budget(root_id, 1000).unwrap();
        budget.reserve_action(1010).unwrap();
        budget.reserve_action(1020).unwrap();
        store.save_budget(&budget).unwrap();
    }

    // Reopen store from same database file
    {
        let store = WorkflowStore::open(tmp_dir.path()).unwrap();
        let budget = store
            .get_budget(root_id)
            .unwrap()
            .expect("budget must exist");
        assert_eq!(budget.total_actions, 2);
        assert!(!budget.exhausted);
    }
}
