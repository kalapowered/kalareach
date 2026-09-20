//! Tests for host-wide rate limits, per-grant rate limits, and per-workflow concurrency limits.

use kr_automation::AdmissionController;
use kr_protocol::ids::{GrantId, WorkflowId};
use kr_protocol::scalars::Uuid;

fn test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn test_grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

#[test]
fn concurrency_limits_are_enforced_per_workflow() {
    let mut controller = AdmissionController::new();

    let wf1 = test_wf_id(1);
    let wf2 = test_wf_id(2);
    let grant = test_grant_id(1);

    // Limit concurrency to 2 for wf1
    let max_conc = Some(2);

    // Admit run 1 and run 2 for wf1
    assert!(
        controller
            .admit_run(wf1, grant, 1000, max_conc, None)
            .is_ok()
    );
    assert!(
        controller
            .admit_run(wf1, grant, 1000, max_conc, None)
            .is_ok()
    );

    // 3rd concurrent run for wf1 is rejected
    let err = controller
        .admit_run(wf1, grant, 1000, max_conc, None)
        .unwrap_err();
    assert!(err.to_string().contains("concurrency limit"));

    // wf2 is unaffected by wf1's limit
    assert!(
        controller
            .admit_run(wf2, grant, 1000, max_conc, None)
            .is_ok()
    );

    // When a run of wf1 completes, another run can be admitted
    controller.release_run(wf1);
    assert!(
        controller
            .admit_run(wf1, grant, 1000, max_conc, None)
            .is_ok()
    );
}

#[test]
fn host_wide_rate_limits_throttle_excessive_traffic() {
    let mut controller = AdmissionController::new();
    controller.host_rate_limit = 3;

    let wf1 = test_wf_id(1);
    let grant = test_grant_id(1);

    // Consume 3 runs
    assert!(controller.admit_run(wf1, grant, 1000, None, None).is_ok());
    assert!(controller.admit_run(wf1, grant, 1000, None, None).is_ok());
    assert!(controller.admit_run(wf1, grant, 1000, None, None).is_ok());

    // 4th run in same sliding window (1 minute) fails
    let err = controller
        .admit_run(wf1, grant, 1000, None, None)
        .unwrap_err();
    assert!(err.to_string().contains("host-wide rate limit"));

    // After 61 seconds (61,000 ms), window slides and runs can be admitted again
    assert!(controller.admit_run(wf1, grant, 62_000, None, None).is_ok());
}

#[test]
fn per_grant_rate_limits_isolate_tenants() {
    let mut controller = AdmissionController::new();
    controller.grant_rate_limit = 2;

    let wf = test_wf_id(1);
    let grant_a = test_grant_id(10);
    let grant_b = test_grant_id(20);
    let max_conc = Some(100);

    // Exhaust grant_a
    assert!(
        controller
            .admit_run(wf, grant_a, 1000, max_conc, None)
            .is_ok()
    );
    assert!(
        controller
            .admit_run(wf, grant_a, 1000, max_conc, None)
            .is_ok()
    );
    let err_a = controller
        .admit_run(wf, grant_a, 1000, max_conc, None)
        .unwrap_err();
    assert!(err_a.to_string().contains("grant"));

    // grant_b has separate quota and succeeds
    assert!(
        controller
            .admit_run(wf, grant_b, 1000, max_conc, None)
            .is_ok()
    );
    assert!(
        controller
            .admit_run(wf, grant_b, 1000, max_conc, None)
            .is_ok()
    );
    let err_b = controller
        .admit_run(wf, grant_b, 1000, max_conc, None)
        .unwrap_err();
    assert!(err_b.to_string().contains("grant"));
}
