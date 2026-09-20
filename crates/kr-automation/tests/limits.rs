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

/// A breached per-workflow limit pauses the revision and leaves one attention record.
#[tokio::test]
async fn a_breached_workflow_limit_pauses_the_workflow_and_raises_one_item() {
    use std::sync::Arc;

    use kr_automation::{
        AttentionSubject, AutomationService, ManualClock, MockActionRunner,
        create_workflow_definition,
    };
    use kr_protocol::automation::{
        WorkflowEnableParams, WorkflowInstallParams, WorkflowNode, WorkflowRunParams,
    };
    use kr_protocol::scalars::Nullable;

    let workflow_id = test_wf_id(9);
    let node = WorkflowNode {
        node_id: "step".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "rate-limited",
        test_grant_id(9),
        vec![node],
        vec![],
    );

    let service = AutomationService::in_memory_with_clock(
        Arc::new(MockActionRunner::new()),
        Arc::new(ManualClock::new(1_000)),
    )
    .expect("a service");
    service
        .install(
            &WorkflowInstallParams {
                workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: definition.grant_reference,
            },
            None,
            1_000,
        )
        .expect("the definition installs");
    service
        .enable(
            &WorkflowEnableParams {
                workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");

    let params = |event: &str| WorkflowRunParams {
        workflow_id,
        revision: definition.revision,
        event_id: event.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
        causal_parent: Nullable::null(),
    };

    // Fill the per-grant minute allowance. Each run releases its concurrency permit on the way
    // out, so what is left to breach is the rate, not the concurrency.
    for index in 0..120 {
        service
            .run(&params(&format!("evt-{index}")), None, 1_000)
            .await
            .unwrap_or_else(|error| panic!("run {index} should be admitted: {error}"));
    }

    let breach = service
        .run(&params("evt-over"), None, 1_000)
        .await
        .expect_err("the run past the rate is refused");
    assert!(breach.to_string().contains("rate limit"), "{breach}");

    // The workflow is now paused, so a later request is refused for that reason alone.
    let paused = service
        .run(&params("evt-after-pause"), None, 1_000)
        .await
        .expect_err("a paused workflow runs nothing");
    assert!(paused.to_string().contains("paused"), "{paused}");

    let pending = service.store().pending_attention().expect("the outbox");
    assert_eq!(pending.len(), 1, "one pause owes one item");
    assert_eq!(
        pending[0].subject,
        AttentionSubject::Workflow {
            workflow_id,
            revision: definition.revision.get(),
        }
    );
    assert!(!pending[0].ends_condition);

    // Enabling the revision again is what clears the pause, and the record that ends the
    // condition is committed with it, so the item does not go on asking for attention.
    service
        .enable(
            &WorkflowEnableParams {
                workflow_id,
                revision: definition.revision,
            },
            2_000,
        )
        .expect("the revision enables again");
    let after_enable = service.store().pending_attention().expect("the outbox");
    assert_eq!(after_enable.len(), 2);
    assert!(after_enable[1].ends_condition);

    let after = service
        .run(&params("evt-after-enable"), None, 200_000)
        .await
        .expect("the workflow runs once its pause is cleared");
    assert_eq!(after.workflow_id, workflow_id);
}

/// A redelivered trigger is answered as a duplicate, and costs the workflow nothing.
#[tokio::test]
async fn a_redelivered_trigger_neither_spends_an_allowance_nor_pauses_the_workflow() {
    use std::sync::Arc;

    use kr_automation::{
        AutomationService, ManualClock, MockActionRunner, create_workflow_definition,
    };
    use kr_protocol::automation::{
        WorkflowEnableParams, WorkflowInstallParams, WorkflowNode, WorkflowRunParams,
    };
    use kr_protocol::scalars::Nullable;

    let workflow_id = test_wf_id(11);
    let node = WorkflowNode {
        node_id: "step".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "redelivered",
        test_grant_id(11),
        vec![node],
        vec![],
    );

    let service = AutomationService::in_memory_with_clock(
        Arc::new(MockActionRunner::new()),
        Arc::new(ManualClock::new(1_000)),
    )
    .expect("a service");
    service
        .install(
            &WorkflowInstallParams {
                workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: definition.grant_reference,
            },
            None,
            1_000,
        )
        .expect("the definition installs");
    service
        .enable(
            &WorkflowEnableParams {
                workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");

    let params = WorkflowRunParams {
        workflow_id,
        revision: definition.revision,
        event_id: "evt-once".to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
        causal_parent: Nullable::null(),
    };

    service
        .run(&params, None, 1_000)
        .await
        .expect("the trigger runs");

    // The same event, delivered again and again. Each is a duplicate and nothing more: no
    // allowance is spent, and the workflow is never paused for load it did not create.
    for _ in 0..200 {
        let repeat = service
            .run(&params, None, 1_000)
            .await
            .expect_err("a redelivery is a duplicate");
        assert!(repeat.to_string().contains("duplicate trigger"), "{repeat}");
    }

    assert!(
        service
            .store()
            .pending_attention()
            .expect("the outbox")
            .is_empty(),
        "nothing was paused, so nothing owes an attention item"
    );
    assert_eq!(
        service.store().list_runs(Some(workflow_id)).unwrap().len(),
        1
    );
}
