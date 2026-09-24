//! Tests for host-wide rate limits, per-grant rate limits, and per-workflow concurrency limits.

use kr_protocol::ids::{GrantId, WorkflowId};
use kr_protocol::scalars::Uuid;

mod common;

use common::Submit;
use kr_protocol::automation::WorkflowActionKind;

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
        test_grant_id(9),
        test_grant_id(10),
        test_grant_id(11),
        test_grant_id(20),
    ])
}

/// A service over an in-memory journal whose runs complete at once, holding the grants
/// `grants` name.
fn service_holding(grants: &[GrantId]) -> kr_automation::AutomationService {
    kr_automation::AutomationService::in_memory(common::host(
        std::sync::Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(grants),
        std::sync::Arc::new(kr_automation::ManualClock::new(1_000)),
    ))
    .expect("a service")
}

/// Installs and enables a one-node workflow under `grant`.
fn installed_under(
    service: &kr_automation::AutomationService,
    id: WorkflowId,
    grant: GrantId,
) -> kr_protocol::automation::WorkflowDefinition {
    use kr_protocol::automation::{WorkflowEnableParams, WorkflowInstallParams};

    let definition = kr_automation::create_workflow_definition(
        id,
        1,
        "rated",
        grant,
        vec![common::node("step", WorkflowActionKind::RunTests)],
        vec![],
    );
    service
        .submit_install(
            &WorkflowInstallParams {
                workflow_id: id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: grant,
            },
            1_000,
        )
        .expect("installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("enables");
    definition
}

fn run_of(
    definition: &kr_protocol::automation::WorkflowDefinition,
    event: &str,
) -> kr_protocol::automation::WorkflowRunParams {
    kr_protocol::automation::WorkflowRunParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
        event_id: event.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: kr_protocol::scalars::Nullable::null(),
    }
}

/// Each grant has its own minute's allowance: one grant spending all of its own leaves another's
/// untouched, and the window moves on after a minute.
#[tokio::test]
async fn per_grant_rate_limits_isolate_tenants() {
    let (grant_a, grant_b) = (test_grant_id(10), test_grant_id(11));
    let service = service_holding(&[grant_a, grant_b]);
    let a = installed_under(&service, test_wf_id(30), grant_a);
    let b = installed_under(&service, test_wf_id(31), grant_b);
    for index in 0..120 {
        service
            .submit_run(&run_of(&a, &format!("evt-{index}")), 1_000)
            .await
            .unwrap_or_else(|error| panic!("run {index} under the first grant: {error}"));
    }
    let refused = service
        .submit_run(&run_of(&a, "evt-over"), 1_000)
        .await
        .expect_err("the first grant's allowance is spent");
    assert!(refused.to_string().contains("grant"), "{refused}");
    service
        .submit_run(&run_of(&b, "evt-other"), 1_000)
        .await
        .expect("the second grant's allowance is its own");
}

/// The host admits no more than its own minute's allowance, whichever grants the runs are under,
/// and a callback that arrives as a new external trigger is counted like any other.
#[tokio::test]
async fn host_wide_rate_limits_throttle_excessive_traffic() {
    let grants: Vec<GrantId> = (40..46).map(test_grant_id).collect();
    let service = service_holding(&grants);
    let definitions: Vec<_> = grants
        .iter()
        .enumerate()
        .map(|(index, grant)| installed_under(&service, test_wf_id(40 + index as u8), *grant))
        .collect();
    // Five grants, each within its own allowance, fill the host's.
    for (definition, _) in definitions.iter().zip(0..5) {
        for index in 0..120 {
            service
                .submit_run(&run_of(definition, &format!("evt-{index}")), 1_000)
                .await
                .unwrap_or_else(|error| panic!("run {index}: {error}"));
        }
    }
    let refused = service
        .submit_run(&run_of(&definitions[5], "evt-sixth-grant"), 1_000)
        .await
        .expect_err("the host's allowance is spent");
    assert!(refused.to_string().contains("host-wide"), "{refused}");
}

/// A breached per-workflow limit pauses the revision and leaves one attention record.
#[tokio::test]
async fn a_breached_workflow_limit_pauses_the_workflow_and_raises_one_item() {
    use std::sync::Arc;

    use kr_automation::{
        AttentionSubject, AutomationService, ManualClock, MockActionRunner,
        create_workflow_definition,
    };
    use kr_protocol::automation::{WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams};
    use kr_protocol::scalars::Nullable;

    let workflow_id = test_wf_id(9);
    let node = common::node("step", WorkflowActionKind::RunTests);
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "rate-limited",
        test_grant_id(9),
        vec![node],
        vec![],
    );

    let service = AutomationService::in_memory(common::host(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    ))
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
    service
        .submit_enable(
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
    };

    // Fill the per-grant minute allowance. Each run releases its concurrency permit on the way
    // out, so what is left to breach is the rate, not the concurrency.
    for index in 0..120 {
        service
            .submit_run(&params(&format!("evt-{index}")), 1_000)
            .await
            .unwrap_or_else(|error| panic!("run {index} should be admitted: {error}"));
    }

    let breach = service
        .submit_run(&params("evt-over"), 1_000)
        .await
        .expect_err("the run past the rate is refused");
    assert!(breach.to_string().contains("rate limit"), "{breach}");

    // The workflow is now paused, so a later request is refused for that reason alone.
    let paused = service
        .submit_run(&params("evt-after-pause"), 1_000)
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
        .submit_enable(
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
        .submit_run(&params("evt-after-enable"), 200_000)
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
    use kr_protocol::automation::{WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams};
    use kr_protocol::scalars::Nullable;

    let workflow_id = test_wf_id(11);
    let node = common::node("step", WorkflowActionKind::RunTests);
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "redelivered",
        test_grant_id(11),
        vec![node],
        vec![],
    );

    let service = AutomationService::in_memory(common::host(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    ))
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
    service
        .submit_enable(
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
    };

    service
        .submit_run(&params, 1_000)
        .await
        .expect("the trigger runs");

    // The same event, delivered again and again. Each is a duplicate and nothing more: no
    // allowance is spent, and the workflow is never paused for load it did not create.
    for _ in 0..200 {
        let repeat = service
            .submit_run(&params, 1_000)
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

/// `workflow.read` shows a revision's pause and the alert it owes until an attention state takes
/// the alert, and the alert that ends it when the revision is enabled again.
#[tokio::test]
async fn a_read_shows_the_pause_and_its_alert() {
    use kr_protocol::automation::{WorkflowAlertKind, WorkflowReadParams};
    use kr_protocol::scalars::Nullable;

    let grant = test_grant_id(40);
    let service = kr_automation::AutomationService::in_memory(common::host(
        std::sync::Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(&[grant]),
        std::sync::Arc::new(kr_automation::ManualClock::new(1_000)),
    ))
    .expect("a service");
    let definition = kr_automation::create_workflow_definition(
        test_wf_id(40),
        1,
        "paused by a limit",
        grant,
        vec![common::node("only", WorkflowActionKind::RunTests)],
        vec![],
    );
    service
        .submit_install(
            &kr_protocol::automation::WorkflowInstallParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: grant,
            },
            1_000,
        )
        .expect("installs");
    service
        .store()
        .pause_workflow_on_breach(definition.workflow_id, 1, "four runs at once", 1_100)
        .expect("paused");

    let read = |service: &kr_automation::AutomationService| {
        service
            .read(
                &WorkflowReadParams {
                    workflow_id: Nullable::some(definition.workflow_id),
                    ..WorkflowReadParams::default()
                },
                None,
                1_200,
            )
            .expect("a read")
    };
    let paused = read(&service);
    assert!(paused.definitions[0].paused);
    assert_eq!(paused.alerts.len(), 1);
    assert_eq!(paused.alerts[0].kind, WorkflowAlertKind::WorkflowPaused);
    assert_eq!(paused.alerts[0].reason, "four runs at once");

    service
        .submit_enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_300,
        )
        .expect("enables");
    let resumed = read(&service);
    assert!(!resumed.definitions[0].paused);
    assert_eq!(
        resumed
            .alerts
            .iter()
            .map(|alert| alert.kind)
            .collect::<Vec<_>>(),
        vec![
            WorkflowAlertKind::WorkflowPaused,
            WorkflowAlertKind::WorkflowResumed
        ]
    );
}

/// A read that names one chain is shown that chain's alert and not another's.
#[tokio::test]
async fn a_read_that_names_a_chain_shows_only_its_alerts() {
    use kr_protocol::automation::{WorkflowAlertKind, WorkflowReadParams};
    use kr_protocol::scalars::Nullable;

    let grant = test_grant_id(41);
    let service = kr_automation::AutomationService::in_memory(common::host(
        std::sync::Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(&[grant]),
        std::sync::Arc::new(kr_automation::ManualClock::new(1_000)),
    ))
    .expect("a service");
    let definition = kr_automation::create_workflow_definition(
        test_wf_id(41),
        1,
        "two chains",
        grant,
        vec![common::node("only", WorkflowActionKind::RunTests)],
        vec![],
    );
    service
        .submit_install(
            &kr_protocol::automation::WorkflowInstallParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: grant,
            },
            1_000,
        )
        .expect("installs");
    service
        .submit_enable(
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("enables");
    let mut roots = Vec::new();
    for event in ["evt-a", "evt-b"] {
        let run = service
            .submit_run(
                &kr_protocol::automation::WorkflowRunParams {
                    workflow_id: definition.workflow_id,
                    revision: definition.revision,
                    event_id: event.to_owned(),
                    event_type: "manual".to_owned(),
                    event_payload: Nullable::null(),
                },
                1_000,
            )
            .await
            .expect("runs");
        // An hour and a second after the chain began, its next reservation exhausts it and
        // commits the one alert it owes.
        assert!(
            service
                .store()
                .reserve_budget_action(run.causal_root_id, 0, 0, 1_000 + 3_600_001)
                .is_err()
        );
        roots.push(run.causal_root_id);
    }

    let read = service
        .read(
            &WorkflowReadParams {
                causal_root_id: Nullable::some(roots[0]),
                ..WorkflowReadParams::default()
            },
            None,
            1_200,
        )
        .expect("a read");
    assert_eq!(read.alerts.len(), 1, "{:?}", read.alerts);
    assert_eq!(read.alerts[0].kind, WorkflowAlertKind::CausalLimit);
    assert_eq!(read.alerts[0].causal_root_id.0, Some(roots[0]));
}

/// The admission rates are the journal's, not the running service's: a minute's allowance spent
/// before a restart is still spent after it, so reopening the service is not a way past the rate.
#[tokio::test]
async fn the_admission_rates_survive_a_restart_of_the_service() {
    use std::sync::Arc;

    use kr_automation::{
        AutomationService, ManualClock, MockActionRunner, create_workflow_definition,
    };
    use kr_protocol::automation::{WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams};
    use kr_protocol::scalars::Nullable;

    let journal = tempfile::tempdir().expect("a journal directory");
    let workflow_id = test_wf_id(20);
    let definition = create_workflow_definition(
        workflow_id,
        1,
        "rate-limited across a restart",
        test_grant_id(20),
        vec![common::node("step", WorkflowActionKind::RunTests)],
        vec![],
    );
    let open = || {
        AutomationService::open(
            journal.path(),
            common::host(
                Arc::new(MockActionRunner::new()),
                authority(),
                Arc::new(ManualClock::new(1_000)),
            ),
        )
        .expect("the journal opens")
    };
    let params = |event: &str| WorkflowRunParams {
        workflow_id,
        revision: definition.revision,
        event_id: event.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
    };
    {
        let service = open();
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
            .expect("installs");
        service
            .submit_enable(
                &WorkflowEnableParams {
                    workflow_id,
                    revision: definition.revision,
                },
                1_000,
            )
            .expect("enables");
        for index in 0..120 {
            service
                .submit_run(&params(&format!("evt-{index}")), 1_000)
                .await
                .unwrap_or_else(|error| panic!("run {index} is admitted: {error}"));
        }
    }

    let service = open();
    let refused = service
        .submit_run(&params("evt-after-restart"), 1_000)
        .await
        .expect_err("the minute's allowance was spent before the restart");
    assert!(refused.to_string().contains("rate limit"), "{refused}");
}
