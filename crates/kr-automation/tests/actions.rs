//! Each mutation is an action whose effect and record commit together.
//!
//! Section 23 gives the four automation mutations `ACTION` idempotency, and section 25 makes a run
//! durable before its first node dispatches. The journal does both in one transaction: an action
//! either has a record, written with its effect, or has not been performed. These cases are the
//! ones that would expose a gap between the two: a repeat that arrives while the run it started is
//! still dispatching, an admission that lapses before the first write, a refusal repeated after the
//! world changed, and a cancellation that lands while an action is running.
//!
//! Requirement rows: KR-REQ-23.52 (the method group's action idempotency), KR-REQ-25.19 (a run is
//! persisted before it dispatches, and cancellation stops undispatched work without claiming
//! anything about what already ran).

use std::sync::{Arc, OnceLock};

use kr_automation::{
    ActionKey, ActionOutcome, ActionRunner, AutomationError, AutomationService, Dispatch,
    ManualClock, Submitted, WorkflowStore, create_workflow_definition,
};
use kr_protocol::automation::{
    NodeStatus, WorkflowDefinition, WorkflowEnableParams, WorkflowInstallParams, WorkflowNode,
    WorkflowRunParams, WorkflowRunStatus,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{GrantId, WorkflowId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use tokio::sync::Notify;

mod common;

use common::Submit;

fn workflow_id(value: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([value; 16]))
}

fn grant_id(value: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([value; 16]))
}

fn one_node(id: WorkflowId, grant: GrantId) -> WorkflowDefinition {
    create_workflow_definition(
        id,
        1,
        "one node",
        grant,
        vec![WorkflowNode {
            node_id: "only".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "unit"}"#.to_owned(),
            declared_environment: Nullable::null(),
        }],
        vec![],
    )
}

fn install_params(definition: &WorkflowDefinition) -> WorkflowInstallParams {
    WorkflowInstallParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
        definition: definition.clone(),
        grant_reference: definition.grant_reference,
    }
}

fn run_params(definition: &WorkflowDefinition, event_id: &str) -> WorkflowRunParams {
    WorkflowRunParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
        event_id: event_id.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
    }
}

/// A runner that holds its one action until the test lets it go.
#[derive(Default)]
struct Held {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl ActionRunner for Held {
    fn execute(
        &self,
        _dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            Ok(ActionOutcome::Success {
                output: "done".to_owned(),
            })
        })
    }
}

/// A repeat of a `workflow.run` action that arrives while its run is still dispatching is told
/// where that run stands. It is neither reported as an outcome nobody can establish nor started a
/// second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeat_during_its_run_is_told_where_the_run_stands_and_starts_nothing() {
    let runner = Arc::new(Held::default());
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&runner) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(1)]),
            Arc::new(ManualClock::new(1_000)),
        ))
        .expect("a service"),
    );
    let definition = one_node(workflow_id(1), grant_id(1));
    service
        .submit_install(&install_params(&definition), 1_000)
        .expect("installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("enables");

    let key = common::fresh_action(Method::WorkflowRun);
    let first = {
        let service = Arc::clone(&service);
        let key = key.clone();
        let params = run_params(&definition, "evt-1");
        tokio::spawn(async move {
            service
                .run(
                    &params,
                    &Submitted {
                        key: &key,
                        admission: &common::admitted,
                    },
                    1_000,
                )
                .await
        })
    };
    runner.entered.notified().await;

    let repeat = service
        .run(
            &run_params(&definition, "evt-1"),
            &Submitted {
                key: &key,
                admission: &common::admitted,
            },
            1_000,
        )
        .await
        .expect("the repeat is answered from the record");
    assert_eq!(repeat.status, WorkflowRunStatus::Running, "{repeat:?}");

    runner.release.notify_one();
    let finished = first
        .await
        .expect("the first submission's task")
        .expect("the run completes");
    assert_eq!(finished.status, WorkflowRunStatus::Completed);
    assert_eq!(repeat.run_id, finished.run_id, "one action, one run");
    assert_eq!(
        service
            .store()
            .list_runs(Some(definition.workflow_id))
            .unwrap()
            .len(),
        1
    );

    // Asked again afterwards, the same action is told what the run came to.
    let later = service
        .answered(&key)
        .expect("the record is read")
        .expect("there is one");
    assert_eq!(
        later,
        kr_automation::Answer::Ran(kr_protocol::automation::WorkflowRunResult {
            status: WorkflowRunStatus::Completed,
            ..repeat
        })
    );
}

/// An admission that lapsed before the first write performs nothing and records nothing, so the
/// same action submitted while still admitted is decided afresh.
#[test]
fn a_lapsed_admission_performs_nothing_and_leaves_no_record() {
    let service = AutomationService::in_memory(common::host(
        Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(&[grant_id(2)]),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");
    let definition = one_node(workflow_id(2), grant_id(2));
    let key = common::fresh_action(Method::WorkflowInstall);

    let lapsed = || -> kr_automation::Result<()> {
        Err(AutomationError::Lapsed {
            code: ErrorCode::PermissionDenied,
            detail: "the authority this action was admitted under was withdrawn".to_owned(),
        })
    };
    let refused = service
        .install(
            &install_params(&definition),
            &Submitted {
                key: &key,
                admission: &lapsed,
            },
            1_000,
        )
        .expect_err("nothing is installed under a lapsed admission");
    assert_eq!(
        ProtocolError::from(refused).code,
        ErrorCode::PermissionDenied
    );
    assert!(
        service
            .store()
            .get_definition(definition.workflow_id, 1)
            .unwrap()
            .is_none()
    );
    assert!(service.answered(&key).unwrap().is_none(), "no record");

    service
        .install(
            &install_params(&definition),
            &Submitted {
                key: &key,
                admission: &common::admitted,
            },
            1_000,
        )
        .expect("the same action, still admitted, is performed");
    assert!(
        service
            .store()
            .get_definition(definition.workflow_id, 1)
            .unwrap()
            .is_some()
    );
}

/// A refusal is what the action came to, and a repeat is given the same refusal even after the
/// state that caused it has changed. Performing it now would be a second, different action under
/// the first one's identifier.
#[test]
fn a_repeated_refusal_is_answered_as_it_was_decided() {
    let service = AutomationService::in_memory(common::host(
        Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(&[grant_id(3)]),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");
    let definition = one_node(workflow_id(3), grant_id(3));
    let enable = WorkflowEnableParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
    };
    let key = common::fresh_action(Method::WorkflowEnable);
    let submitted = Submitted {
        key: &key,
        admission: &common::admitted,
    };

    let first = service
        .enable(&enable, &submitted, 1_000)
        .expect_err("nothing is installed to enable");
    let first = ProtocolError::from(first);

    service
        .submit_install(&install_params(&definition), 1_000)
        .expect("installs");
    let repeated = ProtocolError::from(
        service
            .enable(&enable, &submitted, 1_001)
            .expect_err("the repeat is refused as it was the first time"),
    );
    assert_eq!(repeated, first);
    let installed = service
        .store()
        .get_definition(definition.workflow_id, 1)
        .unwrap()
        .expect("installed");
    assert!(!installed.enabled, "the repeat enabled nothing");

    // A different revision under the same identifier is another action.
    let reused = service
        .enable(
            &WorkflowEnableParams {
                revision: U64::new(2),
                ..enable
            },
            &Submitted {
                key: &ActionKey {
                    digest: vec![0xee],
                    ..key.clone()
                },
                admission: &common::admitted,
            },
            1_002,
        )
        .expect_err("a reused identifier is refused");
    assert_eq!(ProtocolError::from(reused).code, ErrorCode::IdConflict);
}

/// A runner that cancels its own run while its action is running, and then reports success.
#[derive(Default)]
struct CancelledWhileRunning {
    store: OnceLock<Arc<WorkflowStore>>,
}

impl ActionRunner for CancelledWhileRunning {
    fn execute(
        &self,
        dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        let store = Arc::clone(self.store.get().expect("the journal is known"));
        let run_id = dispatch.run_id;
        Box::pin(async move {
            store.cancel_run(run_id, "stopped by the person", 1_500)?;
            Ok(ActionOutcome::Success {
                output: "finished after the host stopped asking".to_owned(),
            })
        })
    }
}

/// A cancellation that lands while a node's action runs keeps the node and the run cancelled.
/// The action's late success is not read as the run having completed.
#[tokio::test]
async fn a_cancellation_during_an_action_is_not_overwritten_by_its_late_success() {
    let runner = Arc::new(CancelledWhileRunning::default());
    let service = AutomationService::in_memory(common::host(
        Arc::clone(&runner) as Arc<dyn ActionRunner>,
        common::every_right(&[grant_id(4)]),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");
    runner
        .store
        .set(Arc::clone(service.store()))
        .expect("set once");
    let definition = one_node(workflow_id(4), grant_id(4));
    service
        .submit_install(&install_params(&definition), 1_000)
        .expect("installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("enables");

    let run = service
        .submit_run(&run_params(&definition, "evt-1"), 1_000)
        .await
        .expect("the run is admitted");
    assert_eq!(run.status, WorkflowRunStatus::Cancelled, "{run:?}");

    let receipts = service.store().list_node_receipts(run.run_id).unwrap();
    assert_eq!(receipts[0].status, NodeStatus::Cancelled);
    assert!(
        receipts[0].output.0.is_none(),
        "the late answer is not recorded"
    );
    let runs = service
        .store()
        .list_runs(Some(definition.workflow_id))
        .unwrap();
    assert_eq!(runs[0].status, WorkflowRunStatus::Cancelled);
}
