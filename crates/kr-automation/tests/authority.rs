//! The grant a workflow acts under: read from the host, checked again before every node.
//!
//! Requirement rows exercised here: KR-REQ-19.04 (a workflow carries a declared grant, cannot
//! give an actor a right the granting actor lacks, and cannot turn a view-only invitation into
//! terminal input) and KR-REQ-25.14 (a shell node is reachable only under an explicit broad shell
//! grant and a declared execution environment, at dispatch and not only at install).

use std::sync::Arc;

use kr_automation::{
    ActionOutcome, ActionRunner, AutomationService, GrantStanding, GrantTable, ManualClock,
    MockActionRunner, create_workflow_definition,
};
use kr_protocol::automation::{
    EdgeCondition, NodeStatus, WorkflowDefinition, WorkflowEdge, WorkflowEnableParams,
    WorkflowInstallParams, WorkflowNode, WorkflowRunParams,
};
use kr_protocol::ids::{EnvironmentId, GrantId, WorkflowId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, Uuid};

mod common;

use common::Submit;

fn test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn test_grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

fn node(node_id: &str, action_kind: &str) -> WorkflowNode {
    WorkflowNode {
        node_id: node_id.to_owned(),
        action_kind: action_kind.to_owned(),
        action_params: match action_kind {
            "shell_command" => r#"{"command": "true"}"#.to_owned(),
            "create_session" => r#"{"title": "review"}"#.to_owned(),
            _ => r#"{"suite": "unit"}"#.to_owned(),
        },
        declared_environment: Nullable::null(),
    }
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

fn service(runner: Arc<dyn ActionRunner>, table: Arc<GrantTable>) -> AutomationService {
    AutomationService::in_memory(common::host(
        runner,
        table,
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service")
}

/// A runner that puts the workflow's grant into another standing while the first node runs.
///
/// This is what a revocation landing mid-run looks like to the engine: the first node succeeds
/// under the grant it was dispatched with, and the second is asked for afterwards.
#[derive(Debug)]
struct RevokesWhileRunning {
    table: Arc<GrantTable>,
    grant_id: GrantId,
}

impl ActionRunner for RevokesWhileRunning {
    fn execute(
        &self,
        dispatch: &kr_automation::Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        if dispatch.node.node_id == "first" {
            self.table.restand(self.grant_id, GrantStanding::Revoked);
        }
        let output = format!("ran {}", dispatch.node.node_id);
        Box::pin(async move { Ok(ActionOutcome::Success { output }) })
    }
}

/// KR-REQ-19.04: a grant that no longer stands admits no run, whatever the reason.
#[tokio::test]
async fn a_withdrawn_grant_admits_no_run() {
    let grant_id = test_grant_id(1);
    let definition = create_workflow_definition(
        test_wf_id(1),
        1,
        "withdrawn",
        grant_id,
        vec![node("step", "run_tests")],
        vec![],
    );

    for (standing, word) in [
        (GrantStanding::Revoked, "revoked"),
        (GrantStanding::Expired, "expired"),
        (GrantStanding::Pending, "redeemed"),
    ] {
        let table = common::standing(grant_id, GrantStanding::Active);
        let service = service(Arc::new(MockActionRunner::new()), Arc::clone(&table));
        service
            .submit_install(&install_params(&definition), 1_000)
            .expect("the definition installs while the grant stands");
        service
            .submit_enable(
                &WorkflowEnableParams {
                    workflow_id: definition.workflow_id,
                    revision: definition.revision,
                },
                1_000,
            )
            .expect("the revision enables");

        assert!(table.restand(grant_id, standing));
        let refusal = service
            .submit_run(&run_params(&definition, "evt-1"), 2_000)
            .await
            .expect_err("a grant in this standing admits nothing");
        assert!(refusal.to_string().contains(word), "{refusal}");
        assert!(
            service
                .store()
                .list_runs(Some(definition.workflow_id))
                .expect("the journal")
                .is_empty(),
            "a refused admission leaves no run behind"
        );
    }
}

/// KR-REQ-19.04: a grant this host never issued names no workflow it will install.
#[tokio::test]
async fn a_definition_naming_an_unissued_grant_is_refused() {
    let definition = create_workflow_definition(
        test_wf_id(2),
        1,
        "unissued",
        test_grant_id(200),
        vec![node("step", "run_tests")],
        vec![],
    );
    let service = service(
        Arc::new(MockActionRunner::new()),
        Arc::new(GrantTable::new()),
    );
    let refusal = service
        .submit_install(&install_params(&definition), 1_000)
        .expect_err("an unissued grant installs nothing");
    assert!(
        refusal.to_string().contains("not one this host issued"),
        "{refusal}"
    );
}

/// KR-REQ-19.04 and KR-REQ-25.14: a view-only grant installs no node that types at a terminal,
/// and it installs no node that creates a session either.
#[tokio::test]
async fn a_view_only_grant_installs_neither_a_shell_node_nor_a_session_node() {
    let grant_id = test_grant_id(3);
    let table = common::holding(grant_id, &[ActionRight::SessionView]);
    let service = service(Arc::new(MockActionRunner::new()), table);

    let mut shell = node("sh", "shell_command");
    shell.declared_environment = Nullable::some(EnvironmentId::new(Uuid::from_bytes([8; 16])));
    let shell_definition = create_workflow_definition(
        test_wf_id(3),
        1,
        "view-only-shell",
        grant_id,
        vec![shell],
        vec![],
    );
    let refusal = service
        .submit_install(&install_params(&shell_definition), 1_000)
        .expect_err("a view-only grant reaches no terminal");
    assert!(refusal.to_string().contains("terminal input"), "{refusal}");

    let session_definition = create_workflow_definition(
        test_wf_id(4),
        1,
        "view-only-session",
        grant_id,
        vec![node("make", "create_session")],
        vec![],
    );
    let refusal = service
        .submit_install(&install_params(&session_definition), 1_000)
        .expect_err("a view-only grant creates no session");
    assert!(refusal.to_string().contains("session.create"), "{refusal}");
}

/// KR-REQ-19.04: authority is read again before each node, so a revocation that lands between two
/// of them stops the run where it stands rather than after it has finished.
#[tokio::test]
async fn a_revocation_between_two_nodes_stops_the_second() {
    let grant_id = test_grant_id(5);
    let table = common::standing(grant_id, GrantStanding::Active);
    let definition = create_workflow_definition(
        test_wf_id(5),
        1,
        "revoked-mid-run",
        grant_id,
        vec![node("first", "run_tests"), node("second", "run_tests")],
        vec![WorkflowEdge {
            from_node: "first".to_owned(),
            to_node: "second".to_owned(),
            condition: EdgeCondition::Success,
        }],
    );

    let runner = Arc::new(RevokesWhileRunning {
        table: Arc::clone(&table),
        grant_id,
    });
    let service = service(runner, Arc::clone(&table));
    service
        .submit_install(&install_params(&definition), 1_000)
        .expect("the definition installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");

    let refusal = service
        .submit_run(&run_params(&definition, "evt-1"), 1_000)
        .await
        .expect_err("the second node is refused");
    assert!(refusal.to_string().contains("revoked"), "{refusal}");

    let receipts = service
        .store()
        .list_node_receipts(
            service
                .store()
                .list_runs(Some(definition.workflow_id))
                .expect("the journal")[0]
                .run_id,
        )
        .expect("the receipts");
    let first = receipts
        .iter()
        .find(|r| r.node_id == "first")
        .expect("the first node");
    let second = receipts
        .iter()
        .find(|r| r.node_id == "second")
        .expect("the second node");
    assert_eq!(
        first.status,
        NodeStatus::Success,
        "the first node ran under a live grant"
    );
    assert_eq!(
        second.status,
        NodeStatus::Paused,
        "the second node was never dispatched"
    );
}

/// A runner that cancels the run and withdraws its grant while the first node runs.
///
/// Both land in the window the engine has to survive: the run is cancelled, and the authority
/// the next node would need is gone. Cancellation is the terminal state, and a refusal that
/// arrives afterwards must not write over it.
#[derive(Debug)]
struct CancelsAndRevokes {
    table: Arc<GrantTable>,
    grant_id: GrantId,
    store: std::sync::Mutex<Option<Arc<kr_automation::WorkflowStore>>>,
    run_id: std::sync::Mutex<Option<kr_protocol::ids::WorkflowRunId>>,
}

impl ActionRunner for CancelsAndRevokes {
    fn execute(
        &self,
        dispatch: &kr_automation::Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        if dispatch.node.node_id == "first" {
            *self.run_id.lock().unwrap() = Some(dispatch.run_id);
            if let Some(store) = self.store.lock().unwrap().as_ref() {
                kr_automation::WorkflowEngine::new(
                    Arc::clone(store),
                    common::host(
                        Arc::new(MockActionRunner::new()),
                        Arc::clone(&self.table) as Arc<dyn kr_automation::AuthoritySource>,
                        Arc::new(ManualClock::new(1_500)),
                    ),
                )
                .cancel_run(dispatch.run_id, 1_500)
                .expect("the run is cancelled");
            }
            self.table.restand(self.grant_id, GrantStanding::Revoked);
        }
        let output = format!("ran {}", dispatch.node.node_id);
        Box::pin(async move { Ok(ActionOutcome::Success { output }) })
    }
}

/// A refusal that arrives after a cancellation does not overwrite it.
///
/// Cancelled says the host stopped asking. Paused says the host would go on once something is
/// resolved. Writing the second over the first would tell a reader a run is waiting for them
/// when nobody is going to run it.
#[tokio::test]
async fn a_refusal_after_a_cancellation_leaves_the_cancellation_standing() {
    let grant_id = test_grant_id(6);
    let table = common::standing(grant_id, GrantStanding::Active);
    let definition = create_workflow_definition(
        test_wf_id(6),
        1,
        "cancelled-then-refused",
        grant_id,
        vec![node("first", "run_tests"), node("second", "run_tests")],
        vec![WorkflowEdge {
            from_node: "first".to_owned(),
            to_node: "second".to_owned(),
            condition: EdgeCondition::Success,
        }],
    );

    let runner = Arc::new(CancelsAndRevokes {
        table: Arc::clone(&table),
        grant_id,
        store: std::sync::Mutex::new(None),
        run_id: std::sync::Mutex::new(None),
    });
    let service = service(
        Arc::clone(&runner) as Arc<dyn ActionRunner>,
        Arc::clone(&table),
    );
    *runner.store.lock().unwrap() = Some(Arc::clone(service.store()));
    service
        .submit_install(&install_params(&definition), 1_000)
        .expect("the definition installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");

    let _ = service
        .submit_run(&run_params(&definition, "evt-1"), 1_000)
        .await;

    let run_id = runner.run_id.lock().unwrap().expect("the run started");
    let receipts = service
        .store()
        .list_node_receipts(run_id)
        .expect("the receipts");
    let second = receipts
        .iter()
        .find(|receipt| receipt.node_id == "second")
        .expect("the second node");
    assert_eq!(
        second.status,
        NodeStatus::Cancelled,
        "a refusal does not undo a cancellation"
    );
    let run = service
        .store()
        .list_runs(Some(definition.workflow_id))
        .expect("the journal")
        .into_iter()
        .find(|summary| summary.run_id == run_id)
        .expect("the run");
    assert_eq!(
        run.status,
        kr_protocol::automation::WorkflowRunStatus::Cancelled
    );
}

/// A node may not reach a workspace the definition's declared scope excludes.
#[tokio::test]
async fn a_capture_node_outside_the_declared_workspace_is_refused() {
    use kr_protocol::automation::WorkflowResourceScope;
    use kr_protocol::changeset::{ChangesetCaptureParams, FileGrant};
    use kr_protocol::ids::WorkspaceId;
    use kr_protocol::project::{InclusionChoice, InclusionPolicy};

    let grant_id = test_grant_id(7);
    let declared = WorkspaceId::new(Uuid::from_bytes([30; 16]));
    let elsewhere = WorkspaceId::new(Uuid::from_bytes([31; 16]));
    let params = ChangesetCaptureParams {
        workspace_id: elsewhere,
        change_set_id: Nullable::null(),
        label: "another tree".to_owned(),
        policy: InclusionPolicy {
            dirty_files: InclusionChoice::Include,
            untracked_files: InclusionChoice::Exclude,
            submodules: InclusionChoice::Exclude,
            binary_files: InclusionChoice::Exclude,
            generated_artefacts: InclusionChoice::Exclude,
        },
        grant: FileGrant::default(),
        quiescence_declared: false,
        required_consistency: Nullable::null(),
        pin: false,
        session_id: Nullable::null(),
        workflow_run_id: Nullable::null(),
        note: String::new(),
    };
    let mut definition = create_workflow_definition(
        test_wf_id(7),
        1,
        "scoped-capture",
        grant_id,
        vec![WorkflowNode {
            node_id: "capture".to_owned(),
            action_kind: "capture_changeset".to_owned(),
            action_params: serde_json::to_string(&params).expect("typed parameters"),
            declared_environment: Nullable::null(),
        }],
        vec![],
    );
    definition.resource_scope = WorkflowResourceScope {
        workspace_id: Nullable::some(declared),
        ..WorkflowResourceScope::default()
    };

    let service = service(
        Arc::new(MockActionRunner::new()),
        common::holding(grant_id, &[ActionRight::ChangesetCreate]),
    );
    let refusal = service
        .submit_install(&install_params(&definition), 1_000)
        .expect_err("a node outside the declared scope is refused");
    assert!(
        refusal.to_string().contains("scoped to workspace"),
        "{refusal}"
    );
}

/// A runner that asks the grant again and is refused before its effect begins.
#[derive(Debug)]
struct RefusesBeforeItsEffect;

impl ActionRunner for RefusesBeforeItsEffect {
    fn execute(
        &self,
        _dispatch: &kr_automation::Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        Box::pin(async {
            Err(kr_automation::AutomationError::PermissionDenied(
                "the grant was revoked while the effect waited to begin".to_owned(),
            ))
        })
    }
}

/// A revocation that completes after the engine's last check and before the effect begins is
/// still a refusal. The runner asks again where the effect starts; the node and its run pause
/// rather than failing, because no action was performed.
#[tokio::test]
async fn a_refusal_where_the_effect_begins_pauses_the_node_and_its_run() {
    let grant_id = test_grant_id(11);
    let definition = create_workflow_definition(
        test_wf_id(11),
        1,
        "refused at the effect",
        grant_id,
        vec![node("only", "run_tests")],
        vec![],
    );
    let service = service(
        Arc::new(RefusesBeforeItsEffect),
        common::standing(grant_id, GrantStanding::Active),
    );
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

    let refusal = service
        .submit_run(&run_params(&definition, "evt-1"), 1_000)
        .await
        .expect_err("the refusal comes back to the caller");
    assert!(refusal.to_string().contains("revoked"), "{refusal}");

    let runs = service
        .store()
        .list_runs(Some(definition.workflow_id))
        .expect("the journal");
    assert_eq!(
        runs[0].status,
        kr_protocol::automation::WorkflowRunStatus::Paused
    );
    let receipts = service
        .store()
        .list_node_receipts(runs[0].run_id)
        .expect("the journal");
    assert_eq!(receipts[0].status, NodeStatus::Paused);
    assert!(receipts[0].output.0.is_none(), "nothing was performed");
}

/// A grant whose environment selector does not cover the environment this host serves admits no
/// definition here, even when the definition declares no environment of its own.
#[tokio::test]
async fn a_grant_that_does_not_cover_this_environment_installs_nothing_here() {
    let grant_id = test_grant_id(12);
    let mut grant = common::grant_of(grant_id, ActionRight::ALL);
    grant.environment_selector = kr_protocol::grant::EnvironmentSelector::These {
        environment_ids: [EnvironmentId::new(Uuid::from_bytes([0x44; 16]))]
            .into_iter()
            .collect(),
    };
    let table = GrantTable::new();
    table.insert(grant);
    let service = service(Arc::new(MockActionRunner::new()), Arc::new(table));
    let definition = create_workflow_definition(
        test_wf_id(12),
        1,
        "elsewhere",
        grant_id,
        vec![node("only", "run_tests")],
        vec![],
    );
    let refusal = service
        .submit_install(&install_params(&definition), 1_000)
        .expect_err("the grant does not reach this environment");
    assert!(refusal.to_string().contains("environment"), "{refusal}");
}

/// A submission that carries its caller's grant reaches only the workflows that act under that
/// grant, and a read for that caller shows only those.
#[tokio::test]
async fn a_caller_grant_reaches_only_the_workflows_under_it() {
    use kr_automation::{ActionKey, Submitted};
    use kr_protocol::method::Method;

    let held = test_grant_id(13);
    let other = test_grant_id(14);
    let service = service(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[held, other]),
    );
    let mine = create_workflow_definition(
        test_wf_id(13),
        1,
        "mine",
        held,
        vec![node("only", "run_tests")],
        vec![],
    );
    let theirs = create_workflow_definition(
        test_wf_id(14),
        1,
        "theirs",
        other,
        vec![node("only", "run_tests")],
        vec![],
    );
    service
        .submit_install(&install_params(&theirs), 1_000)
        .expect("the owner installs under any grant");

    fn as_caller(key: &ActionKey, held: GrantId) -> Submitted<'_> {
        Submitted {
            key,
            admission: &common::admitted,
            caller_grant: Some(held),
        }
    }
    let key = common::fresh_action(Method::WorkflowInstall);
    service
        .install(&install_params(&mine), &as_caller(&key, held), 1_000)
        .expect("a caller installs under the grant it holds");
    let key = common::fresh_action(Method::WorkflowInstall);
    let refusal = service
        .install(
            &install_params(&create_workflow_definition(
                test_wf_id(15),
                1,
                "borrowed",
                other,
                vec![node("only", "run_tests")],
                vec![],
            )),
            &as_caller(&key, held),
            1_000,
        )
        .expect_err("not under a grant it does not hold");
    assert!(refusal.to_string().contains("grant"), "{refusal}");

    let key = common::fresh_action(Method::WorkflowEnable);
    let refusal = service
        .enable(
            &WorkflowEnableParams {
                workflow_id: theirs.workflow_id,
                revision: theirs.revision,
            },
            &as_caller(&key, held),
            1_000,
        )
        .expect_err("another grant's workflow is not the caller's");
    assert!(
        refusal.to_string().contains("not found"),
        "answered as a revision that is not installed: {refusal}"
    );

    let seen = service
        .read(
            &kr_protocol::automation::WorkflowReadParams::default(),
            Some(held),
            1_000,
        )
        .expect("a read");
    assert_eq!(seen.definitions.len(), 1);
    assert_eq!(seen.definitions[0].workflow_id, mine.workflow_id);
    let everything = service
        .read(
            &kr_protocol::automation::WorkflowReadParams::default(),
            None,
            1_000,
        )
        .expect("a read");
    assert_eq!(everything.definitions.len(), 2, "the owner sees both");
}

/// Submits `params` as a paired device holding `held`.
fn as_device(held: GrantId) -> impl Fn(&kr_automation::ActionKey) -> kr_automation::Submitted<'_> {
    move |key| kr_automation::Submitted {
        key,
        admission: &common::admitted,
        caller_grant: Some(held),
    }
}

/// A revision a paired device installed is triggered only by runs under the device's own grant.
/// Without that, a device could subscribe to the owner's events, spend the owner's causal budget
/// with runs admitted into the owner's chain, and read the owner's run identifiers back as its
/// descendants' parents. A subscription the owner installs may still cross grants.
#[tokio::test]
async fn a_device_subscription_is_triggered_only_by_runs_under_its_own_grant() {
    use kr_protocol::method::Method;

    let owners = test_grant_id(20);
    let devices = test_grant_id(21);
    let service = service(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[owners, devices]),
    );
    let with_trigger = |id: u8, grant: GrantId, trigger: &str| {
        let mut definition = create_workflow_definition(
            test_wf_id(id),
            1,
            "subscriber",
            grant,
            vec![node("only", "run_tests")],
            vec![],
        );
        definition.trigger.event_type = trigger.to_owned();
        definition
    };
    let enable_params = |definition: &WorkflowDefinition| WorkflowEnableParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
    };

    // The owner's producer, installed and run by the owner.
    let owner_producer = with_trigger(20, owners, "manual");
    service
        .submit_install(&install_params(&owner_producer), 1_000)
        .expect("installs");
    service
        .submit_enable(&enable_params(&owner_producer), 1_000)
        .expect("enables");

    // A device's subscription to the same event, installed and enabled by the device.
    let device_subscriber = with_trigger(21, devices, "tests.passed");
    let device = as_device(devices);
    let key = common::fresh_action(Method::WorkflowInstall);
    service
        .install(&install_params(&device_subscriber), &device(&key), 1_000)
        .expect("a device installs under its own grant");
    let key = common::fresh_action(Method::WorkflowEnable);
    service
        .enable(&enable_params(&device_subscriber), &device(&key), 1_000)
        .expect("a device enables its own workflow");

    service
        .submit_run(&run_params(&owner_producer, "evt-owner"), 1_000)
        .await
        .expect("the owner's run completes");
    let decisions = service.dispatch_triggers(2_000).await.expect("a pass");
    assert!(
        decisions
            .iter()
            .all(|decision| decision.workflow_id != device_subscriber.workflow_id),
        "the owner's event does not start the device's subscription: {decisions:?}"
    );

    // The device's own producer does start it.
    let device_producer = with_trigger(22, devices, "manual");
    let key = common::fresh_action(Method::WorkflowInstall);
    service
        .install(&install_params(&device_producer), &device(&key), 1_000)
        .expect("installs");
    let key = common::fresh_action(Method::WorkflowEnable);
    service
        .enable(&enable_params(&device_producer), &device(&key), 1_000)
        .expect("enables");
    let key = common::fresh_action(Method::WorkflowRun);
    service
        .run(
            &run_params(&device_producer, "evt-device"),
            &device(&key),
            1_000,
        )
        .await
        .expect("the device's run completes");
    let decisions = service.dispatch_triggers(3_000).await.expect("a pass");
    assert!(
        decisions.iter().any(
            |decision| decision.workflow_id == device_subscriber.workflow_id
                && decision.outcome.is_ok()
        ),
        "{decisions:?}"
    );
}

/// A paired device reaches an existing workflow only when it acts under the device's grant: it
/// cannot add a revision to the owner's workflow, and a revision it cannot reach is answered as
/// one that is not installed, naming no grant. A revision number the store cannot hold is refused.
#[tokio::test]
async fn a_device_cannot_take_or_probe_another_grant_s_workflow() {
    use kr_protocol::error::ProtocolError;
    use kr_protocol::method::Method;

    let owners = test_grant_id(23);
    let devices = test_grant_id(24);
    let service = service(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[owners, devices]),
    );
    let owners_workflow = create_workflow_definition(
        test_wf_id(33),
        1,
        "the owner's",
        owners,
        vec![node("only", "run_tests")],
        vec![],
    );
    service
        .submit_install(&install_params(&owners_workflow), 1_000)
        .expect("installs");
    let device = as_device(devices);

    // Revision 2 of the owner's workflow, under the device's grant.
    let mut next = owners_workflow.clone();
    next.revision = kr_protocol::scalars::U64::new(2);
    next.grant_reference = devices;
    let key = common::fresh_action(Method::WorkflowInstall);
    let refusal = service
        .install(&install_params(&next), &device(&key), 1_000)
        .expect_err("the owner's workflow identity is not the device's");
    assert!(
        !refusal.to_string().contains(&owners.to_string()),
        "{refusal}"
    );
    let mut owners_next = owners_workflow.clone();
    owners_next.revision = kr_protocol::scalars::U64::new(2);
    service
        .submit_install(&install_params(&owners_next), 1_100)
        .expect("the owner's own next revision is still free");

    // The owner's revision and an absent one are refused alike.
    let key = common::fresh_action(Method::WorkflowEnable);
    let inaccessible = ProtocolError::from(
        service
            .enable(
                &WorkflowEnableParams {
                    workflow_id: owners_workflow.workflow_id,
                    revision: owners_workflow.revision,
                },
                &device(&key),
                1_000,
            )
            .expect_err("not the device's"),
    );
    let key = common::fresh_action(Method::WorkflowEnable);
    let absent = ProtocolError::from(
        service
            .enable(
                &WorkflowEnableParams {
                    workflow_id: owners_workflow.workflow_id,
                    revision: kr_protocol::scalars::U64::new(9),
                },
                &device(&key),
                1_000,
            )
            .expect_err("not installed"),
    );
    assert_eq!(inaccessible.code, absent.code);
    assert_eq!(inaccessible.message, absent.message);
    assert!(!inaccessible.message.contains(&owners.to_string()));

    // A revision past what the journal can store exactly.
    let mut enormous = create_workflow_definition(
        test_wf_id(35),
        1,
        "enormous",
        owners,
        vec![node("only", "run_tests")],
        vec![],
    );
    enormous.revision = kr_protocol::scalars::U64::new(u64::MAX);
    let refusal = service
        .submit_install(&install_params(&enormous), 1_000)
        .expect_err("the journal cannot hold this revision number");
    assert!(refusal.to_string().contains("revision"), "{refusal}");
}

/// A node with the parameters its action kind requires.
fn typed_node(node_id: &str, action_kind: &str) -> WorkflowNode {
    WorkflowNode {
        node_id: node_id.to_owned(),
        action_kind: action_kind.to_owned(),
        action_params: match action_kind {
            "request_review" => r#"{"reviewer_id": "reviewer"}"#.to_owned(),
            "create_session" => r#"{"title": "follow-up"}"#.to_owned(),
            _ => r#"{"suite": "unit"}"#.to_owned(),
        },
        declared_environment: Nullable::null(),
    }
}

/// Installs and enables a one-node workflow, as the owner or as a paired device.
fn installed(
    service: &AutomationService,
    id: u8,
    grant: GrantId,
    trigger: &str,
    action_kind: &str,
    device: Option<GrantId>,
) -> WorkflowDefinition {
    use kr_protocol::method::Method;

    let mut definition = create_workflow_definition(
        test_wf_id(id),
        1,
        "chain member",
        grant,
        vec![typed_node("only", action_kind)],
        vec![],
    );
    definition.trigger.event_type = trigger.to_owned();
    let enable = WorkflowEnableParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
    };
    match device {
        None => {
            service
                .submit_install(&install_params(&definition), 1_000)
                .expect("installs");
            service.submit_enable(&enable, 1_000).expect("enables");
        }
        Some(held) => {
            let device = as_device(held);
            let key = common::fresh_action(Method::WorkflowInstall);
            service
                .install(&install_params(&definition), &device(&key), 1_000)
                .expect("a device installs under its own grant");
            let key = common::fresh_action(Method::WorkflowEnable);
            service
                .enable(&enable, &device(&key), 1_000)
                .expect("a device enables its own workflow");
        }
    }
    definition
}

/// A crossing the owner installs, a workflow under a device's grant triggered by the owner's
/// events, brings a run under the device's grant into the owner's chain. That is the owner's
/// decision, and what the device installed does not follow it there: a device's subscription is
/// triggered only by a run whose whole chain, from its root, acts under the device's grant. In
/// a chain of its own, the same subscription is triggered.
#[tokio::test]
async fn a_device_subscription_does_not_follow_an_owner_crossing_into_another_grant_s_chain() {
    use kr_protocol::method::Method;

    let owners = test_grant_id(25);
    let devices = test_grant_id(26);
    let service = service(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[owners, devices]),
    );
    let producer = installed(&service, 40, owners, "manual", "run_tests", None);
    let crossing = installed(
        &service,
        41,
        devices,
        "tests.passed",
        "request_review",
        None,
    );
    let subscriber = installed(
        &service,
        42,
        devices,
        "review.completed",
        "create_session",
        Some(devices),
    );

    let owners_run = service
        .submit_run(&run_params(&producer, "evt-owner"), 1_000)
        .await
        .expect("the owner's run completes");
    let mut decisions = service.dispatch_triggers(2_000).await.expect("a pass");
    decisions.extend(service.dispatch_triggers(3_000).await.expect("a pass"));
    assert!(
        decisions.iter().any(
            |decision| decision.workflow_id == crossing.workflow_id && decision.outcome.is_ok()
        ),
        "the owner's crossing joins the owner's chain: {decisions:?}"
    );
    assert!(
        decisions
            .iter()
            .all(|decision| decision.workflow_id != subscriber.workflow_id),
        "the device's subscription does not follow the crossing: {decisions:?}"
    );
    let budget = service
        .store()
        .get_budget(owners_run.causal_root_id)
        .unwrap()
        .expect("the owner's chain has a budget");
    assert_eq!(
        budget.total_runs, 2,
        "the owner's run and the crossing only"
    );

    // A chain the device's own run started is the device's, and the subscription follows it.
    let device_root = installed(
        &service,
        43,
        devices,
        "manual",
        "request_review",
        Some(devices),
    );
    let device = as_device(devices);
    let key = common::fresh_action(Method::WorkflowRun);
    service
        .run(
            &run_params(&device_root, "evt-device"),
            &device(&key),
            4_000,
        )
        .await
        .expect("the device's run completes");
    let decisions = service.dispatch_triggers(5_000).await.expect("a pass");
    assert!(
        decisions
            .iter()
            .any(|decision| decision.workflow_id == subscriber.workflow_id
                && decision.outcome.is_ok()),
        "{decisions:?}"
    );
}

/// A device reads a run of its own that a crossing brought into another grant's chain as its
/// own, and nothing of that chain: not the run it descends from, not the node that triggered it,
/// not the chain's remaining budget, not the chain's alerts. The owner reads all of it.
#[tokio::test]
async fn a_device_reads_nothing_of_another_grant_s_chain_through_an_owner_crossing() {
    use kr_protocol::automation::WorkflowReadParams;

    let owners = test_grant_id(27);
    let devices = test_grant_id(28);
    let service = service(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[owners, devices]),
    );
    let producer = installed(&service, 44, owners, "manual", "run_tests", None);
    let crossing = installed(
        &service,
        45,
        devices,
        "tests.passed",
        "request_review",
        None,
    );
    let owners_run = service
        .submit_run(&run_params(&producer, "evt-owner"), 1_000)
        .await
        .expect("the owner's run completes");
    service.dispatch_triggers(2_000).await.expect("a pass");
    let root = owners_run.causal_root_id;
    // The owner's chain runs out of time, and owes its alert.
    assert!(
        service
            .store()
            .reserve_budget_action(root, 0, 1_000 + 3_600_001)
            .is_err(),
        "the chain is out of lifetime"
    );

    let about = |run_id| WorkflowReadParams {
        workflow_id: Nullable::some(crossing.workflow_id),
        run_id: Nullable::some(run_id),
        causal_root_id: Nullable::some(root),
        ..WorkflowReadParams::default()
    };
    let owners_view = service
        .read(&WorkflowReadParams::default(), None, 3_000)
        .expect("reads");
    let crossing_run = owners_view
        .runs
        .iter()
        .find(|run| run.workflow_id == crossing.workflow_id)
        .expect("the crossing ran")
        .clone();
    assert_eq!(crossing_run.parent_run_id.0, Some(owners_run.run_id));
    assert_eq!(crossing_run.causal_root_id, root);
    let owners_view = service
        .read(&about(crossing_run.run_id), None, 3_000)
        .expect("reads");
    assert!(owners_view.remaining_causal_budget.0.is_some());
    assert!(
        !owners_view.alerts.is_empty(),
        "the owner sees the chain's alert"
    );
    assert!(
        owners_view
            .node_receipts
            .iter()
            .all(|receipt| receipt.causal_parent.0.is_some())
    );

    let devices_view = service
        .read(&about(crossing_run.run_id), Some(devices), 3_000)
        .expect("reads");
    let seen = devices_view
        .runs
        .iter()
        .find(|run| run.run_id == crossing_run.run_id)
        .expect("the device sees the run under its grant");
    assert_eq!(seen.parent_run_id.0, None);
    assert_eq!(seen.parent_node_id.0, None);
    assert_eq!(seen.trigger_event_id, kr_automation::DERIVED_TRIGGER_PREFIX);
    assert!(!devices_view.node_receipts.is_empty());
    assert!(
        devices_view
            .node_receipts
            .iter()
            .all(|receipt| receipt.causal_parent.0.is_none())
    );
    assert!(devices_view.remaining_causal_budget.0.is_none());
    assert!(devices_view.alerts.is_empty(), "{:?}", devices_view.alerts);
    assert!(
        devices_view
            .runs
            .iter()
            .all(|run| run.run_id != owners_run.run_id)
    );
}

/// A revision number the journal cannot hold names no revision, whoever asks and whatever is
/// stored at the largest number it can hold. Such a request is answered exactly as one for a
/// revision that is not installed, before anything is said about the one that is.
#[tokio::test]
async fn a_revision_past_what_the_journal_holds_is_answered_as_not_installed() {
    use kr_protocol::automation::WorkflowPauseParams;
    use kr_protocol::error::ProtocolError;
    use kr_protocol::method::Method;
    use kr_protocol::scalars::U64;

    let owners = test_grant_id(29);
    let devices = test_grant_id(30);
    let service = service(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[owners, devices]),
    );
    let mut largest = create_workflow_definition(
        test_wf_id(46),
        1,
        "the largest revision",
        owners,
        vec![typed_node("only", "run_tests")],
        vec![],
    );
    largest.revision = U64::new(u64::try_from(i64::MAX).expect("fits"));
    service
        .submit_install(&install_params(&largest), 1_000)
        .expect("the largest revision the journal holds installs");
    let device = as_device(devices);
    let past = U64::new(u64::MAX);

    let key = common::fresh_action(Method::WorkflowEnable);
    let absent = ProtocolError::from(
        service
            .enable(
                &WorkflowEnableParams {
                    workflow_id: largest.workflow_id,
                    revision: U64::new(9),
                },
                &device(&key),
                1_000,
            )
            .expect_err("not installed"),
    );
    let key = common::fresh_action(Method::WorkflowEnable);
    let enable = ProtocolError::from(
        service
            .enable(
                &WorkflowEnableParams {
                    workflow_id: largest.workflow_id,
                    revision: past,
                },
                &device(&key),
                1_000,
            )
            .expect_err("no such revision"),
    );
    let key = common::fresh_action(Method::WorkflowPause);
    let pause = ProtocolError::from(
        service
            .pause(
                &WorkflowPauseParams {
                    workflow_id: largest.workflow_id,
                    revision: past,
                    reason: Nullable::null(),
                },
                &device(&key),
                1_000,
            )
            .expect_err("no such revision"),
    );
    let mut run = run_params(&largest, "evt-past");
    run.revision = past;
    let key = common::fresh_action(Method::WorkflowRun);
    let ran = ProtocolError::from(
        service
            .run(&run, &device(&key), 1_000)
            .await
            .expect_err("no such revision"),
    );
    for refusal in [&enable, &pause, &ran] {
        assert_eq!(refusal.code, absent.code, "{refusal:?}");
        assert_eq!(refusal.message, absent.message, "{refusal:?}");
        assert!(
            !refusal.message.contains(&i64::MAX.to_string()),
            "{refusal:?}"
        );
    }

    // The owner is told the same: the number names nothing, not a revision that differs.
    let owners_enable = ProtocolError::from(
        service
            .submit_enable(
                &WorkflowEnableParams {
                    workflow_id: largest.workflow_id,
                    revision: past,
                },
                1_000,
            )
            .expect_err("no such revision"),
    );
    assert_eq!(owners_enable.code, absent.code, "{owners_enable:?}");
}
