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
        causal_parent: Nullable::null(),
    }
}

fn service(runner: Arc<dyn ActionRunner>, table: Arc<GrantTable>) -> AutomationService {
    AutomationService::in_memory_with_clock(runner, table, Arc::new(ManualClock::new(1_000)))
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
            .install(&install_params(&definition), 1_000)
            .expect("the definition installs while the grant stands");
        service
            .enable(
                &WorkflowEnableParams {
                    workflow_id: definition.workflow_id,
                    revision: definition.revision,
                },
                1_000,
            )
            .expect("the revision enables");

        assert!(table.restand(grant_id, standing));
        let refusal = service
            .run(&run_params(&definition, "evt-1"), 2_000)
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
        .install(&install_params(&definition), 1_000)
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
        .install(&install_params(&shell_definition), 1_000)
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
        .install(&install_params(&session_definition), 1_000)
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
        .install(&install_params(&definition), 1_000)
        .expect("the definition installs");
    service
        .enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");

    let refusal = service
        .run(&run_params(&definition, "evt-1"), 1_000)
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
