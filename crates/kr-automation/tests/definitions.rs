//! Tests for workflow definition validation, cycle rejection, broad-shell requirement,
//! and template rejection.

use kr_automation::{create_workflow_definition, validate_definition};
use kr_protocol::automation::{EdgeCondition, WorkflowEdge, WorkflowNode};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId, WorkflowId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

fn test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn test_grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

fn test_env_id(v: u8) -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([v; 16]))
}

fn make_dummy_grant(grant_id: GrantId, has_terminal_input: bool) -> Grant {
    let mut actions = Vec::new();
    if has_terminal_input {
        actions.push(ActionRight::TerminalInput);
    }
    actions.push(ActionRight::FilesRead);

    Grant {
        grant_id,
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: CanonicalSet::from_iter(actions),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: true,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

#[test]
fn valid_dag_definition_passes() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = WorkflowNode {
        node_id: "test".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: r#"{"suite": "unit"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "review".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: r#"{"reviewer_id": "alice"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };
    let e1 = WorkflowEdge {
        from_node: "test".to_owned(),
        to_node: "review".to_owned(),
        condition: EdgeCondition::Success,
    };

    let def = create_workflow_definition(
        test_wf_id(1),
        1,
        "ci-workflow",
        test_grant_id(1),
        vec![n1, n2],
        vec![e1],
    );

    assert!(validate_definition(&def, Some(&grant)).is_ok());
}

#[test]
fn cyclic_graph_is_rejected_two_nodes() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = WorkflowNode {
        node_id: "a".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "b".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let e1 = WorkflowEdge {
        from_node: "a".to_owned(),
        to_node: "b".to_owned(),
        condition: EdgeCondition::Success,
    };
    let e2 = WorkflowEdge {
        from_node: "b".to_owned(),
        to_node: "a".to_owned(),
        condition: EdgeCondition::Success,
    };

    let def = create_workflow_definition(
        test_wf_id(1),
        1,
        "cyclic-2",
        test_grant_id(1),
        vec![n1, n2],
        vec![e1, e2],
    );

    let err = validate_definition(&def, Some(&grant)).unwrap_err();
    assert!(err.to_string().contains("cyclic"));
}

#[test]
fn cyclic_graph_is_rejected_self_loop() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = WorkflowNode {
        node_id: "self_loop".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let e1 = WorkflowEdge {
        from_node: "self_loop".to_owned(),
        to_node: "self_loop".to_owned(),
        condition: EdgeCondition::Success,
    };

    let def = create_workflow_definition(
        test_wf_id(1),
        1,
        "self-loop",
        test_grant_id(1),
        vec![n1],
        vec![e1],
    );

    let err = validate_definition(&def, Some(&grant)).unwrap_err();
    assert!(err.to_string().contains("cyclic"));
}

#[test]
fn cyclic_graph_is_rejected_three_nodes() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = WorkflowNode {
        node_id: "a".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n2 = WorkflowNode {
        node_id: "b".to_owned(),
        action_kind: "run_tests".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };
    let n3 = WorkflowNode {
        node_id: "c".to_owned(),
        action_kind: "request_review".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };

    let edges = vec![
        WorkflowEdge {
            from_node: "a".to_owned(),
            to_node: "b".to_owned(),
            condition: EdgeCondition::Success,
        },
        WorkflowEdge {
            from_node: "b".to_owned(),
            to_node: "c".to_owned(),
            condition: EdgeCondition::Success,
        },
        WorkflowEdge {
            from_node: "c".to_owned(),
            to_node: "a".to_owned(),
            condition: EdgeCondition::Failure,
        },
    ];

    let def = create_workflow_definition(
        test_wf_id(1),
        1,
        "cyclic-3",
        test_grant_id(1),
        vec![n1, n2, n3],
        edges,
    );

    let err = validate_definition(&def, Some(&grant)).unwrap_err();
    assert!(err.to_string().contains("cyclic"));
}

#[test]
fn broad_shell_command_requires_declared_environment_and_terminal_input() {
    let node_without_env = WorkflowNode {
        node_id: "sh1".to_owned(),
        action_kind: "shell_command".to_owned(),
        action_params: r#"{"command": "cargo test"}"#.to_owned(),
        declared_environment: Nullable::null(),
    };

    let def1 = create_workflow_definition(
        test_wf_id(1),
        1,
        "shell-no-env",
        test_grant_id(1),
        vec![node_without_env],
        vec![],
    );

    let grant_with_terminal = make_dummy_grant(test_grant_id(1), true);
    let grant_without_terminal = make_dummy_grant(test_grant_id(1), false);

    // Fails because no declared environment
    let err1 = validate_definition(&def1, Some(&grant_with_terminal)).unwrap_err();
    assert!(err1.to_string().contains("declared_environment"));

    let node_with_env = WorkflowNode {
        node_id: "sh2".to_owned(),
        action_kind: "shell_command".to_owned(),
        action_params: r#"{"command": "cargo test"}"#.to_owned(),
        declared_environment: Nullable::some(test_env_id(10)),
    };

    let def2 = create_workflow_definition(
        test_wf_id(2),
        1,
        "shell-with-env",
        test_grant_id(1),
        vec![node_with_env],
        vec![],
    );

    // Fails when grant lacks TerminalInput
    let err2 = validate_definition(&def2, Some(&grant_without_terminal)).unwrap_err();
    assert!(err2.to_string().contains("terminal input"));

    // Fails when grant is absent
    let err3 = validate_definition(&def2, None).unwrap_err();
    assert!(
        err3.to_string()
            .contains("validated only against the grant itself")
    );

    // Passes when environment is declared AND grant has TerminalInput
    assert!(validate_definition(&def2, Some(&grant_with_terminal)).is_ok());
}

#[test]
fn arbitrary_template_syntax_is_strictly_rejected() {
    let grant = make_dummy_grant(test_grant_id(1), false);

    let forbidden_payloads = [
        r#"{"cmd": "{{ user_input }}"}"#,
        r#"{"cmd": "${VARIABLE}"}"#,
        r#"{"cmd": "$(whoami)"}"#,
        r#"{"cmd": "<% code %>"}"#,
        r#"{"cmd": "eval(dangerous_code)"}"#,
    ];

    for payload in forbidden_payloads {
        let node = WorkflowNode {
            node_id: "bad_node".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: payload.to_owned(),
            declared_environment: Nullable::null(),
        };

        let def = create_workflow_definition(
            test_wf_id(1),
            1,
            "template-attack",
            test_grant_id(1),
            vec![node],
            vec![],
        );

        let err = validate_definition(&def, Some(&grant)).unwrap_err();
        assert!(
            err.to_string().contains("template code is forbidden"),
            "Expected template code rejection for payload: {payload}, got: {err}"
        );
    }
}

#[test]
fn unregistered_action_kind_is_rejected() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let node = WorkflowNode {
        node_id: "unknown".to_owned(),
        action_kind: "arbitrary_custom_plugin".to_owned(),
        action_params: "{}".to_owned(),
        declared_environment: Nullable::null(),
    };

    let def = create_workflow_definition(
        test_wf_id(1),
        1,
        "unknown-kind",
        test_grant_id(1),
        vec![node],
        vec![],
    );

    let err = validate_definition(&def, Some(&grant)).unwrap_err();
    assert!(err.to_string().contains("unregistered action kind"));
}
