//! Tests for workflow definition validation, cycle rejection, broad-shell requirement,
//! and template rejection.

use kr_automation::{create_workflow_definition, validate_definition};
use kr_protocol::automation::WorkflowActionKind;
use kr_protocol::automation::{EdgeCondition, WorkflowEdge, WorkflowNode};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId, WorkflowId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

mod common;

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
    let n1 = common::node("test", WorkflowActionKind::RunTests);
    let n2 = common::node("review", WorkflowActionKind::RequestReview);
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

    assert!(validate_definition(&def, &grant).is_ok());
}

#[test]
fn cyclic_graph_is_rejected_two_nodes() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = common::node("a", WorkflowActionKind::RunTests);
    let n2 = common::node("b", WorkflowActionKind::RequestReview);
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

    let err = validate_definition(&def, &grant).unwrap_err();
    assert!(err.to_string().contains("cyclic"));
}

#[test]
fn cyclic_graph_is_rejected_self_loop() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = common::node("self_loop", WorkflowActionKind::RunTests);
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

    let err = validate_definition(&def, &grant).unwrap_err();
    assert!(err.to_string().contains("cyclic"));
}

#[test]
fn cyclic_graph_is_rejected_three_nodes() {
    let grant = make_dummy_grant(test_grant_id(1), false);
    let n1 = common::node("a", WorkflowActionKind::RunTests);
    let n2 = common::node("b", WorkflowActionKind::RunTests);
    let n3 = common::node("c", WorkflowActionKind::RequestReview);

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

    let err = validate_definition(&def, &grant).unwrap_err();
    assert!(err.to_string().contains("cyclic"));
}

#[test]
fn broad_shell_command_requires_declared_environment_and_terminal_input() {
    let mut node_without_env = common::node("sh1", WorkflowActionKind::ShellCommand);
    node_without_env.declared_environment = Nullable::null();

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
    let err1 = validate_definition(&def1, &grant_with_terminal).unwrap_err();
    assert!(err1.to_string().contains("declared_environment"));

    let node_with_env = WorkflowNode {
        node_id: "sh2".to_owned(),
        action_kind: WorkflowActionKind::ShellCommand,
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
    let err2 = validate_definition(&def2, &grant_without_terminal).unwrap_err();
    assert!(err2.to_string().contains("terminal input"));

    // Fails when the grant in hand is another workflow's grant
    let another_grant = make_dummy_grant(test_grant_id(2), true);
    let err3 = validate_definition(&def2, &another_grant).unwrap_err();
    assert!(
        err3.to_string().contains("is not the definition's grant"),
        "{err3}"
    );

    // Passes when environment is declared AND grant has TerminalInput
    assert!(validate_definition(&def2, &grant_with_terminal).is_ok());
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
            action_kind: WorkflowActionKind::RunTests,
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

        let err = validate_definition(&def, &grant).unwrap_err();
        assert!(
            err.to_string().contains("template code is forbidden"),
            "Expected template code rejection for payload: {payload}, got: {err}"
        );
    }
}

/// A kind nothing registers never becomes a node: the definition naming it is refused when it is
/// read, before anything could validate or run it.
#[test]
fn unregistered_action_kind_is_rejected() {
    let mut document = serde_json::to_value(create_workflow_definition(
        test_wf_id(1),
        1,
        "unknown-kind",
        test_grant_id(1),
        vec![common::node("unknown", WorkflowActionKind::RunTests)],
        vec![],
    ))
    .expect("encodes");
    document["nodes"][0]["action_kind"] = serde_json::json!("arbitrary_custom_plugin");
    let refused = serde_json::from_value::<kr_protocol::automation::WorkflowDefinition>(document)
        .expect_err("an unregistered kind is refused when the definition is read");
    assert!(
        refused.to_string().contains("arbitrary_custom_plugin"),
        "{refused}"
    );
}

/// A one-node definition whose node takes `params`, under `grant`.
fn one_node_with(
    kind: WorkflowActionKind,
    params: serde_json::Value,
) -> kr_protocol::automation::WorkflowDefinition {
    create_workflow_definition(
        test_wf_id(9),
        1,
        "typed-parameters",
        test_grant_id(9),
        vec![WorkflowNode {
            node_id: "only".to_owned(),
            action_kind: kind,
            action_params: params.to_string(),
            declared_environment: if kind == WorkflowActionKind::ShellCommand {
                Nullable::some(test_env_id(9))
            } else {
                Nullable::null()
            },
        }],
        vec![],
    )
}

/// Every registered kind takes its complete typed parameters and nothing else. A parameter set that
/// lacks what the kind needs, carries a field the kind does not take, or holds an empty name is
/// refused when the definition is installed, and the complete set is accepted.
#[test]
fn each_action_kind_takes_its_complete_typed_parameters() {
    use kr_protocol::changeset::{
        ChangesetCaptureParams, ChangesetMaterializeParams, DestinationClass, DiffApplyParams,
        FileGrant, MaterialisationPurpose, VersionRef,
    };
    use kr_protocol::ids::{ChangeSetId, ChangeSetVersion, WorkspaceId};
    use kr_protocol::project::{InclusionChoice, InclusionPolicy, WorkspaceKind};
    use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};

    let grant = make_dummy_grant(test_grant_id(9), true);
    let version = VersionRef {
        change_set_id: ChangeSetId::new(Uuid::from_bytes([0x33; 16])),
        version: ChangeSetVersion::new(1),
    };
    let version_value = serde_json::to_value(version).expect("a version");
    let workspace_id = WorkspaceId::new(Uuid::from_bytes([0x34; 16]));
    let everything = InclusionPolicy {
        dirty_files: InclusionChoice::Include,
        untracked_files: InclusionChoice::Include,
        submodules: InclusionChoice::Include,
        binary_files: InclusionChoice::Include,
        generated_artefacts: InclusionChoice::Include,
    };
    let complete: Vec<(WorkflowActionKind, serde_json::Value)> = vec![
        (
            WorkflowActionKind::ShellCommand,
            serde_json::json!({ "command": "cargo test" }),
        ),
        (
            WorkflowActionKind::RunTests,
            serde_json::json!({ "suite": "unit", "version": version_value }),
        ),
        (
            WorkflowActionKind::RequestReview,
            serde_json::json!({
                "reviewer_id": "claude-code",
                "version": version_value,
                "workspace": serde_json::to_value(WorkspaceKind::SharedExisting).expect("a kind"),
                "instructions": "Review the change for correctness.",
            }),
        ),
        (
            WorkflowActionKind::CreateSession,
            serde_json::to_value(SessionCreateParams {
                environment_id: test_env_id(9),
                presentation: Presentation::Invisible,
                shell: Nullable::null(),
                shell_mode: ShellMode::NativeCompat,
                cwd: Nullable::null(),
                dimensions: Nullable::null(),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                environment_snapshot: Vec::new(),
                palette: Nullable::null(),
                launch_profile: LaunchProfile::default(),
                terminal: Nullable::null(),
            })
            .expect("session.create's parameters"),
        ),
        (
            WorkflowActionKind::AttentionNotice,
            serde_json::json!({ "summary": "the tests finished" }),
        ),
        (
            WorkflowActionKind::MaterializeChangeset,
            serde_json::to_value(ChangesetMaterializeParams {
                change_set_id: version.change_set_id,
                version: version.version,
                purpose: MaterialisationPurpose::Test,
                label: "a copy".to_owned(),
            })
            .expect("changeset.materialize's parameters"),
        ),
        (
            WorkflowActionKind::ApplyDiff,
            serde_json::to_value(DiffApplyParams {
                change_set_id: version.change_set_id,
                version: version.version,
                destination: DestinationClass::Proposal,
                workspace_id: Nullable::null(),
                expected_reference: Nullable::null(),
                affected: Vec::new(),
                paths: Vec::new(),
                preflight_only: true,
                acknowledged_limitations: Vec::new(),
            })
            .expect("diff.apply's parameters"),
        ),
        (
            WorkflowActionKind::CaptureChangeset,
            serde_json::to_value(ChangesetCaptureParams {
                workspace_id,
                change_set_id: Nullable::null(),
                label: "a reading".to_owned(),
                policy: everything,
                grant: FileGrant::default(),
                quiescence_declared: false,
                required_consistency: Nullable::null(),
                pin: false,
                session_id: Nullable::null(),
                workflow_run_id: Nullable::null(),
                note: String::new(),
            })
            .expect("changeset.capture's parameters"),
        ),
    ];
    for (kind, params) in &complete {
        validate_definition(&one_node_with(*kind, params.clone()), &grant)
            .unwrap_or_else(|error| panic!("{kind} takes {params}: {error}"));
    }

    let refused: Vec<(WorkflowActionKind, serde_json::Value)> = vec![
        (
            WorkflowActionKind::ShellCommand,
            serde_json::json!({ "command": "cargo test", "shell": "bash" }),
        ),
        (
            WorkflowActionKind::ShellCommand,
            serde_json::json!({ "command": "" }),
        ),
        (
            WorkflowActionKind::RunTests,
            serde_json::json!({ "suite": "unit" }),
        ),
        (
            WorkflowActionKind::RunTests,
            serde_json::json!({ "suite": "", "version": version_value }),
        ),
        (
            WorkflowActionKind::RequestReview,
            serde_json::json!({ "reviewer_id": "alice" }),
        ),
        (
            WorkflowActionKind::CreateSession,
            serde_json::json!({ "title": "a reviewer" }),
        ),
        (
            WorkflowActionKind::AttentionNotice,
            serde_json::json!({ "summary": "done", "level": "high" }),
        ),
        (
            WorkflowActionKind::AttentionNotice,
            serde_json::json!({ "summary": "" }),
        ),
        (
            WorkflowActionKind::ApplyDiff,
            serde_json::json!({ "diff": "--- a/file\n+++ b/file\n" }),
        ),
        (
            WorkflowActionKind::MaterializeChangeset,
            serde_json::json!({
                "change_set_id": "not an identifier",
                "version": 1,
                "purpose": "test",
                "label": "a copy",
            }),
        ),
    ];
    for (kind, params) in &refused {
        let error = validate_definition(&one_node_with(*kind, params.clone()), &grant)
            .expect_err(&format!("{kind} does not take {params}"));
        assert!(
            matches!(error, kr_automation::AutomationError::InvalidArgument(_)),
            "{kind}: {error}"
        );
    }
}
