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

/// KR-REQ-25.13: a definition whose edges form a graph without a cycle validates.
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

/// KR-REQ-25.13: a definition whose edges lead from one node to another and back is refused as
/// cyclic.
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

/// KR-REQ-25.13: an edge from a node to itself is a cycle, and the definition is refused.
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

/// KR-REQ-25.13: a cycle through three nodes, closed by a failure edge, is refused.
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

/// KR-REQ-25.13: a node's parameters that hold template code, in any of the common template and
/// shell substitution syntaxes, are refused; a node evaluates no template.
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

/// KR-REQ-25.13: a node names a registered action kind.
///
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

/// KR-REQ-25.13: every node is typed by its registered kind.
///
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
                workspace_id: Nullable::some(workspace_id),
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

    // What a kind's method refuses on the request alone is refused at install too, and nothing
    // the method would refuse only against the host's live state is.
    let apply = |edit: &dyn Fn(&mut DiffApplyParams)| {
        let mut params = DiffApplyParams {
            change_set_id: version.change_set_id,
            version: version.version,
            destination: DestinationClass::Proposal,
            workspace_id: Nullable::some(workspace_id),
            expected_reference: Nullable::null(),
            affected: Vec::new(),
            paths: Vec::new(),
            preflight_only: false,
            acknowledged_limitations: Vec::new(),
        };
        edit(&mut params);
        serde_json::to_value(params).expect("diff.apply's parameters")
    };
    let session = |edit: &dyn Fn(&mut SessionCreateParams)| {
        let mut params: SessionCreateParams =
            serde_json::from_value(complete[3].1.clone()).expect("the complete session parameters");
        edit(&mut params);
        serde_json::to_value(params).expect("session.create's parameters")
    };
    let capture = |edit: &dyn Fn(&mut ChangesetCaptureParams)| {
        let mut params: ChangesetCaptureParams =
            serde_json::from_value(complete[7].1.clone()).expect("the complete capture parameters");
        edit(&mut params);
        serde_json::to_value(params).expect("changeset.capture's parameters")
    };
    let affected = |path: &str| kr_protocol::changeset::AffectedVersion {
        path: path.to_owned(),
        expected_worktree_digest: Nullable::null(),
        expected_index_object_id: Nullable::null(),
        expected_index_mode: Nullable::null(),
        check_index: false,
    };
    let accepted_by_the_method = [
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.affected = vec![affected("src/lib.rs")];
                params.paths = vec!["src/lib.rs".to_owned()];
            }),
        ),
        // A versioned reference reads no affected path, so the method takes one it could not read.
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.destination = DestinationClass::VersionedReference;
                params.expected_reference =
                    Nullable::some(kr_protocol::changeset::ExpectedReference {
                        name: "refs/heads/main".to_owned(),
                        expected_old_value: Nullable::null(),
                    });
                params.affected = vec![affected("../outside")];
            }),
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.destination = DestinationClass::VersionedReference;
                params.expected_reference =
                    Nullable::some(kr_protocol::changeset::ExpectedReference {
                        name: "refs/heads/main".to_owned(),
                        expected_old_value: Nullable::null(),
                    });
            }),
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.destination = DestinationClass::SharedExisting;
                params.acknowledged_limitations =
                    kr_changeset::apply::limitations(DestinationClass::SharedExisting);
            }),
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.destination = DestinationClass::SharedExisting;
                params.preflight_only = true;
            }),
        ),
        (
            WorkflowActionKind::CreateSession,
            session(&|params| {
                params.dimensions = Nullable::some(kr_protocol::session::Dimensions::new(120, 40));
            }),
        ),
    ];
    for (kind, params) in &accepted_by_the_method {
        validate_definition(&one_node_with(*kind, params.clone()), &grant)
            .unwrap_or_else(|error| panic!("{kind} takes {params}: {error}"));
    }
    let refused_by_the_method = [
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| params.workspace_id = Nullable::null()),
            "workspace",
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| params.destination = DestinationClass::VersionedReference),
            "reference",
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.destination = DestinationClass::VersionedReference;
                params.expected_reference =
                    Nullable::some(kr_protocol::changeset::ExpectedReference {
                        name: "--upload-pack=true".to_owned(),
                        expected_old_value: Nullable::null(),
                    });
            }),
            "reference",
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| params.destination = DestinationClass::SharedExisting),
            "limitation",
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| params.affected = vec![affected("../outside")]),
            "affected path 1",
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| {
                params.destination = DestinationClass::SharedExisting;
                params.preflight_only = true;
                params.affected = vec![affected("src/lib.rs"), affected("/etc/hosts")];
            }),
            "affected path 2",
        ),
        (
            WorkflowActionKind::ApplyDiff,
            apply(&|params| params.paths = vec!["src/lib.rs".to_owned()]),
            "asked for by name",
        ),
        (
            WorkflowActionKind::CreateSession,
            session(&|params| {
                params.dimensions = Nullable::some(kr_protocol::session::Dimensions::new(0, 40));
            }),
            "column",
        ),
        (
            WorkflowActionKind::CaptureChangeset,
            capture(&|params| {
                params.required_consistency =
                    Nullable::some(kr_protocol::changeset::SourceConsistency::AtomicSnapshot);
            }),
            "atomic snapshot",
        ),
    ];
    for (kind, params, why) in &refused_by_the_method {
        let error = validate_definition(&one_node_with(*kind, params.clone()), &grant)
            .expect_err(&format!("{kind} does not take {params}"));
        assert!(
            matches!(error, kr_automation::AutomationError::InvalidArgument(_)),
            "{kind}: {error}"
        );
        assert!(error.to_string().contains(why), "{kind}: {error}");
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

/// KR-REQ-07.25: a session a workflow creates takes the host's environment, never one a definition
/// carries, so a create node whose parameters hold environment variables is refused when the
/// definition is installed. A definition is stored as it was installed, and a variable in it would
/// stay on disk for as long as the revision does.
#[test]
fn a_create_node_that_carries_environment_variables_is_refused() {
    use kr_protocol::session::{
        EnvironmentVariable, LaunchProfile, Presentation, SessionCreateParams, ShellMode,
    };

    let grant = make_dummy_grant(test_grant_id(9), true);
    let session = |variables: Vec<EnvironmentVariable>| {
        serde_json::to_value(SessionCreateParams {
            environment_id: test_env_id(9),
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::null(),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: variables,
            palette: Nullable::null(),
            launch_profile: LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("session.create's parameters")
    };

    // The control: the same node with no variables installs.
    validate_definition(
        &one_node_with(WorkflowActionKind::CreateSession, session(Vec::new())),
        &grant,
    )
    .expect("a create node with no variables is installed");

    let carrying = session(vec![EnvironmentVariable {
        name: "KR_PLANTED_TOKEN".to_owned(),
        value: "planted-secret-value".to_owned(),
    }]);
    let error = validate_definition(
        &one_node_with(WorkflowActionKind::CreateSession, carrying.clone()),
        &grant,
    )
    .expect_err("a create node that carries a variable is refused");
    assert!(
        matches!(error, kr_automation::AutomationError::InvalidArgument(_)),
        "{error}"
    );
    let said = error.to_string();
    assert!(said.contains("environment"), "{said}");
    assert!(
        !said.contains("planted-secret-value") && !said.contains("KR_PLANTED_TOKEN"),
        "the refusal names no variable and no value: {said}"
    );

    // However the variables are spelled, the refusal is the same and says nothing of them: a
    // typed decoder's own message would quote the value it could not read, and the refusal is
    // recorded with the action.
    let spelled: Vec<(&str, String)> = vec![
        (
            "a list of text",
            "[\"KR_PLANTED_TOKEN=planted-secret-value\"]".to_owned(),
        ),
        (
            "one text",
            "\"KR_PLANTED_TOKEN=planted-secret-value\"".to_owned(),
        ),
        ("null", "null".to_owned()),
        (
            "a mapping",
            "{\"KR_PLANTED_TOKEN\":\"planted-secret-value\"}".to_owned(),
        ),
    ];
    for (case, value) in &spelled {
        let mut params = session(Vec::new());
        params["environment_snapshot"] =
            serde_json::from_str(value).expect("a JSON value for the field");
        let error = validate_definition(
            &one_node_with(WorkflowActionKind::CreateSession, params),
            &grant,
        )
        .expect_err(&format!("{case}: refused"));
        let said = error.to_string();
        assert!(
            !said.contains("planted-secret-value") && !said.contains("KR_PLANTED_TOKEN"),
            "{case}: the refusal names no variable and no value: {said}"
        );
    }

    // A name repeated in the parameters is read as its last value by a JSON reader that keeps one
    // value for a name, and the stored text keeps both. So the first copy, which holds the
    // variables, would stay in the journal behind an empty list that passes the check.
    let mut text = carrying.to_string();
    text.pop();
    text.push_str(",\"environment_snapshot\":[]}");
    let mut definition = one_node_with(WorkflowActionKind::CreateSession, session(Vec::new()));
    definition.nodes[0].action_params = text;
    let error = validate_definition(&definition, &grant)
        .expect_err("a name repeated in a node's parameters is refused");
    let said = error.to_string();
    assert!(said.contains("repeat"), "{said}");
    assert!(!said.contains("planted-secret-value"), "{said}");

    // The other kinds carry nothing of the kind, and a definition already installed with a name
    // repeated in one of them is admitted again each time it runs, which checks it again: so the
    // refusal is the create node's alone.
    let mut definition = one_node_with(
        WorkflowActionKind::AttentionNotice,
        serde_json::json!({ "summary": "done" }),
    );
    definition.nodes[0].action_params = "{\"summary\":\"first\",\"summary\":\"done\"}".to_owned();
    validate_definition(&definition, &grant)
        .expect("a repeated name in a node of another kind is not refused");
}

/// KR-REQ-07.25: an install the host refuses for the variables a create node carries leaves
/// neither the variables nor a record of them on disk: the refusal says nothing of them, and the
/// refusal is what the journal records with the action.
#[test]
fn a_refused_install_leaves_no_variable_in_the_journal() {
    use common::Submit;
    use kr_automation::{AutomationService, ManualClock, MockActionRunner};
    use kr_protocol::automation::WorkflowInstallParams;
    use kr_protocol::session::{
        EnvironmentVariable, LaunchProfile, Presentation, SessionCreateParams, ShellMode,
    };
    use std::sync::Arc;

    let directory = tempfile::tempdir().expect("a journal directory");
    let grant_id = test_grant_id(9);
    let service = AutomationService::open(
        directory.path(),
        common::host(
            Arc::new(MockActionRunner::new()),
            common::every_right(&[grant_id]),
            Arc::new(ManualClock::new(1_000)),
        ),
    )
    .expect("a service");
    let session = |variables: Vec<EnvironmentVariable>| {
        serde_json::to_value(SessionCreateParams {
            environment_id: common::environment(),
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::null(),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: variables,
            palette: Nullable::null(),
            launch_profile: LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("session.create's parameters")
    };
    let install = |revision: u64, params: serde_json::Value| {
        let mut definition = one_node_with(WorkflowActionKind::CreateSession, params);
        definition.revision = kr_protocol::scalars::U64::new(revision);
        WorkflowInstallParams {
            workflow_id: definition.workflow_id,
            revision: definition.revision,
            grant_reference: definition.grant_reference,
            definition,
        }
    };

    let mut shapes = vec![
        session(vec![EnvironmentVariable {
            name: "KR_PLANTED_TOKEN".to_owned(),
            value: "planted-secret-value".to_owned(),
        }]),
        session(Vec::new()),
        session(Vec::new()),
    ];
    shapes[1]["environment_snapshot"] =
        serde_json::json!(["KR_PLANTED_TOKEN=planted-secret-value"]);
    shapes[2]["environment_snapshot"] = serde_json::json!("planted-secret-value");
    for (at, shape) in shapes.into_iter().enumerate() {
        let error = service
            .submit_install(&install(1 + at as u64, shape), 1_000)
            .expect_err("the install is refused");
        let said = format!("{error} {error:?}");
        assert!(!said.contains("planted-secret-value"), "{at}: {said}");
    }
    // The control: the same node with none installs.
    service
        .submit_install(&install(9, session(Vec::new())), 1_000)
        .expect("a create node with no variables installs");

    drop(service);
    for name in ["workflows.db", "workflows.db-wal", "workflows.db-journal"] {
        if let Ok(bytes) = std::fs::read(directory.path().join(name)) {
            assert!(
                !bytes
                    .windows("planted-secret-value".len())
                    .any(|window| window == b"planted-secret-value"),
                "{name} holds a variable a refused install carried"
            );
        }
    }
}

/// KR-REQ-25.13: a workflow definition is a versioned JSON document. One read from its text, with
/// an event trigger, a resource scope, typed action nodes, success and failure edges, deadlines and
/// a grant reference, installs under the revision that both the request and the document name.
/// Each later install takes a higher revision, and an installed revision never changes: a changed
/// document under a number already installed, a lower number than the latest, and a request that
/// names another revision than its document are each refused, and every installed revision reads
/// back as it was installed.
#[test]
fn a_definition_is_a_versioned_json_document_whose_installed_revisions_never_change() {
    use std::sync::Arc;

    use common::Submit;
    use kr_automation::{AutomationService, ManualClock, MockActionRunner};
    use kr_protocol::automation::{WorkflowDefinition, WorkflowInstallParams};
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::scalars::U64;

    let workflow_id = test_wf_id(12);
    let grant_id = test_grant_id(13);
    let service = AutomationService::in_memory(common::host(
        Arc::new(MockActionRunner::new()),
        common::every_right(&[grant_id]),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");

    // The document as a client sends it: JSON text whose revision is a decimal string. The tests
    // run first; a review follows their success and a notice their failure.
    let read = |revision: u64, name: &str| -> WorkflowDefinition {
        let text = serde_json::json!({
            "workflow_id": "0c0c0c0c-0c0c-0c0c-0c0c-0c0c0c0c0c0c",
            "revision": revision.to_string(),
            "name": name,
            "description": "Runs the unit tests on a captured change and asks for a review.",
            "trigger": { "event_type": "changeset.captured" },
            "resource_scope": {
                "environment_id": null,
                "workspace_id": null,
                "session_id": null,
            },
            "nodes": [
                {
                    "node_id": "tests",
                    "action_kind": "run_tests",
                    "action_params": common::params(WorkflowActionKind::RunTests),
                    "declared_environment": null,
                },
                {
                    "node_id": "review",
                    "action_kind": "request_review",
                    "action_params": common::params(WorkflowActionKind::RequestReview),
                    "declared_environment": null,
                },
                {
                    "node_id": "notice",
                    "action_kind": "attention_notice",
                    "action_params": r#"{"summary":"the unit tests failed"}"#,
                    "declared_environment": null,
                },
            ],
            "edges": [
                { "from_node": "tests", "to_node": "review", "condition": "success" },
                { "from_node": "tests", "to_node": "notice", "condition": "failure" },
            ],
            "deadlines": { "run_deadline_ms": "900000", "action_wait_ms": "300000" },
            "grant_reference": "0d0d0d0d-0d0d-0d0d-0d0d-0d0d0d0d0d0d",
            "enabled": true,
            "explicit_recurrence": false,
        })
        .to_string();
        serde_json::from_str(&text).expect("the document reads")
    };
    let install = |definition: &WorkflowDefinition| WorkflowInstallParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
        definition: definition.clone(),
        grant_reference: definition.grant_reference,
    };
    let installed = |revision: u64| {
        service
            .store()
            .get_definition(workflow_id, revision)
            .expect("the journal reads")
            .map(|installed| installed.definition)
    };
    let refused = |params: &WorkflowInstallParams, why: &str| {
        let refusal = ProtocolError::from(
            service
                .submit_install(params, 1_000)
                .expect_err("the install is refused"),
        );
        assert_eq!(refusal.code, ErrorCode::DraftConflict, "{why}: {refusal:?}");
    };

    let first = read(1, "tests then review");
    assert_eq!(first.workflow_id, workflow_id);
    assert_eq!(first.grant_reference, grant_id);
    assert_eq!(first.revision, U64::new(1));
    service
        .submit_install(&install(&first), 1_000)
        .expect("the document's first revision installs");

    // The request and the document name different revisions: nothing is installed under either.
    let mut mismatched = install(&read(2, "tests then review"));
    mismatched.revision = U64::new(3);
    refused(&mismatched, "a request naming another revision");
    assert_eq!(installed(2), None);
    assert_eq!(installed(3), None);

    // A changed document under the number already installed does not replace it.
    refused(
        &install(&read(1, "a changed document")),
        "an installed revision again",
    );
    assert_eq!(installed(1).as_ref(), Some(&first));

    // A later revision installs beside the first; a number below the latest is refused after it.
    let third = read(3, "tests then review, revised");
    service
        .submit_install(&install(&third), 1_000)
        .expect("a later revision installs");
    refused(&install(&read(2, "a lower number")), "a lower revision");
    assert_eq!(installed(2), None);
    assert_eq!(installed(1).as_ref(), Some(&first));
    assert_eq!(installed(3).as_ref(), Some(&third));
}
