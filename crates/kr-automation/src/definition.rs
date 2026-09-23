//! Workflow definition parsing, graph validation, and constraint enforcement.
//!
//! Section 25 defines workflow definitions as versioned JSON documents with an event trigger,
//! resource scope, typed action nodes, success/failure edges, deadlines, and an explicit grant
//! reference.
//!
//! Graph acyclicity is validated at install time. Nodes reference registered action kinds and typed
//! outputs, with arbitrary template code strictly forbidden. Shell command nodes require both an
//! explicit broad shell grant (`terminal.input`) and a declared execution environment.

use std::collections::{HashMap, HashSet};

use kr_protocol::automation::{
    WorkflowDeadlines, WorkflowDefinition, WorkflowEdge, WorkflowNode, WorkflowResourceScope,
    WorkflowTrigger,
};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{GrantId, WorkflowId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::U64;

use crate::error::{AutomationError, Result};

/// Registered action kinds known to the automation engine.
pub const REGISTERED_ACTION_KINDS: &[&str] = &[
    "shell_command",
    "run_tests",
    "request_review",
    "create_session",
    "attention_notice",
    "materialize_changeset",
    "apply_diff",
    "capture_changeset",
];

/// The event a successful node of a registered kind produces, which is what a trigger names.
///
/// The only events a workflow can raise are the ones the host records when a node it dispatched
/// succeeds, and the type is fixed by the node's action kind. A definition therefore cannot mint
/// an event type of its choosing, just as it cannot mint an event identifier: the identifier of a
/// derived trigger is the action identifier the journal gave the node that produced it.
#[must_use]
pub fn produced_event(action_kind: &str) -> Option<&'static str> {
    Some(match action_kind {
        "shell_command" => "command.completed",
        "run_tests" => "tests.passed",
        "request_review" => "review.completed",
        "create_session" => "session.created",
        "materialize_changeset" => "changeset.materialized",
        "apply_diff" => "diff.applied",
        "capture_changeset" => "changeset.captured",
        _ => return None,
    })
}

/// Validates a workflow definition against everything that must hold before it is installed.
///
/// The order is from the shape of the document outwards, so the refusal names the first thing
/// that is actually wrong with it:
///
/// 1. The document: a name, at least one node, unique and non-empty node identifiers, and an
///    action kind this engine has registered.
/// 2. The graph: edges that point at real nodes, and no cycle.
/// 3. The parameters: valid JSON, matching the typed shape of the node's action kind, and free
///    of template markers even when the raw JSON escaped them.
/// 4. The shell grant: a `shell_command` node needs a declared execution environment, and the
///    definition's own grant has to be a broad shell grant that admits that environment.
///
/// `grant` is the grant the definition names, as the host read it from its own store. There is no
/// way to validate a definition without one: a shell node is never admitted on the strength of a
/// document naming a grant identifier.
pub fn validate_definition(definition: &WorkflowDefinition, grant: &Grant) -> Result<()> {
    if definition.name.trim().is_empty() {
        return Err(AutomationError::InvalidArgument(
            "a workflow definition needs a name".to_owned(),
        ));
    }
    if definition.nodes.is_empty() {
        return Err(AutomationError::InvalidArgument(
            "a workflow definition needs at least one action node".to_owned(),
        ));
    }

    let mut node_ids = HashSet::new();
    for node in &definition.nodes {
        if node.node_id.trim().is_empty() {
            return Err(AutomationError::InvalidArgument(
                "a node identifier cannot be empty".to_owned(),
            ));
        }
        if !node_ids.insert(&node.node_id) {
            return Err(AutomationError::InvalidArgument(format!(
                "duplicate node identifier: {}",
                node.node_id
            )));
        }
        if !REGISTERED_ACTION_KINDS.contains(&node.action_kind.as_str()) {
            return Err(AutomationError::InvalidArgument(format!(
                "unregistered action kind '{}' in node {}",
                node.action_kind, node.node_id
            )));
        }
    }

    validate_graph_acyclic(&definition.nodes, &definition.edges)?;

    let mut shell_nodes = Vec::new();
    for node in &definition.nodes {
        validate_typed_action_params(&node.node_id, &node.action_kind, &node.action_params)?;

        if node.action_kind == "shell_command" {
            let Some(env_id) = node.declared_environment.0 else {
                return Err(AutomationError::ShellGrantRequired {
                    detail: format!(
                        "node {} runs a shell command with no declared_environment",
                        node.node_id
                    ),
                });
            };
            shell_nodes.push((&node.node_id, env_id));
        }
    }

    if !shell_nodes.is_empty() {
        validate_shell_grant(definition, &shell_nodes, grant)?;
    }

    Ok(())
}

/// Checks that a definition with shell nodes carries the broad shell grant it claims.
fn validate_shell_grant(
    definition: &WorkflowDefinition,
    shell_nodes: &[(&String, kr_protocol::ids::EnvironmentId)],
    grant: &Grant,
) -> Result<()> {
    if grant.grant_id != definition.grant_reference {
        return Err(AutomationError::ShellGrantRequired {
            detail: format!(
                "grant {} is not the definition's grant {}",
                grant.grant_id, definition.grant_reference
            ),
        });
    }
    if !grant.actions.contains(&ActionRight::TerminalInput) {
        return Err(AutomationError::ShellGrantRequired {
            detail: format!(
                "grant {} does not carry terminal input, so it is not a broad shell grant",
                definition.grant_reference
            ),
        });
    }
    for (node_id, env_id) in shell_nodes {
        if !grant.environment_selector.admits(*env_id) {
            return Err(AutomationError::ShellGrantRequired {
                detail: format!(
                    "node {node_id} declares environment {env_id}, which grant {} does not admit",
                    definition.grant_reference
                ),
            });
        }
    }
    Ok(())
}

/// Validates typed action parameters and inspects decoded string values for template syntax.
fn validate_typed_action_params(node_id: &str, action_kind: &str, params_json: &str) -> Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(params_json).map_err(|e| {
        AutomationError::InvalidArgument(format!(
            "node {} action_params is not valid JSON: {}",
            node_id, e
        ))
    })?;

    // Recursively check decoded strings for forbidden template patterns
    check_no_template_values(node_id, &parsed)?;

    // Validate typed action schema
    match action_kind {
        "shell_command" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} shell_command params must be a JSON object",
                    node_id
                ))
            })?;
            let cmd = obj.get("command").and_then(|v| v.as_str());
            if cmd.is_none() || cmd.unwrap().trim().is_empty() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} shell_command requires non-empty string 'command'",
                    node_id
                )));
            }
        }
        "run_tests" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} run_tests params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("suite").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} run_tests requires string 'suite'",
                    node_id
                )));
            }
        }
        "request_review" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} request_review params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("reviewer_id").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} request_review requires string 'reviewer_id'",
                    node_id
                )));
            }
        }
        "create_session" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} create_session params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("title").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} create_session requires string 'title'",
                    node_id
                )));
            }
        }
        "attention_notice" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} attention_notice params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("summary").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} attention_notice requires string 'summary'",
                    node_id
                )));
            }
        }
        // A change-set node asks for exactly what the change-set method asks for, so its
        // parameters are that method's own typed parameters and they are checked against that
        // type here. A node that would be refused when it ran is refused when it is installed.
        "materialize_changeset" => {
            typed_params::<kr_protocol::changeset::ChangesetMaterializeParams>(
                node_id,
                action_kind,
                &parsed,
            )?;
        }
        "apply_diff" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} apply_diff params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("diff").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} apply_diff requires string 'diff'",
                    node_id
                )));
            }
        }
        "capture_changeset" => {
            typed_params::<kr_protocol::changeset::ChangesetCaptureParams>(
                node_id,
                action_kind,
                &parsed,
            )?;
        }
        _ => {}
    }

    Ok(())
}

/// Decodes one node's parameters into the exact wire type its action kind is dispatched with.
fn typed_params<T: serde::de::DeserializeOwned>(
    node_id: &str,
    action_kind: &str,
    parsed: &serde_json::Value,
) -> Result<T> {
    serde_json::from_value(parsed.clone()).map_err(|error| {
        AutomationError::InvalidArgument(format!(
            "node {node_id} does not carry the parameters {action_kind} takes: {error}"
        ))
    })
}

/// Returns the workspace a node acts on, when its action kind names one.
///
/// A capture reads one workspace. That is the resource the node's effect touches, so it is the
/// one a definition's declared scope and the grant's own selectors have to admit.
#[must_use]
pub fn node_workspace(node: &WorkflowNode) -> Option<kr_protocol::ids::WorkspaceId> {
    if node.action_kind != "capture_changeset" {
        return None;
    }
    serde_json::from_str::<kr_protocol::changeset::ChangesetCaptureParams>(&node.action_params)
        .ok()
        .map(|params| params.workspace_id)
}

/// Recursively checks that no JSON value contains arbitrary template code or script interpolation.
fn check_no_template_values(node_id: &str, val: &serde_json::Value) -> Result<()> {
    const FORBIDDEN_PATTERNS: &[&str] =
        &["{{", "}}", "${", "$(", "<%", "%>", "eval(", "exec(", "`"];

    match val {
        serde_json::Value::String(s) => {
            for pattern in FORBIDDEN_PATTERNS {
                if s.contains(pattern) {
                    return Err(AutomationError::TemplateCodeRejected {
                        node_id: node_id.to_owned(),
                    });
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                check_no_template_values(node_id, item)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                for pattern in FORBIDDEN_PATTERNS {
                    if key.contains(pattern) {
                        return Err(AutomationError::TemplateCodeRejected {
                            node_id: node_id.to_owned(),
                        });
                    }
                }
                check_no_template_values(node_id, item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates that the graph of nodes and edges is a directed acyclic graph (DAG).
fn validate_graph_acyclic(nodes: &[WorkflowNode], edges: &[WorkflowEdge]) -> Result<()> {
    let node_set: HashSet<&str> = nodes.iter().map(|n| n.node_id.as_str()).collect();

    // Adjacency list: from_node -> Vec<to_node>
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for n in nodes {
        adj.insert(n.node_id.as_str(), Vec::new());
    }

    for edge in edges {
        if !node_set.contains(edge.from_node.as_str()) {
            return Err(AutomationError::InvalidArgument(format!(
                "edge references non-existent from_node '{}'",
                edge.from_node
            )));
        }
        if !node_set.contains(edge.to_node.as_str()) {
            return Err(AutomationError::InvalidArgument(format!(
                "edge references non-existent to_node '{}'",
                edge.to_node
            )));
        }
        if edge.from_node == edge.to_node {
            return Err(AutomationError::CyclicGraph {
                detail: format!("self-loop on node '{}'", edge.from_node),
            });
        }
        adj.entry(edge.from_node.as_str())
            .or_default()
            .push(edge.to_node.as_str());
    }

    // Standard three-color DFS cycle detection:
    // 0: Unvisited (white)
    // 1: Visiting (grey, currently in recursion stack)
    // 2: Visited (black, completed)
    let mut state: HashMap<&str, u8> = HashMap::new();

    fn dfs<'a>(
        u: &'a str,
        adj: &HashMap<&'a str, Vec<&'a str>>,
        state: &mut HashMap<&'a str, u8>,
        path: &mut Vec<&'a str>,
    ) -> Result<()> {
        state.insert(u, 1);
        path.push(u);

        if let Some(neighbors) = adj.get(u) {
            for &v in neighbors {
                match state.get(v).copied().unwrap_or(0) {
                    1 => {
                        // Found cycle
                        let cycle_start = path.iter().position(|&node| node == v).unwrap_or(0);
                        let cycle = path[cycle_start..].join(" -> ") + " -> " + v;
                        return Err(AutomationError::CyclicGraph {
                            detail: format!("cycle detected: {cycle}"),
                        });
                    }
                    0 => {
                        dfs(v, adj, state, path)?;
                    }
                    _ => {}
                }
            }
        }

        path.pop();
        state.insert(u, 2);
        Ok(())
    }

    let mut path = Vec::new();
    for node in nodes {
        let node_id = node.node_id.as_str();
        if state.get(node_id).copied().unwrap_or(0) == 0 {
            dfs(node_id, &adj, &mut state, &mut path)?;
        }
    }

    Ok(())
}

/// Helper to create a valid workflow definition for tests and runtime.
pub fn create_workflow_definition(
    workflow_id: WorkflowId,
    revision: u64,
    name: &str,
    grant_reference: GrantId,
    nodes: Vec<WorkflowNode>,
    edges: Vec<WorkflowEdge>,
) -> WorkflowDefinition {
    WorkflowDefinition {
        workflow_id,
        revision: U64::new(revision),
        name: name.to_owned(),
        description: kr_protocol::scalars::Nullable::null(),
        trigger: WorkflowTrigger {
            event_type: "manual".to_owned(),
        },
        resource_scope: WorkflowResourceScope::default(),
        nodes,
        edges,
        deadlines: WorkflowDeadlines::default(),
        grant_reference,
        explicit_recurrence: false,
        enabled: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::automation::EdgeCondition;
    use kr_protocol::ids::{EnvironmentId, GrantId, WorkflowId};
    use kr_protocol::scalars::{Nullable, Uuid};

    fn dummy_workflow_id() -> WorkflowId {
        WorkflowId::new(Uuid::from_bytes([1; 16]))
    }

    fn dummy_grant_id() -> GrantId {
        GrantId::new(Uuid::from_bytes([2; 16]))
    }

    fn _dummy_env_id() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([3; 16]))
    }

    /// The definition's own grant, carrying every right and covering every environment.
    ///
    /// These tests are about the document, so the grant is the one that lets the document itself
    /// decide the outcome. What a narrower grant refuses is [`crate::authority`]'s subject.
    fn dummy_grant() -> Grant {
        crate::authority::grant_of(dummy_grant_id(), ActionRight::ALL)
    }

    #[test]
    fn valid_acyclic_graph_passes() {
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
            dummy_workflow_id(),
            1,
            "ci-workflow",
            dummy_grant_id(),
            vec![n1, n2],
            vec![e1],
        );

        assert!(validate_definition(&def, &dummy_grant()).is_ok());
    }

    #[test]
    fn cyclic_graph_is_rejected() {
        let n1 = WorkflowNode {
            node_id: "a".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "unit"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };
        let n2 = WorkflowNode {
            node_id: "b".to_owned(),
            action_kind: "request_review".to_owned(),
            action_params: r#"{"reviewer_id": "bob"}"#.to_owned(),
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
            dummy_workflow_id(),
            1,
            "cyclic-workflow",
            dummy_grant_id(),
            vec![n1, n2],
            vec![e1, e2],
        );

        let err = validate_definition(&def, &dummy_grant()).unwrap_err();
        assert!(matches!(err, AutomationError::CyclicGraph { .. }));
    }

    #[test]
    fn arbitrary_template_syntax_is_rejected() {
        let n1 = WorkflowNode {
            node_id: "templated".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "{{ run_all }}"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };
        let def = create_workflow_definition(
            dummy_workflow_id(),
            1,
            "template-workflow",
            dummy_grant_id(),
            vec![n1],
            vec![],
        );

        let err = validate_definition(&def, &dummy_grant()).unwrap_err();
        assert!(matches!(err, AutomationError::TemplateCodeRejected { .. }));
    }

    #[test]
    fn shell_command_node_requires_declared_environment() {
        let n1 = WorkflowNode {
            node_id: "shell".to_owned(),
            action_kind: "shell_command".to_owned(),
            action_params: r#"{"command": "cargo test"}"#.to_owned(),
            declared_environment: Nullable::null(), // Missing environment
        };
        let def = create_workflow_definition(
            dummy_workflow_id(),
            1,
            "shell-workflow",
            dummy_grant_id(),
            vec![n1],
            vec![],
        );

        let err = validate_definition(&def, &dummy_grant()).unwrap_err();
        assert!(matches!(err, AutomationError::ShellGrantRequired { .. }));
    }
}
