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

/// Validates that a workflow definition is syntactically, structurally, and semantically valid.
///
/// 1. Identifier and structure check: non-empty name, at least one node, valid node/edge IDs.
/// 2. Graph validity: acyclic DAG check (via DFS/Tarjan cycle detection).
/// 3. No arbitrary template evaluation: action parameters must parse as valid JSON and no string
///    value (even if unicode-escaped in raw JSON) may contain template markers such as `{{`, `}}`,
///    `${`, `$(`, `<%`, `%>`, `eval(`, `exec(`, or backticks.
/// 4. Typed action parameter validation: ensures parameters conform to the typed schema of the
///    action kind.
/// 5. Shell command requirements: any `shell_command` node requires a declared execution
///    environment and an explicit broad shell grant (`terminal.input`) matching the definition's
///    `grant_reference` whose environment selector admits the declared environment.
pub fn validate_definition(definition: &WorkflowDefinition, grant: Option<&Grant>) -> Result<()> {
    // Basic identifier and field checks
    if definition.name.trim().is_empty() {
        return Err(AutomationError::InvalidArgument(
            "workflow definition name cannot be empty".to_owned(),
        ));
    }
    if definition.nodes.is_empty() {
        return Err(AutomationError::InvalidArgument(
            "workflow definition must contain at least one action node".to_owned(),
        ));
    }

    // Build node map and check node uniqueness
    let mut node_ids = HashSet::new();
    let mut shell_nodes = Vec::new();

    for node in &definition.nodes {
        if node.node_id.trim().is_empty() {
            return Err(AutomationError::InvalidArgument(
                "node_id cannot be empty".to_owned(),
            ));
        }
        if !node_ids.insert(&node.node_id) {
            return Err(AutomationError::InvalidArgument(format!(
                "duplicate node_id: {}",
                node.node_id
            )));
        }

        // Action kind check
        if !REGISTERED_ACTION_KINDS.contains(&node.action_kind.as_str()) {
            return Err(AutomationError::InvalidArgument(format!(
                "unregistered action kind '{}' in node {}",
                node.action_kind, node.node_id
            )));
        }

        // Parse and validate typed action parameters, rejecting any template syntax (decoded)
        validate_typed_action_params(&node.node_id, &node.action_kind, &node.action_params)?;

        // Collect shell command nodes for grant verification
        if node.action_kind == "shell_command" {
            if let Some(env_id) = node.declared_environment.0 {
                shell_nodes.push((&node.node_id, env_id));
            } else {
                return Err(AutomationError::ShellGrantRequired {
                    detail: format!(
                        "node {} has shell_command action but no declared_environment",
                        node.node_id
                    ),
                });
            }
        }
    }

    // Shell grant verification if shell nodes are present
    if !shell_nodes.is_empty() {
        match grant {
            Some(g) => {
                if g.grant_id != definition.grant_reference {
                    return Err(AutomationError::ShellGrantRequired {
                        detail: format!(
                            "grant ID {} does not match definition grant_reference {}",
                            g.grant_id, definition.grant_reference
                        ),
                    });
                }
                if !g.actions.contains(&ActionRight::TerminalInput) {
                    return Err(AutomationError::ShellGrantRequired {
                        detail: format!(
                            "grant {} lacks TerminalInput (broad shell grant required for shell_command)",
                            definition.grant_reference
                        ),
                    });
                }
                for (node_id, env_id) in shell_nodes {
                    if !g.environment_selector.admits(env_id) {
                        return Err(AutomationError::ShellGrantRequired {
                            detail: format!(
                                "node {} declared environment {} is not admitted by grant environment selector",
                                node_id, env_id
                            ),
                        });
                    }
                }
            }
            None => {
                // If grant is not provided at validation time, shell command nodes are refused
                return Err(AutomationError::ShellGrantRequired {
                    detail: "grant information required to validate shell command nodes".to_owned(),
                });
            }
        }
    }

    // Edge validation and cycle detection
    validate_graph_acyclic(&definition.nodes, &definition.edges)?;

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
        "materialize_changeset" => {
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} materialize_changeset params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("changeset_id").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} materialize_changeset requires string 'changeset_id'",
                    node_id
                )));
            }
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
            let obj = parsed.as_object().ok_or_else(|| {
                AutomationError::InvalidArgument(format!(
                    "node {} capture_changeset params must be a JSON object",
                    node_id
                ))
            })?;
            if obj.get("workspace_id").and_then(|v| v.as_str()).is_none() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {} capture_changeset requires string 'workspace_id'",
                    node_id
                )));
            }
        }
        _ => {}
    }

    Ok(())
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
            criteria: kr_protocol::scalars::Nullable::null(),
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
            action_params: r#"{"assignee": "alice"}"#.to_owned(),
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

        assert!(validate_definition(&def, None).is_ok());
    }

    #[test]
    fn cyclic_graph_is_rejected() {
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
            dummy_workflow_id(),
            1,
            "cyclic-workflow",
            dummy_grant_id(),
            vec![n1, n2],
            vec![e1, e2],
        );

        let err = validate_definition(&def, None).unwrap_err();
        assert!(matches!(err, AutomationError::CyclicGraph { .. }));
    }

    #[test]
    fn arbitrary_template_syntax_is_rejected() {
        let n1 = WorkflowNode {
            node_id: "templated".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"command": "{{ run_all }}"}"#.to_owned(),
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

        let err = validate_definition(&def, None).unwrap_err();
        assert!(matches!(err, AutomationError::TemplateCodeRejected { .. }));
    }

    #[test]
    fn shell_command_node_requires_declared_environment() {
        let n1 = WorkflowNode {
            node_id: "shell".to_owned(),
            action_kind: "shell_command".to_owned(),
            action_params: r#"{"cmd": "cargo test"}"#.to_owned(),
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

        let err = validate_definition(&def, None).unwrap_err();
        assert!(matches!(err, AutomationError::ShellGrantRequired { .. }));
    }
}
