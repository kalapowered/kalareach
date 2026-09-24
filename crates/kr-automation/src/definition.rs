//! Workflow definition parsing, graph validation, and constraint enforcement.
//!
//! Section 25 defines workflow definitions as versioned JSON documents with an event trigger,
//! resource scope, typed action nodes, success/failure edges, deadlines, and an explicit grant
//! reference.
//!
//! Graph acyclicity is validated at install time. Nodes name an action kind this engine registers
//! and carry that kind's complete typed parameters, and arbitrary template code is refused. Shell
//! command nodes require both an explicit broad shell grant (`terminal.input`) and a declared
//! execution environment.

use std::collections::{HashMap, HashSet};

use kr_protocol::automation::{
    AttentionNoticeParams, MAX_NOTICE_SUMMARY_BYTES, MAX_SHELL_COMMAND_BYTES, MAX_TEST_SUITE_BYTES,
    RequestReviewParams, RunTestsParams, ShellCommandParams, WorkflowActionKind, WorkflowDeadlines,
    WorkflowDefinition, WorkflowEdge, WorkflowNode, WorkflowResourceScope, WorkflowTrigger,
};
use kr_protocol::changeset::{ChangesetCaptureParams, ChangesetMaterializeParams, DiffApplyParams};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{EnvironmentId, GrantId, WorkflowId, WorkspaceId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::U64;
use kr_protocol::session::SessionCreateParams;

use crate::error::{AutomationError, Result};

/// The event a successful node of a registered kind produces, which is what a trigger names.
///
/// The only events a workflow can raise are the ones the host records when a node it dispatched
/// succeeds, and the type is fixed by the node's action kind. A definition therefore cannot mint
/// an event type of its choosing, just as it cannot mint an event identifier: the identifier of a
/// derived trigger is the action identifier the journal gave the node that produced it. A notice
/// produces no event.
#[must_use]
pub const fn produced_event(action_kind: WorkflowActionKind) -> Option<&'static str> {
    Some(match action_kind {
        WorkflowActionKind::ShellCommand => "command.completed",
        WorkflowActionKind::RunTests => "tests.passed",
        WorkflowActionKind::RequestReview => "review.completed",
        WorkflowActionKind::CreateSession => "session.created",
        WorkflowActionKind::MaterializeChangeset => "changeset.materialized",
        WorkflowActionKind::ApplyDiff => "diff.applied",
        WorkflowActionKind::CaptureChangeset => "changeset.captured",
        WorkflowActionKind::AttentionNotice => return None,
    })
}

/// Validates a workflow definition against everything that must hold before it is installed.
///
/// The order is from the shape of the document outwards, so the refusal names the first thing
/// that is actually wrong with it:
///
/// 1. The document: a name, at least one node, and unique and non-empty node identifiers. A node
///    naming a kind this engine does not register never reaches here: it is refused when the
///    definition is read.
/// 2. The graph: edges that point at real nodes, and no cycle.
/// 3. The parameters: valid JSON, exactly the kind's own typed parameters with no field they do
///    not have, every name they carry non-empty and bounded, and free of template markers even
///    when the raw JSON escaped them.
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
    }

    validate_graph_acyclic(&definition.nodes, &definition.edges)?;

    let mut shell_nodes = Vec::new();
    for node in &definition.nodes {
        validate_typed_action_params(&node.node_id, node.action_kind, &node.action_params)?;

        if node.action_kind == WorkflowActionKind::ShellCommand {
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
    shell_nodes: &[(&String, EnvironmentId)],
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

/// Validates a node's parameters against its kind's own typed parameters, and inspects every
/// decoded string value for template syntax.
fn validate_typed_action_params(
    node_id: &str,
    action_kind: WorkflowActionKind,
    params_json: &str,
) -> Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(params_json).map_err(|e| {
        AutomationError::InvalidArgument(format!(
            "node {node_id} action_params is not valid JSON: {e}"
        ))
    })?;

    // Recursively check decoded strings for forbidden template patterns
    check_no_template_values(node_id, &parsed)?;

    // Each kind takes exactly its own typed parameters. A change-set node or a session node asks
    // for exactly what its method asks for, so its parameters are that method's own, and a node
    // that would be refused when it ran is refused when it is installed.
    match action_kind {
        WorkflowActionKind::ShellCommand => {
            let params: ShellCommandParams = typed_params(node_id, action_kind, &parsed)?;
            bounded(node_id, "command", &params.command, MAX_SHELL_COMMAND_BYTES)?;
        }
        WorkflowActionKind::RunTests => {
            let params: RunTestsParams = typed_params(node_id, action_kind, &parsed)?;
            bounded(node_id, "suite", &params.suite, MAX_TEST_SUITE_BYTES)?;
        }
        WorkflowActionKind::RequestReview => {
            typed_params::<RequestReviewParams>(node_id, action_kind, &parsed)?;
        }
        WorkflowActionKind::CreateSession => {
            let params: SessionCreateParams = typed_params(node_id, action_kind, &parsed)?;
            if let Some(reason) = params.palette_refusal() {
                return Err(AutomationError::InvalidArgument(format!(
                    "node {node_id} creates a session session.create would refuse: {reason}"
                )));
            }
        }
        WorkflowActionKind::AttentionNotice => {
            let params: AttentionNoticeParams = typed_params(node_id, action_kind, &parsed)?;
            bounded(
                node_id,
                "summary",
                &params.summary,
                MAX_NOTICE_SUMMARY_BYTES,
            )?;
        }
        WorkflowActionKind::MaterializeChangeset => {
            typed_params::<ChangesetMaterializeParams>(node_id, action_kind, &parsed)?;
        }
        WorkflowActionKind::ApplyDiff => {
            typed_params::<DiffApplyParams>(node_id, action_kind, &parsed)?;
        }
        WorkflowActionKind::CaptureChangeset => {
            typed_params::<ChangesetCaptureParams>(node_id, action_kind, &parsed)?;
        }
    }

    Ok(())
}

/// Refuses a name a node carries that is empty or longer than its kind allows.
fn bounded(node_id: &str, field: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(AutomationError::InvalidArgument(format!(
            "node {node_id} needs a {field} of 1 to {max_bytes} bytes"
        )));
    }
    Ok(())
}

/// Decodes one node's parameters into the exact wire type its action kind is dispatched with.
fn typed_params<T: serde::de::DeserializeOwned>(
    node_id: &str,
    action_kind: WorkflowActionKind,
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
/// A capture reads one workspace and an apply writes one. That is the resource the node's effect
/// touches, so it is the one a definition's declared scope and the grant's own selectors have to
/// admit.
#[must_use]
pub fn node_workspace(node: &WorkflowNode) -> Option<WorkspaceId> {
    match node.action_kind {
        WorkflowActionKind::CaptureChangeset => {
            serde_json::from_str::<ChangesetCaptureParams>(&node.action_params)
                .ok()
                .map(|params| params.workspace_id)
        }
        WorkflowActionKind::ApplyDiff => {
            serde_json::from_str::<DiffApplyParams>(&node.action_params)
                .ok()
                .and_then(|params| params.workspace_id.0)
        }
        _ => None,
    }
}

/// Returns the environment a node creates a session in, when its action kind creates one.
#[must_use]
pub fn node_environment(node: &WorkflowNode) -> Option<EnvironmentId> {
    match node.action_kind {
        WorkflowActionKind::CreateSession => {
            serde_json::from_str::<SessionCreateParams>(&node.action_params)
                .ok()
                .map(|params| params.environment_id)
        }
        _ => None,
    }
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
        let n1 = crate::fixtures::node("test", WorkflowActionKind::RunTests);
        let n2 = crate::fixtures::node("review", WorkflowActionKind::RequestReview);
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
        let n1 = crate::fixtures::node("a", WorkflowActionKind::RunTests);
        let n2 = crate::fixtures::node("b", WorkflowActionKind::RequestReview);
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
        let mut n1 = crate::fixtures::node("templated", WorkflowActionKind::RunTests);
        n1.action_params = n1.action_params.replace("unit", "{{ run_all }}");
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
        let mut n1 = crate::fixtures::node("shell", WorkflowActionKind::ShellCommand);
        n1.declared_environment = Nullable::null(); // Missing environment
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
