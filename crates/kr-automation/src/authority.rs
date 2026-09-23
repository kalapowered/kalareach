//! The authority a workflow acts under, read again before every dispatch.
//!
//! Section 19 makes a workflow a delegation like any other: it carries a declared grant, it cannot
//! give an actor a right the granting actor lacks, and it cannot turn a view-only invitation into
//! terminal input. Section 25 makes that grant explicit in the definition and names it in every
//! later reference.
//!
//! Four rules follow, and this module holds all four.
//!
//! **The grant is read, never supplied.** A definition names a grant identifier; the host reads
//! that grant from its own store. Nothing a caller passes in decides what a run may do, so a
//! request cannot hand the engine a grant that was never issued or one that has since been
//! narrowed.
//!
//! **A withdrawn grant stops the next node, not only the next run.** A run dispatches its nodes
//! over minutes, and a revocation or an expiry can land between two of them. The grant is
//! therefore read again immediately before each dispatch rather than once at admission, and a
//! grant that no longer authorises anything ends the run where it stands.
//!
//! **Each node needs the right its effect needs.** A node that runs a shell command needs
//! `terminal.input`; a node that captures a change set needs `changeset.create`. The table below
//! gives each registered action kind the right section 23 gives the method that performs the same
//! effect, so a workflow is not a way around the method the person would otherwise have called.
//!
//! **A workflow gets no more than its grant's holder is served.** A host can refuse a grant's
//! holder an effect whatever rights the grant names: it serves a paired device no change-set
//! write, for one, because it cannot hold that write to the device's grant while the write
//! prepares. The host's [`AuthoritySource`] names such a refusal, and every check of a node asks
//! it beside the rights, so a workflow acting under the grant is not a way around the refusal.

use kr_protocol::automation::{WorkflowDefinition, WorkflowNode};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{EnvironmentId, GrantId};
use kr_protocol::rights::ActionRight;

use crate::error::{AutomationError, Result};

/// Where a workflow's grant is read from, as it stands now.
///
/// The host implements this over the grant store that issued the grant, so expiry, revocation and
/// a revoked ancestor are all decided by the one place that knows about them.
pub trait AuthoritySource: Send + Sync + std::fmt::Debug {
    /// Returns the grant `grant_id` names, as it stands at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::PermissionDenied`] when the grant is unknown to this host, has
    /// expired, has been revoked, or has never been redeemed.
    fn grant(&self, grant_id: GrantId, now_ms: u64) -> Result<Grant>;

    /// Returns why this host does not carry out a node of `action_kind` under `grant`, whatever
    /// rights the grant names, or `None` when the grant's rights decide alone.
    ///
    /// [`check_node`] asks this beside the rights, so a refusal here reaches an install, an
    /// admission and every dispatch alike.
    fn refusal(&self, grant: &Grant, action_kind: &str) -> Option<String>;
}

/// The rights one registered action kind needs before a node of that kind may be dispatched.
///
/// # Errors
///
/// Returns [`AutomationError::InvalidArgument`] for an action kind this engine has not registered.
/// An unregistered kind is refused rather than treated as needing nothing.
pub fn node_rights(action_kind: &str) -> Result<&'static [ActionRight]> {
    Ok(match action_kind {
        // Sending a command to a shell exposes the account the shell runs as, which is the right
        // section 23 puts behind `shell.launch` and behind every other way of typing at a terminal.
        "shell_command" | "run_tests" => &[ActionRight::TerminalInput],
        // A review asks an agent to do something, which is `agent.prompt`, and it is read back
        // through the session it ran in.
        "request_review" => &[ActionRight::AgentPrompt, ActionRight::SessionView],
        "create_session" => &[ActionRight::SessionCreate],
        "attention_notice" => &[ActionRight::SessionView],
        // The three change-set kinds take the rights their methods take: `changeset.materialize`
        // is `workspace.manage`, `diff.apply` is `files.apply_diff`, `changeset.capture` is
        // `changeset.create`.
        "materialize_changeset" => &[ActionRight::WorkspaceManage],
        "apply_diff" => &[ActionRight::FilesApplyDiff],
        "capture_changeset" => &[ActionRight::ChangesetCreate],
        other => {
            return Err(AutomationError::InvalidArgument(format!(
                "no rights are registered for action kind '{other}'"
            )));
        }
    })
}

/// Whether a node of `action_kind` writes through the change-set method group: a capture, a
/// materialisation or a diff applied to a workspace.
///
/// A host that serves a grant's holder no change-set write refuses exactly these kinds, so it
/// names them from here rather than keeping a list of its own beside the table above.
#[must_use]
pub fn writes_change_set(action_kind: &str) -> bool {
    matches!(
        action_kind,
        "capture_changeset" | "materialize_changeset" | "apply_diff"
    )
}

/// Checks that `grant` is the definition's own grant and covers the resources it names.
///
/// `environment_id` is the environment this host serves, which is where every node's effect
/// happens whatever the definition declares. The grant has to admit it, and a definition scoped to
/// another environment runs nothing here: leaving the environment out of a definition does not
/// leave it out of the check.
///
/// # Errors
///
/// Returns [`AutomationError::PermissionDenied`] when the grant is another one, when it does not
/// cover this environment or the session the definition is scoped to, or when the definition is
/// scoped to another environment.
pub fn check_scope(
    grant: &Grant,
    definition: &WorkflowDefinition,
    environment_id: EnvironmentId,
) -> Result<()> {
    if grant.grant_id != definition.grant_reference {
        return Err(AutomationError::PermissionDenied(format!(
            "grant {} is not workflow {}'s grant {}",
            grant.grant_id, definition.workflow_id, definition.grant_reference
        )));
    }
    if !grant.environment_selector.admits(environment_id) {
        return Err(AutomationError::PermissionDenied(format!(
            "grant {} does not cover environment {environment_id}, which is where this host acts",
            grant.grant_id
        )));
    }
    if let Some(declared) = definition.resource_scope.environment_id.0
        && declared != environment_id
    {
        return Err(AutomationError::PermissionDenied(format!(
            "workflow {} is scoped to environment {declared}, and this host acts in \
             {environment_id}",
            definition.workflow_id
        )));
    }
    if let Some(session_id) = definition.resource_scope.session_id.0
        && !grant.session_selector.admits(session_id)
    {
        return Err(AutomationError::PermissionDenied(format!(
            "grant {} does not cover session {session_id}",
            grant.grant_id
        )));
    }
    Ok(())
}

/// Checks that `grant` admits one node's effect, immediately before that node is dispatched, and
/// that `source`, the host the grant was read from, carries that effect out for the grant's
/// holder.
///
/// # Errors
///
/// Returns [`AutomationError::PermissionDenied`] when the grant lacks a right the node's action
/// kind needs, when the host refuses that kind to the grant's holder, when the grant does not
/// admit this environment, or when it does not admit the environment a shell node declares.
pub fn check_node(
    source: &dyn AuthoritySource,
    grant: &Grant,
    definition: &WorkflowDefinition,
    node: &WorkflowNode,
    environment_id: EnvironmentId,
) -> Result<()> {
    check_scope(grant, definition, environment_id)?;
    for right in node_rights(&node.action_kind)? {
        if !grant.permits(*right) {
            return Err(AutomationError::PermissionDenied(format!(
                "node {} needs {} and grant {} does not carry it",
                node.node_id,
                right.as_str(),
                grant.grant_id
            )));
        }
    }
    // What the rights admit, the host may still refuse to the grant's holder, and a workflow
    // acting under the grant is not a way around that.
    if let Some(reason) = source.refusal(grant, &node.action_kind) {
        return Err(AutomationError::PermissionDenied(format!(
            "node {} is not carried out under grant {}: {reason}",
            node.node_id, grant.grant_id
        )));
    }
    // A shell node names the environment it runs in, and the grant has to admit that one rather
    // than merely admitting the workflow's own scope.
    if let Some(environment_id) = node.declared_environment.0
        && !grant.environment_selector.admits(environment_id)
    {
        return Err(AutomationError::PermissionDenied(format!(
            "node {} declares environment {environment_id}, which grant {} does not admit",
            node.node_id, grant.grant_id
        )));
    }
    // A node that reads a workspace names the one it reads, and a definition scoped to a
    // workspace may not contain a node that reaches another. The declared scope is what a person
    // reviewing the definition read; a node acting outside it would make that reading false.
    if let (Some(declared), Some(target)) = (
        definition.resource_scope.workspace_id.0,
        crate::definition::node_workspace(node),
    ) && declared != target
    {
        return Err(AutomationError::PermissionDenied(format!(
            "node {} acts on workspace {target}, and workflow {} is scoped to workspace \
             {declared}",
            node.node_id, definition.workflow_id
        )));
    }
    Ok(())
}

/// Checks that `grant` admits every node of a definition, and that `source` carries each node's
/// effect out for the grant's holder.
///
/// This is what an install and an admission ask, so a definition nobody could ever run is refused
/// when it is offered rather than half way through its first run. It does not replace
/// [`check_node`]: the grant is read again before each dispatch, because it can be withdrawn in
/// between.
///
/// # Errors
///
/// Returns the first refusal [`check_node`] produces.
pub fn check_definition(
    source: &dyn AuthoritySource,
    grant: &Grant,
    definition: &WorkflowDefinition,
    environment_id: EnvironmentId,
) -> Result<()> {
    for node in &definition.nodes {
        check_node(source, grant, definition, node, environment_id)?;
    }
    Ok(())
}

/// How a grant stands, for a source that holds its grants itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStanding {
    /// Issued, redeemed and still within its lifetime.
    Active,
    /// Issued and written down, but nobody has redeemed the invitation that carries it.
    Pending,
    /// Its lifetime has passed.
    Expired,
    /// It was withdrawn, or an ancestor of it was.
    Revoked,
}

/// An authority source over grants its holder puts into it.
///
/// The host's own source reads the grant store. This one answers from a table, which is what a
/// caller that already holds the grants uses, and what a test that has to put one grant into a
/// particular standing uses. It is a source a caller builds deliberately, never a default: a
/// service is opened with the source its host chose.
#[derive(Debug, Default)]
pub struct GrantTable {
    entries: std::sync::Mutex<std::collections::HashMap<GrantId, (Grant, GrantStanding)>>,
}

impl GrantTable {
    /// Creates an empty table. Every grant is unknown until it is put in.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts an active grant into the table, replacing whatever was there under its identifier.
    pub fn insert(&self, grant: Grant) {
        self.set(grant, GrantStanding::Active);
    }

    /// Puts a grant into the table in a given standing.
    pub fn set(&self, grant: Grant, standing: GrantStanding) {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(grant.grant_id, (grant, standing));
    }

    /// Moves a grant this table holds into another standing.
    ///
    /// Returns false when the table does not hold it.
    pub fn restand(&self, grant_id: GrantId, standing: GrantStanding) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match entries.get_mut(&grant_id) {
            Some(entry) => {
                entry.1 = standing;
                true
            }
            None => false,
        }
    }
}

impl AuthoritySource for GrantTable {
    fn grant(&self, grant_id: GrantId, _now_ms: u64) -> Result<Grant> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((grant, standing)) = entries.get(&grant_id) else {
            return Err(AutomationError::PermissionDenied(format!(
                "grant {grant_id} is not one this host issued"
            )));
        };
        match standing {
            GrantStanding::Active => Ok(grant.clone()),
            GrantStanding::Pending => Err(AutomationError::PermissionDenied(format!(
                "grant {grant_id} has not been redeemed"
            ))),
            GrantStanding::Expired => Err(AutomationError::PermissionDenied(format!(
                "grant {grant_id} has expired"
            ))),
            GrantStanding::Revoked => Err(AutomationError::PermissionDenied(format!(
                "grant {grant_id} has been revoked"
            ))),
        }
    }

    /// A table serves each grant's holder what the grant's rights admit: whoever put a grant in
    /// decided what it may do.
    fn refusal(&self, _grant: &Grant, _action_kind: &str) -> Option<String> {
        None
    }
}

/// A grant of `rights` over every environment and session, under `grant_id`.
///
/// The crate's own tests build the grant the case is about and leave everything else open, so the
/// thing under test is the rule and not the fixture.
#[cfg(test)]
pub(crate) fn grant_of(grant_id: GrantId, rights: &[ActionRight]) -> Grant {
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{AuthorityRevision, DeviceId};
    use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

    Grant {
        grant_id,
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: rights.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

/// An authority holding one grant of every right under `grant_id`.
#[cfg(test)]
pub(crate) fn every_right(grant_id: GrantId) -> std::sync::Arc<GrantTable> {
    let table = GrantTable::new();
    table.insert(grant_of(grant_id, ActionRight::ALL));
    std::sync::Arc::new(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::automation::WorkflowResourceScope;
    use kr_protocol::grant::{EnvironmentSelector, SessionSelector};
    use kr_protocol::ids::{EnvironmentId, SessionId, WorkflowId};
    use kr_protocol::scalars::{Nullable, Uuid};

    /// The environment this host serves in these cases.
    fn here() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([5; 16]))
    }

    fn grant_with(rights: &[ActionRight]) -> Grant {
        grant_of(GrantId::new(Uuid::from_bytes([7; 16])), rights)
    }

    fn definition_with(node: WorkflowNode) -> WorkflowDefinition {
        crate::definition::create_workflow_definition(
            WorkflowId::new(Uuid::from_bytes([9; 16])),
            1,
            "authority",
            GrantId::new(Uuid::from_bytes([7; 16])),
            vec![node],
            vec![],
        )
    }

    fn node(action_kind: &str) -> WorkflowNode {
        WorkflowNode {
            node_id: "only".to_owned(),
            action_kind: action_kind.to_owned(),
            action_params: match action_kind {
                "shell_command" => r#"{"command": "true"}"#.to_owned(),
                "run_tests" => r#"{"suite": "unit"}"#.to_owned(),
                _ => r#"{"reviewer_id": "bob"}"#.to_owned(),
            },
            declared_environment: Nullable::null(),
        }
    }

    #[test]
    fn a_view_only_grant_reaches_no_terminal_through_a_workflow() {
        // Section 19 ¶1: a view-only invitation cannot obtain terminal input through a workflow.
        let view_only = grant_with(&[ActionRight::SessionView]);
        let definition = definition_with(node("shell_command"));
        let refusal = check_definition(&GrantTable::new(), &view_only, &definition, here())
            .expect_err("a shell node is refused");
        assert!(refusal.to_string().contains("terminal.input"), "{refusal}");

        let with_terminal = grant_with(&[ActionRight::SessionView, ActionRight::TerminalInput]);
        check_definition(&GrantTable::new(), &with_terminal, &definition, here())
            .expect("a broad shell grant admits it");
    }

    #[test]
    fn a_grant_that_covers_another_session_covers_no_node_of_this_one() {
        let session_id = SessionId::new(Uuid::from_bytes([3; 16]));
        let mut grant = grant_with(&[ActionRight::AgentPrompt, ActionRight::SessionView]);
        grant.session_selector = SessionSelector::None;
        let mut definition = definition_with(node("request_review"));
        definition.resource_scope = WorkflowResourceScope {
            session_id: Nullable::some(session_id),
            ..WorkflowResourceScope::default()
        };
        let refusal = check_definition(&GrantTable::new(), &grant, &definition, here())
            .expect_err("the session is not covered");
        assert!(refusal.to_string().contains("session"), "{refusal}");
    }

    #[test]
    fn a_shell_node_names_an_environment_the_grant_must_admit() {
        let environment_id = EnvironmentId::new(Uuid::from_bytes([4; 16]));
        let mut grant = grant_with(&[ActionRight::TerminalInput]);
        grant.environment_selector = EnvironmentSelector::These {
            environment_ids: [EnvironmentId::new(Uuid::from_bytes([5; 16]))]
                .into_iter()
                .collect(),
        };
        let mut shell = node("shell_command");
        shell.declared_environment = Nullable::some(environment_id);
        let definition = definition_with(shell);
        let refusal = check_definition(&GrantTable::new(), &grant, &definition, here())
            .expect_err("the environment is not admitted");
        assert!(refusal.to_string().contains("environment"), "{refusal}");
    }

    /// Leaving the environment out of a definition does not leave it out of the check: the grant
    /// has to admit the environment the effect happens in.
    #[test]
    fn a_grant_that_does_not_cover_this_environment_covers_no_node_here() {
        let mut grant = grant_with(&[ActionRight::AgentPrompt, ActionRight::SessionView]);
        grant.environment_selector = EnvironmentSelector::These {
            environment_ids: [EnvironmentId::new(Uuid::from_bytes([6; 16]))]
                .into_iter()
                .collect(),
        };
        let definition = definition_with(node("request_review"));
        let refusal = check_definition(&GrantTable::new(), &grant, &definition, here())
            .expect_err("this environment is not covered");
        assert!(refusal.to_string().contains("environment"), "{refusal}");
    }

    #[test]
    fn a_definition_scoped_to_another_environment_runs_nothing_here() {
        let grant = grant_with(&[ActionRight::AgentPrompt, ActionRight::SessionView]);
        let mut definition = definition_with(node("request_review"));
        definition.resource_scope = WorkflowResourceScope {
            environment_id: Nullable::some(EnvironmentId::new(Uuid::from_bytes([6; 16]))),
            ..WorkflowResourceScope::default()
        };
        let refusal = check_definition(&GrantTable::new(), &grant, &definition, here())
            .expect_err("another environment's workflow does not run here");
        assert!(refusal.to_string().contains("scoped"), "{refusal}");
    }

    #[test]
    fn a_table_reports_why_a_grant_authorises_nothing() {
        let table = GrantTable::new();
        let grant = grant_with(&[ActionRight::SessionView]);
        let grant_id = grant.grant_id;
        assert!(table.grant(grant_id, 1_000).is_err(), "an unknown grant");

        table.insert(grant);
        table.grant(grant_id, 1_000).expect("an active grant");

        for (standing, word) in [
            (GrantStanding::Revoked, "revoked"),
            (GrantStanding::Expired, "expired"),
            (GrantStanding::Pending, "redeemed"),
        ] {
            assert!(table.restand(grant_id, standing));
            let refusal = table
                .grant(grant_id, 1_000)
                .expect_err("a grant in this standing authorises nothing");
            assert!(refusal.to_string().contains(word), "{refusal}");
        }
    }

    #[test]
    fn an_unregistered_action_kind_has_no_rights_to_fall_through() {
        let refusal = node_rights("anything_at_all").expect_err("an unregistered kind is refused");
        assert!(refusal.to_string().contains("anything_at_all"), "{refusal}");
    }

    /// A host that serves a grant's holder no change-set write, whatever the grant's rights.
    #[derive(Debug)]
    struct NoChangeSetWrites;

    impl AuthoritySource for NoChangeSetWrites {
        fn grant(&self, grant_id: GrantId, _now_ms: u64) -> Result<Grant> {
            Err(AutomationError::PermissionDenied(format!(
                "grant {grant_id} is not read in this case"
            )))
        }

        fn refusal(&self, _grant: &Grant, action_kind: &str) -> Option<String> {
            writes_change_set(action_kind).then(|| "this holder is served no such write".to_owned())
        }
    }

    /// Section 19 ¶1: a workflow gives its grant's holder no more than the host serves that holder.
    /// A grant carrying every right still installs no change-set node on a host that refuses the
    /// holder a change-set write, because the check an install, an admission and a dispatch all
    /// ask puts the host's refusal beside the rights. The same grant is served every other kind,
    /// and the same nodes are admitted where the rights alone decide.
    #[test]
    fn a_node_the_host_refuses_the_holder_is_refused_whatever_the_rights() {
        let grant = grant_with(ActionRight::ALL);
        for kind in ["capture_changeset", "materialize_changeset", "apply_diff"] {
            assert!(writes_change_set(kind), "{kind} writes a change set");
            let definition = definition_with(node(kind));
            let refusal = check_definition(&NoChangeSetWrites, &grant, &definition, here())
                .expect_err("the host refuses the holder this kind");
            assert!(
                matches!(refusal, AutomationError::PermissionDenied(_)),
                "{refusal:?}"
            );
            assert!(
                refusal.to_string().contains("served no such write"),
                "{refusal}"
            );
            check_definition(&GrantTable::new(), &grant, &definition, here())
                .expect("the rights alone admit it");
        }
        for kind in [
            "shell_command",
            "run_tests",
            "request_review",
            "create_session",
            "attention_notice",
        ] {
            assert!(!writes_change_set(kind), "{kind} writes no change set");
            check_definition(
                &NoChangeSetWrites,
                &grant,
                &definition_with(node(kind)),
                here(),
            )
            .expect("a kind the host serves the holder");
        }
    }
}
