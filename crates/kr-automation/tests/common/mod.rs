//! Fixtures the automation suites share.
//!
//! A definition names a grant, and the host reads that grant from its own store rather than from
//! the request. These suites therefore need two things: grants to put into a store, and a store
//! to put them in. Both are here, so a suite that is about budgets or deadlines says nothing
//! about authority beyond naming the grant its definitions use.

#![allow(dead_code)]

use std::sync::Arc;

use kr_automation::{GrantStanding, GrantTable};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

/// A grant of `rights` over every environment and session.
#[must_use]
pub fn grant_of(grant_id: GrantId, rights: &[ActionRight]) -> Grant {
    Grant {
        grant_id,
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
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

/// An authority holding one active grant of every right under each identifier.
#[must_use]
pub fn every_right(grant_ids: &[GrantId]) -> Arc<GrantTable> {
    let table = GrantTable::new();
    for grant_id in grant_ids {
        table.insert(grant_of(*grant_id, ActionRight::ALL));
    }
    Arc::new(table)
}

/// An authority holding one active grant carrying exactly `rights`.
#[must_use]
pub fn holding(grant_id: GrantId, rights: &[ActionRight]) -> Arc<GrantTable> {
    let table = GrantTable::new();
    table.insert(grant_of(grant_id, rights));
    Arc::new(table)
}

/// An authority holding one grant of every right, in a standing the caller chose.
#[must_use]
pub fn standing(grant_id: GrantId, standing: GrantStanding) -> Arc<GrantTable> {
    let table = GrantTable::new();
    table.set(grant_of(grant_id, ActionRight::ALL), standing);
    Arc::new(table)
}

/// A new action of `method`, submitted by the test's own actor.
#[must_use]
pub fn fresh_action(method: kr_protocol::method::Method) -> kr_automation::ActionKey {
    let action_id = uuid::Uuid::new_v4();
    kr_automation::ActionKey {
        actor_id: "tester".to_owned(),
        action_id: action_id.to_string(),
        method: method.as_str().to_owned(),
        digest: action_id.as_bytes().to_vec(),
    }
}

/// An admission that always stands, for a suite that is not about admission.
pub fn admitted() -> kr_automation::Result<()> {
    Ok(())
}

/// Submits each automation mutation as a new action, under an admission that always stands.
///
/// The service performs every mutation as an action and records what it came to. Most suites
/// are about something else, so each call here is a new action; a suite about repeats builds its
/// own [`kr_automation::ActionKey`] and submits it twice.
#[allow(async_fn_in_trait)]
pub trait Submit {
    /// `workflow.install`, as a new action.
    fn submit_install(
        &self,
        params: &kr_protocol::automation::WorkflowInstallParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowInstallResult>;

    /// `workflow.enable`, as a new action.
    fn submit_enable(
        &self,
        params: &kr_protocol::automation::WorkflowEnableParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowEnableResult>;

    /// `workflow.pause`, as a new action.
    fn submit_pause(
        &self,
        params: &kr_protocol::automation::WorkflowPauseParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowPauseResult>;

    /// `workflow.run`, as a new action.
    async fn submit_run(
        &self,
        params: &kr_protocol::automation::WorkflowRunParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowRunResult>;
}

impl Submit for kr_automation::AutomationService {
    fn submit_install(
        &self,
        params: &kr_protocol::automation::WorkflowInstallParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowInstallResult> {
        let key = fresh_action(kr_protocol::method::Method::WorkflowInstall);
        self.install(
            params,
            &kr_automation::Submitted {
                key: &key,
                admission: &admitted,
                caller_grant: None,
            },
            now_ms,
        )
    }

    fn submit_enable(
        &self,
        params: &kr_protocol::automation::WorkflowEnableParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowEnableResult> {
        let key = fresh_action(kr_protocol::method::Method::WorkflowEnable);
        self.enable(
            params,
            &kr_automation::Submitted {
                key: &key,
                admission: &admitted,
                caller_grant: None,
            },
            now_ms,
        )
    }

    fn submit_pause(
        &self,
        params: &kr_protocol::automation::WorkflowPauseParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowPauseResult> {
        let key = fresh_action(kr_protocol::method::Method::WorkflowPause);
        self.pause(
            params,
            &kr_automation::Submitted {
                key: &key,
                admission: &admitted,
                caller_grant: None,
            },
            now_ms,
        )
    }

    async fn submit_run(
        &self,
        params: &kr_protocol::automation::WorkflowRunParams,
        now_ms: u64,
    ) -> kr_automation::Result<kr_protocol::automation::WorkflowRunResult> {
        let key = fresh_action(kr_protocol::method::Method::WorkflowRun);
        self.run(
            params,
            &kr_automation::Submitted {
                key: &key,
                admission: &admitted,
                caller_grant: None,
            },
            now_ms,
        )
        .await
    }
}

/// The environment these suites' host serves.
#[must_use]
pub fn environment() -> kr_protocol::ids::EnvironmentId {
    kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([0xe0; 16]))
}

/// A host serving [`environment`], with the runner, the grants and the clock a suite chose.
#[must_use]
pub fn host(
    runner: Arc<dyn kr_automation::ActionRunner>,
    authority: Arc<dyn kr_automation::AuthoritySource>,
    clock: Arc<dyn kr_automation::HostClock>,
) -> kr_automation::Host {
    kr_automation::Host {
        environment_id: environment(),
        runner,
        authority,
        clock,
    }
}

/// The version the stand-in parameters of a test or review node name.
#[must_use]
pub fn stand_in_version() -> kr_protocol::changeset::VersionRef {
    kr_protocol::changeset::VersionRef {
        change_set_id: kr_protocol::ids::ChangeSetId::new(Uuid::from_bytes([0x33; 16])),
        version: kr_protocol::ids::ChangeSetVersion::new(1),
    }
}

/// Complete parameters of `kind`, as a node carries them, for a host serving [`environment`].
#[must_use]
pub fn params(kind: kr_protocol::automation::WorkflowActionKind) -> String {
    use kr_protocol::automation::WorkflowActionKind;
    let version = stand_in_version();
    let value = match kind {
        WorkflowActionKind::ShellCommand => serde_json::json!({ "command": "cargo test" }),
        WorkflowActionKind::RunTests => serde_json::json!({ "suite": "unit", "version": version }),
        WorkflowActionKind::RequestReview => serde_json::json!({
            "reviewer_id": "reviewer",
            "version": version,
            "workspace": kr_protocol::project::WorkspaceKind::SharedExisting,
            "instructions": "Review the change.",
        }),
        WorkflowActionKind::CreateSession => {
            serde_json::to_value(kr_protocol::session::SessionCreateParams {
                environment_id: environment(),
                presentation: kr_protocol::session::Presentation::Invisible,
                shell: Nullable::null(),
                shell_mode: kr_protocol::session::ShellMode::NativeCompat,
                cwd: Nullable::null(),
                dimensions: Nullable::null(),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                environment_snapshot: Vec::new(),
                palette: Nullable::null(),
                launch_profile: kr_protocol::session::LaunchProfile::default(),
                terminal: Nullable::null(),
            })
            .expect("session.create's parameters")
        }
        WorkflowActionKind::AttentionNotice => {
            serde_json::json!({ "summary": "the tests finished" })
        }
        WorkflowActionKind::MaterializeChangeset => {
            serde_json::to_value(kr_protocol::changeset::ChangesetMaterializeParams {
                change_set_id: version.change_set_id,
                version: version.version,
                purpose: kr_protocol::changeset::MaterialisationPurpose::Test,
                label: "a copy".to_owned(),
            })
            .expect("changeset.materialize's parameters")
        }
        WorkflowActionKind::ApplyDiff => {
            serde_json::to_value(kr_protocol::changeset::DiffApplyParams {
                change_set_id: version.change_set_id,
                version: version.version,
                destination: kr_protocol::changeset::DestinationClass::Proposal,
                workspace_id: Nullable::null(),
                expected_reference: Nullable::null(),
                affected: Vec::new(),
                paths: Vec::new(),
                preflight_only: true,
                acknowledged_limitations: Vec::new(),
            })
            .expect("diff.apply's parameters")
        }
        WorkflowActionKind::CaptureChangeset => {
            serde_json::to_value(kr_protocol::changeset::ChangesetCaptureParams {
                workspace_id: kr_protocol::ids::WorkspaceId::new(Uuid::from_bytes([0x34; 16])),
                change_set_id: Nullable::null(),
                label: "a reading".to_owned(),
                policy: kr_protocol::project::InclusionPolicy {
                    dirty_files: kr_protocol::project::InclusionChoice::Include,
                    untracked_files: kr_protocol::project::InclusionChoice::Include,
                    submodules: kr_protocol::project::InclusionChoice::Include,
                    binary_files: kr_protocol::project::InclusionChoice::Include,
                    generated_artefacts: kr_protocol::project::InclusionChoice::Include,
                },
                grant: kr_protocol::changeset::FileGrant::default(),
                quiescence_declared: false,
                required_consistency: Nullable::null(),
                pin: false,
                session_id: Nullable::null(),
                workflow_run_id: Nullable::null(),
                note: String::new(),
            })
            .expect("changeset.capture's parameters")
        }
    };
    value.to_string()
}

/// A node of `kind` with complete parameters. A shell node declares [`environment`].
#[must_use]
pub fn node(
    node_id: &str,
    kind: kr_protocol::automation::WorkflowActionKind,
) -> kr_protocol::automation::WorkflowNode {
    kr_protocol::automation::WorkflowNode {
        node_id: node_id.to_owned(),
        action_kind: kind,
        action_params: params(kind),
        declared_environment: if kind == kr_protocol::automation::WorkflowActionKind::ShellCommand {
            Nullable::some(environment())
        } else {
            Nullable::null()
        },
    }
}

/// A success of `kind`, with the output an action of that kind produces.
#[must_use]
pub fn succeeded(
    kind: kr_protocol::automation::WorkflowActionKind,
) -> kr_automation::ActionOutcome {
    kr_automation::ActionOutcome::Success {
        output: kr_automation::stand_in_output(kind),
    }
}
