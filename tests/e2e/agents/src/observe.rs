//! What the host says about an agent, and what it does with the typed actions a device sends
//! about it.
//!
//! A device learns what an agent can do from what the host announces: the session's agent
//! instances and the pending resources it arbitrates, in `events.snapshot`, and the capability
//! evidence for the installed package, in `plugin.capabilities`. It acts through typed methods that
//! name the session, an application instance and a binding revision. On a terminal route the host
//! announces no instance, so a typed action has nothing it could act on; each one is sent here
//! anyway, well formed apart from the instance it names, and what the host answers is recorded.

use kr_e2e_m1b::device::Remote;
use kr_protocol::agent::{
    AgentApprovalRespondParams, AgentApprovalRespondResult, AgentCancelParams,
    AgentCapabilitiesParams, AgentCapabilitiesResult, AgentCommandsParams, AgentCommandsResult,
    AgentMutationResult, AgentMutationTarget, AgentPromptParams, AgentSteerParams, AgentSubject,
    PluginActionInvokeParams, PluginActionInvokeResult, PromptText,
};
use kr_protocol::broker::ActionName;
use kr_protocol::catalogue::{
    PluginCapabilitiesParams, PluginCapabilitiesResult, PluginListParams, PluginListResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{
    AgentBindingRevision, AgentTurnId, ApplicationInstanceId, DraftId, DraftRevision,
    PendingResourceId, PluginId, SessionEpoch, SessionId, TransferId,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, Nullable, U64};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    InsertionMethod,
};
use serde_json::json;

use crate::stage::events_snapshot;

/// The text every refused typed prompt carries, which the agent's screen must never show.
pub const TYPED_PROMPT: &str = "kr-typed-prompt";

/// What a session announces about agents: its live instances and the resources it arbitrates.
#[derive(Clone, Debug)]
pub struct Announced {
    /// The live agent instances, as the session announces them.
    pub instances: Vec<serde_json::Value>,
    /// The pending resources on the snapshot's first page.
    pub resources: Vec<serde_json::Value>,
    /// Whether more resources follow on another page.
    pub more: bool,
}

impl Announced {
    /// Whether the session announces nothing at all about agents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty() && self.resources.is_empty() && !self.more
    }

    /// The announcement as evidence.
    #[must_use]
    pub fn evidence(&self) -> serde_json::Value {
        json!({
            "instances": self.instances,
            "resources": self.resources,
            "more_resources": self.more,
        })
    }
}

/// Reads what `session_id` announces about agents.
#[must_use]
pub fn announced(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    session_id: SessionId,
) -> Announced {
    let snapshot = events_snapshot(remote, runtime, session_id);
    Announced {
        instances: snapshot
            .agent_instances
            .instances
            .iter()
            .map(|instance| serde_json::to_value(instance).unwrap_or_default())
            .collect(),
        resources: snapshot
            .agent_resources
            .resources
            .iter()
            .map(|resource| serde_json::to_value(resource).unwrap_or_default())
            .collect(),
        more: snapshot.agent_resources.continue_after.0.is_some(),
    }
}

/// The capability evidence the host holds for an installed package: each capability and its
/// state.
///
/// # Panics
///
/// Panics when the host refuses the read.
#[must_use]
pub fn capability_states(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    plugin_id: &PluginId,
) -> Vec<(String, String)> {
    let answer: PluginCapabilitiesResult = runtime
        .block_on(remote.read(
            Method::PluginCapabilities,
            &PluginCapabilitiesParams {
                environment_id: remote.environment_id(),
                plugin_id: plugin_id.clone(),
            },
        ))
        .unwrap_or_else(|error| panic!("plugin.capabilities: {error}"));
    answer
        .evidence
        .iter()
        .map(|record| {
            (
                record.capability.to_string(),
                serde_json::to_value(record.state)
                    .ok()
                    .and_then(|state| state.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// How many live bindings hold the installed package.
///
/// # Panics
///
/// Panics when the host refuses the read or does not list the package.
#[must_use]
pub fn live_bindings(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    plugin_id: &PluginId,
) -> u64 {
    let listed: PluginListResult = runtime
        .block_on(remote.read(
            Method::PluginList,
            &PluginListParams {
                environment_id: remote.environment_id(),
            },
        ))
        .unwrap_or_else(|error| panic!("plugin.list: {error}"));
    listed
        .plugins
        .iter()
        .find(|plugin| &plugin.plugin_id == plugin_id)
        .map(|plugin| plugin.live_bindings.get())
        .unwrap_or_else(|| panic!("plugin.list names {plugin_id}"))
}

/// What the host answered one typed action or read with.
#[derive(Clone, Debug)]
pub struct Answer {
    /// The method, and for a plugin action the action it names.
    pub call: String,
    /// The code the host refused it with, or nothing when it did not refuse it.
    pub refused: Option<String>,
    /// What came back, in words.
    pub detail: String,
}

impl Answer {
    /// The answer as evidence.
    #[must_use]
    pub fn evidence(&self) -> serde_json::Value {
        json!({ "call": self.call, "refused": self.refused, "detail": self.detail })
    }
}

fn answer<R>(call: String, outcome: Result<R, kr_e2e_m1b::device::RequestError>) -> Answer {
    match outcome {
        Ok(_) => Answer {
            call,
            refused: None,
            detail: "accepted".to_owned(),
        },
        Err(error) => Answer {
            call,
            refused: Some(
                error
                    .refusal()
                    .map_or_else(|| "no code".to_owned(), |code| code.as_str().to_owned()),
            ),
            detail: error.to_string(),
        },
    }
}

/// Sends every typed agent action, and each of the package's actions, for `session_id`, naming an
/// application instance and a binding revision the host never announced, and reads the agent's
/// capabilities and commands the same way. Returns what the host answered each with.
///
/// The attachment request names a draft and an upload that are well formed and exist nowhere: a
/// paired device's connection carries no draft or upload request to the service that keeps them,
/// so a device cannot make real ones on this host, and what the host answers is recorded as it is.
#[must_use]
pub fn typed_actions(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    session_id: SessionId,
    plugin_id: &PluginId,
    actions: &[String],
) -> Vec<Answer> {
    let instance = ApplicationInstanceId::new(kr_ipc::new_uuid());
    let revision = AgentBindingRevision::new(1);
    let subject = AgentSubject {
        session_id,
        application_instance_id: instance,
    };
    let target = AgentMutationTarget {
        subject,
        binding_revision: revision,
    };
    let envelope = ActionTarget {
        environment_id: remote.environment_id(),
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::some(instance),
        agent_binding_revision: Nullable::some(revision),
    };
    let text = PromptText::new(TYPED_PROMPT).expect("a prompt");
    let turn = AgentTurnId::new("turn-1").expect("a turn identifier");
    let mut answers = Vec::new();
    for method in [Method::AgentPromptSubmit, Method::AgentPromptQueue] {
        let sent = runtime.block_on(remote.mutate::<_, AgentMutationResult>(
            method,
            envelope.clone(),
            &AgentPromptParams {
                target,
                draft_id: Nullable::null(),
                text: Nullable::some(text.clone()),
            },
        ));
        answers.push(answer(method.as_str().to_owned(), sent));
    }
    let sent = runtime.block_on(remote.mutate::<_, AgentMutationResult>(
        Method::AgentTurnSteer,
        envelope.clone(),
        &AgentSteerParams {
            target,
            turn_id: turn.clone(),
            text: text.clone(),
        },
    ));
    answers.push(answer(Method::AgentTurnSteer.as_str().to_owned(), sent));
    let sent = runtime.block_on(remote.mutate::<_, AgentMutationResult>(
        Method::AgentTurnCancel,
        envelope.clone(),
        &AgentCancelParams {
            target,
            turn_id: turn,
        },
    ));
    answers.push(answer(Method::AgentTurnCancel.as_str().to_owned(), sent));
    let sent = runtime.block_on(remote.mutate::<_, AgentApprovalRespondResult>(
        Method::AgentApprovalRespond,
        envelope.clone(),
        &AgentApprovalRespondParams {
            target,
            resource_id: PendingResourceId::new(kr_ipc::new_uuid()),
            option_id: "allow".to_owned(),
        },
    ));
    answers.push(answer(
        Method::AgentApprovalRespond.as_str().to_owned(),
        sent,
    ));
    let sent = runtime.block_on(remote.mutate::<_, AgentDraftAddAttachmentResult>(
        Method::AgentDraftAddAttachment,
        envelope.clone(),
        &AgentDraftAddAttachmentParams {
            draft_id: DraftId::new(kr_ipc::new_uuid()),
            expected_revision: DraftRevision::new(1),
            transfer_id: TransferId::new(kr_ipc::new_uuid()),
            contribution: AttachmentContribution {
                operation_id: "prompt".to_owned(),
                accepted_media_types: vec!["image/png".to_owned()],
                max_byte_len: U64::new(1 << 20),
                max_count: U64::new(1),
                insertion_method: InsertionMethod::TypedSubmission,
                external_destination: Nullable::null(),
                model_media_capability: true,
            },
        },
    ));
    answers.push(answer(
        Method::AgentDraftAddAttachment.as_str().to_owned(),
        sent,
    ));
    let parameters = kr_cbor::to_canonical_vec(&json!({})).expect("empty parameters");
    for action in actions {
        let sent = runtime.block_on(remote.mutate::<_, PluginActionInvokeResult>(
            Method::PluginActionInvoke,
            envelope.clone(),
            &PluginActionInvokeParams {
                target,
                plugin_id: plugin_id.clone(),
                action: ActionName::new(action.clone()).expect("an action name"),
                draft_id: Nullable::null(),
                resource_id: Nullable::null(),
                parameters: Bytes::new(parameters.clone()),
            },
        ));
        answers.push(answer(
            format!("{} {action}", Method::PluginActionInvoke.as_str()),
            sent,
        ));
    }
    let read = runtime.block_on(remote.read::<_, AgentCapabilitiesResult>(
        Method::AgentCapabilities,
        &AgentCapabilitiesParams { subject },
    ));
    answers.push(answer(Method::AgentCapabilities.as_str().to_owned(), read));
    let read =
        runtime.block_on(remote.read::<_, AgentCommandsResult>(
            Method::AgentCommands,
            &AgentCommandsParams { subject },
        ));
    answers.push(answer(Method::AgentCommands.as_str().to_owned(), read));
    answers
}
