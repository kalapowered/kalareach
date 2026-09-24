//! The agent-state reads, the five agent mutations and the plugin action call.
//!
//! Section 23 puts these in three method groups, and each group's authority row says something
//! this module has to make expressible.
//!
//! * **Agent state** needs `session.view`, the exact instance, capability evidence and the shared
//!   history filter. Every read therefore names one [`ApplicationInstanceId`] rather than "the
//!   agent", carries the evidence it was answered under, and says where the filter stopped.
//! * **Agent mutations** are five separate methods with distinct rights, and every one of them
//!   carries the binding revision it was prepared against. A stale revision is `DRAFT_CONFLICT` or
//!   `STALE_SESSION`, never a best effort against whatever conversation is selected now.
//! * **Plugin actions** validate the registered action, the actor's grant, the effect class and
//!   the input, draft and request preconditions before anything is dispatched.
//!
//! Every mutation result carries its [`ActionProvenance`]. The app may offer a terminal action as
//! a convenience; what it must never do is report a typed approval from screen text, and a result
//! that cannot name a typed or hook provenance says `terminal_input` instead.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::broker::{ActionName, ActionProvenance, CapabilityMap, IntegrationMode};
use crate::ids::{
    AgentBindingRevision, AgentThreadId, AgentTurnId, ApplicationInstanceId, DraftId,
    LaunchProfileId, PendingResourceId, PluginId, SessionId, UpstreamRequestId,
};
use crate::scalars::{Nullable, TimestampMs, U64};
use crate::semantic::SemanticContinuation;

/// Maximum length in bytes of prompt or steering text one call may carry.
///
/// Longer content belongs in a draft, which has its own revision and its own attachments.
pub const MAX_INLINE_PROMPT_BYTES: usize = 64 * 1024;

/// Prompt or steering text, bounded by the contract rather than by a caller's restraint.
///
/// **The bound is 65,536 bytes of UTF-8, not 65,536 characters.** JSON Schema's `maxLength` counts
/// Unicode characters, so the published `maxLength` is a necessary condition and not a sufficient
/// one: a value of 40,000 accented characters satisfies the schema and is refused here. The
/// normative check is this type's, which every decoder runs, and the schema's description says so
/// for a client that validates before it sends.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PromptText(String);

/// Text that is empty or longer than one call may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("prompt text is 1 to 65536 bytes; longer content belongs in a draft")]
pub struct PromptTextError;

impl PromptText {
    /// Validates and wraps prompt text.
    ///
    /// # Errors
    ///
    /// Returns [`PromptTextError`] when the text is empty or longer than
    /// [`MAX_INLINE_PROMPT_BYTES`] bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, PromptTextError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_INLINE_PROMPT_BYTES {
            return Err(PromptTextError);
        }
        Ok(Self(value))
    }

    /// Returns the text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for PromptText {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::str::FromStr for PromptText {
    type Err = PromptTextError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for PromptText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for PromptText {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PromptText".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::PromptText".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_INLINE_PROMPT_BYTES,
            "description": "Prompt or steering text carried inline. The normative bound is 65536                             bytes of UTF-8; maxLength counts characters and is therefore a                             necessary rather than a sufficient condition."
        })
    }
}

/// What every agent method names: the session and the exact instance inside it.
///
/// Section 12 is explicit that observation binds to the instance, not to a product name: "Semantic
/// observation must bind to the exact `application_instance_id`, upstream execution owner, session
/// and turn."
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSubject {
    /// The session the instance runs in.
    pub session_id: SessionId,
    /// The exact application instance.
    pub application_instance_id: ApplicationInstanceId,
}

/// What the host currently knows about one bound instance.
///
/// This is the answer to "is the thing I am looking at still the thing I was looking at". A client
/// that holds an older revision has to re-read before it may mutate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentBindingState {
    /// The revision in force. It advances when the upstream owner or selected thread changes.
    pub binding_revision: AgentBindingRevision,
    /// The upstream's own conversation identifier, where the connector can observe one.
    pub thread_id: Nullable<AgentThreadId>,
    /// The turn currently running, where one is.
    pub turn_id: Nullable<AgentTurnId>,
    /// The launch profile this instance was started under.
    pub profile_id: Nullable<LaunchProfileId>,
    /// How this instance is integrated.
    pub mode: IntegrationMode,
    /// True while a native selection could not be observed reliably.
    ///
    /// Rich mutations are suspended until the binding is verified. The terminal stays available
    /// throughout, which is why this is a field rather than an error.
    pub rich_mutations_suspended: bool,
    /// Why they are suspended, when they are.
    pub suspension_reason: Nullable<String>,
}

/// Parameters of `agent.capabilities`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCapabilitiesParams {
    /// The session and instance.
    pub subject: AgentSubject,
}

/// The result of `agent.capabilities`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCapabilitiesResult {
    /// The binding this answer is about.
    pub binding: AgentBindingState,
    /// What this installation can currently do, with the evidence behind each entry.
    pub capabilities: CapabilityMap,
}

/// Parameters of `agent.snapshot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshotParams {
    /// The session and instance.
    pub subject: AgentSubject,
    /// The node the reader wants the next part from, when continuing a bounded snapshot.
    pub from_node: Nullable<U64>,
}

/// One entry of a bound agent's shared state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshotEntry {
    /// The entry's position in the producer's walk order.
    pub node: U64,
    /// What kind of entry it is, as the connector's declarative presentation names it.
    pub kind: String,
    /// The entry's text, already filtered by the shared host-side history filter.
    pub text: String,
    /// When it was observed.
    pub observed_at: TimestampMs,
}

/// The result of `agent.snapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshotResult {
    /// The binding this answer is about.
    pub binding: AgentBindingState,
    /// The entries this part carries.
    pub entries: Vec<AgentSnapshotEntry>,
    /// Where a reader continues, when a limit stopped this part.
    pub continuation: Nullable<SemanticContinuation>,
    /// True when the retained range the reader asked for had been evicted.
    ///
    /// Section 24: a rebuilt range shows a history gap for anything unavailable. A grid image or a
    /// transcript file cannot reconstruct an unobserved pending approval, so the gap is reported
    /// rather than filled in.
    pub history_gap: bool,
    /// How many entries the actor's own history filter withheld.
    ///
    /// The count is the honest part: a reader can tell a short answer from a complete one without
    /// being shown what it may not see.
    pub withheld_entries: U64,
}

/// One command a bound agent advertises.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCommand {
    /// The command's name, without its leading marker.
    pub name: String,
    /// What it does, for a person.
    pub summary: String,
    /// How its parameters are encoded when it is executed upstream.
    pub parameter_encoding: String,
}

/// Parameters of `agent.commands`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCommandsParams {
    /// The session and instance.
    pub subject: AgentSubject,
}

/// The result of `agent.commands`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCommandsResult {
    /// The binding this answer is about.
    pub binding: AgentBindingState,
    /// The commands, in the order the upstream advertises them.
    pub commands: Vec<AgentCommand>,
}

/// What a mutation acts on: the subject and the revision it was prepared against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMutationTarget {
    /// The session and instance.
    pub subject: AgentSubject,
    /// The revision the caller read before it prepared this.
    ///
    /// A revision behind the one in force is `STALE_SESSION`: the conversation moved, and applying
    /// the mutation to the new one would be acting on something the caller never saw.
    pub binding_revision: AgentBindingRevision,
}

/// What one accepted agent mutation did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMutationResult {
    /// The revision the mutation was applied at.
    pub binding_revision: AgentBindingRevision,
    /// How it reached the upstream.
    pub provenance: ActionProvenance,
    /// The upstream's own identifier for it, where the upstream gave one.
    pub upstream_request_id: Nullable<UpstreamRequestId>,
    /// The turn it applies to, where the upstream names one.
    pub turn_id: Nullable<AgentTurnId>,
}

/// Parameters of `agent.prompt.submit` and `agent.prompt.queue`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPromptParams {
    /// What the prompt acts on.
    pub target: AgentMutationTarget,
    /// The draft to submit, when the prompt has attachments or was composed elsewhere.
    pub draft_id: Nullable<DraftId>,
    /// The prompt itself, when it is short enough to travel inline.
    pub text: Nullable<PromptText>,
}

impl AgentPromptParams {
    /// Checks that exactly one of the two ways of naming a prompt was used.
    ///
    /// # Errors
    ///
    /// Returns a message naming what was wrong. A call with neither has nothing to submit, and one
    /// with both is two prompts wearing one identifier.
    pub fn validate(&self) -> Result<(), &'static str> {
        match (self.draft_id.is_present(), self.text.is_present()) {
            (true, false) | (false, true) => Ok(()),
            (false, false) => Err("a prompt names either a draft or inline text"),
            (true, true) => Err("a prompt names a draft or inline text, not both"),
        }
    }
}

/// Parameters of `agent.turn.steer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSteerParams {
    /// What the steer acts on.
    pub target: AgentMutationTarget,
    /// The turn being steered. A turn that has ended is refused rather than redirected.
    pub turn_id: AgentTurnId,
    /// The steering text.
    pub text: PromptText,
}

/// Parameters of `agent.turn.cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCancelParams {
    /// What the cancellation acts on.
    pub target: AgentMutationTarget,
    /// The turn to cancel, by the upstream's own identifier.
    pub turn_id: AgentTurnId,
}

/// Parameters of `agent.approval.respond`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentApprovalRespondParams {
    /// What the answer acts on.
    pub target: AgentMutationTarget,
    /// The pending resource being answered.
    pub resource_id: PendingResourceId,
    /// The decision, as one of the options the decoder offered.
    ///
    /// Answering is choosing from what the upstream offered. A free-form answer would be this host
    /// inventing an upstream decision.
    pub option_id: String,
}

/// The result of `agent.approval.respond`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentApprovalRespondResult {
    /// What the mutation did.
    pub mutation: AgentMutationResult,
    /// The resource that was answered.
    pub resource_id: PendingResourceId,
    /// Its state after the answer.
    pub state: crate::gateway::PendingState,
}

/// Parameters of `plugin.action.invoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginActionInvokeParams {
    /// What the action acts on.
    pub target: AgentMutationTarget,
    /// The package whose action this is.
    pub plugin_id: PluginId,
    /// The registered action.
    pub action: ActionName,
    /// The draft the action acts on, where it acts on one.
    pub draft_id: Nullable<DraftId>,
    /// The pending resource this invocation answers.
    ///
    /// An action whose effect class is `approval.respond` answers exactly one pending request,
    /// and this names it. Every other action names none. The caller never supplies the upstream's
    /// own request identifier: an answer carries the identifier the named resource recorded when
    /// the request arrived, so it can resolve only the request it names.
    pub resource_id: Nullable<PendingResourceId>,
    /// The action's parameters, canonically encoded by the caller.
    ///
    /// The bytes are hashed into the action token, so what the component is asked to do and what
    /// the broker authorised cannot differ.
    pub parameters: crate::scalars::Bytes,
}

/// The result of `plugin.action.invoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginActionInvokeResult {
    /// What the action did upstream.
    pub mutation: AgentMutationResult,
    /// The action that ran.
    pub action: ActionName,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    #[test]
    fn every_agent_method_names_one_exact_instance() {
        let subject = AgentSubject {
            session_id: SessionId::new(Uuid::from_bytes([1; 16])),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
        };
        let encoded = serde_json::to_value(subject).expect("the subject encodes");
        assert!(encoded.get("application_instance_id").is_some());
        assert!(encoded.get("session_id").is_some());
    }

    #[test]
    fn inline_text_is_bounded_in_bytes_rather_than_characters() {
        assert!(PromptText::new("hello").is_ok());
        assert!(PromptText::new(String::new()).is_err());
        assert!(PromptText::new("a".repeat(MAX_INLINE_PROMPT_BYTES)).is_ok());
        assert!(PromptText::new("a".repeat(MAX_INLINE_PROMPT_BYTES + 1)).is_err());
        let over_long = serde_json::Value::String("a".repeat(MAX_INLINE_PROMPT_BYTES + 1));
        assert!(
            serde_json::from_value::<PromptText>(over_long).is_err(),
            "the bound is enforced by the type every decoder runs"
        );

        // Two bytes per character: half the characters, the same bytes. The schema's character
        // count would admit this, and the type does not.
        let multibyte = "é".repeat(MAX_INLINE_PROMPT_BYTES / 2);
        assert_eq!(multibyte.len(), MAX_INLINE_PROMPT_BYTES);
        assert_eq!(multibyte.chars().count(), MAX_INLINE_PROMPT_BYTES / 2);
        assert!(PromptText::new(multibyte.clone()).is_ok());
        assert!(
            PromptText::new(format!("{multibyte}é")).is_err(),
            "the bound is bytes, and a multibyte character spends two of them"
        );
        assert!(
            serde_json::from_value::<PromptText>(serde_json::Value::String(format!(
                "{multibyte}é"
            )))
            .is_err()
        );
    }

    #[test]
    fn a_prompt_names_a_draft_or_inline_text_and_not_both() {
        let target = AgentMutationTarget {
            subject: AgentSubject {
                session_id: SessionId::new(Uuid::from_bytes([1; 16])),
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            },
            binding_revision: AgentBindingRevision::new(7),
        };
        let neither = AgentPromptParams {
            target,
            draft_id: Nullable::null(),
            text: Nullable::null(),
        };
        assert!(neither.validate().is_err());
        let inline = AgentPromptParams {
            target,
            draft_id: Nullable::null(),
            text: Nullable::some(PromptText::new("hello").expect("valid")),
        };
        inline.validate().expect("inline text alone is a prompt");
        let both = AgentPromptParams {
            target,
            draft_id: Nullable::some(DraftId::new(Uuid::from_bytes([4; 16]))),
            text: Nullable::some(PromptText::new("hello").expect("valid")),
        };
        assert!(both.validate().is_err());
    }

    /// KR-REQ-12.18 and KR-REQ-11.47: a plugin action call names the pending resource it answers,
    /// or says it answers none. The member is always present, so an older caller that knows
    /// nothing of it is refused rather than read as answering nothing, and only a pending resource
    /// identifier fills it.
    #[test]
    fn a_plugin_action_names_the_pending_resource_it_answers() {
        let target = AgentMutationTarget {
            subject: AgentSubject {
                session_id: SessionId::new(Uuid::from_bytes([1; 16])),
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            },
            binding_revision: AgentBindingRevision::new(7),
        };
        let resource = PendingResourceId::new(Uuid::from_bytes([9; 16]));
        let answer = PluginActionInvokeParams {
            target,
            plugin_id: PluginId::new("kalareach/claude-code").expect("valid"),
            action: ActionName::new("approval.answer").expect("valid"),
            draft_id: Nullable::null(),
            resource_id: Nullable::some(resource),
            parameters: crate::scalars::Bytes::from(br#"{"decision":"allow"}"#.to_vec()),
        };
        let encoded = serde_json::to_value(&answer).expect("the call encodes");
        assert_eq!(
            encoded.get("resource_id"),
            Some(&serde_json::to_value(resource).expect("the identifier encodes"))
        );
        assert_eq!(
            serde_json::from_value::<PluginActionInvokeParams>(encoded.clone())
                .expect("the call decodes"),
            answer
        );

        // An action that answers nothing says so with null.
        let mut none = encoded.clone();
        none["resource_id"] = serde_json::Value::Null;
        let decoded: PluginActionInvokeParams = serde_json::from_value(none).expect("null decodes");
        assert!(!decoded.resource_id.is_present());

        // Absent is not null, and only a pending resource identifier is one.
        let mut absent = encoded.clone();
        absent
            .as_object_mut()
            .expect("an object")
            .remove("resource_id");
        assert!(serde_json::from_value::<PluginActionInvokeParams>(absent).is_err());
        for malformed in [
            serde_json::json!("abcde"),
            serde_json::json!(7),
            serde_json::json!({"resource_id": "abcde"}),
        ] {
            let mut call = encoded.clone();
            call["resource_id"] = malformed.clone();
            assert!(
                serde_json::from_value::<PluginActionInvokeParams>(call).is_err(),
                "{malformed} was read as a pending resource"
            );
        }
    }

    #[test]
    fn a_mutation_carries_the_revision_it_was_prepared_against() {
        let target = AgentMutationTarget {
            subject: AgentSubject {
                session_id: SessionId::new(Uuid::from_bytes([1; 16])),
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            },
            binding_revision: AgentBindingRevision::new(7),
        };
        let encoded = serde_json::to_value(target).expect("the target encodes");
        assert_eq!(
            encoded
                .get("binding_revision")
                .and_then(serde_json::Value::as_str),
            Some("7")
        );
    }
}
