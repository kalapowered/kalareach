//! Turning what a `prepare-action` call carries into what a component reads, and what it returns
//! into what travels.
//!
//! The component's types are generated from the contract; the protocol's are plain data of the
//! service crate, which links no engine. This is the one place the two meet, so a worker and the
//! host agree on what each field means.

use kr_plugin_sdk::effect::EffectClass as WireClass;
use kr_plugin_service::protocol::{
    WireArgument, WireDecoded, WireEncoded, WireField, WireMethodClass, WireNamedArgument,
    WireOperation, WirePlan, WireRequestSnapshot, WireSegment, WireToken,
};

use crate::runtime::bindings::{
    ActionToken, Argument, DecodedRequest, EffectClass, EffectPlan, EncodedResponse,
    FieldAssignment, FieldSegment, MethodClass, NamedArgument, PreparedOperation, RequestSnapshot,
    UpstreamCall,
};

/// The token a component reads, from the one that travelled.
pub(crate) fn token_of(token: WireToken) -> ActionToken {
    ActionToken {
        actor_id: token.actor_id,
        grant_id: token.grant_id,
        binding_revision: token.binding_revision,
        thread_revision: token.thread_revision,
        action_id: token.action_id,
        parameter_hash: token.parameter_hash,
        expires_at: token.expires_at_ms,
    }
}

/// The arguments a component reads, from the ones that travelled.
pub(crate) fn arguments_of(arguments: Vec<WireNamedArgument>) -> Vec<NamedArgument> {
    arguments
        .into_iter()
        .map(|argument| NamedArgument {
            name: argument.name,
            value: argument_of(argument.value),
        })
        .collect()
}

fn argument_of(argument: WireArgument) -> Argument {
    match argument {
        WireArgument::Text(text) => Argument::Text(text),
        WireArgument::Integer(value) => Argument::Integer(value),
        WireArgument::Boolean(value) => Argument::Boolean(value),
        WireArgument::Choice(id) => Argument::Choice(id),
        WireArgument::AttachmentHandle(id) => Argument::AttachmentHandle(id),
        WireArgument::NodeRef(id) => Argument::NodeRef(id),
    }
}

fn wire_argument_of(argument: Argument) -> WireArgument {
    match argument {
        Argument::Text(text) => WireArgument::Text(text),
        Argument::Integer(value) => WireArgument::Integer(value),
        Argument::Boolean(value) => WireArgument::Boolean(value),
        Argument::Choice(id) => WireArgument::Choice(id),
        Argument::AttachmentHandle(id) => WireArgument::AttachmentHandle(id),
        Argument::NodeRef(id) => WireArgument::NodeRef(id),
    }
}

/// The plan that travels, from the one a component returned.
pub(crate) fn wire_plan_of(plan: EffectPlan) -> WirePlan {
    WirePlan {
        action_id: plan.action_id,
        class: match plan.class {
            EffectClass::Observe => WireClass::Observe,
            EffectClass::UpstreamPrompt => WireClass::UpstreamPrompt,
            EffectClass::UpstreamCancel => WireClass::UpstreamCancel,
            EffectClass::UpstreamAttachment => WireClass::UpstreamAttachment,
            EffectClass::ApprovalDecode => WireClass::ApprovalDecode,
            EffectClass::ApprovalRespond => WireClass::ApprovalRespond,
            EffectClass::TerminalInput => WireClass::TerminalInput,
        },
        operation: match plan.operation {
            PreparedOperation::Present => WireOperation::Present,
            PreparedOperation::UpstreamMethod(UpstreamCall { method, fields }) => {
                WireOperation::UpstreamMethod {
                    method,
                    fields: fields.into_iter().map(wire_field_of).collect(),
                }
            }
            PreparedOperation::UpstreamCancel => WireOperation::UpstreamCancel,
            PreparedOperation::UpstreamAttachment(attachment_id) => {
                WireOperation::UpstreamAttachment { attachment_id }
            }
            PreparedOperation::TerminalText(text) => WireOperation::TerminalText(text),
        },
        arguments: plan
            .arguments
            .into_iter()
            .map(|argument| WireNamedArgument {
                name: argument.name,
                value: wire_argument_of(argument.value),
            })
            .collect(),
    }
}

fn wire_field_of(field: FieldAssignment) -> WireField {
    WireField {
        path: field
            .path
            .into_iter()
            .map(|segment| match segment {
                FieldSegment::Member(name) => WireSegment::Member(name),
                FieldSegment::Index(index) => WireSegment::Index(index),
            })
            .collect(),
        value: wire_argument_of(field.value),
    }
}

/// The class a component reads, from the one that travelled.
const fn class_of(class: WireMethodClass) -> MethodClass {
    match class {
        WireMethodClass::Observation => MethodClass::Observation,
        WireMethodClass::Mutation => MethodClass::Mutation,
        WireMethodClass::Credential => MethodClass::Credential,
        WireMethodClass::Unsupported => MethodClass::Unsupported,
    }
}

/// The class that travels, from the one a component returned.
const fn wire_class_of(class: MethodClass) -> WireMethodClass {
    match class {
        MethodClass::Observation => WireMethodClass::Observation,
        MethodClass::Mutation => WireMethodClass::Mutation,
        MethodClass::Credential => WireMethodClass::Credential,
        MethodClass::Unsupported => WireMethodClass::Unsupported,
    }
}

/// The broker's record of a pending request as a component reads it, from the one that travelled.
pub(crate) fn request_snapshot_of(request: &WireRequestSnapshot) -> RequestSnapshot {
    RequestSnapshot {
        request_id: request.request_id.clone(),
        handle: request.handle.as_str().to_owned(),
        method: request.method.clone(),
        class: class_of(request.class),
        received_at: request.received_at_ms,
        deadline_at: request.deadline_at_ms,
        offered_decisions: request.offered_decisions.clone(),
        binding_revision: request.binding_revision,
    }
}

/// The request that travels, from the one a component decoded.
pub(crate) fn wire_decoded_of(decoded: DecodedRequest) -> WireDecoded {
    WireDecoded {
        request_id: decoded.request_id,
        class: wire_class_of(decoded.class),
        summary: decoded.summary,
        decisions: decoded.decisions,
        presentation: decoded.presentation,
    }
}

/// The response that travels, from the one a component encoded.
pub(crate) fn wire_encoded_of(encoded: EncodedResponse) -> WireEncoded {
    WireEncoded {
        request_id: encoded.request_id,
        bytes: encoded.bytes,
    }
}
