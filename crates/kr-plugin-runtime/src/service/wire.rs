//! Turning what a `prepare-action` call carries into what a component reads, and what it returns
//! into what travels.
//!
//! The component's types are generated from the contract; the protocol's are plain data of the
//! service crate, which links no engine. This is the one place the two meet, so a worker and the
//! host agree on what each field means.

use kr_plugin_sdk::effect::EffectClass as WireClass;
use kr_plugin_service::protocol::{
    WireArgument, WireField, WireNamedArgument, WireOperation, WirePlan, WireSegment, WireToken,
};

use crate::runtime::bindings::{
    ActionToken, Argument, EffectClass, EffectPlan, FieldAssignment, FieldSegment, NamedArgument,
    PreparedOperation, UpstreamCall,
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
