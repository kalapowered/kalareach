//! Preparing the effect of a component's action, outside the session boundary.
//!
//! A package's component turns an invoked control into a proposed effect. The call is a round trip
//! to the plugin runtime, bounded by the component's own deadline and the allowance for the trip,
//! and it sends nothing. It is made after the action's intent is committed and before the
//! boundary that revalidates it and writes its dispatch marker, with no lock of this worker held.
//! The receipt stays `accepted` while it runs, so a duplicate request, a cancellation and a
//! revocation all find the action.
//!
//! What comes back is a proposal. The broker builds the effect it will compare from the invocation
//! and the declaration, never from the component's words, and refuses a plan that disagrees with
//! either. A component is therefore a veto, and a chooser of the one operation its action declared.
//! The fields of a routed method a plan may carry are not applied: what leaves is the invocation's
//! own validated arguments, so a plan that carries fields, or names a method other than the one the
//! action goes out as, is refused rather than silently reduced.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_plugin_sdk::effect::{
    ActionArgument, ActionInvocation, ArgumentValue, EffectClass as DeclaredClass, ParameterKind,
};
use kr_plugin_sdk::ids::{NodeId, ParameterName};
use kr_plugin_sdk::scalars::SafeInt;
use kr_plugin_service::client::{PluginClient, ROUND_TRIP_ALLOWANCE};
use kr_plugin_service::error::ServiceError;
use kr_plugin_service::protocol::{
    WireArgument, WireNamedArgument, WireOperation, WirePlan, WireToken,
};
use kr_plugin_service::vocabulary::BindingId;
use kr_protocol::admission::ComponentState;
use kr_protocol::agent::PluginActionInvokeParams;
use kr_protocol::broker::{PreparedEffect, PreparedOperation};
use kr_protocol::ids::BrokerBindingId;
use kr_protocol::scalars::{Digest256, Nullable};

use crate::broker::error::{BrokerError, Result};
use crate::broker::methods::{Caller, RegisteredAction};
use crate::broker::{Broker, DraftSnapshot};

/// How many preparations may be inside a component at once, across every connection.
///
/// The plugin runtime lets one connection have sixteen calls running, and a registration or an
/// unbinding is one of them. Staying well below that keeps a burst of invocations from making the
/// runtime refuse the registration of a binding.
pub const MAX_PREPARATIONS: usize = 8;

/// The longest a component's answer is waited for, including the wait for a place among the
/// preparations in progress and the round trip to the runtime; the action's own accepted deadline
/// can shorten it.
///
/// The component runs under its own ten millisecond deadline. This is what a busy binding may take
/// to reach the call.
pub const PREPARATION_DEADLINE: Duration = Duration::from_secs(5);

/// How a component is asked to prepare an action.
///
/// The link to the plugin runtime holds the connection and publishes it here once it has one, and
/// withdraws it when the connection ends. Nothing in the broker holds the connection itself.
#[derive(Debug)]
pub struct ComponentCalls {
    client: Mutex<Option<Arc<PluginClient>>>,
    /// The preparations inside a component now.
    running: Arc<tokio::sync::Semaphore>,
}

impl ComponentCalls {
    pub(super) fn new() -> Self {
        Self {
            client: Mutex::new(None),
            running: Arc::new(tokio::sync::Semaphore::new(MAX_PREPARATIONS)),
        }
    }

    /// Publishes the runtime's connection, or withdraws it.
    pub fn set(&self, client: Option<Arc<PluginClient>>) {
        *self
            .client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = client;
    }

    /// Returns the runtime's connection, while there is one.
    #[must_use]
    pub fn client(&self) -> Option<Arc<PluginClient>> {
        self.client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// What the first pass of an action established, which preparing it needs.
#[derive(Clone, Debug)]
pub struct PreparationRequest {
    /// The binding whose component prepares the action.
    pub binding_id: BrokerBindingId,
    /// The invocation as it arrived.
    pub params: PluginActionInvokeParams,
    /// The declaration the first pass checked it against, which the second pass finds unchanged.
    pub declared: RegisteredAction,
    /// The arguments, in the declaration's order.
    pub arguments: Vec<WireNamedArgument>,
    /// The hash of the one encoding of the arguments this host will transmit.
    pub argument_hash: Digest256,
    /// The invocation's authority, as the component reads it.
    pub token: WireToken,
}

/// What preparation hands the second pass.
#[derive(Debug)]
pub struct Preparation {
    /// The binding that prepared it.
    pub binding_id: BrokerBindingId,
    /// The declaration the first pass checked it against.
    pub declared: RegisteredAction,
    /// The draft the invocation acts on, as it stood when it was claimed.
    pub draft: Option<DraftSnapshot>,
    /// The effect to compare, or why there is none.
    pub effect: Result<PreparedEffect>,
}

/// Where a binding's component stands, as an action meets it.
enum Standing {
    /// Registered with the plugin runtime.
    Registered,
    /// Not registered yet, or not any longer, and the link will register it.
    Waiting(Option<String>),
    /// Never to be registered: the broker refused its component, because the admissions and the
    /// package's manifest name different ones, or the worker disabled it. A package that ships no
    /// component declares no action one prepares, so the action cannot be made.
    Never(String),
}

impl Standing {
    fn of(
        binding: &crate::broker::Binding,
        reported: Option<&(ComponentState, Option<String>)>,
    ) -> Self {
        if let Some(refusal) = binding
            .component
            .as_ref()
            .and_then(|component| component.refusal.as_ref())
        {
            return Self::Never(refusal.clone());
        }
        if let Some(why) = binding.rich_disabled.as_ref() {
            return Self::Never(format!("it is disabled: {why}"));
        }
        match reported {
            Some((ComponentState::Registered, _)) => Self::Registered,
            Some((ComponentState::Disabled, reason)) => Self::Never(
                reason
                    .clone()
                    .unwrap_or_else(|| "the plugin runtime disabled it".to_owned()),
            ),
            // The runtime lost, or refused, the component; the link offers it again after a delay.
            Some((ComponentState::Unavailable, reason)) => Self::Waiting(reason.clone()),
            Some((ComponentState::Pending, reason)) => Self::Waiting(reason.clone()),
            // Nothing reported yet: the link registers a binding it has not seen in its next pass.
            None => Self::Waiting(None),
        }
    }
}

impl Broker {
    /// Returns the handle the plugin runtime's link publishes its connection through.
    #[must_use]
    pub fn component_calls(&self) -> Arc<ComponentCalls> {
        Arc::clone(&self.component_calls)
    }

    /// Checks an invocation's arguments against the parameters its action declares.
    ///
    /// Every route an invocation takes is held to the declaration, so an argument no declaration
    /// names, a required one that is missing, and a value of the wrong kind or outside its bounds
    /// are refused before anything is admitted, whatever the action does.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] for any of those.
    pub fn check_declared_arguments(
        declared: &RegisteredAction,
        params: &PluginActionInvokeParams,
    ) -> Result<()> {
        read_arguments(declared, &Self::executable_arguments(params)?).map(|_| ())
    }

    /// Checks what can be checked of a component's action before anything is prepared, and
    /// returns what preparing it needs.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the arguments are not the declared ones,
    /// [`BrokerError::ResourceUnavailable`] when the component is not registered with the plugin
    /// runtime yet or any longer (the link registers it, and again after the runtime was lost),
    /// and [`BrokerError::UnsupportedCapability`] when it never will be: the broker refused it
    /// (the admissions and the package's manifest name different components), or it is disabled.
    /// A component the runtime refused is offered again by the link after a delay, so it is
    /// waited for. A draft-acting action gets `UNSUPPORTED_CAPABILITY` too, because this worker
    /// does not read drafts from the control daemon yet.
    pub fn prepare_request(
        &self,
        caller: &Caller,
        binding_id: BrokerBindingId,
        params: &PluginActionInvokeParams,
    ) -> Result<PreparationRequest> {
        let (declared, standing) = {
            let held = self.state();
            let binding = held
                .bindings
                .get(&binding_id)
                .ok_or_else(|| crate::broker::unknown_binding(binding_id))?;
            let declared = binding
                .actions
                .get(&params.action)
                .cloned()
                .ok_or_else(|| {
                    BrokerError::unknown(format!(
                        "{} is not an action {} registered",
                        params.action, params.plugin_id
                    ))
                })?;
            (
                declared,
                Standing::of(binding, held.component_states.get(&binding_id)),
            )
        };
        if !declared.component {
            return Err(BrokerError::invalid(format!(
                "{} is not prepared by a component",
                params.action
            )));
        }
        if declared.needs_draft {
            return Err(BrokerError::UnsupportedCapability {
                detail: format!(
                    "{} acts on a draft, and this worker does not read drafts from the control \
                     daemon yet",
                    params.action
                ),
            });
        }
        let action = &params.action;
        match standing {
            Standing::Registered => {}
            // What is not there yet, or not there now, can be there when the same request is made
            // again: the link registers the component, and registers it again after the runtime
            // has been lost.
            Standing::Waiting(reason) => {
                return Err(BrokerError::ResourceUnavailable {
                    detail: format!(
                        "{action}'s component is not registered with the plugin runtime yet{}",
                        reason.map_or_else(String::new, |reason| format!(": {reason}"))
                    ),
                });
            }
            // What only a change can mend.
            Standing::Never(reason) => {
                return Err(BrokerError::UnsupportedCapability {
                    detail: format!("{action}'s component cannot be prepared: {reason}"),
                });
            }
        }
        if self.component_calls.client().is_none() {
            return Err(BrokerError::ResourceUnavailable {
                detail: "the plugin runtime is not connected".to_owned(),
            });
        }
        let encoded = Self::executable_arguments(params)?;
        let invocation = read_arguments(&declared, &encoded)?;
        let hash = Digest256::from_bytes(kr_cbor::sha256(&encoded));
        let token = WireToken {
            actor_id: caller.actor_id.to_string(),
            grant_id: caller
                .grant_id
                .map_or_else(String::new, |grant| grant.to_string()),
            binding_revision: params.target.binding_revision.get(),
            thread_revision: None,
            action_id: params.action.to_string(),
            parameter_hash: hash.as_bytes().to_vec(),
            // Set from the deadline of the call when the component is asked.
            expires_at_ms: 0,
        };
        Ok(PreparationRequest {
            binding_id,
            params: params.clone(),
            declared,
            arguments: invocation.iter().map(wire_argument_of).collect(),
            argument_hash: hash,
            token,
        })
    }

    /// Asks the component to prepare the action, and compares what it proposes with the
    /// invocation and the declaration.
    ///
    /// Nothing here is held across the call: not this broker's lock, not the session's.
    pub async fn prepare(&self, request: &PreparationRequest, within: Duration) -> Preparation {
        let effect = self.propose(request, within).await;
        Preparation {
            binding_id: request.binding_id,
            declared: request.declared.clone(),
            draft: None,
            effect,
        }
    }

    async fn propose(
        &self,
        request: &PreparationRequest,
        within: Duration,
    ) -> Result<PreparedEffect> {
        let client =
            self.component_calls
                .client()
                .ok_or_else(|| BrokerError::ResourceUnavailable {
                    detail: "the plugin runtime is not connected".to_owned(),
                })?;
        // One bound for the whole of it: the wait for a place and the call both spend the time
        // that is left, and the token the component is given expires with it.
        let deadline = within.min(PREPARATION_DEADLINE);
        let until = tokio::time::Instant::now() + deadline;
        let place = tokio::time::timeout_at(
            until,
            Arc::clone(&self.component_calls.running).acquire_owned(),
        )
        .await
        .map_err(|_| BrokerError::ResourceUnavailable {
            detail: format!(
                "{MAX_PREPARATIONS} actions are being prepared already, and this one was not \
                 reached in time"
            ),
        })?
        .map_err(|_| BrokerError::ResourceUnavailable {
            detail: "preparations are no longer accepted".to_owned(),
        })?;
        // The client waits for the call's deadline and then for the round trip. With less left
        // than the round trip there is no call to give, and none is made.
        let remaining = until.saturating_duration_since(tokio::time::Instant::now());
        let Some(call) = remaining
            .checked_sub(ROUND_TRIP_ALLOWANCE)
            .filter(|call| !call.is_zero() && call.as_millis() > 0)
        else {
            return Err(BrokerError::ResourceUnavailable {
                detail: "the time to prepare this action ran out before the component was asked"
                    .to_owned(),
            });
        };
        let token = WireToken {
            expires_at_ms: kr_ipc::now_ms()
                .get()
                .saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
            ..request.token.clone()
        };
        let called = client
            .prepare_action(
                BindingId::new(request.binding_id.get()),
                token,
                request.arguments.clone(),
                call,
            )
            .await;
        drop(place);
        let called = called.map_err(|error| match error {
            // What a person has to change: a component the runtime has disabled for the
            // binding's life.
            ServiceError::Disabled { reason } => BrokerError::UnsupportedCapability {
                detail: format!("the component is disabled: {reason}"),
            },
            // What did not answer this time: a runtime that is gone or slow, and a component that
            // used its whole allowance. Asking again can succeed.
            other => BrokerError::ResourceUnavailable {
                detail: format!("the component could not be asked to prepare the action: {other}"),
            },
        })?;
        if let Some(fault) = called.fault {
            return Err(BrokerError::InvalidArgument(format!(
                "{}'s component declined to prepare it: {fault}",
                request.params.action
            )));
        }
        let plan = called.plan.ok_or_else(|| {
            BrokerError::InvalidArgument(format!(
                "{}'s component answered with no plan",
                request.params.action
            ))
        })?;
        effect_of(&plan, request)
    }
}

/// Reads an invocation's arguments, as the declaration says each one is.
///
/// The encoding is the one every caller already uses: a JSON object whose members are plain values.
/// What a member's value means is the declared kind of the parameter it names, so the encoding
/// needs no tagging and cannot be read two ways. A value that is not an object, a `null`, a member
/// the declaration does not name, a number that is not a whole number within the exactly
/// representable range, and a value of the wrong kind are all refused, and the list that comes
/// back is in the declaration's order.
///
/// # Errors
///
/// Returns [`BrokerError::InvalidArgument`] for any of those, and for a list the declaration's own
/// schema does not accept (a missing required parameter, a value out of its bounds).
fn read_arguments(declared: &RegisteredAction, encoded: &[u8]) -> Result<Vec<ActionArgument>> {
    let value: serde_json::Value = serde_json::from_slice(encoded).map_err(|error| {
        BrokerError::invalid(format!(
            "{}'s parameters will not read: {error}",
            declared.name
        ))
    })?;
    let serde_json::Value::Object(members) = value else {
        return Err(BrokerError::invalid(format!(
            "{}'s parameters are an object of the declared parameters' values",
            declared.name
        )));
    };
    for name in members.keys() {
        if !declared
            .parameters
            .parameters
            .iter()
            .any(|parameter| parameter.name.as_str() == name)
        {
            return Err(BrokerError::invalid(format!(
                "{} does not declare a parameter named {name}",
                declared.name
            )));
        }
    }
    let mut arguments = Vec::new();
    for parameter in &declared.parameters.parameters {
        let Some(given) = members.get(parameter.name.as_str()) else {
            continue;
        };
        let wrong = || {
            BrokerError::invalid(format!(
                "the parameter {} of {} does not accept this value",
                parameter.name, declared.name
            ))
        };
        let value = match (&parameter.kind, given) {
            (ParameterKind::Text { .. }, serde_json::Value::String(text)) => {
                ArgumentValue::Text { text: text.clone() }
            }
            (ParameterKind::Integer { .. }, serde_json::Value::Number(number)) => {
                let whole = number.as_i64().ok_or_else(wrong)?;
                ArgumentValue::Integer {
                    value: SafeInt::new(whole).map_err(|_| wrong())?,
                }
            }
            (ParameterKind::Boolean {}, serde_json::Value::Bool(decision)) => {
                ArgumentValue::Boolean { value: *decision }
            }
            (ParameterKind::Choice { .. }, serde_json::Value::String(choice)) => {
                ArgumentValue::Choice {
                    choice_id: ParameterName::new(choice.as_str()).map_err(|_| wrong())?,
                }
            }
            (ParameterKind::AttachmentHandle {}, serde_json::Value::String(handle)) => {
                ArgumentValue::AttachmentHandle {
                    handle: handle.clone(),
                }
            }
            (ParameterKind::NodeRef {}, serde_json::Value::String(node)) => {
                ArgumentValue::NodeRef {
                    node_id: NodeId::new(node.as_str()).map_err(|_| wrong())?,
                }
            }
            _ => return Err(wrong()),
        };
        arguments.push(ActionArgument {
            name: parameter.name.clone(),
            value,
        });
    }
    declared
        .parameters
        .check(&ActionInvocation {
            action_id: kr_plugin_sdk::ids::ActionName::new(declared.name.as_str())
                .map_err(|error| BrokerError::invalid(format!("{}: {error}", declared.name)))?,
            resource_id: Nullable::null(),
            arguments: arguments.clone(),
        })
        .map_err(|error| {
            BrokerError::invalid(format!("{}'s parameters: {error}", declared.name))
        })?;
    Ok(arguments)
}

fn wire_argument_of(argument: &ActionArgument) -> WireNamedArgument {
    WireNamedArgument {
        name: argument.name.to_string(),
        value: match &argument.value {
            ArgumentValue::Text { text } => WireArgument::Text(text.clone()),
            ArgumentValue::Integer { value } => WireArgument::Integer(value.get()),
            ArgumentValue::Boolean { value } => WireArgument::Boolean(*value),
            ArgumentValue::Choice { choice_id } => WireArgument::Choice(choice_id.to_string()),
            ArgumentValue::AttachmentHandle { handle } => {
                WireArgument::AttachmentHandle(handle.clone())
            }
            ArgumentValue::NodeRef { node_id } => WireArgument::NodeRef(node_id.to_string()),
        },
    }
}

/// Builds the effect to compare from the invocation, refusing a plan that disagrees with it.
///
/// The worker checks what only it can see: that the plan is for the action invoked, that it is of
/// the class the declaration implies, that it carries the arguments the component was given, and
/// that the operation is one the invocation can carry. Whether that operation is the one the action
/// declared, and whether the binding holds the grant it needs, is the broker's to decide when the
/// effect is validated.
fn effect_of(plan: &WirePlan, request: &PreparationRequest) -> Result<PreparedEffect> {
    let action = &request.params.action;
    if plan.action_id != action.as_str() {
        return Err(BrokerError::invalid(format!(
            "the component prepared {} and {action} was invoked",
            plan.action_id
        )));
    }
    let expected = request.declared.operation.map(class_of);
    if expected != Some(plan.class) {
        return Err(BrokerError::invalid(format!(
            "{action} is declared {} and the component prepared it as {}",
            expected.map_or("with no operation", |class| class.as_str()),
            plan.class.as_str()
        )));
    }
    if plan.arguments != request.arguments {
        return Err(BrokerError::invalid(format!(
            "the component prepared {action} with arguments other than the ones it was given"
        )));
    }
    let operation = match &plan.operation {
        WireOperation::UpstreamMethod { method, fields } => {
            if !fields.is_empty() {
                return Err(BrokerError::invalid(format!(
                    "the component's plan for {action} fills in fields of a routed method, and \
                     what leaves is the invocation's own arguments"
                )));
            }
            if method != action.as_str() {
                return Err(BrokerError::invalid(format!(
                    "the component's plan for {action} names the method {method}, and the action \
                     goes out as {action}"
                )));
            }
            PreparedOperation::UpstreamSubmit
        }
        WireOperation::UpstreamCancel => PreparedOperation::UpstreamCancel,
        WireOperation::UpstreamAttachment { .. } => PreparedOperation::UpstreamAttachment,
        WireOperation::TerminalText(_) => PreparedOperation::TerminalText,
        WireOperation::Present => {
            return Err(BrokerError::invalid(format!(
                "the component's plan for {action} only redraws its document, and a presentation \
                 is a package's presentation implementation"
            )));
        }
    };
    Ok(PreparedEffect {
        action: action.clone(),
        class: kr_protocol::authority::EffectClass::Write,
        operation,
        draft_id: request.params.draft_id,
        argument_hash: request.argument_hash,
    })
}

/// The class an operation belongs to, as a package declares it.
const fn class_of(operation: PreparedOperation) -> DeclaredClass {
    match operation {
        PreparedOperation::UpstreamSubmit => DeclaredClass::UpstreamPrompt,
        PreparedOperation::UpstreamCancel => DeclaredClass::UpstreamCancel,
        PreparedOperation::UpstreamAttachment => DeclaredClass::UpstreamAttachment,
        PreparedOperation::TerminalText => DeclaredClass::TerminalInput,
    }
}
