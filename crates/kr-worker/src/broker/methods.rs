//! The method groups the broker serves: agent state, the five agent mutations and the plugin
//! action call.
//!
//! Section 23's authority table says what each group requires, and this is where the half that is
//! about *this instance* is decided. The half that is about the *actor* is the method registry's,
//! and the worker's service asks that before anything here runs; the two are separate because a
//! caller can hold every right in the table and still be acting on a conversation that changed
//! underneath it.
//!
//! * **Agent state** binds to the exact instance, answers with the capability evidence it was
//!   answered under, and says how much the history filter withheld and whether a range was
//!   evicted.
//! * **Agent mutations** are five methods with five rights, and every one of them carries the
//!   binding revision it was prepared against. A revision behind the one in force is
//!   `STALE_SESSION`; a draft that moved is `DRAFT_CONFLICT`.
//! * **Plugin actions** check the registered action, the grant it declares, its effect class and
//!   the draft and request preconditions before an action token is issued.

use kr_protocol::agent::{
    AgentApprovalRespondParams, AgentApprovalRespondResult, AgentCancelParams,
    AgentCapabilitiesParams, AgentCapabilitiesResult, AgentCommand, AgentCommandsParams,
    AgentCommandsResult, AgentMutationResult, AgentMutationTarget, AgentPromptParams,
    AgentSnapshotParams, AgentSnapshotResult, AgentSteerParams, AgentSubject,
    PluginActionInvokeParams, PluginActionInvokeResult,
};
use kr_protocol::authority::EffectClass;
use kr_protocol::broker::{ActionName, ActionProvenance, BrokerGrant};
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, BrokerBindingId, CapabilityId, CapabilityRevision, GrantId,
    SessionId, StreamCursor,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::broker::error::{BrokerError, Result};
use crate::broker::semantic::HistoryFilter;
use crate::broker::tokens::Invocation;
use crate::broker::{Broker, DispatchAdmission};

/// One action a package registered, and everything the broker checks before it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredAction {
    /// The action's declared name.
    pub name: ActionName,
    /// Which of the three grants it needs.
    pub grant: BrokerGrant,
    /// Whether it reads or writes.
    ///
    /// Section 23's plugin-action row names the effect class among what is validated, and it is
    /// checked rather than inferred: an action declared as a read that arrives on the write path
    /// is a manifest and a call that disagree.
    pub effect: EffectClass,
    /// The capability the action needs, where it needs one.
    pub capability: Option<CapabilityId>,
    /// True when the action acts on a draft, so a draft must be named.
    pub needs_draft: bool,
}

/// What a caller presents for an agent mutation.
#[derive(Clone, Debug)]
pub struct Caller {
    /// The host-verified actor.
    pub actor_id: ActorId,
    /// The grant record the actor's authority comes from.
    pub grant_id: GrantId,
}

impl Broker {
    /// Answers `agent.capabilities`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the instance is not one this worker serves.
    pub fn agent_capabilities(
        &self,
        params: &AgentCapabilitiesParams,
    ) -> Result<AgentCapabilitiesResult> {
        self.check_subject(&params.subject)?;
        Ok(AgentCapabilitiesResult {
            binding: self.binding_state(params.subject.application_instance_id)?,
            capabilities: self.capabilities(params.subject.application_instance_id),
        })
    }

    /// Answers `agent.snapshot`, filtered by the actor's own history filter.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the instance is not one this worker serves.
    pub fn agent_snapshot(
        &self,
        params: &AgentSnapshotParams,
        filter: &dyn HistoryFilter,
    ) -> Result<AgentSnapshotResult> {
        self.check_subject(&params.subject)?;
        let binding = self.binding_state(params.subject.application_instance_id)?;
        let from = params
            .from_node
            .as_ref()
            .map(|node| StreamCursor::new(node.get()));
        let replay = self.replay(params.subject.application_instance_id, from, filter)?;
        Ok(AgentSnapshotResult {
            binding,
            entries: replay.entries,
            continuation: Nullable::from(replay.continuation),
            history_gap: replay.history_gap,
            withheld_entries: U64::new(replay.withheld),
        })
    }

    /// Answers `agent.commands`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the instance is not one this worker serves.
    pub fn agent_commands(&self, params: &AgentCommandsParams) -> Result<AgentCommandsResult> {
        self.check_subject(&params.subject)?;
        Ok(AgentCommandsResult {
            binding: self.binding_state(params.subject.application_instance_id)?,
            commands: self.commands(params.subject.application_instance_id),
        })
    }

    /// Applies `agent.prompt.submit` or `agent.prompt.queue`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the call names neither a draft nor text, or
    /// both, and whatever [`Broker::check_mutation`] refuses.
    pub fn agent_prompt(
        &self,
        caller: &Caller,
        params: &AgentPromptParams,
        queued: bool,
    ) -> Result<AgentMutationResult> {
        params.validate().map_err(BrokerError::invalid)?;
        let capability = if queued {
            "agent.prompt.queue"
        } else {
            "agent.prompt"
        };
        self.check_mutation(caller, &params.target, capability, "prompt.submit")
    }

    /// Applies `agent.turn.steer`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when the turn named is not the one running,
    /// and whatever [`Broker::check_mutation`] refuses.
    pub fn agent_steer(
        &self,
        caller: &Caller,
        params: &AgentSteerParams,
    ) -> Result<AgentMutationResult> {
        let binding = self.binding_state(params.target.subject.application_instance_id)?;
        if binding.turn_id.as_ref() != Some(&params.turn_id) {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{} is not the turn this instance is running",
                    params.turn_id
                ),
            });
        }
        let mut result =
            self.check_mutation(caller, &params.target, "agent.steer", "turn.steer")?;
        result.turn_id = Nullable::some(params.turn_id.clone());
        Ok(result)
    }

    /// Applies `agent.turn.cancel`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when the turn named is not the one running,
    /// and whatever [`Broker::check_mutation`] refuses.
    pub fn agent_cancel(
        &self,
        caller: &Caller,
        params: &AgentCancelParams,
    ) -> Result<AgentMutationResult> {
        let binding = self.binding_state(params.target.subject.application_instance_id)?;
        if binding.turn_id.as_ref() != Some(&params.turn_id) {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{} is not the turn this instance is running",
                    params.turn_id
                ),
            });
        }
        let mut result =
            self.check_mutation(caller, &params.target, "agent.cancel", "turn.cancel")?;
        result.turn_id = Nullable::some(params.turn_id.clone());
        Ok(result)
    }

    /// Applies `agent.approval.respond`: claims the resource, admits the answer and resolves it.
    ///
    /// This is the encode, recheck, claim and dispatch transaction as a method sees it. The
    /// decision is checked against the ones the request actually offered, and the durable marker
    /// is committed before the answer would go.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::check_mutation`], [`Broker::claim`] and
    /// [`Broker::admit_dispatch`] refuse.
    pub fn agent_approval_respond(
        &self,
        caller: &Caller,
        params: &AgentApprovalRespondParams,
        now: TimestampMs,
    ) -> Result<(AgentApprovalRespondResult, DispatchAdmission)> {
        let mutation =
            self.check_mutation(caller, &params.target, "agent.approval", "approval.respond")?;
        let resource = self.pending(params.resource_id).ok_or_else(|| {
            BrokerError::unknown(format!("no pending resource {}", params.resource_id))
        })?;
        if resource.application_instance_id != params.target.subject.application_instance_id {
            return Err(BrokerError::denied(format!(
                "{} belongs to another application instance",
                params.resource_id
            )));
        }
        // The decision is checked before the claim is taken. Claiming and then discovering the
        // answer was never on offer would leave the resource held by a caller that has nothing to
        // spend it on.
        let entry =
            self.decoding(params.resource_id)?
                .ok_or_else(|| BrokerError::PreconditionFailed {
                    detail: format!(
                        "{} has no recorded interpretation, so there is nothing to answer",
                        params.resource_id
                    ),
                })?;
        if !entry.offers(&params.option_id) {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{} is not one of the decisions this request offered",
                    params.option_id
                ),
            });
        }
        let claim = self.claim(params.resource_id, &caller.actor_id, now)?;
        // From here the claim is held, so anything that fails gives it back rather than leaving
        // the resource stuck behind a claim nobody will spend.
        let admission = match self.admit_dispatch(&claim, &params.option_id) {
            Ok(admission) => admission,
            Err(error) => {
                let _ = self.release_claim(&claim, now);
                return Err(error);
            }
        };
        // An answer that went and was not confirmed is not released: it is the caller's to settle
        // as resolved or uncertain, and `resolve` refusing here leaves the marker in place.
        let resolved = self.resolve(&claim, now)?;
        Ok((
            AgentApprovalRespondResult {
                mutation: AgentMutationResult {
                    provenance: admission.provenance,
                    upstream_request_id: Nullable::some(admission.upstream_request_id.clone()),
                    ..mutation
                },
                resource_id: params.resource_id,
                state: resolved.state,
            },
            admission,
        ))
    }

    /// Applies `plugin.action.invoke`.
    ///
    /// Section 23's row names four things this validates before anything runs: the registered
    /// action, the actor's grant, the effect class and the input, draft and request preconditions.
    /// The action token that comes out is the authority for the one invocation that follows.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for an action the package did not register,
    /// [`BrokerError::Grant`] when the binding does not hold the grant the action declares,
    /// [`BrokerError::InvalidArgument`] for an effect class that disagrees with the call, and
    /// [`BrokerError::PreconditionFailed`] when a draft the action needs was not named.
    pub fn plugin_action_invoke(
        &self,
        caller: &Caller,
        binding_id: BrokerBindingId,
        params: &PluginActionInvokeParams,
        now: TimestampMs,
    ) -> Result<PluginActionInvokeResult> {
        let registered = self
            .registered_action(binding_id, &params.action)?
            .ok_or_else(|| {
                BrokerError::unknown(format!(
                    "{} is not an action {} registered",
                    params.action, params.plugin_id
                ))
            })?;
        if registered.effect != EffectClass::Write {
            return Err(BrokerError::invalid(format!(
                "{} is a read, and this is the write path",
                params.action
            )));
        }
        if registered.needs_draft && !params.draft_id.is_present() {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("{} acts on a draft and this call named none", params.action),
            });
        }
        let invocation = Invocation {
            actor_id: caller.actor_id.clone(),
            grant: registered.grant,
            grant_id: caller.grant_id,
            application_instance_id: params.target.subject.application_instance_id,
            binding_revision: params.target.binding_revision,
            action: params.action.clone(),
            capability: registered
                .capability
                .clone()
                .map(|capability| (capability, None)),
            parameters: params.parameters.as_slice().to_vec(),
        };
        let token = self.issue_token(binding_id, &invocation, now)?;
        // The token is the authority for the one invocation that follows, and it is spent by the
        // effect plan that comes back. Nothing between here and there widens it.
        let spent = self.spend_token(&kr_protocol::broker::ActionTokenClaim::from(&token))?;
        Ok(PluginActionInvokeResult {
            mutation: AgentMutationResult {
                binding_revision: spent.binding_revision,
                provenance: ActionProvenance::UpstreamTypedRpc,
                upstream_request_id: Nullable::null(),
                turn_id: Nullable::null(),
            },
            action: spent.action,
        })
    }

    /// Checks everything an agent mutation depends on, and returns what it did.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::StaleBinding`] when the revision has moved,
    /// [`BrokerError::PreconditionFailed`] when rich mutations are suspended, and
    /// [`BrokerError::UnsupportedCapability`] when the capability is not usable here.
    pub fn check_mutation(
        &self,
        caller: &Caller,
        target: &AgentMutationTarget,
        capability: &str,
        action: &str,
    ) -> Result<AgentMutationResult> {
        let _ = caller;
        self.check_subject(&target.subject)?;
        let binding = self.binding_state(target.subject.application_instance_id)?;
        if binding.rich_mutations_suspended {
            return Err(BrokerError::PreconditionFailed {
                detail: binding.suspension_reason.as_ref().map_or_else(
                    || "rich mutations are suspended".to_owned(),
                    |reason| format!("rich mutations are suspended: {reason}"),
                ),
            });
        }
        if binding.binding_revision != target.binding_revision {
            return Err(BrokerError::StaleBinding {
                detail: format!(
                    "{action} was prepared at binding revision {} and the binding is at {}",
                    target.binding_revision, binding.binding_revision
                ),
            });
        }
        let capability_id = CapabilityId::new(capability)
            .map_err(|error| BrokerError::invalid(format!("capability name: {error}")))?;
        self.recheck_capability(
            target.subject.application_instance_id,
            &capability_id,
            None::<CapabilityRevision>,
        )?;
        Ok(AgentMutationResult {
            binding_revision: binding.binding_revision,
            provenance: ActionProvenance::UpstreamTypedRpc,
            upstream_request_id: Nullable::null(),
            turn_id: Nullable::null(),
        })
    }

    /// Checks that a read names an instance this worker serves, in the session it says.
    fn check_subject(&self, subject: &AgentSubject) -> Result<()> {
        if self.serves_session(subject.session_id) {
            Ok(())
        } else {
            Err(BrokerError::unknown(format!(
                "this worker does not serve session {}",
                subject.session_id
            )))
        }
    }
}

/// Builds one command an agent advertises.
#[must_use]
pub fn command(name: &str, summary: &str, parameter_encoding: &str) -> AgentCommand {
    AgentCommand {
        name: name.to_owned(),
        summary: summary.to_owned(),
        parameter_encoding: parameter_encoding.to_owned(),
    }
}

/// The instance one subject names.
#[must_use]
pub const fn subject(
    session_id: SessionId,
    application_instance_id: ApplicationInstanceId,
) -> AgentSubject {
    AgentSubject {
        session_id,
        application_instance_id,
    }
}
