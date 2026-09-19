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

/// What one agent mutation asks of the upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UpstreamOperation {
    /// Submit a prompt now.
    PromptSubmit,
    /// Queue a prompt behind the current turn.
    PromptQueue,
    /// Steer the turn that is running.
    TurnSteer,
    /// Cancel the turn that is running.
    TurnCancel,
    /// Answer a pending approval.
    ApprovalRespond,
    /// Invoke a registered plugin action.
    PluginAction,
}

impl UpstreamOperation {
    /// Returns the stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PromptSubmit => "prompt.submit",
            Self::PromptQueue => "prompt.queue",
            Self::TurnSteer => "turn.steer",
            Self::TurnCancel => "turn.cancel",
            Self::ApprovalRespond => "approval.respond",
            Self::PluginAction => "plugin.action",
        }
    }
}

impl core::fmt::Display for UpstreamOperation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One prepared operation, on its way to the upstream.
#[derive(Clone, Debug)]
pub struct UpstreamRequest {
    /// The instance it acts on.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision it was admitted at.
    pub binding_revision: kr_protocol::ids::AgentBindingRevision,
    /// What it asks for.
    pub operation: UpstreamOperation,
    /// The turn it acts on, where it acts on one.
    pub turn_id: Option<kr_protocol::ids::AgentTurnId>,
    /// The operation's own body, as the connector encodes it.
    pub payload: Vec<u8>,
}

/// What the upstream answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamOutcome {
    /// The upstream's own identifier for the operation, where it gave one.
    pub upstream_request_id: Option<kr_protocol::ids::UpstreamRequestId>,
    /// The turn it applies to, where the upstream named one.
    pub turn_id: Option<kr_protocol::ids::AgentTurnId>,
    /// How the operation actually reached the upstream.
    pub provenance: ActionProvenance,
}

/// What carries a prepared operation to one upstream.
///
/// The broker decides whether an operation may happen. This is what makes it happen, and it is a
/// seam because the thing that implements it is a connector's: section 12's bundled adapters are
/// the plugins repository's, and each one drives its own upstream over its own transport.
///
/// An instance with nothing bound here has no upstream this host can reach, and its mutations are
/// refused before the dispatch marker rather than reported as applied.
pub trait UpstreamDispatch: Send + Sync + core::fmt::Debug {
    /// Submits one prepared operation and returns what the upstream answered.
    ///
    /// # Errors
    ///
    /// Returns whatever the transport could not do. `UPSTREAM_UNAVAILABLE` is the answer when the
    /// framing connection cannot safely continue; section 11 forbids opening a second backend or
    /// replaying an unknown request instead.
    fn submit(&self, request: &UpstreamRequest) -> Result<UpstreamOutcome>;
}

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
    /// The grant record the actor's authority comes from, when one does.
    ///
    /// A local operating-system caller has none: its authority is the identity the listener
    /// authenticated, and section 23 leaves its grant null. Manufacturing one to fill the field
    /// would name a grant nothing issued.
    pub grant_id: Option<GrantId>,
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
        let operation = if queued {
            UpstreamOperation::PromptQueue
        } else {
            UpstreamOperation::PromptSubmit
        };
        let admitted = self.check_mutation(caller, &params.target, capability, operation)?;
        self.dispatch_mutation(&params.target, admitted, operation, None, Vec::new())
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
        self.check_turn(&params.target, &params.turn_id)?;
        let admitted = self.check_mutation(
            caller,
            &params.target,
            "agent.steer",
            UpstreamOperation::TurnSteer,
        )?;
        self.dispatch_mutation(
            &params.target,
            admitted,
            UpstreamOperation::TurnSteer,
            Some(params.turn_id.clone()),
            params.text.as_str().as_bytes().to_vec(),
        )
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
        self.check_turn(&params.target, &params.turn_id)?;
        let admitted = self.check_mutation(
            caller,
            &params.target,
            "agent.cancel",
            UpstreamOperation::TurnCancel,
        )?;
        self.dispatch_mutation(
            &params.target,
            admitted,
            UpstreamOperation::TurnCancel,
            Some(params.turn_id.clone()),
            Vec::new(),
        )
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
        let mutation = self.check_mutation(
            caller,
            &params.target,
            "agent.approval",
            UpstreamOperation::ApprovalRespond,
        )?;
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
        // Nothing carries the answer to this upstream: refuse before the claim, so the resource
        // is not held behind an answer that can never be sent.
        let dispatch = self
            .dispatch_for(params.target.subject.application_instance_id)
            .ok_or_else(|| BrokerError::UnsupportedCapability {
                detail: format!(
                    "nothing carries an answer to {}: this instance has no upstream transport \
                     bound, so the approval is refused rather than reported as answered",
                    params.target.subject.application_instance_id
                ),
            })?;

        let claim = self.claim(params.resource_id, &caller.actor_id, now)?;
        // From here the claim is held, so anything that fails before the marker gives it back
        // rather than leaving the resource stuck behind a claim nobody will spend.
        let admission = match self.admit_dispatch(&claim, &params.option_id) {
            Ok(admission) => admission,
            Err(error) => {
                let _ = self.release_claim(&claim, now);
                return Err(error);
            }
        };
        // The marker is committed. From here the answer may have gone, so a failure leaves the
        // resource uncertain rather than answerable: asking again could apply it twice.
        let outcome = match dispatch.submit(&UpstreamRequest {
            application_instance_id: params.target.subject.application_instance_id,
            binding_revision: mutation.binding_revision,
            operation: UpstreamOperation::ApprovalRespond,
            turn_id: None,
            payload: params.option_id.as_bytes().to_vec(),
        }) {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = self.uncertain(&claim, now);
                return Err(error);
            }
        };
        let resolved = self.resolve(&claim, now)?;
        Ok((
            AgentApprovalRespondResult {
                mutation: AgentMutationResult {
                    provenance: outcome.provenance,
                    upstream_request_id: Nullable::some(admission.upstream_request_id.clone()),
                    turn_id: Nullable::from(outcome.turn_id),
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
        let registered = self.check_action(binding_id, params)?;
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
        let dispatch = self
            .dispatch_for(params.target.subject.application_instance_id)
            .ok_or_else(|| BrokerError::UnsupportedCapability {
                detail: format!(
                    "nothing carries {} to {}: this instance has no upstream transport bound, so \
                     the action is refused rather than reported as applied",
                    params.action, params.target.subject.application_instance_id
                ),
            })?;
        let token = self.issue_token(binding_id, &invocation, now)?;
        // The token is the authority for the one invocation that follows. The invocation happens
        // here; the token is spent afterwards, which is the broker checking that the authority it
        // issued is still the authority the effect ran under.
        let outcome = dispatch.submit(&UpstreamRequest {
            application_instance_id: params.target.subject.application_instance_id,
            binding_revision: params.target.binding_revision,
            operation: UpstreamOperation::PluginAction,
            turn_id: None,
            payload: params.parameters.as_slice().to_vec(),
        })?;
        let spent = self.spend_token(&kr_protocol::broker::ActionTokenClaim::from(&token))?;
        Ok(PluginActionInvokeResult {
            mutation: AgentMutationResult {
                binding_revision: spent.binding_revision,
                provenance: outcome.provenance,
                upstream_request_id: Nullable::from(outcome.upstream_request_id),
                turn_id: Nullable::from(outcome.turn_id),
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
        action: UpstreamOperation,
    ) -> Result<AgentMutationResult> {
        let _ = caller;
        self.check_subject(&target.subject)?;
        // Rich work is fenced while the journal is faulted, and a mutation is rich work. Without
        // this a prompt submitted during the gap would be answered as applied with no durable
        // record of it at all.
        self.require_rich_work()?;
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

    /// Checks that the turn a mutation names is the one this instance is running.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when it is not. A turn that has ended is
    /// refused rather than redirected to whatever is running now.
    pub fn check_turn(
        &self,
        target: &AgentMutationTarget,
        turn_id: &kr_protocol::ids::AgentTurnId,
    ) -> Result<()> {
        let binding = self.binding_state(target.subject.application_instance_id)?;
        if binding.turn_id.as_ref() == Some(turn_id) {
            Ok(())
        } else {
            Err(BrokerError::PreconditionFailed {
                detail: format!("{turn_id} is not the turn this instance is running"),
            })
        }
    }

    /// Checks that one pending resource can be answered with the decision named.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the resource is not one this broker holds,
    /// [`BrokerError::PermissionDenied`] when it belongs to another instance, and
    /// [`BrokerError::PreconditionFailed`] when the decision is not one the request offered.
    pub fn check_answerable(
        &self,
        target: &AgentMutationTarget,
        resource_id: kr_protocol::ids::PendingResourceId,
        option_id: &str,
    ) -> Result<()> {
        let resource = self
            .pending(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        if resource.application_instance_id != target.subject.application_instance_id {
            return Err(BrokerError::denied(format!(
                "{resource_id} belongs to another application instance"
            )));
        }
        let entry = self
            .decoding(resource_id)?
            .ok_or_else(|| BrokerError::PreconditionFailed {
                detail: format!(
                    "{resource_id} has no recorded interpretation, so there is nothing to answer"
                ),
            })?;
        if entry.offers(option_id) {
            Ok(())
        } else {
            Err(BrokerError::PreconditionFailed {
                detail: format!("{option_id} is not one of the decisions this request offered"),
            })
        }
    }

    /// Checks everything a plugin action call declares, without running it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for an action the package did not register,
    /// [`BrokerError::InvalidArgument`] for an effect class that disagrees with the call, and
    /// [`BrokerError::PreconditionFailed`] when a draft the action needs was not named.
    pub fn check_action(
        &self,
        binding_id: BrokerBindingId,
        params: &PluginActionInvokeParams,
    ) -> Result<RegisteredAction> {
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
        Ok(registered)
    }

    /// Carries one admitted mutation to the upstream, and records what it answered.
    ///
    /// This is the half that happens: everything before it decided whether the operation may
    /// happen, and this is the only place in the broker that reaches an upstream at all. An
    /// instance with no transport bound has no upstream this host can reach, and the refusal says
    /// so rather than reporting the operation as applied.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] when nothing carries operations to this
    /// instance, and whatever the transport itself refuses.
    pub fn dispatch_mutation(
        &self,
        target: &AgentMutationTarget,
        admitted: AgentMutationResult,
        operation: UpstreamOperation,
        turn_id: Option<kr_protocol::ids::AgentTurnId>,
        payload: Vec<u8>,
    ) -> Result<AgentMutationResult> {
        let dispatch = self
            .dispatch_for(target.subject.application_instance_id)
            .ok_or_else(|| BrokerError::UnsupportedCapability {
                detail: format!(
                    "nothing carries a {operation} to {}: this instance has no upstream transport \
                     bound, so the operation is refused rather than reported as applied",
                    target.subject.application_instance_id
                ),
            })?;
        let outcome = dispatch.submit(&UpstreamRequest {
            application_instance_id: target.subject.application_instance_id,
            binding_revision: admitted.binding_revision,
            operation,
            turn_id: turn_id.clone(),
            payload,
        })?;
        Ok(AgentMutationResult {
            binding_revision: admitted.binding_revision,
            provenance: outcome.provenance,
            upstream_request_id: Nullable::from(outcome.upstream_request_id),
            turn_id: Nullable::from(outcome.turn_id.or(turn_id)),
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
