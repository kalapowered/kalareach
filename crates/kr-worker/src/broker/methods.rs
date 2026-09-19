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
use kr_protocol::broker::{ActionName, ActionProvenance, ActionToken, BrokerGrant};
use kr_protocol::gateway::PendingState;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId, CapabilityId, GrantId,
    SessionId, StreamCursor,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::broker::arbitration::Claim;
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
    /// What the operation is, with everything the connector needs to encode it.
    pub body: UpstreamBody,
}

/// What one prepared operation actually asks for.
///
/// It is a union rather than bytes because the connector encodes it, and a connector cannot encode
/// what it was not told: an approval needs the request it answers and the decision chosen, and a
/// plugin action needs the package, the action and the draft it acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamBody {
    /// A prompt, by the draft it lives in or the text it carries.
    Prompt {
        /// The draft, when the prompt is one.
        draft_id: Option<kr_protocol::ids::DraftId>,
        /// The text, when the prompt travels inline.
        text: Option<String>,
    },
    /// Steering text for the turn the request names.
    Steer {
        /// What to steer with.
        text: String,
    },
    /// A cancellation of the turn the request names.
    Cancel,
    /// An answer to one pending approval.
    Approval {
        /// The resource being answered.
        resource_id: kr_protocol::ids::PendingResourceId,
        /// The upstream's own identifier for the request.
        upstream_request_id: kr_protocol::ids::UpstreamRequestId,
        /// The method the original request named.
        method: kr_protocol::ids::UpstreamMethod,
        /// The decision, one of the ones the request offered.
        option_id: String,
        /// The answer the core prepared from the connection's own qualified table.
        ///
        /// It names the connection the answer goes out on, so a connector cannot answer a
        /// resource other than the one that was admitted.
        response: crate::broker::gateway::PreparedResponse,
    },
    /// A registered plugin action.
    PluginAction {
        /// The package whose action it is.
        plugin_id: kr_protocol::ids::PluginId,
        /// The action.
        action: ActionName,
        /// The draft it acts on, where it acts on one.
        draft_id: Option<kr_protocol::ids::DraftId>,
        /// The action's own parameters, canonically encoded.
        parameters: Vec<u8>,
        /// The action token this invocation runs under.
        ///
        /// Section 11 binds it to the actor, the grant, the revision, the action and the parameter
        /// hash, and the component that prepares the effect receives it: an effect plan may use
        /// only what this invocation permits.
        token: Option<ActionToken>,
    },
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

/// Which component is answerable for one mutation reaching its upstream.
///
/// A fault disables the rich capabilities of the binding it happened to, and section 11 keeps
/// native traffic out of it. What that means for a mutation is decided here: the mutation is
/// checked against *its own* provider rather than against the instance's bindings as a set, so an
/// unrelated component that is still working cannot admit one through a component that is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Responsible {
    /// The instance's own transport carries it and no component gives it its meaning.
    ///
    /// A prompt, a steer and a cancellation are this: they are encoded by the connector that owns
    /// the connection, not by a component the broker holds a binding for.
    Transport,
    /// One component: the decoder that interpreted an approval, or the package whose action runs.
    Binding(BrokerBindingId),
}

/// Permission to carry one agent mutation to its upstream, and everything it was admitted against.
///
/// Only [`Broker::admit_mutation`] and its two siblings make one, under the broker's own lock, in
/// one operation with the checks. A caller holding one is therefore a caller whose complete
/// invocation was valid against the state the broker had at a single moment: a fence, a
/// suspension, a turn change or a capability invalidation cannot land between the check and the
/// transmission, because there is nothing between them.
///
/// It carries the transport rather than naming it, so the submission does not have to go back to
/// the broker to find one, which is what lets a caller release its own locks before it transmits.
#[derive(Debug)]
pub struct MutationAdmission {
    request: UpstreamRequest,
    dispatch: std::sync::Arc<dyn UpstreamDispatch>,
    responsible: Responsible,
    capability: Option<CapabilityId>,
    admitted_at: TimestampMs,
    provenance: ActionProvenance,
    approval: Option<(Claim, DispatchAdmission)>,
    token: Option<ActionToken>,
    /// True once the effect this admission carries has been validated against its invocation.
    effect_validated: bool,
    /// Spent when the operation is transmitted, so one admission carries one transmission.
    spent: std::sync::atomic::AtomicBool,
}

impl MutationAdmission {
    pub(crate) const fn new(
        request: UpstreamRequest,
        dispatch: std::sync::Arc<dyn UpstreamDispatch>,
        responsible: Responsible,
        capability: Option<CapabilityId>,
        admitted_at: TimestampMs,
    ) -> Self {
        Self {
            request,
            dispatch,
            responsible,
            capability,
            admitted_at,
            provenance: ActionProvenance::UpstreamTypedRpc,
            approval: None,
            token: None,
            effect_validated: false,
            spent: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn with_body(mut self, body: UpstreamBody) -> Self {
        self.request.body = body;
        self
    }

    pub(crate) fn with_approval(mut self, claim: Claim, admission: DispatchAdmission) -> Self {
        self.provenance = admission.provenance;
        self.approval = Some((claim, admission));
        self
    }

    pub(crate) fn with_action_token(mut self, token: ActionToken) -> Self {
        // The token reaches the component that prepares the effect, so it travels with the body
        // the connector encodes rather than beside it.
        if let UpstreamBody::PluginAction { token: carried, .. } = &mut self.request.body {
            *carried = Some(token.clone());
        }
        self.token = Some(token);
        self
    }

    pub(crate) fn claim(&self) -> Option<&Claim> {
        self.approval.as_ref().map(|(claim, _)| claim)
    }

    /// Returns the prepared operation, as it will reach the upstream.
    #[must_use]
    pub const fn request(&self) -> &UpstreamRequest {
        &self.request
    }

    /// Returns the instance this mutation acts on.
    #[must_use]
    pub const fn application_instance_id(&self) -> ApplicationInstanceId {
        self.request.application_instance_id
    }

    /// Returns the binding revision it was admitted at.
    #[must_use]
    pub const fn binding_revision(&self) -> AgentBindingRevision {
        self.request.binding_revision
    }

    /// Returns which component is answerable for it.
    #[must_use]
    pub const fn responsible(&self) -> Responsible {
        self.responsible
    }

    /// Returns the capability it was rechecked against, where it names one.
    #[must_use]
    pub const fn capability(&self) -> Option<&CapabilityId> {
        self.capability.as_ref()
    }

    /// Returns the host time the admission was taken at.
    #[must_use]
    pub const fn admitted_at(&self) -> TimestampMs {
        self.admitted_at
    }

    /// Returns how the answer will be recorded as having reached the upstream.
    #[must_use]
    pub const fn provenance(&self) -> ActionProvenance {
        self.provenance
    }

    /// Returns the dispatch admission of the approval this carries, when it carries one.
    #[must_use]
    pub fn approval(&self) -> Option<&DispatchAdmission> {
        self.approval.as_ref().map(|(_, admission)| admission)
    }

    /// Returns the action token this invocation was admitted under, when it has one.
    #[must_use]
    pub const fn token(&self) -> Option<&ActionToken> {
        self.token.as_ref()
    }

    /// Carries the operation to the upstream and returns what it answered.
    ///
    /// Nothing is held while this runs. That is the point of separating admission from
    /// transmission: the caller has already committed everything a crash would need, so the
    /// transport work happens with no lock of the broker's or the session's held.
    ///
    /// # Errors
    ///
    /// Returns whatever the transport refuses.
    pub fn submit(&self) -> Result<UpstreamOutcome> {
        // One admission, one transmission. A caller that submitted and then submitted again would
        // send one operation twice, and the second send would discover the resolved state only
        // after its bytes had gone.
        if self.spent.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(BrokerError::invalid(
                "this admission has already been transmitted, and one admission carries one \
                 operation",
            ));
        }
        self.dispatch.submit(&self.request)
    }

    /// Returns true when the effect this admission carries has been validated.
    #[must_use]
    pub const fn effect_validated(&self) -> bool {
        self.effect_validated
    }

    /// Returns true when this invocation is one a component prepares an effect for.
    #[must_use]
    pub const fn prepares_an_effect(&self) -> bool {
        self.token.is_some()
    }

    pub(crate) const fn mark_effect_validated(&mut self) {
        self.effect_validated = true;
    }
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
    /// The operation the manifest declares this action performs.
    ///
    /// An effect plan is compared with it, so a component cannot prepare one operation under an
    /// action declared for another.
    pub operation: kr_protocol::broker::PreparedOperation,
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
        // `from_node` names the first node the reader wants, which is what a continuation
        // carries. `replay` starts *after* the cursor it is given, so the cursor is one before.
        let from = params
            .from_node
            .as_ref()
            .and_then(|node| node.get().checked_sub(1))
            .map(StreamCursor::new);
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

    /// Admits one agent mutation, under the broker's own lock, in one operation.
    ///
    /// This is the gate every mutation passes: the session, the fence, the instance, its
    /// suspension, the binding revision, the turn, the component answerable for the dispatch, the
    /// capability and the transport, all against the state at one moment. What comes back is the
    /// authority to transmit, and it is the only thing that is.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for a session or instance this worker does not
    /// serve, [`BrokerError::UpstreamUnavailable`] while rich work is fenced,
    /// [`BrokerError::UnsupportedCapability`] when nothing carries the operation or the component
    /// answerable for it is disabled, [`BrokerError::StaleBinding`] when the revision has moved,
    /// and [`BrokerError::PreconditionFailed`] when rich mutations are suspended or the turn named
    /// is not the one running.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_mutation(
        &self,
        caller: &Caller,
        target: &AgentMutationTarget,
        capability: &str,
        operation: UpstreamOperation,
        turn_id: Option<kr_protocol::ids::AgentTurnId>,
        body: UpstreamBody,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        let _ = caller;
        let capability_id = CapabilityId::new(capability)
            .map_err(|error| BrokerError::invalid(format!("capability name: {error}")))?;
        self.state().admit_mutation_in(
            target,
            Some(capability_id),
            operation,
            turn_id,
            Responsible::Transport,
            body,
            now,
        )
    }

    /// Admits `agent.prompt.submit` or `agent.prompt.queue`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the call names neither a draft nor text, or
    /// both, and whatever [`Broker::admit_mutation`] refuses.
    pub fn admit_prompt(
        &self,
        caller: &Caller,
        params: &AgentPromptParams,
        queued: bool,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        params.validate().map_err(BrokerError::invalid)?;
        let (capability, operation) = if queued {
            ("agent.prompt.queue", UpstreamOperation::PromptQueue)
        } else {
            ("agent.prompt", UpstreamOperation::PromptSubmit)
        };
        self.admit_mutation(
            caller,
            &params.target,
            capability,
            operation,
            None,
            UpstreamBody::Prompt {
                draft_id: params.draft_id.as_ref().copied(),
                text: params.text.as_ref().map(|text| text.as_str().to_owned()),
            },
            now,
        )
    }

    /// Admits `agent.turn.steer`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_mutation`] refuses.
    pub fn admit_steer(
        &self,
        caller: &Caller,
        params: &AgentSteerParams,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        self.admit_mutation(
            caller,
            &params.target,
            "agent.steer",
            UpstreamOperation::TurnSteer,
            Some(params.turn_id.clone()),
            UpstreamBody::Steer {
                text: params.text.as_str().to_owned(),
            },
            now,
        )
    }

    /// Admits `agent.turn.cancel`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_mutation`] refuses.
    pub fn admit_cancel(
        &self,
        caller: &Caller,
        params: &AgentCancelParams,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        self.admit_mutation(
            caller,
            &params.target,
            "agent.cancel",
            UpstreamOperation::TurnCancel,
            Some(params.turn_id.clone()),
            UpstreamBody::Cancel,
            now,
        )
    }

    /// Applies `agent.prompt.submit` or `agent.prompt.queue`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_prompt`] and the transport refuse.
    pub fn agent_prompt(
        &self,
        caller: &Caller,
        params: &AgentPromptParams,
        queued: bool,
        now: TimestampMs,
    ) -> Result<AgentMutationResult> {
        let admitted = self.admit_prompt(caller, params, queued, now)?;
        self.dispatch_mutation(&admitted, now)
    }

    /// Applies `agent.turn.steer`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_steer`] and the transport refuse.
    pub fn agent_steer(
        &self,
        caller: &Caller,
        params: &AgentSteerParams,
        now: TimestampMs,
    ) -> Result<AgentMutationResult> {
        let admitted = self.admit_steer(caller, params, now)?;
        self.dispatch_mutation(&admitted, now)
    }

    /// Applies `agent.turn.cancel`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_cancel`] and the transport refuse.
    pub fn agent_cancel(
        &self,
        caller: &Caller,
        params: &AgentCancelParams,
        now: TimestampMs,
    ) -> Result<AgentMutationResult> {
        let admitted = self.admit_cancel(caller, params, now)?;
        self.dispatch_mutation(&admitted, now)
    }

    /// Admits `agent.approval.respond`: the mutation, the resource, the claim and the marker, in
    /// one operation under the broker's lock.
    ///
    /// This is the encode, recheck, claim and dispatch transaction as a method sees it, and the
    /// whole of it happens here so that nothing the checks read can move before the marker. The
    /// admission carries the answer the core prepared from the connection's own table, so the
    /// bytes that go are the bytes that were admitted.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_mutation`] refuses, [`BrokerError::UnknownSubject`] when
    /// the resource is not one this broker holds, [`BrokerError::PermissionDenied`] when it
    /// belongs to another instance or its decoder may no longer answer,
    /// [`BrokerError::Arbitration`] when it has already been answered, and
    /// [`BrokerError::PreconditionFailed`] when the deadline has passed or the decision is not one
    /// the request offered.
    pub fn admit_approval(
        &self,
        caller: &Caller,
        params: &AgentApprovalRespondParams,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        let _ = caller;
        let mut state = self.state();
        let resource = state.pending_resource(params.resource_id)?.resource.clone();
        if resource.application_instance_id != params.target.subject.application_instance_id {
            return Err(BrokerError::denied(format!(
                "{} belongs to another application instance",
                params.resource_id
            )));
        }
        // One resolution per pending resource. A resource that has already reached an answer, been
        // cancelled or been left uncertain is not answerable again, and saying so here is what
        // keeps the claim from being the thing that discovers it.
        if resource.state != PendingState::Pending {
            return Err(BrokerError::Arbitration(
                kr_protocol::gateway::ArbitrationError::AlreadyResolved {
                    state: resource.state,
                },
            ));
        }
        if let Some(deadline) = resource.deadline_ms.as_ref()
            && deadline.get() <= now.get()
        {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{}'s upstream deadline passed at {}, so this answer would reach nothing",
                    params.resource_id,
                    deadline.get()
                ),
            });
        }
        // The component answerable for an approval is the decoder that interpreted it: it is the
        // one whose meaning the answer carries, and a fault in it disables this dispatch whatever
        // else is bound to the instance.
        let responsible = state
            .decoder_of(params.resource_id)
            .map_or(Responsible::Transport, Responsible::Binding);
        let capability_id = CapabilityId::new("agent.approval")
            .map_err(|error| BrokerError::invalid(format!("capability name: {error}")))?;
        let admitted = state.admit_mutation_in(
            &params.target,
            Some(capability_id),
            UpstreamOperation::ApprovalRespond,
            None,
            responsible,
            UpstreamBody::Cancel,
            now,
        )?;
        let claim = state.claim_in(params.resource_id, &caller.actor_id, now)?;
        // From here the claim is held, so anything that fails before the marker gives it back
        // rather than leaving the resource stuck behind a claim nobody will spend.
        let dispatch = match state.admit_dispatch_in(&claim, &params.option_id) {
            Ok(dispatch) => dispatch,
            Err(error) => {
                let _ = state.release_claim_in(&claim, now);
                return Err(error);
            }
        };
        let body = UpstreamBody::Approval {
            resource_id: params.resource_id,
            upstream_request_id: dispatch.upstream_request_id.clone(),
            method: dispatch.method.clone(),
            option_id: params.option_id.clone(),
            response: dispatch.response.clone(),
        };
        Ok(admitted.with_body(body).with_approval(claim, dispatch))
    }

    /// Applies `agent.approval.respond`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_approval`] and the transport refuse.
    pub fn agent_approval_respond(
        &self,
        caller: &Caller,
        params: &AgentApprovalRespondParams,
        now: TimestampMs,
    ) -> Result<(AgentApprovalRespondResult, MutationAdmission)> {
        let admitted = self.admit_approval(caller, params, now)?;
        let result = self.record_approval(&admitted, now)?;
        Ok((result, admitted))
    }

    /// Carries an admitted approval to its upstream and records the outcome.
    ///
    /// # Errors
    ///
    /// Returns whatever the transport refuses, after leaving the resource uncertain: the marker is
    /// committed, so asking again could apply the answer twice.
    pub fn record_approval(
        &self,
        admitted: &MutationAdmission,
        now: TimestampMs,
    ) -> Result<AgentApprovalRespondResult> {
        let dispatch = admitted.approval().ok_or_else(|| {
            BrokerError::invalid("this admission does not carry an approval to answer")
        })?;
        let claim = admitted
            .claim()
            .ok_or_else(|| BrokerError::invalid("this admission holds no claim"))?;
        let outcome = match admitted.submit() {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = self.uncertain(claim, now);
                return Err(error);
            }
        };
        let resolved = self.resolve(claim, now)?;
        Ok(AgentApprovalRespondResult {
            mutation: AgentMutationResult {
                binding_revision: admitted.binding_revision(),
                provenance: outcome.provenance,
                upstream_request_id: Nullable::some(dispatch.upstream_request_id.clone()),
                turn_id: Nullable::from(outcome.turn_id),
            },
            resource_id: dispatch.resource.resource_id,
            state: resolved.state,
        })
    }

    /// Admits `plugin.action.invoke`: the action, the authority, the token and the transport, in
    /// one operation under the broker's lock.
    ///
    /// Section 23's row names four things this validates before anything runs: the registered
    /// action, the actor's grant, the effect class and the input, draft and request preconditions.
    /// The action token that comes out is the authority for the one invocation that follows, and
    /// it is issued and spent here so that the recheck it performs reads the same state the rest
    /// of the admission did.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for an action the package did not register,
    /// [`BrokerError::Grant`] when the binding does not hold the grant the action declares,
    /// [`BrokerError::InvalidArgument`] for an effect class that disagrees with the call, and
    /// [`BrokerError::PreconditionFailed`] when a draft the action needs was not named.
    pub fn admit_plugin_action(
        &self,
        caller: &Caller,
        binding_id: BrokerBindingId,
        params: &PluginActionInvokeParams,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        let registered = self.check_action(binding_id, params)?;
        let invocation = Self::invocation_for(caller, &registered, params);
        let mut state = self.state();
        let admitted = state.admit_mutation_in(
            &params.target,
            registered.capability.clone(),
            UpstreamOperation::PluginAction,
            None,
            Responsible::Binding(binding_id),
            UpstreamBody::PluginAction {
                plugin_id: params.plugin_id.clone(),
                action: params.action.clone(),
                draft_id: params.draft_id.as_ref().copied(),
                parameters: params.parameters.as_slice().to_vec(),
                token: None,
            },
            now,
        )?;
        let token = state.issue_token_in(binding_id, &invocation, now)?;
        // The token is spent here, before the effect: spending is what rechecks the binding, the
        // grant, the revision and the capability against the present, and doing it afterwards
        // would refuse an action that had already happened. Spending it under the same lock the
        // rest of the admission took is what leaves no window between the two.
        let spent = state.spend_token_in(&kr_protocol::broker::ActionTokenClaim::from(&token))?;
        Ok(admitted.with_action_token(spent))
    }

    /// Applies `plugin.action.invoke`.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_plugin_action`] and the transport refuse.
    pub fn plugin_action_invoke(
        &self,
        caller: &Caller,
        binding_id: BrokerBindingId,
        params: &PluginActionInvokeParams,
        effect: &kr_protocol::broker::PreparedEffect,
        now: TimestampMs,
    ) -> Result<PluginActionInvokeResult> {
        let mut admitted = self.admit_plugin_action(caller, binding_id, params, now)?;
        self.validate_effect(&mut admitted, effect)?;
        self.record_plugin_action(&admitted, now)
    }

    /// Carries an admitted plugin action to its upstream and records the outcome.
    ///
    /// # Errors
    ///
    /// Returns whatever the transport refuses.
    pub fn record_plugin_action(
        &self,
        admitted: &MutationAdmission,
        now: TimestampMs,
    ) -> Result<PluginActionInvokeResult> {
        let _ = now;
        // An invocation that prepared an effect transmits the effect this broker validated, and
        // nothing else. An admission whose component returned a plan that was never checked is
        // one this host will not spend.
        if admitted.prepares_an_effect() && !admitted.effect_validated() {
            return Err(BrokerError::PreconditionFailed {
                detail: "this invocation's prepared effect has not been validated against the \
                         invocation it was prepared under"
                    .to_owned(),
            });
        }
        let token = admitted
            .token()
            .ok_or_else(|| BrokerError::invalid("this admission carries no action token"))?
            .clone();
        let outcome = admitted.submit()?;
        Ok(PluginActionInvokeResult {
            mutation: AgentMutationResult {
                binding_revision: token.binding_revision,
                provenance: outcome.provenance,
                upstream_request_id: Nullable::from(outcome.upstream_request_id),
                turn_id: Nullable::from(outcome.turn_id),
            },
            action: token.action,
        })
    }

    /// Checks everything one agent mutation would be refused for, without admitting it.
    ///
    /// Section 9 makes a refusal this host can decide a rejection rather than an outcome nobody
    /// can establish, so the service asks this before it writes a dispatch marker. It asks exactly
    /// what the admission asks, by taking one and letting it go: a check that drifts from the
    /// admission it stands for is worse than no check at all.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_mutation`] refuses.
    pub fn check_mutation(
        &self,
        caller: &Caller,
        target: &AgentMutationTarget,
        capability: &str,
        action: UpstreamOperation,
        turn_id: Option<kr_protocol::ids::AgentTurnId>,
        now: TimestampMs,
    ) -> Result<()> {
        self.admit_mutation(
            caller,
            target,
            capability,
            action,
            turn_id,
            UpstreamBody::Cancel,
            now,
        )
        .map(|_| ())
    }

    /// Checks what every rich operation on one instance needs, whatever the operation is.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for an instance this broker does not hold,
    /// [`BrokerError::UpstreamUnavailable`] while the journal is fenced, and
    /// [`BrokerError::UnsupportedCapability`] when no transport is bound or every component's
    /// rich capabilities are disabled.
    pub fn check_dispatchable(&self, target: &AgentMutationTarget) -> Result<()> {
        self.state()
            .admit_mutation_in(
                target,
                None,
                UpstreamOperation::PluginAction,
                None,
                Responsible::Transport,
                UpstreamBody::Cancel,
                TimestampMs::new(0),
            )
            .map(|_| ())
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
    /// Everything this checks is checked before the receipt marker is written, so a refusal the
    /// host can make deterministically is a rejection rather than an outcome nobody can
    /// establish. It checks the resource's owner, that it is still open, that the upstream's own
    /// deadline has not passed, everything the claim itself rechecks, and that the decision is one
    /// the recorded interpretation actually offered.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the resource is not one this broker holds,
    /// [`BrokerError::PermissionDenied`] when it belongs to another instance or its decoder may no
    /// longer answer, [`BrokerError::Arbitration`] when it has already been answered,
    /// [`BrokerError::StaleBinding`] when the source generation has moved, and
    /// [`BrokerError::PreconditionFailed`] when the deadline has passed, rich work is suspended or
    /// the decision is not one the request offered.
    pub fn check_answerable(
        &self,
        target: &AgentMutationTarget,
        resource_id: kr_protocol::ids::PendingResourceId,
        option_id: &str,
        now: TimestampMs,
    ) -> Result<()> {
        let resource = self
            .pending(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        if resource.application_instance_id != target.subject.application_instance_id {
            return Err(BrokerError::denied(format!(
                "{resource_id} belongs to another application instance"
            )));
        }
        // One resolution per pending resource. A resource that has already reached an answer,
        // been cancelled or been left uncertain is not answerable again, and saying so here is
        // what keeps the claim below from being the thing that discovers it.
        if resource.state != PendingState::Pending {
            return Err(BrokerError::Arbitration(
                kr_protocol::gateway::ArbitrationError::AlreadyResolved {
                    state: resource.state,
                },
            ));
        }
        // The same bound the claim uses: at the deadline the answer is already too late, so an
        // answer admitted here would be refused a moment later, after the marker.
        if let Some(deadline) = resource.deadline_ms.as_ref()
            && deadline.get() <= now.get()
        {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{resource_id}'s upstream deadline passed at {}, so this answer would reach \
                     nothing",
                    deadline.get()
                ),
            });
        }
        let entry = self
            .decoding(resource_id)?
            .ok_or_else(|| BrokerError::PreconditionFailed {
                detail: format!(
                    "{resource_id} has no recorded interpretation, so there is nothing to answer"
                ),
            })?;
        // The rest is exactly what the claim rechecks: the instance's rich work is not suspended,
        // the request's generation is still the instance's own, and the decoder that interpreted
        // it may still encode the answer. Sharing that check is what keeps this from admitting
        // something the claim would refuse a moment later, after the marker.
        self.state().recheck_answerable(resource_id)?;
        if entry.offers(option_id) {
            Ok(())
        } else {
            Err(BrokerError::PreconditionFailed {
                detail: format!("{option_id} is not one of the decisions this request offered"),
            })
        }
    }

    /// Checks everything a plugin action call can be refused for before anything is marked.
    ///
    /// This is the same work `plugin.action.invoke` does up to the point of issuing the token: the
    /// registered action, the instance's fence and transport, and the invocation's own authority,
    /// which is the grant, the binding revision and the capability. Running it first is what keeps
    /// a withdrawn grant from being discovered after the receipt marker.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::check_action`] and [`Broker::check_dispatchable`] return, and
    /// [`BrokerError::Grant`], [`BrokerError::StaleBinding`] or
    /// [`BrokerError::UnsupportedCapability`] when the invocation's own authority does not hold.
    pub fn check_invocable(
        &self,
        caller: &Caller,
        binding_id: BrokerBindingId,
        params: &PluginActionInvokeParams,
        now: TimestampMs,
    ) -> Result<()> {
        let registered = self.check_action(binding_id, params)?;
        let invocation = Self::invocation_for(caller, &registered, params);
        let mut state = self.state();
        state.admit_mutation_in(
            &params.target,
            registered.capability.clone(),
            UpstreamOperation::PluginAction,
            None,
            Responsible::Binding(binding_id),
            UpstreamBody::Cancel,
            now,
        )?;
        state.check_invocation(binding_id, &invocation)?;
        // And there has to be a token to issue. A full table refuses every invocation whatever
        // the caller does, so it is refused here rather than after the marker.
        state.tokens.check_capacity()?;
        Ok(())
    }

    fn invocation_for(
        caller: &Caller,
        registered: &RegisteredAction,
        params: &PluginActionInvokeParams,
    ) -> Invocation {
        Invocation {
            actor_id: caller.actor_id.clone(),
            grant: registered.grant,
            grant_id: caller.grant_id,
            application_instance_id: params.target.subject.application_instance_id,
            binding_revision: params.target.binding_revision,
            action: params.action.clone(),
            draft_id: params.draft_id.as_ref().copied(),
            capability: registered
                .capability
                .clone()
                .map(|capability| (capability, None)),
            parameters: params.parameters.as_slice().to_vec(),
        }
    }

    /// Validates the effect one component prepared against the token it prepared it under.
    ///
    /// Section 11: "Its effect plan can use only resources and operations permitted by that
    /// invocation." Four things are compared, and each of them is a way a component could ask for
    /// something it was not invited to do: the action, the operation's own grant, the effect class
    /// the action declared, and the draft the invocation named.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Token`] when the plan is not the invocation's,
    /// [`BrokerError::Grant`] when the binding does not hold the grant the operation needs,
    /// [`BrokerError::InvalidArgument`] when the declared class disagrees with the operation, and
    /// [`BrokerError::PreconditionFailed`] when the draft the plan acts on is not the one the
    /// invocation named or is one this host cannot resolve.
    pub fn validate_effect(
        &self,
        admitted: &mut MutationAdmission,
        effect: &kr_protocol::broker::PreparedEffect,
    ) -> Result<()> {
        let token = admitted
            .token()
            .ok_or_else(|| BrokerError::invalid("this admission carries no action token"))?;
        if effect.action != token.action {
            return Err(BrokerError::Token(
                kr_protocol::broker::TokenError::Mismatch { field: "action" },
            ));
        }
        let binding_id = match admitted.responsible() {
            Responsible::Binding(binding_id) => binding_id,
            Responsible::Transport => {
                return Err(BrokerError::invalid(
                    "an effect plan belongs to a component invocation and this admission names \
                     none",
                ));
            }
        };
        // The operation the manifest declared. A plan that asks for something else is asking
        // under an invocation that was admitted for something else.
        let registered = self
            .registered_action(binding_id, &token.action)?
            .ok_or_else(|| {
                BrokerError::unknown(format!("{} is no longer a registered action", token.action))
            })?;
        if registered.operation != effect.operation {
            return Err(BrokerError::invalid(format!(
                "{} is declared as {} and this plan prepares {}",
                token.action, registered.operation, effect.operation
            )));
        }
        // The operation's own grant, checked against the binding as it stands rather than against
        // the grant the token was issued under: a grant withdrawn while the component was working
        // is not a grant. An operation no plugin grant covers is refused outright.
        let needed = effect.operation.grant().ok_or_else(|| {
            BrokerError::denied(format!(
                "{} is not something a component grant carries, so no effect plan may ask for it",
                effect.operation
            ))
        })?;
        let grants = self.grants(binding_id)?;
        grants.require(needed)?;
        // A read cannot arrive on the write path, and an operation that changes the upstream is
        // not a read whatever the plan calls it.
        if effect.class != EffectClass::Write || !effect.operation.writes() {
            return Err(BrokerError::invalid(format!(
                "{} changes the upstream and this plan declares it {:?}",
                effect.operation, effect.class
            )));
        }
        // And the draft. An operation that acts on one acts on the invocation's own, and a draft
        // this host cannot resolve is a precondition nobody has established rather than one to
        // assume.
        if registered.needs_draft {
            let named =
                effect
                    .draft_id
                    .as_ref()
                    .ok_or_else(|| BrokerError::PreconditionFailed {
                        detail: format!(
                            "{} acts on a draft and this plan named none",
                            effect.operation
                        ),
                    })?;
            if token.draft_id.as_ref() != Some(named) {
                return Err(BrokerError::PreconditionFailed {
                    detail: format!(
                        "this plan acts on draft {named} and the invocation named another"
                    ),
                });
            }
            self.resolve_draft(named)?;
        } else if effect.draft_id.is_present() && !effect.operation.may_act_on_a_draft() {
            return Err(BrokerError::invalid(format!(
                "{} acts on no draft and this plan named one",
                effect.operation
            )));
        }
        admitted.mark_effect_validated();
        Ok(())
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
        if registered.needs_draft {
            // A draft-dependent action names a draft *and* the draft is one this host can
            // resolve. Checking only that an identifier was given would send an operation against
            // a draft that may have moved or gone, which is the outcome nobody can establish that
            // section 9 refuses to produce.
            let draft_id =
                params
                    .draft_id
                    .as_ref()
                    .ok_or_else(|| BrokerError::PreconditionFailed {
                        detail: format!(
                            "{} acts on a draft and this call named none",
                            params.action
                        ),
                    })?;
            self.resolve_draft(draft_id)?;
        } else if params.draft_id.is_present() {
            return Err(BrokerError::invalid(format!(
                "{} acts on no draft and this call named one",
                params.action
            )));
        }
        Ok(registered)
    }

    /// Carries one admitted mutation to the upstream, and records what it answered.
    ///
    /// The argument is a [`MutationAdmission`], which only the broker makes. That is the whole
    /// change from a result the caller could have built: an admission is proof that the complete
    /// invocation was valid against the broker's state at one moment, and a result is a shape.
    ///
    /// # Errors
    ///
    /// Returns whatever the transport itself refuses.
    pub fn dispatch_mutation(
        &self,
        admitted: &MutationAdmission,
        now: TimestampMs,
    ) -> Result<AgentMutationResult> {
        let _ = now;
        let turn_id = admitted.request().turn_id.clone();
        let outcome = admitted.submit()?;
        Ok(AgentMutationResult {
            binding_revision: admitted.binding_revision(),
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
