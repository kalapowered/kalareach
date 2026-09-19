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
use kr_protocol::gateway::{PendingState, RichOperation};
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

/// The broker's own mark on a prepared operation. Nothing outside the broker can make one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted(());

impl Admitted {
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

/// One prepared operation, on its way to the upstream.
#[derive(Clone, Debug)]
pub struct UpstreamRequest {
    /// Proof that the broker built this request.
    ///
    /// A prepared operation is what a transport is given to send. Only the broker's own admission
    /// makes one, so nothing outside it can assemble an operation and hand it to a transport as
    /// though this host had admitted it.
    #[allow(dead_code)]
    pub(crate) admitted: Admitted,
    /// The instance it acts on.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision it was admitted at.
    pub binding_revision: kr_protocol::ids::AgentBindingRevision,
    /// What it asks for.
    pub operation: RichOperation,
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
        /// The revision that draft stood at when the invocation was admitted.
        ///
        /// The identifier alone does not say what it denotes: a draft that moves afterwards keeps
        /// its identifier and changes its content. The revision the host checked travels with it,
        /// so the upstream acts on the draft this invocation was admitted against or on nothing.
        draft_revision: Option<kr_protocol::scalars::U64>,
        /// The action's own parameters, canonically encoded.
        parameters: Vec<u8>,
        /// The operation the validated plan prepares.
        ///
        /// It is absent until a plan has been validated against this invocation, and what is
        /// transmitted carries it, so the frame names the operation the host checked rather than
        /// only the action the caller asked for.
        operation: Option<kr_protocol::broker::PreparedOperation>,
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
    /// Answers whether this transport can carry one operation at all, before anything is marked.
    ///
    /// Section 9 makes a refusal this host can decide a rejection rather than an outcome nobody
    /// can establish, and "this upstream has no method for steering" is such a refusal. It is
    /// asked during admission, so an operation the connector cannot encode is refused before the
    /// dispatch marker rather than discovered when the bytes were due.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] for an operation this upstream's tables
    /// name no method for, or name one this build does not support.
    fn admit(&self, request: &UpstreamRequest) -> Result<()>;

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

/// The one transmission an admission authorises, and everything that authorises it.
///
/// It is private and it is consumed. A caller that takes it holds the only authority to transmit
/// this operation and, where the operation answers a pending resource, the only authority to
/// settle it. That is the difference a flag cannot make: a boolean says something was checked, and
/// this *is* the checked operation, with the bytes, the transport, the claim and the effect plan
/// that were admitted together.
#[derive(Debug)]
struct ExecutionPermit {
    /// The exact operation, with the arguments and resources it will execute.
    request: UpstreamRequest,
    /// What carries it, chosen when it was admitted.
    dispatch: std::sync::Arc<dyn UpstreamDispatch>,
    /// The claim that settles the resource this answer resolves, for the caller that transmits it.
    settlement: Option<Claim>,
    /// The approval it answers, as the broker admitted it.
    approval: Option<DispatchAdmission>,
    /// The token this invocation runs under.
    token: Option<ActionToken>,
    /// The draft this invocation was admitted against, as it stood then.
    draft: Option<crate::broker::DraftSnapshot>,
    /// The action declaration the admission checked, as it stood then.
    declared: Option<RegisteredAction>,
    /// The effect plan the component prepared, as validated against that token.
    ///
    /// A plugin action without one is not executable. The permit carries the plan rather than a
    /// flag saying one was seen, so what transmits is what was validated.
    plan: Option<kr_protocol::broker::PreparedEffect>,
}

/// Permission to carry one agent mutation to its upstream, and everything it was admitted against.
///
/// Only the broker's own admissions make one, under its own lock, in
/// one operation with the checks. A caller holding one is therefore a caller whose complete
/// invocation was valid against the state the broker had at a single moment: a fence, a
/// suspension, a turn change or a capability invalidation cannot land between the check and the
/// transmission, because there is nothing between them.
///
/// It carries the transport rather than naming it, so the submission does not have to go back to
/// the broker to find one, which is what lets a caller release its own locks before it transmits.
///
/// What it holds is an [`ExecutionPermit`], taken once. Everything else on it is a fact a caller
/// may read and none of it is authority.
#[derive(Debug)]
pub struct MutationAdmission {
    permit: std::sync::Mutex<Option<ExecutionPermit>>,
    application_instance_id: ApplicationInstanceId,
    binding_revision: AgentBindingRevision,
    operation: RichOperation,
    responsible: Responsible,
    capability: Option<CapabilityId>,
    admitted_at: TimestampMs,
    provenance: ActionProvenance,
    /// The resource this answer resolves, where it answers one.
    resource_id: Option<kr_protocol::ids::PendingResourceId>,
    /// The action this invocation runs, where it runs one.
    action: Option<ActionName>,
}

impl MutationAdmission {
    pub(crate) fn new(
        request: UpstreamRequest,
        dispatch: std::sync::Arc<dyn UpstreamDispatch>,
        responsible: Responsible,
        capability: Option<CapabilityId>,
        admitted_at: TimestampMs,
    ) -> Self {
        Self {
            application_instance_id: request.application_instance_id,
            binding_revision: request.binding_revision,
            operation: request.operation,
            responsible,
            capability,
            admitted_at,
            provenance: ActionProvenance::UpstreamTypedRpc,
            resource_id: None,
            action: None,
            permit: std::sync::Mutex::new(Some(ExecutionPermit {
                request,
                dispatch,
                settlement: None,
                approval: None,
                token: None,
                draft: None,
                declared: None,
                plan: None,
            })),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Option<ExecutionPermit>> {
        self.permit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn with_body(self, body: UpstreamBody) -> Self {
        if let Some(permit) = self.held().as_mut() {
            permit.request.body = body;
        }
        self
    }

    pub(crate) fn with_approval(mut self, claim: Claim, admission: DispatchAdmission) -> Self {
        self.provenance = admission.provenance;
        self.resource_id = Some(admission.resource.resource_id);
        if let Some(permit) = self.held().as_mut() {
            permit.settlement = Some(claim);
            permit.approval = Some(admission);
        }
        self
    }

    pub(crate) fn with_draft(self, draft: Option<crate::broker::DraftSnapshot>) -> Self {
        if let Some(permit) = self.held().as_mut() {
            permit.draft = draft;
        }
        self
    }

    pub(crate) fn with_declaration(self, declared: RegisteredAction) -> Self {
        if let Some(permit) = self.held().as_mut() {
            permit.declared = Some(declared);
        }
        self
    }

    pub(crate) fn with_action_token(mut self, token: ActionToken) -> Self {
        self.action = Some(token.action.clone());
        if let Some(permit) = self.held().as_mut() {
            // The token reaches the component that prepares the effect, so it travels with the
            // body the connector encodes rather than beside it.
            if let UpstreamBody::PluginAction { token: carried, .. } = &mut permit.request.body {
                *carried = Some(token.clone());
            }
            permit.token = Some(token);
        }
        self
    }

    /// Takes this admission's one execution permit.
    ///
    /// The second caller gets [`BrokerError::AlreadyTransmitted`] and nothing else: it does not
    /// transmit, and it does not settle the resource the first caller is answering. That is what
    /// keeps a losing concurrent call from recording the winner's answer as uncertain.
    fn take(&self) -> Result<ExecutionPermit> {
        let permit = self.held().take().ok_or(BrokerError::AlreadyTransmitted)?;
        // A plugin action transmits the plan this broker validated, and nothing else. An
        // invocation whose component returned a plan that was never checked has no permit to
        // execute, whatever else it holds.
        if matches!(permit.request.body, UpstreamBody::PluginAction { .. }) && permit.plan.is_none()
        {
            return Err(BrokerError::PreconditionFailed {
                detail: "this invocation's prepared effect has not been validated against the \
                         invocation it was prepared under"
                    .to_owned(),
            });
        }
        Ok(permit)
    }

    /// Returns the instance this mutation acts on.
    #[must_use]
    pub const fn application_instance_id(&self) -> ApplicationInstanceId {
        self.application_instance_id
    }

    /// Returns the binding revision it was admitted at.
    #[must_use]
    pub const fn binding_revision(&self) -> AgentBindingRevision {
        self.binding_revision
    }

    /// Returns the operation it carries.
    #[must_use]
    pub const fn operation(&self) -> RichOperation {
        self.operation
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

    /// Returns the resource this answer resolves, where it answers one.
    #[must_use]
    pub const fn resource_id(&self) -> Option<kr_protocol::ids::PendingResourceId> {
        self.resource_id
    }

    /// Returns the action this invocation runs, where it runs one.
    #[must_use]
    pub const fn action(&self) -> Option<&ActionName> {
        self.action.as_ref()
    }

    /// Asks the transport whether it can carry this operation, as the body now stands.
    ///
    /// It is asked once the operation is final, which for an answer is after the core has
    /// prepared it. Asking earlier would put a different operation to the transport than the one
    /// it will be given.
    pub(crate) fn check_transport(&self) -> Result<()> {
        let held = self.held();
        let permit = held.as_ref().ok_or(BrokerError::AlreadyTransmitted)?;
        permit.dispatch.admit(&permit.request)
    }

    /// Returns true when the permit has not been taken.
    #[must_use]
    pub fn executable(&self) -> bool {
        self.held().is_some()
    }

    /// Returns true when this invocation carries a validated effect plan.
    #[must_use]
    pub fn carries_a_validated_plan(&self) -> bool {
        self.held()
            .as_ref()
            .is_some_and(|permit| permit.plan.is_some())
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
    fn admit_mutation(
        &self,
        caller: &Caller,
        target: &AgentMutationTarget,
        capability: &str,
        operation: RichOperation,
        turn_id: Option<kr_protocol::ids::AgentTurnId>,
        body: UpstreamBody,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        let _ = caller;
        let capability_id = CapabilityId::new(capability)
            .map_err(|error| BrokerError::invalid(format!("capability name: {error}")))?;
        let admitted = self.state().admit_mutation_in(
            target,
            Some(capability_id),
            operation,
            turn_id,
            Responsible::Transport,
            body,
            None,
            now,
        )?;
        // And whether the transport can carry this operation at all. Asking here is what makes an
        // upstream with no method for the operation a rejection rather than a marker followed by
        // a refusal nobody can act on.
        admitted.check_transport()?;
        Ok(admitted)
    }

    /// Admits `agent.prompt.submit` or `agent.prompt.queue`.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the call names neither a draft nor text, or
    /// both, and whatever the admission refuses.
    pub fn admit_prompt(
        &self,
        caller: &Caller,
        params: &AgentPromptParams,
        queued: bool,
        now: TimestampMs,
    ) -> Result<MutationAdmission> {
        params.validate().map_err(BrokerError::invalid)?;
        let (capability, operation) = if queued {
            ("agent.prompt.queue", RichOperation::PromptQueue)
        } else {
            ("agent.prompt", RichOperation::PromptSubmit)
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
    /// Returns whatever the admission refuses.
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
            RichOperation::TurnSteer,
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
    /// Returns whatever the admission refuses.
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
            RichOperation::TurnCancel,
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
    /// Returns whatever the admission refuses, [`BrokerError::UnknownSubject`] when
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
        // The answer goes out on the connection whose resource it resolves, so the transport is
        // chosen from the resource here rather than being whichever one the instance last bound.
        // A connection that has gone is `UPSTREAM_UNAVAILABLE` before anything is claimed, not a
        // mismatch a writer finds after the marker.
        let connection = resource.request.connection;
        let transport = state
            .connection_dispatch
            .get(&connection)
            .cloned()
            .ok_or_else(|| BrokerError::UpstreamUnavailable {
                detail: format!(
                    "{} was asked on {connection} and nothing carries an answer out on it now",
                    params.resource_id
                ),
            })?;
        let admitted = state.admit_mutation_in(
            &params.target,
            Some(capability_id),
            RichOperation::ApprovalRespond,
            None,
            responsible,
            UpstreamBody::Cancel,
            Some(transport),
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
        let admitted = admitted
            .with_body(body)
            .with_approval(claim.clone(), dispatch);
        // The transport is asked about the answer it will actually be given, which is the frame
        // the core just prepared. A transport that cannot carry it gives the resource back, under
        // the lock this admission already holds: going back to the broker for it here would be a
        // second acquisition of a lock this frame never let go of.
        if let Err(error) = admitted.check_transport() {
            let _ = state.release_claim_in(&claim, now);
            return Err(error);
        }
        Ok(admitted)
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
        // The kind is checked before the permit is taken, so an admission handed to the wrong
        // entry point comes back unspent rather than being destroyed by the mistake.
        if admitted.resource_id().is_none() {
            return Err(BrokerError::invalid(
                "this admission does not carry an approval to answer",
            ));
        }
        // The permit is taken next, and taking it is what makes this caller the one that settles.
        // A second caller gets `AlreadyTransmitted` here and never reaches the transport or the
        // arbitration, so it cannot record the winner's answer as uncertain.
        let permit = admitted.take()?;
        let dispatch = permit.approval.ok_or_else(|| {
            BrokerError::invalid("this admission does not carry an approval to answer")
        })?;
        let claim = permit
            .settlement
            .ok_or_else(|| BrokerError::invalid("this admission holds no claim"))?;
        // The marker goes in immediately before the bytes. Everything that could refuse this
        // answer has already refused it, so what remains after this point is the transport's own
        // failure, which is what uncertainty is for. A marker this host could not write has sent
        // nothing, so the reservation goes back and the resource stays answerable.
        if let Err(error) = self.commit_dispatch(&claim, now) {
            let _ = self.release_claim(&claim, now);
            return Err(error);
        }
        let outcome = match permit.dispatch.submit(&permit.request) {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = self.uncertain(&claim, now);
                return Err(error);
            }
        };
        let resolved = self.resolve(&claim, now)?;
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
        // The draft is resolved before the lock, because the draft store is not the broker's and
        // calling it under the broker's lock would hold every other caller behind it. What comes
        // back is a snapshot, and the admission binds to that.
        let draft = match params.draft_id.as_ref() {
            Some(draft_id) => Some(self.resolve_draft(draft_id)?),
            None => None,
        };
        // The parameters are read once and written back in the one form this host will transmit.
        // What is hashed is that form, so the digest covers the bytes that go rather than a
        // spelling of them: two members of one name, or any other difference the encoder would
        // resolve later, cannot make the transmitted arguments differ from the hashed ones.
        let arguments = Self::executable_arguments(params)?;
        let mut state = self.state();
        // The declaration is read *inside* the admission. Reading it before the lock would let
        // `register_actions` replace it in between, so the grant, the effect class and the draft
        // requirement checked would belong to an action that is no longer registered.
        let registered = state.check_action_in(binding_id, params)?;
        if registered.needs_draft && draft.is_none() {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("{} acts on a draft and this call named none", params.action),
            });
        }
        let invocation = Self::invocation_for(caller, &registered, params, arguments.clone());
        let admitted = state.admit_mutation_in(
            &params.target,
            registered.capability.clone(),
            RichOperation::PluginAction,
            None,
            Responsible::Binding(binding_id),
            UpstreamBody::PluginAction {
                plugin_id: params.plugin_id.clone(),
                action: params.action.clone(),
                draft_id: params.draft_id.as_ref().copied(),
                // The revision the draft stood at when it was resolved for this admission. The
                // frame carries it, so what the upstream acts on is the draft this host checked
                // rather than whatever the identifier denotes by the time the bytes land.
                draft_revision: draft.as_ref().map(|snapshot| snapshot.revision),
                parameters: arguments.clone(),
                operation: None,
                token: None,
            },
            None,
            now,
        )?;
        let token = state.issue_token_in(binding_id, &invocation, now)?;
        // The token is spent here, before the effect: spending is what rechecks the binding, the
        // grant, the revision and the capability against the present, and doing it afterwards
        // would refuse an action that had already happened. Spending it under the same lock the
        // rest of the admission took is what leaves no window between the two. A refusal retires
        // the record rather than leaving a token nobody will spend.
        let spent = state
            .spend_token_in(&kr_protocol::broker::ActionTokenClaim::from(&token))
            .inspect_err(|_| {
                state.tokens.retire(&token.token_id);
            })?;
        let admitted = admitted
            .with_action_token(spent)
            .with_draft(draft)
            .with_declaration(registered);
        admitted.check_transport()?;
        Ok(admitted)
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
        let admitted = self.admit_plugin_action(caller, binding_id, params, now)?;
        self.validate_effect(&admitted, effect)?;
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
        // The kind is checked before the permit is taken. An approval handed to this entry point
        // comes back unspent, with its claim, rather than being consumed by the mistake.
        if admitted.action().is_none() {
            return Err(BrokerError::invalid(
                "this admission carries no action token",
            ));
        }
        // Taking the permit is what refuses an invocation whose component returned a plan nobody
        // validated: an admission with no validated plan has no permit to take.
        let permit = admitted.take()?;
        let token = permit
            .token
            .clone()
            .ok_or_else(|| BrokerError::invalid("this admission carries no action token"))?;
        let outcome = permit.dispatch.submit(&permit.request)?;
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

    /// Gives up one admission without transmitting it.
    ///
    /// The permit is taken and dropped, so nothing can execute the operation afterwards. What the
    /// admission reserved is given back with it: an approval's claim is released, and a plugin
    /// action's token is retired. A caller that abandons an admission leaves the resource exactly
    /// as it found it.
    pub fn abandon(&self, admitted: &MutationAdmission) {
        let Ok(permit) = admitted.take() else {
            return;
        };
        if let Some(claim) = permit.settlement.as_ref() {
            let _ = self.release_claim(claim, admitted.admitted_at());
        }
        if let Some(token) = permit.token.as_ref() {
            self.state().tokens.retire(&token.token_id);
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
    /// Returns whatever [`Broker::check_action`] returns, and
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
        let invocation = Self::invocation_for(
            caller,
            &registered,
            params,
            Self::executable_arguments(params)?,
        );
        let mut state = self.state();
        state.admit_mutation_in(
            &params.target,
            registered.capability.clone(),
            RichOperation::PluginAction,
            None,
            Responsible::Binding(binding_id),
            UpstreamBody::Cancel,
            None,
            now,
        )?;
        state.check_invocation(binding_id, &invocation)?;
        // And there has to be a token to issue. A full table refuses every invocation whatever
        // the caller does, so it is refused here rather than after the marker.
        state.tokens.check_capacity()?;
        Ok(())
    }

    /// Returns the one encoding of an invocation's arguments this host will transmit.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the arguments are not an encoding this host
    /// can carry to an upstream.
    fn executable_arguments(params: &PluginActionInvokeParams) -> Result<Vec<u8>> {
        let arguments: serde_json::Value = serde_json::from_slice(params.parameters.as_slice())
            .map_err(|error| {
                BrokerError::invalid(format!(
                    "{}'s parameters are not an encoding this host can carry to an upstream: \
                     {error}",
                    params.action
                ))
            })?;
        serde_json::to_vec(&arguments).map_err(|error| {
            BrokerError::invalid(format!(
                "{}'s parameters will not encode: {error}",
                params.action
            ))
        })
    }

    fn invocation_for(
        caller: &Caller,
        registered: &RegisteredAction,
        params: &PluginActionInvokeParams,
        arguments: Vec<u8>,
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
            parameters: arguments,
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
        admitted: &MutationAdmission,
        effect: &kr_protocol::broker::PreparedEffect,
    ) -> Result<()> {
        // Everything this invocation was admitted with, read once. The permit's lock is held only
        // for the read: what follows calls out to the draft store and then takes the broker's own
        // lock, and holding two locks across either would make the order they are taken in matter.
        let (token, declared, draft, arguments) = {
            let held = admitted.held();
            let permit = held.as_ref().ok_or(BrokerError::AlreadyTransmitted)?;
            let UpstreamBody::PluginAction { parameters, .. } = &permit.request.body else {
                return Err(BrokerError::invalid(
                    "an effect plan belongs to a plugin action and this admission carries another \
                     operation",
                ));
            };
            (
                permit.token.clone().ok_or_else(|| {
                    BrokerError::invalid("this admission carries no action token")
                })?,
                permit.declared.clone().ok_or_else(|| {
                    BrokerError::invalid("this admission carries no action declaration")
                })?,
                permit.draft.clone(),
                parameters.clone(),
            )
        };
        let binding_id = match admitted.responsible() {
            Responsible::Binding(binding_id) => binding_id,
            Responsible::Transport => {
                return Err(BrokerError::invalid(
                    "an effect plan belongs to a component invocation and this admission names \
                     none",
                ));
            }
        };
        // The arguments this plan is for are the arguments that will execute. The digest is
        // computed from them here rather than read from the plan: a hash a component supplied
        // says only that the component can write a hash.
        let computed =
            kr_protocol::scalars::Digest256::from_bytes(kr_cbor::sha256(arguments.as_slice()));
        if computed != token.parameter_hash {
            return Err(BrokerError::Token(
                kr_protocol::broker::TokenError::Mismatch {
                    field: "parameter_hash",
                },
            ));
        }
        if effect.argument_hash != computed {
            return Err(BrokerError::Token(
                kr_protocol::broker::TokenError::Mismatch {
                    field: "argument_hash",
                },
            ));
        }
        if effect.action != token.action {
            return Err(BrokerError::Token(
                kr_protocol::broker::TokenError::Mismatch { field: "action" },
            ));
        }
        // A read cannot arrive on the write path, and an operation that changes the upstream is
        // not a read whatever the plan calls it.
        if effect.class != EffectClass::Write || !effect.operation.writes() {
            return Err(BrokerError::invalid(format!(
                "{} changes the upstream and this plan declares it {:?}",
                effect.operation, effect.class
            )));
        }
        // The draft. A plan that names one names the invocation's own, whether the manifest
        // required a draft or not: a component invited to act on nothing cannot acquire a draft by
        // putting one in its plan.
        if effect.draft_id.as_ref() != token.draft_id.as_ref() {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "this plan acts on {} and the invocation named {}",
                    effect
                        .draft_id
                        .as_ref()
                        .map_or_else(|| "no draft".to_owned(), ToString::to_string),
                    token
                        .draft_id
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), ToString::to_string)
                ),
            });
        }
        // The draft store is not the broker's, so it is asked before the broker's lock is taken
        // and its answer is what the transaction below is given.
        if let Some(named) = effect.draft_id.as_ref() {
            if !effect.operation.may_act_on_a_draft() {
                return Err(BrokerError::invalid(format!(
                    "{} acts on no draft and this plan named one",
                    effect.operation
                )));
            }
            let snapshot = draft.ok_or_else(|| BrokerError::PreconditionFailed {
                detail: format!("this plan acts on {named} and the invocation resolved no draft"),
            })?;
            if &snapshot.draft_id != named {
                return Err(BrokerError::PreconditionFailed {
                    detail: format!(
                        "this plan acts on {named} and the invocation was admitted against {}",
                        snapshot.draft_id
                    ),
                });
            }
            // And the revision it stood at. A draft that moved while the component was preparing
            // its plan is `DRAFT_CONFLICT`: the plan was made against a draft that is not there
            // any more.
            let current = self.resolve_draft(named)?;
            if current.revision != snapshot.revision {
                return Err(BrokerError::PreconditionFailed {
                    detail: format!(
                        "{named} was at revision {} when this invocation was admitted and is at \
                         {} now",
                        snapshot.revision.get(),
                        current.revision.get()
                    ),
                });
            }
        } else if declared.needs_draft {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{} acts on a draft and this plan named none",
                    effect.operation
                ),
            });
        }
        // And then one transaction. The declaration in force, the grant the operation needs and
        // the invocation's own authority are read together, and the plan becomes executable in
        // the same operation, so nothing any of them depends on can move between the last check
        // and the moment the permit will carry the plan.
        let state = self.state();
        let registered = state
            .registered_action_in(binding_id, &token.action)?
            .ok_or_else(|| {
                BrokerError::unknown(format!("{} is no longer a registered action", token.action))
            })?;
        if registered != declared {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "{} was admitted under one declaration and another is registered now",
                    token.action
                ),
            });
        }
        if registered.operation != effect.operation {
            return Err(BrokerError::invalid(format!(
                "{} is declared as {} and this plan prepares {}",
                token.action, registered.operation, effect.operation
            )));
        }
        if registered.effect != effect.class {
            return Err(BrokerError::invalid(format!(
                "{} is declared {:?} and this plan declares it {:?}",
                token.action, registered.effect, effect.class
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
        // The invocation's own authority, as it stands now. The token was spent to invite the
        // component to prepare this plan, so it is not proof of anything by the time the plan
        // arrives: a grant withdrawn, a thread selection advanced or a capability invalidated
        // while the component was working is a plan this host will not carry.
        let grants =
            state.check_invocation_for(binding_id, &token, registered.capability.clone())?;
        grants.require(needed)?;
        // The plan itself goes into the permit, and the operation it prepares goes into the body
        // that will be transmitted. What reaches the upstream is therefore the plan that was
        // checked, rather than an operation beside a flag saying a plan was seen.
        let mut held = admitted.held();
        let permit = held.as_mut().ok_or(BrokerError::AlreadyTransmitted)?;
        if let UpstreamBody::PluginAction { operation, .. } = &mut permit.request.body {
            *operation = Some(effect.operation);
        }
        permit.plan = Some(effect.clone());
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
        self.state().check_action_in(binding_id, params)
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
        // An answer settles its resource, and this route does not settle anything. Refusing it
        // before the permit is taken leaves the approval's own admission intact.
        if admitted.resource_id().is_some() {
            return Err(BrokerError::invalid(
                "this admission answers a pending resource, and an answer is recorded by the \
                 route that settles it",
            ));
        }
        let permit = admitted.take()?;
        let turn_id = permit.request.turn_id.clone();
        let outcome = permit.dispatch.submit(&permit.request)?;
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
