//! The trusted broker: the worker's own boundary between an upstream application and everything
//! that wants to say what that application is doing.
//!
//! Section 2 calls this a "serial dispatch broker", and the shape follows from that word. One lock
//! covers the whole of the broker's state, and every decision that depends on more than one part
//! of it is one operation under that lock: check the grant, check the binding revision, check the
//! source is fresh, claim the pending resource. Splitting those would leave windows in which a
//! check had passed and the thing it checked had already changed.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`arbitration`] | Pending resources, one resolution each, and what a reconnect does |
//! | [`capability`] | The per-installation capability map and the probes behind it |
//! | [`error`] | The broker's refusals, each mapped to a stable protocol code |
//! | [`ledger`] | The durable records, in the worker's own journal file |
//! | [`process`] | Launched processes, their credentials and their immutable source frames |
//! | [`profiles`] | Launch profiles, the stale-launch refusal and one process per conversation |
//! | [`tokens`] | Action tokens: issued per invocation, spent once |
//! | [`volatile`] | `native_only_volatile`: what is fenced, what continues, and the gap |
//!
//! What the broker will not do is as much of the contract as what it will. It does not let an
//! observation-only component create an approval. It does not believe a decoder that was not
//! granted trust for the method it decoded. It does not let the same source event become two
//! resources. It does not paste a launch command into an application that took the foreground. And
//! it does not answer a request twice, whatever reconnects.

pub mod arbitration;
pub mod capability;
pub mod error;
pub mod ledger;
pub mod process;
pub mod profiles;
pub mod tokens;
pub mod volatile;

use std::collections::BTreeMap;
use std::sync::Mutex;

use kr_protocol::agent::AgentBindingState;
use kr_protocol::broker::{
    ActionName, ActionToken, ActionTokenClaim, BrokerGrant, BrokerGrants, DecoderLedgerEntry,
    DecodingTrust, IntegrationMode, LaunchProfile,
};
use kr_protocol::gateway::{
    Durability, NativeClassification, PendingKind, PendingResource, PendingState,
};
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, AgentThreadId, AgentTurnId, ApplicationInstanceId,
    BrokerBindingId, GatewayConnectionId, LaunchProfileId, PendingResourceId, PluginId,
    PublisherId, SourceEventHandle, SourceGeneration, StreamCursor, UpstreamMethod,
    UpstreamRequestId,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

pub use crate::broker::arbitration::{Arbitration, Claim, Pending, Reconciliation};
pub use crate::broker::capability::{CapabilityOwner, Probe};
pub use crate::broker::error::{BrokerError, Result};
pub use crate::broker::ledger::{BindingRecord, Ledger};
pub use crate::broker::process::{
    BrokerTransport, Credential, ManagedProcess, SourceFrame, TransportHandle,
};
pub use crate::broker::profiles::{ForegroundMark, LaunchIntent, ProfileStore, new_profile_id};
pub use crate::broker::tokens::{Invocation, TokenStore};
pub use crate::broker::volatile::{VolatileState, VolatileTransition};

/// One component bound to one application instance.
#[derive(Debug)]
pub struct Binding {
    /// The binding.
    pub binding_id: BrokerBindingId,
    /// The instance it observes or acts on.
    pub application_instance_id: ApplicationInstanceId,
    /// The package the component came from.
    pub plugin_id: PluginId,
    /// That package's publisher, shown beside anything this binding produced.
    pub publisher_id: PublisherId,
    /// The digest of the exact component bytes.
    pub package_digest: Digest256,
    /// The three grants, held separately.
    pub grants: BrokerGrants,
    /// The decoding trust, where the binding has any.
    pub trust: Option<DecodingTrust>,
    /// True when a component fault has disabled this binding's rich capabilities.
    ///
    /// Native forwarding is untouched by this. Section 11: "A Wasm fault disables the affected
    /// rich capabilities; it cannot stall or discard otherwise valid native traffic."
    pub rich_disabled: Option<String>,
}

impl Binding {
    /// Returns true when this binding may decode the named method into a pending resource.
    ///
    /// Three things must hold together: the approval-interpreter grant, a recorded trust record,
    /// and that record covering this exact method. Any one of them alone would let a component
    /// that was trusted for something else interpret this.
    #[must_use]
    pub fn may_decode(&self, method: &UpstreamMethod) -> bool {
        self.grants.holds(BrokerGrant::ApprovalInterpreter)
            && self
                .trust
                .as_ref()
                .is_some_and(|trust| trust.covers(method))
    }

    /// Returns true when this binding may encode an answer to the named method.
    #[must_use]
    pub fn may_encode(&self, method: &UpstreamMethod) -> bool {
        self.may_decode(method)
            && self
                .trust
                .as_ref()
                .is_some_and(|trust| trust.may_encode_response)
    }
}

/// One managed application instance.
#[derive(Debug)]
pub struct Instance {
    /// The instance.
    pub application_instance_id: ApplicationInstanceId,
    /// The process, where this host launched one.
    pub process: Option<ManagedProcess>,
    /// The revision that advances when the upstream owner or selected thread changes.
    pub binding_revision: AgentBindingRevision,
    /// The upstream's own conversation identifier, where it exposes one.
    pub thread_id: Option<AgentThreadId>,
    /// The turn currently running, where one is.
    pub turn_id: Option<AgentTurnId>,
    /// How this instance is integrated.
    pub mode: IntegrationMode,
    /// The profile it was launched under.
    pub profile_id: Option<LaunchProfileId>,
    /// Why rich mutations are suspended, while they are.
    pub rich_suspension: Option<String>,
    /// How many KalaReach attachments are watching it.
    ///
    /// Closing one does not end the process. Section 7: "Closing a KR attachment does not end the
    /// TUI process in the worker PTY."
    pub attachments: usize,
    /// The source frames the broker is holding for this instance's decoders.
    frames: BTreeMap<SourceEventHandle, SourceFrame>,
}

impl Instance {
    /// Returns the binding state a client reads.
    #[must_use]
    pub fn state(&self) -> AgentBindingState {
        AgentBindingState {
            binding_revision: self.binding_revision,
            thread_id: Nullable::from(self.thread_id.clone()),
            turn_id: Nullable::from(self.turn_id.clone()),
            profile_id: Nullable::from(self.profile_id.clone()),
            mode: self.mode,
            rich_mutations_suspended: self.rich_suspension.is_some(),
            suspension_reason: Nullable::from(self.rich_suspension.clone()),
        }
    }
}

/// What ended an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceEnding {
    /// The native terminal application exited on purpose.
    ///
    /// This ends the instance and stops its dedicated backend through the normal grace period.
    NativeExit,
    /// A KalaReach attachment was closed.
    ///
    /// This ends nothing. The terminal application keeps running in the worker's pseudo-terminal.
    AttachmentClosed,
}

/// What stopping an instance actually does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopOutcome {
    /// True when the instance's record was removed.
    pub instance_ended: bool,
    /// True when a dedicated backend this host owns is to be stopped.
    ///
    /// A bypassed or shared backend is never claimed or terminated as owned, so this is false for
    /// one of those however the instance ended.
    pub stop_backend: bool,
    /// How many attachments are still watching.
    pub attachments_remaining: usize,
}

/// The broker's whole state, behind one lock.
#[derive(Debug, Default)]
struct BrokerState {
    instances: BTreeMap<ApplicationInstanceId, Instance>,
    bindings: BTreeMap<BrokerBindingId, Binding>,
    tokens: TokenStore,
    profiles: ProfileStore,
    arbitration: Arbitration,
    capabilities: CapabilityOwner,
    volatile: VolatileState,
    next_connection: u64,
}

/// The trusted broker.
#[derive(Debug)]
pub struct Broker {
    state: Mutex<BrokerState>,
    ledger: Mutex<Ledger>,
}

impl Broker {
    /// Opens a broker whose durable records live beside the worker's receipt journal.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the ledger cannot be opened.
    pub fn open(journal_path: Option<&std::path::Path>) -> Result<Self> {
        let ledger = Ledger::open(journal_path)?;
        let mut state = BrokerState::default();
        // A restarted worker starts from what it wrote, not from nothing. An unresolved resource
        // that was already dispatched comes back so a reconnect can reconcile it; one that was
        // not comes back answerable.
        for resource in ledger.unresolved()? {
            let dispatched = resource.state == PendingState::Claimed;
            state.arbitration.restore(resource, dispatched);
        }
        state.profiles.restore(ledger.profiles()?);
        Ok(Self {
            state: Mutex::new(state),
            ledger: Mutex::new(ledger),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BrokerState> {
        self.state.lock().expect("the broker lock is not poisoned")
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .expect("the broker ledger lock is not poisoned")
    }

    // -- instances ----------------------------------------------------------------------------

    /// Registers one managed application instance.
    pub fn register_instance(
        &self,
        application_instance_id: ApplicationInstanceId,
        mode: IntegrationMode,
        profile_id: Option<LaunchProfileId>,
        process: Option<ManagedProcess>,
    ) {
        self.state().instances.insert(
            application_instance_id,
            Instance {
                application_instance_id,
                process,
                binding_revision: AgentBindingRevision::new(1),
                thread_id: None,
                turn_id: None,
                mode,
                profile_id,
                rich_suspension: None,
                attachments: 0,
                frames: BTreeMap::new(),
            },
        );
    }

    /// Returns one instance's binding state.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn binding_state(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<AgentBindingState> {
        let state = self.state();
        state
            .instances
            .get(&application_instance_id)
            .map(Instance::state)
            .ok_or_else(|| {
                BrokerError::unknown(format!("no application instance {application_instance_id}"))
            })
    }

    /// Advances the binding revision, because the upstream owner or selected thread changed.
    ///
    /// Everything prepared against the old revision stops being authority at this moment: the
    /// tokens are withdrawn, the source generation moves on, and a draft submitted against the old
    /// revision is a conflict rather than a prompt into whatever is selected now.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn advance_binding(
        &self,
        application_instance_id: ApplicationInstanceId,
        thread_id: Option<AgentThreadId>,
    ) -> Result<AgentBindingRevision> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| {
                BrokerError::unknown(format!("no application instance {application_instance_id}"))
            })?;
        instance.binding_revision =
            AgentBindingRevision::new(instance.binding_revision.get().saturating_add(1));
        instance.thread_id = thread_id;
        instance.turn_id = None;
        if let Some(process) = instance.process.as_mut() {
            process.advance_generation();
        }
        let revision = instance.binding_revision;
        state.tokens.withdraw(application_instance_id);
        state.capabilities.invalidate_instance(
            application_instance_id,
            kr_protocol::broker::CapabilityInvalidation::BindingChanged,
            "the upstream owner or selected thread changed",
            TimestampMs::new(0),
        );
        Ok(revision)
    }

    /// Suspends rich mutations until the binding can be verified.
    ///
    /// The terminal stays available throughout. This is the state section 12 requires when a
    /// native selection cannot be observed reliably, and it is a state rather than an error
    /// because the session is still perfectly usable.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn suspend_rich_mutations(
        &self,
        application_instance_id: ApplicationInstanceId,
        reason: impl Into<String>,
    ) -> Result<()> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| {
                BrokerError::unknown(format!("no application instance {application_instance_id}"))
            })?;
        instance.rich_suspension = Some(reason.into());
        Ok(())
    }

    /// Lifts the suspension, because the binding has been verified.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn resume_rich_mutations(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<()> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| {
                BrokerError::unknown(format!("no application instance {application_instance_id}"))
            })?;
        instance.rich_suspension = None;
        Ok(())
    }

    /// Records that another attachment is watching one instance.
    pub fn attach(&self, application_instance_id: ApplicationInstanceId) {
        if let Some(instance) = self.state().instances.get_mut(&application_instance_id) {
            instance.attachments = instance.attachments.saturating_add(1);
        }
    }

    /// Ends an instance, or does not, depending on what ended.
    ///
    /// Section 7 draws the line here and it is the line users notice: quitting the agent ends the
    /// agent, and closing the window you were watching it through does not.
    pub fn end(
        &self,
        application_instance_id: ApplicationInstanceId,
        ending: InstanceEnding,
    ) -> StopOutcome {
        let mut state = self.state();
        let Some(instance) = state.instances.get_mut(&application_instance_id) else {
            return StopOutcome {
                instance_ended: false,
                stop_backend: false,
                attachments_remaining: 0,
            };
        };
        match ending {
            InstanceEnding::AttachmentClosed => {
                instance.attachments = instance.attachments.saturating_sub(1);
                StopOutcome {
                    instance_ended: false,
                    stop_backend: false,
                    attachments_remaining: instance.attachments,
                }
            }
            InstanceEnding::NativeExit => {
                let stop_backend = instance
                    .process
                    .as_ref()
                    .is_some_and(|process| process.dedicated);
                state.instances.remove(&application_instance_id);
                state.tokens.withdraw(application_instance_id);
                state.profiles.release(application_instance_id);
                state.capabilities.forget(application_instance_id);
                StopOutcome {
                    instance_ended: true,
                    stop_backend,
                    attachments_remaining: 0,
                }
            }
        }
    }

    // -- bindings, grants and decoding trust --------------------------------------------------

    /// Binds one component to one instance, with the grants and trust it was given.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Trust`] when a trust record breaks a rule and
    /// [`BrokerError::LedgerUnavailable`] when the record cannot be written.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        &self,
        binding_id: BrokerBindingId,
        application_instance_id: ApplicationInstanceId,
        plugin_id: PluginId,
        publisher_id: PublisherId,
        package_digest: Digest256,
        grants: BrokerGrants,
        trust: Option<DecodingTrust>,
        now: TimestampMs,
    ) -> Result<()> {
        if let Some(trust) = trust.as_ref() {
            trust.validate()?;
            // Trust without the grant it depends on is a record that would never be acted on.
            // Refusing it here is what keeps "explicit" from meaning "written down somewhere".
            if !grants.holds(BrokerGrant::ApprovalInterpreter) {
                return Err(BrokerError::denied(
                    "decoding trust needs the approval interpreter grant",
                ));
            }
            let _ = trust;
        }
        self.ledger().put_binding(&BindingRecord {
            binding_id,
            application_instance_id,
            grants: grants.clone(),
            trust: trust.clone(),
            bound_at: now,
        })?;
        self.state().bindings.insert(
            binding_id,
            Binding {
                binding_id,
                application_instance_id,
                plugin_id,
                publisher_id,
                package_digest,
                grants,
                trust,
                rich_disabled: None,
            },
        );
        Ok(())
    }

    /// Returns the grants one binding holds.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such binding.
    pub fn grants(&self, binding_id: BrokerBindingId) -> Result<BrokerGrants> {
        self.state()
            .bindings
            .get(&binding_id)
            .map(|binding| binding.grants.clone())
            .ok_or_else(|| BrokerError::unknown(format!("no binding {binding_id}")))
    }

    /// Withdraws one grant from one binding, leaving the others exactly as they were.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such binding, and
    /// [`BrokerError::LedgerUnavailable`] when the change cannot be written.
    pub fn withdraw_grant(&self, binding_id: BrokerBindingId, grant: BrokerGrant) -> Result<()> {
        let mut state = self.state();
        let binding = state
            .bindings
            .get_mut(&binding_id)
            .ok_or_else(|| BrokerError::unknown(format!("no binding {binding_id}")))?;
        binding.grants.remove(grant);
        // Withdrawing the interpreter grant withdraws what depended on it. Leaving the trust
        // record behind would leave a record the broker would refuse to act on anyway, and a
        // record nobody acts on is one somebody will eventually read as permission.
        if grant == BrokerGrant::ApprovalInterpreter {
            binding.trust = None;
        }
        let record = BindingRecord {
            binding_id,
            application_instance_id: binding.application_instance_id,
            grants: binding.grants.clone(),
            trust: binding.trust.clone(),
            bound_at: TimestampMs::new(0),
        };
        drop(state);
        self.ledger().put_binding(&record)
    }

    /// Records that a component fault has disabled one binding's rich capabilities.
    ///
    /// Native traffic is untouched: nothing in this function reaches the forwarding path.
    pub fn disable_rich(&self, binding_id: BrokerBindingId, reason: impl Into<String>) {
        if let Some(binding) = self.state().bindings.get_mut(&binding_id) {
            binding.rich_disabled = Some(reason.into());
        }
    }

    /// Returns why one binding's rich capabilities are disabled, when they are.
    #[must_use]
    pub fn rich_disabled(&self, binding_id: BrokerBindingId) -> Option<String> {
        self.state()
            .bindings
            .get(&binding_id)
            .and_then(|binding| binding.rich_disabled.clone())
    }

    // -- source frames ------------------------------------------------------------------------

    /// Records one immutable frame of upstream bytes against an instance.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance, and
    /// [`BrokerError::InvalidArgument`] when the frame is too large.
    pub fn record_source(
        &self,
        application_instance_id: ApplicationInstanceId,
        bytes: &[u8],
        now: TimestampMs,
    ) -> Result<SourceFrame> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| {
                BrokerError::unknown(format!("no application instance {application_instance_id}"))
            })?;
        let generation = instance.process.as_ref().map_or_else(
            || SourceGeneration::new(1),
            |process| process.source_generation,
        );
        let handle = SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid()))
            .map_err(|error| BrokerError::invalid(format!("source handle: {error}")))?;
        let frame = SourceFrame::new(handle.clone(), generation, bytes, now)?;
        instance.frames.insert(handle, frame.clone());
        Ok(frame)
    }

    /// Returns one recorded source frame.
    #[must_use]
    pub fn source(
        &self,
        application_instance_id: ApplicationInstanceId,
        handle: &SourceEventHandle,
    ) -> Option<SourceFrame> {
        self.state()
            .instances
            .get(&application_instance_id)
            .and_then(|instance| instance.frames.get(handle).cloned())
    }

    // -- the decoder path ---------------------------------------------------------------------

    /// Offers a pending resource a decoder proposed, after every check section 11 names.
    ///
    /// The checks are made in this order, and the order is the argument:
    ///
    /// 1. **Role.** Does this binding hold the approval-interpreter grant, and is there a trust
    ///    record covering this exact method? A display-only component stops here.
    /// 2. **Binding.** Is the frame from the instance this binding is bound to?
    /// 3. **Source generation.** Is the frame from the execution that is bound *now*? A frame an
    ///    earlier owner produced cannot become a resource against the current one.
    /// 4. **Non-reuse.** Has this exact source event already been turned into a resource? A
    ///    decoder gets one resource per frame, and the claim is durable so a restart does not
    ///    reopen the question.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Grant`] or [`BrokerError::PermissionDenied`] for a role the binding
    /// does not have, [`BrokerError::UnknownSubject`] for a binding or instance this broker does
    /// not hold, and [`BrokerError::PreconditionFailed`] for a stale generation or a reused source.
    #[allow(clippy::too_many_arguments)]
    pub fn offer_resource(
        &self,
        binding_id: BrokerBindingId,
        frame: &SourceFrame,
        request: kr_protocol::gateway::DownstreamRequestId,
        method: UpstreamMethod,
        classification: NativeClassification,
        offered_decisions: u64,
        deadline_ms: Option<TimestampMs>,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        let state = self.state();
        let binding = state
            .bindings
            .get(&binding_id)
            .ok_or_else(|| BrokerError::unknown(format!("no binding {binding_id}")))?;
        if !binding.grants.holds(BrokerGrant::ApprovalInterpreter) {
            return Err(BrokerError::Grant(
                kr_protocol::broker::GrantError::NotHeld {
                    grant: BrokerGrant::ApprovalInterpreter,
                },
            ));
        }
        if !binding.may_decode(&method) {
            return Err(BrokerError::denied(format!(
                "this binding is not trusted to decode {method}"
            )));
        }
        if let Some(reason) = binding.rich_disabled.as_ref() {
            return Err(BrokerError::UnsupportedCapability {
                detail: format!("this binding's rich capabilities are disabled: {reason}"),
            });
        }
        let application_instance_id = binding.application_instance_id;
        let plugin_id = binding.plugin_id.clone();
        let publisher_id = binding.publisher_id.clone();
        let package_digest = binding.package_digest;
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| {
                BrokerError::unknown(format!("no application instance {application_instance_id}"))
            })?;
        let current_generation = instance.process.as_ref().map_or_else(
            || SourceGeneration::new(1),
            |process| process.source_generation,
        );
        if !instance.frames.contains_key(&frame.handle) {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "source event {} does not belong to this binding's application",
                    frame.handle
                ),
            });
        }
        if frame.generation != current_generation {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "source event {} is from generation {} and the binding is at {current_generation}",
                    frame.handle, frame.generation
                ),
            });
        }
        let durability = state.volatile.mode().durability();
        drop(state);

        let ledger = self.ledger();
        if !ledger.claim_source(binding_id, frame.generation, &frame.digest, now)? {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "source event {} has already produced a resource",
                    frame.handle
                ),
            });
        }
        let resource = PendingResource {
            resource_id: PendingResourceId::new(Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes())),
            application_instance_id,
            request,
            kind: PendingKind::Approval,
            method: method.clone(),
            classification,
            source_generation: frame.generation,
            state: PendingState::Pending,
            durability,
            deadline_ms: Nullable::from(deadline_ms),
            recorded_at: now,
            interpretation_verified: true,
        };
        ledger.record_decoding(
            resource.resource_id,
            &DecoderLedgerEntry {
                binding_id,
                plugin_id,
                publisher_id,
                package_digest,
                method,
                source_generation: frame.generation,
                source_digest: frame.digest,
                offered_decisions: U64::new(offered_decisions),
                deadline_ms: Nullable::from(deadline_ms),
                decoded_at: now,
            },
        )?;
        if durability == Durability::Durable {
            ledger.put_pending(&resource)?;
        }
        drop(ledger);
        self.state().arbitration.record(resource.clone())?;
        Ok(resource)
    }

    /// Returns the decoder entry behind one pending resource.
    ///
    /// This is what a person is shown beside an approval: whose package interpreted which bytes,
    /// and how many decisions it offered.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the record cannot be read.
    pub fn decoding(&self, resource_id: PendingResourceId) -> Result<Option<DecoderLedgerEntry>> {
        self.ledger().decoding(resource_id)
    }

    // -- action tokens ------------------------------------------------------------------------

    /// Issues an action token for one invocation.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the binding is unknown and
    /// [`BrokerError::Grant`] when it does not hold the grant the invocation names.
    pub fn issue_token(
        &self,
        binding_id: BrokerBindingId,
        invocation: &Invocation,
        now: TimestampMs,
    ) -> Result<ActionToken> {
        let mut state = self.state();
        let grants = state
            .bindings
            .get(&binding_id)
            .map(|binding| binding.grants.clone())
            .ok_or_else(|| BrokerError::unknown(format!("no binding {binding_id}")))?;
        state.tokens.issue(&grants, invocation, now)
    }

    /// Spends an action token against a returned effect plan.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Token`] when the token is unknown, spent, or bound to something
    /// other than what was presented, and [`BrokerError::UnknownSubject`] when the instance has
    /// gone.
    pub fn spend_token(&self, claim: &ActionTokenClaim) -> Result<ActionToken> {
        let mut state = self.state();
        let revision = state
            .instances
            .get(&claim.application_instance_id)
            .map(|instance| instance.binding_revision)
            .ok_or_else(|| {
                BrokerError::unknown(format!(
                    "no application instance {}",
                    claim.application_instance_id
                ))
            })?;
        state.tokens.spend(claim, revision)
    }

    // -- launch profiles ----------------------------------------------------------------------

    /// Prepares a launch against the current idle-shell boundary.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Launch`] when the boundary is not the idle root shell, and
    /// [`BrokerError::LedgerUnavailable`] when the profile cannot be recorded.
    pub fn prepare_launch(
        &self,
        profile: LaunchProfile,
        against: ForegroundMark,
        saved_conversation: Option<String>,
    ) -> Result<LaunchIntent> {
        let intent = self
            .state()
            .profiles
            .prepare(profile, against, saved_conversation)?;
        self.ledger().put_profile(&intent.profile, None)?;
        Ok(intent)
    }

    /// Executes a prepared launch, or refuses it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Launch`] with the refusal that applies.
    pub fn execute_launch(
        &self,
        intent: &LaunchIntent,
        now: &ForegroundMark,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<LaunchProfile> {
        let profile = self
            .state()
            .profiles
            .execute(intent, now, application_instance_id)?;
        self.ledger()
            .put_profile(&profile, Some(application_instance_id))?;
        Ok(profile)
    }

    /// Records a launch the host detected rather than started.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the profile cannot be recorded.
    pub fn adopt_launch(
        &self,
        profile: LaunchProfile,
        application_instance_id: ApplicationInstanceId,
        saved_conversation: Option<String>,
    ) -> Result<()> {
        self.state()
            .profiles
            .adopt(profile.clone(), application_instance_id, saved_conversation);
        self.ledger()
            .put_profile(&profile, Some(application_instance_id))
    }

    /// Returns the profile one instance was launched under.
    #[must_use]
    pub fn profile_of(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<LaunchProfile> {
        self.state()
            .profiles
            .profile_of(application_instance_id)
            .cloned()
    }

    // -- capability evidence ------------------------------------------------------------------

    /// Records one capability record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Capability`] when the record breaks a rule.
    pub fn record_capability(&self, record: kr_protocol::broker::CapabilityRecord) -> Result<()> {
        self.state().capabilities.record(record)
    }

    /// Records the result of a probe the host ran.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the probe was not one the host would run.
    pub fn record_probe(
        &self,
        probe: &Probe,
        record: kr_protocol::broker::CapabilityRecord,
    ) -> Result<()> {
        self.state().capabilities.record_probe(probe, record)
    }

    /// Returns one installation's capability map.
    #[must_use]
    pub fn capabilities(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> kr_protocol::broker::CapabilityMap {
        self.state().capabilities.map(application_instance_id)
    }

    /// Invalidates every record one change makes stale.
    pub fn invalidate_capabilities(
        &self,
        change: kr_protocol::broker::CapabilityInvalidation,
        reason: &str,
        now: TimestampMs,
    ) -> usize {
        self.state().capabilities.invalidate(change, reason, now)
    }

    /// Rechecks one capability before an action is dispatched.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] or [`BrokerError::StaleBinding`] as the
    /// record requires.
    pub fn recheck_capability(
        &self,
        application_instance_id: ApplicationInstanceId,
        capability_id: &kr_protocol::ids::CapabilityId,
        read_at: Option<kr_protocol::ids::CapabilityRevision>,
    ) -> Result<()> {
        self.state()
            .capabilities
            .recheck(application_instance_id, capability_id, read_at)
            .map(|_| ())
    }

    // -- arbitration --------------------------------------------------------------------------

    /// Takes the claim on one pending resource.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] when the resource is already claimed or resolved.
    pub fn claim(
        &self,
        resource_id: PendingResourceId,
        actor_id: &ActorId,
        now: TimestampMs,
    ) -> Result<Claim> {
        let mut state = self.state();
        let claim = state.arbitration.claim(resource_id, actor_id, now)?;
        let resource = state
            .arbitration
            .get(resource_id)
            .map(|pending| pending.resource.clone());
        let durable = state.volatile.mode().durability() == Durability::Durable;
        drop(state);
        if let Some(resource) = resource
            && durable
        {
            self.ledger().settle_pending(&resource, now)?;
        }
        Ok(claim)
    }

    /// Resolves a claimed resource.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] or [`BrokerError::PermissionDenied`] as the claim
    /// requires.
    pub fn resolve(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        state.arbitration.mark_dispatched(claim)?;
        let resource = state.arbitration.resolve(claim)?;
        let durable = state.volatile.mode().durability() == Durability::Durable;
        drop(state);
        if durable {
            self.ledger().settle_pending(&resource, now)?;
        }
        Ok(resource)
    }

    /// Records that the upstream answered or withdrew a request itself.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] or [`BrokerError::Arbitration`] as the state
    /// requires.
    pub fn upstream_resolved(
        &self,
        request: &kr_protocol::gateway::DownstreamRequestId,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        let mut state = self.state();
        let resource = state.arbitration.upstream_resolved(request)?;
        let durable = state.volatile.mode().durability() == Durability::Durable;
        drop(state);
        if durable {
            self.ledger().settle_pending(&resource, now)?;
        }
        Ok(resource)
    }

    /// Reconciles this host's records with what the upstream still has pending.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when a settled record cannot be written.
    pub fn reconcile(
        &self,
        still_open: &[kr_protocol::gateway::DownstreamRequestId],
        now: TimestampMs,
    ) -> Result<Reconciliation> {
        let mut state = self.state();
        let reconciliation = state.arbitration.reconcile(still_open);
        let changed: Vec<PendingResource> = reconciliation
            .uncertain
            .iter()
            .chain(&reconciliation.withdrawn)
            .chain(&reconciliation.released)
            .filter_map(|resource_id| {
                state
                    .arbitration
                    .get(*resource_id)
                    .map(|pending| pending.resource.clone())
            })
            .collect();
        let durable = state.volatile.mode().durability() == Durability::Durable;
        drop(state);
        if durable {
            let ledger = self.ledger();
            for resource in &changed {
                ledger.settle_pending(resource, now)?;
            }
        }
        Ok(reconciliation)
    }

    /// Returns one pending resource.
    #[must_use]
    pub fn pending(&self, resource_id: PendingResourceId) -> Option<PendingResource> {
        self.state()
            .arbitration
            .get(resource_id)
            .map(|pending| pending.resource.clone())
    }

    /// Returns every pending resource this broker currently holds.
    #[must_use]
    pub fn pending_resources(&self) -> Vec<PendingResource> {
        self.state()
            .arbitration
            .iter()
            .map(|pending| pending.resource.clone())
            .collect()
    }

    // -- adapter checkpoints ------------------------------------------------------------------

    /// Records the last semantic cursor one adapter consumed.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the write fails.
    pub fn checkpoint(
        &self,
        application_instance_id: ApplicationInstanceId,
        cursor: StreamCursor,
        now: TimestampMs,
    ) -> Result<()> {
        self.ledger()
            .put_checkpoint(application_instance_id, cursor, now)
    }

    /// Returns the cursor an adapter replays from after a restart.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn consumed_cursor(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<Option<StreamCursor>> {
        self.ledger().checkpoint(application_instance_id)
    }

    /// Mints the next gateway connection identifier.
    ///
    /// Downstream request identifiers are namespaced by it, so two connections that both start at
    /// one are two different sets of pending resources.
    pub fn next_connection(&self) -> GatewayConnectionId {
        let mut state = self.state();
        state.next_connection = state.next_connection.saturating_add(1);
        GatewayConnectionId::new(state.next_connection)
    }

    /// Builds a namespaced downstream identifier.
    #[must_use]
    pub fn downstream(
        connection: GatewayConnectionId,
        upstream: UpstreamRequestId,
    ) -> kr_protocol::gateway::DownstreamRequestId {
        kr_protocol::gateway::DownstreamRequestId::new(connection, upstream)
    }
}

/// A declared action name, or an argument failure that says why it is not one.
///
/// # Errors
///
/// Returns [`BrokerError::InvalidArgument`] when the text is not a valid action name.
pub fn action_name(text: &str) -> Result<ActionName> {
    ActionName::new(text).map_err(|error| BrokerError::invalid(format!("{text}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::gateway::{DownstreamRequestId, NativeMethodClass};
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};

    fn instance_id(byte: u8) -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([byte; 16]))
    }

    fn binding_id(byte: u8) -> BrokerBindingId {
        BrokerBindingId::new(Uuid::from_bytes([byte; 16]))
    }

    fn method() -> UpstreamMethod {
        UpstreamMethod::new("session/request_permission").expect("valid")
    }

    fn trust(may_encode: bool) -> DecodingTrust {
        DecodingTrust {
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            publisher_id: PublisherId::new("kalareach").expect("valid"),
            package_digest: Digest256::from_bytes([5; 32]),
            methods: [method()].into_iter().collect(),
            may_encode_response: may_encode,
            granted_at: TimestampMs::new(1),
        }
    }

    fn managed(instance: ApplicationInstanceId) -> ManagedProcess {
        let process = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
        ManagedProcess::new(
            instance,
            process.clone(),
            TransportHandle {
                transport: BrokerTransport::PrivateSocket,
                application_instance_id: instance,
                executable_digest: Digest256::from_bytes([3; 32]),
                process,
            },
            Credential::from_bytes([9; process::CREDENTIAL_BYTES]),
            true,
            TimestampMs::new(1),
        )
    }

    fn broker_with_binding(grants: BrokerGrants, trust: Option<DecodingTrust>) -> Broker {
        let broker = Broker::open(None).expect("the broker opens");
        broker.register_instance(
            instance_id(2),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance_id(2))),
        );
        broker
            .bind(
                binding_id(9),
                instance_id(2),
                PluginId::new("kalareach.codex").expect("valid"),
                PublisherId::new("kalareach").expect("valid"),
                Digest256::from_bytes([5; 32]),
                grants,
                trust,
                TimestampMs::new(1),
            )
            .expect("the binding is recorded");
        broker
    }

    fn request(id: &str) -> DownstreamRequestId {
        DownstreamRequestId::new(
            GatewayConnectionId::new(1),
            UpstreamRequestId::new(id).expect("valid"),
        )
    }

    #[test]
    fn a_display_only_component_cannot_create_an_approval() {
        let broker = broker_with_binding(BrokerGrants::granted([BrokerGrant::Observation]), None);
        let frame = broker
            .record_source(instance_id(2), b"{}", TimestampMs::new(2))
            .expect("the frame is recorded");
        let refusal = broker
            .offer_resource(
                binding_id(9),
                &frame,
                request("11"),
                method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(3),
            )
            .expect_err("a display-only component is refused");
        assert!(matches!(refusal, BrokerError::Grant(_)));
    }

    #[test]
    fn a_decoder_trusted_for_another_method_is_refused() {
        let broker = broker_with_binding(
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust(true)),
        );
        let frame = broker
            .record_source(instance_id(2), b"{}", TimestampMs::new(2))
            .expect("the frame is recorded");
        let refusal = broker
            .offer_resource(
                binding_id(9),
                &frame,
                request("11"),
                UpstreamMethod::new("fs/write_text_file").expect("valid"),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(3),
            )
            .expect_err("a method outside the trust record is refused");
        assert!(matches!(refusal, BrokerError::PermissionDenied { .. }));
    }

    #[test]
    fn one_source_event_becomes_one_resource() {
        let broker = broker_with_binding(
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust(true)),
        );
        let frame = broker
            .record_source(instance_id(2), b"{\"id\":11}", TimestampMs::new(2))
            .expect("the frame is recorded");
        broker
            .offer_resource(
                binding_id(9),
                &frame,
                request("11"),
                method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(3),
            )
            .expect("the first offer is accepted");
        let refusal = broker
            .offer_resource(
                binding_id(9),
                &frame,
                request("12"),
                method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(4),
            )
            .expect_err("the same source event cannot produce a second resource");
        assert!(matches!(refusal, BrokerError::PreconditionFailed { .. }));
    }

    #[test]
    fn a_frame_from_an_earlier_execution_owner_is_refused() {
        let broker = broker_with_binding(
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust(true)),
        );
        let frame = broker
            .record_source(instance_id(2), b"{\"id\":11}", TimestampMs::new(2))
            .expect("the frame is recorded");
        broker
            .advance_binding(instance_id(2), None)
            .expect("the thread changed");
        let refusal = broker
            .offer_resource(
                binding_id(9),
                &frame,
                request("11"),
                method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                2,
                None,
                TimestampMs::new(5),
            )
            .expect_err("a frame from the previous owner is refused");
        assert!(matches!(refusal, BrokerError::PreconditionFailed { .. }));
    }

    #[test]
    fn the_ledger_says_whose_interpretation_an_approval_is() {
        let broker = broker_with_binding(
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust(true)),
        );
        let frame = broker
            .record_source(instance_id(2), b"{\"id\":11}", TimestampMs::new(2))
            .expect("the frame is recorded");
        let resource = broker
            .offer_resource(
                binding_id(9),
                &frame,
                request("11"),
                method(),
                NativeClassification::declared(NativeMethodClass::Mutation),
                3,
                Some(TimestampMs::new(500)),
                TimestampMs::new(3),
            )
            .expect("the offer is accepted");
        let entry = broker
            .decoding(resource.resource_id)
            .expect("the read succeeds")
            .expect("the entry is recorded");
        assert_eq!(entry.publisher_id.as_str(), "kalareach");
        assert_eq!(entry.package_digest, Digest256::from_bytes([5; 32]));
        assert_eq!(entry.method, method());
        assert_eq!(entry.source_digest, frame.digest);
        assert_eq!(entry.offered_decisions.get(), 3);
        assert_eq!(entry.deadline_ms.as_ref().map(|at| at.get()), Some(500));
    }

    #[test]
    fn withdrawing_the_interpreter_grant_leaves_the_others() {
        let broker = broker_with_binding(
            BrokerGrants::granted([
                BrokerGrant::Observation,
                BrokerGrant::UpstreamAction,
                BrokerGrant::ApprovalInterpreter,
            ]),
            Some(trust(true)),
        );
        broker
            .withdraw_grant(binding_id(9), BrokerGrant::ApprovalInterpreter)
            .expect("the grant is withdrawn");
        let grants = broker.grants(binding_id(9)).expect("the binding is there");
        assert!(grants.holds(BrokerGrant::Observation));
        assert!(grants.holds(BrokerGrant::UpstreamAction));
        assert!(!grants.holds(BrokerGrant::ApprovalInterpreter));
    }

    #[test]
    fn a_native_exit_stops_the_backend_and_closing_an_attachment_does_not() {
        let broker = broker_with_binding(BrokerGrants::granted([BrokerGrant::Observation]), None);
        broker.attach(instance_id(2));
        broker.attach(instance_id(2));
        let closed = broker.end(instance_id(2), InstanceEnding::AttachmentClosed);
        assert!(!closed.instance_ended);
        assert!(!closed.stop_backend);
        assert_eq!(closed.attachments_remaining, 1);
        assert!(broker.binding_state(instance_id(2)).is_ok());

        let exited = broker.end(instance_id(2), InstanceEnding::NativeExit);
        assert!(exited.instance_ended);
        assert!(exited.stop_backend);
        assert!(broker.binding_state(instance_id(2)).is_err());
    }

    #[test]
    fn a_bypassed_backend_is_never_stopped_as_owned() {
        let broker = Broker::open(None).expect("the broker opens");
        broker.register_instance(instance_id(3), IntegrationMode::NativeTerminal, None, None);
        let exited = broker.end(instance_id(3), InstanceEnding::NativeExit);
        assert!(exited.instance_ended);
        assert!(
            !exited.stop_backend,
            "a backend this host did not launch is never claimed or terminated as owned"
        );
    }

    #[test]
    fn a_binding_that_advanced_withdraws_the_tokens_prepared_against_it() {
        let broker =
            broker_with_binding(BrokerGrants::granted([BrokerGrant::UpstreamAction]), None);
        let invocation = Invocation {
            actor_id: ActorId::new("device-1").expect("valid"),
            grant: BrokerGrant::UpstreamAction,
            grant_id: kr_protocol::ids::GrantId::new(Uuid::from_bytes([7; 16])),
            application_instance_id: instance_id(2),
            binding_revision: AgentBindingRevision::new(1),
            action: action_name("prompt.submit").expect("valid"),
            parameters: b"{}".to_vec(),
        };
        let token = broker
            .issue_token(binding_id(9), &invocation, TimestampMs::new(2))
            .expect("issued");
        broker
            .advance_binding(instance_id(2), None)
            .expect("the thread changed");
        assert!(
            broker.spend_token(&ActionTokenClaim::from(&token)).is_err(),
            "a token prepared against the old conversation is not authority over the new one"
        );
    }

    #[test]
    fn a_restart_recovers_what_was_unresolved() {
        let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        let path = directory.join("session.sqlite");
        let resource_id = {
            let broker = Broker::open(Some(&path)).expect("the broker opens");
            broker.register_instance(
                instance_id(2),
                IntegrationMode::Gateway,
                None,
                Some(managed(instance_id(2))),
            );
            broker
                .bind(
                    binding_id(9),
                    instance_id(2),
                    PluginId::new("kalareach.codex").expect("valid"),
                    PublisherId::new("kalareach").expect("valid"),
                    Digest256::from_bytes([5; 32]),
                    BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                    Some(trust(true)),
                    TimestampMs::new(1),
                )
                .expect("the binding is recorded");
            let frame = broker
                .record_source(instance_id(2), b"{\"id\":11}", TimestampMs::new(2))
                .expect("the frame is recorded");
            let resource = broker
                .offer_resource(
                    binding_id(9),
                    &frame,
                    request("11"),
                    method(),
                    NativeClassification::declared(NativeMethodClass::Mutation),
                    2,
                    None,
                    TimestampMs::new(3),
                )
                .expect("the offer is accepted");
            broker
                .claim(
                    resource.resource_id,
                    &ActorId::new("device-1").expect("valid"),
                    TimestampMs::new(4),
                )
                .expect("claimed");
            resource.resource_id
        };

        let restarted = Broker::open(Some(&path)).expect("the broker reopens");
        let recovered = restarted
            .pending(resource_id)
            .expect("the resource came back");
        assert_eq!(recovered.state, PendingState::Claimed);
        let reconciliation = restarted
            .reconcile(&[request("11")], TimestampMs::new(10))
            .expect("the reconnect reconciles");
        assert_eq!(reconciliation.uncertain, vec![resource_id]);
        assert!(
            restarted
                .claim(
                    resource_id,
                    &ActorId::new("device-1").expect("valid"),
                    TimestampMs::new(11)
                )
                .is_err(),
            "a reconnect never reissues an uncertain response"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}
