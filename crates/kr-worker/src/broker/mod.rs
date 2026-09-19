//! The trusted broker: the worker's own boundary between an upstream application and everything
//! that wants to say what that application is doing.
//!
//! Section 2 calls this a "serial dispatch broker", and the shape follows from that word. One lock
//! covers the whole of the broker's state **and its durable ledger**, and every decision that
//! depends on more than one part of them is one operation under that lock: check the grant, check
//! the binding revision, check the source is fresh, write the record, take the claim. Splitting
//! those would leave windows in which a check had passed and the thing it checked had already
//! changed, or in which memory was ahead of the ledger.
//!
//! Two orderings inside that lock are the whole durability contract.
//!
//! * **Validate, write, then apply.** Every state change is planned against the state as it is,
//!   written to the ledger conditionally on the state it expects to find, and only then applied in
//!   memory. A failed or racing write therefore leaves memory exactly as it was.
//! * **The dispatch marker is committed before the answer goes.** A crash between them leaves a
//!   record that says an answer may already have been sent, which is what stops a restart from
//!   sending a second one.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`arbitration`] | Pending resources, one resolution each, and what a reconnect does |
//! | [`capability`] | The per-installation capability map and the probes behind it |
//! | [`error`] | The broker's refusals, each mapped to a stable protocol code |
//! | [`gateway`] | The core-declarative forwarding path, the closed rich table and reverse calls |
//! | [`ledger`] | The durable records, in the worker's own journal file |
//! | [`methods`] | The agent-state reads, the five agent mutations and the plugin action call |
//! | [`listener`] | The private local endpoint, bridge registration and the pinned binary |
//! | [`process`] | Launched processes, their credentials and their immutable source frames |
//! | [`profiles`] | Launch profiles, the stale-launch refusal and one process per conversation |
//! | [`semantic`] | The observed entries, the consumed cursor and the gap an eviction leaves |
//! | [`tokens`] | Action tokens: issued per invocation, spent once |
//! | [`volatile`] | `native_only_volatile`: what is fenced, what continues, and the gap |
//!
//! What the broker will not do is as much of the contract as what it will. It does not let an
//! observation-only component create an approval. It does not believe a decoder that was not
//! granted trust for the exact package, method and projection schema it decoded. It does not let
//! the same source event become two resources. It does not paste a launch command into an
//! application that took the foreground. And it does not answer a request twice, whatever
//! reconnects.

pub mod arbitration;
pub mod capability;
pub mod error;
pub mod gateway;
pub mod ledger;
pub mod listener;
pub mod methods;
pub mod process;
pub mod profiles;
pub mod semantic;
pub mod tokens;
pub mod volatile;

use std::collections::BTreeMap;
use std::sync::Mutex;

use kr_protocol::agent::AgentBindingState;
use kr_protocol::broker::{
    ActionName, ActionProvenance, ActionToken, ActionTokenClaim, BrokerGrant, BrokerGrants,
    CapabilityInvalidation, CapabilityMap, CapabilityRecord, DecodedProjection, DecoderLedgerEntry,
    DecodingTrust, IntegrationMode, LaunchProfile, MAX_RETAINED_SOURCE_BYTES,
};
use kr_protocol::gateway::{
    DownstreamRequestId, Durability, PendingKind, PendingResource, PendingState,
};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, AgentThreadId, AgentTurnId, ApplicationInstanceId,
    BrokerBindingId, CapabilityId, CapabilityRevision, GatewayConnectionId, LaunchProfileId,
    PendingResourceId, PluginId, PublisherId, SessionId, SourceEventHandle, SourceGeneration,
    StreamCursor, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, Uuid};

pub use crate::broker::arbitration::{
    Arbitration, Claim, Pending, ReconcileScope, Reconciliation, Transition,
};
pub use crate::broker::capability::{CapabilityOwner, Probe};
pub use crate::broker::error::{BrokerError, Result};
pub use crate::broker::gateway::{
    Connection, ConnectionOrigin, Forwarded, Gateway, ReverseRequest, RichInvocation,
};
pub use crate::broker::ledger::{BindingRecord, Ledger, UnresolvedRecord};
pub use crate::broker::listener::{
    BoundBinary, BridgeHello, ListenerAddress, Registration, reject_browser_origin,
};
pub use crate::broker::methods::{
    Caller, RegisteredAction, UpstreamDispatch, UpstreamOperation, UpstreamOutcome,
    UpstreamRequest, command, subject,
};
pub use crate::broker::process::{
    BrokerTransport, Credential, ManagedProcess, SourceFrame, TransportHandle,
};
pub use crate::broker::profiles::{ForegroundMark, LaunchIntent, ProfileStore, new_profile_id};
pub use crate::broker::semantic::{GrantLowerBound, HistoryFilter, Replay, SemanticLog};
pub use crate::broker::tokens::{Invocation, TokenStore};
pub use crate::broker::volatile::{VolatileState, VolatileTransition};

/// How many source frames one instance holds while it waits for a decoder to read them.
///
/// A frame is released when it is consumed, so the bound is on what has not been interpreted. A
/// connector that never decodes anything is a connector whose oldest frames this host forgets
/// rather than a session whose memory grows for the rest of the day.
pub const MAX_RETAINED_FRAMES: usize = 64;

/// How many bytes of unconsumed source frames one instance holds.
pub const MAX_RETAINED_FRAME_BYTES: usize = 4 * 1024 * 1024;

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
    /// The actions this package registered, by name.
    pub actions: BTreeMap<ActionName, RegisteredAction>,
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
        self.rich_disabled.is_none()
            && self.grants.holds(BrokerGrant::ApprovalInterpreter)
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
    /// The generation of the source frames this instance is producing.
    ///
    /// It lives here rather than on the process, so an instance the host did not launch still gets
    /// a new generation when its binding changes.
    pub source_generation: SourceGeneration,
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
    /// What carries a prepared operation to this instance's upstream, where anything does.
    dispatch: Option<std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>>,
    /// How many KalaReach attachments are watching it.
    ///
    /// Closing one does not end the process. Section 7: "Closing a KR attachment does not end the
    /// TUI process in the worker PTY."
    pub attachments: usize,
    /// What this instance has been observed doing, and the cursor an adapter replays from.
    semantic: crate::broker::semantic::SemanticLog,
    /// The commands the upstream advertises.
    commands: Vec<kr_protocol::agent::AgentCommand>,
    /// The unconsumed source frames the broker is holding for this instance's decoders.
    frames: BTreeMap<SourceEventHandle, SourceFrame>,
    /// The order those frames arrived in, so the oldest is the one that goes.
    frame_order: std::collections::VecDeque<SourceEventHandle>,
    /// How many bytes those frames hold.
    frame_bytes: usize,
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

    /// Holds one frame, forgetting the oldest unconsumed ones if it must.
    fn retain(&mut self, frame: SourceFrame) {
        self.frame_bytes = self.frame_bytes.saturating_add(frame.bytes().len());
        self.frame_order.push_back(frame.handle.clone());
        self.frames.insert(frame.handle.clone(), frame);
        while self.frames.len() > MAX_RETAINED_FRAMES || self.frame_bytes > MAX_RETAINED_FRAME_BYTES
        {
            let Some(oldest) = self.frame_order.pop_front() else {
                break;
            };
            self.release(&oldest);
        }
    }

    /// Forgets one frame, because it has been consumed or evicted.
    fn release(&mut self, handle: &SourceEventHandle) {
        if let Some(frame) = self.frames.remove(handle) {
            self.frame_bytes = self.frame_bytes.saturating_sub(frame.bytes().len());
        }
        self.frame_order.retain(|held| held != handle);
    }

    /// Advances the source generation and forgets the frames of the execution that has gone.
    fn advance_generation(&mut self) {
        self.source_generation =
            SourceGeneration::new(self.source_generation.get().saturating_add(1));
        self.frames.clear();
        self.frame_order.clear();
        self.frame_bytes = 0;
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

/// Permission to write one answer to the upstream, once.
///
/// It exists only as the return value of [`Broker::admit_dispatch`], which commits the durable
/// marker before it hands one out, so a caller holding this is a caller whose answer the ledger
/// already says may have gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchAdmission {
    /// The resource being answered, as it stands.
    pub resource: PendingResource,
    /// The decision, checked against the ones the request offered.
    pub option_id: String,
    /// The upstream method the original request named.
    pub method: UpstreamMethod,
    /// The upstream's own identifier for it.
    pub upstream_request_id: UpstreamRequestId,
    /// How this answer reaches the upstream, and therefore how it is recorded.
    ///
    /// Section 12 requires every action to record its provenance. An answer admitted here goes
    /// over the gateway's typed connection, so it is a typed result; the app may also offer a
    /// terminal convenience, and that one records itself as terminal input and never as this.
    pub provenance: ActionProvenance,
}

/// What stopping an instance actually does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopOutcome {
    /// True when the instance's record was removed.
    pub instance_ended: bool,
    /// The backend to stop, by full process identity, when this host owns one.
    ///
    /// It is the identity rather than a flag because the supervisor has to know *which* process to
    /// stop, and a process identifier alone can already belong to something else. A bypassed or
    /// shared backend is never claimed or terminated as owned, so this is absent for one of those
    /// however the instance ended.
    pub backend: Option<ProcessStartIdentity>,
    /// How many attachments are still watching.
    pub attachments_remaining: usize,
}

/// The broker's whole state and its ledger, behind one lock.
#[derive(Debug)]
struct BrokerState {
    session_id: SessionId,
    ledger: Ledger,
    gateway: Gateway,
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
}

impl Broker {
    /// Opens a broker whose durable records live beside the worker's receipt journal.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the ledger cannot be opened or read.
    pub fn open(journal_path: Option<&std::path::Path>, session_id: SessionId) -> Result<Self> {
        let ledger = Ledger::open(journal_path)?;
        let mut arbitration = Arbitration::new();
        // A restarted worker starts from what it wrote, not from nothing. The dispatch marker is
        // read back with each resource: one that was answered comes back so a reconnect can
        // reconcile it to uncertain, and one that was not comes back answerable.
        for record in ledger.unresolved()? {
            arbitration.restore(record.resource, record.dispatched, record.decoder);
        }
        let mut profiles = ProfileStore::new();
        profiles.restore(ledger.profiles()?);
        Ok(Self {
            state: Mutex::new(BrokerState {
                session_id,
                ledger,
                gateway: Gateway::new(),
                instances: BTreeMap::new(),
                bindings: BTreeMap::new(),
                tokens: TokenStore::new(),
                profiles,
                arbitration,
                capabilities: CapabilityOwner::new(),
                volatile: VolatileState::new(),
                next_connection: 0,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BrokerState> {
        self.state.lock().expect("the broker lock is not poisoned")
    }

    // -- instances ----------------------------------------------------------------------------

    /// Registers one managed application instance.
    ///
    /// Its semantic numbering resumes after whatever cursor an adapter last checkpointed, so a
    /// restarted worker never issues a cursor an adapter has already passed, and a replay from
    /// before the restart is a visible gap rather than a silently empty answer.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the checkpoint cannot be read.
    pub fn register_instance(
        &self,
        application_instance_id: ApplicationInstanceId,
        mode: IntegrationMode,
        profile_id: Option<LaunchProfileId>,
        process: Option<ManagedProcess>,
    ) -> Result<()> {
        let consumed = self.state().ledger.checkpoint(application_instance_id)?;
        let mut semantic = crate::broker::semantic::SemanticLog::new();
        if let Some(consumed) = consumed {
            semantic.resume_after(consumed);
        }
        self.state().instances.insert(
            application_instance_id,
            Instance {
                application_instance_id,
                process,
                binding_revision: AgentBindingRevision::new(1),
                source_generation: SourceGeneration::new(1),
                thread_id: None,
                turn_id: None,
                mode,
                profile_id,
                rich_suspension: None,
                dispatch: None,
                attachments: 0,
                semantic,
                commands: Vec::new(),
                frames: BTreeMap::new(),
                frame_order: std::collections::VecDeque::new(),
                frame_bytes: 0,
            },
        );
        Ok(())
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
            .ok_or_else(|| unknown_instance(application_instance_id))
    }

    /// Advances the binding revision, because the upstream owner or selected thread changed.
    ///
    /// Everything prepared against the old revision stops being authority at this moment: the
    /// tokens are withdrawn, the source generation moves on so an older frame cannot become a
    /// resource, the evidence gathered through the old binding is invalidated, and the
    /// conversation this instance owns moves with it, so the conversation it left is free and the
    /// one it took is not.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance, and
    /// [`BrokerError::Launch`] when another live execution already owns the conversation being
    /// selected.
    pub fn advance_binding(
        &self,
        application_instance_id: ApplicationInstanceId,
        thread_id: Option<AgentThreadId>,
        now: TimestampMs,
    ) -> Result<AgentBindingRevision> {
        let mut state = self.state();
        if !state.instances.contains_key(&application_instance_id) {
            return Err(unknown_instance(application_instance_id));
        }
        // The conversation moves first, because it is the check that can refuse. Advancing a
        // revision and then finding the conversation taken would leave the instance at a revision
        // whose thread it does not own.
        if let Some(thread) = thread_id.as_ref() {
            state
                .profiles
                .select_conversation(application_instance_id, thread.as_str())?;
        } else {
            state.profiles.leave_conversation(application_instance_id);
        }
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        instance.binding_revision =
            AgentBindingRevision::new(instance.binding_revision.get().saturating_add(1));
        instance.thread_id = thread_id;
        instance.turn_id = None;
        instance.advance_generation();
        let revision = instance.binding_revision;
        state.tokens.withdraw(application_instance_id);
        state.capabilities.invalidate_instance(
            application_instance_id,
            CapabilityInvalidation::BindingChanged,
            "the upstream owner or selected thread changed",
            now,
        );
        Ok(revision)
    }

    /// Records the turn the upstream says is running.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn set_turn(
        &self,
        application_instance_id: ApplicationInstanceId,
        turn_id: Option<AgentTurnId>,
    ) -> Result<()> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        instance.turn_id = turn_id;
        Ok(())
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
            .ok_or_else(|| unknown_instance(application_instance_id))?;
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
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        instance.rich_suspension = None;
        Ok(())
    }

    /// Binds what carries prepared operations to one instance's upstream.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn bind_dispatch(
        &self,
        application_instance_id: ApplicationInstanceId,
        dispatch: std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>,
    ) -> Result<()> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        instance.dispatch = Some(dispatch);
        Ok(())
    }

    /// Returns what carries operations to one instance's upstream, where anything does.
    #[must_use]
    pub fn dispatch_for(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>> {
        self.state()
            .instances
            .get(&application_instance_id)
            .and_then(|instance| instance.dispatch.clone())
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
    /// agent, and closing the window you were watching it through does not. The outcome names the
    /// process to stop by its full identity, so the supervisor stops the process this host started
    /// rather than whatever holds that identifier now.
    pub fn end(
        &self,
        application_instance_id: ApplicationInstanceId,
        ending: InstanceEnding,
    ) -> StopOutcome {
        let mut state = self.state();
        let Some(instance) = state.instances.get_mut(&application_instance_id) else {
            return StopOutcome {
                instance_ended: false,
                backend: None,
                attachments_remaining: 0,
            };
        };
        match ending {
            InstanceEnding::AttachmentClosed => {
                instance.attachments = instance.attachments.saturating_sub(1);
                StopOutcome {
                    instance_ended: false,
                    backend: None,
                    attachments_remaining: instance.attachments,
                }
            }
            InstanceEnding::NativeExit => {
                let backend = instance
                    .process
                    .as_ref()
                    .and_then(|process| process.dedicated.then(|| process.process.clone()));
                state.instances.remove(&application_instance_id);
                state.tokens.withdraw(application_instance_id);
                state.profiles.release(application_instance_id);
                state.capabilities.forget(application_instance_id);
                state.bindings.retain(|_, binding| {
                    binding.application_instance_id != application_instance_id
                });
                StopOutcome {
                    instance_ended: true,
                    backend,
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
    /// Returns [`BrokerError::Trust`] when a trust record breaks a rule,
    /// [`BrokerError::PermissionDenied`] when the trust was granted to a different package or the
    /// grant it depends on is absent, and [`BrokerError::LedgerUnavailable`] when the record
    /// cannot be written.
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
            // And trust granted to one package is never another's. Without this check the ledger
            // would record the bound package's identity beside an interpretation the trust was
            // never granted for, which is the mismatch the ledger exists to make visible.
            if !trust.belongs_to(&plugin_id, &publisher_id, &package_digest) {
                return Err(BrokerError::denied(format!(
                    "this decoding trust was granted to {} at another digest, not to {plugin_id}",
                    trust.plugin_id
                )));
            }
        }
        let mut state = self.state();
        state.ledger.put_binding(&BindingRecord {
            binding_id,
            application_instance_id,
            grants: grants.clone(),
            trust: trust.clone(),
            bound_at: now,
        })?;
        state.bindings.insert(
            binding_id,
            Binding {
                binding_id,
                application_instance_id,
                plugin_id,
                publisher_id,
                package_digest,
                grants,
                trust,
                actions: BTreeMap::new(),
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
            .ok_or_else(|| unknown_binding(binding_id))
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
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        let mut grants = binding.grants.clone();
        grants.remove(grant);
        // Withdrawing the interpreter grant withdraws what depended on it. Leaving the trust
        // record behind would leave a record the broker would refuse to act on anyway, and a
        // record nobody acts on is one somebody will eventually read as permission.
        let trust = if grant == BrokerGrant::ApprovalInterpreter {
            None
        } else {
            binding.trust.clone()
        };
        let record = BindingRecord {
            binding_id,
            application_instance_id: binding.application_instance_id,
            grants: grants.clone(),
            trust: trust.clone(),
            bound_at: TimestampMs::new(0),
        };
        state.ledger.put_binding(&record)?;
        let binding = state
            .bindings
            .get_mut(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        binding.grants = grants;
        binding.trust = trust;
        Ok(())
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
    ) -> Result<SourceEventHandle> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let handle = SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid()))
            .map_err(|error| BrokerError::invalid(format!("source handle: {error}")))?;
        let frame = SourceFrame::new(handle.clone(), instance.source_generation, bytes, now)?;
        instance.retain(frame);
        Ok(handle)
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

    /// Records one opaque native request before it is forwarded, and forwards it.
    ///
    /// Section 11: "The broker records opaque native requests before forwarding them and
    /// arbitrates responses by their IDs." What is recorded is the request, not an approval: its
    /// interpretation is not verified, so no client may offer it as something a person answers.
    /// A request the table does not classify also suspends the instance's rich mutations, because
    /// nothing here knows what it did.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the connection is not a worker-launched
    /// native one, [`BrokerError::InvalidArgument`] when the frame is not one the table describes,
    /// and [`BrokerError::LedgerUnavailable`] when a durable record cannot be written.
    pub fn forward_native(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
        now: TimestampMs,
    ) -> Result<(Forwarded, Option<PendingResource>)> {
        let mut state = self.state();
        let forwarded = state.gateway.forward_native(connection, frame)?;
        let application_instance_id = state
            .gateway
            .connection(connection)
            .map(|held| held.application_instance_id)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        // The native path keeps working while the journal is faulted. What the gap records is
        // that it did.
        state.volatile.note_native_request();

        if forwarded.suspends_rich_mutations
            && let Some(instance) = state.instances.get_mut(&application_instance_id)
        {
            instance.rich_suspension = Some(format!(
                "{} is not classified by this connector's table, so what it changed is unknown",
                forwarded.method
            ));
        }

        let Some(request) = forwarded.request.clone() else {
            return Ok((forwarded, None));
        };
        if !forwarded.expects_response {
            return Ok((forwarded, None));
        }
        // The frame *is* the source event, and the broker records it here rather than trusting a
        // caller to record it and then to name the right one. That is what ties an interpretation
        // to the bytes it is an interpretation of.
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let source_generation = instance.source_generation;
        let source = SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid()))
            .map_err(|error| BrokerError::invalid(format!("source handle: {error}")))?;
        instance.retain(SourceFrame::new(
            source.clone(),
            source_generation,
            frame,
            now,
        )?);
        let resource = PendingResource {
            resource_id: PendingResourceId::new(Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes())),
            application_instance_id,
            request,
            kind: PendingKind::ReverseRpc,
            method: forwarded.method.clone(),
            classification: forwarded.classification,
            source_generation,
            state: PendingState::Pending,
            durability: state.volatile.durability(),
            deadline_ms: Nullable::null(),
            recorded_at: now,
            // Opaque. A decoder's verified interpretation is what makes it answerable.
            interpretation_verified: false,
        };
        if resource.durability == Durability::Durable {
            state.ledger.record_opaque(&resource)?;
        }
        state
            .arbitration
            .record(resource.clone(), None, Some(source))?;
        Ok((forwarded, Some(resource)))
    }

    /// Records the answer the upstream produced for one of its own requests.
    ///
    /// This is what makes a native answer win during encoding: it resolves the pending resource,
    /// and a rich answer that reaches the claim afterwards is told the resolved state.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the response carries no correlation
    /// identifier, and [`BrokerError::Arbitration`] when the resource has already ended.
    pub fn native_answer(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
        now: TimestampMs,
    ) -> Result<PendingResource> {
        let mut state = self.state();
        let request = state.gateway.correlate_response(connection, frame)?;
        state.volatile.note_native_response();
        let transition = state.arbitration.plan_upstream_resolved(&request)?;
        state.write_transition(&transition, now)?;
        state.arbitration.commit(transition)
    }

    /// Verifies a decoder's interpretation of a request this broker already holds.
    ///
    /// The checks are made in this order, and the order is the argument:
    ///
    /// 1. **Role.** Does this binding hold the approval-interpreter grant, is there a trust record
    ///    granted to this exact package, and does it cover this method? A display-only component
    ///    stops here.
    /// 2. **Schema policy.** Is the projection written against a schema version the trust covers,
    ///    with decisions this trust permits? An interpretation outside the policy is not one this
    ///    trust was granted for.
    /// 3. **Binding and generation.** The frame is looked up by its handle in this binding's own
    ///    instance, so nothing the caller says about its generation or digest is believed, and a
    ///    frame from an execution that has gone is refused.
    /// 4. **Non-reuse.** Consuming the source, recording the decoder and making the row actionable
    ///    are one transaction, keyed by the broker's own event identity. A decoder gets one
    ///    interpretation per event, and the claim is durable so a restart does not reopen it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Grant`] or [`BrokerError::PermissionDenied`] for a role the binding
    /// does not have, [`BrokerError::Trust`] for a projection outside the schema policy,
    /// [`BrokerError::UnknownSubject`] for a binding, instance or resource this broker does not
    /// hold, and [`BrokerError::PreconditionFailed`] for a stale generation or a reused source.
    pub fn interpret(
        &self,
        binding_id: BrokerBindingId,
        resource_id: PendingResourceId,
        projection: DecodedProjection,
        deadline_ms: Option<TimestampMs>,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        let mut state = self.state();
        // Interpreting a request into something a person answers is rich work. While the journal
        // is faulted the native forwarding path continues and this does not.
        state.volatile.require_rich_work()?;
        let binding = state
            .bindings
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        if !binding.grants.holds(BrokerGrant::ApprovalInterpreter) {
            return Err(BrokerError::Grant(
                kr_protocol::broker::GrantError::NotHeld {
                    grant: BrokerGrant::ApprovalInterpreter,
                },
            ));
        }
        if let Some(reason) = binding.rich_disabled.as_ref() {
            return Err(BrokerError::UnsupportedCapability {
                detail: format!("this binding's rich capabilities are disabled: {reason}"),
            });
        }
        let pending = state
            .arbitration
            .get(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?
            .resource
            .clone();
        if pending.state != PendingState::Pending {
            return Err(BrokerError::Arbitration(
                kr_protocol::gateway::ArbitrationError::AlreadyResolved {
                    state: pending.state,
                },
            ));
        }
        let binding = state
            .bindings
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        if binding.application_instance_id != pending.application_instance_id {
            return Err(BrokerError::denied(format!(
                "binding {binding_id} is not bound to {}",
                pending.application_instance_id
            )));
        }
        if !binding.may_decode(&pending.method) {
            return Err(BrokerError::denied(format!(
                "this binding is not trusted to decode {}",
                pending.method
            )));
        }
        let trust = binding
            .trust
            .as_ref()
            .ok_or_else(|| BrokerError::denied("this binding holds no decoding trust"))?;
        trust.check_projection(&projection)?;
        let plugin_id = binding.plugin_id.clone();
        let publisher_id = binding.publisher_id.clone();
        let package_digest = binding.package_digest;
        let application_instance_id = pending.application_instance_id;

        // The frame is the one *this request* was recorded from. A caller naming any other would
        // put one request's bytes in another's ledger row, so it does not get to name one.
        let handle = state
            .arbitration
            .source_of(resource_id)
            .cloned()
            .ok_or_else(|| BrokerError::PreconditionFailed {
                detail: format!("{resource_id} was not recorded from a source event of its own"),
            })?;
        let handle = &handle;
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let frame = instance.frames.get(handle).cloned().ok_or_else(|| {
            BrokerError::PreconditionFailed {
                detail: format!(
                    "source event {handle} has already been consumed, so {resource_id} has already \
                     been interpreted"
                ),
            }
        })?;
        if frame.generation != instance.source_generation {
            return Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "source event {handle} is from generation {} and the binding is at {}",
                    frame.generation, instance.source_generation
                ),
            });
        }
        // Section 11 requires the ledger to retain the original source, and a partial copy is not
        // the original. A request too large to keep whole is not turned into an approval: it is
        // still forwarded opaquely on the native path, which depends on nothing this host stores.
        if frame.bytes().len() > MAX_RETAINED_SOURCE_BYTES {
            return Err(BrokerError::UnsupportedCapability {
                detail: format!(
                    "source event {handle} is {} bytes and an approval's original source is \
                     retained whole up to {MAX_RETAINED_SOURCE_BYTES}",
                    frame.bytes().len()
                ),
            });
        }

        let entry = DecoderLedgerEntry {
            binding_id,
            plugin_id,
            publisher_id,
            package_digest,
            method: pending.method.clone(),
            upstream_request_id: pending.request.upstream.clone(),
            source_generation: frame.generation,
            source_digest: frame.digest,
            source_bytes: Bytes::from(frame.bytes().to_vec()),
            projection,
            deadline_ms: Nullable::from(deadline_ms),
            decoded_at: now,
        };
        let interpreted = PendingResource {
            kind: PendingKind::Approval,
            deadline_ms: Nullable::from(deadline_ms),
            interpretation_verified: true,
            ..pending
        };
        let admitted =
            state
                .ledger
                .admit_resource(handle, binding_id, &entry, &interpreted, now)?;
        if !admitted {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("source event {handle} has already produced an interpretation"),
            });
        }
        state
            .arbitration
            .set_interpretation(resource_id, interpreted.clone(), binding_id)?;
        if let Some(instance) = state.instances.get_mut(&application_instance_id) {
            instance.release(handle);
        }
        Ok(interpreted)
    }

    /// Returns the decoder entry behind one pending resource.
    ///
    /// This is what a person is shown beside an approval: whose package interpreted which bytes,
    /// the bytes themselves, and the exact decisions it offered.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the record cannot be read.
    pub fn decoding(&self, resource_id: PendingResourceId) -> Result<Option<DecoderLedgerEntry>> {
        self.state().ledger.decoding(resource_id)
    }

    // -- action tokens ------------------------------------------------------------------------

    /// Issues an action token for one invocation.
    ///
    /// Everything the invocation names is checked against what this broker holds *now*: that the
    /// binding is bound to the instance the invocation acts on, that the binding holds the grant,
    /// that its rich capabilities are not disabled, that the instance is not suspended, and that
    /// the revision the caller prepared against is the one in force.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when the binding or instance is unknown,
    /// [`BrokerError::Grant`] when the grant is not held, [`BrokerError::StaleBinding`] when the
    /// revision has moved, and [`BrokerError::RichWorkFenced`] when rich work is fenced.
    pub fn issue_token(
        &self,
        binding_id: BrokerBindingId,
        invocation: &Invocation,
        now: TimestampMs,
    ) -> Result<ActionToken> {
        let mut state = self.state();
        state.volatile.require_rich_work()?;
        let grants = state.check_invocation(binding_id, invocation)?;
        state.tokens.issue(binding_id, &grants, invocation, now)
    }

    /// Spends an action token against a returned effect plan.
    ///
    /// The bindings are checked, then the authority is checked again against the present: the
    /// issuing binding still exists, still holds the grant it was issued under, is not disabled,
    /// and the instance is still live, unsuspended and at the revision the token names.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Token`] when the token is unknown, spent, or bound to something
    /// other than what was presented, and the same authority failures [`Broker::issue_token`]
    /// returns.
    pub fn spend_token(&self, claim: &ActionTokenClaim) -> Result<ActionToken> {
        let mut state = self.state();
        state.volatile.require_rich_work()?;
        let (token, binding_id, capability) = state.tokens.spend_checked(claim)?;
        // The token has been consumed. Whatever follows, it cannot be spent again, so a failed
        // authority check costs the caller its invocation rather than giving it another attempt.
        let invocation = Invocation {
            actor_id: token.actor_id.clone(),
            grant: token.grant,
            grant_id: token.grant_id.as_ref().copied(),
            application_instance_id: token.application_instance_id,
            binding_revision: token.binding_revision,
            action: token.action.clone(),
            capability: capability.clone(),
            parameters: Vec::new(),
        };
        state.check_invocation(binding_id, &invocation)?;
        Ok(token)
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
        let mut state = self.state();
        let intent = state
            .profiles
            .prepare(profile, against, saved_conversation)?;
        state.ledger.put_profile(&intent.profile, None)?;
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
        let mut state = self.state();
        let profile = state
            .profiles
            .execute(intent, now, application_instance_id)?;
        state
            .ledger
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
        let mut state = self.state();
        state
            .profiles
            .adopt(profile.clone(), application_instance_id, saved_conversation);
        state
            .ledger
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

    /// Returns which instance owns the live execution of one saved conversation.
    #[must_use]
    pub fn conversation_owner(&self, saved_conversation: &str) -> Option<ApplicationInstanceId> {
        self.state().profiles.owner_of(saved_conversation)
    }

    // -- capability evidence ------------------------------------------------------------------

    /// Records one capability record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Capability`] when the record breaks a rule or is not newer than the
    /// one held.
    pub fn record_capability(&self, record: CapabilityRecord) -> Result<()> {
        let mut state = self.state();
        state.check_evidence_identity(&record)?;
        state.capabilities.record(record)
    }

    /// Records the result of a probe the host ran.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the probe was not one the host would run.
    pub fn record_probe(&self, probe: &Probe, record: CapabilityRecord) -> Result<()> {
        let mut state = self.state();
        state.check_evidence_identity(&record)?;
        state.capabilities.record_probe(probe, record)
    }

    /// Returns one installation's capability map.
    #[must_use]
    pub fn capabilities(&self, application_instance_id: ApplicationInstanceId) -> CapabilityMap {
        self.state().capabilities.map(application_instance_id)
    }

    /// Invalidates every record one change makes stale.
    pub fn invalidate_capabilities(
        &self,
        change: CapabilityInvalidation,
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
        capability_id: &CapabilityId,
        read_at: Option<CapabilityRevision>,
    ) -> Result<()> {
        self.state()
            .capabilities
            .recheck(application_instance_id, capability_id, read_at)
            .map(|_| ())
    }

    // -- arbitration --------------------------------------------------------------------------

    /// Takes the claim on one pending resource.
    ///
    /// The recheck covers everything that could have changed while the answer was being encoded:
    /// the resource's own state, its deadline, the instance it belongs to, the generation that
    /// produced it, and whether the decoder that interpreted it may still encode an answer.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] when the resource is already claimed or resolved, and
    /// [`BrokerError::PreconditionFailed`] or [`BrokerError::PermissionDenied`] when one of the
    /// rechecks fails.
    pub fn claim(
        &self,
        resource_id: PendingResourceId,
        actor_id: &ActorId,
        now: TimestampMs,
    ) -> Result<Claim> {
        let mut state = self.state();
        state.volatile.require_rich_work()?;
        state.recheck_answerable(resource_id)?;
        let transition = state.arbitration.plan_claim(resource_id, actor_id, now)?;
        let claim = transition
            .claim()
            .cloned()
            .ok_or_else(|| BrokerError::invalid("a claim transition carries a claim"))?;
        state.write_transition(&transition, now)?;
        state.arbitration.commit(transition)?;
        Ok(claim)
    }

    /// Admits one answer to dispatch, and commits the marker before it goes.
    ///
    /// This is the last gate before bytes reach the upstream, and it is one operation because
    /// everything it checks can change between the claim and the dispatch. Under the lock it
    /// rechecks that rich work is admitted at all, that the resource is still answerable by this
    /// claim, that the decision is one the upstream actually offered, and that no answer has gone
    /// already; then it commits the durable marker. A caller that holds the returned admission may
    /// write the answer, and nothing else may.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::RichWorkFenced`] while rich work is fenced,
    /// [`BrokerError::PermissionDenied`] when another claim holds the resource or its decoder may
    /// no longer answer, [`BrokerError::PreconditionFailed`] when the decision is not one the
    /// request offered, [`BrokerError::Arbitration`] when an answer has already been admitted, and
    /// [`BrokerError::LedgerUnavailable`] when the marker cannot be committed.
    pub fn admit_dispatch(&self, claim: &Claim, option_id: &str) -> Result<DispatchAdmission> {
        let mut state = self.state();
        // Fenced rich work is fenced here too. Without this a claim taken before the journal
        // faulted could dispatch inside the gap, with no durable marker to stop a second answer.
        state.volatile.require_rich_work()?;
        state.recheck_answerable(claim.resource_id)?;
        let entry = state.ledger.decoding(claim.resource_id)?.ok_or_else(|| {
            BrokerError::PreconditionFailed {
                detail: format!(
                    "{} has no recorded interpretation, so there is nothing to answer",
                    claim.resource_id
                ),
            }
        })?;
        if !entry.offers(option_id) {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("{option_id} is not one of the decisions this request offered"),
            });
        }
        let transition = state.arbitration.plan_dispatch(claim)?;
        state.ledger.mark_dispatched(&transition.resource)?;
        let resource = state.arbitration.commit(transition)?;
        let provenance = state
            .gateway
            .provenance(resource.request.connection)
            .unwrap_or(ActionProvenance::UpstreamTypedRpc);
        Ok(DispatchAdmission {
            resource,
            option_id: option_id.to_owned(),
            method: entry.method,
            upstream_request_id: entry.upstream_request_id,
            provenance,
        })
    }

    /// Resolves a claimed resource: the upstream confirmed the answer.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] or [`BrokerError::PermissionDenied`] as the claim
    /// requires.
    pub fn resolve(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_resolve(claim)?;
        state.write_transition(&transition, now)?;
        state.arbitration.commit(transition)
    }

    /// Gives a claim back, because nothing was dispatched under it.
    ///
    /// A caller whose answer was refused between the claim and the dispatch releases it here, so
    /// the resource is answerable again rather than stuck behind a claim nobody will spend.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] when an answer has already gone for the resource.
    pub fn release_claim(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_release(claim)?;
        state.write_transition(&transition, now)?;
        state.arbitration.commit(transition)
    }

    /// Leaves a claimed resource uncertain: an answer went and nothing confirmed it.
    ///
    /// # Errors
    ///
    /// Returns the same failures [`Broker::resolve`] does.
    pub fn uncertain(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_uncertain(claim)?;
        state.write_transition(&transition, now)?;
        state.arbitration.commit(transition)
    }

    /// Records that the upstream answered or withdrew a request itself.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] or [`BrokerError::Arbitration`] as the state
    /// requires.
    pub fn upstream_resolved(
        &self,
        request: &DownstreamRequestId,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_upstream_resolved(request)?;
        state.write_transition(&transition, now)?;
        state.arbitration.commit(transition)
    }

    /// Reconciles one upstream's records with what it still has pending.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when a settled record cannot be written.
    pub fn reconcile(
        &self,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
        now: TimestampMs,
    ) -> Result<Reconciliation> {
        self.reconcile_within(scope, still_open, now)
    }

    fn reconcile_within(
        &self,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
        now: TimestampMs,
    ) -> Result<Reconciliation> {
        let mut state = self.state();
        let (reconciliation, transitions) = state.arbitration.plan_reconcile(scope, still_open);
        for transition in transitions {
            state.write_transition(&transition, now)?;
            state.arbitration.commit(transition)?;
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

    /// Returns what the ledger records about one resource, resolved or not.
    ///
    /// [`Broker::pending`] reads the live arbitration, which holds what can still happen. This
    /// reads what was written down, which is how a resolved or uncertain resource is inspected
    /// after the live record has gone.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the read fails.
    pub fn recorded(&self, resource_id: PendingResourceId) -> Result<Option<PendingResource>> {
        self.state().ledger.pending(resource_id)
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

    // -- volatile-native mode -----------------------------------------------------------------

    /// Refuses a rich operation while rich work is fenced, and counts the refusal in the gap.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::RichWorkFenced`] while the gateway is fenced or recovering.
    pub fn require_rich_work(&self) -> Result<()> {
        let mut state = self.state();
        if let Err(error) = state.volatile.require_rich_work() {
            state.volatile.note_fenced();
            return Err(error);
        }
        Ok(())
    }

    /// Returns the gateway's current durability mode.
    #[must_use]
    pub fn mode(&self) -> kr_protocol::gateway::GatewayMode {
        self.state().volatile.mode()
    }

    /// Returns the evidence gap that is open, while one is.
    #[must_use]
    pub fn gap(&self) -> Option<kr_protocol::gateway::EvidenceGap> {
        self.state().volatile.gap().cloned()
    }

    /// Enters volatile-native mode, atomically.
    ///
    /// One operation fences the rich work, marks every unresolved resource volatile, counts the
    /// identifiers that must never be answered twice and opens the gap. Nothing is admitted
    /// between those steps because there are no steps between them.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is already fenced.
    pub fn enter_volatile(
        &self,
        reason: impl Into<String>,
        now: TimestampMs,
    ) -> Result<VolatileTransition> {
        let mut state = self.state();
        let (carried, _) = state.arbitration.enter_volatile();
        let transition = state.volatile.enter(reason, carried, now)?;
        // The gap's own record is written if the ledger will take it. It usually will not, which
        // is why the mode exists; a gap nobody could write is still exposed in memory and is
        // committed when storage returns.
        if let Ok(row) = state.ledger.open_gap(&transition.gap) {
            state.volatile.set_row(row);
        }
        Ok(transition)
    }

    /// Commits the gap and reconciles what lived inside it, then restores rich work.
    ///
    /// Recovery is two steps because it can fail halfway. `begin` says storage is back; this
    /// commits the gap and the resources that lived in it, and only then does rich work resume.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not fenced, and
    /// [`BrokerError::LedgerUnavailable`] when the gap cannot be committed, in which case the
    /// gateway falls back to the fence rather than claiming to have recovered.
    pub fn recover(&self, now: TimestampMs) -> Result<VolatileTransition> {
        let mut state = self.state();
        let beginning = state.volatile.begin_recovery(now)?;
        let records = state.arbitration.volatile_records();
        let row = state.volatile.row();
        if let Err(error) = state.ledger.commit_recovery(&records, &beginning.gap, row) {
            // Nothing was committed, so the fence goes back over a ledger that has not
            // half-recorded a recovery.
            let (carried, _) = state.arbitration.enter_volatile();
            state
                .volatile
                .fall_back("storage failed again during recovery", carried, now)?;
            return Err(error);
        }
        state.arbitration.clear_volatile_records();
        // Rich work does not come back here. Section 11 requires the pending identifiers to be
        // reconciled with the same upstream first, and that is `reconcile_recovered`, because it
        // needs something this host does not have yet: what the upstream still holds.
        Ok(beginning)
    }

    /// Finishes recovery, once the upstream has said what it still holds.
    ///
    /// This is the second half of section 11's "commit the gap and reconcile pending IDs with the
    /// same upstream before restoring rich mutation". The reconciliation runs first, so a resource
    /// this host may already have answered is uncertain before anything can claim it again.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not recovering, and whatever
    /// the reconciliation's own writes refuse.
    pub fn reconcile_recovered(
        &self,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
        now: TimestampMs,
    ) -> Result<(Reconciliation, VolatileTransition)> {
        {
            let state = self.state();
            if state.volatile.mode() != kr_protocol::gateway::GatewayMode::Recovering {
                return Err(BrokerError::invalid(format!(
                    "the gateway is {} and this finishes a recovery",
                    state.volatile.mode()
                )));
            }
        }
        let reconciliation = self.reconcile_within(scope, still_open, now)?;
        let mut state = self.state();
        let finished = state.volatile.finish_recovery()?;
        Ok((reconciliation, finished))
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
        self.state()
            .ledger
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
        self.state().ledger.checkpoint(application_instance_id)
    }

    // -- the gateway --------------------------------------------------------------------------

    /// Opens a native connection for a terminal this worker launched and authenticated.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when a table does not qualify, and
    /// [`BrokerError::PermissionDenied`] when the presented credential and process identity are
    /// not the launch this broker made.
    #[allow(clippy::too_many_arguments)]
    pub fn open_native_connection(
        &self,
        connection: GatewayConnectionId,
        application_instance_id: ApplicationInstanceId,
        presented_credential: &[u8],
        process: &ProcessStartIdentity,
        table: kr_protocol::gateway::DeclarativeTable,
        rich: kr_protocol::gateway::RichMethodTable,
        installed_protocol_version: &str,
    ) -> Result<()> {
        let mut state = self.state();
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let launched = instance.process.as_ref().ok_or_else(|| {
            BrokerError::denied(
                "this host did not launch this application, so nothing about it is a native                  connection it can authenticate",
            )
        })?;
        // Both halves. A session identifier that leaked is not a launch binding, and a process
        // that matches without the private exchange is not one either.
        if !launched.authenticates(presented_credential, process) {
            return Err(BrokerError::denied(
                "this connection does not present the launch binding and the private exchange of                  a terminal this worker started",
            ));
        }
        state.gateway.open_native(
            connection,
            application_instance_id,
            process.clone(),
            table,
            rich,
            installed_protocol_version,
        )
    }

    /// Opens a connection for a rich client or a component.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when a table does not qualify, and
    /// [`BrokerError::InvalidArgument`] when the caller asks for the native origin here.
    pub fn open_connection(
        &self,
        connection: GatewayConnectionId,
        application_instance_id: ApplicationInstanceId,
        origin: ConnectionOrigin,
        table: kr_protocol::gateway::DeclarativeTable,
        rich: kr_protocol::gateway::RichMethodTable,
        installed_protocol_version: &str,
    ) -> Result<()> {
        self.state().gateway.open(
            connection,
            application_instance_id,
            origin,
            table,
            rich,
            installed_protocol_version,
        )
    }

    /// Closes one gateway connection.
    ///
    /// The pending resources it produced stay exactly where they are: a connection ending is not
    /// an answer, and a reconnect is what reconciles them.
    pub fn close_connection(&self, connection: GatewayConnectionId) {
        self.state().gateway.close(connection);
    }

    /// Admits one rich invocation against the closed method table.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Rich`] for a method with no entry or one this build does not
    /// support, and [`BrokerError::RichWorkFenced`] while rich work is fenced.
    pub fn admit_rich(
        &self,
        connection: GatewayConnectionId,
        method: &UpstreamMethod,
        upstream_request_id: UpstreamRequestId,
    ) -> Result<RichInvocation> {
        let mut state = self.state();
        if let Err(error) = state.volatile.require_rich_work() {
            state.volatile.note_fenced();
            return Err(error);
        }
        state
            .gateway
            .admit_rich(connection, method, upstream_request_id)
    }

    /// Builds the reverse request the upstream asked for, with the site it runs at.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] or [`BrokerError::PermissionDenied`] as the
    /// connection requires.
    pub fn reverse_request(
        &self,
        connection: GatewayConnectionId,
        upstream_request_id: UpstreamRequestId,
        operation: kr_protocol::gateway::ReverseOperation,
        environment_id: kr_protocol::ids::EnvironmentId,
        os_user: &str,
    ) -> Result<ReverseRequest> {
        self.state().gateway.reverse_request(
            connection,
            upstream_request_id,
            operation,
            environment_id,
            os_user,
        )
    }

    /// Returns every connection that observes one instance, so a resolution is fanned out to all
    /// of them.
    #[must_use]
    pub fn observers(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Vec<GatewayConnectionId> {
        self.state()
            .gateway
            .observers(application_instance_id)
            .map(|connection| connection.connection)
            .collect()
    }

    /// Returns true when this broker serves the named session.
    #[must_use]
    pub fn serves_session(&self, session_id: SessionId) -> bool {
        self.state().session_id == session_id
    }

    /// Returns the session this broker serves.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.state().session_id
    }

    // -- observed history ---------------------------------------------------------------------

    /// Records one observed semantic entry and returns its cursor.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn observe(
        &self,
        application_instance_id: ApplicationInstanceId,
        kind: &str,
        text: &str,
        now: TimestampMs,
    ) -> Result<StreamCursor> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        Ok(instance.semantic.append(kind, text, now))
    }

    /// Replays what an adapter has not consumed, through the actor's own history filter.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn replay(
        &self,
        application_instance_id: ApplicationInstanceId,
        from: Option<StreamCursor>,
        filter: &dyn crate::broker::semantic::HistoryFilter,
    ) -> Result<crate::broker::semantic::Replay> {
        let state = self.state();
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        Ok(instance.semantic.replay(from, filter))
    }

    /// Records the commands the upstream advertises.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such instance.
    pub fn set_commands(
        &self,
        application_instance_id: ApplicationInstanceId,
        commands: Vec<kr_protocol::agent::AgentCommand>,
    ) -> Result<()> {
        let mut state = self.state();
        let instance = state
            .instances
            .get_mut(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        instance.commands = commands;
        Ok(())
    }

    /// Returns the commands one instance advertises.
    #[must_use]
    pub fn commands(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Vec<kr_protocol::agent::AgentCommand> {
        self.state()
            .instances
            .get(&application_instance_id)
            .map(|instance| instance.commands.clone())
            .unwrap_or_default()
    }

    // -- registered actions -------------------------------------------------------------------

    /// Records the actions one package registered.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such binding.
    pub fn register_actions(
        &self,
        binding_id: BrokerBindingId,
        actions: impl IntoIterator<Item = RegisteredAction>,
    ) -> Result<()> {
        let mut state = self.state();
        let binding = state
            .bindings
            .get_mut(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        binding.actions = actions
            .into_iter()
            .map(|action| (action.name.clone(), action))
            .collect();
        Ok(())
    }

    /// Returns the binding one package holds against one instance.
    ///
    /// A package may be bound to several instances, and an action names the instance it acts on,
    /// so the pair is what identifies the binding rather than the package alone.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when no binding of that package is bound to that
    /// instance.
    pub fn binding_for(
        &self,
        plugin_id: &PluginId,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<BrokerBindingId> {
        self.state()
            .bindings
            .values()
            .find(|binding| {
                &binding.plugin_id == plugin_id
                    && binding.application_instance_id == application_instance_id
            })
            .map(|binding| binding.binding_id)
            .ok_or_else(|| {
                BrokerError::unknown(format!(
                    "{plugin_id} is not bound to {application_instance_id}"
                ))
            })
    }

    /// Returns one registered action.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] when this broker holds no such binding.
    pub fn registered_action(
        &self,
        binding_id: BrokerBindingId,
        action: &ActionName,
    ) -> Result<Option<RegisteredAction>> {
        let state = self.state();
        let binding = state
            .bindings
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        Ok(binding.actions.get(action).cloned())
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
    ) -> DownstreamRequestId {
        DownstreamRequestId::new(connection, upstream)
    }
}

impl BrokerState {
    /// Writes one planned transition durably, conditional on the state it expects to find.
    ///
    /// A volatile record is not written: that is what volatile means, and writing it would be the
    /// manufactured durable history section 11 forbids.
    fn write_transition(&self, transition: &Transition, now: TimestampMs) -> Result<()> {
        // What decides whether a write happens is whether the ledger can take one now, not the
        // evidence quality of the resource's own history. A resource that lived through a gap
        // keeps `durability = volatile` for ever, because that is what its history was; its later
        // transitions are still written down.
        if !self.volatile.writes_are_durable() {
            return Ok(());
        }
        self.ledger.settle_pending(
            &transition.resource,
            transition.from,
            transition.resource.state == PendingState::Uncertain,
            now,
        )
    }

    /// Checks everything an invocation depends on against what this broker holds now.
    fn check_invocation(
        &self,
        binding_id: BrokerBindingId,
        invocation: &Invocation,
    ) -> Result<BrokerGrants> {
        let binding = self
            .bindings
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        if binding.application_instance_id != invocation.application_instance_id {
            return Err(BrokerError::denied(format!(
                "binding {binding_id} is not bound to {}",
                invocation.application_instance_id
            )));
        }
        if let Some(reason) = binding.rich_disabled.as_ref() {
            return Err(BrokerError::UnsupportedCapability {
                detail: format!("this binding's rich capabilities are disabled: {reason}"),
            });
        }
        binding.grants.require(invocation.grant)?;
        let instance = self
            .instances
            .get(&invocation.application_instance_id)
            .ok_or_else(|| unknown_instance(invocation.application_instance_id))?;
        if let Some(reason) = instance.rich_suspension.as_ref() {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("rich mutations are suspended: {reason}"),
            });
        }
        if instance.binding_revision != invocation.binding_revision {
            return Err(BrokerError::StaleBinding {
                detail: format!(
                    "this action was prepared at binding revision {} and the binding is at {}",
                    invocation.binding_revision, instance.binding_revision
                ),
            });
        }
        // The capability is rechecked independently of the grant, because the two answer separate
        // questions and either can have changed since the caller read it.
        if let Some((capability_id, read_at)) = invocation.capability.as_ref() {
            self.capabilities.recheck(
                invocation.application_instance_id,
                capability_id,
                *read_at,
            )?;
        }
        Ok(binding.grants.clone())
    }

    /// Checks that a capability record is about the installation it names.
    ///
    /// Evidence that names a binary, a launch profile or a binding has to name *this* one.
    /// Without the check a newer record gathered against another binary would be accepted for
    /// this instance and would then pass every later recheck, because those compare the revision
    /// and the state and not what the evidence was about.
    fn check_evidence_identity(&self, record: &CapabilityRecord) -> Result<()> {
        let instance = self
            .instances
            .get(&record.application_instance_id)
            .ok_or_else(|| unknown_instance(record.application_instance_id))?;
        if let Some(profile_id) = record.identity.profile_id.as_ref()
            && instance.profile_id.as_ref() != Some(profile_id)
        {
            return Err(BrokerError::invalid(format!(
                "this evidence was gathered under launch profile {profile_id}, and the instance \
                 was launched under another"
            )));
        }
        if let Some(digest) = record.identity.binary_digest.as_ref() {
            let launched = self
                .profiles
                .profile_of(record.application_instance_id)
                .map(|profile| profile.binary.digest);
            if let Some(launched) = launched
                && &launched != digest
            {
                return Err(BrokerError::invalid(
                    "this evidence was gathered against another binary than the one running",
                ));
            }
        }
        if let Some(binding_id) = record.identity.binding_id.as_ref() {
            let binding = self
                .bindings
                .get(binding_id)
                .ok_or_else(|| unknown_binding(*binding_id))?;
            if binding.application_instance_id != record.application_instance_id {
                return Err(BrokerError::invalid(format!(
                    "binding {binding_id} is not bound to {}",
                    record.application_instance_id
                )));
            }
        }
        if let Some(revision) = record.identity.binding_revision.as_ref()
            && *revision != instance.binding_revision
        {
            return Err(BrokerError::StaleBinding {
                detail: format!(
                    "this evidence was gathered at binding revision {revision} and the binding \
                     is at {}",
                    instance.binding_revision
                ),
            });
        }
        Ok(())
    }

    /// Checks that one pending resource is still one an answer may be dispatched for.
    fn recheck_answerable(&self, resource_id: PendingResourceId) -> Result<()> {
        let pending = self
            .arbitration
            .get(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?;
        let instance = self
            .instances
            .get(&pending.resource.application_instance_id)
            .ok_or_else(|| unknown_instance(pending.resource.application_instance_id))?;
        if let Some(reason) = instance.rich_suspension.as_ref() {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("rich mutations are suspended: {reason}"),
            });
        }
        if pending.resource.source_generation != instance.source_generation {
            return Err(BrokerError::StaleBinding {
                detail: format!(
                    "{resource_id} came from generation {} and the binding is at {}",
                    pending.resource.source_generation, instance.source_generation
                ),
            });
        }
        // The decoder that interpreted this request is the one that would encode the answer. If
        // its trust has been withdrawn, its package disabled, or it was never permitted to answer,
        // there is nobody to encode with, and a claim would be a promise this host cannot keep.
        if let Some(binding_id) = pending.decoder {
            let binding = self
                .bindings
                .get(&binding_id)
                .ok_or_else(|| unknown_binding(binding_id))?;
            if !binding.may_encode(&pending.resource.method) {
                return Err(BrokerError::denied(format!(
                    "the decoder that interpreted {resource_id} may no longer answer {}",
                    pending.resource.method
                )));
            }
        }
        Ok(())
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

fn unknown_instance(application_instance_id: ApplicationInstanceId) -> BrokerError {
    BrokerError::unknown(format!("no application instance {application_instance_id}"))
}

fn unknown_binding(binding_id: BrokerBindingId) -> BrokerError {
    BrokerError::unknown(format!("no binding {binding_id}"))
}
