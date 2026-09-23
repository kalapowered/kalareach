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
//! | [`agents`] | Which launched agent a process belongs to, and its binding, for the question ledger |
//! | [`arbitration`] | Pending resources, one resolution each, and what a reconnect does |
//! | [`capability`] | The per-installation capability map and the probes behind it |
//! | [`endpoint`] | The bound local socket, and who the kernel says connected to it |
//! | [`error`] | The broker's refusals, each mapped to a stable protocol code |
//! | [`gateway`] | The core-declarative forwarding path, the closed rich table and reverse calls |
//! | [`ledger`] | The durable records, in the worker's own journal file |
//! | [`attach`] | Endpoint acceptance, launch authentication and the connection it becomes |
//! | [`duplex`] | One supervised owner per live connection: both directions, both queues |
//! | [`framing`] | How one connector's frames are wrapped and taken apart again |
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

pub mod agents;
pub mod arbitration;
pub mod attach;
pub mod capability;
pub mod duplex;
pub mod endpoint;
pub mod error;
pub mod framing;
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
    CapabilityMap, DecodedProjection, DecoderLedgerEntry, DecodingTrust, InstanceCapabilityRecord,
    InstanceInvalidation, IntegrationMode, LaunchProfile, MAX_RETAINED_SOURCE_BYTES,
};
use kr_protocol::gateway::{DownstreamRequestId, PendingKind, PendingResource, PendingState};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, AgentThreadId, AgentTurnId, ApplicationInstanceId,
    BrokerBindingId, CapabilityId, CapabilityRevision, GatewayConnectionId, LaunchProfileId,
    PendingResourceId, PluginId, PublisherId, SessionId, SourceEventHandle, SourceGeneration,
    StreamCursor, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, Uuid};

pub use crate::broker::arbitration::{
    Arbitration, Claim, Pending, ReconcileScope, Reconciliation, Transition, Transmitter,
};
pub use crate::broker::attach::{
    Attached, Ended, Launched, NativeGateway, NativeLaunch, TEARDOWN_DEADLINE, TerminalWatch,
    hello_frame,
};
pub use crate::broker::capability::{CapabilityOwner, Probe};
pub use crate::broker::duplex::{
    CLIENT_REPLY_DEADLINE, Carried, Closure, Delivery, Dispatch, Duplex,
    MAX_FORWARDED_CLIENT_REQUESTS, MAX_QUEUED_BYTES, MAX_QUEUED_OBSERVATIONS, Observations,
    Observatory, Queued, ResourceTransition, Sink, UpstreamFailure, UpstreamReply, WRITE_DEADLINE,
};
pub use crate::broker::endpoint::{Accepted, BoundEndpoint, PeerIdentity, Stream};
pub use crate::broker::error::{BrokerError, Result};
pub use crate::broker::framing::Framing;
pub use crate::broker::gateway::{
    Connection, ConnectionOrigin, Forwarded, Gateway, PreparedResponse, ReverseRequest,
    RichInvocation,
};
pub use crate::broker::ledger::{
    BindingRecord, ClientIntent, ClientRequestOutcome, Ledger, TransitionCause, TransitionEvent,
    UnresolvedRecord,
};
pub use crate::broker::listener::{
    BoundBinary, BridgeHello, ListenerAddress, Registration, reject_browser_origin,
};
pub use crate::broker::methods::{
    ActionInFlight, AnswerInFlight, Caller, MutationAdmission, MutationInFlight,
    PendingTransmission, RegisteredAction, Responsible, UpstreamBody, UpstreamDispatch,
    UpstreamOutcome, UpstreamRequest, command, subject,
};
pub use crate::broker::process::{
    BackendStop, BrokerTransport, Credential, ManagedProcess, SourceFrame, TransportHandle,
    stop_backend,
};
pub use crate::broker::profiles::{ForegroundMark, LaunchIntent, ProfileStore, new_profile_id};
pub use crate::broker::semantic::{GrantLowerBound, HistoryFilter, Replay, SemanticLog};
pub use crate::broker::tokens::{Invocation, TokenStore};
pub use crate::broker::volatile::{RecoveryGeneration, VolatileState, VolatileTransition};

/// How many source frames one instance holds while it waits for a decoder to read them.
///
/// A frame is released when it is consumed, so the bound is on what has not been interpreted. A
/// connector that never decodes anything is a connector whose oldest frames this host forgets
/// rather than a session whose memory grows for the rest of the day.
pub const MAX_RETAINED_FRAMES: usize = 64;

/// How many bytes of unconsumed source frames one instance holds.
pub const MAX_RETAINED_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// One component bound to one application instance.
#[derive(Clone, Debug)]
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

/// One resource's single transmission, reserved, with the answer that will go.
///
/// It is made only inside [`Broker::admit_approval`], which takes the claim and the reservation
/// together, so a caller holding one holds the resource's only remaining way to be answered. The
/// durable marker follows it rather than accompanying it: `record_approval` writes the marker
/// immediately before the bytes.
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
    /// The gateway connection the answer goes out on, which namespaces its identifier.
    pub connection: GatewayConnectionId,
    /// The answer itself, prepared by the core from that connection's qualified table.
    pub response: crate::broker::gateway::PreparedResponse,
    /// How this answer reaches the upstream, and therefore how it is recorded.
    ///
    /// Section 12 requires every action to record its provenance. An answer admitted here goes
    /// over the gateway's typed connection, so it is a typed result; the app may also offer a
    /// terminal convenience, and that one records itself as terminal input and never as this.
    pub provenance: ActionProvenance,
}

/// The native client's own answer, admitted to be forwarded once.
///
/// It exists only as the return value of [`Broker::admit_native_answer`], which commits the
/// durable marker and takes the resource's one transmission admission before it hands one out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAnswer {
    /// The namespaced identifier this answer resolves.
    pub request: DownstreamRequestId,
    /// The resource it answers.
    pub resource_id: PendingResourceId,
    /// The bytes to forward, exactly as the native client wrote them.
    pub frame: Vec<u8>,
}

/// One request of the native client's, admitted to be forwarded to its own upstream.
///
/// It exists only as the return value of [`Broker::admit_client_request`], which classifies the
/// method, retains the bytes as a source event, records the intent and suspends this instance's
/// rich mutations for a method the table does not classify — all before anything is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRequest {
    /// This host's own record of the request.
    intent_id: Uuid,
    /// The instance it is going to.
    pub application_instance_id: ApplicationInstanceId,
    /// The binding revision in force when it was admitted.
    pub binding_revision: AgentBindingRevision,
    /// The method the client named.
    pub method: UpstreamMethod,
    /// How the connection's own pinned table classified it.
    pub classification: kr_protocol::gateway::NativeClassification,
    /// The source event the client's own bytes were retained as.
    pub source: SourceEventHandle,
    /// True when admitting it suspended this instance's rich mutations.
    pub suspends_rich_mutations: bool,
}

/// One draft as it stood when an invocation was admitted against it.
///
/// The admission binds to this rather than to a resolver call, so what the effect plan is checked
/// against is the draft the invocation was admitted for and not whatever the store answers a
/// moment later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftSnapshot {
    /// The draft.
    pub draft_id: kr_protocol::ids::DraftId,
    /// Its revision when the snapshot was taken.
    pub revision: kr_protocol::scalars::U64,
}

/// What resolves a draft the broker is asked to act on.
///
/// The draft store is not the broker's, so this is a seam. What the broker needs of it is one
/// answer: is this draft one an operation may act on now, and at which revision? A draft that has
/// gone, or that moved since the invocation named it, is `DRAFT_CONFLICT` rather than an operation
/// sent hopefully.
pub trait DraftResolver: Send + Sync + core::fmt::Debug {
    /// Answers whether one draft can be acted on now, and returns it as it stands.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when the draft has gone or has moved.
    fn resolve(&self, draft_id: &kr_protocol::ids::DraftId) -> Result<DraftSnapshot>;
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

/// How many transitions one replay page carries at most.
pub const MAX_REPLAY_EVENTS: usize = 256;

/// How many bytes of transition one replay page carries at most.
pub const MAX_REPLAY_BYTES: usize = 1024 * 1024;

/// Where a consumer of this broker's transitions is, and which stream those numbers belong to.
///
/// A sequence alone is not a position. It is unique inside one generation and reused across two,
/// because a stretch the journal could not take spends numbers that the next process hands out
/// again. Carrying the generation with the sequence is what makes a saved position readable after
/// a restart: the same generation means the number can be compared, and a different one means the
/// consumer is holding a position in a stream that no longer exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayCursor {
    /// The generation those sequence numbers were issued in.
    pub generation: u64,
    /// The last position the consumer accounted for.
    pub sequence: u64,
}

/// One bounded page of what a consumer missed, and what it must do about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionReplay {
    /// The recovered transitions, in stream order.
    pub events: Vec<crate::broker::ledger::TransitionEvent>,
    /// Where this page ends, to continue from.
    pub cursor: ReplayCursor,
    /// True when the cursor named another generation and this page starts the stream again.
    pub reset: bool,
    /// True when something after the cursor was announced and never recorded, so it is lost.
    pub gap: bool,
    /// True when the backlog continues after this page.
    pub more: bool,
}

/// How many resources one snapshot page carries at most.
pub const MAX_SNAPSHOT_RESOURCES: usize = MAX_REPLAY_EVENTS;

/// What this broker holds now, with the position that state is current at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceSnapshot {
    /// The position the state below is current at.
    pub cursor: ReplayCursor,
    /// Every resource the broker is still arbitrating, in identifier order.
    pub resources: Vec<PendingResource>,
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
    /// What resolves a draft this host is asked to act on, where anything does.
    drafts: Option<std::sync::Arc<dyn DraftResolver>>,
    /// What carries an answer out on each live connection.
    ///
    /// An answer resolves a resource one connection created, and it goes back on that connection.
    /// Holding the transports by connection is what lets the admission choose the right one, so a
    /// mismatch is not something a writer discovers after the resource has been claimed.
    connection_dispatch:
        BTreeMap<GatewayConnectionId, std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>>,
    /// The declarative tables this host pinned at installation, by instance and package.
    ///
    /// Section 11: "Tables are pinned and qualified against the installed protocol version under
    /// the connector publisher's semantic trust grant." A table presented at connection time is
    /// compared with this, so a package cannot open a connection with a table nobody installed.
    pinned_tables: BTreeMap<(ApplicationInstanceId, PluginId), PinnedTable>,
    /// Every observer of this broker's transitions.
    ///
    /// One registry, the broker's own. A gateway asks for it rather than supplying one, so a
    /// second gateway's connections join the observers of the first instead of replacing them.
    watchers: crate::broker::duplex::Observatory,
    /// The last event announced about each live resource, so an event can name its parent.
    announced: BTreeMap<PendingResourceId, u64>,
    /// The position the next transition event takes in this broker's stream.
    ///
    /// It continues above whatever the ledger already holds, so one stream of transitions runs
    /// across restarts. A transition whose durable write fails leaves its number unused: the
    /// cursor orders what did happen and never claims to count it.
    next_event: u64,
    /// The generation of this broker stream instance, advanced on every restart.
    stream_generation: u64,
    /// The highest position this broker announced and could not record.
    ///
    /// A transition made while the journal is faulted is published and not written, so no replay
    /// can return it. Keeping the highest of those is what lets a recovery say that something
    /// after a consumer's cursor is gone, rather than handing back a shorter history and letting
    /// the consumer believe it is complete.
    unrecorded_after: u64,
}

/// The tables one installation was qualified with, as the installation pinned them.
///
/// The tables themselves are held, not a description of them. A connection is interpreted with
/// what this host installed, so there is nothing for a package to present at connection time and
/// nothing to compare: altered framing, an altered classification or an added reverse operation
/// cannot reach the core, whatever labels travel beside them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedTable {
    /// The qualified declarative table the core interprets this installation's frames with.
    pub table: kr_protocol::gateway::DeclarativeTable,
    /// The closed rich method table for its upstream version.
    pub rich: kr_protocol::gateway::RichMethodTable,
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
        // A recovery this host began and did not finish comes back as a recovery: what ends one
        // is an upstream saying what it still holds, and no upstream has spoken to this process.
        // Starting normal would make a resource this host may already have answered claimable
        // again.
        let mut volatile = VolatileState::new();
        if let Some((row, gap)) = ledger.unfinished_recovery()? {
            let owed: Vec<(ApplicationInstanceId, GatewayConnectionId)> = arbitration
                .iter()
                .filter(|pending| !pending.resource.state.is_terminal())
                .map(|pending| {
                    (
                        pending.resource.application_instance_id,
                        pending.resource.request.connection,
                    )
                })
                .collect();
            volatile.restore_recovering(row, gap, owed);
        }
        // And connection identifiers are numbered above everything this ledger has seen, so a new
        // connection never lands in an old one's namespace.
        let next_connection = ledger.highest_connection()?;
        // And transition events are numbered above everything this ledger has recorded, so the
        // stream a consumer follows has one order across a restart. What each live resource was
        // last announced under comes back with it, so the next event about one this host was
        // already answering names that event as its parent rather than starting a second chain.
        let next_event = ledger.highest_event()?.saturating_add(1);
        // One generation per open. Sequence numbers are unique inside a generation and mean
        // nothing across two, because a stretch the journal could not take spends numbers that the
        // next process hands out again.
        let stream_generation = ledger.advance_stream_generation()?;
        let announced: BTreeMap<PendingResourceId, u64> =
            ledger.latest_events()?.into_iter().collect();
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
                volatile,
                next_connection,
                drafts: None,
                connection_dispatch: BTreeMap::new(),
                pinned_tables: BTreeMap::new(),
                watchers: crate::broker::duplex::Observatory::new(),
                announced,
                next_event,
                stream_generation,
                unrecorded_after: 0,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BrokerState> {
        // A poisoned lock means a caller panicked mid-decision. Every write here is planned
        // against the state, written to the ledger and only then applied, so what a panic leaves
        // behind is the state as it was rather than half a transition, and continuing is what
        // lets a cleanup that runs while unwinding still settle what it holds.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
            InstanceInvalidation::BindingChanged,
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

    /// Registers what carries answers out on one live connection.
    ///
    /// A resource is created by a connection and answered on it. This is what the admission looks
    /// the transport up in, so the answer's transport is chosen from the resource rather than from
    /// the instance, which may have several connections open.
    pub fn bind_connection_dispatch(
        &self,
        connection: GatewayConnectionId,
        dispatch: std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>,
    ) {
        self.state()
            .connection_dispatch
            .insert(connection, dispatch);
    }

    /// Takes back the transport one instance's rich mutations were going out over.
    ///
    /// A connection that has ended is not a route to the upstream any more, and an instance left
    /// pointing at one would admit a mutation against a transport nothing is reading. Only the
    /// transport that is still bound is withdrawn, so a connection that replaced this one keeps
    /// its own.
    pub fn unbind_dispatch(
        &self,
        application_instance_id: ApplicationInstanceId,
        dispatch: &std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>,
    ) {
        let mut state = self.state();
        let Some(instance) = state.instances.get_mut(&application_instance_id) else {
            return;
        };
        if instance
            .dispatch
            .as_ref()
            .is_some_and(|held| std::sync::Arc::ptr_eq(held, dispatch))
        {
            instance.dispatch = None;
        }
    }

    /// Returns what carries answers out on one connection, where anything does.
    #[must_use]
    pub fn connection_dispatch(
        &self,
        connection: GatewayConnectionId,
    ) -> Option<std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>> {
        self.state().connection_dispatch.get(&connection).cloned()
    }

    /// Returns what carries an instance's own operations, where anything does.
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

    /// Returns true when this instance has bindings and every one of them is rich-disabled.
    ///
    /// One disabled binding stops that binding's rich capabilities. All of them disabled stops
    /// the instance's, because there is nothing left to interpret or prepare with.
    #[must_use]
    pub fn rich_bindings_all_disabled(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> bool {
        let state = self.state();
        let mut bound = state
            .bindings
            .values()
            .filter(|binding| binding.application_instance_id == application_instance_id)
            .peekable();
        bound.peek().is_some() && bound.all(|binding| binding.rich_disabled.is_some())
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
        // Before anything is counted, recorded or suspended. An upstream that mints an identifier
        // in this host's own namespace is an upstream whose next response this host could not tell
        // from an answer to a request of its own, and a refusal that left a resource, a ledger row
        // and a retained source behind it would have made the ambiguity anyway.
        if let Some(request) = forwarded.request.as_ref()
            && crate::broker::duplex::is_host_minted(&request.upstream)
        {
            return Err(BrokerError::invalid(format!(
                "{} begins with {}, which names the requests this host sends, and an upstream \
                 request cannot be one of those",
                request.upstream,
                crate::broker::duplex::HOST_REQUEST_PREFIX
            )));
        }
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
        // to the bytes it is an interpretation of. It is built now and retained only once the
        // admission has been written, because retaining evicts, and a refused request must not
        // cost an accepted one its source.
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let source_generation = instance.source_generation;
        let source = SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid()))
            .map_err(|error| BrokerError::invalid(format!("source handle: {error}")))?;
        let source_frame = SourceFrame::new(source.clone(), source_generation, frame, now)?;
        if state.arbitration.holds_request(&request) {
            return Err(BrokerError::invalid(format!(
                "{request} already names a pending resource"
            )));
        }
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
        // What decides whether the row is written is whether the ledger can take a write now,
        // the same predicate every later transition uses. What the record *says* about itself is
        // the mode's own durability, which is the honest label for a resource admitted while a
        // gap was open.
        // The record and the event that announces it, in one transaction: a request this host
        // took is a state change, and section 24 puts the change and its announcement together.
        let event = state.next_transition_event(
            &resource,
            now,
            crate::broker::ledger::TransitionCause::Recorded,
            None,
        );
        if state.volatile.writes_are_durable() {
            state.ledger.record_opaque(&resource, &event)?;
        } else {
            state.announced_without_record(&event);
        }
        state.remember(&event);
        state.publish(&resource, &event);
        state
            .arbitration
            .record(resource.clone(), None, Some(source))?;
        // A request recorded while a recovery is running belongs to an upstream that has not said
        // what it still holds, so it joins what that recovery owes.
        state.volatile.owe_one(application_instance_id, connection);
        if let Some(instance) = state.instances.get_mut(&application_instance_id) {
            instance.retain(source_frame);
        }
        Ok((forwarded, Some(resource)))
    }

    /// Admits one request or notification the native client is making of its own upstream.
    ///
    /// The native client and the upstream are two ends of one connection, and a frame the client
    /// writes changes upstream state exactly as a frame the upstream writes does. So it goes
    /// through the same admission rather than straight onto the socket: the method is classified
    /// with the table this host pinned, the bytes are retained as a source event of the instance,
    /// the intent is recorded before anything is written, and a method the table does not classify
    /// suspends this instance's rich mutations *first*. Section 11 forbids an unclassified request
    /// acting while rich mutations stay enabled, and the order here is what makes that true rather
    /// than likely.
    ///
    /// The caller writes the frame and then reports what happened through
    /// [`Broker::client_request_settled`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the connection is not a worker-launched
    /// native one, [`BrokerError::UnknownSubject`] when the connection or its instance is not one
    /// this broker holds, [`BrokerError::InvalidArgument`] when the frame names no method, and
    /// [`BrokerError::LedgerUnavailable`] when the intent cannot be recorded.
    pub fn admit_client_request(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
        upstream_request_id: Option<&UpstreamRequestId>,
        now: TimestampMs,
    ) -> Result<ClientRequest> {
        let mut state = self.state();
        let (method, classification) = state.gateway.classify_native(connection, frame)?;
        let application_instance_id = state
            .gateway
            .connection(connection)
            .map(|held| held.application_instance_id)
            .ok_or_else(|| BrokerError::unknown(format!("no gateway connection {connection}")))?;
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let binding_revision = instance.binding_revision;
        let source_generation = instance.source_generation;
        let source = SourceEventHandle::new(format!("src-{}", kr_ipc::new_uuid()))
            .map_err(|error| BrokerError::invalid(format!("source handle: {error}")))?;
        let source_frame = SourceFrame::new(source.clone(), source_generation, frame, now)?;
        let intent = crate::broker::ledger::ClientIntent {
            intent_id: Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()),
            application_instance_id,
            connection,
            upstream_request_id: upstream_request_id.cloned(),
            method: method.clone(),
            classification,
            source: source.clone(),
            outcome: crate::broker::ledger::ClientRequestOutcome::Recorded,
            recorded_at: now,
        };
        // Recorded before the bytes, exactly as an upstream request is. A crash between the two
        // leaves a row saying this host was about to forward something it could not classify,
        // which is the honest record; a row written afterwards would say nothing about the frame
        // that went out during the crash.
        if state.volatile.writes_are_durable() {
            state.ledger.record_client_intent(&intent)?;
        }
        // The native path keeps working while the journal is faulted, and the gap records that it
        // did.
        state.volatile.note_native_request();
        let suspends_rich_mutations = classification.suspends_rich_mutations();
        if let Some(instance) = state.instances.get_mut(&application_instance_id) {
            if suspends_rich_mutations {
                instance.rich_suspension = Some(format!(
                    "{method} is not classified by this connector's table, so what the terminal \
                     asked for is unknown"
                ));
            }
            instance.retain(source_frame);
        }
        Ok(ClientRequest {
            intent_id: intent.intent_id,
            application_instance_id,
            binding_revision,
            method,
            classification,
            source,
            suspends_rich_mutations,
        })
    }

    /// Returns every request of the native client's this host recorded, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the records cannot be read.
    pub fn client_requests(&self) -> Result<Vec<crate::broker::ledger::ClientIntent>> {
        self.state().ledger.client_intents()
    }

    /// Records what became of one admitted client request.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the record cannot be written.
    pub fn client_request_settled(
        &self,
        request: &ClientRequest,
        outcome: crate::broker::ledger::ClientRequestOutcome,
    ) -> Result<()> {
        let state = self.state();
        if !state.volatile.writes_are_durable() {
            return Ok(());
        }
        state
            .ledger
            .settle_client_intent(request.intent_id, outcome)
    }

    /// Admits the native client's own answer to be forwarded, exclusively.
    ///
    /// This is what makes a native answer win during encoding. The admission is taken **before**
    /// the bytes go, and it is the same one admission a rich answer takes at
    /// [`Broker::admit_approval`]: whichever writer reaches it first may transmit, and the other
    /// is refused rather than recorded as a competing answer afterwards. A rich answer that
    /// reaches its recheck after this is told the resolved state.
    ///
    /// The caller forwards [`NativeAnswer::frame`] and then reports what happened through
    /// [`Broker::native_answer_sent`] or [`Broker::native_answer_uncertain`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the response carries no correlation
    /// identifier, [`BrokerError::Arbitration`] when the resource has already ended, and
    /// [`BrokerError::PermissionDenied`] when a rich answer already holds the one admission.
    pub fn admit_native_answer(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
        now: TimestampMs,
    ) -> Result<NativeAnswer> {
        let mut state = self.state();
        let request = state.gateway.correlate_response(connection, frame)?;
        let transition = state.arbitration.plan_native_dispatch(&request)?;
        let resource_id = transition.resource.resource_id;
        // The marker before the bytes, exactly as the rich path does it. A crash between them
        // leaves a record saying an answer may already have gone, which is what stops a restart
        // from sending a second one.
        state.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::Dispatched,
            None,
        )?;
        state.volatile.note_native_response();
        Ok(NativeAnswer {
            request,
            resource_id,
            frame: frame.to_vec(),
        })
    }

    /// Records that an admitted native answer reached the upstream.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the native writer does not hold the
    /// admission, and [`BrokerError::Arbitration`] when the resource has already ended.
    pub fn native_answer_sent(
        &self,
        answer: &NativeAnswer,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        self.settle_native(answer, PendingState::Resolved, now)
    }

    /// Commits the dispatch marker for one claim, immediately before its bytes go.
    ///
    /// Section 24 puts the durable marker before the effect: once this returns, a restart reads
    /// the resource back as one an answer may already have gone for, so no second answer is sent.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] when this claim does not hold the resource's
    /// transmission admission, and [`BrokerError::LedgerUnavailable`] when the marker cannot be
    /// written.
    fn commit_dispatch(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_dispatched(claim)?;
        // The resource's own state does not change here: it was claimed and stays claimed. What
        // changes is the marker, and that is a durable change like any other, so the event that
        // announces it is written in the same transaction and published with it.
        let event = state.next_transition_event(
            &transition.resource,
            now,
            crate::broker::ledger::TransitionCause::Dispatched,
            Some(claim.actor_id.clone()),
        );
        state.ledger.mark_dispatched(&transition.resource, &event)?;
        state.remember(&event);
        let resource = state.arbitration.commit(transition)?;
        state.publish(&resource, &event);
        Ok(resource)
    }

    /// Records that an admitted native answer went and nothing confirmed it.
    ///
    /// # Errors
    ///
    /// Returns the same failures [`Broker::native_answer_sent`] does.
    pub fn native_answer_uncertain(
        &self,
        answer: &NativeAnswer,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        self.settle_native(answer, PendingState::Uncertain, now)
    }

    fn settle_native(
        &self,
        answer: &NativeAnswer,
        to: PendingState,
        now: TimestampMs,
    ) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_native_settled(&answer.request, to)?;
        state.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::NativeAnswer,
            None,
        )
    }

    /// Admits one native answer, forwards it and records what happened, in that order.
    ///
    /// The order is the contract and this is where a transport gets it for free: nothing is
    /// forwarded until the one admission is held, and the outcome is recorded only after the
    /// forwarding has been attempted. A send that fails leaves the resource uncertain, because an
    /// answer whose fate nobody can establish is never answered a second time.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Broker::admit_native_answer`] refuses, and whatever `send` refuses.
    pub fn native_answer_through(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
        now: TimestampMs,
        send: impl FnOnce(&[u8]) -> Result<()>,
    ) -> Result<PendingResource> {
        let answer = self.admit_native_answer(connection, frame, now)?;
        match send(&answer.frame) {
            Ok(()) => self.native_answer_sent(&answer, now),
            Err(error) => {
                let _ = self.native_answer_uncertain(&answer, now);
                Err(error)
            }
        }
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
        // A recorded request becoming an answerable approval is a durable change of that resource,
        // so its own event goes in the same transaction as the change.
        let event = state.next_transition_event(
            &interpreted,
            now,
            crate::broker::ledger::TransitionCause::Interpreted,
            None,
        );
        let admitted =
            state
                .ledger
                .admit_resource(handle, binding_id, &entry, &interpreted, now, &event)?;
        if !admitted {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("source event {handle} has already produced an interpretation"),
            });
        }
        state.remember(&event);
        state.publish(&interpreted, &event);
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

    /// Binds what resolves a draft this host acts on.
    ///
    /// A draft-dependent action names a draft, and the broker refuses one it cannot resolve rather
    /// than sending an operation against a draft that may have moved. The draft store itself is
    /// not the broker's; this is the seam it is reached through.
    pub fn bind_drafts(&self, drafts: std::sync::Arc<dyn DraftResolver>) {
        self.state().drafts = Some(drafts);
    }

    /// Returns true when this host can resolve a draft at all.
    #[must_use]
    pub fn resolves_drafts(&self) -> bool {
        self.state().drafts.is_some()
    }

    /// Checks that one draft is one this host can act on.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when nothing resolves drafts here, and whatever
    /// the resolver refuses for a draft that has gone or moved.
    pub fn resolve_draft(&self, draft_id: &kr_protocol::ids::DraftId) -> Result<DraftSnapshot> {
        let drafts = self.state().drafts.clone();
        let drafts = drafts.ok_or_else(|| BrokerError::PreconditionFailed {
            detail: format!(
                "this host cannot resolve draft {draft_id}, so an operation that acts on it is \
                 refused rather than sent against a draft nobody checked"
            ),
        })?;
        drafts.resolve(draft_id)
    }

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
        self.state().issue_token_in(binding_id, invocation, now)
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
        self.state().spend_token_in(claim)
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
        // Refuse first, write second, publish third. A reservation published before its record
        // was written would outlive a failed write, and the retry would be refused for a launch
        // that never happened.
        state
            .profiles
            .check_executable(intent, now, application_instance_id)?;
        state
            .ledger
            .put_profile(&intent.profile, Some(application_instance_id))?;
        state.profiles.execute(intent, now, application_instance_id)
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
    pub fn record_capability(&self, record: InstanceCapabilityRecord) -> Result<()> {
        let mut state = self.state();
        state.check_evidence_identity(&record)?;
        state.capabilities.record(record)
    }

    /// Records the result of a probe the host ran.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the probe was not one the host would run.
    pub fn record_probe(&self, probe: &Probe, record: InstanceCapabilityRecord) -> Result<()> {
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
        change: InstanceInvalidation,
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
    //
    // The four steps below — claim, admit, mark, settle — are the broker's own, and nothing
    // outside it reaches them. Section 11 gives a resource one resolution, and the whole of that
    // guarantee is that the caller that settles is the caller that was admitted and transmitted:
    // a sequence that claimed a resource and resolved it without an execution permit would settle
    // a resource no answer had gone for. The way in is `admit_approval`, which reserves the
    // resource and hands back the permit, and `record_approval`, which marks, transmits and
    // settles under it; `abandon` gives an unspent reservation back.

    /// Resolves a claimed resource: the upstream confirmed the answer.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Arbitration`] or [`BrokerError::PermissionDenied`] as the claim
    /// requires.
    fn resolve(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_resolve(claim)?;
        let actor_id = Some(claim.actor_id.clone());
        state.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::RichAnswer,
            actor_id,
        )
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
        self.state().release_claim_in(claim, now)
    }

    /// Leaves a claimed resource uncertain: an answer went and nothing confirmed it.
    ///
    /// # Errors
    ///
    /// Returns the same failures [`Broker::resolve`] does.
    fn uncertain(&self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let mut state = self.state();
        let transition = state.arbitration.plan_uncertain(claim)?;
        let actor_id = Some(claim.actor_id.clone());
        state.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::RichAnswer,
            actor_id,
        )
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
        state.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::Upstream,
            None,
        )
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
        self.state().reconcile_in(scope, still_open, now)
    }

    /// Returns one binding as it stands now.
    ///
    /// A grant is checked against this rather than against whatever was recorded when a component
    /// last acted, because a grant that has since been withdrawn is not a grant.
    #[must_use]
    pub fn binding_record(&self, binding_id: BrokerBindingId) -> Option<Binding> {
        self.state().bindings.get(&binding_id).cloned()
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

    /// Returns which recovery is running, or which one last ran.
    ///
    /// A reconciliation names it, so an acknowledgement prepared under one recovery cannot finish
    /// another that a second storage failure opened in the meantime.
    #[must_use]
    pub fn recovery_generation(&self) -> RecoveryGeneration {
        self.state().volatile.generation()
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
        let sequence = match state.ledger.commit_recovery(&records, &beginning.gap, row) {
            Ok(sequence) => sequence,
            Err(error) => {
                // Nothing was committed, so the fence goes back over a ledger that has not
                // half-recorded a recovery.
                let (carried, _) = state.arbitration.enter_volatile();
                state
                    .volatile
                    .fall_back("storage failed again during recovery", carried, now)?;
                return Err(error);
            }
        };
        // The gap this recovery closes is the row the ledger just wrote, whether it existed
        // before or the fault itself was what stopped it being written. Holding it here is what
        // lets the end of this recovery mark that same row finished.
        state.volatile.set_row(sequence);
        // Every upstream that still has an unresolved resource owes a reconciliation before rich
        // work comes back. Reconciling one says nothing about another's pending identifiers.
        let owed: Vec<(ApplicationInstanceId, GatewayConnectionId)> = state
            .arbitration
            .iter()
            .filter(|pending| !pending.resource.state.is_terminal())
            .map(|pending| {
                (
                    pending.resource.application_instance_id,
                    pending.resource.request.connection,
                )
            })
            .collect();
        state.volatile.owe_reconciliation(owed);
        state.arbitration.clear_volatile_records();
        // Rich work does not come back here. Section 11 requires the pending identifiers to be
        // reconciled with the same upstream first, and that is `reconcile_recovered`, because it
        // needs something this host does not have yet: what each upstream still holds.
        Ok(beginning)
    }

    /// Reconciles one upstream that a recovery owes, and finishes the recovery when it was the
    /// last one.
    ///
    /// This is the second half of section 11's "commit the gap and reconcile pending IDs with the
    /// same upstream before restoring rich mutation". The reconciliation runs first, so a resource
    /// this host may already have answered is uncertain before anything can claim it again, and
    /// rich work comes back only when every upstream that had an unresolved resource has said
    /// what it still holds. The transition is `None` while any of them has not.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the gateway is not recovering, and whatever
    /// the reconciliation's own writes refuse.
    pub fn reconcile_recovered(
        &self,
        generation: RecoveryGeneration,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
        now: TimestampMs,
    ) -> Result<(Reconciliation, Option<VolatileTransition>)> {
        // One lock covers the whole of it. Validating the mode, reconciling the upstream and
        // finishing the recovery under separate locks left two windows: a scope could be added to
        // the owed set between them, and a late acknowledgement could remove one from a recovery
        // it was never about. The generation closes the second, and this closes the first.
        let mut state = self.state();
        if state.volatile.mode() != kr_protocol::gateway::GatewayMode::Recovering {
            return Err(BrokerError::invalid(format!(
                "the gateway is {} and this finishes a recovery",
                state.volatile.mode()
            )));
        }
        // The generation is checked before anything is written. An acknowledgement prepared under
        // a recovery that failed carries a list about a moment that has passed, and applying it
        // first would cancel resources that are current before the refusal was reported.
        state.volatile.check_generation(generation)?;
        let reconciliation = state.reconcile_in(scope, still_open, now)?;
        // This upstream is reconciled. Rich work comes back when every one that owed a
        // reconciliation has given it, and not before.
        if state
            .volatile
            .reconciled(generation, scope.application_instance_id, scope.connection)?
            > 0
        {
            return Ok((reconciliation, None));
        }
        // The gap accounting is written before the fence is lifted. A gap whose final counts were
        // never recorded is one nobody can read afterwards to see what the fault cost.
        if let Some(row) = state.volatile.row() {
            let gap = state.volatile.gap().cloned();
            if let Some(gap) = gap.as_ref() {
                state.ledger.commit_gap(row, gap)?;
            }
            state.ledger.finish_recovery(row)?;
        }
        let finished = state.volatile.finish_recovery(generation)?;
        Ok((reconciliation, Some(finished)))
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

    /// Pins one connector's qualified tables for one installation.
    ///
    /// A table is qualified at installation, under the publisher's semantic trust grant, and this
    /// is what that qualification leaves behind. Both tables are held whole, because the core
    /// interprets frames with them: a table a connection supplied would be a package choosing how
    /// its own bytes are read.
    ///
    /// The declarative table's recorded digest is checked against the digest of what it declares,
    /// so the qualification names the semantics that were qualified rather than a label beside
    /// them.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when either table is not one the core will interpret, which
    /// includes a declarative table whose digest is not the digest of its own content.
    pub fn pin_table(
        &self,
        application_instance_id: ApplicationInstanceId,
        table: kr_protocol::gateway::DeclarativeTable,
        rich: kr_protocol::gateway::RichMethodTable,
    ) -> Result<()> {
        table.validate()?;
        rich.qualify(&table.upstream_protocol_version)?;
        self.state().pinned_tables.insert(
            (application_instance_id, table.plugin_id.clone()),
            PinnedTable { table, rich },
        );
        Ok(())
    }

    /// Returns what this host pinned for one installation's package.
    #[must_use]
    pub fn pinned_table(
        &self,
        application_instance_id: ApplicationInstanceId,
        plugin_id: &PluginId,
    ) -> Option<PinnedTable> {
        self.state()
            .pinned_tables
            .get(&(application_instance_id, plugin_id.clone()))
            .cloned()
    }

    /// Returns the digest a declarative table's own content has.
    ///
    /// This is what an installation records when it qualifies a table, and what
    /// [`Broker::pin_table`] checks the table's recorded digest against.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when the table cannot be encoded canonically.
    pub fn table_digest(table: &kr_protocol::gateway::DeclarativeTable) -> Result<Digest256> {
        table
            .canonical_digest()
            .map_err(|_| BrokerError::Table(kr_protocol::gateway::TableError::Unrepresentable))
    }

    /// Opens a native connection for a terminal this worker launched and authenticated.
    ///
    /// The connection names the connector package it speaks for, and the core interprets it with
    /// the tables this host pinned for that package. Nothing about the protocol travels with the
    /// connection.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when the pinned tables do not qualify against the installed
    /// upstream version, and [`BrokerError::PermissionDenied`] when no table is pinned for the
    /// package or the presented credential and process identity are not the launch this broker
    /// made.
    pub fn open_native_connection(
        &self,
        application_instance_id: ApplicationInstanceId,
        presented_credential: &[u8],
        process: &ProcessStartIdentity,
        plugin_id: &PluginId,
        installed_protocol_version: &str,
    ) -> Result<GatewayConnectionId> {
        let mut state = self.state();
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let launched = instance.process.as_ref().ok_or_else(|| {
            BrokerError::denied(
                "this host did not launch this application, so nothing about it is a native \
                 connection it can authenticate",
            )
        })?;
        // Both halves. A session identifier that leaked is not a launch binding, and a process
        // that matches without the private exchange is not one either.
        if !launched.authenticates(presented_credential, process) {
            return Err(BrokerError::denied(
                "this connection does not present the launch binding and the private exchange of \
                 a terminal this worker started",
            ));
        }
        let pinned = state.pinned_table(application_instance_id, plugin_id)?;
        // The identifier is minted here, inside the admission, rather than taken from the caller.
        // An identifier a caller chose could be one this host already used, and a response on the
        // new connection would then correlate to a resource the old one recorded.
        let connection = state.mint_connection();
        state.gateway.open_native(
            connection,
            application_instance_id,
            process.clone(),
            pinned.table,
            pinned.rich,
            installed_protocol_version,
        )?;
        Ok(connection)
    }

    /// Opens a connection for a rich client or a component.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Table`] when the pinned tables do not qualify,
    /// [`BrokerError::PermissionDenied`] when no table is pinned for the package, and
    /// [`BrokerError::InvalidArgument`] when the caller asks for the native origin here.
    pub fn open_connection(
        &self,
        application_instance_id: ApplicationInstanceId,
        origin: ConnectionOrigin,
        plugin_id: &PluginId,
        installed_protocol_version: &str,
    ) -> Result<GatewayConnectionId> {
        let mut state = self.state();
        let pinned = state.pinned_table(application_instance_id, plugin_id)?;
        let connection = state.mint_connection();
        state.gateway.open(
            connection,
            application_instance_id,
            origin,
            pinned.table,
            pinned.rich,
            installed_protocol_version,
        )?;
        Ok(connection)
    }

    /// Restores one connection a restart left behind, keeping its identifier.
    ///
    /// A reconnect has to reach the resources it left pending, and those are namespaced by the
    /// identifier the old connection had. Reusing one is therefore permitted, but only for the
    /// instance that owned it and only while no live connection holds it: an identifier reopened
    /// for another instance would correlate that instance's responses to somebody else's
    /// resources, which is the defect this refuses rather than documents.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the identifier is live, belongs to another
    /// instance, or names no retained resource of this one, and whatever
    /// [`Broker::open_native_connection`] refuses.
    pub fn restore_native_connection(
        &self,
        connection: GatewayConnectionId,
        application_instance_id: ApplicationInstanceId,
        presented_credential: &[u8],
        process: &ProcessStartIdentity,
        plugin_id: &PluginId,
        installed_protocol_version: &str,
    ) -> Result<()> {
        let mut state = self.state();
        if state.gateway.connection(connection).is_some() {
            return Err(BrokerError::denied(format!(
                "{connection} is a live connection, and a restoration is not a replacement"
            )));
        }
        let instance_generation = state
            .instances
            .get(&application_instance_id)
            .map(|instance| instance.source_generation);
        // Every retained resource of this connection, not the first one found. A connection can
        // hold resources from both sides of a binding change, and checking one of them would
        // restore the rest of them with it.
        let mut retained = 0_usize;
        for pending in state
            .arbitration
            .iter()
            .filter(|pending| pending.resource.request.connection == connection)
        {
            retained += 1;
            if pending.resource.application_instance_id != application_instance_id {
                return Err(BrokerError::denied(format!(
                    "{connection} holds resources of {} and this restoration names \
                     {application_instance_id}",
                    pending.resource.application_instance_id
                )));
            }
            if Some(pending.resource.source_generation) != instance_generation {
                return Err(BrokerError::denied(format!(
                    "{connection} holds resources from generation {} and this instance is at \
                     another, so restoring it would expose an old execution's resources to a new \
                     one",
                    pending.resource.source_generation
                )));
            }
        }
        if retained == 0 {
            return Err(BrokerError::denied(format!(
                "{connection} names no retained resource, so there is nothing to restore"
            )));
        }
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        let launched = instance.process.as_ref().ok_or_else(|| {
            BrokerError::denied(
                "this host did not launch this application, so nothing about it is a native \
                 connection it can authenticate",
            )
        })?;
        if !launched.authenticates(presented_credential, process) {
            return Err(BrokerError::denied(
                "this connection does not present the launch binding and the private exchange of \
                 a terminal this worker started",
            ));
        }
        let pinned = state.pinned_table(application_instance_id, plugin_id)?;
        state.gateway.open_native(
            connection,
            application_instance_id,
            process.clone(),
            pinned.table,
            pinned.rich,
            installed_protocol_version,
        )
    }

    /// Returns one gateway connection as the broker holds it.
    #[must_use]
    pub fn connection(&self, connection: GatewayConnectionId) -> Option<Connection> {
        self.state().gateway.connection(connection).cloned()
    }

    /// Reads which request one response frame correlates to, and checks it is a response.
    ///
    /// Nothing is recorded and nothing is resolved. A transport asks this so it can tell a reply
    /// to one of its own requests from the upstream's answer to a request of the upstream's,
    /// which are two different frames that can carry the same raw identifier.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the frame is a request, is not a readable
    /// response, or carries no correlation identifier.
    pub fn correlate_response(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
    ) -> Result<DownstreamRequestId> {
        self.state().gateway.correlate_response(connection, frame)
    }

    /// Records the upstream answering or withdrawing a request of its own.
    ///
    /// This is the acknowledgement half, kept separate from the native writer's own answer. A
    /// frame that resolves nothing is not an error the connection ends over: an upstream may
    /// answer something this host never recorded.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the frame carries no correlation identifier.
    pub fn upstream_response(
        &self,
        connection: GatewayConnectionId,
        frame: &[u8],
        now: TimestampMs,
    ) -> Result<Option<PendingResource>> {
        let mut state = self.state();
        let request = state.gateway.correlate_response(connection, frame)?;
        if state.arbitration.by_request(&request).is_none() {
            return Ok(None);
        }
        let transition = state.arbitration.plan_upstream_resolved(&request)?;
        state
            .commit_transition(
                transition,
                now,
                crate::broker::ledger::TransitionCause::Upstream,
                None,
            )
            .map(Some)
    }

    /// Closes one gateway connection.
    ///
    /// The pending resources it produced stay exactly where they are: a connection ending is not
    /// an answer, and a reconnect is what reconciles them.
    pub fn close_connection(&self, connection: GatewayConnectionId) {
        let mut state = self.state();
        state.gateway.close(connection);
        state.connection_dispatch.remove(&connection);
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

    /// Returns this broker's one registry of observers.
    ///
    /// Section 12 fans resolutions out to every authorised observer, and section 24 makes the
    /// state transition and the event one contract. Both hold only if there is one registry and
    /// every transition goes through it, so a gateway asks for this rather than supplying one of
    /// its own: a resolution a rich client caused and one the person caused in the terminal reach
    /// the same watchers, and a second gateway joins them rather than replacing them.
    #[must_use]
    pub fn observatory(&self) -> crate::broker::duplex::Observatory {
        self.state().watchers.clone()
    }

    /// Reads one bounded page of the transitions this broker recorded after one cursor.
    ///
    /// This is the outbox a consumer replays from after it has been away, and what it returns says
    /// three things beyond the events themselves.
    ///
    /// * **Where the cursor belongs.** A cursor names the generation its numbers came from. One
    ///   that names an earlier generation is not comparable with this stream's numbers, so the
    ///   page is read from the start of the stream and marked `reset`: the consumer discards what
    ///   it held rather than continuing a count that means something else now.
    /// * **What cannot be recovered.** A transition announced while the journal was faulted was
    ///   never written, so no read can return it. When one of those falls after the cursor the
    ///   page is marked `gap`, and the consumer tells its views to resynchronise rather than
    ///   presenting a history with a hole in it.
    /// * **Where to continue.** The page ends at `cursor`, and `more` says whether the backlog
    ///   continues. The broker's lock is taken for one page and given back, so a consumer that is
    ///   far behind does not hold every other caller behind its own read.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::LedgerUnavailable`] when the records cannot be read.
    pub fn replay_after(&self, cursor: ReplayCursor) -> Result<TransitionReplay> {
        let state = self.state();
        let generation = state.stream_generation;
        let reset = cursor.generation != generation;
        let from = if reset { 0 } else { cursor.sequence };
        let page = state
            .ledger
            .events_after(from, MAX_REPLAY_EVENTS, MAX_REPLAY_BYTES)?;
        // An announcement the journal could not take spends a number that no read returns. The
        // highest of those is enough to answer the only question a consumer asks: was anything
        // after my cursor lost for good?
        let gap = state.unrecorded_after > from;
        let sequence = page.events.last().map_or(from, |event| event.sequence);
        Ok(TransitionReplay {
            events: page.events,
            cursor: ReplayCursor {
                generation,
                sequence,
            },
            reset,
            gap,
            more: page.more,
        })
    }

    /// Returns where a consumer that has seen nothing of this broker's stream starts.
    #[must_use]
    pub fn stream_start(&self) -> ReplayCursor {
        ReplayCursor {
            generation: self.state().stream_generation,
            sequence: 0,
        }
    }

    /// Returns the generation of this broker's stream, advanced on every restart.
    #[must_use]
    pub fn stream_generation(&self) -> u64 {
        self.state().stream_generation
    }

    /// Returns the resources this broker still holds, as a consumer installs them.
    ///
    /// This is what a view that lost its place restores from. It is taken under the broker's own
    /// lock with the cursor it is current at, so the two agree: every transition this broker had
    /// committed when the snapshot was taken is in the state it describes, and every one after it
    /// carries a sequence above the cursor. A view that installs this and then ignores the events
    /// it has already accounted for has the whole stream and no duplicates.
    ///
    /// It is the whole state and not a page of it because the state has to be one state. How many
    /// resources a host arbitrates is decided by its upstreams, so what this returns does not fit
    /// one control frame and is delivered in pages; the pages are cut from one copy of this,
    /// taken once here, rather than from the live arbitration, which moves between them.
    #[must_use]
    pub fn resource_snapshot(&self) -> ResourceSnapshot {
        let state = self.state();
        ResourceSnapshot {
            cursor: ReplayCursor {
                generation: state.stream_generation,
                // The position of the last event this broker announced. `next_event` is the
                // position the next one will take.
                sequence: state.next_event.saturating_sub(1),
            },
            resources: state
                .arbitration
                .iter()
                .map(|pending| pending.resource.clone())
                .collect(),
        }
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
        self.state().mint_connection()
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
    /// Takes the claim on one pending resource.
    ///
    /// The recheck covers everything that could have changed while the answer was being encoded:
    /// the resource's own state, its deadline, the instance it belongs to, the generation that
    /// produced it, and whether the decoder that interpreted it may still encode an answer.
    fn claim_in(
        &mut self,
        resource_id: PendingResourceId,
        actor_id: &ActorId,
        now: TimestampMs,
    ) -> Result<Claim> {
        self.volatile.require_rich_work()?;
        self.recheck_answerable(resource_id)?;
        let transition = self.arbitration.plan_claim(resource_id, actor_id, now)?;
        let claim = transition
            .claim()
            .cloned()
            .ok_or_else(|| BrokerError::invalid("a claim transition carries a claim"))?;
        self.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::RichClaim,
            Some(actor_id.clone()),
        )?;
        Ok(claim)
    }

    /// Gives a claim back. See [`Broker::release_claim`].
    fn release_claim_in(&mut self, claim: &Claim, now: TimestampMs) -> Result<PendingResource> {
        let transition = self.arbitration.plan_release(claim)?;
        let actor_id = Some(claim.actor_id.clone());
        self.commit_transition(
            transition,
            now,
            crate::broker::ledger::TransitionCause::RichClaim,
            actor_id,
        )
    }

    /// Reserves one claimed resource's single transmission, and prepares the answer that will go.
    ///
    /// This is the last gate before an answer becomes transmissible, and it is one operation
    /// because everything it checks can change between the claim and the dispatch. Under the lock
    /// it rechecks that rich work is admitted at all, that the resource is still answerable by
    /// this claim, that the decision is one the upstream actually offered, and that no answer has
    /// been admitted already. The durable marker is not written here: it goes in immediately
    /// before the bytes, in [`Broker::commit_dispatch`].
    fn admit_dispatch_in(&mut self, claim: &Claim, option_id: &str) -> Result<DispatchAdmission> {
        // Fenced rich work is fenced here too. Without this a claim taken before the journal
        // faulted could dispatch inside the gap, with no durable marker to stop a second answer.
        self.volatile.require_rich_work()?;
        self.recheck_answerable(claim.resource_id)?;
        let entry = self.ledger.decoding(claim.resource_id)?.ok_or_else(|| {
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
        let transition = self.arbitration.plan_dispatch(claim)?;
        let connection = transition.resource.request.connection;
        // The answer is prepared here, from the connection's own qualified table, so the
        // admission and the bytes it authorises are one object. The marker is not written yet:
        // this reserves the resource's one transmission, and the marker goes in immediately
        // before the bytes, so an admission that is abandoned leaves the resource answerable.
        let response = self.gateway.prepare_response(
            connection,
            &entry.upstream_request_id,
            &entry.method,
            option_id,
        )?;
        let resource = self.arbitration.commit(transition)?;
        let provenance = self
            .gateway
            .provenance(connection)
            .unwrap_or(ActionProvenance::UpstreamTypedRpc);
        Ok(DispatchAdmission {
            resource,
            option_id: option_id.to_owned(),
            method: entry.method,
            upstream_request_id: entry.upstream_request_id,
            connection,
            response,
            provenance,
        })
    }

    /// Issues an action token for one invocation. See [`Broker::issue_token`].
    fn issue_token_in(
        &mut self,
        binding_id: BrokerBindingId,
        invocation: &Invocation,
        now: TimestampMs,
    ) -> Result<ActionToken> {
        self.volatile.require_rich_work()?;
        let grants = self.check_invocation(binding_id, invocation)?;
        self.tokens.issue(binding_id, &grants, invocation, now)
    }

    /// Spends an action token against a returned effect plan. See [`Broker::spend_token`].
    fn spend_token_in(&mut self, claim: &ActionTokenClaim) -> Result<ActionToken> {
        // The record is consumed before anything is checked. A token whose spending is refused —
        // by the fence, by a withdrawn grant, by a revision that moved — is a token nobody will
        // spend, and leaving it in the store would hold a slot against every later invocation.
        let spent = self.tokens.spend_checked(claim);
        self.volatile.require_rich_work()?;
        let (token, binding_id, capability) = spent?;
        // The token has been consumed. Whatever follows, it cannot be spent again, so a failed
        // authority check costs the caller its invocation rather than giving it another attempt.
        let invocation = Invocation {
            actor_id: token.actor_id.clone(),
            grant: token.grant,
            grant_id: token.grant_id.as_ref().copied(),
            application_instance_id: token.application_instance_id,
            binding_revision: token.binding_revision,
            action: token.action.clone(),
            draft_id: token.draft_id.as_ref().copied(),
            capability: capability.clone(),
            parameters: Vec::new(),
        };
        self.check_invocation(binding_id, &invocation)?;
        Ok(token)
    }

    /// Admits one agent mutation, with every check and the transport in one operation.
    ///
    /// Section 11 puts arbitration and authority behind one serial boundary, and this is where a
    /// mutation crosses it. Everything the operation depends on is read and checked against the
    /// state as it stands here: the fence, the instance, its suspension, the binding revision, the
    /// turn, the component answerable for the dispatch and the capability. The transport is taken
    /// too rather than looked up later, so the admission a caller holds is authority over a
    /// specific upstream rather than permission to go and find one.
    #[allow(clippy::too_many_arguments)]
    fn admit_mutation_in(
        &mut self,
        target: &kr_protocol::agent::AgentMutationTarget,
        capability: Option<CapabilityId>,
        operation: kr_protocol::gateway::RichOperation,
        turn_id: Option<AgentTurnId>,
        responsible: crate::broker::methods::Responsible,
        body: crate::broker::methods::UpstreamBody,
        transport: Option<std::sync::Arc<dyn crate::broker::methods::UpstreamDispatch>>,
        now: TimestampMs,
    ) -> Result<crate::broker::methods::MutationAdmission> {
        let application_instance_id = target.subject.application_instance_id;
        if self.session_id != target.subject.session_id {
            return Err(BrokerError::unknown(format!(
                "this worker does not serve session {}",
                target.subject.session_id
            )));
        }
        // Rich work is fenced while the journal is faulted, and a mutation is rich work. The
        // refusal is counted in the gap, because a gap that does not say what it cost is a gap
        // nobody can reconcile.
        if let Err(error) = self.volatile.require_rich_work() {
            self.volatile.note_fenced();
            return Err(error);
        }
        let instance = self
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| unknown_instance(application_instance_id))?;
        // Nothing carries an operation to an instance with no transport bound. Section 9 makes a
        // refusal this host can decide a rejection rather than an outcome nobody can establish.
        // An answer names the transport of the connection whose resource it resolves; everything
        // else takes the instance's own.
        let dispatch = transport
            .or_else(|| instance.dispatch.clone())
            .ok_or_else(|| BrokerError::UnsupportedCapability {
                detail: format!(
                    "nothing carries a {operation} to {application_instance_id}: this instance \
                     has no upstream transport bound, so the operation is refused rather than \
                     reported as applied"
                ),
            })?;
        if let Some(reason) = instance.rich_suspension.as_ref() {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("rich mutations are suspended: {reason}"),
            });
        }
        if instance.binding_revision != target.binding_revision {
            return Err(BrokerError::StaleBinding {
                detail: format!(
                    "{operation} was prepared at binding revision {} and the binding is at {}",
                    target.binding_revision, instance.binding_revision
                ),
            });
        }
        // The turn a mutation names is the turn this instance is running, read here rather than
        // before the lock: a turn that ended between the two would otherwise be steered.
        if let Some(turn_id) = turn_id.as_ref()
            && instance.turn_id.as_ref() != Some(turn_id)
        {
            return Err(BrokerError::PreconditionFailed {
                detail: format!("{turn_id} is not the turn this instance is running"),
            });
        }
        let binding_revision = instance.binding_revision;
        self.check_responsible(application_instance_id, responsible)?;
        // The capability is rechecked independently of everything else, because it answers its own
        // question: the grant says whether this actor may, and this says whether it would work. An
        // operation that names none has none to recheck.
        if let Some(capability_id) = capability.as_ref() {
            self.capabilities
                .recheck(application_instance_id, capability_id, None)?;
        }
        let request = crate::broker::methods::UpstreamRequest {
            admitted: crate::broker::methods::Admitted::new(),
            application_instance_id,
            binding_revision,
            operation,
            turn_id,
            body,
        };
        Ok(crate::broker::methods::MutationAdmission::new(
            request,
            dispatch,
            responsible,
            capability,
            now,
        ))
    }

    /// Reconciles one upstream's records with what it still has pending. See
    /// [`Broker::reconcile`].
    fn reconcile_in(
        &mut self,
        scope: ReconcileScope,
        still_open: &[DownstreamRequestId],
        now: TimestampMs,
    ) -> Result<Reconciliation> {
        let (reconciliation, transitions) = self.arbitration.plan_reconcile(scope, still_open);
        for transition in transitions {
            self.commit_transition(
                transition,
                now,
                crate::broker::ledger::TransitionCause::Reconciliation,
                None,
            )?;
        }
        Ok(reconciliation)
    }

    /// Returns one action's current declaration, under the lock this state is read with.
    fn registered_action_in(
        &self,
        binding_id: BrokerBindingId,
        action: &ActionName,
    ) -> Result<Option<crate::broker::methods::RegisteredAction>> {
        let binding = self
            .bindings
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        Ok(binding.actions.get(action).cloned())
    }

    /// Rechecks one spent token's own authority, under the lock this state is read with.
    fn check_invocation_for(
        &self,
        binding_id: BrokerBindingId,
        token: &ActionToken,
        capability: Option<CapabilityId>,
    ) -> Result<BrokerGrants> {
        // Rich work is fenced while the journal is faulted, and carrying a component's effect is
        // rich work. A fence that came down while the component was preparing its plan is the
        // same refusal as a grant withdrawn while it was preparing one.
        self.volatile.require_rich_work()?;
        let invocation = Invocation {
            actor_id: token.actor_id.clone(),
            grant: token.grant,
            grant_id: token.grant_id.as_ref().copied(),
            application_instance_id: token.application_instance_id,
            binding_revision: token.binding_revision,
            action: token.action.clone(),
            draft_id: token.draft_id.as_ref().copied(),
            capability: capability.map(|capability| (capability, None)),
            parameters: Vec::new(),
        };
        self.check_invocation(binding_id, &invocation)
    }

    /// Reads one action's current declaration and checks what the call says about it.
    ///
    /// It reads the declaration under the broker's own lock, which is what keeps a replacement
    /// registration from landing between the read and the admission that depends on it.
    fn check_action_in(
        &self,
        binding_id: BrokerBindingId,
        params: &kr_protocol::agent::PluginActionInvokeParams,
    ) -> Result<crate::broker::methods::RegisteredAction> {
        let binding = self
            .bindings
            .get(&binding_id)
            .ok_or_else(|| unknown_binding(binding_id))?;
        let registered = binding
            .actions
            .get(&params.action)
            .cloned()
            .ok_or_else(|| {
                BrokerError::unknown(format!(
                    "{} is not an action {} registered",
                    params.action, params.plugin_id
                ))
            })?;
        if registered.effect != kr_protocol::authority::EffectClass::Write {
            return Err(BrokerError::invalid(format!(
                "{} is a read, and this is the write path",
                params.action
            )));
        }
        if !registered.needs_draft && params.draft_id.is_present() {
            return Err(BrokerError::invalid(format!(
                "{} acts on no draft and this call named one",
                params.action
            )));
        }
        Ok(registered)
    }

    /// Returns the tables this host pinned for one installation's package.
    fn pinned_table(
        &self,
        application_instance_id: ApplicationInstanceId,
        plugin_id: &PluginId,
    ) -> Result<PinnedTable> {
        self.pinned_tables
            .get(&(application_instance_id, plugin_id.clone()))
            .cloned()
            .ok_or_else(|| {
                BrokerError::denied(format!(
                    "no declarative table of {plugin_id} is pinned for \
                     {application_instance_id}, and the core interprets frames only with a table \
                     this host installed"
                ))
            })
    }

    /// Mints the next gateway connection identifier, above everything this ledger has seen.
    fn mint_connection(&mut self) -> GatewayConnectionId {
        self.next_connection = self.next_connection.saturating_add(1);
        GatewayConnectionId::new(self.next_connection)
    }

    /// Returns one pending resource, or says this broker does not hold it.
    fn pending_resource(&self, resource_id: PendingResourceId) -> Result<&Pending> {
        self.arbitration
            .get(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))
    }

    /// Returns the binding whose decoder interpreted one resource, where one did.
    fn decoder_of(&self, resource_id: PendingResourceId) -> Option<BrokerBindingId> {
        self.arbitration
            .get(resource_id)
            .and_then(|pending| pending.decoder)
    }

    /// Checks the component answerable for one dispatch, at admission.
    ///
    /// A fault disables one binding's rich capabilities. Asking only whether *every* binding is
    /// disabled would let an unrelated working component admit a mutation through the one that is
    /// not working, so the binding that actually carries this dispatch is the one checked.
    fn check_responsible(
        &self,
        application_instance_id: ApplicationInstanceId,
        responsible: crate::broker::methods::Responsible,
    ) -> Result<()> {
        match responsible {
            crate::broker::methods::Responsible::Binding(binding_id) => {
                let binding = self
                    .bindings
                    .get(&binding_id)
                    .ok_or_else(|| unknown_binding(binding_id))?;
                if binding.application_instance_id != application_instance_id {
                    return Err(BrokerError::denied(format!(
                        "binding {binding_id} is not bound to {application_instance_id}"
                    )));
                }
                if let Some(reason) = binding.rich_disabled.as_ref() {
                    return Err(BrokerError::UnsupportedCapability {
                        detail: format!(
                            "the component answerable for this operation has had its rich \
                             capabilities disabled: {reason}"
                        ),
                    });
                }
                Ok(())
            }
            // No component gives a prompt, a steer or a cancellation its meaning: the connector
            // that owns the connection encodes it. What would stop one is every component of the
            // instance being disabled, because then nothing is interpreting this upstream at all.
            crate::broker::methods::Responsible::Transport => {
                let mut bound = self
                    .bindings
                    .values()
                    .filter(|binding| binding.application_instance_id == application_instance_id)
                    .peekable();
                if bound.peek().is_some() && bound.all(|binding| binding.rich_disabled.is_some()) {
                    return Err(BrokerError::UnsupportedCapability {
                        detail: format!(
                            "every component bound to {application_instance_id} has had its rich \
                             capabilities disabled"
                        ),
                    });
                }
                Ok(())
            }
        }
    }

    /// Commits one planned transition and tells every authorised observer about it.
    ///
    /// Three things happen in one place because they are one fact. The transition and the event
    /// that announces it are written in one ledger transaction, so a crash cannot leave a change
    /// nobody was told about. The arbitration is then committed. And the observers are told while
    /// this lock is still held.
    ///
    /// That last part is the ordering guarantee. Two tasks settling two resources of one instance
    /// are serialised by this lock, so the order the observers are told in is the order the
    /// transitions committed in. Publishing after the lock was given back can be overtaken, and an
    /// observer would then read a `Pending` after the `Resolved` that replaced it. Publication
    /// itself never blocks: each observer's queue is bounded and a subscriber that has stopped
    /// reading is withdrawn rather than waited for.
    fn commit_transition(
        &mut self,
        transition: Transition,
        now: TimestampMs,
        cause: crate::broker::ledger::TransitionCause,
        actor_id: Option<ActorId>,
    ) -> Result<PendingResource> {
        let event = self.next_transition_event(&transition.resource, now, cause, actor_id);
        self.write_transition(&transition, now, &event)?;
        // Recorded as this resource's latest only once the write has succeeded, so a transition
        // that failed does not become the parent of one that did.
        self.remember(&event);
        let settled = self.arbitration.commit(transition)?;
        self.publish(&settled, &event);
        Ok(settled)
    }

    /// Takes the next position in this broker's stream of transitions.
    ///
    /// A transition whose durable write then fails leaves its number unused. The cursor says what
    /// order things happened in; it does not promise that every number was spent. A consumer
    /// deduplicates on the event's own identifier, which is what section 24 makes immutable.
    ///
    /// A transition made while the journal is faulted is published and not recorded, exactly as
    /// the resource itself is: the event says `volatile`, and the gap is what records that the
    /// stretch happened at all. Across a restart the numbering resumes above the recorded events.
    /// Under the cursor-reset contract in [`Broker::transitions_after`], if an observer reconnects
    /// with a volatile cursor beyond the durable boundary, the cursor is reset to the start of the
    /// stream so that subsequent durable events are never hidden.
    fn next_transition_event(
        &mut self,
        resource: &PendingResource,
        now: TimestampMs,
        cause: crate::broker::ledger::TransitionCause,
        actor_id: Option<ActorId>,
    ) -> crate::broker::ledger::TransitionEvent {
        let sequence = self.next_event;
        self.next_event = self.next_event.saturating_add(1);
        let binding_revision = self
            .instances
            .get(&resource.application_instance_id)
            .map_or_else(
                || AgentBindingRevision::new(0),
                |instance| instance.binding_revision,
            );
        let parent_sequence = self.announced.get(&resource.resource_id).copied();
        crate::broker::ledger::TransitionEvent {
            sequence,
            event_id: Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()),
            application_instance_id: resource.application_instance_id,
            resource_id: resource.resource_id,
            binding_revision,
            state: resource.state,
            classification: resource.classification,
            content: crate::broker::ledger::content_class(resource),
            durability: resource.durability,
            cause,
            actor_id,
            causal_root: resource.request.to_string(),
            parent_sequence,
            recorded_at: now,
        }
    }

    /// Notes one position that was announced and could not be written.
    ///
    /// No read returns it, so a consumer reading from below it is told that something after its
    /// cursor is lost rather than handed a shorter history it would take for a complete one.
    fn announced_without_record(&mut self, event: &crate::broker::ledger::TransitionEvent) {
        self.unrecorded_after = self.unrecorded_after.max(event.sequence);
    }

    /// Records one written event as the latest about its resource, so the next names it.
    ///
    /// A resource that has reached a state nothing follows has no next event, so it stops being
    /// remembered rather than staying for the life of the process.
    fn remember(&mut self, event: &crate::broker::ledger::TransitionEvent) {
        if event.state.is_terminal() {
            self.announced.remove(&event.resource_id);
        } else {
            self.announced.insert(event.resource_id, event.sequence);
        }
    }

    /// Tells every authorised observer of one instance what its resource became.
    ///
    /// Who is authorised is this state's own answer: a connection observes the instance it was
    /// opened against, and nothing else is told.
    fn publish(&self, resource: &PendingResource, event: &crate::broker::ledger::TransitionEvent) {
        let authorised: Vec<GatewayConnectionId> = self
            .gateway
            .observers(resource.application_instance_id)
            .map(|connection| connection.connection)
            .collect();
        self.watchers.publish(
            &authorised,
            &crate::broker::duplex::ResourceTransition {
                sequence: event.sequence,
                event_id: event.event_id,
                application_instance_id: resource.application_instance_id,
                resource_id: resource.resource_id,
                binding_revision: event.binding_revision,
                state: resource.state,
                content: event.content,
                durability: event.durability,
                cause: event.cause,
                actor_id: event.actor_id.clone(),
                causal_root: event.causal_root.clone(),
                parent_sequence: event.parent_sequence,
            },
        );
    }

    /// Writes one planned transition durably, conditional on the state it expects to find.
    ///
    /// A volatile record is not written: that is what volatile means, and writing it would be the
    /// manufactured durable history section 11 forbids. The event goes with it or not at all, so
    /// the outbox never records a transition the ledger does not hold.
    fn write_transition(
        &mut self,
        transition: &Transition,
        now: TimestampMs,
        event: &crate::broker::ledger::TransitionEvent,
    ) -> Result<()> {
        // What decides whether a write happens is whether the ledger can take one now, not the
        // evidence quality of the resource's own history. A resource that lived through a gap
        // keeps `durability = volatile` for ever, because that is what its history was; its later
        // transitions are still written down.
        if !self.volatile.writes_are_durable() {
            self.announced_without_record(event);
            return Ok(());
        }
        self.ledger.settle_pending(
            &transition.resource,
            transition.from,
            transition.sets_marker(),
            now,
            event,
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
    /// Evidence that names a binary, a package, a publisher, a schema, a launch profile or a
    /// binding has to name *this* one. Without the check a record gathered against another binary
    /// or another package would be accepted for this instance and would then pass every later
    /// recheck, because those compare the revision and the state and not what the evidence was
    /// about.
    ///
    /// Every field is compared against something this host established itself, and a field it
    /// cannot check is a field it refuses. Evidence about a binary this host has no recorded
    /// launch for says nothing verifiable about the process that is running.
    fn check_evidence_identity(&self, record: &InstanceCapabilityRecord) -> Result<()> {
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
            // The launch profile is where this host recorded what it resolved and started. An
            // instance it adopted rather than launched has no profile and still has a managed
            // process, whose handle names the executable this host is talking to. Either is an
            // identity this host established; with neither there is nothing to check against, and
            // an unverifiable claim about the running binary is the one worth making falsely.
            let known = self
                .profiles
                .profile_of(record.application_instance_id)
                .map(|profile| profile.binary.digest)
                .or_else(|| {
                    instance
                        .process
                        .as_ref()
                        .map(|process| process.handle.executable_digest)
                })
                .ok_or_else(|| {
                    BrokerError::invalid(
                        "this evidence names a binary and this host has neither a launch profile \
                         nor a managed process for this instance, so there is nothing to check it \
                         against",
                    )
                })?;
            if &known != digest {
                return Err(BrokerError::invalid(
                    "this evidence was gathered against another binary than the one running",
                ));
            }
        }
        let binding = match record.identity.binding_id.as_ref() {
            Some(binding_id) => {
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
                Some(binding)
            }
            None => None,
        };
        // The package, its bytes and its publisher, against the binding the evidence came through
        // or the table this host pinned for that package. A record naming a package this
        // installation does not run is evidence about something else.
        if let Some(plugin_id) = record.identity.plugin_id.as_ref() {
            let installed = binding.map_or_else(
                || {
                    self.pinned_tables
                        .contains_key(&(record.application_instance_id, plugin_id.clone()))
                },
                |binding| &binding.plugin_id == plugin_id,
            );
            if !installed {
                return Err(BrokerError::invalid(format!(
                    "this evidence is about {plugin_id}, which is not installed for {}",
                    record.application_instance_id
                )));
            }
        } else if record.identity.package_digest.is_present()
            || record.identity.publisher_id.is_present()
            || record.identity.schema_version.is_present()
        {
            return Err(BrokerError::invalid(
                "this evidence names a package's bytes, publisher or schema without naming the \
                 package, so there is nothing to check them against",
            ));
        }
        if let Some(package_digest) = record.identity.package_digest.as_ref() {
            let binding = binding.ok_or_else(|| {
                BrokerError::invalid(
                    "this evidence names package bytes and no binding, and a binding is where \
                     this host knows what bytes it loaded",
                )
            })?;
            if &binding.package_digest != package_digest {
                return Err(BrokerError::invalid(
                    "this evidence was gathered against other package bytes than the ones bound",
                ));
            }
        }
        if let Some(publisher_id) = record.identity.publisher_id.as_ref() {
            let installed = binding.map_or_else(
                || {
                    record
                        .identity
                        .plugin_id
                        .as_ref()
                        .and_then(|plugin_id| {
                            self.pinned_tables
                                .get(&(record.application_instance_id, plugin_id.clone()))
                        })
                        .is_some_and(|pinned| &pinned.table.publisher_id == publisher_id)
                },
                |binding| &binding.publisher_id == publisher_id,
            );
            if !installed {
                return Err(BrokerError::invalid(format!(
                    "this evidence names publisher {publisher_id} and another publishes what is \
                     installed here"
                )));
            }
        }
        // The schema the evidence is about is the upstream version the pinned table qualified
        // against. Evidence gathered against another version describes another protocol.
        if let Some(schema_version) = record.identity.schema_version.as_ref() {
            let pinned = record
                .identity
                .plugin_id
                .as_ref()
                .and_then(|plugin_id| {
                    self.pinned_tables
                        .get(&(record.application_instance_id, plugin_id.clone()))
                })
                .ok_or_else(|| {
                    BrokerError::invalid(
                        "this evidence names a schema version and no table is pinned for its \
                         package, so there is nothing to check it against",
                    )
                })?;
            if pinned.table.upstream_protocol_version != schema_version.0 {
                return Err(BrokerError::invalid(format!(
                    "this evidence was gathered against upstream schema {} and {} is pinned here",
                    schema_version.0, pinned.table.upstream_protocol_version
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
