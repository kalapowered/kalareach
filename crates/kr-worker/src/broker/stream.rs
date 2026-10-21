//! What a gateway connection's stream says about the terminal's conversation and turn, and what the
//! broker does about it.
//!
//! The terminal behind a gateway starts, resumes, forks and leaves conversations, and the server
//! it speaks to answers or announces each in its own protocol. A connector's table says which
//! messages those are and where in them the thread and the turn are named (see
//! [`Reading`](crate::broker::reading::Reading)); this module reads them and keeps the instance's
//! binding true to them. Thread identity never comes from matching prompt text and timestamps.
//!
//! # What holds rich mutations back
//!
//! Rich mutations are suspended, with a reason of their own, for as long as the broker cannot say
//! which conversation the terminal is in:
//!
//! * a request of the terminal's that selects or leaves a conversation is in flight, since a
//!   mutation admitted meanwhile would reach the conversation being left;
//! * the outcome of such a request is unknown (its reply was unreadable, it was given up at the
//!   deadline or its connection ended, or its bytes went in part), or the conversation it selected
//!   belongs to another live execution;
//! * no reply has named a conversation yet ([`THREAD_NOT_READ`](crate::broker::THREAD_NOT_READ),
//!   set at launch).
//!
//! Only the reply to the selecting request admitted last is adopted. Replies can come in any
//! order, and an older one never restores a conversation the terminal has left or clears the
//! uncertainty of a later request.
//!
//! A permit admitted before any of this happened is checked again when it is taken: see
//! [`Broker::take_mutation`](crate::broker::Broker::take_mutation).

use std::collections::BTreeMap;

use kr_protocol::broker::{
    InstanceCapabilityIdentity, InstanceCapabilityRecord, InstanceCapabilityState,
    InstanceEvidenceSource, InstanceInvalidation,
};
use kr_protocol::gateway::RichOperation;
use kr_protocol::ids::{
    AgentThreadId, AgentTurnId, ApplicationInstanceId, CapabilityId, CapabilityRevision,
    GatewayConnectionId, PendingResourceId, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::scalars::{Nullable, TimestampMs};

use crate::broker::connectors::DECISION_SCHEMA;
use crate::broker::error::{BrokerError, Result};
use crate::broker::gateway::{identifier_of, member_at};
use crate::broker::ledger::TransitionCause;
use crate::broker::{Broker, BrokerState, OnStoreFault, THREAD_NOT_READ};
use kr_protocol::gateway::DownstreamRequestId;

/// Why rich mutations wait while a request of the terminal's that selects or leaves a conversation
/// has not been answered.
const SELECTION_IN_FLIGHT: &str = "the terminal has asked to change its conversation and the \
                                   server has not answered, so which conversation it is in is \
                                   unknown";

/// Why rich mutations wait after such a request ended in a way that does not say what became of
/// it.
const SELECTION_UNKNOWN: &str = "what became of the terminal's last request to change its \
                                 conversation is unknown, so which conversation it is in is \
                                 unknown";

/// What a request of the terminal's that is still open is, as far as the broker's reading goes.
#[derive(Clone, Debug)]
enum OpenKind {
    /// A request whose success reply names the conversation the terminal selected, and where.
    Selection(kr_plugin_sdk::connector::FieldPath),
    /// A request that leaves the conversation it names.
    Leave(Option<String>),
    /// A request the connector's table does not classify, whose effect is unknown.
    Unlisted,
}

/// One request of the terminal's forwarded to the server and not yet answered or given up.
#[derive(Clone, Debug)]
struct OpenRequest {
    seq: u64,
    kind: OpenKind,
}

/// Why the instance stays suspended after a selection's outcome was lost or refused.
#[derive(Clone, Debug)]
struct Hold {
    /// The request that left it, by sequence number.
    seq: u64,
    reason: String,
}

/// What the broker keeps of one gateway-served instance's stream.
#[derive(Debug, Default)]
pub struct StreamState {
    next_seq: u64,
    /// The requests of the terminal's still open, by the identifier this host forwarded them
    /// under.
    open: BTreeMap<UpstreamRequestId, OpenRequest>,
    /// The sequence number of the last reply adopted.
    adopted: u64,
    hold: Option<Hold>,
    /// The sequence number of the last frame of an unlisted method, which suspended rich mutations
    /// for a reason of its own.
    unlisted: Option<u64>,
}

impl StreamState {
    /// Returns why rich mutations wait on the stream, while they do.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        if self
            .open
            .values()
            .any(|open| matches!(open.kind, OpenKind::Selection(_) | OpenKind::Leave(_)))
        {
            return Some(SELECTION_IN_FLIGHT);
        }
        self.hold.as_ref().map(|hold| hold.reason.as_str())
    }

    fn take_seq(&mut self) -> u64 {
        self.next_seq = self.next_seq.saturating_add(1);
        self.next_seq
    }

    /// Notes a frame of an unlisted method.
    pub(super) fn note_unlisted(&mut self) -> u64 {
        let seq = self.take_seq();
        self.unlisted = Some(seq);
        seq
    }

    /// Forgets a request of the terminal's that will not be answered, and says whether the server
    /// may have read it.
    pub(super) fn give_up(&mut self, id: &UpstreamRequestId, unknown: bool) {
        if let Some(open) = self.open.remove(id)
            && unknown
            && matches!(open.kind, OpenKind::Selection(_) | OpenKind::Leave(_))
        {
            self.hold_unknown(open.seq);
        }
    }

    /// Holds the instance back, because what became of request `seq` is unknown, unless a later
    /// reply has already been adopted.
    fn hold_unknown(&mut self, seq: u64) {
        if seq <= self.adopted {
            return;
        }
        let later = self.hold.as_ref().is_some_and(|hold| hold.seq > seq);
        if !later {
            self.hold = Some(Hold {
                seq,
                reason: SELECTION_UNKNOWN.to_owned(),
            });
        }
    }
}

/// Reads a thread or a turn named in a message, where the message names one as text.
fn named(value: &serde_json::Value, path: &kr_plugin_sdk::connector::FieldPath) -> Option<String> {
    member_at(value, path)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

impl BrokerState {
    /// Notes a request of the terminal's that has just been admitted, and returns the identifier
    /// it stays open under when it is one whose reply or end matters.
    ///
    /// A request that selects or leaves a conversation takes the next sequence number as the one
    /// whose reply may be adopted, and a request the table does not classify is noted so that the
    /// suspension it caused lifts only when a later selection has named the conversation and every
    /// such request before it has been answered.
    pub(super) fn stream_admit(
        &mut self,
        connection: GatewayConnectionId,
        application_instance_id: ApplicationInstanceId,
        method: &UpstreamMethod,
        frame: &[u8],
        upstream_request_id: Option<&UpstreamRequestId>,
        unlisted: bool,
    ) -> Option<UpstreamRequestId> {
        let reading = self
            .gateway
            .connection(connection)
            .and_then(|held| held.reading.clone());
        let instance = self.instances.get_mut(&application_instance_id)?;
        let kind = match reading.as_deref() {
            Some(reading) if reading.selections.contains_key(method) => reading
                .selections
                .get(method)
                .cloned()
                .map(OpenKind::Selection),
            Some(reading) if reading.leaves.contains_key(method) => {
                let named_by = reading.leaves.get(method).and_then(|path| {
                    serde_json::from_slice::<serde_json::Value>(frame)
                        .ok()
                        .and_then(|body| named(&body, path))
                });
                Some(OpenKind::Leave(named_by))
            }
            _ => None,
        };
        match kind {
            Some(kind) => {
                let id = upstream_request_id?.clone();
                let seq = instance.stream.take_seq();
                instance
                    .stream
                    .open
                    .insert(id.clone(), OpenRequest { seq, kind });
                Some(id)
            }
            None if unlisted => {
                let seq = instance.stream.note_unlisted();
                let id = upstream_request_id?.clone();
                instance.stream.open.insert(
                    id.clone(),
                    OpenRequest {
                        seq,
                        kind: OpenKind::Unlisted,
                    },
                );
                Some(id)
            }
            None => None,
        }
    }

    /// Takes the conversation a reply named as the instance's binding, or holds the instance back
    /// when it cannot be taken.
    fn adopt_thread(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        seq: u64,
        thread: Option<AgentThreadId>,
        now: TimestampMs,
    ) {
        let current = self
            .instances
            .get(&application_instance_id)
            .and_then(|instance| instance.thread_id.clone());
        let mut refusal = None;
        if current != thread
            && let Err(error) = self.advance_binding(application_instance_id, thread.clone(), now)
        {
            // Another live execution owns the conversation the terminal selected. It is never
            // published as this instance's binding: the binding becomes none, and the instance
            // says why it waits.
            let _ = self.advance_binding(application_instance_id, None, now);
            refusal = Some(format!(
                "the conversation the terminal selected cannot be bound here: {error}"
            ));
        }
        let selected = refusal.is_none() && thread.is_some();
        let Some(instance) = self.instances.get_mut(&application_instance_id) else {
            return;
        };
        instance.stream.adopted = instance.stream.adopted.max(seq);
        // Every selecting or leaving request older than the one adopted is superseded: its reply,
        // when it comes, is ignored, and it holds nothing back meanwhile.
        instance
            .stream
            .open
            .retain(|_, other| matches!(other.kind, OpenKind::Unlisted) || other.seq > seq);
        instance.thread_unread = (!selected).then_some(THREAD_NOT_READ);
        instance.stream.hold = match refusal {
            Some(reason) => Some(Hold { seq, reason }),
            None => instance.stream.hold.take().filter(|hold| hold.seq > seq),
        };
        // An unlisted frame's suspension lifts when a conversation was named after it and no
        // unlisted request before that is still unanswered.
        if let Some(unlisted) = instance.stream.unlisted
            && unlisted < seq
            && !instance
                .stream
                .open
                .values()
                .any(|open| matches!(open.kind, OpenKind::Unlisted) && open.seq < seq)
        {
            instance.rich_suspension = None;
            instance.stream.unlisted = None;
        }
        self.renew_gateway_evidence(application_instance_id, now);
    }

    /// Applies the reply to one request of the terminal's that was open.
    fn stream_replied(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        open: &OpenRequest,
        succeeded: bool,
        body: &serde_json::Value,
        now: TimestampMs,
    ) {
        let Some(instance) = self.instances.get(&application_instance_id) else {
            return;
        };
        // Only the reply to the newest request that has not ended in a proven refusal is adopted.
        // An older one is superseded: it changes nothing, so it never restores a conversation the
        // terminal has left, and it never clears the uncertainty of a later request.
        let stream = &instance.stream;
        let newer_open = stream
            .open
            .values()
            .any(|other| other.seq > open.seq && !matches!(other.kind, OpenKind::Unlisted));
        let newer_held = stream.hold.as_ref().is_some_and(|hold| hold.seq > open.seq);
        if open.seq <= stream.adopted || newer_open || newer_held {
            return;
        }
        // An error reply is a refusal the server proved: the terminal changes its conversation only
        // on a success reply that names it, so nothing changed.
        if !succeeded {
            return;
        }
        match &open.kind {
            OpenKind::Selection(path) => {
                match named(body, path).and_then(|thread| AgentThreadId::new(thread).ok()) {
                    Some(thread) => {
                        self.adopt_thread(application_instance_id, open.seq, Some(thread), now)
                    }
                    None => {
                        if let Some(instance) = self.instances.get_mut(&application_instance_id) {
                            instance.stream.hold_unknown(open.seq);
                        }
                    }
                }
            }
            OpenKind::Leave(left) => {
                let bound = instance.thread_id.as_ref().map(ToString::to_string);
                if left.is_some() && *left == bound {
                    self.adopt_thread(application_instance_id, open.seq, None, now);
                } else if let Some(instance) = self.instances.get_mut(&application_instance_id) {
                    // A conversation other than the bound one was left: the binding stands, and
                    // the request no longer holds anything back.
                    instance.stream.adopted = instance.stream.adopted.max(open.seq);
                }
            }
            OpenKind::Unlisted => {}
        }
    }

    /// Records what the capability map says about a gateway-served instance: what the connection's
    /// tables let a client do, and whether the package may answer an approval.
    ///
    /// The evidence is the connection's own (`LiveBinding`), the vocabulary a channel's is written
    /// in. Evidence about the thread the binding names is invalidated by every change of binding,
    /// so this runs again after each, and when the binding's grants change.
    pub(super) fn renew_gateway_evidence(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        now: TimestampMs,
    ) {
        let Some(connection) = self.gateway.native_connection_of(application_instance_id) else {
            return;
        };
        let rich = connection.rich.clone();
        let reading = connection.reading.clone();
        let connection_id = connection.connection;
        let Some(package) = self.connection_packages.get(&connection_id).cloned() else {
            return;
        };
        let Some(instance) = self.instances.get(&application_instance_id) else {
            return;
        };
        let mut identity = InstanceCapabilityIdentity {
            profile_id: Nullable::from(instance.profile_id.clone()),
            binary_digest: Nullable::from(
                instance
                    .process
                    .as_ref()
                    .map(|launched| launched.handle.executable_digest),
            ),
            ..InstanceCapabilityIdentity::default()
        };
        let binding = self.bindings.values().find(|binding| {
            binding.application_instance_id == application_instance_id
                && binding.package() == package
        });
        identity.plugin_id = Nullable::some(package.plugin_id.clone());
        identity.package_digest = Nullable::some(package.package_digest);
        identity.publisher_id = Nullable::some(package.publisher_id.clone());
        identity.binding_id = Nullable::from(binding.map(|binding| binding.binding_id));
        identity.binding_revision = Nullable::some(instance.binding_revision);
        let operation = |operation: RichOperation, what: &str| {
            rich.for_operation(operation)
                .map(|_| ())
                .map_err(|_| format!("this connector's table declares no way to {what}"))
        };
        let answers = match (&reading, binding) {
            (Some(reading), Some(binding)) => reading.answers.as_ref().map_or_else(
                || Err("this connector's table answers no approval".to_owned()),
                |answers| {
                    if answers
                        .methods
                        .iter()
                        .any(|method| binding.may_encode(method))
                    {
                        Ok(())
                    } else {
                        Err(
                            "this package is not trusted to answer the approvals its table \
                             names"
                                .to_owned(),
                        )
                    }
                },
            ),
            _ => Err("this connector's table answers no approval".to_owned()),
        };
        let wanted = [
            (
                "agent.prompt",
                operation(RichOperation::PromptSubmit, "submit a prompt"),
            ),
            (
                "agent.prompt.queue",
                operation(RichOperation::PromptQueue, "queue a prompt"),
            ),
            (
                "agent.steer",
                operation(RichOperation::TurnSteer, "steer a turn"),
            ),
            (
                "agent.cancel",
                operation(RichOperation::TurnCancel, "cancel a turn"),
            ),
            ("agent.approval", answers),
        ];
        for (name, outcome) in wanted {
            let Ok(capability_id) = CapabilityId::new(name) else {
                continue;
            };
            let held = self
                .capabilities
                .map(application_instance_id)
                .record(&capability_id)
                .cloned();
            let (state, reason) = match outcome {
                Ok(()) => (InstanceCapabilityState::QualifiedAvailable, None),
                Err(reason) => (InstanceCapabilityState::Incompatible, Some(reason)),
            };
            // Only a change is recorded, as the next revision of the capability's record, so a
            // stream of selections does not move a revision a client read for nothing.
            if held.as_ref().is_some_and(|record| {
                record.state == state
                    && record.source == InstanceEvidenceSource::LiveBinding
                    && record.identity == identity
                    && record.disabled_reason.as_ref() == reason.as_ref()
            }) {
                continue;
            }
            let revision = held.map_or(0, |record| record.revision.get());
            let _ = self.capabilities.record(InstanceCapabilityRecord {
                capability_id,
                capability_version: "1".to_owned(),
                application_instance_id,
                identity: identity.clone(),
                revision: CapabilityRevision::new(revision.saturating_add(1)),
                state,
                source: InstanceEvidenceSource::LiveBinding,
                invalidated_by: [
                    InstanceInvalidation::BinaryChanged,
                    InstanceInvalidation::BindingChanged,
                ]
                .into_iter()
                .collect(),
                disabled_reason: Nullable::from(reason),
                observed_at: now,
            });
        }
    }

    /// Withdraws what a gateway connection's evidence said, because the connection ended.
    pub(super) fn withdraw_gateway_evidence(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        now: TimestampMs,
    ) {
        let map = self.capabilities.map(application_instance_id);
        let records: Vec<InstanceCapabilityRecord> = map
            .usable()
            .filter(|record| {
                record.source == InstanceEvidenceSource::LiveBinding
                    && record.identity.plugin_id.is_present()
            })
            .cloned()
            .collect();
        for record in records {
            let _ = self.capabilities.record(InstanceCapabilityRecord {
                revision: CapabilityRevision::new(record.revision.get().saturating_add(1)),
                state: InstanceCapabilityState::TemporarilyUnavailable,
                disabled_reason: Nullable::some(
                    "the gateway connection that established this has ended".to_owned(),
                ),
                observed_at: now,
                ..record
            });
        }
    }
}

impl Broker {
    /// Applies the reply to one request of the terminal's, which the server answered.
    ///
    /// A reply to a request that selects or leaves a conversation is read by what the connector's
    /// table says it names. It is adopted only when it answers the selecting request admitted
    /// last; see the module's account of what holds rich mutations back.
    pub fn client_replied(
        &self,
        connection: GatewayConnectionId,
        upstream_request_id: &UpstreamRequestId,
        frame: &[u8],
        now: TimestampMs,
    ) {
        let mut state = self.state();
        let Some(application_instance_id) = state.gateway.instance_of(connection) else {
            return;
        };
        let Some(open) = state
            .instances
            .get_mut(&application_instance_id)
            .and_then(|instance| instance.stream.open.remove(upstream_request_id))
        else {
            return;
        };
        let (succeeded, body) = state.gateway.connection(connection).map_or_else(
            || (false, serde_json::Value::Null),
            |held| {
                let body: serde_json::Value =
                    serde_json::from_slice(frame).unwrap_or(serde_json::Value::Null);
                let succeeded = body
                    .as_object()
                    .is_some_and(|members| members.contains_key(&held.table.result_field));
                (succeeded, body)
            },
        );
        state.stream_replied(application_instance_id, &open, succeeded, &body, now);
    }

    /// Records that a request of the terminal's will not be answered: it was given up at its
    /// deadline, its connection ended, or its bytes never went or went in part.
    ///
    /// `unknown` says whether the server may have read it. A request that selects or leaves a
    /// conversation and may have been read leaves the instance suspended until a later reply names
    /// the conversation; one the server never saw leaves nothing behind.
    pub fn client_request_given_up(
        &self,
        connection: GatewayConnectionId,
        upstream_request_id: &UpstreamRequestId,
        unknown: bool,
    ) {
        let mut state = self.state();
        let Some(application_instance_id) = state.gateway.instance_of(connection) else {
            return;
        };
        let Some(instance) = state.instances.get_mut(&application_instance_id) else {
            return;
        };
        instance.stream.give_up(upstream_request_id, unknown);
    }

    /// Reads what one frame the server sent says about the terminal's conversation and turn, after
    /// the frame was recorded and forwarded.
    ///
    /// A notification that a turn started or ended in the bound conversation names the running
    /// turn; one that ends the bound conversation leaves the instance with none; and one that says
    /// a request was answered or cleared settles a pending resource nobody answered. A frame about
    /// another conversation changes nothing.
    pub fn read_upstream_frame(
        &self,
        connection: GatewayConnectionId,
        method: &UpstreamMethod,
        frame: &[u8],
        now: TimestampMs,
    ) {
        let mut state = self.state();
        let Some(reading) = state
            .gateway
            .connection(connection)
            .and_then(|held| held.reading.clone())
        else {
            return;
        };
        if !reading.reads_the_stream() {
            return;
        }
        let Some(application_instance_id) = state.gateway.instance_of(connection) else {
            return;
        };
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(frame) else {
            return;
        };
        let bound = state
            .instances
            .get(&application_instance_id)
            .and_then(|instance| instance.thread_id.as_ref().map(ToString::to_string));
        for (places, started) in [(&reading.turn_started, true), (&reading.turn_ended, false)] {
            let Some(places) = places.as_ref().filter(|places| &places.method == method) else {
                continue;
            };
            let (Some(thread), Some(turn)) =
                (named(&body, &places.thread), named(&body, &places.turn))
            else {
                continue;
            };
            if bound.as_deref() != Some(thread.as_str()) {
                continue;
            }
            let Ok(turn) = AgentTurnId::new(turn) else {
                continue;
            };
            let Some(instance) = state.instances.get_mut(&application_instance_id) else {
                continue;
            };
            if started {
                instance.turn_id = Some(turn);
            } else if instance.turn_id.as_ref() == Some(&turn) {
                instance.turn_id = None;
            }
        }
        if let Some(path) = reading.leaves.get(method)
            && named(&body, path).is_some_and(|thread| bound.as_deref() == Some(thread.as_str()))
        {
            state.adopt_thread_left(application_instance_id, now);
        }
        if let Some((resolved, path)) = reading.request_resolved.as_ref()
            && resolved == method
            && let Some(identifier) = member_at(&body, path)
            && let Ok(upstream) = identifier_of(identifier, "the cleared request")
        {
            let request = DownstreamRequestId::new(connection, upstream);
            state.stream_resolved(&request, now);
        }
    }

    /// Interprets one request a gateway connection forwarded from the terminal's server, from the
    /// connector table's own decision response, where the instance holds a binding of that package
    /// trusted to decode it.
    ///
    /// The projection is the table's: schema [`DECISION_SCHEMA`], the decisions the table maps in
    /// its order, labelled as the package's answer action labels them, and no summary (a view shows
    /// the source frame). It goes through the broker's own checks for an interpretation. Returns
    /// `None` where no binding may decode it: the resource then stays recorded, visible and
    /// unanswerable here, and the terminal answers it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for a resource this broker does not hold,
    /// [`BrokerError::InvalidArgument`] for one a connection that reads no decision response
    /// forwarded, and whatever the interpretation refuses.
    pub fn interpret_native(
        &self,
        resource_id: PendingResourceId,
        now: TimestampMs,
    ) -> Result<Option<kr_protocol::gateway::PendingResource>> {
        let mut state = self.state();
        let (binding_id, projection) = {
            let pending = state
                .arbitration
                .get(resource_id)
                .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?
                .resource
                .clone();
            let connection = pending.request.connection;
            let answers = state
                .gateway
                .connection(connection)
                .and_then(|held| held.reading.as_ref())
                .and_then(|reading| reading.answers.as_ref())
                .filter(|answers| answers.methods.contains(&pending.method))
                .ok_or_else(|| {
                    BrokerError::invalid(format!(
                        "{resource_id} is not a request this connection's table answers, so no \
                         table gives it a meaning"
                    ))
                })?
                .clone();
            let Some(package) = state.connection_package(connection) else {
                return Ok(None);
            };
            // A binding of exactly the package whose table the connection reads: the same
            // identifier at other bytes or from another publisher is another decoder, whose
            // meaning this table's answer would not carry.
            let Some(binding) = state.bindings.values().find(|binding| {
                binding.application_instance_id == pending.application_instance_id
                    && binding.package() == package
                    && binding.may_decode(&pending.method)
            }) else {
                return Ok(None);
            };
            (
                binding.binding_id,
                kr_protocol::broker::DecodedProjection {
                    schema_version: DECISION_SCHEMA.to_owned(),
                    summary: String::new(),
                    decisions: answers.offered,
                },
            )
        };
        state
            .interpret_in(binding_id, resource_id, projection, None, now)
            .map(Some)
    }
}

impl BrokerState {
    /// The bound conversation was ended by the server, so the instance has none.
    fn adopt_thread_left(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        now: TimestampMs,
    ) {
        if self
            .advance_binding(application_instance_id, None, now)
            .is_ok()
            && let Some(instance) = self.instances.get_mut(&application_instance_id)
        {
            instance.thread_unread = Some(THREAD_NOT_READ);
        }
        self.renew_gateway_evidence(application_instance_id, now);
    }

    /// Settles a pending resource the server says was answered or cleared.
    ///
    /// A resource nobody answered, or whose answer is reserved and has no marker, is cancelled: the
    /// server decided alone, and a rich answer waiting for its marker loses. A resource whose
    /// answer is dispatched and held by a writer is left to that writer, whose settlement says
    /// whether the answer went: the notification can arrive before the write is accounted for. One
    /// whose answer went before this process started is uncertain. One that has ended stays as it
    /// is.
    pub(super) fn stream_resolved(&mut self, request: &DownstreamRequestId, now: TimestampMs) {
        let Some(pending) = self.arbitration.by_request(request) else {
            return;
        };
        if pending.resource.state.is_terminal() {
            return;
        }
        if pending.dispatched
            && pending.transmitter != Some(crate::broker::arbitration::Transmitter::Spent)
        {
            return;
        }
        let Ok(transition) = self.arbitration.plan_upstream_resolved(request) else {
            return;
        };
        let _ = self.commit_transition(
            transition,
            now,
            TransitionCause::Upstream,
            None,
            OnStoreFault::CarryOn,
        );
    }
}
