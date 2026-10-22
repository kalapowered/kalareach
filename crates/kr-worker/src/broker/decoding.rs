//! What the worker takes of a component's decoding of a native request, and how a request gets to
//! be decoded.
//!
//! # Which decoder, and when
//!
//! [`Broker::interpret_request`] decides, once a request is recorded and forwarded, who gives it a
//! meaning. A package whose table the connection reads and that holds a binding trusted to decode
//! the method has one of two decoders. If the binding ships a component the component decodes, and
//! nothing else does: the request waits in a bounded queue ([`DecodeQueue`]) for the task of the
//! plugin runtime's link that asks the component (`crate::plugin_decoding`), and the terminal's own
//! answer waits for none of it. If the binding ships none the connector's table interprets it at
//! once, as it always did. The choice reads no component's state; whether the component then
//! decodes does, and a request whose component is unavailable, faults or declines stays recorded and
//! opaque for the terminal to answer, with no other decoder substituted.
//!
//! # What is taken of the answer
//!
//! A component that decodes proposes how it reads: the request it read, a one-line summary of what
//! answering yes would do, and the decisions it finds offered. The worker believes none of it as it
//! stands. The request a person will answer is the one the broker holds, the answers that can be
//! given are the ones the connector's table maps, and the words that name them are the table's. So
//! the proposal is turned into a [`DecodedProjection`] by [`project`], which refuses anything the
//! broker did not already know:
//!
//! * a request other than the one the component was handed;
//! * a decision the connector's table does not map to an answer, or one offered twice.
//!
//! The component chooses which of the mapped decisions to offer and in what order, since a decoder
//! is inside the trust boundary and the native terminal can still give any answer the upstream
//! accepts.
//! The summary is carried whole. A summary longer than the decoder's trust allows is refused by the
//! trust's own check when the broker interprets the projection, and is never cut to fit, since a
//! shortened sentence can say something the component did not. The component's own class for the
//! method and the document nodes it proposes to present the request with are not part of the
//! proposal: the connector's table classifies a method, and a person answers an approval, not a
//! component's drawing of one.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use kr_plugin_service::vocabulary::{ScopedSourceEvent, SourceProvenance};
use kr_protocol::admission::ComponentState;
use kr_protocol::broker::{
    DecodedProjection, MAX_RETAINED_SOURCE_BYTES, OfferedDecision, TrustError,
};
use kr_protocol::gateway::{PendingResource, PendingState};
use kr_protocol::ids::{BrokerBindingId, PendingResourceId, SourceEventHandle, UpstreamMethod};
use kr_protocol::scalars::TimestampMs;

use crate::broker::connectors::component_schema;
use crate::broker::{Broker, BrokerError, BrokerState};

/// What the broker's own operations return.
type BrokerResult<T> = crate::broker::Result<T>;

/// What a component proposed when it decoded a native request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentDecoded {
    /// The identifier the upstream gave the request, as the component read it.
    pub request_id: String,
    /// A one-line summary of what answering yes would do.
    pub summary: String,
    /// The decisions the component finds offered, as the identifiers the table maps.
    pub decisions: Vec<String>,
}

/// A proposal the worker will not turn into an approval.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeRefusal {
    /// The component decoded some other request than the one it was handed.
    #[error("the component read request {read:?}, and the request it was handed is {pending:?}")]
    OtherRequest {
        /// The identifier the component named.
        read: String,
        /// The identifier of the request that is waiting.
        pending: String,
    },
    /// A decision the connector's table does not map to an answer.
    #[error("the component offered {id:?}, which the connector's table does not map to an answer")]
    UnmappedDecision {
        /// The identifier the component offered.
        id: String,
    },
    /// A decision offered more than once.
    #[error("the component offered {id:?} more than once")]
    DuplicateDecision {
        /// The identifier it repeated.
        id: String,
    },
}

/// Turns a component's proposal into the projection the broker interprets, or refuses it.
///
/// `pending` is the identifier the upstream gave the request that is waiting, and `table` is the
/// decisions the connector's table maps for it, labelled as the package's answer action labels
/// them. The projection offers the decisions the component named, in the order it named them, each
/// under the table's label and none under the component's.
///
/// # Errors
///
/// Returns the first thing the worker will not believe: another request, a decision the table does
/// not map, or a decision offered twice.
pub fn project(
    decoded: &ComponentDecoded,
    pending: &str,
    table: &[OfferedDecision],
) -> Result<DecodedProjection, DecodeRefusal> {
    if decoded.request_id != pending {
        return Err(DecodeRefusal::OtherRequest {
            read: decoded.request_id.clone(),
            pending: pending.to_owned(),
        });
    }
    let mut decisions: Vec<OfferedDecision> = Vec::with_capacity(decoded.decisions.len());
    for id in &decoded.decisions {
        let Some(mapped) = table.iter().find(|mapped| mapped.option_id == *id) else {
            return Err(DecodeRefusal::UnmappedDecision { id: id.clone() });
        };
        if decisions.iter().any(|offered| offered.option_id == *id) {
            return Err(DecodeRefusal::DuplicateDecision { id: id.clone() });
        }
        decisions.push(mapped.clone());
    }
    Ok(DecodedProjection {
        schema_version: component_schema(),
        summary: decoded.summary.clone(),
        decisions,
    })
}

/// How many requests may wait to be decoded by components, all bindings together.
pub const MAX_QUEUED_DECODES: usize = 32;

/// How many of them may be one binding's: a binding that is flooded costs the others no more than
/// this.
pub const MAX_QUEUED_DECODES_PER_BINDING: usize = 8;

/// One request waiting for a component to decode it.
///
/// It names the request and does not hold its bytes: the task that asks the component reads them
/// from the instance's retained frames when it starts, so a request the instance has let go of is
/// not kept alive by a queue.
#[derive(Clone, Debug)]
pub struct DecodeJob {
    /// The recorded request.
    pub resource_id: PendingResourceId,
    /// The binding whose component decodes it.
    pub binding_id: BrokerBindingId,
    /// The method it names.
    pub method: UpstreamMethod,
    /// The identifier the upstream gave it, as the upstream wrote it.
    pub upstream_id: String,
    /// The retained frame it was recorded from.
    pub handle: SourceEventHandle,
    /// The decisions the connector's table maps for it, labelled as the package labels them.
    pub table: Vec<OfferedDecision>,
    /// Whether privacy mode stood when it was recorded: what a component is handed of a request
    /// made in privacy mode is made in it, however long the request waits.
    pub private: bool,
}

/// Why a request was not turned into an approval by its component, in the fixed words a person is
/// told.
///
/// A component's own words are never among them: the identifiers and texts it chose are not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotDecoded {
    /// The queue was full.
    QueueFull,
    /// The plugin runtime was not connected.
    NotConnected,
    /// The component was not registered and would not be, or was disabled.
    NotRegistered,
    /// The plugin runtime refused the request, was busy, or the call failed, ran out of time or
    /// lost its connection.
    Failed,
    /// The component declared a fault and decoded nothing.
    Declined,
    /// The component's answer was not a decoded request.
    NoAnswer,
    /// The answer named another request than the one it was asked about.
    OtherRequest,
    /// The answer offered a decision the connector's table does not map.
    UnmappedDecision,
    /// The answer offered a decision twice.
    DuplicateDecision,
    /// The answer offered no decision.
    NoDecisions,
    /// The answer's summary was over the bound.
    SummaryTooLong,
    /// The request was refused when the answer came: it had been answered, the source had moved on
    /// or the decoder's trust was gone.
    Refused,
}

impl NotDecoded {
    /// Returns the words a person is told.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::QueueFull => "the decoding queue was full",
            Self::NotConnected => "the plugin runtime was not connected",
            Self::NotRegistered => "the component was not registered or was disabled",
            Self::Failed => {
                "the plugin runtime refused the request or the call failed, ran out of time or lost \
                 its connection"
            }
            Self::Declined => "the component declined",
            Self::NoAnswer => "the component's answer was not a decoded request",
            Self::OtherRequest => "its answer named another request",
            Self::UnmappedDecision => {
                "its answer offered a decision the connector's table does not map"
            }
            Self::DuplicateDecision => "its answer offered a decision twice",
            Self::NoDecisions => "its answer offered no decision",
            Self::SummaryTooLong => "its summary was over the bound",
            Self::Refused => {
                "the request was refused when the answer came, because it had been answered, its \
                 source had moved on or the decoder's trust was gone"
            }
        }
    }
}

impl From<DecodeRefusal> for NotDecoded {
    fn from(refusal: DecodeRefusal) -> Self {
        match refusal {
            DecodeRefusal::OtherRequest { .. } => Self::OtherRequest,
            DecodeRefusal::UnmappedDecision { .. } => Self::UnmappedDecision,
            DecodeRefusal::DuplicateDecision { .. } => Self::DuplicateDecision,
        }
    }
}

/// What the task that asks components does with one waiting job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Ask the component now.
    Take,
    /// Leave it where it is: its component is not registered yet, or is being asked.
    Wait,
    /// It will not be asked, for this reason.
    Drop(NotDecoded),
}

/// Where a binding's component stands for a decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// Registered with the plugin runtime.
    Ready,
    /// Not registered yet: the link is registering it.
    Waiting,
    /// Never, or not any longer: refused, disabled, unavailable or gone.
    Never,
}

/// The requests waiting for a component to decode them.
///
/// A leaf lock, taken to push and to take, never across a call. A request is refused, and counted
/// by the caller, when the queue holds [`MAX_QUEUED_DECODES`] or its binding already has
/// [`MAX_QUEUED_DECODES_PER_BINDING`] waiting.
#[derive(Debug, Default)]
pub struct DecodeQueue {
    jobs: Mutex<VecDeque<DecodeJob>>,
    arrived: tokio::sync::Notify,
    /// The pause the task that asks components takes before it takes a job, for this host's own
    /// tests.
    #[cfg(feature = "testing")]
    hold: Arc<kr_plugin_service::hold::Hold>,
}

impl DecodeQueue {
    fn jobs(&self) -> std::sync::MutexGuard<'_, VecDeque<DecodeJob>> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues a job, and says whether the queue took it.
    pub fn push(&self, job: DecodeJob) -> bool {
        {
            let mut jobs = self.jobs();
            let theirs = jobs
                .iter()
                .filter(|waiting| waiting.binding_id == job.binding_id)
                .count();
            if jobs.len() >= MAX_QUEUED_DECODES || theirs >= MAX_QUEUED_DECODES_PER_BINDING {
                return false;
            }
            jobs.push_back(job);
        }
        self.arrived.notify_one();
        true
    }

    /// Returns the bindings that have a job waiting.
    #[must_use]
    pub fn bindings(&self) -> Vec<BrokerBindingId> {
        let mut bindings: Vec<BrokerBindingId> =
            self.jobs().iter().map(|job| job.binding_id).collect();
        bindings.sort();
        bindings.dedup();
        bindings
    }

    /// Takes the oldest job `judge` says to take, removes the ones it says to drop, and leaves the
    /// rest. Returns the job taken and each job dropped with its reason.
    pub fn take(
        &self,
        mut judge: impl FnMut(&DecodeJob) -> Verdict,
    ) -> (Option<DecodeJob>, Vec<(BrokerBindingId, NotDecoded)>) {
        let mut jobs = self.jobs();
        let mut dropped = Vec::new();
        let mut at = 0;
        while at < jobs.len() {
            match judge(&jobs[at]) {
                Verdict::Take => return (jobs.remove(at), dropped),
                Verdict::Wait => at += 1,
                Verdict::Drop(why) => {
                    if let Some(job) = jobs.remove(at) {
                        dropped.push((job.binding_id, why));
                    }
                }
            }
        }
        (None, dropped)
    }

    /// Returns how many jobs wait.
    #[must_use]
    pub fn len(&self) -> usize {
        self.jobs().len()
    }

    /// Returns true when no job waits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jobs().is_empty()
    }

    /// Wakes the task that takes jobs: something it was waiting for may have happened.
    pub fn wake(&self) {
        self.arrived.notify_one();
    }

    /// Waits until something may have changed for the jobs that wait.
    pub async fn wait(&self) {
        self.arrived.notified().await;
    }

    /// Holds the task that takes jobs, for this host's own tests: until the returned hold is
    /// released it takes none.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold(&self) -> kr_plugin_service::hold::HoldHandle {
        self.hold.set()
    }

    /// Waits at a hold a test has set.
    #[cfg(feature = "testing")]
    pub async fn pause(&self) {
        self.hold.pause().await;
    }
}

/// What decides who decodes a request.
enum Chosen {
    /// No binding may decode it.
    Nobody,
    /// The table of a gateway connection does.
    GatewayTable,
    /// The table of a channel does.
    ChannelTable,
    /// A component does.
    Component(DecodeJob),
}

impl BrokerState {
    /// Chooses who decodes one recorded request: the component of a binding that ships one, else
    /// the table.
    ///
    /// The binding is the package's own, on the request's instance, trusted to decode the method
    /// ([`crate::broker::Binding::may_decode`]); the package is the one whose table the connection
    /// reads, so another package's binding, or the same identifier at other bytes, is never chosen.
    /// Nothing about the component's state is read: a request that is not decoded because its
    /// component is down stays opaque, and the table does not stand in.
    fn choose_decoder(&self, resource_id: PendingResourceId) -> BrokerResult<Chosen> {
        let pending = self
            .arbitration
            .get(resource_id)
            .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?
            .resource
            .clone();
        let connection = pending.request.connection;
        let (offered, channel) = if let Some(channel) = self.gateway.channel(connection) {
            (channel.offered.clone(), true)
        } else if let Some(answers) = self
            .gateway
            .connection(connection)
            .and_then(|held| held.reading.as_ref())
            .and_then(|reading| reading.answers.as_ref())
            .filter(|answers| answers.methods.contains(&pending.method))
        {
            (answers.offered.clone(), false)
        } else {
            return Ok(Chosen::Nobody);
        };
        let Some(package) = self.connection_package(connection) else {
            return Ok(Chosen::Nobody);
        };
        let mut table = false;
        for binding in self.bindings.values().filter(|binding| {
            binding.application_instance_id == pending.application_instance_id
                && binding.package() == package
                && binding.may_decode(&pending.method)
        }) {
            if binding
                .component
                .as_ref()
                .is_some_and(|component| component.refusal.is_none())
            {
                let Some(handle) = self.arbitration.source_of(resource_id).cloned() else {
                    return Ok(Chosen::Nobody);
                };
                return Ok(Chosen::Component(DecodeJob {
                    resource_id,
                    binding_id: binding.binding_id,
                    method: pending.method.clone(),
                    upstream_id: pending.request.upstream.as_str().to_owned(),
                    handle,
                    table: offered,
                    private: false,
                }));
            }
            table = true;
        }
        Ok(match (table, channel) {
            (false, _) => Chosen::Nobody,
            (true, true) => Chosen::ChannelTable,
            (true, false) => Chosen::GatewayTable,
        })
    }
}

impl Broker {
    /// Returns the requests waiting for a component to decode them.
    #[must_use]
    pub fn decode_queue(&self) -> Arc<DecodeQueue> {
        Arc::clone(&self.decoding)
    }

    /// Gives a recorded request its meaning, or queues it for the component that will.
    ///
    /// Called after the request was recorded and forwarded, never before: the terminal's own answer
    /// does not wait for a meaning. The package's table interprets it at once when no binding of the
    /// package that ships a component may decode it ([`Self::interpret_native`] and
    /// [`Self::interpret_declared`] are the table's two paths); otherwise the component does, later,
    /// and what it proposes is checked in full when it comes back ([`Self::interpret_decoded`]).
    /// Returns the approval the request became where it became one now.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for a resource this broker does not hold, and what
    /// the table's interpretation refuses.
    pub fn interpret_request(
        &self,
        resource_id: PendingResourceId,
        now: TimestampMs,
    ) -> BrokerResult<Option<PendingResource>> {
        let chosen = self.state().choose_decoder(resource_id)?;
        match chosen {
            Chosen::Nobody => Ok(None),
            Chosen::GatewayTable => self.interpret_native(resource_id, now),
            Chosen::ChannelTable => self.interpret_declared(resource_id, now),
            Chosen::Component(mut job) => {
                job.private = self.observation.is_private();
                let binding_id = job.binding_id;
                if !self.decoding.push(job) {
                    self.note_not_decoded(binding_id, NotDecoded::QueueFull);
                }
                Ok(None)
            }
        }
    }

    /// Says where each of these bindings' components stands for a decode.
    #[must_use]
    pub fn decode_readiness(
        &self,
        bindings: &[BrokerBindingId],
    ) -> BTreeMap<BrokerBindingId, Readiness> {
        let state = self.state();
        bindings
            .iter()
            .map(|binding_id| {
                let readiness =
                    state
                        .bindings
                        .get(binding_id)
                        .map_or(Readiness::Never, |binding| {
                            if binding
                                .component
                                .as_ref()
                                .is_none_or(|component| component.refusal.is_some())
                                || binding.rich_disabled.is_some()
                            {
                                return Readiness::Never;
                            }
                            match state.component_states.get(binding_id) {
                                Some((ComponentState::Registered, _)) => Readiness::Ready,
                                Some((ComponentState::Pending, _)) | None => Readiness::Waiting,
                                Some((
                                    ComponentState::Unavailable | ComponentState::Disabled,
                                    _,
                                )) => Readiness::Never,
                            }
                        });
                (*binding_id, readiness)
            })
            .collect()
    }

    /// Returns the request a job is about as a component is given it: the retained frame's bytes
    /// and the provenance the broker recorded them with, under the handle they were retained as.
    ///
    /// Nothing where the request is no longer one to decode: it was answered or interpreted, its
    /// frame is gone or from a generation the instance has left, or it is larger than a request is
    /// retained whole.
    #[must_use]
    pub fn decode_event(&self, job: &DecodeJob) -> Option<ScopedSourceEvent> {
        let state = self.state();
        let pending = &state.arbitration.get(job.resource_id)?.resource;
        if pending.state != PendingState::Pending || pending.interpretation_verified {
            return None;
        }
        let instance = state.instances.get(&pending.application_instance_id)?;
        let held = instance.frames.get(&job.handle)?;
        if held.frame.generation != instance.source_generation
            || held.frame.bytes().len() > MAX_RETAINED_SOURCE_BYTES
        {
            return None;
        }
        Some(ScopedSourceEvent::new(
            job.handle.clone(),
            SourceProvenance::NativeProtocol,
            held.frame.received_at.get(),
            Some(job.upstream_id.clone()),
            held.frame.shared(),
        ))
    }

    /// Turns what a component decoded into the approval the request becomes, or says why it does
    /// not.
    ///
    /// The proposal is converted ([`project`]) and the broker's own interpretation checks it again
    /// under its lock: the binding, its grant and its trust, the request still being pending, the
    /// schema and the bounds of the projection, the package that recorded the request, the source
    /// generation and one interpretation for each source event.
    ///
    /// # Errors
    ///
    /// Returns what kind of refusal it was, never a component's words.
    pub fn interpret_decoded(
        &self,
        job: &DecodeJob,
        decoded: &ComponentDecoded,
        now: TimestampMs,
    ) -> std::result::Result<PendingResource, NotDecoded> {
        let projection = project(decoded, &job.upstream_id, &job.table)?;
        self.interpret(job.binding_id, job.resource_id, projection, None, now)
            .map_err(|error| match error {
                BrokerError::Trust(TrustError::NoDecisions) => NotDecoded::NoDecisions,
                BrokerError::Trust(TrustError::SummaryTooLong { .. }) => NotDecoded::SummaryTooLong,
                _ => NotDecoded::Refused,
            })
    }

    /// Records that a request was not decoded by its component, in the words a person reads in the
    /// binding's report.
    pub fn note_not_decoded(&self, binding_id: BrokerBindingId, why: NotDecoded) {
        self.note_component(
            binding_id,
            crate::broker::component::ComponentNote::Decoding(why),
        );
    }
}
