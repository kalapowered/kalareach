//! The whole of it: offer, admit, dispatch, validate, publish, unload.
//!
//! Every other module in this crate decides one thing. This one puts them in an order and holds
//! the state between ticks. The order is fixed and each step can refuse:
//!
//! 1. **Fenced?** Privacy mode stops everything here, before a reading is taken.
//! 2. **Admitted?** The resource and power policy decides, and `resource_paused` is its answer.
//! 3. **Mapped?** One model per environment, unloaded before another is mapped.
//! 4. **Anything eligible?** The queue decides, under the cooldown and the fairness bound.
//! 5. **Produced?** The runtime, under the grammar, a deadline measured from *this* point and a
//!    cancellation token.
//! 6. **Valid?** [`crate::output::validate`] against what is in force now, not at admission.
//! 7. **Published.** Into the store, with its provenance, unless the name is pinned.
//!
//! A refusal at any step leaves the session with the label it had, which is a pin, a previous
//! description or the deterministic title. There is no step whose failure removes a name.
//!
//! # What a crash does
//!
//! Section 22: *missing weights, cancellation, load failure or an inference-process crash never
//! removes metadata titles or verified state. Restart only inference.*
//! [`DescriptionService::note_inference_crash`] drops the runtime and nothing else. The store, the
//! pins, the trackers, the queue positions and every session are untouched, and the next tick maps
//! the model again. There is no path in this module that ends a worker or a session.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_worker::privacy::PrivacyGeneration;

use crate::budget::{Budgets, ResidentCost};
use crate::context::{
    ContextBinding, ContextBuilder, ContextRevision, ContextSignal, ContextTracker,
    DescriptionContext, Observed, Settled,
};
use crate::environment::{DataAccessChoice, ExecutionEnvironment, ModelMapping, Placement};
use crate::error::Result;
use crate::metadata::{
    LabelSource, SessionFacts, SessionLabel, VerifiedStatus, deterministic_title,
};
use crate::metrics::LatencyLedger;
use crate::output::{Expectation, ProducedUnder, Rejection, prompt, validate};
use crate::priority::Cancellation;
use crate::privacy::{DescriptionFence, DescriptionPrivacy, InFlight};
use crate::profile::catalogue::{Catalogue, MetGates, Selection};
use crate::profile::{DownloadPolicy, ModelProfile, ProfileRevision};
use crate::queue::{Enqueued, Freshness, NothingToDequeue, Priority, Scheduler, SessionStanding};
use crate::resource::{
    HostConditions, PauseReason, ResourcePolicy, ResourceSettings, ResourceState,
};
use crate::runtime::{GenerationRequest, InferenceRuntime, Produced};
use crate::store::DescriptionStore;
use crate::time::Reading;

/// How long a host with no sessions keeps the model mapped.
pub const IDLE_UNLOAD_MS: u64 = 15 * 60 * 1000;

/// Builds a runtime for a profile.
///
/// It is a function rather than a trait because a host supplies exactly one and a test supplies
/// exactly one, and neither needs anything else from the other. A build with no inference runtime
/// compiled in supplies a factory that refuses, which is a host with deterministic titles and no
/// model - a supported configuration rather than a broken one.
pub type RuntimeFactory = Box<dyn FnMut(&ModelProfile) -> Result<Box<dyn InferenceRuntime>>>;

/// How the downloading of a selected profile's assets is going.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadProgress {
    /// Nothing has been fetched.
    NotStarted,
    /// A fetch is running.
    Running {
        /// How many bytes have arrived.
        fetched_bytes: u64,
        /// How many there are.
        total_bytes: u64,
    },
    /// Every asset is present and every digest matched.
    Verified,
    /// A person cancelled it.
    Cancelled,
    /// It failed, and here is what the host said.
    Failed {
        /// What went wrong.
        why: String,
    },
}

/// What a person is shown when descriptions are offered at setup.
///
/// Section 22: *offered/enabled during host setup, with visible asset size, cancel/disable controls
/// and no hosted-account dependency*. This is the host side of that: the size before anything is
/// fetched, whether the two controls are available now, and the progress. The graphical surface
/// that shows it belongs to the setup assistant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupState {
    /// Whether this host can offer descriptions at all.
    pub offered: bool,
    /// Whether an owner has enabled them.
    pub enabled: bool,
    /// The profile that would be fetched, when one is selected.
    pub profile_id: Option<String>,
    /// Exactly how many bytes that is, before anything is fetched.
    pub asset_bytes: u64,
    /// Where the fetch would reach.
    pub sources: Vec<String>,
    /// How the fetch is going.
    pub progress: DownloadProgress,
    /// Whether a running fetch can be cancelled now.
    pub can_cancel: bool,
    /// Whether the feature can be turned off now. It always can.
    pub can_disable: bool,
    /// Whether any of this needs a hosted account. It never does.
    pub needs_hosted_account: bool,
    /// Why this host offers nothing, when it offers nothing.
    pub unavailable: Option<String>,
}

/// What one tick did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tick {
    /// Privacy mode is on. Nothing was admitted, dispatched or published.
    Fenced,
    /// The resource or power policy is not admitting inference.
    ResourcePaused {
        /// Why.
        reason: PauseReason,
        /// Whether a mapped model was unloaded to get here.
        unloaded: bool,
    },
    /// The model was unloaded because this host has had no sessions for long enough.
    IdleUnloaded {
        /// How long it had been.
        idle_ms: u64,
    },
    /// Nothing was waiting.
    Idle {
        /// Why nothing ran.
        why: NothingToDequeue,
    },
    /// A description was produced and published.
    Published {
        /// The session it describes.
        session_id: SessionId,
        /// How long it waited in the queue.
        queue_wait_ms: u64,
        /// How long it took once dequeued.
        execution_ms: u64,
    },
    /// A job ran and its result was refused.
    Rejected {
        /// The session.
        session_id: SessionId,
        /// Why.
        rejection: Rejection,
    },
    /// A job was cancelled before it finished.
    Cancelled {
        /// The session.
        session_id: SessionId,
    },
    /// A job passed its deadline.
    DeadlineExceeded {
        /// The session.
        session_id: SessionId,
    },
    /// The runtime itself failed. Only inference is restarted.
    InferenceFailed {
        /// The session whose job was running.
        session_id: SessionId,
        /// What the runtime said.
        detail: String,
    },
}

/// Where a description service runs.
///
/// The three facts travel together because no one of them decides anything on its own: the
/// environment says what kind of host this is, the choice is what a WSL distribution needs before
/// its data may cross, and the target is what a profile has to list before it can be mapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPlacement {
    /// The execution environment.
    pub environment: ExecutionEnvironment,
    /// The explicit local data-access choice, when one has been recorded.
    pub data_access: Option<DataAccessChoice>,
    /// The target triple this build runs on.
    pub target: String,
}

/// The description service for one execution environment.
pub struct DescriptionService {
    environment: ExecutionEnvironment,
    choice: Option<DataAccessChoice>,
    target: String,
    catalogue: Catalogue,
    met: MetGates,
    selection: Selection,
    mapping: ModelMapping,
    scheduler: Scheduler,
    policy: ResourcePolicy,
    store: DescriptionStore,
    fence: DescriptionFence,
    in_flight: InFlight,
    factory: RuntimeFactory,
    runtime: Option<Box<dyn InferenceRuntime>>,
    trackers: BTreeMap<SessionId, ContextTracker>,
    bindings: BTreeMap<SessionId, ContextBinding>,
    live_sessions: BTreeSet<SessionId>,
    latency: LatencyLedger,
    no_sessions_since_ms: Option<u64>,
    inference_restarts: u64,
    generation: PrivacyGeneration,
    progress: DownloadProgress,
    enabled: bool,
}

impl std::fmt::Debug for DescriptionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DescriptionService")
            .field("environment", &self.environment)
            .field("selection", &self.selection)
            .field("queued", &self.scheduler.queued())
            .field("state", &self.policy.state())
            .field("mapped", &self.mapping.mapped(self.environment.id()))
            .field("in_flight", &self.in_flight.get())
            .field("inference_restarts", &self.inference_restarts)
            .finish_non_exhaustive()
    }
}

impl DescriptionService {
    /// Builds the service for one environment.
    ///
    /// The selection is made once, here, from the target and the gates an owner has recorded.
    /// Nothing about the host's condition reaches it, which is section 22's rule that pressure, a
    /// timeout or bad output never chooses a different model.
    #[must_use]
    pub fn new(
        host: HostPlacement,
        catalogue: Catalogue,
        met: MetGates,
        settings: ResourceSettings,
        store: DescriptionStore,
        factory: RuntimeFactory,
    ) -> Self {
        let HostPlacement {
            environment,
            data_access: choice,
            target,
        } = host;
        let selection = catalogue.select(&target, &met);
        let budgets = Budgets::DEFAULTS;
        Self {
            environment,
            choice,
            target,
            catalogue,
            met,
            selection,
            mapping: ModelMapping::new(),
            scheduler: Scheduler::new(budgets),
            policy: ResourcePolicy::new(settings, budgets),
            store,
            fence: DescriptionFence::new(),
            in_flight: InFlight::new(),
            factory,
            runtime: None,
            trackers: BTreeMap::new(),
            bindings: BTreeMap::new(),
            live_sessions: BTreeSet::new(),
            latency: LatencyLedger::new(),
            no_sessions_since_ms: None,
            inference_restarts: 0,
            generation: PrivacyGeneration::INITIAL,
            progress: DownloadProgress::NotStarted,
            enabled: settings.enabled,
        }
    }

    /// Returns the environment.
    #[must_use]
    pub const fn environment(&self) -> &ExecutionEnvironment {
        &self.environment
    }

    /// Returns the environment's identifier.
    #[must_use]
    pub const fn environment_id(&self) -> &EnvironmentId {
        self.environment.id()
    }

    /// Returns the profile this host selected, or why it selected none.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    /// Returns the catalogue.
    #[must_use]
    pub const fn catalogue(&self) -> &Catalogue {
        &self.catalogue
    }

    /// Returns the resource state, whose paused form is section 22's `resource_paused`.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        self.policy.state()
    }

    /// Returns the fence privacy mode raises.
    #[must_use]
    pub const fn fence(&self) -> &DescriptionFence {
        &self.fence
    }

    /// Returns how many jobs are dispatched and not yet reconciled.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight.get()
    }

    /// Returns how many times inference has been restarted.
    #[must_use]
    pub const fn inference_restarts(&self) -> u64 {
        self.inference_restarts
    }

    /// Returns the published latency figures.
    #[must_use]
    pub const fn latency(&self) -> &LatencyLedger {
        &self.latency
    }

    /// Returns the queue.
    #[must_use]
    pub const fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Returns the store.
    #[must_use]
    pub const fn store(&self) -> &DescriptionStore {
        &self.store
    }

    /// Returns whether a model is mapped in this environment.
    #[must_use]
    pub fn is_mapped(&self) -> bool {
        self.mapping.mapped(self.environment.id()).is_some()
    }

    /// Returns how many environments this service has a model mapped in, which is never more than
    /// one.
    #[must_use]
    pub fn mapped_environments(&self) -> usize {
        self.mapping.mapped_environments()
    }

    /// Returns privacy mode's hook over this crate's stores.
    pub fn privacy(&mut self) -> DescriptionPrivacy<'_> {
        DescriptionPrivacy::over(
            &self.fence,
            &mut self.scheduler,
            &self.store,
            &self.in_flight,
        )
    }

    /// Records the privacy generation now in force.
    ///
    /// The caller records it durably first; this crate holds it only to stamp jobs with, and every
    /// publication compares the stamp with what is in force at that moment.
    pub const fn set_privacy_generation(&mut self, generation: PrivacyGeneration) {
        self.generation = generation;
    }

    /// Returns the generation jobs are being admitted under.
    #[must_use]
    pub const fn privacy_generation(&self) -> PrivacyGeneration {
        self.generation
    }

    /// Returns what a person is offered at setup.
    #[must_use]
    pub fn setup_state(&self) -> SetupState {
        let placement = self.environment.placement(self.choice.as_ref());
        let unavailable = match placement {
            Placement::Refused(refusal) => Some(refusal.as_str().to_owned()),
            Placement::Local | Placement::NativeHostBroker => None,
        };
        let policy = self
            .selection
            .profile()
            .filter(|_| placement.admits_a_model())
            .map(DownloadPolicy::of);
        SetupState {
            offered: policy.is_some(),
            enabled: self.enabled,
            profile_id: policy.as_ref().map(|policy| policy.profile_id.clone()),
            asset_bytes: policy.as_ref().map_or(0, |policy| policy.bytes),
            sources: policy.map(|policy| policy.sources).unwrap_or_default(),
            progress: self.progress.clone(),
            can_cancel: matches!(self.progress, DownloadProgress::Running { .. }),
            can_disable: true,
            // Nothing in this feature reaches a hosted account: the profile is in the binary, the
            // assets come from their publisher, and the inference is local.
            needs_hosted_account: false,
            unavailable,
        }
    }

    /// Records how a fetch of the selected profile's assets is going.
    pub fn note_download(&mut self, progress: DownloadProgress) {
        self.progress = progress;
    }

    /// Turns descriptions on or off. Turning them off unloads whatever is mapped.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.unload();
        }
    }

    /// Records that a session exists.
    pub fn session_opened(&mut self, session_id: SessionId, binding: ContextBinding) {
        self.trackers.insert(
            session_id,
            ContextTracker::new(self.policy.budgets().context_debounce_ms),
        );
        self.bindings.insert(session_id, binding);
        self.live_sessions.insert(session_id);
        self.no_sessions_since_ms = None;
    }

    /// Records that a session has closed.
    ///
    /// The pin and the provenance stay in the store, which is the whole of section 24's *metadata
    /// and pins survive closure*. What goes is the live tracking: a closed session has no context
    /// to advance and no job to queue.
    pub fn session_closed(&mut self, session_id: &SessionId, now: Reading) {
        self.trackers.remove(session_id);
        self.bindings.remove(session_id);
        self.live_sessions.remove(session_id);
        self.scheduler.cancel(session_id);
        if self.live_sessions.is_empty() {
            self.no_sessions_since_ms = Some(now.monotonic_ms());
        }
    }

    /// Returns how many sessions this environment is tracking.
    #[must_use]
    pub fn live_sessions(&self) -> usize {
        self.live_sessions.len()
    }

    /// Records a meaningful change to what a session is doing.
    ///
    /// This is the only entry point that reaches the queue. There is no other, and there is in
    /// particular no path from the shell's input, query or resize handling to anything here.
    pub fn observe(
        &mut self,
        session_id: &SessionId,
        signal: ContextSignal,
        now: Reading,
    ) -> Option<Observed> {
        self.trackers
            .get_mut(session_id)
            .map(|tracker| tracker.observe(signal, now))
    }

    /// Advances a session's revision when its debounce has elapsed, and queues a job when it does.
    pub fn settle(
        &mut self,
        session_id: &SessionId,
        priority: Priority,
        now: Reading,
    ) -> Option<Enqueued> {
        if self.fence.is_fenced() {
            return None;
        }
        let tracker = self.trackers.get_mut(session_id)?;
        let Settled::Advanced { revision, .. } = tracker.settle(now) else {
            return None;
        };
        let facts = tracker.facts();
        let binding = self.bindings.get(session_id)?.clone();
        let context = build_context(
            *self.environment.id(),
            *session_id,
            binding,
            revision,
            &facts,
            tracker,
        );
        Some(self.scheduler.enqueue(priority, context, now))
    }

    /// Returns a session's context revision.
    #[must_use]
    pub fn revision(&self, session_id: &SessionId) -> Option<ContextRevision> {
        self.trackers.get(session_id).map(ContextTracker::revision)
    }

    /// Returns what a client is shown about one session's place in the queue.
    #[must_use]
    pub fn standing(&self, session_id: &SessionId, now: Reading) -> SessionStanding {
        self.scheduler.standing(session_id, now)
    }

    /// Returns how current a session's published description is.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the store cannot be read.
    pub fn freshness(&self, session_id: &SessionId, now: Reading) -> Result<Option<Freshness>> {
        let Some(record) = self.store.generated(session_id)? else {
            return Ok(None);
        };
        let current = self
            .revision(session_id)
            .unwrap_or(ContextRevision::INITIAL);
        let waiting = self.scheduler.standing(session_id, now).queued_age_ms;
        Ok(Some(Freshness::of(record.revision, current, waiting)))
    }

    /// Returns the label to show for one session.
    ///
    /// While the fence is up this never reads a generated description, so privacy mode's
    /// metadata-only titles hold from the instant the fence goes up rather than from the moment the
    /// removal finishes.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the store cannot be read.
    pub fn label(
        &self,
        session_id: &SessionId,
        facts: &SessionFacts,
        status: VerifiedStatus,
    ) -> Result<SessionLabel> {
        if self.fence.is_fenced() {
            if let Some(pin) = self.store.pinned(session_id)? {
                return Ok(SessionLabel {
                    title: pin.title,
                    source: LabelSource::Pinned,
                    activity: None,
                    status,
                });
            }
            return Ok(SessionLabel {
                title: deterministic_title(facts),
                source: LabelSource::Metadata,
                activity: None,
                status,
            });
        }
        self.store.label(session_id, facts, status)
    }

    /// Drops the runtime after an inference failure, and nothing else.
    ///
    /// Section 22: *restart only inference*. This is the whole of that restart. The store, the
    /// pins, the provenance, every tracker, every queue position and every session survive it, and
    /// the next tick maps the model again.
    pub fn note_inference_crash(&mut self) {
        self.runtime = None;
        self.mapping.unload(self.environment.id());
        self.inference_restarts = self.inference_restarts.saturating_add(1);
        self.in_flight.reconciled();
    }

    /// Unloads the model, keeping everything else.
    pub fn unload(&mut self) {
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.unload();
        }
        self.runtime = None;
        self.mapping.unload(self.environment.id());
    }

    /// Returns what a resident model is costing, when one is resident.
    #[must_use]
    pub fn resident_cost(&self) -> Option<ResidentCost> {
        self.runtime.as_ref().map(|runtime| runtime.resident_cost())
    }

    /// Runs one tick: evaluate, map, dequeue, produce, validate, publish.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the store cannot be written, which is the only
    /// failure a tick propagates: everything else is an outcome in [`Tick`].
    pub fn tick(&mut self, conditions: &HostConditions, now: Reading) -> Result<Tick> {
        if self.fence.is_fenced() {
            return Ok(Tick::Fenced);
        }
        if let Some(idle_since) = self.no_sessions_since_ms
            && now.since_ms(idle_since) >= IDLE_UNLOAD_MS
            && self.is_mapped()
        {
            self.unload();
            return Ok(Tick::IdleUnloaded {
                idle_ms: now.since_ms(idle_since),
            });
        }
        let Some(profile) = self.selection.profile().cloned() else {
            return Ok(Tick::Idle {
                why: NothingToDequeue::Empty,
            });
        };
        // The cost checked before a load is the profile's own itemised estimate; once a model is
        // resident the runtime's own figure replaces it, so the reserve is checked against what is
        // actually held rather than against what was predicted.
        let cost = self
            .resident_cost()
            .unwrap_or(profile.execution().resident_estimate);
        let transition = self.policy.evaluate(conditions, &cost);
        match transition.to {
            ResourceState::ResourcePaused { reason, unloaded } => {
                if unloaded {
                    self.unload();
                }
                return Ok(Tick::ResourcePaused { reason, unloaded });
            }
            ResourceState::Ready => {
                return Ok(Tick::Idle {
                    why: NothingToDequeue::Empty,
                });
            }
            ResourceState::Resident => {}
        }
        let job = match self.scheduler.dequeue(now) {
            Ok(job) => job,
            Err(why) => return Ok(Tick::Idle { why }),
        };
        let queue_wait_ms = now.since_ms(job.queued_at_ms);
        self.ensure_mapped(&profile, now)?;
        let Some(runtime) = self.runtime.as_mut() else {
            return Ok(Tick::InferenceFailed {
                session_id: job.session_id,
                detail: "no runtime is loaded".to_owned(),
            });
        };
        let handle = runtime.handle();
        let produced_under = ProducedUnder {
            session_epoch: job.context.session_epoch(),
            binding: job.context.binding().clone(),
            profile_id: handle.profile_id.clone(),
            profile_revision: handle.profile_revision,
            generation: self.generation,
        };
        let budgets = self.policy.budgets();
        let request = GenerationRequest {
            prompt: prompt(&job.context),
            grammar: crate::output::DESCRIPTION_GRAMMAR,
            context_tokens: budgets.context_tokens,
            max_output_tokens: budgets.max_output_tokens,
            cpu_threads: budgets.cpu_threads,
            sampler: *profile.sampler(),
            // The deadline starts here, at dequeue, which is what section 22 says and what stops a
            // job that waited in a busy queue from being killed for waiting.
            deadline_ms: budgets.execution_deadline_ms,
            cancellation: Cancellation::new(),
        };
        self.in_flight.dispatched();
        let started = now;
        let produced = runtime.generate(&request);
        let execution_ms = now.since_ms(started.monotonic_ms());
        self.in_flight.reconciled();
        self.scheduler.record_service(execution_ms.max(1));
        self.latency
            .record(self.live_sessions.len() as u32, queue_wait_ms, execution_ms);

        let bytes = match produced {
            Ok(Produced::Json(bytes)) => bytes,
            Ok(Produced::Cancelled) => {
                return Ok(Tick::Cancelled {
                    session_id: job.session_id,
                });
            }
            Ok(Produced::DeadlineExceeded) => {
                return Ok(Tick::DeadlineExceeded {
                    session_id: job.session_id,
                });
            }
            Err(error) => {
                let detail = error.to_string();
                self.note_inference_crash();
                return Ok(Tick::InferenceFailed {
                    session_id: job.session_id,
                    detail,
                });
            }
        };
        let expectation = Expectation {
            session_epoch: job.context.session_epoch(),
            revision: self
                .revision(&job.session_id)
                .unwrap_or(job.context.revision()),
            binding: self
                .bindings
                .get(&job.session_id)
                .cloned()
                .unwrap_or_else(|| job.context.binding().clone()),
            profile_revision: profile.revision(),
            generation: self.generation,
            name_pinned: self.store.pinned(&job.session_id)?.is_some(),
        };
        match validate(&bytes, &produced_under, &expectation) {
            Ok(description) => {
                self.store
                    .publish(&job.session_id, &description, now.wall_ms().get())?;
                self.scheduler.record_success(&job.session_id, now);
                Ok(Tick::Published {
                    session_id: job.session_id,
                    queue_wait_ms,
                    execution_ms,
                })
            }
            Err(rejection) => Ok(Tick::Rejected {
                session_id: job.session_id,
                rejection,
            }),
        }
    }

    /// Maps the profile when it is not mapped, unloading whatever was there first.
    fn ensure_mapped(&mut self, profile: &ModelProfile, now: Reading) -> Result<()> {
        if self
            .mapping
            .mapped(self.environment.id())
            .is_some_and(|mapped| {
                mapped.profile_id == profile.profile_id() && mapped.revision == profile.revision()
            })
            && self.runtime.is_some()
        {
            return Ok(());
        }
        // Unload before mapping. The mapping does it for its own record; the runtime has to be told
        // as well, because it is the one holding the weights.
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.unload();
        }
        self.runtime = None;
        self.mapping.map(
            &self.environment,
            self.choice.as_ref(),
            profile,
            &self.met,
            &self.target,
            now.wall_ms(),
        )?;
        self.runtime = Some((self.factory)(profile)?);
        Ok(())
    }

    /// Returns whether a result produced under a profile revision is still current.
    #[must_use]
    pub fn accepts_profile_revision(&self, profile_id: &str, revision: ProfileRevision) -> bool {
        self.mapping
            .accepts_result(self.environment.id(), profile_id, revision)
    }

    /// Returns the gates an owner has recorded as met.
    #[must_use]
    pub const fn met_gates(&self) -> &MetGates {
        &self.met
    }
}

/// Builds the bounded context one job is described from.
fn build_context(
    environment_id: EnvironmentId,
    session_id: SessionId,
    binding: ContextBinding,
    revision: ContextRevision,
    facts: &SessionFacts,
    tracker: &ContextTracker,
) -> DescriptionContext {
    let mut builder = ContextBuilder::new(
        environment_id,
        session_id,
        kr_protocol::ids::SessionEpoch::V1,
        binding,
        revision,
    );
    if let Some(directory) = &facts.directory {
        builder = builder.directory(directory);
    }
    if let Some(repository) = &facts.repository {
        builder = builder.repository(repository);
    }
    if let Some(application) = &facts.application {
        builder = builder.application(application);
    }
    if let Some(thread) = tracker.thread() {
        builder = builder.thread(thread);
    }
    // The intent a person gave comes first; a completion the host recorded is what stands in for
    // it when nobody gave one, because "the last task failed" is more use than nothing.
    if let Some(intent) = tracker.intent() {
        builder = builder.intent(intent);
    } else if let Some(completion) = tracker.completion() {
        builder = builder.intent(match completion {
            crate::context::Completion::Succeeded => "the last task finished",
            crate::context::Completion::Failed => "the last task failed",
        });
    }
    builder.build()
}
