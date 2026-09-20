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

use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_worker::privacy::PrivacyGeneration;

use crate::budget::{Budgets, ResidentCost};
use crate::context::{
    ContextBinding, ContextBuilder, ContextRevision, ContextSignal, ContextTracker,
    DescriptionContext, Observed, SemanticEvent, Settled,
};
use crate::environment::{DataAccessChoice, ExecutionEnvironment, ModelMapping, Placement};
use crate::error::{DescribeError, Result};
use crate::metadata::{
    LabelSource, SessionFacts, SessionLabel, VerifiedStatus, deterministic_title,
};
use crate::metrics::LatencyLedger;
use crate::output::{Expectation, ProducedUnder, Rejection, prompt, validate};
use crate::priority::{Applied, Cancellation};
use crate::privacy::{CleanupDebt, DescriptionFence, DescriptionPrivacy, InFlight, RunningJob};
use crate::profile::catalogue::{Catalogue, MetGates, Selection};
use crate::profile::{DownloadPolicy, ModelProfile, ProfileRevision};
use crate::queue::{Enqueued, Freshness, NothingToDequeue, Priority, Scheduler, SessionStanding};
use crate::resource::{
    HostConditions, PauseReason, ResourcePolicy, ResourceSettings, ResourceState,
};
use crate::runtime::{GenerationRequest, InferenceRuntime, LoadOutcome, Produced};
use crate::store::DescriptionStore;
use crate::time::{JobClock, Reading};

/// How long a host with no sessions keeps the model mapped.
pub const IDLE_UNLOAD_MS: u64 = 15 * 60 * 1000;

/// Builds a runtime for a profile.
///
/// It is a function rather than a trait because a host supplies exactly one and a test supplies
/// exactly one, and neither needs anything else from the other. A build with no inference runtime
/// compiled in supplies a factory that refuses, which is a host with deterministic titles and no
/// model - a supported configuration rather than a broken one.
pub type RuntimeFactory = Box<dyn FnMut(&ModelProfile, &Cancellation, u64) -> Result<LoadOutcome>>;

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

/// What mapping or loading a profile produced.
#[derive(Debug)]
enum EnsureMappedOutcome {
    Mapped,
    Cancelled,
    DeadlineExceeded,
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
    running: RunningJob,
    debt: CleanupDebt,
    factory: RuntimeFactory,
    runtime: Option<Box<dyn InferenceRuntime>>,
    trackers: BTreeMap<SessionId, ContextTracker>,
    bindings: BTreeMap<SessionId, ContextBinding>,
    epochs: BTreeMap<SessionId, SessionEpoch>,
    events: BTreeMap<SessionId, Vec<SemanticEvent>>,
    generations: BTreeMap<SessionId, PrivacyGeneration>,
    live_sessions: BTreeSet<SessionId>,
    latency: LatencyLedger,
    no_sessions_since_ms: Option<u64>,
    inference_restarts: u64,
    progress: DownloadProgress,
    settings: ResourceSettings,
    job_clock: JobClock,
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
            .field("in_flight", &self.in_flight.total())
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
            running: RunningJob::new(),
            debt: CleanupDebt::new(),
            factory,
            runtime: None,
            trackers: BTreeMap::new(),
            bindings: BTreeMap::new(),
            epochs: BTreeMap::new(),
            events: BTreeMap::new(),
            generations: BTreeMap::new(),
            live_sessions: BTreeSet::new(),
            latency: LatencyLedger::new(),
            no_sessions_since_ms: None,
            inference_restarts: 0,
            progress: DownloadProgress::NotStarted,
            settings,
            job_clock: JobClock::monotonic(),
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

    /// Returns how many jobs are dispatched and not yet reconciled, across every session.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight.total()
    }

    /// Returns the background priority this host applied to its inference, when a model is loaded.
    ///
    /// It is the runtime's own answer rather than this service's: the thread that loads a model is
    /// the thread that runs it, and that is the thread the class was applied to.
    #[must_use]
    pub fn background_priority(&self) -> Option<Applied> {
        self.runtime.as_ref().and_then(|runtime| runtime.priority())
    }

    /// Returns the handle that cancels the job the runtime is executing.
    ///
    /// It is shared, so a caller on another thread can cancel the job this service is inside. A
    /// caller on *this* thread cannot: [`Self::tick`] holds the service for the whole of a
    /// synchronous generation, and a host that needs to interrupt one runs the service on a thread
    /// of its own.
    #[must_use]
    pub const fn running_job(&self) -> &RunningJob {
        &self.running
    }

    /// Returns the clock used to measure the execution deadline.
    #[must_use]
    pub const fn job_clock(&self) -> &JobClock {
        &self.job_clock
    }

    /// Sets the clock used to measure the execution deadline, which a test drives by hand.
    pub fn set_job_clock(&mut self, clock: JobClock) {
        self.job_clock = clock;
    }

    /// Returns what cleanup privacy mode is still owed.
    #[must_use]
    pub const fn cleanup_debt(&self) -> &CleanupDebt {
        &self.debt
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

    /// Returns privacy mode's hook over one session's queue position, context and store row.
    ///
    /// One session, because that is the scope privacy mode has in this product: a private session
    /// sits beside one that is not, and a hook that emptied the whole queue would cancel work for
    /// sessions nobody asked about.
    pub fn privacy(&mut self, session_id: SessionId) -> DescriptionPrivacy<'_> {
        DescriptionPrivacy::over(
            session_id,
            &self.fence,
            &mut self.scheduler,
            self.trackers.get_mut(&session_id),
            self.events.get_mut(&session_id),
            &self.store,
            &self.in_flight,
            &self.running,
            &self.debt,
        )
    }

    /// Records the privacy generation now in force for one session.
    ///
    /// The caller records it durably first; this crate holds it only to stamp jobs with, and every
    /// publication compares the stamp with what is in force at that moment.
    pub fn set_privacy_generation(&mut self, session_id: SessionId, generation: PrivacyGeneration) {
        self.generations.insert(session_id, generation);
    }

    /// Returns the generation a session's jobs are being admitted under.
    #[must_use]
    pub fn privacy_generation(&self, session_id: &SessionId) -> PrivacyGeneration {
        self.generations
            .get(session_id)
            .copied()
            .unwrap_or(PrivacyGeneration::INITIAL)
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
            enabled: self.settings.enabled,
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

    /// Turns descriptions on or off.
    ///
    /// There is one setting and it is the policy's, so turning descriptions off stops admission and
    /// dispatch as well as unloading what is mapped, and turning them on again lets the next tick
    /// map a model. A flag that only changed what a setup surface displayed would be a switch that
    /// did not switch anything.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.settings.enabled = enabled;
        self.policy = ResourcePolicy::new(self.settings, Budgets::DEFAULTS);
        if !enabled {
            self.unload();
        }
    }

    /// Records that a session exists, with the epoch it was addressed in.
    pub fn session_opened(
        &mut self,
        session_id: SessionId,
        session_epoch: SessionEpoch,
        binding: ContextBinding,
    ) {
        self.trackers.insert(
            session_id,
            ContextTracker::new(self.policy.budgets().context_debounce_ms),
        );
        self.bindings.insert(session_id, binding);
        self.epochs.insert(session_id, session_epoch);
        self.live_sessions.insert(session_id);
        self.no_sessions_since_ms = None;
    }

    /// Admits one authorised recent semantic event into a session's context.
    ///
    /// It is the only way an event reaches a description, and the bound is the context's:
    /// [`crate::context::MAX_RECENT_EVENTS`] of them, newest first. A session this host is not
    /// tracking, or one that is fenced, takes none.
    pub fn note_event(&mut self, session_id: &SessionId, event: SemanticEvent) -> bool {
        if self.fence.is_fenced(session_id) || !self.live_sessions.contains(session_id) {
            return false;
        }
        let events = self.events.entry(*session_id).or_default();
        events.push(event);
        events.sort_by_key(|event| event.cursor);
        while events.len() > crate::context::MAX_RECENT_EVENTS {
            events.remove(0);
        }
        true
    }

    /// Records that a session has closed.
    ///
    /// The pin and the provenance stay in the store, which is the whole of section 24's *metadata
    /// and pins survive closure*. What goes is the live tracking: a closed session has no context
    /// to advance and no job to queue.
    pub fn session_closed(&mut self, session_id: &SessionId, now: Reading) {
        self.trackers.remove(session_id);
        self.bindings.remove(session_id);
        self.epochs.remove(session_id);
        self.events.remove(session_id);
        self.generations.remove(session_id);
        self.live_sessions.remove(session_id);
        // The fence and the debt go only when the cleanup they describe has actually finished.
        // A closed session whose generated row this host could not remove still has one, and
        // lowering its fence would let a later read show it; clearing its debt would let
        // reconciliation report complete over it. So a debt is retried once here, and both stay
        // when the retry fails.
        if self.debt.owed(session_id).is_some() {
            match self.store.remove_generated_for(session_id) {
                Ok(_) => {
                    self.debt.settle(session_id);
                    self.fence.lower(session_id);
                }
                Err(error) => self.debt.owe(*session_id, error.to_string()),
            }
        } else {
            self.fence.lower(session_id);
        }
        // Everything the queue remembered about this session goes with it. Its pin and its
        // provenance stay, because they are in a store the session does not own.
        self.scheduler.forget(session_id);
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
        // Capture is the first thing privacy mode disables. A context kept while private would be
        // private content waiting for the fence to drop, so a fenced session records nothing at
        // all rather than recording and discarding later.
        if self.fence.is_fenced(session_id) {
            return self
                .trackers
                .contains_key(session_id)
                .then_some(Observed::Fenced);
        }
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
        if self.fence.is_fenced(session_id) {
            return None;
        }
        let tracker = self.trackers.get_mut(session_id)?;
        let Settled::Advanced { revision, .. } = tracker.settle(now) else {
            return None;
        };
        let facts = tracker.facts();
        let intent = tracker.intent().map(str::to_owned);
        let thread = tracker.thread().map(str::to_owned);
        let completion = tracker.completion();
        let binding = self.bindings.get(session_id)?.clone();
        let session_epoch = self.epochs.get(session_id).copied()?;
        let events = self.events.get(session_id).cloned().unwrap_or_default();
        let context = build_context(
            *self.environment.id(),
            *session_id,
            session_epoch,
            binding,
            revision,
            &facts,
            intent.as_deref(),
            thread.as_deref(),
            completion,
            &events,
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
        if self.fence.is_fenced(session_id) {
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

    /// Runs one tick: evaluate, dequeue, produce, validate, publish.
    ///
    /// Two things are checked twice on purpose. The fence is read before a job is dequeued and
    /// again before its result is published, because a session can be made private while its job is
    /// inside the runtime. The resource policy is told whether a model is *actually* loaded rather
    /// than inferring it, because inferring it is how a host comes to refuse a load and admit the
    /// same load a tick later.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::Store`] when the store cannot be read or written, which is the only
    /// failure a tick propagates: everything else is an outcome in [`Tick`].
    #[allow(clippy::too_many_lines)]
    pub fn tick(&mut self, conditions: &HostConditions, now: Reading) -> Result<Tick> {
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
        // Before a load the model's cost has to come out of the memory this host can see; once it
        // is loaded it is already out. Which world this is comes from the runtime, not from the
        // policy's own previous answer.
        let resident = self.runtime.is_some();
        let cost = self
            .resident_cost()
            .unwrap_or(profile.execution().resident_estimate);
        let transition = self.policy.evaluate(conditions, &cost, resident);
        match transition.to {
            ResourceState::ResourcePaused { reason, unloaded } => {
                if resident {
                    self.unload();
                }
                return Ok(Tick::ResourcePaused { reason, unloaded });
            }
            ResourceState::Ready => {
                return Ok(Tick::Idle {
                    why: NothingToDequeue::Empty,
                });
            }
            ResourceState::Admitted => {}
        }
        let job = match self.scheduler.dequeue(now) {
            Ok(job) => job,
            Err(why) => return Ok(Tick::Idle { why }),
        };
        let session_id = job.session_id;
        // The deadline starts here, at dequeue, which is what section 22 says. Loading a model is
        // inside it: a job that spent twenty seconds waiting for weights has ten left, not another
        // thirty.
        let dequeued_ms = self.job_clock.now_ms();
        let queue_wait_ms = now.since_ms(job.queued_at_ms);
        if self.fence.is_fenced(&session_id) {
            return Ok(Tick::Fenced);
        }
        let budgets = self.policy.budgets();

        // Start tracking running job and in-flight work before loading, so a fence raised during
        // load cancels the load token.
        let cancellation = self.running.started(session_id);
        self.in_flight.dispatched(session_id);

        let elapsed_before_load = self.job_clock.now_ms().saturating_sub(dequeued_ms);
        let remaining_before_load = budgets
            .execution_deadline_ms
            .saturating_sub(elapsed_before_load);
        if elapsed_before_load >= budgets.execution_deadline_ms || remaining_before_load == 0 {
            self.running.finished();
            self.in_flight.reconciled(&session_id);
            return Ok(Tick::DeadlineExceeded { session_id });
        }
        if cancellation.is_cancelled() {
            self.running.finished();
            self.in_flight.reconciled(&session_id);
            return Ok(Tick::Cancelled { session_id });
        }

        match self.ensure_mapped(&profile, &cancellation, remaining_before_load, now) {
            Ok(EnsureMappedOutcome::Mapped) => {}
            Ok(EnsureMappedOutcome::Cancelled) => {
                self.running.finished();
                self.in_flight.reconciled(&session_id);
                return Ok(Tick::Cancelled { session_id });
            }
            Ok(EnsureMappedOutcome::DeadlineExceeded) => {
                self.running.finished();
                self.in_flight.reconciled(&session_id);
                return Ok(Tick::DeadlineExceeded { session_id });
            }
            Err(error) => {
                self.running.finished();
                self.in_flight.reconciled(&session_id);
                return Ok(Tick::InferenceFailed {
                    session_id,
                    detail: error.to_string(),
                });
            }
        }

        let generation = self.privacy_generation(&session_id);
        let produced_under = ProducedUnder {
            session_epoch: job.context.session_epoch(),
            binding: job.context.binding().clone(),
            context_revision: job.context.revision(),
            cursor: job.context.cursor(),
            profile_id: profile.profile_id().to_owned(),
            profile_revision: profile.revision(),
            generation,
        };
        let elapsed_before_gen = self.job_clock.now_ms().saturating_sub(dequeued_ms);
        let remaining_ms = budgets
            .execution_deadline_ms
            .saturating_sub(elapsed_before_gen);
        if elapsed_before_gen >= budgets.execution_deadline_ms || remaining_ms == 0 {
            self.running.finished();
            self.in_flight.reconciled(&session_id);
            return Ok(Tick::DeadlineExceeded { session_id });
        }
        if cancellation.is_cancelled() {
            self.running.finished();
            self.in_flight.reconciled(&session_id);
            return Ok(Tick::Cancelled { session_id });
        }

        let request = GenerationRequest {
            prompt: prompt(&job.context),
            grammar: crate::output::DESCRIPTION_GRAMMAR,
            // The profile's own figures, bounded by section 22's budgets. A profile that asked for
            // more threads or a longer answer than the budget allows gets the budget; one that
            // asked for less gets what it asked for, because that is what it was qualified with.
            context_tokens: budgets
                .context_tokens
                .min(profile.execution().context_tokens),
            max_output_tokens: budgets
                .max_output_tokens
                .min(profile.execution().max_output_tokens),
            cpu_threads: budgets.cpu_threads.min(profile.execution().cpu_threads),
            sampler: *profile.sampler(),
            deadline_ms: remaining_ms,
            cancellation: cancellation.clone(),
        };

        let produced = self.runtime.as_mut().map_or_else(
            || {
                Err(DescribeError::Runtime {
                    detail: "no runtime is loaded".to_owned(),
                })
            },
            |runtime| runtime.generate(&request),
        );
        let execution_ms = self.job_clock.now_ms().saturating_sub(dequeued_ms);
        self.running.finished();
        self.in_flight.reconciled(&session_id);
        self.scheduler.record_service(execution_ms.max(1));
        self.latency
            .record(self.live_sessions.len() as u32, queue_wait_ms, execution_ms);

        let bytes = match produced {
            Ok(Produced::Json(bytes)) => bytes,
            Ok(Produced::Cancelled) => return Ok(Tick::Cancelled { session_id }),
            Ok(Produced::DeadlineExceeded) => return Ok(Tick::DeadlineExceeded { session_id }),
            Err(error) => {
                let detail = error.to_string();
                self.note_inference_crash();
                return Ok(Tick::InferenceFailed { session_id, detail });
            }
        };
        // The deadline again, over the whole job rather than over the runtime's own view of it:
        // a load that ran long leaves a result nobody asked for by the time it arrives.
        if execution_ms > budgets.execution_deadline_ms {
            return Ok(Tick::DeadlineExceeded { session_id });
        }
        if cancellation.is_cancelled() {
            return Ok(Tick::Cancelled { session_id });
        }
        // The fence again, now that the runtime has answered. A session made private while its job
        // was running has a result produced under the generation before the enabling, and section
        // 24 refuses it rather than publishing it.
        if self.fence.is_fenced(&session_id) {
            return Ok(Tick::Rejected {
                session_id,
                rejection: Rejection::LateGeneration {
                    expected: self
                        .fence
                        .generation(&session_id)
                        .unwrap_or(PrivacyGeneration::INITIAL),
                    found: generation,
                },
            });
        }
        let Some(session_epoch) = self.epochs.get(&session_id).copied() else {
            // The session closed while its job was running. Nothing is published against a session
            // this host is no longer tracking.
            return Ok(Tick::Rejected {
                session_id,
                rejection: Rejection::WrongSessionEpoch {
                    expected: job.context.session_epoch(),
                    found: job.context.session_epoch(),
                },
            });
        };
        let expectation = Expectation {
            session_epoch,
            revision: self.revision(&session_id).unwrap_or(job.context.revision()),
            binding: self
                .bindings
                .get(&session_id)
                .cloned()
                .unwrap_or_else(|| job.context.binding().clone()),
            profile_id: profile.profile_id().to_owned(),
            profile_revision: profile.revision(),
            generation: self.privacy_generation(&session_id),
            name_pinned: self.store.pinned(&session_id)?.is_some(),
        };
        let description = match validate(&bytes, &produced_under, &expectation) {
            Ok(description) => description,
            Err(rejection) => {
                return Ok(Tick::Rejected {
                    session_id,
                    rejection,
                });
            }
        };

        self.store
            .publish(&session_id, &description, now.wall_ms().get())?;
        self.scheduler.record_success(&session_id, now);
        let published = Tick::Published {
            session_id,
            queue_wait_ms,
            execution_ms,
        };
        // The ceiling is a process figure, so it is checked against the process rather than against
        // the profile's estimate. A run that has grown past it unloads: section 22's budget is a
        // bound on what this product costs, not a prediction it is allowed to be wrong about.
        if let Some(rss) = process_rss_bytes()
            && rss > budgets.process_memory_ceiling_bytes
        {
            self.unload();
            return Ok(Tick::ResourcePaused {
                reason: PauseReason::MemoryPressure,
                unloaded: true,
            });
        }
        Ok(published)
    }

    /// Loads the profile when it is not loaded, releasing whatever was there first.
    ///
    /// The runtime is built *before* the mapping is recorded, so a load that fails leaves no record
    /// of a model this host does not have.
    fn ensure_mapped(
        &mut self,
        profile: &ModelProfile,
        cancellation: &Cancellation,
        remaining_ms: u64,
        now: Reading,
    ) -> Result<EnsureMappedOutcome> {
        if self.runtime.as_ref().is_some_and(|runtime| {
            let handle = runtime.handle();
            handle.profile_id == profile.profile_id()
                && handle.profile_revision == profile.revision()
        }) && self.is_mapped()
        {
            return Ok(EnsureMappedOutcome::Mapped);
        }
        // Release before loading. Section 22 states that order, and it is what keeps the process
        // ceiling a ceiling: two sets of weights resident at once would exceed it for as long as
        // the changeover took.
        if let Some(runtime) = self.runtime.as_mut() {
            runtime.unload();
        }
        self.runtime = None;
        self.mapping.unload(self.environment.id());
        // Every reason this environment may not run this profile is decided before a byte of it is
        // read: a WSL distribution with no data-access choice, a mobile device, a target the
        // profile does not list and a candidate whose gates are outstanding all refuse here, and
        // loading weights first would be doing the thing the refusal exists to prevent.
        self.mapping.admits(
            &self.environment,
            self.choice.as_ref(),
            profile,
            &self.met,
            &self.target,
        )?;
        let outcome = (self.factory)(profile, cancellation, remaining_ms)?;
        let runtime = match outcome {
            LoadOutcome::Loaded(runtime) => runtime,
            LoadOutcome::Cancelled => return Ok(EnsureMappedOutcome::Cancelled),
            LoadOutcome::DeadlineExceeded => return Ok(EnsureMappedOutcome::DeadlineExceeded),
        };
        // And what came back is the profile that was asked for. A runtime that loaded something
        // else would have every description attributed to a model this host is not running.
        let handle = runtime.handle();
        if handle.profile_id != profile.profile_id()
            || handle.profile_revision != profile.revision()
        {
            return Err(DescribeError::Runtime {
                detail: format!(
                    "{} revision {} was asked for and {} revision {} was loaded",
                    profile.profile_id(),
                    profile.revision().get(),
                    handle.profile_id,
                    handle.profile_revision.get()
                ),
            });
        }
        self.mapping.map(
            &self.environment,
            self.choice.as_ref(),
            profile,
            &self.met,
            &self.target,
            now.wall_ms(),
        )?;
        self.runtime = Some(runtime);
        Ok(EnsureMappedOutcome::Mapped)
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

/// Returns this process's resident set, when this platform will say.
fn process_rss_bytes() -> Option<u64> {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map(sysinfo::Process::memory)
}

/// Builds the bounded context one job is described from.
#[allow(clippy::too_many_arguments)]
fn build_context(
    environment_id: EnvironmentId,
    session_id: SessionId,
    session_epoch: SessionEpoch,
    binding: ContextBinding,
    revision: ContextRevision,
    facts: &SessionFacts,
    intent: Option<&str>,
    thread: Option<&str>,
    completion: Option<crate::context::Completion>,
    events: &[SemanticEvent],
) -> DescriptionContext {
    let mut builder =
        ContextBuilder::new(environment_id, session_id, session_epoch, binding, revision);
    if let Some(directory) = &facts.directory {
        builder = builder.directory(directory);
    }
    if let Some(repository) = &facts.repository {
        builder = builder.repository(repository);
    }
    if let Some(application) = &facts.application {
        builder = builder.application(application);
    }
    if let Some(thread) = thread {
        builder = builder.thread(thread);
    }
    // The intent a person gave comes first; a completion the host recorded is what stands in for
    // it when nobody gave one, because "the last task failed" is more use than nothing.
    if let Some(intent) = intent {
        builder = builder.intent(intent);
    } else if let Some(completion) = completion {
        builder = builder.intent(match completion {
            crate::context::Completion::Succeeded => "the last task finished",
            crate::context::Completion::Failed => "the last task failed",
        });
    }
    for event in events {
        builder = builder.event(event.clone());
    }
    builder.build()
}
