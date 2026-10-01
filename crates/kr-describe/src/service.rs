//! The whole of it: offer, admit, load, dispatch, validate, publish, unload.
//!
//! Every other module in this crate decides one thing. This one puts them in an order and holds
//! the state between calls. It holds no model: the model runs in the description process, and the
//! host drives this service with two calls.
//!
//! * [`DescriptionService::next`] says what the host does now: load a profile in the process, send
//!   it a job, cancel the work it is doing, end it, or wait until a given time or until something
//!   changes.
//! * [`DescriptionService::finished`] takes the process's answer to one piece of work, and
//!   [`DescriptionService::process_ended`] takes the news that the process has gone.
//!
//! Between the calls the host applies whatever arrived: settled contexts, closures, bindings, pins,
//! privacy. So a result is judged against the state in force when it arrives, never the state when
//! its job was sent. The order is fixed and each step can refuse:
//!
//! 1. **Fenced?** Privacy mode stops a session's work here, and a fenced job is never sent.
//! 2. **Admitted?** The resource and power policy decides, and `resource_paused` is its answer.
//! 3. **Loaded?** A model loads before any job is taken from the queue, under a deadline of its
//!    own, so a slow load is paid for by the queue's wait rather than by a job's thirty seconds.
//! 4. **Anything eligible?** The queue decides, under the cooldown, the cadence and the fairness
//!    bound.
//! 5. **Produced?** The process answers, under the grammar and a deadline measured from dequeue.
//! 6. **Valid?** [`crate::output::validate`] against what is in force now, not at dispatch.
//! 7. **Published.** Into the store, with its provenance, unless the name is pinned.
//!
//! A refusal at any step leaves the session with the label it had, which is a pin, a previous
//! description or the deterministic title. There is no step whose failure removes a name.
//!
//! # What a crash does
//!
//! Section 22: *missing weights, cancellation, load failure or an inference-process crash never
//! removes metadata titles or verified state. Restart only inference.* A process that ends, fails a
//! job or is ended by the host takes the loaded model with it and nothing else. The store, the pins,
//! the trackers and every session are untouched; the job it was running is queued again once with
//! its aging position; and the next load waits a second, doubling to five minutes while failures
//! repeat, until a description is published.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_worker::privacy::PrivacyGeneration;

use crate::budget::{Budgets, ResidentCost};
use crate::context::{
    ContextBinding, ContextBuilder, ContextRevision, ContextSignal, ContextTracker,
    DescriptionContext, Observed, SemanticEvent, Settled,
};
use crate::environment::{DataAccessChoice, ExecutionEnvironment, ModelMapping, Placement};
use crate::error::Result;
use crate::metadata::{
    LabelSource, SessionFacts, SessionLabel, VerifiedStatus, deterministic_title,
};
use crate::metrics::LatencyLedger;
use crate::output::{Expectation, ProducedUnder, Rejection, prompt, validate};
use crate::priority::Cancellation;
use crate::privacy::{
    CleanupDebt, DescriptionFence, DescriptionPrivacy, InFlight, PublishGate, RunningJob,
};
use crate::profile::catalogue::{Catalogue, MetGates, Selection};
use crate::profile::{DownloadPolicy, ModelProfile, ProfileRevision};
use crate::queue::{Enqueued, Freshness, Priority, QueuedJob, Scheduler, SessionStanding};
use crate::resource::{
    HostConditions, PauseReason, ResourcePolicy, ResourceSettings, ResourceState,
};
use crate::store::DescriptionStore;
use crate::time::Reading;
use crate::wire::{JobEnd, LoadEnd, Phases};

/// How long a host with no sessions keeps the model mapped.
pub const IDLE_UNLOAD_MS: u64 = 15 * 60 * 1000;

/// How long a load may take. A load is not a job: it happens before any job is dequeued, and a job
/// always has its whole execution deadline after it.
pub const LOAD_DEADLINE_MS: u64 = 5 * 60 * 1000;

/// How long the next load waits after the first failure. It doubles with each failure after that.
pub const RESTART_FIRST_MS: u64 = 1_000;

/// The longest the next load waits after repeated failures.
pub const RESTART_MOST_MS: u64 = 5 * 60 * 1000;

/// How many failures in a row, none of them followed by a publication, make inference failed.
pub const INFERENCE_FAILED_AFTER: u32 = 3;

/// How soon a paused service with work waiting looks at the host's conditions again.
pub const PAUSE_RECHECK_MS: u64 = 10_000;

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

/// One job, as it is sent to the description process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationRequest {
    /// The prompt, whose data section holds every piece of project text.
    pub prompt: String,
    /// The grammar the sampler is held to.
    pub grammar: &'static str,
    /// The context window, in tokens.
    pub context_tokens: u32,
    /// The output bound, in tokens.
    pub max_output_tokens: u32,
    /// How many processor threads the job may use.
    pub cpu_threads: u32,
    /// The execution deadline, from the moment the job was dequeued, which is the moment this was
    /// built.
    pub deadline_ms: u64,
    /// The resident set past which the process ends the job, in bytes.
    pub ceiling_bytes: u64,
}

/// Which kind of work an identifier names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    /// A load.
    Load,
    /// A job.
    Job,
}

/// Why the host is to end the description process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnloadReason {
    /// This host has had no sessions for this long.
    Idle {
        /// How long.
        idle_ms: u64,
    },
    /// The resource or power policy paused inference, or the owner turned it off.
    Paused(PauseReason),
    /// The process failed, and only inference is restarted.
    Failed,
}

impl UnloadReason {
    /// Returns the stable name this reason is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle { .. } => "idle",
            Self::Paused(reason) => reason.as_str(),
            Self::Failed => "failed",
        }
    }
}

/// What the host does now.
#[derive(Clone, Debug, PartialEq)]
pub enum Instruction {
    /// Start the description process if it is not running, and load this profile in it.
    Load {
        /// The load's identifier, which its answer repeats.
        id: u64,
        /// The profile.
        profile: Box<ModelProfile>,
        /// How long the load may take.
        deadline_ms: u64,
    },
    /// Send the process this job.
    Generate {
        /// The job's identifier, which its answer repeats.
        id: u64,
        /// The session it describes.
        session_id: SessionId,
        /// The job.
        request: GenerationRequest,
    },
    /// Cancel the work with this identifier. Its answer still comes, and is still given to
    /// [`DescriptionService::finished`].
    Cancel {
        /// The work.
        id: u64,
        /// Which kind of work it is.
        work: Work,
    },
    /// End the description process. The service has already let go of the model.
    Unload {
        /// Why.
        why: UnloadReason,
    },
    /// Nothing to do until then, on the continuous clock, or until something changes.
    Wait {
        /// When to ask again, when there is a time.
        until_ms: Option<u64>,
    },
}

/// The process's answer to one piece of work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answered {
    /// The model is loaded.
    Loaded {
        /// How long the load took in the process.
        load_ms: u64,
        /// The process's resident set once it was loaded.
        rss_bytes: u64,
    },
    /// The load ended with no model.
    LoadEnded {
        /// Why.
        why: LoadEnd,
        /// What the process said.
        detail: Option<String>,
    },
    /// A job produced bytes, not yet trusted.
    Produced {
        /// The bytes.
        bytes: Vec<u8>,
        /// Where the job's time went.
        phases: Phases,
        /// The process's largest resident set during the job.
        peak_rss_bytes: u64,
    },
    /// A job ended with nothing.
    Ended {
        /// Why.
        why: JobEnd,
        /// What the process said.
        detail: Option<String>,
    },
}

/// How the description process ended, when the host did not end it on this service's word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcessEnd {
    /// It could not be started.
    CouldNotStart,
    /// It exited, or closed its output, on its own.
    Exited,
    /// Its output was not whole frames of the wire.
    BrokenWire,
    /// It is a build or a wire version this daemon does not speak to.
    WrongBuild,
    /// It did not answer the handshake in time.
    SilentAtStart,
    /// A load or a job ran past its deadline and the process did not end it.
    PastDeadline,
    /// A cancellation went unanswered: the process did not say it had read it, so it is not
    /// listening.
    CancelUnanswered,
    /// The process said it had read the cancellation of a load or of a check of a file, and the
    /// work did not stop within the bound after it. The daemon ended the process for work it had
    /// itself called off.
    StopOverdue,
    /// A check of a file ran past its deadline. The daemon ended the process for a check that
    /// took too long, which says nothing of inference.
    CheckOverdue,
    /// Its resident set passed the ceiling.
    MemoryCeiling,
    /// It stopped reading its requests.
    NotReading,
}

impl ProcessEnd {
    /// Returns the stable name this end is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CouldNotStart => "could_not_start",
            Self::Exited => "exited",
            Self::BrokenWire => "broken_wire",
            Self::WrongBuild => "wrong_build",
            Self::SilentAtStart => "silent_at_start",
            Self::PastDeadline => "past_deadline",
            Self::CancelUnanswered => "cancel_unanswered",
            Self::StopOverdue => "stop_overdue",
            Self::CheckOverdue => "check_overdue",
            Self::MemoryCeiling => "memory_ceiling",
            Self::NotReading => "not_reading",
        }
    }

    /// Returns whether this end counts as a failure of inference: toward the failures in a row
    /// that pause it, and toward the delay before the next start.
    ///
    /// An end the daemon causes to stop work it called off, or a check of a file that took too
    /// long, lost nothing and says nothing of the model. Every other end is the process failing
    /// to do what it was asked, or failing to listen.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::StopOverdue | Self::CheckOverdue)
    }
}

/// What one answer, or one end of the process, came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A model is loaded, and this is how long it took from asking to the answer.
    Loaded {
        /// The cold start, reported apart from any job's execution.
        cold_start_ms: u64,
    },
    /// A load ended with no model.
    LoadEnded {
        /// Why.
        why: LoadEnd,
        /// What the process said.
        detail: Option<String>,
    },
    /// A description was published.
    Published {
        /// The session it describes.
        session_id: SessionId,
        /// How long its job waited in the queue.
        queue_wait_ms: u64,
        /// How long its job took once dequeued.
        execution_ms: u64,
    },
    /// A job's result was refused.
    Rejected {
        /// The session.
        session_id: SessionId,
        /// Why.
        rejection: Rejection,
    },
    /// A job was cancelled.
    Cancelled {
        /// The session.
        session_id: SessionId,
    },
    /// A job passed its deadline.
    DeadlineExceeded {
        /// The session.
        session_id: SessionId,
    },
    /// A job did not finish, and its session's job is queued again with its aging position.
    Requeued {
        /// The session.
        session_id: SessionId,
    },
    /// A job failed and is not queued again.
    Failed {
        /// The session.
        session_id: SessionId,
        /// What went wrong.
        detail: String,
    },
    /// An answer for work nobody is waiting for. It was dropped.
    Dropped {
        /// The identifier it carried.
        id: u64,
    },
    /// The description process ended.
    ProcessEnded {
        /// How.
        why: ProcessEnd,
    },
}

/// How every job has ended, counted.
///
/// Section 22's queue promises that nothing grows under load, and this is how it is shown: every
/// job ends replaced, cancelled, refused, published, past its deadline, failed or queued again,
/// and every answer nobody was waiting for is counted as dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobCounts {
    /// Jobs whose content a newer change replaced in the queue.
    pub replaced: u64,
    /// Descriptions published.
    pub published: u64,
    /// Results refused.
    pub refused: u64,
    /// Jobs cancelled, or dropped from the queue by privacy mode.
    pub cancelled: u64,
    /// Jobs past their deadline.
    pub deadline_exceeded: u64,
    /// Jobs that failed and were not queued again.
    pub failed: u64,
    /// Jobs queued again after they did not finish.
    pub requeued: u64,
    /// Answers for work nobody was waiting for.
    pub dropped_answers: u64,
}

/// What the description process has.
#[derive(Clone, Debug)]
enum Model {
    /// Nothing, as far as this service knows.
    Absent,
    /// A load is running.
    Loading {
        id: u64,
        profile: Box<ModelProfile>,
        asked_ms: u64,
        cancel_sent: bool,
    },
    /// A model is loaded.
    Resident { profile: Box<ModelProfile> },
}

/// Why work in flight is being stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// Its token was cancelled: privacy mode, or a caller.
    Cancelled,
    /// Its session closed.
    Closed,
    /// Inference paused, or was turned off.
    Paused,
    /// The session's revision moved on, so the result would describe what it was.
    Superseded,
}

impl Stop {
    /// Returns whether the job is still wanted, and goes back in the queue.
    const fn requeues(self) -> bool {
        matches!(self, Self::Paused)
    }
}

/// The job the description process has.
#[derive(Clone, Debug)]
struct Dispatched {
    id: u64,
    job: QueuedJob,
    produced_under: ProducedUnder,
    dequeued_ms: u64,
    queue_wait_ms: u64,
    cancellation: Cancellation,
    stopping: Option<Stop>,
    requeued_before: bool,
    /// Whether its session closed, or was opened again, while it ran. Such a job is stopped,
    /// publishes nothing, is never queued again, and leaves no mark on the session there now.
    outlived: bool,
}

/// Restarts after failures: when the next load may happen, and whether the service is paused
/// until then.
#[derive(Clone, Copy, Debug, Default)]
struct Restart {
    failures: u32,
    not_before_ms: u64,
    pause: Option<PauseReason>,
}

impl Restart {
    fn failed(&mut self, now: Reading, pause: Option<PauseReason>) {
        self.failures = self.failures.saturating_add(1);
        let doublings = self.failures.saturating_sub(1).min(20);
        let wait_ms = RESTART_FIRST_MS
            .saturating_mul(1_u64 << doublings)
            .min(RESTART_MOST_MS);
        self.not_before_ms = now.monotonic_ms().saturating_add(wait_ms);
        // A pressure pause is what it says. Failing again and again without one is the
        // service's own: shown while the restart delay runs, so a host that only hears that
        // descriptions have stopped is told why.
        self.pause = pause.or_else(|| {
            (self.failures >= INFERENCE_FAILED_AFTER).then_some(PauseReason::InferenceFailed)
        });
    }

    /// Delays the next load without counting a failure, for work the daemon had to end that the
    /// process did not stop in time.
    fn paced(&mut self, now: Reading) {
        self.not_before_ms = self
            .not_before_ms
            .max(now.monotonic_ms().saturating_add(RESTART_FIRST_MS));
    }

    /// Whether a delay was set, by a failure or by a pace.
    const fn waiting(&self) -> bool {
        self.not_before_ms != 0
    }

    fn succeeded(&mut self) {
        *self = Self::default();
    }
}

/// The records of work in flight that other threads read, shared with whoever drives the service.
///
/// A host that raises privacy mode's fence, cancels a job or asks what is outstanding does so from
/// a thread that is not the service's, so it holds clones of these before the service moves to its
/// own thread. Each clone is the same record: the fence is raised in the service's own, and the
/// running job's token is the one the service cancels.
#[derive(Clone, Debug, Default)]
pub struct Handles {
    /// Which sessions have description processing stopped.
    pub fence: DescriptionFence,
    /// The job in the process, and the handle that cancels it.
    pub running: RunningJob,
    /// How many jobs are dispatched and not yet reconciled.
    pub in_flight: InFlight,
    /// Cleanup privacy mode was asked to do and could not finish.
    pub debt: CleanupDebt,
    /// How many loads are in the process: nought or one.
    pub loading: Arc<AtomicU64>,
}

/// What a host holds a publication under.
///
/// Privacy mode's admission is the host's, and this crate cannot name it, so the service asks it
/// through this: the write that publishes a description runs inside [`Self::hold`], while whatever
/// admits a publication at the job's generation is held, and does not run at all when nothing
/// does. A change of privacy mode then waits for the write, or finds the generation changed and
/// refuses the publication.
pub trait PublicationGate: Send {
    /// Runs `publish` while a publication produced under `generation` is admitted, and returns
    /// what it returned; or returns `None`, without running it, when none is.
    fn hold(
        &self,
        generation: PrivacyGeneration,
        publish: &mut dyn FnMut() -> Result<PublishGate>,
    ) -> Option<Result<PublishGate>>;
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
    state: ResourceState,
    store: DescriptionStore,
    fence: DescriptionFence,
    in_flight: InFlight,
    running: RunningJob,
    debt: CleanupDebt,
    loading: Arc<AtomicU64>,
    gate: Option<Box<dyn PublicationGate>>,
    assets_held: bool,
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
    next_id: u64,
    model: Model,
    job: Option<Dispatched>,
    unload_owed: Option<UnloadReason>,
    restart: Restart,
    counts: JobCounts,
    /// Sessions whose job failed once and is queued again: a second failure is not retried.
    retried: BTreeSet<SessionId>,
    /// Sessions whose last job was superseded: the next one runs to its end.
    superseded: BTreeSet<SessionId>,
    /// Sessions whose changes are waiting for that next job to end, with the priority last given.
    waiting: BTreeMap<SessionId, Priority>,
}

impl std::fmt::Debug for DescriptionService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DescriptionService")
            .field("environment", &self.environment)
            .field("selection", &self.selection)
            .field("queued", &self.scheduler.queued())
            .field("state", &self.state)
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
    ) -> Self {
        Self::sharing(host, catalogue, met, settings, store, Handles::default())
    }

    /// Builds the service for one environment over records of work in flight its host already
    /// holds, so that a thread that is not the service's reads and cancels the same ones.
    #[must_use]
    pub fn sharing(
        host: HostPlacement,
        catalogue: Catalogue,
        met: MetGates,
        settings: ResourceSettings,
        store: DescriptionStore,
        handles: Handles,
    ) -> Self {
        let HostPlacement {
            environment,
            data_access: choice,
            target,
        } = host;
        let selection = catalogue.select(&target, &met);
        let budgets = Budgets::DEFAULTS;
        let policy = ResourcePolicy::new(settings, budgets);
        Self {
            environment,
            choice,
            target,
            catalogue,
            met,
            selection,
            mapping: ModelMapping::new(),
            scheduler: Scheduler::new(budgets),
            state: policy.state(),
            policy,
            store,
            fence: handles.fence,
            in_flight: handles.in_flight,
            running: handles.running,
            debt: handles.debt,
            loading: handles.loading,
            gate: None,
            assets_held: true,
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
            next_id: 0,
            model: Model::Absent,
            job: None,
            unload_owed: None,
            restart: Restart::default(),
            counts: JobCounts::default(),
            retried: BTreeSet::new(),
            superseded: BTreeSet::new(),
            waiting: BTreeMap::new(),
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
    ///
    /// It is the state [`Self::next`] last found, which includes the pause a process past its
    /// memory ceiling leaves until the next load may happen.
    #[must_use]
    pub const fn resource_state(&self) -> ResourceState {
        self.state
    }

    /// Returns the fence privacy mode raises.
    #[must_use]
    pub const fn fence(&self) -> &DescriptionFence {
        &self.fence
    }

    /// Returns the records of work in flight, which another thread may hold clones of.
    #[must_use]
    pub fn handles(&self) -> Handles {
        Handles {
            fence: self.fence.clone(),
            running: self.running.clone(),
            in_flight: self.in_flight.clone(),
            debt: self.debt.clone(),
            loading: Arc::clone(&self.loading),
        }
    }

    /// Holds every publication under `gate` from now on.
    pub fn set_publication_gate(&mut self, gate: Box<dyn PublicationGate>) {
        self.gate = Some(gate);
    }

    /// Says whether publications are held under a gate.
    #[must_use]
    pub const fn publication_gated(&self) -> bool {
        self.gate.is_some()
    }

    /// Says whether the selected profile's files are here and verified.
    ///
    /// A service nobody has said otherwise to takes them to be: a host that fetches its files
    /// says they are not until they have been checked. While they are not, nothing is loaded and
    /// the state is `resource_paused` for `not_downloaded`, and a model that is loaded is
    /// unloaded.
    pub const fn set_assets_held(&mut self, held: bool) {
        self.assets_held = held;
    }

    /// Returns whether the selected profile's files are here and verified.
    #[must_use]
    pub const fn assets_held(&self) -> bool {
        self.assets_held
    }

    /// Returns whether a load is in the process.
    #[must_use]
    pub fn is_loading(&self) -> bool {
        self.loading.load(Ordering::Acquire) != 0
    }

    /// Returns when the changes now waiting in any live session have waited long enough to
    /// settle, on the continuous clock, when any are waiting.
    #[must_use]
    pub fn settle_due_ms(&self) -> Option<u64> {
        // A session whose changes wait for its job settles when the job ends, and a fenced one
        // records nothing: neither has a time to wake for, and a time already past would have the
        // host wake at once, find nothing to do, and wake again for as long as the job runs.
        self.trackers
            .iter()
            .filter(|(session_id, _)| {
                !self.waiting.contains_key(*session_id) && !self.fence.is_fenced(session_id)
            })
            .filter_map(|(_, tracker)| tracker.settles_at_ms())
            .min()
    }

    /// Returns the sessions this environment is tracking.
    #[must_use]
    pub fn live_session_ids(&self) -> Vec<SessionId> {
        self.live_sessions.iter().copied().collect()
    }

    /// Returns how many jobs are dispatched and not yet reconciled, across every session.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight.total()
    }

    /// Returns the handle that cancels the job the process is running.
    #[must_use]
    pub const fn running_job(&self) -> &RunningJob {
        &self.running
    }

    /// Cancels the running job for this session if one is running, and returns whether it stopped
    /// one. The next [`Self::next`] tells the host to cancel it in the process.
    ///
    /// A job whose description had already reached the store is past cancelling, and this returns
    /// false for it rather than reporting work it did not take back.
    pub fn cancel_running(&self, session_id: &SessionId) -> bool {
        self.running.cancel(session_id)
    }

    /// Returns what cleanup privacy mode is still owed.
    #[must_use]
    pub const fn cleanup_debt(&self) -> &CleanupDebt {
        &self.debt
    }

    /// Returns how many times inference has been restarted after a failure.
    #[must_use]
    pub const fn inference_restarts(&self) -> u64 {
        self.inference_restarts
    }

    /// Returns how every job has ended, counted.
    #[must_use]
    pub const fn counts(&self) -> JobCounts {
        self.counts
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

    /// Returns whether a model is loaded in this environment.
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

    /// Returns the resident set past which the description process is ended, in bytes: section
    /// 22's ceiling, or an owner's stricter one.
    #[must_use]
    pub const fn ceiling_bytes(&self) -> u64 {
        self.policy.budgets().process_memory_ceiling_bytes
    }

    /// Returns the next load's earliest time after a failure, when one is waiting.
    #[must_use]
    pub const fn restart_not_before_ms(&self) -> Option<u64> {
        if self.restart.waiting() {
            Some(self.restart.not_before_ms)
        } else {
            None
        }
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
        if let Some(generation) = self.fence.generation(session_id) {
            return generation;
        }
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
    /// There is one setting and it is the policy's, so turning descriptions off stops admission
    /// and dispatch, cancels the work in flight and ends the process, and turning them on again
    /// lets the next load happen. A flag that only changed what a setup surface displayed would be
    /// a switch that did not switch anything.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.settings.enabled = enabled;
        self.policy = ResourcePolicy::new(self.settings, Budgets::DEFAULTS);
    }

    /// Allows or forbids inference while the host is on battery.
    ///
    /// Section 22 keeps it off unless an owner turns it on. Like [`Self::set_enabled`] it is the
    /// policy's own setting, so it applies at the next turn: a model that was unloaded for battery
    /// is loaded again when work is due, and one that was allowed is let go when the host goes onto
    /// battery.
    pub fn set_on_battery(&mut self, allowed: bool) {
        self.settings.on_battery = allowed;
        self.policy = ResourcePolicy::new(self.settings, Budgets::DEFAULTS);
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
        // A session opened afresh starts with a context of its own, and owes nothing to what an
        // earlier job of the same identifier went through: one still in the process, one waiting
        // in the queue with the old context, or the retry an earlier failure used up. The semantic
        // events its earlier self recorded go too, as they do when a session closes.
        self.events.remove(&session_id);
        self.outlive_job_of(&session_id);
        self.scheduler.cancel(&session_id);
        self.retried.remove(&session_id);
        self.superseded.remove(&session_id);
        self.waiting.remove(&session_id);
        self.no_sessions_since_ms = None;
    }

    /// Admits one authorised recent semantic event into a session's context.
    ///
    /// It is the only way an event reaches a description, and the bound is the context's:
    /// [`crate::context::MAX_RECENT_EVENTS`] of them, newest first. A session this host is not
    /// tracking, or one that is fenced, takes none. An event at a cursor the session already holds
    /// is the same event, and changes nothing; a new one is a change of the context, which starts
    /// the debounce at `now`.
    pub fn note_event(
        &mut self,
        session_id: &SessionId,
        event: SemanticEvent,
        now: Reading,
    ) -> bool {
        if self.fence.is_fenced(session_id) || !self.live_sessions.contains(session_id) {
            return false;
        }
        let events = self.events.entry(*session_id).or_default();
        if events.iter().any(|held| held.cursor == event.cursor) {
            return true;
        }
        events.push(event);
        events.sort_by_key(|event| event.cursor);
        while events.len() > crate::context::MAX_RECENT_EVENTS {
            events.remove(0);
        }
        // A new event is a change of the context, so a job follows it after the debounce.
        if let Some(tracker) = self.trackers.get_mut(session_id) {
            tracker.note_event(now);
        }
        true
    }

    /// Records that a session has closed.
    ///
    /// The pin and the provenance stay in the store, which is the whole of section 24's *metadata
    /// and pins survive closure*. What goes is the live tracking: a closed session has no context
    /// to advance and no job to queue, and a job of its that is running is cancelled.
    pub fn session_closed(&mut self, session_id: &SessionId, now: Reading) {
        self.trackers.remove(session_id);
        self.bindings.remove(session_id);
        self.epochs.remove(session_id);
        self.events.remove(session_id);
        self.generations.remove(session_id);
        self.live_sessions.remove(session_id);
        self.outlive_job_of(session_id);
        self.retried.remove(session_id);
        self.superseded.remove(session_id);
        self.waiting.remove(session_id);
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

    /// Forgets every piece of content this service holds in memory, for every session: the queued
    /// jobs, the retained contexts and events, and whatever waits behind a job. Returns how many
    /// queued jobs and sessions with changes pending went. The store's rows are not touched:
    /// removing them is the store's own step.
    ///
    /// This is what privacy mode owes the part of the service that holds no row: a change captured
    /// before it could otherwise reach a job after privacy mode ended.
    pub fn forget_content(&mut self) -> u64 {
        let mut forgotten = self.scheduler.cancel_all();
        for tracker in self.trackers.values_mut() {
            if tracker.settles_at_ms().is_some() {
                forgotten += 1;
            }
            tracker.forget();
        }
        self.events.clear();
        self.retried.clear();
        self.superseded.clear();
        self.waiting.clear();
        forgotten
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
    ///
    /// A revision that advances while the session's job is in the process refuses that job's
    /// result, which describes the session as it was, and the job is cancelled. A session is
    /// superseded at most once in a row, though: while the job after a superseded one runs, the
    /// session's changes wait for it, and they settle as one revision the moment it ends. So a
    /// session that never stops changing, in a long active turn, is still described at least every
    /// other job, and what is published is at most one job behind it (section 22 coalesces events
    /// *so a long active turn can receive useful text without invalidating every job*).
    pub fn settle(
        &mut self,
        session_id: &SessionId,
        priority: Priority,
        now: Reading,
    ) -> Option<Enqueued> {
        if self.superseded.contains(session_id)
            && self
                .job
                .as_ref()
                .is_some_and(|dispatched| dispatched.job.session_id == *session_id)
        {
            self.waiting.insert(*session_id, priority);
            return None;
        }
        self.settle_with(session_id, priority, now, false)
    }

    /// Settles a session's pending changes into a queued job: once the debounce has elapsed, or at
    /// once for changes that waited for a job.
    fn settle_with(
        &mut self,
        session_id: &SessionId,
        priority: Priority,
        now: Reading,
        at_once: bool,
    ) -> Option<Enqueued> {
        if self.fence.is_fenced(session_id) {
            return None;
        }
        let tracker = self.trackers.get_mut(session_id)?;
        let settled = if at_once {
            tracker.settle_pending()
        } else {
            tracker.settle(now)
        };
        let Settled::Advanced { revision, .. } = settled else {
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
        let enqueued = self.scheduler.enqueue(priority, context, now);
        if matches!(enqueued, Enqueued::Replaced { .. }) {
            self.counts.replaced = self.counts.replaced.saturating_add(1);
        }
        Some(enqueued)
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
    /// Returns [`crate::DescribeError::Store`] when the store cannot be read.
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
    /// Returns [`crate::DescribeError::Store`] when the store cannot be read.
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

    /// Returns what the loaded model is costing, when one is loaded.
    #[must_use]
    pub fn resident_cost(&self) -> Option<ResidentCost> {
        match &self.model {
            Model::Resident { profile } => Some(profile.execution().resident_estimate),
            Model::Absent | Model::Loading { .. } => None,
        }
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

    /// Says what the host does now.
    ///
    /// Work in flight comes first: it is cancelled when it should stop - privacy mode or a caller
    /// cancelled it, its session closed, inference paused or was turned off, or a load has nothing
    /// left to be for - and otherwise its answer is waited for. With nothing in flight, an unload
    /// that is owed, an idle host and a pause each end the process; then a model is loaded when
    /// work is due and none is loaded; then the next job is dequeued, with its whole execution
    /// deadline from this moment.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DescribeError::Store`] when the store cannot be read.
    pub fn next(&mut self, conditions: &HostConditions, now: Reading) -> Result<Instruction> {
        if let Some(instruction) = self.stop_in_flight(conditions) {
            return Ok(instruction);
        }
        if self.job.is_some() || matches!(self.model, Model::Loading { .. }) {
            return Ok(Instruction::Wait { until_ms: None });
        }
        let resident = matches!(self.model, Model::Resident { .. });
        if let Some(why) = self.unload_owed.take() {
            self.release();
            return Ok(Instruction::Unload { why });
        }
        let Some(profile) = self.selection.profile().cloned() else {
            return Ok(Instruction::Wait { until_ms: None });
        };
        if resident
            && let Some(idle_since) = self.no_sessions_since_ms
            && now.since_ms(idle_since) >= IDLE_UNLOAD_MS
        {
            self.release();
            return Ok(Instruction::Unload {
                why: UnloadReason::Idle {
                    idle_ms: now.since_ms(idle_since),
                },
            });
        }
        // Without the files nothing is loaded, and a model that is loaded without them is let go.
        if !self.assets_held {
            self.state = ResourceState::ResourcePaused {
                reason: PauseReason::NotDownloaded,
                unloaded: resident,
            };
            if resident {
                self.release();
                return Ok(Instruction::Unload {
                    why: UnloadReason::Paused(PauseReason::NotDownloaded),
                });
            }
            return Ok(Instruction::Wait { until_ms: None });
        }
        // Before a load the model's cost has to come out of the memory this host can see; once it
        // is loaded it is already out. Which world this is comes from what the process answered,
        // not from the policy's own previous answer.
        let cost = self
            .resident_cost()
            .unwrap_or(profile.execution().resident_estimate);
        self.state = self.policy.evaluate(conditions, &cost, resident).to;
        if let ResourceState::ResourcePaused { reason, .. } = self.state {
            if resident {
                self.release();
                return Ok(Instruction::Unload {
                    why: UnloadReason::Paused(reason),
                });
            }
            return Ok(Instruction::Wait {
                until_ms: (self.scheduler.queued() > 0)
                    .then(|| now.monotonic_ms().saturating_add(PAUSE_RECHECK_MS)),
            });
        }
        // A process that passed its ceiling leaves inference paused until the next load may
        // happen, whether or not work is waiting.
        if let Some(reason) = self.restart.pause {
            if now.monotonic_ms() < self.restart.not_before_ms {
                self.state = ResourceState::ResourcePaused {
                    reason,
                    unloaded: !resident,
                };
                return Ok(Instruction::Wait {
                    until_ms: Some(self.restart.not_before_ms),
                });
            }
            self.restart.pause = None;
        }
        if !resident {
            return Ok(self.load_when_due(profile, now));
        }
        Ok(self.dispatch(&profile, now))
    }

    /// Takes the process's answer to one piece of work.
    ///
    /// An answer for work that is not in flight is dropped and counted, and changes nothing. A
    /// job's result is judged against what is in force now: the session's epoch, binding and
    /// revision, the selected profile, privacy mode's generation and fence, the job's token and
    /// deadline, and a pin, which the store checks again in the statement that writes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DescribeError::Store`] when the store cannot be read or written, which is
    /// the only failure this propagates: everything else is an [`Outcome`].
    pub fn finished(&mut self, id: u64, answer: Answered, now: Reading) -> Result<Outcome> {
        if let Model::Loading { id: loading, .. } = &self.model
            && *loading == id
        {
            return Ok(self.finish_load(answer, now));
        }
        if self
            .job
            .as_ref()
            .is_some_and(|dispatched| dispatched.id == id)
        {
            let dispatched = self
                .job
                .take()
                .unwrap_or_else(|| unreachable!("the job was just found"));
            let (session_id, stop) = (dispatched.job.session_id, dispatched.stopping);
            let outlived = dispatched.outlived;
            let outcome = self.finish_job(dispatched, answer, now);
            let superseded = stop == Some(Stop::Superseded)
                || matches!(
                    outcome,
                    Ok(Outcome::Rejected {
                        rejection: Rejection::ChangedContext { .. },
                        ..
                    })
                );
            let requeued = matches!(outcome, Ok(Outcome::Requeued { .. }));
            self.after_job(&session_id, outlived, superseded, requeued, now);
            return outcome;
        }
        self.counts.dropped_answers = self.counts.dropped_answers.saturating_add(1);
        Ok(Outcome::Dropped { id })
    }

    /// Takes the news that the description process ended without this service asking.
    ///
    /// The model goes with it and nothing else. The work in flight ends: a job the process was
    /// cancelling ends cancelled, a job past its deadline ends so, and any other job is queued
    /// again once with its aging position. The next load waits out the restart delay.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DescribeError::Store`] only as [`Self::finished`] does; nothing here writes.
    pub fn process_ended(&mut self, why: ProcessEnd, now: Reading) -> Result<Vec<Outcome>> {
        let mut outcomes = Vec::new();
        if let Some(dispatched) = self.job.take() {
            let (session_id, stop) = (dispatched.job.session_id, dispatched.stopping);
            let outlived = dispatched.outlived;
            let outcome = self.job_ended_with_process(dispatched, why, now);
            let requeued = matches!(outcome, Outcome::Requeued { .. });
            let superseded = stop == Some(Stop::Superseded);
            self.after_job(&session_id, outlived, superseded, requeued, now);
            outcomes.push(outcome);
        }
        let load_called_off = matches!(
            self.model,
            Model::Loading {
                cancel_sent: true,
                ..
            }
        );
        if let Model::Loading { cancel_sent, .. } = &self.model {
            let load_why = match why {
                ProcessEnd::PastDeadline => LoadEnd::DeadlineExceeded,
                ProcessEnd::CancelUnanswered | ProcessEnd::StopOverdue if *cancel_sent => {
                    LoadEnd::Cancelled
                }
                _ => LoadEnd::Failed,
            };
            outcomes.push(Outcome::LoadEnded {
                why: load_why,
                detail: Some(format!("the description process ended: {}", why.as_str())),
            });
        }
        self.release();
        if why.is_failure() {
            self.inference_restarts = self.inference_restarts.saturating_add(1);
            self.restart.failed(
                now,
                (why == ProcessEnd::MemoryCeiling).then_some(PauseReason::MemoryPressure),
            );
        } else if load_called_off {
            // Not a failure of inference, but a host that is near the reserve would otherwise admit
            // a load, call it off and end the process in a loop with nothing between.
            self.restart.paced(now);
        }
        if why == ProcessEnd::MemoryCeiling {
            self.state = ResourceState::ResourcePaused {
                reason: PauseReason::MemoryPressure,
                unloaded: true,
            };
        }
        outcomes.push(Outcome::ProcessEnded { why });
        Ok(outcomes)
    }

    /// Notes whether a session's job was superseded, and settles the changes that waited for the
    /// job after a superseded one, now that it has ended.
    ///
    /// A job queued again keeps its session's standing, so the attempt that runs it next is still
    /// the one after a superseded job. A job whose session closed, or was opened again, while it
    /// ran leaves no mark on the session that is there now.
    fn after_job(
        &mut self,
        session_id: &SessionId,
        outlived: bool,
        superseded: bool,
        requeued: bool,
        now: Reading,
    ) {
        if outlived {
            return;
        }
        if superseded {
            self.superseded.insert(*session_id);
        } else if !requeued {
            self.superseded.remove(session_id);
        }
        if let Some(priority) = self.waiting.remove(session_id) {
            let _ = self.settle_with(session_id, priority, now, true);
        }
    }

    /// Notes that the job in the process, when it is this session's, has outlived the session it
    /// was admitted for.
    fn outlive_job_of(&mut self, session_id: &SessionId) {
        if let Some(dispatched) = self.job.as_mut()
            && dispatched.job.session_id == *session_id
        {
            dispatched.outlived = true;
        }
    }

    /// Decides whether the work in flight stops, and says to cancel it once when it does.
    fn stop_in_flight(&mut self, conditions: &HostConditions) -> Option<Instruction> {
        let enabled = self.settings.enabled;
        if let Some(dispatched) = &self.job {
            if dispatched.stopping.is_some() {
                return None;
            }
            let session_id = dispatched.job.session_id;
            let cancelled = dispatched.cancellation.is_cancelled();
            let ran_at = dispatched.produced_under.context_revision;
            let stop = if cancelled
                // A fence raised while this job was being dispatched finds no token to cancel, as
                // it is raised before the job's is registered: the job is stopped here instead, at
                // the next look, whatever the fence's own cancellation reached.
                || self.fence.is_fenced(&session_id)
            {
                Stop::Cancelled
            } else if dispatched.outlived || !self.live_sessions.contains(&session_id) {
                Stop::Closed
            } else if self.revision(&session_id) != Some(ran_at) {
                Stop::Superseded
            } else if !enabled || self.paused_now(conditions, true) {
                Stop::Paused
            } else {
                return None;
            };
            let dispatched = self.job.as_mut()?;
            dispatched.cancellation.cancel();
            dispatched.stopping = Some(stop);
            return Some(Instruction::Cancel {
                id: dispatched.id,
                work: Work::Job,
            });
        }
        if !matches!(
            self.model,
            Model::Loading {
                cancel_sent: false,
                ..
            }
        ) {
            return None;
        }
        let stop = !enabled
            || !self.assets_held
            || self.paused_now(conditions, false)
            || self.scheduler.queued() == 0;
        if !stop {
            return None;
        }
        let Model::Loading {
            id, cancel_sent, ..
        } = &mut self.model
        else {
            return None;
        };
        *cancel_sent = true;
        Some(Instruction::Cancel {
            id: *id,
            work: Work::Load,
        })
    }

    /// Returns whether the policy pauses inference under these conditions.
    fn paused_now(&mut self, conditions: &HostConditions, resident: bool) -> bool {
        let cost = self.resident_cost().or_else(|| {
            self.selection
                .profile()
                .map(|profile| profile.execution().resident_estimate)
        });
        let Some(cost) = cost else {
            return false;
        };
        self.state = self.policy.evaluate(conditions, &cost, resident).to;
        matches!(self.state, ResourceState::ResourcePaused { .. })
    }

    /// Asks for a load when work is due, the restart delay has passed and this environment may
    /// run the profile.
    fn load_when_due(&mut self, profile: ModelProfile, now: Reading) -> Instruction {
        if !self.scheduler.has_eligible(now) {
            return Instruction::Wait {
                until_ms: self.scheduler.next_due_ms(now),
            };
        }
        if now.monotonic_ms() < self.restart.not_before_ms {
            return Instruction::Wait {
                until_ms: Some(self.restart.not_before_ms),
            };
        }
        // Every reason this environment may not run this profile is decided before a byte of it is
        // read: a WSL distribution with no data-access choice, a mobile device, a target the
        // profile does not list and a candidate whose gates are outstanding all refuse here, and
        // loading weights first would be doing the thing the refusal exists to prevent.
        if self
            .mapping
            .admits(
                &self.environment,
                self.choice.as_ref(),
                &profile,
                &self.met,
                &self.target,
            )
            .is_err()
        {
            return Instruction::Wait { until_ms: None };
        }
        let id = self.take_id();
        self.set_model(Model::Loading {
            id,
            profile: Box::new(profile.clone()),
            asked_ms: now.monotonic_ms(),
            cancel_sent: false,
        });
        Instruction::Load {
            id,
            profile: Box::new(profile),
            deadline_ms: LOAD_DEADLINE_MS,
        }
    }

    /// Takes the next eligible job, with its whole deadline from now, and says to send it.
    fn dispatch(&mut self, profile: &ModelProfile, now: Reading) -> Instruction {
        loop {
            let job = match self.scheduler.dequeue(now) {
                Ok(job) => job,
                Err(_) => {
                    let idle_unload = self
                        .no_sessions_since_ms
                        .map(|since| since.saturating_add(IDLE_UNLOAD_MS));
                    let until_ms = match (self.scheduler.next_due_ms(now), idle_unload) {
                        (Some(due), Some(idle)) => Some(due.min(idle)),
                        (due, idle) => due.or(idle),
                    };
                    return Instruction::Wait { until_ms };
                }
            };
            let session_id = job.session_id;
            // A job of a session made private is never sent. Privacy mode takes it back from the
            // queue itself; this is the same rule at the last moment it can be applied.
            if self.fence.is_fenced(&session_id) {
                self.counts.cancelled = self.counts.cancelled.saturating_add(1);
                continue;
            }
            let budgets = self.policy.budgets();
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
            let request = GenerationRequest {
                prompt: prompt(&job.context),
                grammar: crate::output::DESCRIPTION_GRAMMAR,
                // The profile's own figures, bounded by section 22's budgets. A profile that asked
                // for more threads or a longer answer than the budget allows gets the budget; one
                // that asked for less gets what it asked for, because that is what it was
                // qualified with.
                context_tokens: budgets
                    .context_tokens
                    .min(profile.execution().context_tokens),
                max_output_tokens: budgets
                    .max_output_tokens
                    .min(profile.execution().max_output_tokens),
                cpu_threads: budgets.cpu_threads.min(profile.execution().cpu_threads),
                // The deadline starts here, at dequeue, which is what section 22 says. The model
                // is already loaded, so the job has the whole of it.
                deadline_ms: budgets.execution_deadline_ms,
                ceiling_bytes: budgets.process_memory_ceiling_bytes,
            };
            let cancellation = self.running.started(session_id);
            self.in_flight.dispatched(session_id);
            let id = self.take_id();
            let queue_wait_ms = now.since_ms(job.queued_at_ms);
            let requeued_before = self.retried.remove(&session_id);
            self.job = Some(Dispatched {
                id,
                job,
                produced_under,
                dequeued_ms: now.monotonic_ms(),
                queue_wait_ms,
                cancellation,
                stopping: None,
                requeued_before,
                outlived: false,
            });
            return Instruction::Generate {
                id,
                session_id,
                request,
            };
        }
    }

    /// Takes a load's answer.
    fn finish_load(&mut self, answer: Answered, now: Reading) -> Outcome {
        let Model::Loading {
            profile, asked_ms, ..
        } = self.set_model(Model::Absent)
        else {
            unreachable!("a load is in flight")
        };
        match answer {
            Answered::Loaded { .. } => {
                // The mapping is recorded only once the process has the model, so a load that
                // failed leaves no record of a model this host does not have.
                let _ = self.mapping.map(
                    &self.environment,
                    self.choice.as_ref(),
                    &profile,
                    &self.met,
                    &self.target,
                    now.wall_ms(),
                );
                self.set_model(Model::Resident { profile });
                Outcome::Loaded {
                    cold_start_ms: now.since_ms(asked_ms),
                }
            }
            Answered::LoadEnded { why, detail } => {
                if why != LoadEnd::Cancelled {
                    self.restart.failed(now, None);
                }
                Outcome::LoadEnded { why, detail }
            }
            // A job's answer to a load is not an answer to it. The process is not speaking this
            // wire, and it is ended rather than believed.
            Answered::Produced { .. } | Answered::Ended { .. } => {
                self.unload_owed = Some(UnloadReason::Failed);
                self.restart.failed(now, None);
                Outcome::LoadEnded {
                    why: LoadEnd::Failed,
                    detail: Some("the process answered a load as if it were a job".to_owned()),
                }
            }
        }
    }

    /// Takes a job's answer.
    fn finish_job(
        &mut self,
        dispatched: Dispatched,
        answer: Answered,
        now: Reading,
    ) -> Result<Outcome> {
        // The job stays running, and in flight, until its outcome is complete, publication
        // included: a cancellation from another thread is told it was too late only once the
        // description is in the store, and privacy mode's reconciliation waits for the write.
        let _in_flight = InFlightRecords::of(self, dispatched.job.session_id);
        let execution_ms = self.measure(&dispatched, now);
        let (bytes, peak_rss_bytes) = match answer {
            Answered::Produced {
                bytes,
                peak_rss_bytes,
                ..
            } => (bytes, peak_rss_bytes),
            Answered::Ended { why, detail } => {
                return Ok(self.job_ended(dispatched, why, detail, now));
            }
            // A load's answer to a job is not an answer to it.
            Answered::Loaded { .. } | Answered::LoadEnded { .. } => {
                return Ok(self.job_failed(
                    dispatched,
                    "the process answered a job as if it were a load".to_owned(),
                    now,
                ));
            }
        };
        // A job that was being stopped for a pause is still wanted, and its token is cancelled, so
        // what it produced is not published: it goes back in the queue. So does a job whose
        // answer arrives after descriptions were turned off, which publish nothing new.
        if stopped(&dispatched).is_some_and(Stop::requeues) || !self.settings.enabled {
            return Ok(self.requeue_unless_cancelled(dispatched));
        }
        let outcome = self.publish(&dispatched, &bytes, execution_ms, now)?;
        let ceiling = self.policy.budgets().process_memory_ceiling_bytes;
        if peak_rss_bytes > ceiling {
            // The ceiling is a process figure, and the process passed it. The description it
            // produced stands; the model is unloaded and inference pauses until the restart delay
            // has passed.
            self.unload_owed = Some(UnloadReason::Paused(PauseReason::MemoryPressure));
            self.restart.failed(now, Some(PauseReason::MemoryPressure));
            self.state = ResourceState::ResourcePaused {
                reason: PauseReason::MemoryPressure,
                unloaded: true,
            };
        } else if matches!(outcome, Outcome::Published { .. }) {
            self.restart.succeeded();
        }
        Ok(outcome)
    }

    /// Records one attempt's queue wait and execution, however it ended, and returns the
    /// execution. The service time the cadence is worked out from is what the process was busy
    /// for, so a job that timed out or was cancelled counts as well as one that published.
    fn measure(&mut self, dispatched: &Dispatched, now: Reading) -> u64 {
        let execution_ms = now.since_ms(dispatched.dequeued_ms);
        self.scheduler.record_service(execution_ms.max(1));
        self.latency.record(
            self.live_sessions.len() as u32,
            dispatched.queue_wait_ms,
            execution_ms,
        );
        execution_ms
    }

    /// Validates a job's bytes against what is in force now, and publishes them.
    fn publish(
        &mut self,
        dispatched: &Dispatched,
        bytes: &[u8],
        execution_ms: u64,
        now: Reading,
    ) -> Result<Outcome> {
        let session_id = dispatched.job.session_id;
        let produced_under = &dispatched.produced_under;
        let rejected = |counts: &mut JobCounts, rejection: Rejection| {
            counts.refused = counts.refused.saturating_add(1);
            Outcome::Rejected {
                session_id,
                rejection,
            }
        };
        if !self.live_sessions.contains(&session_id) {
            return Ok(rejected(&mut self.counts, Rejection::SessionClosed));
        }
        let Some(session_epoch) = self.epochs.get(&session_id).copied() else {
            return Ok(rejected(&mut self.counts, Rejection::SessionClosed));
        };
        let (profile_id, profile_revision) = self.selection.profile().map_or_else(
            || (String::new(), ProfileRevision::new(0)),
            |profile| (profile.profile_id().to_owned(), profile.revision()),
        );
        let expectation = Expectation {
            session_epoch,
            revision: self
                .revision(&session_id)
                .unwrap_or(ContextRevision::INITIAL),
            binding: self
                .bindings
                .get(&session_id)
                .cloned()
                .unwrap_or_else(|| produced_under.binding.clone()),
            profile_id,
            profile_revision,
            generation: self.privacy_generation(&session_id),
            name_pinned: self.store.pinned(&session_id)?.is_some(),
        };
        let description = match validate(bytes, produced_under, &expectation) {
            Ok(description) => description,
            Err(rejection) => return Ok(rejected(&mut self.counts, rejection)),
        };
        // A job that outlived the session it was admitted for describes a session that is gone,
        // even when the session there now has the same epoch, binding and revision.
        if dispatched.outlived {
            return Ok(rejected(&mut self.counts, Rejection::SessionClosed));
        }
        let mut write = || {
            self.fence.publish_under_lock(
                &self.store,
                &session_id,
                &description,
                now.wall_ms().get(),
                produced_under.generation,
                self.privacy_generation(&session_id),
                &dispatched.cancellation,
                execution_ms,
                self.policy.budgets().execution_deadline_ms,
            )
        };
        let gate = match &self.gate {
            None => write()?,
            Some(held) => match held.hold(produced_under.generation, &mut write) {
                Some(done) => done?,
                // Nothing admits a publication at the generation the job was produced under: privacy
                // mode is on, or the generation moved on.
                None => {
                    return Ok(rejected(
                        &mut self.counts,
                        Rejection::NotAdmitted {
                            found: produced_under.generation,
                        },
                    ));
                }
            },
        };
        Ok(match gate {
            PublishGate::Allowed => {
                self.scheduler.record_success(&session_id, now);
                self.counts.published = self.counts.published.saturating_add(1);
                Outcome::Published {
                    session_id,
                    queue_wait_ms: dispatched.queue_wait_ms,
                    execution_ms,
                }
            }
            PublishGate::Cancelled => {
                self.counts.cancelled = self.counts.cancelled.saturating_add(1);
                Outcome::Cancelled { session_id }
            }
            PublishGate::DeadlineExceeded => {
                self.counts.deadline_exceeded = self.counts.deadline_exceeded.saturating_add(1);
                self.restart.failed(now, None);
                Outcome::DeadlineExceeded { session_id }
            }
            // A pin committed after validation read none. Nothing was recorded, so nothing is a
            // success: the queue's last success stays where it was.
            PublishGate::NamePinned => rejected(&mut self.counts, Rejection::NamePinned),
            PublishGate::Fenced => rejected(
                &mut self.counts,
                Rejection::LateGeneration {
                    expected: self
                        .fence
                        .generation(&session_id)
                        .unwrap_or(PrivacyGeneration::INITIAL),
                    found: produced_under.generation,
                },
            ),
            PublishGate::LateGeneration { expected, found } => rejected(
                &mut self.counts,
                Rejection::LateGeneration { expected, found },
            ),
        })
    }

    /// Takes a job that the process ended with nothing.
    fn job_ended(
        &mut self,
        dispatched: Dispatched,
        why: JobEnd,
        detail: Option<String>,
        now: Reading,
    ) -> Outcome {
        let session_id = dispatched.job.session_id;
        match why {
            JobEnd::Cancelled => {
                if stopped(&dispatched).is_some_and(Stop::requeues) {
                    return self.requeue_unless_cancelled(dispatched);
                }
                self.counts.cancelled = self.counts.cancelled.saturating_add(1);
                Outcome::Cancelled { session_id }
            }
            JobEnd::DeadlineExceeded => {
                self.counts.deadline_exceeded = self.counts.deadline_exceeded.saturating_add(1);
                self.restart.failed(now, None);
                Outcome::DeadlineExceeded { session_id }
            }
            JobEnd::MemoryCeiling => {
                // The job is not queued again: it is the job that passed the ceiling.
                self.unload_owed = Some(UnloadReason::Paused(PauseReason::MemoryPressure));
                self.restart.failed(now, Some(PauseReason::MemoryPressure));
                self.state = ResourceState::ResourcePaused {
                    reason: PauseReason::MemoryPressure,
                    unloaded: true,
                };
                self.counts.failed = self.counts.failed.saturating_add(1);
                Outcome::Failed {
                    session_id,
                    detail: detail.unwrap_or_else(|| "the process passed its ceiling".to_owned()),
                }
            }
            JobEnd::NotLoaded | JobEnd::Refused | JobEnd::Failed => self.job_failed(
                dispatched,
                detail.unwrap_or_else(|| format!("the job ended {}", why.as_str())),
                now,
            ),
        }
    }

    /// Takes a job whose process failed it: only inference is restarted, and the job is queued
    /// again once, unless it was being stopped anyway.
    fn job_failed(&mut self, dispatched: Dispatched, detail: String, now: Reading) -> Outcome {
        self.release();
        self.unload_owed = Some(UnloadReason::Failed);
        self.inference_restarts = self.inference_restarts.saturating_add(1);
        self.restart.failed(now, None);
        self.retry_or_end(dispatched, detail)
    }

    /// Ends the job the process had when it ended.
    fn job_ended_with_process(
        &mut self,
        dispatched: Dispatched,
        why: ProcessEnd,
        now: Reading,
    ) -> Outcome {
        let session_id = dispatched.job.session_id;
        let _in_flight = InFlightRecords::of(self, session_id);
        self.measure(&dispatched, now);
        match why {
            ProcessEnd::PastDeadline => {
                self.counts.deadline_exceeded = self.counts.deadline_exceeded.saturating_add(1);
                Outcome::DeadlineExceeded { session_id }
            }
            ProcessEnd::MemoryCeiling => {
                self.counts.failed = self.counts.failed.saturating_add(1);
                Outcome::Failed {
                    session_id,
                    detail: "the process passed its ceiling".to_owned(),
                }
            }
            _ => self.retry_or_end(
                dispatched,
                format!("the description process ended: {}", why.as_str()),
            ),
        }
    }

    /// Decides what a job that did not finish comes to: a job a caller cancelled ends cancelled, a
    /// job being stopped for a pause goes back in the queue, a job being stopped for any other
    /// reason ends cancelled, and any other job is queued again once.
    ///
    /// A caller's cancellation is read at the moment of the decision, and it outranks the
    /// service's own reasons: a job queued again would get a new token that nothing had cancelled.
    fn retry_or_end(&mut self, dispatched: Dispatched, detail: String) -> Outcome {
        let session_id = dispatched.job.session_id;
        if self.cancelled_by_caller(&dispatched) {
            self.counts.cancelled = self.counts.cancelled.saturating_add(1);
            return Outcome::Cancelled { session_id };
        }
        match stopped(&dispatched) {
            Some(stop) if stop.requeues() => self.requeue(dispatched, false),
            Some(_) => {
                self.counts.cancelled = self.counts.cancelled.saturating_add(1);
                Outcome::Cancelled { session_id }
            }
            None if dispatched.requeued_before => {
                self.counts.failed = self.counts.failed.saturating_add(1);
                Outcome::Failed { session_id, detail }
            }
            None => self.requeue(dispatched, true),
        }
    }

    /// Queues a job that was stopped for a pause again, with its place, unless a caller cancelled
    /// it, which ends it.
    fn requeue_unless_cancelled(&mut self, dispatched: Dispatched) -> Outcome {
        if self.cancelled_by_caller(&dispatched) {
            self.counts.cancelled = self.counts.cancelled.saturating_add(1);
            return Outcome::Cancelled {
                session_id: dispatched.job.session_id,
            };
        }
        self.requeue(dispatched, false)
    }

    /// Closes the running job's handle, which is the moment its fate is decided, and says whether a
    /// caller cancelled it first. A cancellation after this finds nothing running.
    fn cancelled_by_caller(&self, dispatched: &Dispatched) -> bool {
        let by_caller = self.running.close(&dispatched.job.session_id);
        #[cfg(feature = "testing")]
        crate::testing::decided();
        by_caller
    }

    /// Puts a job back in the queue with its aging position. A job put back after a failure is put
    /// back once: its session's next failure is not retried, however many pauses come between.
    fn requeue(&mut self, dispatched: Dispatched, after_failure: bool) -> Outcome {
        let session_id = dispatched.job.session_id;
        // A job whose session closed, or opened again, belongs to a session that is gone.
        if dispatched.outlived
            || !self.live_sessions.contains(&session_id)
            || self.fence.is_fenced(&session_id)
        {
            self.counts.cancelled = self.counts.cancelled.saturating_add(1);
            return Outcome::Cancelled { session_id };
        }
        if after_failure || dispatched.requeued_before {
            self.retried.insert(session_id);
        }
        self.scheduler.requeue(dispatched.job);
        self.counts.requeued = self.counts.requeued.saturating_add(1);
        Outcome::Requeued { session_id }
    }

    /// Lets go of the model: this service no longer counts on the process having one.
    fn release(&mut self) {
        self.set_model(Model::Absent);
        self.mapping.unload(self.environment.id());
    }

    /// Replaces what this service believes the process has, and says so to whoever reads whether a
    /// load is in it, from another thread. Returns what it replaced.
    fn set_model(&mut self, model: Model) -> Model {
        self.loading.store(
            u64::from(matches!(model, Model::Loading { .. })),
            Ordering::Release,
        );
        std::mem::replace(&mut self.model, model)
    }

    /// Returns a new identifier for a piece of work.
    const fn take_id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
}

impl Drop for DescriptionService {
    /// A service that goes owes nothing: the job it had in the process and the load it had asked
    /// for are no longer outstanding for whoever holds the records it shared.
    fn drop(&mut self) {
        if let Some(dispatched) = self.job.take() {
            drop(InFlightRecords::of(self, dispatched.job.session_id));
        }
        self.loading.store(0, Ordering::Release);
    }
}

/// The records of a job in the process that another thread reads: the handle that cancels it
/// and privacy mode's count of work in flight. They are cleared when this goes out of scope,
/// which is when the job's outcome is complete, publication included, and on every early return.
struct InFlightRecords {
    running: RunningJob,
    in_flight: InFlight,
    session_id: SessionId,
}

impl InFlightRecords {
    fn of(service: &DescriptionService, session_id: SessionId) -> Self {
        Self {
            running: service.running.clone(),
            in_flight: service.in_flight.clone(),
            session_id,
        }
    }
}

impl Drop for InFlightRecords {
    fn drop(&mut self) {
        self.running.finished();
        self.in_flight.reconciled(&self.session_id);
    }
}

/// Returns why a job is being stopped: what the service decided, or a cancellation a caller or
/// privacy mode made that the service has not yet acted on.
fn stopped(dispatched: &Dispatched) -> Option<Stop> {
    dispatched.stopping.or_else(|| {
        dispatched
            .cancellation
            .is_cancelled()
            .then_some(Stop::Cancelled)
    })
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
