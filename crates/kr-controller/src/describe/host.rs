//! The description host: the one thread that owns the description service and the process it
//! drives, and what the rest of the daemon is allowed to say to it.
//!
//! # Who owns what
//!
//! One OS thread owns the [`Driver`], the service inside it and a store connection of its own. Every
//! other part of the daemon reaches it through this module's handle and nothing else: the links to
//! the workers write the newest page of each session's facts into a slot and wake it, the
//! controller tells it when a session opens or closes, the owner's settings arrive as messages,
//! and a reader of `session.describe` reads a snapshot it publishes after each turn. Nothing runs
//! on a keystroke's path: no input, resize or query reaches a worker's facts, and the facts reach
//! this thread only as pages the worker decided to send.
//!
//! # Privacy mode
//!
//! A page is applied under [`PrivacyState::admit_send`] at the generation it was captured under,
//! which refuses it while privacy mode is on and when that generation is not the one in force; a
//! result is published under the same admission, through the gate the service is given, so a
//! change of privacy mode waits for a publication in progress and a publication that comes after
//! it is refused. Neither ever nests inside the other, and nothing here takes the privacy record's
//! own mutex or reads [`PrivacyState`] while it holds an admission: the host is called by the
//! record's subsystems while the record holds its mutex, and a host that reached back for it would
//! wait on itself.
//!
//! Fences follow the published state. Privacy mode raises them synchronously, from the thread that
//! enables it ([`DescribeHost::fence`]); this thread lowers one only at the first admission at a
//! newer generation than the one it was raised at, with the session's generation set first, so a
//! job dispatched in between is stamped with the generation that is in force. The memory the
//! service holds, its queue and contexts, is forgotten by a purge the subsystem posts and waits
//! for, within a bound ([`DescribeHost::purge`]): the rows are removed by the caller at once,
//! through the module's own store.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use kr_describe::context::{ContextBinding, ContextSignal, ProjectText, SemanticEvent};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::privacy::PublishGate;
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::queue::{Freshness, Priority};
use kr_describe::resource::{HostConditions, PauseReason, ResourceSettings, ResourceState, Signal};
use kr_describe::service::{DescriptionService, Handles, HostPlacement, PublicationGate};
use kr_describe::store::DescriptionStore;
use kr_describe::supervise::{Driver, Launch, Waker};
use kr_describe::time::Reading;
use kr_protocol::describe::{
    DescriptionCompletion, DescriptionEventKind, DescriptionFactsPage, DescriptionFreshness,
    DescriptionPause, DescriptionState,
};
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_worker::privacy::{PrivacyGeneration, Unavailable};

use crate::error::{ControllerError, Result};
use crate::privacy::PrivacyState;

/// How long a purge the daemon posted may take before the caller is told to ask again.
pub(crate) const PURGE_WAIT: Duration = Duration::from_secs(2);

/// The longest the host sleeps with nothing due: it is woken for everything else.
const IDLE_WAIT: Duration = Duration::from_secs(30);

/// How often the host's conditions are read, off the host's own thread.
const CONDITIONS_EVERY: Duration = Duration::from_secs(10);

/// What the daemon says to the host.
#[derive(Debug)]
enum Message {
    /// A session exists, addressed in this epoch and bound as this.
    Opened {
        session_id: SessionId,
        epoch: SessionEpoch,
        binding: ContextBinding,
    },
    /// A session closed.
    Closed { session_id: SessionId },
    /// The owner's settings: a setting left `None` is left as it is.
    Settings {
        enabled: Option<bool>,
        on_battery: Option<bool>,
    },
    /// Forget everything held in memory, and answer when it is done.
    Purge { done: SyncSender<()> },
    /// Something the host reads changed: the privacy state, a clock a test moved, the conditions.
    Wake,
}

/// What the host publishes about the service after each turn, for a reader of `session.describe`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Snapshot {
    /// What state inference is in.
    pub state: Option<DescriptionState>,
    /// Why it is paused, when it is.
    pub paused: Option<DescriptionPause>,
    /// The cadence the host is running at.
    pub cadence_ms: u64,
    /// Each live session's standing.
    pub sessions: BTreeMap<SessionId, SessionStanding>,
    /// What the host has done.
    pub figures: Figures,
    /// What setup offers, as the service reads it.
    pub setup: Option<kr_describe::service::SetupState>,
    /// When this host started, on the wall clock: a description produced before it is from an
    /// earlier daemon, whose context revisions say nothing about this one's.
    pub started_wall_ms: u64,
}

/// What the host has done, counted, for this crate's own tests and for the doctor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Figures {
    /// How every job has ended.
    pub jobs: kr_describe::service::JobCounts,
    /// How many jobs are dispatched and not yet reconciled.
    pub in_flight: u64,
    /// How many environments have a model mapped, which is never more than one.
    pub mapped: usize,
    /// How many description processes the host has started.
    pub started: u64,
    /// The running process's identifier, when there is one.
    pub pid: Option<u32>,
    /// How many times inference was restarted after a failure.
    pub restarts: u64,
    /// How many sessions the host tracks.
    pub sessions: usize,
    /// Whether a load is in the process.
    pub loading: bool,
}

/// What one session's description stands at.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionStanding {
    /// How long its queued job has been waiting, when it has one.
    pub queued_age_ms: Option<u64>,
    /// How current the description is.
    pub freshness: DescriptionFreshness,
}

/// Where the clocks come from: the machine's, and in this crate's own tests a skew a test moves.
#[derive(Clone, Debug, Default)]
pub(crate) struct Clock {
    skew_ms: Arc<AtomicU64>,
}

impl Clock {
    /// Builds a clock that reads the machine's, advanced by `skew_ms`, which a test moves.
    #[cfg_attr(not(feature = "testing"), allow(dead_code))]
    pub(crate) const fn skewed(skew_ms: Arc<AtomicU64>) -> Self {
        Self { skew_ms }
    }

    /// Returns both clocks now.
    pub(crate) fn now(&self) -> Reading {
        let skew = self.skew_ms.load(Ordering::Acquire);
        Reading::new(
            kr_ipc::clock::boot_elapsed_ms().saturating_add(skew),
            kr_ipc::now_ms().get().saturating_add(skew),
        )
    }
}

/// How the host is built.
pub(crate) struct Setup {
    pub state_dir: PathBuf,
    pub environment_id: EnvironmentId,
    pub launch: Launch,
    pub build: String,
    pub catalogue: Catalogue,
    pub settings: ResourceSettings,
    pub clock: Clock,
    pub privacy: PrivacyState,
    /// Conditions a test holds, in place of reading the host's own.
    pub conditions: Option<Arc<Mutex<HostConditions>>>,
    /// Whether the process is left running when the host stops, as a daemon that hung would leave
    /// it. Only this crate's tests ask for it.
    pub abandon: bool,
}

/// What the rest of the daemon holds of the host.
#[derive(Debug)]
pub(crate) struct DescribeHost {
    shared: Arc<Shared>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Debug)]
struct Shared {
    inbox: Mutex<Sender<Message>>,
    waker: Waker,
    handles: Handles,
    /// The sessions the host tracks, kept here as well as in the service so a fence can be raised
    /// for every one of them from a thread that is not the host's.
    known: Mutex<BTreeSet<SessionId>>,
    /// The newest page of facts of each session, which the thread takes.
    slots: Mutex<BTreeMap<SessionId, Box<DescriptionFactsPage>>>,
    snapshot: RwLock<Snapshot>,
    /// How many purges were posted and not yet done.
    purges_owed: AtomicU64,
    running: AtomicBool,
}

impl DescribeHost {
    /// Opens the service over a store connection of its own and starts the host's thread.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be opened or the
    /// thread cannot be started.
    pub(crate) fn start(setup: Setup) -> Result<Arc<Self>> {
        let Setup {
            state_dir,
            environment_id,
            launch,
            build,
            catalogue,
            settings,
            clock,
            privacy,
            conditions,
            abandon,
        } = setup;
        let started_wall_ms = clock.now().wall_ms().get();
        let store = DescriptionStore::open(&state_dir).map_err(ControllerError::registry)?;
        let handles = Handles::default();
        let mut service = DescriptionService::sharing(
            HostPlacement {
                environment: kr_describe::environment::ExecutionEnvironment::new(
                    environment_id,
                    kr_describe::environment::EnvironmentKind::Native,
                ),
                data_access: None,
                target: kr_describe::environment::build_target().to_owned(),
            },
            catalogue,
            MetGates::default(),
            settings,
            store,
            handles.clone(),
        );
        service.set_publication_gate(Box::new(Admission {
            privacy: privacy.clone(),
        }));
        let driver = Driver::new(service, launch, build);
        let (tell, inbox) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            inbox: Mutex::new(tell),
            waker: driver.waker(),
            handles,
            known: Mutex::new(BTreeSet::new()),
            slots: Mutex::new(BTreeMap::new()),
            snapshot: RwLock::new(Snapshot::default()),
            purges_owed: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });
        // The conditions are read on a thread of their own: a platform reading can spawn a program,
        // and nothing here waits on one.
        if conditions.is_none() {
            let reader = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("describe-conditions".to_owned())
                .spawn(move || read_conditions_until_stopped(&reader))
                .map_err(|error| {
                    ControllerError::registry(format!(
                        "the description host's reader of conditions could not start: {error}"
                    ))
                })?;
        }
        let thread = {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("describe-host".to_owned())
                .spawn(move || {
                    Thread {
                        shared: Arc::clone(&shared),
                        driver,
                        inbox,
                        privacy,
                        clock,
                        conditions,
                        last_event: BTreeMap::new(),
                        started_wall_ms,
                        abandon,
                    }
                    .run();
                    shared.running.store(false, Ordering::Release);
                    shared.purges_owed.store(0, Ordering::Release);
                })
                .map_err(|error| {
                    ControllerError::registry(format!(
                        "the description host's thread could not start: {error}"
                    ))
                })?
        };
        Ok(Arc::new(Self {
            shared,
            thread: Mutex::new(Some(thread)),
        }))
    }

    fn post(&self, message: Message) {
        let sent = self
            .shared
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(message)
            .is_ok();
        if sent {
            self.shared.waker.wake();
        }
    }

    fn known(&self) -> MutexGuard<'_, BTreeSet<SessionId>> {
        self.shared
            .known
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Wakes the host: something it reads changed.
    pub(crate) fn wake(&self) {
        self.post(Message::Wake);
    }

    /// Tells the host a session exists, and that its worker may be read.
    pub(crate) fn session_opened(
        &self,
        session_id: SessionId,
        epoch: SessionEpoch,
        binding: ContextBinding,
    ) {
        self.known().insert(session_id);
        self.post(Message::Opened {
            session_id,
            epoch,
            binding,
        });
    }

    /// Tells the host a session closed.
    pub(crate) fn session_closed(&self, session_id: SessionId) {
        self.known().remove(&session_id);
        self.shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&session_id);
        self.post(Message::Closed { session_id });
    }

    /// Hands the host the newest page of a session's facts, replacing one it has not read.
    pub(crate) fn page(&self, session_id: SessionId, page: Box<DescriptionFactsPage>) {
        self.shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id, page);
        self.shared.waker.wake();
    }

    /// Applies the owner's settings, which take effect at the host's next turn.
    pub(crate) fn settings(&self, enabled: Option<bool>, on_battery: Option<bool>) {
        self.post(Message::Settings {
            enabled,
            on_battery,
        });
    }

    /// Stops description processing for every session the host tracks, from the thread that
    /// enabled privacy mode: raises each session's fence at `generation` and cancels the job
    /// running for it. The host cancels a load when it next turns, with the queue purged.
    pub(crate) fn fence(&self, generation: PrivacyGeneration) -> u64 {
        let sessions: Vec<SessionId> = self.known().iter().copied().collect();
        let mut cancelled = 0;
        for session_id in &sessions {
            self.shared.handles.fence.raise(*session_id, generation);
            cancelled += u64::from(self.shared.handles.running.cancel(session_id));
        }
        self.wake();
        cancelled
    }

    /// Has the host forget what it holds in memory, and waits for it to say so.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`] when the host did not say so within [`PURGE_WAIT`]: the purge goes
    /// on, and the caller asks again. A host that does not run owes nothing.
    pub(crate) fn purge(&self) -> std::result::Result<(), Unavailable> {
        if !self.shared.running.load(Ordering::Acquire) {
            return Ok(());
        }
        let (done, answered) = std::sync::mpsc::sync_channel(1);
        self.shared.purges_owed.fetch_add(1, Ordering::AcqRel);
        self.post(Message::Purge { done });
        match answered.recv_timeout(PURGE_WAIT) {
            Ok(()) => Ok(()),
            Err(_) if !self.shared.running.load(Ordering::Acquire) => Ok(()),
            Err(_) => Err(Unavailable::new(
                "the description host has not finished forgetting what it held",
            )),
        }
    }

    /// Returns how much work the host still owes privacy mode: jobs in flight, a load, and a purge
    /// that has been posted and not done.
    pub(crate) fn outstanding(&self) -> u64 {
        if !self.shared.running.load(Ordering::Acquire) {
            return 0;
        }
        self.shared.handles.in_flight.total()
            + u64::from(self.shared.handles.loading.load(Ordering::Acquire) != 0)
            + self.shared.purges_owed.load(Ordering::Acquire)
    }

    /// Returns what the host last published.
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.shared
            .snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the host's thread is running.
    pub(crate) fn runs(&self) -> bool {
        self.shared.running.load(Ordering::Acquire)
    }

    /// Stops the host's thread and ends the description process.
    pub(crate) fn stop(&self) {
        self.shared.running.store(false, Ordering::Release);
        let _ = self
            .shared
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(Message::Wake);
        self.shared.waker.wake();
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for DescribeHost {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Publishes a description under privacy mode's admission: the write runs while a publication
/// produced under `generation` is admitted, and does not run at all when none is.
struct Admission {
    privacy: PrivacyState,
}

impl PublicationGate for Admission {
    fn hold(
        &self,
        generation: PrivacyGeneration,
        publish: &mut dyn FnMut() -> kr_describe::Result<PublishGate>,
    ) -> Option<kr_describe::Result<PublishGate>> {
        let _admission = self.privacy.admit_send(generation)?;
        Some(publish())
    }
}

/// The host's thread.
struct Thread {
    shared: Arc<Shared>,
    driver: Driver,
    inbox: Receiver<Message>,
    privacy: PrivacyState,
    clock: Clock,
    conditions: Option<Arc<Mutex<HostConditions>>>,
    /// The newest event cursor taken from each session's facts.
    last_event: BTreeMap<SessionId, u64>,
    /// When this thread started, on the wall clock.
    started_wall_ms: u64,
    /// Whether the process is left running when this thread ends.
    abandon: bool,
}

impl Thread {
    fn run(mut self) {
        while self.shared.running.load(Ordering::Acquire) {
            let now = self.clock.now();
            self.take_messages(now);
            self.take_pages(now);
            self.settle_sessions(now);
            let conditions = self.conditions();
            let _ = self.driver.turn(&conditions, now);
            self.publish_snapshot(now);
            let wait = self.next_wait(now);
            self.driver.wait(wait);
        }
        // The process goes with the host: the driver ends it when it is dropped, unless a test
        // asked for it to outlive this daemon.
        #[cfg(feature = "testing")]
        if self.abandon {
            self.driver.abandon();
        }
        #[cfg(not(feature = "testing"))]
        let _ = self.abandon;
    }

    fn conditions(&self) -> HostConditions {
        match &self.conditions {
            Some(held) => *held.lock().unwrap_or_else(PoisonError::into_inner),
            None => latest_conditions(&self.shared),
        }
    }

    fn take_messages(&mut self, now: Reading) {
        while let Ok(message) = self.inbox.try_recv() {
            match message {
                Message::Opened {
                    session_id,
                    epoch,
                    binding,
                } => {
                    self.driver
                        .service_mut()
                        .session_opened(session_id, epoch, binding);
                    // A session opened while privacy mode is on is fenced from the start, at the
                    // generation in force.
                    let published = self.privacy.now();
                    if published.private {
                        self.shared
                            .handles
                            .fence
                            .raise(session_id, published.generation);
                    }
                }
                Message::Closed { session_id } => {
                    self.driver.service_mut().session_closed(&session_id, now);
                    self.last_event.remove(&session_id);
                }
                Message::Settings {
                    enabled,
                    on_battery,
                } => {
                    if let Some(enabled) = enabled {
                        self.driver.service_mut().set_enabled(enabled);
                    }
                    if let Some(allowed) = on_battery {
                        self.driver.service_mut().set_on_battery(allowed);
                    }
                }
                Message::Purge { done } => {
                    let _ = self.driver.service_mut().forget_content();
                    self.shared
                        .slots
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clear();
                    self.last_event.clear();
                    // Owed until it is done, and no longer.
                    let _ = self.shared.purges_owed.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |owed| Some(owed.saturating_sub(1)),
                    );
                    let _ = done.send(());
                }
                Message::Wake => {}
            }
        }
    }

    fn take_pages(&mut self, now: Reading) {
        let pages = std::mem::take(
            &mut *self
                .shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for (session_id, page) in pages {
            self.apply(session_id, &page, now);
        }
    }

    /// Applies one page of a session's facts under privacy mode's admission at the generation it
    /// was captured under, or drops it when none admits it.
    fn apply(&mut self, session_id: SessionId, page: &DescriptionFactsPage, now: Reading) {
        let Some(facts) = page.facts.0.as_ref() else {
            return;
        };
        if !self
            .driver
            .service()
            .live_session_ids()
            .contains(&session_id)
        {
            return;
        }
        let generation = PrivacyGeneration::new(facts.generation.get());
        let Some(admission) = self.privacy.admit_send(generation) else {
            return;
        };
        // The session's fence follows the published state: lowered at the first admission at a
        // newer non-private generation than the one it was raised at, and only when it was raised
        // at an older one, with the session's generation set first so that a job dispatched
        // between the two is stamped with the generation in force.
        let service = self.driver.service_mut();
        if let Some(raised) = service.fence().generation(&session_id) {
            if raised.get() >= generation.get() {
                return;
            }
            service.set_privacy_generation(session_id, generation);
            service.fence().lower(&session_id);
        } else {
            service.set_privacy_generation(session_id, generation);
        }
        capture(service, session_id, facts, now, &mut self.last_event);
        drop(admission);
    }

    fn settle_sessions(&mut self, now: Reading) {
        let sessions = self.driver.service().live_session_ids();
        let service = self.driver.service_mut();
        for session_id in sessions {
            let _ = service.settle(&session_id, Priority::Ordinary, now);
        }
    }

    fn publish_snapshot(&mut self, now: Reading) {
        let service = self.driver.service();
        let setup = service.setup_state();
        let (state, paused) = if setup.offered {
            match service.resource_state() {
                ResourceState::ResourcePaused { reason, .. } => {
                    (DescriptionState::ResourcePaused, Some(pause_of(reason)))
                }
                ResourceState::Ready | ResourceState::Admitted => (
                    if service.is_mapped() {
                        DescriptionState::Resident
                    } else {
                        DescriptionState::Ready
                    },
                    None,
                ),
            }
        } else {
            (
                DescriptionState::ResourcePaused,
                Some(DescriptionPause::NoModelHere),
            )
        };
        let mut sessions = BTreeMap::new();
        for session_id in service.live_session_ids() {
            let standing = service.standing(&session_id, now);
            let freshness = match service.freshness(&session_id, now) {
                Ok(Some(Freshness::Current)) => DescriptionFreshness::Current,
                Ok(Some(Freshness::Delayed { .. })) => DescriptionFreshness::Delayed,
                Ok(Some(Freshness::Stale { .. })) => DescriptionFreshness::Stale,
                Ok(None) | Err(_) => DescriptionFreshness::None,
            };
            sessions.insert(
                session_id,
                SessionStanding {
                    queued_age_ms: standing.queued_age_ms,
                    freshness,
                },
            );
        }
        let cadence_ms = sessions.keys().next().map_or(
            kr_describe::budget::Budgets::DEFAULTS.session_cooldown_ms,
            |session_id| service.standing(session_id, now).cadence_ms,
        );
        let figures = Figures {
            jobs: service.counts(),
            in_flight: service.in_flight(),
            mapped: service.mapped_environments(),
            started: self.driver.started(),
            pid: self.driver.pid(),
            restarts: service.inference_restarts(),
            sessions: service.live_sessions(),
            loading: service.is_loading(),
        };
        let snapshot = Snapshot {
            state: Some(state),
            paused,
            cadence_ms,
            sessions,
            figures,
            setup: Some(setup),
            started_wall_ms: self.started_wall_ms,
        };
        *self
            .shared
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner) = snapshot;
    }

    /// How long the host may sleep: until the driver's next timer or the earliest change that will
    /// have settled, and never longer than [`IDLE_WAIT`].
    fn next_wait(&self, now: Reading) -> Duration {
        let due = [self.driver.due_ms(), self.driver.service().settle_due_ms()]
            .into_iter()
            .flatten()
            .min();
        due.map_or(IDLE_WAIT, |due| {
            Duration::from_millis(due.saturating_sub(now.monotonic_ms())).min(IDLE_WAIT)
        })
    }
}

/// Puts one session's facts into the service as the signals and events they are.
fn capture(
    service: &mut DescriptionService,
    session_id: SessionId,
    facts: &kr_protocol::describe::DescriptionFacts,
    now: Reading,
    last_event: &mut BTreeMap<SessionId, u64>,
) {
    if let Some(directory) = facts.directory.0.clone() {
        let repository = facts
            .repository
            .0
            .as_ref()
            .map(|repository| RepositoryFacts {
                name: repository.name.clone(),
                branch: repository.branch.0.clone(),
            });
        let _ = service.observe(
            &session_id,
            ContextSignal::WorkingDirectory {
                directory,
                repository,
            },
            now,
        );
    }
    if let Some(application) = facts.application.0.clone() {
        let _ = service.observe(
            &session_id,
            ContextSignal::ForegroundApplication(application),
            now,
        );
    }
    if let Some(thread) = facts.thread.0.clone() {
        let _ = service.observe(&session_id, ContextSignal::SelectedThread(thread), now);
    }
    if let Some(intent) = facts.intent.0.clone() {
        let _ = service.observe(&session_id, ContextSignal::TaskIntent(intent), now);
    }
    if let Some(completion) = facts.completion.0 {
        let _ = service.observe(
            &session_id,
            ContextSignal::Completion(match completion {
                DescriptionCompletion::Succeeded => kr_describe::context::Completion::Succeeded,
                DescriptionCompletion::Failed => kr_describe::context::Completion::Failed,
            }),
            now,
        );
    }
    // Oldest first, and only the ones not taken before.
    let taken = last_event.get(&session_id).copied();
    for event in facts.events.iter().rev() {
        let cursor = event.cursor.get();
        if taken.is_some_and(|taken| cursor <= taken) {
            continue;
        }
        if let Some(summary) = ProjectText::new(&event.summary) {
            let _ = service.note_event(
                &session_id,
                SemanticEvent {
                    cursor,
                    kind: match event.kind {
                        DescriptionEventKind::CommandAccepted => {
                            kr_describe::context::SemanticEventKind::CommandAccepted
                        }
                        DescriptionEventKind::TaskStarted => {
                            kr_describe::context::SemanticEventKind::TaskStarted
                        }
                        DescriptionEventKind::TaskCompleted => {
                            kr_describe::context::SemanticEventKind::TaskCompleted
                        }
                        DescriptionEventKind::ApprovalRequested => {
                            kr_describe::context::SemanticEventKind::ApprovalRequested
                        }
                        DescriptionEventKind::FileChanged => {
                            kr_describe::context::SemanticEventKind::FileChanged
                        }
                    },
                    summary,
                },
            );
        }
        last_event.insert(session_id, cursor);
    }
}

/// Maps the service's pause onto the protocol's word for it.
const fn pause_of(reason: PauseReason) -> DescriptionPause {
    match reason {
        PauseReason::MemoryReserve => DescriptionPause::MemoryReserve,
        PauseReason::MemoryPressure => DescriptionPause::MemoryPressure,
        PauseReason::Thermal => DescriptionPause::Thermal,
        PauseReason::Battery => DescriptionPause::Battery,
        PauseReason::SignalUnqualified { .. } => DescriptionPause::SignalUnqualified,
        PauseReason::Disabled => DescriptionPause::Disabled,
        PauseReason::NotDownloaded => DescriptionPause::NotDownloaded,
        PauseReason::InferenceFailed => DescriptionPause::InferenceFailed,
    }
}

/// The host's own conditions, read by [`read_conditions_until_stopped`] and held for the thread.
static LATEST: Mutex<BTreeMap<usize, HostConditions>> = Mutex::new(BTreeMap::new());

fn key_of(shared: &Arc<Shared>) -> usize {
    Arc::as_ptr(shared) as usize
}

fn latest_conditions(shared: &Arc<Shared>) -> HostConditions {
    LATEST
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key_of(shared))
        .copied()
        .unwrap_or_else(|| {
            // Nothing read yet: every signal is unqualified, which the policy treats as a pause.
            let unread = Signal::Unqualified {
                why: "the host's conditions have not been read yet",
            };
            HostConditions {
                physical_memory_bytes: unread,
                available_memory_bytes: unread,
                power: Signal::Unqualified {
                    why: "the host's conditions have not been read yet",
                },
                thermal: Signal::Unqualified {
                    why: "the host's conditions have not been read yet",
                },
            }
        })
}

fn read_conditions_until_stopped(shared: &Arc<Shared>) {
    while shared.running.load(Ordering::Acquire) {
        let reading = kr_describe::resource::platform::read_conditions();
        LATEST
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key_of(shared), reading);
        shared.waker.wake();
        let until = std::time::Instant::now() + CONDITIONS_EVERY;
        while shared.running.load(Ordering::Acquire) && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    LATEST
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&key_of(shared));
}

/// Where the host keeps what the process downloads: `<state>/models`.
pub(crate) fn models_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("models")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::Published;
    use kr_describe::profile::catalogue::Catalogue;
    use kr_describe::resource::ResourceSettings;
    use kr_protocol::describe::{DescriptionFacts, DescriptionFactsPage};
    use kr_protocol::ids::RequestId;
    use kr_protocol::scalars::{Nullable, U64, Uuid};

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([7; 16]))
    }

    /// A host thread over a service that is never asked to start a process, in `state`.
    fn thread(state: Published) -> (tempfile::TempDir, Thread) {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let privacy = PrivacyState::at(state);
        let handles = Handles::default();
        let service = DescriptionService::sharing(
            HostPlacement {
                environment: kr_describe::environment::ExecutionEnvironment::new(
                    EnvironmentId::new(Uuid::from_bytes([9; 16])),
                    kr_describe::environment::EnvironmentKind::Native,
                ),
                data_access: None,
                target: kr_describe::environment::build_target().to_owned(),
            },
            Catalogue::builtin().expect("this build ships profiles it can run"),
            MetGates::default(),
            ResourceSettings::default(),
            DescriptionStore::in_memory().expect("a store in memory"),
            handles.clone(),
        );
        let driver = Driver::new(
            service,
            Launch {
                program: directory.path().join("never-started"),
                arguments: Vec::new(),
                working_directory: directory.path().to_path_buf(),
                environment: Vec::new(),
                models: directory.path().join("models"),
            },
            "kr-test/0".to_owned(),
        );
        let (tell, inbox) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            inbox: Mutex::new(tell),
            waker: driver.waker(),
            handles,
            known: Mutex::new(BTreeSet::new()),
            slots: Mutex::new(BTreeMap::new()),
            snapshot: RwLock::new(Snapshot::default()),
            purges_owed: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });
        let mut thread = Thread {
            shared,
            driver,
            inbox,
            privacy,
            clock: Clock::default(),
            conditions: None,
            last_event: BTreeMap::new(),
            started_wall_ms: 0,
            abandon: false,
        };
        thread.driver.service_mut().session_opened(
            session(),
            SessionEpoch::V1,
            ContextBinding::new("display-1/epoch-1"),
        );
        (directory, thread)
    }

    /// A page of one session's facts, captured under `generation`.
    fn page(generation: u64) -> DescriptionFactsPage {
        DescriptionFactsPage {
            request_id: RequestId::new(1),
            session_id: session(),
            privacy_generation: Nullable::some(U64::new(generation)),
            private: false,
            facts: Nullable::some(DescriptionFacts {
                revision: U64::new(1),
                generation: U64::new(generation),
                directory: Nullable::some("kalareach".to_owned()),
                repository: Nullable::null(),
                application: Nullable::some("cargo".to_owned()),
                completion: Nullable::null(),
                intent: Nullable::null(),
                thread: Nullable::null(),
                events: Vec::new(),
            }),
        }
    }

    fn pending(thread: &Thread) -> bool {
        thread.driver.service().settle_due_ms().is_some()
    }

    fn state(generation: u64, private: bool) -> Published {
        Published {
            generation: PrivacyGeneration::new(generation),
            private,
        }
    }

    /// A page is applied under privacy mode's admission at the generation it was captured under:
    /// it is taken while privacy mode is off at that generation, and refused while it is on and
    /// when the generation in force is another. The control is the first case, which is taken.
    #[test]
    fn a_page_is_applied_only_under_an_admission_at_its_own_generation() {
        let now = Reading::new(1_000, 1_700_000_000_000);
        let (_directory, mut taken) = thread(state(0, false));
        taken.apply(session(), &page(0), now);
        assert!(pending(&taken), "off, and the page is of that generation");

        let (_directory, mut private) = thread(state(1, true));
        private.apply(session(), &page(1), now);
        private.apply(session(), &page(0), now);
        assert!(!pending(&private), "privacy mode is on");

        let (_directory, mut behind) = thread(state(2, false));
        behind.apply(session(), &page(1), now);
        assert!(!pending(&behind), "the generation in force is another");
    }

    /// A session's fence is lowered at the first page admitted at a newer non-private generation
    /// than the one it was raised at, with the generation set first; a fence raised at the
    /// generation of the page, or later, is left up. The control is a fence that is not up, whose
    /// session takes the page as any other.
    #[test]
    fn a_fence_is_lowered_only_at_a_page_of_a_newer_generation_than_it_was_raised_at() {
        let now = Reading::new(1_000, 1_700_000_000_000);
        let (_directory, mut lowered) = thread(state(2, false));
        lowered
            .shared
            .handles
            .fence
            .raise(session(), PrivacyGeneration::new(1));
        lowered.apply(session(), &page(2), now);
        assert!(
            !lowered.shared.handles.fence.is_fenced(&session()),
            "the fence went down"
        );
        assert_eq!(
            lowered.driver.service().privacy_generation(&session()),
            PrivacyGeneration::new(2),
            "and the session is stamped with the generation in force"
        );
        assert!(pending(&lowered));

        let (_directory, mut held) = thread(state(2, false));
        held.shared
            .handles
            .fence
            .raise(session(), PrivacyGeneration::new(2));
        held.apply(session(), &page(2), now);
        assert!(
            held.shared.handles.fence.is_fenced(&session()),
            "raised at this generation: not lowered by a page of it"
        );
        assert!(!pending(&held));
    }

    /// A publication runs inside the admission and only while a result produced under its
    /// generation is admitted: it runs while privacy mode is off at that generation, and does not
    /// run at all while privacy mode is on or when the generation in force is another.
    #[test]
    fn a_publication_runs_only_while_its_generation_is_admitted() {
        let ran = |state: Published, generation: u64| {
            let gate = Admission {
                privacy: PrivacyState::at(state),
            };
            let mut ran = false;
            let outcome = gate.hold(PrivacyGeneration::new(generation), &mut || {
                ran = true;
                Ok(PublishGate::Allowed)
            });
            (ran, outcome.is_some())
        };
        assert_eq!(ran(state(3, false), 3), (true, true));
        assert_eq!(ran(state(3, true), 3), (false, false), "privacy mode is on");
        assert_eq!(
            ran(state(4, false), 3),
            (false, false),
            "another generation"
        );
    }
}
