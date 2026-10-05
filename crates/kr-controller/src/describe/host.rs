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
use kr_describe::profile::ModelProfile;
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::queue::{Freshness, Priority};
use kr_describe::resource::{HostConditions, PauseReason, ResourceSettings, ResourceState, Signal};
use kr_describe::service::{
    DescriptionService, DownloadProgress, Handles, HostPlacement, PublicationGate,
};
use kr_describe::store::DescriptionStore;
use kr_describe::supervise::{Check, Checked, Driver, Launch, Report, Waker};
use kr_describe::time::Reading;
use kr_describe::wire::VerifyResult;
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

/// How old a reading of the host's conditions may be before it says nothing: the policy admits no
/// load on an older one, and a reader that stops answering leaves every signal unqualified rather
/// than leaving the last answer in force.
const CONDITIONS_MAX_AGE_MS: u64 = 60_000;

/// Where the identifiers of checks begin: well apart from the service's own, which count from one.
const CHECK_IDS_FROM: u64 = 1 << 40;

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
    /// Everything posted before this has been taken: answer once the turn that took it has
    /// published what it found.
    Turned {
        done: tokio::sync::oneshot::Sender<()>,
    },
    /// Forget everything held in memory, and answer when it is done.
    Purge { done: SyncSender<()> },
    /// Something the host reads changed: the privacy state, a clock a test moved, the conditions.
    Wake,
    /// How a fetch of the model's files is going, and answer when the host has taken it, when
    /// asked to.
    Download {
        progress: DownloadProgress,
        done: Option<tokio::sync::oneshot::Sender<()>>,
    },
    /// Whether this host holds the model's files.
    Assets { held: bool },
    /// Have the process check a file, and send what it says.
    Check {
        request: CheckRequest,
        reply: tokio::sync::oneshot::Sender<Checked>,
    },
    /// Stop the check that is waiting or running.
    CancelCheck,
    /// Fails the host's thread, for this crate's own tests of what a failing thread leaves behind.
    #[cfg(test)]
    Fail,
}

/// A file the process is to check against the size and digest its profile records.
#[derive(Debug)]
pub(crate) struct CheckRequest {
    pub profile_id: String,
    pub revision: u64,
    pub file_name: String,
    pub path: PathBuf,
    pub deadline_ms: u64,
}

/// A page of facts waiting for the host's thread.
#[derive(Debug)]
struct Waiting {
    page: Box<DescriptionFactsPage>,
    /// Whether it is what the worker answered a new connection with at once: facts it kept from
    /// before the connection, whose moment nothing here knows. A page that replaces one that was
    /// not read keeps the mark, since it holds those facts as well as what came after.
    found: bool,
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
    /// What the host last observed of each live session's directory and program.
    pub seen: BTreeMap<SessionId, Seen>,
}

/// What the host observed of one session's directory and program, and when.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Seen {
    /// The directory the newest command ran in, with its repository when it is inside one.
    pub directory: Option<SeenText>,
    /// The program of the newest command.
    pub application: Option<SeenText>,
}

/// One thing the host observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SeenText {
    /// What was observed.
    pub text: String,
    /// When the host first observed it as it stands, on the wall clock, in milliseconds.
    pub at_ms: u64,
    /// The privacy generation it was captured under: nothing of another generation is read.
    pub generation: PrivacyGeneration,
    /// Whether it came in a page the worker answered a new connection with at once, which holds the
    /// facts it kept from before: they were produced at a moment nothing here knows, and the
    /// moment the host saw them says nothing of it.
    pub inherited: bool,
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
    /// Whether every publication is held under privacy mode's admission.
    pub gated: bool,
    /// Whether this host holds the model's files.
    pub assets_held: bool,
    /// The host's own clock as its last turn read it, in milliseconds: a turn that began after a
    /// moment reads a time at or past it.
    pub read_at_ms: u64,
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
    /// The target this was built for, and the instruction sets the processor it runs on has.
    pub target: String,
    pub processor: kr_describe::processor::Features,
    pub settings: ResourceSettings,
    pub clock: Clock,
    pub privacy: PrivacyState,
    /// Conditions a test holds, in place of reading the host's own.
    pub conditions: Option<Arc<Mutex<HostConditions>>>,
    /// Whether the process is left running when the host stops, as a daemon that hung would leave
    /// it. Only this crate's tests ask for it.
    pub abandon: bool,
    /// The room a test says the disk has, in place of the disk's own.
    pub free_space: Option<Arc<Mutex<Option<u64>>>>,
    /// How long a test lets a fetch wait for the server, in place of the product's own bound.
    pub stall: Option<Arc<Mutex<Option<Duration>>>>,
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
    slots: Mutex<BTreeMap<SessionId, Waiting>>,
    snapshot: RwLock<Snapshot>,
    /// How many purges were posted and not yet done.
    purges_owed: AtomicU64,
    running: AtomicBool,
    /// The newest reading of the host's own conditions, and when it was taken.
    reading: Mutex<Option<Taken>>,
    files: Files,
}

/// Where the model's files are kept and what the fetch of them needs of the host.
#[derive(Debug, Default)]
struct Files {
    models: PathBuf,
    /// The profile the host selected, whose files these are.
    profile: Option<ModelProfile>,
    /// The room a test says the disk has.
    free_space: Option<Arc<Mutex<Option<u64>>>>,
    /// How long a test lets a fetch wait for the server.
    stall: Option<Arc<Mutex<Option<Duration>>>>,
    /// The identifiers the host gives the checks it has made.
    next_check: AtomicU64,
}

/// What the host's thread keeps of the model's files: whether the marker is on disk, the check
/// waiting for the process, the one the process has, and who is to be told when a turn is done.
#[derive(Debug, Default)]
struct Held {
    marker: bool,
    pending: Option<(Check, tokio::sync::oneshot::Sender<Checked>)>,
    awaiting: Option<(u64, tokio::sync::oneshot::Sender<Checked>)>,
    acks: Vec<tokio::sync::oneshot::Sender<()>>,
}

/// One reading of the host's own conditions.
#[derive(Clone, Copy, Debug)]
struct Taken {
    /// When it was taken, on the continuous clock.
    at_ms: u64,
    conditions: HostConditions,
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
            target,
            processor,
            settings,
            clock,
            privacy,
            conditions,
            abandon,
            free_space,
            stall,
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
                target,
                processor,
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
        // The files the selected profile needs are held when the marker says so and each is there:
        // until they are, nothing is loaded, and a session is shown its title from metadata.
        let models = models_dir(&state_dir);
        let profile = service.selection().profile().cloned();
        // A fetch that was cut off by the daemon going leaves a partial file, which nothing reads.
        if let Some(profile) = &profile {
            super::assets::remove_leftovers(&models, profile);
        }
        let files_held = profile
            .as_ref()
            .is_some_and(|profile| super::assets::held(&models, profile));
        if profile.is_some() {
            service.set_assets_held(files_held);
            if files_held {
                service.note_download(DownloadProgress::Verified);
                if let Some(profile) = &profile {
                    super::assets::remove_other_revisions(&models, profile);
                }
            }
        }
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
            reading: Mutex::new(None),
            files: Files {
                models,
                profile,
                free_space,
                stall,
                next_check: AtomicU64::new(CHECK_IDS_FROM),
            },
        });
        // The conditions are read on a thread of their own: a platform reading can spawn a program,
        // and nothing here waits on one.
        if conditions.is_none() {
            let reader = Arc::clone(&shared);
            let clock = clock.clone();
            std::thread::Builder::new()
                .name("describe-conditions".to_owned())
                .spawn(move || {
                    read_conditions_until_stopped(
                        &reader,
                        &clock,
                        &kr_describe::resource::platform::read_conditions,
                        CONDITIONS_EVERY,
                    );
                })
                .map_err(|error| {
                    ControllerError::registry(format!(
                        "the description host's reader of conditions could not start: {error}"
                    ))
                })?;
        }
        let thread = {
            let held = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("describe-host".to_owned())
                .spawn(move || {
                    Thread {
                        shared: held,
                        driver,
                        inbox,
                        privacy,
                        clock,
                        conditions,
                        last_event: BTreeMap::new(),
                        seen: BTreeMap::new(),
                        started_wall_ms,
                        abandon,
                        held: Held {
                            marker: files_held,
                            ..Held::default()
                        },
                    }
                    .run();
                })
                .map_err(|error| {
                    // The reader of conditions started first and must not outlive a host that did
                    // not start.
                    shared.running.store(false, Ordering::Release);
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

    /// Where the model's files are kept.
    pub(crate) fn models(&self) -> &Path {
        &self.shared.files.models
    }

    /// The profile whose files this host keeps, when it has selected one.
    pub(crate) fn profile(&self) -> Option<&ModelProfile> {
        self.shared.files.profile.as_ref()
    }

    /// The bytes free on the disk that holds `path`, when it can be said.
    pub(crate) fn free_space(&self, path: &Path) -> Option<u64> {
        match &self.shared.files.free_space {
            Some(held) => *held.lock().unwrap_or_else(PoisonError::into_inner),
            None => kr_describe::resource::platform::free_space(path),
        }
    }

    /// How long a fetch waits for the server's answer and then for each chunk of a body.
    pub(crate) fn stall(&self) -> Duration {
        self.shared
            .files
            .stall
            .as_ref()
            .and_then(|held| *held.lock().unwrap_or_else(PoisonError::into_inner))
            .unwrap_or(super::assets::STALL)
    }

    /// Tells the host how a fetch is going.
    pub(crate) fn progress(&self, progress: DownloadProgress) {
        self.post(Message::Download {
            progress,
            done: None,
        });
    }

    /// Tells the host how a fetch is going, and returns what completes once the host has taken it
    /// and published it.
    pub(crate) fn progress_and_wait(
        &self,
        progress: DownloadProgress,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (done, taken) = tokio::sync::oneshot::channel();
        self.post(Message::Download {
            progress,
            done: Some(done),
        });
        taken
    }

    /// Tells the host whether the model's files are held.
    pub(crate) fn assets_held(&self, held: bool) {
        self.post(Message::Assets { held });
    }

    /// Has the process check a file, and returns what completes with what it says.
    pub(crate) fn check(&self, request: CheckRequest) -> tokio::sync::oneshot::Receiver<Checked> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        self.post(Message::Check { request, reply });
        answer
    }

    /// Stops the check that is waiting or running.
    pub(crate) fn cancel_check(&self) {
        self.post(Message::CancelCheck);
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

    /// Hands the host the newest page of a session's facts, replacing one it has not read. `found`
    /// says the page is what the worker answered a new connection with at once.
    pub(crate) fn page(&self, session_id: SessionId, page: Box<DescriptionFactsPage>, found: bool) {
        {
            let mut slots = self
                .shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // Checked under the lock the exit and the purge clear the slots under: a page that
            // arrives for a host that has stopped is dropped, and never left for nobody to take.
            if !self.shared.running.load(Ordering::Acquire) {
                return;
            }
            // A reply with no facts says only that nothing is newer than what the link has read,
            // and the host applies none: it never takes the place of a page that has facts.
            if page.facts.0.is_none()
                && slots
                    .get(&session_id)
                    .is_some_and(|older| older.page.facts.0.is_some())
            {
                return;
            }
            let found = found || slots.get(&session_id).is_some_and(|older| older.found);
            slots.insert(session_id, Waiting { page, found });
        }
        self.shared.waker.wake();
    }

    /// Applies the owner's settings, which take effect at the host's next turn.
    pub(crate) fn settings(&self, enabled: Option<bool>, on_battery: Option<bool>) {
        self.post(Message::Settings {
            enabled,
            on_battery,
        });
    }

    /// Returns what completes once the host has taken everything posted to it before this call and
    /// published the turn that took it, so that an answer built after it shows what that turn
    /// found: the pause an owner's setting causes, and not the one from before it.
    pub(crate) fn turned(&self) -> tokio::sync::oneshot::Receiver<()> {
        let (done, taken) = tokio::sync::oneshot::channel();
        self.post(Message::Turned { done });
        taken
    }

    /// Waits up to `bound` for what [`Self::turned`] returns, and says whether the host answered,
    /// or ended and so will answer nothing; `false` says only that the bound passed first.
    pub(crate) async fn turned_within(&self, bound: Duration) -> bool {
        tokio::time::timeout(bound, self.turned()).await.is_ok()
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
            // Nothing will take what is waiting in the slots, and it is not left in memory.
            self.shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
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

/// What the host's thread leaves behind when it ends, by returning or by unwinding.
struct Exit(Arc<Shared>);

impl Drop for Exit {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
        self.0.purges_owed.store(0, Ordering::Release);
        self.0
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
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

    fn admit_dispatch(&self, generation: PrivacyGeneration, register: &mut dyn FnMut()) {
        if let Some(_admission) = self.privacy.admit_send(generation) {
            register();
        }
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
    /// What was last observed of each session's directory and program, and when.
    seen: BTreeMap<SessionId, Seen>,
    /// When this thread started, on the wall clock.
    started_wall_ms: u64,
    /// Whether the process is left running when this thread ends.
    abandon: bool,
    /// What it keeps of the model's files.
    held: Held,
}

impl Thread {
    fn run(mut self) {
        // Cleared however the thread ends, a panic included: a host that is gone owes privacy
        // mode nothing, holds nothing in its slots and says it is not running.
        let _exit = Exit(Arc::clone(&self.shared));
        while self.shared.running.load(Ordering::Acquire) {
            self.turn();
            self.rest();
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

    /// One turn: takes what arrived, drives the service, publishes what it reads, and then tells
    /// everyone who asked to be told that the turn is done.
    fn turn(&mut self) {
        let now = self.clock.now();
        self.take_messages(now);
        self.follow_privacy();
        self.take_pages(now);
        self.settle_sessions(now);
        let conditions = self.conditions();
        let reports = self.driver.turn(&conditions, now).unwrap_or_default();
        self.answer_checks(reports);
        self.offer_check(now);
        self.sync_marker();
        self.publish_snapshot(now);
        for done in std::mem::take(&mut self.held.acks) {
            let _ = done.send(());
        }
    }

    /// Ends a turn: sleeps until something wakes the thread or something is due, unless a message
    /// is waiting, and says how long it was ready to sleep.
    ///
    /// A message is posted and then its wake sent, and the turn reads the wakes when it asks the
    /// driver for what arrived, which is after it read the messages. A message posted between the
    /// two has its wake read by this turn and its text left for the next, and the next turn could
    /// wait as long as the thread's longest sleep ([`IDLE_WAIT`]). So the messages are read once
    /// more here, after everything this turn did, and when there were any the thread turns again
    /// at once. A message posted after this read has its wake still to come, and the sleep ends at
    /// it.
    fn rest(&mut self) -> Duration {
        let now = self.clock.now();
        let wait = if self.take_messages(now) {
            Duration::ZERO
        } else {
            self.next_wait(now)
        };
        self.driver.wait(wait);
        wait
    }

    fn conditions(&self) -> HostConditions {
        match &self.conditions {
            Some(held) => *held.lock().unwrap_or_else(PoisonError::into_inner),
            None => latest_conditions(&self.shared, self.clock.now().monotonic_ms()),
        }
    }

    /// Applies every message that has arrived, and says whether there were any.
    fn take_messages(&mut self, now: Reading) -> bool {
        let mut took = false;
        while let Ok(message) = self.inbox.try_recv() {
            took = true;
            match message {
                Message::Opened {
                    session_id,
                    epoch,
                    binding,
                } => {
                    self.driver
                        .service_mut()
                        .session_opened(session_id, epoch, binding);
                    // The service forgot the session's events; so does the host's cursor, or the
                    // events its worker still holds would be taken for ones it had seen.
                    self.last_event.remove(&session_id);
                    self.seen.remove(&session_id);
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
                    self.seen.remove(&session_id);
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
                Message::Turned { done } => {
                    // Told once the turn has published what it found, so the answer the caller
                    // builds next shows the pause what came before it causes.
                    self.held.acks.push(done);
                }
                Message::Purge { done } => {
                    let _ = self.driver.service_mut().forget_content();
                    self.shared
                        .slots
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clear();
                    self.last_event.clear();
                    self.seen.clear();
                    // Owed until it is done, and no longer.
                    let _ = self.shared.purges_owed.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |owed| Some(owed.saturating_sub(1)),
                    );
                    let _ = done.send(());
                }
                Message::Wake => {}
                Message::Download { progress, done } => {
                    self.driver.service_mut().note_download(progress);
                    // Told once the turn has published what it took, so the answer the caller
                    // builds next shows it.
                    self.held.acks.extend(done);
                }
                Message::Assets { held } => {
                    self.driver.service_mut().set_assets_held(held);
                }
                Message::Check { request, reply } => {
                    let id = self.shared.files.next_check.fetch_add(1, Ordering::AcqRel);
                    // One at a time: a check that was waiting is replaced, and told it was
                    // cancelled, as the fetch that asked for it has been replaced too.
                    if let Some((_, older)) = self.held.pending.take() {
                        let _ = older.send(cancelled_check());
                    }
                    self.held.pending = Some((
                        Check {
                            id,
                            profile_id: request.profile_id,
                            revision: request.revision,
                            file_name: request.file_name,
                            path: request.path,
                            deadline_ms: request.deadline_ms,
                        },
                        reply,
                    ));
                }
                Message::CancelCheck => {
                    if let Some((_, reply)) = self.held.pending.take() {
                        let _ = reply.send(cancelled_check());
                    }
                    if self.held.awaiting.is_some() {
                        let reports = self.driver.cancel_check(now).unwrap_or_default();
                        self.answer_checks(reports);
                    }
                }
                #[cfg(test)]
                Message::Fail => panic!("the host's thread fails, as a test asked"),
            }
        }
        took
    }

    /// Raises the fence of every session that does not hold one while privacy mode is published as
    /// on, at the generation it is on at, and cancels the job running for it. Privacy mode raises
    /// the fences itself once it is published; between its publication and that, a turn of this
    /// thread could dispatch a job, and this is what stops it: no job starts for a session after
    /// privacy mode is published, whichever of the two comes first. Read with no admission held.
    fn follow_privacy(&mut self) {
        let published = self.privacy.now();
        if !published.private {
            return;
        }
        for session_id in self.driver.service().live_session_ids() {
            let raised = self.driver.service().fence().generation(&session_id);
            if raised.is_some_and(|raised| raised.get() >= published.generation.get()) {
                continue;
            }
            self.shared
                .handles
                .fence
                .raise(session_id, published.generation);
            self.shared.handles.running.cancel(&session_id);
        }
    }

    /// Sends what the process said of the check the host was waiting on, when one ended.
    fn answer_checks(&mut self, reports: Vec<Report>) {
        for report in reports {
            if let Report::Checked { id, checked } = report
                && self
                    .held
                    .awaiting
                    .as_ref()
                    .is_some_and(|(awaited, _)| *awaited == id)
                && let Some((_, reply)) = self.held.awaiting.take()
            {
                let _ = reply.send(checked);
            }
        }
    }

    /// Hands the check that is waiting to the process once it can take one: a check is refused
    /// behind work, and tried again at the next turn, which the end of that work wakes.
    fn offer_check(&mut self, now: Reading) {
        if self.held.awaiting.is_some() {
            return;
        }
        let Some((check, reply)) = self.held.pending.take() else {
            return;
        };
        let id = check.id;
        match self.driver.verify(&check, now) {
            Ok(reports) => {
                let refused = reports.iter().any(|report| {
                    matches!(
                        report,
                        Report::Checked { id: refused, checked: Checked::Refused } if *refused == id
                    )
                });
                if refused {
                    self.held.pending = Some((check, reply));
                } else {
                    self.held.awaiting = Some((id, reply));
                    self.answer_checks(reports);
                }
            }
            // The store could not be written: the check is not made, and its asker is told so by
            // the reply ending unsent.
            Err(_) => drop(reply),
        }
    }

    /// Keeps the marker on disk as the service has the files: gone when they are not held.
    fn sync_marker(&mut self) {
        let held = self.driver.service().assets_held();
        if self.held.marker && !held {
            if let Some(profile) = &self.shared.files.profile {
                super::assets::clear_marker(&self.shared.files.models, profile);
            }
            self.held.marker = false;
        } else if held && !self.held.marker && self.shared.files.profile.is_some() {
            // Written by the fetch before it said so.
            self.held.marker = true;
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
        let live = self.driver.service().live_session_ids();
        for (session_id, waiting) in pages {
            if live.contains(&session_id) {
                self.apply_page(session_id, &waiting.page, waiting.found, now);
            } else if waiting.page.facts.0.is_some()
                && self
                    .shared
                    .known
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .contains(&session_id)
            {
                // The session is open and the message that says so has not been taken yet: the page
                // waits for it. Dropped here, the page would take with it the mark that the facts
                // it holds were kept from before, and the next page would carry the same facts as
                // seen now.
                self.wait_for_session(session_id, waiting);
            }
        }
    }

    /// Puts a page back in its session's slot until the session is taken, unless a newer page has
    /// come meanwhile, which keeps the mark of the one it replaces.
    fn wait_for_session(&mut self, session_id: SessionId, waiting: Waiting) {
        let mut slots = self
            .shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.shared.running.load(Ordering::Acquire) {
            return;
        }
        match slots.get_mut(&session_id) {
            // A newer page with facts replaces it and keeps its mark; one without facts says only
            // that nothing is newer, and the waiting page stays.
            Some(newer) if newer.page.facts.0.is_some() => newer.found |= waiting.found,
            Some(newer) => {
                let found = newer.found || waiting.found;
                *newer = Waiting {
                    page: waiting.page,
                    found,
                };
            }
            None => {
                slots.insert(session_id, waiting);
            }
        }
    }

    /// Applies a page that was not found on a new connection, for this crate's own tests.
    #[cfg(test)]
    fn apply(&mut self, session_id: SessionId, page: &DescriptionFactsPage, now: Reading) {
        self.apply_page(session_id, page, false, now);
    }

    /// Applies one page of a session's facts under privacy mode's admission at the generation it
    /// was captured under, or drops it when none admits it. `found` says it is what the worker
    /// answered a new connection with at once.
    fn apply_page(
        &mut self,
        session_id: SessionId,
        page: &DescriptionFactsPage,
        found: bool,
        now: Reading,
    ) {
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
        note_seen(
            self.seen.entry(session_id).or_default(),
            facts,
            generation,
            now.wall_ms().get(),
            found,
        );
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
            let freshness = freshness_of(service.freshness(&session_id, now));
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
            gated: service.publication_gated(),
            assets_held: service.assets_held(),
            read_at_ms: now.monotonic_ms(),
        };
        let snapshot = Snapshot {
            state: Some(state),
            paused,
            cadence_ms,
            sessions,
            figures,
            setup: Some(setup),
            started_wall_ms: self.started_wall_ms,
            seen: self.seen.clone(),
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

/// Records what a page of facts says of a session's directory and program, keeping the moment each
/// was first observed as it stands: a page that repeats what is held moves nothing, and one that
/// changes it, or that is of another privacy generation, starts its moment again.
///
/// The program is held only while its command runs. The worker keeps the program of the newest
/// command in its record when the command ends, and records how it ended beside it, so a record
/// with an ending is a program that is no longer in the foreground.
fn note_seen(
    seen: &mut Seen,
    facts: &kr_protocol::describe::DescriptionFacts,
    generation: PrivacyGeneration,
    at_ms: u64,
    found: bool,
) {
    let directory = facts
        .directory
        .0
        .as_ref()
        .map(|name| match facts.repository.0.as_ref() {
            Some(repository) => match repository.branch.0.as_deref() {
                Some(branch) if !branch.is_empty() => {
                    format!("{name} (repository {}, branch {branch})", repository.name)
                }
                _ => format!("{name} (repository {})", repository.name),
            },
            None => name.clone(),
        });
    let running = facts
        .application
        .0
        .clone()
        .filter(|_| facts.completion.0.is_none());
    for (held, text) in [
        (&mut seen.directory, directory),
        (&mut seen.application, running),
    ] {
        *held = match (held.take(), text) {
            (Some(was), Some(text)) if was.text == text && was.generation == generation => {
                Some(was)
            }
            (_, Some(text)) => Some(SeenText {
                text,
                at_ms,
                generation,
                inherited: found,
            }),
            (_, None) => None,
        };
    }
}

/// Puts one session's facts into the service as the signals and events they are.
///
/// The record is the whole of what the worker holds, so each fact is applied as it stands, and a
/// fact the worker no longer has is cleared here as well: a completion cleared when a command
/// starts and a thread cleared when it ends are changes, and nothing of either is left behind to
/// describe the session.
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
    let _ = service.observe(
        &session_id,
        ContextSignal::ForegroundApplication(facts.application.0.clone()),
        now,
    );
    let _ = service.observe(
        &session_id,
        ContextSignal::SelectedThread(facts.thread.0.clone()),
        now,
    );
    if let Some(intent) = facts.intent.0.clone() {
        let _ = service.observe(&session_id, ContextSignal::TaskIntent(intent), now);
    }
    // After the intent, which a new task clears the completion of: what the record says is the
    // completion is what stands.
    let _ = service.observe(
        &session_id,
        ContextSignal::Completion(facts.completion.0.map(|completion| match completion {
            DescriptionCompletion::Succeeded => kr_describe::context::Completion::Succeeded,
            DescriptionCompletion::Failed => kr_describe::context::Completion::Failed,
        })),
        now,
    );
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
                now,
            );
        }
        last_event.insert(session_id, cursor);
    }
}

/// What a check that was cancelled before the process had it says.
fn cancelled_check() -> Checked {
    Checked::Answered {
        result: VerifyResult::Cancelled,
        detail: None,
    }
}

/// Maps how current a description is onto the protocol's word for it: none when there is no
/// description to be current or the store could not say.
fn freshness_of(freshness: kr_describe::Result<Option<Freshness>>) -> DescriptionFreshness {
    match freshness {
        Ok(Some(Freshness::Current)) => DescriptionFreshness::Current,
        Ok(Some(Freshness::Delayed { .. })) => DescriptionFreshness::Delayed,
        Ok(Some(Freshness::Stale { .. })) => DescriptionFreshness::Stale,
        Ok(None) | Err(_) => DescriptionFreshness::None,
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

/// The newest reading of the host's own conditions, when it is less than
/// [`CONDITIONS_MAX_AGE_MS`] old at `now_ms`, and every signal unqualified when it is not or when
/// none has been read: which the policy treats as a pause.
fn latest_conditions(shared: &Shared, now_ms: u64) -> HostConditions {
    let taken = *shared
        .reading
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match taken {
        Some(taken) if now_ms.saturating_sub(taken.at_ms) < CONDITIONS_MAX_AGE_MS => {
            taken.conditions
        }
        Some(_) => unqualified("the host's conditions were last read over a minute ago"),
        None => unqualified("the host's conditions have not been read yet"),
    }
}

fn unqualified(why: &'static str) -> HostConditions {
    HostConditions {
        physical_memory_bytes: Signal::Unqualified { why },
        available_memory_bytes: Signal::Unqualified { why },
        power: Signal::Unqualified { why },
        thermal: Signal::Unqualified { why },
    }
}

/// Reads the host's conditions with `read` every [`CONDITIONS_EVERY`] until the host stops, and
/// stamps each reading with the time it was taken.
fn read_conditions_until_stopped(
    shared: &Shared,
    clock: &Clock,
    read: &dyn Fn() -> HostConditions,
    every: Duration,
) {
    while shared.running.load(Ordering::Acquire) {
        // Stamped before the reading is taken, so it is never taken for newer than it is.
        let at_ms = clock.now().monotonic_ms();
        let conditions = read();
        *shared
            .reading
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Taken { at_ms, conditions });
        shared.waker.wake();
        let until = std::time::Instant::now() + every;
        while shared.running.load(Ordering::Acquire) && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(250).min(every));
        }
    }
}

/// Where the host keeps what the process downloads: `<state>/models`.
pub(crate) fn models_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("models")
}

#[cfg(test)]
pub(crate) mod tests {
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
                processor: kr_describe::processor::Features::running(),
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
            reading: Mutex::new(None),
            files: Files::default(),
        });
        let mut thread = Thread {
            shared,
            driver,
            inbox,
            privacy,
            clock: Clock::skewed(Arc::new(AtomicU64::new(0))),
            conditions: None,
            last_event: BTreeMap::new(),
            seen: BTreeMap::new(),
            started_wall_ms: 0,
            abandon: false,
            held: Held::default(),
        };
        thread.driver.service_mut().session_opened(
            session(),
            SessionEpoch::V1,
            ContextBinding::new("display-1/epoch-1"),
        );
        (directory, thread)
    }

    /// The handle a daemon holds on the host thread `host`, which a test turns by hand.
    fn handle_of(host: &Thread) -> DescribeHost {
        DescribeHost {
            shared: Arc::clone(&host.shared),
            thread: Mutex::new(None),
        }
    }

    /// A host whose thread a test turns by hand, for the tests of what holds a handle on it. It
    /// holds the one handle, which ends the host when the last reference to it goes.
    pub(crate) struct ByHand {
        _directory: tempfile::TempDir,
        thread: Thread,
        handle: Arc<DescribeHost>,
    }

    impl ByHand {
        /// A host over a service that is never asked to start a process, with privacy mode off.
        pub(crate) fn new() -> Self {
            let (_directory, thread) = thread(Published::default());
            let handle = Arc::new(handle_of(&thread));
            Self {
                _directory,
                thread,
                handle,
            }
        }

        /// The handle a daemon holds on it.
        pub(crate) fn handle(&self) -> Arc<DescribeHost> {
            Arc::clone(&self.handle)
        }

        /// One turn of its thread.
        pub(crate) fn turn(&mut self) {
            self.thread.turn();
        }

        /// The session its thread tracks.
        pub(crate) fn session_id(&self) -> SessionId {
            session()
        }

        /// Hands the host a page that names `program` as the foreground, as the worker answers a
        /// new connection (`found`) or as it answers a request that was held, and turns once.
        pub(crate) fn observes(&mut self, program: &str, found: bool) {
            let page = page_with(0, 2, |facts| {
                facts.application = Nullable::some(program.to_owned());
            });
            self.handle.page(session(), Box::new(page), found);
            self.turn();
        }
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

    /// A page of one session's facts, captured under `generation`, as `edit` leaves it.
    fn page_with(
        generation: u64,
        revision: u64,
        edit: impl FnOnce(&mut DescriptionFacts),
    ) -> DescriptionFactsPage {
        let mut page = page(generation);
        let facts = page.facts.0.as_mut().expect("a page with facts");
        facts.revision = U64::new(revision);
        edit(facts);
        page
    }

    /// Takes a session's waiting changes into a queued job, once the debounce has passed, and says
    /// whether it made one.
    fn settled(thread: &mut Thread, at_ms: u64) -> bool {
        thread
            .driver
            .service_mut()
            .settle(
                &session(),
                Priority::Ordinary,
                Reading::new(at_ms, 1_700_000_000_000 + at_ms),
            )
            .is_some()
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

    /// What the host observed of a session's directory and program carries the moment it first
    /// observed each as it stands: a page that repeats what is held keeps it, a change starts the
    /// moment again for what changed and for nothing else, and the program is held only while its
    /// command runs. What a page found on a new connection held is marked as found and not seen to
    /// change, since a worker answers a new connection with the facts it kept from before. The
    /// control is the first page, which sets both.
    #[test]
    fn what_was_observed_keeps_the_moment_it_was_first_observed_as_it_stands() {
        let (_directory, mut host) = thread(state(0, false));
        let seen = |host: &Thread| host.seen.get(&session()).cloned().expect("a record");
        host.apply_page(
            session(),
            &page(0),
            true,
            Reading::new(1_000, 1_700_000_001_000),
        );
        let first = seen(&host);
        assert_eq!(
            first.directory.as_ref().map(|d| (d.at_ms, d.inherited)),
            Some((1_700_000_001_000, true))
        );
        assert_eq!(
            first.application.as_ref().map(|a| (a.at_ms, a.inherited)),
            Some((1_700_000_001_000, true))
        );

        // The same facts again, with another revision: nothing moves.
        host.apply(
            session(),
            &page_with(0, 2, |_| {}),
            Reading::new(2_000, 1_700_000_002_000),
        );
        assert_eq!(seen(&host), first);

        // A program that changes moves its moment, and is seen to change; the directory's stays.
        host.apply(
            session(),
            &page_with(0, 3, |facts| {
                facts.application = Nullable::some("make".to_owned());
            }),
            Reading::new(3_000, 1_700_000_003_000),
        );
        let changed = seen(&host);
        assert_eq!(changed.directory, first.directory);
        let application = changed.application.expect("a program");
        assert_eq!(
            (
                application.text.as_str(),
                application.at_ms,
                application.inherited
            ),
            ("make", 1_700_000_003_000, false)
        );

        // A command that has ended is no longer held, and the same program run again is a new
        // observation with its own moment.
        host.apply(
            session(),
            &page_with(0, 4, |facts| {
                facts.application = Nullable::some("make".to_owned());
                facts.completion = Nullable::some(DescriptionCompletion::Succeeded);
            }),
            Reading::new(4_000, 1_700_000_004_000),
        );
        assert_eq!(seen(&host).application, None);
        assert_eq!(seen(&host).directory, first.directory);
        host.apply(
            session(),
            &page_with(0, 5, |facts| {
                facts.application = Nullable::some("make".to_owned());
            }),
            Reading::new(5_000, 1_700_000_005_000),
        );
        assert_eq!(
            seen(&host).application.map(|held| held.at_ms),
            Some(1_700_000_005_000)
        );
    }

    /// A page that reaches the host before the message that opens its session is taken waits for
    /// the session, and keeps what it found: a page the host dropped for want of the session would
    /// take with it the mark that the facts it held were kept from before, and the next page would
    /// carry the same facts as seen at that moment. A page for a session that is not open is
    /// dropped, as it was.
    #[test]
    fn a_page_that_comes_before_its_session_is_opened_waits_and_keeps_its_mark() {
        let now = Reading::new(1_000, 1_700_000_001_000);
        let (_directory, mut host) = thread(state(0, false));
        let handle = handle_of(&host);
        let other = SessionId::new(Uuid::from_bytes([8; 16]));
        let stranger = SessionId::new(Uuid::from_bytes([9; 16]));
        let slot = |host: &Thread, session_id: &SessionId| {
            host.shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(session_id)
        };

        // The session is open, and the message that says so is not taken yet.
        handle.session_opened(
            other,
            SessionEpoch::V1,
            ContextBinding::new("display-2/epoch-1"),
        );
        let mut found = page(0);
        found.session_id = other;
        handle.page(other, Box::new(found), true);
        let mut unknown = page(0);
        unknown.session_id = stranger;
        handle.page(stranger, Box::new(unknown), true);
        host.take_pages(now);
        assert!(slot(&host, &other), "the page waits for its session");
        assert!(
            !slot(&host, &stranger),
            "a page for no open session is dropped"
        );

        // A reply with no facts arrives while it waits, and the session is taken: the page is
        // applied, with its mark.
        let mut empty = page(0);
        empty.session_id = other;
        empty.facts = Nullable::null();
        handle.page(other, Box::new(empty), false);
        host.take_messages(now);
        host.take_pages(now);
        let seen = host
            .seen
            .get(&other)
            .cloned()
            .expect("the session's record");
        assert_eq!(seen.directory.map(|held| held.inherited), Some(true));
    }

    /// A page put back to wait for its session is not replaced by a reply with no facts that came
    /// while the host held it, and a newer page with facts replaces it and keeps its mark: the
    /// race this decides is between the host taking the slots and putting a page back.
    #[test]
    fn a_page_put_back_to_wait_is_replaced_only_by_a_newer_page_with_facts() {
        let (_directory, mut host) = thread(state(0, false));
        let held = |host: &Thread| {
            let slots = host
                .shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            slots
                .get(&session())
                .map(|waiting| (waiting.page.facts.0.is_some(), waiting.found))
        };
        let mut empty = page(0);
        empty.facts = Nullable::null();
        host.shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                session(),
                Waiting {
                    page: Box::new(empty),
                    found: false,
                },
            );
        host.wait_for_session(
            session(),
            Waiting {
                page: Box::new(page(0)),
                found: true,
            },
        );
        assert_eq!(held(&host), Some((true, true)), "the page with facts stays");

        host.wait_for_session(
            session(),
            Waiting {
                page: Box::new(page_with(0, 2, |_| {})),
                found: false,
            },
        );
        assert_eq!(held(&host), Some((true, true)), "and keeps its mark");
    }

    /// A reply that carries no facts never replaces a page that does, because it says only that
    /// nothing is newer than what the link has read: a worker answers a held request with one when
    /// its wait ends, and a page with facts that was not read yet and was replaced by it would take
    /// with it the mark that the facts were kept from before. The control is a reply with facts,
    /// which does replace the page and keeps its mark.
    #[test]
    fn a_reply_without_facts_does_not_replace_a_page_with_facts() {
        let now = Reading::new(1_000, 1_700_000_001_000);
        let (_directory, mut host) = thread(state(0, false));
        let handle = handle_of(&host);
        let mut empty = page(0);
        empty.facts = Nullable::null();

        handle.page(session(), Box::new(page(0)), true);
        handle.page(session(), Box::new(empty), false);
        host.take_pages(now);
        let seen = host
            .seen
            .get(&session())
            .cloned()
            .expect("the facts were applied");
        assert_eq!(seen.directory.map(|held| held.inherited), Some(true));

        let (_directory, mut host) = thread(state(0, false));
        let handle = handle_of(&host);
        handle.page(session(), Box::new(page(0)), true);
        handle.page(
            session(),
            Box::new(page_with(0, 2, |facts| {
                facts.application = Nullable::some("make".to_owned());
            })),
            false,
        );
        host.take_pages(now);
        let seen = host
            .seen
            .get(&session())
            .cloned()
            .expect("the facts were applied");
        assert_eq!(
            seen.application.map(|held| (held.text, held.inherited)),
            Some(("make".to_owned(), true)),
            "the newer facts replace the older, and keep the mark"
        );
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

    /// A page is the whole of what the worker holds, so a fact it no longer has is cleared here
    /// too: a completion cleared when a command starts and a thread cleared when it ends are
    /// changes, and a record that says the same again is not. Nothing of a fact that is gone is
    /// left to describe the session.
    #[test]
    fn a_page_is_applied_whole_and_a_fact_the_worker_no_longer_has_is_cleared() {
        let now = Reading::new(1_000, 1_700_000_000_000);
        let (_directory, mut host) = thread(state(0, false));
        host.apply(
            session(),
            &page_with(0, 1, |facts| {
                facts.completion = Nullable::some(DescriptionCompletion::Succeeded);
                facts.thread = Nullable::some("review".to_owned());
            }),
            now,
        );
        assert!(settled(&mut host, 10_000), "the first record makes a job");
        assert!(!pending(&host), "and leaves nothing waiting");

        // The same facts again, under a newer revision: nothing changed.
        host.apply(
            session(),
            &page_with(0, 2, |facts| {
                facts.completion = Nullable::some(DescriptionCompletion::Succeeded);
                facts.thread = Nullable::some("review".to_owned());
            }),
            Reading::new(11_000, 1_700_000_011_000),
        );
        assert!(!pending(&host), "the control: a record that says the same");

        // A command started: the completion is gone. The agent's thread ended: so is the thread.
        host.apply(
            session(),
            &page_with(0, 3, |facts| {
                facts.thread = Nullable::some("review".to_owned());
            }),
            Reading::new(12_000, 1_700_000_012_000),
        );
        assert!(pending(&host), "a cleared completion is a change");
        assert!(settled(&mut host, 20_000));
        host.apply(
            session(),
            &page_with(0, 4, |_| {}),
            Reading::new(21_000, 1_700_000_021_000),
        );
        assert!(pending(&host), "a cleared thread is a change");
    }

    /// A new event is a change of its own: a command with the same program in the same directory
    /// still starts the debounce, and the same event seen again does not.
    #[test]
    fn a_new_event_alone_starts_the_debounce_and_the_same_event_again_does_not() {
        let event = |cursor: u64| kr_protocol::describe::DescriptionEvent {
            cursor: U64::new(cursor),
            kind: DescriptionEventKind::CommandAccepted,
            summary: "cargo".to_owned(),
        };
        let (_directory, mut host) = thread(state(0, false));
        host.apply(
            session(),
            &page_with(0, 1, |facts| facts.events = vec![event(0)]),
            Reading::new(1_000, 1_700_000_001_000),
        );
        assert!(settled(&mut host, 10_000));
        assert!(!pending(&host));

        host.apply(
            session(),
            &page_with(0, 2, |facts| facts.events = vec![event(0)]),
            Reading::new(11_000, 1_700_000_011_000),
        );
        assert!(!pending(&host), "the control: an event taken before");

        host.apply(
            session(),
            &page_with(0, 3, |facts| facts.events = vec![event(1), event(0)]),
            Reading::new(12_000, 1_700_000_012_000),
        );
        assert!(pending(&host), "an event that is new is a change");
    }

    /// Each way a description can stand is the word the client is shown: current, delayed while a
    /// newer job waits at the same revision, stale when the session has moved on, and none when
    /// there is no description or the store could not say.
    #[test]
    fn each_standing_of_a_description_is_the_word_a_client_is_shown() {
        use kr_describe::context::ContextRevision;

        assert_eq!(
            freshness_of(Ok(Some(Freshness::Current))),
            DescriptionFreshness::Current
        );
        assert_eq!(
            freshness_of(Ok(Some(Freshness::Delayed {
                queued_age_ms: 70_000
            }))),
            DescriptionFreshness::Delayed
        );
        assert_eq!(
            freshness_of(Ok(Some(Freshness::Stale {
                produced_at: ContextRevision::new(1),
                current: ContextRevision::new(2),
            }))),
            DescriptionFreshness::Stale
        );
        assert_eq!(freshness_of(Ok(None)), DescriptionFreshness::None);
        assert_eq!(
            freshness_of(Err(kr_describe::DescribeError::Store {
                detail: "the store is closed".to_owned()
            })),
            DescriptionFreshness::None
        );
    }

    /// A session that holds no fence when privacy mode is published as on is fenced at the host's
    /// next turn, at the generation it is on at, so a job cannot start in the moment between the
    /// publication and the fences privacy mode raises itself. A session already fenced at that
    /// generation or a later one is left as it is, and nothing is fenced while privacy mode is
    /// off.
    #[test]
    fn a_turn_fences_every_session_that_holds_no_fence_while_privacy_mode_is_published_as_on() {
        let (_directory, mut host) = thread(state(3, true));
        assert!(!host.shared.handles.fence.is_fenced(&session()));
        host.follow_privacy();
        assert_eq!(
            host.shared.handles.fence.generation(&session()),
            Some(PrivacyGeneration::new(3))
        );

        // Raised at a later generation already: left as it is.
        let (_directory, mut later) = thread(state(3, true));
        later
            .shared
            .handles
            .fence
            .raise(session(), PrivacyGeneration::new(5));
        later.follow_privacy();
        assert_eq!(
            later.shared.handles.fence.generation(&session()),
            Some(PrivacyGeneration::new(5))
        );

        // The control: privacy mode off.
        let (_directory, mut off) = thread(state(3, false));
        off.follow_privacy();
        assert!(!off.shared.handles.fence.is_fenced(&session()));
    }

    /// A message posted while a turn is under way, whose wake that turn's own look at what arrived
    /// then took, is read before the thread sleeps, so a fetch's check is offered at once and not
    /// when the longest sleep has passed. The control is the setting before the message, which is
    /// still on.
    #[test]
    fn a_message_whose_wake_a_turn_already_took_is_read_before_the_thread_sleeps() {
        let (_directory, mut host) = thread(state(0, false));
        let now = host.clock.now();
        host.take_messages(now);
        assert!(
            host.driver.service().setup_state().enabled,
            "on to begin with"
        );

        host.shared
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(Message::Settings {
                enabled: Some(false),
                on_battery: None,
            })
            .expect("the message is posted");
        host.shared.waker.wake();
        host.driver
            .turn(&host.conditions(), now)
            .expect("the turn runs");

        assert_eq!(
            host.rest(),
            Duration::ZERO,
            "the thread turns again at once, with no sleep"
        );
        assert!(
            !host.driver.service().setup_state().enabled,
            "the message was read before the thread slept"
        );
    }

    /// What is posted to the host is acknowledged by the turn that takes it, and that turn's
    /// snapshot shows the pause it causes: an answer built when the acknowledgement arrives is
    /// not the one from before the change. The control is the snapshot before the change, which
    /// shows no pause.
    #[test]
    fn a_settings_change_is_acknowledged_by_the_turn_that_shows_its_pause() {
        use kr_describe::budget::GIB;
        use kr_describe::resource::{PowerSource, ThermalState};

        let (_directory, mut host) = thread(state(0, false));
        host.conditions = Some(Arc::new(Mutex::new(HostConditions::measured(
            16 * GIB,
            12 * GIB,
            PowerSource::Mains,
            ThermalState::Nominal,
        ))));
        let handle = handle_of(&host);
        handle.assets_held(true);
        host.turn();
        assert!(handle.snapshot().setup.is_some_and(|setup| setup.offered));
        assert_eq!(
            handle.snapshot().paused,
            None,
            "nothing pauses it to begin with"
        );

        handle.settings(Some(false), None);
        let mut acknowledged = handle.turned();
        assert!(
            acknowledged.try_recv().is_err(),
            "not acknowledged before the host has turned"
        );
        host.turn();
        assert!(
            acknowledged.try_recv().is_ok(),
            "acknowledged by the turn that took the change"
        );
        assert_eq!(handle.snapshot().paused, Some(DescriptionPause::Disabled));
    }

    /// A host that has not turned when the bound passes is not confirmed, and one that turns inside
    /// it is. The control is the host that turns.
    #[tokio::test]
    async fn a_host_that_does_not_turn_inside_the_bound_is_not_confirmed() {
        let (_directory, mut host) = thread(state(0, false));
        let handle = handle_of(&host);
        assert!(
            !handle.turned_within(Duration::from_millis(10)).await,
            "no turn came inside the bound"
        );
        let (confirmed, ()) = tokio::join!(handle.turned_within(Duration::from_secs(60)), async {
            host.turn();
        });
        assert!(confirmed, "a turn came");
    }

    /// A page that arrives for a host that has stopped is dropped, where a page for one that runs
    /// is kept: nothing is left in the slots for a thread that is not there to take it.
    #[test]
    fn a_page_for_a_host_that_has_stopped_is_dropped() {
        for running in [true, false] {
            let (_directory, host) = thread(state(0, false));
            host.shared.running.store(running, Ordering::Release);
            let handle = DescribeHost {
                shared: Arc::clone(&host.shared),
                thread: Mutex::new(None),
            };
            handle.page(session(), Box::new(page(0)), false);
            let held = host
                .shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len();
            assert_eq!(held, usize::from(running), "running: {running}");
        }
    }

    /// A job is registered as in flight only while a send at its session's generation is admitted:
    /// while privacy mode is off at that generation, and not while it is on or when the generation
    /// in force is another. The registration is what a change of privacy mode finds to cancel, so
    /// a job that is not registered is never sent.
    #[test]
    fn a_dispatch_registers_only_while_its_generation_is_admitted() {
        let registered = |state: Published, generation: u64| {
            let gate = Admission {
                privacy: PrivacyState::at(state),
            };
            let mut ran = false;
            gate.admit_dispatch(PrivacyGeneration::new(generation), &mut || {
                ran = true;
            });
            ran
        };
        assert!(registered(state(3, false), 3));
        assert!(!registered(state(3, true), 3), "privacy mode is on");
        assert!(!registered(state(4, false), 3), "another generation");
    }

    /// A reading of the host's conditions serves while it is under a minute old and says nothing
    /// after: a reader that stalls after a good reading leaves every signal unqualified once the
    /// reading is old, where the policy pauses, and does not leave the last answer in force. The
    /// control is the same reading, a moment after it was taken.
    #[test]
    fn a_reading_over_a_minute_old_is_not_used_and_a_reader_that_stalls_leaves_none_in_force() {
        use kr_describe::budget::GIB;
        use kr_describe::resource::{PowerSource, ThermalState};

        let (_directory, host) = thread(state(0, false));
        let started = std::sync::atomic::AtomicUsize::new(0);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let held = Mutex::new(held);
        let roomy = || {
            HostConditions::measured(
                16 * GIB,
                12 * GIB,
                PowerSource::Mains,
                ThermalState::Nominal,
            )
        };
        /// Stops the reader when the test ends, by returning or by failing, so the scope can end.
        struct Stop<'a>(&'a Shared, std::sync::mpsc::Sender<()>);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.running.store(false, Ordering::Release);
                let _ = self.1.send(());
            }
        }
        std::thread::scope(|scope| {
            let _stop = Stop(&host.shared, release);
            scope.spawn(|| {
                read_conditions_until_stopped(
                    &host.shared,
                    &host.clock,
                    &|| {
                        // The first reading is good; the next one stalls until it is released.
                        if started.fetch_add(1, Ordering::AcqRel) > 0 {
                            let _ = held.lock().unwrap_or_else(PoisonError::into_inner).recv();
                        }
                        roomy()
                    },
                    Duration::from_millis(1),
                );
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while started.load(Ordering::Acquire) < 2 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "waited for the reader to begin the reading that stalls"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert_eq!(host.conditions(), roomy(), "just taken, so it is used");

            host.clock.skew_ms.fetch_add(61_000, Ordering::AcqRel);
            let old = host.conditions();
            assert_ne!(old, roomy(), "over a minute old, so it is not used");
            assert!(
                matches!(old.power, Signal::Unqualified { .. })
                    && matches!(old.available_memory_bytes, Signal::Unqualified { .. }),
                "every signal is unqualified: {old:?}"
            );
        });
    }

    /// A reading is as old as the moment it was begun at: one that took over a minute to take is
    /// not used, though it was stored a moment ago.
    #[test]
    fn a_reading_that_took_over_a_minute_to_take_is_as_old_as_when_it_began() {
        use kr_describe::budget::GIB;
        use kr_describe::resource::{PowerSource, ThermalState};

        let (_directory, host) = thread(state(0, false));
        let roomy = HostConditions::measured(
            16 * GIB,
            12 * GIB,
            PowerSource::Mains,
            ThermalState::Nominal,
        );
        read_conditions_until_stopped(
            &host.shared,
            &host.clock,
            &|| {
                host.clock.skew_ms.fetch_add(61_000, Ordering::AcqRel);
                host.shared.running.store(false, Ordering::Release);
                roomy
            },
            Duration::from_millis(1),
        );
        assert_ne!(host.conditions(), roomy, "the reading is over a minute old");
    }

    /// A purge the host's thread does not answer within its bound is unavailable, and stays owed
    /// until the thread has made it, which it does when it turns; one it answers is done and owes
    /// nothing; and a host whose thread is gone owes none, so privacy mode is never kept waiting
    /// for a purge nobody will make.
    #[test]
    fn a_purge_is_owed_until_the_host_has_made_it_and_a_host_that_is_gone_owes_nothing() {
        let (_directory, host) = thread(state(0, false));
        let handle = handle_of(&host);
        assert!(
            handle.purge().is_err(),
            "nobody is making the purge, so it is not done in time"
        );
        assert_eq!(handle.outstanding(), 1, "and it is still owed");

        // The control: the same purge, with the host's thread turning.
        let now = Reading::new(1_000, 1_700_000_000_000);
        let mut host = host;
        std::thread::scope(|scope| {
            let purging = scope.spawn(|| handle.purge());
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while handle.outstanding() < 2 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "waited for the second purge to be posted"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            host.take_messages(now);
            assert_eq!(
                purging.join().expect("the purge returns"),
                Ok(()),
                "made, so done"
            );
        });
        assert_eq!(
            handle.outstanding(),
            0,
            "the thread made the late purge as well, and nothing is owed"
        );

        handle.shared.running.store(false, Ordering::Release);
        assert_eq!(handle.purge(), Ok(()), "a host that is gone owes nothing");
        assert_eq!(handle.outstanding(), 0);
    }

    /// A page waiting in its slot when privacy mode is enabled is never applied: the purge the
    /// enabling asks for empties the slots as well as the queue. The control is a page left alone,
    /// which the host's next turn takes.
    #[test]
    fn a_page_waiting_in_its_slot_is_forgotten_by_the_purge_and_one_left_alone_is_taken() {
        let now = Reading::new(1_000, 1_700_000_000_000);
        for purged in [false, true] {
            let (_directory, mut host) = thread(state(0, false));
            let handle = DescribeHost {
                shared: Arc::clone(&host.shared),
                thread: Mutex::new(None),
            };
            handle.page(session(), Box::new(page(0)), false);
            if purged {
                std::thread::scope(|scope| {
                    let purging = scope.spawn(|| handle.purge());
                    let deadline = std::time::Instant::now() + Duration::from_secs(30);
                    while handle.outstanding() == 0 {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "waited for the purge to be posted"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    host.take_messages(now);
                    purging
                        .join()
                        .expect("the purge returns")
                        .expect("the host made it");
                });
            }
            host.take_pages(now);
            assert_eq!(
                pending(&host),
                !purged,
                "a page is taken unless the purge emptied its slot (purged: {purged})"
            );
        }
    }

    /// What the host's thread leaves behind is cleared when it ends by unwinding as well as by
    /// returning: a host whose thread failed is not running, owes privacy mode no purge and holds
    /// nothing in its slots.
    #[test]
    fn a_host_thread_that_panics_is_not_left_running_or_owing_a_purge() {
        let (_directory, host) = thread(state(0, false));
        host.shared.purges_owed.store(3, Ordering::Release);
        let shared = Arc::clone(&host.shared);
        // Kept to the end: dropping a handle stops its host.
        let handle = DescribeHost {
            shared: Arc::clone(&shared),
            thread: Mutex::new(None),
        };
        handle.page(session(), Box::new(page(0)), false);
        shared
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(Message::Fail)
            .expect("the host is listening");
        let ended = std::thread::spawn(move || host.run()).join();
        assert!(ended.is_err(), "the thread panicked");
        assert!(!shared.running.load(Ordering::Acquire));
        assert_eq!(shared.purges_owed.load(Ordering::Acquire), 0);
        assert!(
            shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty(),
            "nothing is left in the slots"
        );
        drop(handle);
    }

    /// A host that has stopped forgets the pages waiting for it when it is asked to purge, and
    /// owes nothing.
    #[test]
    fn a_purge_of_a_host_that_has_stopped_empties_its_slots() {
        let (_directory, host) = thread(state(0, false));
        let handle = handle_of(&host);
        handle.page(session(), Box::new(page(0)), false);
        handle.shared.running.store(false, Ordering::Release);
        assert_eq!(handle.purge(), Ok(()));
        assert!(
            handle
                .shared
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
    }

    /// A session opened again starts its events from nothing: the host's cursor of what it took is
    /// forgotten with the service's own, and the events its worker still holds are taken again.
    #[test]
    fn a_session_opened_again_takes_the_events_its_worker_still_holds() {
        let now = Reading::new(1_000, 1_700_000_000_000);
        let (_directory, mut host) = thread(state(0, false));
        let page_of = |revision: u64| {
            page_with(0, revision, |facts| {
                facts.events = vec![kr_protocol::describe::DescriptionEvent {
                    cursor: U64::new(0),
                    kind: DescriptionEventKind::CommandAccepted,
                    summary: "cargo".to_owned(),
                }];
            })
        };
        host.apply(session(), &page_of(1), now);
        assert_eq!(host.last_event.get(&session()), Some(&0));
        host.shared
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(Message::Opened {
                session_id: session(),
                epoch: SessionEpoch::V1,
                binding: ContextBinding::new("display-1/epoch-1"),
            })
            .expect("the host is listening");
        host.take_messages(now);
        assert_eq!(host.last_event.get(&session()), None, "forgotten with it");
        host.apply(session(), &page_of(2), now);
        assert_eq!(host.last_event.get(&session()), Some(&0), "taken again");
    }

    /// A session opened while privacy mode is on is fenced from the start at the generation in
    /// force, so nothing of it is captured or described; one opened while it is off is not. The
    /// control is the second.
    #[test]
    fn a_session_opened_while_privacy_mode_is_on_is_fenced_from_the_start() {
        let now = Reading::new(1_000, 1_700_000_000_000);
        let other = SessionId::new(Uuid::from_bytes([8; 16]));
        for (private, fenced) in [(true, true), (false, false)] {
            let (_directory, mut host) = thread(state(4, private));
            host.shared
                .inbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(Message::Opened {
                    session_id: other,
                    epoch: SessionEpoch::V1,
                    binding: ContextBinding::new("display-2/epoch-1"),
                })
                .expect("the host is listening");
            host.take_messages(now);
            assert_eq!(host.shared.handles.fence.is_fenced(&other), fenced);
            if fenced {
                assert_eq!(
                    host.shared.handles.fence.generation(&other),
                    Some(PrivacyGeneration::new(4))
                );
            }
        }
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
