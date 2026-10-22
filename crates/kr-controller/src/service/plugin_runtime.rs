//! The plugin runtime: one `kr-plugin-host` process for each protocol and environment, started when
//! a worker first asks for it.
//!
//! The daemon does not start the runtime when it starts, and it does not start it for an idle
//! session. A worker whose binding holds a package that ships a component sends
//! [`PluginRuntimeWanted`] on the rendezvous endpoint, and this is what answers it. The runtime is
//! started through the same supervisor a worker is started through, as a job of its own outside
//! this daemon's kill tree, so a daemon that exits, is upgraded or crashes leaves it running; the
//! workers keep their connections to it, because they talk to it directly and this daemon is not
//! in that path.
//!
//! | State | Meaning | Leaves it |
//! | --- | --- | --- |
//! | idle | this daemon knows of no runtime | a request: it adopts the runtime a previous daemon started, or starts one |
//! | starting | one attempt is under way and every request waits for it | the attempt ends: running or failed |
//! | running | a runtime this daemon started or adopted | the kernel says its process has ended: idle |
//! | failed | the last attempt, or the last look at a silent runtime, failed | [`FAILURE_MEMORY`] passes: idle |
//!
//! # One runtime for each protocol
//!
//! A plugin host speaks one protocol and has an endpoint and a descriptor of its own
//! ([`HostProtocol`]), so the hosts of two protocols run side by side. This daemon holds one
//! [`PluginRuntime`] for the protocol of its own release and one for each protocol a retained
//! level recorded ([`PluginRuntimes`]), and answers a worker's request with the one of the level
//! the worker is at. The holder of a retained protocol adopts a host of that protocol that runs,
//! which a daemon of the release before started and which outlived the update, and otherwise
//! starts the `kr-plugin-host` of the release the asking worker runs, from the release store this
//! daemon runs from ([`ReleasePrograms`]). Where the host keeps no store, or the release is not in
//! it, nothing is started and the answer is that the runtime cannot be reached, with the reason.
//! A rich binding of such a worker is unavailable; its terminal and everything else go on.
//!
//! # Starting is bounded
//!
//!
//! At most [`START_ATTEMPTS`] runtimes are started in [`START_WINDOW`]. A runtime that ends as soon
//! as it is started would otherwise be started again by every request, so past the bound requests
//! are answered that the runtime cannot be reached, with how long until the window next admits a
//! start. The worker asks again no sooner than it is told. A runtime that is adopted, or that is
//! started after a long life, uses almost none of the allowance.
//!
//! # What a silent runtime costs
//!
//! A runtime a previous daemon published, whose process is running and which does not answer a
//! challenge, is not started over: the new one could not bind the endpoint the old one holds. The
//! request is answered that it cannot be reached, and the process is left alone, because nothing
//! in this daemon stops a process by its identity. It ends by itself if it never served; one that
//! served and then stopped answering stays until it is ended.
//!
//! The challenge is made when a runtime is looked for, and not at each request. A runtime this
//! daemon holds as running is answered running whenever its process is, and a worker that cannot
//! reach it says so itself, in its report of the binding.
//!
//! A runtime of another release that speaks the protocol and answers is kept whatever started it.
//! A descriptor whose content this build refuses (another protocol, another environment, not a
//! descriptor) is taken away, and a runtime still behind it holds its endpoint, so the new one
//! cannot report itself and the start fails after the wait the launcher gives it. A descriptor of
//! another protocol is never met, because each protocol publishes in a file of its own. A
//! descriptor that cannot be read at all, a link or a file another account could write, is left in
//! place, and the answer is that the runtime cannot be reached.
//!
//! # Which requests are answered
//!
//! Only a request from the process this daemon recorded for the session, as the kernel names that
//! process now. Starting the runtime gives a requester no authority over anything, but it spends
//! the start allowance, so another process of the same user does not get to spend it.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::peer::PeerIdentity;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::launcher::{
    self, HostJobRetirement, HostLaunchPlan, HostStartOutcome, HostSupervisor, LaunchError,
};
use kr_plugin_service::protocol::HostProtocol;
use kr_plugin_service::retained_host;
use kr_protocol::admission::{PluginRuntimeState, PluginRuntimeUnavailable, PluginRuntimeWanted};
use kr_protocol::ids::SessionId;
use kr_protocol::limits::MAX_REPORT_DETAIL_BYTES;
use kr_protocol::retained::Level;
use kr_protocol::scalars::U64;
use kr_protocol::update::{CompatibilityLevel, ReleaseName};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::supervision::{
    JobRetirement, LaunchOutcome, ServiceLaunch, WorkerSupervisor, retire_service_job,
};

use super::Controller;

/// How many runtimes are started in [`START_WINDOW`].
pub const START_ATTEMPTS: usize = 5;

/// The window [`START_ATTEMPTS`] is counted in.
pub const START_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How long a failed attempt, or a runtime that did not answer, is answered from memory.
pub const FAILURE_MEMORY: Duration = Duration::from_secs(10);

/// How long the launcher waits for a started runtime to report itself.
///
/// The runtime's own wait for the daemon to accept its claim is 30 seconds, and a start that has
/// not been answered by then has already been given up by the runtime.
const START_DEADLINE: Duration = Duration::from_secs(30);

/// How long a look at a runtime another daemon started waits for it to answer a challenge.
const ADOPTION_PROBE: Duration = Duration::from_secs(5);

/// How long a worker that was told the runtime is not ready leaves before it asks again, where the
/// answer has no better figure: the worker is not recorded yet.
const NOT_RECORDED_RETRY: Duration = Duration::from_secs(1);

/// The starts made lately, so that a runtime that ends as it starts is not started without end.
#[derive(Debug, Default)]
struct StartBudget {
    starts: VecDeque<Instant>,
}

impl StartBudget {
    /// Spends one start at `now`, or says how long until the window admits one.
    fn spend(&mut self, now: Instant) -> Result<(), Duration> {
        while self
            .starts
            .front()
            .is_some_and(|at| now.duration_since(*at) >= START_WINDOW)
        {
            self.starts.pop_front();
        }
        if self.starts.len() >= START_ATTEMPTS {
            let oldest = self.starts.front().copied().unwrap_or(now);
            return Err(START_WINDOW.saturating_sub(now.duration_since(oldest)));
        }
        self.starts.push_back(now);
        Ok(())
    }
}

/// A runtime this daemon can answer for.
struct Running {
    descriptor: kr_plugin_service::protocol::HostDescriptor,
    /// Held while this daemon started the runtime: it keeps the reservation's endpoint this
    /// launcher's, so a second claim on it is refused and counted. An adopted runtime has none.
    _fence: Option<launcher::HostFence>,
}

enum State {
    Idle,
    Starting(watch::Receiver<Option<PluginRuntimeState>>),
    Running(Running),
    Failed { reason: String, until: Instant },
}

/// What a look at the descriptor a previous daemon published found.
enum Found {
    /// No runtime is published, or the one published has ended.
    Nothing,
    /// A runtime that answered a challenge.
    Alive(Running),
    /// A runtime whose process is running and which did not answer.
    Silent(String),
}

/// Who asks for a plugin runtime: the level of the worker, and the release it runs where it stated
/// one, which is the release a retained protocol's host is started from.
#[derive(Clone, Debug)]
pub struct Asking {
    /// The level the worker is at.
    pub level: CompatibilityLevel,
    /// The release the worker stated it runs.
    pub release: Option<ReleaseName>,
}

impl Asking {
    /// A worker of this daemon's own release, whose host is the program beside the daemon.
    #[must_use]
    pub const fn this() -> Self {
        Self {
            level: kr_protocol::update::THIS_LEVEL,
            release: None,
        }
    }
}

/// Where a holder takes the program it starts a host from.
pub enum HostProgram {
    /// The program beside the daemon, of the daemon's own release.
    Fixed(PathBuf),
    /// The program of the release the asking worker runs, from the release store the daemon runs
    /// from. The 0.78 cut removes it with the route of the protocol it serves.
    Stored(Arc<dyn ReleasePrograms>),
}

/// A plugin host program of a release in the release store, and the hold that keeps the release
/// there until the host has reported in.
pub struct StoredHost {
    /// The program.
    pub program: PathBuf,
    /// Dropped when the start ends.
    hold: Box<dyn std::any::Any + Send>,
}

/// The release store, as far as the plugin hosts of retained releases are concerned.
pub trait ReleasePrograms: Send + Sync {
    /// The `kr-plugin-host` of `release`, held, when `release` is in the store at `level`.
    ///
    /// # Errors
    ///
    /// Returns why no program can be taken, in words for the asker.
    fn plugin_host_of(
        &self,
        release: Option<&ReleaseName>,
        level: CompatibilityLevel,
    ) -> std::result::Result<StoredHost, String>;
}

/// The store this daemon runs from, where it runs from one. A tree outside a store, and every
/// Windows host, has none.
pub struct StoreReleases {
    #[cfg(unix)]
    store: Option<kr_ipc::install::Store>,
}

impl StoreReleases {
    /// The store the running daemon's release is in.
    #[must_use]
    pub fn of_this_process() -> Self {
        Self {
            #[cfg(unix)]
            store: kr_ipc::install::this_process()
                .ok()
                .and_then(|running| running.store())
                .map(|store| kr_ipc::install::Store::at(store.root())),
        }
    }

    /// A store at a directory, for a test that makes one.
    #[cfg(all(unix, test))]
    #[must_use]
    pub fn at(store: kr_ipc::install::Store) -> Self {
        Self { store: Some(store) }
    }
}

impl ReleasePrograms for StoreReleases {
    fn plugin_host_of(
        &self,
        release: Option<&ReleaseName>,
        level: CompatibilityLevel,
    ) -> std::result::Result<StoredHost, String> {
        let Some(release) = release else {
            return Err("the worker states no release to take a plugin host of".to_owned());
        };
        #[cfg(unix)]
        {
            let none = || {
                format!(
                    "no plugin host of the release before runs, and none can be started: the \
                     release {release} is not in this host's release store"
                )
            };
            let Some(store) = &self.store else {
                return Err(format!(
                    "no plugin host of the release before runs, and none can be started: this \
                     host keeps no release store (the worker runs {release})"
                ));
            };
            let pin = store
                .pin(release)
                .map_err(|error| format!("the release {release} could not be held: {error}"))?
                .ok_or_else(none)?;
            if CompatibilityLevel::of(pin.manifest().protocol_version) != level {
                return Err(format!(
                    "the release {release} is not at the level {level} of the worker that asks"
                ));
            }
            let program = store
                .release_directory(release)
                .join("bin")
                .join(format!("kr-plugin-host{}", std::env::consts::EXE_SUFFIX));
            if !program.is_file() {
                return Err(format!(
                    "the release {release} holds no plugin host program"
                ));
            }
            Ok(StoredHost {
                program,
                hold: Box::new(pin),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = level;
            Err(format!(
                "no plugin host of the release before runs, and none can be started: this host \
                 keeps no release store (the worker runs {release})"
            ))
        }
    }
}

/// What a start has resolved before it spends the budget.
struct Resolved {
    program: PathBuf,
    /// Held until the host has reported in.
    hold: Option<Box<dyn std::any::Any + Send>>,
}

/// The environment's plugin runtime of one protocol, as this daemon holds it.
pub struct PluginRuntime {
    paths: EnvironmentPaths,
    starter: Arc<dyn HostSupervisor>,
    protocol: HostProtocol,
    program: HostProgram,
    packages: PathBuf,
    state: tokio::sync::Mutex<State>,
    budget: std::sync::Mutex<StartBudget>,
    /// How long a failure is answered from memory.
    failure_memory: Duration,
}

impl std::fmt::Debug for PluginRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginRuntime")
            .field("protocol", &self.protocol.name)
            .field("packages", &self.packages)
            .finish_non_exhaustive()
    }
}

impl PluginRuntime {
    /// Builds the holder of one protocol for an environment: nothing is started.
    ///
    /// `program` says where the runtime's executable comes from and `packages` is the directory its
    /// components are read from, which is the catalogue's own.
    pub fn new(
        paths: EnvironmentPaths,
        supervisor: Arc<dyn WorkerSupervisor>,
        protocol: HostProtocol,
        program: HostProgram,
        packages: PathBuf,
    ) -> Self {
        Self {
            paths,
            starter: Arc::new(ServiceStarter { supervisor }),
            protocol,
            program,
            packages,
            state: tokio::sync::Mutex::new(State::Idle),
            budget: std::sync::Mutex::new(StartBudget::default()),
            failure_memory: FAILURE_MEMORY,
        }
    }

    /// Remembers a failure for as long as `memory` instead, for tests that decide by what was
    /// answered and not by how long they took to ask twice.
    #[cfg(test)]
    fn remembering_for(mut self, memory: Duration) -> Self {
        self.failure_memory = memory;
        self
    }

    /// Where the program of a start comes from, resolved before the start budget is spent: a start
    /// that cannot happen is not a start.
    fn resolve(&self, asking: &Asking) -> std::result::Result<Resolved, String> {
        match &self.program {
            HostProgram::Fixed(program) => Ok(Resolved {
                program: program.clone(),
                hold: None,
            }),
            HostProgram::Stored(releases) => releases
                .plugin_host_of(asking.release.as_ref(), asking.level)
                .map(|stored| Resolved {
                    program: stored.program,
                    hold: Some(stored.hold),
                }),
        }
    }

    /// Answers one worker's request: the runtime is running, or why it cannot be reached.
    pub async fn request(self: &Arc<Self>, asking: &Asking) -> PluginRuntimeState {
        loop {
            let mut state = self.state.lock().await;
            match &*state {
                State::Running(running) => {
                    let ended = matches!(
                        kr_ipc::identity::process_state(&running.descriptor.process_start_identity),
                        kr_ipc::identity::ProcessState::Ended
                    );
                    if !ended {
                        return PluginRuntimeState::Running;
                    }
                    // Its job goes with it the next time a runtime is started; the descriptor
                    // goes now, so no worker connects to the address of a process that is gone.
                    let _ = launcher::retire_descriptor(&self.paths, &self.protocol);
                    *state = State::Idle;
                }
                State::Starting(attempt) => {
                    let attempt = attempt.clone();
                    drop(state);
                    return Self::answer_of(attempt, self.failure_memory).await;
                }
                State::Failed { reason, until } => {
                    let now = Instant::now();
                    if now < *until {
                        return unavailable(reason, until.duration_since(now));
                    }
                    *state = State::Idle;
                }
                State::Idle => match self.look().await {
                    Found::Alive(running) => {
                        *state = State::Running(running);
                    }
                    Found::Silent(reason) => {
                        *state = State::Failed {
                            reason: reason.clone(),
                            until: Instant::now() + self.failure_memory,
                        };
                        return unavailable(&reason, self.failure_memory);
                    }
                    Found::Nothing => {
                        let resolved = match self.resolve(asking) {
                            Ok(resolved) => resolved,
                            Err(reason) => {
                                let reason = cut(&reason);
                                *state = State::Failed {
                                    reason: reason.clone(),
                                    until: Instant::now() + self.failure_memory,
                                };
                                return unavailable(&reason, self.failure_memory);
                            }
                        };
                        let spent = self
                            .budget
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .spend(Instant::now());
                        if let Err(wait) = spent {
                            return unavailable(
                                &format!(
                                    "the plugin runtime has been started {START_ATTEMPTS} times \
                                     in the last {} minutes, so it is not started again yet",
                                    START_WINDOW.as_secs() / 60
                                ),
                                wait,
                            );
                        }
                        let (finished, attempt) = watch::channel(None);
                        *state = State::Starting(attempt.clone());
                        drop(state);
                        // The attempt is a task of its own, so a requester that stops waiting
                        // leaves it to finish: the runtime it was starting is not abandoned
                        // half way.
                        let started = tokio::spawn(Arc::clone(self).attempt(finished, resolved));
                        // And one that ends abnormally leaves a failure behind, not a start that
                        // never finishes: every later request would be told it was lost.
                        tokio::spawn({
                            let runtime = Arc::clone(self);
                            async move {
                                if started.await.is_err() {
                                    let mut state = runtime.state.lock().await;
                                    if matches!(&*state, State::Starting(_)) {
                                        *state = State::Failed {
                                            reason: "the attempt to start the plugin runtime \
                                                     ended abnormally"
                                                .to_owned(),
                                            until: Instant::now() + runtime.failure_memory,
                                        };
                                    }
                                }
                            }
                        });
                        return Self::answer_of(attempt, self.failure_memory).await;
                    }
                },
            }
        }
    }

    /// Waits for one attempt's answer.
    async fn answer_of(
        mut attempt: watch::Receiver<Option<PluginRuntimeState>>,
        memory: Duration,
    ) -> PluginRuntimeState {
        loop {
            if let Some(answer) = attempt.borrow_and_update().clone() {
                return answer;
            }
            if attempt.changed().await.is_err() {
                return unavailable("the attempt to start the plugin runtime was lost", memory);
            }
        }
    }

    /// Starts the runtime and settles the state, whoever is still waiting for it.
    async fn attempt(
        self: Arc<Self>,
        finished: watch::Sender<Option<PluginRuntimeState>>,
        resolved: Resolved,
    ) {
        let started = launcher::start(
            &self.paths,
            self.protocol,
            resolved.program,
            &self.packages,
            &self.starter,
            START_DEADLINE,
        )
        .await;
        drop(resolved.hold);
        let mut state = self.state.lock().await;
        let answer = match started {
            Ok((descriptor, fence)) => {
                *state = State::Running(Running {
                    descriptor,
                    _fence: Some(fence),
                });
                PluginRuntimeState::Running
            }
            Err(error) => {
                // Whether nothing started or a process may be running, the launcher gave up the
                // rendezvous the runtime would report itself on, so a runtime that was started
                // cannot finish starting and ends. Either way the next attempt is made after the
                // failure has been answered from memory for a moment.
                let reason = cut(&error.to_string());
                *state = State::Failed {
                    reason: reason.clone(),
                    until: Instant::now() + self.failure_memory,
                };
                unavailable(&reason, self.failure_memory)
            }
        };
        drop(state);
        let _ = finished.send(Some(answer));
    }

    /// Looks for a runtime a previous daemon started.
    async fn look(&self) -> Found {
        let descriptor = match launcher::read_descriptor(&self.paths, &self.protocol) {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => return Found::Nothing,
            // A descriptor whose content this build refuses (another protocol, another
            // environment, not a descriptor) is not one a worker could use either. Taking it away
            // is what lets a runtime be started; if one is in fact running behind it, it holds its
            // endpoint and the new one fails to report itself.
            Err(LaunchError::Refused { .. }) => {
                let _ = launcher::retire_descriptor(&self.paths, &self.protocol);
                return Found::Nothing;
            }
            // A descriptor that could not be read at all may be a runtime's, and taking it away
            // would lose it for as long as that runtime lives.
            Err(error) => {
                return Found::Silent(cut(&format!(
                    "the published plugin runtime could not be looked at: {error}"
                )));
            }
        };
        if matches!(
            kr_ipc::identity::process_state(&descriptor.process_start_identity),
            kr_ipc::identity::ProcessState::Ended
        ) {
            let _ = launcher::retire_descriptor(&self.paths, &self.protocol);
            return Found::Nothing;
        }
        let paths = self.paths.clone();
        let protocol = self.protocol;
        let probe = tokio::time::timeout(ADOPTION_PROBE, async move {
            // This protocol is looked at the way a worker connects to it; a retained one, which
            // this build has no client for, only by the handshake.
            if protocol == HostProtocol::THIS {
                PluginClient::connect(&paths).await.map(|_client| ())
            } else {
                retained_host::probe(&paths, &protocol).await.map(|_| ())
            }
        })
        .await;
        match probe {
            Ok(Ok(())) => Found::Alive(Running {
                descriptor,
                _fence: None,
            }),
            Ok(Err(error)) => Found::Silent(cut(&format!(
                "the plugin runtime (process {}) is running and does not answer: {error}",
                descriptor.process_start_identity.pid.get()
            ))),
            Err(_elapsed) => Found::Silent(format!(
                "the plugin runtime (process {}) is running and did not answer within {} seconds",
                descriptor.process_start_identity.pid.get(),
                ADOPTION_PROBE.as_secs()
            )),
        }
    }
}

/// The plugin runtimes of an environment, one for each protocol this daemon serves: its own
/// release's, and each protocol a retained level recorded.
pub struct PluginRuntimes {
    this: Arc<PluginRuntime>,
    retained: Vec<(&'static str, Arc<PluginRuntime>)>,
}

impl PluginRuntimes {
    /// Builds the holders: nothing is started.
    ///
    /// `program` is this release's plugin host and `releases` the store a retained level's host is
    /// taken from. Each distinct protocol a retained level recorded gets one holder, and a level
    /// that recorded this release's protocol is served by this release's holder.
    pub fn new(
        paths: &EnvironmentPaths,
        supervisor: &Arc<dyn WorkerSupervisor>,
        program: PathBuf,
        packages: &Path,
        releases: &Arc<dyn ReleasePrograms>,
    ) -> Self {
        let holder = |protocol, program| {
            Arc::new(PluginRuntime::new(
                paths.clone(),
                Arc::clone(supervisor),
                protocol,
                program,
                packages.to_path_buf(),
            ))
        };
        let this = holder(HostProtocol::THIS, HostProgram::Fixed(program));
        let mut retained: Vec<(&'static str, Arc<PluginRuntime>)> = Vec::new();
        for level in &kr_protocol::retained::RETAINED {
            let name = level.plugin_host.trim();
            if name == HostProtocol::THIS.name || retained.iter().any(|(held, _)| *held == name) {
                continue;
            }
            let Some(protocol) = HostProtocol::named(name) else {
                continue;
            };
            retained.push((
                name,
                holder(protocol, HostProgram::Stored(Arc::clone(releases))),
            ));
        }
        Self { this, retained }
    }

    /// The runtime that serves the workers at `level`, where this daemon has one.
    #[must_use]
    pub fn of(&self, level: Level) -> Option<&Arc<PluginRuntime>> {
        let name = level.plugin_host();
        if name == HostProtocol::THIS.name {
            return Some(&self.this);
        }
        self.retained
            .iter()
            .find(|(held, _)| *held == name)
            .map(|(_, runtime)| runtime)
    }
}

/// Starts a runtime through the daemon's supervisor, as a service of its own.
struct ServiceStarter {
    supervisor: Arc<dyn WorkerSupervisor>,
}

impl HostSupervisor for ServiceStarter {
    fn start(&self, plan: &HostLaunchPlan) -> HostStartOutcome {
        let launch = ServiceLaunch {
            label: plan.label.clone(),
            program: plan.program.clone(),
            arguments: plan.arguments.clone(),
            jobs_directory: plan.jobs_directory.clone(),
            working_directory: plan.working_directory.clone(),
        };
        // `launchctl`, `systemd-run` and the Task Scheduler block, and this is called on an
        // executor thread.
        let started = crate::supervision::blocking_start(|| self.supervisor.start_service(&launch));
        match started {
            LaunchOutcome::Started(identity) => HostStartOutcome::Started(identity),
            LaunchOutcome::NotStarted { detail } => HostStartOutcome::NotStarted { detail },
            LaunchOutcome::Uncertain { detail, pid } => HostStartOutcome::Uncertain { detail, pid },
        }
    }

    fn retire(&self, jobs_directory: &std::path::Path, label: &str) -> HostJobRetirement {
        match retire_service_job(jobs_directory, label) {
            JobRetirement::Gone => HostJobRetirement::Gone,
            JobRetirement::StillRunning => HostJobRetirement::StillRunning,
            JobRetirement::Unsettled(detail) => HostJobRetirement::Unsettled(detail),
        }
    }
}

/// Cuts `text` to the bound a report carries, at a character boundary.
fn cut(text: &str) -> String {
    if text.len() <= MAX_REPORT_DETAIL_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_REPORT_DETAIL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The answer that the runtime cannot be reached, with how long the worker leaves before it asks.
fn unavailable(reason: &str, retry_after: Duration) -> PluginRuntimeState {
    PluginRuntimeState::Unavailable(PluginRuntimeUnavailable {
        reason: cut(reason),
        retry_after_ms: U64::new(u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX)),
    })
}

/// The answer to a running worker whose session has no worker recorded yet: ask again.
pub(super) fn not_recorded_yet() -> PluginRuntimeState {
    unavailable(
        "the daemon has not recorded that session's worker yet",
        NOT_RECORDED_RETRY,
    )
}

/// Why a request on the rendezvous endpoint was not taken from the process that made it.
#[derive(Debug)]
pub(super) enum Asker {
    /// The daemon has no record of that session's worker yet, or could not tell who is asking. The
    /// asker is told to ask again.
    NotYet(&'static str),
    /// The process asking is not the worker the daemon recorded.
    NotTheWorker(&'static str),
}

impl Asker {
    /// Why, in words for the asker.
    pub(super) const fn reason(&self) -> &'static str {
        match self {
            Self::NotYet(reason) | Self::NotTheWorker(reason) => reason,
        }
    }
}

impl Controller {
    /// Checks that a request on the rendezvous endpoint comes from the process this daemon recorded
    /// for the session it names, as the kernel names that process, and from no other.
    ///
    /// A worker is recorded when its ready report has been taken, which can be a moment after it
    /// starts to serve; a request that arrives before is told to ask again, and is not admitted
    /// on a weaker proof.
    pub(super) async fn recorded_worker(
        &self,
        session_id: SessionId,
        peer: &PeerIdentity,
    ) -> std::result::Result<(), Asker> {
        let Some(pid) = peer.pid else {
            return Err(Asker::NotYet(
                "the platform did not report which process is asking",
            ));
        };
        let Ok(asking) = kr_ipc::identity::process_start_identity(pid) else {
            return Err(Asker::NotYet(
                "the kernel would not describe the process that is asking",
            ));
        };
        let recorded = self
            .directory
            .lock()
            .await
            .get(session_id)
            .map(|worker| worker.descriptor.process_start_identity.clone());
        match recorded {
            None => Err(Asker::NotYet(
                "this daemon has not recorded that session's worker yet",
            )),
            Some(recorded) if !recorded.matches(&asking) => Err(Asker::NotTheWorker(
                "the process that is asking is not the worker this daemon recorded",
            )),
            Some(_) => Ok(()),
        }
    }

    /// Answers a worker's request for the plugin runtime, from the process this daemon recorded
    /// for the session and from no other, with the runtime of the protocol the worker's level
    /// speaks.
    pub(super) async fn plugin_runtime_wanted(
        &self,
        wanted: PluginRuntimeWanted,
        peer: &PeerIdentity,
        level: Level,
    ) -> PluginRuntimeState {
        match self.recorded_worker(wanted.session_id, peer).await {
            Err(refusal) => unavailable(refusal.reason(), NOT_RECORDED_RETRY),
            Ok(()) => {
                let Some(runtime) = self.plugin_runtimes.of(level) else {
                    return unavailable(
                        &format!(
                            "this daemon has no plugin runtime for the protocol {} that the \
                             worker's level speaks",
                            level.plugin_host()
                        ),
                        NOT_RECORDED_RETRY,
                    );
                };
                let release = self
                    .directory
                    .lock()
                    .await
                    .get(wanted.session_id)
                    .and_then(|worker| worker.release.clone());
                runtime
                    .request(&Asking {
                        level: level.level(),
                        release,
                    })
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn after(base: Instant, seconds: u64) -> Instant {
        base + Duration::from_secs(seconds)
    }

    #[test]
    fn a_runtime_that_ends_as_it_starts_is_started_five_times_and_then_not_again_until_the_window_moves()
     {
        let base = Instant::now();
        let mut budget = StartBudget::default();
        for second in 0..START_ATTEMPTS as u64 {
            assert!(budget.spend(after(base, second)).is_ok(), "start {second}");
        }
        let wait = budget
            .spend(after(base, 30))
            .expect_err("the sixth start inside the window is refused");
        // Told when the oldest start leaves the window, so a worker asks again no sooner.
        assert_eq!(wait, START_WINDOW - Duration::from_secs(30));
        // At the moment the oldest leaves, one start is admitted and the next is not.
        assert!(budget.spend(after(base, START_WINDOW.as_secs())).is_ok());
        assert!(budget.spend(after(base, START_WINDOW.as_secs())).is_err());
    }

    /// A supervisor that refuses to start a service once it is let go, and counts the times it
    /// was asked.
    #[derive(Debug, Default)]
    struct Gated {
        asked: AtomicUsize,
        open: std::sync::Mutex<bool>,
        opened: std::sync::Condvar,
    }

    impl Gated {
        fn let_go(&self) {
            *self.open.lock().expect("not poisoned") = true;
            self.opened.notify_all();
        }
    }

    impl WorkerSupervisor for Gated {
        fn start(&self, _launch: &crate::supervision::WorkerLaunch) -> LaunchOutcome {
            LaunchOutcome::NotStarted {
                detail: "this supervisor starts no worker".to_owned(),
            }
        }

        fn start_service(&self, _launch: &ServiceLaunch) -> LaunchOutcome {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.lock().expect("not poisoned");
            while !*open {
                open = self.opened.wait(open).expect("not poisoned");
            }
            LaunchOutcome::NotStarted {
                detail: "this supervisor starts nothing".to_owned(),
            }
        }

        fn describe(&self) -> &'static str {
            "a supervisor that counts what it is asked to start and starts nothing"
        }
    }

    fn runtime_over(host: &kr_ipc::testing::TempHost, supervisor: &Arc<Gated>) -> PluginRuntime {
        let supervisor: Arc<dyn WorkerSupervisor> = Arc::clone(supervisor) as _;
        PluginRuntime::new(
            host.environment(),
            supervisor,
            HostProtocol::THIS,
            HostProgram::Fixed(host.root().join("kr-plugin-host")),
            host.root().join("repositories"),
        )
    }

    /// Requests that arrive while a start is under way wait for it: the supervisor is asked once,
    /// and each requester is given that one attempt's answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn requests_that_arrive_together_wait_for_one_start() {
        let host = kr_ipc::testing::TempHost::create();
        let supervisor = Arc::new(Gated::default());
        let runtime = runtime_over(&host, &supervisor).remembering_for(Duration::from_secs(3600));
        let runtime = Arc::new(runtime);

        let first = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.request(&Asking::this()).await }
        });
        while supervisor.asked.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let second = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.request(&Asking::this()).await }
        });
        supervisor.let_go();

        let (first, second) = (
            first.await.expect("the first request is answered"),
            second.await.expect("the second request is answered"),
        );
        // The second is given the attempt's own answer, or, if it asked after the attempt ended,
        // the same one from memory: either way the supervisor was asked once.
        let (PluginRuntimeState::Unavailable(first), PluginRuntimeState::Unavailable(second)) =
            (first, second)
        else {
            panic!("a start that failed was answered that the runtime is running");
        };
        assert_eq!(first.reason, second.reason);
        assert_eq!(supervisor.asked.load(Ordering::SeqCst), 1);
    }

    /// A start that failed is answered from memory for a moment, so a worker that asks again at
    /// once does not start another.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_start_that_failed_is_answered_from_memory_and_not_started_again_at_once() {
        let host = kr_ipc::testing::TempHost::create();
        let supervisor = Arc::new(Gated::default());
        supervisor.let_go();
        let memory = Duration::from_secs(3600);
        let runtime = Arc::new(runtime_over(&host, &supervisor).remembering_for(memory));

        let first = runtime.request(&Asking::this()).await;
        let PluginRuntimeState::Unavailable(told) = &first else {
            panic!("a start that failed was answered {first:?}");
        };
        assert!(told.reason.contains("starts nothing"), "{}", told.reason);
        // Told to wait for as long as the failure is remembered, and no longer.
        assert_eq!(
            told.retry_after_ms.get(),
            u64::try_from(memory.as_millis()).expect("a figure")
        );

        let again = runtime.request(&Asking::this()).await;
        let PluginRuntimeState::Unavailable(told) = &again else {
            panic!("a failure was answered {again:?}");
        };
        assert!(told.reason.contains("starts nothing"), "{}", told.reason);
        assert_eq!(supervisor.asked.load(Ordering::SeqCst), 1);
    }

    /// A supervisor that panics when it is asked to start a service.
    #[derive(Debug)]
    struct Panicking;

    impl WorkerSupervisor for Panicking {
        fn start(&self, _launch: &crate::supervision::WorkerLaunch) -> LaunchOutcome {
            LaunchOutcome::NotStarted {
                detail: "this supervisor starts no worker".to_owned(),
            }
        }

        fn start_service(&self, _launch: &ServiceLaunch) -> LaunchOutcome {
            panic!("the platform's service manager failed in a way nobody planned for");
        }

        fn describe(&self) -> &'static str {
            "a supervisor that panics"
        }
    }

    /// An attempt that ends abnormally leaves a failure behind, and not a start that never
    /// finishes: every later request is answered from memory, and none is told for ever that the
    /// attempt was lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_attempt_that_ends_abnormally_leaves_a_failure_and_not_a_start_for_ever() {
        let host = kr_ipc::testing::TempHost::create();
        let runtime = Arc::new(
            PluginRuntime::new(
                host.environment(),
                Arc::new(Panicking),
                HostProtocol::THIS,
                HostProgram::Fixed(host.root().join("kr-plugin-host")),
                host.root().join("repositories"),
            )
            .remembering_for(Duration::from_secs(3600)),
        );

        // The first request is told the attempt was lost; the ones after are told the failure
        // the watcher left. Without the watcher the state stays `Starting` and no request is ever
        // told the failure, so a bound on the wait is what makes that a failure of this test and
        // not a test that turns for ever.
        let PluginRuntimeState::Unavailable(first) = runtime.request(&Asking::this()).await else {
            panic!("an attempt that failed was answered that the runtime is running");
        };
        assert!(first.reason.contains("was lost"), "{}", first.reason);
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let PluginRuntimeState::Unavailable(told) = runtime.request(&Asking::this()).await
                else {
                    panic!("an attempt that failed was answered that the runtime is running");
                };
                if told.reason.contains("ended abnormally") {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the attempt that ended abnormally was left as a failure");
        // And the failure stays the answer.
        let PluginRuntimeState::Unavailable(again) = runtime.request(&Asking::this()).await else {
            panic!("a failure was answered that the runtime is running");
        };
        assert!(
            again.reason.contains("ended abnormally"),
            "{}",
            again.reason
        );
    }

    /// A runtime whose process is running and which does not answer is not started over: its
    /// endpoint is held, so the new one could not bind it. The request is answered, and nothing is
    /// started.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_runtime_that_is_running_and_does_not_answer_is_not_started_over() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        // This test process stands for a runtime: a process that is running and holds no endpoint
        // anybody can reach.
        let identity =
            launcher::HostIdentity::generate(host.environment_id()).expect("an identity");
        launcher::publish_descriptor(
            &environment,
            &HostProtocol::THIS,
            &kr_plugin_service::protocol::HostDescriptor {
                protocol: HostProtocol::THIS.name.to_owned(),
                environment_id: host.environment_id(),
                reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
                endpoint: launcher::host_endpoint(&environment, &HostProtocol::THIS)
                    .expect("an endpoint")
                    .as_text(),
                boot_identity: identity.boot_identity().clone(),
                process_start_identity: identity.process_start_identity().clone(),
                host_public_key: *identity.public_key(),
            },
        )
        .expect("a descriptor");
        let supervisor = Arc::new(Gated::default());
        supervisor.let_go();
        let runtime = Arc::new(runtime_over(&host, &supervisor));

        let answer = runtime.request(&Asking::this()).await;
        let PluginRuntimeState::Unavailable(told) = &answer else {
            panic!("a runtime that does not answer was answered {answer:?}");
        };
        assert!(
            told.reason.contains("is running and does not answer"),
            "{}",
            told.reason
        );
        assert_eq!(supervisor.asked.load(Ordering::SeqCst), 0);
    }

    /// A plugin host standing in for a running one of `protocol`: it is published as one and
    /// answers the handshake, so a holder adopts it.
    struct StandIn {
        _listener: tokio::task::JoinHandle<()>,
        descriptor: kr_plugin_service::protocol::HostDescriptor,
    }

    impl StandIn {
        async fn publish(host: &kr_ipc::testing::TempHost, protocol: &HostProtocol) -> Self {
            use kr_plugin_service::protocol::{Frame, Request, RequestBody, ResponseBody};

            let environment = host.environment();
            let identity =
                launcher::HostIdentity::generate(host.environment_id()).expect("an identity");
            let endpoint = launcher::host_endpoint(&environment, protocol).expect("an endpoint");
            let listener =
                kr_ipc::endpoint::Listener::bind(&endpoint).expect("the stand-in listens");
            let descriptor = kr_plugin_service::protocol::HostDescriptor {
                protocol: protocol.name.to_owned(),
                environment_id: host.environment_id(),
                reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
                endpoint: endpoint.as_text(),
                boot_identity: identity.boot_identity().clone(),
                process_start_identity: identity.process_start_identity().clone(),
                host_public_key: *identity.public_key(),
            };
            launcher::publish_descriptor(&environment, protocol, &descriptor)
                .expect("a descriptor");
            let served = descriptor.clone();
            let name = protocol.name;
            let task = tokio::spawn(async move {
                loop {
                    let Ok((connection, _peer)) = listener.accept().await else {
                        return;
                    };
                    let (mut reader, mut writer) =
                        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                    while let Ok(request) = reader.read_message_without_schema::<Request>().await {
                        let body = match request.body {
                            RequestBody::Hello { .. } => ResponseBody::Hello {
                                protocol: name.to_owned(),
                                descriptor: Box::new(served.clone()),
                            },
                            RequestBody::Verify { nonce } => ResponseBody::Verified(Box::new(
                                identity
                                    .answer(&nonce, &served.endpoint)
                                    .expect("an answer"),
                            )),
                            _ => return,
                        };
                        let frame = Frame::Response {
                            reply_to: request.request_id,
                            body,
                        };
                        if writer.write_message(&frame).await.is_err() {
                            return;
                        }
                    }
                }
            });
            Self {
                _listener: task,
                descriptor,
            }
        }
    }

    fn runtimes_over(host: &kr_ipc::testing::TempHost, supervisor: &Arc<Gated>) -> PluginRuntimes {
        let supervisor: Arc<dyn WorkerSupervisor> = Arc::clone(supervisor) as _;
        PluginRuntimes::new(
            &host.environment(),
            &supervisor,
            host.root().join("kr-plugin-host"),
            &host.root().join("repositories"),
            &(Arc::new(StoreReleases::of_this_process()) as Arc<dyn ReleasePrograms>),
        )
    }

    fn the_retained_level() -> Level {
        Level::retained(&kr_protocol::retained::RETAINED[0])
    }

    /// Every level this daemon serves has a runtime of the protocol it speaks, and no two
    /// protocols share a holder.
    #[test]
    fn every_retained_level_has_a_runtime_of_its_own_protocol() {
        let host = kr_ipc::testing::TempHost::create();
        let runtimes = runtimes_over(&host, &Arc::new(Gated::default()));
        let this = runtimes
            .of(Level::this())
            .expect("a runtime for this level");
        for retained in &kr_protocol::retained::RETAINED {
            let held = runtimes
                .of(Level::retained(retained))
                .unwrap_or_else(|| panic!("level {} has no runtime", retained.level));
            assert_eq!(
                held.protocol.name,
                retained.plugin_host.trim(),
                "level {}",
                retained.level
            );
            assert!(
                !Arc::ptr_eq(held, this),
                "level {} shares this release's runtime",
                retained.level
            );
        }
    }

    /// A host of each protocol that runs is adopted by the holder of that protocol and by no other,
    /// and a worker of each level is answered that its own runtime runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_host_of_each_protocol_is_adopted_by_the_holder_of_its_own() {
        let host = kr_ipc::testing::TempHost::create();
        let supervisor = Arc::new(Gated::default());
        supervisor.let_go();
        let runtimes = runtimes_over(&host, &supervisor);
        let retained = the_retained_level();
        let retained_host = StandIn::publish(
            &host,
            &HostProtocol::named(retained.plugin_host()).expect("a route"),
        )
        .await;
        let this_host = StandIn::publish(&host, &HostProtocol::THIS).await;
        assert_ne!(
            retained_host.descriptor.endpoint,
            this_host.descriptor.endpoint
        );

        let retained_asks = Asking {
            level: retained.level(),
            release: None,
        };
        assert_eq!(
            runtimes
                .of(retained)
                .expect("a runtime")
                .request(&retained_asks)
                .await,
            PluginRuntimeState::Running
        );
        assert_eq!(
            runtimes
                .of(Level::this())
                .expect("a runtime")
                .request(&Asking::this())
                .await,
            PluginRuntimeState::Running
        );
        // Both adopted, and nothing started.
        assert_eq!(supervisor.asked.load(Ordering::SeqCst), 0);
    }

    /// Where the host keeps no release store and no host of the retained protocol runs, a retained
    /// worker is answered that the runtime cannot be reached, with the reason, however often it
    /// asks, and the answer spends none of the start allowance. A worker of this level is unaffected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_retained_worker_is_told_why_when_there_is_no_store_and_no_host() {
        let host = kr_ipc::testing::TempHost::create();
        let supervisor = Arc::new(Gated::default());
        supervisor.let_go();
        let runtimes = runtimes_over(&host, &supervisor);
        let retained = the_retained_level();
        let retained_runtime = runtimes.of(retained).expect("a runtime");
        // Remembered for no time, so every ask is looked at afresh.
        let retained_runtime = Arc::new(PluginRuntime {
            failure_memory: Duration::ZERO,
            ..PluginRuntime::new(
                host.environment(),
                Arc::new(Gated::default()) as Arc<dyn WorkerSupervisor>,
                retained_runtime.protocol,
                HostProgram::Stored(Arc::new(StoreReleases::of_this_process())),
                host.root().join("repositories"),
            )
        });
        let asks = Asking {
            level: retained.level(),
            release: kr_protocol::update::ReleaseName::new("0.76.0+aaaaaaaaaaaa").ok(),
        };
        let mut told = Vec::new();
        for _ in 0..START_ATTEMPTS + 3 {
            let PluginRuntimeState::Unavailable(unavailable) =
                retained_runtime.request(&asks).await
            else {
                panic!("a worker with no host to take was answered that its runtime runs");
            };
            told.push(unavailable.reason);
        }
        assert!(
            told[0].contains("no plugin host of the release before runs"),
            "{}",
            told[0]
        );
        assert!(told.iter().all(|reason| *reason == told[0]), "{told:?}");
        assert_eq!(
            retained_runtime
                .budget
                .lock()
                .expect("not poisoned")
                .starts
                .len(),
            0,
            "no start was spent on a start that could not happen"
        );
        // A worker of this level, with a host that runs, is answered as before.
        let _this_host = StandIn::publish(&host, &HostProtocol::THIS).await;
        assert_eq!(
            runtimes
                .of(Level::this())
                .expect("a runtime")
                .request(&Asking::this())
                .await,
            PluginRuntimeState::Running
        );
    }

    /// A release store of a test, with releases put in it.
    #[cfg(unix)]
    struct Store {
        store: kr_ipc::install::Store,
        _root: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl Drop for Store {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._root);
        }
    }

    #[cfg(unix)]
    impl Store {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("kr-releases-{}", kr_ipc::new_uuid()));
            let store = kr_ipc::install::Store::at(root.join("host"));
            store.create_directories().expect("the store's directories");
            kr_ipc::paths::write_owner_only_file(&store.record(), b"{}\n").expect("a record");
            Self { store, _root: root }
        }

        /// Puts a release in the store at `version`, with a plugin host program when `host`.
        fn release(&self, name: &str, version: (u16, u16, u16), host: bool) -> ReleaseName {
            use kr_protocol::update::{
                CommitId, FloorSystem, FloorVersion, ManifestKind, OsFloor, ReleaseManifest,
            };

            let release = ReleaseName::new(name).expect("a release name");
            let directory = self.store.release_directory(&release);
            std::fs::create_dir_all(directory.join("bin")).expect("the release's bin");
            let manifest = ReleaseManifest {
                kind: ManifestKind::Release,
                release: release.clone(),
                sequence: U64::new(1),
                commit: CommitId::new("4254aa6e62e585478ff8dcff5518f23c7263f4ce")
                    .expect("a commit"),
                target: "aarch64-apple-darwin".to_owned(),
                os_floor: OsFloor {
                    system: FloorSystem::Macos,
                    version: FloorVersion {
                        major: 14,
                        minor: 0,
                    },
                },
                protocol_version: kr_protocol::hello::PackageVersion::new(
                    version.0, version.1, version.2,
                ),
                public_majors: vec![1],
                retained_levels: Vec::new(),
                shells: Vec::new(),
                agents: Vec::new(),
                dependencies: Some(kr_protocol::update::ReleaseDependencies {
                    lock_sha256: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
                    pinned: Vec::new(),
                    vectors: Vec::new(),
                }),
                stores: vec![kr_protocol::update::ReleaseStore {
                    store: "registry".to_owned(),
                    scope: kr_protocol::update::StoreScope::Environment,
                    path: "registry.sqlite".to_owned(),
                    recording: kr_protocol::update::Recording::SqliteTable {
                        table: "schema_version".to_owned(),
                    },
                    version: 7,
                    migrates_from: 1,
                    reads_through: None,
                }],
                files: Vec::new(),
            };
            std::fs::write(
                self.store.manifest(&release),
                serde_json::json!({ "signed": manifest, "signatures": [] }).to_string(),
            )
            .expect("the manifest");
            if host {
                std::fs::write(directory.join("bin").join("kr-plugin-host"), b"#!/bin/sh\n")
                    .expect("a program");
            }
            release
        }
    }

    /// The program a retained protocol's host is started from is the asking worker's own release's
    /// among the releases of the store at its level, and none when that release is not in the
    /// store, is at another level, or holds no host program.
    #[cfg(unix)]
    #[test]
    fn the_host_a_retained_worker_is_given_is_that_of_the_release_it_runs() {
        let store = Store::new();
        let level = CompatibilityLevel::of(kr_protocol::hello::PackageVersion::new(0, 76, 0));
        let earlier = store.release("0.76.0+aaaaaaaaaaaa", (0, 76, 0), true);
        let later = store.release("0.76.0+bbbbbbbbbbbb", (0, 76, 0), true);
        let other_level = store.release("0.75.0+cccccccccccc", (0, 75, 0), true);
        let without = store.release("0.76.0+dddddddddddd", (0, 76, 0), false);
        let absent = ReleaseName::new("0.76.0+eeeeeeeeeeee").expect("a release name");
        let releases = StoreReleases::at(kr_ipc::install::Store::at(store.store.root()));

        for (asker, chosen) in [(&earlier, &earlier), (&later, &later)] {
            let found = releases
                .plugin_host_of(Some(asker), level)
                .unwrap_or_else(|error| panic!("{asker}: {error}"));
            assert_eq!(
                found.program,
                store
                    .store
                    .release_directory(chosen)
                    .join("bin")
                    .join("kr-plugin-host"),
                "a worker of {asker} takes the host of {chosen}"
            );
        }
        for (asker, why) in [
            (Some(&absent), "is not in this host's release store"),
            (Some(&other_level), "is not at the level"),
            (Some(&without), "holds no plugin host program"),
            (None, "states no release"),
        ] {
            let Err(error) = releases.plugin_host_of(asker, level) else {
                panic!("{asker:?} was given a host");
            };
            assert!(error.contains(why), "{asker:?}: {error}");
        }
    }
}
