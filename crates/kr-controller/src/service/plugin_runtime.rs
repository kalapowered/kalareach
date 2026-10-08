//! The plugin runtime: one `kr-plugin-host` process per environment, started when a worker first
//! asks for it.
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
//! # Starting is bounded
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
//! A runtime of another release that answers is kept whatever started it. A descriptor whose
//! content this build refuses (another protocol, another environment, not a descriptor) is taken
//! away, and a runtime still behind it holds its endpoint, so the new one cannot report itself and
//! the start fails after the wait the launcher gives it. A descriptor that cannot be read at all, a
//! link or a file another account could write, is left in place, and the answer is that the
//! runtime cannot be reached.
//!
//! # Which requests are answered
//!
//! Only a request from the process this daemon recorded for the session, as the kernel names that
//! process now. Starting the runtime gives a requester no authority over anything, but it spends
//! the start allowance, so another process of the same user does not get to spend it.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::peer::PeerIdentity;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::launcher::{
    self, HostJobRetirement, HostLaunchPlan, HostStartOutcome, HostSupervisor, LaunchError,
};
use kr_protocol::admission::{PluginRuntimeState, PluginRuntimeUnavailable, PluginRuntimeWanted};
use kr_protocol::limits::MAX_REPORT_DETAIL_BYTES;
use kr_protocol::scalars::U64;
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

/// The environment's plugin runtime, as this daemon holds it.
pub struct PluginRuntime {
    paths: EnvironmentPaths,
    starter: Arc<dyn HostSupervisor>,
    program: PathBuf,
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
            .field("program", &self.program)
            .field("packages", &self.packages)
            .finish_non_exhaustive()
    }
}

impl PluginRuntime {
    /// Builds the holder for an environment: nothing is started.
    ///
    /// `program` is the runtime's executable and `packages` the directory its components are read
    /// from, which is the catalogue's own.
    pub fn new(
        paths: EnvironmentPaths,
        supervisor: Arc<dyn WorkerSupervisor>,
        program: PathBuf,
        packages: PathBuf,
    ) -> Self {
        Self {
            paths,
            starter: Arc::new(ServiceStarter { supervisor }),
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

    /// Answers one worker's request: the runtime is running, or why it cannot be reached.
    pub async fn request(self: &Arc<Self>) -> PluginRuntimeState {
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
                    let _ = launcher::retire_descriptor(&self.paths);
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
                        let started = tokio::spawn(Arc::clone(self).attempt(finished));
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
    async fn attempt(self: Arc<Self>, finished: watch::Sender<Option<PluginRuntimeState>>) {
        let started = launcher::start(
            &self.paths,
            self.program.clone(),
            &self.packages,
            &self.starter,
            START_DEADLINE,
        )
        .await;
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
        let descriptor = match launcher::read_descriptor(&self.paths) {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => return Found::Nothing,
            // A descriptor whose content this build refuses (another protocol, another
            // environment, not a descriptor) is not one a worker could use either. Taking it away
            // is what lets a runtime be started; if one is in fact running behind it, it holds its
            // endpoint and the new one fails to report itself.
            Err(LaunchError::Refused { .. }) => {
                let _ = launcher::retire_descriptor(&self.paths);
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
            let _ = launcher::retire_descriptor(&self.paths);
            return Found::Nothing;
        }
        let paths = self.paths.clone();
        let probe = tokio::time::timeout(ADOPTION_PROBE, PluginClient::connect(&paths)).await;
        match probe {
            Ok(Ok(_client)) => Found::Alive(Running {
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
        // `launchctl` and `systemd-run` block, and this is called on an executor thread. A runtime
        // that can hand its thread's other work to its peers does so; one that cannot (a current
        // thread runtime, which no daemon here is) starts the job where it stands.
        let started = if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            tokio::task::block_in_place(|| self.supervisor.start_service(&launch))
        } else {
            self.supervisor.start_service(&launch)
        };
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

impl Controller {
    /// Answers a worker's request for the plugin runtime, from the process this daemon recorded
    /// for the session and from no other.
    ///
    /// A worker is recorded when its ready report has been taken, which can be a moment after it
    /// starts to serve; a request that arrives before is told to ask again, and is not admitted
    /// on a weaker proof.
    pub(super) async fn plugin_runtime_wanted(
        &self,
        wanted: PluginRuntimeWanted,
        peer: &PeerIdentity,
    ) -> PluginRuntimeState {
        let refuse = |reason: &str| unavailable(reason, NOT_RECORDED_RETRY);
        let Some(pid) = peer.pid else {
            return refuse("the platform did not report which process is asking");
        };
        let Ok(asking) = kr_ipc::identity::process_start_identity(pid) else {
            return refuse("the kernel would not describe the process that is asking");
        };
        let recorded = self
            .directory
            .lock()
            .await
            .get(wanted.session_id)
            .map(|worker| worker.descriptor.process_start_identity.clone());
        match recorded {
            None => refuse("this daemon has not recorded that session's worker yet"),
            Some(recorded) if !recorded.matches(&asking) => {
                refuse("the process that is asking is not the worker this daemon recorded")
            }
            Some(_) => self.plugin_runtime.request().await,
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
            host.root().join("kr-plugin-host"),
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
            async move { runtime.request().await }
        });
        while supervisor.asked.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let second = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.request().await }
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

        let first = runtime.request().await;
        let PluginRuntimeState::Unavailable(told) = &first else {
            panic!("a start that failed was answered {first:?}");
        };
        assert!(told.reason.contains("starts nothing"), "{}", told.reason);
        // Told to wait for as long as the failure is remembered, and no longer.
        assert_eq!(
            told.retry_after_ms.get(),
            u64::try_from(memory.as_millis()).expect("a figure")
        );

        let again = runtime.request().await;
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
                host.root().join("kr-plugin-host"),
                host.root().join("repositories"),
            )
            .remembering_for(Duration::from_secs(3600)),
        );

        // The first request is told the attempt was lost; the ones after are told the failure
        // the watcher left. Without the watcher the state stays `Starting` and no request is ever
        // told the failure, so a bound on the wait is what makes that a failure of this test and
        // not a test that turns for ever.
        let PluginRuntimeState::Unavailable(first) = runtime.request().await else {
            panic!("an attempt that failed was answered that the runtime is running");
        };
        assert!(first.reason.contains("was lost"), "{}", first.reason);
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let PluginRuntimeState::Unavailable(told) = runtime.request().await else {
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
        let PluginRuntimeState::Unavailable(again) = runtime.request().await else {
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
            &kr_plugin_service::protocol::HostDescriptor {
                protocol: kr_plugin_service::protocol::PROTOCOL.to_owned(),
                environment_id: host.environment_id(),
                reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
                endpoint: launcher::host_endpoint(&environment)
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

        let answer = runtime.request().await;
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
}
