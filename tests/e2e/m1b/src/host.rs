//! The host: a real `kr-controller` daemon over a host tree of the run's own, and `kr` run against
//! it the way a person runs it.
//!
//! The daemon is the binary this build produced, started with the run's runtime and state
//! directories, the file secret store inside that tree and the copied worker. It chooses how to
//! start workers itself, as an installed daemon does: launchd on macOS, the user's systemd manager
//! on Linux where the environment reaches one, and a detached process otherwise. Its network is the
//! one its configuration document selects, which here is loopback alone with no relay and no
//! discovery service: the device and the host meet directly, and the deployed site is reached only
//! for the rendezvous.
//!
//! Stopping is the order a person's machine sees it in: every live session is closed through the
//! daemon, the workers end, the daemon removes their jobs, and only then is the daemon asked to
//! stop, with the interrupt it answers. Where an agent under test has been started in the run, no
//! `kr` is run any more, since `kr` takes its target from the run's state, which that agent may
//! have changed: the daemon is interrupted, the jobs of the run's workers are removed and the
//! recorded processes are ended, all by the identities the run recorded.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessQuery, query_process};
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::EnvironmentId;
use serde_json::Value;

use crate::LIVENESS;
use crate::compare::{self, Interval, Layout};
use crate::floor::{Opening, Readings, Watch};
use crate::index::{self, Looked};
use crate::outside::Outside;
use crate::run::{
    HARNESS_PROGRAM, Run, binary_place, ended_within, output_within, processes_under,
    read_tail_below, running, signal, socket_below, worker_session,
};
use crate::tables::{self, Tables};
use crate::tree::{Entry, OPTIONAL_ROOTS, REQUIRED_ROOTS, RUNTIME_ROOT, Record, STATE_ROOT};
use crate::worker::Place;

/// The daemon's log, in the run's directory.
const DAEMON_LOG: &str = "controller.log";

/// How long the daemon is given to stop once it has been interrupted.
const DAEMON_STOP: Duration = Duration::from_secs(20);

/// How long a closed session's worker and its job are given to go before the daemon stops.
///
/// The daemon removes a worker's launchd job once the closure is recorded and the worker has
/// ended, so it is kept running until that has happened.
const RETIREMENT: Duration = Duration::from_secs(90);

/// How long finding the processes a host started is tried for before the run is told it could
/// not be completed.
const DISCOVERY: Duration = Duration::from_secs(10);

/// How long one `kr` command is given when a leg cleans up after itself.
const CLEANUP_COMMAND: Duration = Duration::from_secs(20);

/// How long a wait pauses between two asks of `kr status`, and between two asks of `kr list` while
/// the daemon has not yet answered.
const ASK_AGAIN: Duration = Duration::from_millis(200);

/// How long a leg that closed its sessions pauses between two asks of `kr list`.
const LIST_AGAIN: Duration = Duration::from_millis(250);

/// One deadline for a whole wait, which bounds every step taken inside it.
///
/// A wait that compared the time only between its steps, and gave each step a whole bound of its
/// own, could overrun by as much as one step: a `kr` that answered just before the wait's bound was
/// followed by one more, given the whole bound again. Here each step is given what is left of the
/// wait and no more, so a `kr` that answers slowly, or not at all, ends the wait at its deadline
/// rather than a step's bound after it, and once the deadline has passed no step is started at all.
/// What the deadline does not bound is the handover of a finished `kr`'s output, which
/// [`output_within`] bounds by itself.
#[derive(Clone, Copy, Debug)]
struct Deadline {
    at: Instant,
}

impl Deadline {
    /// The deadline `within` from now.
    fn after(within: Duration) -> Self {
        Self {
            at: Instant::now() + within,
        }
    }

    /// The bound for one step inside the wait: what is left of it, and never more than `step`, or
    /// nothing once the deadline has passed, so that no step is started with no time to run in.
    fn bound(self, step: Duration) -> Option<Duration> {
        let left = self.at.saturating_duration_since(Instant::now());
        (!left.is_zero()).then(|| left.min(step))
    }

    /// Takes `step` until it gives the answer the wait is for.
    ///
    /// Each step is given its bound, which is what is left of the wait and never more than `each`,
    /// and has to finish within it. Between two steps the wait pauses for `pause`, or for what is
    /// left when that is less. A step says what it heard when it has not got the answer.
    ///
    /// # Errors
    ///
    /// Returns what the last step heard when the deadline passes without the answer.
    fn poll<T>(
        self,
        each: Duration,
        pause: Duration,
        mut step: impl FnMut(Duration) -> ControlFlow<T, String>,
    ) -> Result<T, String> {
        let mut heard = "the deadline passed before anything was asked".to_owned();
        while let Some(bound) = self.bound(each) {
            match step(bound) {
                ControlFlow::Break(answer) => return Ok(answer),
                ControlFlow::Continue(said) => heard = said,
            }
            if let Some(pause) = self.bound(pause) {
                std::thread::sleep(pause);
            }
        }
        Err(heard)
    }
}

/// Asks for a session's status through `status` until it reports the session closed, within one
/// deadline `within` from now, and returns that report.
///
/// `status` runs `kr status <display> --json` and has to finish within the bound it is given, which
/// is what is left of the wait.
///
/// # Errors
///
/// Returns what the last ask heard when the session was not reported closed within `within`.
fn until_closed(
    within: Duration,
    mut status: impl FnMut(Duration) -> Result<Output, String>,
) -> Result<Value, String> {
    Deadline::after(within).poll(within, ASK_AGAIN, |bound| match status(bound) {
        Ok(output) => {
            if output.status.success()
                && let Ok(report) = document(&output.stdout)
                && report["state"] == "closed"
            {
                ControlFlow::Break(report)
            } else {
                ControlFlow::Continue(String::from_utf8_lossy(&output.stdout).into_owned())
            }
        }
        Err(why) => ControlFlow::Continue(format!("kr status {why}")),
    })
}

/// Closes every session `list` names through `close`, then waits until `list` names none, all
/// within one deadline `within` from now.
///
/// `list` runs `kr list --json` and `close` runs `kr close <display> --json`. Each is given what is
/// left of the deadline and never more than [`CLEANUP_COMMAND`], and none is started once the
/// deadline has passed: the sessions not yet closed then are named instead.
///
/// # Errors
///
/// Returns what did not happen: a session that could not be closed, the sessions left when the
/// deadline passed, or what the last listing said.
fn close_all(
    within: Duration,
    mut list: impl FnMut(Duration) -> Result<Vec<Value>, String>,
    mut close: impl FnMut(&str, Duration) -> Result<Output, String>,
) -> Result<(), String> {
    let deadline = Deadline::after(within);
    let passed = || format!("the {within:?} for closing the sessions passed");
    let listed = list(deadline.bound(CLEANUP_COMMAND).ok_or_else(passed)?)?;
    let mut problems = Vec::new();
    let mut displays = listed
        .iter()
        .map(|session| session["display_number"].to_string());
    for display in displays.by_ref() {
        let Some(bound) = deadline.bound(CLEANUP_COMMAND) else {
            problems.push(format!("session {display} was not closed: {}", passed()));
            break;
        };
        if !close(&display, bound).is_ok_and(|output| output.status.success()) {
            problems.push(format!("session {display} could not be closed"));
        }
    }
    problems.extend(displays.map(|display| format!("session {display} was not closed")));
    let emptied = deadline.poll(CLEANUP_COMMAND, LIST_AGAIN, |bound| match list(bound) {
        Ok(open) if open.is_empty() => ControlFlow::Break(()),
        Ok(open) => ControlFlow::Continue(format!(
            "{} sessions were still open when {}",
            open.len(),
            passed()
        )),
        Err(why) => ControlFlow::Continue(why),
    });
    if let Err(heard) = emptied {
        problems.push(heard);
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// What a host is started with.
#[derive(Clone, Debug, Default)]
pub struct HostOptions {
    /// The managed shell packages the daemon resolves, when the leg runs a managed session.
    pub shell_packages: Option<PathBuf>,
}

/// What a leg that prepares its host before the daemon opens it asks for beyond [`HostOptions`].
#[derive(Clone, Debug, Default)]
pub struct Preparation {
    /// The plugins whose command integrations the configuration document turns on.
    pub command_integrations: Vec<String>,
    /// Whether the host keeps the loopback address a device dials across a restart of its daemon,
    /// by binding a port chosen once instead of one the system chooses at each start.
    pub stable_address: bool,
}

/// What a case says of a restart of the control daemon after its agent has started
/// ([`Host::declares_a_restart`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Restart {
    /// The case starts no daemon again after its agent started, or does so only for the harness's
    /// own stand-in, which changes none of the run's files.
    #[default]
    Off,
    /// The case kills the daemon and starts it again after its agent started: the host records the
    /// run's tree when the agent starts, unless the agent is the stand-in.
    Declared,
    /// The survey of the files a restart changes: the host records the run's tree when the agent
    /// starts on the stand-in too, and says each change that the compares would refuse, without
    /// refusing it.
    Survey,
}

/// Why a leg did not run, carried by the unwinding of a case's body to the end of the case, which
/// records the leg as not run with this text and then fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegNotRun(pub String);

/// The lines every survey host ([`Restart::Survey`]) has said in this process, in the order they
/// were said.
static SURVEYED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The lines every survey host has said so far in this process.
#[must_use]
pub fn surveyed() -> Vec<String> {
    SURVEYED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// How the survey waits after a kill, and how it looks for the files that the worker's
/// maintenance writes to stand still.
#[derive(Clone, Copy, Debug)]
struct SurveyTiming {
    /// The wait after a kill before the first look: two maintenance intervals of the worker, so
    /// that a pass has had its beat after the kill (a pass is put on the session's beat and can
    /// follow its last by more than one interval).
    after_the_kill: Duration,
    /// The time between two looks.
    apart: Duration,
    /// How long after the kill the looks go on.
    at_most: Duration,
}

impl Default for SurveyTiming {
    fn default() -> Self {
        Self {
            after_the_kill: 2 * kr_worker::service::HOST_MAINTENANCE,
            apart: Duration::from_secs(5),
            at_most: Duration::from_secs(180),
        }
    }
}

/// What the survey of a restart has done so far.
#[derive(Debug, Default)]
struct Survey {
    timing: SurveyTiming,
    /// The kills surveyed.
    kills: usize,
    /// The record made at the latest kill, and the moment of the kill.
    at_the_kill: Option<(Instant, Record)>,
    /// How many entries differ between the record made when the agent started and the latest kill.
    changes_to_the_kill: usize,
    /// The lines this host has said.
    lines: Vec<String>,
}

impl Survey {
    /// Says `lines`: prints each and keeps it.
    fn say(&mut self, lines: Vec<String>) {
        for line in lines {
            eprintln!("{line}");
            SURVEYED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line.clone());
            self.lines.push(line);
        }
    }
}

/// Whether the survey watches the entry at `path` for standing still: the output-time index and
/// the session journals, which the worker's maintenance pass writes while no daemon runs.
fn survey_watches(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some("output-times" | "sessions")
        )
    })
}

/// Waits after a kill for what the survey watches to stand still: the time `timing` gives for the
/// wait, then looks `timing.apart` apart until two looks agree. Returns the time after the kill at
/// which two looks agreed, or `None` where the bound passed first.
fn wait_for_standing_still(
    timing: SurveyTiming,
    killed: Instant,
    mut view: impl FnMut() -> Option<Vec<(PathBuf, Entry)>>,
) -> Option<Duration> {
    std::thread::sleep(timing.after_the_kill.saturating_sub(killed.elapsed()));
    let mut before = view();
    loop {
        std::thread::sleep(timing.apart);
        let after = view();
        if before.is_some() && before == after {
            return Some(killed.elapsed());
        }
        if killed.elapsed() >= timing.at_most {
            return None;
        }
        before = after;
    }
}

/// What the survey says of the wait: that the watched files stood still, or that they did not and
/// the list is incomplete.
fn standing_still_said(timing: SurveyTiming, stood_still: Option<Duration>) -> String {
    match stood_still {
        Some(at) => format!(
            "the files of the index and the journals stood still {} s after the kill; whether the \
             worker's maintenance pass completed was not observed",
            at.as_secs()
        ),
        None => format!(
            "the files of the index and the journals did not stand still within {} s after the \
             kill, so this list is incomplete; whether the worker's maintenance pass completed was \
             not observed",
            timing.at_most.as_secs()
        ),
    }
}

/// What a host holds of a restart: what the case declared and the record made when its agent
/// started.
#[derive(Debug, Default)]
struct Restarts {
    declared: Restart,
    /// The record of the run's tree, made once at the first start of the agent.
    record: Option<Record>,
    /// The watch on the clock floor, made with the record: the mapping is kept from the start.
    clock: Option<Watch>,
    /// What the compares of a restart read: made at the start, kept at each kill.
    verified: Option<Verified>,
    survey: Survey,
}

/// What the compares of a restart hold besides the record made at the start.
#[derive(Debug)]
struct Verified {
    /// The address the configuration document gave at the start, read once.
    address: Option<std::net::SocketAddr>,
    /// The output-time indexes at the start.
    indexes: Looked,
    /// The record and the indexes at the latest kill: what the attempt is compared with.
    kill: Option<(Record, Looked)>,
    /// The tables of the session journals at the latest kill, on a leg where the table check is on.
    tables: Option<Tables>,
    /// What the compares at the kills refused.
    refused: Vec<String>,
    /// How many daemon starts have followed the start's record.
    starts: usize,
}

/// Why one start of the daemon failed.
enum Failed {
    /// The daemon exited before it answered, with what it wrote.
    Exited(String),
    /// The daemon neither exited nor answered in time: what it was last heard to say, and what it
    /// wrote.
    Silent { heard: String, said: String },
}

/// Ends the leg as not run with `said`: the unwinding carries the text to the end of the case.
fn leg_not_run(said: String) -> ! {
    eprintln!("{said}");
    std::panic::resume_unwind(Box::new(LegNotRun(said)))
}

/// A running host.
#[derive(Debug)]
pub struct Host<'r> {
    run: &'r Run,
    paths: HostPaths,
    environment: EnvironmentPaths,
    shell_packages: Option<PathBuf>,
    daemon: Mutex<Option<Daemon>>,
    /// The control socket the daemon bound, by its device and inode, once the daemon has answered:
    /// what `kr` is run against is checked to be that socket, or why it could not be recorded.
    control: Mutex<Option<Result<(i128, i128), String>>>,
    /// Whether the agent under test has been started ([`Host::agent_starts`]).
    agent_started: AtomicBool,
    /// Whether the agent under test is the harness's own stand-in ([`Host::agent_is_a_stand_in`]).
    stand_in: AtomicBool,
    /// The `kr` commands asked for after the agent under test started, each as its arguments: none
    /// is run, and the record shows that none was asked for either.
    kr_after_start: Arc<Mutex<Vec<String>>>,
    /// The restart the case declared and the record of the run's tree made when its agent started.
    restarts: Mutex<Restarts>,
    /// The wall clock and the continuous clock, read before the host's first daemon start: the
    /// anchor of the clock floor's limit.
    anchor: Readings,
}

#[derive(Debug)]
struct Daemon {
    child: std::process::Child,
    identity: ProcessStartIdentity,
}

impl<'r> Host<'r> {
    /// Makes the host tree, writes its configuration document and starts its daemon.
    ///
    /// # Panics
    ///
    /// Panics when the tree cannot be made or the daemon does not answer within [`LIVENESS`], with
    /// what the daemon wrote.
    #[must_use]
    pub fn start(run: &'r Run, options: &HostOptions) -> Self {
        Self::start_prepared(run, options, &Preparation::default(), |_| {})
    }

    /// Makes the host tree, writes its configuration document, lets `seed` put state in the tree
    /// before any daemon has opened it, and starts the daemon.
    ///
    /// # Panics
    ///
    /// Panics when the tree cannot be made or the daemon does not answer within [`LIVENESS`], with
    /// what the daemon wrote.
    #[must_use]
    pub fn start_prepared(
        run: &'r Run,
        options: &HostOptions,
        preparation: &Preparation,
        seed: impl FnOnce(&EnvironmentPaths),
    ) -> Self {
        kr_ipc::testing::account_launchd::require("the host start");
        let paths = HostPaths::new(run.root().join(RUNTIME_ROOT), run.root().join(STATE_ROOT))
            .expect("absolute host roots");
        // The same identity the daemon opens when it starts: it reads the one that is there.
        let environment_id = paths
            .open_environment_id()
            .expect("the environment's identity");
        let environment = paths.environment(environment_id);
        environment.create().expect("the environment's directories");
        let mut port = if preparation.stable_address {
            free_loopback_port()
        } else {
            0
        };
        write_configuration(&environment, &preparation.command_integrations, port);
        seed(&environment);
        let host = Self {
            run,
            paths,
            environment,
            shell_packages: options.shell_packages.clone(),
            daemon: Mutex::new(None),
            control: Mutex::new(None),
            agent_started: AtomicBool::new(false),
            stand_in: AtomicBool::new(false),
            kr_after_start: Arc::default(),
            restarts: Mutex::default(),
            anchor: Readings::now(),
        };
        // The port was free when it was chosen, and it is bound when the daemon starts: other legs
        // choose theirs meanwhile, on this machine and on a shared one, and two can choose alike.
        // A daemon that exited because it could not bind the sockets for the address it was given
        // served nothing (it did record its own start in its state, which nothing here reads), so
        // another port is chosen and the daemon started again; nothing holds the old address yet,
        // because no device has paired.
        for attempt in 1..=PORT_ATTEMPTS {
            match host.start_daemon_once() {
                Ok(()) => return host,
                Err(said)
                    if preparation.stable_address
                        && attempt < PORT_ATTEMPTS
                        && address_was_taken(&said) =>
                {
                    port = free_loopback_port();
                    write_configuration(&host.environment, &preparation.command_integrations, port);
                }
                Err(said) => panic!("the control daemon exited before it answered: {said}"),
            }
        }
        unreachable!("the last attempt returns or panics")
    }

    /// Starts the daemon over the host tree.
    ///
    /// A host that keeps its address cannot take another port, because a device dials the one it
    /// has, and the port is free only until another program binds it. A daemon that exited because
    /// it could not bind the sockets for that address is started again once the address can be
    /// bound, for as many starts as `RESTART_ATTEMPTS` allows in all. A daemon that exits for any
    /// other reason fails the start at once.
    ///
    /// # Panics
    ///
    /// Panics when it does not answer within [`LIVENESS`], or exits before it does, or when the
    /// address stays held for the whole of `ADDRESS_FREE`, or when it cannot be bound in any of the
    /// starts.
    pub fn start_daemon(&self) {
        self.start_daemon_ready_by(&|bound| self.kr_lists(bound));
    }

    /// [`Self::start_daemon`], where the daemon is ready when `ready` says so within the bound it is
    /// given, not when `kr list` answers: after the agent under test has started no `kr` is run.
    ///
    /// A daemon is started after the agent under test started only where that agent is the
    /// harness's own stand-in ([`Host::agent_is_a_stand_in`]), or where the case declared a restart
    /// ([`Host::declares_a_restart`]) and a record was made when the agent started: that start is
    /// `Host::restart_after_a_real_agent`, and it ends the leg as not run where it cannot go on.
    /// The start acts on the run's tree: it
    /// reads the address from the configuration document, opens the log by its path, and starts the
    /// programs placed under `b/` with no check that they are the placed files, and a live agent
    /// runs in the same account and may have changed any of them. The stand-in is the harness's own
    /// program, which changes none, but for the variant that rewrites the run's state for another
    /// host: a run with that variant is not said to be a stand-in here.
    ///
    /// # Panics
    ///
    /// As [`Self::start_daemon`], and when the agent under test has started, is not the stand-in and
    /// no record was made.
    pub fn start_daemon_ready_by(&self, ready: &dyn Fn(Duration) -> Result<(), String>) {
        let real =
            self.agent_started.load(Ordering::SeqCst) && !self.stand_in.load(Ordering::SeqCst);
        let verified = self
            .restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .verified
            .is_some();
        assert!(
            !real || verified,
            "no daemon is started after the agent under test started, unless that agent is the \
             harness's own stand-in: the start acts on the run's tree, which a live agent may have \
             changed"
        );
        if real {
            self.restart_after_a_real_agent(ready, ADDRESS_FREE, LIVENESS);
            return;
        }
        self.survey_before_the_attempt();
        let kept = self
            .configured_address()
            .filter(|address| address.port() != 0);
        for attempt in 1..=RESTART_ATTEMPTS {
            let Err(said) = self.start_daemon_once_ready_by(ready) else {
                return;
            };
            match kept {
                Some(address) if address_was_taken(&said) => {
                    assert!(
                        attempt < RESTART_ATTEMPTS,
                        "the control daemon could not bind {address} in {RESTART_ATTEMPTS} \
                         starts, each after the address could be bound: {said}"
                    );
                    until_the_address_is_free(address);
                }
                _ => panic!("the control daemon exited before it answered: {said}"),
            }
        }
        unreachable!("the last attempt returns or panics")
    }

    /// The address the host's configuration document gives its daemon to bind.
    fn configured_address(&self) -> Option<std::net::SocketAddr> {
        let path = kr_worker::config::document_path(&self.environment);
        let document: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        document["network"]["bind_address"].as_str()?.parse().ok()
    }

    /// Starts the daemon over the host tree once, and returns what it wrote when it exited before
    /// it answered.
    ///
    /// # Panics
    ///
    /// Panics when it does not answer within [`LIVENESS`].
    fn start_daemon_once(&self) -> Result<(), String> {
        kr_ipc::testing::account_launchd::require("the host start");
        self.start_daemon_once_ready_by(&|bound| self.kr_lists(bound))
    }

    /// Whether `kr list` answers within `bound`, and why not where it does not.
    fn kr_lists(&self, bound: Duration) -> Result<(), String> {
        match self.kr_within(&["list", "--json"], bound) {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(format!("kr list ended with {}", output.status)),
            Err(why) => Err(format!("kr list {why}")),
        }
    }

    /// [`Self::start_daemon_once`], ready where `ready` says so.
    fn start_daemon_once_ready_by(
        &self,
        ready: &dyn Fn(Duration) -> Result<(), String>,
    ) -> Result<(), String> {
        match self.start_once(ready, LIVENESS) {
            Ok(()) => Ok(()),
            Err(Failed::Exited(said)) => Err(said),
            Err(Failed::Silent { heard, said }) => {
                panic!("the control daemon did not answer within {LIVENESS:?} ({heard}): {said}")
            }
        }
    }

    /// Starts the daemon over the host tree once and waits up to `liveness` for the readiness that
    /// `ready` names, and says how the start failed where it did.
    fn start_once(
        &self,
        ready: &dyn Fn(Duration) -> Result<(), String>,
        liveness: Duration,
    ) -> Result<(), Failed> {
        kr_ipc::testing::account_launchd::require("the host start");
        *self.control.lock().unwrap_or_else(PoisonError::into_inner) = None;
        // What the log holds before this start is an earlier start's, and is not this one's to say.
        let earlier = std::fs::metadata(self.daemon_log()).map_or(0, |log| log.len());
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.daemon_log())
            .expect("the daemon's log");
        let mut command = Command::new(self.run.binary("kr-controller"));
        command
            .arg("--runtime-dir")
            .arg(self.paths.runtime_root())
            .arg("--state-dir")
            .arg(self.paths.state_root())
            .arg("--secret-store")
            .arg("file")
            .arg("--worker")
            .arg(self.run.binary("kr-worker"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.run.home())
            .env(self.run.mark().0, self.run.mark().1)
            .current_dir(self.run.root())
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("the daemon's log"))
            .stderr(log);
        // What a login gives a daemon so it can reach the user's own service manager. Without
        // them a Linux daemon cannot ask systemd and starts its workers detached instead.
        for inherited in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(inherited) {
                command.env(inherited, value);
            }
        }
        if let Some(packages) = &self.shell_packages {
            command.env("KR_SHELL_PACKAGES", packages);
        }
        let mut child = command.spawn().expect("the daemon starts");
        let Some(identity) = self.run.record_child(child.id(), "the control daemon") else {
            // A daemon that has already exited has no identity to read on some systems. Whether it
            // exited, and what it wrote, is what decides what this start came to.
            return match child.try_wait() {
                Ok(Some(_)) => Err(Failed::Exited(self.daemon_said_since(earlier))),
                _ => panic!("the daemon ended at once: {}", self.daemon_said()),
            };
        };
        *self.daemon.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Daemon { child, identity });
        let answered = Deadline::after(liveness).poll(CLEANUP_COMMAND, ASK_AGAIN, |bound| {
            let heard = match ready(bound) {
                Ok(()) => return ControlFlow::Break(None),
                Err(heard) => heard,
            };
            let ended = self
                .daemon
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
                .is_some_and(|daemon| daemon.child.try_wait().ok().flatten().is_some());
            if ended {
                return ControlFlow::Break(Some(self.daemon_said_since(earlier)));
            }
            ControlFlow::Continue(heard)
        });
        match answered {
            Ok(None) => {
                self.note_control_socket();
                if let Some(verified) = self
                    .restarts
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .verified
                    .as_mut()
                {
                    verified.starts += 1;
                }
                Ok(())
            }
            Ok(Some(said)) => Err(Failed::Exited(said)),
            Err(heard) => Err(Failed::Silent {
                heard,
                said: self.daemon_said(),
            }),
        }
    }

    /// Says that the agent under test is about to be started, as many times as it is started.
    ///
    /// From then on the harness acts on nothing it reads from the run, since the agent runs in the
    /// same account and may leave anything in the run's tree. `kr` reads the environment's identity
    /// and the endpoint it connects to from that tree at every call, so no `kr` is run once the
    /// agent may have started ([`Host::kr_within`] refuses, and [`Host::command`] panics); the host
    /// is stopped, and dropped, by ending what the run recorded by identity instead.
    ///
    /// A case that declared a restart ([`Host::declares_a_restart`]) has the whole tree of the run's
    /// two host roots recorded here, once, at the first call, while the daemon is alive and the
    /// agent has not run: the record is what a later compare takes as the tree before the agent
    /// acted. No record is made for any other case, nor on the stand-in path (the flag set by
    /// [`Host::agent_is_a_stand_in`] comes before this call), except for the survey
    /// ([`Restart::Survey`]), which records on the stand-in too.
    ///
    /// # Panics
    ///
    /// Unwinds with a [`LegNotRun`] when the record cannot be made: the leg ends as not run before
    /// the agent is launched.
    pub fn agent_starts(&self) {
        self.agent_started.store(true, Ordering::SeqCst);
        let made = {
            let mut restarts = self.restarts.lock().unwrap_or_else(PoisonError::into_inner);
            let records = match restarts.declared {
                Restart::Off => false,
                Restart::Declared => !self.stand_in.load(Ordering::SeqCst),
                Restart::Survey => true,
            };
            if !records || restarts.record.is_some() {
                return;
            }
            self.standing().and_then(|(indexes, record)| {
                let clock = self.watch_the_floor()?;
                restarts.verified = Some(Verified {
                    address: self.configured_address(),
                    indexes,
                    kill: None,
                    tables: None,
                    refused: Vec::new(),
                    starts: 0,
                });
                restarts.record = Some(record);
                restarts.clock = Some(clock);
                Ok(())
            })
        };
        if let Err(why) = made {
            let said = format!("no record could be made before the agent started: {why}");
            eprintln!("{said}");
            std::panic::resume_unwind(Box::new(LegNotRun(said)));
        }
    }

    /// The record of the run's tree as it stands: the host's two roots, the run's programs and the
    /// application directory of the run's home where it exists.
    fn record(&self) -> Result<Record, String> {
        Record::of(
            self.run.root(),
            self.run.pin(),
            &REQUIRED_ROOTS,
            &OPTIONAL_ROOTS,
        )
    }

    /// Maps the clock floor as the daemon does and keeps the mapping, with the readings of the
    /// clocks now.
    fn watch_the_floor(&self) -> Result<Watch, String> {
        let path = self.environment.utc_floor_file();
        let relative = path
            .strip_prefix(self.run.root())
            .expect("the clock floor lies below the run's directory");
        let boot = kr_ipc::identity::boot_identity()
            .and_then(|identity| kr_ipc::identity::boot_epoch(&identity))
            .map_err(|why| format!("the clock floor cannot be read at the start: {why}"))?;
        Watch::at_the_start(
            Opening {
                root: self.run.root(),
                pin: self.run.pin(),
                relative,
                path: &path,
            },
            self.environment.environment_id(),
            boot,
            self.anchor,
            Readings::now(),
        )
    }

    /// Says how the case restarts the daemon after its agent has started. A case calls it before
    /// its agent starts ([`Host::agent_starts`]); a case that does not call it declares none.
    pub fn declares_a_restart(&self, how: Restart) {
        self.restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .declared = how;
    }

    /// Says that the agent under test is the harness's own stand-in, which runs none of the run's
    /// programs and changes nothing of its tree: only then does [`Host::start_daemon_ready_by`]
    /// start a daemon after [`Host::agent_starts`]. A stand-in variant that rewrites the run's
    /// state, as the one that leaves for another host does, is not that: the caller does not say it.
    pub fn agent_is_a_stand_in(&self) {
        self.stand_in.store(true, Ordering::SeqCst);
    }

    /// The record of the `kr` commands asked for after the agent under test started, which the
    /// record outlives the host to show: it holds nothing when none was asked for.
    #[must_use]
    pub fn kr_after_the_agent_started(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.kr_after_start)
    }

    /// Whether `kr` is asked for after the agent under test started, which it is never given.
    fn kr_is_refused(&self, arguments: &[&str]) -> bool {
        let started = self.agent_started.load(Ordering::SeqCst);
        if started {
            self.kr_after_start
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(arguments.join(" "));
        }
        started
    }

    /// The run this host belongs to.
    #[must_use]
    pub const fn run(&self) -> &'r Run {
        self.run
    }

    /// The environment this host serves.
    #[must_use]
    pub fn environment_id(&self) -> EnvironmentId {
        self.environment.environment_id()
    }

    /// The environment's directories.
    #[must_use]
    pub const fn environment(&self) -> &EnvironmentPaths {
        &self.environment
    }

    /// The host's runtime and state roots, which `kr` is pointed at.
    #[must_use]
    pub const fn roots(&self) -> &HostPaths {
        &self.paths
    }

    /// The daemon's identity.
    #[must_use]
    pub fn daemon_identity(&self) -> Option<ProcessStartIdentity> {
        self.daemon
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|daemon| daemon.identity.clone())
    }

    /// The place of the daemon's control socket below the run's directory.
    fn control_socket_place(&self) -> Result<PathBuf, String> {
        let endpoint = self
            .environment
            .controller_endpoint()
            .map_err(|error| format!("the control socket has no place: {error}"))?;
        endpoint
            .as_path()
            .strip_prefix(self.run.root())
            .map(Path::to_path_buf)
            .map_err(|_| "the control socket is not below the run's directory".to_owned())
    }

    /// Records the control socket the daemon bound, by its device and inode, found by a walk from
    /// the run's pinned directory that follows no link, or why it could not be. A test that puts
    /// its own socket at the daemon's name, or puts the daemon's back, records the one that stands
    /// there by this.
    pub(crate) fn note_control_socket(&self) {
        let found = self.control_socket_place().and_then(|place| {
            socket_below(self.run.root(), self.run.pin(), &place)
                .map_err(|why| format!("the control socket cannot be recorded: {why}"))?
                .ok_or_else(|| "the control socket is not there".to_owned())
        });
        *self.control.lock().unwrap_or_else(PoisonError::into_inner) = Some(found);
    }

    /// Checks that the control socket `kr` will use is the one the daemon bound: the same device and
    /// inode, found again by a walk from the pin that follows no link. Before the daemon has
    /// answered there is none to check.
    fn control_socket_is_the_daemons(&self) -> Result<(), String> {
        let Some(recorded) = self
            .control
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return Ok(());
        };
        let recorded = recorded?;
        match socket_below(
            self.run.root(),
            self.run.pin(),
            &self.control_socket_place()?,
        ) {
            Ok(Some(now)) if now == recorded => Ok(()),
            Ok(Some(_)) => Err("the control socket is not the one the daemon bound".to_owned()),
            Ok(None) => Err("the control socket the daemon bound is gone".to_owned()),
            Err(why) => Err(format!(
                "the control socket cannot be looked at as the daemon's: {why}"
            )),
        }
    }

    fn daemon_log(&self) -> PathBuf {
        self.run.root().join(DAEMON_LOG)
    }

    /// What the daemon wrote after its log was `earlier` bytes long, the last forty lines of it.
    ///
    /// The log is read through the run's handles ([`read_tail_below`]), so a link or a second name
    /// left in its place gives a class and no line of the file it names.
    fn daemon_said_since(&self, earlier: u64) -> String {
        let bytes = match read_tail_below(
            self.run.root(),
            self.run.pin(),
            Path::new(DAEMON_LOG),
            earlier,
        ) {
            Ok(bytes) => bytes.unwrap_or_default(),
            Err(why) => return format!("the daemon's log was not read: {why}"),
        };
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(40);
        lines[start..].join("\n")
    }

    /// The last of what the daemon wrote, for a failure message.
    #[must_use]
    pub fn daemon_said(&self) -> String {
        self.daemon_said_since(0)
    }

    /// What the worker of `session_id` said to its own standard error, for a failure message: the
    /// last forty lines of its diagnostics file (`jobs/<label>.diagnostics` in the state directory),
    /// each cleaned and cut as a worker cuts a refusal's reason. A launch refused before its
    /// credential authenticates leaves only its line there.
    ///
    /// The label is the one the run kept while the worker ran ([`Run::worker_of`]), so a worker that
    /// has ended is read too, and no other session's file is. The file is read through the run's
    /// handles ([`read_tail_below`]), as the daemon's log is.
    #[must_use]
    pub fn worker_said(&self, session_id: &str) -> String {
        match self.environment.jobs_dir().strip_prefix(self.run.root()) {
            Ok(jobs) => worker_diagnostics_of(self.run, jobs, session_id),
            Err(_) => diagnostics_not_read("the jobs directory is not below the run's directory"),
        }
    }

    /// The identity of the worker process that serves `session_id`: the process running this run's
    /// copy of `kr-worker` for that session ([`Run::worker_of`]).
    ///
    /// # Panics
    ///
    /// Panics when no such process is in the process table within [`LIVENESS`].
    #[must_use]
    pub fn worker_of(&self, session_id: &str) -> ProcessStartIdentity {
        self.run.worker_of(session_id)
    }

    /// Records every worker this host started, with everything that runs beneath it, by start
    /// identity.
    ///
    /// A worker is found in the process table by its command line, whose program is exactly the
    /// worker this run placed and which names the session it serves, and is recorded as the run's
    /// own only then ([`Run::record_worker`]). That needs nothing of the host, so a leg that stops part
    /// way still reaches the sessions it made, their shells and what runs in them, whether or not
    /// the daemon still answers, and no file of the host's is opened. A search that does not finish
    /// is kept with the run, whose closing check then fails rather than report a search that did
    /// not finish, and it is tried again within `DISCOVERY` so that the run can still end what a
    /// later search finds. A later search that finishes does not clear the earlier failure: what
    /// the earlier one missed may since have left the tree it searched.
    pub fn record_workers(&self) {
        let started = Instant::now();
        loop {
            match self.discover_workers() {
                Ok(()) => return,
                Err(why) => {
                    self.run.undiscovered(&why);
                    if started.elapsed() >= DISCOVERY {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }

    fn discover_workers(&self) -> Result<(), String> {
        let table = processes_under(self.run.root())?;
        // The job each worker runs as is learned while the worker runs: its label is the one the
        // service manager is asked about at the close.
        self.run
            .propose_jobs_from(table.iter().map(|(_, command)| command.as_str()));
        let program = self.run.binary("kr-worker");
        for (pid, command) in table {
            let Some(session) = worker_session(&command, &program) else {
                continue;
            };
            let what = format!("the worker of session {session}");
            match self.run.record_worker(pid, &what, session) {
                Some(identity) => self
                    .run
                    .record_descendants(&identity, &format!("under {what}"))?,
                // Ended since the table was read, or not the process the table named any more.
                None if matches!(query_process(pid), ProcessQuery::Gone) => {}
                None => {
                    return Err(format!(
                        "process {pid}, which runs {what}, could not be recorded"
                    ));
                }
            }
        }
        Ok(())
    }

    /// The environment every `kr` this host runs is given, and nothing else.
    ///
    /// It names the managed shell packages when the host has them, so `kr shell` sees the
    /// packages the daemon resolves sessions from.
    #[must_use]
    pub fn variables(&self) -> Vec<(String, String)> {
        let mut variables = vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
            ("HOME".to_owned(), self.run.home().display().to_string()),
            (
                "KR_RUNTIME_DIR".to_owned(),
                self.paths.runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR".to_owned(),
                self.paths.state_root().display().to_string(),
            ),
        ];
        if let Some(packages) = &self.shell_packages {
            variables.push((
                "KR_SHELL_PACKAGES".to_owned(),
                packages.display().to_string(),
            ));
        }
        // Every program the run starts has it, the sessions' shells and the agent among them: they
        // are created with the environment these variables make.
        let (name, value) = self.run.mark();
        variables.push((name.to_owned(), value.to_owned()));
        variables
    }

    /// A `kr` command with this host's environment, run in the run's own directory.
    ///
    /// # Panics
    ///
    /// Panics once the agent under test has started ([`Host::agent_starts`]).
    #[must_use]
    pub fn command(&self, arguments: &[&str]) -> Command {
        assert!(
            !self.kr_is_refused(arguments),
            "kr {arguments:?} is not run once the agent under test has started"
        );
        let mut command = Command::new(self.run.binary("kr"));
        command
            .args(arguments)
            .env_clear()
            .envs(self.variables())
            .current_dir(self.run.root());
        command
    }

    /// Runs `kr` with nothing on its input and waits at most `within` for it.
    ///
    /// The program is run only while it is the file that was placed in the run, and against the
    /// control socket the daemon bound: the agent under test runs in the same account and may leave
    /// anything in the run's tree, and `kr` runs with the person's own rights.
    ///
    /// # Errors
    ///
    /// Returns why it was not run or did not finish; it is never run once the agent under test has
    /// started ([`Host::agent_starts`]).
    pub fn kr_within(&self, arguments: &[&str], within: Duration) -> Result<Output, String> {
        if self.kr_is_refused(arguments) {
            return Err("the agent under test has started, and no kr is run after it".to_owned());
        }
        self.run.placed_as_it_was(&binary_place(HARNESS_PROGRAM))?;
        self.control_socket_is_the_daemons()?;
        output_within(self.command(arguments), within)
    }

    /// Runs `kr` and waits for it within [`LIVENESS`].
    ///
    /// # Panics
    ///
    /// Panics when it does not finish.
    #[must_use]
    pub fn kr(&self, arguments: &[&str]) -> Output {
        self.kr_within(arguments, LIVENESS)
            .unwrap_or_else(|error| panic!("kr {arguments:?}: {error}"))
    }

    /// Runs `kr --json`, requires it to succeed, and returns what it printed.
    ///
    /// # Panics
    ///
    /// Panics when it fails or prints something that is not one document.
    #[must_use]
    pub fn kr_json(&self, arguments: &[&str]) -> Value {
        let mut arguments = arguments.to_vec();
        arguments.push("--json");
        let output = self.kr(&arguments);
        assert!(
            output.status.success(),
            "kr {arguments:?} exited {:?}: {}{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        document(&output.stdout)
            .unwrap_or_else(|error| panic!("kr {arguments:?} printed no document: {error}"))
    }

    /// The live sessions, as `kr list` reports them.
    ///
    /// # Panics
    ///
    /// Panics when `kr list` does not answer with a list of sessions: an answer without one has
    /// not said that there are none.
    #[must_use]
    pub fn live_sessions(&self) -> Vec<Value> {
        let listed = self.kr_json(&["list"]);
        listed["sessions"].as_array().cloned().unwrap_or_else(|| {
            panic!("kr list answered something that is not a list of sessions: {listed}")
        })
    }

    /// Waits for `kr status` to report a session closed, and returns that report.
    ///
    /// The whole wait has one deadline, [`LIVENESS`] from now, and each `kr status` is given what
    /// is left of it.
    ///
    /// # Panics
    ///
    /// Panics when it is not closed within [`LIVENESS`], with what the last `kr status` said.
    #[must_use]
    pub fn wait_until_closed(&self, display: &str) -> Value {
        until_closed(LIVENESS, |bound| {
            self.kr_within(&["status", display, "--json"], bound)
        })
        .unwrap_or_else(|heard| {
            panic!("session {display} did not close within {LIVENESS:?}: {heard}")
        })
    }

    /// Closes every live session, waits for its worker and job to go, then stops the daemon.
    ///
    /// # Errors
    ///
    /// Returns what did not end as it should. The daemon is stopped whatever happened before.
    pub fn stop(&self) -> Result<(), String> {
        self.record_workers();
        if self.agent_started.load(Ordering::SeqCst) {
            return self.end_by_identity();
        }
        let mut problems = Vec::new();
        if let Err(problem) = self.close_sessions() {
            problems.push(problem);
        }
        // A closed session's worker ends and the daemon then removes its job, so the daemon stays
        // up until the jobs it defined are gone.
        let started = Instant::now();
        while started.elapsed() < RETIREMENT
            && !self.run.loaded_jobs().is_ok_and(|loaded| loaded.is_empty())
        {
            std::thread::sleep(Duration::from_millis(500));
        }
        match self.run.loaded_jobs() {
            Ok(loaded) if loaded.is_empty() => {}
            Ok(loaded) => problems.push(format!(
                "the daemon had not removed these jobs within {RETIREMENT:?}: {}",
                loaded.join(", ")
            )),
            Err(why) => problems.push(why),
        }
        if let Err(problem) = self.stop_daemon() {
            problems.push(problem);
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Ends what the run started, once the agent under test has started, by what the run recorded
    /// before: the daemon is interrupted by its identity, the jobs the service manager shows to run
    /// this run's worker are removed, and every recorded process (the workers, and the shells and
    /// the agent beneath them, which [`Host::record_workers`] found in the process table) is ended
    /// by its start identity. Nothing `kr` prints, and no file of the run, decides what is ended.
    ///
    /// # Errors
    ///
    /// Returns what did not end as it should.
    fn end_by_identity(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        if let Err(problem) = self.stop_daemon() {
            problems.push(problem);
        }
        self.run.remove_loaded_jobs();
        self.run.end_everything();
        // A job the service manager started again while the workers ended is removed as well.
        self.run.remove_loaded_jobs();
        match self.run.loaded_jobs() {
            Ok(loaded) if loaded.is_empty() => {}
            Ok(loaded) => problems.push(format!(
                "these jobs of the run's workers are still loaded: {}",
                loaded.join(", ")
            )),
            Err(why) => problems.push(why),
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    /// Closes every live session and waits until `kr list` names none.
    ///
    /// Listing, closing and waiting share one deadline, [`LIVENESS`] from the start (see
    /// [`close_all`]).
    fn close_sessions(&self) -> Result<(), String> {
        close_all(
            LIVENESS,
            |bound| self.listed_sessions(bound),
            |display, bound| self.kr_within(&["close", display, "--json"], bound),
        )
    }

    /// The sessions `kr list` names, asked within `bound`.
    ///
    /// # Errors
    ///
    /// Returns why the list was not read: a `kr` that did not answer, failed or answered something
    /// that is not a list of sessions has not said that there are none.
    fn listed_sessions(&self, bound: Duration) -> Result<Vec<Value>, String> {
        let output = self
            .kr_within(&["list", "--json"], bound)
            .map_err(|why| format!("the daemon did not list its sessions: {why}"))?;
        if !output.status.success() {
            return Err(format!(
                "the daemon did not list its sessions: kr list ended with {}",
                output.status
            ));
        }
        document(&output.stdout)
            .ok()
            .and_then(|listed| listed["sessions"].as_array().cloned())
            .ok_or_else(|| "kr list answered something that is not a list of sessions".to_owned())
    }

    /// Kills the daemon with nothing said to it, as a crash does, and waits until it has gone.
    /// The sessions it started go on; [`Self::start_daemon`] starts a daemon over the same tree.
    ///
    /// Where the agent under test has started and is not the stand-in, the workers and what runs
    /// beneath them are recorded before this returns ([`Host::record_workers`]): a case that ends a
    /// worker next leaves the agent running beneath it, and only a record made while the worker
    /// lived lets the host end the agent.
    ///
    /// # Panics
    ///
    /// Panics when the daemon is not running or does not end within twenty seconds.
    pub fn kill_daemon(&self) {
        let mut daemon = self
            .daemon
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("a running daemon to kill");
        signal(&daemon.identity, rustix::process::Signal::KILL);
        assert!(
            ended_within(&daemon.identity, DAEMON_STOP),
            "the control daemon did not end within {DAEMON_STOP:?} of being killed"
        );
        let _ = daemon.child.wait();
        self.survey_the_kill();
        self.verify_the_kill();
        if self.agent_started.load(Ordering::SeqCst) && !self.stand_in.load(Ordering::SeqCst) {
            self.record_workers();
        }
    }

    /// The survey's look at the tree at a kill ([`Restart::Survey`]): the record at the kill, and
    /// what differs between it and the record made when the agent started, said in one line for
    /// each entry. Nothing is refused.
    fn survey_the_kill(&self) {
        let mut restarts = self.restarts.lock().unwrap_or_else(PoisonError::into_inner);
        if restarts.declared != Restart::Survey {
            return;
        }
        let Some(start) = restarts.record.clone() else {
            return;
        };
        restarts.survey.kills += 1;
        let kill = restarts.survey.kills;
        let killed = Instant::now();
        match self.record() {
            Ok(now) => {
                let changes = start.changes_to(&now);
                let lines = changes
                    .iter()
                    .map(|change| format!("survey: kill {kill}, at the kill: {change}"))
                    .collect();
                restarts.survey.changes_to_the_kill = changes.len();
                restarts.survey.at_the_kill = Some((killed, now));
                restarts.survey.say(lines);
            }
            Err(why) => {
                restarts.survey.at_the_kill = None;
                restarts.survey.say(vec![format!(
                    "survey: kill {kill}: the record at the kill could not be made: {why}"
                )]);
            }
        }
    }

    /// The survey's look at the tree before the attempt to start the daemon ([`Restart::Survey`]):
    /// it waits until the worker's maintenance has had its beats and the files it writes stand
    /// still, or the bound passes, and then says what differs between the record made at the kill
    /// and the tree, and each change that the compares of the kill and of the attempt refuse.
    /// Nothing is refused here: the start goes on.
    fn survey_before_the_attempt(&self) {
        let (timing, kill, killed, at_the_kill, to_the_kill) = {
            let restarts = self.restarts.lock().unwrap_or_else(PoisonError::into_inner);
            if restarts.declared != Restart::Survey {
                return;
            }
            let Some((killed, record)) = restarts.survey.at_the_kill.clone() else {
                return;
            };
            (
                restarts.survey.timing,
                restarts.survey.kills,
                killed,
                record,
                restarts.survey.changes_to_the_kill,
            )
        };
        let stood_still = self.survey_waits(timing, killed);
        let lines = match self.record() {
            Ok(now) => {
                let changes = at_the_kill.changes_to(&now);
                let state = standing_still_said(timing, stood_still);
                let mut lines: Vec<String> = changes
                    .iter()
                    .map(|change| format!("survey: kill {kill}, before the attempt: {change}"))
                    .collect();
                let refused = self.verify_before_the_attempt();
                lines.extend(
                    refused
                        .iter()
                        .map(|line| format!("survey: kill {kill}, refused: {line}")),
                );
                lines.push(format!(
                    "survey: kill {kill}: {to_the_kill} change(s) from the agent's start to the \
                     kill and {} from the kill to the attempt; {state}",
                    changes.len()
                ));
                lines
            }
            Err(why) => vec![format!(
                "survey: kill {kill}: the record before the attempt could not be made: {why}; \
                 this list is incomplete"
            )],
        };
        let mut restarts = self.restarts.lock().unwrap_or_else(PoisonError::into_inner);
        restarts.survey.at_the_kill = None;
        restarts.survey.say(lines);
    }

    /// The tables of the journals of the sessions that `record` holds, as they stand, read through
    /// copies in a directory of the run outside both host roots.
    fn look_at_the_journals(&self, record: &Record) -> Tables {
        let layout = Layout::of(self.run.root(), &self.environment);
        let place = Place {
            root: self.run.root(),
            pin: self.run.pin(),
        };
        tables::look(
            &layout,
            place,
            &self.run.root().join("i"),
            &tables::sessions_of(&layout, record),
        )
    }

    fn place(&self) -> Place<'_> {
        Place {
            root: self.run.root(),
            pin: self.run.pin(),
        }
    }

    /// The output-time indexes and the record of the run's tree as they stand. The indexes are
    /// copied before the tree is listed, so that a row pruned between the two is not taken as lost.
    fn standing(&self) -> Result<(Looked, Record), String> {
        let layout = Layout::of(self.run.root(), &self.environment);
        let known = self.record()?;
        let indexes = index::look(
            &layout,
            self.place(),
            &self.run.root().join("i"),
            &index::sessions_of(&layout, &known),
        );
        Ok((indexes, self.record()?))
    }

    /// What lies outside the two roots and can change what a restarted daemon runs or reads: the
    /// Git it would run, the values it inherits, the shell packages and its log.
    fn outside_refusals(&self) -> Vec<String> {
        let inherited = [
            ("XDG_RUNTIME_DIR", std::env::var_os("XDG_RUNTIME_DIR")),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                std::env::var_os("DBUS_SESSION_BUS_ADDRESS"),
            ),
        ];
        let log = self.daemon_log();
        Outside {
            run_root: self.run.root(),
            pin: self.run.pin(),
            search_path: "/usr/bin:/bin",
            inherited: &inherited,
            shell_packages: self.shell_packages.as_deref(),
            log: log.strip_prefix(self.run.root()).unwrap_or(&log),
        }
        .refusals()
    }

    /// At a kill of a real agent's host: compares the tree with the record made at the start and
    /// keeps what the attempt is compared with. What it refuses is held until the attempt.
    fn verify_the_kill(&self) {
        let mut guard = self.restarts.lock().unwrap_or_else(PoisonError::into_inner);
        let restarts = &mut *guard;
        let (Some(verified), Some(watch), Some(start)) = (
            restarts.verified.as_mut(),
            restarts.clock.as_mut(),
            restarts.record.as_ref(),
        ) else {
            return;
        };
        let (indexes, record) = match self.standing() {
            Ok(standing) => standing,
            Err(why) => {
                verified
                    .refused
                    .push(format!("the record at the kill could not be made: {why}"));
                verified.kill = None;
                return;
            }
        };
        let layout = Layout::of(self.run.root(), &self.environment);
        let interval = Interval::AtTheKill {
            restarted: verified.starts > 0,
        };
        let uid = rustix::process::getuid().as_raw();
        let compared = compare::compare(&layout, self.place(), start, &record, interval, uid);
        verified
            .refused
            .extend(compared.refusals.iter().map(ToString::to_string));
        verified.refused.extend(self.outside_refusals());
        let readings = Readings::now();
        verified.refused.extend(watch.at_the_kill(readings));
        verified.refused.extend(
            index::compare(
                &layout,
                &verified.indexes,
                &indexes,
                &record,
                watch.limit(readings),
            )
            .iter()
            .map(ToString::to_string),
        );
        if tables::applies(self.stand_in.load(Ordering::SeqCst)) {
            verified.tables = Some(self.look_at_the_journals(&record));
        }
        verified.kill = Some((record, indexes));
    }

    /// Before the attempt on a real agent's host: compares the tree with the record made at the
    /// kill, and returns every refusal, those of the kills included.
    fn verify_before_the_attempt(&self) -> Vec<String> {
        let mut guard = self.restarts.lock().unwrap_or_else(PoisonError::into_inner);
        let restarts = &mut *guard;
        let (Some(verified), Some(watch)) = (restarts.verified.as_mut(), restarts.clock.as_mut())
        else {
            return Vec::new();
        };
        let mut refused = std::mem::take(&mut verified.refused);
        let Some((killed, killed_indexes)) = verified.kill.clone() else {
            refused.push("the record at the kill was not made".to_owned());
            return refused;
        };
        let (indexes, record) = match self.standing() {
            Ok(standing) => standing,
            Err(why) => {
                refused.push(format!(
                    "the record before the attempt could not be made: {why}"
                ));
                return refused;
            }
        };
        let layout = Layout::of(self.run.root(), &self.environment);
        let uid = rustix::process::getuid().as_raw();
        let compared = compare::compare(
            &layout,
            self.place(),
            &killed,
            &record,
            Interval::BeforeTheAttempt,
            uid,
        );
        refused.extend(compared.refusals.iter().map(ToString::to_string));
        refused.extend(self.outside_refusals());
        let readings = Readings::now();
        refused.extend(watch.before_the_attempt(readings));
        if let Err(why) = watch.open_again(
            &self.environment.utc_floor_file(),
            self.environment.environment_id(),
        ) {
            refused.push(why);
        }
        refused.extend(
            index::compare(
                &layout,
                &killed_indexes,
                &indexes,
                &record,
                watch.limit(readings),
            )
            .iter()
            .map(ToString::to_string),
        );
        if let Some(before) = &verified.tables {
            refused.extend(
                tables::compare(&layout, before, &self.look_at_the_journals(&record))
                    .iter()
                    .map(ToString::to_string),
            );
        }
        refused
    }

    /// The one start of the daemon after a real agent started: the address must be free, every
    /// compare must pass, and the daemon must answer. A leg that fails any of them ends as not run
    /// before another start is tried.
    fn restart_after_a_real_agent(
        &self,
        ready: &dyn Fn(Duration) -> Result<(), String>,
        address_bound: Duration,
        liveness: Duration,
    ) {
        let address = self
            .restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .verified
            .as_ref()
            .and_then(|verified| verified.address)
            .filter(|address| address.port() != 0);
        if let Some(address) = address
            && let Err(why) = address_is_free(address, address_bound)
        {
            leg_not_run(format!("the address was not free: {why}"));
        }
        let refused = self.verify_before_the_attempt();
        if !refused.is_empty() {
            leg_not_run(format!("the restart was refused: {}", refused.join("; ")));
        }
        match self.start_once(ready, liveness) {
            Ok(()) => {}
            Err(Failed::Exited(said)) => leg_not_run(format!(
                "the control daemon did not start after the kill: {said}"
            )),
            Err(Failed::Silent { heard, said }) => leg_not_run(format!(
                "the control daemon did not start after the kill: it did not answer within \
                 {liveness:?} ({heard}): {said}"
            )),
        }
    }

    /// Waits after a kill for the files that the worker's maintenance writes to stand still: the
    /// time `timing` gives for the wait, then looks `timing.apart` apart until two looks agree.
    /// Returns the time after the kill at which two looks agreed, or `None` where the bound passed
    /// first.
    fn survey_waits(&self, timing: SurveyTiming, killed: Instant) -> Option<Duration> {
        wait_for_standing_still(timing, killed, || self.survey_view())
    }

    /// The entries the survey watches for standing still, as they are now, or `None` where the
    /// tree cannot be recorded.
    fn survey_view(&self) -> Option<Vec<(PathBuf, Entry)>> {
        let record = self.record().ok()?;
        Some(
            record
                .entries()
                .filter(|(path, _)| survey_watches(path))
                .map(|(path, entry)| (path.to_path_buf(), entry.clone()))
                .collect(),
        )
    }

    fn stop_daemon(&self) -> Result<(), String> {
        let Some(mut daemon) = self
            .daemon
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return Ok(());
        };
        // The daemon's own ending: it serves until it is interrupted.
        signal(&daemon.identity, rustix::process::Signal::INT);
        if !ended_within(&daemon.identity, DAEMON_STOP) {
            signal(&daemon.identity, rustix::process::Signal::KILL);
            let _ = daemon.child.wait();
            return Err(format!(
                "the control daemon did not stop within {DAEMON_STOP:?} of being interrupted"
            ));
        }
        let status = daemon.child.wait().map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "the control daemon ended with {status}: {}",
                self.daemon_said()
            ))
        }
    }
}

impl Drop for Host<'_> {
    fn drop(&mut self) {
        let running = self
            .daemon
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|daemon| running(&daemon.identity));
        // A leg that failed before it stopped its host. Whatever the host started is recorded
        // first, from the process table, so the run can end it even when the daemon no longer
        // answers; then the same order as a clean stop, bounded, or, where the agent under test has
        // started, the ending by identity.
        self.record_workers();
        if self.agent_started.load(Ordering::SeqCst) {
            let _ = self.end_by_identity();
        } else if running {
            let _ = self.close_sessions();
            let _ = self.stop_daemon();
        }
    }
}

/// How many times a host with a stable address is given a port before the daemon's refusal of it is
/// reported. It ends a hang: each refusal is taken to be a port another leg chose at the same moment.
const PORT_ATTEMPTS: usize = 5;

/// How many times a daemon is started on the address a paired device keeps, and cannot change, before
/// the daemon's refusal of it is reported. It ends a hang: each refusal is taken to be a program that
/// holds the address for a moment, and the address is waited for before the next start.
const RESTART_ATTEMPTS: usize = 5;

/// How long a daemon's address is waited for when another program holds it, before the leg is told
/// it stayed held. It ends a hang: the wait is over when the address can be bound.
const ADDRESS_FREE: Duration = Duration::from_secs(20);

/// How long the wait for a daemon's address pauses between two tries to bind it.
const ADDRESS_ASK_AGAIN: Duration = Duration::from_millis(200);

/// Returns once a socket can be bound to `address`, and lets it go again. The daemon that stood on
/// the address or the program that took it after it has not always let it go.
///
/// # Panics
///
/// Panics when the address stays held for [`ADDRESS_FREE`], or cannot be bound for another reason.
fn until_the_address_is_free(address: std::net::SocketAddr) {
    address_is_free(address, ADDRESS_FREE).unwrap_or_else(|why| panic!("{why}"));
}

/// `until_the_address_is_free` with a bound of its own, saying why where the address is not free.
fn address_is_free(address: std::net::SocketAddr, bound: Duration) -> Result<(), String> {
    let free =
        Deadline::after(bound).poll(
            bound,
            ADDRESS_ASK_AGAIN,
            |_| match std::net::UdpSocket::bind(address) {
                Ok(socket) => {
                    drop(socket);
                    ControlFlow::Break(None)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    ControlFlow::Continue(error.to_string())
                }
                Err(error) => ControlFlow::Break(Some(format!(
                    "the daemon's address {address} cannot be bound: {error}"
                ))),
            },
        );
    match free {
        Ok(None) => Ok(()),
        Ok(Some(why)) => Err(why),
        Err(heard) => Err(format!(
            "the daemon's address {address} stayed held for {bound:?}: {heard}"
        )),
    }
}

/// A loopback port nothing holds now; the daemon binds it at each start, and the address a paired
/// device holds stays the address the host answers on.
fn free_loopback_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("a free loopback port")
        .local_addr()
        .expect("its address")
        .port()
}

/// What the transport says when the sockets of its endpoint cannot be bound, which is the one way a
/// taken address makes a bind fail. Its other bind failures (the QUIC endpoint, the network
/// monitor, the TLS configuration) are not words of a taken address.
const SOCKETS_NOT_BOUND: &str = "Failed to bind sockets";

/// Whether what a daemon wrote says it exited because it could not bind the sockets for its
/// configured address. A port another leg chose is the reason this harness knows of.
fn address_was_taken(said: &str) -> bool {
    said.contains("network.bind_address")
        && said.contains("could not be bound")
        && said.contains(SOCKETS_NOT_BOUND)
}

/// Writes the environment's configuration document: this host joins the network on loopback, with
/// no relay and no discovery service.
fn write_configuration(environment: &EnvironmentPaths, command_integrations: &[String], port: u16) {
    let path = kr_worker::config::document_path(environment);
    let mut document = serde_json::json!({
        "version": 1,
        "revision": 1,
        "network": {
            "enabled": true,
            "bind_address": format!("127.0.0.1:{port}"),
            "local_discovery": false,
            "mainline_dht": false,
        },
    });
    if !command_integrations.is_empty() {
        document["preferences"] =
            serde_json::json!({ "command_integrations": command_integrations });
    }
    kr_ipc::paths::write_owner_only_file(
        &path,
        serde_json::to_vec_pretty(&document)
            .expect("a document")
            .as_slice(),
    )
    .unwrap_or_else(|error| panic!("the configuration document {}: {error}", path.display()));
}

/// Reads one JSON document out of what a command printed.
///
/// # Errors
///
/// Returns why it is not one.
pub fn document(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| {
        format!(
            "{error}: {}",
            String::from_utf8_lossy(bytes)
                .chars()
                .take(2000)
                .collect::<String>()
        )
    })
}

/// Quotes a path for a POSIX shell line.
///
/// # Panics
///
/// Panics for a path with a quote in it, which no path a leg makes has.
#[must_use]
pub fn quoted(path: &Path) -> String {
    let text = path.display().to_string();
    assert!(
        !text.contains('\''),
        "a quoted path has no quote in it: {text}"
    );
    format!("'{text}'")
}

/// What a worker puts before a line it says to its standard error.
const WORKER_LINE_PREFIX: &str = "kr-worker: a launch was not admitted: ";

/// The most bytes of one diagnostics line a report keeps: the prefix of a refused launch's line and
/// what a worker cuts a refusal's reason to.
const WORKER_LINE_AT_MOST: usize = WORKER_LINE_PREFIX.len() + 512;

/// The last forty lines of a worker's diagnostics file, each with its control characters replaced
/// by spaces and cut to [`WORKER_LINE_AT_MOST`] bytes at a character boundary, so that the whole of
/// a reason a worker cut to 512 bytes is there.
fn worker_lines(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(40);
    lines[start..]
        .iter()
        .map(|line| {
            let mut cleaned: String = line
                .chars()
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect();
            if cleaned.len() > WORKER_LINE_AT_MOST {
                let mut end = WORKER_LINE_AT_MOST;
                while !cleaned.is_char_boundary(end) {
                    end -= 1;
                }
                cleaned.truncate(end);
            }
            cleaned
        })
        .collect()
}

/// What a report says of the diagnostics file of the worker with `label`: its last lines, or that
/// there is no file, or that it is empty, or why it was not read.
fn worker_diagnostics_text(label: &str, read: Result<Option<Vec<u8>>, String>) -> String {
    match read {
        Ok(Some(bytes)) => {
            let lines = worker_lines(&bytes);
            if lines.is_empty() {
                "(the file is empty)".to_owned()
            } else {
                lines.join("\n")
            }
        }
        Ok(None) => format!("(no file at jobs/{label}.diagnostics)"),
        Err(why) => diagnostics_not_read(&why),
    }
}

/// What a report says when a worker's diagnostics could not be read.
fn diagnostics_not_read(why: &str) -> String {
    format!("(the worker's diagnostics were not read: {why})")
}

/// What a report says of the diagnostics of the worker of `session_id`: its label's file below
/// `jobs` (relative to the run's directory), or that the run has no such worker.
fn worker_diagnostics_of(run: &Run, jobs: &Path, session_id: &str) -> String {
    let Some(label) = run.worker_label_of(session_id) else {
        return "(no worker of this run is in the process table)".to_owned();
    };
    let place = jobs.join(format!("{label}.diagnostics"));
    let read = read_tail_below(run.root(), run.pin(), &place, 0).map_err(|why| why.to_string());
    format!("{label}:\n{}", worker_diagnostics_text(&label, read))
}

/// What the lines of a worker's diagnostics file read as in a report.
#[cfg(test)]
mod worker_diagnostics_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!("kr-host-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        directory
    }

    #[test]
    fn the_last_forty_lines_are_kept_each_cleaned_and_cut() {
        let whole = format!("{WORKER_LINE_PREFIX}{}", "a".repeat(512));
        let mut file = String::new();
        for number in 0..45 {
            file.push_str(&format!("line {number}\n"));
        }
        file.push_str(&format!("{whole}\n"));
        file.push_str(&format!(
            "{WORKER_LINE_PREFIX}the file\u{1b}[31m\tcould not {}\n",
            "\u{e9}".repeat(600)
        ));
        let lines = worker_lines(file.as_bytes());
        assert_eq!(lines.len(), 40, "the last forty");
        assert_eq!(lines[0], "line 7", "the earlier lines are dropped");
        assert_eq!(
            lines[38], whole,
            "a reason cut to 512 bytes is kept whole after its prefix"
        );
        let last = lines.last().expect("a last line");
        assert!(
            last.starts_with(&format!("{WORKER_LINE_PREFIX}the file [31m could not ")),
            "{last}"
        );
        assert!(last.len() <= WORKER_LINE_AT_MOST, "{}", last.len());
        assert!(last.chars().all(|character| !character.is_control()));
    }

    #[test]
    fn a_missing_an_empty_and_an_unread_diagnostics_file_are_said_apart() {
        let label = "kr-worker-00000001-0000-4000-8000-000000000001";
        assert_eq!(
            worker_diagnostics_text(label, Ok(None)),
            format!("(no file at jobs/{label}.diagnostics)")
        );
        assert_eq!(
            worker_diagnostics_text(label, Ok(Some(Vec::new()))),
            "(the file is empty)"
        );
        assert_eq!(
            worker_diagnostics_text(label, Err("no such file".to_owned())),
            "(the worker's diagnostics were not read: no such file)"
        );
        assert_eq!(
            worker_diagnostics_text(label, Ok(Some(b"one\ntwo\n".to_vec()))),
            "one\ntwo"
        );
    }

    /// A worker that has ended is read through the label kept for its session while it ran, and
    /// another session's file is not read in its place; a session the run never met has no worker.
    #[test]
    fn an_ended_worker_is_read_through_the_label_kept_for_its_session() {
        let root = scratch("worker-said");
        let run = Run::over(&root);
        let reservation = |n: u8| format!("{n:08x}-0000-4000-8000-{n:012x}");
        let program = run.binary("kr-worker");
        let command = |n: u8, session: &str| {
            format!(
                "{} --reservation {} --session {session}",
                program.display(),
                reservation(n)
            )
        };
        // Both workers are met while they run; neither is in the process table when it is read.
        run.note_workers_from([
            command(1, "session-a").as_str(),
            command(2, "session-b").as_str(),
        ]);
        std::fs::create_dir_all(root.join("jobs")).expect("the jobs directory");
        let said = |n: u8| format!("{WORKER_LINE_PREFIX}the reason of worker {n}");
        for n in [1_u8, 2] {
            std::fs::write(
                root.join(format!("jobs/kr-worker-{}.diagnostics", reservation(n))),
                format!("{}\n", said(n)),
            )
            .expect("a diagnostics file");
        }
        for (n, session) in [(1_u8, "session-a"), (2, "session-b")] {
            assert_eq!(
                worker_diagnostics_of(&run, Path::new("jobs"), session),
                format!("kr-worker-{}:\n{}", reservation(n), said(n)),
                "{session} reads its own worker's file and no other"
            );
        }
        assert_eq!(
            worker_diagnostics_of(&run, Path::new("jobs"), "session-c"),
            "(no worker of this run is in the process table)"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
    }
}

/// What the host's shutdown helpers do with a tree that holds links the agent under test left.
#[cfg(test)]
mod shutdown_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!("kr-host-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        directory
    }

    /// A run directory of this test's own whose path is short enough for the sockets below it: on
    /// macOS below `/private/tmp`, whose per-user temporary directory is long, and elsewhere below
    /// the system's temporary directory.
    fn short_run_directory() -> PathBuf {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::fs::canonicalize(std::env::temp_dir()).expect("the temporary directory")
        };
        let root = base.join(format!("kt-{}", &kr_ipc::new_uuid().to_string()[..8]));
        std::fs::create_dir_all(&root).expect("a short run directory");
        root
    }

    /// A host over a run's tree with no daemon started.
    fn host_over(run: &Run) -> Host<'_> {
        let paths = HostPaths::new(run.root().join(RUNTIME_ROOT), run.root().join(STATE_ROOT))
            .expect("absolute host roots");
        let identity = paths
            .open_environment_id()
            .expect("the environment's identity");
        let environment = paths.environment(identity);
        environment.create().expect("the environment's directories");
        // The floor a daemon would have made, so that the tree is one a case's agent starts in.
        let boot = kr_ipc::identity::boot_epoch(
            &kr_ipc::identity::boot_identity().expect("a boot identity"),
        )
        .expect("a boot epoch");
        kr_ipc::floor::SharedFloor::create(
            &environment.utc_floor_file(),
            environment.environment_id(),
            boot,
            1_000_000,
        )
        .expect("a clock floor");
        Host {
            run,
            paths,
            environment,
            shell_packages: None,
            daemon: Mutex::new(None),
            control: Mutex::new(None),
            agent_started: AtomicBool::new(false),
            stand_in: AtomicBool::new(false),
            kr_after_start: Arc::default(),
            restarts: Mutex::default(),
            anchor: Readings::now(),
        }
    }

    /// Starts `program` with `arguments` as a process that an interrupt ends, and returns it once it
    /// has said it is ready, which it says after it has set the interrupt back to its default and
    /// before it runs the program: none is sent before then. A process that was started in the
    /// background of a shell with no job control, as a run on the build box is, has the interrupt
    /// ignored; a signal that is ignored when a program starts stays ignored in each program it
    /// runs, and a shell cannot set it back with `trap`.
    fn started_for_an_interrupt(program: &str, arguments: &[&str]) -> std::process::Child {
        use std::io::BufRead as _;
        let mut child = Command::new("/usr/bin/perl")
            .args([
                "-e",
                r#"$SIG{INT} = "DEFAULT"; $| = 1; print "ready\n"; exec { $ARGV[0] } @ARGV;"#,
                program,
            ])
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("a process for the interrupt to end");
        let mut said = String::new();
        std::io::BufReader::new(child.stdout.take().expect("the process's output"))
            .read_line(&mut said)
            .expect("the process says it is ready");
        assert_eq!(said, "ready\n", "the process is ready");
        child
    }

    /// The text the host's stop gives for a daemon that ended with a failure: a `sleep` stands for
    /// the daemon, and the interrupt ends it.
    fn error_of_a_failing_daemon(host: &Host<'_>) -> String {
        let child = started_for_an_interrupt("/bin/sleep", &["30"]);
        let identity = host
            .run
            .record_child(child.id(), "the control daemon")
            .expect("the process's identity");
        *host.daemon.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Daemon { child, identity });
        host.stop_daemon()
            .expect_err("a daemon that ended by the interrupt did not end well")
    }

    /// A host over a scratch run with a `kr` that is a script writing a mark in the run's home.
    fn host_with_a_kr(root: &Path) -> (Run, PathBuf) {
        std::fs::create_dir_all(root.join("b")).expect("b");
        std::fs::create_dir_all(root.join("h")).expect("h");
        let mark = root.join("h/ran");
        let kr = root.join("b/kr");
        std::fs::write(&kr, "#!/bin/sh\necho placed >> \"$HOME/ran\"\n").expect("a kr");
        std::fs::set_permissions(&kr, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("executable");
        (Run::over(root), mark)
    }

    fn runs(mark: &Path) -> usize {
        std::fs::read_to_string(mark).map_or(0, |text| text.lines().count())
    }

    /// The `kr` the harness starts after the agent has run is the file that was placed: a file
    /// rewritten in place, replaced, linked, or given a second name is not run, and the control
    /// is the placed file, which is.
    #[test]
    fn a_kr_that_is_not_the_file_that_was_placed_is_not_run() {
        let root = scratch("kr");
        let theirs = scratch("kr-theirs");
        let (run, mark) = host_with_a_kr(&root);
        run.note_placed(Path::new("b/kr"))
            .expect("the placed kr is recorded");
        let host = host_over(&run);
        let kr = root.join("b/kr");
        host.kr_within(&["list"], Duration::from_secs(10))
            .expect("the placed kr runs");
        assert_eq!(runs(&mark), 1);

        // Rewritten in place: the same inode and name, and other bytes.
        let placed = std::fs::read(&kr).expect("the placed bytes");
        std::fs::write(&kr, "#!/bin/sh\necho hijacked >> \"$HOME/ran\"\n").expect("rewritten");
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("a kr rewritten in place is not run");
        assert!(why.contains("not the file that was placed"), "{why}");
        assert_eq!(runs(&mark), 1, "the rewritten file did not run");

        // Rewritten and put back: the bytes are the placed ones again and it runs.
        std::fs::write(&kr, &placed).expect("put back");
        host.kr_within(&["list"], Duration::from_secs(10))
            .expect("the placed bytes run");
        assert_eq!(runs(&mark), 2);

        // A link to a program of the person's.
        let outside = theirs.join("program");
        std::fs::write(&outside, "#!/bin/sh\necho theirs >> \"$HOME/ran\"\n").expect("a program");
        std::fs::set_permissions(
            &outside,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        std::fs::remove_file(&kr).expect("removed");
        std::os::unix::fs::symlink(&outside, &kr).expect("a link at kr");
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("a link is not run");
        assert!(why.contains("symbolic link"), "{why}");
        std::fs::remove_file(&kr).expect("removed");

        // A second name for the placed file.
        std::fs::write(&kr, &placed).expect("the placed bytes");
        std::fs::set_permissions(&kr, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("executable");
        std::fs::hard_link(&kr, theirs.join("second")).expect("a second name");
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("a file with a second name is not run");
        assert!(why.contains("more than one name"), "{why}");
        assert_eq!(runs(&mark), 2, "nothing but the placed kr ever ran");
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
        std::fs::remove_dir_all(&theirs).expect("clean up");
    }

    /// The control socket `kr` is run against is the one the daemon bound: a link at its place, a
    /// socket that is another one, and a file that is no socket are each refused, and the control
    /// is the socket that was bound.
    #[test]
    fn a_control_socket_that_is_not_the_one_the_daemon_bound_is_not_run_against() {
        use std::os::unix::net::UnixListener;
        let root = short_run_directory();
        let (run, mark) = host_with_a_kr(&root);
        run.note_placed(Path::new("b/kr"))
            .expect("the placed kr is recorded");
        let host = host_over(&run);
        let place = root.join(host.control_socket_place().expect("a place"));
        let bound = UnixListener::bind(&place).expect("the daemon's socket");
        host.note_control_socket();
        host.kr_within(&["list"], Duration::from_secs(10))
            .expect("the bound socket is used");
        assert_eq!(runs(&mark), 1);

        let elsewhere = root.join("elsewhere.sock");
        let another = UnixListener::bind(&elsewhere).expect("another socket");
        // A link to another socket.
        std::fs::remove_file(&place).expect("removed");
        std::os::unix::fs::symlink(&elsewhere, &place).expect("a link at the socket");
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("a link is not the daemon's socket");
        assert!(why.contains("symbolic link"), "{why}");
        // Another socket bound at the place.
        std::fs::remove_file(&place).expect("removed");
        let impostor = UnixListener::bind(&place).expect("another socket at the place");
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("another socket is not the daemon's");
        assert!(why.contains("not the one the daemon bound"), "{why}");
        // A file that is no socket.
        std::fs::remove_file(&place).expect("removed");
        std::fs::write(&place, b"not a socket").expect("a file at the place");
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("a file is not a socket");
        assert!(why.contains("not the kind of entry"), "{why}");
        assert_eq!(
            runs(&mark),
            1,
            "kr was run once, against the socket that was bound"
        );
        drop((bound, another, impostor));
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A link left at the host's registry, to a database of the person's, is not opened: the file it
    /// names is byte for byte what it was and nothing is made beside it. The workers are found in
    /// the process table all the same: the control is a process that runs as a worker of this run,
    /// which is recorded with what runs beneath it.
    #[test]
    fn a_link_at_the_registry_is_not_opened_and_the_workers_are_found_by_their_command_lines() {
        use std::os::unix::process::CommandExt as _;
        let root = scratch("registry");
        let theirs = scratch("registry-theirs");
        let database = theirs.join("personal.sqlite");
        std::fs::write(&database, b"").expect("a database of the person's, not yet written to");
        let run = Run::over(&root);
        let host = host_over(&run);
        let place = host.environment().registry_database();
        std::os::unix::fs::symlink(&database, &place).expect("a link at the registry");
        let session = kr_ipc::new_uuid().to_string();
        let reservation = kr_ipc::new_uuid().to_string();
        // A process that runs as this run's worker for a session, with a child beneath it.
        let mut worker = Command::new("/bin/sh")
            .arg0(run.root().join("b/kr-worker"))
            .args([
                "-c",
                "/bin/sleep 30; true",
                "--session",
                &session,
                "--reservation",
                &reservation,
            ])
            .stdin(Stdio::null())
            .spawn()
            .expect("a process standing for a worker");
        let started = Instant::now();
        let recorded = loop {
            host.record_workers();
            let owned = run.owned();
            if owned.len() >= 2 || started.elapsed() > Duration::from_secs(10) {
                break owned;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        run.end_everything();
        let _ = worker.wait();
        assert!(
            run.proposed_labels()
                .contains(&format!("kr-worker-{reservation}")),
            "the label the worker's job has is learned from its command line"
        );
        assert_eq!(
            std::fs::read(&database).expect("theirs"),
            b"",
            "the database the link names is unchanged"
        );
        let mut beside = std::fs::read_dir(&theirs)
            .expect("theirs")
            .map(|entry| entry.expect("an entry").file_name())
            .collect::<Vec<_>>();
        beside.sort();
        assert_eq!(beside, ["personal.sqlite"], "nothing was made beside it");
        let names: Vec<&str> = recorded.iter().map(|owned| owned.what.as_str()).collect();
        assert!(
            names.contains(&format!("the worker of session {session}").as_str())
                && names
                    .iter()
                    .any(|what| what.starts_with("under the worker of")),
            "the worker and what runs beneath it are recorded: {names:?}"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
        std::fs::remove_dir_all(&theirs).expect("clean up");
    }

    /// A command line names a run's directory only by its path components, and a worker is a run's
    /// only by its exact program: another host's directory whose name begins with this one's is not
    /// this one, and nor is a worker whose program is another file.
    #[test]
    fn a_command_line_names_the_run_by_path_components_and_a_worker_by_its_exact_program() {
        use crate::run::names_the_root;
        let root = Path::new("/tmp/kr-a");
        assert!(names_the_root("/tmp/kr-a/b/kr-worker --session 1", root));
        assert!(names_the_root(
            "kr-controller --state-dir=/tmp/kr-a/s",
            root
        ));
        assert!(names_the_root("/tmp/kr-a --x", root));
        assert!(names_the_root(
            "codex resume --remote unix:///tmp/kr-a/s/gw.sock",
            root
        ));
        assert!(!names_the_root(
            "codex resume --remote unix:///tmp/kr-a-other/s/gw.sock",
            root
        ));
        assert!(!names_the_root(
            "/tmp/kr-a-other/b/kr-worker --session 1",
            root
        ));
        assert!(!names_the_root(
            "kr-controller --state-dir=/tmp/kr-ab/s",
            root
        ));
        assert!(!names_the_root("/tmp/kr-a-other", root));
        let program = Path::new("/tmp/kr-a/b/kr-worker");
        assert_eq!(
            worker_session(
                "/tmp/kr-a/b/kr-worker -c x --session s1 --reservation r",
                program
            ),
            Some("s1")
        );
        assert_eq!(
            worker_session("/tmp/kr-a-other/b/kr-worker --session s1", program),
            None
        );
        assert_eq!(
            worker_session("/tmp/kr-a/b/kr-worker-2 --session s1", program),
            None
        );
        assert_eq!(worker_session("/tmp/kr-a/b/kr-worker", program), None);
    }

    /// Ends the stand-in's process group when the case ends, passed or failed: the shell's `sleep` is
    /// another process, and it outlives the shell.
    struct StandIn(std::process::Child);

    impl std::ops::Deref for StandIn {
        type Target = std::process::Child;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for StandIn {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl Drop for StandIn {
        fn drop(&mut self) {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", self.0.id())])
                .status();
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A worker of a second host of the case's own, whose run directory's name begins with this
    /// run's directory's name, is not found in this run's process table, is not recorded, and is
    /// left running when this run's host stops and again when it is dropped; this run's own worker
    /// is found and recorded.
    #[test]
    fn a_worker_of_a_host_whose_directory_name_begins_with_this_ones_is_kept_when_this_host_ends() {
        use std::os::unix::process::CommandExt as _;
        let root = scratch("prefix");
        let other = PathBuf::from(format!("{}-other", root.display()));
        std::fs::create_dir_all(&other).expect("the second host's directory");
        let run = Run::over(&root);
        let standing_for = |directory: &Path, session: &str| {
            StandIn(
                Command::new("/bin/sh")
                    .arg0(directory.join("b/kr-worker"))
                    .args(["-c", "/bin/sleep 30; true", "--session", session])
                    .stdin(Stdio::null())
                    // A group of its own: the shell's `sleep` is another process, and ending the
                    // shell alone leaves it running with the case's output open.
                    .process_group(0)
                    .spawn()
                    .expect("a process standing for a worker"),
            )
        };
        let (own_session, foreign_session) = (
            kr_ipc::new_uuid().to_string(),
            kr_ipc::new_uuid().to_string(),
        );
        let mut foreign = standing_for(&other, &foreign_session);
        let own = standing_for(&root, &own_session);
        let host = host_over(&run);
        let started = Instant::now();
        loop {
            host.record_workers();
            if run.owned().len() >= 2 || started.elapsed() > Duration::from_secs(10) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let names: Vec<String> = run.owned().into_iter().map(|owned| owned.what).collect();
        assert!(
            names.contains(&format!("the worker of session {own_session}")),
            "this run's own worker is recorded: {names:?}"
        );
        assert!(
            names.iter().all(|what| !what.contains(&foreign_session)),
            "the other host's worker is not recorded: {names:?}"
        );
        assert!(
            processes_under(&root)
                .expect("the process table")
                .iter()
                .all(|(pid, _)| *pid != foreign.id()),
            "the other host's worker does not run out of this run's directory"
        );
        host.agent_starts();
        let stopped = host.stop();
        assert!(stopped.is_ok(), "the host stopped: {stopped:?}");
        assert!(
            foreign.try_wait().expect("the other worker").is_none(),
            "the other host's worker still runs after this run's host stopped"
        );
        drop(host);
        assert!(
            foreign.try_wait().expect("the other worker").is_none(),
            "the other host's worker still runs after this run's host was dropped"
        );
        drop(foreign);
        drop(own);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
        std::fs::remove_dir_all(&other).expect("clean up");
    }

    /// What an agent under test can leave in the run's state before the host is stopped: the
    /// environment's identity rewritten to another host's, and a socket that is not the daemon's
    /// bound at the place that identity gives. The run's `kr` is a script that connects to that
    /// socket, as the product's `kr` does by path, and writes a mark.
    struct Rewritten {
        connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        ended: std::sync::Arc<AtomicBool>,
        accepting: Option<std::thread::JoinHandle<()>>,
        worker: std::process::Child,
        mark: PathBuf,
        asked: Arc<Mutex<Vec<String>>>,
    }

    impl Rewritten {
        fn leave(host: &Host<'_>, mark: &Path) -> Self {
            use std::os::unix::net::UnixListener;
            use std::os::unix::process::CommandExt as _;
            use std::sync::atomic::AtomicUsize;
            let run = host.run;
            // A process that stands for the daemon: the interrupt ends it well.
            let child = started_for_an_interrupt(
                "/bin/sh",
                &["-c", "trap 'exit 0' INT; while :; do /bin/sleep 1; done"],
            );
            let identity = run
                .record_child(child.id(), "the control daemon")
                .expect("the process's identity");
            *host.daemon.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Daemon { child, identity });
            // A process that runs as this run's worker, with a child beneath it.
            let worker = Command::new("/bin/sh")
                .arg0(run.root().join("b/kr-worker"))
                .args([
                    "-c",
                    "/bin/sleep 30; true",
                    "--session",
                    &kr_ipc::new_uuid().to_string(),
                    "--reservation",
                    &kr_ipc::new_uuid().to_string(),
                ])
                .stdin(Stdio::null())
                .spawn()
                .expect("a process standing for a worker");
            host.agent_starts();
            // What the agent left: another identity, and a socket of another host at its place.
            let other = EnvironmentId::new(kr_ipc::new_uuid());
            std::fs::write(host.paths.environment_id_file(), format!("{other}\n"))
                .expect("the identity rewritten");
            let elsewhere = host.paths.environment(other);
            elsewhere.create().expect("the other host's directories");
            let place = elsewhere
                .controller_endpoint()
                .expect("the other host's endpoint")
                .as_path()
                .to_path_buf();
            let listener = UnixListener::bind(&place).expect("the other host's socket");
            listener.set_nonblocking(true).expect("a polling listener");
            std::fs::write(run.home().join("socket-place"), place.display().to_string())
                .expect("where kr connects");
            let connections = Arc::new(AtomicUsize::new(0));
            let ended = Arc::new(AtomicBool::new(false));
            let accepting = {
                let (connections, ended) = (Arc::clone(&connections), Arc::clone(&ended));
                std::thread::spawn(move || {
                    while !ended.load(Ordering::SeqCst) {
                        if listener.accept().is_ok() {
                            connections.fetch_add(1, Ordering::SeqCst);
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                })
            };
            Self {
                connections,
                ended,
                accepting: Some(accepting),
                worker,
                mark: mark.to_path_buf(),
                asked: host.kr_after_the_agent_started(),
            }
        }

        /// Checks that nothing connected to the other host's socket and no `kr` ran, and that every
        /// process the run recorded has ended.
        fn finish(mut self, run: &Run) {
            std::thread::sleep(Duration::from_millis(200));
            self.ended.store(true, Ordering::SeqCst);
            if let Some(accepting) = self.accepting.take() {
                accepting.join().expect("the accepting thread");
            }
            // Before the worker is waited for: it must have been ended by the host, not have run out.
            let alive: Vec<String> = run
                .owned()
                .iter()
                .filter(|owned| running(&owned.identity))
                .map(|owned| owned.what.clone())
                .collect();
            assert!(alive.is_empty(), "still running: {alive:?}");
            let _ = self.worker.wait();
            assert_eq!(
                self.connections.load(Ordering::SeqCst),
                0,
                "something connected to the socket of the host the identity named"
            );
            assert_eq!(runs(&self.mark), 0, "a kr was run after the agent started");
            assert!(
                self.asked
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_empty(),
                "a kr was asked for after the agent started"
            );
            assert!(
                run.owned()
                    .iter()
                    .any(|owned| owned.what.starts_with("the worker of session")),
                "the worker was recorded by its command line: {:?}",
                run.owned().iter().map(|o| &o.what).collect::<Vec<_>>()
            );
        }
    }

    /// Once the agent under test has started, a `kr` that is asked for is not run, and the record
    /// of what was asked for after the start says it.
    #[test]
    fn a_kr_asked_for_after_the_agent_started_is_not_run_and_is_recorded() {
        let root = scratch("kr-after");
        let (run, mark) = host_with_a_kr(&root);
        run.note_placed(Path::new("b/kr"))
            .expect("the placed kr is recorded");
        let host = host_over(&run);
        host.kr_within(&["list"], Duration::from_secs(10))
            .expect("kr runs before the agent has started");
        assert_eq!(runs(&mark), 1);
        assert!(
            host.kr_after_the_agent_started()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
        host.agent_starts();
        let why = host
            .kr_within(&["list"], Duration::from_secs(10))
            .expect_err("no kr is run after the agent started");
        assert!(why.contains("no kr is run after it"), "{why}");
        assert_eq!(runs(&mark), 1, "the placed kr ran once, before the start");
        assert_eq!(
            *host
                .kr_after_the_agent_started()
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            ["list".to_owned()]
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// Once a live agent has started, no daemon is started over the run's tree: the start reads the
    /// tree and runs the programs under `b/`, which the agent may have changed.
    #[test]
    fn no_daemon_is_started_after_the_agent_started_unless_it_is_the_stand_in() {
        let root = scratch("daemon-after");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        host.agent_starts();
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host.start_daemon_ready_by(&|_| Ok(()));
        }))
        .expect_err("a start beside a live agent is refused");
        let said = refused
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                refused
                    .downcast_ref::<&str>()
                    .map(|said| (*said).to_owned())
            })
            .unwrap_or_default();
        assert!(
            said.contains("unless that agent is the harness's own stand-in"),
            "{said}"
        );
        assert!(
            host.daemon
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none(),
            "nothing was started"
        );
        assert!(
            recorded(&host).is_none(),
            "a case that declared no restart has no record of the tree"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The record `agent_starts` made, if it made one.
    fn recorded(host: &Host<'_>) -> Option<Record> {
        host.restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record
            .clone()
    }

    /// The run's two host roots are recorded once, when the agent of a case that declared a restart
    /// starts, and what the agent writes afterwards is not taken into the record.
    #[test]
    fn a_case_that_declares_a_restart_has_the_run_tree_recorded_once_when_its_agent_starts() {
        let root = scratch("record-once");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        std::fs::write(root.join("s/before"), b"before").expect("a file");
        std::fs::create_dir_all(root.join("h/.claude")).expect("the application directory");
        std::fs::write(root.join("h/.claude/recipe"), b"recipe").expect("a recipe file");
        host.declares_a_restart(Restart::Declared);
        assert!(
            recorded(&host).is_none(),
            "nothing is recorded before the agent starts"
        );
        host.agent_starts();
        let held = recorded(&host).expect("the tree is recorded");
        assert!(held.get(Path::new("s/before")).is_some());
        assert!(
            held.get(Path::new("b/kr")).is_some(),
            "the run's programs are recorded"
        );
        assert!(
            held.get(Path::new("h/.claude/recipe")).is_some(),
            "the application directory is recorded where it is"
        );
        assert!(
            held.get(Path::new("h/ran")).is_none(),
            "the rest of the run's home is not recorded"
        );
        std::fs::write(root.join("s/later"), b"later").expect("a file the agent wrote");
        host.agent_starts();
        let again = recorded(&host).expect("the record");
        assert!(
            again.get(Path::new("s/later")).is_none(),
            "the record is made once, at the first start"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// No record is made for a case that declares no restart, nor for the stand-in path of one
    /// that does; the survey records on the stand-in too.
    #[test]
    fn no_record_is_made_for_a_case_with_no_restart_or_on_the_stand_in_path() {
        for (how, stand_in, records) in [
            (Restart::Off, false, false),
            (Restart::Off, true, false),
            (Restart::Declared, true, false),
            (Restart::Declared, false, true),
            (Restart::Survey, true, true),
            (Restart::Survey, false, true),
        ] {
            let root = scratch("record-when");
            let (run, _mark) = host_with_a_kr(&root);
            let host = host_over(&run);
            host.declares_a_restart(how);
            if stand_in {
                host.agent_is_a_stand_in();
            }
            host.agent_starts();
            assert_eq!(
                recorded(&host).is_some(),
                records,
                "{how:?}, stand-in {stand_in}"
            );
            drop(host);
            drop(run);
            std::fs::remove_dir_all(&root).expect("clean up");
        }
    }

    /// A record that cannot be made ends the leg as not run, by the unwinding the end of the case
    /// reads, before the agent is launched, and leaves no record.
    #[test]
    fn a_record_that_cannot_be_made_ends_the_leg_as_not_run_and_leaves_no_record() {
        let root = scratch("record-fails");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        std::fs::remove_dir_all(root.join(STATE_ROOT)).expect("the state root removed");
        std::os::unix::fs::symlink(&root, root.join(STATE_ROOT)).expect("a link at the state root");
        host.declares_a_restart(Restart::Declared);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host.agent_starts();
        }))
        .expect_err("no record, no start");
        let not_run = unwound
            .downcast_ref::<LegNotRun>()
            .expect("the leg is not run, it did not fail");
        assert!(
            not_run
                .0
                .starts_with("no record could be made before the agent started: "),
            "{}",
            not_run.0
        );
        assert!(recorded(&host).is_none());
        drop(host);
        drop(run);
        std::fs::remove_file(root.join(STATE_ROOT)).expect("the link removed");
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A clock floor that cannot be opened as the daemon opens it ends the leg as not run, before
    /// the agent is launched, and leaves no record and no watch; with a floor the watch is kept.
    #[test]
    fn a_clock_floor_that_cannot_be_opened_ends_the_leg_as_not_run_and_one_that_opens_is_kept() {
        let root = scratch("record-floor");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        host.declares_a_restart(Restart::Declared);
        host.agent_starts();
        let kept = host
            .restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clock
            .is_some();
        assert!(kept, "the mapping is kept from the start");
        drop(host);
        let host = host_over(&run);
        std::fs::remove_file(host.environment.utc_floor_file()).expect("the floor removed");
        host.declares_a_restart(Restart::Declared);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host.agent_starts();
        }))
        .expect_err("no floor, no start");
        let not_run = unwound
            .downcast_ref::<LegNotRun>()
            .expect("the leg is not run, it did not fail");
        assert!(
            not_run.0.starts_with(
                "no record could be made before the agent started: the clock floor cannot be \
                 read at the start: "
            ),
            "{}",
            not_run.0
        );
        assert!(recorded(&host).is_none());
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The lines a survey host has said.
    fn surveyed_by(host: &Host<'_>) -> Vec<String> {
        host.restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .survey
            .lines
            .clone()
    }

    /// Gives a survey host no wait after the kill, looks 150 ms apart and one second in all.
    fn survey_quickly(host: &Host<'_>) {
        host.restarts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .survey
            .timing = SurveyTiming {
            after_the_kill: Duration::ZERO,
            apart: Duration::from_millis(150),
            at_most: Duration::from_secs(1),
        };
    }

    /// The survey says each entry that changed between the record made when the agent started and
    /// the kill, and each that changed between the kill and the attempt; what changed before the
    /// kill is not said again at the attempt.
    #[test]
    fn the_survey_says_what_changed_at_the_kill_and_what_changed_after_it() {
        let root = scratch("survey-lists");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        std::fs::write(root.join("s/kept"), b"kept").expect("a file");
        std::fs::write(root.join("s/goes"), b"goes").expect("a file");
        host.declares_a_restart(Restart::Survey);
        // The survey's host is the stand-in's.
        host.agent_is_a_stand_in();
        host.agent_starts();
        survey_quickly(&host);
        std::fs::write(root.join("s/before-the-kill"), b"before").expect("written by the agent");
        std::fs::remove_file(root.join("s/goes")).expect("removed by the agent");
        host.survey_the_kill();
        // The compares of the kill, as `kill_daemon` makes them after the survey's look.
        host.verify_the_kill();
        std::fs::write(root.join("s/after-the-kill"), b"after").expect("written by the worker");
        host.survey_before_the_attempt();
        let lines = surveyed_by(&host);
        let said = |text: &str| lines.iter().any(|line| line.contains(text));
        assert!(
            said("survey: kill 1, at the kill: s/before-the-kill: added, a file"),
            "{lines:#?}"
        );
        assert!(
            said("survey: kill 1, at the kill: s/goes: gone, it was a file"),
            "{lines:#?}"
        );
        assert!(
            !said("before the attempt: s/before-the-kill"),
            "a change made before the kill is not said again: {lines:#?}"
        );
        assert!(
            said("survey: kill 1, before the attempt: s/after-the-kill: added, a file"),
            "{lines:#?}"
        );
        assert!(
            said(
                "survey: kill 1: 2 change(s) from the agent's start to the kill and 1 from the \
                 kill to the attempt; the files of the index and the journals stood still"
            ),
            "{lines:#?}"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The survey says each journal table that changed between the kill and the attempt, and none
    /// that changed before the kill.
    #[test]
    fn the_survey_says_the_journal_tables_that_changed_after_the_kill_and_not_before_it() {
        let root = scratch("survey-tables");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        let journal = host
            .environment
            .state_dir()
            .join("sessions/session-a1.sqlite");
        std::fs::create_dir_all(journal.parent().expect("a parent")).expect("a directory");
        let connection = rusqlite::Connection::open(&journal).expect("a journal");
        connection
            .execute_batch(
                "CREATE TABLE requests (id INTEGER); CREATE TABLE bindings (id INTEGER);",
            )
            .expect("tables");
        host.declares_a_restart(Restart::Survey);
        // The survey's host is the stand-in's.
        host.agent_is_a_stand_in();
        host.agent_starts();
        survey_quickly(&host);
        connection
            .execute_batch("INSERT INTO requests VALUES (1);")
            .expect("a row before the kill");
        host.survey_the_kill();
        // The compares of the kill, as `kill_daemon` makes them after the survey's look.
        host.verify_the_kill();
        connection
            .execute_batch("INSERT INTO bindings VALUES (1);")
            .expect("a row after the kill");
        host.survey_before_the_attempt();
        let lines = surveyed_by(&host);
        let said = |text: &str| lines.iter().any(|line| line.contains(text));
        assert!(
            said(
                "survey: kill 1, refused: the journal table bindings of a1 changed, appeared or is \
                 gone between the kill and the attempt"
            ),
            "{lines:#?}"
        );
        assert!(!said("table requests"), "{lines:#?}");
        drop(connection);
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A file that a daemon changes only when it starts is refused at a kill with no start before it,
    /// and not at one that follows a start, in the survey as on the real route.
    #[test]
    fn the_survey_counts_a_start_for_the_kill_that_follows_it() {
        let root = scratch("survey-starts");
        let run = run_with_a_controller(&root);
        let host = host_over(&run);
        let lock = host.environment.state_dir().join("controller.lock");
        std::fs::write(&lock, b"1").expect("a lock file");
        assert!(
            host.start_once(&started(&root, 1), Duration::from_secs(10))
                .is_ok(),
            "the first start"
        );
        host.declares_a_restart(Restart::Survey);
        host.agent_is_a_stand_in();
        host.agent_starts();
        survey_quickly(&host);
        std::fs::write(&lock, b"22").expect("written before the first kill");
        host.kill_daemon();
        host.start_daemon_ready_by(&started(&root, 2));
        std::fs::write(&lock, b"333").expect("written before the second kill");
        host.kill_daemon();
        host.start_daemon_ready_by(&started(&root, 3));
        let lines = surveyed_by(&host);
        let refused_at = |kill: usize| {
            lines.iter().any(|line| {
                line.starts_with(&format!("survey: kill {kill}, refused: "))
                    && line.contains("controller.lock changes only when a daemon starts")
            })
        };
        assert!(
            refused_at(1),
            "a file that changes only at a start is refused at the first kill: {lines:#?}"
        );
        assert!(
            !refused_at(2),
            "the same file is not refused at a kill that follows a start: {lines:#?}"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The survey says each write that no row of the live daemon's files covers as a refusal, made
    /// before the kill or after it.
    #[test]
    fn the_survey_says_a_write_that_no_row_covers_as_refused_before_the_kill_and_after_it() {
        let root = scratch("survey-refuses");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        host.declares_a_restart(Restart::Survey);
        host.agent_is_a_stand_in();
        host.agent_starts();
        survey_quickly(&host);
        std::fs::write(root.join("s/before-the-kill"), b"before").expect("written by the agent");
        host.survey_the_kill();
        host.verify_the_kill();
        std::fs::write(root.join("s/after-the-kill"), b"after").expect("written by the worker");
        host.survey_before_the_attempt();
        let lines = surveyed_by(&host);
        for name in ["before-the-kill", "after-the-kill"] {
            let refused = lines.iter().any(|line| {
                line.starts_with(&format!("survey: kill 1, refused: s/{name}: added, a file"))
                    && line.ends_with("; no row of the live daemon's files covers this entry")
            });
            assert!(refused, "{name}: {lines:#?}");
        }
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A scratch run whose `kr-controller` is a script that counts its starts in the run's home,
    /// exits when the home holds a file `fail`, exits once, with what a daemon says of an address
    /// that was taken, when the home holds a file `taken`, and otherwise stays running.
    fn run_with_a_controller(root: &Path) -> Run {
        std::fs::create_dir_all(root.join("b")).expect("b");
        std::fs::create_dir_all(root.join("h")).expect("h");
        let program = root.join("b/kr-controller");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho started >> \"$HOME/starts\"\nif [ -e \"$HOME/fail\" ]; then\n  \
                 echo \"the controller broke\" >&2\n  exit 3\nfi\nif [ -e \"$HOME/taken\" ]; then\n  \
                 rm \"$HOME/taken\"\n  \
                 echo \"network.bind_address could not be bound: {SOCKETS_NOT_BOUND}\" >&2\n  \
                 exit 1\nfi\nexec sleep 30\n"
            ),
        )
        .expect("a controller");
        std::fs::set_permissions(
            &program,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        Run::over(root)
    }

    fn started(root: &Path, count: usize) -> impl Fn(Duration) -> Result<(), String> + '_ {
        move |_| {
            if starts(root) >= count {
                Ok(())
            } else {
                Err("the controller has not started".to_owned())
            }
        }
    }

    fn starts(root: &Path) -> usize {
        std::fs::read_to_string(root.join("h/starts")).map_or(0, |text| text.lines().count())
    }

    /// A host that declared a restart, whose daemon started once and was killed after the agent
    /// started: `setup` runs before the agent starts and `before_the_kill` after it.
    fn killed_host<'r>(
        run: &'r Run,
        setup: impl FnOnce(&Host<'r>),
        before_the_kill: impl FnOnce(),
    ) -> Host<'r> {
        let host = host_over(run);
        setup(&host);
        assert!(
            host.start_once(&started(run.root(), 1), Duration::from_secs(10))
                .is_ok(),
            "the first start"
        );
        host.declares_a_restart(Restart::Declared);
        host.agent_starts();
        before_the_kill();
        host.kill_daemon();
        host
    }

    /// A host that declared `how` as its restart, whose daemon started once and was killed after
    /// the harness's own stand-in started as its agent: `setup` runs before the agent starts.
    fn killed_stand_in_host<'r>(
        run: &'r Run,
        how: Restart,
        setup: impl FnOnce(&Host<'r>),
    ) -> Host<'r> {
        let host = host_over(run);
        setup(&host);
        assert!(
            host.start_once(&started(run.root(), 1), Duration::from_secs(10))
                .is_ok(),
            "the first start"
        );
        host.declares_a_restart(how);
        host.agent_is_a_stand_in();
        host.agent_starts();
        host.kill_daemon();
        host
    }

    /// The reason a leg that ends as not run gives.
    fn not_run(attempt: impl FnOnce()) -> String {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt))
            .expect_err("the leg ends as not run")
            .downcast_ref::<LegNotRun>()
            .expect("a leg that is not run")
            .0
            .clone()
    }

    /// What `attempt` unwound with, or `None` where it returned.
    fn unwound(attempt: impl FnOnce()) -> Option<Box<dyn std::any::Any + Send>> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(attempt)).err()
    }

    /// The text an unwinding carries: the reason of a leg that did not run, or a panic's message.
    fn said_by(unwinding: &(dyn std::any::Any + Send)) -> String {
        unwinding
            .downcast_ref::<LegNotRun>()
            .map(|not_run| not_run.0.clone())
            .or_else(|| unwinding.downcast_ref::<String>().cloned())
            .or_else(|| {
                unwinding
                    .downcast_ref::<&str>()
                    .map(|said| (*said).to_owned())
            })
            .unwrap_or_default()
    }

    const QUICKLY: Duration = Duration::from_secs(2);

    /// A real agent's restart is one start after every compare passed, and the daemon is then
    /// running again.
    #[test]
    fn a_real_agents_restart_is_one_start_after_the_compares_pass() {
        let root = scratch("verified-start");
        let run = run_with_a_controller(&root);
        let host = killed_host(&run, |_| {}, || {});
        assert_eq!(starts(&root), 1);
        host.restart_after_a_real_agent(&started(&root, 2), QUICKLY, Duration::from_secs(10));
        assert_eq!(starts(&root), 2);
        assert!(host.daemon.lock().expect("a lock").is_some());
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// An address that stays held, a start that fails, a daemon that does not answer in time and a
    /// compare that refuses each end the leg as not run with their reason and make no further
    /// attempt.
    #[test]
    fn a_restart_that_cannot_go_on_ends_the_leg_as_not_run_and_tries_once() {
        let held = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let port = held.local_addr().expect("an address").port();
        let root = scratch("verified-address");
        let run = run_with_a_controller(&root);
        let host = killed_host(
            &run,
            |host| write_configuration(&host.environment, &[], port),
            || {},
        );
        let said = not_run(|| {
            host.restart_after_a_real_agent(&|_| Ok(()), Duration::from_millis(300), QUICKLY);
        });
        assert!(
            said.starts_with(&format!(
                "the address was not free: the daemon's address 127.0.0.1:{port} stayed held for "
            )),
            "{said}"
        );
        assert_eq!(starts(&root), 1, "no start was tried");
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");

        let root = scratch("verified-failing");
        let run = run_with_a_controller(&root);
        let host = killed_host(&run, |_| {}, || {});
        std::fs::write(root.join("h/fail"), b"").expect("a mark");
        let said = not_run(|| {
            host.restart_after_a_real_agent(&|_| Err("not ready".to_owned()), QUICKLY, QUICKLY);
        });
        assert!(
            said.starts_with("the control daemon did not start after the kill: ")
                && said.contains("the controller broke"),
            "{said}"
        );
        assert_eq!(starts(&root), 2, "one attempt and no retry");
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");

        let root = scratch("verified-silent");
        let run = run_with_a_controller(&root);
        let host = killed_host(&run, |_| {}, || {});
        let said = not_run(|| {
            host.restart_after_a_real_agent(
                &|_| Err("not yet".to_owned()),
                QUICKLY,
                Duration::from_secs(1),
            );
        });
        assert!(
            said.starts_with(
                "the control daemon did not start after the kill: it did not answer within 1s \
                 (not yet): "
            ),
            "{said}"
        );
        assert_eq!(starts(&root), 2, "one attempt and no retry");
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A file changed between the kill and the attempt, and one changed between the start and the
    /// kill, each refuse the restart before any daemon starts; the record of the kill is kept.
    #[test]
    fn a_restart_over_a_tree_that_changed_is_refused_before_any_start() {
        for (name, after_the_kill) in [("after-the-kill", true), ("before-the-kill", false)] {
            let root = scratch(&format!("verified-refused-{name}"));
            let run = run_with_a_controller(&root);
            let recorded = root.join("s/recorded");
            let host = killed_host(
                &run,
                |_| std::fs::write(&recorded, b"before").expect("a file"),
                || {
                    if !after_the_kill {
                        std::fs::write(&recorded, b"after").expect("written by the agent");
                    }
                },
            );
            if after_the_kill {
                std::fs::write(&recorded, b"after").expect("written by the agent");
            }
            let said = not_run(|| {
                host.start_daemon_ready_by(&|_| Ok(()));
            });
            assert!(
                said.starts_with("the restart was refused: ")
                    && said.contains("no row of the live daemon's files covers this entry"),
                "{name}: {said}"
            );
            assert_eq!(starts(&root), 1, "{name}: no start was tried");
            assert!(
                host.restarts
                    .lock()
                    .expect("a lock")
                    .verified
                    .as_ref()
                    .is_some_and(|verified| verified.kill.is_some()),
                "{name}: the record of the kill is kept"
            );
            drop(host);
            drop(run);
            std::fs::remove_dir_all(&root).expect("clean up");
        }
    }

    /// The harness's own stand-in restarts as it did: no record, no compare, the same start.
    #[test]
    fn a_stand_in_restarts_as_it_did() {
        let root = scratch("verified-stand-in");
        let run = run_with_a_controller(&root);
        let host = host_over(&run);
        assert!(
            host.start_once(&started(run.root(), 1), Duration::from_secs(10))
                .is_ok(),
            "the first start"
        );
        host.agent_is_a_stand_in();
        host.agent_starts();
        host.kill_daemon();
        host.start_daemon_ready_by(&started(&root, 2));
        assert_eq!(starts(&root), 2);
        assert!(host.restarts.lock().expect("a lock").verified.is_none());
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The harness's own stand-in restarts by the route it always had, whatever the host records:
    /// the survey host says what changed before the attempt, a start that fails is a failed leg and
    /// not a leg that did not run, and a start that failed for its address is made again.
    #[test]
    fn a_stand_in_restarts_by_its_own_route_whatever_the_host_records() {
        let root = scratch("stand-in-survey");
        let run = run_with_a_controller(&root);
        let host = killed_stand_in_host(&run, Restart::Survey, |_| {});
        survey_quickly(&host);
        std::fs::write(root.join("s/after-the-kill"), b"after").expect("written by the worker");
        let unwinding = unwound(|| host.start_daemon_ready_by(&started(&root, 2)));
        assert!(
            unwinding.is_none(),
            "the stand-in restarts: {:?}",
            unwinding.as_deref().map(said_by)
        );
        let lines = surveyed_by(&host);
        assert!(
            lines.iter().any(|line| line
                .contains("survey: kill 1, before the attempt: s/after-the-kill: added, a file")),
            "the survey host says what changed before the attempt: {lines:#?}"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");

        let root = scratch("stand-in-failing");
        let run = run_with_a_controller(&root);
        let host = killed_stand_in_host(&run, Restart::Declared, |_| {});
        std::fs::write(root.join("h/fail"), b"").expect("a mark");
        let unwinding = unwound(|| host.start_daemon_ready_by(&|_| Err("not ready".to_owned())))
            .expect("a start that fails unwinds");
        assert!(
            unwinding.downcast_ref::<LegNotRun>().is_none(),
            "a start of the stand-in that fails is a failed leg, not a leg that did not run"
        );
        let said = said_by(&*unwinding);
        assert!(
            said.starts_with("the control daemon exited before it answered: ")
                && said.contains("the controller broke"),
            "{said}"
        );
        assert_eq!(starts(&root), 2);
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");

        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("a socket")
            .local_addr()
            .expect("an address")
            .port();
        let root = scratch("stand-in-address");
        let run = run_with_a_controller(&root);
        let host = killed_stand_in_host(&run, Restart::Declared, |host| {
            write_configuration(&host.environment, &[], port);
        });
        std::fs::write(root.join("h/taken"), b"").expect("a mark");
        let unwinding = unwound(|| host.start_daemon_ready_by(&started(&root, 3)));
        assert!(
            unwinding.is_none(),
            "the start is made again where the address was taken: {:?}",
            unwinding.as_deref().map(said_by)
        );
        assert_eq!(
            starts(&root),
            3,
            "the first start, the one refused, the retry"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A restart that is refused, and one that fails, after the worker was ended beside the dead
    /// daemon, each end the leg as not run and leave no process of the agent: the agent runs on
    /// beneath the dead worker, and the host's end ends it by the identity recorded while the worker
    /// lived.
    #[test]
    fn a_restart_that_is_refused_or_fails_leaves_no_agent_process() {
        use std::os::unix::process::CommandExt as _;
        for refused in [true, false] {
            let name = if refused { "refused" } else { "failing" };
            let root = scratch(&format!("no-agent-{name}"));
            let run = run_with_a_controller(&root);
            let recorded = root.join("s/recorded");
            // A process that runs as this run's worker for a session, with a process beneath it
            // that stands for the agent.
            let beneath = root.join("agent-started");
            let mut worker = Command::new("/bin/sh")
                .arg0(run.root().join("b/kr-worker"))
                .args([
                    "-c",
                    &format!(
                        "/bin/sleep 30 & echo started > '{}'; wait",
                        beneath.display()
                    ),
                    "--session",
                    &kr_ipc::new_uuid().to_string(),
                ])
                .stdin(Stdio::null())
                .spawn()
                .expect("a process standing for a worker");
            let waiting = Instant::now();
            while !beneath.exists() && waiting.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                beneath.exists(),
                "the worker started the process beneath it"
            );
            let host = killed_host(
                &run,
                |_| std::fs::write(&recorded, b"before").expect("a file"),
                || {},
            );
            // The kill of a real agent's host records the worker and what runs beneath it, before
            // the case ends the worker.
            let agent = run
                .owned()
                .into_iter()
                .find(|owned| owned.what.starts_with("under the worker of"))
                .map(|owned| owned.identity);
            let _ = worker.kill();
            let _ = worker.wait();
            let agent = agent.expect("the agent is recorded beneath the worker");
            assert!(
                running(&agent),
                "{name}: the agent runs on beneath the dead worker"
            );
            let said = if refused {
                std::fs::write(&recorded, b"after").expect("written by the worker");
                not_run(|| host.start_daemon_ready_by(&|_| Ok(())))
            } else {
                std::fs::write(root.join("h/fail"), b"").expect("a mark");
                not_run(|| {
                    host.restart_after_a_real_agent(
                        &|_| Err("not ready".to_owned()),
                        QUICKLY,
                        QUICKLY,
                    );
                })
            };
            let opening = if refused {
                "the restart was refused: "
            } else {
                "the control daemon did not start after the kill: "
            };
            assert!(said.starts_with(opening), "{name}: {said}");
            drop(host);
            let left_running = running(&agent);
            signal(&agent, rustix::process::Signal::KILL);
            assert!(
                !left_running,
                "{name}: the agent was left running when the leg ended"
            );
            drop(run);
            std::fs::remove_dir_all(&root).expect("clean up");
        }
    }

    /// The kill of the harness's own stand-in's host records no worker: what that host ends is
    /// found when it ends, as it was.
    #[test]
    fn the_kill_of_a_stand_ins_host_records_no_worker() {
        use std::os::unix::process::CommandExt as _;
        let root = scratch("stand-in-kill");
        let run = run_with_a_controller(&root);
        let mut worker = Command::new("/bin/sh")
            .arg0(run.root().join("b/kr-worker"))
            .args([
                "-c",
                "/bin/sleep 30; true",
                "--session",
                &kr_ipc::new_uuid().to_string(),
            ])
            .stdin(Stdio::null())
            .spawn()
            .expect("a process standing for a worker");
        let host = killed_stand_in_host(&run, Restart::Declared, |_| {});
        let workers: Vec<String> = run
            .owned()
            .into_iter()
            .map(|owned| owned.what)
            .filter(|what| what.contains("the worker of session"))
            .collect();
        assert!(
            workers.is_empty(),
            "the kill recorded workers of the stand-in's host: {workers:?}"
        );
        let _ = worker.kill();
        let _ = worker.wait();
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// An address that nothing holds is free at once, and one that is held says how long it was
    /// held.
    #[test]
    fn an_address_is_free_or_says_how_long_it_was_held() {
        let held = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let address = held.local_addr().expect("an address");
        let why = address_is_free(address, Duration::from_millis(200)).expect_err("held");
        assert!(
            why.starts_with(&format!(
                "the daemon's address {address} stayed held for 200ms: "
            )),
            "{why}"
        );
        drop(held);
        assert_eq!(address_is_free(address, Duration::from_secs(2)), Ok(()));
    }

    /// The wait for the watched files to stand still returns when two looks agree, and gives up at
    /// its bound where every look differs from the one before or no look can be made; the lines
    /// that say which are the survey's.
    #[test]
    fn the_wait_for_the_watched_files_returns_when_two_looks_agree_and_gives_up_at_its_bound() {
        let timing = SurveyTiming {
            after_the_kill: Duration::ZERO,
            apart: Duration::from_millis(1),
            at_most: Duration::from_secs(1),
        };
        let held = vec![(PathBuf::from("s/sessions/file"), entry_of_size(3))];
        let stood = wait_for_standing_still(timing, Instant::now(), || Some(held.clone()));
        assert!(stood.is_some(), "two equal looks agree");
        let mut size = 0;
        let moving = wait_for_standing_still(timing, Instant::now(), || {
            size += 1;
            Some(vec![(
                PathBuf::from("s/sessions/file"),
                entry_of_size(size),
            )])
        });
        assert_eq!(moving, None, "looks that all differ do not agree");
        let none = wait_for_standing_still(timing, Instant::now(), || None);
        assert_eq!(none, None, "no look can be made");
        assert!(standing_still_said(timing, stood).starts_with(
            "the files of the index and the journals stood still 0 s after the kill; "
        ));
        assert!(standing_still_said(timing, None).starts_with(
            "the files of the index and the journals did not stand still within 1 s after \
                 the kill, so this list is incomplete; "
        ));
    }

    /// The survey watches what the worker's maintenance writes while no daemon runs: the
    /// output-time index and the session journals, and nothing else.
    #[test]
    fn the_survey_watches_the_index_and_the_journals_only() {
        for (path, watched) in [
            ("s/environments/e1/output-times/a.sqlite", true),
            ("s/environments/e1/sessions/session-a.sqlite-wal", true),
            (
                "s/environments/e1/spool/a.log/00000000000000000000.out",
                false,
            ),
            ("r/e1/utc-floor", false),
        ] {
            assert_eq!(survey_watches(Path::new(path)), watched, "{path}");
        }
    }

    /// An entry of a file of this size, for a look.
    fn entry_of_size(size: u64) -> Entry {
        Entry {
            kind: crate::tree::Kind::File,
            size,
            digest: None,
            device: 1,
            inode: 1,
            owner: 1,
            mode: 0o600,
            target: None,
            content: None,
        }
    }

    /// A host that is not a survey says nothing at a kill or before the attempt.
    #[test]
    fn a_host_that_is_not_a_survey_says_nothing_at_a_kill() {
        let root = scratch("survey-off");
        let (run, _mark) = host_with_a_kr(&root);
        let host = host_over(&run);
        host.declares_a_restart(Restart::Declared);
        host.agent_starts();
        std::fs::write(root.join("s/written"), b"written").expect("a file");
        host.survey_the_kill();
        host.survey_before_the_attempt();
        assert!(surveyed_by(&host).is_empty());
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A `kr` that connects to the socket named in the run's home, as the product's `kr` connects
    /// to the endpoint it makes from the identity it reads, and writes a mark.
    fn host_with_a_connecting_kr(root: &Path) -> (Run, PathBuf) {
        let (run, mark) = host_with_a_kr(root);
        let kr = root.join("b/kr");
        std::fs::write(
            &kr,
            "#!/bin/sh\necho placed >> \"$HOME/ran\"\n/usr/bin/nc -U \"$(cat \"$HOME/socket-place\")\" \
             </dev/null >/dev/null 2>&1\n",
        )
        .expect("a kr");
        (run, mark)
    }

    /// After the agent under test has started, the host's stop runs no `kr`: an identity rewritten
    /// to another host's, with that host's socket at the place it gives, is never connected to, and
    /// the daemon, the worker and what runs beneath it, which the run recorded, are ended.
    #[test]
    fn a_rewritten_identity_and_another_hosts_socket_are_never_connected_to_when_the_host_stops() {
        let root = short_run_directory();
        let (run, mark) = host_with_a_connecting_kr(&root);
        run.note_placed(Path::new("b/kr"))
            .expect("the placed kr is recorded");
        let host = host_over(&run);
        let left = Rewritten::leave(&host, &mark);
        host.record_workers();
        let stopped = host.stop();
        assert!(stopped.is_ok(), "the host stopped: {stopped:?}");
        left.finish(&run);
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// The same where the host is dropped with its daemon still running, as a case that failed
    /// leaves it.
    #[test]
    fn a_rewritten_identity_and_another_hosts_socket_are_never_connected_to_when_the_host_is_dropped()
     {
        let root = short_run_directory();
        let (run, mark) = host_with_a_connecting_kr(&root);
        run.note_placed(Path::new("b/kr"))
            .expect("the placed kr is recorded");
        let host = host_over(&run);
        let left = Rewritten::leave(&host, &mark);
        drop(host);
        left.finish(&run);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    /// A link, or a second name, left at the daemon's log is a class in the error and none of the
    /// file it names; the control is a log of the run's own, whose last lines the error gives.
    #[test]
    fn a_link_or_a_second_name_at_the_daemons_log_is_a_class_and_none_of_the_file_it_names() {
        let root = scratch("log");
        let theirs = scratch("log-theirs");
        let personal = theirs.join("personal.txt");
        std::fs::write(
            &personal,
            "a line of the person's\nanother line of the person's\n",
        )
        .expect("a file of the person's");
        let run = Run::over(&root);
        let host = host_over(&run);
        let log = root.join("controller.log");

        std::os::unix::fs::symlink(&personal, &log).expect("a link at the log");
        let said = error_of_a_failing_daemon(&host);
        assert!(!said.contains("of the person's"), "{said}");
        assert!(said.contains("symbolic link"), "a class is said: {said}");
        std::fs::remove_file(&log).expect("the link goes");

        std::fs::hard_link(&personal, &log).expect("a second name for the file");
        let said = error_of_a_failing_daemon(&host);
        assert!(!said.contains("of the person's"), "{said}");
        assert!(
            said.contains("more than one name"),
            "a class is said: {said}"
        );
        std::fs::remove_file(&log).expect("the second name goes");

        std::fs::write(&log, "the daemon's own last line\n").expect("the run's own log");
        let said = error_of_a_failing_daemon(&host);
        assert!(said.contains("the daemon's own last line"), "{said}");
        assert_eq!(
            std::fs::read_to_string(&personal).expect("theirs"),
            "a line of the person's\nanother line of the person's\n",
            "the file the link named is unchanged"
        );
        drop(host);
        drop(run);
        std::fs::remove_dir_all(&root).expect("clean up");
        std::fs::remove_dir_all(&theirs).expect("clean up");
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{ExitStatus, Output};
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use super::{close_all, until_closed};

    /// The bound each wait below is given.
    const BOUND: Duration = Duration::from_secs(3);

    /// How far past its bound a wait may end: the scheduler's delays and the ending of the step
    /// that was running when the bound passed. Half what a wait that compares the time only
    /// between its steps overruns by in the first test below, and a quarter of the bound.
    const MARGIN: Duration = Duration::from_millis(750);

    /// What `kr status --json` prints for a session in `state`.
    fn status(state: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(0),
            stdout: serde_json::json!({ "state": state })
                .to_string()
                .into_bytes(),
            stderr: Vec::new(),
        }
    }

    /// A `kr status` that answers at once for the first half of the wait and then stops answering
    /// ends the wait at the wait's own deadline. It never reports the session closed, and once it
    /// stops answering it runs for the whole bound it is given and is ended there, as a `kr` that
    /// does not finish is. A wait that gave each ask a whole bound of its own, and compared the
    /// time only between asks, would end half a bound late at least.
    #[test]
    fn a_status_that_stops_answering_ends_the_wait_at_its_deadline() {
        let began = Instant::now();
        let mut asked = 0_u32;
        let waited = until_closed(BOUND, |bound| {
            asked += 1;
            if began.elapsed() < BOUND / 2 {
                return Ok(status("closing"));
            }
            std::thread::sleep(bound);
            Err(format!("did not finish within {bound:?}"))
        });
        let took = began.elapsed();
        let heard = waited.expect_err("the session is never reported closed");
        assert!(
            took < BOUND + MARGIN,
            "a wait bounded by {BOUND:?} took {took:?} over {asked} asks, and last heard: {heard}"
        );
        assert!(
            heard.contains("did not finish"),
            "the wait says what the last ask heard: {heard}"
        );
    }

    /// The control: a `kr status` that reports the session closed ends the wait at once, with that
    /// report.
    #[test]
    fn a_status_that_reports_the_session_closed_ends_the_wait_with_that_report() {
        let began = Instant::now();
        let mut asked = 0_u32;
        let report = until_closed(BOUND, |_| {
            asked += 1;
            Ok(status("closed"))
        })
        .expect("the session is reported closed");
        assert_eq!(report["state"], "closed");
        assert_eq!(asked, 1, "the first report that says closed ends the wait");
        assert!(
            began.elapsed() < MARGIN,
            "the wait ended at once rather than after {:?}",
            began.elapsed()
        );
    }

    /// Closing sessions starts no command once its deadline has passed. The first close runs for
    /// the whole bound it is given, which is the rest of the deadline: the other sessions are named
    /// as not closed, and neither another close nor another listing is started.
    #[test]
    fn closing_sessions_starts_no_command_once_its_deadline_has_passed() {
        let began = Instant::now();
        let listed: Vec<Value> = (1..=3)
            .map(|display| serde_json::json!({ "display_number": display }))
            .collect();
        let mut lists = 0_u32;
        let mut closes = Vec::new();
        let closed = close_all(
            BOUND,
            |_| {
                lists += 1;
                Ok(listed.clone())
            },
            |display, bound| {
                closes.push(display.to_owned());
                std::thread::sleep(bound);
                Err(format!("did not finish within {bound:?}"))
            },
        );
        let took = began.elapsed();
        let problems = closed.expect_err("no session was closed");
        assert_eq!(
            closes,
            ["1"],
            "one close ran, and took the rest of the deadline: {problems}"
        );
        assert_eq!(
            lists, 1,
            "nothing was listed after the deadline: {problems}"
        );
        assert!(
            problems.contains("session 1 could not be closed")
                && problems.contains("session 2 was not closed")
                && problems.contains("session 3 was not closed"),
            "every session left is named: {problems}"
        );
        assert!(
            took < BOUND + MARGIN,
            "closing within {BOUND:?} took {took:?}"
        );
    }
}
