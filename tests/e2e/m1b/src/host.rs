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
use crate::run::{
    HARNESS_PROGRAM, Run, binary_place, ended_within, output_within, processes_under,
    read_tail_below, running, signal, socket_below,
};

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
    /// The `kr` commands asked for after the agent under test started, each as its arguments: none
    /// is run, and the record shows that none was asked for either.
    kr_after_start: Arc<Mutex<Vec<String>>>,
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
        let paths = HostPaths::new(run.root().join("r"), run.root().join("s"))
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
            kr_after_start: Arc::default(),
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
        let kept = self
            .configured_address()
            .filter(|address| address.port() != 0);
        for attempt in 1..=RESTART_ATTEMPTS {
            let Err(said) = self.start_daemon_once() else {
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
                Ok(Some(_)) => Err(self.daemon_said_since(earlier)),
                _ => panic!("the daemon ended at once: {}", self.daemon_said()),
            };
        };
        *self.daemon.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Daemon { child, identity });
        let answered = Deadline::after(LIVENESS).poll(CLEANUP_COMMAND, ASK_AGAIN, |bound| {
            let heard = match self.kr_within(&["list", "--json"], bound) {
                Ok(output) if output.status.success() => return ControlFlow::Break(None),
                Ok(output) => format!("kr list ended with {}", output.status),
                Err(why) => format!("kr list {why}"),
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
                Ok(())
            }
            Ok(Some(said)) => Err(said),
            Err(heard) => panic!(
                "the control daemon did not answer within {LIVENESS:?} ({heard}): {}",
                self.daemon_said()
            ),
        }
    }

    /// Says that the agent under test is about to be started, as many times as it is started.
    ///
    /// From then on the harness acts on nothing it reads from the run, since the agent runs in the
    /// same account and may leave anything in the run's tree. `kr` reads the environment's identity
    /// and the endpoint it connects to from that tree at every call, so no `kr` is run once the
    /// agent may have started ([`Host::kr_within`] refuses, and [`Host::command`] panics); the host
    /// is stopped, and dropped, by ending what the run recorded by identity instead.
    pub fn agent_starts(&self) {
        self.agent_started.store(true, Ordering::SeqCst);
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
    /// the run's pinned directory that follows no link, or why it could not be.
    fn note_control_socket(&self) {
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

    /// The identity of the worker process that serves `session_id`: the process running this run's
    /// copy of `kr-worker` for that session, recorded with the run once its start holds the number
    /// the process table gave.
    ///
    /// # Panics
    ///
    /// Panics when no such process is in the process table within [`LIVENESS`].
    #[must_use]
    pub fn worker_of(&self, session_id: &str) -> ProcessStartIdentity {
        let started = Instant::now();
        let session = format!("--session {session_id}");
        loop {
            if let Some(identity) = crate::run::processes_under(self.run.root())
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, command)| command.contains("kr-worker") && command.contains(&session))
                .find_map(|(pid, _)| {
                    self.run
                        .record_named(pid, "the session's worker", &["kr-worker", &session])
                })
            {
                return identity;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "no worker for session {session_id} is in the process table"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Records every worker this host started, with everything that runs beneath it, by start
    /// identity.
    ///
    /// A worker is found in the process table by its command line, which names this run's
    /// directory and the session it serves, and is recorded like any other process this run
    /// learns of ([`Run::record_named`]). That needs nothing of the host, so a leg that stops part
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
        for (pid, command) in table {
            let Some(session) = worker_session(&command) else {
                continue;
            };
            let what = format!("the worker of session {session}");
            match self.run.record_named(pid, &what, &["--session"]) {
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

/// The session a command line is the worker of: the program is `kr-worker` and `--session` names it.
fn worker_session(command: &str) -> Option<&str> {
    let mut words = command.split_whitespace();
    let program = words.next()?;
    if Path::new(program).file_name()? != "kr-worker" {
        return None;
    }
    words.skip_while(|word| *word != "--session").nth(1)
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
    let free = Deadline::after(ADDRESS_FREE).poll(ADDRESS_FREE, ADDRESS_ASK_AGAIN, |_| {
        match std::net::UdpSocket::bind(address) {
            Ok(socket) => {
                drop(socket);
                ControlFlow::Break(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                ControlFlow::Continue(error.to_string())
            }
            Err(error) => panic!("the daemon's address {address} cannot be bound: {error}"),
        }
    });
    if let Err(heard) = free {
        panic!("the daemon's address {address} stayed held for {ADDRESS_FREE:?}: {heard}");
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

    /// A host over a run's tree with no daemon started.
    fn host_over(run: &Run) -> Host<'_> {
        let paths = HostPaths::new(run.root().join("r"), run.root().join("s"))
            .expect("absolute host roots");
        let identity = paths
            .open_environment_id()
            .expect("the environment's identity");
        let environment = paths.environment(identity);
        environment.create().expect("the environment's directories");
        Host {
            run,
            paths,
            environment,
            shell_packages: None,
            daemon: Mutex::new(None),
            control: Mutex::new(None),
            agent_started: AtomicBool::new(false),
            kr_after_start: Arc::default(),
        }
    }

    /// The text the host's stop gives for a daemon that ended with a failure.
    fn error_of_a_failing_daemon(host: &Host<'_>) -> String {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .expect("a process to stand for the daemon");
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
        let root = std::path::PathBuf::from(format!(
            "/private/tmp/kt-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        std::fs::create_dir_all(&root).expect("a short run directory");
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
            let child = Command::new("/bin/sh")
                .args(["-c", "trap 'exit 0' INT; while :; do /bin/sleep 1; done"])
                .stdin(Stdio::null())
                .spawn()
                .expect("a process to stand for the daemon");
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
            let alive: Vec<String> = run
                .owned()
                .iter()
                .filter(|owned| running(&owned.identity))
                .map(|owned| owned.what.clone())
                .collect();
            assert!(alive.is_empty(), "still running: {alive:?}");
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
        let root = PathBuf::from(format!(
            "/private/tmp/kt-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        std::fs::create_dir_all(&root).expect("a short run directory");
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
        let root = PathBuf::from(format!(
            "/private/tmp/kt-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        std::fs::create_dir_all(&root).expect("a short run directory");
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
