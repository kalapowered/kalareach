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
//! stop, with the interrupt it answers.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::EnvironmentId;
use serde_json::Value;

use crate::LIVENESS;
use crate::run::{Run, ended_within, output_within, running, signal};

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
/// rather than a step's bound after it. What the deadline does not bound is the handover of a
/// finished `kr`'s output, which [`output_within`] bounds by itself.
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

    /// What is left of the wait, and never more than `step`: the bound for one step inside it.
    fn bound(self, step: Duration) -> Duration {
        self.at.saturating_duration_since(Instant::now()).min(step)
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
        loop {
            let bound = self.bound(each);
            if bound.is_zero() {
                return Err(heard);
            }
            match step(bound) {
                ControlFlow::Break(answer) => return Ok(answer),
                ControlFlow::Continue(said) => heard = said,
            }
            std::thread::sleep(self.bound(pause));
        }
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

/// What a host is started with.
#[derive(Clone, Debug, Default)]
pub struct HostOptions {
    /// The managed shell packages the daemon resolves, when the leg runs a managed session.
    pub shell_packages: Option<PathBuf>,
}

/// A running host.
#[derive(Debug)]
pub struct Host<'r> {
    run: &'r Run,
    paths: HostPaths,
    environment: EnvironmentPaths,
    shell_packages: Option<PathBuf>,
    daemon: Mutex<Option<Daemon>>,
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
        let paths = HostPaths::new(run.root().join("r"), run.root().join("s"))
            .expect("absolute host roots");
        // The same identity the daemon opens when it starts: it reads the one that is there.
        let environment_id = paths
            .open_environment_id()
            .expect("the environment's identity");
        let environment = paths.environment(environment_id);
        environment.create().expect("the environment's directories");
        write_configuration(&environment);
        let host = Self {
            run,
            paths,
            environment,
            shell_packages: options.shell_packages.clone(),
            daemon: Mutex::new(None),
        };
        host.start_daemon();
        host
    }

    fn start_daemon(&self) {
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
        let child = command.spawn().expect("the daemon starts");
        let identity = self
            .run
            .record_child(child.id(), "the control daemon")
            .unwrap_or_else(|| panic!("the daemon ended at once: {}", self.daemon_said()));
        *self.daemon.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Daemon { child, identity });
        let answered = Deadline::after(LIVENESS).poll(CLEANUP_COMMAND, ASK_AGAIN, |bound| {
            let heard = match self.kr_within(&["list", "--json"], bound) {
                Ok(output) if output.status.success() => return ControlFlow::Break(()),
                Ok(output) => format!("kr list ended with {}", output.status),
                Err(why) => format!("kr list {why}"),
            };
            let ended = self
                .daemon
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
                .is_some_and(|daemon| daemon.child.try_wait().ok().flatten().is_some());
            assert!(
                !ended,
                "the control daemon exited before it answered: {}",
                self.daemon_said()
            );
            ControlFlow::Continue(heard)
        });
        if let Err(heard) = answered {
            panic!(
                "the control daemon did not answer within {LIVENESS:?} ({heard}): {}",
                self.daemon_said()
            );
        }
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

    fn daemon_log(&self) -> PathBuf {
        self.run.root().join("controller.log")
    }

    /// The last of what the daemon wrote, for a failure message.
    #[must_use]
    pub fn daemon_said(&self) -> String {
        let text = std::fs::read_to_string(self.daemon_log()).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(40);
        lines[start..].join("\n")
    }

    /// Records every worker this host's registry names, with everything that runs beneath it, by
    /// start identity.
    ///
    /// The registry is where the host itself keeps each worker's identity, and it is readable
    /// whether or not the daemon still answers. So a leg that stops part way still reaches the
    /// sessions it made, their shells and what runs in them, through the record rather than by a
    /// name. A search that does not finish is kept with the run, whose closing check then fails
    /// rather than report a search that did not finish, and it is tried again within
    /// [`DISCOVERY`] so that the run can still end what a later search finds. A later search that
    /// finishes does not clear the earlier failure: what the earlier one missed may since have
    /// left the tree it searched.
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
        let registry = kr_controller::registry::Registry::open(
            self.environment.registry_database(),
            self.environment.environment_id(),
        )
        .map_err(|error| format!("the host's registry could not be opened: {error}"))?;
        let workers = registry
            .workers()
            .map_err(|error| format!("the host's registry could not be read: {error}"))?;
        drop(registry);
        for worker in workers {
            let what = format!("the worker of session {}", worker.session_id);
            self.run.record(worker.process_identity.clone(), &what);
            self.run
                .record_descendants(&worker.process_identity, &format!("under {what}"))?;
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
    #[must_use]
    pub fn command(&self, arguments: &[&str]) -> Command {
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
    /// # Errors
    ///
    /// Returns why it did not finish.
    pub fn kr_within(&self, arguments: &[&str], within: Duration) -> Result<Output, String> {
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

    /// Closes every live session and waits until `kr list` names none.
    ///
    /// Listing, closing and waiting share one deadline, [`LIVENESS`] from the start, and each `kr`
    /// is given what is left of it and never more than [`CLEANUP_COMMAND`].
    fn close_sessions(&self) -> Result<(), String> {
        let deadline = Deadline::after(LIVENESS);
        let mut problems = Vec::new();
        for session in self.listed_sessions(deadline.bound(CLEANUP_COMMAND))? {
            let display = session["display_number"].to_string();
            let closed = self.kr_within(
                &["close", &display, "--json"],
                deadline.bound(CLEANUP_COMMAND),
            );
            if !closed.is_ok_and(|output| output.status.success()) {
                problems.push(format!("session {display} could not be closed"));
            }
        }
        let emptied = deadline.poll(CLEANUP_COMMAND, LIST_AGAIN, |bound| {
            match self.listed_sessions(bound) {
                Ok(open) if open.is_empty() => ControlFlow::Break(()),
                Ok(open) => ControlFlow::Continue(format!(
                    "{} sessions were still open when the {LIVENESS:?} for closing them had passed",
                    open.len()
                )),
                Err(why) => ControlFlow::Continue(why),
            }
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
        // first, from its registry, so the run can end it even when the daemon no longer answers;
        // then the same order as a clean stop, bounded.
        self.record_workers();
        if running {
            let _ = self.close_sessions();
            let _ = self.stop_daemon();
        }
    }
}

/// Writes the environment's configuration document: this host joins the network on loopback, with
/// no relay and no discovery service.
fn write_configuration(environment: &EnvironmentPaths) {
    let path = kr_worker::config::document_path(environment);
    let document = serde_json::json!({
        "version": 1,
        "revision": 1,
        "network": {
            "enabled": true,
            "bind_address": "127.0.0.1:0",
            "local_discovery": false,
            "mainline_dht": false,
        },
    });
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

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{ExitStatus, Output};
    use std::time::{Duration, Instant};

    use super::until_closed;

    /// The bound each wait below is given.
    const BOUND: Duration = Duration::from_secs(2);

    /// How far past its bound a wait may end: the scheduler's delays and the ending of the step
    /// that was running when the bound passed. Far less than one step's whole bound, which is what
    /// a wait that compares the time only between its steps can overrun by.
    const MARGIN: Duration = Duration::from_millis(500);

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

    /// A `kr status` that answers at once until the wait is nearly over and then stops answering
    /// ends the wait at the wait's own deadline. It never reports the session closed, and once it
    /// stops answering it runs for the whole bound it is given and is ended there, as a `kr` that
    /// does not finish is.
    #[test]
    fn a_status_that_stops_answering_ends_the_wait_at_its_deadline() {
        let began = Instant::now();
        let mut asked = 0_u32;
        let waited = until_closed(BOUND, |bound| {
            asked += 1;
            if began.elapsed() < BOUND * 9 / 10 {
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
}
