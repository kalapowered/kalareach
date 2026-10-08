//! What a suite that starts a control daemon owes the machine when a test ends.
//!
//! A test's own path closes the sessions it made, and each worker ends with its session. A test
//! that fails part way through never reaches its closes, and a worker is deliberately not a child
//! of the daemon that asked for it: it outlives that daemon, the test and the test's host tree, and
//! runs its shell until the machine restarts. So the tree a test holds ends, before it goes, every
//! worker its daemon started, whichever way the test ended.
//!
//! Two rules make that complete and make it touch nothing else.
//!
//! Nothing starts after the count. A daemon that runs inside the test launches through the tree's
//! own supervisor, which the teardown closes before it looks: a launch already under way finishes
//! first, and none begins afterwards. A daemon that runs as a process of its own is ended by its
//! harness before the tree is dropped.
//!
//! Nothing is signalled by a number the test does not hold. A worker is asked to close its session
//! through its own endpoint and ends itself; a job is removed by its service manager; and a signal
//! goes only to a process this test process started and has not collected, whose number nothing
//! else can be given until it is collected. A worker that none of these reaches is reported, and
//! the tree is kept rather than removed from under it.
//!
//! What was started is read from two places: what the tree's supervisor launched, and the daemon's
//! registry, whose launch records hold the process identity of everything it started, whatever
//! became of the reservation afterwards, and whose worker table holds the workers that reported
//! themselves ready. The registry is read without writing to it, both in one read transaction.
//!
//! Every job registered for the tree goes before the tree does, whoever registered it: a job its
//! service manager keeps outlives the test, and once the tree is gone it names a program nothing
//! can find. A launchd job is known by its definition, which is written into the jobs directory of
//! one of the tree's environments, and a systemd unit by the directory it runs in, which is inside
//! the tree. A job still registered once the tree has tried to remove it fails the test, and the
//! tree is kept. A job registered for anything else is never looked at.
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::io::Write as _;
use std::ops::Deref;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kr_controller::supervision::{LaunchOutcome, ServiceLaunch, WorkerLaunch, WorkerSupervisor};
use kr_ipc::identity::{ProcessState, process_state};
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::testing::TempHost;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};

/// How long a launch the registry records as under way is given to record what it started, and how
/// long each signal is given.
const PATIENCE: Duration = Duration::from_secs(5);

/// How long one call to the platform's own tools, one request to a worker, or one launch already
/// under way when the teardown begins may take.
const TOOL_BOUND: Duration = Duration::from_secs(10);

/// How long the workers asked to close are given, all together, to answer: a connection, a proof
/// of identity and the close itself, each within [`TOOL_BOUND`], and a margin.
const ASKING_BOUND: Duration = Duration::from_secs(35);

/// A host tree whose daemon's workers are ended before the tree goes, however the test ended.
///
/// It is the tree a test would otherwise hold, and reads as one. A tree in which something the
/// daemon started cannot be established as ended is kept, and where it is is printed: a live
/// worker reading a directory removed underneath it is a worse state to leave the machine in than
/// a directory to remove.
pub struct Tree {
    tree: Option<TempHost>,
    launches: Arc<Launches>,
}

/// What the tree's own supervisor has started, whether it may start anything more, and how many of
/// its launches are under way.
#[derive(Debug, Default)]
struct Launches {
    state: Mutex<LaunchState>,
    /// Signalled whenever a launch finishes.
    finished: Condvar,
}

#[derive(Debug, Default)]
struct LaunchState {
    closed: bool,
    under_way: usize,
    started: Vec<ProcessStartIdentity>,
    /// Why something that shares the tree's life asked for it to be kept.
    held: Vec<String>,
}

impl Launches {
    fn lock(&self) -> MutexGuard<'_, LaunchState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admits no launch from here on, waits at most [`TOOL_BOUND`] for the ones already admitted to
    /// finish, and returns what was started and how many are still under way.
    fn close(&self) -> (Vec<ProcessStartIdentity>, usize, Vec<String>) {
        let mut state = self.lock();
        state.closed = true;
        let deadline = Instant::now() + TOOL_BOUND;
        while state.under_way > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            state = match self.finished.wait_timeout(state, left) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        (
            std::mem::take(&mut state.started),
            state.under_way,
            std::mem::take(&mut state.held),
        )
    }
}

/// Keeps the tree it came from, for something that shares the tree's life and cannot establish
/// that its own part has ended, such as a daemon running as a process of its own.
#[derive(Clone, Debug)]
pub struct Holder(Arc<Launches>);

impl Holder {
    /// Keeps the tree when it is dropped, saying why.
    pub fn hold(&self, why: String) {
        self.0.lock().held.push(why);
    }
}

impl Tree {
    /// Creates a fresh tree under the platform's temporary directory.
    pub fn create() -> Self {
        Self {
            tree: Some(TempHost::create()),
            launches: Arc::default(),
        }
    }

    /// Creates a fresh tree whose state root is the tree's directory `state_name`.
    pub fn create_with_state_name(state_name: &str) -> Self {
        Self {
            tree: Some(TempHost::create_with_state_name(
                &std::env::temp_dir(),
                state_name,
            )),
            launches: Arc::default(),
        }
    }

    /// Something that can keep this tree when it is dropped.
    pub fn holder(&self) -> Holder {
        Holder(Arc::clone(&self.launches))
    }

    /// Keeps this tree when it is dropped, saying why.
    pub fn hold(&self, why: String) {
        self.holder().hold(why);
    }

    /// The supervisor a daemon running inside this test launches through: `inner`, which the
    /// tree's teardown closes to new launches before it counts what was started.
    pub fn supervisor(&self, inner: Box<dyn WorkerSupervisor>) -> Box<dyn WorkerSupervisor> {
        Box::new(Closable {
            inner,
            launches: Arc::clone(&self.launches),
        })
    }
}

impl Deref for Tree {
    type Target = TempHost;

    fn deref(&self) -> &TempHost {
        self.tree
            .as_ref()
            .expect("the tree is held until it is dropped")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let Some(tree) = self.tree.take() else {
            return;
        };
        // From here the tree's supervisor starts nothing, and a launch it had already admitted is
        // waited for, within a bound, so what it started is counted.
        let (launched, under_way, held) = self.launches.close();
        let mut unresolved = held;
        if under_way > 0 {
            unresolved.push(format!(
                "{under_way} launches were still under way {TOOL_BOUND:?} after this host was closed \
                 to new ones"
            ));
        }
        unresolved.extend(end_what_the_daemon_started(&tree.environment(), launched));
        // Then every job registered for the tree. A worker still inside one did not complete its
        // own closure, is reported above, and is ended by its service manager as the job goes.
        let jobs_left = remove_jobs(&tree);
        if unresolved.is_empty() && jobs_left.is_empty() {
            return;
        }
        // Kept first, so nothing the lines below do can let the tree go.
        let root = tree.root().to_path_buf();
        std::mem::forget(tree);
        for what in &unresolved {
            say(format_args!(
                "could not establish that what this test started has ended: {what}"
            ));
        }
        for job in &jobs_left {
            say(format_args!(
                "a job registered for this test is still registered: {job}"
            ));
        }
        say(format_args!(
            "the host tree has been kept at {}",
            root.display()
        ));
        // A job left registered outlives the test, so the test fails; one already failing has
        // said so, and a second panic would end the whole run instead.
        if !jobs_left.is_empty() && !std::thread::panicking() {
            panic!(
                "this test left {} jobs registered with the service manager: {}",
                jobs_left.len(),
                jobs_left.join("; ")
            );
        }
    }
}

/// `inner`, closed to new launches once the tree's teardown has begun.
#[derive(Debug)]
struct Closable {
    inner: Box<dyn WorkerSupervisor>,
    launches: Arc<Launches>,
}

impl Closable {
    fn launch(&self, start: impl FnOnce() -> LaunchOutcome) -> LaunchOutcome {
        // Admitted under the lock, so a launch either counts as under way before the teardown
        // closes this, or is refused.
        {
            let mut state = self.launches.lock();
            if state.closed {
                return LaunchOutcome::NotStarted {
                    detail: "this host's teardown has begun, so it starts nothing".to_owned(),
                };
            }
            state.under_way += 1;
        }
        let outcome = start();
        let mut state = self.launches.lock();
        state.under_way -= 1;
        match &outcome {
            LaunchOutcome::Started(identity) => state.started.push(identity.clone()),
            LaunchOutcome::Uncertain { pid: Some(pid), .. } => {
                if let Ok(identity) = kr_ipc::identity::process_start_identity(*pid) {
                    state.started.push(identity);
                }
            }
            _ => {}
        }
        self.launches.finished.notify_all();
        outcome
    }
}

impl WorkerSupervisor for Closable {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        self.launch(|| self.inner.start(launch))
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.launch(|| self.inner.start_service(launch))
    }

    fn describe(&self) -> &'static str {
        self.inner.describe()
    }
}

/// Ends every process the daemon of `environment` started that is still running, `launched` among
/// them, and returns what it could not establish as ended.
pub fn end_what_the_daemon_started(
    environment: &EnvironmentPaths,
    launched: Vec<ProcessStartIdentity>,
) -> Vec<String> {
    let mut unresolved = Vec::new();

    // What was started. A launch recorded as under way records its process within moments, so the
    // registry is read again, within a bound, until none is.
    let settle_by = Instant::now() + PATIENCE;
    let recorded = loop {
        match recorded(environment) {
            Ok(recorded) if recorded.in_flight > 0 && Instant::now() < settle_by => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(recorded) => break recorded,
            Err(error) => {
                unresolved.push(error);
                break Recorded::default();
            }
        }
    };
    if recorded.in_flight > 0 {
        unresolved.push(format!(
            "{} launch records name no process yet, so what they started cannot be found",
            recorded.in_flight
        ));
    }
    let mut started = recorded.started;
    started.sort();
    started.dedup_by(|later, earlier| later.0 == earlier.0);
    // The registry's name for a process says which session it served, so a launch the registry
    // recorded keeps that name.
    for identity in launched {
        if !started.iter().any(|(known, _)| *known == identity) {
            let what = format!(
                "the process {} this host's supervisor started",
                identity.pid.get()
            );
            started.push((identity, what));
        }
    }

    // Every worker still running is asked, through its own endpoint, to close its session, and is
    // given the whole of the worker's own closure to do it: the grace its processes have to stop,
    // the drain after them and a margin for a busy machine. A worker closing its own session ends
    // what it started, which no other way of ending it establishes.
    started.retain(|(identity, _)| running_or_unknown(identity));
    let mut accepted = Vec::new();
    let closure = kr_worker::session::GRACE_PERIOD + kr_worker::session::DRAIN_PERIOD + TOOL_BOUND;
    if !started.is_empty() {
        for (_, what) in &started {
            say(format_args!(
                "ending {what}, which this test started and did not close"
            ));
        }
        accepted = ask_to_close(environment);
        wait_for_the_end(&mut started, closure);
    }

    if started.is_empty() {
        return unresolved;
    }

    // What is still running did not complete its own closure. A signal goes only to this test
    // process's own child, and a worker ended by a signal or by launchd may leave what it started
    // behind, so each one leaves the tree kept.
    for (identity, what) in &started {
        let answer = if accepted.contains(identity) {
            "accepted its close"
        } else {
            "did not accept a close"
        };
        unresolved.push(format!(
            "{what} {answer} and was still running {closure:?} later"
        ));
    }
    #[cfg(unix)]
    {
        let mut children: Vec<_> = started
            .into_iter()
            .filter(|(identity, _)| is_own_child(identity))
            .collect();
        for signal in ["-TERM", "-KILL"] {
            if children.is_empty() {
                break;
            }
            for (identity, what) in &children {
                if let Err(error) = signal_child(identity, signal) {
                    say(format_args!("signalling {what}: {error}"));
                }
            }
            wait_for_the_end(&mut children, PATIENCE);
        }
        unresolved.extend(
            children
                .into_iter()
                .map(|(_, what)| format!("{what} was signalled and has not ended")),
        );
    }
    unresolved
}

/// Waits at most `bound` for the kernel to say that each process has ended, and keeps the ones it
/// has not said so of.
fn wait_for_the_end(following: &mut Vec<(ProcessStartIdentity, String)>, bound: Duration) {
    let deadline = Instant::now() + bound;
    loop {
        following.retain(|(identity, _)| running_or_unknown(identity));
        if following.is_empty() || Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What the registry says was started, and how many launches have yet to say.
#[derive(Default)]
struct Recorded {
    /// Every process identity the daemon recorded, with what it was for.
    started: Vec<(ProcessStartIdentity, String)>,
    /// Reservations reserved or spawned with no process identity recorded yet.
    in_flight: usize,
}

/// Reads the registry through a connection that cannot write, both answers in one read
/// transaction, and waits at most [`PATIENCE`] for a writer to finish.
fn recorded(environment: &EnvironmentPaths) -> Result<Recorded, String> {
    let database = environment.registry_database();
    if !database.exists() {
        // No daemon ever ran on this tree, so nothing was started.
        return Ok(Recorded::default());
    }
    let unreadable =
        |error: rusqlite::Error| format!("this host's registry could not be read: {error}");
    let mut connection = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(unreadable)?;
    connection.busy_timeout(PATIENCE).map_err(unreadable)?;
    // One snapshot for both questions: a launch that records its process between them is either
    // in both answers' world or in neither's.
    let transaction = connection.transaction().map_err(unreadable)?;
    let mut started = Vec::new();
    {
        let mut statement = transaction
            .prepare(
                "SELECT launcher_pid, launcher_source, launcher_start, lower(hex(session_id))
                 FROM reservations WHERE launcher_pid IS NOT NULL
                 UNION ALL
                 SELECT process_pid, process_source, process_start, lower(hex(session_id))
                 FROM workers",
            )
            .map_err(unreadable)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(unreadable)?;
        for row in rows {
            let (pid, source, start, session) = row.map_err(unreadable)?;
            let known: ProcessStartSource = serde_json::from_value(serde_json::Value::String(
                source.clone(),
            ))
            .map_err(|_| {
                format!(
                    "a recorded process identity names a source this build does not know: {source}"
                )
            })?;
            let identity = ProcessStartIdentity::new(
                u64::try_from(pid).unwrap_or_default(),
                known,
                u64::try_from(start).unwrap_or_default(),
            );
            started.push((identity, format!("the worker of session {session}")));
        }
    }
    let in_flight: i64 = transaction
        .query_row(
            "SELECT count(*) FROM reservations
             WHERE phase IN ('reserved', 'spawned') AND launcher_pid IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(unreadable)?;
    Ok(Recorded {
        started,
        in_flight: usize::try_from(in_flight).unwrap_or_default(),
    })
}

/// Whether the kernel says the recorded process is still running, or will not say.
fn running_or_unknown(identity: &ProcessStartIdentity) -> bool {
    !matches!(process_state(identity), ProcessState::Ended)
}

/// Asks every running worker that published a descriptor in this environment to close its session,
/// through its own endpoint, and returns the ones that accepted.
///
/// Each worker is first made to prove that it is the one its descriptor names, so a request reaches
/// no process but that worker, which then ends itself: nothing here names a process by its number.
/// The workers are asked together, on a runtime on a thread of its own because this runs inside a
/// drop, and none of it is waited for longer than [`ASKING_BOUND`].
fn ask_to_close(environment: &EnvironmentPaths) -> Vec<ProcessStartIdentity> {
    let Ok(entries) = kr_ipc::descriptor::read_all(environment) else {
        return Vec::new();
    };
    let workers: Vec<_> = entries
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .filter(|descriptor| running_or_unknown(&descriptor.process_start_identity))
        .collect();
    if workers.is_empty() {
        return Vec::new();
    }
    let environment_id = environment.environment_id();
    let (answered, answers) = std::sync::mpsc::channel();
    let asking = std::thread::Builder::new()
        .name("asking workers to close".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let accepted = runtime.block_on(async move {
                let mut asks = tokio::task::JoinSet::new();
                for worker in workers {
                    asks.spawn(ask_one_to_close(worker, environment_id));
                }
                let mut accepted = Vec::new();
                while let Some(answer) = asks.join_next().await {
                    if let Ok(Some(identity)) = answer {
                        accepted.push(identity);
                    }
                }
                accepted
            });
            let _ = answered.send(accepted);
            // A request stuck where no timeout reaches it is left behind rather than waited for.
            runtime.shutdown_timeout(Duration::from_secs(1));
        });
    if let Err(error) = asking {
        say(format_args!(
            "the workers could not be asked to close: {error}"
        ));
        return Vec::new();
    }
    answers.recv_timeout(ASKING_BOUND).unwrap_or_else(|_| {
        say(format_args!(
            "the workers asked to close had not all answered within {ASKING_BOUND:?}"
        ));
        Vec::new()
    })
}

/// Asks one worker to close its session, once it has proved it is the worker its descriptor names,
/// and returns its identity when it accepted.
pub async fn ask_one_to_close(
    worker: kr_protocol::worker::WorkerDescriptor,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Option<ProcessStartIdentity> {
    let endpoint = kr_ipc::paths::Endpoint::from_path(worker.endpoint.clone()).ok()?;
    let mut client = tokio::time::timeout(
        TOOL_BOUND,
        kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            kr_protocol::ids::BuildId::new("kr-test/0").ok()?,
        ),
    )
    .await
    .ok()?
    .ok()?;
    tokio::time::timeout(TOOL_BOUND, client.verify_worker(&worker))
        .await
        .ok()?
        .ok()?;
    let answer = tokio::time::timeout(
        TOOL_BOUND,
        client.mutate(
            kr_protocol::method::Method::SessionClose,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget {
                environment_id,
                session_id: kr_protocol::scalars::Nullable::some(worker.session_id),
                session_epoch: kr_protocol::scalars::Nullable::some(worker.session_epoch),
                application_instance_id: kr_protocol::scalars::Nullable::null(),
                agent_binding_revision: kr_protocol::scalars::Nullable::null(),
            },
            &kr_protocol::session::SessionCloseParams {
                session_id: worker.session_id,
            },
        ),
    )
    .await
    .ok()?;
    matches!(answer, Ok(Ok(_))).then_some(worker.process_start_identity)
}

/// Whether the recorded process is this test process's own child, which it has not collected.
///
/// The parent is asked first. A child keeps its number until its parent collects it, and the tests
/// never collect their daemons' workers, so a number established as a child's cannot come to name
/// anything else before the signal; the identity is then checked to be the one recorded.
#[cfg(unix)]
fn is_own_child(identity: &ProcessStartIdentity) -> bool {
    let Ok(parent) = run_bounded_output(
        Command::new("/bin/ps")
            .args(["-o", "ppid=", "-p"])
            .arg(identity.pid.get().to_string()),
    ) else {
        return false;
    };
    parent.trim().parse::<u32>().ok() == Some(std::process::id())
        && matches!(process_state(identity), ProcessState::Running)
}

/// Sends `signal` to one of this test process's own children.
#[cfg(unix)]
fn signal_child(identity: &ProcessStartIdentity, signal: &str) -> Result<(), String> {
    let status = run_bounded(
        Command::new("/bin/kill")
            .arg(signal)
            .arg(identity.pid.get().to_string()),
    )?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill {signal} answered {status}"))
    }
}

/// Runs one of the platform's own tools to its end, for no longer than [`TOOL_BOUND`], and says
/// how it ended.
fn run_bounded(command: &mut Command) -> Result<ExitStatus, String> {
    command.stdout(Stdio::null());
    finish_bounded(command).map(|(status, _)| status)
}

/// Runs one of the platform's own tools to its end, for no longer than [`TOOL_BOUND`], and returns
/// what it printed when it succeeded.
fn run_bounded_output(command: &mut Command) -> Result<String, String> {
    command.stdout(Stdio::piped());
    let (status, printed) = finish_bounded(command)?;
    if status.success() {
        Ok(printed)
    } else {
        Err(format!("{command:?} answered {status}"))
    }
}

fn finish_bounded(command: &mut Command) -> Result<(ExitStatus, String), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{command:?} could not be started: {error}"))?;
    // What it prints is read while it runs: a tool that fills its pipe waits for a reader before it
    // can end, and one read only afterwards would be reported as not finishing. A tool ended below
    // closes its pipe, which ends the reading as well.
    let printed = child.stdout.take().map(|mut stdout| {
        let (read, printed) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = std::io::Read::read_to_string(&mut stdout, &mut text);
            let _ = read.send(text);
        });
        printed
    });
    let deadline = Instant::now() + TOOL_BOUND;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Read to its end once the pipe closes, which is when the tool ends unless
                // something it started still holds the pipe; that is waited for until the bound,
                // or for [`PATIENCE`] where less of it is left.
                let left = deadline.saturating_duration_since(Instant::now());
                let printed = printed
                    .and_then(|printed| printed.recv_timeout(left.max(PATIENCE)).ok())
                    .unwrap_or_default();
                return Ok((status, printed));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let failed = end_and_collect(&mut child);
                return Err(format!(
                    "{command:?} did not finish within {TOOL_BOUND:?}{failed}"
                ));
            }
            // This process's own child, so it is ended and collected here too.
            Err(error) => {
                let failed = end_and_collect(&mut child);
                return Err(format!(
                    "{command:?} could not be waited for: {error}{failed}"
                ));
            }
        }
    }
}

/// Ends one of this process's own children that it has not collected, and collects it within
/// [`PATIENCE`]; returns what of that failed, as text to add to a reason, or nothing.
fn end_and_collect(child: &mut std::process::Child) -> String {
    let mut failed = String::new();
    if let Err(error) = child.kill() {
        failed.push_str(&format!("; ending it failed: {error}"));
    }
    let deadline = Instant::now() + PATIENCE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return failed,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                failed.push_str(&format!(
                    "; it was still running {PATIENCE:?} after it was ended"
                ));
                return failed;
            }
            Err(error) => {
                failed.push_str(&format!("; collecting it failed: {error}"));
                return failed;
            }
        }
    }
}

/// Writes one line to the test's error output. A write that fails is no reason to stop a teardown.
fn say(line: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Removes every launchd job whose definition is in the jobs directory of one of `tree`'s
/// environments from each of this user's domains that has it loaded, and returns each job that is
/// still loaded afterwards or that could not be established as removed.
///
/// A job the daemon bootstrapped can stay loaded after its worker has ended, and a test that starts
/// its workers through launchd would then leave one behind on every run. Every environment in the
/// tree is looked at, not only the one it was created with, and each definition is named after its
/// job's label. Removing a job ends the process in it, which launchd does as the process's parent.
#[cfg(target_os = "macos")]
fn remove_jobs(tree: &TempHost) -> Vec<String> {
    let mut left = Vec::new();
    let environments = tree.paths().state_root().join("environments");
    for environment in listed(&environments, &mut left) {
        if !environment.is_dir() {
            continue;
        }
        for definition in listed(&environment.join("jobs"), &mut left) {
            if definition
                .extension()
                .is_none_or(|extension| extension != "plist")
            {
                continue;
            }
            let Some(label) = definition.file_stem().and_then(|stem| stem.to_str()) else {
                left.push(format!("{} names no label", definition.display()));
                continue;
            };
            left.extend(remove_launchd_job(label));
        }
    }
    left
}

/// Removes the launchd job `label` from each of this user's domains that has it loaded, and says
/// where it is still loaded afterwards or could not be established as removed.
#[cfg(target_os = "macos")]
fn remove_launchd_job(label: &str) -> Vec<String> {
    let mut left = Vec::new();
    let uid = kr_ipc::paths::current_uid();
    for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
        let target = format!("{domain}/{label}");
        match loaded(&target) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                left.push(error);
                continue;
            }
        }
        let removal = run_bounded(Command::new("/bin/launchctl").arg("bootout").arg(&target));
        match loaded(&target) {
            Ok(false) => {}
            Ok(true) => left.push(format!(
                "the launchd job {target} is still loaded after its removal ({removal:?})"
            )),
            Err(error) => left.push(error),
        }
    }
    left
}

/// Returns the entries of `directory`, none where it does not exist, and says in `left` what could
/// not be read: a definition that cannot be listed is a job that cannot be established as removed.
#[cfg(target_os = "macos")]
fn listed(directory: &std::path::Path, left: &mut Vec<String>) -> Vec<std::path::PathBuf> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            left.push(format!(
                "{} could not be listed: {error}",
                directory.display()
            ));
            return Vec::new();
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(error) => left.push(format!(
                "an entry of {} could not be read: {error}",
                directory.display()
            )),
        }
    }
    paths
}

/// The units this host starts a job as: its labels, `kr-worker-<reservation>` and
/// `kr-plugin-host-<reservation>`, as systemd names a service.
#[cfg(target_os = "linux")]
const JOB_LABEL_PATTERNS: [&str; 2] = ["kr-worker-*.service", "kr-plugin-host-*.service"];

/// Stops every systemd user unit with a label this host gives a job whose working directory is
/// inside `tree`, clears what the manager keeps of it, and returns each unit that is still loaded
/// afterwards or that could not be established as gone.
#[cfg(target_os = "linux")]
fn remove_jobs(tree: &TempHost) -> Vec<String> {
    remove_units_through(tree, std::path::Path::new("systemctl"))
}

/// Does what [`remove_jobs`] does, asking the user manager through `systemctl`, and returns each
/// unit still loaded afterwards and each question the manager did not answer.
///
/// A transient unit is collected once its process has ended, but one whose process is still
/// running outlives the test and the tree its program was in. A unit is this tree's when the
/// directory it runs in is inside the tree, which the host sets for every job it starts; a unit
/// that runs anywhere else is never touched. An account with no user manager running has no unit
/// to remove, and that is read from where every user manager listens, its private socket in the
/// runtime directory, rather than from a question that fails: a manager that is there and does not
/// answer leaves every unit it may hold not established as gone.
#[cfg(target_os = "linux")]
pub fn remove_units_through(tree: &TempHost, systemctl: &std::path::Path) -> Vec<String> {
    let mut left = Vec::new();
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return left;
    };
    if !std::path::Path::new(&runtime)
        .join("systemd/private")
        .exists()
    {
        return left;
    }
    let manager = || {
        let mut command = Command::new(systemctl);
        command.arg("--user");
        command
    };
    let listed = match run_bounded_output(
        manager()
            .args([
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--type=service",
            ])
            .args(JOB_LABEL_PATTERNS),
    ) {
        Ok(listed) => listed,
        Err(error) => {
            left.push(format!(
                "the user manager's units could not be listed: {error}"
            ));
            return left;
        }
    };
    let units: Vec<&str> = listed
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    if units.is_empty() {
        return left;
    }
    let shown = match run_bounded_output(
        manager()
            .args(["show", "--property=Id,WorkingDirectory"])
            .args(&units),
    ) {
        Ok(shown) => shown,
        Err(error) => {
            left.push(format!(
                "the user manager's units could not be read: {error}"
            ));
            return left;
        }
    };
    // The tree as it was named and as the kernel resolves it, since a daemon may hand a unit
    // either spelling.
    let roots: Vec<std::path::PathBuf> = [
        Some(tree.root().to_path_buf()),
        tree.root().canonicalize().ok(),
    ]
    .into_iter()
    .flatten()
    .collect();
    for described in shown.split("\n\n") {
        let property = |name: &str| {
            described
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
        };
        let (Some(unit), Some(directory)) = (property("Id"), property("WorkingDirectory")) else {
            continue;
        };
        if directory.is_empty()
            || !roots
                .iter()
                .any(|root| std::path::Path::new(directory).starts_with(root))
        {
            continue;
        }
        // Stopping the unit ends the process in it, which the manager does as its parent, and a
        // unit that failed is kept listed until it is reset.
        let stopped = run_bounded(manager().args(["stop", unit]));
        let reset = run_bounded(manager().args(["reset-failed", unit]));
        match unit_gone(&manager, unit) {
            Ok(true) => {}
            Ok(false) => left.push(format!(
                "the systemd unit {unit} is still loaded after it was stopped ({stopped:?}) and \
                 reset ({reset:?})"
            )),
            Err(error) => left.push(error),
        }
    }
    left
}

/// Whether the user manager `manager` asks no longer has `unit`, given at most [`PATIENCE`] to
/// collect it, or why that could not be established.
#[cfg(target_os = "linux")]
fn unit_gone(manager: &dyn Fn() -> Command, unit: &str) -> Result<bool, String> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let state =
            run_bounded_output(manager().args(["show", "--property=LoadState", "--value", unit]))?;
        if state.trim() == "not-found" {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Only launchd and systemd keep a job of this kind, so elsewhere there is nothing to remove.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn remove_jobs(_tree: &TempHost) -> Vec<String> {
    Vec::new()
}

/// Whether launchd has `target` loaded: yes, no, or why that could not be established. launchd
/// answers 113 for a job a domain does not have, and 112 for a domain that is not there, such as
/// the graphical domain of a user who is not logged in, which has nothing loaded in it.
#[cfg(target_os = "macos")]
fn loaded(target: &str) -> Result<bool, String> {
    const NO_SUCH_DOMAIN: i32 = 112;
    const NOT_LOADED: i32 = 113;
    let status = run_bounded(Command::new("/bin/launchctl").arg("print").arg(target))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(NO_SUCH_DOMAIN | NOT_LOADED) => Ok(false),
        _ => Err(format!(
            "launchctl could not say whether {target} is loaded: {status}"
        )),
    }
}
