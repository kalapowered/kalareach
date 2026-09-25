//! One leg's run: a directory of its own on the internal disk, the binaries it launches, and the
//! record of every process it started.
//!
//! The directory holds everything a launched process touches. A process that a service manager
//! starts is its own identity to the operating system, and one that opens a path on a removable
//! volume makes the person at the machine answer a permission prompt; so the binaries are copied
//! here and started once where nothing is timed, and every working, runtime and state directory is
//! here too.
//!
//! A process is recorded by its start identity, never by its number alone: a number comes round
//! again, and a run that signalled a number it stored earlier could end somebody else's work. So a
//! number becomes a record in one of three ways only. A child this process started is recorded
//! before it is reaped, while its number cannot pass to anyone else ([`Run::record_child`]). A
//! number learned from a listing or a file is recorded only when, read while one start holds it,
//! the process is beneath a process this run recorded ([`Run::record_descendants`]) or its command
//! line names this run's directory, which is new for every run ([`Run::record_named`]). A worker's
//! identity comes whole from the host's own registry.
//!
//! The closing check asks four questions, and a run that leaves anything behind fails on it:
//! whether any recorded process still runs, whether any process at all still runs out of this
//! run's directory, whether the service manager still holds a job this run's daemon defined, and
//! whether every search for the processes a leg's host started finished. A search that did not
//! finish fails the check for good: a later one that finished cannot show what the earlier one
//! missed.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_ipc::identity::{
    ProcessQuery, ProcessState, process_start_identity, process_state, query_process,
};
use kr_protocol::identity::ProcessStartIdentity;

/// The binaries a leg launches, by the name each is built and copied under.
///
/// `kr` looks for its restoration guard beside itself, so the two travel together.
pub const BINARIES: [&str; 4] = ["kr", "kr-attach-guard", "kr-controller", "kr-worker"];

/// How long a process asked to stop is given before it is made to.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// How long the closing check waits for recorded processes to end once everything was asked to.
const CLOSING_WAIT: Duration = Duration::from_secs(60);

/// One process this run started or learned the identity of.
#[derive(Clone, Debug)]
pub struct Owned {
    /// Who it is, as the kernel reports it.
    pub identity: ProcessStartIdentity,
    /// What it is, in words.
    pub what: String,
}

/// One leg's run.
#[derive(Debug)]
pub struct Run {
    leg: String,
    root: PathBuf,
    owned: Mutex<Vec<Owned>>,
    /// Why a search for the processes a leg's host started did not finish, once for each reason.
    ///
    /// A closing check that did not look for everything has not shown that nothing is left, so
    /// while this holds anything the check fails. Nothing clears it.
    undiscovered: Mutex<Vec<String>>,
    /// Set once the closing check has passed, so the directory can go.
    passed: Mutex<bool>,
}

impl Run {
    /// Makes the run's directory and copies the binaries into it.
    ///
    /// # Panics
    ///
    /// Panics when a binary this build should have produced is missing. `scripts/e2e-m1b.sh`
    /// builds them before it runs a leg; a leg that skipped instead would report a pass for a path
    /// it never ran.
    #[must_use]
    pub fn start(leg: &str) -> Self {
        let built = built_directory();
        for name in BINARIES {
            assert!(
                built.join(name).is_file(),
                "the {leg} leg launches {name} and there is none at {}; build it with `cargo build \
                 -p kr-cli -p kr-controller -p kr-worker --bins` or run `scripts/e2e-m1b.sh`, \
                 which does",
                built.join(name).display()
            );
        }
        // Short on purpose: a Unix socket address is 104 bytes on macOS, and the temporary
        // directory there already spends about half of that.
        let suffix = kr_ipc::new_uuid().to_string();
        let root = std::env::temp_dir().join(format!("krm-{}", &suffix[..8]));
        kr_ipc::paths::create_private_tree(&root, &root)
            .expect("an owner-only directory for this run on the internal disk");
        let root = std::fs::canonicalize(&root).expect("the run's directory resolves");
        for directory in ["b", "h", "w"] {
            kr_ipc::paths::create_private_tree(&root, &root.join(directory))
                .expect("an owner-only directory inside the run's own");
        }
        let run = Self {
            leg: leg.to_owned(),
            root,
            owned: Mutex::new(Vec::new()),
            undiscovered: Mutex::new(Vec::new()),
            passed: Mutex::new(false),
        };
        for name in BINARIES {
            // Run once here, where nothing is timed: the operating system checks a newly written
            // executable the first time it starts, and that can take seconds.
            kr_ipc::testing::place_and_start_once(
                &built.join(name),
                &run.binary(name),
                &["--version"],
            );
        }
        println!("the {leg} leg runs in {}", run.root.display());
        run
    }

    /// The leg this run belongs to.
    #[must_use]
    pub fn leg(&self) -> &str {
        &self.leg
    }

    /// The run's own directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where one copied binary is.
    #[must_use]
    pub fn binary(&self, name: &str) -> PathBuf {
        self.root.join("b").join(name)
    }

    /// The home directory every process this run starts is given, so none reads the person's own.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.join("h")
    }

    /// The directory sessions start in and agents are placed in.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.root.join("w")
    }

    /// Records a process by its identity.
    pub fn record(&self, identity: ProcessStartIdentity, what: &str) {
        let mut owned = self.owned.lock().unwrap_or_else(PoisonError::into_inner);
        if owned.iter().any(|entry| entry.identity == identity) {
            return;
        }
        owned.push(Owned {
            identity,
            what: what.to_owned(),
        });
    }

    /// Records a child this process started, by the number its spawn returned.
    ///
    /// Only for a child that has not been reaped: until it is, its number cannot pass to another
    /// process, so the start identity read now is the child's.
    pub fn record_child(&self, pid: u32, what: &str) -> Option<ProcessStartIdentity> {
        let identity = process_start_identity(pid).ok()?;
        self.record(identity.clone(), what);
        Some(identity)
    }

    /// Records the process that has the number `pid` now, when its command line names this run's
    /// directory and holds every one of `marks`; returns nothing otherwise, and when the kernel does
    /// not say.
    ///
    /// For a number learned from a process listing or a file, which can pass to another process
    /// before it is recorded. The start identity is read first and the command line after it, while
    /// that start still holds the number, so the command line is that start's. Only this run's
    /// processes name its directory, which is new for every run, and `marks` tell its processes
    /// apart.
    pub fn record_named(
        &self,
        pid: u32,
        what: &str,
        marks: &[&str],
    ) -> Option<ProcessStartIdentity> {
        let ProcessQuery::Present(identity) = query_process(pid) else {
            return None;
        };
        let described = describe(&identity).ok()??;
        let root = self.root.display().to_string();
        if !described.command.contains(&root)
            || !marks.iter().all(|mark| described.command.contains(mark))
        {
            return None;
        }
        self.record(identity.clone(), what);
        Some(identity)
    }

    /// Every process this run recorded.
    #[must_use]
    pub fn owned(&self) -> Vec<Owned> {
        self.owned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Asks every recorded process that still runs to stop, and makes it after a grace period.
    ///
    /// Only a process whose number still names the start the record holds is signalled.
    pub fn end_everything(&self) {
        let alive: Vec<Owned> = self
            .owned()
            .into_iter()
            .filter(|owned| running(&owned.identity))
            .collect();
        for owned in &alive {
            signal(&owned.identity, rustix::process::Signal::TERM);
        }
        let started = Instant::now();
        while started.elapsed() < STOP_GRACE && alive.iter().any(|o| running(&o.identity)) {
            std::thread::sleep(Duration::from_millis(50));
        }
        for owned in &alive {
            if running(&owned.identity) {
                eprintln!("{} did not stop when asked and is killed", owned.what);
                signal(&owned.identity, rustix::process::Signal::KILL);
            }
        }
    }

    /// Checks that nothing this run started is still running, and says what was checked.
    ///
    /// # Errors
    ///
    /// Returns what is still running: a recorded process, a process running out of this run's
    /// directory, or a service-manager job this run's daemon defined.
    pub fn closing_check(&self) -> Result<String, String> {
        let owned = self.owned();
        let started = Instant::now();
        while started.elapsed() < CLOSING_WAIT && owned.iter().any(|o| running(&o.identity)) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut left: Vec<String> = owned
            .iter()
            .filter(|owned| running(&owned.identity))
            .map(|owned| format!("{} (process {})", owned.what, owned.identity.pid.get()))
            .collect();
        match processes_under(&self.root) {
            Ok(found) => left.extend(
                found
                    .into_iter()
                    .map(|(pid, command)| format!("process {pid} running {command}")),
            ),
            Err(why) => left.push(why),
        }
        let jobs = self.loaded_jobs();
        left.extend(jobs.iter().map(|job| format!("the launchd job {job}")));
        left.extend(
            self.undiscovered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|why| format!("not every process could be found: {why}")),
        );
        if left.is_empty() {
            *self.passed.lock().unwrap_or_else(PoisonError::into_inner) = true;
            Ok(format!(
                "none of the {} processes this run started is running, no process runs out of \
                 its directory and no job it defined is loaded",
                owned.len()
            ))
        } else {
            Err(left.join("; "))
        }
    }

    /// The service-manager jobs this run's daemon defined that are still loaded.
    ///
    /// On macOS the daemon writes a definition for each worker's launchd job into its
    /// environment's jobs directory, and removes it once the job has gone. Every other supervisor
    /// leaves no job of this kind behind, so elsewhere this is always empty.
    #[must_use]
    pub fn loaded_jobs(&self) -> Vec<String> {
        if !cfg!(target_os = "macos") {
            return Vec::new();
        }
        let uid = rustix::process::getuid().as_raw();
        let mut loaded = Vec::new();
        for label in self.defined_jobs() {
            for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
                let target = format!("{domain}/{label}");
                let mut print = std::process::Command::new("/bin/launchctl");
                print.args(["print", &target]);
                let answer = output_within(print, SERVICE_MANAGER_BOUND);
                match answer.as_ref().map(|output| output.status.code()) {
                    // 112 is a domain that is not there and 113 a job the domain does not have.
                    Ok(Some(112 | 113)) => {}
                    Ok(Some(0)) => loaded.push(target),
                    Ok(other) => {
                        loaded.push(format!("{target} (launchctl print answered {other:?})"))
                    }
                    Err(why) => loaded.push(format!("{target} (launchctl print {why})")),
                }
            }
        }
        loaded
    }

    /// Removes every launchd job this run's daemon defined and still has loaded.
    ///
    /// For a run that failed part way: launchd ends whatever still runs inside a job it removes,
    /// and each job is named by the label this run's own daemon gave it.
    pub fn remove_loaded_jobs(&self) {
        for target in self.loaded_jobs() {
            let target = target.split(' ').next().unwrap_or_default().to_owned();
            let mut bootout = std::process::Command::new("/bin/launchctl");
            bootout.args(["bootout", &target]);
            let _ = output_within(bootout, SERVICE_MANAGER_BOUND);
        }
    }

    /// Records every process that runs beneath `ancestor` now, by its start identity, so the
    /// closing check and an ending of a failed leg reach them however they were started.
    ///
    /// A session's shell and what runs in it belong to the worker that started them, not to this
    /// run's own processes, and a command line may not name this run's directory at all. What makes
    /// them this run's is their place in the process table, below a process this run recorded.
    ///
    /// A number the table lists can pass to another process before it is recorded, so each one is
    /// checked where it is recorded: its start identity is read, then its parent and command line
    /// while that start holds the number, and then the process recorded above it must still be
    /// running, so it was the parent that was read. A process is passed over only when the kernel
    /// says it has ended; an answer the kernel or `ps` did not give ends the search with an error.
    /// A process whose parent ends while the search runs is passed over with it: it is no longer
    /// beneath anything this run recorded, and the closing check finds it only if its command line
    /// names this run's directory.
    ///
    /// # Errors
    ///
    /// Returns why the search did not finish. The failure is kept with the run too, so its closing
    /// check does not pass on a search that did not finish.
    pub fn record_descendants(
        &self,
        ancestor: &ProcessStartIdentity,
        what: &str,
    ) -> Result<(), String> {
        let found = self.descend(ancestor, what);
        if let Err(why) = &found {
            self.undiscovered(why);
        }
        found
    }

    fn descend(&self, ancestor: &ProcessStartIdentity, what: &str) -> Result<(), String> {
        if !still_running(ancestor, what)? {
            return Ok(());
        }
        let table = process_table()?;
        let mut under = vec![ancestor.clone()];
        while let Some(parent) = under.pop() {
            let parent_pid = u32::try_from(parent.pid.get())
                .map_err(|_| format!("process {} has no number ps lists", parent.pid.get()))?;
            for entry in table.iter().filter(|entry| entry.parent == parent_pid) {
                let identity = match query_process(entry.pid) {
                    ProcessQuery::Present(identity) => identity,
                    // It has ended since the table was read.
                    ProcessQuery::Gone => continue,
                    ProcessQuery::CannotEstablish(error) => {
                        return Err(format!(
                            "process {} beneath {what} could not be identified: {error}",
                            entry.pid
                        ));
                    }
                };
                let Some(described) = describe(&identity)? else {
                    continue;
                };
                if described.parent != parent_pid || !still_running(&parent, what)? {
                    continue;
                }
                self.record(identity.clone(), &format!("{what}: {}", described.command));
                under.push(identity);
            }
        }
        Ok(())
    }

    /// Keeps why a search for a leg's processes did not finish, which fails the closing check.
    pub fn undiscovered(&self, why: &str) {
        let mut reasons = self
            .undiscovered
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !reasons.iter().any(|reason| reason == why) {
            reasons.push(why.to_owned());
        }
    }

    /// The labels of every job definition this run's daemon wrote.
    fn defined_jobs(&self) -> Vec<String> {
        let environments = self.root.join("s").join("environments");
        let Ok(entries) = std::fs::read_dir(environments) else {
            return Vec::new();
        };
        let mut labels = Vec::new();
        for environment in entries.flatten() {
            let Ok(jobs) = std::fs::read_dir(environment.path().join("jobs")) else {
                continue;
            };
            for job in jobs.flatten() {
                let path = job.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "plist")
                    && let Some(label) = path.file_stem().and_then(|stem| stem.to_str())
                {
                    labels.push(label.to_owned());
                }
            }
        }
        labels
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let passed = *self.passed.lock().unwrap_or_else(PoisonError::into_inner);
        if passed {
            let _ = std::fs::remove_dir_all(&self.root);
            return;
        }
        // A leg that failed part way. What it started is ended through the record, the jobs its
        // daemon defined are removed, and what the closing check still finds is said. The
        // directory is kept: a process that outlived the leg may be reading it, and what the
        // daemon and the sessions wrote is the evidence.
        self.end_everything();
        self.remove_loaded_jobs();
        match self.closing_check() {
            Ok(checked) => eprintln!("after the {} leg failed: {checked}", self.leg),
            Err(left) => eprintln!("after the {} leg failed, still running: {left}", self.leg),
        }
        eprintln!(
            "the {} leg's directory is kept: {}",
            self.leg,
            self.root.display()
        );
    }
}

/// Whether a recorded process still runs.
///
/// A kernel that will not say is read as running, so nothing is taken to have ended without the
/// kernel saying so.
#[must_use]
pub fn running(identity: &ProcessStartIdentity) -> bool {
    !matches!(process_state(identity), ProcessState::Ended)
}

/// Sends one signal to a recorded process, only while its number still names that process.
pub fn signal(identity: &ProcessStartIdentity, signal: rustix::process::Signal) {
    if !matches!(process_state(identity), ProcessState::Running) {
        return;
    }
    let Some(pid) = i32::try_from(identity.pid.get())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    let _ = rustix::process::kill_process(pid, signal);
}

/// Waits until a recorded process has ended, and says whether it did within `within`.
#[must_use]
pub fn ended_within(identity: &ProcessStartIdentity, within: Duration) -> bool {
    let started = Instant::now();
    loop {
        if matches!(process_state(identity), ProcessState::Ended) {
            return true;
        }
        if started.elapsed() >= within {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One row of the process table.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The process.
    pub pid: u32,
    /// Its parent.
    pub parent: u32,
    /// Its command line.
    pub command: String,
}

/// The process table, as `ps` reports it.
///
/// # Errors
///
/// Returns why it could not be read. A `ps` that did not succeed has said nothing about which
/// processes run, so its empty answer is never read as "none".
pub fn process_table() -> Result<Vec<Entry>, String> {
    let mut ps = std::process::Command::new("/bin/ps");
    ps.args(["-A", "-ww", "-o", "pid=,ppid=,command="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let output = output_within(ps, SERVICE_MANAGER_BOUND)
        .map_err(|why| format!("the process table could not be read: ps {why}"))?;
    if !output.status.success() {
        return Err(format!(
            "the process table could not be read: ps ended with {}",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse().ok()?;
            let parent = fields.next()?.parse().ok()?;
            let command = fields.collect::<Vec<_>>().join(" ");
            Some(Entry {
                pid,
                parent,
                command,
            })
        })
        .collect())
}

/// What `ps` says about one process: its parent and its command line.
#[derive(Clone, Debug)]
pub struct Described {
    /// The parent's number.
    pub parent: u32,
    /// The command line.
    pub command: String,
}

/// The parent and the command line of the process `identity` names, read while that start holds
/// its number, or `None` once the kernel says it has ended.
///
/// The start identity is checked again after `ps` has answered: a process that ran before and
/// after the answer held its number throughout, so the answer is that process's. A `ps` that named
/// nothing is read as an ended process only when that check says so.
///
/// # Errors
///
/// Returns why neither answer is established: `ps` did not answer or failed for a process that
/// runs, or the kernel would not say whether the process runs.
pub fn describe(identity: &ProcessStartIdentity) -> Result<Option<Described>, String> {
    let pid = identity.pid.get();
    let mut ps = std::process::Command::new("/bin/ps");
    ps.args(["-ww", "-o", "ppid=,command=", "-p", &pid.to_string()])
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let output = output_within(ps, SERVICE_MANAGER_BOUND)
        .map_err(|why| format!("process {pid} could not be described: ps {why}"))?;
    if !still_running(identity, &format!("process {pid}"))? {
        return Ok(None);
    }
    if !output.status.success() {
        return Err(format!(
            "ps did not describe process {pid}, which runs: it ended with {}",
            output.status
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    let (parent, command) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let parent = parent
        .parse()
        .map_err(|_| format!("ps named no parent for process {pid}: {text:?}"))?;
    Ok(Some(Described {
        parent,
        command: command.trim().to_owned(),
    }))
}

/// Whether a recorded process still runs, as the kernel says: `false` once it has ended.
///
/// # Errors
///
/// Returns why the kernel's answer is not established, naming the process as `what`.
fn still_running(identity: &ProcessStartIdentity, what: &str) -> Result<bool, String> {
    match process_state(identity) {
        ProcessState::Running => Ok(true),
        ProcessState::Ended => Ok(false),
        ProcessState::Unknown { detail } => Err(format!(
            "whether {what} still runs is not established: {detail}"
        )),
    }
}

/// Every process whose command line names `root`, other than this one.
///
/// Every binary a leg launches is a copy inside its directory and every path it hands a process is
/// inside it, so a process still running out of it is one the leg started, whoever its parent is.
///
/// # Errors
///
/// Returns why the process table could not be read.
pub fn processes_under(root: &Path) -> Result<Vec<(u32, String)>, String> {
    let needle = root.display().to_string();
    let own = std::process::id();
    Ok(process_table()?
        .into_iter()
        .filter(|entry| entry.pid != own && entry.command.contains(&needle))
        .map(|entry| (entry.pid, entry.command))
        .collect())
}

/// How long a command a leg runs to ask the operating system something is given.
pub const SERVICE_MANAGER_BOUND: Duration = Duration::from_secs(20);

/// How long a command's output is waited for once the command has exited.
///
/// Its pipes close when it exits, unless something it started holds them open; this is the bound
/// on that.
const OUTPUT_HANDOVER: Duration = Duration::from_secs(5);

/// Runs `command` with nothing on its input and waits at most `within` for it to exit, then at
/// most [`OUTPUT_HANDOVER`] for its output.
///
/// What it prints is read by threads of its own, so a command that prints more than a pipe holds
/// cannot stall. One still running at `within` is killed and collected; it is this run's own
/// child, named by the handle that started it. Output a descendant keeps open past the handover
/// is a failure rather than a wait.
///
/// # Errors
///
/// Returns why it did not finish.
pub fn output_within(
    mut command: std::process::Command,
    within: Duration,
) -> Result<std::process::Output, String> {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start: {error}"))?;
    let stdout = read_all(child.stdout.take());
    let stderr = read_all(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < within => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("did not finish within {within:?}"));
            }
            Err(error) => return Err(format!("could not be waited for: {error}")),
        }
    };
    let handover = Instant::now() + OUTPUT_HANDOVER;
    let collect = |pipe: std::sync::mpsc::Receiver<Vec<u8>>| {
        pipe.recv_timeout(handover.saturating_duration_since(Instant::now()))
            .map_err(|_| format!("exited, and its output was held open past {OUTPUT_HANDOVER:?}"))
    };
    Ok(std::process::Output {
        status,
        stdout: collect(stdout)?,
        stderr: collect(stderr)?,
    })
}

fn read_all<R: std::io::Read + Send + 'static>(
    source: Option<R>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut source) = source {
            let _ = source.read_to_end(&mut bytes);
        }
        let _ = send.send(bytes);
    });
    receive
}

/// The directory this build put its binaries in, beside this test's own.
fn built_directory() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    directory
}
