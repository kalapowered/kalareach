//! What a part's agent ran, and whether that was the build under test.
//!
//! A part tests the pinned build only when its sessions ran nothing else, and three things are
//! checked. The session's shell searches the run's link to the installed build, the run's links to
//! the runtimes the build needs, and the system's own directories, and nothing another installation
//! keeps on a person's PATH. Each launch runs the pinned file in the way its build list names
//! ([`Launch`]): a native build's own process maps it; a runtime starts a process that maps it; a
//! runtime's first argument is it; or a runtime loads the installation the harness compared with
//! the pinned wheel. And from just before each launch to the end of the part's sessions, the
//! processes beneath each session an agent is launched in are looked at every
//! [`SAMPLE_INTERVAL`], and once more when the part's own steps end: each process's executable
//! image, as the kernel maps it, is read on every look, so an image that changes under the same
//! process is seen too, and each image is hashed through one handle whose device and inode are the
//! mapped ones and that did not change while it was read. Every image must lie in the build's own
//! directory, a runtime's, the run's own, the managed shell's or the system's; the newer build's
//! directory counts only in the upgrade part. A process that starts and ends between two looks is
//! not seen, and one that ended before its image was read is named. A session that searched another
//! PATH, launched anything but the pinned file, ran an image from anywhere else, or could not be
//! looked at did not test the pinned build: the part stops, and the record names why.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::run::{Run, describe, output_within, process_table};
use kr_e2e_m1b::shells::ManagedShell;
use kr_ipc::identity::{ProcessQuery, ProcessState, process_state, query_process};
use kr_protocol::identity::ProcessStartIdentity;
use serde::Serialize;
use serde_json::json;

use crate::build::{Build, Launch, Newer};
use crate::stage::AgentProcess;

/// How a part's failure begins when its session ran something other than the build under test.
/// The harness records such a part as not run, with the rest of the line as its reason.
pub const NOT_PINNED: &str = "not the pinned build:";

/// The file the session's shell writes its PATH to before each prompt, in the run's home.
pub const PATH_FILE: &str = ".kr-agents-path";

/// How often the processes beneath a watched session are looked at.
pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Where the system keeps the executables a build may start. `/usr/local` is not among them:
/// another installation of an agent can live there.
const SYSTEM: [&str; 10] = [
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/usr/lib/",
    "/bin/",
    "/sbin/",
    "/System/",
    "/Library/Apple/",
    "/Library/Developer/CommandLineTools/",
    "/Applications/Xcode.app/",
];

/// The system's directories a session's PATH may name after the run's own.
const SYSTEM_PATH: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// The build one launch is expected to run.
#[derive(Clone, Debug)]
pub struct Expected {
    /// The file the build's digest names, with links resolved.
    pub file: PathBuf,
    /// Its SHA-256, lower-case hexadecimal.
    pub sha256: String,
    /// How the launch reaches it.
    pub launch: Launch,
    /// Where the build is installed, with links resolved.
    pub prefix: PathBuf,
}

impl Expected {
    /// The pinned build.
    #[must_use]
    pub fn pinned(build: &Build) -> Self {
        Self {
            file: resolved(&build.pinned_file()),
            sha256: build.sha256.clone(),
            launch: build.launch,
            prefix: resolved(&build.prefix),
        }
    }

    /// The newer build the upgrade part moves to.
    #[must_use]
    pub fn newer(build: &Build, newer: &Newer) -> Self {
        Self {
            file: resolved(&newer.prefix.join(&newer.pinned)),
            sha256: newer.sha256.clone(),
            launch: build.launch,
            prefix: resolved(&newer.prefix),
        }
    }
}

/// One executable image a process beneath a session ran.
#[derive(Clone, Debug, Serialize)]
pub struct Executed {
    /// The image, as the kernel mapped it, with links resolved.
    pub image: String,
    /// Its SHA-256, read through a handle on the file the process maps.
    pub sha256: String,
    /// The device and inode the process maps.
    pub device: u64,
    /// See `device`.
    pub inode: u64,
    /// Where it lies: `build`, `newer build`, `runtime`, `run`, `shell`, `system`, or `elsewhere`.
    pub from: &'static str,
    /// The first process seen running it.
    pub pid: u64,
    /// That process's command line, as the process table shows it.
    pub command: String,
}

/// What `lsof` says one process maps: its executable, the first file it lists, with the device
/// and inode it listed for it, then every other text mapping.
#[derive(Clone, Debug)]
struct Mapping {
    image: PathBuf,
    device: Option<u64>,
    inode: Option<u64>,
    mapped: Vec<PathBuf>,
}

/// What has been seen so far.
#[derive(Default)]
struct Seen {
    /// Every process whose image was read, with the device and inode it mapped then.
    processes: BTreeMap<ProcessStartIdentity, (u64, u64)>,
    /// Every image read, by device and inode.
    executed: BTreeMap<(u64, u64), Executed>,
    /// Processes that ended before their image was read, by command line.
    unread: Vec<String>,
    /// What each launch ran.
    launches: Vec<serde_json::Value>,
    /// The first thing found that was not the build under test.
    problem: Option<String>,
    /// How many times the processes were looked at.
    samples: u64,
}

/// What a stage's sessions ran, checked as they ran it.
pub struct Provenance {
    marks: Vec<PathBuf>,
    places: Vec<(PathBuf, &'static str)>,
    run_root: PathBuf,
    run_resolved: PathBuf,
    link: PathBuf,
    path_file: PathBuf,
    seen_path: Mutex<Option<String>>,
    seen: Mutex<Seen>,
    roots: Mutex<Vec<ProcessStartIdentity>>,
    stopped: AtomicBool,
}

impl Provenance {
    /// What `build` may run on `run` in part `part`, with its sessions' shell from `shell`. The
    /// newer build counts as the build's own only in the upgrade part.
    #[must_use]
    pub fn new(build: &Build, run: &Run, shell: &ManagedShell, part: &str) -> Self {
        let run_resolved = resolved(run.root());
        let runtimes: Vec<PathBuf> = build
            .runtime
            .iter()
            .map(|file| runtime_root(file))
            .collect();
        let newer: Vec<&Newer> = build.newer.iter().filter(|_| part == "6a").collect();
        let mut marks = vec![build.prefix.clone(), run.root().join("agent")];
        marks.extend(newer.iter().map(|newer| newer.prefix.clone()));
        marks.extend(runtimes.iter().cloned());
        let written = marks.clone();
        marks.extend(written.iter().map(|mark| resolved(mark)));
        let mut places = vec![(resolved(&build.prefix), "build")];
        places.extend(
            newer
                .iter()
                .map(|newer| (resolved(&newer.prefix), "newer build")),
        );
        places.extend(runtimes.iter().map(|root| (root.clone(), "runtime")));
        places.push((run_resolved.clone(), "run"));
        places.push((resolved(&shell.prefix), "shell"));
        places.extend(SYSTEM.iter().map(|root| (PathBuf::from(root), "system")));
        Self {
            marks,
            places,
            run_root: run.root().to_path_buf(),
            run_resolved,
            link: run.root().join("agent").join("current").join("bin"),
            path_file: run.home().join(PATH_FILE),
            seen_path: Mutex::new(None),
            seen: Mutex::new(Seen::default()),
            roots: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
        }
    }

    /// The directories whose presence in a process's command line or executable says it belongs
    /// to the build: the pinned build's, the newer one's in the upgrade part, their runtimes', and
    /// the run's link to the installation, each as written and as resolved.
    #[must_use]
    pub fn marks(&self) -> &[PathBuf] {
        &self.marks
    }

    /// Checks the PATH the session's shell searches, as it wrote it before its last prompt: every
    /// directory lies in the run's own directory or is the system's, and `command` is found first
    /// in the run's link to the installed build.
    ///
    /// # Errors
    ///
    /// Returns why, beginning with [`NOT_PINNED`], when the shell searches anything else.
    pub fn check_path(&self, command: &str) -> Result<(), String> {
        let seen = std::fs::read_to_string(&self.path_file).map_err(|error| {
            format!(
                "{NOT_PINNED} the session's shell wrote no PATH to {}: {error}",
                self.path_file.display()
            )
        })?;
        let seen = seen.trim_end_matches('\n').to_owned();
        *self
            .seen_path
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(seen.clone());
        let outside: Vec<&str> = seen
            .split(':')
            .filter(|directory| {
                !(SYSTEM_PATH.contains(directory)
                    || Path::new(directory).starts_with(&self.run_root)
                    || Path::new(directory).starts_with(&self.run_resolved))
            })
            .collect();
        if !outside.is_empty() {
            return Err(format!(
                "{NOT_PINNED} the session's shell searches {}, outside the run and the system",
                outside.join(", ")
            ));
        }
        let found = seen
            .split(':')
            .map(|directory| Path::new(directory).join(command))
            .find(|candidate| candidate.is_file());
        match found {
            Some(file) if file.parent() == Some(self.link.as_path()) => Ok(()),
            Some(file) => Err(format!(
                "{NOT_PINNED} `{command}` is found first at {}, not in the run's link to the build",
                file.display()
            )),
            None => Err(format!(
                "{NOT_PINNED} `{command}` is not found on the session's PATH {seen}"
            )),
        }
    }

    /// Records the image each of `processes` maps and checks where it lies.
    ///
    /// # Errors
    ///
    /// Returns why, beginning with [`NOT_PINNED`], when one maps an image from anywhere else, or
    /// its image cannot be read while it runs.
    pub fn record(&self, processes: &[AgentProcess]) -> Result<(), String> {
        let mappings = mappings(&pids_of(processes))?;
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        for process in processes {
            let mapping = mapping_of(&mappings, &process.identity);
            if let Some(executed) =
                self.inspect(&mut seen, &process.identity, &process.command, mapping)?
            {
                elsewhere(&executed)?;
            }
        }
        Ok(())
    }

    /// Checks that one launch ran `expected` in the way its build list names, and records what it
    /// found under `what`. The agent's own process is the shell's child.
    ///
    /// # Errors
    ///
    /// Returns why, beginning with [`NOT_PINNED`], when the launch ran anything else, or what it
    /// ran cannot be shown.
    pub fn verify_launch(
        &self,
        processes: &[AgentProcess],
        shell: u64,
        expected: &Expected,
        what: &str,
    ) -> Result<(), String> {
        let mappings = mappings(&pids_of(processes))?;
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let own = processes
            .iter()
            .find(|process| u64::from(process.parent) == shell)
            .ok_or_else(|| format!("{NOT_PINNED} {what}: the shell started no process"))?;
        let own_mapping = mapping_of(&mappings, &own.identity);
        let own_image = self
            .inspect(&mut seen, &own.identity, &own.command, own_mapping)?
            .ok_or_else(|| {
                format!(
                    "{NOT_PINNED} {what}: the agent's process ({}) ended before its image was read",
                    own.command
                )
            })?;
        if expected.launch != Launch::Native && own_image.from != "runtime" {
            return Err(format!(
                "{NOT_PINNED} {what}: the agent's process maps {}, which is not the build's runtime",
                own_image.image
            ));
        }
        let reached = match expected.launch {
            Launch::Native => {
                if Path::new(&own_image.image) != expected.file
                    || own_image.sha256 != expected.sha256
                {
                    return Err(format!(
                        "{NOT_PINNED} {what}: the agent's process maps {} (sha256 {}), not {} \
                         (sha256 {})",
                        own_image.image,
                        own_image.sha256,
                        expected.file.display(),
                        expected.sha256
                    ));
                }
                "the agent's own process maps it".to_owned()
            }
            Launch::Child => {
                let mut mapped = None;
                for process in processes
                    .iter()
                    .filter(|process| process.identity != own.identity)
                {
                    let mapping = mapping_of(&mappings, &process.identity);
                    if let Some(executed) =
                        self.inspect(&mut seen, &process.identity, &process.command, mapping)?
                        && Path::new(&executed.image) == expected.file
                    {
                        mapped = Some((process, executed));
                    }
                }
                let (process, executed) = mapped.ok_or_else(|| {
                    format!(
                        "{NOT_PINNED} {what}: no process the runtime started maps {}",
                        expected.file.display()
                    )
                })?;
                if executed.sha256 != expected.sha256 {
                    return Err(format!(
                        "{NOT_PINNED} {what}: process {} maps {} with sha256 {}, not {}",
                        process.identity.pid.get(),
                        executed.image,
                        executed.sha256,
                        expected.sha256
                    ));
                }
                format!(
                    "process {} ({}), started by the runtime, maps it",
                    process.identity.pid.get(),
                    process.command
                )
            }
            Launch::Script => {
                let script = own.command.split_whitespace().nth(1).unwrap_or_default();
                if !script.starts_with('/') || resolved(Path::new(script)) != expected.file {
                    return Err(format!(
                        "{NOT_PINNED} {what}: the runtime's first argument is {script:?}, not {}",
                        expected.file.display()
                    ));
                }
                let digest = hash_file(&expected.file)?;
                if digest != expected.sha256 {
                    return Err(format!(
                        "{NOT_PINNED} {what}: {} has sha256 {digest}, not {}",
                        expected.file.display(),
                        expected.sha256
                    ));
                }
                format!("the runtime's first argument is it: {}", own.command)
            }
            Launch::Wheel => {
                let installed = expected.prefix.join("lib");
                let loaded = own_mapping
                    .into_iter()
                    .flat_map(|mapping| mapping.mapped.iter())
                    .map(|path| resolved(path))
                    .find(|path| path.starts_with(&installed))
                    .ok_or_else(|| {
                        format!(
                            "{NOT_PINNED} {what}: the runtime maps nothing of the installation at {}",
                            expected.prefix.display()
                        )
                    })?;
                format!(
                    "the runtime loads the installation the harness compared with the wheel, \
                     mapping {}",
                    loaded.display()
                )
            }
        };
        seen.launches.push(json!({
            "what": what,
            "launch": expected.launch,
            "file": expected.file,
            "sha256": expected.sha256,
            "agent_process": {
                "pid": own.identity.pid.get(),
                "command": own.command,
                "image": own_image.image,
                "sha256": own_image.sha256,
                "from": own_image.from,
            },
            "reached": reached,
        }));
        Ok(())
    }

    /// Looks at the processes beneath `root` from now until [`Provenance::stop`], at every
    /// [`SAMPLE_INTERVAL`] of [`Provenance::sample_until_stopped`].
    pub fn watch(&self, root: ProcessStartIdentity) {
        let mut roots = self.roots.lock().unwrap_or_else(PoisonError::into_inner);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }

    /// Looks at the watched sessions' processes until [`Provenance::stop`] is called.
    pub fn sample_until_stopped(&self) {
        while !self.stopped.load(Ordering::SeqCst) {
            let began = Instant::now();
            self.sample();
            while !self.stopped.load(Ordering::SeqCst) && began.elapsed() < SAMPLE_INTERVAL {
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }

    /// Looks at the watched sessions' processes once, now.
    pub fn sample_now(&self) {
        self.sample();
    }

    /// Ends [`Provenance::sample_until_stopped`].
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    /// The first thing the part's sessions ran that was not the build under test, if anything.
    ///
    /// # Errors
    ///
    /// Returns it, beginning with [`NOT_PINNED`].
    pub fn finish(&self) -> Result<(), String> {
        match &self
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .problem
        {
            Some(problem) => Err(problem.clone()),
            None => Ok(()),
        }
    }

    /// What the stage's sessions searched and ran, for the part's evidence.
    #[must_use]
    pub fn evidence(&self) -> serde_json::Value {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let executed: Vec<&Executed> = seen.executed.values().collect();
        json!({
            "session_path": *self.seen_path.lock().unwrap_or_else(PoisonError::into_inner),
            "sample_interval_ms": SAMPLE_INTERVAL.as_millis(),
            "samples": seen.samples,
            "launches": seen.launches,
            "executed": executed,
            "ended_before_read": seen.unread,
        })
    }

    /// One look at every watched session's processes: the process table, each process beneath a
    /// session, a process not seen before taken only once its parent holds, and then every one's
    /// mapped image, read in one call so an image that changed under a known process is seen.
    fn sample(&self) {
        let roots = self
            .roots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if roots.is_empty() {
            return;
        }
        let table = process_table();
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.samples += 1;
        let table = match table {
            Ok(table) => table,
            Err(why) => {
                problem(
                    &mut seen,
                    format!("{NOT_PINNED} the processes could not be listed: {why}"),
                );
                return;
            }
        };
        let mut found: Vec<(ProcessStartIdentity, String)> = Vec::new();
        for root in roots {
            match process_state(&root) {
                ProcessState::Running => {}
                ProcessState::Ended => continue,
                ProcessState::Unknown { detail } => {
                    problem(
                        &mut seen,
                        format!(
                            "{NOT_PINNED} whether a watched session's shell runs is not established: {detail}"
                        ),
                    );
                    continue;
                }
            }
            let mut under = vec![root];
            while let Some(parent) = under.pop() {
                let Ok(parent_pid) = u32::try_from(parent.pid.get()) else {
                    continue;
                };
                for entry in table.iter().filter(|entry| entry.parent == parent_pid) {
                    let identity = match query_process(entry.pid) {
                        ProcessQuery::Present(identity) => identity,
                        ProcessQuery::Gone => continue,
                        ProcessQuery::CannotEstablish(error) => {
                            problem(
                                &mut seen,
                                format!(
                                    "{NOT_PINNED} process {} beneath a session could not be identified: {error}",
                                    entry.pid
                                ),
                            );
                            continue;
                        }
                    };
                    // A number read from the table can name another process by the time it is
                    // looked up: a process not seen before is taken as this session's only once its
                    // parent, read again under its own start identity, is the one it was found
                    // under, and that parent still runs.
                    if !seen.processes.contains_key(&identity) {
                        match beneath_parent(&identity, &parent) {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(why) => {
                                problem(&mut seen, why);
                                continue;
                            }
                        }
                    }
                    found.push((identity.clone(), entry.command.clone()));
                    under.push(identity);
                }
            }
        }
        let pids: Vec<u32> = found
            .iter()
            .filter_map(|(identity, _)| u32::try_from(identity.pid.get()).ok())
            .collect();
        let mappings = match mappings(&pids) {
            Ok(mappings) => mappings,
            Err(why) => {
                problem(&mut seen, why);
                return;
            }
        };
        for (identity, command) in found {
            let mapping = mapping_of(&mappings, &identity);
            match self.inspect(&mut seen, &identity, &command, mapping) {
                Ok(Some(executed)) => {
                    if let Err(why) = elsewhere(&executed) {
                        problem(&mut seen, why);
                    }
                }
                Ok(None) => {}
                Err(why) => problem(&mut seen, why),
            }
        }
    }

    /// Notes the image `identity` maps, as `mapping` read it, hashing an image not seen before;
    /// nothing when the process ended before its image was read.
    fn inspect(
        &self,
        seen: &mut Seen,
        identity: &ProcessStartIdentity,
        command: &str,
        mapping: Option<&Mapping>,
    ) -> Result<Option<Executed>, String> {
        let pid = identity.pid.get();
        // The number named the process while its start held it: what was read in between is that
        // process's.
        match process_state(identity) {
            ProcessState::Running => {}
            ProcessState::Ended => {
                if !seen.processes.contains_key(identity) {
                    seen.unread.push(command.to_owned());
                }
                return Ok(None);
            }
            ProcessState::Unknown { detail } => {
                return Err(format!(
                    "{NOT_PINNED} whether process {pid} ({command}) runs is not established: {detail}"
                ));
            }
        }
        let mapping = mapping.ok_or_else(|| {
            format!("{NOT_PINNED} the image of process {pid} ({command}) could not be read while it runs")
        })?;
        let (Some(device), Some(inode)) = (mapping.device, mapping.inode) else {
            return Err(format!(
                "{NOT_PINNED} the image of process {pid} ({command}), {}, was listed without its \
                 device or inode",
                mapping.image.display()
            ));
        };
        let key = (device, inode);
        let executed = if let Some(executed) = seen.executed.get(&key) {
            executed.clone()
        } else {
            let image = resolved(&mapping.image);
            let executed = Executed {
                image: image.display().to_string(),
                sha256: hash_mapped(&image, device, inode)?,
                device,
                inode,
                from: self.place_of(&image),
                pid,
                command: command.to_owned(),
            };
            seen.executed.insert(key, executed.clone());
            executed
        };
        seen.processes.insert(identity.clone(), key);
        Ok(Some(executed))
    }

    /// Where an image lies.
    fn place_of(&self, image: &Path) -> &'static str {
        self.places
            .iter()
            .find(|(root, _)| image.starts_with(root))
            .map_or("elsewhere", |(_, from)| *from)
    }
}

/// Stops [`Provenance::sample_until_stopped`] when it goes out of scope, a panic included, so a
/// part that failed does not leave the sampler running.
pub struct StopSampling<'p>(pub &'p Provenance);

impl Drop for StopSampling<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Keeps the first problem.
fn problem(seen: &mut Seen, why: String) {
    if seen.problem.is_none() {
        seen.problem = Some(why);
    }
}

/// Refuses an image from anywhere but the places the build may run from.
fn elsewhere(executed: &Executed) -> Result<(), String> {
    if executed.from == "elsewhere" {
        return Err(format!(
            "{NOT_PINNED} process {} ({}) ran {} (sha256 {}), which is not the pinned build, its \
             runtime, the run's own, the managed shell's or the system's",
            executed.pid, executed.command, executed.image, executed.sha256
        ));
    }
    Ok(())
}

/// Whether `identity` still runs beneath `parent`, which still runs: `Ok(false)` when it has
/// ended or its number now names a process with another parent.
fn beneath_parent(
    identity: &ProcessStartIdentity,
    parent: &ProcessStartIdentity,
) -> Result<bool, String> {
    let described = describe(identity).map_err(|why| {
        format!(
            "{NOT_PINNED} process {} beneath a session could not be described: {why}",
            identity.pid.get()
        )
    })?;
    let Some(described) = described else {
        return Ok(false);
    };
    match process_state(parent) {
        ProcessState::Running => Ok(u64::from(described.parent) == parent.pid.get()),
        ProcessState::Ended => Ok(false),
        ProcessState::Unknown { detail } => Err(format!(
            "{NOT_PINNED} whether the parent of process {} runs is not established: {detail}",
            identity.pid.get()
        )),
    }
}

/// The processes' numbers.
fn pids_of(processes: &[AgentProcess]) -> Vec<u32> {
    processes
        .iter()
        .filter_map(|process| u32::try_from(process.identity.pid.get()).ok())
        .collect()
}

/// The mapping `lsof` read for a process, by its number.
fn mapping_of<'m>(
    mappings: &'m BTreeMap<u32, Mapping>,
    identity: &ProcessStartIdentity,
) -> Option<&'m Mapping> {
    u32::try_from(identity.pid.get())
        .ok()
        .and_then(|pid| mappings.get(&pid))
}

/// What each of `pids` maps, as one `lsof` reads it: the executable first, its device and inode,
/// then every other text mapping. A process that has ended is absent.
fn mappings(pids: &[u32]) -> Result<BTreeMap<u32, Mapping>, String> {
    let mut found = BTreeMap::new();
    if pids.is_empty() {
        return Ok(found);
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut lsof = Command::new("/usr/sbin/lsof");
    lsof.args(["-a", "-p", &list, "-d", "txt", "-FpDin"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin");
    // It exits 1 when one of the processes has gone; what it printed is still read.
    let output = output_within(lsof, LIVENESS).map_err(|why| {
        format!("{NOT_PINNED} the processes' images could not be read: lsof {why}")
    })?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Each process begins with `p`, each of its files with `f`; a file's device, inode and name
    // follow its `f`, and any of them can be absent. The first file of a process is its
    // executable, whatever it lacks.
    let mut pid: Option<u32> = None;
    let mut file: Option<(Option<u64>, Option<u64>, Option<PathBuf>)> = None;
    let close = |pid: Option<u32>,
                 file: Option<(Option<u64>, Option<u64>, Option<PathBuf>)>,
                 found: &mut BTreeMap<u32, Mapping>| {
        let (Some(pid), Some((device, inode, Some(path)))) = (pid, file) else {
            return;
        };
        match found.get_mut(&pid) {
            None => {
                found.insert(
                    pid,
                    Mapping {
                        image: path,
                        device,
                        inode,
                        mapped: Vec::new(),
                    },
                );
            }
            Some(mapping) => mapping.mapped.push(path),
        }
    };
    for line in text.lines() {
        let (field, value) = line.split_at(line.len().min(1));
        match field {
            "p" => {
                close(pid, file.take(), &mut found);
                pid = value.parse::<u32>().ok();
            }
            "f" => {
                close(pid, file.take(), &mut found);
                file = Some((None, None, None));
            }
            "D" => {
                if let Some(file) = file.as_mut() {
                    file.0 = u64::from_str_radix(value.trim_start_matches("0x"), 16).ok();
                }
            }
            "i" => {
                if let Some(file) = file.as_mut() {
                    file.1 = value.parse::<u64>().ok();
                }
            }
            "n" => {
                if let Some(file) = file.as_mut() {
                    file.2 = Some(PathBuf::from(value));
                }
            }
            _ => {}
        }
    }
    close(pid, file.take(), &mut found);
    Ok(found)
}

/// A mapped image's SHA-256, read through one handle on the file whose device and inode the
/// process maps, which must not change while it is read.
fn hash_mapped(file: &Path, device: u64, inode: u64) -> Result<String, String> {
    hash_handle(file, Some((device, inode)))
}

/// A file's SHA-256, read through one handle.
fn hash_file(file: &Path) -> Result<String, String> {
    hash_handle(file, None)
}

/// Reads a regular file through one handle and returns its SHA-256. The file is opened without
/// waiting, so a path that has become a pipe or a device cannot hold the reader; the handle must
/// hold a regular file, the device and inode `wanted` names when it names one, before anything is
/// read; no more than its size is read; and its size and modification time must not change while
/// it is read.
fn hash_handle(file: &Path, wanted: Option<(u64, u64)>) -> Result<String, String> {
    use rustix::fs::{Mode, OFlags};
    let unreadable = |error: &dyn std::fmt::Display| {
        format!("{NOT_PINNED} {} cannot be read: {error}", file.display())
    };
    let descriptor = rustix::fs::open(
        file,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|error| unreadable(&error))?;
    let handle = std::fs::File::from(descriptor);
    let before = handle.metadata().map_err(|error| unreadable(&error))?;
    if !before.file_type().is_file() {
        return Err(format!(
            "{NOT_PINNED} {} is not a regular file, so what it holds cannot be hashed",
            file.display()
        ));
    }
    if let Some((device, inode)) = wanted
        && (before.dev(), before.ino()) != (device, inode)
    {
        return Err(format!(
            "{NOT_PINNED} {} is device {} inode {} now, not the device {device} inode {inode} the \
             process maps, so what it runs cannot be hashed",
            file.display(),
            before.dev(),
            before.ino()
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    (&handle)
        .take(before.len().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable(&error))?;
    let after = handle.metadata().map_err(|error| unreadable(&error))?;
    if u64::try_from(bytes.len()).ok() != Some(before.len())
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
    {
        return Err(format!(
            "{NOT_PINNED} {} changed while it was read",
            file.display()
        ));
    }
    Ok(kr_cbor::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Where a runtime's installation lies: the directory above the one its executable is in, with
/// links resolved, so the images it runs from its own tree count as the runtime's.
fn runtime_root(executable: &Path) -> PathBuf {
    let file = resolved(executable);
    file.parent()
        .and_then(Path::parent)
        .or_else(|| file.parent())
        .map_or_else(|| file.clone(), Path::to_path_buf)
}

/// A path with its links resolved, or as written when it cannot be.
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
