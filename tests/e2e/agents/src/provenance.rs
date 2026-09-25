//! What a part's agent ran, and whether that was the build under test.
//!
//! A part tests the pinned build only when its sessions ran nothing else, and three things are
//! checked. The session's shell searches the run's link to the installed build, the run's links to
//! the runtimes the build needs, and the system's own directories, and nothing another installation
//! keeps on a person's PATH. Each launch runs the pinned file: a native build's own process maps
//! it; a runtime's process runs it as its script, or starts a process that maps it; and a build
//! installed from a wheel runs the code the harness compared with the wheel before the run. And
//! from the first launch to the end of the part, the processes beneath each session an agent was
//! launched in are looked at every [`SAMPLE_INTERVAL`]: each new process, and each whose command
//! line changed, has the executable image it maps read, with its file's SHA-256, and the image must
//! lie in the build's own directory, a runtime's, the run's own, the managed shell's or the
//! system's. The newer build's directory counts only in the upgrade part. A process that starts
//! and ends between two looks is not seen, and one that ended before its image was read is named.
//! A session that searched another PATH, launched anything but the pinned file, or ran an image
//! from anywhere else did not test the pinned build: the part stops, and the record names what ran.

use std::collections::BTreeMap;
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

use crate::build::{Build, Newer};
use crate::stage::{AgentProcess, text_image};

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
    /// Whether the agent's own process maps that file, as a native build's does, rather than a
    /// runtime that runs it.
    pub native: bool,
}

impl Expected {
    /// The pinned build.
    #[must_use]
    pub fn pinned(build: &Build) -> Self {
        Self {
            file: resolved(&build.pinned_file()),
            sha256: build.sha256.clone(),
            native: build.runtime.is_empty(),
        }
    }

    /// The newer build the upgrade part moves to.
    #[must_use]
    pub fn newer(build: &Build, newer: &Newer) -> Self {
        Self {
            file: resolved(&newer.prefix.join(&newer.pinned)),
            sha256: newer.sha256.clone(),
            native: build.runtime.is_empty(),
        }
    }

    /// Whether the build is a wheel, whose installed code the harness compares with it.
    fn is_wheel(&self) -> bool {
        self.file
            .extension()
            .is_some_and(|extension| extension == "whl")
    }
}

/// One executable image a process beneath a session ran.
#[derive(Clone, Debug, Serialize)]
pub struct Executed {
    /// The image, as the kernel mapped it, with links resolved.
    pub image: String,
    /// Its file's SHA-256, read from the file whose inode the process maps.
    pub sha256: String,
    /// The inode the process maps, which the file hashed has.
    pub inode: u64,
    /// Where it lies: `build`, `newer build`, `runtime`, `run`, `shell`, `system`, or `elsewhere`.
    pub from: &'static str,
    /// The first process seen running it.
    pub pid: u64,
    /// That process's command line, as the process table shows it.
    pub command: String,
}

/// What has been seen so far.
#[derive(Default)]
struct Seen {
    /// Every process whose image was read, with the command line it had then.
    processes: BTreeMap<ProcessStartIdentity, String>,
    /// Every image read, by path and inode.
    executed: BTreeMap<(PathBuf, u64), Executed>,
    /// The digest of each pinned file checked, by path.
    pinned: BTreeMap<PathBuf, String>,
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
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        for process in processes {
            if let Some(executed) = self.inspect(&mut seen, &process.identity, &process.command)? {
                elsewhere(&executed)?;
            }
        }
        Ok(())
    }

    /// Checks that one launch ran `expected`: the agent's own process, the shell's child, maps the
    /// pinned file when the build is native and a runtime's image otherwise, and the pinned file is
    /// reached, by a process that maps it, by a runtime that names it as its script, or, for a
    /// wheel, by the code the harness compared with it. Records what it found under `what`.
    ///
    /// # Errors
    ///
    /// Returns why, beginning with [`NOT_PINNED`], when the launch ran anything else.
    pub fn verify_launch(
        &self,
        processes: &[AgentProcess],
        shell: u64,
        expected: &Expected,
        what: &str,
    ) -> Result<(), String> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let own = processes
            .iter()
            .find(|process| u64::from(process.parent) == shell)
            .ok_or_else(|| format!("{NOT_PINNED} {what}: the shell started no process"))?;
        let own_image = self
            .inspect(&mut seen, &own.identity, &own.command)?
            .ok_or_else(|| {
                format!(
                    "{NOT_PINNED} {what}: the agent's process ({}) ended before its image was read",
                    own.command
                )
            })?;
        if expected.native {
            if Path::new(&own_image.image) != expected.file || own_image.sha256 != expected.sha256 {
                return Err(format!(
                    "{NOT_PINNED} {what}: the agent's process maps {} (sha256 {}), not {} (sha256 {})",
                    own_image.image,
                    own_image.sha256,
                    expected.file.display(),
                    expected.sha256
                ));
            }
        } else if own_image.from != "runtime" {
            return Err(format!(
                "{NOT_PINNED} {what}: the agent's process maps {}, which is not the build's runtime",
                own_image.image
            ));
        }
        let reached = if expected.native {
            "the agent's own process maps it".to_owned()
        } else {
            let mut mapped = None;
            for process in processes {
                if let Some(executed) =
                    self.inspect(&mut seen, &process.identity, &process.command)?
                    && Path::new(&executed.image) == expected.file
                {
                    mapped = Some((process, executed));
                }
            }
            if let Some((process, executed)) = mapped {
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
                    "process {} ({}) maps it",
                    process.identity.pid.get(),
                    process.command
                )
            } else if let Some(process) = processes.iter().find(|process| {
                process
                    .command
                    .split_whitespace()
                    .any(|word| word.starts_with('/') && resolved(Path::new(word)) == expected.file)
            }) {
                let digest = pinned_digest(&mut seen, &expected.file)?;
                if digest != expected.sha256 {
                    return Err(format!(
                        "{NOT_PINNED} {what}: {} has sha256 {digest}, not {}",
                        expected.file.display(),
                        expected.sha256
                    ));
                }
                format!("the runtime runs it as its script: {}", process.command)
            } else if expected.is_wheel() {
                "the runtime runs the installed code the harness compared with the wheel".to_owned()
            } else {
                return Err(format!(
                    "{NOT_PINNED} {what}: no process of the agent maps or names {}",
                    expected.file.display()
                ));
            }
        };
        seen.launches.push(json!({
            "what": what,
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
        self.roots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(root);
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

    /// One look at every watched session's processes.
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
        for root in roots {
            if !matches!(process_state(&root), ProcessState::Running) {
                continue;
            }
            let mut under = vec![root];
            while let Some(parent) = under.pop() {
                let Ok(parent_pid) = u32::try_from(parent.pid.get()) else {
                    continue;
                };
                for entry in table.iter().filter(|entry| entry.parent == parent_pid) {
                    let ProcessQuery::Present(identity) = query_process(entry.pid) else {
                        continue;
                    };
                    if seen.processes.get(&identity) != Some(&entry.command) {
                        let found = self.inspect(&mut seen, &identity, &entry.command).and_then(
                            |executed| executed.map_or(Ok(()), |executed| elsewhere(&executed)),
                        );
                        // A number that names another process by now is not this session's: the
                        // finding stands only while the process is still beneath its parent.
                        if let Err(why) = found
                            && still_beneath(&identity, &parent)
                        {
                            problem(&mut seen, why);
                        }
                    }
                    under.push(identity);
                }
            }
        }
    }

    /// Reads the image `identity` maps, with its file's digest, and notes it; nothing when the
    /// process ended before its image was read.
    fn inspect(
        &self,
        seen: &mut Seen,
        identity: &ProcessStartIdentity,
        command: &str,
    ) -> Result<Option<Executed>, String> {
        let pid = u32::try_from(identity.pid.get())
            .map_err(|_| format!("{NOT_PINNED} process {} has no number", identity.pid.get()))?;
        let read = text_image(pid);
        // The number still names the process only while that start holds it: the image read in
        // between is that process's.
        match process_state(identity) {
            ProcessState::Running => {}
            ProcessState::Ended => {
                seen.unread.push(command.to_owned());
                seen.processes.insert(identity.clone(), command.to_owned());
                return Ok(None);
            }
            ProcessState::Unknown { detail } => {
                return Err(format!(
                    "{NOT_PINNED} whether process {pid} ({command}) runs is not established: {detail}"
                ));
            }
        }
        let (path, inode) = read.map_err(|why| {
            format!("{NOT_PINNED} the image of process {pid} ({command}) could not be read: {why}")
        })?;
        let image = resolved(&path);
        let key = (image.clone(), inode);
        let executed = if let Some(executed) = seen.executed.get(&key) {
            executed.clone()
        } else {
            let on_disk = std::fs::metadata(&image)
                .map(|metadata| metadata.ino())
                .map_err(|error| {
                    format!(
                        "{NOT_PINNED} process {pid} maps {}, which cannot be read: {error}",
                        image.display()
                    )
                })?;
            if on_disk != inode {
                return Err(format!(
                    "{NOT_PINNED} process {pid} ({command}) maps inode {inode} at {}, and the file there \
                     now is inode {on_disk}, so what it runs cannot be hashed",
                    image.display()
                ));
            }
            let executed = Executed {
                image: image.display().to_string(),
                sha256: sha256_of(&image)?,
                inode,
                from: self.place_of(&image),
                pid: identity.pid.get(),
                command: command.to_owned(),
            };
            seen.executed.insert(key, executed.clone());
            executed
        };
        seen.processes.insert(identity.clone(), command.to_owned());
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

/// Whether `identity` still runs beneath `parent`, which still runs.
fn still_beneath(identity: &ProcessStartIdentity, parent: &ProcessStartIdentity) -> bool {
    matches!(process_state(parent), ProcessState::Running)
        && matches!(describe(identity), Ok(Some(described)) if u64::from(described.parent) == parent.pid.get())
}

/// The digest of a pinned file, read once.
fn pinned_digest(seen: &mut Seen, file: &Path) -> Result<String, String> {
    if let Some(digest) = seen.pinned.get(file) {
        return Ok(digest.clone());
    }
    let digest = sha256_of(file)?;
    seen.pinned.insert(file.to_path_buf(), digest.clone());
    Ok(digest)
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

/// A file's SHA-256, lower-case hexadecimal.
fn sha256_of(file: &Path) -> Result<String, String> {
    let mut shasum = Command::new("/usr/bin/shasum");
    shasum
        .args(["-a", "256"])
        .arg(file)
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let output = output_within(shasum, LIVENESS).map_err(|why| format!("shasum {why}"))?;
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .filter(|digest| digest.len() == 64)
        .map(str::to_owned)
        .ok_or_else(|| format!("shasum named no digest for {}", file.display()))
}
