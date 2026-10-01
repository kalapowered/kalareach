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

/// How a part's failure begins when its session exports a variable the build list clears. The
/// agent was not started, or was ended before anything was typed to it, so the harness records the
/// part as not run, with the rest of the line as its reason.
pub const ENVIRONMENT_NOT_CLEAR: &str = "the session's environment is not clear:";

/// How a part's failure begins when the names its session's shell exports could not be read, so
/// that none of the variables the build list clears is exported cannot be established. The part
/// is not run either.
pub const ENVIRONMENT_NOT_READ: &str = "the session's environment could not be read:";

/// The file the session's shell writes its PATH to before each prompt, in the run's home.
pub const PATH_FILE: &str = ".kr-agents-path";

/// The file the session's shell writes the names of its exported variables to before each prompt,
/// one on each line and never a value, in the run's home.
pub const EXPORTED_FILE: &str = ".kr-agents-exported";

/// The file the session's shell writes the same names to just before it runs a command line, so
/// that the last line it ran, the agent's, is the one it describes.
pub const STARTED_FILE: &str = ".kr-agents-started";

/// The variable every shell of a session exports, whose name the shell's list must hold for the
/// list to be one: a list without it was not written.
const EXPORTED_WITNESS: &str = "PATH";

/// The last line of every list the shell writes, after the names: a list that does not end with it
/// was read while it was being written, or not written whole. It cannot be a variable's name.
pub const LIST_END: &str = "-- end of the names --";

/// Whether `name` is one `pattern` names: a name, or a prefix when the pattern ends in `*`.
fn names_of(pattern: &str, name: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == name, |prefix| name.starts_with(prefix))
}

/// Checks the names a session's shell wrote against the variables `cleared` names, each a name or
/// a prefix that ends in `*`, except the names in `allowed`, which the build list sets itself: the
/// agent inherits what the shell exports, so none of them may be there.
///
/// # Errors
///
/// Returns why: beginning with [`ENVIRONMENT_NOT_READ`] when `exported` does not end with
/// [`LIST_END`] or holds no `PATH`, since a list like that was not written whole; beginning with
/// [`ENVIRONMENT_NOT_CLEAR`], naming the variables that are exported, and never a value, when it
/// holds a cleared one.
pub fn exported_clear(
    exported: &str,
    cleared: &[String],
    allowed: &[String],
) -> Result<(), String> {
    let lines: Vec<&str> = exported.lines().collect();
    let Some((last, names)) = lines.split_last() else {
        return Err(format!(
            "{ENVIRONMENT_NOT_READ} the shell wrote no names it exports"
        ));
    };
    if *last != LIST_END || !names.contains(&EXPORTED_WITNESS) {
        return Err(format!(
            "{ENVIRONMENT_NOT_READ} the names the session's shell exports were not written whole: \
             the list does not end with its end mark and hold {EXPORTED_WITNESS}"
        ));
    }
    let present: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| !allowed.iter().any(|allowed| allowed == name))
        .filter(|name| cleared.iter().any(|pattern| names_of(pattern, name)))
        .collect();
    if present.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{ENVIRONMENT_NOT_CLEAR} the session's shell exports {}, which the build list clears",
            present.join(", ")
        ))
    }
}

/// Removes `file`, where a list of an earlier command line may be, so that only the next line's
/// can be read. A file that is not there is what is wanted; any other error leaves a list that
/// could pass as the next one.
///
/// # Errors
///
/// Returns why, beginning with [`ENVIRONMENT_NOT_READ`], when the file could not be removed.
pub fn forget_names(file: &Path) -> Result<(), String> {
    match std::fs::remove_file(file) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(format!(
            "{ENVIRONMENT_NOT_READ} the list of names an earlier command line wrote to {} could \
             not be removed: {error}",
            file.display()
        )),
        _ => Ok(()),
    }
}

/// Waits at most `within` for the shell to write `file` whole, and checks the names in it as
/// [`exported_clear`] does.
///
/// # Errors
///
/// Returns why, as [`exported_clear`] does; a list that is not there whole in time is
/// [`ENVIRONMENT_NOT_READ`].
pub fn wait_for_names(
    file: &Path,
    within: Duration,
    cleared: &[String],
    allowed: &[String],
) -> Result<(), String> {
    let deadline = Instant::now() + within;
    loop {
        let read = std::fs::read_to_string(file);
        match &read {
            Ok(names) if names.lines().last() == Some(LIST_END) => {
                return exported_clear(names, cleared, allowed);
            }
            _ if Instant::now() >= deadline => {
                return Err(format!(
                    "{ENVIRONMENT_NOT_READ} the session's shell wrote no whole list of the names it \
                     exports to {} in time: {}",
                    file.display(),
                    read.map_or_else(
                        |error| error.to_string(),
                        |_| "it has no end mark".to_owned()
                    )
                ));
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

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

/// What `lsof` says one process maps: its executable, the first file it lists, with the name,
/// device and inode it listed for it, any of which can be absent, then every other text mapping
/// that has a name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Mapping {
    image: Option<PathBuf>,
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
    /// The system's own programs seen running as another user beneath a session, which the kernel
    /// will not describe: by number and the file each runs.
    other_users: Vec<(u32, PathBuf)>,
    /// Why a look did not find every process beneath the sessions, once for each reason.
    untracked: Vec<String>,
    /// Every process a look found beneath the sessions and took as theirs, by its start identity,
    /// with its command line, whatever became of reading its image: the run's close requires each
    /// ended.
    identified: BTreeMap<ProcessStartIdentity, String>,
    /// The first process found whose command line names a word the part forbids.
    forbidden: Option<String>,
}

/// The processes a look has published, and whether the part has been halted.
#[derive(Debug, Default)]
struct Published {
    processes: Vec<ProcessStartIdentity>,
    halted: bool,
}

/// What a stage's sessions ran, checked as they ran it.
pub struct Provenance {
    marks: Vec<PathBuf>,
    places: Vec<(PathBuf, &'static str)>,
    run_root: PathBuf,
    run_resolved: PathBuf,
    link: PathBuf,
    path_file: PathBuf,
    exported_file: PathBuf,
    started_file: PathBuf,
    cleared: Vec<String>,
    allowed: Vec<String>,
    cleared_required: AtomicBool,
    seen_path: Mutex<Option<String>>,
    seen: Mutex<Seen>,
    /// The words no command line beneath the sessions may name, each a whole word of it, compared
    /// without regard to case: the names of the servers a confined agent must start none of.
    forbidden_words: Mutex<Vec<String>>,
    roots: Mutex<Vec<ProcessStartIdentity>>,
    /// Every process a look found beneath the sessions, published the moment the look takes it as
    /// theirs, under a lock of its own that is held only to read or extend it: what a stop reads
    /// without waiting on a look. Once the part is halted ([`Provenance::halt`]), a process
    /// published after that is killed as it is published.
    published: Mutex<Published>,
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
            exported_file: run.home().join(EXPORTED_FILE),
            started_file: run.home().join(STARTED_FILE),
            cleared: build
                .account
                .as_ref()
                .map(|account| account.cleared.clone())
                .unwrap_or_default(),
            // What the build list sets in the session itself is not the person's.
            allowed: build
                .environment
                .keys()
                .chain(
                    build
                        .account
                        .iter()
                        .flat_map(|account| account.variables.keys()),
                )
                .chain(
                    build
                        .account
                        .iter()
                        .filter_map(|account| account.config_directory.as_ref())
                        .map(|directory| &directory.variable),
                )
                .chain(
                    build
                        .account
                        .iter()
                        .filter_map(|account| account.confinement.as_ref())
                        .flat_map(|confinement| {
                            std::iter::once(&confinement.variable)
                                .chain(&confinement.proxy_variables)
                        }),
                )
                .cloned()
                .collect(),
            cleared_required: AtomicBool::new(false),
            seen_path: Mutex::new(None),
            seen: Mutex::new(Seen::default()),
            forbidden_words: Mutex::new(Vec::new()),
            roots: Mutex::new(Vec::new()),
            published: Mutex::new(Published::default()),
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

    /// Checks the variables the session's shell exports, as it wrote their names before its last
    /// prompt, against those the build list clears: the agent is started from that shell.
    ///
    /// # Errors
    ///
    /// Returns why, as [`exported_clear`] does, or beginning with [`ENVIRONMENT_NOT_READ`] when
    /// the shell wrote no names.
    pub fn check_cleared(&self) -> Result<(), String> {
        self.check_names(&self.exported_file)
    }

    /// Removes the names the shell wrote before an earlier command line, so that the list the
    /// next line writes is the only one [`Provenance::check_cleared_at_start`] can read.
    ///
    /// # Errors
    ///
    /// Returns why, as [`forget_names`] does.
    pub fn forget_started(&self) -> Result<(), String> {
        if self.checks_names() {
            forget_names(&self.started_file)
        } else {
            Ok(())
        }
    }

    /// Whether the launch checks the names the shell exports: the build list clears some, and the
    /// part has a login.
    fn checks_names(&self) -> bool {
        !self.cleared.is_empty() && self.cleared_required.load(Ordering::SeqCst)
    }

    /// Checks the same names as the shell wrote them just before it ran the command line typed
    /// since [`Provenance::forget_started`], which is the agent's: what the agent started with,
    /// and not what the shell had at the prompt before it. Waits at most `within` for the list.
    ///
    /// # Errors
    ///
    /// Returns why, as [`wait_for_names`] does.
    pub fn check_cleared_at_start(&self, within: Duration) -> Result<(), String> {
        if !self.checks_names() {
            return Ok(());
        }
        wait_for_names(&self.started_file, within, &self.cleared, &self.allowed)
    }

    /// Makes the launch check the variables the build list clears: the parts that run with the
    /// person's login, whose turns the model answers, need them absent; the others start no turn.
    pub fn require_cleared(&self) {
        self.cleared_required.store(true, Ordering::SeqCst);
    }

    fn check_names(&self, file: &Path) -> Result<(), String> {
        if !self.checks_names() {
            return Ok(());
        }
        let exported = std::fs::read_to_string(file).map_err(|error| {
            format!(
                "{ENVIRONMENT_NOT_READ} the session's shell wrote no exported names to {}: {error}",
                file.display()
            )
        })?;
        exported_clear(&exported, &self.cleared, &self.allowed)
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

    /// Sets the words no command line beneath the sessions may name: a process whose command line
    /// holds one as a whole word is found by the next look, and [`Provenance::forbidden_found`]
    /// says so.
    pub fn forbid_words(&self, words: Vec<String>) {
        *self
            .forbidden_words
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = words;
    }

    /// What the looks found of the forbidden words: the first process whose command line named one,
    /// by its number and the word's place in the list, never the word.
    #[must_use]
    pub fn forbidden_found(&self) -> Option<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .forbidden
            .clone()
    }

    /// Every process a look found beneath the sessions and took as theirs, with its command line,
    /// for the run's closing check to find ended.
    #[must_use]
    pub fn identified(&self) -> Vec<(ProcessStartIdentity, String)> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .identified
            .iter()
            .map(|(identity, command)| (identity.clone(), command.clone()))
            .collect()
    }

    /// Halts the part, as a stop does, and returns every process a look has published so far,
    /// read without waiting on a look: from here on a look kills each process it would publish,
    /// so every process it takes is either in what this returns or killed by the look.
    #[must_use]
    pub fn halt(&self) -> Vec<ProcessStartIdentity> {
        let mut published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        published.halted = true;
        published.processes.clone()
    }

    /// Publishes a process a look has taken as the sessions', or kills it where the part has been
    /// halted.
    fn publish(&self, identity: &ProcessStartIdentity) {
        let mut published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if published.halted {
            kr_e2e_m1b::run::signal(identity, rustix::process::Signal::KILL);
        }
        if !published.processes.contains(identity) {
            published.processes.push(identity.clone());
        }
    }

    /// The sessions' root shells the looks walk from.
    #[must_use]
    pub fn watched(&self) -> Vec<ProcessStartIdentity> {
        self.roots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Why a look did not find every process beneath the sessions, for the run's closing check to
    /// fail on as well.
    #[must_use]
    pub fn untracked(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .untracked
            .clone()
    }

    /// Notes one of the system's own programs running as another user that another search beneath
    /// the sessions found, so its number goes with the part's evidence too.
    pub fn note_system_program(&self, pid: u32, path: &Path) {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if !seen.other_users.iter().any(|(number, _)| *number == pid) {
            seen.other_users.push((pid, path.to_path_buf()));
        }
    }

    /// The system's own programs seen running as another user beneath the sessions, by number and
    /// the file each runs, for the run's closing check to find ended.
    #[must_use]
    pub fn system_programs(&self) -> Vec<(u32, PathBuf)> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .other_users
            .clone()
    }

    /// What the stage's sessions searched and ran, for the part's evidence.
    #[must_use]
    pub fn evidence(&self) -> serde_json::Value {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let executed: Vec<&Executed> = seen.executed.values().collect();
        // Every process number seen beneath the sessions, which is how the system's
        // authentication and privacy services name the processes that call them.
        let pids: std::collections::BTreeSet<u64> = seen
            .processes
            .keys()
            .chain(seen.identified.keys())
            .map(|identity| identity.pid.get())
            .chain(seen.other_users.iter().map(|(pid, _)| u64::from(*pid)))
            .collect();
        json!({
            "session_path": *self.seen_path.lock().unwrap_or_else(PoisonError::into_inner),
            "sample_interval_ms": SAMPLE_INTERVAL.as_millis(),
            "samples": seen.samples,
            "launches": seen.launches,
            "executed": executed,
            "pids": pids,
            "system_programs_of_another_user": seen
                .other_users
                .iter()
                .map(|(pid, image)| json!({ "pid": pid, "image": image }))
                .collect::<Vec<_>>(),
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
                untracked(
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
                    untracked(
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
                            // One of the system's own programs running as another user runs a
                            // file the system protects, and is recorded as such.
                            if let Some(path) = kr_e2e_m1b::run::system_program_of_another_user(
                                entry.pid,
                                &error.to_string(),
                            ) {
                                // Its number goes with the part's evidence whatever else holds.
                                if !seen.other_users.iter().any(|(pid, _)| *pid == entry.pid) {
                                    seen.other_users.push((entry.pid, path.clone()));
                                }
                                // What it started could not be followed back to it, so it may
                                // start nothing.
                                if let Some(child) =
                                    table.iter().find(|child| child.parent == entry.pid)
                                {
                                    untracked(
                                        &mut seen,
                                        format!(
                                            "{NOT_PINNED} the system program {} (process {}) beneath a session started process {}, which cannot be followed back to it",
                                            path.display(),
                                            entry.pid,
                                            child.pid
                                        ),
                                    );
                                    continue;
                                }
                                continue;
                            }
                            untracked(
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
                                untracked(&mut seen, why);
                                continue;
                            }
                        }
                    }
                    seen.identified
                        .entry(identity.clone())
                        .or_insert_with(|| entry.command.clone());
                    // Published at once, before anything else is looked at.
                    self.publish(&identity);
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
        let words = self
            .forbidden_words
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for (identity, command) in &found {
            if seen.forbidden.is_none()
                && let Some(place) = names_a_word(command, &words)
            {
                seen.forbidden = Some(format!(
                    "process {} runs a command line that names forbidden word {place} of {}",
                    identity.pid.get(),
                    words.len()
                ));
            }
        }
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
        let (Some(listed), Some(device), Some(inode)) =
            (mapping.image.as_ref(), mapping.device, mapping.inode)
        else {
            return Err(format!(
                "{NOT_PINNED} the image of process {pid} ({command}) was listed without its name, \
                 device or inode: {mapping:?}"
            ));
        };
        let key = (device, inode);
        let executed = if let Some(executed) = seen.executed.get(&key) {
            executed.clone()
        } else {
            let image = resolved(listed);
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
/// The place in `words` of the first that `command` holds as a whole word, compared without regard
/// to case: with no letter or digit on either side of it, so `dtt-mcp` and `dtt/mcp` hold `dtt`
/// and `dttx` does not.
fn names_a_word(command: &str, words: &[String]) -> Option<usize> {
    let command = command.to_lowercase();
    words.iter().position(|word| {
        let word = word.to_lowercase();
        !word.is_empty()
            && command.match_indices(word.as_str()).any(|(at, found)| {
                let before = command[..at].chars().next_back();
                let after = command[at + found.len()..].chars().next();
                !before.is_some_and(char::is_alphanumeric)
                    && !after.is_some_and(char::is_alphanumeric)
            })
    })
}

fn problem(seen: &mut Seen, why: String) {
    if seen.problem.is_none() {
        seen.problem = Some(why);
    }
}

/// Records a problem that also leaves the processes beneath the sessions not all found: the run's
/// closing check has to fail on it as well, since what was not found was not ended either.
fn untracked(seen: &mut Seen, why: String) {
    if !seen.untracked.contains(&why) {
        seen.untracked.push(why.clone());
    }
    problem(seen, why);
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
///
/// # Errors
///
/// Returns why the process or its parent could not be read.
pub fn beneath_parent(
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
    if pids.is_empty() {
        return Ok(BTreeMap::new());
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
    Ok(parse_mappings(&String::from_utf8_lossy(&output.stdout)))
}

/// Reads `lsof -F pDin` output. Each process begins with `p`, each of its files with `f`; a
/// file's device, inode and name follow its `f`, and any of them can be absent. The first file of
/// a process is its executable, kept whatever it lacks; a later file counts only with a name.
fn parse_mappings(text: &str) -> BTreeMap<u32, Mapping> {
    type File = (Option<u64>, Option<u64>, Option<PathBuf>);
    let close = |pid: Option<u32>, file: Option<File>, found: &mut BTreeMap<u32, Mapping>| {
        let (Some(pid), Some((device, inode, path))) = (pid, file) else {
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
            Some(mapping) => mapping.mapped.extend(path),
        }
    };
    let mut found = BTreeMap::new();
    let mut pid: Option<u32> = None;
    let mut file: Option<File> = None;
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
    found
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A process's first file is its executable even when `lsof` gives it no name: a later
    /// mapping never takes its place, so what the process runs is not established.
    #[test]
    fn a_command_line_names_a_forbidden_word_only_as_a_whole_word() {
        let words = vec!["pushary".to_owned(), "dtt".to_owned()];
        assert_eq!(
            names_a_word("/usr/bin/node /x/dtt-mcp serve", &words),
            Some(1)
        );
        assert_eq!(names_a_word("node /x/dttx/mcp serve", &words), None);
        assert_eq!(names_a_word("node /x/dtt/mcp serve", &words), Some(1));
        assert_eq!(
            names_a_word("run my-server now", &["my-server".to_owned()]),
            Some(0)
        );
        assert_eq!(names_a_word("npx -y Pushary --stdio", &words), Some(0));
        assert_eq!(names_a_word("kimi-code", &words), None);
        assert_eq!(names_a_word("echo hi > /tmp/work/a", &words), None);
        assert_eq!(names_a_word("echo dtt", &[]), None);
        assert_eq!(names_a_word("echo dtt", &[String::new()]), None);
    }

    #[test]
    fn a_first_file_without_a_name_is_kept_as_the_unnamed_executable() {
        let text = "p42\nftxt\nD0x1000012\ni7\nftxt\nD0x1000012\ni8\nn/usr/lib/dyld\n";
        let found = parse_mappings(text);
        assert_eq!(
            found.get(&42),
            Some(&Mapping {
                image: None,
                device: Some(0x0100_0012),
                inode: Some(7),
                mapped: vec![PathBuf::from("/usr/lib/dyld")],
            })
        );
    }

    /// A first file without a device or an inode is kept as the executable, without them.
    #[test]
    fn a_first_file_without_its_device_or_inode_is_kept_without_them() {
        let text = "p7\nftxt\nn/bin/zsh\nftxt\nD0x1000012\ni3\nn/usr/lib/dyld\n";
        let mapping = parse_mappings(text).remove(&7).expect("the process");
        assert_eq!(mapping.image, Some(PathBuf::from("/bin/zsh")));
        assert_eq!((mapping.device, mapping.inode), (None, None));
    }

    /// The names a shell would write: each on a line, then the end mark.
    fn list(names: &[&str]) -> String {
        names
            .iter()
            .chain(&[LIST_END])
            .map(|name| format!("{name}\n"))
            .collect()
    }

    /// A cleared variable the shell exports fails the check by name, a prefix clears every name
    /// that begins with it but for those the build list sets itself, and a list that does not end
    /// with its mark or holds no PATH was not written whole.
    #[test]
    fn a_cleared_variable_the_shell_exports_fails_the_check_by_name() {
        let exported = list(&["HOME", "PATH", "CLAUDE_CODE_SUBAGENT_MODEL", "TERM"]);
        let cleared = [
            "CLAUDE_CODE_SUBAGENT_MODEL".to_owned(),
            "CLAUDE_CODE_SUBAGENT_MODEL_FORCE".to_owned(),
        ];
        let refused =
            exported_clear(&exported, &cleared, &[]).expect_err("an exported cleared name");
        assert!(refused.starts_with(ENVIRONMENT_NOT_CLEAR), "{refused}");
        assert!(refused.ends_with("CLAUDE_CODE_SUBAGENT_MODEL, which the build list clears"));
        assert!(
            !refused.contains("_FORCE"),
            "only the exported name is said: {refused}"
        );
        assert_eq!(
            exported_clear(&list(&["HOME", "PATH"]), &cleared, &[]),
            Ok(())
        );
        // A name that merely starts with a cleared one, or holds it, is another variable.
        assert_eq!(
            exported_clear(
                &list(&[
                    "PATH",
                    "CLAUDE_CODE_SUBAGENT_MODEL_X",
                    "X_CLAUDE_CODE_SUBAGENT_MODEL"
                ]),
                &cleared,
                &[]
            ),
            Ok(())
        );
        // A prefix clears every name beneath it, but for the names the build list sets itself, and
        // the end mark is no name.
        let prefixes = [
            "ANTHROPIC_*".to_owned(),
            "CLAUDE_*".to_owned(),
            "KR_*".to_owned(),
        ];
        let allowed = ["CLAUDE_CONFIG_DIR".to_owned()];
        assert_eq!(
            exported_clear(
                &list(&["PATH", "CLAUDE_CONFIG_DIR", "OTHER"]),
                &prefixes,
                &allowed
            ),
            Ok(())
        );
        let refused = exported_clear(
            &list(&[
                "PATH",
                "CLAUDE_CONFIG_DIR",
                "ANTHROPIC_DEFAULT_OPUS_MODEL",
                "CLAUDE_CODE_USE_VERTEX",
            ]),
            &prefixes,
            &allowed,
        )
        .expect_err("names beneath the prefixes");
        assert!(
            refused.ends_with(
                "exports ANTHROPIC_DEFAULT_OPUS_MODEL, CLAUDE_CODE_USE_VERTEX, which the build list clears"
            ),
            "{refused}"
        );
        // A list without its end mark, or without PATH, was not written whole, whatever else it
        // holds or lacks: a partial write with PATH first and a cleared name after it fails.
        for unwritten in [
            String::new(),
            "HOME\nTERM\n".to_owned(),
            list(&["HOME", "TERM"]),
            "PATH\nHOME\n".to_owned(),
            "PATH\nCLAUDE_CODE_SUBAGENT_MODEL\n".to_owned(),
            // The mark cannot be a name, and a name that looks like a mark is not one.
            "PATH\nKR_AGENTS_END\n".to_owned(),
        ] {
            let refused = exported_clear(&unwritten, &cleared, &[]).expect_err("not whole");
            assert!(refused.starts_with(ENVIRONMENT_NOT_READ), "{refused}");
        }
    }

    /// The wait for the list the agent's line writes: no file is not read in time, a file that is
    /// not whole is waited on until it is, a list written during the wait is the one checked, and
    /// a list of an earlier line, removed first, cannot be the one read.
    #[test]
    fn the_wait_for_the_agents_names_reads_only_a_whole_list_written_after_the_removal() {
        let unique: String = kr_ipc::new_uuid()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let directory = std::env::temp_dir().join(format!("kr-names-{unique}"));
        std::fs::create_dir(&directory).expect("a directory of the test's own");
        let file = directory.join("names");
        let cleared = ["CLAUDE_CODE_*".to_owned()];
        let quick = Duration::from_millis(150);
        // No file.
        let refused = wait_for_names(&file, quick, &cleared, &[]).expect_err("no file");
        assert!(refused.starts_with(ENVIRONMENT_NOT_READ), "{refused}");
        // A file that is not whole: PATH before the cleared name, and no end mark.
        std::fs::write(&file, "PATH\n").expect("writes part of a list");
        let refused = wait_for_names(&file, quick, &cleared, &[]).expect_err("no end mark");
        assert!(refused.starts_with(ENVIRONMENT_NOT_READ), "{refused}");
        // A list of an earlier line, removed first, is not there to pass.
        std::fs::write(&file, list(&["PATH"])).expect("writes an earlier list");
        forget_names(&file).expect("removes it");
        assert!(!file.exists());
        forget_names(&file).expect("a file that is not there is what is wanted");
        assert!(wait_for_names(&file, quick, &cleared, &[]).is_err());
        // A list written whole during the wait is the one checked, whichever way it ends.
        for (names, clear) in [
            (list(&["PATH", "HOME"]), true),
            (list(&["PATH", "CLAUDE_CODE_X"]), false),
        ] {
            let writer = {
                let file = file.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    std::fs::write(&file, "PATH\n").expect("writes a part");
                    std::thread::sleep(Duration::from_millis(100));
                    std::fs::write(&file, names).expect("writes the rest");
                })
            };
            let found = wait_for_names(&file, Duration::from_secs(5), &cleared, &[]);
            writer.join().expect("the writer ends");
            assert_eq!(found.is_ok(), clear, "{found:?}");
            if let Err(refused) = &found {
                assert!(
                    refused.starts_with(ENVIRONMENT_NOT_CLEAR),
                    "a refusal, not a timeout: {refused}"
                );
            }
            forget_names(&file).expect("removes it");
        }
        // A file that cannot be removed says so.
        let refused = forget_names(&directory).expect_err("a directory is not removed as a file");
        assert!(refused.starts_with(ENVIRONMENT_NOT_READ), "{refused}");
        std::fs::remove_dir_all(&directory).expect("removes the test's directory");
    }

    /// Each process's files are its own, and each begins at its `f`.
    #[test]
    fn each_process_keeps_its_own_first_file() {
        let text = "p1\nftxt\nD0x10\ni1\nn/bin/zsh\np2\nftxt\nD0x10\ni2\nn/bin/sh\nftxt\nD0x10\ni3\nn/usr/lib/dyld\n";
        let found = parse_mappings(text);
        assert_eq!(found[&1].image, Some(PathBuf::from("/bin/zsh")));
        assert_eq!((found[&1].device, found[&1].inode), (Some(16), Some(1)));
        assert_eq!(found[&2].image, Some(PathBuf::from("/bin/sh")));
        assert_eq!(found[&2].mapped, vec![PathBuf::from("/usr/lib/dyld")]);
    }
}
