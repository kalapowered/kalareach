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
//! again, and a run that signalled a number it stored earlier could end somebody else's work. The
//! closing check asks three questions of the operating system, and a run that leaves anything
//! behind fails on it: whether any recorded process still runs, whether any process at all still
//! runs out of this run's directory, and whether the service manager still holds a job this run's
//! daemon defined.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, process_start_identity, process_state};
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

    /// Records a process by the number it has now, when the kernel still describes it.
    pub fn record_pid(&self, pid: u32, what: &str) -> Option<ProcessStartIdentity> {
        let identity = process_start_identity(pid).ok()?;
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
        left.extend(
            processes_under(&self.root)
                .into_iter()
                .map(|(pid, command)| format!("process {pid} running {command}")),
        );
        let jobs = self.loaded_jobs();
        left.extend(jobs.iter().map(|job| format!("the launchd job {job}")));
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
                let answer = std::process::Command::new("/bin/launchctl")
                    .args(["print", &target])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                match answer.map(|status| status.code()) {
                    // 112 is a domain that is not there and 113 a job the domain does not have.
                    Ok(Some(112 | 113)) => {}
                    Ok(Some(0)) => loaded.push(target),
                    other => loaded.push(format!("{target} (launchctl print answered {other:?})")),
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
            let _ = std::process::Command::new("/bin/launchctl")
                .args(["bootout", &target])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
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

/// Every process whose command line names `root`, other than this one.
///
/// Every binary a leg launches is a copy inside its directory and every path it hands a process is
/// inside it, so a process still running out of it is one the leg started, whoever its parent is.
#[must_use]
pub fn processes_under(root: &Path) -> Vec<(u32, String)> {
    let needle = root.display().to_string();
    let Ok(output) = std::process::Command::new("ps")
        .args(["-A", "-ww", "-o", "pid=,command="])
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null())
        .output()
    else {
        return vec![(0, "the process table could not be read".to_owned())];
    };
    let own = std::process::id();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, command) = line.split_once(' ')?;
            let pid: u32 = pid.parse().ok()?;
            (pid != own && command.contains(&needle)).then(|| (pid, command.trim().to_owned()))
        })
        .collect()
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
