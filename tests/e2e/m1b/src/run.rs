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
//! line names this run's directory, which is new for every run ([`Run::record_named`]). A worker is
//! found by its command line in the process table, and no file of the host's is opened for it.
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
    /// The directory `root` named when this run made it, for the run's whole life.
    pin: RootPin,
    owned: Mutex<Vec<Owned>>,
    /// The system's own programs seen running as another user beneath the run's processes, by
    /// number and the file each runs: not the run's to end, and checked ended at the close.
    system_programs: Mutex<Vec<(u32, PathBuf)>>,
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
    /// it never ran. It also panics when the directory cannot be made or a binary cannot be placed
    /// in it, and the directory it made, which holds nothing but copied binaries, is removed first.
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
        // Short on purpose: a Unix socket address is 104 bytes on macOS, and the per-user
        // temporary directory there is 57 of them. A socket a worker binds for a command it
        // integrates lies 42 bytes below the run's directory, which would make it 111 bytes.
        // `/tmp` is on the internal disk there as well.
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        // Made by this call and no other, and pinned from the handle it was opened by: a directory
        // that was there is never taken, a mount or a link put in its place is refused, and a start
        // that fails here leaves the path where it is and removes nothing.
        let (root, pin) = make_root(&base, &mut || kr_ipc::new_uuid().to_string(), &mut |_| {})
            .unwrap_or_else(|why| panic!("{why}"));
        let run = Self {
            leg: leg.to_owned(),
            root,
            pin,
            owned: Mutex::new(Vec::new()),
            system_programs: Mutex::new(Vec::new()),
            undiscovered: Mutex::new(Vec::new()),
            passed: Mutex::new(false),
        };
        // A start that fails here has started nothing and holds nothing but the binaries copied so
        // far, so its directory goes with it and is not kept as a failed leg's is.
        let placed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for directory in ["b", "h", "w"] {
                kr_ipc::paths::create_private_tree(&run.root, &run.root.join(directory))
                    .expect("an owner-only directory inside the run's own");
            }
            for name in BINARIES {
                // Run once here, where nothing is timed: the operating system checks a newly
                // written executable the first time it starts, and that can take seconds.
                kr_ipc::testing::place_and_start_once(
                    &built.join(name),
                    &run.binary(name),
                    &["--version"],
                );
            }
        }));
        if let Err(panic) = placed {
            let _ = run.closing_check();
            std::panic::resume_unwind(panic);
        }
        println!("the {leg} leg runs in {}", run.root.display());
        run
    }

    /// A run over a directory that is already there, for the cases that look at what the run's
    /// helpers do to a tree of its own: nothing is placed and nothing is started.
    #[cfg(test)]
    pub(crate) fn over(root: &Path) -> Self {
        Self {
            leg: "test".to_owned(),
            root: root.to_path_buf(),
            pin: RootPin::of(root).expect("a pin of the directory"),
            owned: Mutex::new(Vec::new()),
            system_programs: Mutex::new(Vec::new()),
            undiscovered: Mutex::new(Vec::new()),
            passed: Mutex::new(false),
        }
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

    /// The identity of the directory this run made, which a reader or a removal of the run's
    /// directory checks the directory it is given against.
    #[must_use]
    pub fn pin(&self) -> &RootPin {
        &self.pin
    }

    /// Where one copied binary is.
    #[must_use]
    pub fn binary(&self, name: &str) -> PathBuf {
        self.root.join("b").join(name)
    }

    /// Places another program this build made at `destination`, for a leg that needs it beside the
    /// run's own binaries or under another name, and starts it once with `arguments` where nothing
    /// is timed.
    ///
    /// # Panics
    ///
    /// Panics when the program this build should have produced is missing, or cannot be placed or
    /// started.
    pub fn place_built(&self, name: &str, destination: &Path, arguments: &[&str]) {
        let built = built_directory().join(name);
        assert!(
            built.is_file(),
            "the {} leg needs {name} and there is none at {}; build it with `cargo build -p \
             kr-hook -p kr-codex-stand-in`, as `cargo test --workspace` does",
            self.leg,
            built.display()
        );
        kr_ipc::testing::place_and_start_once(&built, destination, arguments);
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

    /// Notes one of the system's own programs running as another user beneath the run's processes
    /// ([`system_program_of_another_user`]), which the closing check requires to have ended.
    pub fn note_system_program(&self, pid: u32, path: &Path) {
        let mut noted = self
            .system_programs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !noted.iter().any(|(number, _)| *number == pid) {
            noted.push((pid, path.to_path_buf()));
        }
    }

    /// The system programs noted under [`Run::note_system_program`], by number and file.
    #[must_use]
    pub fn system_programs(&self) -> Vec<(u32, PathBuf)> {
        self.system_programs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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
        let checked = self.nothing_running()?;
        *self.passed.lock().unwrap_or_else(PoisonError::into_inner) = true;
        Ok(checked)
    }

    /// Checks, as [`Run::closing_check`] does, that nothing this run started is still running,
    /// without taking the run as passed: its directory is kept when it is dropped.
    ///
    /// # Errors
    ///
    /// Returns what is still running, as [`Run::closing_check`] does.
    pub fn nothing_running(&self) -> Result<String, String> {
        let owned = self.owned();
        let programs = self
            .system_programs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let started = Instant::now();
        while started.elapsed() < CLOSING_WAIT
            && (owned.iter().any(|o| running(&o.identity))
                || programs.iter().any(|(pid, _)| system_program_may_run(*pid)))
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut left: Vec<String> = owned
            .iter()
            .filter(|owned| running(&owned.identity))
            .map(|owned| format!("{} (process {})", owned.what, owned.identity.pid.get()))
            .collect();
        left.extend(
            programs
                .iter()
                .filter(|(pid, _)| system_program_may_run(*pid))
                .map(|(pid, path)| {
                    format!("the system program {} (process {pid})", path.display())
                }),
        );
        match processes_under(&self.root) {
            Ok(found) => left.extend(
                found
                    .into_iter()
                    .map(|(pid, command)| format!("process {pid} running {command}")),
            ),
            Err(why) => left.push(why),
        }
        match self.loaded_jobs() {
            Ok(jobs) => left.extend(jobs.iter().map(|job| format!("the launchd job {job}"))),
            Err(why) => left.push(why),
        }
        left.extend(
            self.undiscovered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|why| format!("not every process could be found: {why}")),
        );
        if left.is_empty() {
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
    /// leaves no job of this kind behind, so elsewhere this is always empty. A job `launchctl` gave
    /// no clear answer about is listed as loaded, with the answer it gave.
    ///
    /// # Errors
    ///
    /// Returns why the definitions could not be read, which says nothing about which jobs are
    /// loaded.
    pub fn loaded_jobs(&self) -> Result<Vec<String>, String> {
        if !cfg!(target_os = "macos") {
            return Ok(Vec::new());
        }
        let labels = self.defined_jobs().map_err(|why| {
            format!("the jobs this run's daemon defined could not be listed: {why}")
        })?;
        let uid = rustix::process::getuid().as_raw();
        let mut loaded = Vec::new();
        for label in labels {
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
        Ok(loaded)
    }

    /// Removes every launchd job this run's daemon defined and still has loaded.
    ///
    /// For a run that failed part way: launchd ends whatever still runs inside a job it removes,
    /// and each job is named by the label this run's own daemon gave it.
    pub fn remove_loaded_jobs(&self) {
        let Ok(targets) = self.loaded_jobs() else {
            // Which jobs to remove is not known; the closing check says why.
            return;
        };
        for target in targets {
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
                    // One of the system's own programs running as another user is not this run's
                    // to end: it is noted, so the close finds it ended, and it may start nothing,
                    // since what it started could not be followed back to it.
                    ProcessQuery::CannotEstablish(error) => {
                        let Some(path) =
                            system_program_of_another_user(entry.pid, &error.to_string())
                        else {
                            return Err(format!(
                                "process {} beneath {what} could not be identified: {error}",
                                entry.pid
                            ));
                        };
                        self.note_system_program(entry.pid, &path);
                        if let Some(child) = table.iter().find(|child| child.parent == entry.pid) {
                            return Err(format!(
                                "the system program {} (process {}) beneath {what} started \
                                 process {}, which cannot be followed back to it",
                                path.display(),
                                entry.pid,
                                child.pid
                            ));
                        }
                        continue;
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
    ///
    /// # Errors
    ///
    /// Returns why a directory of definitions could not be read. A directory the daemon never
    /// made holds none; one that could not be read has not said which it holds.
    fn defined_jobs(&self) -> Result<Vec<String>, String> {
        let unread = |directory: &Path, error: std::io::Error| {
            format!("{} could not be read: {error}", directory.display())
        };
        let environments = self.root.join("s").join("environments");
        let entries = match std::fs::read_dir(&environments) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(unread(&environments, error)),
        };
        let mut labels = Vec::new();
        for environment in entries {
            let environment = environment.map_err(|error| unread(&environments, error))?;
            let is_directory = environment
                .file_type()
                .map_err(|error| unread(&environment.path(), error))?
                .is_dir();
            if !is_directory {
                continue;
            }
            let directory = environment.path().join("jobs");
            let jobs = match std::fs::read_dir(&directory) {
                Ok(jobs) => jobs,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(unread(&directory, error)),
            };
            for job in jobs {
                let path = job.map_err(|error| unread(&directory, error))?.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "plist")
                    && let Some(label) = path.file_stem().and_then(|stem| stem.to_str())
                {
                    labels.push(label.to_owned());
                }
            }
        }
        Ok(labels)
    }
}

/// Makes the run's own directory below `base`, with a name `names` gives (eight characters of it),
/// and pins it, through handles only: `base` is opened as a handle, the directory is made with
/// `mkdirat` on it and opened with `openat` and no link followed, and on that handle the directory
/// must be on `base`'s device (a volume mounted on the new name is refused), owner-only, and empty (a
/// directory moved in is refused). The pin and the directory's resolved path are read from that
/// handle. `between` is told the new name once it is made and before it is opened, which is where a
/// test puts something else in its place.
///
/// # Errors
///
/// Returns why the directory was not made or is not the directory this call made, as a class and no
/// name. Nothing is removed in any case: a failed start leaves the path where it is.
fn make_root(
    base: &Path,
    names: &mut dyn FnMut() -> String,
    between: &mut dyn FnMut(&Path),
) -> Result<(PathBuf, RootPin), String> {
    use rustix::fs::{Mode, OFlags};
    let said = |what: &str, error: rustix::io::Errno| {
        format!("the run's directory {what}: {error}; whatever is at its path was left where it is")
    };
    let base_handle = rustix::fs::open(
        base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| said("cannot be made, its base cannot be opened", error))?;
    let base_stat = rustix::fs::fstat(&base_handle)
        .map_err(|error| said("cannot be made, its base cannot be looked at", error))?;
    let mut name = None;
    for _ in 0..64 {
        let candidate = format!("krm-{}", &names()[..8]);
        match rustix::fs::mkdirat(&base_handle, candidate.as_str(), Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                name = Some(candidate);
                break;
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(said("cannot be made", error)),
        }
    }
    let name = name
        .ok_or_else(|| "the run's directory has no free name among sixty-four tries".to_owned())?;
    between(&base.join(&name));
    let handle = rustix::fs::openat(
        &base_handle,
        name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        said(
            "is not the directory that was made, a link or another entry is there",
            error,
        )
    })?;
    let stat = rustix::fs::fstat(&handle).map_err(|error| said("cannot be looked at", error))?;
    if stat.st_dev != base_stat.st_dev {
        return Err(
            "the run's directory is on another file system than its base, as a mounted \
                    volume is; it was left where it is"
                .to_owned(),
        );
    }
    if stat.st_uid != rustix::process::getuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err("the run's directory is not owner-only; it was left where it is".to_owned());
    }
    let entries = rustix::fs::Dir::read_from(&handle)
        .map_err(|error| said("cannot be listed", error))?
        .filter(|entry| {
            entry.as_ref().map_or(true, |entry| {
                entry.file_name().to_bytes() != b"." && entry.file_name().to_bytes() != b".."
            })
        })
        .count();
    if entries != 0 {
        return Err(
            "the run's directory is not empty, so it is not the directory that was made \
                    (the count of its entries is {entries}); it was left where it is"
                .replace("{entries}", &entries.to_string()),
        );
    }
    let pin = RootPin::of_handle(&handle)?;
    // The access list, which the handle's mode does not show, is read from the path the handle
    // has, and the directory found there is checked to be the pinned one.
    let root = pin.place.clone();
    kr_ipc::paths::create_private_tree(&root, &root)
        .map_err(|error| format!("the run's directory is not private: {error}"))?;
    let again = open_directory(&root).map_err(|error| said("is not at its place", error))?;
    if !pin.holds(&again) {
        return Err(
            "the run's directory is not the directory that was made; it was left where \
                    it is"
                .to_owned(),
        );
    }
    Ok((root, pin))
}

/// The directory a run made: its device and inode from the handle opened on it right after it was
/// made, and the place that handle then had. A mount point is never the directory a run made, and
/// neither is another directory renamed to its path, so a directory that does not match is not the
/// run's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootPin {
    device: i128,
    inode: i128,
    place: PathBuf,
}

/// Opens the directory at `path`, following no link at its last component.
fn open_directory(path: &Path) -> rustix::io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// The place an open file or directory has now, as the system says it, or `None` where it will not.
#[must_use]
pub fn current_place(handle: impl std::os::fd::AsFd) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let place = rustix::fs::getpath(handle).ok()?;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(place.to_bytes())))
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::fd::AsRawFd as _;
        std::fs::read_link(format!("/proc/self/fd/{}", handle.as_fd().as_raw_fd())).ok()
    }
}

impl RootPin {
    /// Pins the directory at `path`.
    ///
    /// # Errors
    ///
    /// Returns why it could not be opened and looked at.
    pub fn of(path: &Path) -> Result<Self, String> {
        let handle = open_directory(path)
            .map_err(|error| format!("the run's directory cannot be pinned: {error}"))?;
        Self::of_handle(&handle)
    }

    /// Pins the directory `handle` is open on: its device and inode, and the place the system says
    /// it has now.
    ///
    /// # Errors
    ///
    /// Returns why it could not be looked at.
    pub fn of_handle(handle: impl std::os::fd::AsFd) -> Result<Self, String> {
        let stat = rustix::fs::fstat(&handle)
            .map_err(|error| format!("the run's directory cannot be pinned: {error}"))?;
        let place = current_place(&handle)
            .ok_or_else(|| "the system names no place for the run's directory".to_owned())?;
        Ok(Self {
            device: i128::from(stat.st_dev),
            inode: i128::from(stat.st_ino),
            place,
        })
    }

    /// Whether `handle` is the directory that was pinned.
    #[must_use]
    pub fn holds(&self, handle: impl std::os::fd::AsFd) -> bool {
        rustix::fs::fstat(handle).is_ok_and(|stat| {
            i128::from(stat.st_dev) == self.device && i128::from(stat.st_ino) == self.inode
        })
    }

    /// Whether the open file or directory `handle` is now beneath the pinned directory's place: a
    /// directory that was moved out of the run, or a file moved into one that was, is not.
    #[must_use]
    pub fn contains(&self, handle: impl std::os::fd::AsFd) -> bool {
        current_place(handle).is_some_and(|place| place.starts_with(&self.place))
    }
}

/// Why a path below the run's directory was not opened to be read: a class, and no name, so that
/// nothing about a place outside the run is said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The run's directory is not the directory the run made.
    RootChanged,
    /// An entry on the way, or the file itself, is a symbolic link.
    Link,
    /// An entry is not the kind of entry the path names: a directory on the way, a regular file at
    /// its end.
    NotAFile,
    /// The file has more than one name, so it may be a file of the person's under another one.
    SecondName,
    /// An entry lies on another file system than the run's directory, as a mounted volume does.
    OtherDevice,
    /// An entry was another one when it was opened than when it was looked at.
    Replaced,
    /// An entry that was opened is no longer beneath the run's directory.
    Moved,
    /// The system refused a look or an opening.
    Refused(rustix::io::Errno),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootChanged => {
                formatter.write_str("the run's directory is not the directory the run made")
            }
            Self::Link => formatter
                .write_str("an entry on the way is a symbolic link, which is followed by nothing"),
            Self::NotAFile => {
                formatter.write_str("an entry is not the kind of entry the path names")
            }
            Self::SecondName => formatter.write_str(
                "the file has more than one name, which is refused and read through by nothing",
            ),
            Self::OtherDevice => {
                formatter.write_str("an entry lies on another file system than the run's")
            }
            Self::Replaced => formatter.write_str(
                "an entry was another one when it was opened than when it was looked at",
            ),
            Self::Moved => formatter.write_str("an entry is no longer beneath the run's directory"),
            Self::Refused(error) => {
                write!(
                    formatter,
                    "the system refused a look or an opening: {error}"
                )
            }
        }
    }
}

/// Looks at `name` in `directory`, following no link, on the file system `device`: `None` where it
/// is not there.
fn look_below(
    directory: &std::os::fd::OwnedFd,
    name: &std::ffi::CStr,
    device: rustix::fs::Dev,
) -> Result<Option<rustix::fs::Stat>, Refusal> {
    match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(looked) if looked.st_dev == device => Ok(Some(looked)),
        // For mounts only: the system's own volumes share one device number.
        Ok(_) => Err(Refusal::OtherDevice),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(Refusal::Refused(error)),
    }
}

/// Opens the regular file `relative` below the run's directory `root`, through handles only: `root`
/// must be the directory `pin` names, and each component is looked at with no link followed, on
/// `root`'s file system, and opened relative to its directory's handle with no link followed, then
/// checked to be what was looked at and to lie beneath the pinned place. The file must be a regular
/// file with one name. A link, a second name, another file system, a directory where a file is
/// named or the reverse is a [`Refusal`] and nothing is opened through it. `Ok(None)` is a path
/// that is not there.
///
/// # Errors
///
/// Returns why the path is not a regular file of the run with one name.
pub fn open_file_below(
    root: &Path,
    pin: &RootPin,
    relative: &Path,
) -> Result<Option<std::os::fd::OwnedFd>, Refusal> {
    open_file_below_by(root, pin, relative, &mut |_| {})
}

/// [`open_file_below`] with the moment before each component is looked at, told its name, at which
/// a test changes the tree.
fn open_file_below_by(
    root: &Path,
    pin: &RootPin,
    relative: &Path,
    before_look: &mut dyn FnMut(&[u8]),
) -> Result<Option<std::os::fd::OwnedFd>, Refusal> {
    use rustix::fs::{FileType, Mode, OFlags};
    let mut directory = open_directory(root).map_err(|error| match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => Refusal::RootChanged,
        other => Refusal::Refused(other),
    })?;
    let device = rustix::fs::fstat(&directory)
        .map_err(Refusal::Refused)?
        .st_dev;
    if !pin.holds(&directory) {
        return Err(Refusal::RootChanged);
    }
    let mut names = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(Refusal::NotAFile);
        };
        names.push(std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| Refusal::NotAFile)?);
    }
    let Some((last, parents)) = names.split_last() else {
        return Err(Refusal::NotAFile);
    };
    let replaced = |error: rustix::io::Errno| match error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR | rustix::io::Errno::NOENT => {
            Refusal::Replaced
        }
        other => Refusal::Refused(other),
    };
    for name in parents {
        before_look(name.to_bytes());
        let Some(looked) = look_below(&directory, name.as_c_str(), device)? else {
            return Ok(None);
        };
        match FileType::from_raw_mode(looked.st_mode) {
            FileType::Directory => {}
            FileType::Symlink => return Err(Refusal::Link),
            _ => return Err(Refusal::NotAFile),
        }
        let child = rustix::fs::openat(
            &directory,
            name.as_c_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(replaced)?;
        let opened = rustix::fs::fstat(&child).map_err(Refusal::Refused)?;
        if (opened.st_dev, opened.st_ino) != (looked.st_dev, looked.st_ino) {
            return Err(Refusal::Replaced);
        }
        if !pin.contains(&child) {
            return Err(Refusal::Moved);
        }
        directory = child;
    }
    before_look(last.to_bytes());
    let Some(looked) = look_below(&directory, last.as_c_str(), device)? else {
        return Ok(None);
    };
    match FileType::from_raw_mode(looked.st_mode) {
        FileType::RegularFile => {}
        FileType::Symlink => return Err(Refusal::Link),
        _ => return Err(Refusal::NotAFile),
    }
    // A file with a second name is the same file under another name, whoever made it.
    if looked.st_nlink != 1 {
        return Err(Refusal::SecondName);
    }
    let file = rustix::fs::openat(
        &directory,
        last.as_c_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(replaced)?;
    let opened = rustix::fs::fstat(&file).map_err(Refusal::Refused)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || (opened.st_dev, opened.st_ino) != (looked.st_dev, looked.st_ino)
    {
        return Err(Refusal::Replaced);
    }
    // A name added since the look is a second name too.
    if opened.st_nlink != 1 {
        return Err(Refusal::SecondName);
    }
    if !pin.contains(&file) {
        return Err(Refusal::Moved);
    }
    Ok(Some(file))
}

/// How much of the end of a file [`read_tail_below`] reads at most.
const TAIL_AT_MOST: u64 = 1 << 20;

/// Reads the regular file `relative` below the run's directory as [`open_file_below`] opens it,
/// from the byte `after` on and at most the last mebibyte of that: `Ok(None)` for a file that is
/// not there.
///
/// # Errors
///
/// Returns why the path is not a regular file of the run with one name, or why it was not read.
pub fn read_tail_below(
    root: &Path,
    pin: &RootPin,
    relative: &Path,
    after: u64,
) -> Result<Option<Vec<u8>>, Refusal> {
    use std::os::unix::fs::FileExt as _;
    let Some(file) = open_file_below(root, pin, relative)? else {
        return Ok(None);
    };
    let file = std::fs::File::from(file);
    let refused = |error: std::io::Error| {
        Refusal::Refused(rustix::io::Errno::from_raw_os_error(
            error.raw_os_error().unwrap_or(0),
        ))
    };
    let length = file.metadata().map_err(refused)?.len();
    let from = after.min(length).max(length.saturating_sub(TAIL_AT_MOST));
    let mut bytes = vec![0; usize::try_from(length - from).unwrap_or(0)];
    file.read_exact_at(&mut bytes, from).map_err(refused)?;
    Ok(Some(bytes))
}

/// Why a run's directory was left where it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Left {
    /// The path is not the directory the run made.
    RootChanged,
    /// An entry lies on another file system than the run's directory, as a mounted volume does:
    /// nothing is entered or removed on it, and nothing else is removed either.
    AnotherFileSystem,
    /// A directory the removal held open is no longer beneath the run's directory: it was moved
    /// out, and nothing more is unlinked through it.
    MovedOut,
    /// The system refused a look, an opening or a removal.
    Refused,
}

impl std::fmt::Display for Left {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RootChanged => "the path is not the directory the run made",
            Self::AnotherFileSystem => "an entry below it lies on another file system",
            Self::MovedOut => "a directory it held open is no longer beneath it",
            Self::Refused => "the system refused a look or a removal",
        })
    }
}

/// What became of the removal of a run's directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// The directory is gone.
    Removed,
    /// The directory, or part of it, is where it was.
    Left(Left),
}

/// The deepest the removal goes.
const DEEPEST_REMOVAL: usize = 128;

/// Looks at every entry of `directory` and below, and with `remove` unlinks it, all through
/// handles: each entry is looked at with no link followed and compared with `device`, each
/// directory is opened with no link followed and checked to be the one that was looked at, and each
/// entry is unlinked relative to its directory's handle. An entry on another device is entered by
/// nothing and removed by nothing.
fn walk_for_removal(
    directory: &std::os::fd::OwnedFd,
    device: rustix::fs::Dev,
    pin: &RootPin,
    depth: usize,
    remove: bool,
    before_unlink: &mut dyn FnMut(&[u8]),
) -> Result<(), Left> {
    use rustix::fs::{AtFlags, FileType};
    if depth > DEEPEST_REMOVAL {
        return Err(Left::Refused);
    }
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory).map_err(|_| Left::Refused)? {
        let name = entry.map_err(|_| Left::Refused)?.file_name().to_owned();
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name);
        }
    }
    for name in names {
        let looked = match rustix::fs::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        {
            Ok(looked) => looked,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(_) => return Err(Left::Refused),
        };
        if looked.st_dev != device {
            return Err(Left::AnotherFileSystem);
        }
        if FileType::from_raw_mode(looked.st_mode) == FileType::Directory {
            let child = rustix::fs::openat(
                directory,
                name.as_c_str(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| Left::Refused)?;
            let opened = rustix::fs::fstat(&child).map_err(|_| Left::Refused)?;
            if (opened.st_dev, opened.st_ino) != (looked.st_dev, looked.st_ino) {
                return Err(Left::AnotherFileSystem);
            }
            // A directory moved out of the run since it was looked at is not the run's to empty.
            if !pin.contains(&child) {
                return Err(Left::MovedOut);
            }
            walk_for_removal(&child, device, pin, depth + 1, remove, before_unlink)?;
            if remove {
                before_unlink(name.to_bytes());
                if !pin.contains(directory) {
                    return Err(Left::MovedOut);
                }
                rustix::fs::unlinkat(directory, name.as_c_str(), AtFlags::REMOVEDIR)
                    .map_err(|_| Left::Refused)?;
            }
        } else if remove {
            before_unlink(name.to_bytes());
            // Checked just before the unlink: the directory this name is in may have been moved
            // out of the run since it was opened, and a name there is not the run's.
            if !pin.contains(directory) {
                return Err(Left::MovedOut);
            }
            rustix::fs::unlinkat(directory, name.as_c_str(), AtFlags::empty())
                .map_err(|_| Left::Refused)?;
        }
    }
    Ok(())
}

/// Removes the run's directory `root` and what is below it, and only that: the directory must be the
/// one `pin` names, and it is looked through once for an entry on another file system before
/// anything is removed. A volume mounted below the run, or a root that is not the directory the run
/// made, leaves the whole directory where it is, and the removal enters and removes nothing on
/// another device in any case; a directory that is moved out of the run is left, and nothing more is
/// unlinked through it. The root's own name is removed relative to its parent's handle, after a look
/// through that handle shows the name is still the pinned directory.
#[must_use]
pub fn remove_run_directory(root: &Path, pin: &RootPin) -> Removal {
    remove_run_directory_by(root, pin, &mut |_| {})
}

/// [`remove_run_directory`] with the moment before each unlink, told the name about to be unlinked
/// (the root's own name is told as an empty one), at which a test changes the tree.
fn remove_run_directory_by(
    root: &Path,
    pin: &RootPin,
    before_unlink: &mut dyn FnMut(&[u8]),
) -> Removal {
    let handle = match open_directory(root) {
        Ok(handle) => handle,
        Err(rustix::io::Errno::NOENT) => return Removal::Removed,
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
            return Removal::Left(Left::RootChanged);
        }
        Err(_) => return Removal::Left(Left::Refused),
    };
    if !pin.holds(&handle) {
        return Removal::Left(Left::RootChanged);
    }
    let Ok(stat) = rustix::fs::fstat(&handle) else {
        return Removal::Left(Left::Refused);
    };
    for remove in [false, true] {
        if let Err(left) = walk_for_removal(&handle, stat.st_dev, pin, 1, remove, before_unlink) {
            return Removal::Left(left);
        }
    }
    // The root's own name, relative to its parent's handle.
    let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
        return Removal::Left(Left::Refused);
    };
    let Ok(name) = std::ffi::CString::new(name.as_encoded_bytes()) else {
        return Removal::Left(Left::Refused);
    };
    let Ok(parent) = open_directory(parent) else {
        return Removal::Left(Left::Refused);
    };
    before_unlink(b"");
    match rustix::fs::statat(
        &parent,
        name.as_c_str(),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(looked)
            if i128::from(looked.st_dev) == pin.device
                && i128::from(looked.st_ino) == pin.inode => {}
        Ok(_) => return Removal::Left(Left::RootChanged),
        Err(rustix::io::Errno::NOENT) => return Removal::Removed,
        Err(_) => return Removal::Left(Left::Refused),
    }
    match rustix::fs::unlinkat(&parent, name.as_c_str(), rustix::fs::AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Removal::Removed,
        Err(_) => Removal::Left(Left::Refused),
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let passed = *self.passed.lock().unwrap_or_else(PoisonError::into_inner);
        if passed {
            // Inside the run: a volume mounted below it, or a root that is no longer the directory
            // this run made, leaves the directory where it is.
            if let Removal::Left(why) = remove_run_directory(&self.root, &self.pin) {
                eprintln!("the {} leg's directory is left in place: {why}", self.leg);
            }
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

/// The file `pid` runs, where it is one of the system's own programs running as another user: a
/// set-user-ID program a person's tools start, such as `/bin/ps` or `/usr/bin/top`. The kernel
/// will not describe such a process to this user (`error`, from reading its identity, says
/// "Operation not permitted"), and it still says which file the process runs; that file lies in
/// one of the system's own directories on the volume mounted read-only at `/`, the sealed system
/// volume, and not under `/System/Volumes`, where the writable data volume is. Such a process is
/// neither a build under test nor anything a run started or can signal: it ends by itself, and a
/// caller still follows what it starts and checks that it has ended.
#[must_use]
pub fn system_program_of_another_user(pid: u32, error: &str) -> Option<PathBuf> {
    const SYSTEM: [&str; 6] = [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/System/",
    ];
    if !error.contains("errno = 1,") {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let path = PathBuf::from(libproc::proc_pid::pidpath(i32::try_from(pid).ok()?).ok()?);
        let text = path.display().to_string();
        let stat = rustix::fs::statfs(&path).ok()?;
        let mounted_on: Vec<u8> = stat
            .f_mntonname
            .iter()
            .take_while(|character| **character != 0)
            .map(|character| character.to_ne_bytes()[0])
            .collect();
        // MNT_RDONLY.
        let read_only = stat.f_flags & 1 != 0;
        (SYSTEM.iter().any(|prefix| text.starts_with(prefix))
            && !text.starts_with("/System/Volumes/")
            && mounted_on == b"/"
            && read_only)
            .then_some(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (pid, SYSTEM);
        None
    }
}

/// The path of the file the process `pid` runs, as the system says it (`proc_pidpath` on macOS, the
/// process's own link on Linux), and not as the process that started it named it: `None` where the
/// system will not say, as of a process of another account, or where the platform has no such
/// answer.
#[must_use]
pub fn executable_path(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(
            libproc::proc_pid::pidpath(i32::try_from(pid).ok()?).ok()?,
        ))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// Whether the process `pid`, a system program noted under [`Run::note_system_program`], may
/// still run: only the kernel's answer that it has no such process (`ESRCH`, to a question about
/// that one number) says it has ended. Any other answer, a process under that number whatever it
/// runs now among them, leaves it running, so nothing is taken to have ended without the kernel
/// saying so.
#[must_use]
pub fn system_program_may_run(pid: u32) -> bool {
    #[cfg(target_os = "macos")]
    {
        let Ok(number) = i32::try_from(pid) else {
            return true;
        };
        match libproc::proc_pid::pidpath(number) {
            Ok(_) => true,
            Err(message) => !message.contains("errno = 3,"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        true
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

/// Whether the process `identity` names is stopped, as a stop signal leaves it, read while that
/// start holds its number: `None` where it has ended or the kernel will not say.
#[must_use]
pub fn stopped(identity: &ProcessStartIdentity) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        // `SSTOP` in the kernel's process states.
        const STOPPED: u32 = 4;
        let pid = i32::try_from(identity.pid.get()).ok()?;
        if !matches!(process_state(identity), ProcessState::Running) {
            return None;
        }
        let info = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid, 0).ok()?;
        // The number still names the same start after the read, so what was read is its.
        if !matches!(process_state(identity), ProcessState::Running) {
            return None;
        }
        Some(info.pbi_status == STOPPED)
    }
    #[cfg(target_os = "linux")]
    {
        if !matches!(process_state(identity), ProcessState::Running) {
            return None;
        }
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", identity.pid.get())).ok()?;
        // The state follows the command's name, which is in parentheses and may hold any byte.
        let state = stat[stat.rfind(')')? + 1..].trim_start().chars().next()?;
        if !matches!(process_state(identity), ProcessState::Running) {
            return None;
        }
        Some(matches!(state, 'T' | 't'))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = identity;
        None
    }
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

/// The process group a process leads or belongs to, and the one its controlling terminal has in
/// the foreground.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Groups {
    /// The process group the process belongs to.
    pub group: i64,
    /// The process group in the foreground of the process's controlling terminal, or a value that
    /// is not a group (zero or negative) where it has none.
    pub foreground: i64,
}

/// The groups of the process `identity` names, read while that start holds its number, or `None`
/// once the kernel says it has ended.
///
/// # Errors
///
/// Returns why neither answer is established, as [`describe`] does.
pub fn groups(identity: &ProcessStartIdentity) -> Result<Option<Groups>, String> {
    let pid = identity.pid.get();
    let mut ps = std::process::Command::new("/bin/ps");
    ps.args(["-o", "pgid=,tpgid=", "-p", &pid.to_string()])
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
    let mut numbers = text.split_whitespace().map(str::parse::<i64>);
    match (numbers.next(), numbers.next()) {
        (Some(Ok(group)), Some(Ok(foreground))) => Ok(Some(Groups { group, foreground })),
        _ => Err(format!("ps named no groups for process {pid}: {text:?}")),
    }
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
/// most `OUTPUT_HANDOVER` for its output.
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn a_set_user_id_system_program_is_told_by_the_file_it_runs() {
        // `top` is set-user-ID root on macOS: the kernel will not describe it to its own user.
        let mut child = std::process::Command::new("/usr/bin/top")
            .args(["-l", "30", "-s", "1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("top starts");
        let started = Instant::now();
        let refused = loop {
            match query_process(child.id()) {
                ProcessQuery::CannotEstablish(error) => break Some(error.to_string()),
                _ if started.elapsed() < Duration::from_secs(5) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break None,
            }
        };
        let told = refused
            .as_deref()
            .and_then(|error| system_program_of_another_user(child.id(), error));
        let running_then = system_program_may_run(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            running_then,
            "a program still running is not taken to have ended"
        );
        assert!(
            !system_program_may_run(child.id()),
            "the kernel's list no longer names a program that has ended"
        );
        let error = refused.expect("the kernel refuses to describe a set-user-ID program");
        assert_eq!(told, Some(PathBuf::from("/usr/bin/top")), "{error}");
        assert_eq!(
            system_program_of_another_user(std::process::id(), "errno = 2, gone"),
            None,
            "only a refusal is taken for another user"
        );
    }
}

#[cfg(test)]
mod root_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!("kr-run-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&base).expect("a scratch directory");
        base
    }

    #[test]
    fn a_root_that_was_there_is_left_as_it_is_and_another_name_is_taken() {
        let base = scratch("root");
        // A directory of another run, owner-only, which a start that took it would remove.
        let taken = base.join("krm-aaaaaaaa");
        std::fs::create_dir(&taken).expect("a directory of another run");
        std::fs::write(taken.join("kept"), b"evidence").expect("a file in it");
        // A name taken by a link is taken too.
        std::os::unix::fs::symlink(&taken, base.join("krm-bbbbbbbb")).expect("a link");
        let mut names = ["aaaaaaaa", "bbbbbbbb", "cccccccc"]
            .into_iter()
            .map(str::to_owned);
        let (made, pin) =
            make_root(&base, &mut || names.next().expect("a name"), &mut |_| {}).expect("a root");
        assert_eq!(made, base.join("krm-cccccccc"));
        assert!(pin.holds(open_directory(&made).expect("it opens")));
        assert!(
            taken.join("kept").is_file(),
            "the other run's directory is untouched"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
    }

    /// A link, or a directory with something in it, put at the new name between its making and its
    /// opening is refused, and nothing is written into it or removed from it; a failed start removes
    /// nothing.
    #[test]
    fn a_link_or_a_full_directory_put_in_the_new_root_s_place_is_refused_and_nothing_is_removed() {
        let base = scratch("swap");
        let theirs = scratch("swap-theirs");
        std::fs::write(theirs.join("personal"), b"a file of the person's").expect("a file");
        let put_in_place = |place: &Path, with: &dyn Fn(&Path)| {
            let away = place.with_extension("away");
            std::fs::rename(place, &away).expect("the new directory moved away");
            with(place);
        };
        // A link to a directory of the person's.
        let why = make_root(&base, &mut || "dddddddd".to_owned(), &mut |place| {
            put_in_place(place, &|place| {
                std::os::unix::fs::symlink(&theirs, place).expect("a link");
            });
        })
        .expect_err("a link put in the new root's place");
        assert!(why.contains("a link or another entry"), "{why}");
        assert_eq!(std::fs::read_dir(&theirs).expect("theirs").count(), 1);
        assert!(theirs.join("personal").is_file());
        // A directory of the person's with a file in it, moved into the place.
        let full = base.join("full");
        std::fs::create_dir(&full).expect("a directory");
        std::fs::set_permissions(&full, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("owner-only");
        std::fs::write(full.join("personal"), b"a file of the person's").expect("a file");
        let why = make_root(&base, &mut || "eeeeeeee".to_owned(), &mut |place| {
            put_in_place(place, &|place| {
                std::fs::rename(&full, place).expect("moved in");
            });
        })
        .expect_err("a full directory put in the new root's place");
        assert!(why.contains("not empty"), "{why}");
        assert!(base.join("krm-eeeeeeee/personal").is_file());
        std::fs::remove_dir_all(&base).expect("clean up");
        std::fs::remove_dir_all(&theirs).expect("clean up");
    }

    /// A volume mounted on the new name between its making and its opening is refused, and nothing
    /// is written into it or removed from it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_volume_mounted_on_the_new_root_is_refused_and_nothing_on_it_is_touched() {
        use kr_ipc::testing::volumes::{Volume, not_attachable};
        let base = scratch("mount");
        let images = scratch("mount-images");
        let mut volume = None;
        let mut before = 0;
        let why = make_root(&base, &mut || "ffffffff".to_owned(), &mut |place| {
            let attached =
                Volume::attach(place, &images, "root").unwrap_or_else(|| not_attachable());
            std::fs::write(place.join("theirs"), b"a file of the person's").expect("a file");
            before = std::fs::read_dir(place).expect("the volume").count();
            volume = Some(attached);
        })
        .expect_err("a volume mounted on the new root");
        let there = base.join("krm-ffffffff/theirs").is_file();
        let entries = std::fs::read_dir(base.join("krm-ffffffff"))
            .expect("the volume")
            .count();
        volume.expect("it was attached").detach();
        assert!(why.contains("another file system"), "{why}");
        assert!(
            there && entries == before,
            "nothing was written or removed on the volume"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
        std::fs::remove_dir_all(&images).expect("clean up");
    }

    /// A file below the run is opened only as a regular file of the run with one name: a link at the
    /// file or on the way, a second name, a directory where a file is named, a run's directory that
    /// is not the one the run made, and a directory moved out of the run on the way are each a class
    /// and nothing is read; a file that is not there is none.
    #[test]
    fn a_file_below_the_run_is_opened_only_as_a_regular_file_of_the_run_with_one_name() {
        let base = scratch("below");
        let theirs = scratch("below-theirs");
        std::fs::write(theirs.join("personal"), b"a file of the person's").expect("a file");
        let root = base.join("run");
        std::fs::create_dir_all(root.join("a/b")).expect("a run");
        std::fs::write(root.join("a/b/file"), b"the run's own file").expect("a file");
        let pin = RootPin::of(&root).expect("a pin");
        let read = |relative: &str| {
            read_tail_below(&root, &pin, Path::new(relative), 0)
                .map(|bytes| bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
        };
        assert_eq!(read("a/b/file"), Ok(Some("the run's own file".to_owned())));
        assert_eq!(read("a/b/absent"), Ok(None));
        assert_eq!(read("a/absent/file"), Ok(None));
        // A link at the file.
        std::os::unix::fs::symlink(theirs.join("personal"), root.join("a/b/link")).expect("a link");
        assert_eq!(read("a/b/link"), Err(Refusal::Link));
        // A link on the way.
        std::os::unix::fs::symlink(&theirs, root.join("a/way")).expect("a link");
        assert_eq!(read("a/way/personal"), Err(Refusal::Link));
        // A second name for a file of the person's.
        std::fs::hard_link(theirs.join("personal"), root.join("a/b/second")).expect("a hard link");
        assert_eq!(read("a/b/second"), Err(Refusal::SecondName));
        // A directory where a file is named, and a file where a directory is.
        assert_eq!(read("a/b"), Err(Refusal::NotAFile));
        assert_eq!(read("a/b/file/deeper"), Err(Refusal::NotAFile));
        assert_eq!(read("../run/a/b/file"), Err(Refusal::NotAFile));
        // A directory moved out of the run once it is open, with the file below it still read
        // through its handle.
        let moved_to = base.join("moved");
        std::fs::create_dir(&moved_to).expect("a directory");
        let mut moved = false;
        let opened = open_file_below_by(&root, &pin, Path::new("a/b/file"), &mut |name| {
            if name == b"b" && !moved {
                moved = true;
                std::fs::rename(root.join("a"), moved_to.join("a")).expect("moved out");
            }
        });
        assert!(moved);
        assert_eq!(opened.err(), Some(Refusal::Moved));
        std::fs::rename(moved_to.join("a"), root.join("a")).expect("moved back");
        // The run's directory renamed away and another directory with the same file put at its path.
        std::fs::rename(&root, base.join("away")).expect("renamed away");
        std::fs::create_dir_all(root.join("a/b")).expect("another directory");
        std::fs::write(root.join("a/b/file"), b"another directory's file").expect("a file");
        assert_eq!(read("a/b/file"), Err(Refusal::RootChanged));
        // The run's directory made a link.
        std::fs::remove_dir_all(&root).expect("clean up");
        std::os::unix::fs::symlink(base.join("away"), &root).expect("a link at the root");
        assert_eq!(read("a/b/file"), Err(Refusal::RootChanged));
        assert_eq!(
            std::fs::read(theirs.join("personal")).expect("theirs"),
            b"a file of the person's"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
        std::fs::remove_dir_all(&theirs).expect("clean up");
    }

    /// A volume mounted below the run is another file system: a file on it is refused.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_file_on_a_volume_mounted_below_the_run_is_refused() {
        use kr_ipc::testing::volumes::{Volume, not_attachable};
        let base = scratch("below-mount");
        let images = scratch("below-mount-images");
        let root = base.join("run");
        std::fs::create_dir_all(root.join("mnt")).expect("a run");
        let pin = RootPin::of(&root).expect("a pin");
        let volume =
            Volume::attach(&root.join("mnt"), &images, "below").unwrap_or_else(|| not_attachable());
        std::fs::write(root.join("mnt/theirs"), b"a file on the volume").expect("a file");
        let through = read_tail_below(&root, &pin, Path::new("mnt/theirs"), 0);
        let at_the_point = read_tail_below(&root, &pin, Path::new("mnt"), 0);
        volume.detach();
        assert_eq!(through, Err(Refusal::OtherDevice));
        assert_eq!(at_the_point, Err(Refusal::OtherDevice));
        std::fs::remove_dir_all(&base).expect("clean up");
        std::fs::remove_dir_all(&images).expect("clean up");
    }

    /// A directory moved out of the run between the first pass and the second, with a file put under
    /// an entry's name, is not emptied; and the root's own name is not removed when it is another
    /// directory by then.
    #[test]
    fn a_directory_moved_out_during_the_removal_is_left_and_so_is_a_directory_put_at_the_root() {
        let base = scratch("removal");
        let elsewhere = scratch("removal-elsewhere");
        let root = base.join("krm-gggggggg");
        let run = |root: &Path| {
            std::fs::create_dir_all(root.join("a/inner")).expect("a run");
            std::fs::write(root.join("a/inner/x"), b"the run's own file").expect("a file");
            std::fs::write(root.join("a/y"), b"the run's own file").expect("a file");
            RootPin::of(root).expect("a pin")
        };
        // The directory `inner` is moved out and a file of the person's is put under the name `x`.
        let pin = run(&root);
        let mut moved = false;
        let removal = remove_run_directory_by(&root, &pin, &mut |name| {
            if name == b"x" && !moved {
                moved = true;
                std::fs::rename(root.join("a/inner"), elsewhere.join("inner")).expect("moved out");
                std::fs::remove_file(elsewhere.join("inner/x")).expect("the run's own file");
                std::fs::write(elsewhere.join("inner/x"), b"a file of the person's")
                    .expect("a file put under the name");
            }
        });
        assert!(moved);
        assert_eq!(removal, Removal::Left(Left::MovedOut));
        assert!(
            elsewhere.join("inner/x").is_file(),
            "the file put under the name is still there"
        );
        // The same for the name of an emptied directory in a directory that was moved out before its
        // unlink: an empty directory of the person's put under that name is still there.
        std::fs::remove_dir_all(&root).expect("clean up");
        std::fs::remove_dir_all(elsewhere.join("inner")).expect("clean up");
        let pin = run(&root);
        let mut moved = false;
        let removal = remove_run_directory_by(&root, &pin, &mut |name| {
            if name == b"inner" && !moved {
                moved = true;
                std::fs::rename(root.join("a"), elsewhere.join("a")).expect("moved out");
                std::fs::remove_dir(elsewhere.join("a/inner")).expect("the emptied directory");
                std::fs::create_dir(elsewhere.join("a/inner")).expect("another empty directory");
            }
        });
        assert!(moved);
        assert_eq!(removal, Removal::Left(Left::MovedOut));
        assert!(
            elsewhere.join("a/inner").is_dir(),
            "the directory put under the name is still there"
        );
        std::fs::remove_dir_all(&root).expect("clean up");
        // The root is renamed away after the walk, and an empty directory is put at its path.
        let pin = run(&root);
        let mut swapped = false;
        let removal = remove_run_directory_by(&root, &pin, &mut |name| {
            if name.is_empty() && !swapped {
                swapped = true;
                std::fs::rename(&root, base.join("away")).expect("renamed away");
                std::fs::create_dir(&root).expect("another directory at the path");
            }
        });
        assert!(swapped);
        assert_eq!(removal, Removal::Left(Left::RootChanged));
        assert!(
            root.is_dir(),
            "the directory put at the root's path is still there"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
        std::fs::remove_dir_all(&elsewhere).expect("clean up");
    }
}
