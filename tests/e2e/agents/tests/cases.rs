//! The parts of the qualification cases a host shows on an agent's terminal route.
//!
//! Each test is one part, runs on a stage of its own (its own directory on the internal disk, its
//! own host, its own owner device with fresh keys, the agent's package installed on that device's
//! confirmation) and starts the agent the way a person does, by typing its command at the prompt
//! of a managed shell. It checks the part's property, then runs a control that breaks the property
//! on purpose, and the same check must then fail, so a check that could not fail is not reported as
//! one that passed. Each test closes what it opened, requires the closing check to find nothing
//! left, and only then appends its outcome to the result file. The parts that need no login (2b,
//! 2c, 5a, 6a, 8a and 14.03a) are the gateway target's `staged_a` module.
//!
//! The parts drive terminals, process identities and signals the way a Unix host has them, so the
//! suite is built for Unix hosts alone.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_e2e_agents::account::{AppendOnly, Guarded, appended_since, guarded_files, read_if_there};
use kr_e2e_agents::build::{InstallSwitch, read_build};
use kr_e2e_agents::confine::{self};
use kr_e2e_agents::held::{
    ISOLATION_UNPROVEN, KEY_SEARCHES, holds_a_key, kept_clear, recorded_text, unsearchable_count,
};
use kr_e2e_agents::keys;
use kr_e2e_agents::outcome::Outcome;
use kr_e2e_agents::provenance::{ENVIRONMENT_NOT_CLEAR, beneath_parent, exported_clear};
use kr_e2e_agents::stage::{
    closed_port, default_keychain_of_a_session, names_a_session_exports, prepare_home,
    session_variables,
};
use kr_e2e_agents::{BUILD_VARIABLE, REQUIRE_VARIABLE, RESULT_VARIABLE};
use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::host::{Host, HostOptions};
use kr_e2e_m1b::run::{Run, signal};
use kr_e2e_m1b::shells::{self};
use kr_ipc::identity::{ProcessState, process_state};
use kr_protocol::identity::ProcessStartIdentity;
use serde_json::json;

/// How a part says its agent's login could not be established: its status command did not report
/// it, the agent did not reach its composer with it, or the agent showed that it is signed out. A
/// part that says so stops its agent.
const LOGIN_UNPROVEN: &str = "the agent's login is not established:";

/// What a guard says of a look at the login's files that failed: whether the files held a string
/// the search cannot be run for, or could not be read, what they held then is not known, and no
/// further prompt may be submitted on it.
const LOGIN_LOOK_FAILED: &str =
    "a look at the login's files failed while the part ran, so what they held is not known";

/// The stop a failed look makes, where one failed.
fn failed_look(failed: &std::sync::atomic::AtomicBool) -> Option<String> {
    failed
        .load(std::sync::atomic::Ordering::SeqCst)
        .then(|| LOGIN_LOOK_FAILED.to_owned())
}

/// What a guard says of a subagent's start, which the part's turn ledger cannot count.
const SUBAGENT_STARTED: &str = "a subagent started:";

/// What a guard says of a prompt in the agent's record that no person typed, whose request to the
/// model the part's turns do not include.
const UNCHARGED_PROMPT: &str = "a prompt that no person typed is in the agent's record:";

/// What a guard says of a process beneath the agent that the isolation was to prevent.
const TREE_BROKEN: &str = "a process beneath the agent broke its isolation:";

/// The class a guard's text stops the agent for.
fn guard_class(what: &str) -> &'static str {
    if what.contains(SUBAGENT_STARTED) {
        "subagent_started"
    } else if what.contains(UNCHARGED_PROMPT) {
        "uncharged_turns"
    } else if what.contains(TREE_BROKEN) {
        "isolation_not_established"
    } else if what.contains(LOGIN_LOOK_FAILED) {
        "secret_found"
    } else {
        "guarded_file_changed"
    }
}

/// The person's files a part watches while it runs, as it found them before it started.
struct Guards {
    home: PathBuf,
    /// Every file watched, relative to the home: those no part may change, those the person's
    /// own programs also write, and those whose change is only recorded.
    files: Vec<String>,
    before: Vec<Guarded>,
    guarded: Vec<String>,
    shared: Vec<String>,
    /// The files the agent and the person's other programs only append lines to, as the part found
    /// them: a line that was there changing or going is a change the part stops on.
    append_only: Vec<AppendOnly>,
    /// The list of workspaces the agent keeps in the person's data directory, as the part found it:
    /// it may only gain the run's own folder.
    workspaces: Option<Workspaces>,
    /// The run's directory of sessions in the person's data directory, where a subagent's start
    /// stops the part: its requests to the model are not turns the ledger counts.
    subagents: Option<PathBuf>,
    /// Whether a look at the login's files failed while the part ran, so the strings they held at
    /// that moment are not known.
    login_look_failed: std::sync::atomic::AtomicBool,
    /// The person's data directory, where the login's files are read again at each look, and every
    /// string they held at any look: the agent may refresh its token more than once while it runs.
    login_data: Option<PathBuf>,
    login_seen: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// When the files were last read.
    read_at: std::sync::Mutex<Option<std::time::Instant>>,
}

/// The person's list of workspaces as a part found it, and the folder it may gain.
struct Workspaces {
    /// The list's file, relative to the person's home.
    relative: String,
    /// Its bytes before the part.
    before: String,
    /// The run's folder, as the agent names it.
    folder: PathBuf,
}

/// The probes a part runs, each by its process group, whose leader stays unreaped while it is
/// listed, and whether a change has stopped the part.
#[derive(Default)]
struct Registry {
    tripped: bool,
    probes: Vec<i32>,
}

impl Guards {
    /// What changed since the part started, where anything did: a look at the login's files that
    /// failed, a file of the person's that no part may change, one the person's own programs also
    /// write that now holds `needles` (the part's mark or the run's directory), a line that was
    /// there in a file only appended to, or a file that cannot be read.
    fn change(&self, needles: &[&str]) -> Option<String> {
        if let Some(why) = failed_look(&self.login_look_failed) {
            return Some(why);
        }
        let now = match guarded_files(&self.home, &self.files, needles) {
            Ok(now) => now,
            Err(why) => return Some(why),
        };
        let lines = self
            .append_only
            .iter()
            .map(|file| {
                read_if_there(&self.home.join(&file.relative))
                    .map(|now| appended_since(file.before.as_deref(), now.as_deref()).is_some())
                    .map_err(|error| format!("~/{}: {error}", file.relative))
            })
            .collect::<Result<Vec<bool>, String>>();
        if let Ok(mut read_at) = self.read_at.lock() {
            *read_at = Some(std::time::Instant::now());
        }
        let intact = match lines {
            Ok(intact) => intact,
            Err(why) => return Some(why),
        };
        if let Some((file, _)) = self
            .append_only
            .iter()
            .zip(&intact)
            .find(|(_, intact)| !**intact)
        {
            return Some(format!(
                "~/{}: a line that was there before the part changed or went while it ran",
                file.relative
            ));
        }
        if let Some(workspaces) = &self.workspaces {
            let path = self.home.join(&workspaces.relative);
            match read_if_there(&path) {
                Ok(Some(bytes)) => {
                    let verdict = String::from_utf8(bytes)
                        .map_err(|_| "the list is not text".to_owned())
                        .and_then(|now| {
                            confine::workspaces_verdict(
                                &workspaces.before,
                                &now,
                                &workspaces.folder,
                            )
                        });
                    if let Err(why) = verdict {
                        return Some(format!(
                            "~/{}: it changed other than by gaining the run's folder: {why}",
                            workspaces.relative
                        ));
                    }
                }
                Ok(None) => {
                    return Some(format!("~/{} went while the part ran", workspaces.relative));
                }
                Err(error) => return Some(format!("~/{}: {error}", workspaces.relative)),
            }
        }
        if let Some(why) = self
            .subagents
            .as_deref()
            .and_then(confine::subagent_started)
        {
            return Some(format!("{SUBAGENT_STARTED} {why}"));
        }
        if let Some(bucket) = self.subagents.as_deref()
            && let Ok(prompts) = confine::wire_prompts(bucket)
            && prompts.other > 0
        {
            return Some(format!(
                "{UNCHARGED_PROMPT} {} of another origin than a person's",
                prompts.other
            ));
        }
        self.before.iter().zip(&now).find_map(|(first, second)| {
            let changed = first.sha256 != second.sha256;
            if changed && self.guarded.contains(&first.relative) {
                Some(format!("~/{} changed while the part ran", first.relative))
            } else if changed && second.holds && self.shared.contains(&first.relative) {
                Some(format!(
                    "~/{} changed to hold the part's mark or the run's directory",
                    first.relative
                ))
            } else {
                None
            }
        })
    }

    /// Reads the login's files again and keeps every string they hold that a search can be run for.
    /// A look that cannot read them, or that finds a string a search cannot be run for, has failed,
    /// and the part stops on it; what else the look found is kept all the same.
    fn look_at_login(&self) {
        let Some(data) = &self.login_data else {
            return;
        };
        let fail = || {
            self.login_look_failed
                .store(true, std::sync::atomic::Ordering::SeqCst);
        };
        match confine::login_strings_read(data) {
            Ok(strings) => {
                let (strings, refused) = confine::split_searchable(strings);
                match self.login_seen.lock() {
                    Ok(mut seen) => seen.extend(strings),
                    Err(_) => fail(),
                }
                if refused {
                    fail();
                }
            }
            Err(_) => fail(),
        }
    }
}

/// What [`freeze`] stopped: each process confirmed stopped, each it signalled but could not confirm
/// stopped, why any process could not be looked at or stopped, and whether its walk was complete.
#[derive(Debug, Default)]
struct Frozen {
    stopped: Vec<ProcessStartIdentity>,
    unconfirmed: Vec<ProcessStartIdentity>,
    /// Processes whose state the kernel would not give, kept for the checks after the kill.
    unknown: Vec<ProcessStartIdentity>,
    failures: Vec<String>,
    complete: bool,
}

/// Stops the process `identity` names, only while that start holds its number, and says whether the
/// kernel then reports it stopped within a fifth of a second: `Ok(None)` where it had ended.
///
/// # Errors
///
/// Where the kernel will not say whether it runs, or the stop cannot be sent.
fn stop_one(identity: &ProcessStartIdentity) -> Result<Option<bool>, String> {
    match process_state(identity) {
        ProcessState::Running => {}
        ProcessState::Ended => return Ok(None),
        ProcessState::Unknown { detail } => {
            return Err(format!(
                "whether process {} runs is not established: {detail}",
                identity.pid.get()
            ));
        }
    }
    let pid = i32::try_from(identity.pid.get())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .ok_or_else(|| format!("process {} has no number to signal", identity.pid.get()))?;
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).map_err(|error| {
        format!(
            "process {} could not be stopped: {error}",
            identity.pid.get()
        )
    })?;
    let started = std::time::Instant::now();
    loop {
        match kr_e2e_m1b::run::stopped(identity) {
            Some(true) => return Ok(Some(true)),
            None if matches!(process_state(identity), ProcessState::Ended) => return Ok(None),
            _ if started.elapsed() >= Duration::from_millis(200) => return Ok(Some(false)),
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Stops each of `roots` that runs and, pass by pass, every process beneath one it stopped, each the
/// moment it is found and confirmed a child of that process under its own start identity, so none
/// can start another or leave its children to the system while the set is gathered; a pass reads
/// the process table once, and passes go on until one finds nothing new, at most fifty. A process
/// found by its number but not confirmed beneath its parent, one that could not be stopped or
/// looked at, a table that could not be read, and a walk the passes did not finish are each
/// recorded, and the last three leave the walk incomplete.
fn freeze(roots: &[ProcessStartIdentity]) -> Frozen {
    let mut frozen = Frozen {
        complete: true,
        ..Frozen::default()
    };
    let take = |frozen: &mut Frozen, identity: ProcessStartIdentity| -> bool {
        match stop_one(&identity) {
            Ok(Some(true)) => {
                frozen.stopped.push(identity);
                true
            }
            Ok(Some(false)) => {
                frozen.failures.push(format!(
                    "process {} was signalled and not seen stopped",
                    identity.pid.get()
                ));
                frozen.unconfirmed.push(identity);
                true
            }
            Ok(None) => false,
            Err(why) => {
                frozen.failures.push(why);
                frozen.complete = false;
                frozen.unknown.push(identity);
                false
            }
        }
    };
    for root in roots {
        let known = frozen.stopped.contains(root)
            || frozen.unconfirmed.contains(root)
            || frozen.unknown.contains(root);
        if !known {
            let _ = take(&mut frozen, root.clone());
        }
    }
    for _ in 0..50 {
        let table = match kr_e2e_m1b::run::process_table() {
            Ok(table) => table,
            Err(why) => {
                frozen.failures.push(why);
                frozen.complete = false;
                return frozen;
            }
        };
        let parents: Vec<ProcessStartIdentity> = frozen
            .stopped
            .iter()
            .chain(&frozen.unconfirmed)
            .cloned()
            .collect();
        let mut found = false;
        for parent in &parents {
            let Ok(parent_pid) = u32::try_from(parent.pid.get()) else {
                continue;
            };
            for entry in table.iter().filter(|entry| entry.parent == parent_pid) {
                let identity = match kr_ipc::identity::query_process(entry.pid) {
                    kr_ipc::identity::ProcessQuery::Present(identity) => identity,
                    kr_ipc::identity::ProcessQuery::Gone => continue,
                    kr_ipc::identity::ProcessQuery::CannotEstablish(error) => {
                        frozen.failures.push(format!(
                            "process {} beneath process {parent_pid} could not be identified: \
                             {error}",
                            entry.pid
                        ));
                        frozen.complete = false;
                        continue;
                    }
                };
                if frozen.stopped.contains(&identity)
                    || frozen.unconfirmed.contains(&identity)
                    || frozen.unknown.contains(&identity)
                {
                    continue;
                }
                match beneath_parent(&identity, parent) {
                    Ok(true) => found |= take(&mut frozen, identity),
                    Ok(false) => {}
                    Err(why) => {
                        frozen.failures.push(why);
                        frozen.complete = false;
                    }
                }
            }
        }
        if !found {
            return frozen;
        }
    }
    frozen
        .failures
        .push("fifty passes still found new processes".to_owned());
    frozen.complete = false;
    frozen
}

/// What `ps` says: the processes whose name, in either column of the process table (the program's
/// own name and the title it gave itself), is one of `names`, and each process's parent. The agent
/// renames itself, so the program's name alone would miss it.
struct ProcessView {
    named: Vec<u32>,
    parents: std::collections::BTreeMap<u32, u32>,
}

/// Reads the process table.
///
/// # Errors
///
/// Returns why the process list could not be read: the answer is then not "none".
fn process_view(names: &[String]) -> Result<ProcessView, String> {
    let listing = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid=,ucomm=,comm="])
        .output()
        .map_err(|error| format!("the process list cannot be read: {error}"))?;
    if !listing.status.success() {
        return Err(format!(
            "the process list cannot be read: ps exited {}",
            listing.status
        ));
    }
    Ok(view_of(&String::from_utf8_lossy(&listing.stdout), names))
}

/// The view of `listing`, the lines of `ps -axo pid=,ppid=,ucomm=,comm=`.
fn view_of(listing: &str, names: &[String]) -> ProcessView {
    let mut view = ProcessView {
        named: Vec::new(),
        parents: std::collections::BTreeMap::new(),
    };
    for line in listing.lines() {
        let mut words = line.split_whitespace();
        let (Some(pid), Some(parent)) = (
            words.next().and_then(|word| word.parse::<u32>().ok()),
            words.next().and_then(|word| word.parse::<u32>().ok()),
        ) else {
            continue;
        };
        view.parents.insert(pid, parent);
        if words.any(|word| {
            names
                .iter()
                .any(|name| word == name || word.rsplit('/').next() == Some(name.as_str()))
        }) {
            view.named.push(pid);
        }
    }
    view
}

/// The numbers of the processes of the agent's names.
///
/// # Errors
///
/// Returns why the process list could not be read.
fn agent_processes(names: &[String]) -> Result<Vec<u32>, String> {
    process_view(names).map(|view| view.named)
}

fn outside_of(view: &ProcessView, roots: &[u32]) -> Vec<u32> {
    view.named
        .iter()
        .copied()
        .filter(|pid| {
            let mut at = *pid;
            // A chain is at most as long as the table; a loop is not the part's.
            for _ in 0..=view.parents.len() {
                if roots.contains(&at) {
                    return false;
                }
                match view.parents.get(&at) {
                    Some(parent) if *parent != at && *parent != 0 => at = *parent,
                    _ => return true,
                }
            }
            true
        })
        .collect()
}

/// What the part records of a dialog it refused: why, which dialog, with which key, and the rows the
/// screen showed then, without its blank rows.
///
/// The screen is left out where it holds a piece of a key the part holds (`secrets`: see
/// [`holds_a_key`]): what a part's log keeps is searched for exact values, which a key cut in two
/// would escape.
fn refusal_note(why: &str, shown: &str, key: &str, rows: &[String], secrets: &[&str]) -> String {
    let screen: Vec<&str> = rows
        .iter()
        .map(String::as_str)
        .filter(|row| !row.trim().is_empty())
        .collect();
    let said = if holds_a_key(&screen, secrets) {
        "the screen holds a key, so it is not noted".to_owned()
    } else {
        format!("the screen:\n{}", screen.join("\n"))
    };
    format!("{why}: a dialog showing {shown:?}, refused with {key:?}; {said}")
}

/// The files under a part's conversation roots, each with its length, modification time and
/// inode, as the part found them before its agent started.
type Inventory = std::collections::HashMap<PathBuf, FileState>;

/// A file's length, modification time and inode, where its metadata could be read.
type FileState = (u64, Option<std::time::SystemTime>, u64);

/// A file's [`FileState`] now.
fn file_state(path: &Path) -> Option<FileState> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.len(), metadata.modified().ok(), metadata.ino()))
}

/// The files under `roots` now, each with its [`FileState`]; a file whose metadata cannot be read
/// is left out, so it is read at every search.
fn inventory(roots: &[PathBuf]) -> Inventory {
    let mut found = Inventory::new();
    let mut pending = roots.to_vec();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                pending.extend(entries.flatten().map(|entry| entry.path()));
            }
            continue;
        }
        if let Some(state) = file_state(&path) {
            found.insert(path, state);
        }
    }
    found
}

/// What kind of keychain `named`, a path `security default-keychain` printed, possibly quoted, is,
/// said without its name, which can be the person's own: their login keychain, another in their
/// home, one in the run's home, another, or none.
fn keychain_kind(named: &str, home: &Path, run_home: Option<&Path>) -> &'static str {
    let path = Path::new(named.trim().trim_matches('"'));
    if path.as_os_str().is_empty() {
        "none"
    } else if path
        == home
            .join("Library")
            .join("Keychains")
            .join("login.keychain-db")
    {
        "the person's login keychain"
    } else if path.starts_with(home) {
        "another keychain in the person's home"
    } else if run_home.is_some_and(|run_home| path.starts_with(run_home)) {
        "a keychain in the run's home"
    } else {
        "another keychain"
    }
}

/// [`probe_output`] with the registry it lists the probe in, where there is one.
fn grouped_output(
    mut command: std::process::Command,
    listing: Option<&std::sync::Mutex<Registry>>,
) -> Result<std::process::Output, String> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    command
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start: {error}"))?;
    let group = i32::try_from(child.id()).map_err(|_| "a process number too large".to_owned())?;
    let pid = rustix::process::Pid::from_raw(group).ok_or("a process number of zero")?;
    let end_group = || {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    };
    // Listed, or, after a change, ended at once and refused.
    let tripped = listing.is_some_and(|registry| {
        let mut registry = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registry.tripped {
            true
        } else {
            registry.probes.push(group);
            false
        }
    });
    if tripped {
        end_group();
        let _ = child.wait();
        return Err("a file of the person's changed before it could run".to_owned());
    }
    let read = |pipe: Option<Box<dyn Read + Send>>| {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            let _ = sent.send(bytes);
        });
        received
    };
    let stdout = read(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    );
    let stderr = read(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    );
    let started = std::time::Instant::now();
    let ended = loop {
        // Whether the leader has ended, read without reaping it, so its number stays its own.
        let exited = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        );
        match exited {
            Ok(Some(_)) => break Ok(()),
            Ok(None) if started.elapsed() < LIVENESS => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => break Err(format!("it did not finish within {LIVENESS:?}")),
            Err(error) => break Err(format!("it could not be waited for: {error}")),
        }
    };
    // The group goes whole while its leader is unreaped, and comes off the list under the same
    // lock a stop takes; only then is the leader reaped.
    {
        let registry = listing.map(|registry| {
            registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        end_group();
        if let Some(mut registry) = registry {
            registry.probes.retain(|listed| *listed != group);
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("it could not be reaped: {error}"))?;
    ended?;
    let handover = std::time::Instant::now() + Duration::from_secs(5);
    let collect = |received: std::sync::mpsc::Receiver<Vec<u8>>| {
        received
            .recv_timeout(handover.saturating_duration_since(std::time::Instant::now()))
            .map_err(|_| "it ended and its output stayed open past five seconds".to_owned())
    };
    Ok(std::process::Output {
        status,
        stdout: collect(stdout)?,
        stderr: collect(stderr)?,
    })
}

/// A random number below `bound`, from the system's random source.
fn random_below(bound: u64) -> u64 {
    let bytes = *kr_ipc::new_uuid().as_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes")) % bound
}

/// A marker only this part's text holds: `kr` and twelve hexadecimal digits.
fn nonce() -> String {
    format!("kr{:012x}", random_below(1 << 48))
}

/// The lines of the files under `roots` that hold both `needle` and `marker`, by file. A file whose
/// length, modification time and inode are still those `before` found before the agent started is
/// taken to hold nothing of the part and is not read: an agent's directory of the day can hold
/// hundreds of megabytes of the person's own conversations, and reading them all at every look
/// would take seconds. That rests on the agents writing a conversation as a new file or appending
/// to one, either of which changes its length or time; a rewrite of the same length that kept the
/// old time and inode would go unread. Every other file is read, whatever its time.
fn conversation_lines(
    roots: &[PathBuf],
    needle: &str,
    marker: &str,
    before: &Inventory,
) -> Vec<(PathBuf, usize)> {
    let mut found = Vec::new();
    let mut pending = roots.to_vec();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                pending.extend(entries.flatten().map(|entry| entry.path()));
            }
            continue;
        }
        if before
            .get(&path)
            .is_some_and(|earlier| file_state(&path).as_ref() == Some(earlier))
        {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let count = String::from_utf8_lossy(&bytes)
            .lines()
            .filter(|line| line.contains(needle) && line.contains(marker))
            .count();
        if count > 0 {
            found.push((path, count));
        }
    }
    found.sort();
    found
}

/// The screens `read` gives, read again until a row shows `shown`, and the last of them. An agent
/// draws what was typed into it a moment after it takes it, so a screen read at once can lack it:
/// after `reads` reads without it, what the last shows is what the agent shows.
fn screen_until_shown(
    mut read: impl FnMut() -> Vec<String>,
    shown: &str,
    reads: usize,
    pause: impl Fn(),
) -> Vec<String> {
    let mut rows = read();
    for _ in 1..reads {
        if rows.iter().any(|row| row.contains(shown)) {
            break;
        }
        pause();
        rows = read();
    }
    rows
}

/// The longest whitespace-separated word of `text`, without the punctuation at its ends (an agent
/// can drop a question mark or redraw a bracket), the first of them where several are as long.
fn longest_word(text: &str) -> &str {
    text.split_whitespace()
        .map(|word| word.trim_matches(|character: char| !character.is_alphanumeric()))
        .fold("", |longest, word| {
            if word.len() > longest.len() {
                word
            } else {
                longest
            }
        })
}

/// Whether the screen `rows` shows the prompt `text` typed into a composer: its longest word is on
/// some row. A prompt with no words is shown.
fn typed_text_shows(rows: &[String], text: &str) -> bool {
    let word = longest_word(text);
    word.is_empty() || rows.iter().any(|row| row.contains(word))
}

/// The markers of the part's two commands, the approved one and the control's, each `kr` and six
/// hexadecimal digits of the part's mark: the last six and the first six after its `kr`. They are
/// as long as each other, so the control's command fits the agent's dialog where the first does.
///
/// # Panics
///
/// Panics when the two are the same, which would let one command's marker stand for the other's.
fn approval_markers(mark: &str) -> (String, String) {
    let first = format!("kr{}", &mark[mark.len() - 6..]);
    let second = format!("kr{}", &mark[2..8]);
    assert_ne!(first, second, "the part's two markers are the same");
    (first, second)
}

/// The question session B asks of the conversation it resumed, and its words before the question
/// mark, by which the conversation is searched for it.
const RESUMED_QUESTION: &str =
    "What code did I ask you to remember? Reply with only the code, in upper case.";
const RESUMED_QUESTION_WORDS: &str = "What code did I ask you to remember";

/// Whether what a failed probe wrote to its error output is the agent's database being locked at its
/// start and nothing else: its lines, without colour codes, are the agent's "Unexpected error" line
/// and the lock's own, and the lock's is there.
fn lock_failure(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    let mut plain = String::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            plain.push(character);
            continue;
        }
        // Only a whole colour sequence is skipped: `ESC [`, digits and semicolons, `m`. Any other
        // escape, or one that does not end, is not the agent's colouring and refuses the output.
        if characters.next() != Some('[') {
            return false;
        }
        loop {
            match characters.next() {
                Some(next) if next.is_ascii_digit() || next == ';' => {}
                Some('m') => break,
                _ => return false,
            }
        }
    }
    let lines: Vec<&str> = plain
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    lines.contains(&"database is locked")
        && lines
            .iter()
            .all(|line| matches!(*line, "database is locked" | "Error: Unexpected error"))
}

/// Starts a probe with `start` and, while it ends in a failure that is the agent's database being
/// locked and nothing else (no output, an error output that is the lock alone), starts it again, up
/// to `times` starts in all, `wait` apart; returns the last start's output. Any other end is
/// returned at once.
fn started_again(
    times: usize,
    wait: Duration,
    mut start: impl FnMut() -> Result<std::process::Output, String>,
) -> Result<std::process::Output, String> {
    let mut output = start()?;
    for _ in 1..times {
        // Only a start that said nothing but the lock: what a failed start wrote to its output is
        // evidence a later, clean start must not replace.
        if output.status.success() || !output.stdout.is_empty() || !lock_failure(&output.stderr) {
            break;
        }
        eprintln!("a probe is started again: the agent's database was locked at its start");
        std::thread::sleep(wait);
        output = start()?;
    }
    Ok(output)
}

/// The prompt of the long turn an interrupt stops and what the screen shows while the reply runs: the
/// agent's own reply mark where it has one, else the part's code in upper case, which the reply is
/// asked to write at the start of every line.
fn long_turn(mark: &str, reply_mark: Option<&str>) -> (String, String) {
    match reply_mark {
        Some(reply_mark) => (
            format!(
                "Without using any tool or file, count from 1 to 400 in your reply, one number per \
                 line, and write nothing else. ({mark}-i)"
            ),
            reply_mark.to_owned(),
        ),
        None => (
            format!(
                "Without using any tool or file, write the code {mark} in upper case at the start \
                 of every line of your reply, then a space and the number, count from 1 to 400, one \
                 number per line, and write nothing else. ({mark}-i)"
            ),
            mark.to_uppercase(),
        ),
    }
}

/// The answers among `answers` that a screen shows when they are typed: the ones with no control
/// character in them, and not empty.
fn visible_answers<'a>(answers: &[&'a str]) -> Vec<&'a str> {
    answers
        .iter()
        .copied()
        .filter(|answer| !answer.is_empty() && !answer.chars().any(char::is_control))
        .collect()
}

/// Whether the composer shows either answer typed again before `probe`, which was typed into an
/// empty composer: an answer the host replayed after a reconnection lands there first.
fn replayed(rows: &[String], probe: &str, answers: &[&str]) -> Result<(), String> {
    let Some(row) = rows.iter().find(|row| row.contains(probe)) else {
        return Err(format!("the composer does not show {probe}"));
    };
    let before = row[..row.find(probe).unwrap_or(0)].trim_end();
    match answers.iter().find(|answer| before.ends_with(**answer)) {
        Some(answer) => Err(format!(
            "the composer shows {answer:?} before the probe, typed again: {row}"
        )),
        None => Ok(()),
    }
}

/// On macOS, a session a person starts with their own home keeps their own default keychain, the
/// login keychain: the product's sessions leave the keychain search to the home the person gives
/// them, and a keychain a program in a session looks for is found. This starts one with `kr new`,
/// the home this test runs with and no agent, reads the default keychain its shell sees with
/// `security default-keychain`, which changes nothing, and appends what it read to the result file.
/// It is not a part of a case: it says whether a keychain request from a session can reach the
/// person as a dialog through the product itself.
#[test]
fn a_session_started_with_a_persons_own_home_keeps_their_login_keychain_as_its_default() {
    const TEST: &str =
        "a_session_started_with_a_persons_own_home_keeps_their_login_keychain_as_its_default";
    let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
    let Some(result) = std::env::var_os(RESULT_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    else {
        assert!(
            !required,
            "{REQUIRE_VARIABLE}=1 and {RESULT_VARIABLE} names no file"
        );
        eprintln!("skipping: the own-home keychain check: {RESULT_VARIABLE} names no result file");
        return;
    };
    if !cfg!(target_os = "macos") {
        eprintln!("skipping: the own-home keychain check: keychains are macOS's");
        return;
    }
    let home = PathBuf::from(std::env::var_os("HOME").expect("the person's home"));
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the own-home check's managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: the own-home keychain check: {why}");
            return;
        }
    };
    let run = Run::start("person's own home");
    let host = Host::start(
        &run,
        &HostOptions {
            shell_packages: Some(shell.prefix.clone()),
        },
    );
    let own = default_keychain_of_a_session(&host, &shell, &home);
    let named = own.default_keychain.clone();
    host.stop()
        .unwrap_or_else(|why| panic!("the host did not stop cleanly: {why}"));
    let checked = run
        .closing_check()
        .unwrap_or_else(|left| panic!("still running after the own-home check: {left}"));
    println!("{checked}");
    // Compared as a path, and said by its kind without its name, which can be the person's own:
    // this text goes into the record.
    let kind = keychain_kind(&named, &home, None);
    assert!(
        kind == "the person's login keychain",
        "a session with the person's own home names as its default keychain {kind}, not the \
         person's login keychain"
    );
    Outcome::passed(
        "own-home",
        TEST,
        json!({
            "home": home,
            "default_keychain": kind,
            "worker_profile": own.worker_profile,
            "bound_to_a_desktop": own.bound_to_a_desktop,
            "show_keychain_info_status": own.keychain_info_status,
        }),
    )
    .append(&result);
}

/// The variables a person's own shell can hold that would give an agent another model account,
/// with the harmless one a control passes alongside them: each with a value that is no key.
const PROVIDER_KEYS_HELD: [&str; 35] = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "CODEX_API_KEY",
    "CODEX_HOME",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_SECRET_ACCESS_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "CLOUDSDK_CONFIG",
    "KIMI_API_KEY",
    "KIMI_CODE_HOME",
    "MOONSHOT_API_KEY",
    "MOONSHOT_BASE_URL",
    "OPENROUTER_API_KEY",
    "OPENCODE_CONFIG",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "MISTRAL_API_KEY",
    "XAI_API_KEY",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
    "HF_TOKEN",
    "AZURE_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "SOME_PROVIDER_BASE_URL",
    "CLARIFAI_PAT",
    "WATSONX_AI_APIKEY",
    "PRIVATEMODE_ENDPOINT",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "KR_SESSION_TOKEN",
];

/// A session a part with a login creates exports no variable its account clears but the ones the
/// build list sets itself, though the environment it was made from held the person's keys, and
/// a harmless variable passes through the same route. This builds the session environment a part
/// builds from the entry the harness names, adds to it what a person's own shell holds (keys with
/// values that are no keys, and one harmless variable), takes the entry's cleared names out as a
/// part does, starts a real session on that and reads the names its shell exports. Control: the
/// same environment with nothing taken out starts a session whose names the part's own check
/// refuses, naming each variable, and not the harmless one.
#[test]
fn a_session_exports_no_provider_key_but_those_the_build_list_sets_and_a_harmless_variable_passes()
{
    let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
    let Some(file) = std::env::var_os(BUILD_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    else {
        assert!(
            !required,
            "{REQUIRE_VARIABLE}=1 and {BUILD_VARIABLE} names no file"
        );
        eprintln!("skipping: the provider-key check: {BUILD_VARIABLE} names no build");
        return;
    };
    let build = read_build(&file);
    let Some(account) = build.account.as_ref() else {
        eprintln!("skipping: the provider-key check: the build list names no login for this agent");
        return;
    };
    // The entry switches the agent's updates and installs off in what its parts give the agent; the same entry
    // with a switch it does not give is refused, and so is one that names none.
    build
        .installs_are_off()
        .unwrap_or_else(|why| panic!("the installs check: {why}"));
    let mut unswitched = build.clone();
    if let Some(account) = unswitched.account.as_mut() {
        account.installs_off.push(InstallSwitch::Variable {
            name: "KR_NO_SUCH_SWITCH".to_owned(),
            value: "1".to_owned(),
        });
    }
    let refused = unswitched
        .installs_are_off()
        .expect_err("a switch the entry does not give");
    assert!(refused.contains("KR_NO_SUCH_SWITCH"), "{refused}");
    if let Some(account) = unswitched.account.as_mut() {
        account.installs_off.clear();
    }
    let refused = unswitched
        .installs_are_off()
        .expect_err("an entry that names no switch");
    assert!(refused.contains("names no switch"), "{refused}");
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the provider-key check's managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: the provider-key check: {why}");
            return;
        }
    };
    let run = Run::start("provider keys");
    let host = Host::start(
        &run,
        &HostOptions {
            shell_packages: Some(shell.prefix.clone()),
        },
    );
    let base = session_variables(
        &host,
        &shell,
        &std::collections::BTreeMap::new(),
        closed_port(),
    );
    prepare_home(&host, &base);
    // What the environment is made from when the person's own shell passes it on.
    let mut held = base.clone();
    for name in PROVIDER_KEYS_HELD {
        held.push((name.to_owned(), format!("kr-not-a-key-{name}")));
    }
    held.push(("HARMLESS_CONTROL".to_owned(), "1".to_owned()));
    let allowed = build.names_it_sets();
    let mut cleared = held.clone();
    let mut taken = build.without_provider_keys(&mut cleared);
    taken.sort();
    let mut expected: Vec<String> = PROVIDER_KEYS_HELD
        .iter()
        .filter(|name| {
            keys::cleared(&account.cleared, name) && !allowed.iter().any(|set| set == *name)
        })
        .map(|name| (*name).to_owned())
        .collect();
    expected.sort();
    assert_eq!(
        taken, expected,
        "the names the build list's cleared list takes out"
    );
    assert!(
        expected.len() >= 20,
        "the entry clears most of what a person's shell holds: {expected:?}"
    );
    assert!(
        !taken.contains(&"KR_SESSION_TOKEN".to_owned())
            && !taken.contains(&"HARMLESS_CONTROL".to_owned()),
        "a product's own name and a harmless one stay"
    );

    // The launched session: none of what was taken out, every harmless name and every name the
    // build list sets itself, and the part's own check passes.
    let exported = names_a_session_exports(&host, &shell, &cleared);
    exported_clear(&exported, &account.cleared, &allowed).unwrap_or_else(|why| panic!("{why}"));
    let names: Vec<&str> = exported.lines().collect();
    for name in &expected {
        assert!(
            !names.contains(&name.as_str()),
            "{name} reached the session"
        );
    }
    for name in ["HARMLESS_CONTROL", "PATH", "HOME", "ZDOTDIR"] {
        assert!(
            names.contains(&name),
            "{name} is exported: a harmless variable passes"
        );
    }
    for name in PROVIDER_KEYS_HELD
        .iter()
        .filter(|name| allowed.iter().any(|set| set == *name))
    {
        assert!(
            names.contains(name),
            "{name}, which the build list sets, is exported"
        );
    }

    // Control, breaking the property: nothing taken out, and the session's names fail the check.
    let dirty = names_a_session_exports(&host, &shell, &held);
    let refused = exported_clear(&dirty, &account.cleared, &allowed)
        .expect_err("the session exports what the build list clears");
    assert!(refused.starts_with(ENVIRONMENT_NOT_CLEAR), "{refused}");
    for name in &expected {
        assert!(
            refused.contains(name.as_str()),
            "the check names {name}: {refused}"
        );
    }
    assert!(
        !refused.contains("HARMLESS_CONTROL") && !refused.contains("KR_SESSION_TOKEN"),
        "{refused}"
    );

    host.stop()
        .unwrap_or_else(|why| panic!("the host did not stop cleanly: {why}"));
    let checked = run
        .closing_check()
        .unwrap_or_else(|left| panic!("still running after the provider-key check: {left}"));
    println!("{checked}");
}

/// Processes a test started, in a process group of their own, killed when it ends however it ends:
/// every process it named, then the whole group while its leader is still unreaped, so its number
/// still names that group, and only then the leader is reaped; a failed assertion leaves nothing
/// running or stopped behind.
struct TestTree {
    child: std::process::Child,
    named: Vec<ProcessStartIdentity>,
}

impl Drop for TestTree {
    fn drop(&mut self) {
        for identity in &self.named {
            signal(identity, rustix::process::Signal::KILL);
        }
        if let Some(group) = i32::try_from(self.child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = self.child.wait();
    }
}

/// Starts `/bin/sh -c script` for a test, and returns it with its start identity, once it has
/// `children` children or five seconds have passed.
fn test_tree(script: &str, children: usize) -> (TestTree, ProcessStartIdentity) {
    use std::os::unix::process::CommandExt;
    let child = std::process::Command::new("/bin/sh")
        .args(["-c", script])
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a shell");
    let pid = child.id();
    let tree = TestTree {
        child,
        named: Vec::new(),
    };
    let kr_ipc::identity::ProcessQuery::Present(identity) = kr_ipc::identity::query_process(pid)
    else {
        panic!("the shell's identity");
    };
    let waited = std::time::Instant::now();
    while waited.elapsed() < Duration::from_secs(5) {
        let count = kr_e2e_m1b::run::process_table()
            .expect("the process table")
            .into_iter()
            .filter(|entry| entry.parent == pid)
            .count();
        if count >= children {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    (tree, identity)
}

/// Kills each of `processes` and waits, five seconds at most, until none runs.
fn kill_and_wait(processes: &[ProcessStartIdentity]) -> bool {
    for identity in processes {
        signal(identity, rustix::process::Signal::KILL);
    }
    let waited = std::time::Instant::now();
    while processes
        .iter()
        .any(|identity| matches!(process_state(identity), ProcessState::Running))
    {
        if waited.elapsed() >= Duration::from_secs(5) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// The conversation search skips only files still as they were before the agent started: one
/// unchanged, even one that holds the needle, is not read; one new, even with a modification time
/// older than the part, or one that changed, is.
#[test]
fn a_conversation_search_skips_only_files_unchanged_since_before_the_agent_started() {
    let root = std::env::temp_dir().join(format!("kr-conversations-{}", nonce()));
    let day = root.join("2026").join("09").join("27");
    std::fs::create_dir_all(&day).expect("a day's directory");
    let line = "{\"role\":\"user\",\"text\":\"kr0123\"}\n";
    let marker = "\"role\":\"user\"";
    let set_old_time = |path: &Path| {
        let an_hour_ago = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_times(std::fs::FileTimes::new().set_modified(an_hour_ago)))
            .expect("a file's time");
    };
    let unchanged = day.join("unchanged.jsonl");
    std::fs::write(&unchanged, line).expect("a file there before");
    let appended = day.join("appended.jsonl");
    std::fs::write(&appended, "{\"role\":\"user\",\"text\":\"theirs\"}\n").expect("another file");
    let before = inventory(std::slice::from_ref(&root));
    assert_eq!(
        conversation_lines(std::slice::from_ref(&root), "kr0123", marker, &before),
        Vec::<(PathBuf, usize)>::new(),
        "a file still as it was before the agent started is not read, whatever it holds"
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&appended)
        .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()))
        .expect("an appended line");
    let new = day.join("new.jsonl");
    std::fs::write(&new, line).expect("a new file");
    set_old_time(&new);
    assert_eq!(
        conversation_lines(std::slice::from_ref(&root), "kr0123", marker, &before),
        vec![(appended, 1), (new, 1)],
        "a changed file and a new one are read, the new one though its time is older than the part"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The agent renames itself: the program is `kimi` and the table's other column shows the title it
/// gave itself, `kimi-code`. A process of either name is the agent's, wherever its file is, and it is
/// the part's own only when a run's process is among its parents.
#[test]
fn a_process_of_the_agent_is_found_by_either_name_and_is_the_parts_own_by_its_parents() {
    let names = ["kimi".to_owned(), "kimi-code".to_owned()];
    // The shape of the rows of a real listing (`ps -axo pid=,ppid=,ucomm=,comm=`) while the agent
    // ran: the agent's own row beneath a shell, the shell, a row with a path, and an unrelated one.
    let listing = " 4907  4829 kimi             kimi-code\n 4829  4821 zsh              /bin/zsh\n\
                    \u{20}  77     1 kimi             /Users/someone/.kimi-code/bin/kimi\n\
                    \u{20} 880   500 kimi-code-helper  kimi-code-helper\n\
                    \u{20} 901     1 bash             /bin/bash\n";
    let view = view_of(listing, &names);
    assert_eq!(view.named, vec![4907, 77]);
    assert_eq!(
        outside_of(&view, &[4829]),
        vec![77],
        "beneath the session's shell is the part's"
    );
    assert_eq!(
        outside_of(&view, &[4907]),
        vec![77],
        "a registered agent is its own"
    );
    assert_eq!(
        outside_of(&view, &[]),
        vec![4907, 77],
        "with no roots nothing is the part's"
    );
    assert_eq!(
        outside_of(&view, &[4821]),
        vec![77],
        "the root may be further up"
    );
    assert!(view_of("", &names).named.is_empty());
    assert!(view_of("not a listing\n", &names).named.is_empty());
    assert!(agent_processes(&["no-such-program-kr".to_owned()]).is_ok_and(|pids| pids.is_empty()));
}

/// The values a part's searches cannot be sure of finding in a result are counted whoever's they
/// are: the login's own value as much as the other keys the person's shell holds.
#[test]
fn a_value_a_result_could_hide_is_counted_whether_it_is_the_logins_own_or_another_key() {
    let plain = "sk-or-v1-0123456789abcdef".to_owned();
    let quoted = "sk-or-v1-0123\"456789abcdef".to_owned();
    let lined = "sk-or-v1-0123\n456789abcdef".to_owned();
    assert_eq!(
        unsearchable_count(Some(&plain), std::slice::from_ref(&plain)),
        0
    );
    assert_eq!(unsearchable_count(None, &[]), 0);
    assert_eq!(
        unsearchable_count(Some(&quoted), &[]),
        1,
        "the login's own value"
    );
    assert_eq!(
        unsearchable_count(Some(&lined), &[]),
        1,
        "the login's own value"
    );
    assert_eq!(
        unsearchable_count(
            Some(&plain),
            &[quoted.clone(), "a\\b-0123456789".to_owned()]
        ),
        2,
        "the other keys"
    );
    assert_eq!(
        unsearchable_count(Some(&quoted), &[quoted.clone(), lined]),
        2,
        "the login's own value is counted once, whether or not another key is the same"
    );
}

/// A probe that ends with a failure says how it ended, and what it wrote to its error output where
/// that is safe to say: the run's own home holds nothing of the person's, and the part's log is
/// searched for every key it was given.
#[test]
fn a_probe_that_failed_says_what_it_wrote_only_where_the_run_holds_nothing_of_the_persons() {
    let written = b"error: cannot open the database\nat start (file.ts:1)\n".as_slice();
    assert_eq!(
        probe_failed("exit status: 1", written, false, &[]),
        "it exited exit status: 1"
    );
    assert_eq!(
        probe_failed("exit status: 1", written, true, &[]),
        "it exited exit status: 1 and wrote: error: cannot open the database / at start (file.ts:1)"
    );
    assert_eq!(
        probe_failed("exit status: 1", b"  \n", true, &[]),
        "it exited exit status: 1"
    );
    let long = "x".repeat(900).into_bytes();
    assert!(
        probe_failed("exit status: 1", &long, true, &[])
            .chars()
            .count()
            < 520
    );
    // A key the probe was given, at the place the text is cut or past it, is no part of the note.
    let key = "sk-or-v1-0123456789abcdef0123456789abcdef";
    let mut leaking = "y".repeat(380).into_bytes();
    leaking.extend_from_slice(format!(" key {key} end").as_bytes());
    let said = probe_failed("exit status: 1", &leaking, true, &[key]);
    assert_eq!(said, "it exited exit status: 1", "{said}");
    // Whatever the held values are to one another, and however the output wrapped or clipped one,
    // a piece of eight characters of a held key anywhere in it stops the whole note.
    let long_key = "sk-synthetic-1234567890abcdef";
    for written in [
        format!("a {long_key} b"),
        "token sk-synthetic-1234\n567890abcdef end".to_owned(),
        "token ...567890abcdef end".to_owned(),
        "abcabcabcabc sk-synthetic-1234 567890abcdef".to_owned(),
    ] {
        for held in [
            vec![long_key],
            vec!["sk-synthetic-1234", long_key],
            vec![long_key, "sk-synthetic-1234"],
        ] {
            let said = probe_failed("exit status: 1", written.as_bytes(), true, &held);
            assert_eq!(
                said, "it exited exit status: 1",
                "{written:?} {held:?}: {said}"
            );
        }
    }
    let said = probe_failed("exit status: 1", b"database is locked\n", true, &[long_key]);
    assert!(said.ends_with("wrote: database is locked"), "{said}");
}

/// A prompt's own text is shown on a screen once the agent has taken it into its composer; the
/// longest word of it, which no other row of the part holds unless the part typed it, is what is
/// looked for, and the same word on a row that wraps is still one word.
#[test]
fn a_typed_prompt_is_shown_once_its_longest_word_is_on_the_screen() {
    let text = "What is 741 plus 830 Reply with only the number. (kr370dcc681495-r)";
    let rows = |lines: &[&str]| {
        lines
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(longest_word(text), "kr370dcc681495-r");
    // A question mark an agent drops is not part of the word the wait looks for.
    assert_eq!(
        longest_word("What code did I ask you to remember? Reply with only the code."),
        "remember"
    );
    assert!(typed_text_shows(
        &rows(&[
            " > What is 741 plus 830 Reply with only the number.",
            " (kr370dcc681495-r)"
        ]),
        text
    ));
    assert!(typed_text_shows(
        &rows(&["> [Image colour.png] (kr370dcc681495-r)"]),
        text
    ));
    // The composer still empty while the agent draws its reply: nothing is shown yet.
    assert!(!typed_text_shows(
        &rows(&[" >   Type your message or @path/to/file", "  123", "  124"]),
        text
    ));
    assert!(
        typed_text_shows(&rows(&["anything"]), ""),
        "an empty prompt has nothing to wait for"
    );
}

/// The part's two commands, the one it approves and the one its control denies, are the same length,
/// so that the second fits the agent's dialog wherever the first does, and neither marker holds the
/// other.
#[test]
fn the_two_approval_markers_are_as_long_as_each_other_and_differ() {
    let (first, second) = approval_markers("kr0123456789ab");
    assert_eq!((first.as_str(), second.as_str()), ("kr6789ab", "kr012345"));
    assert_eq!(first.len(), second.len());
    // Two markers that would be the same stop the part before it types anything.
    let same = std::panic::catch_unwind(|| approval_markers("kr123456123456"));
    assert!(same.is_err());
}

/// The question session B asks of the resumed conversation is looked for in the conversation by its
/// words before the question mark, which an agent can drop from what a person types.
#[test]
fn the_resumed_question_is_found_by_its_words_and_not_by_its_question_mark() {
    assert!(RESUMED_QUESTION.starts_with(RESUMED_QUESTION_WORDS));
    assert!(!RESUMED_QUESTION_WORDS.contains('?'));
    assert!(RESUMED_QUESTION_WORDS.split_whitespace().count() >= 6);
}

/// An agent's first start in a fresh home can fail because its own database is still locked by the
/// start before it. A probe whose whole account of itself is that lock is started again, a few
/// times; one that says anything else besides it, or ends otherwise, is not, and its answer is the
/// last start's own.
#[test]
fn a_probe_is_started_again_only_when_the_lock_is_all_it_said() {
    use std::os::unix::process::ExitStatusExt;
    let ended = |code: i32, stderr: &str| std::process::Output {
        status: std::process::ExitStatus::from_raw(code << 8),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    };
    let locked = "\u{1b}[91m\u{1b}[1mError: \u{1b}[0mUnexpected error\ndatabase is locked\n";
    assert!(lock_failure(locked.as_bytes()));
    assert!(lock_failure(b"database is locked"));
    assert!(!lock_failure(b""));
    assert!(!lock_failure(b"Error: Unexpected error\n"));
    assert!(!lock_failure(
        b"Error: Unexpected error\ndatabase is locked\nconfig is not valid\n"
    ));
    assert!(!lock_failure(b"the config says database is locked"));
    // An escape that is not a whole colour sequence is not skipped over, and cannot hide text.
    assert!(!lock_failure(b"database is locked\n\x1b[1~403\n"));
    assert!(!lock_failure(
        b"database is locked\n\x1b[91m403 forbidden\n"
    ));
    assert!(!lock_failure(b"database is locked\n\x1bX\n"));
    assert!(!lock_failure(b"database is locked\x1b"));

    let mut starts = 0;
    let result = started_again(3, Duration::ZERO, || {
        starts += 1;
        Ok(if starts < 3 {
            ended(1, locked)
        } else {
            ended(0, "")
        })
    });
    assert!(result.expect("an output").status.success());
    assert_eq!(starts, 3);

    let mut starts = 0;
    let result = started_again(3, Duration::ZERO, || {
        starts += 1;
        Ok(ended(1, locked))
    });
    assert!(!result.expect("an output").status.success());
    assert_eq!(
        starts, 3,
        "the last start's answer is returned after the bound"
    );

    // A failed start that wrote to its output besides the lock is not started again: a later
    // start's clean output must not stand in for what the first one said.
    let mut starts = 0;
    let with_output = || {
        starts += 1;
        let mut output = ended(1, locked);
        output.stdout = b"loaded ~/.config/opencode/opencode.json".to_vec();
        Ok(output)
    };
    let result = started_again(3, Duration::ZERO, with_output);
    assert!(result.is_ok());
    assert_eq!(starts, 1);

    for (stderr, code) in [
        (
            "Error: Unexpected error\ndatabase is locked\nconfig is not valid\n",
            1,
        ),
        ("Error: config is not valid\n", 1),
        ("", 0),
    ] {
        let mut starts = 0;
        let result = started_again(3, Duration::ZERO, || {
            starts += 1;
            Ok(ended(code, stderr))
        });
        assert!(result.is_ok());
        assert_eq!(starts, 1, "{stderr:?} is not started again");
    }
    // A start that cannot be made at all is not tried again either.
    let mut starts = 0;
    let result = started_again(3, Duration::ZERO, || {
        starts += 1;
        Err("the probe did not start".to_owned())
    });
    assert_eq!(
        (result.err().as_deref(), starts),
        (Some("the probe did not start"), 1)
    );
}

/// The long turn an interrupt stops asks for a reply the screen shows the key's cue in throughout:
/// the agent's own mark where it has one at each reply's start, and where it has none the part's code
/// at the start of every line, so that a fast model, whose reply scrolls the first line off the
/// screen within a second, still shows the code while the turn runs.
#[test]
fn the_long_turn_shows_its_cue_on_every_line_where_the_agent_has_no_reply_mark() {
    let (text, cue) = long_turn("kr0123456789ab", Some("✦"));
    assert_eq!(cue, "✦");
    assert!(
        text.contains("count from 1 to 400") && text.ends_with("(kr0123456789ab-i)"),
        "{text}"
    );
    let (text, cue) = long_turn("kr0123456789ab", None);
    assert_eq!(cue, "KR0123456789AB");
    assert!(
        text.contains("KR0123456789AB at the start of every line")
            || text.contains("kr0123456789ab in upper case at the start of every line"),
        "{text}"
    );
    assert!(
        text.contains("count from 1 to 400") && text.ends_with("(kr0123456789ab-i)"),
        "{text}"
    );
}

/// A text the part keeps or prints, a panic's message and a note, holds no piece of a key the part
/// holds, in any way the output can show it: whole, wrapped, clipped, between colour codes, behind
/// an escape that is not a colour code, or after one. A text that holds one is replaced.
#[test]
fn a_text_the_part_keeps_carries_no_piece_of_a_held_key_whatever_escapes_surround_it() {
    let key = "sk-synthetic-1234567890abcdef";
    for text in [
        // an escape that is not a colour code, and the key digits after it
        "token \u{1b}[1~1234567890abcdef".to_owned(),
        // a sequence of key digits that ends in a letter, where a colour code would end in `m`
        "\u{1b}[1234567890abcdef".to_owned(),
        // a cursor save, then a piece of the key
        "x \u{1b}7567890abcdef y".to_owned(),
        // a colour code between the pieces of the key
        "sk-synthetic-\u{1b}[31m1234567890abcdef".to_owned(),
        // the key digits written as if they were a colour code's parameters
        "sk-synthetic-\u{1b}[1234567890m abcdef".to_owned(),
        // framed and wrapped
        "┃ sk-synthetic-1234\n┃ 567890abcdef".to_owned(),
    ] {
        let kept = kept_clear(&text, &[key]);
        assert!(kept.contains("holds a key"), "{text:?} -> {kept:?}");
    }
    assert_eq!(
        kept_clear("Error: database is locked", &[key]),
        "Error: database is locked"
    );
    assert_eq!(
        kept_clear("\u{1b}[91mError: \u{1b}[0mUnexpected", &[key]),
        "\u{1b}[91mError: \u{1b}[0mUnexpected"
    );
}

/// A failure is classed by what it said, and what is recorded or printed of it is held to the key
/// rule: a message that holds a piece of a held key is still of its class, and only its text is
/// replaced.
#[test]
fn a_failure_that_holds_a_piece_of_a_key_keeps_its_class_and_loses_only_its_text() {
    let key = "sk-or-v1-0123456789abcdef0123456789abcdef";
    let message = format!("{LOGIN_UNPROVEN} the screen shows an error for {key}");
    let kept = kept_clear(&message, &[key]);
    assert!(!kept.contains("sk-or-v1"), "{kept}");
    // The class is read from the message as it was written, and recorded as the harness's own words.
    assert!(message.starts_with(LOGIN_UNPROVEN));
    assert_eq!(
        recorded_text(&message, &[key]),
        format!("{LOGIN_UNPROVEN} (the rest holds a key, so it is not kept)")
    );
    assert_eq!(recorded_text("fine", &[key]), "fine");
    let wrapped =
        format!("{ISOLATION_UNPROVEN} a probe wrote sk-or-\nv1-0123456789abcdef0123456789abcdef");
    assert!(recorded_text(&wrapped, &[key]).starts_with(ISOLATION_UNPROVEN));
}

/// A text that holds a key is recorded after a number of searches that its length cannot raise: the
/// first words it keeps are decided by the first delimiter alone, because a longer head holds every
/// piece a shorter one does.
#[test]
fn a_long_text_that_holds_a_key_is_recorded_after_a_fixed_number_of_searches() {
    let key = "sk-or-v1-0123456789abcdef0123456789abcdef";
    let text = format!("{key}{}", ":abcdefg\n".repeat(2000));
    let before = KEY_SEARCHES.with(std::cell::Cell::get);
    let kept = recorded_text(&text, &[key]);
    let searches = KEY_SEARCHES.with(std::cell::Cell::get) - before;
    assert!(!kept.contains("0123456789abcdef"), "{kept}");
    assert!(
        kept.ends_with("so it is not kept)") && kept.len() < 100,
        "the rows after the key are not kept"
    );
    assert!(
        searches <= 2,
        "{searches} searches for a text of 2,000 rows"
    );
    // The first delimiter decides because a head never holds less than a shorter one: checked over
    // the ways a key is written, escapes and wraps included.
    let synthetic = "sk-synthetic-1234567890abcdef";
    let coloured = "sk-synthetic-1234mabcdefg";
    let escaped = [
        ("token \u{1b}[1~1234567890abcdef: x\n", synthetic),
        ("sk-synthetic-\u{1b}[31m1234567890abcdef: x\n", synthetic),
        ("sk-synthetic-\u{1b}[1234567890m abcdef: x\n", synthetic),
        ("\u{1b}[1234ma\u{1b}[0mbcdefg: x\n", coloured),
        ("\u{1b}[1234mabcdefg: x\n", coloured),
        ("┃ sk-synthetic-1234\n┃ 567890abcdef: x\n", synthetic),
    ];
    for (text, key) in escaped {
        let mut held = false;
        for (at, _) in text.match_indices([':', '\n']) {
            let now = holds_a_key(&[&text[..at]], &[key]);
            assert!(
                now || !held,
                "{text:?}: the head to {at} holds less than a shorter one"
            );
            held |= now;
        }
        assert!(held, "{text:?} holds the key");
    }
}

/// A screen that lacks what was just typed is read again until it shows it: the agent draws a
/// typed marker a moment after it takes it, which a real run showed for each of two sessions.
#[test]
fn a_screen_is_read_again_until_it_shows_what_was_typed() {
    let marker = "only-a-1234";
    let mut reads = 0;
    let rows = screen_until_shown(
        || {
            reads += 1;
            vec![if reads < 3 {
                "> ".to_owned()
            } else {
                format!("> {marker}")
            }]
        },
        marker,
        20,
        || {},
    );
    assert_eq!((reads, rows), (3, vec![format!("> {marker}")]));
    let mut reads = 0;
    let rows = screen_until_shown(
        || {
            reads += 1;
            vec![format!("> {reads}")]
        },
        marker,
        20,
        || {},
    );
    assert_eq!((reads, rows), (20, vec!["> 20".to_owned()]));
}

/// A colour code that is also a run of key characters, beside another that is not: each is read
/// either way, so a key is found however the codes are told apart.
#[test]
fn a_key_is_found_whichever_of_its_colour_looking_runs_are_colour() {
    let key = "sk-synthetic-1234mabcdefg";
    assert!(holds_a_key(&["\u{1b}[1234ma\u{1b}[0mbcdefg"], &[key]));
    assert!(holds_a_key(&["\u{1b}[1234mabcdefg"], &[key]));
    assert!(
        !holds_a_key(&["\u{1b}[1234ma"], &[key]),
        "six characters of the key are no piece"
    );
    assert!(holds_a_key(&["x1234m\u{1b}[0mabcdefg"], &[key]));
    assert!(!holds_a_key(
        &["\u{1b}[91mError\u{1b}[0m: nothing here"],
        &[key]
    ));
    // A long screen full of colour codes is searched in time and stack of its own length.
    let long = "\u{1b}[0m".repeat(100_000);
    assert!(!holds_a_key(&[long.as_str()], &[key]));
    let with_key = format!("{long}sk-synthetic-1234mabcdefg{long}");
    assert!(holds_a_key(&[with_key.as_str()], &[key]));
}

/// An answer that is a control key, such as Enter or Escape, shows nowhere on the screen, so the
/// composer cannot show it typed again; only the answers a person would see are looked for there.
#[test]
fn only_an_answer_that_shows_on_the_screen_is_looked_for_in_the_composer() {
    assert_eq!(visible_answers(&["\r", "\u{1b}"]), Vec::<&str>::new());
    assert_eq!(visible_answers(&["1", "\u{1b}"]), vec!["1"]);
    assert_eq!(visible_answers(&["y", "n", ""]), vec!["y", "n"]);
    // The check itself still finds a visible answer before the probe and not a control key, which
    // the row trims away as a space.
    assert!(replayed(&["> 1zq0123".to_owned()], "zq0123", &["1"]).is_err());
    assert!(replayed(&["> \rzq0123".to_owned()], "zq0123", &["\r"]).is_ok());
}

/// How a probe that did not succeed is said to have ended: its status and, where `say` is set, the
/// first 400 characters of what it wrote to its error output, its lines joined by ` / `, and
/// nothing of it where it holds a piece of a key the part holds (`secrets`: see [`holds_a_key`]).
fn probe_failed(status: &str, written: &[u8], say: bool, secrets: &[&str]) -> String {
    let text = String::from_utf8_lossy(written).into_owned();
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    // Nothing is said of what was written when a piece of a held key is in it.
    if !say || lines.is_empty() || holds_a_key(&lines, secrets) {
        return format!("it exited {status}");
    }
    let joined: String = lines.join(" / ").chars().take(400).collect();
    format!("it exited {status} and wrote: {joined}")
}

/// A dialog the part refuses is noted with the screen it was refused on, so that a part that then
/// fails for want of a dialog says what became of the one that was there.
#[test]
fn a_refused_dialog_is_noted_with_the_rows_the_part_refused_it_on() {
    let rows = vec![
        "  ┃  △ Permission required".to_owned(),
        String::new(),
        "  ┃  $ echo kr0123 >> a".to_owned(),
    ];
    let note = refusal_note(
        "a command other than the part's",
        "Permission required",
        "\u{1b}",
        &rows,
        &[],
    );
    assert!(
        note.starts_with(
            "a command other than the part's: a dialog showing \"Permission required\", refused \
             with \"\\u{1b}\""
        ),
        "{note}"
    );
    assert!(
        note.contains("  ┃  △ Permission required\n  ┃  $ echo kr0123 >> a"),
        "the rows are in the note without the blank one: {note}"
    );
    // No piece of a held key is noted, whole or wrapped, clipped at a screen edge or cut by a
    // colour code: a piece of eight characters or more of a value, in any row.
    let key8 = "sk-synthetic-1234567890abcdef";
    for piece in ["567890abcdef end", "x 1234567890 x", "synthetic"] {
        let rows = vec![format!("  ┃  $ {piece}")];
        let note = refusal_note("why", "Permission required", "\u{1b}", &rows, &[key8]);
        assert!(note.contains("holds a key"), "{piece}: {note}");
    }
    let coloured = vec!["  ┃  $ sk-synth\u{1b}[31metic-1234567890".to_owned()];
    let note = refusal_note("why", "Permission required", "\u{1b}", &coloured, &[key8]);
    assert!(note.contains("holds a key"), "{note}");
    // Seven characters of a value are an ordinary word.
    let rows = vec!["  ┃  $ abcdefg".to_owned()];
    let note = refusal_note(
        "why",
        "Permission required",
        "\u{1b}",
        &rows,
        &["abcdefghij"],
    );
    assert!(!note.contains("holds a key"), "{note}");
    // A key that wraps inside a frame, or between boxes, is still one key.
    let framed = vec![
        "  ┃  $ echo sk-synthetic-1234".to_owned(),
        "  ┃  567890abcdef".to_owned(),
    ];
    let note = refusal_note(
        "why",
        "Permission required",
        "\u{1b}",
        &framed,
        &["sk-synthetic-1234567890abcdef"],
    );
    assert!(
        !note.contains("sk-synthetic") && !note.contains("567890"),
        "{note}"
    );
    let boxed = vec![
        "│ │ sk-synthetic-1234 │ │".to_owned(),
        "│ │ 567890abcdef      │ │".to_owned(),
    ];
    let note = refusal_note(
        "why",
        "Allow",
        "1",
        &boxed,
        &["sk-synthetic-1234567890abcdef"],
    );
    assert!(!note.contains("567890"), "{note}");
    // A screen that shows a key the part holds, whole in a row or across two rows, is not noted.
    let key = "sk-or-v1-0123456789abcdef0123456789abcdef";
    for held in [
        vec![format!("  ┃  $ echo {key}")],
        vec![
            "  ┃  $ echo sk-or-v1-0123456789ab".to_owned(),
            "cdef0123456789abcdef".to_owned(),
        ],
    ] {
        let note = refusal_note("why", "Permission required", "\u{1b}", &held, &[key]);
        assert!(!note.contains("sk-or"), "{note}");
        assert!(note.contains("holds a key"), "{note}");
    }
}

/// A default keychain is said by its kind, compared as a path: a name that only begins like the
/// login keychain's is another keychain, and no name is said.
#[test]
fn a_default_keychain_is_said_by_its_kind_compared_as_a_path() {
    let home = Path::new("/Users/someone");
    let run_home = Path::new("/private/var/folders/xx/T/krm-1/h");
    let kind = |named: &str| keychain_kind(named, home, Some(run_home));
    assert_eq!(
        kind("    \"/Users/someone/Library/Keychains/login.keychain-db\""),
        "the person's login keychain"
    );
    assert_eq!(
        kind("/Users/someone/Library/Keychains/login.keychain-db-client.keychain-db"),
        "another keychain in the person's home"
    );
    assert_eq!(
        kind("/Users/someone/Library/Keychains/client-someone.keychain-db"),
        "another keychain in the person's home"
    );
    assert_eq!(
        kind("/private/var/folders/xx/T/krm-1/h/Library/Keychains/kr.keychain-db"),
        "a keychain in the run's home"
    );
    assert_eq!(
        kind("/Library/Keychains/System.keychain"),
        "another keychain"
    );
    assert_eq!(kind("  "), "none");
}

#[test]
fn a_stop_freezes_a_tree_whole_before_it_is_killed() {
    let (mut tree, root) = test_tree("/bin/sleep 60 & /bin/sleep 60 & wait", 2);
    let frozen = freeze(std::slice::from_ref(&root));
    tree.named.extend(frozen.stopped.iter().cloned());
    tree.named.extend(frozen.unconfirmed.iter().cloned());
    assert!(
        frozen.complete && frozen.failures.is_empty() && frozen.unconfirmed.is_empty(),
        "{frozen:?}"
    );
    assert_eq!(
        frozen.stopped.len(),
        3,
        "the shell and its two children: {frozen:?}"
    );
    assert!(
        frozen
            .stopped
            .iter()
            .all(|identity| kr_e2e_m1b::run::stopped(identity) == Some(true)),
        "each is stopped before anything is killed"
    );
    assert!(
        kill_and_wait(&frozen.stopped),
        "the shell and its children ended"
    );
}

/// The marked sleeps the tree's inner shell starts. Every other process on the machine that runs
/// the same program with the same argument is somebody else's: another copy of this case, another
/// run on a shared machine, or a sleep a failed run left behind for its whole minute.
const MARKED_SLEEP: &str = "/bin/sleep 61.75";

/// The processes of `table` beneath `root`, at any depth.
fn beneath(table: &[kr_e2e_m1b::run::Entry], root: u32) -> std::collections::BTreeSet<u32> {
    let mut found = std::collections::BTreeSet::from([root]);
    loop {
        let before = found.len();
        for entry in table {
            if found.contains(&entry.parent) {
                found.insert(entry.pid);
            }
        }
        if found.len() == before {
            return found;
        }
    }
}

#[test]
fn a_tree_whose_descendant_keeps_starting_children_is_caught_whole() {
    // The shell's child is another shell that starts a marked sleep every hundredth of a second,
    // so children are being started while the walk goes down to it.
    let (mut tree, root) = test_tree(
        &format!("/bin/sh -c 'while :; do {MARKED_SLEEP} & /bin/sleep 0.01; done'; :"),
        1,
    );
    let root_pid = u32::try_from(root.pid.get()).expect("the shell's number");
    // The inner shell has started a few children by now, and goes on starting them while the walk
    // goes down to it. How long that takes is the machine's, so the tree is waited for.
    let started = std::time::Instant::now();
    loop {
        let table = kr_e2e_m1b::run::process_table().expect("the process table");
        let tree_now = beneath(&table, root_pid);
        let children = table
            .iter()
            .filter(|entry| entry.command == MARKED_SLEEP && tree_now.contains(&entry.pid))
            .count();
        if children >= 3 {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the inner shell started {children} children in {:?}, and the case needs three",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let frozen = freeze(std::slice::from_ref(&root));
    tree.named.extend(frozen.stopped.iter().cloned());
    tree.named.extend(frozen.unconfirmed.iter().cloned());
    assert!(frozen.complete, "{frozen:?}");
    let table = kr_e2e_m1b::run::process_table().expect("the process table");
    let beneath_the_tree = beneath(&table, root_pid);
    let before: Vec<u32> = table
        .iter()
        .filter(|entry| entry.command == MARKED_SLEEP && beneath_the_tree.contains(&entry.pid))
        .map(|entry| entry.pid)
        .collect();
    assert!(
        before.len() > 2,
        "the inner shell started its children: {before:?}"
    );
    let caught: Vec<u32> = frozen
        .stopped
        .iter()
        .filter_map(|identity| u32::try_from(identity.pid.get()).ok())
        .collect();
    assert!(
        before.iter().all(|pid| caught.contains(pid)),
        "every child the frozen tree had is stopped with it: {before:?} against {caught:?}"
    );
    assert!(
        frozen
            .stopped
            .iter()
            .all(|identity| kr_e2e_m1b::run::stopped(identity) == Some(true)),
        "each is seen stopped before anything is killed"
    );
    assert!(kill_and_wait(&tree.named), "the tree ended");
    let after: Vec<u32> = kr_e2e_m1b::run::process_table()
        .expect("the process table")
        .iter()
        .filter(|entry| entry.command == MARKED_SLEEP && before.contains(&entry.pid))
        .map(|entry| entry.pid)
        .collect();
    assert!(after.is_empty(), "nothing of the tree is left: {after:?}");
}

#[test]
fn a_probe_runs_in_a_group_of_its_own_that_goes_whole_and_is_refused_after_a_stop() {
    let registry = std::sync::Mutex::new(Registry::default());
    // A probe that leaves a child behind holding its output: the group goes, and so does the
    // child, so the output closes.
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", "echo said; /bin/sleep 30 &"]);
    let started = std::time::Instant::now();
    let output = grouped_output(command, Some(&registry)).expect("the probe's output");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "said\n");
    assert!(output.status.success());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the child it left went with its group"
    );
    assert!(
        registry.lock().expect("the registry").probes.is_empty(),
        "the probe is off the list once it returned"
    );
    registry.lock().expect("the registry").tripped = true;
    let mut refused = std::process::Command::new("/bin/echo");
    refused.arg("never");
    assert!(
        grouped_output(refused, Some(&registry))
            .is_err_and(|why| why.contains("changed before it could run")),
        "a probe after a stop is refused"
    );
}

/// Guards that watch nothing, whose only state is whether a look at the login's files failed.
fn bare_guards(failed_look: bool) -> Guards {
    Guards {
        home: std::env::temp_dir(),
        files: Vec::new(),
        before: Vec::new(),
        guarded: Vec::new(),
        shared: Vec::new(),
        append_only: Vec::new(),
        workspaces: None,
        subagents: None,
        login_look_failed: std::sync::atomic::AtomicBool::new(failed_look),
        login_data: None,
        login_seen: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        read_at: std::sync::Mutex::new(None),
    }
}

#[test]
fn a_failed_look_at_the_logins_files_stops_the_part_before_its_next_prompt() {
    assert_eq!(bare_guards(false).change(&[]), None);
    let why = bare_guards(true).change(&[]).expect("a stop");
    assert_eq!(why, LOGIN_LOOK_FAILED);
    assert!(
        !why.contains('"'),
        "what it says quotes nothing of the files"
    );
    assert_eq!(
        guard_class(&why),
        "secret_found",
        "the record says a string of the files is the cause, not a changed file"
    );
}

#[test]
fn a_look_at_the_logins_files_keeps_what_it_can_search_for_and_fails_on_what_it_cannot() {
    let data = std::env::temp_dir().join(format!("kr-guard-look-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(data.join("credentials")).expect("directories");
    std::fs::write(data.join("config.toml"), "default_model = \"x\"\n").expect("write");
    let write = |text: &str| {
        std::fs::write(data.join("credentials/a.json"), text).expect("write");
    };
    let mut guards = bare_guards(false);
    guards.login_data = Some(data.clone());
    // A string a search can be run for is kept and the look has not failed.
    write(r#"{"access":"ABCDEFGHIJKLMNOPQRSTUVWXYZ"}"#);
    guards.look_at_login();
    assert!(
        !guards
            .login_look_failed
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert_eq!(
        guards
            .login_seen
            .lock()
            .expect("seen")
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_owned()]
    );
    // A refresh that adds a string a search cannot be run for: the look fails, and the string that
    // can be searched for is kept all the same.
    write(r#"{"access":"ZYXWVUTSRQPONMLKJIHGFEDCBA","other":"has \"a quote\" in it of length"}"#);
    guards.look_at_login();
    assert!(
        guards
            .login_look_failed
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert!(
        guards
            .login_seen
            .lock()
            .expect("seen")
            .contains("ZYXWVUTSRQPONMLKJIHGFEDCBA"),
        "the look's other string is kept"
    );
    assert!(
        guards
            .login_seen
            .lock()
            .expect("seen")
            .iter()
            .all(|string| confine::searchable(string)),
        "nothing kept is a string a search cannot be run for"
    );
    // A file that is not JSON is a look that failed.
    let again = {
        let mut guards = bare_guards(false);
        guards.login_data = Some(data.clone());
        guards
    };
    write("{ not json");
    again.look_at_login();
    assert!(
        again
            .login_look_failed
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    let _ = std::fs::remove_dir_all(&data);
}
