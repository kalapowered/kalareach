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

use kr_client::cursors::StreamCursors;
use kr_e2e_agents::account::{
    AppendOnly, Guarded, Ledger, RunRules, append_only_files, appended_since,
    borrow_login_keychain, changes, conversation_id, files_holding_any, guarded_files, holds_any,
    keychain_item_modified, line_identity, now_ms, read_if_there, record_guarded, record_key_scan,
    record_rewrites, remove_appended_lines, remove_created, reported_rewrites, run_files_holding,
    run_files_holding_any, snapshot, which_hold,
};
use kr_e2e_agents::build::{
    Account, AccountHome, Action, Build, Confinement, Inputs, InstallSwitch, quote, read_build,
    with_dates,
};
use kr_e2e_agents::confine::{self, Layout, Setup};
use kr_e2e_agents::detect::{
    Detection, Held, Launched, Shown, Surface, announced_now, backend_files, capabilities_of,
    check_detected, check_observation_only, detected_evidence, wait_for_detection,
};
use kr_e2e_agents::held::{
    Absent, CONFIG_DIRECTORY, HeldKeys, ISOLATION_UNPROVEN, KEY_SEARCHES, PROXY_VARIABLES,
    folder_of, holds_a_key, kept_clear, kept_panic_text, panic_text, recorded_text,
    unsearchable_count,
};
use kr_e2e_agents::keychain::RunKeychain;
use kr_e2e_agents::keys;
use kr_e2e_agents::mirror::{self, Mirroring};
use kr_e2e_agents::network::{Policy, Proxy};
use kr_e2e_agents::observe::{AGENT_READS, Answer, live_bindings, typed_actions};
use kr_e2e_agents::outcome::{Failure, Outcome};
use kr_e2e_agents::provenance::{
    ENVIRONMENT_NOT_CLEAR, ENVIRONMENT_NOT_READ, Expected, NOT_PINNED, Provenance, StopSampling,
    beneath_parent, exported_clear,
};
use kr_e2e_agents::stage::{
    AgentProcess, Context, Installation, Installed, Keyboard, Owner, Refused, Replacement, Session,
    closed_for_all_but_the_stand_in, closed_port, default_keychain_of_a_session, events_snapshot,
    free_port, install, launch, launch_or_refusal, names_a_session_exports, open_session,
    place_forwarder, prepare_home, runtime, scan_rules, session_variables,
};
use kr_e2e_agents::stub::RequestStub;
use kr_e2e_agents::{BUILD_VARIABLE, REQUIRE_VARIABLE, RESULT_VARIABLE};
use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::host::{Host, HostOptions};
use kr_e2e_m1b::run::{Run, output_within, running, signal};
use kr_e2e_m1b::shells::{self, ManagedShell};
use kr_e2e_m1b::view::View;
use kr_e2e_m1b::window::Window;
use kr_ipc::identity::{ProcessState, process_state};
use kr_protocol::agent::AgentSubject;
use kr_protocol::identity::ProcessStartIdentity;
use serde_json::json;

/// How a part says its agent's login could not be established: its status command did not report
/// it, the agent did not reach its composer with it, or the agent showed that it is signed out. A
/// part that says so stops its agent.
const LOGIN_UNPROVEN: &str = "the agent's login is not established:";

/// How a part says its guards found what stops it while it ran: a file of the person's that no
/// part may change changed, or the agent started a subagent. A part that says so does nothing
/// more, and its agent stops.
const GUARD_CHANGED: &str = "the part's guards found what stops it:";

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

/// Why the part stops, where a look at the processes beneath the agent found one whose command line
/// names a server of the person's.
fn tree_broken(provenance: &Provenance) -> Option<String> {
    provenance
        .forbidden_found()
        .map(|why| format!("{TREE_BROKEN} {why}"))
}

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

/// Everything a part runs on.
struct Stage<'a, 'r> {
    build: &'a Build,
    run: &'r Run,
    host: &'a Host<'r>,
    owner: &'a mut Owner,
    runtime: &'a tokio::runtime::Runtime,
    shell: &'a ManagedShell,
    installed: &'a Installed,
    provenance: &'a Provenance,
    /// The person's login, for a part that needs it.
    login: Option<&'a Login>,
    /// Text only this part's own prompts and files carry, chosen before the part starts, by which
    /// what the part left in the person's agent directories is told from what anything else left.
    mark: &'a str,
    /// Whether the part's latest request to the agent's model has been answered with what only the
    /// model could have written: cleared by each charged request, set by its answer. A part that
    /// ends without passing while it is clear has no proof its login still holds.
    held: &'a std::sync::atomic::AtomicBool,
    /// Each request for approval the part refused, by what the agent asked: every one but the one
    /// command part 3 names.
    declined: &'a std::sync::Mutex<Vec<String>>,
    /// The person's files no part may change, and those their own programs also write, as the
    /// part found them before it started: checked again after the probes, once the agent is up,
    /// before each prompt and approval, and after each wait.
    guards: Option<&'a Guards>,
    /// The local dates `{date}` stands for in the build list's paths: the day the part started and
    /// the next.
    dates: &'a [String],
    /// The files under the agent's conversation roots as the part found them before anything
    /// started: one that is still as it was cannot hold the part's mark.
    conversations_before: &'a Inventory,
    /// What each probe that stands in for the vendor's model service found the agent offer its
    /// model: the tools' kinds and names, which say what of the person's own it loaded.
    offered: &'a std::sync::Mutex<Vec<serde_json::Value>>,
}

/// What a part's stage shares with the step that runs it, which reads each once the part is over:
/// whether the closing check found nothing left, whether the login held, each request the part
/// refused, the part's dates and the tools a probe found the agent offer its model.
struct Shared<'a> {
    closed: &'a std::sync::atomic::AtomicBool,
    held: &'a std::sync::atomic::AtomicBool,
    declined: &'a std::sync::Mutex<Vec<String>>,
    dates: &'a [String],
    offered: &'a std::sync::Mutex<Vec<serde_json::Value>>,
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
    /// The names the agent's processes go by in the process table, and whether a process of one of
    /// them that is not the part's own was seen while it ran: whatever it wrote to the person's
    /// data directory is not the part's, so nothing is put back over it.
    agent_names: Vec<String>,
    other_writer: std::sync::atomic::AtomicBool,
    /// Whether a look at the login's files failed while the part ran, so the strings they held at
    /// that moment are not known, and when the process table and the files were last read.
    login_look_failed: std::sync::atomic::AtomicBool,
    last_noted: std::sync::Mutex<Option<std::time::Instant>>,
    /// The person's data directory, where the login's files are read again at each look, and every
    /// string they held at any look: the agent may refresh its token more than once while it runs.
    login_data: Option<PathBuf>,
    login_seen: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// When the files were last read.
    read_at: std::sync::Mutex<Option<std::time::Instant>>,
    /// What changed, once a look found a change: the part stops on it.
    changed: std::sync::Mutex<Option<String>>,
    /// Whether the watcher still reads them.
    watching: std::sync::atomic::AtomicBool,
    /// The probes that run and whether a change has stopped the part, under one lock, so a probe
    /// is either ended by the stop or refused by it, and its group is never signalled once its
    /// leader has been reaped.
    registry: std::sync::Mutex<Registry>,
    /// The agent's processes and its server's, as each launch found them, ended at a change.
    agents: std::sync::Mutex<Vec<ProcessStartIdentity>>,
    /// What a stop on a change ended, and what still ran after it: for the part's outcome.
    stopped: std::sync::Mutex<Option<serde_json::Value>>,
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

    /// Looks at what changes beneath the part without being a file of the person's: every string the
    /// login's files hold now is kept for the search after the part, and a process of the agent's
    /// name that is not the run's is noted. At most once every [`GUARD_WATCH`], by whoever asks.
    fn note(&self, run: &Run, provenance: &Provenance) {
        {
            let Ok(mut last) = self.last_noted.lock() else {
                self.login_look_failed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            };
            if last.is_some_and(|at| at.elapsed() < GUARD_WATCH) {
                return;
            }
            *last = Some(std::time::Instant::now());
        }
        self.look_at_login();
        if self.agent_names.is_empty() {
            return;
        }
        // The part's own are the processes beneath the run's recorded ones, the sessions' root shells
        // and the agent's registered processes, whether or not a launch has registered its agent yet.
        let identities: Vec<ProcessStartIdentity> = run
            .owned()
            .into_iter()
            .map(|owned| owned.identity)
            .chain(provenance.watched())
            .chain(
                self.agents
                    .lock()
                    .map(|agents| agents.clone())
                    .unwrap_or_default(),
            )
            .collect();
        // A number names the process the run recorded only while that process, by its start, still
        // runs: a number an ended process left may name another, whose children are not the part's.
        // A root whose state cannot be established is a reason to put nothing back.
        let mut roots: Vec<u32> = Vec::new();
        let mut unknown = false;
        for identity in &identities {
            match process_state(identity) {
                ProcessState::Running => {
                    if let Ok(pid) = u32::try_from(identity.pid.get()) {
                        roots.push(pid);
                    }
                }
                ProcessState::Ended => {}
                ProcessState::Unknown { .. } => unknown = true,
            }
        }
        roots.sort_unstable();
        roots.dedup();
        if unknown {
            self.other_writer
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let other = match agent_processes_outside(&self.agent_names, &roots) {
            Ok(others) => !others.is_empty(),
            Err(_) => true,
        };
        if other {
            self.other_writer
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// What a look has found changed, once one has.
    fn changed(&self) -> Option<String> {
        self.changed.lock().ok().and_then(|changed| changed.clone())
    }

    /// Records `what` changed and, the first time, ends every process of the part it can reach,
    /// waiting on nothing of the provenance sampler: each probe's process group that runs, under
    /// the registry's lock; then it halts the sampler, which from then on kills each process it
    /// would take, and freezes ([`freeze`]) the run's recorded processes, the sessions' root shells,
    /// the processes each launch found, those the sampler published, and every process beneath
    /// them; then it kills each, and records what it stopped, what it could not confirm stopped,
    /// whether the walk was complete, what ended and what still ran two seconds later.
    fn trip(&self, what: String, run: &Run, provenance: &Provenance) {
        if let Ok(mut changed) = self.changed.lock() {
            changed.get_or_insert(what);
        }
        {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if registry.tripped {
                return;
            }
            registry.tripped = true;
            for group in &registry.probes {
                if let Some(group) = rustix::process::Pid::from_raw(*group) {
                    let _ =
                        rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                }
            }
        }
        let published = provenance.halt();
        let mut roots: Vec<ProcessStartIdentity> = run
            .owned()
            .into_iter()
            .map(|owned| owned.identity)
            .collect();
        roots.extend(provenance.watched());
        roots.extend(
            self.agents
                .lock()
                .map(|agents| agents.clone())
                .unwrap_or_default(),
        );
        roots.extend(published);
        let frozen = freeze(&roots);
        let targets: Vec<&ProcessStartIdentity> = frozen
            .stopped
            .iter()
            .chain(&frozen.unconfirmed)
            .chain(&frozen.unknown)
            .collect();
        for identity in &targets {
            signal(identity, rustix::process::Signal::KILL);
        }
        run.end_everything();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let states = loop {
            let states: Vec<ProcessState> = targets
                .iter()
                .map(|identity| process_state(identity))
                .collect();
            if states
                .iter()
                .all(|state| matches!(state, ProcessState::Ended))
                || std::time::Instant::now() >= deadline
            {
                break states;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let pids_where = |wanted: fn(&ProcessState) -> bool| -> Vec<u64> {
            targets
                .iter()
                .zip(&states)
                .filter(|(_, state)| wanted(state))
                .map(|(identity, _)| identity.pid.get())
                .collect()
        };
        let summary = json!({
            "stopped_confirmed": frozen.stopped.len(),
            "stop_unconfirmed": frozen.unconfirmed.iter().map(|identity| identity.pid.get()).collect::<Vec<_>>(),
            "walk_complete": frozen.complete,
            "walk_failures": frozen.failures,
            "ended": pids_where(|state| matches!(state, ProcessState::Ended)).len(),
            "still_running": pids_where(|state| matches!(state, ProcessState::Running)),
            "state_unknown": pids_where(|state| matches!(state, ProcessState::Unknown { .. })),
        });
        if let Ok(mut stopped) = self.stopped.lock() {
            *stopped = Some(summary);
        }
    }
}

/// How often the watcher reads the files a part watches.
const GUARD_WATCH: Duration = Duration::from_millis(250);

/// Reads the files the part watches every [`GUARD_WATCH`] while it runs, from a thread of its own,
/// so a change is seen whatever the part's own steps wait on: at the first change it ends
/// everything the part started ([`Guards::trip`]); the part then stops on it at its next step,
/// and its outcome says so.
fn watch_guards(guards: &Guards, run: &Run, provenance: &Provenance, needles: &[&str]) {
    while guards.watching.load(std::sync::atomic::Ordering::SeqCst) {
        guards.note(run, provenance);
        if let Some(what) = guards.change(needles).or_else(|| tree_broken(provenance)) {
            guards.trip(what, run, provenance);
            return;
        }
        std::thread::sleep(GUARD_WATCH);
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

/// Stops the watcher of a part's files when the part's own steps end, however they end.
struct StopWatching<'g>(Option<&'g Guards>);

impl Drop for StopWatching<'_> {
    fn drop(&mut self) {
        if let Some(guards) = self.0 {
            guards
                .watching
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// How often a part that waits reads the files it watches again.
const GUARD_EVERY: Duration = Duration::from_millis(500);

/// [`guards_hold`], where the files were not read in the last [`GUARD_EVERY`], and at once where the
/// watcher found a change: for a part's waits, which call it on every turn of their loops.
fn guards_hold_while_waiting(stage: &Stage<'_, '_>) {
    let due = stage.guards.is_some_and(|guards| {
        guards.changed().is_some()
            || guards.read_at.lock().map_or(true, |read_at| {
                read_at.is_none_or(|at| at.elapsed() >= GUARD_EVERY)
            })
    });
    if due {
        guards_hold(stage);
    }
}

/// Stops the part at once when a look at the login's files failed, a file of the person's that no
/// part may change has changed since the part started, or one the person's own programs also write
/// has changed to hold the part's mark or the run's directory; or when either cannot be read; or
/// when the watcher has found so.
fn guards_hold(stage: &Stage<'_, '_>) {
    let Some(guards) = stage.guards else {
        return;
    };
    if let Some(what) = guards.changed() {
        panic!("{GUARD_CHANGED} {what}");
    }
    let root = stage.run.root().display().to_string();
    guards.note(stage.run, stage.provenance);
    if let Some(what) = guards
        .change(&[stage.mark, root.as_str()])
        .or_else(|| tree_broken(stage.provenance))
    {
        // Whichever look sees a change first ends what the part started, before the part stops.
        guards.trip(what.clone(), stage.run, stage.provenance);
        panic!("{GUARD_CHANGED} {what}");
    }
}

/// The person's login as a part that needs it holds it: how the agent runs with it, the budget its
/// turns are charged to, the variable the login is where it is one (read from the harness's pipe,
/// in no environment until the agent's session is given it), and the person's home.
struct Login {
    account: Account,
    ledger: Ledger,
    key: Option<(String, String)>,
    /// The values of the other keys the harness's own shell holds, which no session is given and
    /// which the part's data is searched for.
    others: Vec<String>,
    person_home: PathBuf,
    /// For a confined agent: what its data directory said before the part, read once.
    setup: Option<Setup>,
    /// For a confined agent: the run's proxy, its only way out of the machine.
    proxy: Option<Proxy>,
}

impl Login {
    /// The account the build list names for the agent.
    const fn account(&self) -> &Account {
        &self.account
    }
}

/// What a part leaves for the stage to close.
struct Ending {
    outcome: Outcome,
    /// The sessions it opened, whose terminals end once the host closes them.
    sessions: Vec<Session>,
    /// A daemon it started in place of one it killed.
    replacement: Option<Replacement>,
    /// Local terminals it attached besides its sessions' own, which end once the host closes them.
    windows: Vec<Window>,
}

impl Ending {
    fn new(outcome: Outcome, sessions: Vec<Session>) -> Self {
        Self {
            outcome,
            sessions,
            replacement: None,
            windows: Vec::new(),
        }
    }
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

/// The processes of the agent's names that are not beneath one of `roots`: a process is the part's
/// own when walking up its parents reaches one of them.
///
/// # Errors
///
/// Returns why the process list could not be read.
fn agent_processes_outside(names: &[String], roots: &[u32]) -> Result<Vec<u32>, String> {
    let view = process_view(names)?;
    Ok(outside_of(&view, roots))
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

/// The paths and the proxy port of a confined agent's sandbox, as the system resolves them.
fn layout_of(stage: &Stage<'_, '_>) -> Layout {
    let login = stage.login.expect("a part with a login");
    let confinement = login
        .account
        .confinement
        .as_ref()
        .expect("a confined agent");
    let setup = login.setup.as_ref().expect("a confined agent's setup");
    let resolved = |path: PathBuf| {
        std::fs::canonicalize(&path)
            .unwrap_or_else(|error| panic!("{} as the system names it: {error}", path.display()))
    };
    Layout {
        home: resolved(stage.run.home()),
        work: folder_of(stage.run),
        tmp: resolved(stage.run.root().join("tmp")),
        skills: resolved(stage.run.root().join("skills")),
        agent: resolved(stage.run.root().join("agent")),
        build: resolved(stage.build.prefix.clone()),
        shells: resolved(stage.shell.prefix.clone()),
        data: resolved(login.person_home.join(&confinement.data)),
        bucket: resolved(login.person_home.join(&confinement.data))
            .join("sessions")
            .join(confine::workdir_key(&folder_of(stage.run))),
        history: resolved(login.person_home.join(&confinement.data))
            .join("user-history")
            .join(
                confine::md5_hex(&folder_of(stage.run).display().to_string()).unwrap_or_else(
                    |why| {
                        panic!("{ISOLATION_UNPROVEN} the name of the run's prompt history: {why}")
                    },
                ),
            ),
        file_history: resolved(login.person_home.join(&confinement.data))
            .join("file-history")
            .join(confine::workdir_key(&folder_of(stage.run))),
        slot: setup.slot.clone(),
        proxy_port: login.proxy.as_ref().expect("the run's proxy").port(),
    }
}

/// Before the agent's host starts, for a confined agent: its folder is where the system says it is,
/// with no `.git` above it, its empty skills directory exists, the project file that switches the
/// person's servers off is written, and the folder is trusted, by a record that is the run's own.
///
/// # Panics
///
/// Panics, as an isolation that is not established, when any of it is not so.
fn confine_prepare(login: &Login, run: &Run) {
    let (Some(confinement), Some(setup)) = (&login.account.confinement, &login.setup) else {
        return;
    };
    let folder = folder_of(run);
    if let Some(above) = confine::git_above(&folder) {
        panic!(
            "{ISOLATION_UNPROVEN} a .git lies above the run's folder ({} levels up), so the agent \
             would read instruction files from the directories between them",
            folder
                .ancestors()
                .position(|path| path == above)
                .unwrap_or(0)
        );
    }
    let skills = run.root().join("skills");
    if !skills.is_dir() {
        kr_ipc::paths::create_private_tree(run.root(), &skills)
            .expect("the run's empty skills directory");
    }
    let project = folder.join(&confinement.servers.file);
    if let Some(parent) = project.parent() {
        std::fs::create_dir_all(parent).expect("the project file's directory");
    }
    std::fs::write(
        &project,
        confine::project_servers(
            &setup.servers,
            &confinement.servers.member,
            &confinement.servers.entry,
        ),
    )
    .expect("writes the project file");
    let trust = login
        .person_home
        .join(&confinement.data)
        .join(confine::TRUST);
    confine::write_trust(&trust, &folder, now_ms())
        .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
}

/// At each start of a confined agent: the settings of the person's configuration would let no tool
/// run unasked, the project file is the one written and nothing else is in its directory, and the
/// folder is trusted, so the agent starts none of the person's servers.
///
/// # Panics
///
/// Panics, as an isolation that is not established, when any of it is not so.
fn confine_holds(stage: &Stage<'_, '_>) {
    let login = stage.login.expect("a part with a login");
    let (Some(confinement), Some(setup)) = (&login.account.confinement, &login.setup) else {
        return;
    };
    if let Some(why) = setup.settings.problem() {
        panic!("{ISOLATION_UNPROVEN} {why}");
    }
    let folder = folder_of(stage.run);
    let project = folder.join(&confinement.servers.file);
    let written = std::fs::read_to_string(&project).unwrap_or_default();
    assert!(
        confine::is_project_servers(
            &written,
            &setup.servers,
            &confinement.servers.member,
            &confinement.servers.entry
        ),
        "{ISOLATION_UNPROVEN} the run's project file is not the one that switches the person's \
         servers off"
    );
    let directory = project.parent().expect("the project file's directory");
    let others = std::fs::read_dir(directory)
        .map(|entries| entries.flatten().count())
        .unwrap_or(0);
    assert!(
        others == 1,
        "{ISOLATION_UNPROVEN} the project file's directory holds {others} entries, not the one \
         file written"
    );
    let trust = login
        .person_home
        .join(&confinement.data)
        .join(confine::TRUST);
    assert!(
        confine::trust_records_for(&trust, &folder) == 1,
        "{ISOLATION_UNPROVEN} the run's folder is not trusted by exactly one record"
    );
}

/// How many requests for a conversation's title the agent made during the part, as far as it shows
/// them: the lines of the run's own conversations' logs that name a request that failed, and the
/// run's conversations whose own record says a request titled them. Each is a request to the agent's
/// model that no submission of the part made. Read before the run's sessions are removed.
fn confine_titles(confinement: &Confinement, bucket: &Path) -> Result<u64, String> {
    let titles = &confinement.title_requests;
    let failed = confine::count_marks(bucket, &titles.logs, &titles.log_mark)?;
    let generated = confine::titled_conversations(
        bucket,
        &titles.state_file,
        &titles.state_key,
        &titles.state_value,
    )?;
    Ok(failed + generated)
}

/// What a confined part's search found, made before anything of the run is cleaned up: the strings
/// of the login's files in the run's directory and in what the agent wrote of the run into the
/// person's data directory, and whether the agent started a subagent.
struct Searched {
    /// How many strings were searched for: those read before the part and those the login file
    /// holds now.
    strings: usize,
    /// How many files of the run's directory held one.
    in_run: usize,
    /// How many files of the data directory held one.
    in_data: usize,
    /// How many places of the data directory were searched.
    places: usize,
    /// Whether every place was read whole and the login file could be read again.
    complete: bool,
    /// Why the login file could not be read again, where it could not.
    login_unread: Option<String>,
    /// What shows that the agent started a subagent, where anything does.
    subagent: Option<String>,
    /// How many strings the login's files held at some look while the part ran that they held
    /// neither before the part nor after it: a token the agent refreshed more than once.
    intermediate: usize,
    /// Whether a look at the login's files failed while the part ran.
    look_failed: bool,
    /// Whether a process of the agent's name that is not the run's was seen while the part ran.
    other_writer: bool,
    /// The prompts the agent's own record holds, by who made them, or why they could not be counted.
    wire: Result<confine::WirePrompts, String>,
    /// How many requests for a conversation's title the agent made, as its log and the run's
    /// conversations show them, or why they could not be counted.
    titles: Result<u64, String>,
    /// Every string searched for, kept in memory only: the part's result is held against them
    /// before it is written.
    values: Vec<String>,
}

/// Before a confined part's cleanup, once what it started has ended where it has: the strings of the
/// login's files, as read before the part and as the login file holds them now (the agent may have
/// refreshed its token), are searched for in the run's directory and in every place of the person's
/// data directory the agent writes the run's work to: the run's sessions (the wire files), the
/// run's history and the logs and indexes and every path the build list reports. The run's
/// sessions are also searched for a subagent's start. Nothing of a string is printed.
fn confine_scan(
    login: &Login,
    guards: Option<&Guards>,
    root: &Path,
    rules: &RunRules,
) -> Option<Searched> {
    let (Some(confinement), Some(setup)) = (&login.account.confinement, &login.setup) else {
        return None;
    };
    let data = login.person_home.join(&confinement.data);
    let folder = root.join("w");
    let folder = std::fs::canonicalize(&folder).unwrap_or(folder);
    let bucket = data.join("sessions").join(confine::workdir_key(&folder));
    // The strings read before the part, every string the login's files held at any look while it
    // ran, and those they hold now.
    let mut values = setup.secrets.clone();
    let mut login_unread = None;
    let mut known: std::collections::BTreeSet<String> = values.iter().cloned().collect();
    match confine::login_strings_read(&data) {
        Ok(now) => {
            let (now, refused) = confine::split_searchable(now);
            known.extend(now.iter().cloned());
            values.extend(now);
            if refused {
                login_unread = Some(confine::UNSEARCHABLE.to_owned());
            }
        }
        Err(why) => login_unread = Some(why),
    }
    let mut intermediate = 0;
    if let Some(seen) = guards.map(|guards| {
        guards
            .login_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }) {
        intermediate = seen
            .iter()
            .filter(|string| !known.contains(*string))
            .count();
        values.extend(seen.iter().cloned());
    }
    values.sort();
    values.dedup();
    // What the proxy refused and tunnelled to goes to the part's log before the search, so the
    // search finds nothing the part writes after it.
    if let Some(proxy) = &login.proxy {
        proxy.settle(Duration::from_secs(3));
        let names = proxy.refused_authorities();
        if !names.is_empty() {
            eprintln!("the proxy refused, in order: {}", names.join("; "));
        }
        for tunnel in &proxy.tunnels() {
            eprintln!(
                "the proxy tunnelled to {} through {} at {} ms: {}",
                tunnel.authority,
                tunnel.address,
                tunnel.opened_ms,
                tunnel.carried.map_or_else(
                    || "still open".to_owned(),
                    |(sent, received)| format!("sent {sent} bytes, received {received}")
                )
            );
        }
    }
    let bytes: Vec<&[u8]> = values.iter().map(String::as_bytes).collect();
    let mut places: Vec<PathBuf> = vec![
        bucket.clone(),
        data.join("user-history"),
        data.join("file-history"),
        data.join("logs"),
        data.join("workspaces.json"),
        data.join("device_id"),
        data.join("region"),
        data.join("migrations-effort.json"),
    ];
    // The part's own evidence, written so far: the harness searches it again at the end for the
    // strings it read before and after, and this finds those a second refresh left between them.
    if let Some(evidence) = std::env::var_os(kr_e2e_agents::account::KEY_SCAN_VARIABLE)
        .filter(|value| !value.is_empty())
        .and_then(|value| PathBuf::from(value).parent().map(Path::to_path_buf))
    {
        places.push(evidence);
    }
    places.extend(
        login
            .account
            .recorded
            .iter()
            .chain(&login.account.append_only)
            .map(|relative| login.person_home.join(relative)),
    );
    places.extend(
        confinement
            .reported
            .iter()
            .map(|relative| data.join(relative)),
    );
    places.sort();
    places.dedup();
    // The files that keep the login itself are the strings' source, not a place they must not be.
    places.retain(|place| {
        place.exists()
            && !place.starts_with(data.join("credentials"))
            && !place.starts_with(data.join("oauth"))
    });
    let in_run = run_files_holding_any(root, rules, &bytes);
    let mut in_data = 0;
    let look_failed = guards.is_some_and(|guards| {
        guards
            .login_look_failed
            .load(std::sync::atomic::Ordering::SeqCst)
    });
    let mut complete = login_unread.is_none() && !look_failed && in_run.complete();
    for place in &places {
        let scan = files_holding_any(place, &bytes);
        in_data += scan.held_by.len();
        complete = complete && scan.complete();
    }
    Some(Searched {
        strings: values.len(),
        in_run: in_run.held_by.len(),
        in_data,
        places: places.len(),
        complete,
        login_unread,
        subagent: confine::subagent_started(&bucket),
        intermediate,
        look_failed: guards.is_some_and(|guards| {
            guards
                .login_look_failed
                .load(std::sync::atomic::Ordering::SeqCst)
        }),
        other_writer: guards.is_some_and(|guards| {
            guards
                .other_writer
                .load(std::sync::atomic::Ordering::SeqCst)
        }),
        wire: confine::wire_prompts(&bucket),
        titles: confine_titles(confinement, &bucket),
        values,
    })
}

/// After a confined part, once what it started has ended: what it left of the run in the person's
/// data directory is removed and checked gone (the trust records for its folder, its bucket of
/// sessions), the list of workspaces is compared with the copy taken before it and restored if it
/// changed other than by gaining the run's folder and no other process of the agent runs, and what
/// the search before cleanup found is turned into why the agent stops. Returns the evidence, by
/// counts and booleans, and why the agent stops, where it does.
fn confine_close(
    login: &Login,
    guards: Option<&Guards>,
    (part, root): (&str, &Path),
    ended: bool,
    searched: Option<&Searched>,
) -> (serde_json::Value, Vec<(&'static str, String)>) {
    let (Some(confinement), Some(setup), Some(proxy), Some(searched)) = (
        &login.account.confinement,
        &login.setup,
        &login.proxy,
        searched,
    ) else {
        return (serde_json::Value::Null, Vec::new());
    };
    let mut stop: Vec<(&'static str, String)> = Vec::new();
    let data = login.person_home.join(&confinement.data);
    let folder = root.join("w");
    let folder = std::fs::canonicalize(&folder).unwrap_or(folder);
    let trust = data.join(confine::TRUST);
    let trust_removed = confine::remove_trust(&trust, &folder).unwrap_or_else(|why| {
        stop.push(("run_data_left", why));
        0
    });
    let trust_left = confine::trust_records_for(&trust, &folder);
    let bucket = data.join("sessions").join(confine::workdir_key(&folder));
    let bucket_existed = bucket.exists();
    if ended && bucket_existed {
        let _ = std::fs::remove_dir_all(&bucket);
    }
    let bucket_left = bucket.exists();
    // The record the agent keeps of the files a tool edited, for the run's folder: a refused edit
    // leaves none, and any that exists is the run's own, since its name is the folder's.
    let file_history = data
        .join("file-history")
        .join(confine::workdir_key(&folder));
    let file_history_existed = file_history.exists();
    if ended && file_history_existed {
        let _ =
            std::fs::remove_dir_all(&file_history).or_else(|_| std::fs::remove_file(&file_history));
    }
    let file_history_removed = usize::from(file_history_existed && !file_history.exists());
    if file_history.exists() {
        stop.push((
            "run_data_left",
            "the run's file-history record could not be removed".to_owned(),
        ));
    }
    if trust_left > 0 || bucket_left {
        stop.push((
            "run_data_left",
            format!(
                "what the run left in the person's data directory could not be removed: {trust_left} \
                 trust record(s), its sessions {}",
                if bucket_left { "still there" } else { "gone" }
            ),
        ));
    }
    let workspaces = guards
        .and_then(|guards| guards.workspaces.as_ref())
        .map(|workspaces| {
            let path = login.person_home.join(&workspaces.relative);
            let now = std::fs::read_to_string(&path).map_err(|error| error.to_string());
            let verdict = now.and_then(|now| {
                confine::workspaces_verdict(&workspaces.before, &now, &workspaces.folder)
            });
            // The copy is put back only where nothing else could have written the list: the run's
            // processes ended, no process of the agent's name other than the run's was seen while
            // it ran, and none runs now, since a change that is not the run's folder may be that
            // one's, and the copy would erase it.
            let mut restored = false;
            let mut kept = "it could not be put back";
            if verdict.is_err() {
                let other_seen = guards.is_some_and(|guards| {
                    guards
                        .other_writer
                        .load(std::sync::atomic::Ordering::SeqCst)
                });
                match (
                    ended,
                    other_seen,
                    agent_processes(&confinement.process_names),
                ) {
                    (true, false, Ok(pids)) if pids.is_empty() => {
                        let temporary = path.with_extension("json.kr-restore");
                        restored = write_private_file(&temporary, workspaces.before.as_bytes())
                            .and_then(|()| std::fs::rename(&temporary, &path))
                            .is_ok();
                        let read_again = std::fs::read_to_string(&path).ok();
                        restored =
                            restored && read_again.as_deref() == Some(workspaces.before.as_str());
                        if restored {
                            kept = "the copy taken before the part was put back";
                        }
                    }
                    (true, true, _) | (true, false, Ok(_)) => {
                        kept = "it was not put back, since a process of the agent that is not \
                                the run's ran, or may have, and may have written it";
                    }
                    (true, false, Err(_)) => {
                        kept = "it was not put back, since whether a process of the agent runs \
                                could not be told";
                    }
                    (false, _, _) => {
                        kept = "it was not put back, since something the part started still runs";
                    }
                }
            }
            if verdict.is_err() {
                stop.push((
                    "workspace_list_changed",
                    format!(
                        "the person's list of workspaces changed other than by gaining the run's \
                     folder ({}), and {kept}",
                        verdict.clone().err().unwrap_or_default(),
                    ),
                ));
            }
            (verdict.is_ok(), restored)
        });
    if workspaces.is_some_and(|(additive, _)| additive)
        && let Some(path) = private_copy_path()
    {
        let _ = std::fs::remove_file(path);
    }
    if searched.in_run > 0 || searched.in_data > 0 || !searched.complete {
        stop.push((
            "secret_found",
            format!(
                "{} file(s) of the run's directory and {} of what the agent wrote into the person's \
                 data directory held a string of the login's files, and the search was {}complete{}",
                searched.in_run,
                searched.in_data,
                if searched.complete { "" } else { "not " },
                searched.login_unread.as_ref().map_or_else(
                    || {
                        if searched.look_failed {
                            " (a look at the login's files failed while the part ran)".to_owned()
                        } else {
                            String::new()
                        }
                    },
                    |why| format!(" ({why})")
                )
            ),
        ));
    }
    // Every prompt the agent's own record holds is a request to its model: those the part submitted
    // were charged before they were typed, so the record holds no more, and none of another origin.
    let charged = login.ledger.charged_here();
    let turns = match &searched.wire {
        Ok(wire) => {
            let found = wire.user + wire.steers + wire.other;
            if wire.other > 0 || found > charged {
                let surplus = found.saturating_sub(charged);
                let ledger_says = login
                    .ledger
                    .charge_found(
                        part,
                        "a prompt in the agent's record that the part did not charge",
                        surplus,
                    )
                    .map_or_else(
                        |why| format!("the ledger could not be written: {why}"),
                        |total| format!("the ledger now says {total} spent"),
                    );
                stop.push((
                    "uncharged_turns",
                    format!(
                        "the agent's record holds {} prompt(s) the part typed, {} steering, and {} of \
                         another origin, against {charged} turn(s) charged; {surplus} charged now \
                         ({ledger_says})",
                        wire.user, wire.steers, wire.other
                    ),
                ));
            }
            json!({ "charged": charged, "prompts": wire.user, "steers": wire.steers, "others": wire.other })
        }
        Err(why) => {
            stop.push((
                "uncharged_turns",
                format!("the prompts in the agent's record could not be counted: {why}"),
            ));
            json!({ "charged": charged })
        }
    };
    // A request for a conversation's title is a request to the agent's model that no submission of
    // the part made: each is charged as a turn, beyond the limit where need be, and since the part
    // reserved turns for its own submissions alone, the part stops: the pinned terminal makes none,
    // so one that is seen is a path nobody has looked at.
    let titles = match &searched.titles {
        Ok(count) => {
            if *count > 0 {
                let said = login
                    .ledger
                    .charge_found(
                        part,
                        "a request for a conversation's title that the agent made",
                        *count,
                    )
                    .map_or_else(
                        |why| format!("the ledger could not be written: {why}"),
                        |total| format!("the ledger now says {total} spent"),
                    );
                stop.push((
                    "uncharged_turns",
                    format!(
                        "the agent made {count} request(s) for a conversation's title, which the \
                         part did not reserve turns for; charged as turns ({said})"
                    ),
                ));
            }
            *count
        }
        Err(why) => {
            stop.push((
                "uncharged_turns",
                format!("the agent's requests for a title could not be counted: {why}"),
            ));
            0
        }
    };
    let mut turns = turns;
    turns["titles"] = json!(titles);
    if let Some(why) = &searched.subagent {
        stop.push((
            "subagent_started",
            format!("{SUBAGENT_STARTED} {why}, and its requests to the model are not turns the ledger counts"),
        ));
    }
    let tunnels = proxy.tunnels();
    let by_host: Vec<serde_json::Value> = confinement
        .hosts
        .iter()
        .map(|host| {
            let of_host: Vec<_> = tunnels
                .iter()
                .filter(|tunnel| {
                    tunnel
                        .authority
                        .rsplit_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case(host))
                })
                .collect();
            json!({
                "host": host,
                "tunnels": of_host.len(),
                "sent": of_host.iter().filter_map(|tunnel| tunnel.carried).map(|(sent, _)| sent).sum::<u64>(),
                "received": of_host.iter().filter_map(|tunnel| tunnel.carried).map(|(_, received)| received).sum::<u64>(),
                "open": of_host.iter().filter(|tunnel| tunnel.carried.is_none()).count(),
            })
        })
        .collect();
    let profile = std::fs::read(&confinement.profile).map_or_else(
        |_| "unreadable".to_owned(),
        |bytes| {
            kr_cbor::sha256(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        },
    );
    (
        json!({
            "profile_sha256": profile,
            "proxy": {
                "hosts": confinement.hosts,
                "tunnels": proxy.counts().allowed(),
                "refused": proxy.counts().refused(),
                "by_host": by_host,
            },
            "unasked_tools": confinement.unasked_tools,
            "residuals": confinement.residuals,
            "settings": { "rules": setup.settings.rules, "allow_built_in": setup.settings.allow_built_in, "mode_manual": !setup.settings.mode_not_manual && setup.settings.unlisted == 0, "loads_more": setup.settings.loads_more, "unlisted": setup.settings.unlisted },
            "servers_switched_off": setup.servers.len(),
            "left_in_data": { "trust_records_removed": trust_removed, "trust_records_left": trust_left, "sessions_bucket_existed": bucket_existed, "sessions_bucket_left": bucket_left, "file_history_removed": file_history_removed },
            "workspaces": workspaces.map(|(additive, restored)| json!({ "additive": additive, "restored": restored })),
            "secrets": { "strings": searched.strings, "found_in_run": searched.in_run, "found_in_data": searched.in_data, "places_in_data": searched.places, "intermediate": searched.intermediate, "complete": searched.complete },
            "other_writer_seen": searched.other_writer,
            "subagent_started": searched.subagent.is_some(),
            "turns": turns,
            "new_sessions": NEW_SESSIONS.load(std::sync::atomic::Ordering::SeqCst),
            "resumed_launches": RESUMED_LAUNCHES.load(std::sync::atomic::Ordering::SeqCst),
            "fresh_screen_ms": FRESH_MS.lock().map(|measured| measured.clone()).unwrap_or_default(),
            "zero_turn": ZERO_TURN.lock().map(|zero| zero.clone()).unwrap_or_default(),
        }),
        stop,
    )
}

/// Writes `bytes` to a new file at `path` that only its owner can read or write, and syncs it.
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// What each launch of a confined agent showed before its first turn, by booleans and counts, for
/// the part's evidence: one test runs in a process, so this is the part's.
static ZERO_TURN: std::sync::Mutex<Vec<serde_json::Value>> = std::sync::Mutex::new(Vec::new());

/// How long each fresh screen read before a submission took, in milliseconds, as measured at the
/// composer before any turn: the time a submission's two checks add to the part's own steps.
static FRESH_MS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// How many fresh conversations the part started after its checks.
static NEW_SESSIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many launches of a confined agent resumed a saved conversation and so ran no checks of their
/// own: those of the part's first launch, which showed the same profile, cover them.
static RESUMED_LAUNCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

/// The values of the keys the part holds: its login's own and the other keys the harness's shell
/// holds, which a text the part keeps must not carry.
fn held_keys(stage: &Stage<'_, '_>) -> Vec<String> {
    stage.login.map_or_else(Vec::new, |login| {
        login
            .others
            .iter()
            .cloned()
            .chain(login.key.iter().map(|(_, value)| value.clone()))
            .collect()
    })
}

/// The digits a line of the agent's screen shows after `prefix`, as a status: `kr-zt-3-1007` after
/// `kr-zt-3-` is 7. The typed line itself shows `$((1000+$?))` there, never digits.
fn status_after(rows: &[String], prefix: &str) -> Option<i64> {
    rows.iter().rev().find_map(|row| {
        let at = row.find(prefix)?;
        let digits: String = row[at + prefix.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        (digits.len() == 4)
            .then(|| digits.parse::<i64>().ok())?
            .map(|value| value - 1000)
    })
}

/// Runs one shell line at the confined agent's composer, with the agent's own `!` escape: the agent
/// runs it in its own process tree with no model call and no dialog. Waits for the line's status
/// and returns it with the screen.
fn shell_line(
    logged: &mut Logged,
    stage: &Stage<'_, '_>,
    number: u32,
    line: &str,
) -> (i64, Vec<String>) {
    let prefix = format!("kr-zt-{number}-");
    // The escape is a key of its own: a line that reaches the composer in one write is taken for a
    // paste, whose first character is text, and would be sent to the model as a prompt. Nothing
    // else is typed until the composer shows it is in shell mode.
    // Sent as the terminal's enhanced keyboard protocol reports the key, which the agent reads
    // whether or not it asked for that protocol: a bare `!` in a write of its own was dropped.
    logged.type_text(stage, "\u{1b}[33u");
    let _ = logged.wait_for(
        stage,
        "shell mode",
        "the composer shows its shell mode after the escape, before any shell line is typed",
    );
    logged.type_text(stage, &format!(" {line}; echo {prefix}$((1000+$?))"));
    std::thread::sleep(Duration::from_millis(300));
    let submit = stage
        .login
        .expect("a part with a login")
        .account
        .submit
        .clone();
    logged.type_text(stage, &submit);
    let rows = logged.wait_for(
        stage,
        &format!("{prefix}1"),
        "the agent's shell line reports its status",
    );
    let status = status_after(&rows, &prefix)
        .unwrap_or_else(|| panic!("{ISOLATION_UNPROVEN} the shell line {number} shows no status"));
    (status, rows)
}

/// Before a confined agent's first turn: it shows every one of the person's servers disabled and no
/// tool of theirs; through the agent's own `!` escape, in its own process tree, a read outside the
/// profile is refused where one inside is not, a write outside is refused, a direct connection to a
/// provider address of either family is refused, the run's proxy refuses a host it was not given and
/// tunnels to one it was, and the person's own copy of the agent cannot be run; and no connection
/// of the tree goes anywhere but the run's proxy. A failure stops the agent before a turn.
///
/// # Panics
///
/// Panics, as an isolation that is not established, when anything is otherwise.
fn confine_checks(stage: &Stage<'_, '_>, logged: &mut Logged) {
    let login = stage.login.expect("a part with a login");
    let (Some(confinement), Some(setup), Some(proxy)) =
        (&login.account.confinement, &login.setup, &login.proxy)
    else {
        return;
    };
    let account = login.account();
    let rows = logged.screen.view.rows();
    assert!(
        !rows.iter().any(|row| row.contains("Trust this folder?")),
        "{ISOLATION_UNPROVEN} the agent asks whether to trust the folder, so its record is not the \
         one the agent looks for"
    );
    // The servers: every one of the person's is listed, disabled, and no tool is available.
    logged.type_text(stage, &account.slash.input);
    std::thread::sleep(Duration::from_millis(300));
    logged.type_text(stage, &account.submit);
    let panel = logged.wait_for(stage, &account.slash.shows, "the agent lists its servers");
    let count = setup.servers.len();
    let listed_disabled = setup.servers.iter().all(|name| {
        panel
            .iter()
            .any(|row| row.contains(name.as_str()) && row.contains("disabled"))
    });
    let counted = panel
        .iter()
        .any(|row| row.contains(&format!("{count} disabled")) && row.contains("0 tools available"));
    if !account.dismiss.is_empty() {
        logged.type_text(stage, &account.dismiss);
    }
    let _ = logged.wait_idle(stage, "the composer is back after the server list");
    assert!(
        listed_disabled && counted,
        "{ISOLATION_UNPROVEN} the agent's server list does not show all {count} of the person's \
         servers disabled with no tool available"
    );
    // The canaries: one outside the run, one inside it.
    let token = nonce();
    let outside = std::env::temp_dir().join(format!("krcanary-{token}"));
    let inside = folder_of(stage.run).join("canary-in");
    std::fs::write(&outside, format!("kr-out-{token}")).expect("the outside canary");
    std::fs::write(&inside, format!("kr-in-{token}")).expect("the inside canary");
    let _guards = (Remove(outside.clone()), Remove(outside.with_extension("w")));
    let (read_outside, screen_out) =
        shell_line(logged, stage, 1, &format!("cat '{}'", outside.display()));
    let (read_inside, screen_in) =
        shell_line(logged, stage, 2, &format!("cat '{}'", inside.display()));
    let (write_outside, _) = shell_line(
        logged,
        stage,
        3,
        &format!("echo x > '{}'", outside.with_extension("w").display()),
    );
    let (direct_v4, _) = shell_line(
        logged,
        stage,
        4,
        "/usr/bin/curl --noproxy '*' -4 -sS -m 6 -o /dev/null https://1.1.1.1/",
    );
    let (direct_v6, _) = shell_line(
        logged,
        stage,
        5,
        "/usr/bin/curl --noproxy '*' -6 -sS -m 6 -o /dev/null 'https://[2606:4700:4700::1111]/'",
    );
    let refused_before = proxy.counts().refused();
    let tunnels_before = proxy.counts().allowed();
    let (other_host, _) = shell_line(
        logged,
        stage,
        6,
        "/usr/bin/curl -sS -m 6 -o /dev/null https://example.com/",
    );
    let host = confinement.hosts.first().cloned().unwrap_or_default();
    let (through_proxy, _) = shell_line(
        logged,
        stage,
        7,
        &format!("/usr/bin/curl -sS -m 15 -o /dev/null https://{host}/"),
    );
    let person_copy = login
        .person_home
        .join(&confinement.data)
        .join("bin")
        .join(&stage.build.command);
    let exec_denied = if person_copy.exists() {
        let (status, _) = shell_line(
            logged,
            stage,
            8,
            &format!("'{}' --version >/dev/null 2>&1", person_copy.display()),
        );
        // The shell's own status for a program the kernel refused to run; a program that ran and
        // failed would give another.
        Some(status == 126)
    } else {
        None
    };
    // The keys the parts use at the composer go through the device's keyboard as any other: a
    // digit typed on its own is text, and Ctrl-U clears what was typed. (The approval keys and
    // Ctrl-S act on a dialog and a queued prompt, which only a turn makes.)
    let probe = format!("kr-zk-{token}");
    logged.no_dialog_now(stage, "before the keyboard probe");
    logged.type_text(stage, &probe);
    logged.type_text(stage, "1");
    let typed = logged
        .wait_for(
            stage,
            &format!("{probe}1"),
            "the composer shows what was typed, a digit last",
        )
        .iter()
        .any(|row| row.contains(&format!("{probe}1")));
    logged.type_text(stage, &account.clear);
    let mut cleared = false;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(250));
        if !fresh_rows(stage, &logged.agent.session)
            .iter()
            .any(|row| row.contains(&probe))
        {
            cleared = true;
            break;
        }
    }
    let refused = proxy.counts().refused() > refused_before;
    let tunnelled = proxy.counts().allowed() > tunnels_before;
    let processes: Vec<u32> = logged
        .agent
        .every_process()
        .iter()
        .filter_map(|process| u32::try_from(process.identity.pid.get()).ok())
        .collect();
    let connections = tcp_connections_of(&processes);
    let only_the_proxy = connections.as_ref().is_ok_and(|remotes| {
        remotes
            .iter()
            .all(|remote| remote == &format!("127.0.0.1:{}", proxy.port()))
    });
    let shows_outside = screen_out
        .iter()
        .any(|row| row.contains(&format!("kr-out-{token}")));
    let shows_inside = screen_in
        .iter()
        .any(|row| row.contains(&format!("kr-in-{token}")));
    let result = json!({
        "servers_disabled": count,
        "server_list_complete": listed_disabled && counted,
        "canary_read_outside_refused": read_outside != 0 && !shows_outside,
        "canary_read_inside_works": read_inside == 0 && shows_inside,
        "write_outside_refused": write_outside != 0,
        "direct_connection_v4_refused": direct_v4 == 7,
        "direct_connection_v6_refused": direct_v6 == 7,
        "proxy_refused_a_host_it_was_not_given": other_host != 0 && refused,
        "proxy_tunnelled_to_a_host_it_was_given": through_proxy == 0 && tunnelled,
        "person_copy_cannot_run": exec_denied,
        "connections_only_to_the_proxy": only_the_proxy,
        "connections_seen": connections.as_ref().map_or(0, Vec::len),
        "device_keys_reach_the_composer": typed && cleared,
    });
    if let Ok(mut zero) = ZERO_TURN.lock() {
        zero.push(result.clone());
    }
    let failed: Vec<&str> = result
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, value)| **value == json!(false))
        .map(|(key, _)| key.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "{ISOLATION_UNPROVEN} before any turn the confined agent showed: {}",
        failed.join(", ")
    );
    guards_hold(stage);
}

/// Removes a file when dropped, whatever ended the part.
struct Remove(PathBuf);

impl Drop for Remove {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The remote end of each TCP connection the processes `pids` hold, as `lsof` names them.
fn tcp_connections_of(pids: &[u32]) -> Result<Vec<String>, String> {
    if pids.is_empty() {
        return Ok(Vec::new());
    }
    let list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let output = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-iTCP", "-p", &list, "-Fn"])
        .output()
        .map_err(|error| format!("lsof did not run: {error}"))?;
    // lsof exits 1 when it finds no such connection; any other status means it did not look, and
    // no connection found then says nothing. Its `n` lines name `local->remote` pairs.
    if !matches!(output.status.code(), Some(0 | 1)) {
        return Err(format!(
            "lsof ended with {} and {} bytes of complaint",
            output.status,
            output.stderr.len()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .filter_map(|pair| pair.split_once("->").map(|(_, remote)| remote.to_owned()))
        .collect())
}

/// The part's private copy of the person's list of workspaces, beside the guarded files' record.
fn private_copy_path() -> Option<PathBuf> {
    std::env::var_os(kr_e2e_agents::account::KEY_SCAN_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).with_file_name("workspaces-before.json"))
}

/// Keeps `text` in the part's private copy, owner-only.
fn write_private_copy(text: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(path) = private_copy_path() {
        let _ = std::fs::remove_file(&path);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .unwrap_or_else(|error| panic!("the private copy {}: {error}", path.display()));
    }
}

/// The most of a file in the person's agent directories that is read to tell an append from a
/// rewrite; a larger file that changed is reported as changed and not compared.
const HASH_LIMIT: u64 = 16 << 20;

/// Runs one part that needs the person's login on a stage of its own. The harness runs it only
/// for a build whose list entry names an approved login.
fn on_account_stage(part: &str, test: &str, body: impl FnOnce(&mut Stage<'_, '_>) -> Ending) {
    staged(part, test, true, body);
}

/// The texts of why an agent stops, joined.
fn stop_text(stop: &[(&'static str, String)]) -> String {
    stop.iter()
        .map(|(_, text)| text.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The classes of why an agent stops, each once, as the failures a record publishes.
fn stop_failures(stop: &[(&'static str, String)]) -> Vec<Failure> {
    let mut failures: Vec<Failure> = Vec::new();
    for (class, _) in stop {
        let failure = Failure::AgentStops(class);
        if !failures.contains(&failure) {
            failures.push(failure);
        }
    }
    failures
}

/// Runs one part on a stage of its own, closes the stage, and appends the part's outcome once the
/// closing check has passed.
///
/// A part with a login is also cleaned up after, whatever became of it. Every process it started
/// has ended first: the closing check found so, or, after a part that stopped part way, the run
/// ends everything and checks again; where that check still finds something running, nothing the
/// part left is taken as final, the part fails and its agent stops. Then, where the agent ran with
/// the person's home, what the part created there is compared, its own conversations removed and
/// every other change reported, and an agent that rewrote a file it had is stopped; and where the
/// part carried a key in its session's environment, the run's directory is searched for the key's
/// bytes, which files held it is recorded by path, and the directory is removed and checked gone. A
/// search that could not read everything, or a directory still there, fails the part. A part that
/// stopped part way still records what it left, the process numbers its sessions ran, and whether
/// its agent stops: it stops when its login could not be established.
fn staged(
    part: &str,
    test: &str,
    needs_login: bool,
    body: impl FnOnce(&mut Stage<'_, '_>) -> Ending,
) {
    let Some(inputs) = Inputs::from_environment(part) else {
        return;
    };
    // The first statement after the inputs: every part, with or without a login, is refused here
    // for a build that is not the test's own stand-in, before it starts a probe, a session or an
    // agent.
    closed_for_all_but_the_stand_in(&inputs.build).unwrap_or_else(|why| panic!("{why}"));
    let login = needs_login.then(|| {
        let account = inputs.build.account.clone().unwrap_or_else(|| {
            panic!("part {part} needs a login, and the build list names none for this agent")
        });
        // The login's own key and the other keys the harness's shell holds, whose values the part's
        // data is searched for. A value a result's own syntax could hide cannot be held out or found
        // in one: the part does not start, and from here every panic's message goes through the
        // held-key rule before it is printed.
        let HeldKeys { key, others } = HeldKeys::read(&format!("part {part}"), &account);
        let person_home =
            PathBuf::from(std::env::var_os("HOME").expect("the person's home in HOME"));
        let mut account = account;
        // A confined agent's data directory is read once, before anything starts: which login is in
        // use, what its configuration sets, and which servers it names. Its other logins join the
        // files that may not change, and the one in use those whose change is only recorded.
        let setup = account.confinement.clone().map(|confinement| {
            match agent_processes(&confinement.process_names) {
                Ok(pids) if pids.is_empty() => {}
                Ok(pids) => panic!(
                    "part {part} does not start: {} process(es) of the person's own run the agent, \
                     which shares the data directory the part guards",
                    pids.len()
                ),
                Err(why) => panic!(
                    "{ISOLATION_UNPROVEN} {why}, so whether a process of the person's own runs the \
                     agent was not established"
                ),
            }
            let setup = Setup::read(
                &person_home,
                &confinement.data,
                &confinement.provider,
                &confinement.servers,
            )
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
            account.guarded.extend(setup.other_logins.iter().cloned());
            account.recorded.push(format!(
                "{}/credentials/{}.json",
                confinement.data, setup.slot
            ));
            setup
        });
        let proxy = account.confinement.as_ref().map(|confinement| {
            Proxy::start(Policy::public(&confinement.hosts)).expect("the run's proxy")
        });
        Login {
            ledger: Ledger::from_environment(&account.budget, account.turns),
            account,
            key,
            others,
            person_home,
            setup,
            proxy,
        }
    });
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("part {part}'s managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: part {part}: {why}");
            return;
        }
    };
    let runtime = runtime();
    let mark = nonce();
    let dates = local_dates();
    let directories = login
        .as_ref()
        .map(|login| with_dates(&login.account.directories, &dates))
        .unwrap_or_default();
    // The person's agent directories as the part finds them, before anything starts: whole, or the
    // part does not start, since a file it could not read could later be taken for one it made.
    let person = login
        .as_ref()
        .filter(|login| login.account.home == AccountHome::Person)
        .map(|login| snapshot(&login.person_home, &directories, HASH_LIMIT));
    if let Some(before) = person.as_ref().filter(|before| !before.whole()) {
        // Counted by directory: an entry's own name can be the person's, and this text goes into
        // the record.
        panic!(
            "part {part}: the person's agent directories could not be read whole before it \
             started, so it does not start: entries that could not be read, by directory: {}",
            before
                .unread_by_root()
                .iter()
                .map(|(root, count)| format!("{} ({count})", root.display()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // The person's files no part may change, and those their own programs also write, as the part
    // finds them; and when the login's keychain item was last written.
    let watched = login.as_ref().map(|login| {
        let files: Vec<String> = login
            .account
            .guarded
            .iter()
            .chain(&login.account.shared)
            .chain(&login.account.recorded)
            .cloned()
            .collect();
        let before = guarded_files(&login.person_home, &files, &[]).unwrap_or_else(|why| {
            panic!("part {part}: a file of the person's that must not change cannot be read: {why}")
        });
        let item = login
            .account
            .keychain_item
            .as_ref()
            .map(|service| keychain_item_modified(&login.person_home, service));
        // The files only appended to, the line files among them, whole: each later look compares
        // their earlier bytes.
        let appended_to: Vec<String> = login
            .account
            .append_only
            .iter()
            .chain(&login.account.line_files)
            .cloned()
            .collect();
        let lines = append_only_files(&login.person_home, &appended_to).unwrap_or_else(|why| {
            panic!("part {part}: a file of the person's only appended to cannot be read: {why}")
        });
        (files, before, item, lines)
    });
    let run = Run::start(&format!("part {part}"));
    let root = run.root().to_path_buf();
    let rules = scan_rules(
        &run,
        &inputs.build.pinned,
        std::fs::canonicalize(inputs.build.prefix.join(&inputs.build.pinned))
            .ok()
            .as_deref(),
        &inputs.build.runtime,
    );
    // An agent that keeps its conversations in a database: the files the part reads are exported from
    // it while the part runs and once more, whole, when everything the part started has ended.
    let mirroring = login
        .as_ref()
        .and_then(|login| login.account.mirror.as_ref())
        .map(|mirror| {
            Mirroring::start(
                run.home().join(&mirror.database),
                mirror.query.clone(),
                root.join(mirror::DIRECTORY),
            )
        });
    // The person's list of workspaces before anything starts: it may only gain the run's folder. A
    // copy of its bytes goes to the part's private evidence, for the one case that restores it.
    let workspaces = login.as_ref().and_then(|login| {
        let confinement = login.account.confinement.as_ref()?;
        let relative = format!("{}/workspaces.json", confinement.data);
        let before =
            std::fs::read_to_string(login.person_home.join(&relative)).unwrap_or_else(|error| {
                panic!("{ISOLATION_UNPROVEN} ~/{relative} cannot be read: {error}")
            });
        let folder = std::fs::canonicalize(run.work())
            .unwrap_or_else(|error| panic!("the run's folder as the system names it: {error}"));
        write_private_copy(&before);
        Some(Workspaces {
            relative,
            before,
            folder,
        })
    });
    let guards = login
        .as_ref()
        .zip(watched.as_ref())
        .map(|(login, (files, before, _, lines))| Guards {
            home: login.person_home.clone(),
            files: files.clone(),
            before: before.clone(),
            guarded: login.account.guarded.clone(),
            shared: login.account.shared.clone(),
            append_only: lines.clone(),
            workspaces,
            agent_names: login
                .account
                .confinement
                .as_ref()
                .map(|confinement| confinement.process_names.clone())
                .unwrap_or_default(),
            other_writer: std::sync::atomic::AtomicBool::new(false),
            login_look_failed: std::sync::atomic::AtomicBool::new(false),
            last_noted: std::sync::Mutex::new(None),
            login_data: login
                .account
                .confinement
                .as_ref()
                .map(|confinement| login.person_home.join(&confinement.data)),
            login_seen: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            subagents: login.account.confinement.as_ref().map(|confinement| {
                let folder = std::fs::canonicalize(run.work()).unwrap_or_else(|error| {
                    panic!("the run's folder as the system names it: {error}")
                });
                login
                    .person_home
                    .join(&confinement.data)
                    .join("sessions")
                    .join(confine::workdir_key(&folder))
            }),
            read_at: std::sync::Mutex::new(None),
            changed: std::sync::Mutex::new(None),
            watching: std::sync::atomic::AtomicBool::new(false),
            registry: std::sync::Mutex::new(Registry::default()),
            agents: std::sync::Mutex::new(Vec::new()),
            stopped: std::sync::Mutex::new(None),
        });
    let provenance = Provenance::new(&inputs.build, &run, &shell, part);
    // A process beneath a confined agent whose command line names one of the person's servers is
    // one the part's isolation was to prevent.
    if let Some(setup) = login.as_ref().and_then(|login| login.setup.as_ref()) {
        provenance.forbid_words(setup.servers.clone());
    }
    if needs_login {
        provenance.require_cleared();
    }
    let closed = std::sync::atomic::AtomicBool::new(false);
    let held = std::sync::atomic::AtomicBool::new(false);
    let declined = std::sync::Mutex::new(Vec::new());
    let offered = std::sync::Mutex::new(Vec::new());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_part(
            part,
            &inputs,
            login.as_ref(),
            &mark,
            &shell,
            &runtime,
            &run,
            &provenance,
            Shared {
                closed: &closed,
                held: &held,
                declined: &declined,
                dates: &dates,
                offered: &offered,
            },
            guards.as_ref(),
            body,
        )
    }));
    let login_held = held.load(std::sync::atomic::Ordering::SeqCst);
    // What the watcher of the person's files found changed while the part ran, where anything did:
    // the agent stops on it, whatever the part's own steps then failed on.
    let guard_change = guards.as_ref().and_then(Guards::changed);
    let guard_stop = guards.as_ref().and_then(|guards| {
        guards
            .stopped
            .lock()
            .ok()
            .and_then(|stopped| stopped.clone())
    });
    // What the part left is read only once nothing it started still runs: after the closing
    // check, or, after a part that stopped part way, once the run has ended everything and found
    // nothing left. The run's directory is still there then.
    let closed_now = closed.load(std::sync::atomic::Ordering::SeqCst);
    if !closed_now {
        // A part that stopped before its close: what the sampler found, and could not find, goes
        // to the run, whose own close, now or when it is dropped, requires it ended.
        hand_over(&provenance, &run);
    }
    let writers = if closed_now {
        Ok(())
    } else if needs_login {
        run.end_everything();
        run.remove_loaded_jobs();
        run.nothing_running().map(|_| ())
    } else {
        Ok(())
    };
    // The mirror's last export, once nothing the part started can write the agent's database.
    let mirror_failure = mirroring
        .map(Mirroring::finish)
        .and_then(Result::err)
        .map(|why| format!("the agent's conversations could not be mirrored: {why}"));
    // The search for the login's strings and for a subagent's start comes before anything is
    // cleaned up, so what the cleanup removes was searched.
    let searched = login
        .as_ref()
        .and_then(|login| confine_scan(login, guards.as_ref(), &root, &rules));
    // Every string a result is held out of: the login's files' strings, the login's own value
    // where it is a variable, and the values of the other keys the person's shell holds.
    let secret_values: Vec<String> = searched
        .as_ref()
        .map(|searched| searched.values.clone())
        .unwrap_or_default()
        .into_iter()
        .chain(login.iter().flat_map(|login| {
            login
                .others
                .iter()
                .filter(|value| confine::searchable(value))
                .cloned()
                .chain(
                    login
                        .key
                        .iter()
                        .map(|(_, value)| value.clone())
                        .filter(|value| confine::searchable(value)),
                )
        }))
        .collect();
    let removable: Vec<PathBuf> = login
        .as_ref()
        .map(|login| {
            with_dates(&login.account.removable, &dates)
                .iter()
                .map(|relative| login.person_home.join(relative))
                .collect()
        })
        .unwrap_or_default();
    let home = login.as_ref().zip(person.as_ref()).map(|(login, before)| {
        person_home_report(
            login,
            before,
            (&directories, &removable),
            &mark,
            &root,
            (part, writers.is_ok()),
        )
    });
    let scan = login
        .as_ref()
        .and_then(|login| login.key.as_ref())
        .map(|(name, value)| {
            (
                name.clone(),
                run_files_holding(&root, &rules, value.as_bytes()),
            )
        });
    // The values of the other keys the person's shell holds, searched for in the same directory:
    // no session was given one, so a file that holds one is a leak.
    let others_found = login
        .as_ref()
        .filter(|login| !login.others.is_empty())
        .map(|login| {
            let values: Vec<&[u8]> = login.others.iter().map(String::as_bytes).collect();
            run_files_holding_any(&root, &rules, &values)
        });
    // The configuration directory of the run's own goes whatever became of the part, and is
    // checked gone.
    let config_gone = login
        .as_ref()
        .filter(|login| login.account.config_directory.is_some())
        .map(|_| {
            let directory = root.join(CONFIG_DIRECTORY);
            let _ = std::fs::remove_dir_all(&directory);
            !directory.exists()
        });
    // What a confined agent left of the run in the person's data directory, while the run's directory
    // is still there to search.
    let (confinement_evidence, confinement_stop) =
        login
            .as_ref()
            .map_or((serde_json::Value::Null, Vec::new()), |login| {
                confine_close(
                    login,
                    guards.as_ref(),
                    (part, &root),
                    writers.is_ok(),
                    searched.as_ref(),
                )
            });
    drop(run);
    let mut key_evidence = None;
    let mut key_failure = None;
    if let Some((name, scan)) = scan {
        let _ = std::fs::remove_dir_all(&root);
        let gone = !root.exists();
        record_key_scan(part, &name, &scan, now_ms(), gone);
        if !scan.complete() || !gone || writers.is_err() {
            key_failure = Some(format!(
                "the run's directory that held {name} was {}searched whole ({} entries unread) \
                 {}and is {}gone",
                if scan.complete() { "" } else { "not " },
                scan.unread.len(),
                if writers.is_ok() {
                    ""
                } else {
                    "while something the part started may still have been writing, "
                },
                if gone { "" } else { "not " }
            ));
        }
        key_evidence = Some(json!({
            "variable": name,
            "held_by": scan.held_by.iter().map(|holder| &holder.path).collect::<Vec<_>>(),
            "complete": scan.complete(),
            "run_gone": gone,
        }));
    }
    if let Some(found) = &others_found
        && !found.complete()
        && key_failure.is_none()
    {
        key_failure = Some(format!(
            "the run's directory was not searched whole for the keys the person's shell holds \
             ({} entries unread)",
            found.unread.len()
        ));
    }
    // The person's watched files as the part leaves them: a guarded one changed, or a shared one
    // changed and naming the run's directory or the part's mark, stops the agent.
    let mut watched_evidence = None;
    let mut watched_stop: Vec<(&'static str, String)> = Vec::new();
    if let (Some(login), Some((files, before, item, lines))) = (login.as_ref(), watched.as_ref()) {
        let root_text = root.display().to_string();
        match guarded_files(
            &login.person_home,
            files,
            &[mark.as_str(), root_text.as_str()],
        ) {
            Ok(after) => {
                record_guarded(part, before, &after);
                let mut entries = Vec::new();
                for (first, second) in before.iter().zip(&after) {
                    let changed = first.sha256 != second.sha256;
                    let shared = login.account.shared.contains(&first.relative);
                    let recorded = login.account.recorded.contains(&first.relative);
                    // The digest and the search are of the same bytes.
                    let names_run = changed && second.holds;
                    if changed && !recorded && (!shared || names_run) {
                        watched_stop.push((
                            "guarded_file_changed",
                            format!("~/{} changed", first.relative),
                        ));
                    }
                    entries.push(json!({ "file": format!("~/{}", first.relative), "changed": changed, "size_changed": first.bytes != second.bytes, "modified_changed": first.modified_ns != second.modified_ns, "shared": shared, "recorded_only": recorded, "names_run": names_run }));
                }
                let item_after = login
                    .account
                    .keychain_item
                    .as_ref()
                    .map(|service| keychain_item_modified(&login.person_home, service));
                let rewritten = match (item, &item_after) {
                    (Some(Some(first)), Some(Some(second))) => Some(first != second),
                    _ => None,
                };
                // The lines appended to the files only appended to: every earlier line must still be
                // there. The part's own, those that hold its mark or the run's directory or that name
                // a conversation the part created, are listed with the conversation they name, their
                // time and which of those they hold; the others, someone else's, are only counted.
                let needles = [mark.as_str(), root_text.as_str()];
                let own_conversations: &[String] = home
                    .as_ref()
                    .map_or(&[], |(_, _, _, conversations)| conversations);
                let appended: Vec<serde_json::Value> = lines
                    .iter()
                    .map(|file| {
                        let now = read_if_there(&login.person_home.join(&file.relative));
                        match now.as_ref().map(|now| {
                            appended_since(file.before.as_deref(), now.as_deref())
                        }) {
                            Ok(Some(added)) => {
                                let own: Vec<serde_json::Value> = added
                                    .iter()
                                    .filter_map(|line| {
                                        let (id, time) = line_identity(line);
                                        let marked = holds_any(line, &[mark.as_str()]);
                                        let names_run = holds_any(line, &[root_text.as_str()]);
                                        let created = id
                                            .as_ref()
                                            .is_some_and(|id| own_conversations.contains(id));
                                        (marked || names_run || created).then(|| {
                                            json!({ "id": id, "time": time, "holds_the_mark": marked, "names_the_run_directory": names_run, "names_a_conversation_it_created": created })
                                        })
                                    })
                                    .collect();
                                json!({
                                    "file": format!("~/{}", file.relative),
                                    "earlier_lines_intact": true,
                                    "appended": added.len(),
                                    "own": own,
                                    "others": added.len() - own.len(),
                                })
                            }
                            Ok(None) => {
                                watched_stop.push((
                                    "appended_file_changed",
                                    format!(
                                        "~/{}: a line that was there before the part changed or went",
                                        file.relative
                                    ),
                                ));
                                json!({ "file": format!("~/{}", file.relative), "earlier_lines_intact": false })
                            }
                            Err(error) => {
                                watched_stop.push((
                                    "person_file_unreadable",
                                    format!(
                                        "~/{} cannot be read after the part: {error}",
                                        file.relative
                                    ),
                                ));
                                json!({ "file": format!("~/{}", file.relative), "error": error.to_string() })
                            }
                        }
                    })
                    .collect();
                // The part's own lines in the line files, whose every writer locks the file for
                // each line, go under that lock, once nothing the part started still writes.
                let lines_removed: Vec<serde_json::Value> = if writers.is_ok() {
                    lines
                        .iter()
                        .filter(|file| login.account.line_files.contains(&file.relative))
                        .map(|file| {
                            let relative = &file.relative;
                            match remove_appended_lines(
                                &login.person_home.join(relative),
                                file.before.as_deref(),
                                &needles,
                            ) {
                                Ok(count) => json!({ "file": format!("~/{relative}"), "removed": count }),
                                Err(why) => {
                                    watched_stop.push((
                                        "lines_not_removed",
                                        format!(
                                            "the part's lines could not be removed from ~/{relative}: {why}"
                                        ),
                                    ));
                                    json!({ "file": format!("~/{relative}"), "error": why })
                                }
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                watched_evidence = Some(json!({
                    "files": entries,
                    "appended": appended,
                    "lines_removed": lines_removed,
                    "searched_for": { "mark": mark, "run_directory": root_text },
                    "keychain_item_rewritten": rewritten,
                    "config_directory_removed": config_gone,
                }));
            }
            Err(why) => watched_stop.push((
                "person_file_unreadable",
                format!(
                    "a file of the person's that must not change cannot be read after the part: {why}"
                ),
            )),
        }
    }
    if config_gone == Some(false) {
        watched_stop.push((
            "configuration_directory_left",
            "the run's configuration directory is still there after its removal".to_owned(),
        ));
    }
    // Why the agent stops here, if it does: something the part started outlived it, the person's
    // directories could not be read whole afterwards, the agent rewrote a file it had there, or a
    // file of the person's that must not change did.
    let mut stop = watched_stop;
    stop.extend(confinement_stop);
    if let Some(found) = others_found
        .as_ref()
        .filter(|found| !found.held_by.is_empty())
    {
        stop.push((
            "provider_key_found",
            format!(
                "the value of a key the person's shell holds is in {} file(s) of the run's \
                 directory, which no session was given it in",
                found.held_by.len()
            ),
        ));
    }
    // A look the stop of the watcher did not see: the sample taken once the part's steps ended.
    if guard_change.is_none()
        && let Some(what) = tree_broken(&provenance)
    {
        stop.push(("isolation_not_established", what));
    }
    if let Some(what) = &guard_change {
        stop.push((
            guard_class(what),
            format!(
                "{GUARD_CHANGED} {what}; the part then sent nothing more and tried to stop and kill \
                 every process it could reach (the probe that ran, the run's recorded processes, the \
                 sessions' shells, the agent's processes, those the provenance sampler had taken and \
                 every process beneath them), and recorded {}",
                guard_stop
                    .as_ref()
                    .map_or_else(|| "nothing".to_owned(), ToString::to_string)
            ),
        ));
    }
    if let Err(left) = &writers {
        stop.push((
            "process_outlived_the_run",
            format!(
                "something the part started still ran after the run ended everything, so what it \
                 left is not final: {left}"
            ),
        ));
    }
    if let Some((_, rewrites, whole, _)) = &home {
        if !whole {
            stop.push((
                "agent_directories_unread",
                "the person's agent directories could not be read whole after the part, so \
                 nothing was removed and no edit can be ruled out"
                    .to_owned(),
            ));
        }
        // Counted by directory: a file's own name can be the person's, and this text goes into
        // the record; the part's evidence lists what it may name.
        if !rewrites.is_empty()
            && login
                .as_ref()
                .is_some_and(|login| login.account.stop_on_rewrite)
        {
            stop.push((
                "agent_rewrote_files",
                format!(
                    "the agent rewrote or removed files it had before the part, by directory: {}",
                    rewrites
                        .iter()
                        .map(|(root, count)| match root {
                            Some(root) => format!("{} ({count})", root.display()),
                            None => format!("outside the listed directories ({count})"),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    let mut outcome = match result {
        Ok(outcome) => outcome,
        Err(panic) => {
            // A part that refused a dialog before it failed says so where its failure is read.
            if let Ok(declined) = declined.lock() {
                for note in declined.iter() {
                    eprintln!("a request the part refused before it failed: {note}");
                }
            }
            // A part with a login that stopped part way still says what it left, the process
            // numbers its sessions ran, and whether its agent stops, before its failure goes on.
            if needs_login {
                let raw = panic_text(&*panic);
                let class = if raw.starts_with(LOGIN_UNPROVEN) {
                    Some("login_not_established")
                } else if raw.starts_with(ISOLATION_UNPROVEN) {
                    Some("isolation_not_established")
                } else if raw.starts_with(GUARD_CHANGED) && guard_change.is_none() {
                    Some(guard_class(&raw))
                } else {
                    None
                };
                let said = kept_panic_text(&raw);
                if let Some(class) = class {
                    stop.push((class, said.clone()));
                }
                let mut evidence = serde_json::Map::new();
                evidence.insert("provenance".to_owned(), provenance.evidence());
                evidence.insert("login_held".to_owned(), json!(login_held));
                evidence.insert(
                    "declined_requests".to_owned(),
                    json!(
                        declined
                            .lock()
                            .map(|declined| declined.clone())
                            .unwrap_or_default()
                    ),
                );
                evidence.insert(
                    "tools_offered".to_owned(),
                    json!(
                        offered
                            .lock()
                            .map(|offered| offered.clone())
                            .unwrap_or_default()
                    ),
                );
                if let Some(watched) = &watched_evidence {
                    evidence.insert("person_files".to_owned(), watched.clone());
                }
                if let Some((report, _, _, _)) = &home {
                    evidence.insert("person_home".to_owned(), report.clone());
                }
                if let Some(keys) = &key_evidence {
                    evidence.insert("key".to_owned(), keys.clone());
                }
                if !confinement_evidence.is_null() {
                    evidence.insert("confinement".to_owned(), confinement_evidence.clone());
                }
                if !stop.is_empty() {
                    evidence.insert("stop_agent".to_owned(), json!(true));
                }
                let evidence = serde_json::Value::Object(evidence);
                // The session ran something other than the build, held a variable the build list
                // clears, or its names could not be read, so the part did not test it: not run,
                // as the harness records such a part.
                // The class is read from what the failure said, and the text kept of it is held to
                // the key rule: where it holds a piece of a key, only its first words are kept.
                let not_run = raw
                    .find(NOT_PINNED)
                    .map(|at| (at, Failure::NotPinned))
                    .or_else(|| {
                        raw.starts_with(ENVIRONMENT_NOT_CLEAR)
                            .then_some((0, Failure::EnvironmentNotClear))
                    })
                    .or_else(|| {
                        raw.starts_with(ENVIRONMENT_NOT_READ)
                            .then_some((0, Failure::EnvironmentNotRead))
                    });
                // The part's own code goes with the classes of what stopped the agent.
                let mut failures = match (&not_run, class) {
                    (Some((_, failure)), _) => vec![failure.clone()],
                    (None, None) => vec![Failure::PartFailed],
                    (None, Some(_)) => Vec::new(),
                };
                failures.extend(stop_failures(&stop));
                let outcome = match not_run {
                    Some((at, failure)) if stop.is_empty() => {
                        let said = kept_panic_text(&raw[at..]);
                        Outcome::not_run(part, test, &said, evidence).with_failures(&[failure])
                    }
                    _ if stop.is_empty() => {
                        Outcome::failed(part, test, &said, evidence).with_failures(&failures)
                    }
                    _ => Outcome::failed(
                        part,
                        test,
                        &format!("{said}; and the agent stops here: {}", stop_text(&stop)),
                        evidence,
                    )
                    .with_failures(&failures),
                };
                outcome.without(&secret_values).append(&inputs.result);
            }
            std::panic::resume_unwind(panic)
        }
    };
    if let Some(evidence) = outcome.evidence.as_object_mut() {
        if needs_login {
            evidence.insert("login_held".to_owned(), json!(login_held));
        }
        if let Some(watched) = &watched_evidence {
            evidence.insert("person_files".to_owned(), watched.clone());
        }
        if let Some((report, _, _, _)) = &home {
            evidence.insert("person_home".to_owned(), report.clone());
        }
        if let Some(keys) = &key_evidence {
            evidence.insert("key".to_owned(), keys.clone());
        }
        if !confinement_evidence.is_null() {
            evidence.insert("confinement".to_owned(), confinement_evidence.clone());
        }
    }
    if !stop.is_empty() {
        if let Some(evidence) = outcome.evidence.as_object_mut() {
            evidence.insert("stop_agent".to_owned(), json!(true));
        }
        // What the part itself found wrong stays in the reason, in front of the stop.
        let own = (outcome.outcome == "failed")
            .then(|| outcome.reason.clone())
            .flatten()
            .map(|reason| format!("{reason}; and "))
            .unwrap_or_default();
        outcome = Outcome::failed(
            part,
            test,
            &format!("{own}the agent stops here: {}", stop_text(&stop)),
            outcome.evidence.clone(),
        )
        .with_failures(&stop_failures(&stop));
    }
    if let Some(why) = key_failure {
        outcome = Outcome::failed(part, test, &why, outcome.evidence.clone())
            .with_failures(&[Failure::KeyScanIncomplete]);
    }
    if let Some(why) = mirror_failure {
        outcome = Outcome::failed(part, test, &why, outcome.evidence.clone())
            .with_failures(&[Failure::PartFailed]);
    }
    // The result is held against every string searched for before it is written, and the message
    // of the failure is the one that is kept.
    let outcome = outcome.without(&secret_values);
    let failed = (outcome.outcome == "failed").then(|| outcome.reason.clone().unwrap_or_default());
    outcome.append(&inputs.result);
    if let Some(reason) = failed {
        panic!("part {part} failed: {reason}");
    }
}

/// Gives the run what the provenance sampler found beneath the sessions, before any close: each
/// process it took, which the close requires ended; what it could not find, on which the close
/// fails; and the system programs every search noted, which go to both, so the close requires each
/// ended and the evidence names each.
fn hand_over(provenance: &Provenance, run: &Run) {
    for (pid, path) in provenance.system_programs() {
        run.note_system_program(pid, &path);
    }
    for (pid, path) in run.system_programs() {
        provenance.note_system_program(pid, &path);
    }
    for why in provenance.untracked() {
        run.undiscovered(&why);
    }
    for (identity, command) in provenance.identified() {
        run.record(identity, &format!("beneath a session: {command}"));
    }
}

/// How many files lie under each listed directory, `None` for those under none.
type DirectoryCounts = Vec<(Option<PathBuf>, usize)>;

/// What a part changed in the person's agent directories since `before`: its own conversations,
/// the files it created holding its marker or the run's directory, removed, and every other change
/// reported, with those of the changed files left that hold the marker or the run's directory; the
/// files it had that were rewritten or changed and too large to compare, counted by the listed
/// directory they lie in (`None` for none); and whether the directories were read whole
/// afterwards. Nothing is removed unless they were, and unless everything the part started had
/// ended (`settled`).
fn person_home_report(
    login: &Login,
    before: &kr_e2e_agents::account::Snapshot,
    (directories, removable): (&[String], &[PathBuf]),
    mark: &str,
    root: &Path,
    (part, settled): (&str, bool),
) -> (serde_json::Value, DirectoryCounts, bool, Vec<String>) {
    let after = snapshot(&login.person_home, directories, HASH_LIMIT);
    let found = changes(before, &after);
    let root = root.display().to_string();
    let (removed, left) = if after.whole() && settled {
        remove_created(before, &found, &[mark, &root], removable)
    } else {
        (Vec::new(), found.created.clone())
    };
    // What the part changed and left, the person's own programs' files among them, searched for
    // the part's marker and the run's directory; nothing of it is touched.
    let kept: Vec<PathBuf> = left
        .iter()
        .chain(&found.appended)
        .chain(&found.rewritten)
        .chain(&found.changed_uncompared)
        .cloned()
        .collect();
    let (holding, unsearched) = which_hold(&kept, &[mark, &root]);
    let home = |paths: &[PathBuf]| -> Vec<String> {
        paths
            .iter()
            .map(|path| {
                path.strip_prefix(&login.person_home).map_or_else(
                    |_| path.display().to_string(),
                    |relative| format!("~/{}", relative.display()),
                )
            })
            .collect()
    };
    // The files a confined agent keeps up itself, and the login it refreshes, are reported and
    // never stop it, where each was read whole before and after (a digest is the report's proof of
    // what it rewrote); every other rewrite or removal of a file it had does.
    let upkeep = |path: &Path, removed: bool| {
        login
            .account
            .confinement
            .as_ref()
            .is_some_and(|confinement| {
                let data = login.person_home.join(&confinement.data);
                let hashed = removed || (before.is_hashed(path) && after.is_hashed(path));
                hashed
                    && (confinement
                        .reported
                        .iter()
                        .any(|reported| path.starts_with(data.join(reported)))
                        || (!removed
                            && login.setup.as_ref().is_some_and(|setup| {
                                path == data
                                    .join("credentials")
                                    .join(format!("{}.json", setup.slot))
                            })))
            })
    };
    let rewrites = before.count_paths_by_root(
        found
            .rewritten
            .iter()
            .chain(&found.changed_uncompared)
            .map(PathBuf::as_path)
            .filter(|path| !upkeep(path, false))
            .chain(
                found
                    .removed
                    .iter()
                    .map(PathBuf::as_path)
                    .filter(|path| !upkeep(path, true)),
            ),
    );
    // What the agent's own upkeep rewrote, by listed path: sizes, times and digests only, with the
    // files themselves in the part's private evidence.
    let upkeep_report = login.account.confinement.as_ref().map(|confinement| {
        let data = login.person_home.join(&confinement.data);
        let (published, private) =
            reported_rewrites(&data, &confinement.reported, (before, &after), &found);
        record_rewrites(part, &private);
        published
    });
    let mut report = json!({
        "created_and_removed": home(&removed),
            "created_and_left": home(&left),
            "appended": home(&found.appended),
            "rewritten": home(&found.rewritten),
            "changed_uncompared": home(&found.changed_uncompared),
            "removed_by_something_else": home(&found.removed),
            "left_holding_the_part": home(&holding),
            "left_unsearched": unsearched,
        "read_whole_after": after.whole(),
        "unread_after": after.unread(),
    });
    if let (Some(upkeep_report), Some(object)) = (upkeep_report, report.as_object_mut()) {
        object.insert("upkeep".to_owned(), json!(upkeep_report));
    }
    (
        report,
        rewrites,
        after.whole(),
        removed.iter().map(|file| conversation_id(file)).collect(),
    )
}

/// The part itself on its stage: the host, the owner device, the package, the part's steps, the
/// stage closed, the closing check, and the outcome with what the whole stage observed. `closed`
/// is set once the closing check has found nothing of the part still running.
#[expect(
    clippy::too_many_arguments,
    reason = "the stage's parts, each of which the part reads"
)]
fn run_part(
    part: &str,
    inputs: &Inputs,
    login: Option<&Login>,
    mark: &str,
    shell: &ManagedShell,
    runtime: &tokio::runtime::Runtime,
    run: &Run,
    provenance: &Provenance,
    Shared {
        closed,
        held,
        declined,
        dates,
        offered,
    }: Shared<'_>,
    guards: Option<&Guards>,
    body: impl FnOnce(&mut Stage<'_, '_>) -> Ending,
) -> Outcome {
    if let Some(login) = login {
        confine_prepare(login, run);
    }
    // Before anything starts in the run's home: a keychain of its own, its default there, or, for
    // an agent whose login is a keychain item, the person's login keychain, borrowed.
    let keychain = match login {
        Some(login) if login.account.login_keychain => {
            // The person's own home searches their login keychain already; a run's home is given it.
            if login.account.home == AccountHome::Run {
                borrow_login_keychain(&run.home(), &login.person_home).unwrap_or_else(|why| {
                    panic!("the run's home searches the login keychain: {why}")
                });
            }
            None
        }
        _ => RunKeychain::create(&run.home()),
    };
    place_forwarder(run);
    let host = Host::start(
        run,
        &HostOptions {
            shell_packages: Some(shell.prefix.clone()),
        },
    );
    let mut owner = Owner::pair(&host, runtime);
    let installed = install(
        &host,
        &owner,
        runtime,
        &inputs.generation,
        &inputs.build.package,
    );
    // The sessions an agent is launched in are watched from just before the launch until they have
    // ended, by a thread of their own, with one more look when the part's own steps end; the
    // thread stops when the part ends, however it ends.
    let root_text = run.root().display().to_string();
    let outcome = std::thread::scope(|scope| {
        let _stop = StopSampling(provenance);
        let _sampler = scope.spawn(|| provenance.sample_until_stopped());
        // The person's files are watched while the part's own steps run, the probes among them.
        if let Some(guards) = guards {
            guards
                .watching
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let root_text = root_text.as_str();
            scope.spawn(move || watch_guards(guards, run, provenance, &[mark, root_text]));
        }
        let ending = {
            let _watching = StopWatching(guards);
            // The conversation roots' files before the agent starts.
            let conversations_before = login.map_or_else(Inventory::new, |login| {
                inventory(&roots_of_conversations(login, run, dates))
            });
            let mut stage = Stage {
                build: &inputs.build,
                run,
                host: &host,
                owner: &mut owner,
                runtime,
                shell,
                installed: &installed,
                provenance,
                login,
                mark,
                held,
                declined,
                dates,
                conversations_before: &conversations_before,
                offered,
                guards,
            };
            body(&mut stage)
        };
        provenance.sample_now();
        for session in &ending.sessions {
            session.remote.close();
        }
        owner.close(runtime);
        let stopped = host.stop();
        match ending.replacement {
            // The host's own daemon was killed on purpose, and its stop says so. What else went
            // wrong there is what the closing check below finds still running.
            Some(replacement) => replacement
                .stop()
                .unwrap_or_else(|why| panic!("the replacement daemon: {why}")),
            None => stopped.unwrap_or_else(|why| panic!("the host did not stop cleanly: {why}")),
        }
        for mut session in ending.sessions {
            let _ = session.window.exit_code(LIVENESS);
        }
        for mut window in ending.windows {
            let _ = window.exit_code(LIVENESS);
        }
        ending.outcome
    });
    hand_over(provenance, run);
    let checked = run
        .closing_check()
        .unwrap_or_else(|left| panic!("still running after part {part}: {left}"));
    closed.store(true, std::sync::atomic::Ordering::SeqCst);
    println!("{checked}");
    drop(keychain);
    provenance.finish().unwrap_or_else(|why| panic!("{why}"));
    let mut outcome = outcome;
    if let Some(evidence) = outcome.evidence.as_object_mut() {
        evidence.insert("provenance".to_owned(), provenance.evidence());
        evidence.insert(
            "installed".to_owned(),
            json!({
                "plugin_id": installed.plugin_id.to_string(),
                "version": installed.version,
                "manifest_digest": installed.package_digest,
                "grant": installed.grant,
            }),
        );
    }
    outcome
}

/// The agent as a part runs it: its session, its processes, and the session its terminal route's
/// server runs in, where it has one.
struct Agent {
    session: Session,
    processes: Vec<AgentProcess>,
    server: Option<(Session, Vec<AgentProcess>)>,
}

impl Agent {
    /// Every process the agent's execution is: its own and its server's.
    fn every_process(&self) -> Vec<&AgentProcess> {
        self.processes
            .iter()
            .chain(
                self.server
                    .iter()
                    .flat_map(|(_, processes)| processes.iter()),
            )
            .collect()
    }

    fn sessions(self) -> Vec<Session> {
        let mut sessions = vec![self.session];
        sessions.extend(self.server.map(|(session, _)| session));
        sessions
    }
}

/// Links the build, prepares the run's home and returns the session environment.
fn prepare(stage: &Stage<'_, '_>, prefix: &Path) -> (Installation, Vec<(String, String)>) {
    let installation = Installation::link(stage.run, prefix, &stage.build.runtime);
    let variables = session_variables(
        stage.host,
        stage.shell,
        &stage.build.environment,
        closed_port(),
    );
    prepare_home(stage.host, &variables);
    let home = stage.run.home();
    for (relative, content) in &stage.build.home {
        let path = home.join(relative);
        assert!(
            path.starts_with(&home) && !relative.contains(".."),
            "a home file stays in the home: {relative}"
        );
        if let Some(directory) = path.parent() {
            std::fs::create_dir_all(directory).expect("the home file's directory");
        }
        std::fs::write(&path, content).expect("writes the home file");
    }
    (installation, variables)
}

/// Where a part's sessions run: in the person's desktop for an agent whose login is a keychain
/// item, and in the host's headless context otherwise.
fn context_of(stage: &Stage<'_, '_>) -> Context {
    if stage
        .login
        .is_some_and(|login| login.account.login_keychain)
    {
        Context::Desktop
    } else {
        Context::Headless
    }
}

/// Starts the agent as the part says, where a refusal of the agent to run is an answer (`refusal` is `Some`, with
/// the texts it shows): the session the agent was started in comes back with what refused it.
fn start_agent_or_refusal(
    stage: &Stage<'_, '_>,
    variables: &[(String, String)],
    what: &str,
    extra: &[String],
    ready: &str,
    refusal: Option<&[String]>,
) -> Result<Agent, Box<(Session, Refused)>> {
    let port = free_port();
    let server = stage.build.server.as_ref().map(|server| {
        let session = open_session(
            stage.host,
            stage.owner,
            stage.runtime,
            stage.shell,
            variables,
            &format!("{what}'s server"),
            context_of(stage),
        );
        let mut words = vec![stage.build.command.clone()];
        words.extend(
            server
                .arguments
                .iter()
                .map(|argument| quote(&argument.replace("{port}", &port.to_string()))),
        );
        let processes = launch(
            stage.run,
            &session,
            (&words.join(" "), &server.ready, &stage.build.command),
            stage.provenance,
            &Expected::pinned(stage.build),
            &|| guards_hold(stage),
        );
        register_for_guards(stage, &processes);
        // The line that says it listens can come before the server answers requests.
        let listening = std::time::Instant::now();
        while !serves(port, server.health.as_deref()) {
            assert!(
                listening.elapsed() < LIVENESS,
                "the server answers on port {port}"
            );
            guards_hold_while_waiting(stage);
            std::thread::sleep(Duration::from_millis(200));
        }
        (session, processes)
    });
    let session = open_session(
        stage.host,
        stage.owner,
        stage.runtime,
        stage.shell,
        variables,
        what,
        context_of(stage),
    );
    let confined = stage
        .login
        .and_then(|login| login.account.confinement.as_ref());
    let line = if let Some(confinement) = confined {
        // The system's sandbox program applies the profile and executes the agent in the same
        // process: the run's proxy is the only way out, and the agent is the shell's own child.
        let mut arguments: Vec<String> = stage
            .build
            .arguments
            .iter()
            .map(|argument| argument.replace("{port}", &port.to_string()))
            .collect();
        arguments.extend(extra.iter().cloned());
        confine::sandbox_words(
            &confinement.profile,
            &layout_of(stage),
            &stage.build.command,
            &arguments,
        )
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" ")
    } else {
        let mut line = stage.build.command_line(port);
        for word in extra {
            line.push(' ');
            line.push_str(&quote(word));
        }
        line
    };
    let processes = match launch_or_refusal(
        stage.run,
        &session,
        (&line, ready, &stage.build.command),
        refusal,
        stage.provenance,
        &Expected::pinned(stage.build),
        &|| guards_hold(stage),
    ) {
        Ok(processes) => processes,
        Err(refused) => return Err(Box::new((session, refused))),
    };
    register_for_guards(stage, &processes);
    Ok(Agent {
        session,
        processes,
        server,
    })
}

/// Gives the watcher of the person's files the processes a launch found, which it ends at a change.
fn register_for_guards(stage: &Stage<'_, '_>, processes: &[AgentProcess]) {
    if let Some(mut agents) = stage.guards.and_then(|guards| guards.agents.lock().ok()) {
        agents.extend(processes.iter().map(|process| process.identity.clone()));
    }
}

/// Whether a server on the loopback `port` serves: it takes a connection and, where `health` names
/// a path, answers a request for it with status 200.
fn serves(port: u16, health: Option<&str>) -> bool {
    use std::io::{Read as _, Write as _};
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let Some(path) = health else {
        return true;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut status = [0_u8; 12];
    stream.read_exact(&mut status).is_ok() && status.ends_with(b" 200")
}

/// What the host shows about the agent in `session` once it has had time to detect it: the
/// session's live instances, the one instance's binding as a device reads it, and how many live
/// bindings hold the package.
fn detect(stage: &Stage<'_, '_>, session: &Session) -> Shown {
    let detection = wait_for_detection(&session.remote, stage.runtime, session.session_id, &|| {
        guards_hold_while_waiting(stage)
    });
    shown_from(stage, session, detection)
}

/// What the host shows about the agent in `session` now, with no wait.
fn shown_now(stage: &Stage<'_, '_>, session: &Session) -> Shown {
    let detection = Detection {
        instances: announced_now(&session.remote, stage.runtime, session.session_id),
        waited_ms: 0,
    };
    shown_from(stage, session, detection)
}

fn shown_from(stage: &Stage<'_, '_>, session: &Session, detection: Detection) -> Shown {
    let binding = detection.only().and_then(|instance| {
        capabilities_of(
            &session.remote,
            stage.runtime,
            AgentSubject {
                session_id: session.session_id,
                application_instance_id: instance.application_instance_id,
            },
        )
        .ok()
    });
    let live_bindings = live_bindings(
        &stage.owner.remote,
        stage.runtime,
        &stage.installed.plugin_id,
    );
    Shown {
        detection,
        binding,
        live_bindings,
    }
}

/// The agent as it was launched: the installed package, and whether every process of its
/// execution still runs.
fn launched(stage: &Stage<'_, '_>, agent: &Agent) -> Launched {
    Launched {
        plugin_id: stage.installed.plugin_id.clone(),
        running: still_running(&agent.every_process()).is_ok(),
    }
}

/// The typed surface a device reaches for the agent in `session`: each typed agent mutation and
/// each of the package's upstream actions sent for the instance the host announced, at its binding
/// revision (a fresh identifier where it announced none), the capability records, the pending
/// resources and every command backend in the host's runtime directory. The agent reads, which a
/// device is served under its grant, come back apart from the mutations.
fn surface(stage: &Stage<'_, '_>, session: &Session, shown: &Shown) -> (Surface, Vec<Answer>) {
    let upstream: Vec<Action> = stage
        .build
        .actions
        .iter()
        .filter(|action| action.upstream())
        .cloned()
        .collect();
    let answers = typed_actions(
        &session.remote,
        stage.runtime,
        session.session_id,
        &stage.installed.plugin_id,
        &upstream,
        Held::of(shown).map(|held| (held.instance, held.revision)),
    );
    let (reads, mutations): (Vec<Answer>, Vec<Answer>) = answers
        .into_iter()
        .partition(|answer| AGENT_READS.contains(&answer.call.as_str()));
    let snapshot = events_snapshot(&session.remote, stage.runtime, session.session_id);
    let resources = snapshot.agent_resources.resources.len()
        + usize::from(snapshot.agent_resources.continue_after.0.is_some());
    (
        Surface {
            records: Surface::records_of(shown.binding.as_ref()),
            answers: mutations,
            resources,
            backend_files: backend_files(stage.host.roots().runtime_root()),
        },
        reads,
    )
}

/// A session's environment, variable by variable.
type Variables = Vec<(String, String)>;

/// Links the build and prepares the run's home as a part without a login does, and returns the
/// environment of the host's own steps and that of the agent's session: the login's home, the
/// person's USER and LOGNAME, no proxy variable, and, where the login is a variable, that variable,
/// which only the agent's session is given.
fn prepare_login(stage: &Stage<'_, '_>) -> (Installation, Variables, Variables) {
    let login = stage.login.expect("a part with a login");
    let (installation, setup) = prepare(stage, &stage.build.prefix.clone());
    let mut variables: Vec<(String, String)> = setup
        .iter()
        .filter(|(name, _)| !PROXY_VARIABLES.contains(&name.as_str()))
        .cloned()
        .collect();
    if login.account.home == AccountHome::Person && login.account.confinement.is_none() {
        for (name, value) in &mut variables {
            if name == "HOME" {
                *value = login.person_home.display().to_string();
            }
        }
    }
    for name in ["USER", "LOGNAME"] {
        if let Ok(value) = std::env::var(name) {
            variables.push((name.to_owned(), value));
        }
    }
    if let Some((name, value)) = &login.key {
        variables.push((name.clone(), value.clone()));
    }
    for (name, value) in &login.account.variables {
        variables.retain(|(existing, _)| existing != name);
        variables.push((name.clone(), value.clone()));
    }
    // A confined agent keeps the run's own home, gets the person's data directory by its variable,
    // and reaches the network through the run's proxy alone.
    if let (Some(confinement), Some(proxy)) = (&login.account.confinement, &login.proxy) {
        let data = login.person_home.join(&confinement.data);
        variables.retain(|(existing, _)| existing != &confinement.variable);
        variables.push((confinement.variable.clone(), data.display().to_string()));
        for name in &confinement.proxy_variables {
            variables.retain(|(existing, _)| existing != name);
            variables.push((name.clone(), proxy.url()));
        }
    }
    if let Some(config) = &login.account.config_directory {
        let directory = stage.run.root().join(CONFIG_DIRECTORY);
        if !directory.is_dir() {
            kr_ipc::paths::create_private_tree(stage.run.root(), &directory)
                .expect("the run's configuration directory");
        }
        for (relative, content) in &config.files {
            let path = directory.join(relative);
            assert!(
                path.starts_with(&directory) && !relative.contains(".."),
                "a configuration file stays in its directory: {relative}"
            );
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("the configuration file's directory");
            }
            std::fs::write(&path, content).expect("writes the configuration file");
        }
        variables.retain(|(existing, _)| existing != &config.variable);
        variables.push((config.variable.clone(), directory.display().to_string()));
    }
    // Whatever put one there, the session gets no variable the account clears but the ones the
    // build list sets itself.
    let _ = stage.build.without_provider_keys(&mut variables);
    (installation, setup, variables)
}

/// Where the agent keeps its conversations in a part with a login: under its configuration
/// directory of the run's own where it has one, and under the home it runs with otherwise; one
/// directory for each of the part's dates where the build list's path has `{date}`.
fn conversation_roots(stage: &Stage<'_, '_>) -> Vec<PathBuf> {
    roots_of_conversations(
        stage.login.expect("a part with a login"),
        stage.run,
        stage.dates,
    )
}

/// Where the agent keeps its conversations for a part with `login` in `run`, on `dates`.
fn roots_of_conversations(login: &Login, run: &Run, dates: &[String]) -> Vec<PathBuf> {
    // An agent that keeps its conversations in a database has them read from the mirror's files.
    if login.account.mirror.is_some() {
        return vec![run.root().join(mirror::DIRECTORY)];
    }
    let base = if login.account.config_directory.is_some() {
        run.root().join(CONFIG_DIRECTORY)
    } else {
        match login.account.home {
            AccountHome::Run => run.home(),
            AccountHome::Person => login.person_home.clone(),
        }
    };
    // Where a confined agent files a folder's conversations is named by the folder.
    let bucket = login.account.confinement.is_some().then(|| {
        confine::workdir_key(&std::fs::canonicalize(run.work()).unwrap_or_else(|_| run.work()))
    });
    with_dates(std::slice::from_ref(&login.account.conversations), dates)
        .iter()
        .map(|relative| match &bucket {
            Some(bucket) => base.join(relative.replace("{bucket}", bucket)),
            None => base.join(relative),
        })
        .collect()
}

/// The identifier of the conversation `file` holds: the member of its first line the build list names,
/// where it names one, else what its name and place say.
fn conversation_id_of(account: &Account, file: &Path) -> String {
    account
        .conversation_id_member
        .as_deref()
        .and_then(|member| {
            let text = std::fs::read_to_string(file).ok()?;
            let first: serde_json::Value = serde_json::from_str(text.lines().next()?).ok()?;
            first[member].as_str().map(str::to_owned)
        })
        .unwrap_or_else(|| conversation_id(file))
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

/// The local dates a part's `{date}` stands for, as `YYYY/MM/DD`: today, as the system's own clock
/// and time zone give it, and tomorrow, since a session the part starts after midnight files under
/// the day it starts.
fn local_dates() -> Vec<String> {
    let date = |arguments: &[&str]| -> String {
        let mut command = std::process::Command::new("/bin/date");
        command.args(arguments);
        let output =
            output_within(command, LIVENESS).unwrap_or_else(|why| panic!("the local date: {why}"));
        assert!(
            output.status.success(),
            "the local date: date exited {}",
            output.status
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    vec![date(&["+%Y/%m/%d"]), date(&["-v+1d", "+%Y/%m/%d"])]
}

/// The directories named, for a failure message.
fn listed(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The files the build list says must not exist before the agent starts, which `which` selects, with
/// each template filled in for the part's run, the home the agent runs with and the person's own.
fn absent_paths(stage: &Stage<'_, '_>, which: Absent) -> Vec<PathBuf> {
    let login = stage.login.expect("a part with a login");
    kr_e2e_agents::held::absent_paths(
        login.account(),
        stage.run,
        &login_home(stage),
        &login.person_home,
        &folder_of(stage.run),
        which,
    )
}

/// The home the agent runs with in a part with a login.
fn login_home(stage: &Stage<'_, '_>) -> PathBuf {
    let login = stage.login.expect("a part with a login");
    match login.account.home {
        AccountHome::Run => stage.run.home(),
        // A confined agent runs with the run's own home, and only keeps its data in the person's.
        AccountHome::Person if login.account.confinement.is_some() => stage.run.home(),
        AccountHome::Person => login.person_home.clone(),
    }
}

/// An agent started with the person's login: its session, the device's view of its screen, the
/// device's keyboard holding the input lease, and the turns this part charged to the budget.
struct Logged {
    agent: Agent,
    screen: Watch,
    keyboard: Keyboard,
    part: &'static str,
    turns: u64,
}

impl Logged {
    /// Starts the agent with its login's arguments and `extra`, watches it from the device and takes
    /// the input lease, and brings it to its composer: through the build list's first steps, or,
    /// where `ready` names the first screen of a start that has none, from there. The login is
    /// checked first, where the agent has a status command; a start that does not reach the
    /// composer is taken as a login that cannot be established.
    fn start(
        stage: &Stage<'_, '_>,
        variables: &[(String, String)],
        what: &str,
        part: &'static str,
        extra: &[String],
        ready: Option<&str>,
    ) -> Self {
        Self::start_with(stage, variables, what, part, extra, ready, None).unwrap_or_else(
            |refused: Box<(Session, Refused)>| {
                panic!(
                    "{what}: the agent was refused where it was expected to start: {}",
                    refused.1
                )
            },
        )
    }

    /// [`Logged::start`], where a refusal of the agent to run is an answer (`refusal` is `Some`,
    /// with the texts it shows): its session comes back with what refused it, to be ended with the
    /// part's.
    fn start_with(
        stage: &Stage<'_, '_>,
        variables: &[(String, String)],
        what: &str,
        part: &'static str,
        extra: &[String],
        ready: Option<&str>,
        refusal: Option<&[String]>,
    ) -> Result<Self, Box<(Session, Refused)>> {
        login_holds(stage, variables);
        keychain_readable_in_a_session(stage, variables);
        let reached = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::reach_composer(stage, variables, what, part, extra, ready, refusal)
        }))
        .unwrap_or_else(|panic| {
            // A session that ran something other than the build, whose exported names refuse or
            // could not be read, or in which a file of the person's changed or the agent's
            // isolation could not be shown, says so, and is not a login that cannot be
            // established.
            let said = panic_text(&*panic);
            if [
                NOT_PINNED,
                ENVIRONMENT_NOT_CLEAR,
                ENVIRONMENT_NOT_READ,
                GUARD_CHANGED,
                ISOLATION_UNPROVEN,
            ]
            .iter()
            .any(|prefix| said.starts_with(prefix))
            {
                std::panic::resume_unwind(panic);
            }
            panic!(
                "{LOGIN_UNPROVEN} the agent did not reach its composer with it: {}",
                kept_panic_text(&said)
            )
        });
        let mut logged = reached?;
        // The composer's own screen says so where the agent found no login, before any turn.
        let account = stage.login.expect("a part with a login").account();
        let rows = logged.screen.view.rows();
        if let Some(shown) = account
            .signed_out
            .iter()
            .find(|text| rows.iter().any(|row| row.contains(text.as_str())))
        {
            panic!(
                "{LOGIN_UNPROVEN} the agent's composer shows {shown:?} before any turn:\n{}",
                rows.join("\n")
            );
        }
        // A launch that resumes a saved conversation runs none of the checks: an earlier launch of
        // the part showed the same sandbox, proxy and files, and a shell line typed now would go
        // into the conversation the part resumes.
        let resumes = [&account.resume, &account.fork]
            .into_iter()
            .filter_map(|words| words.first())
            .any(|word| extra.first() == Some(word));
        if resumes {
            if stage
                .login
                .is_some_and(|login| login.account.confinement.is_some())
            {
                RESUMED_LAUNCHES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        } else {
            confine_checks(stage, &mut logged);
        }
        // The checks' shell lines are in the agent's record of its first conversation, and would go
        // to its model with the first prompt: a launch that does not resume one starts a fresh
        // conversation for the part's own turns.
        if !resumes
            && let Some(new_session) = stage
                .login
                .and_then(|login| login.account.confinement.as_ref())
                .and_then(|confinement| confinement.new_session.as_ref())
        {
            logged.type_text(stage, &new_session.input);
            std::thread::sleep(Duration::from_millis(300));
            logged.type_text(stage, &account.submit);
            let _ = logged.wait_for(
                stage,
                &new_session.shows,
                "the agent starts a fresh conversation",
            );
            let _ = logged.wait_idle(stage, "the composer is back after the fresh conversation");
            NEW_SESSIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        // What the two fresh screen reads of a submission cost, measured here where no turn can be
        // affected: three reads, each from opening a new attachment to its drawn screen. Only for
        // an agent that is confined: the others' parts are as they were.
        let measured_runs = if stage
            .login
            .is_some_and(|login| login.account.confinement.is_some())
        {
            3
        } else {
            0
        };
        for _ in 0..measured_runs {
            let started = std::time::Instant::now();
            logged.no_dialog_now(stage, "in the measurement before any turn");
            if let Ok(mut measured) = FRESH_MS.lock() {
                measured.push(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            }
        }
        guards_hold(stage);
        assert!(
            !account.stop_before_turns,
            "the part stops once the agent is up and the checks before its first turn have passed, \
             as the build list asks: no turn was started"
        );
        Ok(logged)
    }

    /// [`Logged::start`] without its checks.
    fn reach_composer(
        stage: &Stage<'_, '_>,
        variables: &[(String, String)],
        what: &str,
        part: &'static str,
        extra: &[String],
        ready: Option<&str>,
        refusal: Option<&[String]>,
    ) -> Result<Self, Box<(Session, Refused)>> {
        let account = stage.login.expect("a part with a login").account();
        let mut arguments = account.arguments.clone();
        arguments.extend(switches_of(stage));
        arguments.extend(extra.iter().cloned());
        let first = ready.unwrap_or(&account.ready).to_owned();
        // The last look before the agent starts.
        guards_hold(stage);
        let agent = start_agent_or_refusal(stage, variables, what, &arguments, &first, refusal)?;
        let mut screen = watch(stage, &agent.session, &first);
        let mut keyboard = keyboard(stage, &agent.session);
        if ready.is_none() {
            for keys in &account.prepare {
                let _ = keyboard
                    .type_text(&agent.session.remote, stage.runtime, &keys.input)
                    .unwrap_or_else(|why| panic!("{why}"));
                let _ = screen.wait_for(
                    stage,
                    &agent.session,
                    &keys.shows,
                    "the agent reaches its composer",
                );
            }
        }
        let _ = screen.wait_for(
            stage,
            &agent.session,
            &account.composer,
            "the composer waits for a prompt",
        );
        Ok(Self {
            agent,
            screen,
            keyboard,
            part,
            turns: 0,
        })
    }

    /// Types `text` through the device's keyboard, which holds the lease.
    fn type_text(&mut self, stage: &Stage<'_, '_>, text: &str) {
        let _ = self
            .keyboard
            .type_text(&self.agent.session.remote, stage.runtime, text)
            .unwrap_or_else(|why| panic!("{why}"));
    }

    /// Charges one turn to the budget, then types `text` at the composer and submits it. Until the
    /// agent answers it, the part holds no proof that its login still holds.
    fn submit(&mut self, stage: &Stage<'_, '_>, text: &str, what: &str) {
        let key = stage
            .login
            .expect("a part with a login")
            .account
            .submit
            .clone();
        self.submit_with(stage, text, what, &key);
    }

    /// [`Logged::submit`] with `key` in place of the submit key: the key that queues a prompt
    /// behind a running turn, where the agent has one of its own.
    fn submit_with(&mut self, stage: &Stage<'_, '_>, text: &str, what: &str, key: &str) {
        guards_hold(stage);
        let login = stage.login.expect("a part with a login");
        // A dialog the agent raised before this takes a typed digit as a choice, and the key that
        // submits picks the choice shown first, which may approve a command or change the agent's
        // mode: a fresh screen is read before the text is typed, which is before the turn is charged
        // (nothing has gone to the agent yet), and again before the key goes, and a dialog on either
        // is refused and fails the part.
        self.no_dialog_now(stage, "before the part typed a prompt");
        let _ = login
            .ledger
            .charge(self.part, what)
            .unwrap_or_else(|why| panic!("{why}"));
        stage.held.store(false, std::sync::atomic::Ordering::SeqCst);
        self.turns += 1;
        self.type_text(stage, text);
        // An agent that is busy drawing a reply can take what was typed late, and the line end
        // typed after it then arrives with it, as one paste whose line end is text and not a
        // submission: the submission waits until the screen shows what was typed (ten seconds at
        // most, after which the part goes on and its own checks say what happened), and then for
        // a moment, so that it arrives on its own.
        let shown_by = std::time::Instant::now() + Duration::from_secs(10);
        while !typed_text_shows(&self.screen.view.rows(), text)
            && std::time::Instant::now() < shown_by
        {
            guards_hold_while_waiting(stage);
            self.screen.pump(stage, Duration::from_millis(200));
        }
        std::thread::sleep(Duration::from_millis(300));
        self.no_dialog_now(stage, "where the part was about to submit");
        self.type_text(stage, key);
    }

    /// Reads a fresh screen of the session, as a new attachment is drawn it, and where a dialog of
    /// the agent's shows refuses it with the agent's own key and fails the part: a cached view that
    /// had stopped updating would hide one.
    fn no_dialog_now(&mut self, stage: &Stage<'_, '_>, when: &str) {
        let account = stage.login.expect("a part with a login").account();
        let rows = fresh_rows(stage, &self.agent.session);
        if let Some(shown) = Self::dialogs(account)
            .into_iter()
            .find(|needle| rows.iter().any(|row| row.contains(needle)))
        {
            let key = if shown == account.approval.shows {
                account.approval.deny.clone()
            } else {
                account.approval.refusal().to_owned()
            };
            self.type_text(stage, &key);
            if let Ok(mut declined) = stage.declined.lock() {
                declined.push(format!(
                    "a dialog showing {shown:?} {when}, refused with {key:?}"
                ));
            }
            panic!(
                "a dialog showing {shown:?} was on the screen {when}, so no prompt or key that \
                 submits was sent"
            );
        }
    }

    /// Waits until the device's view shows `needle`, text only the agent's model could have
    /// answered, and takes it as the vendor having accepted the login in this part.
    fn answered(&mut self, stage: &Stage<'_, '_>, needle: &str, why: &str) -> Vec<String> {
        let rows = self.wait_for(stage, needle, why);
        stage.held.store(true, std::sync::atomic::Ordering::SeqCst);
        rows
    }

    /// The texts of every permission dialog the agent raises: its command dialog first.
    fn dialogs(account: &Account) -> Vec<&str> {
        std::iter::once(account.approval.shows.as_str())
            .chain(account.approval.others.iter().map(String::as_str))
            .collect()
    }

    /// Refuses the dialog showing `shown`, which asks for something the part does not allow, and
    /// records it: a command with the agent's own key that declines a command, anything else with
    /// the key that refuses any request without the agent keeping a rule from it; then waits the
    /// dialog out, before the part goes on.
    fn refuse(&mut self, stage: &Stage<'_, '_>, shown: &str, why: &str) {
        let account = stage.login.expect("a part with a login").account();
        // The screen is read once more: a key sent after the dialog closed would go to whatever
        // the agent shows then.
        self.screen.pump(stage, Duration::from_millis(50));
        if !self
            .screen
            .view
            .rows()
            .iter()
            .any(|row| row.contains(shown))
        {
            if let Ok(mut declined) = stage.declined.lock() {
                declined.push(format!(
                    "{why}: a dialog showing {shown:?}, which closed before the part refused it"
                ));
            }
            return;
        }
        let key = if shown == account.approval.shows {
            account.approval.deny.clone()
        } else {
            account.approval.refusal().to_owned()
        };
        let rows = self.screen.view.rows();
        self.type_text(stage, &key);
        if let Ok(mut declined) = stage.declined.lock() {
            let held = held_keys(stage);
            let held: Vec<&str> = held.iter().map(String::as_str).collect();
            declined.push(refusal_note(why, shown, &key, &rows, &held));
        }
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(10)
            && self
                .screen
                .view
                .rows()
                .iter()
                .any(|row| row.contains(shown))
        {
            guards_hold_while_waiting(stage);
            self.screen.pump(stage, Duration::from_millis(200));
        }
    }

    /// Waits until the device's view no longer shows the dialog showing `shown`, once the part has
    /// answered it, so nothing that waits next takes the answered dialog for a new one.
    fn dialog_goes(&mut self, stage: &Stage<'_, '_>, shown: &str, why: &str) {
        let started = std::time::Instant::now();
        while self
            .screen
            .view
            .rows()
            .iter()
            .any(|row| row.contains(shown))
        {
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the agent still shows {shown:?} after it was answered"
            );
            guards_hold_while_waiting(stage);
            self.screen.pump(stage, Duration::from_millis(200));
        }
    }

    /// Waits until the composer waits for a prompt: the device's view shows the composer and not
    /// the text the agent shows while a turn runs, which an agent whose composer stays on the
    /// screen during a turn still shows then.
    fn wait_idle(&mut self, stage: &Stage<'_, '_>, why: &str) -> Vec<String> {
        let account = stage.login.expect("a part with a login").account();
        let started = std::time::Instant::now();
        loop {
            let rows = self.wait_for(stage, &account.composer, why);
            if !rows.iter().any(|row| row.contains(&account.busy)) {
                return rows;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the device's screen still shows {:?} after {LIVENESS:?}:\n{}",
                account.busy,
                rows.join("\n")
            );
            self.screen.pump(stage, Duration::from_millis(200));
        }
    }

    /// Waits until the device's view shows `needle`. When it does not, and the screen shows one
    /// of the texts the agent shows when it is signed out, the part says the login is not
    /// established.
    ///
    /// An approval the agent asks for while the part waits for anything else is declined with the
    /// agent's own key, and counted: only part 3 answers one, for the one command it names.
    fn wait_for(&mut self, stage: &Stage<'_, '_>, needle: &str, why: &str) -> Vec<String> {
        let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let account = stage.login.expect("a part with a login").account();
            // A dialog on the screen is refused before anything else shown is taken.
            let mut needles = Self::dialogs(account);
            needles.push(needle);
            loop {
                let (index, rows) =
                    self.screen
                        .wait_for_any(stage, &self.agent.session, &needles, why);
                if index == needles.len() - 1 {
                    guards_hold(stage);
                    return rows;
                }
                self.refuse(stage, needles[index], "a request the part did not make");
            }
        }));
        waited.unwrap_or_else(|panic| {
            if panic_text(&*panic).starts_with(GUARD_CHANGED) {
                std::panic::resume_unwind(panic)
            }
            let account = stage.login.expect("a part with a login").account();
            let rows = self.screen.view.rows();
            if let Some(shown) = account
                .signed_out
                .iter()
                .find(|text| rows.iter().any(|row| row.contains(text.as_str())))
            {
                panic!(
                    "{LOGIN_UNPROVEN} the agent shows {shown:?}: {}",
                    kept_panic_text(&panic_text(&*panic))
                );
            }
            std::panic::resume_unwind(panic)
        })
    }
}

/// For an agent whose login is a login keychain item: whether a session made as the agent's own can
/// read its default keychain, before the agent starts. The agent itself runs `security
/// show-keychain-info` and takes exit status 36, user interaction not allowed, as a keychain it
/// cannot take its login from; the same command runs here, at the prompt of a session with the
/// agent's variables, with its output discarded, and only its status is read. The session is
/// closed again before the agent's own opens.
fn keychain_readable_in_a_session(stage: &Stage<'_, '_>, variables: &[(String, String)]) {
    let account = stage.login.expect("a part with a login").account();
    if !account.login_keychain {
        return;
    }
    let session = open_session(
        stage.host,
        stage.owner,
        stage.runtime,
        stage.shell,
        variables,
        "a session that reads its default keychain",
        context_of(stage),
    );
    // What the session names its default keychain and its search list, for the record; then the
    // status, as 1000 more than itself, so the line that shows it is not the command's own echo.
    session
        .window
        .type_text(b"echo kr-keychain-default-$(/usr/bin/security default-keychain -d user | tr -d ' \"')-end\r");
    let named = session.window.wait_for_screen(
        "kr-keychain-default-/",
        "the session names its default keychain",
    );
    let default = named
        .iter()
        .find_map(|row| {
            let at = row.find("kr-keychain-default-/")?;
            let rest = &row[at + "kr-keychain-default-".len()..];
            rest.find("-end").map(|end| rest[..end].to_owned())
        })
        .unwrap_or_default();
    session.window.type_text(
        b"/usr/bin/security show-keychain-info >/dev/null 2>&1; echo kr-keychain-probe-$(( $? + 1000 ))\r",
    );
    let rows = session.window.wait_for_screen(
        "kr-keychain-probe-1",
        "the session says how its keychain answered",
    );
    let status = rows
        .iter()
        .find_map(|row| {
            let at = row.find("kr-keychain-probe-1")?;
            row[at + "kr-keychain-probe-".len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<i64>()
                .ok()
        })
        .map(|shown| shown - 1000);
    session.window.type_text(b"exit\r");
    let mut session = session;
    let _ = session.window.exit_code(LIVENESS);
    session.remote.close();
    assert!(
        status == Some(0),
        "{LOGIN_UNPROVEN} in a session made as the agent's own, whose default keychain is {}, \
         `security show-keychain-info` exits {status:?}, where the agent's own check takes 36 \
         (user interaction not allowed) as a keychain it cannot read its login from",
        keychain_kind(
            &default,
            &stage.login.expect("a part with a login").person_home,
            Some(&stage.run.home())
        )
    );
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

/// Checks, where the build list names the agent's status command, that the login holds, and with
/// each of its isolation commands, that the agent loads nothing of the person's own: each command,
/// run as the agent runs, with its variables, home, working directory and switches, says so
/// without calling a model. Their answers are read for those texts alone and never kept or printed,
/// but for the tools a probe that stands in for the vendor's model service found offered, which
/// the part records.
fn login_holds(stage: &Stage<'_, '_>, variables: &[(String, String)]) {
    let login = stage.login.expect("a part with a login");
    let account = login.account();
    let switches = switches_of(stage);
    let servers = server_names(stage);
    let answered = |probe: &kr_e2e_agents::build::Probe| -> Result<(), String> {
        let stub = probe
            .arguments
            .iter()
            .any(|argument| argument.contains("{stub}"))
            .then(RequestStub::start)
            .transpose()?;
        let arguments: Vec<String> = probe
            .arguments
            .iter()
            .map(|argument| match &stub {
                Some(stub) => argument.replace("{stub}", stub.address()),
                None => argument.clone(),
            })
            .collect();
        // An agent's first start in a fresh home can find its own database still locked by the start
        // before it: a probe whose whole answer is that is started again, a few times, through the
        // same guards each time.
        let output = started_again(3, Duration::from_secs(3), || {
            let command = kr_e2e_agents::stage::login_probe(
                stage.build,
                &arguments,
                &switches,
                variables,
                &stage.run.work(),
            );
            probe_output(stage, command)
        })?;
        let accepted = match &probe.accepted {
            Some(block) => Some(
                std::fs::read_to_string(login.person_home.join(&block.file))
                    .map_err(|error| format!("~/{}: {error}", block.file))?,
            ),
            None => None,
        };
        match stub {
            // The stub refused the request on purpose, so how the command ended says nothing; what
            // the request offered is the answer. The same check is shown one more tool, named for
            // the first text the answer must lack, and must refuse it.
            Some(stub) => {
                let tools = stub.finish()?;
                let text = tools.join("\n");
                let checked = probe.check(&text, &servers, accepted.as_deref());
                // Whether the text the control names is one of the person's servers (the first
                // that `{servers}` stands for) or one the build list names.
                let of_a_server = probe.lacks.first().is_some_and(|lack| lack == "{servers}");
                let lacking = probe
                    .lacks
                    .iter()
                    .find_map(|lack| {
                        if lack == "{servers}" {
                            servers.first().cloned()
                        } else {
                            Some(lack.clone())
                        }
                    })
                    .unwrap_or_default();
                let control = format!("{text}\nnested control/{lacking}");
                let rejected = !lacking.is_empty()
                    && probe
                        .check(&control, &servers, accepted.as_deref())
                        .is_err();
                stage
                    .offered
                    .lock()
                    .map_err(|_| "the offered tools' record is poisoned".to_owned())?
                    .push(json!({ "probe": probe.arguments, "tools": tools, "check": checked.as_ref().err().cloned().unwrap_or_else(|| "passed".to_owned()), "control": if of_a_server && !servers.is_empty() { json!({ "server": true, "rejected": rejected }) } else { json!({ "added": format!("nested control/{lacking}"), "server": false, "rejected": rejected }) } }));
                checked?;
                if rejected {
                    Ok(())
                } else {
                    Err(format!(
                        "its check did not refuse a tool named for {lacking:?}, added on purpose"
                    ))
                }
            }
            None => {
                if !output.status.success() {
                    let held = held_keys(stage);
                    let held: Vec<&str> = held.iter().map(String::as_str).collect();
                    return Err(probe_failed(
                        &output.status.to_string(),
                        &output.stderr,
                        account.home == AccountHome::Run,
                        &held,
                    ));
                }
                let text = String::from_utf8_lossy(&output.stdout).into_owned()
                    + &String::from_utf8_lossy(&output.stderr);
                probe.check(&text, &servers, accepted.as_deref())
            }
        }
    };
    guards_hold(stage);
    // The files an agent searches for up the tree come before any program of it runs, the probes
    // included: one that was there would load into them.
    for path in absent_paths(stage, Absent::Ancestors) {
        assert!(
            !path.exists(),
            "{ISOLATION_UNPROVEN} {} exists, which an agent searches for up the tree and would load \
             into its environment",
            path.display()
        );
    }
    if let Some(status) = &account.status {
        answered(status).unwrap_or_else(|why| {
            panic!(
                "{LOGIN_UNPROVEN} `{} {}` did not say that it holds: {why}",
                stage.build.command,
                status.arguments.join(" ")
            )
        });
    }
    for probe in &account.isolated {
        guards_hold(stage);
        answered(probe).unwrap_or_else(|why| {
            panic!(
                "{ISOLATION_UNPROVEN} `{} {}` did not answer as it must: {why}",
                stage.build.command,
                probe.arguments.join(" ")
            )
        });
    }
    confine_holds(stage);
    for path in absent_paths(stage, Absent::All) {
        assert!(
            !path.exists(),
            "{ISOLATION_UNPROVEN} {} exists, which would load the person's own settings, hooks or \
             servers into the agent, or which it would remove",
            path.display()
        );
    }
    // The probes may not have changed anything of the person's either.
    guards_hold(stage);
}

/// Runs one probe in a process group of its own and returns its output. The probe is listed with
/// the watcher of the person's files while it runs, so a change ends its group at once
/// ([`Guards::trip`]); one that starts after a change is ended and refused. Its leader is reaped
/// only once it is off the list, and its group is ended whole first, while the leader's number
/// still names it, so no signal can reach a group that took that number since. Where it does not
/// end within [`LIVENESS`], or its output stays open past five seconds after it ended, that is the
/// answer.
fn probe_output(
    stage: &Stage<'_, '_>,
    command: std::process::Command,
) -> Result<std::process::Output, String> {
    grouped_output(command, stage.guards.map(|guards| &guards.registry))
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

/// The servers the person's configuration names, where the build list says where: each section
/// header `[<table>.<name>...]` of the file, once.
fn server_names(stage: &Stage<'_, '_>) -> Vec<String> {
    let login = stage.login.expect("a part with a login");
    let Some(servers) = &login.account.server_switches else {
        return Vec::new();
    };
    let path = login.person_home.join(&servers.file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{ISOLATION_UNPROVEN} the configuration naming the person's servers, {}, cannot be \
             read: {error}",
            path.display()
        )
    });
    servers.names_in(&text)
}

/// The switches the agent and its probes are given: the build list's own, `{work}` made the
/// working directory as the system resolves it, which is how an agent that keys settings by
/// directory names it, and `{run}` the run's own directory; and those that switch off each server
/// the person's configuration names.
fn switches_of(stage: &Stage<'_, '_>) -> Vec<String> {
    let login = stage.login.expect("a part with a login");
    let work = || {
        std::fs::canonicalize(stage.run.work())
            .unwrap_or_else(|error| {
                panic!("the working directory as the system resolves it: {error}")
            })
            .display()
            .to_string()
    };
    let mut switches: Vec<String> = login
        .account
        .switches
        .iter()
        .map(|switch| {
            let switch = switch.replace("{run}", &stage.run.root().display().to_string());
            if switch.contains("{work}") {
                switch.replace("{work}", &work())
            } else {
                switch
            }
        })
        .collect();
    if let Some(servers) = &login.account.server_switches {
        for name in server_names(stage) {
            switches.extend(
                servers
                    .switch
                    .iter()
                    .map(|word| word.replace("{name}", &name)),
            );
        }
    }
    switches
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

/// A question whose answer, a number, is not in the question: the sum of two three-digit numbers,
/// at least 1000, so no count a part asks for, which stops at 400, can be taken for it.
fn sum_question() -> (String, String) {
    loop {
        let (first, second) = (500 + random_below(400), 500 + random_below(400));
        let sum = (first + second).to_string();
        let question = format!("What is {first} plus {second}? Reply with only the number.");
        if !question.contains(&sum) {
            return (question, sum);
        }
    }
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

/// The account a part with a login records: its kind, where it is kept and whose home the agent
/// ran with, never an identifier.
fn account_evidence(stage: &Stage<'_, '_>, turns: u64) -> serde_json::Value {
    let login = stage.login.expect("a part with a login");
    json!({
        "login": login.account.login,
        "stored": login.account.stored,
        "home": login.account.home,
        "variable": login.account.variable,
        "mirror": login.account.mirror.is_some(),
        "arguments": login.account.arguments,
        "variables_absent": login.account.cleared,
        "turns": turns,
        "declined_requests": stage.declined.lock().map(|declined| declined.clone()).unwrap_or_default(),
        "budget_spent": login.ledger.spent().ok(),
        "budget_limit": login.ledger.limit(),
        "isolation": {
            "probes": login.account.isolated.iter().map(|probe| json!({ "command": probe.arguments, "shows": probe.shows, "lines": probe.lines, "lacks": probe.lacks, "accepted": probe.accepted.as_ref().map(|block| json!({ "starts": block.starts, "file": block.file })), "shows_within": probe.shows_within })).collect::<Vec<_>>(),
            "tools_offered": stage.offered.lock().map(|offered| offered.clone()).unwrap_or_default(),
            "switches": switches_of(stage),
            "servers_switched_off": server_names(stage),
            "absent_before_start": absent_paths(stage, Absent::Published),
        },
    })
}

/// The event a worker sends an attachment it tells to start again from a fresh screen.
const RESYNC: &str = "session.resync";

/// A view of one session's screen from the owner device, over a connection of its own: a
/// connection serves one session and its view, and the session's own connection carries the typed
/// actions and the keyboard.
struct Watch {
    remote: kr_e2e_m1b::device::Remote,
    view: View,
}

impl Watch {
    /// Opens a connection and attaches a view of the session over it.
    fn open(stage: &Stage<'_, '_>, session: &Session) -> Self {
        let remote = stage.owner.connect(stage.runtime);
        let snapshot = events_snapshot(&remote, stage.runtime, session.session_id);
        let view = stage
            .runtime
            .block_on(View::attach(
                &remote,
                session.session_id,
                snapshot.geometry.dimensions,
                &StreamCursors::new(),
            ))
            .unwrap_or_else(|why| panic!("the device attaches: {why}"));
        Self { remote, view }
    }

    /// Detaches the view and ends its connection.
    fn close(self, stage: &Stage<'_, '_>) {
        let _ = stage.runtime.block_on(self.view.detach(&self.remote));
        self.remote.close();
    }

    /// Applies what has arrived, waiting at most `within` for the first of it.
    fn pump(&mut self, stage: &Stage<'_, '_>, within: Duration) {
        stage
            .runtime
            .block_on(self.view.pump(&self.remote, within))
            .unwrap_or_else(|why| panic!("{why}"));
    }

    /// Waits until the screen shows one of `needles`, and returns which and the screen, as
    /// [`Watch::wait_for`] does for one.
    fn wait_for_any(
        &mut self,
        stage: &Stage<'_, '_>,
        session: &Session,
        needles: &[&str],
        why: &str,
    ) -> (usize, Vec<String>) {
        let deadline = std::time::Instant::now() + LIVENESS;
        loop {
            guards_hold_while_waiting(stage);
            let rows = self.view.rows();
            if let Some(index) = needles
                .iter()
                .position(|needle| rows.iter().any(|row| row.contains(needle)))
            {
                return (index, rows);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{why}: the device's screen did not show {needles:?} within {LIVENESS:?}:\n{}\nthe \
                 view was sent: {:?}",
                rows.join("\n"),
                self.view.kinds()
            );
            self.pump(stage, Duration::from_millis(500));
            if self.view.kinds().iter().any(|kind| kind == RESYNC) {
                let stale = std::mem::replace(self, Self::open(stage, session));
                stale.close(stage);
            }
        }
    }

    /// Waits until the screen shows `needle`, and returns it.
    ///
    /// A worker tells an attachment that fell behind to resynchronise, and the product's own client
    /// then subscribes again and is sent a fresh screen. A watch does the same by opening a fresh
    /// one, so a screen that stopped at a resynchronisation is not read as one the agent stopped
    /// drawing.
    fn wait_for(
        &mut self,
        stage: &Stage<'_, '_>,
        session: &Session,
        needle: &str,
        why: &str,
    ) -> Vec<String> {
        let deadline = std::time::Instant::now() + LIVENESS;
        loop {
            guards_hold_while_waiting(stage);
            match stage
                .runtime
                .block_on(self.view.wait_for(&self.remote, needle, GUARD_EVERY))
            {
                Ok(rows) => return rows,
                Err(error) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "{why}: {error}\nthe view was sent: {:?}",
                        self.view.kinds()
                    );
                    if self.view.kinds().iter().any(|kind| kind == RESYNC) {
                        let stale = std::mem::replace(self, Self::open(stage, session));
                        stale.close(stage);
                    }
                }
            }
        }
    }
}

/// Watches a session from the owner device, as a person's phone does, and waits to be drawn
/// `ready`.
fn watch(stage: &Stage<'_, '_>, session: &Session, ready: &str) -> Watch {
    let mut watch = Watch::open(stage, session);
    let _ = watch.wait_for(stage, session, ready, "the device is drawn the agent");
    watch
}

/// The screen a fresh watch of the session is drawn, for a check that something does not appear:
/// a view that had stopped updating would show nothing new either way.
fn fresh_rows(stage: &Stage<'_, '_>, session: &Session) -> Vec<String> {
    let mut watch = Watch::open(stage, session);
    let deadline = std::time::Instant::now() + LIVENESS;
    let mut rows = watch.view.rows();
    while rows.iter().all(String::is_empty) && std::time::Instant::now() < deadline {
        watch.pump(stage, Duration::from_millis(300));
        rows = watch.view.rows();
    }
    watch.close(stage);
    assert!(
        rows.iter().any(|row| !row.is_empty()),
        "a fresh view of the session is drawn its screen"
    );
    rows
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

/// A keyboard attachment on the session's own connection, holding the input lease.
fn keyboard(stage: &Stage<'_, '_>, session: &Session) -> Keyboard {
    let mut keyboard = Keyboard::attach(&session.remote, stage.runtime, session.session_id)
        .unwrap_or_else(|why| panic!("the device's keyboard attaches: {why}"));
    keyboard
        .acquire(&session.remote, stage.runtime)
        .unwrap_or_else(|why| panic!("the device takes the input lease: {why}"));
    keyboard
}

/// Whether every process the agent's execution is still runs, with the identity it started with.
fn still_running(processes: &[&AgentProcess]) -> Result<(), String> {
    let ended: Vec<String> = processes
        .iter()
        .filter(|process| !running(&process.identity))
        .map(|process| {
            format!(
                "process {} ({})",
                process.identity.pid.get(),
                process.command
            )
        })
        .collect();
    if ended.is_empty() {
        Ok(())
    } else {
        Err(format!("these have ended: {}", ended.join(", ")))
    }
}

/// The first line of `file` after line `after`, where one is given, that holds every one of
/// `needles`, by index.
fn first_line_with(file: &Path, after: Option<usize>, needles: &[&str]) -> Option<usize> {
    let bytes = std::fs::read(file).ok()?;
    String::from_utf8_lossy(&bytes)
        .lines()
        .enumerate()
        .skip(after.map_or(0, |line| line + 1))
        .find(|(_, line)| needles.iter().all(|needle| line.contains(needle)))
        .map(|(index, _)| index)
}

/// The conversation file under `roots` whose prompt lines hold `needle`, where exactly one does.
fn conversation_of(
    roots: &[PathBuf],
    needle: &str,
    marker: &str,
    before: &Inventory,
) -> Option<PathBuf> {
    match conversation_lines(roots, needle, marker, before).as_slice() {
        [(file, _)] => Some(file.clone()),
        _ => None,
    }
}

/// Waits, a while at most, until a line of `conversation` holds every one of `needles`: the agent
/// writes its record of a reply shortly after the screen shows it.
fn settled_line(stage: &Stage<'_, '_>, conversation: &Path, needles: &[&str]) {
    let started = std::time::Instant::now();
    while first_line_with(conversation, None, needles).is_none()
        && started.elapsed() < Duration::from_secs(20)
    {
        guards_hold_while_waiting(stage);
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Whether any of `rows`, from a screen the part read, shows `mark`; the rows that do go to the
/// part's log under `what`, not into its record, since a screen can show anything of the person's.
fn shown_in_log(stage: &Stage<'_, '_>, what: &str, rows: &[String], mark: &str) -> bool {
    let showing: Vec<&String> = rows.iter().filter(|row| row.contains(mark)).collect();
    for row in &showing {
        eprintln!("part's screen, {what} ({}): {row}", stage.mark);
    }
    !showing.is_empty()
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
        agent_names: Vec::new(),
        other_writer: std::sync::atomic::AtomicBool::new(false),
        login_look_failed: std::sync::atomic::AtomicBool::new(failed_look),
        last_noted: std::sync::Mutex::new(None),
        login_data: None,
        login_seen: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        read_at: std::sync::Mutex::new(None),
        changed: std::sync::Mutex::new(None),
        watching: std::sync::atomic::AtomicBool::new(false),
        registry: std::sync::Mutex::new(Registry::default()),
        agents: std::sync::Mutex::new(Vec::new()),
        stopped: std::sync::Mutex::new(None),
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
