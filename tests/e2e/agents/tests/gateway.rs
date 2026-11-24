//! The gateway cases for the Codex package: what its table assumes of the pinned release's own
//! terminal and server, shown against whichever agent the run is given.
//!
//! The host is the `kr-controller` daemon with the Codex command integration turned on before it
//! starts, its sessions are `kr-worker` processes, the shell is the managed zsh package, the person
//! is `kr` on a real terminal, and the owner's device is the client library over loopback. A signed
//! generation of the test's own lists the agent's executable by its digest as the one qualified
//! build, and the Codex package 0.3.0 as the repository publishes it is installed from that
//! generation with its integration's grant confirmed, as the published development generation will
//! be once a record passes every part.
//!
//! One switch picks the agent, and every case runs either way:
//!
//! - Without `KR_AGENTS_GATEWAY_BUILD` the agent is the application stand-in
//!   (`tests/support/codex-stand-in`) placed as `codex`. A case runs offline and spends no turn.
//! - With it, naming a build list entry as the agents harness reads it, the agent is that entry's
//!   pinned native executable, in a home of the run's own, with the entry's configuration directory
//!   and its login variable. The command integration serves a launch that types the command alone,
//!   or `resume` or `fork` and a saved thread, and no launch that types an option, so the line
//!   typed is never more than that and the entry's arguments and switches are keys of the
//!   `config.toml` of the run's own configuration directory instead
//!   (`build::Account::configuration_with_switches`). Before the first launch the entry's isolation
//!   probes (`features list`, `debug prompt-input`, `mcp list`, the stub's request) run with the
//!   run's configuration directory and none of the switches, and their answers are compared with
//!   the entry's lines: a switch the file does not give the agent stops the case before any
//!   prompt, and so does an entry that asks to stop before its first turn. Each probe runs in a
//!   process group that is ended whole when the probe ends, with the session's variables but not
//!   the login's. Before a case sends any prompt, the host must announce the instance as served
//!   through a gateway, and a case that sends slash commands reads the agent's list of commands for
//!   each of them: it types the command, requires a row of the list that was not on the screen
//!   before it was typed, and clears the composer, with no prompt sent and no turn spent (an entry
//!   that asks to stop before its first turn stops after that read). The model answers, so each
//!   prompt a case sends is charged to the turn ledger (`KR_AGENTS_TURNS`), on disk before it is
//!   typed or sent; a slash command is sent only once the agent's own list of commands names it on
//!   the screen, and its text is the entry's (`commands`). The harness's closed-port proxy
//!   variables stay in the session, since the entry's provider and the gateway are on loopback.
//!   The login's value arrives on the descriptor `KR_AGENTS_KEY_FD` names and the values of the
//!   other keys the harness's shell holds on the one `KR_AGENTS_SCAN_FD` names, exactly as for the
//!   qualification cases, `KR_AGENTS_KEY_SCAN` names the file the search of the run's directory is
//!   recorded in and is required, and one case runs in each process: the pipes empty when they are
//!   read.
//!
//! On a real route the person's home is the account database's, and a run whose `HOME` is another
//! directory is refused before anything runs. Every case, whatever became of it (a failure of its
//! own setup included), ends the same way (`held`): what the run started is ended, the run's
//! directory is searched for the keys and removed, and the search and the removal are recorded; the
//! person's own Codex directory is looked at again, every entry under it by its metadata alone
//! through directory handles that follow no link, and nothing there may have changed (a link at the
//! directory itself is refused, and no text names an entry under it); the agent's own record is
//! counted for the turns it ran, and one the ledger was not charged for is charged and stops the
//! case, as does a case that passed with a charged turn and finds none in the record; an outcome
//! line is written; and no panic message prints a piece of a held key. Where the managed shell is missing and a real agent was asked
//! for, the case fails and does not skip.
//!
//! Each case shows one assumption of the package's table, and where the real agent's answer differs
//! from the table's reading it fails and says what it saw:
//!
//! 1. The server's word that a request was answered reaches the terminal through the gateway, and
//!    the terminal closes its prompt on it, when a device answers an approval the terminal holds.
//! 2. The terminal shows a turn the host started for a device's prompt.
//! 3. The binding's thread changes where the terminal starts, resumes or forks one and nowhere else.
//! 4. A whole session names no method the package's table does not list: the binding is never
//!    suspended.
//! 5. A device's prompt over a running turn is refused, and nothing reaches the agent.
//!
//! What each route shows. The stand-in route proves the driver and the host and gateway side of
//! each case, which the cross-boundary checkpoint's own gateway file covers too; no assertion on
//! it shows an assumption about the pinned release. A real run shows an assumption as far as the
//! host's record of the binding, the terminal's screen and the agent's own record show it. Case 4
//! reads the binding at every step and at every poll, and the host keeps no cumulative record of
//! the methods a session named, so a suspension that a later selection cleared between two polls
//! is not seen. Case 5 shows the host's refusal, which is made before any `turn/start` is sent, so
//! the pinned server is never sent that frame, and that the agent's own record holds the
//! terminal's prompt and not the device's; the stand-in route's count of the requests its server
//! received is the only upstream record, and a real run has none.
//!
//! With a real agent a case spends one turn and case 5 a second, which it charges before the
//! device's prompt that the host must refuse: six in all, and none that is not charged. Each case
//! appends its outcome to the file `KR_AGENTS_RESULT` names, where one is named.
//!
//! ```text
//! KR_AGENTS_GATEWAY_BUILD=<entry> KR_AGENTS_TURNS=<ledger> KR_AGENTS_RESULT=<file> \
//!     KR_AGENTS_KEY_FD=3 KR_AGENTS_SCAN_FD=4 KR_AGENTS_KEY_SCAN=<file> KR_SHELL_PACKAGES=<prefix> \
//!     cargo test -p kr-e2e-agents --test gateway -- <case> --exact --nocapture
//! ```
//!
//! Not claimed: Windows, where no gateway runs.

#![cfg(unix)]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_e2e_agents::account::{KEY_SCAN_VARIABLE, Ledger};
use kr_e2e_agents::build::{self, Account, Build, InstallSwitch, Probe};
use kr_e2e_agents::held::{
    Absent, Audit, CONFIG_DIRECTORY, HeldKeys, ISOLATION_UNPROVEN, MetaGuard,
    NEWER_CONFIG_DIRECTORY, Recorded, RunScan, Stop, absent_below, absent_paths, absent_paths_in,
    audit_turns, conversations_relative, conversations_relative_in, folder_of, grouped_output,
    kept_panic_text, new_turns, other_agent_processes, other_agents_refusal, panic_text,
    person_home, read_record, turns_recorded, unchanged_before_the_charge,
};
use kr_e2e_agents::launch_report::{Seen, launch_report};
use kr_e2e_agents::outcome::{Failure, Outcome};
use kr_e2e_agents::session_environment::{self, Expected};
use kr_e2e_agents::stage::{
    Installation, PlacedProgram, closed_port, inode_of, scan_rules, session_variables, text_image,
};
use kr_e2e_agents::stub::RequestStub;
use kr_e2e_agents::{GENERATION_VARIABLE, RESULT_VARIABLE};
use kr_e2e_m1b::device::{Device, PairedHost, Remote, RequestError};
use kr_e2e_m1b::host::{Host, HostOptions, Preparation};
use kr_e2e_m1b::run::{PlacedDirectory, Run, binary_place};
use kr_e2e_m1b::window::{Window, answered};
use kr_e2e_m1b::{LIVENESS, ceremony, shells};
use kr_ipc::paths::EnvironmentPaths;
use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, Change, Enrolment, InstallationGrant, Owner, RepositoryId,
    RepositoryKind,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::catalogue::QualifiedBuild;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::matching::{Architecture, OperatingSystem};
use kr_plugin_sdk::text::Label;
use kr_protocol::agent::{
    AgentApprovalInspectParams, AgentApprovalInspectResult, AgentApprovalRespondParams,
    AgentApprovalRespondResult, AgentBindingState, AgentCancelParams, AgentCapabilitiesParams,
    AgentCapabilitiesResult, AgentMutationResult, AgentMutationTarget, AgentPromptParams,
    AgentSubject, PromptText,
};
use kr_protocol::broker::{InstanceCapabilityIdentity, InstanceCapabilityState};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::PendingState;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    AgentBindingRevision, AgentTurnId, ApplicationInstanceId, PendingResourceId, PluginId,
    SessionEpoch, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::recovery::{AgentInstancesParams, AgentInstancesResult};
use kr_protocol::scalars::{Digest256, Nullable};
use kr_worker::broker::connectors::fixture;

/// The test support that builds signed catalogue generations.
#[allow(dead_code)]
#[path = "../../../../crates/kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// The parts of the qualification that start no model turn and need no login, on this driver.
#[path = "gateway/staged_a.rs"]
mod staged_a;

/// The parts of the qualification that need the person's login (1, 3 and 4), on this driver.
#[path = "gateway/staged_b.rs"]
mod staged_b;

/// The parts of the qualification that start the agent by hand with the person's login, on this
/// driver.
#[path = "gateway/staged_c.rs"]
mod staged_c;

/// The variable naming the build list entry of a real agent; without it the agent is the stand-in.
const BUILD_VARIABLE: &str = "KR_AGENTS_GATEWAY_BUILD";

/// Set (to anything) on the upgrade case's run, beside [`BUILD_VARIABLE`], to run the one mode that
/// stops after the newer build's probes: no login, no model, no turn, no charge, and no start of
/// the agent. It records the newer build's answers to the pinned entry's isolation probes, from
/// which the entry's set for the newer build is written.
const PROBE_ONLY_VARIABLE: &str = "KR_AGENTS_GATEWAY_PROBE_ONLY";

/// What the session's shell prompts with, so a case knows it is reading.
const PROMPT: &str = "kr-session$ ";

/// The person's own startup file for the session's shell. `kr shell install` adds the marked entry
/// that loads the package's integration after it.
const ZSHRC: &str =
    "PROMPT='kr-session$ '\nRPROMPT=''\nHISTFILE=''\nsetopt no_beep\nunsetopt prompt_sp\n";

/// What the stand-in says when it runs as typed, with no gateway's address among its words.
const RAN_AS_TYPED: &str = "codex-stand-in: serves";

/// What the stand-in's terminal writes when the server asks it for the approval of a command.
const ASKED: &str = "TUI: the server asks for item/commandExecution/requestApproval";

/// The decision a device gives an approval: the one the package's table names for running the
/// command once.
const ACCEPT: &str = "accept";

/// The decision a device gives to end the turn that waits on an approval.
const DECLINE: &str = "decline-and-stop";

/// The person's own Codex directory, whose every entry a real run is held to leave as it found it:
/// the login, the settings, the instructions and hooks the agent would load, its conversations and
/// the files it appends to when it is used. Entries are looked at by their metadata alone: nothing
/// of a file is read, and nothing is written there.
const PERSON_TREES: [&str; 1] = [".codex"];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime for the device")
}

fn codex() -> PluginId {
    PluginId::new("kalareach/codex").expect("a plugin identifier")
}

/// The directory of the Codex package the cases install: a byte copy of the package source whose
/// table states the conditions under which a thread the terminal starts is not its conversation.
fn codex_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("codex-package")
}

/// A marker only this case's text holds: `kr` and twelve hexadecimal digits.
fn mark() -> String {
    let bytes = *kr_ipc::new_uuid().as_bytes();
    format!(
        "kr{:012x}",
        u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes")) % (1 << 48)
    )
}

/// A question whose answer, a number of at least 1000, is in none of `avoid`, the texts a case
/// types or its screen shows, and not in the question, in the plain form or the one with a
/// thousands separator.
fn fresh_question(avoid: &[&str]) -> (String, String) {
    loop {
        let bytes = *kr_ipc::new_uuid().as_bytes();
        let first = 500 + u64::from(bytes[0]) + u64::from(bytes[1]);
        let second = 500 + u64::from(bytes[2]) + u64::from(bytes[3]);
        let sum = (first + second).to_string();
        let question = format!("What is {first} plus {second}? Reply with only the number.");
        let holds = |text: &str| text.contains(&sum) || text.contains(&with_thousands(&sum));
        if !holds(&question) && avoid.iter().all(|text| !holds(text)) {
            return (question, sum);
        }
    }
}

/// The words typed at the shell to start the agent: its command, and `extra` after it. Never an
/// option: the command integration serves a launch that types none.
fn launch_words(command: &str, extra: &[&str]) -> Vec<String> {
    std::iter::once(command)
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
}

/// A slash command a case sends on a real route, which the agent's list of commands is read for
/// before the case's first charge.
#[derive(Clone, Copy, Debug)]
enum Slash {
    /// The one the entry shows a screen for, which calls no model and selects nothing.
    Shown,
    /// The entry's `fork`.
    Fork,
    /// The entry's `new`.
    New,
    /// The entry's `quit`.
    Quit,
}

/// The commands the thread case sends, in the order it sends them.
const THREAD_CASE_COMMANDS: [Slash; 4] = [Slash::Shown, Slash::Fork, Slash::New, Slash::Quit];

/// The name of the file a typed agent command runs: `codex` for `codex`, and for a command typed
/// with a path the file name at its end.
fn executable_name(command: &str) -> String {
    Path::new(command).file_name().map_or_else(
        || command.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// The agent a run is given.
enum Route {
    /// The application stand-in, placed as `codex`: offline, no turn.
    StandIn,
    /// The pinned native build of a build list entry, with its login.
    Real(Box<Real>),
}

/// A real agent: the entry, its turn ledger (none where the case runs with no login), the keys the
/// run's files are searched for, the person's home as the system's account database names it, and
/// the person's own files as they stood before anything started.
struct Real {
    build: Build,
    account: Account,
    /// The ledger the case's turns are charged to: none in a case that runs with no login, which
    /// starts no model turn and so owns no allowance.
    ledger: Option<Ledger>,
    held: HeldKeys,
    home: PathBuf,
    person: MetaGuard,
    /// The agent's program as the run placed it, recorded once before the agent first starts.
    placed: std::sync::OnceLock<PlacedProgram>,
    /// The agent's configuration files as the harness wrote them, by their place below the run's
    /// directory, each recorded with its stamp and digest when it was written.
    configured: std::sync::Mutex<Vec<PathBuf>>,
    /// The session's variables as they stood when the configuration was written, before the
    /// agent's first start: what every later read of them returns.
    prepared: std::sync::Mutex<Option<Vec<(String, String)>>>,
    /// The session variables of the second person's shell in a case that upgrades: the newer
    /// build's own configuration directory, which has no provider, and no login.
    prepared_newer: std::sync::Mutex<Option<Vec<(String, String)>>>,
    /// The files that would load the person's own settings into the newer build, listed once before
    /// the agent's first start: what every later check of them looks at.
    newer_absent: std::sync::OnceLock<Vec<PathBuf>>,
    /// The turns the newer build's conversation directory held right after its probes, with their
    /// identities: the probes are the build's own and may leave a record, and the audit at the end
    /// finds the turns whose identities are not among these, since no prompt is sent to the newer
    /// build.
    newer_baseline: std::sync::OnceLock<Recorded>,
    /// The signed catalogue generation the package is installed from, which the operator names:
    /// a real route has no fixture generation to fall back to.
    generation: PathBuf,
    /// Whether this is the probe-only run of the upgrade case: it records the newer build's probes
    /// and starts no agent.
    probe_only: bool,
}

impl Route {
    /// The route this run was given.
    ///
    /// # Panics
    ///
    /// With `login` false the case runs with no login: the entry still gives its configuration, but
    /// the descriptor of the login's value is not read, no ledger is asked for and none can be
    /// charged, while the file guards and the searches for the other keys are kept. The mode is
    /// the case's own and is chosen here, before any key is acquired.
    ///
    /// # Panics
    ///
    /// Panics when the entry names no login, the run's `HOME` is not the person's home as the
    /// system's account database names it, the values of the keys cannot be read, or the person's
    /// files cannot be looked at: nothing has started, and no turn is spent.
    fn from_environment(case: &str, login: bool, probe_only: bool) -> Self {
        let Some(path) = std::env::var_os(BUILD_VARIABLE)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
        else {
            return Self::StandIn;
        };
        assert!(
            std::env::var_os(KEY_SCAN_VARIABLE).is_some_and(|value| !value.is_empty()),
            "{BUILD_VARIABLE} asks for a real agent, and {KEY_SCAN_VARIABLE} names no file to record \
             the search of the run's directory for the keys in"
        );
        let generation = std::env::var_os(GENERATION_VARIABLE)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!(
                    "{BUILD_VARIABLE} asks for a real agent, and {GENERATION_VARIABLE} names no \
                     signed generation to install its package from"
                )
            });
        assert!(
            generation.is_absolute() && generation.join("root.json").is_file(),
            "{GENERATION_VARIABLE} names no generation (an absolute directory with a root.json)"
        );
        let build = build::read_build(&path);
        let account = build.account.clone().unwrap_or_else(|| {
            panic!("{BUILD_VARIABLE} names an entry with no login, which no case may start")
        });
        // The person's files are the ones under the home the system names, and a run started under
        // another `HOME` would guard a tree that is not theirs and pass.
        let home =
            person_home(std::env::var_os("HOME").as_deref()).unwrap_or_else(|why| panic!("{why}"));
        // The turn ledger is made by the operator before the run: a missing one, or one with no
        // array for the budget, stops the run here, before anything starts and before any key is read.
        let ledger = login.then(|| Ledger::from_environment(&account.budget, account.turns));
        // The guard over the person's directory compares the whole of it at the end, and cannot
        // tell a write of another agent process of theirs from the run's: none runs at the start.
        let others = other_agent_processes(&executable_name(&build.command), None)
            .unwrap_or_else(|why| panic!("{why}"));
        assert!(
            others.is_empty(),
            "{}",
            other_agents_refusal(&others, "before the run starts")
        );
        let who = format!("gateway case {case}");
        let held = if login {
            HeldKeys::read(&who, &account)
        } else {
            HeldKeys::read_without_login(&who)
        };
        let person = MetaGuard::take(&home, &PERSON_TREES);
        Self::Real(Box::new(Real {
            build,
            account,
            ledger,
            held,
            home,
            person,
            placed: std::sync::OnceLock::new(),
            configured: std::sync::Mutex::new(Vec::new()),
            prepared: std::sync::Mutex::new(None),
            prepared_newer: std::sync::Mutex::new(None),
            newer_absent: std::sync::OnceLock::new(),
            newer_baseline: std::sync::OnceLock::new(),
            generation,
            probe_only,
        }))
    }
}

impl Real {
    /// Whether the agent's configuration names the provider the entry routes the pinned build to
    /// (the subscription proxy): only a run with a login does. A run with none is given the
    /// switches alone, so the build has no provider and sends no request of a model, whatever it
    /// does at its start ([`Account::configuration_without_provider`]).
    fn names_a_provider(&self) -> bool {
        self.ledger.is_some()
    }

    /// The run's directory for the agent's configuration and conversations.
    fn config(run: &Run) -> PathBuf {
        run.root().join(CONFIG_DIRECTORY)
    }

    /// The line typed at the shell to start the agent: the command, and `extra` after it.
    fn typed(&self, extra: &[&str]) -> String {
        launch_words(&self.build.command, extra)
            .iter()
            .map(|word| build::quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The run's directory and the working directory the entry's `{run}` and `{work}` stand for.
    fn places(run: &Run) -> (String, String) {
        let work = std::fs::canonicalize(run.work())
            .unwrap_or_else(|error| {
                panic!("the working directory as the system resolves it: {error}")
            })
            .display()
            .to_string();
        (run.root().display().to_string(), work)
    }

    /// The list `kr new` is given for a session of the run, which the host's worker keeps but for
    /// the names the host owns (the reserved `KR_` prefix, the terminal's identity, the desktop's
    /// names: the host's own state and runtime directories are among them, and are not the
    /// session's): the harness's own for a session, its closed-port proxy variables included (the
    /// entry's provider and the gateway are on loopback, which `NO_PROXY` exempts), the entry's
    /// variables, its configuration directory with the entry's arguments and switches written as
    /// the keys of its `config.toml`, and its login, and none of the variables the entry clears but
    /// the ones it sets itself. What the session's shell really holds of it is read at its prompt
    /// before the first typing ([`Person::reads_the_environment`]), a moment before the agent reads
    /// it, and nothing later.
    ///
    /// This is the one write of the configuration files: it runs once, before the agent's first
    /// start, and keeps the list it returns ([`Real::variables`]).
    fn prepare_variables(
        &self,
        host: &Host<'_>,
        shell: &shells::ManagedShell,
    ) -> Vec<(String, String)> {
        let mut variables = session_variables(host, shell, &self.build.environment, closed_port());
        for name in ["USER", "LOGNAME"] {
            if let Ok(value) = std::env::var(name) {
                variables.push((name.to_owned(), value));
            }
        }
        if let Some((name, value)) = &self.held.key {
            variables.push((name.clone(), value.clone()));
        }
        for (name, value) in &self.account.variables {
            variables.retain(|(existing, _)| existing != name);
            variables.push((name.clone(), value.clone()));
        }
        let config = self.account.config_directory.as_ref().expect(
            "the entry gives the agent no configuration directory of the run's own, and its \
             switches have nowhere to go",
        );
        let directory = Self::config(host.run());
        if !directory.is_dir() {
            kr_ipc::paths::create_private_tree(host.run().root(), &directory)
                .expect("the run's configuration directory");
        }
        let (root, work) = Self::places(host.run());
        let files = if self.names_a_provider() {
            self.account
                .configuration_with_switches("config.toml", &root, &work)
        } else {
            self.account
                .configuration_without_provider("config.toml", &root, &work)
        }
        .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        for (relative, content) in &files {
            let path = directory.join(relative);
            assert!(
                path.starts_with(&directory) && !relative.contains(".."),
                "a configuration file stays in its directory: {relative}"
            );
            // A run with no login writes no provider: what is read back through the run's handles
            // before every probe and every typing is this file, so the build has none to send a
            // request to.
            if !self.names_a_provider() && relative.ends_with(".toml") {
                let named = provider_keys_in(content);
                assert!(
                    named.is_empty(),
                    "{ISOLATION_UNPROVEN} the configuration of a run with no login names a provider \
                     ({named:?} in {relative})"
                );
            }
            std::fs::write(&path, content).expect("writes the configuration file");
            // What the probes vouch for: the file as it is now, read back through the run's handles.
            let place = Path::new(CONFIG_DIRECTORY).join(relative);
            host.run()
                .note_placed(&place)
                .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
            let mut configured = self
                .configured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !configured.contains(&place) {
                configured.push(place);
            }
        }
        variables.retain(|(existing, _)| existing != &config.variable);
        variables.push((config.variable.clone(), directory.display().to_string()));
        let _ = self.build.without_provider_keys(&mut variables);
        let mut prepared = self
            .prepared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            prepared.is_none(),
            "the configuration is written once, before the agent's first start"
        );
        *prepared = Some(variables.clone());
        variables
    }

    /// The list [`Real::prepare_variables`] returned, with nothing written.
    fn variables(&self) -> Vec<(String, String)> {
        self.prepared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("the configuration was prepared before the agent's first start")
    }

    /// The newer build's own configuration directory of the run, written once with the list of
    /// the first shell, before the agent's first start: a `config.toml` of the entry's switches as
    /// keys and none of the entry's own text, so it names no provider, and the list for the second
    /// person's shell, which holds this directory and no login. The directory and the file are
    /// recorded as placed, as the first directory's are, and what the probes of the newer build
    /// vouch for is this file as it is now.
    ///
    /// # Panics
    ///
    /// Panics when the entry gives no configuration directory, or the file cannot be made.
    fn prepare_newer_variables(
        &self,
        host: &Host<'_>,
        first: &[(String, String)],
    ) -> Vec<(String, String)> {
        let config = self.account.config_directory.as_ref().expect(
            "the entry gives the agent no configuration directory of the run's own, and its \
             switches have nowhere to go",
        );
        let directory = host.run().root().join(NEWER_CONFIG_DIRECTORY);
        kr_ipc::paths::create_private_tree(host.run().root(), &directory)
            .expect("the newer build's configuration directory");
        let (root, work) = Self::places(host.run());
        let text = self
            .account
            .switch_keys_file(&root, &work)
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        // The file names no provider, whatever the entry's switches are: the newer build has no
        // login, and a file that names one is refused before it is written.
        let named = provider_keys_in(&text);
        assert!(
            named.is_empty(),
            "{ISOLATION_UNPROVEN} the newer build's configuration names a provider ({named:?})"
        );
        std::fs::write(directory.join("config.toml"), text).expect("writes the configuration file");
        let place = Path::new(NEWER_CONFIG_DIRECTORY).join("config.toml");
        host.run()
            .note_placed(&place)
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        self.configured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(place);
        let login = self.held.key.as_ref().map(|(name, _)| name.as_str());
        let mut variables: Vec<(String, String)> = first
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != login && name != &config.variable)
            .cloned()
            .collect();
        variables.push((config.variable.clone(), directory.display().to_string()));
        let mut prepared = self
            .prepared_newer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            prepared.is_none(),
            "the newer build's configuration is written once, before the agent's first start"
        );
        *prepared = Some(variables.clone());
        variables
    }

    /// The list [`Real::prepare_newer_variables`] returned, with nothing written.
    fn newer_variables(&self) -> Vec<(String, String)> {
        self.prepared_newer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("the newer build's configuration was prepared before the agent's first start")
    }

    /// Records the turns the newer build's conversation directory holds now, once, right after its
    /// probes ([`Real::newer_baseline`]): their count and their identities, so that the audit finds
    /// a turn that is new by its identity; the probes' record stays among the evidence.
    ///
    /// # Panics
    ///
    /// Panics where a directory that exists cannot be counted: nothing has started, and no turn is
    /// spent.
    fn records_the_newer_baseline(&self, run: &Run) {
        let relative = conversations_relative_in(&self.account, NEWER_CONFIG_DIRECTORY);
        let turns = match turns_recorded(&self.account, run.root(), run.pin(), &relative) {
            Ok(found) => found,
            Err(_) if !run.root().join(&relative).exists() => Recorded::default(),
            Err(why) => panic!(
                "{ISOLATION_UNPROVEN} the newer build's record after its probes was not counted: {why}"
            ),
        };
        self.newer_baseline.get_or_init(|| turns);
    }

    /// [`Real::absent_list`] for the newer build's configuration directory.
    fn newer_absent_list(&self, run: &Run) -> Vec<PathBuf> {
        absent_paths_in(
            &self.account,
            run,
            NEWER_CONFIG_DIRECTORY,
            &run.home(),
            &self.home,
            &folder_of(run),
            Absent::All,
        )
    }

    /// Fails the case when the agent would not have its updates and installs switched off: the
    /// entry must give it each switch, and the switches that are options reach it as keys of its
    /// file.
    fn checks_installs_off(&self, run: &Run) {
        self.build
            .installs_are_off()
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        let (root, work) = Self::places(run);
        let keys = self
            .account
            .switches_as_keys(&root, &work)
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        for switch in &self.account.installs_off {
            if let InstallSwitch::Argument { text } = switch {
                let given = text
                    .split_once('=')
                    .is_some_and(|(key, value)| keys.contains(&(key.to_owned(), value.to_owned())));
                assert!(
                    given,
                    "{ISOLATION_UNPROVEN} {text:?} switches the agent's updates and installs off, \
                     and no key of its configuration file says so"
                );
            }
        }
    }

    /// The paths of the entry's list of files that would load the person's own settings, hooks or
    /// servers into the agent, with every template filled in. Made once, before the agent first
    /// starts, from the working directory as the system resolves it then, and kept: nothing is
    /// resolved again once the agent has run.
    fn absent_list(&self, run: &Run) -> Vec<PathBuf> {
        absent_paths(
            &self.account,
            run,
            &run.home(),
            &self.home,
            &folder_of(run),
            Absent::All,
        )
    }

    /// Fails the case when a file of `absent`, the entry's list ([`Real::absent_list`]), exists:
    /// each path in the run is looked at by a walk from the run's pinned directory that follows no
    /// link at any component.
    fn checks_absent(&self, run: &Run, absent: &[PathBuf]) {
        for path in absent {
            match absent_below(run.root(), run.pin(), path) {
                Ok(true) => {}
                Ok(false) => panic!(
                    "{ISOLATION_UNPROVEN} {} exists, which would load the person's own settings, \
                     hooks or servers into the agent, or which it would remove",
                    path.display()
                ),
                Err(error) => panic!(
                    "{ISOLATION_UNPROVEN} {} cannot be shown absent: {error}",
                    path.display()
                ),
            }
        }
    }

    /// Runs the entry's isolation probes before the agent's first launch, as the qualification
    /// parts run them, but with the run's own configuration directory and none of the switches the
    /// entry types: what each answers is what the run's `config.toml` gave the agent. Each answer is
    /// compared with the entry's lines, which stand for what the switches do; a probe that does not
    /// answer as it must stops the case, with no prompt sent and no turn spent. A probe that sends
    /// the agent's request to the stub is checked too against a tool added on purpose, which its
    /// check must refuse. No model is called, and `variables` are the caller's: the caller leaves
    /// the login out of them. Each probe's process group is ended whole when the probe ends. The
    /// person's servers are not read: the run's home names none.
    ///
    /// # Panics
    ///
    /// Panics at the first probe that does not answer as it must.
    fn proves_isolation(&self, run: &Run, variables: &[(String, String)]) {
        for probe in &self.account.isolated {
            self.proves(run, self.placed(), false, variables, probe)
                .unwrap_or_else(|why| {
                    panic!(
                        "{ISOLATION_UNPROVEN} `{} {}` did not answer as it must with the entry's \
                         switches in the run's configuration file alone: {why}",
                        self.build.command,
                        probe.arguments.join(" ")
                    )
                });
        }
    }

    /// [`Real::proves_isolation`] for the newer build, before the upgrade: the build's own set of
    /// probes, run with its own configuration directory and no login, by the file recorded for it
    /// ([`PlacedProgram::checked_as_recorded`]), since the installation's link still names the
    /// pinned build. An answer that is not the recorded one stops the case before any start.
    ///
    /// # Panics
    ///
    /// Panics at the first probe that does not answer as it must, and where the newer build has no
    /// set of probes.
    fn proves_newer_isolation(
        &self,
        run: &Run,
        newer: &PlacedProgram,
        variables: &[(String, String)],
    ) {
        let probes = &self
            .build
            .newer
            .as_ref()
            .expect("the entry names a newer build")
            .isolated;
        assert!(
            !probes.is_empty(),
            "{ISOLATION_UNPROVEN} the entry gives the newer build no isolation set, and a build \
             nobody has shown to load nothing of the person's own is not started"
        );
        for probe in probes {
            self.proves(run, newer, true, variables, probe)
                .unwrap_or_else(|why| {
                    panic!(
                        "{ISOLATION_UNPROVEN} the newer build's `{} {}` did not answer as it must \
                         with its own configuration directory and no login: {why}",
                        self.build.command,
                        probe.arguments.join(" ")
                    )
                });
        }
    }

    /// One probe of [`Real::proves_isolation`], of `program`: the pinned build ([`Real::placed`]),
    /// or, with `as_recorded`, a build the installation's link does not name yet.
    fn proves(
        &self,
        run: &Run,
        program: &PlacedProgram,
        as_recorded: bool,
        variables: &[(String, String)],
        probe: &Probe,
    ) -> Result<(), String> {
        let answer = self.answer(run, program, as_recorded, variables, probe)?;
        judged(probe, &answer)
    }

    /// Runs one probe of `program` and returns what it answered, judging nothing.
    fn answer(
        &self,
        run: &Run,
        program: &PlacedProgram,
        as_recorded: bool,
        variables: &[(String, String)],
        probe: &Probe,
    ) -> Result<Answer, String> {
        let stub = probe
            .arguments
            .iter()
            .any(|argument| argument.contains("{stub}"))
            .then(RequestStub::start)
            .transpose()?;
        // The program is started by the absolute path recorded when it was placed, once the route to
        // it is checked to be as it was: the agent's earlier start may have left another link.
        self.configuration_as_placed(run)?;
        let mut command = if as_recorded {
            program.command_as_recorded(run.root(), run.pin())?
        } else {
            program.command(run.root(), run.pin())?
        };
        command
            .args(probe.arguments.iter().map(|argument| match &stub {
                Some(stub) => argument.replace("{stub}", stub.address()),
                None => argument.clone(),
            }))
            .env_clear()
            .envs(
                variables
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            );
        // The probe runs in a process group that is ended whole before its output is returned, so
        // that nothing it started outlives it with the environment it was given, when the run's
        // directory is searched for the keys.
        let output = grouped_output(command, LIVENESS)?;
        Ok(match stub {
            // The stub refuses the request on purpose, so how the command ended says nothing: what
            // the request offered is the answer.
            Some(stub) => Answer {
                text: stub.finish()?.join("\n"),
                stubbed: true,
                ended: Ok(()),
            },
            None => Answer {
                text: String::from_utf8_lossy(&output.stdout).into_owned()
                    + &String::from_utf8_lossy(&output.stderr),
                stubbed: false,
                ended: if output.status.success() {
                    Ok(())
                } else {
                    Err(format!("it ended with {}", output.status))
                },
            },
        })
    }

    /// What the probe-only run records: each of the pinned entry's isolation probes run against the
    /// newer build, with its own configuration directory and no login, by the file recorded for it.
    /// The whole answer of each probe is kept in the evidence directory the operator names
    /// ([`EVIDENCE_VARIABLE`]) after the answer is searched for the keys the run holds; the record
    /// holds its digest, the search's result and the rows the isolation criteria are read from
    /// (every feature row, and every row that holds a text the probe expects or refuses), within a
    /// bound for all probes together. A cut is reported, and adoption of the record is refused where
    /// any evidence is incomplete ([`probe_record`]). Nothing is judged here: the criteria are no
    /// server, each listed feature off, the read-only sandbox, no skills section, only the exec tools.
    fn records_the_newer_probes(
        &self,
        run: &Run,
        newer: &PlacedProgram,
        variables: &[(String, String)],
    ) -> serde_json::Value {
        let keys = self.held.values();
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let directory = std::env::var_os(EVIDENCE_VARIABLE)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let mut total_left = RECORDED_TOTAL_CHARS;
        let probes: Vec<serde_json::Value> = self
            .account
            .isolated
            .iter()
            .enumerate()
            .map(
                |(index, probe)| match self.answer(run, newer, true, variables, probe) {
                    Ok(answer) => {
                        let kept = searches_and_keeps(
                            &keys,
                            directory.as_deref(),
                            &format!("{}-newer-probe-{index}.txt", run.mark().1),
                            &answer.text,
                        );
                        probe_record(probe, &answer, &kept, &mut total_left)
                    }
                    Err(why) => serde_json::json!({
                        "arguments": probe.arguments,
                        "answered": false,
                        "why": why,
                        "adoptable": false,
                    }),
                },
            )
            .collect();
        let refusals: Vec<String> = probes
            .iter()
            .filter(|probe| probe["adoptable"] != true)
            .map(|probe| format!("probe {}: evidence incomplete", probe["arguments"]))
            .collect();
        serde_json::json!({
            "probe_only": true,
            "adoption": { "allowed": refusals.is_empty(), "refused_because": refusals },
            "probes": probes,
        })
    }

    /// The agent's program as the run placed it.
    ///
    /// # Panics
    ///
    /// Panics when it is asked for before the program was placed.
    fn placed(&self) -> &PlacedProgram {
        self.placed
            .get()
            .expect("the agent's program is placed before the agent starts")
    }

    /// Fails the case unless the route the agent's name is found by, right before it is typed, is
    /// the one the run placed.
    fn checks_the_route(&self, run: &Run) {
        self.placed()
            .checked(run.root(), run.pin())
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        self.configuration_as_placed(run)
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
    }

    /// Fails the case unless the newer build is as the run recorded it, the installation's link
    /// names it, each configuration file is as it was written, and no file that would load the
    /// person's own settings into it exists: right before the second typing, and again before any
    /// turn is charged to the first agent after the second launch.
    fn checks_the_newer_route(&self, run: &Run, newer: &PlacedProgram) {
        newer
            .checked(run.root(), run.pin())
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        self.configuration_as_placed(run)
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        let absent = self
            .newer_absent
            .get()
            .expect("the files absent for the newer build were listed before the first start");
        self.checks_absent(run, absent);
    }

    /// Whether each configuration file the harness wrote is still the file that was written, read
    /// through the run's handles with its stamp and digest: the isolation probes vouch for the
    /// agent's configuration, and an earlier start of the agent may have rewritten it.
    fn configuration_as_placed(&self, run: &Run) -> Result<(), String> {
        let configured = self
            .configured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for place in configured {
            run.placed_as_it_was(&place)
                .map_err(|why| format!("the agent's configuration: {why}"))?;
        }
        Ok(())
    }

    /// The text of the slash command `which`.
    fn slash(&self, which: Slash) -> &str {
        match which {
            Slash::Shown => &self.account.slash.input,
            Slash::Fork => self.command("fork"),
            Slash::New => self.command("new"),
            Slash::Quit => self.command("quit"),
        }
    }

    /// The text the entry names for the slash command `name` (`fork`, `new` or `quit`).
    ///
    /// # Panics
    ///
    /// Panics when the entry names none: the driver's code carries no command of its own.
    fn command(&self, name: &str) -> &str {
        self.account.commands.get(name).map_or_else(
            || panic!("the entry names no {name:?} command, which this case sends"),
            String::as_str,
        )
    }

    /// Charges one turn to the entry's budget before a prompt the model answers is sent, once no
    /// other process of this user is the agent outside `run` and the person's own agent files are as
    /// they stood at the start: a process that started since the run began, and any change of the
    /// files since (by a process the listing missed, or any other writer), stops the case here with
    /// no turn charged or spent.
    fn charge(&self, run: &Run, case: &str, what: &str) {
        let others = other_agent_processes(&executable_name(&self.build.command), Some(run.root()))
            .unwrap_or_else(|why| panic!("no turn is charged: {why}"));
        assert!(
            others.is_empty(),
            "{}",
            other_agents_refusal(&others, "right before the charge, so no turn was charged")
        );
        unchanged_before_the_charge(&self.person)
            .unwrap_or_else(|why| panic!("no turn is charged: the person's files changed: {why}"));
        let _ = self
            .ledger
            .as_ref()
            .unwrap_or_else(|| {
                panic!("the case {case} runs with no login and has no ledger: nothing is charged")
            })
            .charge(case, what)
            .unwrap_or_else(|why| panic!("{why}"));
    }

    /// The text of every file under the agent's conversation directory, read as the audit of the
    /// turns reads the record: through directory handles with no link followed, so nothing is
    /// read through a link.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be read whole: a record that is not whole shows nothing.
    fn conversations(&self, run: &Run) -> Result<String, String> {
        let mut text = String::new();
        read_record(
            run.root(),
            run.pin(),
            &conversations_relative(&self.account),
            &mut |_, content| text.push_str(&String::from_utf8_lossy(content)),
        )?;
        Ok(text)
    }
}

/// Where the stand-in agent is placed in the run, below its directory.
const STAND_IN_PLACE: &str = "t/codex";

/// How many reads of the host's list of application instances a failure's text keeps.
const POLLS_KEPT: usize = 20;

/// The top-level keys of a configuration file that name the provider the build sends its requests
/// to: the provider's name, its table, and any address of a service.
fn provider_keys_in(text: &str) -> Vec<String> {
    let Ok(document) = text.parse::<toml_edit::DocumentMut>() else {
        return vec!["a file that is not TOML".to_owned()];
    };
    document
        .iter()
        .map(|(key, _)| key.to_owned())
        .filter(|key| key.starts_with("model_provider") || key.ends_with("_base_url"))
        .collect()
}

/// The variables a session is given beyond the harness's: the stand-in's own, where the route has
/// them, and `more`, the case's own, on every route (a real agent takes no stand-in variable, and
/// the forging launcher's root is none of them).
fn given_variables(
    stand_in: Option<Vec<(String, String)>>,
    more: &[(&str, String)],
) -> Vec<(String, String)> {
    let mut variables = stand_in.unwrap_or_default();
    variables.extend(
        more.iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    );
    variables
}

/// What one probe answered.
struct Answer {
    /// What it printed, or, for a probe against the request stub, the names of the tools the
    /// request offered, one per line.
    text: String,
    /// Whether the probe was answered by the request stub: how the command ended then says nothing.
    stubbed: bool,
    /// Whether the command ended as a probe's must, with why not.
    ended: Result<(), String>,
}

/// Whether `answer` is what `probe` expects of the build it was written for.
fn judged(probe: &Probe, answer: &Answer) -> Result<(), String> {
    if answer.stubbed {
        probe.check(&answer.text, &[], None)?;
        let lacking = probe
            .lacks
            .iter()
            .find(|lack| lack.as_str() != "{servers}")
            .cloned()
            .unwrap_or_default();
        if !lacking.is_empty()
            && probe
                .check(
                    &format!("{}\nnested control/{lacking}", answer.text),
                    &[],
                    None,
                )
                .is_ok()
        {
            return Err(format!(
                "its check did not refuse a tool named for {lacking:?}, added on purpose"
            ));
        }
        Ok(())
    } else {
        answer.ended.clone()?;
        probe.check(&answer.text, &[], None)
    }
}

/// The directory the probe-only run keeps each probe's whole answer in: an absolute path of an
/// existing directory, which the operator names and which is not the run's own.
const EVIDENCE_VARIABLE: &str = "KR_AGENTS_GATEWAY_EVIDENCE";

/// The most rows of one answer the probe-only run records, the most characters of each, and the
/// most characters of all the probes' rows together.
const RECORDED_ROWS: usize = 400;
const RECORDED_ROW_CHARS: usize = 240;
const RECORDED_TOTAL_CHARS: usize = 96 * 1024;

/// What was done with one probe's whole answer before the record was made.
struct Kept {
    /// The file the whole answer is in, or why it is in none.
    kept_in: Result<String, String>,
    /// How many values the answer was searched for, and whether it held one.
    keys_searched: usize,
    key_found: bool,
}

/// Searches `text`, the whole answer of a probe, for the `keys` the run holds, by the part's own
/// search (every key, and every piece of eight characters of one), and keeps it whole in the file
/// `name` of `directory` where it holds none. An answer that holds a key is written nowhere.
fn searches_and_keeps(keys: &[&str], directory: Option<&Path>, name: &str, text: &str) -> Kept {
    let keys: Vec<&str> = keys.iter().copied().filter(|key| !key.is_empty()).collect();
    let lines: Vec<&str> = text.lines().collect();
    let found = kr_e2e_agents::held::holds_a_key(&lines, &keys);
    let kept_in = if found {
        Err("the answer holds a key the run holds".to_owned())
    } else {
        keeps_the_answer(directory, name, text)
    };
    Kept {
        kept_in,
        keys_searched: keys.len(),
        key_found: found,
    }
}

/// Writes `text`, the whole answer of a probe, to the new private file `name` of `directory`, which
/// is an absolute path of an existing directory, and returns the file's name. A file that is there
/// is not written over.
fn keeps_the_answer(directory: Option<&Path>, name: &str, text: &str) -> Result<String, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let directory = directory.ok_or_else(|| format!("{EVIDENCE_VARIABLE} names no directory"))?;
    if !directory.is_absolute() || !directory.is_dir() {
        return Err(format!(
            "{EVIDENCE_VARIABLE} does not name an existing absolute directory"
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .map_err(|error| format!("the answer is not kept: {error}"))?;
    file.write_all(text.as_bytes())
        .map_err(|error| format!("the answer is not kept: {error}"))?;
    Ok(name.to_owned())
}

/// A row of a feature list: a name, a stage and `true` or `false`.
fn is_feature_row(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words.len() >= 3 && matches!(words.last(), Some(&("true" | "false")))
}

/// The rows of `text` the record keeps for `probe`, in order: every feature row and every row that
/// holds a text the probe expects or refuses (spaces and case aside), each cut to
/// [`RECORDED_ROW_CHARS`], at most [`RECORDED_ROWS`] of them and at most `total_left` characters
/// of all the probes' together, which it takes from; with what was cut, as texts, and how many
/// non-empty rows of the whole answer are not kept because they are neither.
fn relevant_rows(
    probe: &Probe,
    text: &str,
    total_left: &mut usize,
) -> (Vec<String>, Vec<String>, usize) {
    let squeeze = |text: &str| {
        text.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    let wanted: Vec<String> = probe
        .shows
        .iter()
        .chain(&probe.lines)
        .chain(&probe.lacks)
        .filter(|text| text.as_str() != "{servers}")
        .map(|text| squeeze(text))
        .collect();
    let relevant = |line: &str| {
        let squeezed = squeeze(line);
        is_feature_row(line) || wanted.iter().any(|text| squeezed.contains(text.as_str()))
    };
    let left_out = text
        .lines()
        .filter(|line| !line.trim().is_empty() && !relevant(line))
        .count();
    let (mut rows, mut cut) = (Vec::new(), Vec::new());
    for line in text.lines() {
        if !relevant(line) {
            continue;
        }
        if rows.len() == RECORDED_ROWS {
            cut.push(format!("more than {RECORDED_ROWS} relevant rows"));
            break;
        }
        let kept: String = line.chars().take(RECORDED_ROW_CHARS).collect();
        if kept.chars().count() < line.chars().count() {
            cut.push(format!(
                "a row of {} characters was cut to {RECORDED_ROW_CHARS}",
                line.chars().count()
            ));
        }
        if *total_left < kept.len() {
            cut.push("the bound for all the probes' rows together was reached".to_owned());
            break;
        }
        *total_left -= kept.len();
        rows.push(kept);
    }
    (rows, cut, left_out)
}

/// Whether `probe` is the feature list, whose every row the criteria are read from.
fn lists_features(probe: &Probe) -> bool {
    probe
        .arguments
        .iter()
        .map(String::as_str)
        .take(2)
        .eq(["features", "list"])
}

/// One probe of the probe-only run: its arguments, how it ended, whether the answer holds what the
/// probe expects of the pinned build, which expectation it misses where it does not, the answer's
/// size and digest and the file that holds it whole, the search of it for keys, the rows the
/// criteria are read from, what was cut, how many non-empty rows were left out of those (the
/// reviewers read them in the whole answer that was kept), and whether the record may be adopted:
/// only where the probe answered, the whole answer is kept, no key was found in it, nothing was cut
/// and, for the feature list, no non-empty row was left out.
fn probe_record(
    probe: &Probe,
    answer: &Answer,
    kept: &Kept,
    total_left: &mut usize,
) -> serde_json::Value {
    let verdict = judged(probe, answer);
    let (rows, cut, left_out) = relevant_rows(probe, &answer.text, total_left);
    let digest: String = kr_cbor::sha256(answer.text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let adoptable = kept.kept_in.is_ok()
        && !kept.key_found
        && cut.is_empty()
        && !(lists_features(probe) && left_out > 0);
    serde_json::json!({
        "arguments": probe.arguments,
        "answered": true,
        "ended": answer.ended.clone().err().unwrap_or_else(|| "as a probe must".to_owned()),
        "holds_the_pinned_entrys_expectations": verdict.is_ok(),
        "misses": verdict.err(),
        "answer": {
            "bytes": answer.text.len(),
            "line_count": answer.text.lines().count(),
            "sha256": digest,
            "kept_in": kept.kept_in.clone().ok(),
            "not_kept_because": kept.kept_in.clone().err(),
        },
        "keys": { "values_searched": kept.keys_searched, "found": kept.key_found },
        "relevant_rows": rows,
        "rows_left_out": left_out,
        "truncated": !cut.is_empty(),
        "truncated_because": cut,
        "adoptable": adoptable,
    })
}

/// The last reads of the host's list of application instances, as the device read them, each with
/// the time it was read after the case began and what it listed.
struct Polls {
    began: Instant,
    last: std::sync::Mutex<std::collections::VecDeque<String>>,
}

impl Polls {
    fn new() -> Self {
        Self {
            began: Instant::now(),
            last: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Keeps one read, and drops the oldest beyond the last [`POLLS_KEPT`].
    fn record(&self, listed: &str) {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.len() == POLLS_KEPT {
            last.pop_front();
        }
        last.push_back(format!(
            "+{} ms {}",
            self.began.elapsed().as_millis(),
            listed.chars().take(400).collect::<String>()
        ));
    }

    /// The kept reads, oldest first, one to a line.
    fn text(&self) -> String {
        let last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_empty() {
            "(no read)".to_owned()
        } else {
            last.iter().cloned().collect::<Vec<_>>().join("\n")
        }
    }
}

/// What a failure at the instance wait or at the device's prompt adds to its text: the host's list
/// of application instances as the device read it, and the terminal's screen as the harness holds
/// it. Nothing of the run's tree is read for it and nothing is started.
fn diagnosis_text(polls: &Polls, screen: &[String]) -> String {
    let rows: Vec<&str> = screen.iter().map(|row| row.trim_end()).collect();
    let used = rows
        .iter()
        .rposition(|row| !row.is_empty())
        .map_or(0, |last| last + 1);
    format!(
        "the host's list of application instances as the device read it, the last {POLLS_KEPT} \
         reads, oldest first:\n{}\nthe terminal's screen:\n{}",
        polls.text(),
        rows[..used].join("\n")
    )
}

/// Everything a case needs besides its host.
struct Context {
    runtime: tokio::runtime::Runtime,
    run: Run,
    shell: shells::ManagedShell,
    route: Route,
    /// The file the qualified build's digest names.
    executable: PathBuf,
    /// The directory the shell's search path names first.
    bin: PathBuf,
    /// The run's working directory as it was when the agent was placed, before the session's shell
    /// was started in it.
    work: Option<PlacedDirectory>,
    /// The device's reads of the host's list of application instances.
    polls: Polls,
    /// Whether the run holds a second, newer build behind the installation's link, for a case that
    /// upgrades the agent (stand-in route).
    upgrade: bool,
    /// Whether the launcher the worker gives the shell is the forging launcher, with the real one
    /// beside it.
    forge: bool,
    /// Whether the agent is started by hand, with the host's command integration off.
    manual: bool,
    /// The installation the upgrade case switches.
    installation: Option<Installation>,
    /// The newer build's file and version, where the run placed one.
    newer: Option<(PathBuf, String)>,
    /// The newer build as the run recorded it, on a real route: probed before the upgrade.
    newer_placed: Option<PlacedProgram>,
    /// The installed prefix of the newer build the upgrade points the link at: the run's own on the
    /// stand-in route, the entry's on a real one.
    newer_prefix: Option<PathBuf>,
    /// The digest of the package the host's catalogue installed, as the catalogue computed it.
    package_digest: std::sync::Mutex<Option<[u8; 32]>>,
    /// The programs of the stand-in route that every typed launch may run, by their place below
    /// the run's directory, each recorded when it was placed.
    placed_files: Vec<PathBuf>,
}

impl Context {
    /// A case's context before the agent is placed: nothing but what exists already, so nothing in
    /// it can fail.
    fn new(
        shell: shells::ManagedShell,
        route: Route,
        run: Run,
        runtime: tokio::runtime::Runtime,
    ) -> Self {
        Self {
            runtime,
            run,
            shell,
            route,
            executable: PathBuf::new(),
            bin: PathBuf::new(),
            work: None,
            polls: Polls::new(),
            upgrade: false,
            forge: false,
            manual: false,
            installation: None,
            newer: None,
            newer_placed: None,
            newer_prefix: None,
            package_digest: std::sync::Mutex::new(None),
            placed_files: Vec::new(),
        }
    }

    /// Places the forwarder and the agent in the run, and checks the entry. A failure here is a
    /// failure of the case, which ends as every case does.
    fn place(&mut self) {
        let run = &self.run;
        // Recorded before the session's shell is started in it: the shell's current directory is this
        // object for as long as the shell runs.
        let work = PlacedDirectory::record(run.root(), run.pin(), Path::new("w"))
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        run.place_built("kr-hook", &run.binary("kr-hook"), &["--version"]);
        let mut forge_files = Vec::new();
        if self.forge {
            // The real launcher is placed at `b/h/kr-hook` and runs once there, where no step has a
            // time limit; the forging launcher takes the place the worker gives the shell its
            // launcher at, and runs once there too (it runs the real one in place).
            let real = run.root().join("b/h");
            kr_ipc::paths::create_private_tree(run.root(), &real)
                .expect("a directory for the launcher");
            run.place_built("kr-hook", &real.join("kr-hook"), &["--version"]);
            std::fs::remove_file(run.binary("kr-hook")).expect("the copied launcher is replaced");
            run.place_built("kr-e2e-forge", &run.binary("kr-hook"), &["--version"]);
            run.note_placed(Path::new("b/h/kr-hook"))
                .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
            forge_files.push(PathBuf::from("b/h/kr-hook"));
        }
        // The launcher the worker gives the shell is run by every typed launch.
        run.note_placed(&binary_place("kr-hook"))
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        let mut placed_files = forge_files;
        let mut installation = None;
        let mut newer = None;
        let mut newer_placed = None;
        let mut newer_prefix = None;
        let (executable, bin) = match &self.route {
            Route::StandIn if self.upgrade => {
                // Two installed builds behind the link `agent/current`: the pinned stand-in and the
                // newer one, each a program built from the stand-in's source, each at
                // `t/<prefix>/bin/codex`; the link names the first.
                let (first, second) = (run.root().join("t/a"), run.root().join("t/b"));
                for prefix in [&first, &second] {
                    kr_ipc::paths::create_private_tree(run.root(), &prefix.join("bin"))
                        .expect("a directory for the programs");
                }
                run.place_built("codex-stand-in", &first.join("bin/codex"), &["--version"]);
                run.place_built(
                    "codex-stand-in-newer",
                    &second.join("bin/codex"),
                    &["--version"],
                );
                for relative in ["t/a/bin/codex", "t/b/bin/codex"] {
                    run.note_placed(Path::new(relative))
                        .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
                    placed_files.push(PathBuf::from(relative));
                }
                let linked = Installation::link(run, &first, &[]);
                let bin = linked.bin();
                installation = Some(linked);
                newer = Some((second.join("bin/codex"), "0.156.1".to_owned()));
                newer_prefix = Some(second);
                (first.join("bin/codex"), bin)
            }
            Route::StandIn => {
                let tools = run.root().join("t");
                kr_ipc::paths::create_private_tree(run.root(), &tools)
                    .expect("a directory for the programs");
                run.place_built("codex-stand-in", &tools.join("codex"), &["--version"]);
                // The shell finds the stand-in by its name on a search path, as it finds the build.
                run.note_placed(Path::new(STAND_IN_PLACE))
                    .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
                placed_files.push(PathBuf::from(STAND_IN_PLACE));
                (tools.join("codex"), tools)
            }
            Route::Real(real) => {
                real.checks_installs_off(run);
                let pinned = real.build.pinned_file();
                let bytes = std::fs::read(&pinned).unwrap_or_else(|error| {
                    panic!("the pinned build {}: {error}", pinned.display())
                });
                assert_eq!(
                    kr_cbor::sha256(&bytes)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    real.build.sha256,
                    "the pinned build is the file the entry's digest names"
                );
                let linked = Installation::link(run, &real.build.prefix, &real.build.runtime);
                let placed = PlacedProgram::record(
                    &real.build.prefix,
                    &real.build.runtime,
                    &real.build.command,
                    &real.build.pinned,
                    work.clone(),
                )
                .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
                if real.build.launch == build::Launch::Native {
                    assert_eq!(
                        std::fs::canonicalize(&pinned).ok().as_deref(),
                        Some(placed.resolved()),
                        "{ISOLATION_UNPROVEN} the command the entry names is not the file it pins"
                    );
                }
                real.placed
                    .set(placed)
                    .expect("the agent's program is placed once");
                let bin = linked.bin();
                if self.upgrade {
                    // The newer build is a file the entry names and digests, installed outside the
                    // run: recorded as the pinned one is, before any start, and not run until the
                    // installation's link is replaced by the upgrade.
                    let build_newer = real
                        .build
                        .newer
                        .as_ref()
                        .expect("the entry names a newer build for the upgrade case");
                    let file = build_newer.prefix.join(&build_newer.pinned);
                    let bytes = std::fs::read(&file).unwrap_or_else(|error| {
                        panic!("the newer build {}: {error}", file.display())
                    });
                    assert_eq!(
                        kr_cbor::sha256(&bytes)
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                        build_newer.sha256,
                        "the newer build is the file the entry's digest names"
                    );
                    newer_placed = Some(
                        PlacedProgram::record(
                            &build_newer.prefix,
                            &real.build.runtime,
                            &real.build.command,
                            &build_newer.pinned,
                            work.clone(),
                        )
                        .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}")),
                    );
                    newer = Some((file, build_newer.version.clone()));
                    newer_prefix = Some(build_newer.prefix.clone());
                    installation = Some(linked);
                }
                (pinned, bin)
            }
        };
        self.executable = executable;
        self.bin = bin;
        self.work = Some(work);
        self.placed_files = placed_files;
        self.installation = installation;
        self.newer = newer;
        self.newer_placed = newer_placed;
        self.newer_prefix = newer_prefix;
    }

    /// Fails the case unless each executable the run placed that a typed launch runs is still the
    /// file that was placed, and the run's working directory is still the object the session's
    /// shell was started in, right before the launch is typed: the launcher the worker gives the
    /// shell, and, on the stand-in route, the stand-in the shell finds by name. The agent that an
    /// earlier start ran may have replaced either by a link or another file, and the shell would run
    /// it with the session's variables; and a probe that has ended may have moved the directory out
    /// of the run and put an empty one in its place, which leaves the shell's current directory the
    /// moved object, where the typed launch would start. The directory at the pinned place is
    /// reached by the walk that follows no link and must be the recorded object. The real route's
    /// own program is checked by [`Real::checks_the_route`].
    fn checks_the_placed_files(&self) {
        self.work
            .as_ref()
            .expect("the work directory is recorded when the agent is placed")
            .place_for_a_start(self.run.root(), self.run.pin())
            .unwrap_or_else(|why| {
                panic!(
                    "{ISOLATION_UNPROVEN} {why}. A directory that the agent moved out of the run \
                     is outside it and is not scanned for keys; the end removes it only where it \
                     is empty, and stops the case where it holds anything"
                )
            });
        let mut files = vec![binary_place("kr-hook")];
        files.extend(self.placed_files.iter().cloned());
        for file in files {
            self.run
                .placed_as_it_was(&file)
                .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        }
    }

    /// The checks made right before a launch is typed, after every probe: each file the run placed
    /// that a typed launch runs, the run's working directory, and on a real route the agent's
    /// program and configuration. A probe may have replaced a launcher or the program.
    fn checks_before_a_typing(&self) {
        self.checks_the_placed_files();
        if let Route::Real(real) = &self.route {
            real.checks_the_route(&self.run);
        }
    }

    /// The distribution and version the generation lists the executable as.
    fn qualified_as(&self) -> (&'static str, String) {
        match &self.route {
            Route::StandIn => (
                "test stand-in",
                fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
            ),
            Route::Real(real) => ("native build", real.build.version.clone()),
        }
    }

    /// A host whose catalogue holds the package installed and whose configuration turns its
    /// integration on, with the address devices dial kept across a restart of its daemon.
    fn host(&self) -> Host<'_> {
        Host::start_prepared(
            &self.run,
            &HostOptions {
                shell_packages: Some(self.shell.prefix.clone()),
            },
            &Preparation {
                command_integrations: if self.manual {
                    Vec::new()
                } else {
                    vec![codex().to_string()]
                },
                stable_address: true,
            },
            |environment| {
                let (distribution, version) = self.qualified_as();
                let mut builds = vec![(self.executable.clone(), version)];
                builds.extend(self.newer.iter().cloned());
                let generation = match &self.route {
                    Route::StandIn => None,
                    Route::Real(real) => Some(real.generation.as_path()),
                };
                let package = self.runtime.block_on(install_codex(
                    environment,
                    &builds,
                    distribution,
                    generation,
                ));
                *self
                    .package_digest
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(package);
            },
        )
    }

    /// The environment every `kr` the case runs before the agent's first start is given, and the
    /// one write of the agent's configuration files (real route).
    fn prepare_variables(&self, host: &Host<'_>) -> Vec<(String, String)> {
        match &self.route {
            Route::StandIn => {
                let mut variables = host.variables();
                variables.retain(|(name, _)| name != "PATH");
                variables.push((
                    "PATH".to_owned(),
                    format!("{}:/usr/bin:/bin", self.bin.display()),
                ));
                variables.push(("ZDOTDIR".to_owned(), self.run.home().display().to_string()));
                variables.push((
                    "SHELL".to_owned(),
                    self.shell.executable.display().to_string(),
                ));
                variables
            }
            Route::Real(real) => {
                let variables = real.prepare_variables(host, &self.shell);
                if self.upgrade {
                    let _ = real.prepare_newer_variables(host, &variables);
                }
                variables
            }
        }
    }

    /// The environment the second person's shell is created with: the newer build's in a case that
    /// upgrades, and the first shell's otherwise, so that a second session that resumes the first
    /// one's conversation has the login and the configuration directory that conversation is in.
    fn second_variables(&self, host: &Host<'_>) -> Vec<(String, String)> {
        match second_list(self.upgrade) {
            SecondList::Newer => self.newer_variables(host),
            SecondList::First => self.variables(host),
        }
    }

    /// The environment the second person's shell is created with in a case that upgrades: no login,
    /// and on a real route the newer build's own configuration directory.
    fn newer_variables(&self, host: &Host<'_>) -> Vec<(String, String)> {
        match &self.route {
            Route::StandIn => self.without_login(&self.variables(host)),
            Route::Real(real) => real.newer_variables(),
        }
    }

    /// The same environment as [`Context::prepare_variables`] returned, with nothing written: the
    /// stand-in route's list is computed again, a real route's is the one kept.
    fn variables(&self, host: &Host<'_>) -> Vec<(String, String)> {
        match &self.route {
            Route::StandIn => self.prepare_variables(host),
            Route::Real(real) => real.variables(),
        }
    }

    /// The variables a session is created with beyond the harness's: on the stand-in route its
    /// variants, the file that releases it, the file its server notes what it received in and the
    /// program its server starts; on every route `more`, the case's own ([`given_variables`]).
    fn stand_in_variables(&self, variants: &str, more: &[(&str, String)]) -> Vec<(String, String)> {
        given_variables(
            matches!(self.route, Route::StandIn).then(|| {
                vec![
                    ("STAND_IN".to_owned(), variants.to_owned()),
                    (
                        "STAND_IN_RELEASE".to_owned(),
                        release_of(self).display().to_string(),
                    ),
                    (
                        "STAND_IN_RECEIVED".to_owned(),
                        received_by(self).display().to_string(),
                    ),
                    ("STAND_IN_COMMAND".to_owned(), command(&self.bin)),
                ]
            }),
            more,
        )
    }

    /// What the session's shell is expected to hold of `variables`, the list its `kr new` is given
    /// ([`Person::reads_the_environment`]): the names the host drops by design are the ones the
    /// harness gives `kr` itself and the terminal's own, and the names the build list clears are
    /// the ones the shell may not export, those it sets itself apart.
    fn expects(&self, host: &Host<'_>, variables: &[(String, String)]) -> Expected {
        let for_the_host: Vec<String> = host
            .variables()
            .into_iter()
            .map(|(name, _)| name)
            .chain(["TERM".to_owned(), "SHELL".to_owned()])
            .collect();
        let (cleared, allowed) = match &self.route {
            Route::Real(real) => (real.account.cleared.clone(), real.build.names_it_sets()),
            Route::StandIn => (Vec::new(), Vec::new()),
        };
        Expected::new(
            variables,
            self.run.mark(),
            &for_the_host,
            &cleared,
            &allowed,
        )
        .unwrap_or_else(|why| panic!("{why}"))
    }

    /// `variables` without the login's variable: the login is the agent's session's, and no step of
    /// the host's needs it.
    fn without_login(&self, variables: &[(String, String)]) -> Vec<(String, String)> {
        let login = match &self.route {
            Route::Real(real) => real.held.key.as_ref().map(|(name, _)| name.as_str()),
            Route::StandIn => None,
        };
        variables
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != login)
            .cloned()
            .collect()
    }

    /// Pairs a device with the host as its first owner.
    fn pair(&self, host: &Host<'_>) -> (Device, PairedHost, Remote) {
        let device = self
            .runtime
            .block_on(Device::create("phone", &self.run.root().join("d")));
        let (paired, remote) = ceremony::pair_first_owner(host, &device, &self.runtime);
        (device, paired, remote)
    }

    /// Reads what a session holds of its agents, with the error as the device got it.
    ///
    /// # Errors
    ///
    /// Returns why the request failed: the host's refusal, or a failure of the connection.
    fn requests_instances(
        &self,
        remote: &Remote,
        session_id: SessionId,
    ) -> Result<AgentInstancesResult, RequestError> {
        self.runtime.block_on(remote.read(
            Method::AgentInstances,
            &AgentInstancesParams {
                session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
    }

    /// Reads what an instance's capabilities and binding are, with the error as the device got it.
    ///
    /// # Errors
    ///
    /// Returns why the request failed: the host's refusal, or a failure of the connection.
    fn requests_capabilities(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
    ) -> Result<AgentCapabilitiesResult, RequestError> {
        self.runtime.block_on(remote.read(
            Method::AgentCapabilities,
            &AgentCapabilitiesParams {
                subject: subject(session_id, instance),
            },
        ))
    }

    /// Reads what a session holds of its agents, and keeps what it listed with the polls.
    ///
    /// # Errors
    ///
    /// Returns why the host could not be read.
    fn read_instances(
        &self,
        remote: &Remote,
        session_id: SessionId,
    ) -> Result<AgentInstancesResult, String> {
        let read: Result<AgentInstancesResult, String> = self
            .requests_instances(remote, session_id)
            .map_err(|why| format!("agent.instances: {why}"));
        match &read {
            Ok(result) => self.polls.record(&format!("{:?}", result.agent_instances)),
            Err(why) => self.polls.record(why),
        }
        read
    }

    /// Reads what a session holds of its agents.
    fn instances(&self, remote: &Remote, session_id: SessionId) -> AgentInstancesResult {
        self.read_instances(remote, session_id)
            .unwrap_or_else(|why| panic!("{why}"))
    }

    /// Reads the instances until `holds` is true of them, within the liveness bound.
    ///
    /// # Errors
    ///
    /// Returns what the last read held when the bound passed.
    fn instances_within(
        &self,
        remote: &Remote,
        session_id: SessionId,
        why: &str,
        holds: impl Fn(&AgentInstancesResult) -> bool,
    ) -> Result<AgentInstancesResult, String> {
        let started = Instant::now();
        loop {
            // A read that fails is tried again until the bound, and the last failure is what the
            // wait returns: it never panics in a body that has assertions still to make.
            let last = match self.read_instances(remote, session_id) {
                Ok(read) if holds(&read) => return Ok(read),
                Ok(read) => format!("{why}: the session holds {read:?}"),
                Err(error) => format!("{why}: {error}"),
            };
            if started.elapsed() >= LIVENESS {
                return Err(last);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Reads the instances until `holds` is true of them, within the liveness bound.
    fn instances_until(
        &self,
        remote: &Remote,
        session_id: SessionId,
        why: &str,
        holds: impl Fn(&AgentInstancesResult) -> bool,
    ) -> AgentInstancesResult {
        self.instances_within(remote, session_id, why, holds)
            .unwrap_or_else(|why| panic!("{why}\n{}", self.polls.text()))
    }

    /// Reads what the host says of an instance's binding.
    ///
    /// # Errors
    ///
    /// Returns why the host could not be read.
    fn read_binding(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
    ) -> Result<AgentBindingState, String> {
        let read = self
            .requests_capabilities(remote, session_id, instance)
            .map_err(|why| format!("agent.capabilities: {why}"))?;
        Ok(read.binding)
    }

    /// [`Context::read_binding`] where a failed read stops the case at once.
    fn binding(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
    ) -> AgentBindingState {
        self.read_binding(remote, session_id, instance)
            .unwrap_or_else(|why| panic!("{why}"))
    }

    /// Reads the binding until `holds` is true of it, within the liveness bound.
    ///
    /// # Errors
    ///
    /// Returns why a read failed, or the last binding read when the bound passed.
    fn binding_within(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> Result<AgentBindingState, String> {
        let started = Instant::now();
        loop {
            let read = self.read_binding(remote, session_id, instance)?;
            if holds(&read) {
                return Ok(read);
            }
            if started.elapsed() >= LIVENESS {
                return Err(format!("{why}: the binding is {read:?}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// [`Context::binding_within`] where a failure stops the case at once.
    fn binding_until(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> AgentBindingState {
        self.binding_within(remote, session_id, instance, why, holds)
            .unwrap_or_else(|why| panic!("{why}"))
    }

    /// What a rich call at `binding` acts on.
    fn target(
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
    ) -> (ActionTarget, AgentMutationTarget) {
        (
            ActionTarget {
                environment_id: remote.environment_id(),
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::some(instance),
                agent_binding_revision: Nullable::some(binding.binding_revision),
            },
            AgentMutationTarget {
                subject: subject(session_id, instance),
                binding_revision: binding.binding_revision,
            },
        )
    }

    /// Answers the pending approval `resource` with `option`.
    fn answers(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
        resource: PendingResourceId,
        option: &str,
    ) -> Result<AgentApprovalRespondResult, RequestError> {
        let (target, mutation_target) = Self::target(remote, session_id, instance, binding);
        self.runtime.block_on(remote.mutate(
            Method::AgentApprovalRespond,
            target,
            &AgentApprovalRespondParams {
                target: mutation_target,
                resource_id: resource,
                option_id: option.to_owned(),
            },
        ))
    }

    /// Submits a prompt to an instance at the revision of `binding`.
    fn prompts(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
        text: &str,
    ) -> Result<AgentMutationResult, RequestError> {
        let (target, mutation_target) = Self::target(remote, session_id, instance, binding);
        self.runtime.block_on(remote.mutate(
            Method::AgentPromptSubmit,
            target,
            &AgentPromptParams {
                target: mutation_target,
                draft_id: Nullable::null(),
                text: Nullable::some(PromptText::new(text).expect("a prompt")),
            },
        ))
    }

    /// Reads the host's record of the approval `resource` of an instance: what the decoder read,
    /// with the source bytes the upstream sent.
    fn inspects(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        resource: PendingResourceId,
    ) -> Result<AgentApprovalInspectResult, RequestError> {
        self.runtime.block_on(remote.read(
            Method::AgentApprovalInspect,
            &AgentApprovalInspectParams {
                subject: subject(session_id, instance),
                resource_id: resource,
            },
        ))
    }

    /// Asks the host to cancel the turn `turn` of an instance at the revision of `binding`: a
    /// cancel on an instance with no turn running cannot request model work.
    fn cancels(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding_revision: AgentBindingRevision,
        turn: &str,
    ) -> Result<AgentMutationResult, RequestError> {
        let binding = AgentBindingState {
            binding_revision,
            thread_id: Nullable::null(),
            turn_id: Nullable::null(),
            profile_id: Nullable::null(),
            mode: kr_protocol::broker::IntegrationMode::NativeTerminal,
            rich_mutations_suspended: false,
            suspension_reason: Nullable::null(),
        };
        let (target, mutation_target) = Self::target(remote, session_id, instance, &binding);
        self.runtime.block_on(remote.mutate(
            Method::AgentTurnCancel,
            target,
            &AgentCancelParams {
                target: mutation_target,
                turn_id: AgentTurnId::new(turn).expect("a turn"),
            },
        ))
    }

    /// Closes the host and checks that nothing the run started is still running.
    fn close(&self, host: &Host<'_>) {
        host.stop().expect("the host stops");
        let closing = self
            .run
            .closing_check()
            .unwrap_or_else(|why| panic!("{why}"));
        println!("{closing}");
    }
}

fn subject(session_id: SessionId, instance: ApplicationInstanceId) -> AgentSubject {
    AgentSubject {
        session_id,
        application_instance_id: instance,
    }
}

/// Publishes the Codex package in a signed generation of its own, whose index names the digest of
/// `executable` as the one build it qualifies, and installs and enables it in the environment with
/// the grants it asks for, as the owner's confirmation of that exact installation does.
async fn install_codex(
    environment: &EnvironmentPaths,
    executables: &[(PathBuf, String)],
    distribution: &str,
    generation: Option<&Path>,
) -> [u8; 32] {
    let builds: Vec<QualifiedBuild> = executables
        .iter()
        .map(|(executable, version)| QualifiedBuild {
            application: Label::new("codex").expect("a label"),
            distribution: Label::new(distribution).expect("a label"),
            version: kr_plugin_sdk::version::PackageVersion::parse(version).expect("a version"),
            os: if cfg!(target_os = "macos") {
                OperatingSystem::MacOs
            } else {
                OperatingSystem::Linux
            },
            architecture: if std::env::consts::ARCH == "aarch64" {
                Architecture::Aarch64
            } else {
                Architecture::X86_64
            },
            executable_digest: PayloadDigest::of(
                &std::fs::read(executable).expect("the placed agent"),
            ),
        })
        .collect();
    // The stand-in route publishes a generation of its own, whose index names the digests of the
    // executables above. A real route installs from the signed generation the operator names
    // ([`GENERATION_VARIABLE`]): the package and the builds it qualifies are that generation's, and
    // there is no fixture to fall back to.
    let fixture;
    let (metadata_url, targets_url, root_bytes, wanted) = if let Some(directory) = generation {
        let wanted = generation_entry(directory);
        (
            generations::directory_url(&directory.join("metadata")),
            generations::directory_url(&directory.join("targets")),
            std::fs::read(directory.join("root.json")).expect("the generation's root"),
            Some(wanted),
        )
    } else {
        let home = environment.state_dir().join("generation-source");
        std::fs::create_dir_all(&home).expect("a directory for the generation");
        fixture = generations::Generation::build(
            &home,
            generations::GenerationSpec {
                package: Some(codex_package()),
                builds,
                ..generations::GenerationSpec::default()
            },
        )
        .await;
        (
            generations::directory_url(&fixture.metadata_dir()),
            generations::directory_url(&fixture.targets_dir()),
            fixture.root_bytes(),
            None,
        )
    };
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                metadata_url,
                targets_url,
                root_bytes,
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse(
        wanted
            .as_ref()
            .map_or("0.3.0", |entry| entry.version.as_str()),
    )
    .expect("a version");
    let package = catalogue
        .index(&id)
        .expect("activated")
        .find(&codex(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install_with(
            &id,
            environment.environment_id(),
            &codex(),
            &version,
            package,
            InstallationGrant::with(wanted.as_ref().map_or_else(
                || {
                    vec![
                        PluginCapability::CommandIntegrationLaunch,
                        PluginCapability::ApprovalDecode,
                        PluginCapability::ApprovalRespond,
                        PluginCapability::UpstreamAction,
                    ]
                },
                |entry| entry.grant.clone(),
            )),
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment.environment_id(), &codex(), true)
        .await
        .expect("enabled");
    // The package installed is the one the generation's index names: its digest is recorded, and
    // compared with the index's own text of it.
    if let Some(entry) = &wanted {
        assert_eq!(
            package.to_string(),
            entry.manifest_digest,
            "the package installed is the digest the generation's index names"
        );
    }
    *package.as_bytes()
}

/// The entry of the Codex package in a generation the operator names, as its index says it.
struct GenerationEntry {
    version: String,
    manifest_digest: String,
    /// The capabilities the entry requests that the repository's ceiling does not already allow.
    grant: Vec<PluginCapability>,
}

/// Reads the Codex package's entry of the generation at `directory`.
///
/// # Panics
///
/// Panics where the generation's index does not name the package exactly once, or names a
/// capability the vocabulary does not hold.
fn generation_entry(directory: &Path) -> GenerationEntry {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join("targets/index.json")).expect("the generation's index"),
    )
    .expect("the index is JSON");
    let named: Vec<&serde_json::Value> = index["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["plugin_id"] == codex().to_string())
        .collect();
    assert_eq!(
        named.len(),
        1,
        "the generation's index names the Codex package once, not {} times",
        named.len()
    );
    let entry = named[0];
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_owned();
    let mut grant: Vec<PluginCapability> = entry["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|request| {
            serde_json::from_value::<PluginCapability>(request["capability"].clone())
                .expect("a capability of the vocabulary")
        })
        .filter(|capability| !CapabilityCeiling::default_ceiling().permits(*capability))
        .collect();
    grant.sort();
    grant.dedup();
    GenerationEntry {
        version: text(&entry["version"]),
        manifest_digest: text(&entry["manifest_digest"]),
        grant,
    }
}

/// Which list of variables a second person's shell is created with.
#[derive(Debug, PartialEq, Eq)]
enum SecondList {
    /// The newer build's: its own configuration directory and no login.
    Newer,
    /// The first shell's: the login and the configuration directory the run prepared, where the
    /// case has them.
    First,
}

/// The newer build's list is prepared only in a case that upgrades, and it holds no login, so the
/// second session of any other case takes the first shell's.
fn second_list(upgrade: bool) -> SecondList {
    if upgrade {
        SecondList::Newer
    } else {
        SecondList::First
    }
}

/// A second session of a case that does not upgrade is given the first shell's list, which a real
/// route has prepared, and not the newer build's, which it has not.
#[test]
fn a_second_session_of_a_case_that_does_not_upgrade_takes_the_first_shells_variables() {
    assert_eq!(second_list(false), SecondList::First);
    assert_eq!(second_list(true), SecondList::Newer);
}

/// A person at a terminal in a managed session.
struct Person {
    window: Window,
    session_id: SessionId,
    /// What the shell is expected to hold of the list its `kr new` was given.
    expected: Expected,
}

impl Person {
    /// Enters a managed shell with `kr new` on a terminal of its own, and waits for its prompt. The
    /// session is created with the harness's variables and `given`, the case's own.
    fn enters(
        ctx: &Context,
        host: &Host<'_>,
        given: &[(String, String)],
        known: &[SessionId],
    ) -> Self {
        let home = ctx.run.home();
        let mut variables = if known.is_empty() {
            ctx.prepare_variables(host)
        } else {
            ctx.second_variables(host)
        };
        variables.extend(given.iter().cloned());
        let expected = ctx.expects(host, &variables);
        std::fs::write(home.join(".zshrc"), ZSHRC).expect("writes the startup file");
        // The login is the agent's session's alone: `kr shell install` is not given it.
        let mut install = host.command(&["shell", "install", "--json"]);
        install
            .env_clear()
            .envs(ctx.without_login(&variables).iter().cloned());
        let installed = kr_e2e_m1b::run::output_within(install, LIVENESS)
            .unwrap_or_else(|why| panic!("kr shell install: {why}"));
        assert!(
            installed.status.success(),
            "kr shell install: {}{}",
            String::from_utf8_lossy(&installed.stdout),
            String::from_utf8_lossy(&installed.stderr)
        );
        let (window, queries) = Window::open_answering(
            &ctx.run,
            "kr new",
            &ctx.run.binary("kr"),
            &[
                "new",
                "--attach",
                "--headless",
                "--shell",
                &ctx.shell.executable.display().to_string(),
                "--shell-mode",
                "managed",
                "--startup",
                "interactive",
                "--cwd",
                &ctx.run.work().display().to_string(),
            ],
            ctx.run.root(),
            &variables,
        );
        answered(&window, queries);
        let _ =
            window.wait_for_screen(PROMPT.trim_end(), "the managed shell reads at the terminal");
        let sessions = host.live_sessions();
        assert_eq!(
            sessions.len(),
            known.len() + 1,
            "one live session more than the {} known: {sessions:?}",
            known.len()
        );
        let added: Vec<SessionId> = sessions
            .iter()
            .map(|session| {
                session["session_id"]
                    .as_str()
                    .expect("a session identifier")
                    .parse()
                    .expect("a session identifier")
            })
            .filter(|id| !known.contains(id))
            .collect();
        assert_eq!(added.len(), 1, "one session the entry added: {sessions:?}");
        let session_id = added[0];
        Self {
            window,
            session_id,
            expected,
        }
    }

    /// Types one line and its return.
    fn types(&self, line: &str) {
        self.window.type_text(format!("{line}\r").as_bytes());
    }

    /// Waits until the screen shows `needle`.
    fn sees(&self, needle: &str, why: &str) -> Vec<String> {
        self.window.wait_for_screen(needle, why)
    }

    /// Waits until the screen no longer shows `needle`.
    fn stops_seeing(&self, needle: &str, why: &str) {
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if !rows.iter().any(|row| row.contains(needle)) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the screen still shows {needle:?} after {LIVENESS:?}:\n{}",
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits until the agent's composer waits for a prompt: the screen shows `composer` and not
    /// `busy`, which it shows while a turn runs.
    fn waits_for_the_composer(&self, composer: &str, busy: &str, why: &str) {
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            let shows = |needle: &str| rows.iter().any(|row| row.contains(needle));
            if shows(composer) && !shows(busy) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the composer does not wait for a prompt after {LIVENESS:?}; the screen is:\n{}",
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits until the agent's start is over: the screen shows `composer` and none of the entry's
    /// start `draft` texts. The agent's start draws a composer that drops what is typed at it, so
    /// the first turn is typed only after this.
    fn waits_for_the_start_draft_to_end(&self, composer: &str, draft: &[String], why: &str) {
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if start_is_over(&rows, composer, draft) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: {} after {LIVENESS:?}:\n{}",
                draft_showing(&rows, composer, draft).map_or_else(
                    || "the composer does not wait for a prompt".to_owned(),
                    |text| format!("the screen still shows the agent's start draft ({text})")
                ),
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Clears the shell's screen, so that what it shows afterwards is what the next line did.
    fn clears_the_screen(&self) {
        self.window.type_text(b"\x0c");
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if !rows.iter().any(|row| {
                row.contains(RAN_AS_TYPED) || row.contains("TUI:") || row.contains("kr-hook:")
            }) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the shell did not clear its screen in {:?}; it shows:\n{}",
                started.elapsed(),
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Reads the environment the shell holds at its prompt, with no agent run, and compares it with
    /// what `expected` gives it ([`session_environment`]): one line a part at the prompt, each
    /// printing names and digests and no value, read from the window's own screen and nowhere in
    /// the run's tree.
    ///
    /// # Errors
    ///
    /// Returns why the shell's environment is not as given, naming each variable and never a
    /// value, or why the answer could not be read whole. A pass returns the line that says what
    /// was compared ([`Expected::passed_line`]).
    fn reads_the_environment(&self, expected: &Expected) -> Result<String, String> {
        let mut tag = 0;
        let mut readings = Vec::new();
        for part in 0..expected.value_parts() {
            let rows = self.types_the_check(expected, &expected.value_line(part, tag), tag)?;
            readings.extend(expected.read_values(part, tag, &rows)?);
            tag += 1;
        }
        let mut exported: Vec<String> = Vec::new();
        let mut said: Option<session_environment::Snapshot> = None;
        let snapshot = loop {
            let rows =
                self.types_the_check(expected, &Expected::exported_line(exported.len(), tag), tag)?;
            let (names, snapshot) =
                session_environment::read_exported(tag, &exported, said.as_ref(), &rows)?;
            tag += 1;
            exported.extend(names);
            if exported.len() == snapshot.total {
                break snapshot;
            }
            said = Some(snapshot);
        };
        session_environment::checks_the_snapshot(&exported, &snapshot)?;
        self.clears_the_screen_of(session_environment::ROW);
        expected.judge(&readings, &exported)?;
        Ok(expected.passed_line(&exported))
    }

    /// Types one line of the environment's check on a cleared screen, and returns the screen once
    /// the row that ends the answer, numbered `tag`, shows.
    fn types_the_check(
        &self,
        expected: &Expected,
        line: &str,
        tag: usize,
    ) -> Result<Vec<String>, String> {
        self.clears_the_screen_of(session_environment::ROW);
        self.types(line);
        let end = tag.to_string();
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if let Some(name) = expected.shown_on(&rows) {
                return Err(format!(
                    "{} the screen shows the value of {name}, which no line of the check holds",
                    session_environment::NOT_AS_GIVEN
                ));
            }
            if rows.iter().any(|row| {
                row.split_whitespace()
                    .eq([session_environment::ROW, "end", end.as_str()])
            }) {
                return Ok(rows);
            }
            if started.elapsed() >= LIVENESS {
                return Err(format!(
                    "{} the shell did not end the answer in {LIVENESS:?}; the screen shows {} rows",
                    session_environment::NOT_READ_WHOLE,
                    rows.len()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Clears the shell's screen, so that no row of an earlier answer, which holds `needle`, is
    /// read as this one's.
    fn clears_the_screen_of(&self, needle: &str) {
        self.window.type_text(b"\x0c");
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if !rows.iter().any(|row| row.contains(needle)) {
                return;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the shell did not clear its screen of {needle:?} in {:?}; it shows:\n{}",
                started.elapsed(),
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Types `line`, which runs through the integration, and waits until the screen shows
    /// `needle`, with `before_typing` called right before each time the line is typed: each is a
    /// start of the agent. A line the shell ran as typed before the worker answered (its bound for
    /// the answer is one second) is typed again on a cleared screen; a launcher that refused the
    /// launch fails the case at once.
    fn types_until_it_shows(
        &self,
        line: &str,
        needle: &str,
        why: &str,
        before_typing: &dyn Fn(),
    ) -> Vec<String> {
        let started = Instant::now();
        let mut typed = 0_usize;
        loop {
            // Before the screen is cleared, which waits for a shell that an agent still running holds,
            // and again right before the typing.
            before_typing();
            self.clears_the_screen();
            before_typing();
            self.types(line);
            typed += 1;
            loop {
                let rows = self.window.screen();
                if rows.iter().any(|row| row.contains(needle)) {
                    return rows;
                }
                assert!(
                    !rows.iter().any(|row| row.contains("kr-hook:")),
                    "{why}: the launcher refused the line (typed {typed} times), and the screen is:\n{}",
                    rows.join("\n")
                );
                if rows.iter().any(|row| row.contains(RAN_AS_TYPED)) {
                    break;
                }
                assert!(
                    started.elapsed() < LIVENESS,
                    "{why}: waited {:?} for {needle:?} (typed {typed} times), and the screen is:\n{}",
                    started.elapsed(),
                    rows.join("\n")
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the line ran as typed each of the {typed} times it was typed in {:?}",
                started.elapsed()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Types `text`, which holds `mark`, at an agent's composer, waits until the screen shows the
    /// mark, and submits it after a moment, so that the line end arrives on its own and is not
    /// taken for a character of the text. A slash command is typed this way too, its own text as
    /// the mark.
    fn composes(&self, text: &str, mark: &str) {
        self.window.type_text(text.as_bytes());
        let _ = self
            .window
            .wait_for_screen(mark, "the typed prompt is on the screen");
        std::thread::sleep(Duration::from_millis(300));
        self.window.type_text(b"\r");
    }

    /// Types the slash command `command` and waits until a row of the agent's own list of commands
    /// names it: a row below the composer's own row ([`list_region`]) that the screen did not show
    /// before the command was typed. Returns the rows the screen showed before, which the caller
    /// compares the screen with once the composer is cleared. A row that was on the screen already
    /// (a history row, a help screen, the tip a terminal prints at its start), a row above the
    /// composer, whatever it says or becomes when the screen is drawn again, and the composer's own
    /// row are not the list.
    ///
    /// # Panics
    ///
    /// Panics when no such row appears: a text the agent does not know as a command goes to its
    /// model as a prompt, which no charge was made for.
    fn lists(&self, command: &str) -> Vec<String> {
        let before = self.window.screen();
        self.window.type_text(command.as_bytes());
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if list_region(&before, &rows, command)
                .iter()
                .any(|row| lists_command(row, command))
            {
                return before;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the agent's own list of commands does not name {command:?} in a row below the \
                 composer's own that was not on the screen before it was typed, after \
                 {LIVENESS:?}, so it was not sent; the screen is:\n{}",
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Types the slash command `command`, waits until the agent's own list of commands names it
    /// ([`Person::lists`]), pauses, and submits it.
    fn sends_command(&self, command: &str) {
        let _ = self.lists(command);
        std::thread::sleep(Duration::from_millis(300));
        self.window.type_text(b"\r");
    }

    /// Reads the agent's list of commands for each of `commands`, before any turn is charged: types
    /// the command, requires a row of the list that names it ([`Person::lists`]), clears the
    /// composer with the entry's key, and waits until what the typing drew has gone. No prompt is
    /// sent and no turn is spent, so a command the list does not name stops the case before its
    /// first charge, and a `stop_before_turns` run shows the list in remote mode with none.
    ///
    /// # Panics
    ///
    /// Panics at the first command no row of the list names, or when the composer is not cleared.
    fn reads_the_commands(&self, account: &Account, commands: &[&str]) {
        for command in commands {
            let before = self.lists(command);
            self.window.type_text(account.clear.as_bytes());
            let started = Instant::now();
            loop {
                let rows = self.window.screen();
                if !new_rows(&before, &rows)
                    .iter()
                    .any(|row| row.contains(command))
                {
                    break;
                }
                assert!(
                    started.elapsed() < LIVENESS,
                    "the composer is not cleared of {command:?} after {LIVENESS:?}; the screen is:\n{}",
                    rows.join("\n")
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// Waits until a row that the screen did not show in `before`, the rows it showed when the
    /// prompt was sent, shows `sum` as a number of its own ([`shows_sum`]): the answer is output
    /// drawn after the prompt, and not text that was on the screen already.
    fn sees_the_sum(&self, sum: &str, before: &[String], why: &str) -> Vec<String> {
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if answered_since(before, &rows, sum) {
                return rows;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: no row drawn since the prompt shows {sum} as a number of its own after \
                 {LIVENESS:?}; the screen is:\n{}",
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A question whose answer, a number of at least 1000, is not on the screen now (by the matcher
    /// the answer is checked with) and is in none of `avoid`, so that the answer's appearing is the
    /// agent's.
    fn asks(&self, avoid: &[&str]) -> (String, String) {
        loop {
            let (question, sum) = fresh_question(avoid);
            if !on_screen(&self.window.screen(), &sum) {
                return (question, sum);
            }
        }
    }

    /// Waits for the agent's approval dialog, read once more for up to a second where it does not
    /// yet ask for `command` alone, and returns its rows only where it asks to run `command` and
    /// nothing else.
    fn dialog_names(&self, account: &Account, command: &str) -> Vec<String> {
        let mut rows = self.sees(&account.approval.shows, "the agent asks for approval");
        let settling = Instant::now();
        loop {
            match account.approval.names_only(&rows, command) {
                Ok(()) => return rows,
                Err(_) if settling.elapsed() < Duration::from_secs(1) => {
                    std::thread::sleep(Duration::from_millis(200));
                    rows = self.window.screen();
                }
                Err(what) => {
                    panic!("the agent asks for something other than the case's command: {what}")
                }
            }
        }
    }
}

/// Whether `row` of the screen is a line of the agent's own list of commands that names `command`:
/// the command first, with the frame an agent draws around its rows and the spaces beside it taken
/// off, and a description after it. The composer's own row, which shows what was typed after the
/// prompt's mark, and a longer command that begins with the same letters, are not it.
fn lists_command(row: &str, command: &str) -> bool {
    let row = row.trim_matches(|character: char| {
        character.is_whitespace() || matches!(character, '│' | '┃' | '║')
    });
    row.strip_prefix(command)
        .is_some_and(|rest| rest.starts_with(char::is_whitespace) && !rest.trim().is_empty())
}

/// The rows of `after`, each with its place on the screen, that `before` did not show: every row of
/// `after` that is not matched by a row of `before`, each row of `before` matching one. A row shown
/// twice where it was shown once is new once.
fn new_row_places<'a>(before: &[String], after: &'a [String]) -> Vec<(usize, &'a str)> {
    let mut shown: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for row in before {
        *shown.entry(row.trim()).or_default() += 1;
    }
    let mut fresh = Vec::new();
    for (place, row) in after.iter().enumerate() {
        match shown.get_mut(row.trim()) {
            Some(count) if *count > 0 => *count -= 1,
            _ => fresh.push((place, row.as_str())),
        }
    }
    fresh
}

/// The rows of `after` that `before` did not show ([`new_row_places`]).
fn new_rows<'a>(before: &[String], after: &'a [String]) -> Vec<&'a str> {
    new_row_places(before, after)
        .into_iter()
        .map(|(_, row)| row)
        .collect()
}

/// The characters of the frame a card is drawn in.
const FRAME: [char; 3] = ['│', '┃', '║'];

/// Whether `row` draws `text` as the agent's start draft does: the text alone on its row, the frame
/// and the blanks beside it cut off (a line of its own, as the resume and fork drafts draw), or a
/// whole field of a card row that starts and ends with the frame, bounded on each side by a blank or
/// the frame (the header card's `model:     loading`). The text inside a longer word or a path
/// (`/work/loading`, `loading-app`) is no draft, and neither is it in a row that is no card, such as
/// a line of prose or a command's continuation row (`  │ echo loading data`), which has no closing
/// frame. A line of the agent's history that holds a text alone, or inside a closed frame, still
/// reads as the draft; such a start is taken to be a draft and the part fails at its time bound with
/// the screen printed.
fn draws_draft(row: &str, text: &str) -> bool {
    let edge = |character: Option<char>| {
        character.is_none_or(|character| character.is_whitespace() || FRAME.contains(&character))
    };
    row.trim_matches(|character: char| character.is_whitespace() || FRAME.contains(&character))
        == text
        || (row.trim_start().starts_with(FRAME)
            && row.trim_end().ends_with(FRAME)
            && row.match_indices(text).any(|(at, _)| {
                edge(row[..at].chars().next_back()) && edge(row[at + text.len()..].chars().next())
            }))
}

/// The first of the entry's start draft texts that `rows` show, where the agent's start is still a
/// draft whose composer is not yet the one a prompt is typed at. The agent draws the draft above
/// its composer, so only the rows above the first row that shows `composer` count (a status line
/// below it does not), and only as [`draws_draft`] reads a row. `None` where the entry names no
/// text or none shows.
fn draft_showing<'t>(rows: &[String], composer: &str, draft: &'t [String]) -> Option<&'t str> {
    let above = rows
        .iter()
        .position(|row| row.contains(composer))
        .unwrap_or(rows.len());
    draft
        .iter()
        .map(String::as_str)
        .find(|text| rows[..above].iter().any(|row| draws_draft(row, text)))
}

/// Whether the agent's start is over on `rows`: its composer shows, and none of the entry's start
/// draft texts does. A composer drawn while the start is still a draft drops what is typed at it.
fn start_is_over(rows: &[String], composer: &str, draft: &[String]) -> bool {
    rows.iter().any(|row| row.contains(composer)) && draft_showing(rows, composer, draft).is_none()
}

/// Said at a part's first start where the entry names no start draft text: nothing waits for the
/// start draft to end before the first turn is typed.
fn says_when_no_draft_is_named(account: &Account) {
    if account.draft.is_empty() {
        eprintln!(
            "the entry names no start draft texts (account.draft), so the first turn is typed \
             without waiting for the start draft to end"
        );
    }
}

/// The first turn is typed only once the agent's start is over: the draft's composer beside its
/// `loading` header is not the real screen, the real screen is, and an entry that names no draft
/// text has none to wait for.
#[test]
fn a_composer_drawn_beside_the_start_draft_is_not_the_real_screen() {
    let rows = |rows: &[&str]| rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>();
    let composer = "Ask Codex to do anything";
    let draft = ["loading".to_owned()];
    let drawn = rows(&[
        "│ model:     loading   /model to change │",
        "› Ask Codex to do anything",
    ]);
    let real = rows(&[
        "│ model:     gpt-5.5   /model to change │",
        "› Ask Codex to do anything",
    ]);
    assert!(
        !start_is_over(&drawn, composer, &draft),
        "the draft's composer, beside its loading header, is not the real screen"
    );
    assert!(start_is_over(&real, composer, &draft), "the real screen is");
    assert!(
        !start_is_over(&rows(&["starting"]), composer, &draft),
        "no composer is no start over"
    );
    assert!(
        start_is_over(&drawn, composer, &[]),
        "an entry that names no draft text has none to wait for"
    );
}

/// A `loading` in a path, in a status line under the composer, in the history or in a command's
/// continuation row is not the start draft, and the header card's `loading` and the resume and fork
/// lines are, framed or not: a start that is over stays over where the real screen holds the word
/// elsewhere, and a start that is a draft stays one.
#[test]
fn a_loading_in_a_path_a_status_line_or_the_history_is_not_the_start_draft() {
    let rows = |rows: &[&str]| rows.iter().map(|row| (*row).to_owned()).collect::<Vec<_>>();
    let composer = "Ask Codex to do anything";
    let draft = [
        "loading".to_owned(),
        "Resuming session…".to_owned(),
        "Forking session…".to_owned(),
    ];
    let elsewhere = rows(&[
        "│ model:     gpt-5.5   /model to change │",
        "│ directory: /work/loading │",
        "│ directory: ~/loading-app │",
        "› the loading screen shows a spinner",
        "  Codex is loading it",
        "  │ echo loading data",
        "  the loading │",
        "› Ask Codex to do anything",
        "  gpt-5.5 loading · ~/work",
        "  loading",
    ]);
    assert_eq!(
        draft_showing(&elsewhere, composer, &draft),
        None,
        "a path, the history, a command's continuation row, a row that only closes with the frame and the status line under the composer are no draft"
    );
    assert!(
        start_is_over(&elsewhere, composer, &draft),
        "a correct start with the word elsewhere on the screen is over"
    );
    assert_eq!(
        draft_showing(
            &rows(&[
                "│ model:     loading   /model to change │",
                "› Ask Codex to do anything",
            ]),
            composer,
            &draft
        ),
        Some("loading"),
        "the header card's field is the draft"
    );
    assert_eq!(
        draft_showing(
            &rows(&["  Resuming session…", "› Ask Codex to do anything"]),
            composer,
            &draft
        ),
        Some("Resuming session…"),
        "the resume line, alone on its row, is the draft"
    );
    assert_eq!(
        draft_showing(
            &rows(&["│  Forking session…  │", "› Ask Codex to do anything"]),
            composer,
            &draft
        ),
        Some("Forking session…"),
        "the fork line inside a frame is the draft"
    );
    assert!(
        !start_is_over(
            &rows(&["  loading", "› Ask Codex to do anything"]),
            composer,
            &draft
        ),
        "the word alone on its row above the composer is the draft"
    );
}

/// Whether `row` is the composer's own row holding the typed `command`: the command with
/// something of the composer's before it, its mark, once the frame and the spaces beside the row
/// are taken off. A row of the list begins with the command.
fn is_composer_row(row: &str, command: &str) -> bool {
    let bare = |text: &str| {
        text.trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, '│' | '┃' | '║')
        })
        .to_owned()
    };
    let row = bare(row);
    row.find(command)
        .is_some_and(|at| !bare(&row[..at]).is_empty())
}

/// The rows that make up the agent's list of commands after `command` was typed: the rows the
/// screen did not show before, below the new row that is the composer's own holding the typed
/// command. The agent draws its list under the composer, so a row above it, a history row that is
/// drawn again with other words, and a help row that appears elsewhere are not the list; where no
/// new row is the composer's own, there is no region.
fn list_region<'a>(before: &[String], after: &'a [String], command: &str) -> Vec<&'a str> {
    let fresh = new_row_places(before, after);
    let Some(composer) = fresh
        .iter()
        .find(|(_, row)| is_composer_row(row, command))
        .map(|(place, _)| *place)
    else {
        return Vec::new();
    };
    fresh
        .into_iter()
        .filter(|(place, _)| *place > composer)
        .map(|(_, row)| row)
        .collect()
}

/// `digits` with a comma before each group of three from the right: `1557` as `1,557`.
fn with_thousands(digits: &str) -> String {
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

/// Whether `row` holds `form` as a whole word: not as part of a longer word, number or identifier.
/// A letter, a digit, a hyphen, an underscore, a slash or a colon on either side joins it to one
/// (`a1557`, `0198-1557-7abc`), and so does a point or a comma that stands between it and another
/// digit (`1557.25`, `1557,123`, `12,1557`). A point or a comma that ends a sentence does not.
fn whole_word(row: &str, form: &str) -> bool {
    let joins = |character: char| character.is_alphanumeric() || "-_/:".contains(character);
    row.match_indices(form).any(|(start, _)| {
        let mut before = row[..start].chars().rev();
        let mut after = row[start + form.len()..].chars();
        let joined_before = match before.next() {
            Some(character) if joins(character) => true,
            Some('.' | ',') => before.next().is_some_and(|digit| digit.is_ascii_digit()),
            _ => false,
        };
        let joined_after = match after.next() {
            Some(character) if joins(character) => true,
            Some('.' | ',') => after.next().is_some_and(|digit| digit.is_ascii_digit()),
            _ => false,
        };
        !joined_before && !joined_after
    })
}

/// Whether `row` shows `sum`, a number of four digits or more, as a number of its own, written as
/// digits alone or with a comma as the thousands separator.
fn shows_sum(row: &str, sum: &str) -> bool {
    whole_word(row, sum) || whole_word(row, &with_thousands(sum))
}

/// Whether a row of `rows` shows `sum` ([`shows_sum`]): what a question's answer must not already
/// be on the screen as, by the matcher the answer is checked with.
fn on_screen(rows: &[String], sum: &str) -> bool {
    rows.iter().any(|row| shows_sum(row, sum))
}

/// Whether `after` has a row that shows `sum` ([`shows_sum`]) and that `before`, the screen when
/// the prompt was sent, did not show: the answer is output drawn since the prompt.
fn answered_since(before: &[String], after: &[String], sum: &str) -> bool {
    new_rows(before, after)
        .iter()
        .any(|row| shows_sum(row, sum))
}

/// A named pipe in the run's working directory: a command that writes to it waits there until the
/// case reads, so the case holds a turn open for as long as it needs, and reads what the command
/// wrote. It is made before the agent first starts, through the working directory's held handle
/// (the harness writes nothing through a path of the run after that), and its reader is opened
/// through the same handle with no link followed at its name, on the object that was made.
struct Fifo {
    name: String,
    made: (u64, u64),
}

impl Fifo {
    /// Makes the pipe `name` in the working directory.
    fn made_in(ctx: &Context, name: &str) -> Self {
        let made = ctx
            .work
            .as_ref()
            .expect("the working directory was recorded")
            .make_fifo(ctx.run.root(), ctx.run.pin(), name)
            .unwrap_or_else(|why| panic!("the case's pipe: {why}"));
        Self {
            name: name.to_owned(),
            made,
        }
    }

    /// Opens the pipe for reading without waiting for a writer, which lets a command blocked on
    /// opening it for writing go on. The reader stays open, so that a second run of the command,
    /// which would block on opening the pipe, finds it open and writes: what it wrote is read too.
    fn reader(&self, ctx: &Context) -> FifoReader {
        let file = ctx
            .work
            .as_ref()
            .expect("the working directory was recorded")
            .open_fifo_for_reading(ctx.run.root(), ctx.run.pin(), &self.name, self.made)
            .unwrap_or_else(|why| panic!("the case's pipe cannot be opened: {why}"));
        FifoReader {
            file,
            text: Vec::new(),
        }
    }
}

/// An open reader of a [`Fifo`], and everything it has read.
struct FifoReader {
    file: std::fs::File,
    text: Vec<u8>,
}

impl FifoReader {
    /// Reads what the pipe holds now, without waiting.
    fn poll(&mut self) {
        loop {
            let mut buffer = [0_u8; 256];
            match self.file.read(&mut buffer) {
                Ok(count) if count > 0 => self.text.extend_from_slice(&buffer[..count]),
                Ok(_) => return,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(error) => panic!("the case's pipe cannot be read: {error}"),
            }
        }
    }

    /// The lines read so far, each trimmed.
    fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.text)
            .lines()
            .map(|line| line.trim().to_owned())
            .collect()
    }
}

/// What the application's server starts for the turn: a shell with a process of its own, so that
/// there is something below the server to end.
fn command(tools: &Path) -> String {
    format!(
        r#"["/bin/sh", "-c", "sleep 120 & wait", "{}"]"#,
        tools.display()
    )
}

/// The file that lets the stand-in's terminal go on, in the working directory.
fn release_of(ctx: &Context) -> PathBuf {
    ctx.run.work().join("release")
}

/// Lets the stand-in's terminal go on: the file [`release_of`] names is created through the working
/// directory's held handle, by exclusive creation with no link followed at its name, so a file or a
/// link the agent left there refuses the release and nothing is written through it.
fn releases(ctx: &Context) {
    ctx.work
        .as_ref()
        .expect("the working directory was recorded")
        .create_new(ctx.run.root(), ctx.run.pin(), "release", b"go")
        .unwrap_or_else(|why| panic!("the release: {why}"));
}

/// The file the stand-in's server notes the frames it received in.
fn received_by(ctx: &Context) -> PathBuf {
    ctx.run.root().join("received")
}

/// The lines the stand-in's server noted for what it received.
fn received_lines(ctx: &Context) -> Vec<String> {
    std::fs::read_to_string(received_by(ctx))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// How many requests of `method` the stand-in's server received.
fn requests_of(ctx: &Context, method: &str) -> usize {
    let prefix = format!("params {method} ");
    received_lines(ctx)
        .iter()
        .filter(|line| line.starts_with(&prefix))
        .count()
}

/// Whether the binding names `thread` and, when `turn` is given, that turn, and rich work is not
/// suspended.
fn names(binding: &AgentBindingState, thread: &str, turn: Option<&str>) -> bool {
    text_of(&binding.thread_id).as_deref() == Some(thread)
        && text_of(&binding.turn_id).as_deref() == turn
        && unsuspended(binding)
}

/// What a nullable identifier says, where it says one.
fn text_of<T: ToString>(nullable: &Nullable<T>) -> Option<String> {
    nullable.0.as_ref().map(ToString::to_string)
}

/// Whether rich work is available on the binding: nothing has suspended it.
fn unsuspended(binding: &AgentBindingState) -> bool {
    !binding.rich_mutations_suspended && binding.suspension_reason.0.is_none()
}

/// The thread a binding names, where it names one.
fn thread_of(binding: &AgentBindingState) -> Option<String> {
    text_of(&binding.thread_id)
}

/// What the binding says while a request of the terminal's that selects or leaves a conversation has
/// not been answered: rich work waits for the answer, which takes a round trip.
const IN_FLIGHT_REASON: &str =
    "the terminal has asked to change its conversation and the server has not answered";

/// The longest a binding may stay held for a request in flight. A request is answered in a round
/// trip; a hold that lasts past this is one the answer never ended.
const IN_FLIGHT_BOUND: Duration = Duration::from_secs(10);

/// How long a case keeps reading a binding after a turn, so that the terminal's own helper thread
/// (a title for the conversation, which it leaves when the turn on it ends or after thirty seconds)
/// has been started and left before the last read.
const HELPER_FLOW: Duration = Duration::from_secs(35);

/// What one read of a binding is, to a wait that takes a bounded hold for a request in flight.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Rich work is available: the read counts.
    Open,
    /// Rich work waits for a request in flight, for less than the bound: read again.
    Waiting,
    /// Anything else, with why: the wait fails.
    Failed(String),
}

/// Judges each read of a binding for a wait that accepts a hold for a request in flight, for a
/// bounded time, and no other suspension: a suspension for any other reason, a thread other than
/// the one the wait is for, and a hold that does not end each fail it.
struct InFlightWatch {
    /// The thread every read must name, where the wait knows it.
    thread: Option<String>,
    /// When the hold that is still going on began.
    since: std::cell::Cell<Option<Instant>>,
}

impl InFlightWatch {
    fn new(thread: Option<&str>) -> Self {
        Self {
            thread: thread.map(str::to_owned),
            since: std::cell::Cell::new(None),
        }
    }

    /// The verdict on a read taken at `now`.
    fn judge(&self, binding: &AgentBindingState, now: Instant) -> Verdict {
        if let Some(want) = &self.thread {
            match thread_of(binding) {
                Some(got) if &got == want => {}
                Some(got) => {
                    return Verdict::Failed(format!("it names the thread {got}, not {want}"));
                }
                None => return Verdict::Failed(format!("it names no thread, not {want}")),
            }
        }
        if unsuspended(binding) {
            self.since.set(None);
            return Verdict::Open;
        }
        match binding.suspension_reason.0.as_deref() {
            Some(reason)
                if binding.rich_mutations_suspended && reason.starts_with(IN_FLIGHT_REASON) =>
            {
                let since = self.since.get().unwrap_or(now);
                self.since.set(Some(since));
                if now.duration_since(since) >= IN_FLIGHT_BOUND {
                    Verdict::Failed(format!(
                        "rich work has waited more than {IN_FLIGHT_BOUND:?} for a request in flight: {reason}"
                    ))
                } else {
                    Verdict::Waiting
                }
            }
            other => Verdict::Failed(format!("rich work is suspended: {other:?}")),
        }
    }
}

/// A host, a paired device and a person in a managed shell, with the agent not yet started.
struct Session<'a> {
    ctx: &'a Context,
    host: Host<'a>,
    remote: Remote,
    person: Person,
    device: Device,
    paired: PairedHost,
    /// Whether the shell's environment was read before the agent's first start.
    environment_read: std::cell::Cell<bool>,
    /// Whether the stand-in leaves the run's tree as the harness made it, so that a daemon may be
    /// started again after it started ([`the_stand_in_leaves_the_runs_tree`]).
    stand_in_leaves_the_tree: bool,
    /// A second person on the same host and device, in a second session, with a connection of
    /// the device's of its own (a connection is fixed to one session by the host).
    second: Option<Second>,
}

/// Whether the stand-in that `variants` select leaves the run's tree as the harness made it. The
/// variant `leave-a-host` rewrites the environment's identity in the run's state and links
/// another host's socket there, so a daemon is never started again over that tree.
fn the_stand_in_leaves_the_runs_tree(variants: &str) -> bool {
    !variants
        .split(',')
        .map(str::trim)
        .any(|variant| variant == "leave-a-host")
}

/// Only the variants that change nothing of the run's tree allow a daemon to be started again.
#[test]
fn a_stand_in_that_rewrites_the_runs_state_is_not_one_that_leaves_the_tree_as_it_was() {
    assert!(the_stand_in_leaves_the_runs_tree(""));
    assert!(the_stand_in_leaves_the_runs_tree(
        "leave-unanswered,tick,ping-when-released,stay"
    ));
    assert!(!the_stand_in_leaves_the_runs_tree(
        "answer-when-released,keep-reading,stay,leave-a-host"
    ));
    assert!(!the_stand_in_leaves_the_runs_tree("leave-a-host"));
    assert!(!the_stand_in_leaves_the_runs_tree("stay, leave-a-host "));
    assert!(!the_stand_in_leaves_the_runs_tree(" leave-a-host,stay"));
    assert!(!the_stand_in_leaves_the_runs_tree(
        "stay,\tleave-a-host\t,tick"
    ));
    assert!(the_stand_in_leaves_the_runs_tree(" stay , tick "));
}

/// The second person of a [`Session::open_two`], with the device's second connection.
struct Second {
    person: Person,
    remote: Remote,
}

impl<'a> Session<'a> {
    /// Opens the session; `variants` are the stand-in's, and a real agent takes none.
    fn open(ctx: &'a Context, variants: &str) -> Self {
        Self::open_with(ctx, variants, &[])
    }

    /// Opens the session as [`Session::open`] does, with `more` variables of the stand-in's given
    /// in the same list.
    fn open_with(ctx: &'a Context, variants: &str, more: &[(&str, String)]) -> Self {
        let host = ctx.host();
        let (device, paired, remote) = ctx.pair(&host);
        let person = Person::enters(ctx, &host, &ctx.stand_in_variables(variants, more), &[]);
        Self {
            ctx,
            host,
            remote,
            person,
            device,
            paired,
            environment_read: std::cell::Cell::new(false),
            stand_in_leaves_the_tree: the_stand_in_leaves_the_runs_tree(variants),
            second: None,
        }
    }

    /// Opens two sessions on one host and one device before anything of the agent starts: the
    /// device's two connections are made first, one for each session, the first person enters, then
    /// the second person enters with the sessions seen before (and so is the session that entry
    /// added), and both shells' environments are read at their prompts. `second_variants` are the
    /// stand-in's variants in the second person's shell.
    fn open_two(ctx: &'a Context, variants: &str, second_variants: &str) -> Self {
        let host = ctx.host();
        let (device, paired, remote) = ctx.pair(&host);
        let second_remote = ctx
            .runtime
            .block_on(device.connect(&paired))
            .unwrap_or_else(|why| panic!("the device's second connection: {why}"));
        let person = Person::enters(ctx, &host, &ctx.stand_in_variables(variants, &[]), &[]);
        let second = Person::enters(
            ctx,
            &host,
            &ctx.stand_in_variables(second_variants, &[]),
            &[person.session_id],
        );
        match second.reads_the_environment(&second.expected) {
            Ok(compared) => eprintln!("{compared}"),
            Err(why) => panic!("{why}"),
        }
        Self {
            ctx,
            host,
            remote,
            person,
            device,
            paired,
            environment_read: std::cell::Cell::new(false),
            stand_in_leaves_the_tree: the_stand_in_leaves_the_runs_tree(variants),
            second: Some(Second {
                person: second,
                remote: second_remote,
            }),
        }
    }

    fn session_id(&self) -> SessionId {
        self.person.session_id
    }

    /// Types the agent's command, alone or with `extra` words after it (`resume` and a thread),
    /// waits until the terminal is up, and returns the live instance the host announces for it,
    /// other than `not`, once the host says that a gateway serves it: a launch that ran as typed,
    /// with no gateway, is found here, before any prompt is sent or charged. On a real route the
    /// terminal's list of commands is then read for each of `commands`, the slash commands the case
    /// goes on to send, still before any prompt, so that a command the list does not name stops
    /// the case with no charge; and only then does an entry that asks to stop before its first turn
    /// stop the case.
    fn starts_the_agent(
        &self,
        extra: &[&str],
        not: Option<ApplicationInstanceId>,
        commands: &[Slash],
    ) -> ApplicationInstanceId {
        self.starts_the_agent_showing(ASKED, extra, not, commands)
    }

    /// [`Self::starts_the_agent`] with the text that the stand-in's screen shows once it is up
    /// behind the gateway named: a stand-in that starts no turn of its own never asks for the
    /// approval that [`ASKED`] names.
    fn starts_the_agent_showing(
        &self,
        stand_in_shows: &str,
        extra: &[&str],
        not: Option<ApplicationInstanceId>,
        commands: &[Slash],
    ) -> ApplicationInstanceId {
        // Before anything of the agent runs, the probes of a real route included, the shell's own
        // environment is read at its prompt: the first start only, since an agent's start can change
        // what a later read would show.
        if !self.environment_read.replace(true) {
            match self.person.reads_the_environment(&self.person.expected) {
                Ok(compared) => eprintln!("{compared}"),
                Err(why) => panic!("{why}"),
            }
        }
        // From here the harness runs no `kr` and ends the host's processes by the identities it
        // recorded: the agent runs in the same account and may leave anything in the run's state.
        // The stand-in is the harness's own program and, but for the variant that leaves for
        // another host, leaves nothing: a case on it may start the daemon again.
        if matches!(self.ctx.route, Route::StandIn) && self.stand_in_leaves_the_tree {
            self.host.agent_is_a_stand_in();
        }
        self.host.agent_starts();
        match &self.ctx.route {
            Route::StandIn => {
                let _ = self.person.types_until_it_shows(
                    "codex",
                    stand_in_shows,
                    "the terminal reaches the server through the gateway",
                    &|| self.ctx.checks_the_placed_files(),
                );
            }
            Route::Real(real) => {
                // The files that would load the person's own settings are known absent before the
                // agent's first start, as they are before any part's.
                if not.is_none() {
                    let absent = real.absent_list(&self.ctx.run);
                    real.checks_absent(&self.ctx.run, &absent);
                    // The entry's isolation probes, with the run's configuration directory and no
                    // switch typed: no prompt, no turn, and no model.
                    // No probe is given the login: none of them needs an account, and the account
                    // variable selects the person's pooled account.
                    real.proves_isolation(
                        &self.ctx.run,
                        &self.ctx.without_login(&self.ctx.variables(&self.host)),
                    );
                    real.checks_absent(&self.ctx.run, &absent);
                    // A case that upgrades proves the newer build's isolation here too, before
                    // any start of either: with its own configuration directory and no login.
                    if let Some(newer) = &self.ctx.newer_placed {
                        let newer_absent = real
                            .newer_absent
                            .get_or_init(|| real.newer_absent_list(&self.ctx.run));
                        real.checks_absent(&self.ctx.run, newer_absent);
                        real.proves_newer_isolation(
                            &self.ctx.run,
                            newer,
                            &self.ctx.newer_variables(&self.host),
                        );
                        real.checks_absent(&self.ctx.run, newer_absent);
                        real.records_the_newer_baseline(&self.ctx.run);
                    }
                }
                // The shell finds the agent by its name on a search path that starts in the run, which
                // an earlier start may have changed: the route is checked before each typing. An
                // agent started by hand with no login shows the build's first screen and no
                // composer.
                let _ = self.person.types_until_it_shows(
                    &real.typed(extra),
                    if self.ctx.manual {
                        &real.build.ready
                    } else {
                        &real.account.composer
                    },
                    "the agent reaches its composer",
                    &|| {
                        self.ctx.checks_the_placed_files();
                        real.checks_the_route(&self.ctx.run);
                    },
                );
                if !self.ctx.manual {
                    if not.is_none() {
                        says_when_no_draft_is_named(&real.account);
                    }
                    self.person.waits_for_the_start_draft_to_end(
                        &real.account.composer,
                        &real.account.draft,
                        "the agent reaches its composer",
                    );
                }
            }
        }
        let instance = self
            .ctx
            .instances_within(&self.remote, self.session_id(), "the instance", |read| {
                read.agent_instances
                    .instances
                    .iter()
                    .any(|instance| Some(instance.application_instance_id) != not)
            })
            .unwrap_or_else(|why| panic!("{why}\n{}", self.diagnosis()))
            .agent_instances
            .instances
            .iter()
            .map(|instance| instance.application_instance_id)
            .find(|id| Some(*id) != not)
            .expect("an instance");
        if !self.ctx.manual {
            self.gateway_serves(instance);
        }
        if let Route::Real(real) = &self.ctx.route
            && !self.ctx.manual
        {
            if !commands.is_empty() {
                self.person.waits_for_the_composer(
                    &real.account.composer,
                    &real.account.busy,
                    "the composer waits before the list of commands is read",
                );
                let texts: Vec<&str> = commands.iter().map(|which| real.slash(*which)).collect();
                self.person.reads_the_commands(&real.account, &texts);
            }
            assert!(
                !real.account.stop_before_turns,
                "the case stops once the agent is up behind the gateway and the checks before its \
                 first prompt have passed (the list of commands included), as the build list \
                 asks: no turn was started"
            );
        }
        instance
    }

    /// The probe-only run of the upgrade case: the shell's environment is read at its prompt, the
    /// harness stops running `kr`, the files that would load the person's own settings are known
    /// absent, the newer build's probes are recorded, and the files are known absent again. No
    /// agent is started, no prompt is typed and no login is given, so nothing is charged.
    ///
    /// # Panics
    ///
    /// Panics on a stand-in route, which has no newer build to probe.
    fn records_the_newer_probes(&self) -> serde_json::Value {
        let Route::Real(real) = &self.ctx.route else {
            panic!("a probe-only run probes the newer build of a build list entry");
        };
        let newer = self
            .ctx
            .newer_placed
            .as_ref()
            .expect("the newer build was placed");
        if !self.environment_read.replace(true) {
            match self.person.reads_the_environment(&self.person.expected) {
                Ok(compared) => eprintln!("{compared}"),
                Err(why) => panic!("{why}"),
            }
        }
        self.host.agent_starts();
        let absent = real.newer_absent_list(&self.ctx.run);
        real.checks_absent(&self.ctx.run, &absent);
        let recorded = real.records_the_newer_probes(
            &self.ctx.run,
            newer,
            &self.ctx.newer_variables(&self.host),
        );
        real.checks_absent(&self.ctx.run, &absent);
        real.records_the_newer_baseline(&self.ctx.run);
        recorded
    }

    /// What a failure at the instance wait or at the device's prompt adds to its text: one more read
    /// of the host's list of instances through the device, the last reads of it, and the terminal's
    /// screen ([`diagnosis_text`]).
    fn diagnosis(&self) -> String {
        let _ = self.ctx.read_instances(&self.remote, self.session_id());
        diagnosis_text(&self.ctx.polls, &self.person.window.screen())
    }

    /// Fails the case unless the host announces `instance` as served through a gateway, with no
    /// reason for running the line as typed.
    fn gateway_serves(&self, instance: ApplicationInstanceId) {
        let read = self.ctx.instances(&self.remote, self.session_id());
        let summary = read
            .agent_instances
            .instances
            .iter()
            .find(|summary| summary.application_instance_id == instance)
            .expect("the instance is still announced");
        assert!(
            summary.mode.uses_gateway() && summary.bypass.0.is_none(),
            "the launch was not served through a gateway: the host announces the mode {:?} and, for \
             running the line as typed, {:?}",
            summary.mode,
            summary.bypass.0
        );
        let binding = self.ctx.binding(&self.remote, self.session_id(), instance);
        assert!(
            binding.mode.uses_gateway(),
            "the binding is not a gateway's: its mode is {:?}",
            binding.mode
        );
    }

    fn binding_until(
        &self,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> AgentBindingState {
        self.ctx
            .binding_until(&self.remote, self.session_id(), instance, why, holds)
    }

    /// [`Session::binding_until`] where the failure is returned.
    fn binding_within(
        &self,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> Result<AgentBindingState, String> {
        self.ctx
            .binding_within(&self.remote, self.session_id(), instance, why, holds)
    }

    /// Reads the binding until `holds` is true of it with rich work available, and fails on any read
    /// that finds rich work suspended for a reason other than a request in flight, and on a hold for
    /// a request in flight that lasts past its bound.
    fn binding_unsuspended_until(
        &self,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> AgentBindingState {
        self.binding_settled_until(instance, why, None, holds)
    }

    /// As [`Self::binding_unsuspended_until`], and fails too on a read that names a thread other than
    /// `thread`, where one is given.
    fn binding_settled_until(
        &self,
        instance: ApplicationInstanceId,
        why: &str,
        thread: Option<&str>,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> AgentBindingState {
        let watch = InFlightWatch::new(thread);
        self.binding_until(instance, why, |binding| {
            match watch.judge(binding, Instant::now()) {
                Verdict::Open => holds(binding),
                Verdict::Waiting => false,
                Verdict::Failed(what) => panic!("{why}: {what}: {binding:?}"),
            }
        })
    }

    /// Reads the binding for `HELPER_FLOW` and fails on any read that does not name `thread` with
    /// no turn and rich work available (or held for a request in flight, within its bound): what the
    /// terminal's own helper thread does to the conversation is over by the end of it.
    fn binding_stays_on(&self, instance: ApplicationInstanceId, why: &str, thread: &str) {
        let watch = InFlightWatch::new(Some(thread));
        let until = Instant::now() + HELPER_FLOW;
        while Instant::now() < until {
            let binding = self.ctx.binding(&self.remote, self.session_id(), instance);
            match watch.judge(&binding, Instant::now()) {
                Verdict::Open => assert!(
                    binding.turn_id.0.is_none(),
                    "{why}: a turn runs: {binding:?}"
                ),
                Verdict::Waiting => {}
                Verdict::Failed(what) => panic!("{why}: {what}: {binding:?}"),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The approval the host holds, once its interpretation is verified under the package's
    /// decoder.
    fn interpreted_approval(&self) -> kr_protocol::gateway::PendingResource {
        let read = self.ctx.instances_until(
            &self.remote,
            self.session_id(),
            "the request is interpreted",
            |read| {
                read.agent_resources.resources.len() == 1
                    && read.agent_resources.resources[0].interpretation_verified
            },
        );
        read.agent_resources.resources[0].clone()
    }

    /// [`Session::interpreted_approval`] where a failed read or a wait that passed its bound is
    /// returned to the body, which has assertions still to make.
    ///
    /// # Errors
    ///
    /// Returns why the approval was not read.
    fn interpreted_approval_within(&self) -> Result<kr_protocol::gateway::PendingResource, String> {
        self.ctx
            .instances_within(
                &self.remote,
                self.session_id(),
                "the request is interpreted",
                |read| {
                    read.agent_resources.resources.len() == 1
                        && read.agent_resources.resources[0].interpretation_verified
                },
            )
            .map(|read| read.agent_resources.resources[0].clone())
    }
}

/// What a case does on a real route that the stand-in route does not: the work that every outcome
/// of a case, a panic and a failure of its own setup included, is followed by.
///
/// What the run started is ended, the person's own files are looked at again by their metadata, the
/// agent's record is counted for turns the ledger was not charged for, the run's directory is
/// searched for the keys and removed, and the outcome is appended. A case that failed is recorded as
/// failed and its failure goes on, as it came. `run` is none where the case failed before a run
/// stood: there is then no directory to search and no record to count, and the person's files are
/// looked at again and the outcome appended all the same.
/// Whether the agent's record and the run's directory may be read: only once everything the run
/// started is shown ended, since a process still running may be writing there. Otherwise nothing of
/// the run is read, and the outcome says so with a class.
fn run_may_be_read(writers_ended: bool) -> Result<(), Stop> {
    if writers_ended {
        Ok(())
    } else {
        Err((
            "run_not_read",
            "a process the run started was not shown ended, so the agent's record and the run's \
             directory were not read, and the run's directory was left where it is"
                .to_owned(),
        ))
    }
}

/// How a case that came back with `shows` and no panic is recorded, once the end has read what it
/// reads and found `stops`.
#[derive(Debug, PartialEq, Eq)]
enum Filed {
    /// A probe-only run: it started no agent and says nothing of the case itself.
    ProbeOnly,
    /// The body ran nothing and said why (a `not_run` in what it returned): the part has no result,
    /// whatever else the end found nothing wrong with.
    NotRun(String),
    /// The case showed what it was to, and the end found nothing.
    Passed,
    /// The end found something after the case showed what it was to.
    Failed,
}

/// Chooses how a returned case is recorded. A body that returns `not_run` is never recorded as
/// passed: a record that is empty because nothing ran agrees with every count the end makes.
fn recorded_as(shows: &serde_json::Value, stops: &[Stop], probe_only: bool) -> Filed {
    if !stops.is_empty() {
        return Filed::Failed;
    }
    if probe_only {
        return Filed::ProbeOnly;
    }
    match shows.get("not_run") {
        None | Some(serde_json::Value::Null) => Filed::Passed,
        Some(serde_json::Value::String(why)) => Filed::NotRun(why.clone()),
        Some(other) => Filed::NotRun(other.to_string()),
    }
}

/// A body that returns `not_run` is recorded as not run and never as passed, whatever its reason
/// says; a case the end stopped is recorded failed in either case, and a probe-only run is recorded
/// as one.
#[test]
fn a_body_that_returns_not_run_is_recorded_not_run_and_never_passed() {
    let ran = serde_json::json!({ "arm": "stand-in" });
    let not_run =
        serde_json::json!({ "arm": "pinned build", "not_run": "the entry names no fork" });
    assert_eq!(recorded_as(&ran, &[], false), Filed::Passed);
    assert_eq!(
        recorded_as(&not_run, &[], false),
        Filed::NotRun("the entry names no fork".to_owned())
    );
    assert!(matches!(
        recorded_as(&serde_json::json!({ "not_run": true }), &[], false),
        Filed::NotRun(_)
    ));
    let stops = [("uncharged_turns", "a turn went uncharged".to_owned())];
    assert_eq!(recorded_as(&ran, &stops, false), Filed::Failed);
    assert_eq!(recorded_as(&not_run, &stops, false), Filed::Failed);
    assert_eq!(recorded_as(&ran, &[], true), Filed::ProbeOnly);
}

/// The outcome of a real route that ended with `stops` (a key found in the run's directory before
/// the charge, a turn that was not charged, a run left in place), marked so that the harness stops
/// the agent here: `stop_agent` in its evidence and an `agent_stops` code of each stop's class. An
/// outcome with no stop, and one of the stand-in route, which has no account to protect, is left as
/// it is.
fn with_agent_stops(mut outcome: Outcome, real_route: bool, stops: &[Stop]) -> Outcome {
    if !real_route || stops.is_empty() {
        return outcome;
    }
    if !outcome.evidence.is_object() {
        outcome.evidence = serde_json::json!({});
    }
    outcome.evidence["stop_agent"] = serde_json::json!(true);
    let codes: Vec<Failure> = stops
        .iter()
        .map(|(class, _)| Failure::AgentStops(class))
        .collect();
    outcome.with_failures(&codes)
}

/// A real route's outcome with a stop stops the agent, under the stop's class; one with no stop, and
/// one of the stand-in route, does not.
#[test]
fn a_real_route_outcome_with_a_stop_stops_the_agent_under_the_stops_class() {
    let stops = [(
        "provider_key_found",
        "a key was found in the run's directory".to_owned(),
    )];
    let failed = || Outcome::failed("7", "a test", "why", serde_json::json!({ "turns": 0 }));
    let stopped = with_agent_stops(failed(), true, &stops);
    assert_eq!(stopped.evidence["stop_agent"], true);
    assert_eq!(
        stopped.evidence["failure_codes"],
        serde_json::json!([{ "code": "agent_stops", "class": "provider_key_found" }])
    );
    assert_eq!(stopped.evidence["turns"], 0);
    let unmarked = with_agent_stops(failed(), true, &[]);
    assert!(unmarked.evidence.get("stop_agent").is_none());
    let stand_in = with_agent_stops(failed(), false, &stops);
    assert!(stand_in.evidence.get("stop_agent").is_none());
    assert!(stand_in.evidence.get("failure_codes").is_none());
}

/// The outcome the end of a case records, from what the case showed or the text it failed with
/// (`said`), the stops the end found, and the route. A case that showed what it was to and found
/// no stop is passed, not run where it says so, or a probe-only run; one that stopped, or failed,
/// is failed, and its outcome on a real route stops the agent under each stop's class
/// ([`with_agent_stops`]).
fn outcome_of(
    case: &str,
    test: &str,
    said: &Result<serde_json::Value, String>,
    stops: &[Stop],
    probe_only: bool,
    real_route: bool,
    mut evidence: serde_json::Value,
) -> Outcome {
    let stopped: Vec<String> = stops
        .iter()
        .map(|(class, why)| format!("{class}: {why}"))
        .collect();
    match said {
        Ok(shows) => match recorded_as(shows, stops, probe_only) {
            Filed::ProbeOnly => {
                // A probe-only run starts no agent, so it says nothing of the case itself: it is a
                // run that was not made, with what it recorded.
                evidence["shows"] = shows.clone();
                Outcome::not_run(
                    case,
                    test,
                    "a probe-only run: the newer build's probes were recorded and no agent was \
                     started",
                    evidence,
                )
            }
            Filed::NotRun(why) => {
                evidence["shows"] = shows.clone();
                Outcome::not_run(case, test, &why, evidence)
            }
            Filed::Passed => {
                evidence["shows"] = shows.clone();
                Outcome::passed(case, test, evidence)
            }
            Filed::Failed => {
                evidence["shows"] = shows.clone();
                with_agent_stops(
                    Outcome::failed(case, test, &stopped.join("; "), evidence),
                    real_route,
                    stops,
                )
            }
        },
        Err(said) => {
            let reason = if stopped.is_empty() {
                said.clone()
            } else {
                format!("{said}; {}", stopped.join("; "))
            };
            with_agent_stops(
                Outcome::failed(case, test, &reason, evidence),
                real_route,
                stops,
            )
        }
    }
}

/// A case's end records a real route's failure or stop under the stops' classes, each of two
/// classes in order, whether the case showed what it was to or panicked; the stand-in route's
/// outcome, and one with no stop, does not stop the agent.
#[test]
fn the_outcome_a_case_ends_with_stops_the_agent_under_each_stops_class_on_a_real_route() {
    let stops = [
        (
            "provider_key_found",
            "a key was found in the run's directory".to_owned(),
        ),
        ("uncharged_turns", "a turn went uncharged".to_owned()),
    ];
    let codes = serde_json::json!([
        { "code": "agent_stops", "class": "provider_key_found" },
        { "code": "agent_stops", "class": "uncharged_turns" },
    ]);
    let shown: Result<serde_json::Value, String> = Ok(serde_json::json!({ "arm": "pinned build" }));
    let panicked: Result<serde_json::Value, String> = Err("the case panicked".to_owned());
    let end = |said: &Result<serde_json::Value, String>, stops: &[Stop], real_route: bool| {
        outcome_of(
            "7",
            "a test",
            said,
            stops,
            false,
            real_route,
            serde_json::json!({ "turns": 0 }),
        )
    };
    for said in [&shown, &panicked] {
        let stopped = end(said, &stops, true);
        assert_eq!(stopped.outcome, "failed");
        assert_eq!(stopped.evidence["stop_agent"], true);
        assert_eq!(stopped.evidence["failure_codes"], codes);
        let stand_in = end(said, &stops, false);
        assert_eq!(stand_in.outcome, "failed");
        assert!(stand_in.evidence.get("stop_agent").is_none());
        assert!(stand_in.evidence.get("failure_codes").is_none());
    }
    let passed = end(&shown, &[], true);
    assert_eq!(passed.outcome, "passed");
    assert!(passed.evidence.get("stop_agent").is_none());
    let failed = end(&panicked, &[], true);
    assert_eq!(failed.outcome, "failed");
    assert!(failed.evidence.get("stop_agent").is_none());
}

fn ends(
    route: Route,
    run: Option<Run>,
    case: &str,
    test: &str,
    result: std::thread::Result<serde_json::Value>,
) {
    let root = run.as_ref().map(|run| run.root().to_path_buf());
    // Nothing the run started may still write when its directory is searched: after a case that
    // stopped part way, everything is ended first and the run's check made.
    let writers_ended = match (&run, &result) {
        (Some(run), Err(_)) => {
            run.end_everything();
            run.remove_loaded_jobs();
            run.nothing_running().is_ok()
        }
        _ => true,
    };
    let mut stops: Vec<Stop> = Vec::new();
    let mut evidence = serde_json::json!({
        "route": if matches!(route, Route::StandIn) { "the application stand-in" } else { "the pinned build" },
        "run_started": run.is_some(),
    });
    let mut scan = None;
    let mut secrets: Vec<String> = Vec::new();
    evidence["turns"] = serde_json::json!({ "charged": 0 });
    // When the check that everything ended has failed, neither the agent's record nor the run's
    // directory is read, and the outcome says so.
    let readable = run_may_be_read(writers_ended);
    if let (Err(stop), Route::Real(_)) = (&readable, &route) {
        stops.push(stop.clone());
        evidence["keys"] = serde_json::json!({ "read": false });
    }
    if let Route::Real(real) = &route {
        let (guard_stops, guard_evidence) = real.person.compare();
        stops.extend(guard_stops);
        evidence["person_files"] = guard_evidence;
        let charged = real.ledger.as_ref().map_or(0, Ledger::charged_here);
        evidence["turns"] = serde_json::json!({ "charged": charged });
        if let (Some(run), Ok(())) = (&run, &readable) {
            let recorded = turns_recorded(
                &real.account,
                run.root(),
                run.pin(),
                &conversations_relative(&real.account),
            );
            match audit_turns(result.is_ok(), charged, &recorded) {
                Audit::Agrees => {}
                Audit::Surplus(surplus) => {
                    let said = real.ledger.as_ref().map_or_else(
                        || "the case runs with no login and has no ledger".to_owned(),
                        |ledger| {
                            ledger
                                .charge_found(
                                    case,
                                    "a turn in the agent's record that the case did not charge",
                                    surplus,
                                )
                                .map_or_else(
                                    |why| format!("the ledger could not be written: {why}"),
                                    |total| format!("the ledger now says {total} spent"),
                                )
                        },
                    );
                    let found = recorded.as_ref().ok().cloned().unwrap_or_default();
                    stops.push((
                        "uncharged_turns",
                        format!(
                            "the agent's record holds {} turn(s), {} of them counted by each \
                             occurrence of their line, against {charged} charged; {surplus} \
                             charged now ({said}). A conversation written again counts its turns \
                             twice, so the count can be too high; it is too low where a line of \
                             the record was lost or two turns share a name",
                            found.turns, found.unnamed
                        ),
                    ));
                }
                Audit::Blind { files } => stops.push((
                    "turn_audit_blind",
                    format!(
                        "the case passed with {charged} turn(s) charged, and the agent's record \
                         holds no turn ({files} file(s) read): the record is not where or in the \
                         form the entry says, so the check that no turn went uncharged saw \
                         nothing, and no further case is to be started on it"
                    ),
                )),
                Audit::Incomplete(why) => stops.push((
                    "turn_audit_incomplete",
                    format!(
                        "the turns in the agent's record were not counted, and the case's charge \
                         cannot be checked against them: {why}. Nothing of the record was read \
                         beyond the bound, and the end went on to the key scan, the removal and \
                         the outcome"
                    ),
                )),
                Audit::Uncountable(why) => stops.push((
                    "uncharged_turns",
                    format!("the turns in the agent's record could not be counted: {why}"),
                )),
            }
            evidence["turns"] = serde_json::json!({
                "charged": charged,
                "in_the_agents_record": recorded.as_ref().ok().map(|found| found.turns),
                "counted_by_occurrence_of_their_line": recorded.as_ref().ok().map(|found| found.unnamed),
                "record_files_read": recorded.as_ref().ok().map(|found| found.files),
                "named_by_uuid": recorded.as_ref().ok().map(|found| found.by_uuid),
                "named_by_a_name_that_is_no_uuid": recorded.as_ref().ok().map(|found| found.by_other_name),
                "forms_of_the_names_that_are_no_uuid": recorded.as_ref().ok().map(|found| found.forms.clone()),
            });
            // Every configuration directory the run prepared is counted: no prompt is sent to a
            // newer build, so its directory holds no turn.
            let prepared_newer = real
                .prepared_newer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some();
            if prepared_newer {
                let newer_record = conversations_relative_in(&real.account, NEWER_CONFIG_DIRECTORY);
                // The probes of the newer build may leave a record of their own: the turns counted
                // are those above what its directory held right after them.
                let baseline = real.newer_baseline.get().cloned().unwrap_or_default();
                match turns_recorded(&real.account, run.root(), run.pin(), &newer_record) {
                    Ok(found) => {
                        // A turn is new where its identity is not among those the probes left, so
                        // a turn the probes left that is gone and a new one do not pass as an equal
                        // count.
                        let new = new_turns(&baseline, &found);
                        evidence["newer_turns"] = serde_json::json!({
                            "after_the_probes": baseline.turns,
                            "at_the_end": found.turns,
                            "new_since_the_probes": new,
                        });
                        if new > 0 {
                            stops.push((
                                "uncharged_turns",
                                format!(
                                    "the newer build's configuration directory holds {new} turn(s) \
                                     that its probes did not leave, and no prompt is sent to the \
                                     newer build"
                                ),
                            ));
                        }
                    }
                    Err(why) if run.root().join(&newer_record).exists() => stops.push((
                        "turn_audit_incomplete",
                        format!("the newer build's record was not counted: {why}"),
                    )),
                    Err(_) => {}
                }
            }
        }
        if let (Some(run), Ok(())) = (&run, &readable) {
            let rules = scan_rules(
                run,
                &real.build.pinned,
                real.placed.get().and_then(PlacedProgram::pinned_resolved),
                &real.build.runtime,
            );
            scan = Some(RunScan::of(run.root(), &rules, &real.held));
        }
        secrets = real.held.values();
    }
    // The run is dropped before its directory goes: where the case failed, its own end says it keeps
    // the directory, and the search that follows removes it.
    drop(run);
    if let (Some(scan), Some(root)) = (scan, &root) {
        let (scan_stops, scan_evidence) = scan.finish(root, case, writers_ended);
        stops.extend(scan_stops);
        eprintln!(
            "the {case} run's directory was searched for the keys and removed, and both are \
             recorded: it is {}. Where the run's own end said above that it keeps the directory, \
             this removed that one.",
            if scan_evidence["run_gone"] == serde_json::json!(true) {
                "gone"
            } else {
                "still there"
            }
        );
        evidence["keys"] = scan_evidence;
    }
    // What a probe that moved the working directory left beside the run's root, outside the run.
    if let (Route::Real(_), Some(root)) = (&route, &root) {
        tells_the_moved_work_directory(root, &mut evidence, &mut stops);
    }
    // The person's files once more, after the run's directory went: a removal that reached them
    // would show here.
    if let Route::Real(real) = &route {
        let (after_the_removal, _) = real.person.compare();
        for stop in after_the_removal {
            if !stops.contains(&stop) {
                stops.push(stop);
            }
        }
    }
    let path = std::env::var_os(RESULT_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let record = |outcome: Outcome| {
        if let Some(path) = &path {
            outcome.without(&secrets).append(path);
        }
    };
    let stopped: Vec<String> = stops
        .iter()
        .map(|(class, why)| format!("{class}: {why}"))
        .collect();
    let probe_only = matches!(&route, Route::Real(real) if real.probe_only);
    let real_route = matches!(&route, Route::Real(_));
    let said: Result<serde_json::Value, String> = match &result {
        Ok(shows) => Ok(shows.clone()),
        Err(panic) => Err(kept_panic_text(&panic_text(&**panic))),
    };
    let failed_after_showing =
        matches!(&said, Ok(shows) if recorded_as(shows, &stops, probe_only) == Filed::Failed);
    record(outcome_of(
        case, test, &said, &stops, probe_only, real_route, evidence,
    ));
    match result {
        Ok(_) => assert!(
            !failed_after_showing,
            "the case showed what it was to, and then: {}",
            stopped.join("; ")
        ),
        Err(panic) => {
            for line in &stopped {
                eprintln!("{line}");
            }
            std::panic::resume_unwind(panic);
        }
    }
}

/// What the end does with the directory a probe moved beside the run's root: removes it where it is
/// empty, says what was found in the outcome's evidence, and adds the stop where it holds something.
fn tells_the_moved_work_directory(
    root: &Path,
    evidence: &mut serde_json::Value,
    stops: &mut Vec<Stop>,
) {
    let (moved, holds_something) = removes_the_moved_work_directory(root);
    evidence["moved_work_directory"] = serde_json::json!(moved);
    if holds_something {
        stops.push((
            "moved_work_directory_left",
            format!("{moved}: what it holds is outside the run, so the key scan did not cover it"),
        ));
    }
}

/// What a probe that moves the run's working directory out of the run leaves beside the run's
/// root: the directory it moved, named after the root with `-moved` added. It lies outside the run,
/// so the key scan did not read it and the run's removal did not take it. It is removed here only
/// where it is an empty directory, by the name this derives from the run's root and no name read
/// from the run, and what was done or left is said.
///
/// Returns what was found and done, and whether the directory holds something (or could not be
/// removed), which stops the case: what it holds was not scanned.
fn removes_the_moved_work_directory(root: &Path) -> (&'static str, bool) {
    let Some(name) = root.file_name() else {
        return ("no place to look for", false);
    };
    let mut moved_name = name.to_os_string();
    moved_name.push("-moved");
    let moved = root.with_file_name(moved_name);
    match std::fs::symlink_metadata(&moved) {
        Err(_) => ("none beside the run", false),
        Ok(found) if found.is_dir() => {
            if std::fs::remove_dir(&moved).is_ok() {
                ("an empty directory beside the run, removed", false)
            } else {
                (
                    "a directory beside the run that holds something or could not be removed, \
                     outside the run, not scanned for keys and not removed",
                    true,
                )
            }
        }
        Ok(_) => (
            "an entry beside the run that is not a directory, left in place",
            false,
        ),
    }
}

/// A case that failed before its run stood: it ends as every case does ([`ends`]) with no run, and
/// its failure goes on.
fn fails_before_its_run(
    route: Route,
    case: &str,
    test: &str,
    panic: Box<dyn std::any::Any + Send>,
) -> ! {
    ends(route, None, case, test, Err(panic));
    unreachable!("a case that failed ends by raising its failure again")
}

/// Appends the outcome of a case that failed before it had a route, where a result file is named.
fn records_failure(case: &str, test: &str, why: &str, secrets: &[String]) {
    if let Some(path) = std::env::var_os(RESULT_VARIABLE).filter(|value| !value.is_empty()) {
        Outcome::failed(case, test, why, serde_json::json!({}))
            .without(secrets)
            .append(Path::new(&path));
    }
}

/// Runs one case: a host, a paired device and a person in a managed shell, `body` on them, the
/// host's close, and whatever follows every outcome of a case ([`ends`]). What fails before the run
/// exists (the managed shell, the route, the runtime, the run's own start) ends as every case does,
/// with no run: the route's guard looks at the person's files again, and an outcome line is
/// written. What fails once the run does, placing the agent included, ends with the run. A case
/// that asked for a real agent does not skip where the managed shell is missing.
fn run_case(
    leg: &str,
    case: &str,
    test: &str,
    variants: &str,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    run_case_in(Setup::default(), leg, case, test, variants, body);
}

/// What a case's run holds beyond the one agent and one session of the rest.
#[derive(Clone, Copy, Default)]
struct Setup {
    /// Two installed builds behind the installation's link and two sessions (6b).
    upgrade: bool,
    /// The forging launcher at the place of the worker's launcher, the real one beside it (8b).
    forge: bool,
    /// The case runs with no login: no login descriptor is read and no turn is charged (8b).
    no_login: bool,
    /// The agent is started by hand: the host's command integration is not turned on, so nothing
    /// serves the launch through a gateway and the host sees the agent as a native terminal.
    manual: bool,
    /// A second person's session is opened beside the first before anything starts, with no newer
    /// build behind it (the forging session of 8a, and the second start of 7 and 7f). The agent in
    /// it is the first's, with the same variants.
    second: bool,
}

/// The stand-in's variants in a case's second session's shell: none where the second session
/// stands for an upgrade (`upgrade`), whose newer build the variants of the first are not for,
/// whatever else the run asks for; otherwise the first's where the case has two sessions of one
/// agent (`second`), so that a start by hand in either is the one the variants name.
fn second_session_variants(setup: Setup, variants: &str) -> &str {
    if setup.second && !setup.upgrade {
        variants
    } else {
        ""
    }
}

/// A second session of one agent starts the way the first does, and the upgrade's does not.
#[test]
fn a_second_session_of_one_agent_is_given_the_first_ones_variants_and_an_upgrades_is_given_none() {
    let second = Setup {
        second: true,
        ..Setup::default()
    };
    let upgrade = Setup {
        upgrade: true,
        ..Setup::default()
    };
    assert_eq!(second_session_variants(second, "by-hand"), "by-hand");
    assert_eq!(second_session_variants(upgrade, "by-hand"), "");
    assert_eq!(
        second_session_variants(upgrade, "leave-unanswered,two-approvals,stay"),
        ""
    );
    assert_eq!(second_session_variants(Setup::default(), "by-hand"), "");
    // An upgrade's second session is the upgrade's whichever else the run asks for.
    let both = Setup {
        second: true,
        upgrade: true,
        ..Setup::default()
    };
    assert_eq!(second_session_variants(both, "by-hand"), "");
}

/// Whether the run is the probe-only run: asked for by [`PROBE_ONLY_VARIABLE`], which only the
/// upgrade case on a real build takes.
///
/// # Errors
///
/// Returns why the run cannot be a probe-only run where it was asked to be one.
fn probe_only_mode(setup: Setup, asked: bool, real_asked: bool) -> Result<bool, String> {
    if !asked {
        return Ok(false);
    }
    if !setup.upgrade {
        return Err(format!(
            "{PROBE_ONLY_VARIABLE} is set, and only the case that upgrades the agent has a newer \
             build to probe"
        ));
    }
    if !real_asked {
        return Err(format!(
            "{PROBE_ONLY_VARIABLE} is set, and {BUILD_VARIABLE} names no build list entry whose \
             newer build it could probe"
        ));
    }
    Ok(true)
}

/// [`run_case`], with the run `setup` asks for.
fn run_case_in(
    setup: Setup,
    leg: &str,
    case: &str,
    test: &str,
    variants: &str,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    // A host's workers are jobs of the account's own launchd on a Mac, which a run loads only
    // where it asks (`KR_ALLOW_ACCOUNT_LAUNCHD=1`): the case stands down otherwise.
    if kr_ipc::testing::account_launchd::stands_down("the host start") {
        return;
    }
    let real_asked = std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty());
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() || real_asked => {
            let why = format!("the {leg} leg's managed shell: {why}");
            records_failure(case, test, &why, &[]);
            panic!("{why}");
        }
        Err(why) => {
            eprintln!("skipping: the {leg} leg: {why}");
            return;
        }
    };
    let route = match std::panic::catch_unwind(|| {
        let asked = std::env::var_os(PROBE_ONLY_VARIABLE).is_some_and(|value| !value.is_empty());
        let probe_only =
            probe_only_mode(setup, asked, real_asked).unwrap_or_else(|why| panic!("{why}"));
        // A probe-only run has no login, whatever the case's own mode is.
        Route::from_environment(case, !setup.no_login && !probe_only, probe_only)
    }) {
        Ok(route) => route,
        Err(panic) => {
            records_failure(case, test, &kept_panic_text(&panic_text(&*panic)), &[]);
            std::panic::resume_unwind(panic);
        }
    };
    // The runtime is made before the run's directory, so that nothing that can fail is left to
    // fail between the run and the context that holds it.
    let runtime = match std::panic::catch_unwind(runtime) {
        Ok(runtime) => runtime,
        Err(panic) => fails_before_its_run(route, case, test, panic),
    };
    let run = match std::panic::catch_unwind(|| Run::start(leg)) {
        Ok(run) => run,
        Err(panic) => fails_before_its_run(route, case, test, panic),
    };
    let mut ctx = Context::new(shell, route, run, runtime);
    ctx.upgrade = setup.upgrade;
    ctx.forge = setup.forge;
    ctx.manual = setup.manual;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.place();
        let session = if setup.upgrade || setup.second {
            Session::open_two(&ctx, variants, second_session_variants(setup, variants))
        } else if setup.forge {
            // The root every path the forging launcher reads must lie below, given in the
            // environment the session is created with (a name outside the host's reserved prefix).
            let root = std::fs::canonicalize(ctx.run.root()).expect("the run's directory");
            Session::open_with(
                &ctx,
                variants,
                &[("KALAREACH_E2E_FORGE_ROOT", root.display().to_string())],
            )
        } else {
            Session::open(&ctx, variants)
        };
        let shows = body(&ctx, &session);
        ctx.close(&session.host);
        shows
    }));
    let Context {
        run,
        route,
        runtime,
        ..
    } = ctx;
    drop(runtime);
    ends(route, Some(run), case, test, result);
}

// ---------------------------------------------------------------------------------------------
// Part 6b: an upgrade leaves the first process its own build, and a build outside the range is
// refused the typed routes.
// ---------------------------------------------------------------------------------------------

/// Every process below `root` in `table`, `root` excluded, with its command line.
fn below(table: &[kr_e2e_m1b::run::Entry], root: u32) -> Vec<(u32, String)> {
    let mut found: Vec<(u32, String)> = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for entry in table.iter().filter(|entry| entry.parent == parent) {
            if !found.iter().any(|(pid, _)| *pid == entry.pid) {
                found.push((entry.pid, entry.command.clone()));
                frontier.push(entry.pid);
            }
        }
    }
    found
}

/// The identity of every process below any of the `workers` whose command line names an
/// application server, added to `servers` where it is not there yet. A process that starts and ends
/// between two reads is not seen.
fn servers_seen(workers: &[u32], servers: &mut Vec<ProcessStartIdentity>) -> Result<(), String> {
    let table = kr_e2e_m1b::run::process_table()?;
    for worker in workers {
        for (pid, command) in below(&table, *worker) {
            if command.contains("app-server")
                && let Ok(identity) = kr_ipc::identity::process_start_identity(pid)
                && !servers.contains(&identity)
            {
                servers.push(identity);
            }
        }
    }
    Ok(())
}

/// The process below `worker` that maps the file with `inode` (and whose command line holds
/// `containing`, where one is given), waited for within [`LIVENESS`] by reads of the process table
/// every 25 ms, with the servers below `workers` collected on every read. The wait ends on the
/// condition: the deadline is a limit.
fn process_mapping_within(
    worker: u32,
    inode: u64,
    containing: Option<&str>,
    workers: &[u32],
    servers: &mut Vec<ProcessStartIdentity>,
) -> Result<ProcessStartIdentity, String> {
    let started = Instant::now();
    loop {
        servers_seen(workers, servers)?;
        if let Some(identity) = process_mapping_once(worker, inode, containing)? {
            return Ok(identity);
        }
        if started.elapsed() >= LIVENESS {
            return Err(format!(
                "no process below worker {worker} maps inode {inode} within {LIVENESS:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The process below `worker` that maps the file with `inode` now, one read of the process table.
fn process_mapping_once(
    worker: u32,
    inode: u64,
    containing: Option<&str>,
) -> Result<Option<ProcessStartIdentity>, String> {
    let table = kr_e2e_m1b::run::process_table()?;
    for (pid, command) in below(&table, worker) {
        if containing.is_none_or(|needle| command.contains(needle))
            && text_image(pid).is_ok_and(|(_, found)| found == inode)
            && let Ok(identity) = kr_ipc::identity::process_start_identity(pid)
        {
            return Ok(Some(identity));
        }
    }
    Ok(None)
}

/// What a launch typed in a session shows: the process below its worker that maps the program's
/// file, the screen that shows the program is ready, and whether every read of the process table
/// was made.
struct Launch {
    process: Result<ProcessStartIdentity, String>,
    ready: Result<(), String>,
    sampled: Result<(), String>,
}

/// The launch just typed in `person`'s shell, waited for until the process that maps `inode` below
/// `worker` is seen AND the screen shows `shows`, within [`LIVENESS`]: the process table is read
/// every 25 ms from the first call, made right after the typing, to the readiness, with the
/// servers below `workers` collected on every read. A read of the table that fails ends the wait
/// and is returned in `sampled`. A process that starts and ends between two reads is not seen.
fn launch_within(
    person: &Person,
    worker: u32,
    inode: u64,
    shows: &str,
    workers: &[u32],
    servers: &mut Vec<ProcessStartIdentity>,
) -> Launch {
    let started = Instant::now();
    let mut process = None;
    let mut sampled = Ok(());
    let mut rows = Vec::new();
    let mut shown = false;
    loop {
        let read = servers_seen(workers, servers).and_then(|()| {
            if process.is_none() {
                process = process_mapping_once(worker, inode, None)?;
            }
            Ok(())
        });
        if let Err(why) = read {
            sampled = Err(why);
            break;
        }
        rows = person.window.screen();
        shown = rows.iter().any(|row| row.contains(shows));
        if (process.is_some() && shown) || started.elapsed() >= LIVENESS {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if sampled.is_ok() {
        sampled = servers_seen(workers, servers);
    }
    Launch {
        process: process.ok_or_else(|| {
            format!("no process below worker {worker} maps inode {inode} within {LIVENESS:?}")
        }),
        ready: if shown {
            Ok(())
        } else {
            Err(format!(
                "the screen does not show {shows:?} after {LIVENESS:?}:\n{}",
                rows.join("\n")
            ))
        },
        sampled,
    }
}

/// The identity the host holds for an instance and how many of its capabilities are usable, read
/// through the connection of the device that is fixed to the instance's session.
fn capability_identity(
    ctx: &Context,
    remote: &Remote,
    session_id: SessionId,
    instance: ApplicationInstanceId,
) -> Result<
    (
        Option<InstanceCapabilityIdentity>,
        usize,
        AgentBindingRevision,
    ),
    RequestError,
> {
    let read: AgentCapabilitiesResult = ctx.runtime.block_on(remote.read(
        Method::AgentCapabilities,
        &AgentCapabilitiesParams {
            subject: subject(session_id, instance),
        },
    ))?;
    let usable = read
        .capabilities
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.state,
                InstanceCapabilityState::QualifiedAvailable
                    | InstanceCapabilityState::VersionQualified
            )
        })
        .count();
    Ok((
        read.capabilities
            .records
            .first()
            .map(|record| record.identity.clone()),
        usable,
        read.binding.binding_revision,
    ))
}

/// Waits for an approval that is pending, interpreted under the package's decoder and not one of
/// `seen`, within [`LIVENESS`].
fn fresh_approval_within(
    ctx: &Context,
    remote: &Remote,
    session_id: SessionId,
    seen: &[PendingResourceId],
) -> Result<kr_protocol::gateway::PendingResource, String> {
    let fresh = |resource: &kr_protocol::gateway::PendingResource| {
        resource.state == PendingState::Pending
            && resource.interpretation_verified
            && !seen.contains(&resource.resource_id)
    };
    ctx.instances_within(remote, session_id, "a fresh approval", |read| {
        read.agent_resources.resources.iter().any(fresh)
    })
    .map(|read| {
        read.agent_resources
            .resources
            .iter()
            .find(|resource| fresh(resource))
            .cloned()
            .expect("the approval the wait found")
    })
}

/// Why a process is not one served through the gateway with the pinned build's own table.
#[derive(Debug, PartialEq, Eq)]
enum Cause {
    /// The host announces no gateway for it.
    NoGateway,
    /// It runs another image than the pinned build's.
    NotThePinnedImage,
}

/// The control of 6b: this process is the pinned build, served through the gateway.
fn check_served(through_a_gateway: bool, image: u64, pinned: u64) -> Result<(), Cause> {
    if !through_a_gateway {
        return Err(Cause::NoGateway);
    }
    if image != pinned {
        return Err(Cause::NotThePinnedImage);
    }
    Ok(())
}

/// The package's table is bound to the build a process started as, not to the build installed
/// now: a process started on the pinned build keeps its image, its binding and its table across an
/// upgrade of the installation, and what it is asked after the upgrade is interpreted by that
/// table; a process started after the upgrade runs the newer build, which the package's range does
/// not admit, so the host serves it no gateway and the typed routes refuse it.
///
/// KR-REQ-12.15, the binding keeps the binary identity across an upgrade: the first process, its
/// binding's identity fields and its image are those of before; KR-REQ-12.17, the pinned schemas:
/// an approval the pinned server asks after the upgrade is interpreted under the pinned decoder.
/// Not claimed: that the screen of the refused launch names the range (it names that the backend
/// refused it).
#[test]
fn gateway_a_process_started_after_an_upgrade_keeps_the_first_its_own_build_and_the_build_outside_the_range_is_refused_the_typed_routes()
 {
    const TEST: &str = "gateway_a_process_started_after_an_upgrade_keeps_the_first_its_own_build_and_the_build_outside_the_range_is_refused_the_typed_routes";
    run_case_in(
        Setup {
            upgrade: true,
            ..Setup::default()
        },
        "gateway-upgrade",
        "6b",
        TEST,
        "leave-unanswered,two-approvals,stay",
        |ctx, session| {
            if let Route::Real(real) = &ctx.route
                && real.probe_only
            {
                return session.records_the_newer_probes();
            }
            let second = session.second.as_ref().expect("two sessions");
            let first_session = session.session_id();
            let second_session = second.person.session_id;
            let pinned_inode = inode_of(&ctx.executable);
            let newer_inode = inode_of(&ctx.newer.as_ref().expect("a newer build").0);
            let newer_prefix = ctx.newer_prefix.clone().expect("the newer build's prefix");
            let installation = ctx.installation.as_ref().expect("an installation");
            // The digests of the pinned build's program and of the installed package, recorded
            // before anything started: what the first binding's identity is compared with.
            let pinned_digest = Digest256::from_bytes(
                *PayloadDigest::of(&std::fs::read(&ctx.executable).expect("the pinned program"))
                    .as_bytes(),
            );
            let package_digest = Digest256::from_bytes(
                ctx.package_digest
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .expect("the package was installed with the host"),
            );
            // The workers of both sessions, by the identities the run records.
            let workers = [
                u32::try_from(ctx.run.worker_of(&first_session.to_string()).pid.get())
                    .expect("a pid"),
                u32::try_from(ctx.run.worker_of(&second_session.to_string()).pid.get())
                    .expect("a pid"),
            ];
            let mut servers: Vec<ProcessStartIdentity> = Vec::new();

            // Step 5: the first agent starts on the pinned build, and its identity is recorded.
            let instance = session.starts_the_agent(&[], None, &[]);
            // On the stand-in route the first process holds an approval that the device answers
            // after the upgrade; the real build holds none before its one charged turn.
            let held =
                matches!(ctx.route, Route::StandIn).then(|| session.interpreted_approval_within());
            let first_process = process_mapping_within(
                workers[0],
                pinned_inode,
                Some("--remote"),
                &workers,
                &mut servers,
            );
            let before = capability_identity(ctx, &session.remote, first_session, instance);
            let summary_before =
                ctx.read_instances(&session.remote, first_session)
                    .and_then(|read| {
                        read.agent_instances
                            .instances
                            .into_iter()
                            .find(|summary| summary.application_instance_id == instance)
                            .ok_or_else(|| "the first instance is not announced".to_owned())
                    });

            // Step 6: the installation is upgraded through the held handle.
            let upgraded = installation.upgrade(&ctx.run, &newer_prefix);
            // The upgrade took, and the agent that ran has not pointed the link elsewhere since.
            assert!(
                upgraded.is_ok(),
                "the upgrade through the held handle: {upgraded:?}"
            );

            // Step 7: the second shell types the agent's name: right before the typing the route
            // is checked (the placed files, the installation's link by the held handle and, on a
            // real route, the newer build, its configuration and the files absent), and the process
            // table is read from the typing until the second program is seen running as typed.
            ctx.checks_the_placed_files();
            installation
                .names(&ctx.run, &newer_prefix)
                .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
            if let Route::Real(real) = &ctx.route {
                real.checks_the_newer_route(
                    &ctx.run,
                    ctx.newer_placed
                        .as_ref()
                        .expect("the newer build was placed"),
                );
            }
            let sampled_before = servers_seen(&workers, &mut servers);
            let (typed, shows) = match &ctx.route {
                Route::StandIn => ("codex".to_owned(), RAN_AS_TYPED.to_owned()),
                Route::Real(real) => (
                    real.typed(&[]),
                    real.build
                        .newer
                        .as_ref()
                        .expect("the entry names a newer build")
                        .ready
                        .clone(),
                ),
            };
            second.person.types(&typed);
            let Launch {
                process: second_process,
                ready: as_typed,
                sampled,
            } = launch_within(
                &second.person,
                workers[1],
                newer_inode,
                &shows,
                &workers,
                &mut servers,
            );

            // The second instance, read right after its launch and before any turn is charged: what
            // the host announces for it, its capabilities, and the program the launch typed.
            let second_read = ctx.instances_within(
                &second.remote,
                second_session,
                "the second instance",
                |read| !read.agent_instances.instances.is_empty(),
            );
            let second_summary = second_read
                .as_ref()
                .ok()
                .and_then(|read| read.agent_instances.instances.first().cloned());
            let second_capabilities = second_summary.as_ref().map(|summary| {
                capability_identity(
                    ctx,
                    &second.remote,
                    second_session,
                    summary.application_instance_id,
                )
            });

            // Step 8: fresh traffic through the pinned adapter, made after the upgrade: the device
            // answers the held approval, and the pinned server asks a second one that did not exist
            // before the upgrade.
            let mut inspected = None;
            let (answered, fresh, typed_command) = match (&ctx.route, held.as_ref()) {
                (Route::StandIn, Some(held)) => {
                    let answered = held.as_ref().map_err(Clone::clone).and_then(|held| {
                        let binding = ctx.read_binding(&session.remote, first_session, instance)?;
                        ctx.answers(
                            &session.remote,
                            first_session,
                            instance,
                            &binding,
                            held.resource_id,
                            ACCEPT,
                        )
                        .map_err(|why| why.to_string())
                    });
                    let fresh = match held {
                        Ok(held) => fresh_approval_within(
                            ctx,
                            &session.remote,
                            first_session,
                            &[held.resource_id],
                        ),
                        Err(why) => Err(why.clone()),
                    };
                    (answered, fresh, None)
                }
                (Route::Real(real), _) => {
                    // Before any turn is charged: the second launch ran as typed on the newer
                    // program, every read of the process table was made, and the newer build, its
                    // configuration and the files absent are as they were placed.
                    assert!(
                        second_process.is_ok(),
                        "the second program runs the newer build: {second_process:?}"
                    );
                    assert!(
                        as_typed.is_ok(),
                        "the second program runs as typed: {as_typed:?}"
                    );
                    assert!(
                        sampled_before.is_ok() && sampled.is_ok(),
                        "the process table was read: {sampled_before:?}, {sampled:?}"
                    );
                    assert!(
                        second_summary.as_ref().is_some_and(|summary| {
                            !summary.mode.uses_gateway()
                                && summary.mode
                                    == kr_protocol::broker::IntegrationMode::NativeTerminal
                        }),
                        "the second instance is a native terminal with no gateway: \
                         {second_read:?}"
                    );
                    assert!(
                        matches!(&second_capabilities, Some(Ok((_, 0, _)))),
                        "the second instance's capabilities are read and none is usable: \
                         {second_capabilities:?}"
                    );
                    real.checks_the_newer_route(
                        &ctx.run,
                        ctx.newer_placed
                            .as_ref()
                            .expect("the newer build was placed"),
                    );
                    // One charged turn, typed in the first session after the upgrade, so that the
                    // approval it asks is traffic that did not exist before: a command that makes
                    // no pipe and is declined, so the case shows the declined resource and the
                    // closed dialog and never that a command did not run.
                    let mark = mark();
                    let command = format!("echo {mark}");
                    assert!(
                        real.account
                            .approval
                            .command_line
                            .as_deref()
                            .unwrap_or("")
                            .len()
                            + command.len()
                            + 8
                            <= usize::from(kr_e2e_m1b::window::COLUMNS),
                        "the case's command, {} characters, would not fit on one line of the \
                         agent's dialog",
                        command.len()
                    );
                    real.charge(&ctx.run, "6b", "an approval-gated command");
                    session.person.composes(
                        &format!(
                            "({mark}) Use your shell tool to run exactly this command and nothing \
                             else: {command}"
                        ),
                        &mark,
                    );
                    let _ = session.person.dialog_names(&real.account, &command);
                    // Each observation is a result, asserted here before the step that depends
                    // on it.
                    let bound = session.binding_within(
                        instance,
                        "the stream names the thread and the running turn",
                        |binding| {
                            binding.thread_id.0.is_some()
                                && binding.turn_id.0.is_some()
                                && unsuspended(binding)
                        },
                    );
                    assert!(
                        bound.is_ok(),
                        "the turn's binding names its thread and turn: {bound:?}"
                    );
                    let binding = bound.expect("asserted above");
                    let fresh = fresh_approval_within(ctx, &session.remote, first_session, &[]);
                    assert!(
                        fresh.is_ok(),
                        "the approval the turn asks is interpreted by the pinned table: {fresh:?}"
                    );
                    let pending = fresh.as_ref().expect("asserted above");
                    let looked_at = ctx.inspects(
                        &session.remote,
                        first_session,
                        instance,
                        pending.resource_id,
                    );
                    assert!(
                        looked_at.is_ok(),
                        "the host's record of the approval: {looked_at:?}"
                    );
                    inspected = Some(looked_at);
                    let answered = ctx
                        .answers(
                            &session.remote,
                            first_session,
                            instance,
                            &binding,
                            pending.resource_id,
                            DECLINE,
                        )
                        .map_err(|why| why.to_string());
                    assert!(
                        answered.is_ok(),
                        "the device's decline of the approval: {answered:?}"
                    );
                    let ended = session.binding_within(
                        instance,
                        "the turn ends after the decline",
                        |binding| binding.turn_id.0.is_none() && unsuspended(binding),
                    );
                    assert!(ended.is_ok(), "the turn ends: {ended:?}");
                    (answered, fresh, Some(command))
                }
                (Route::StandIn, None) => panic!("the stand-in route holds the first approval"),
            };

            // On the stand-in route nothing of step 8 makes the host renew its evidence of the first
            // instance, and that evidence is what the capabilities read returns. The first terminal
            // starts a new chat: the binding names another thread, which the host takes up by
            // renewing its evidence of the program, as it does after the typed turn's reply on a
            // real route. The path the profile names holds the newer program by now, so evidence
            // renewed from the file at that path is not that of the program that runs.
            if matches!(ctx.route, Route::StandIn) {
                let named = ctx.read_binding(&session.remote, first_session, instance);
                assert!(
                    named.is_ok(),
                    "the first binding before the new chat: {named:?}"
                );
                let thread = thread_of(&named.expect("asserted above"));
                assert!(thread.is_some(), "the first binding names a thread");
                session.person.types("/new");
                let moved = session.binding_within(
                    instance,
                    "the first binding names the new chat's thread",
                    |binding| {
                        thread_of(binding).is_some_and(|now| Some(&now) != thread.as_ref())
                            && unsuspended(binding)
                    },
                );
                assert!(
                    moved.is_ok(),
                    "the first terminal's new chat is the binding's thread: {moved:?}"
                );
            }

            // Reads for the assertions.
            let after = capability_identity(ctx, &session.remote, first_session, instance);
            let cancel = second_summary.as_ref().map(|summary| {
                ctx.cancels(
                    &second.remote,
                    second_session,
                    summary.application_instance_id,
                    AgentBindingRevision::new(1),
                    "turn-6b-test",
                )
            });
            let first_image = first_process
                .as_ref()
                .ok()
                .and_then(|identity| text_image(u32::try_from(identity.pid.get()).ok()?).ok())
                .map(|(_, inode)| inode);
            let first_gateway = summary_before
                .as_ref()
                .is_ok_and(|summary| summary.mode.uses_gateway());
            let second_gateway = second_summary
                .as_ref()
                .is_some_and(|summary| summary.mode.uses_gateway());

            // The assertions, each in this body.
            assert!(
                first_process.is_ok(),
                "the first agent's terminal is running on the pinned image: {first_process:?}"
            );
            // 9a: the first process is the same process and runs the pinned image.
            let still = first_process.as_ref().ok().and_then(|identity| {
                kr_ipc::identity::process_start_identity(u32::try_from(identity.pid.get()).ok()?)
                    .ok()
                    .map(|now| now == *identity)
            });
            assert_eq!(
                still,
                Some(true),
                "the first process is the same process after the upgrade"
            );
            assert_eq!(
                first_image,
                Some(pinned_inode),
                "the first process still runs the pinned image"
            );
            // 9b: the identity fields of its binding are those of before (the revision, thread and
            // turn are not compared: step 8 changes them).
            let identity_of = |read: &Result<
                (
                    Option<InstanceCapabilityIdentity>,
                    usize,
                    AgentBindingRevision,
                ),
                RequestError,
            >| match read {
                Ok((identity, _, _)) => identity.clone(),
                Err(_) => None,
            };
            let (identity_before, identity_after): (
                Option<InstanceCapabilityIdentity>,
                Option<InstanceCapabilityIdentity>,
            ) = (identity_of(&before), identity_of(&after));
            assert!(
                identity_before.is_some() && identity_after.is_some(),
                "the first identity before and after the upgrade: {before:?}, {after:?}"
            );
            let (identity_before, identity_after) = (
                identity_before.as_ref().expect("asserted above"),
                identity_after.as_ref().expect("asserted above"),
            );
            assert!(
                identity_before.profile_id.0.is_some(),
                "the first binding holds a profile: {identity_before:?}"
            );
            // The digests are those recorded before anything started: the pinned build's program
            // and the installed package, before the upgrade and after it.
            assert_eq!(
                identity_before.binary_digest,
                Nullable::some(pinned_digest),
                "the first binding's binary digest is the pinned program's"
            );
            assert_eq!(
                identity_before.package_digest,
                Nullable::some(package_digest),
                "the first binding's package digest is the installed package's"
            );
            assert_eq!(identity_after.profile_id, identity_before.profile_id);
            assert_eq!(identity_after.binary_digest, identity_before.binary_digest);
            assert_eq!(
                identity_after.package_digest,
                identity_before.package_digest
            );
            // 9c: what the pinned server asked after the upgrade is a request that did not exist
            // before, and it is interpreted under the pinned decoder.
            assert!(
                answered.is_ok(),
                "the device's answer to the held approval: {answered:?}"
            );
            assert!(
                fresh.is_ok(),
                "a fresh approval, interpreted by the pinned table: {fresh:?}"
            );
            let fresh = fresh.as_ref().expect("asserted above");
            if let Some(held) = &held {
                assert!(held.is_ok(), "the first approval: {held:?}");
                assert_ne!(
                    Some(fresh.resource_id),
                    held.as_ref().ok().map(|held| held.resource_id)
                );
            }
            // The real arm: the interpreted command is the typed command, read from the source
            // bytes the host recorded for the approval.
            if let Some(command) = &typed_command {
                let inspected = inspected
                    .as_ref()
                    .expect("the approval was inspected")
                    .as_ref()
                    .unwrap_or_else(|why| panic!("the host's record of the approval: {why:?}"));
                assert!(
                    String::from_utf8_lossy(inspected.decoding.source_bytes.as_slice())
                        .contains(command.as_str()),
                    "the approval's source bytes do not name the typed command"
                );
            }
            // 9e: the host announced no gateway for it, and no capability of it is usable. Asserted before
            // the second program's own assertions: where the host does announce a gateway, this is
            // the assertion that fails.
            assert!(
                second_summary.is_some(),
                "the second instance is announced: {second_read:?}"
            );
            let second_summary = second_summary.expect("asserted above");
            assert!(
                !second_gateway,
                "the host announced a gateway for the newer build: {second_summary:?}"
            );
            assert_eq!(
                second_summary.mode,
                kr_protocol::broker::IntegrationMode::NativeTerminal,
                "the newer build runs as a native terminal: {second_summary:?}"
            );
            // The capabilities of the second instance were read, and none of them is usable.
            assert!(
                matches!(&second_capabilities, Some(Ok(_))),
                "the second instance's capabilities are read: {second_capabilities:?}"
            );
            if let Some(Ok((_, usable, _))) = &second_capabilities {
                assert_eq!(
                    *usable, 0,
                    "no typed capability of the newer build is usable"
                );
            }
            // 9d: the second process runs the newer image.
            assert!(
                second_process.is_ok(),
                "the second program runs: {second_process:?}"
            );
            let second_identity = second_process.as_ref().expect("asserted above");
            let second_image = text_image(u32::try_from(second_identity.pid.get()).expect("a pid"))
                .map(|(_, inode)| inode);
            assert_eq!(
                second_image,
                Ok(newer_inode),
                "the second process runs the newer image"
            );
            assert_ne!(newer_inode, pinned_inode);
            assert!(
                as_typed.is_ok(),
                "the second program runs as typed: {as_typed:?}"
            );
            assert!(
                sampled_before.is_ok() && sampled.is_ok(),
                "every read of the process table was made: {sampled_before:?}, {sampled:?}"
            );
            // 9f: both profile identifiers are present and unequal.
            assert!(
                summary_before.is_ok(),
                "the first instance is announced: {summary_before:?}"
            );
            let first_summary = summary_before.as_ref().expect("asserted above");
            assert!(
                first_summary.profile_id.0.is_some() && second_summary.profile_id.0.is_some(),
                "both instances hold a profile"
            );
            assert_ne!(first_summary.profile_id, second_summary.profile_id);
            // 9g: the cancel of a well-formed turn is refused with the code of an unsupported
            // capability and no other.
            assert!(cancel.is_some(), "a cancel was sent to the second instance");
            let cancel = cancel.expect("asserted above");
            assert_eq!(
                cancel.as_ref().err().and_then(RequestError::refusal),
                Some(ErrorCode::UnsupportedCapability),
                "the cancel of the newer build's instance: {cancel:?}"
            );
            // 9i: one server for the two workers.
            assert_eq!(servers.len(), 1, "one application server: {servers:?}");
            // 10: the control separates the two processes by the gateway.
            assert_eq!(
                check_served(first_gateway, pinned_inode, pinned_inode),
                Ok(())
            );
            assert_eq!(
                check_served(second_gateway, newer_inode, pinned_inode),
                Err(Cause::NoGateway)
            );
            assert!(ctx.run.root().is_dir());
            serde_json::json!({
                "first_process_image_unchanged": true,
                "fresh_approval_interpreted_by_the_pinned_table": true,
                "second_process_runs_the_newer_image": true,
                "second_instance_has_no_gateway": true,
                "servers": servers.len(),
            })
        },
    );
}

/// What `Installation::upgrade` left where the agent changed the directory `agent` of the run
/// before it, as the helper read it: nothing in it is asserted.
struct UpgradeAfterAChange {
    first: PathBuf,
    refused: Result<(), String>,
    /// The entries of the directory the link at `agent` names (the "link" change).
    elsewhere_entries: Option<usize>,
    /// The entries of the directory that took the place of `agent` (the "directory" change).
    agent_entries: Option<usize>,
    /// Where `current.next` and `current` pointed afterwards (the "next" change).
    next_target: Option<PathBuf>,
    current_target: Option<PathBuf>,
    closing: Result<String, String>,
}

/// Makes the change `how` to the directory `agent` of a run that holds two builds, asks for the
/// upgrade, and returns what it read. The change is "link", "directory" or "next".
fn upgrade_after_the_agent_changed(how: &str) -> UpgradeAfterAChange {
    let run = Run::start("gateway-upgrade-guard");
    let (first, second) = (run.root().join("t/a"), run.root().join("t/b"));
    for prefix in [&first, &second] {
        kr_ipc::paths::create_private_tree(run.root(), &prefix.join("bin"))
            .expect("a directory for a build");
    }
    let installation = Installation::link(&run, &first, &[]);
    let agent = run.root().join("agent");
    let elsewhere = run.root().join("elsewhere");
    let moved = run.root().join("agent-moved");
    match how {
        "link" => {
            std::fs::create_dir(&elsewhere).expect("another directory");
            std::fs::rename(&agent, &moved).expect("the directory moved");
            std::os::unix::fs::symlink(&elsewhere, &agent).expect("a link in its place");
        }
        "directory" => {
            std::fs::rename(&agent, &moved).expect("the directory moved");
            std::fs::create_dir(&agent).expect("another directory in its place");
        }
        "next" => {
            std::os::unix::fs::symlink(&first, agent.join("current.next")).expect("a link");
        }
        other => panic!("{other}"),
    }
    let refused = installation.upgrade(&run, &second);
    let entries = |directory: &Path| std::fs::read_dir(directory).ok().map(Iterator::count);
    UpgradeAfterAChange {
        refused,
        elsewhere_entries: (how == "link").then(|| entries(&elsewhere)).flatten(),
        agent_entries: (how == "directory").then(|| entries(&agent)).flatten(),
        next_target: std::fs::read_link(agent.join("current.next")).ok(),
        current_target: std::fs::read_link(agent.join("current")).ok(),
        closing: run.closing_check(),
        first,
    }
}

/// A link left at `agent` is not followed by the upgrade.
#[test]
fn gateway_an_upgrade_is_refused_where_the_agent_replaced_the_installation_directory_by_a_link() {
    let read = upgrade_after_the_agent_changed("link");
    assert!(
        read.refused.is_err(),
        "the upgrade after the agent changed `agent` (link) is refused"
    );
    assert_eq!(
        read.elsewhere_entries,
        Some(0),
        "nothing is made in the directory the link names"
    );
    assert!(read.closing.is_ok(), "nothing runs: {:?}", read.closing);
}

/// Another directory at `agent` is not the one the run made.
#[test]
fn gateway_an_upgrade_is_refused_where_the_agent_replaced_the_installation_directory_by_another() {
    let read = upgrade_after_the_agent_changed("directory");
    assert!(
        read.refused.is_err(),
        "the upgrade after the agent changed `agent` (directory) is refused"
    );
    assert_eq!(
        read.agent_entries,
        Some(0),
        "nothing is made in the directory that took its place"
    );
    assert!(read.closing.is_ok(), "nothing runs: {:?}", read.closing);
}

/// A `current.next` that is already there stops the upgrade, and nothing is unlinked by name.
#[test]
fn gateway_an_upgrade_is_refused_where_a_link_for_the_next_build_is_already_there() {
    let read = upgrade_after_the_agent_changed("next");
    assert!(
        read.refused.is_err(),
        "the upgrade after the agent left `current.next` is refused"
    );
    // The link that was there is not unlinked by name, and `current` still names the first.
    assert_eq!(read.next_target.as_ref(), Some(&read.first));
    assert_eq!(read.current_target.as_ref(), Some(&read.first));
    assert!(read.closing.is_ok(), "nothing runs: {:?}", read.closing);
}

/// A link the agent pointed at the first build after the upgrade is found by the check the case
/// makes right before the second typing, through the held handle of the directory `agent`: the
/// second launch would run the first build, and what it showed would pass for the newer one.
#[test]
fn gateway_an_installation_link_the_agent_pointed_elsewhere_after_the_upgrade_is_refused_before_the_second_typing()
 {
    let run = Run::start("gateway-upgrade-relinked");
    let (first, second) = (run.root().join("t/a"), run.root().join("t/b"));
    for prefix in [&first, &second] {
        kr_ipc::paths::create_private_tree(run.root(), &prefix.join("bin"))
            .expect("a directory for a build");
    }
    let installation = Installation::link(&run, &first, &[]);
    let upgraded = installation.upgrade(&run, &second);
    let control = installation.names(&run, &second);
    let agent = run.root().join("agent");
    std::fs::remove_file(agent.join("current")).expect("the link removed");
    std::os::unix::fs::symlink(&first, agent.join("current")).expect("the link names the first");
    let relinked = installation.names(&run, &second);
    let closing = run.closing_check();
    assert!(upgraded.is_ok(), "the upgrade: {upgraded:?}");
    assert!(
        control.is_ok(),
        "the link names the newer build right after the upgrade: {control:?}"
    );
    assert!(
        relinked.is_err(),
        "a link the agent pointed at the first build is refused"
    );
    assert!(closing.is_ok(), "nothing runs: {closing:?}");
}

/// A newer build's file replaced by a link after it was placed is found by the check that runs
/// right before each typing.
#[test]
fn gateway_a_newer_build_the_agent_replaced_is_not_run_by_the_next_start() {
    let run = Run::start("gateway-upgrade-newer");
    let tools = run.root().join("t/b/bin");
    kr_ipc::paths::create_private_tree(run.root(), &tools).expect("a directory for the build");
    run.place_built("codex-stand-in-newer", &tools.join("codex"), &["--version"]);
    let place = Path::new("t/b/bin/codex");
    run.note_placed(place).expect("the newer build is placed");
    run.placed_as_it_was(place).expect("as it was placed");
    let elsewhere = run.root().join("elsewhere");
    std::fs::write(&elsewhere, b"another program").expect("another file");
    std::fs::remove_file(tools.join("codex")).expect("the file removed");
    std::os::unix::fs::symlink(&elsewhere, tools.join("codex")).expect("a link in its place");
    let why = run
        .placed_as_it_was(place)
        .expect_err("a replaced newer build is not as it was placed");
    assert!(why.contains("symbolic link"), "{why}");
    run.closing_check().expect("nothing runs");
}

/// The newer build's own probes run before the upgrade, while the installation's link still names
/// the pinned build: the check that compares the link refuses the newer build then, and the check
/// as recorded takes it by the file recorded for it. A newer file replaced after it was recorded is
/// refused by the check as recorded, so the probes do not run it.
#[test]
fn gateway_a_newer_build_replaced_before_its_probes_is_not_run_by_them() {
    let run = Run::start("gateway-upgrade-probes");
    let prefix = run.root().join("t/b");
    kr_ipc::paths::create_private_tree(run.root(), &prefix.join("bin"))
        .expect("a directory for the build");
    run.place_built(
        "codex-stand-in-newer",
        &prefix.join("bin/codex"),
        &["--version"],
    );
    let work = PlacedDirectory::record(run.root(), run.pin(), Path::new("w"))
        .expect("the working directory is a directory of the run");
    let placed = PlacedProgram::record(&prefix, &[], "codex", "bin/codex", work)
        .expect("the newer build is recorded");
    assert!(
        placed.checked(run.root(), run.pin()).is_err(),
        "the check that compares the link refuses a build the link does not name"
    );
    placed
        .checked_as_recorded()
        .expect("the newer build is as it was recorded");
    placed
        .command_as_recorded(run.root(), run.pin())
        .expect("a probe of the newer build can be made");
    let file = prefix.join("bin/codex");
    std::fs::remove_file(&file).expect("the file removed");
    std::fs::write(&file, b"another program").expect("another file in its place");
    let why = placed
        .checked_as_recorded()
        .expect_err("a replaced newer build is not as it was recorded");
    assert!(why.contains("its bytes differ"), "{why}");
    assert!(
        placed.command_as_recorded(run.root(), run.pin()).is_err(),
        "no probe is made of a replaced build"
    );
    run.closing_check().expect("nothing runs");
}

/// What the agent left in the working directory before the harness releases the stand-in or makes
/// a pipe there does not decide where the harness writes: a file is made only where none is (by
/// exclusive creation), a link at the name is not followed and nothing is written through it, a
/// pipe is read only where it is the pipe that was made, and a directory that is not the recorded
/// one is refused.
#[test]
fn gateway_a_release_or_a_pipe_is_made_only_through_the_recorded_directory_and_never_over_what_the_agent_left()
 {
    let run = Run::start("gateway-release-guard");
    let work = PlacedDirectory::record(run.root(), run.pin(), Path::new("w"))
        .expect("the working directory is a directory of the run");
    let (root, pin) = (run.root(), run.pin());
    work.create_new(root, pin, "release", b"go")
        .expect("the release is made where none is");
    assert_eq!(
        std::fs::read(run.work().join("release")).expect("the release"),
        b"go"
    );
    assert!(
        work.create_new(root, pin, "release", b"again").is_err(),
        "a release over a file that is there is refused"
    );
    let outside = run.root().join("outside");
    std::fs::write(&outside, b"theirs").expect("a file outside the directory");
    std::os::unix::fs::symlink(&outside, run.work().join("linked")).expect("a link");
    assert!(
        work.create_new(root, pin, "linked", b"go").is_err(),
        "a release at a link is refused"
    );
    assert_eq!(
        std::fs::read(&outside).expect("the file the link names"),
        b"theirs",
        "nothing was written through the link"
    );
    assert!(
        work.create_new(root, pin, "../escape", b"go").is_err(),
        "a name that is not one name is refused"
    );
    let made = work
        .make_fifo(root, pin, "f")
        .expect("the pipe is made where none is");
    assert!(
        work.make_fifo(root, pin, "f").is_err(),
        "a pipe over a name that is there is refused"
    );
    work.open_fifo_for_reading(root, pin, "f", made)
        .expect("the pipe that was made is opened");
    // The agent replaces the pipe by a link to another pipe: the reader is refused.
    std::fs::remove_file(run.work().join("f")).expect("the pipe removed");
    std::os::unix::fs::symlink(&outside, run.work().join("f")).expect("a link in its place");
    assert!(
        work.open_fifo_for_reading(root, pin, "f", made).is_err(),
        "a link at the pipe's name is refused"
    );
    // The agent moves the directory away and puts another in its place.
    std::fs::rename(run.work(), run.root().join("w-moved")).expect("the directory moved");
    std::fs::create_dir(run.work()).expect("another directory");
    assert!(
        work.create_new(root, pin, "release", b"go").is_err(),
        "a release in a directory that is not the recorded one is refused"
    );
    run.closing_check().expect("nothing runs");
}

// ---------------------------------------------------------------------------------------------
// Part 5b: the gateway's request state survives the daemon's crash (stand-in route).
// ---------------------------------------------------------------------------------------------

/// What the device reads of an agent and one pending request of it: the instances and resources
/// the host lists, the instance's binding, the identity of its capabilities and the host's record
/// of what the decoder read.
#[derive(Debug)]
struct Observed {
    listed: AgentInstancesResult,
    binding: AgentBindingState,
    identity: Option<InstanceCapabilityIdentity>,
    inspected: AgentApprovalInspectResult,
}

/// Reads `instance` and its pending `resource` as the device sees them.
///
/// # Errors
///
/// Returns why a read failed.
fn observes(
    ctx: &Context,
    remote: &Remote,
    session_id: SessionId,
    instance: ApplicationInstanceId,
    resource: PendingResourceId,
) -> Result<Observed, String> {
    Ok(Observed {
        listed: ctx.read_instances(remote, session_id)?,
        binding: ctx.read_binding(remote, session_id, instance)?,
        identity: capability_identity(ctx, remote, session_id, instance)
            .map_err(|why| format!("agent.capabilities: {why}"))?
            .0,
        inspected: ctx
            .inspects(remote, session_id, instance, resource)
            .map_err(|why| format!("agent.approval.inspect: {why}"))?,
    })
}

/// The processes of a session's agent: its worker, and the terminal and the server below it.
#[derive(Debug)]
struct Agent {
    worker: ProcessStartIdentity,
    terminal: ProcessStartIdentity,
    server: ProcessStartIdentity,
}

impl Agent {
    /// The terminal and the server below `worker`, waited for within [`LIVENESS`].
    ///
    /// # Errors
    ///
    /// Returns why they were not found, or why the process table was not read.
    fn below(worker: ProcessStartIdentity) -> Result<Self, String> {
        let pid = u32::try_from(worker.pid.get()).map_err(|_| "a pid".to_owned())?;
        let started = Instant::now();
        loop {
            let table = kr_e2e_m1b::run::process_table()?;
            let found = below(&table, pid);
            let one = |needle: &str| {
                let mut named = found.iter().filter(|(_, command)| command.contains(needle));
                match (named.next(), named.next()) {
                    (Some((pid, _)), None) => kr_ipc::identity::process_start_identity(*pid).ok(),
                    _ => None,
                }
            };
            if let (Some(terminal), Some(server)) = (one("--remote"), one("app-server")) {
                return Ok(Self {
                    worker,
                    terminal,
                    server,
                });
            }
            if started.elapsed() >= LIVENESS {
                return Err(format!(
                    "no one terminal and one server below worker {pid} within {LIVENESS:?}: {found:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether all three are the processes recorded, running.
    fn run(&self) -> bool {
        [&self.worker, &self.terminal, &self.server]
            .into_iter()
            .all(kr_e2e_m1b::run::running)
    }
}

/// Lets the stand-in's terminal print its tick `number`: a file of the working directory, made by
/// exclusive creation through the directory's held handle.
fn releases_tick(ctx: &Context, number: u64) {
    ctx.work
        .as_ref()
        .expect("the working directory was recorded")
        .create_new(
            ctx.run.root(),
            ctx.run.pin(),
            &format!("release.tick{number}"),
            b"go",
        )
        .unwrap_or_else(|why| panic!("the tick's release: {why}"));
}

/// How many times the terminal wrote that the server asked for an approval, in `bytes` of its
/// stream.
fn asked_in(bytes: &[u8]) -> usize {
    String::from_utf8_lossy(bytes).matches(ASKED).count()
}

/// How many times the terminal's byte stream carries that line since `mark`: a request that
/// scrolled off the screen is counted as well as one that is still on it.
fn asked_since(person: &Person, mark: usize) -> usize {
    asked_in(&person.window.collected().since(mark))
}

/// Waits until the person's screen shows `needle`, within [`LIVENESS`].
///
/// # Errors
///
/// Returns the screen that showed no such text when the bound passed.
fn shows_within(person: &Person, needle: &str) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let rows = person.window.screen();
        if rows.iter().any(|row| row.contains(needle)) {
            return Ok(());
        }
        if started.elapsed() >= LIVENESS {
            return Err(format!(
                "the screen shows no {needle:?} after {LIVENESS:?}:\n{}",
                rows.join("\n")
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs `exchange` on the runtime for at most `bound`, so that what the host allows a step of its
/// start is what the step takes.
///
/// # Errors
///
/// Returns why `exchange` failed, or that it did not finish within `bound`.
fn within<T, E: std::fmt::Display>(
    runtime: &tokio::runtime::Runtime,
    bound: Duration,
    what: &str,
    exchange: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    match runtime.block_on(async { tokio::time::timeout(bound, exchange).await }) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(why)) => Err(format!("{what}: {why}")),
        Err(_) => Err(format!("{what} did not finish within {bound:?}")),
    }
}

/// Starts the daemon again over the host's tree and returns the device's connection to it: the
/// daemon is ready when the device connects within the bound the start gives the step, and no `kr`
/// is run, as none may be after the agent started.
fn restarts_the_daemon(ctx: &Context, session: &Session<'_>) -> Remote {
    let connection = std::cell::RefCell::new(None);
    session.host.start_daemon_ready_by(&|bound| {
        let remote = within(
            &ctx.runtime,
            bound,
            "the device's connection",
            session.device.connect(&session.paired),
        )?;
        *connection.borrow_mut() = Some(remote);
        Ok(())
    });
    let connected = connection.into_inner();
    assert!(
        connected.is_some(),
        "the device connects to the restarted daemon"
    );
    connected.expect("asserted above")
}

/// Reads the host's list of sessions, closed ones too.
///
/// # Errors
///
/// Returns why the host could not be read.
fn sessions_within(
    ctx: &Context,
    remote: &Remote,
) -> Result<kr_protocol::session::SessionListResult, String> {
    ctx.runtime
        .block_on(remote.read(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        ))
        .map_err(|why| format!("session.list: {why}"))
}

/// What the daemon started again says of a session whose worker ended while no daemon ran.
#[derive(Debug)]
struct Closed {
    /// The state the host's list of sessions, closed ones included, gives the session, read until
    /// it says the session is closed or the bound passed.
    state: Result<Option<kr_protocol::session::SessionState>, String>,
    /// The reads of the session's agent, each as the device got it.
    instances: Result<AgentInstancesResult, RequestError>,
    capabilities: Result<AgentCapabilitiesResult, RequestError>,
    inspected: Result<AgentApprovalInspectResult, RequestError>,
}

impl Closed {
    /// The code the host refused a read with, where it was the host that refused it.
    fn refusals(&self) -> [Option<ErrorCode>; 3] {
        [
            self.instances
                .as_ref()
                .err()
                .and_then(RequestError::refusal),
            self.capabilities
                .as_ref()
                .err()
                .and_then(RequestError::refusal),
            self.inspected
                .as_ref()
                .err()
                .and_then(RequestError::refusal),
        ]
    }
}

/// The control of 5b: the daemon is killed first, so that no cleanup of its own runs, then the
/// worker is ended by its recorded identity and waited for, and the daemon is started again; the
/// host's list of sessions is read until it shows the session closed, and the agent is read through
/// the daemon started again, the pending `resource` included.
fn ends_the_worker_beside_a_dead_daemon(
    ctx: &Context,
    session: &Session<'_>,
    agent: &Agent,
    instance: ApplicationInstanceId,
    resource: PendingResourceId,
) -> Closed {
    session.host.kill_daemon();
    kr_e2e_m1b::run::signal(&agent.worker, rustix::process::Signal::KILL);
    let started = Instant::now();
    while kr_e2e_m1b::run::running(&agent.worker) {
        assert!(
            started.elapsed() < LIVENESS,
            "the worker did not end within {LIVENESS:?} of being killed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let remote = restarts_the_daemon(ctx, session);
    let session_id = session.session_id();
    let started = Instant::now();
    let state = loop {
        let read = sessions_within(ctx, &remote).map(|listed| {
            listed
                .sessions
                .iter()
                .find(|entry| entry.session_id == session_id)
                .map(|entry| entry.state)
        });
        let closed = matches!(read, Ok(Some(kr_protocol::session::SessionState::Closed)));
        if closed || read.is_err() || started.elapsed() >= LIVENESS {
            break read;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    Closed {
        state,
        instances: ctx.requests_instances(&remote, session_id),
        capabilities: ctx.requests_capabilities(&remote, session_id, instance),
        inspected: ctx.inspects(&remote, session_id, instance, resource),
    }
}

/// Waits until the terminal's stream carries the line of a request at least `count` times since
/// `mark`, within [`LIVENESS`].
///
/// # Errors
///
/// Returns how many times it was there when the bound passed.
fn asked_up_to(person: &Person, mark: usize, count: usize) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let asked = asked_since(person, mark);
        if asked >= count {
            return Ok(());
        }
        if started.elapsed() >= LIVENESS {
            return Err(format!("the terminal was asked {asked} times, not {count}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The gateway's state of a request survives a crash of the control daemon: with a request pending
/// at the gateway, killing only the daemon leaves the worker, the terminal and the server running
/// and the terminal writing; a daemon started again, with no `kr` and no client that takes anything
/// from the run, serves the same instance, the same binding, the same capability identity and the
/// same pending resource, field for field, at the same positions of the session's and the broker's
/// streams; the request then resolves once, through that daemon, and the terminal that was asked
/// once is not asked again, as the terminal's byte stream shows. The control kills the daemon, then
/// ends the worker, and reads the daemon started again: the session is recorded closed, and the
/// reads of its instance, its binding and the request are refused as a closed session's, so the
/// comparison above is not one that anything passes.
///
/// KR-REQ-12.10, KR-REQ-11.27 (the daemon-reconnect leg). Stand-in route only. Not claimed: a
/// kill made during a write (KR-ACC-006), keyboard input to a real terminal while the daemon is
/// dead, and that a real server saw one answer.
#[test]
fn gateway_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request()
 {
    const TEST: &str = "gateway_a_daemon_killed_with_a_request_pending_leaves_the_agent_and_the_restarted_daemon_serves_the_same_request";
    run_case(
        "gateway-restart",
        "5b",
        TEST,
        "leave-unanswered,tick,ping-when-released,stay",
        |ctx, session| {
            assert!(
                matches!(ctx.route, Route::StandIn),
                "the restart case runs on the stand-in route only"
            );
            let session_id = session.session_id();
            // What the terminal is asked is counted in its byte stream from here, before the agent
            // starts, and not from the screen, which scrolls.
            let mark = session.person.window.collected().mark();
            let instance = session.starts_the_agent(&[], None, &[]);
            let pending = session.interpreted_approval_within();
            assert!(
                pending.is_ok(),
                "a request is pending at the gateway and interpreted: {pending:?}"
            );
            let pending = pending.expect("asserted above");
            assert_eq!(pending.state, PendingState::Pending);
            let asked = shows_within(&session.person, ASKED);
            assert!(
                asked.is_ok(),
                "the terminal is asked for the approval: {asked:?}"
            );

            // The state before, read by the device and the process table.
            let before = observes(
                ctx,
                &session.remote,
                session_id,
                instance,
                pending.resource_id,
            );
            assert!(before.is_ok(), "the state before the kill: {before:?}");
            let before = before.expect("asserted above");
            assert!(
                before.identity.is_some(),
                "the instance's capability identity is read: {before:?}"
            );
            assert_eq!(before.listed.agent_resources.resources.len(), 1);
            assert_eq!(before.listed.agent_instances.instances.len(), 1);
            let agent = Agent::below(ctx.run.worker_of(&session_id.to_string()));
            assert!(
                agent.is_ok(),
                "the worker, the terminal and the server: {agent:?}"
            );
            let agent = agent.expect("asserted above");
            assert_eq!(
                asked_since(&session.person, mark),
                1,
                "the terminal was asked once"
            );

            // Only the daemon is killed. The agent goes on, and the terminal writes with no daemon
            // to carry what it writes.
            session.host.kill_daemon();
            assert!(
                agent.run(),
                "the worker, the terminal and the server go on without the daemon"
            );
            releases_tick(ctx, 1);
            let ticked = shows_within(&session.person, "TUI: tick 1");
            assert!(
                ticked.is_ok(),
                "the terminal writes while no daemon runs: {ticked:?}"
            );
            assert!(agent.run(), "all three still run after the tick");
            assert_eq!(
                asked_since(&session.person, mark),
                1,
                "the terminal was not asked again while no daemon ran"
            );

            // A daemon is started again, and the device connects to it: nothing is asked of `kr`.
            let remote = restarts_the_daemon(ctx, session);
            let served = ctx.instances_within(
                &remote,
                session_id,
                "the restarted daemon serves the instance and its request",
                |read| {
                    !read.agent_instances.instances.is_empty()
                        && !read.agent_resources.resources.is_empty()
                },
            );
            assert!(served.is_ok(), "the restarted daemon serves: {served:?}");
            let after = observes(ctx, &remote, session_id, instance, pending.resource_id);
            assert!(after.is_ok(), "the state after the restart: {after:?}");
            let after = after.expect("asserted above");
            assert_eq!(
                after.listed.agent_instances.instances, before.listed.agent_instances.instances,
                "the same instance"
            );
            assert_eq!(
                after.listed.agent_instances.sequence, before.listed.agent_instances.sequence,
                "the same position in the session's announcements"
            );
            assert_eq!(
                after.listed.agent_resources.resources, before.listed.agent_resources.resources,
                "the same pending resource, field for field"
            );
            assert_eq!(
                after.listed.agent_resources.stream_generation,
                before.listed.agent_resources.stream_generation,
                "the same generation of the broker's stream"
            );
            assert_eq!(
                after.listed.agent_resources.cursor, before.listed.agent_resources.cursor,
                "the same position in the broker's stream"
            );
            assert_eq!(
                after.listed.agent_resources.continue_after,
                before.listed.agent_resources.continue_after,
                "the same end of the resource page"
            );
            assert_eq!(after.binding, before.binding, "the same binding");
            assert_eq!(
                after.identity, before.identity,
                "the same capability identity"
            );
            assert_eq!(
                after
                    .identity
                    .as_ref()
                    .map(|identity| &identity.binary_digest),
                before
                    .identity
                    .as_ref()
                    .map(|identity| &identity.binary_digest),
                "the same digest of the program"
            );
            assert_eq!(
                after
                    .identity
                    .as_ref()
                    .map(|identity| &identity.package_digest),
                before
                    .identity
                    .as_ref()
                    .map(|identity| &identity.package_digest),
                "the same digest of the package"
            );
            assert_eq!(
                after.inspected, before.inspected,
                "the same record of the request, with the decoder's whole record of it"
            );
            assert!(
                agent.run(),
                "the processes of the restarted daemon's session are the ones that ran before"
            );
            assert_eq!(asked_since(&session.person, mark), 1, "not asked again");

            // The request resolves once, through the restarted daemon, and the terminal's own
            // reads of the server go on after it.
            let answered = ctx.answers(
                &remote,
                session_id,
                instance,
                &after.binding,
                pending.resource_id,
                ACCEPT,
            );
            assert!(
                answered.is_ok(),
                "the device's answer through the restarted daemon: {answered:?}"
            );
            assert_eq!(
                answered.expect("asserted above").state,
                PendingState::Resolved
            );
            let told = shows_within(&session.person, "TUI: serverRequest/resolved");
            assert!(
                told.is_ok(),
                "the terminal reads the server's word that the request was answered: {told:?}"
            );
            let resolved =
                ctx.instances_within(&remote, session_id, "the request resolves", |read| {
                    read.agent_resources.resources.len() == 1
                        && read.agent_resources.resources[0].state == PendingState::Resolved
                });
            assert!(resolved.is_ok(), "the request resolves: {resolved:?}");
            assert_eq!(
                resolved.expect("asserted above").agent_resources.resources[0].resource_id,
                pending.resource_id,
                "the same resource resolved"
            );
            releases(ctx);
            let replied = shows_within(&session.person, "TUI: the server answered after the turn");
            assert!(
                replied.is_ok(),
                "the terminal's reply to its own question after the turn: {replied:?}"
            );
            let answers = received_lines(ctx)
                .iter()
                .filter(|line| line.starts_with("response "))
                .count();
            assert_eq!(answers, 1, "the server received one answer");
            assert_eq!(
                asked_since(&session.person, mark),
                1,
                "asked once, through the turn's end"
            );
            assert!(
                agent.run(),
                "the server goes on: it was sent no second answer"
            );

            // The control: the daemon is killed first, so no cleanup runs, then the worker ends;
            // a daemon started again records the session closed and refuses each read of it as a
            // closed session's.
            let kept = observes(ctx, &remote, session_id, instance, pending.resource_id);
            assert!(kept.is_ok(), "the state before the control: {kept:?}");
            let closed = ends_the_worker_beside_a_dead_daemon(
                ctx,
                session,
                &agent,
                instance,
                pending.resource_id,
            );
            assert!(
                closed.state.is_ok(),
                "the host lists its sessions: {:?}",
                closed.state
            );
            assert_eq!(
                closed.state.as_ref().ok().copied().flatten(),
                Some(kr_protocol::session::SessionState::Closed),
                "a session whose worker ended is recorded closed"
            );
            assert_eq!(
                closed.refusals(),
                [Some(ErrorCode::SessionClosed); 3],
                "the instance, the binding and the request of a session whose worker ended are \
                 refused as a closed session's, not lost to the transport: {closed:?}"
            );
            // What is left of the agent is ended by identity: the terminal and the server go with
            // their session's shell, and anything that does not is ended here.
            for identity in [&agent.terminal, &agent.server] {
                kr_e2e_m1b::run::signal(identity, rustix::process::Signal::KILL);
            }
            assert!(
                session
                    .host
                    .kr_after_the_agent_started()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty(),
                "no `kr` ran after the agent started"
            );
            serde_json::json!({
                "pending_resource_compared_field_for_field": true,
                "answers_the_server_received": answers,
                "session_after_the_worker_ended": format!("{:?}", closed.state),
                "refusals_after_the_worker_ended": format!("{:?}", closed.refusals()),
            })
        },
    );
}

/// The control with a second request pending: the first approval is answered through the device and
/// the server asks a second one, which is pending under a new identifier and is asked of the
/// terminal too. The daemon is killed, then the worker; the daemon started again records the
/// session closed, and the instance, the binding and the second request, which was pending, are
/// refused as a closed session's: a pending request is lost with its worker, so the comparison of
/// one that the restart case makes is not one that anything passes.
///
/// KR-REQ-12.10, KR-REQ-11.27. Stand-in route only, at no charge.
#[test]
fn gateway_a_second_request_pending_when_the_daemon_and_then_the_worker_are_killed_is_refused_as_a_closed_sessions()
 {
    const TEST: &str = "gateway_a_second_request_pending_when_the_daemon_and_then_the_worker_are_killed_is_refused_as_a_closed_sessions";
    run_case(
        "gateway-restart-pending",
        "5b",
        TEST,
        "leave-unanswered,tick,two-approvals,stay",
        |ctx, session| {
            assert!(
                matches!(ctx.route, Route::StandIn),
                "the control runs on the stand-in route only"
            );
            let session_id = session.session_id();
            let mark = session.person.window.collected().mark();
            let instance = session.starts_the_agent(&[], None, &[]);
            let first = session.interpreted_approval_within();
            assert!(first.is_ok(), "the first request is pending: {first:?}");
            let first = first.expect("asserted above");
            assert_eq!(first.state, PendingState::Pending);
            let binding = ctx.read_binding(&session.remote, session_id, instance);
            assert!(binding.is_ok(), "the binding: {binding:?}");
            let answered = ctx.answers(
                &session.remote,
                session_id,
                instance,
                &binding.expect("asserted above"),
                first.resource_id,
                ACCEPT,
            );
            assert!(
                answered.is_ok(),
                "the device's answer to the first request: {answered:?}"
            );
            assert_eq!(
                answered.expect("asserted above").state,
                PendingState::Resolved
            );
            // The server asks again once the first is answered: a request under a new identifier.
            let second =
                fresh_approval_within(ctx, &session.remote, session_id, &[first.resource_id]);
            assert!(second.is_ok(), "a second request is pending: {second:?}");
            let second = second.expect("asserted above");
            assert_ne!(
                second.resource_id, first.resource_id,
                "the second request has an identifier of its own"
            );
            assert_eq!(second.state, PendingState::Pending);
            let again = ctx.inspects(&session.remote, session_id, instance, second.resource_id);
            assert!(
                again.is_ok(),
                "the host's record of the second request: {again:?}"
            );
            assert_eq!(
                again.expect("asserted above").state,
                PendingState::Pending,
                "the second request is still pending"
            );
            let asked = asked_up_to(&session.person, mark, 2);
            assert!(
                asked.is_ok(),
                "the terminal is asked for each request: {asked:?}"
            );
            assert_eq!(
                asked_since(&session.person, mark),
                2,
                "a request the terminal was asked for again is counted again"
            );
            let agent = Agent::below(ctx.run.worker_of(&session_id.to_string()));
            assert!(
                agent.is_ok(),
                "the worker, the terminal and the server: {agent:?}"
            );
            let agent = agent.expect("asserted above");

            // The daemon is killed first, then the worker.
            let closed = ends_the_worker_beside_a_dead_daemon(
                ctx,
                session,
                &agent,
                instance,
                second.resource_id,
            );
            assert!(
                closed.state.is_ok(),
                "the host lists its sessions: {:?}",
                closed.state
            );
            assert_eq!(
                closed.state.as_ref().ok().copied().flatten(),
                Some(kr_protocol::session::SessionState::Closed),
                "a session whose worker ended is recorded closed"
            );
            assert_eq!(
                closed.refusals(),
                [Some(ErrorCode::SessionClosed); 3],
                "the instance, the binding and the pending request of a session whose worker \
                 ended are refused as a closed session's, not lost to the transport: {closed:?}"
            );
            for identity in [&agent.terminal, &agent.server] {
                kr_e2e_m1b::run::signal(identity, rustix::process::Signal::KILL);
            }
            assert!(
                session
                    .host
                    .kr_after_the_agent_started()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty(),
                "no `kr` ran after the agent started"
            );
            serde_json::json!({
                "second_request_pending_when_the_worker_ended": true,
                "session_after_the_worker_ended": format!("{:?}", closed.state),
                "refusals_after_the_worker_ended": format!("{:?}", closed.refusals()),
            })
        },
    );
}

/// The terminal's byte stream is counted for what it was asked, and a request asked for twice is
/// two, whatever the screen has scrolled off.
#[test]
fn a_request_the_terminal_was_asked_for_twice_is_counted_twice_though_the_screen_shows_one() {
    let first = format!("\x1b[2J{ASKED}\r\n");
    assert_eq!(asked_in(first.as_bytes()), 1);
    let again = format!("{first}TUI: tick 1\r\n{ASKED}\r\n");
    assert_eq!(asked_in(again.as_bytes()), 2);
    assert_eq!(asked_in(b"TUI: tick 1\r\n"), 0);
    assert_eq!(asked_in(b""), 0);
}

/// A step of the daemon's restart is given the bound the host allows it: a connection that does not
/// finish within it fails then, though it would finish later, and one that finishes or fails within
/// it is returned or says why.
#[test]
fn a_connection_that_would_finish_late_fails_within_the_bound_the_restart_gave_it() {
    // The runtime's clock is paused: the connection's three seconds and the bound's 200 ms are
    // both read off a clock only the runtime moves, so a delay of the machine moves neither.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime with a clock of its own");
    let started = runtime.block_on(async { tokio::time::Instant::now() });
    let late = within(
        &runtime,
        Duration::from_millis(200),
        "the connection",
        async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok::<_, String>(1)
        },
    );
    let waited = runtime.block_on(async { started.elapsed() });
    let said = late.expect_err("a connection that finishes after the bound fails");
    assert!(said.contains("did not finish within"), "{said}");
    assert!(
        waited < Duration::from_secs(1),
        "the failure came at the bound, not when the connection would have finished: {waited:?}"
    );
    assert_eq!(
        within(&runtime, Duration::from_secs(5), "the connection", async {
            Ok::<_, String>(7)
        }),
        Ok(7)
    );
    let said = within(&runtime, Duration::from_secs(5), "the connection", async {
        Err::<u8, _>("refused".to_owned())
    })
    .expect_err("a failure is returned");
    assert_eq!(said, "the connection: refused");
}

// ---------------------------------------------------------------------------------------------
// Part 8b: a forged credential fails at the check where the host's own registration for the same
// launch passes.
// ---------------------------------------------------------------------------------------------

/// What the launch typed in the 8b case showed.
struct Presented {
    line: Result<Vec<u8>, String>,
    instance: Result<AgentInstancesResult, String>,
    ready: Result<(), String>,
    sampled: Result<(), String>,
    /// When, from the typing, each step of the launch was first seen.
    seen: Seen,
}

/// The helper's line, an instance served through the gateway and, where `ready` is given, the
/// build's first screen, waited for together within [`LIVENESS`] from the typing. The process table
/// is read every 25 ms by a thread of its own, with the servers below `worker` collected, from the
/// typing until the wait ends, so that a read of the host's instances that blocks does not widen
/// the gap between two reads of the table. A read of the table that fails ends the wait and is
/// returned in `sampled`. A process that starts and ends between two reads is not seen. The time
/// each step of the launch was first seen, from the typing, is returned in `seen`, for a launch that
/// ran as typed to be told from one the host refused.
fn presented_within(
    ctx: &Context,
    session: &Session<'_>,
    mark: usize,
    worker: u32,
    ready: Option<&str>,
    servers: &mut Vec<ProcessStartIdentity>,
) -> Presented {
    const NEEDLE: &str = "forged presentation";
    let started = Instant::now();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let mut line = None;
    let mut served: Result<AgentInstancesResult, String> = Err("no read yet".to_owned());
    let mut found = false;
    let mut shown = ready.is_none();
    let mut rows = Vec::new();
    let mut seen = Seen::default();
    let sampled = std::thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            loop {
                if let Err(why) = servers_seen(&[worker], servers) {
                    failed.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(why);
                }
                if stop.load(std::sync::atomic::Ordering::SeqCst) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        loop {
            if failed.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            if line.is_none() || seen.launcher_report.is_none() {
                let bytes = session.person.window.collected().since(mark);
                seen.observe_terminal(started.elapsed(), &String::from_utf8_lossy(&bytes), NEEDLE);
                if line.is_none() && seen.helper_line.is_some() {
                    line = Some(bytes);
                }
            }
            served = ctx.read_instances(&session.remote, session.session_id());
            found = served.as_ref().is_ok_and(|read| {
                read.agent_instances
                    .instances
                    .iter()
                    .any(|summary| summary.mode.uses_gateway())
            });
            seen.observe_instances(
                started.elapsed(),
                served
                    .as_ref()
                    .ok()
                    .map(|read| read.agent_instances.instances.len()),
                found,
            );
            if let Some(needle) = ready {
                rows = session.person.window.screen();
                shown = rows.iter().any(|row| row.contains(needle));
            }
            if (line.is_some() && found && shown) || started.elapsed() >= LIVENESS {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        sampler
            .join()
            .unwrap_or_else(|_| Err("the process sampler panicked".to_owned()))
    });
    let sampled = sampled.and_then(|()| servers_seen(&[worker], servers));
    Presented {
        line: line.ok_or_else(|| {
            format!(
                "the terminal's bytes after the typing do not hold {NEEDLE:?} within {LIVENESS:?}"
            )
        }),
        instance: if found {
            served
        } else {
            Err(format!(
                "no instance served through the gateway: {served:?}"
            ))
        },
        ready: if shown {
            Ok(())
        } else {
            Err(format!(
                "the screen does not show {ready:?} after {LIVENESS:?}:\n{}",
                rows.join("\n")
            ))
        },
        sampled,
        seen,
    }
}

/// The pid and the start value of the helper's line `pid <n> start <s> forged presentation ...`.
fn helper_identity(text: &str) -> Option<(u32, u64)> {
    let line = text
        .lines()
        .find(|line| line.contains("kr-e2e-forge: pid ") && line.contains("forged presentation"))?;
    let mut words = line.split_whitespace();
    words.find(|word| *word == "pid")?;
    let pid = words.next()?.parse().ok()?;
    words.find(|word| *word == "start")?;
    let start = words.next()?.parse().ok()?;
    Some((pid, start))
}

/// A launch whose first presentation carries a credential that is not the backend's is refused at
/// the check of the credential, and the same launch, presented a second time by the same process
/// with the host's own credential, is admitted: the host serves the instance through its gateway.
/// The two presentations differ in nothing but the credential (one backend, one root-shell child,
/// one process identity, one executable, one vector, one environment), so only that check tells
/// them apart.
///
/// KR-REQ-12.14 is evidence only: this is the launch admission's check, not the native gateway
/// listener's. Not claimed: that a refusal's text is shown (the host drops it).
#[test]
fn gateway_a_launch_whose_first_presentation_carries_a_forged_credential_is_refused_at_the_launch_check_and_the_hosts_own_credential_for_the_same_launch_is_admitted()
 {
    const TEST: &str = "gateway_a_launch_whose_first_presentation_carries_a_forged_credential_is_refused_at_the_launch_check_and_the_hosts_own_credential_for_the_same_launch_is_admitted";
    run_case_in(
        Setup {
            forge: true,
            no_login: true,
            ..Setup::default()
        },
        "gateway-credential",
        "8b",
        TEST,
        "stay",
        |ctx, session| {
            let stand_in_inode = inode_of(&ctx.executable);
            let worker = u32::try_from(
                ctx.run
                    .worker_of(&session.session_id().to_string())
                    .pid
                    .get(),
            )
            .expect("a pid");
            // The forging launcher's root is among the variables the shell is expected to hold on
            // every route, and its value is compared when the shell's environment is read, before
            // any probe or start.
            assert!(
                session
                    .person
                    .expected
                    .names()
                    .contains(&"KALAREACH_E2E_FORGE_ROOT"),
                "the forging launcher's root is not among the variables the shell is expected to hold"
            );
            // The shell's environment is read at its prompt before the agent's first start, as for
            // every case, and the mode of this case was chosen before any key was acquired: it
            // takes no login.
            match session
                .person
                .reads_the_environment(&session.person.expected)
            {
                Ok(compared) => eprintln!("{compared}"),
                Err(why) => panic!("{why}"),
            }
            session.environment_read.set(true);
            session.host.agent_starts();
            ctx.checks_the_placed_files();
            // The real arm: the files that would load the person's own settings are known absent
            // and the entry's isolation probes answer as they must, with the run's configuration
            // directory and no login, before the build is started; the route to it is checked
            // right before the typing.
            if let Route::Real(real) = &ctx.route {
                let absent = real.absent_list(&ctx.run);
                real.checks_absent(&ctx.run, &absent);
                real.proves_isolation(&ctx.run, &ctx.variables(&session.host));
                real.checks_absent(&ctx.run, &absent);
            }
            // The placed launchers, the working directory and the agent's program are checked again
            // after every probe, right before the typing: a probe may have replaced any of them.
            ctx.checks_before_a_typing();
            // One typed launch: the line is typed once, with a mark on the byte stream before it.
            let mark = session.person.window.collected().mark();
            let typed = match &ctx.route {
                Route::StandIn => "codex".to_owned(),
                Route::Real(real) => real.typed(&[]),
            };
            let mut servers: Vec<ProcessStartIdentity> = Vec::new();
            // The process table is read from before the typing to the readiness.
            let sampled_before = servers_seen(&[worker], &mut servers);
            session.person.types(&typed);
            let Presented {
                line,
                instance,
                ready,
                sampled,
                seen,
            } = presented_within(
                ctx,
                session,
                mark,
                worker,
                match &ctx.route {
                    Route::StandIn => None,
                    Route::Real(real) => Some(real.build.ready.as_str()),
                },
                &mut servers,
            );
            let text = line
                .as_ref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            let identity = helper_identity(&text);
            let after = String::from_utf8_lossy(&session.person.window.collected().since(mark))
                .into_owned();

            // (a) the forged presentation is refused: the helper's line says so, once, with the
            // identity it presented as.
            assert!(line.is_ok(), "the helper's line: {line:?}");
            assert_eq!(
                text.matches("forged presentation refused").count(),
                1,
                "the forged presentation is refused, once: {text}"
            );
            assert!(
                !text.contains("forged presentation admitted"),
                "the forged presentation was admitted: {text}"
            );
            assert!(
                identity.is_some(),
                "the helper's line names its pid and its start: {text}"
            );
            let (pid, start) = identity.expect("asserted above");
            // (b) one process identity: the process with the helper's pid and start is the program
            // (helper, launcher and program are one process).
            let now = kr_ipc::identity::process_start_identity(pid);
            assert_eq!(
                now.as_ref().map(|now| now.start_value.get()).ok(),
                Some(start),
                "the process the helper presented as is still running with its start: {now:?}"
            );
            assert_eq!(
                text_image(pid).map(|(_, inode)| inode),
                Ok(stand_in_inode),
                "the process that presented the forged credential now runs the program"
            );
            // (c) the host announces an instance served through a gateway for the session: the
            // genuine presentation of the same launch was admitted.
            assert!(
                instance.is_ok(),
                "the instance served through the gateway (the real launcher runs from `b/h/kr-hook` \
                 as a loose build, and a worker that refused it would end the launch here): \
                 {instance:?}\n{}",
                launch_report(
                    &after,
                    &seen,
                    &ctx.polls.text(),
                    &session.host.daemon_said(),
                    &session.host.worker_said(&session.session_id().to_string())
                )
            );
            // (d) the program did not run as typed: the stand-in's marker is absent; the real
            // build reaches its first screen with the gateway behind it.
            match &ctx.route {
                Route::StandIn => assert!(
                    !after.contains(RAN_AS_TYPED),
                    "the line ran as typed: {after}"
                ),
                Route::Real(_) => assert!(
                    ready.is_ok(),
                    "the build reaches its first screen behind the gateway: {ready:?}"
                ),
            }
            // (e) one application server for the session's worker, every read of the process table
            // made.
            assert!(
                sampled_before.is_ok() && sampled.is_ok(),
                "the process table was read: {sampled_before:?}, {sampled:?}"
            );
            assert_eq!(servers.len(), 1, "one application server: {servers:?}");
            // (f) no `kr` ran after the agent started.
            assert!(
                session
                    .host
                    .kr_after_the_agent_started()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty(),
                "no `kr` ran after the agent started"
            );
            serde_json::json!({
                "forged_presentation_refused": true,
                "one_process_identity": true,
                "gateway_served_after_the_same_launch_was_admitted": true,
                "servers": servers.len(),
            })
        },
    );
}

// ---------------------------------------------------------------------------------------------
// Case 1: a device answers an approval, and the terminal closes its prompt.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that the server's word that a request was answered
/// (`serverRequest/resolved`) reaches the terminal through the gateway, which is the only
/// connection both writers use, and that the terminal closes its prompt on it: a paired device
/// answers the approval of a command the terminal holds, the host's resource resolves, the
/// terminal's prompt goes while the turn still runs, and the command runs once.
///
/// KR-REQ-11.33, the rich approval half: the host interprets the approval the terminal holds, the
/// device's rich answer is encoded and dispatched through the gateway, and the server receives one
/// answer. Not claimed: a native answer that arrives while the rich one is being encoded.
#[test]
fn gateway_a_device_answers_an_approval_and_the_terminal_closes_its_prompt() {
    const TEST: &str = "gateway_a_device_answers_an_approval_and_the_terminal_closes_its_prompt";
    run_case(
        "gateway-approval",
        "gateway-1",
        TEST,
        "answer-when-released,keep-reading,ping-when-released,stay",
        |ctx, session| {
            // The pipe is made before the agent first starts: nothing is written through a path of
            // the run after that.
            let pipe = matches!(ctx.route, Route::Real(_)).then(|| Fifo::made_in(ctx, "f"));
            let instance = session.starts_the_agent(&[], None, &[]);
            match &ctx.route {
                Route::StandIn => {
                    let binding = session.binding_until(
                        instance,
                        "the stream names the thread and the turn",
                        |binding| names(binding, "thread-1", Some("turn-1")),
                    );
                    let pending = session.interpreted_approval();
                    assert_eq!(pending.state, PendingState::Pending);
                    let answered = ctx
                        .answers(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &binding,
                            pending.resource_id,
                            ACCEPT,
                        )
                        .expect("the device's answer is carried");
                    assert_eq!(answered.state, PendingState::Resolved);
                    let _ = session.person.sees(
                        "TUI: serverRequest/resolved",
                        "the terminal reads the server's word that the request was answered",
                    );
                    let answers = received_lines(ctx)
                        .iter()
                        .filter(|line| line.starts_with("response "))
                        .count();
                    assert_eq!(answers, 1, "the server received one answer");
                    serde_json::json!({ "answers_the_server_received": answers })
                }
                Route::Real(real) => {
                    // The command writes to a pipe, so it waits to be read: the turn stays open
                    // until the case reads, whatever the terminal does with its prompt meanwhile.
                    let mark = mark();
                    let pipe = pipe.expect("the real route made its pipe before the start");
                    let command = format!("echo {mark} > {}", ctx.run.work().join("f").display());
                    assert!(
                        real.account
                            .approval
                            .command_line
                            .as_deref()
                            .unwrap_or("")
                            .len()
                            + command.len()
                            + 8
                            <= usize::from(kr_e2e_m1b::window::COLUMNS),
                        "the case's command, {} characters, would not fit on one line of the \
                         agent's dialog",
                        command.len()
                    );
                    real.charge(&ctx.run, "gateway-1", "an approval-gated command");
                    session.person.composes(
                        &format!(
                            "({mark}) Use your shell tool to run exactly this command and nothing \
                             else: {command}"
                        ),
                        &mark,
                    );
                    // The device answers only a dialog that asks to run the case's command and
                    // nothing else: an accepted request runs outside the read-only sandbox.
                    let _ = session.person.dialog_names(&real.account, &command);
                    let binding = session.binding_until(
                        instance,
                        "the stream names the thread and the running turn",
                        |binding| {
                            binding.thread_id.0.is_some()
                                && binding.turn_id.0.is_some()
                                && unsuspended(binding)
                        },
                    );
                    let pending = session.interpreted_approval();
                    assert_eq!(pending.state, PendingState::Pending);
                    let answered = ctx
                        .answers(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &binding,
                            pending.resource_id,
                            ACCEPT,
                        )
                        .expect("the device's answer is carried");
                    assert_eq!(answered.state, PendingState::Resolved);
                    session.person.stops_seeing(
                        &real.account.approval.shows,
                        "the terminal closes its prompt once the server says the request was answered",
                    );
                    // The command is still waiting for the pipe to be read, so the turn is open:
                    // the prompt closed on the server's word and not on the turn's end.
                    let open = ctx.binding(&session.remote, session.session_id(), instance);
                    assert!(
                        open.turn_id.0.is_some(),
                        "the turn ended with the dialog's closing, so the closing is not shown to be \
                         the server's word: {open:?}"
                    );
                    // The reader is opened now, and stays open until the turn has ended: a run of
                    // the command is a line in the pipe, and a second run would find the pipe open
                    // and write its line too.
                    let mut reader = pipe.reader(ctx);
                    let started = Instant::now();
                    loop {
                        reader.poll();
                        let binding = ctx.binding(&session.remote, session.session_id(), instance);
                        if binding.turn_id.0.is_none() && unsuspended(&binding) {
                            break;
                        }
                        assert!(
                            started.elapsed() < LIVENESS,
                            "the turn does not end after {LIVENESS:?}: the binding is {binding:?}"
                        );
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    reader.poll();
                    let ran = reader.lines().iter().filter(|line| **line == mark).count();
                    let others = reader.lines().len() - ran;
                    assert!(
                        ran == 1 && others == 0,
                        "the command wrote its marker {ran} time(s) and something else {others} time(s) \
                         through the end of the turn, where it was to run once"
                    );
                    serde_json::json!({ "command_ran": ran, "turn_open_after_the_prompt_closed": true })
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------------------------
// Case 2: the terminal shows a turn the host started.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that the terminal shows a turn the host started for a device's
/// prompt: with no turn running, a device submits a prompt, the host starts the turn, and the
/// terminal shows what the turn did.
#[test]
fn gateway_the_terminal_shows_a_turn_the_host_started() {
    const TEST: &str = "gateway_the_terminal_shows_a_turn_the_host_started";
    run_case(
        "gateway-host-turn",
        "gateway-2",
        TEST,
        "answer-when-released,keep-reading,stay",
        |ctx, session| {
            let instance = session.starts_the_agent(&[], None, &[]);
            match &ctx.route {
                Route::StandIn => {
                    let _ =
                        session.binding_until(instance, "the stream names the turn", |binding| {
                            names(binding, "thread-1", Some("turn-1"))
                        });
                    releases(ctx);
                    let idle = session.binding_until(instance, "the turn ends", |binding| {
                        names(binding, "thread-1", None)
                    });
                    let from = session.person.window.mark();
                    let started = ctx
                        .prompts(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &idle,
                            "run it again",
                        )
                        .unwrap_or_else(|why| {
                            panic!(
                                "the device's prompt is carried: {why:?}\n{}",
                                session.diagnosis()
                            )
                        });
                    assert!(started.turn_id.0.is_some(), "the host started a turn");
                    let _ = session.person.window.wait_for(
                        from,
                        b"TUI: turn/started",
                        "the terminal shows the turn the host started",
                    );
                    serde_json::json!({ "turn_started_by_the_host": true })
                }
                Route::Real(real) => {
                    let idle = session.binding_until(
                        instance,
                        "the stream names a thread and no turn",
                        |binding| {
                            binding.thread_id.0.is_some()
                                && binding.turn_id.0.is_none()
                                && unsuspended(binding)
                        },
                    );
                    let marked = mark();
                    let root = ctx.run.root().display().to_string();
                    let (question, sum) = session.person.asks(&[&marked, &root]);
                    real.charge(&ctx.run, "gateway-2", "a prompt from a device");
                    let before = session.person.window.screen();
                    let started = ctx
                        .prompts(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &idle,
                            &format!("({marked}) {question}"),
                        )
                        .unwrap_or_else(|why| {
                            panic!(
                                "the device's prompt is carried: {why:?}\n{}",
                                session.diagnosis()
                            )
                        });
                    assert!(started.turn_id.0.is_some(), "the host started a turn");
                    let _ = session.person.sees_the_sum(
                        &sum,
                        &before,
                        "the terminal shows the turn the host started",
                    );
                    // After the host's turn, and after what the terminal does on a thread of its own
                    // for the conversation's title has ended, the binding still names the thread the
                    // turn ran on, with no turn, and rich work is available.
                    let first = thread_of(&idle).expect("the idle binding names a thread");
                    let _ = session.binding_settled_until(
                        instance,
                        "the host's turn ends on the thread it ran on",
                        Some(&first),
                        |binding| binding.turn_id.0.is_none(),
                    );
                    session.binding_stays_on(
                        instance,
                        "the terminal's own helper thread leaves the conversation as it was",
                        &first,
                    );
                    serde_json::json!({ "turn_started_by_the_host": true })
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------------------------
// The terminal's helper thread where it stays or comes again: the stand-in's two variants of the
// title flow.
// ---------------------------------------------------------------------------------------------

/// A terminal that a person is at starts a thread of its own for the conversation's title and
/// leaves it when its turn ends. A terminal that never leaves that thread (`keep-the-title-thread`)
/// and one that asks for a title at every message (`retitle`) are the cases where the helper thread
/// outlives the turn or comes again. The binding must name the conversation's thread, with no
/// turn, for as long as the helper flow lasts: the package's hidden start keeps the helper thread
/// out of it. Only the stand-in is the agent here; a real agent is never asked to keep or repeat
/// its helper flow. `leaves` is how many of its helper threads the terminal leaves with a
/// `thread/unsubscribe` by the end: none where it keeps the one it started, one for each prompt
/// where it asks again (a helper that returns has been left before it comes back).
fn a_helper_thread_that_stays_or_returns_leaves_the_binding_alone(
    test: &str,
    variants: &str,
    prompts: usize,
    leaves: usize,
) {
    if std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty()) {
        return;
    }
    run_case(
        "gateway-helper-thread",
        "gateway-helper-thread",
        test,
        variants,
        |ctx, session| {
            let instance = session.starts_the_agent_showing("TUI: thread/started", &[], None, &[]);
            let mut idle = session.binding_until(
                instance,
                "the stream names a thread and no turn",
                |binding| {
                    binding.thread_id.0.is_some()
                        && binding.turn_id.0.is_none()
                        && unsuspended(binding)
                },
            );
            for round in 1..=prompts {
                let started = ctx
                    .prompts(
                        &session.remote,
                        session.session_id(),
                        instance,
                        &idle,
                        &format!("run it again, time {round}"),
                    )
                    .unwrap_or_else(|why| {
                        panic!(
                            "the device's prompt is carried: {why:?}\n{}",
                            session.diagnosis()
                        )
                    });
                assert!(started.turn_id.0.is_some(), "the host started a turn");
                idle = session.binding_settled_until(
                    instance,
                    "the host's turn ends on the thread it ran on",
                    Some("thread-1"),
                    |binding| binding.turn_id.0.is_none(),
                );
            }
            // The case shows something only where the terminal did start a thread of its own for
            // the title at each prompt: the conversation's thread and one helper thread for each
            // prompt are the starts the server received.
            let wanted = 1 + prompts;
            let until = Instant::now() + Duration::from_secs(30);
            while requests_of(ctx, "thread/start") < wanted && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(100));
            }
            assert!(
                requests_of(ctx, "thread/start") >= wanted,
                "the terminal started a helper thread for the title at each prompt: {:?}",
                received_lines(ctx)
            );
            session.binding_stays_on(
                instance,
                "the terminal's helper thread, kept or asked for again, leaves the conversation as it was",
                "thread-1",
            );
            let left = requests_of(ctx, "thread/unsubscribe");
            assert!(
                if leaves == 0 {
                    left == 0
                } else {
                    left >= leaves
                },
                "the terminal left its helper thread {left} times, where {leaves} is the case: {:?}",
                received_lines(ctx)
            );
            serde_json::json!({ "helper_thread_left_alone": true })
        },
    );
}

/// The terminal never leaves the thread it started for the title (`keep-the-title-thread`).
#[test]
fn gateway_a_helper_thread_that_is_kept_with_no_leave_leaves_the_binding_alone() {
    a_helper_thread_that_stays_or_returns_leaves_the_binding_alone(
        "gateway_a_helper_thread_that_is_kept_with_no_leave_leaves_the_binding_alone",
        "write-the-record,keep-reading,stay,keep-the-title-thread",
        1,
        0,
    );
}

/// The terminal asks for a title again at the next prompt (`retitle`).
#[test]
fn gateway_a_title_asked_for_again_at_the_next_prompt_leaves_the_binding_alone() {
    a_helper_thread_that_stays_or_returns_leaves_the_binding_alone(
        "gateway_a_title_asked_for_again_at_the_next_prompt_leaves_the_binding_alone",
        "write-the-record,keep-reading,stay,retitle",
        2,
        2,
    );
}

// ---------------------------------------------------------------------------------------------
// Case 3: the binding's thread changes only where a thread starts, resumes or forks.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that `thread/start`, `thread/resume` and `thread/fork` are the only
/// frames that change the thread a terminal is on: the binding keeps its revision and thread
/// through a turn and through a slash command that selects nothing, takes a new one when the
/// terminal forks and when it starts a new conversation, and names the saved one when a launch
/// resumes it.
///
/// KR-REQ-12.06, the binding's revision and thread: the revision moves with each thread the
/// terminal selects and stays through a turn and through a command that selects nothing, and the
/// thread the binding names is the one the terminal's frames select. Not claimed: a stale
/// submission, or the suspension of rich mutations.
#[test]
fn gateway_the_binding_changes_its_thread_only_where_the_terminal_starts_resumes_or_forks_one() {
    const TEST: &str = "gateway_the_binding_changes_its_thread_only_where_the_terminal_starts_resumes_or_forks_one";
    run_case(
        "gateway-thread",
        "gateway-3",
        TEST,
        "answer-when-released,keep-reading,stay",
        |ctx, session| {
            let instance = session.starts_the_agent(&[], None, &THREAD_CASE_COMMANDS);
            match &ctx.route {
                Route::StandIn => {
                    let started =
                        session.binding_until(instance, "the stream names the thread", |binding| {
                            names(binding, "thread-1", Some("turn-1"))
                        });
                    releases(ctx);
                    let idle = session.binding_until(instance, "the turn ends", |binding| {
                        names(binding, "thread-1", None)
                    });
                    assert_eq!(
                        idle.binding_revision, started.binding_revision,
                        "a turn and its end leave the binding's revision as the thread's start made it"
                    );
                    serde_json::json!({ "revision_unchanged_through_a_turn": true })
                }
                Route::Real(real) => {
                    let account = &real.account;
                    // The thread and the revision the terminal's start selected, before any prompt.
                    let before = session.binding_until(
                        instance,
                        "the stream names a thread and no turn",
                        |binding| {
                            binding.thread_id.0.is_some()
                                && binding.turn_id.0.is_none()
                                && unsuspended(binding)
                        },
                    );
                    let first_thread = thread_of(&before).expect("a thread");
                    let marked = mark();
                    let root = ctx.run.root().display().to_string();
                    let (question, sum) = session.person.asks(&[&marked, &root]);
                    real.charge(&ctx.run, "gateway-3", "a turn in the first thread");
                    let rows_before = session.person.window.screen();
                    session
                        .person
                        .composes(&format!("({marked}) {question}"), &marked);
                    let _ = session
                        .person
                        .sees_the_sum(&sum, &rows_before, "the agent answers");
                    let first = session.binding_until(instance, "the turn ends", |binding| {
                        binding.thread_id.0.is_some()
                            && binding.turn_id.0.is_none()
                            && unsuspended(binding)
                    });
                    assert_eq!(
                        (thread_of(&first), first.binding_revision),
                        (Some(first_thread.clone()), before.binding_revision),
                        "a turn leaves the binding's thread and revision as the terminal's start \
                         made them"
                    );

                    // A command that selects nothing changes nothing.
                    session.person.waits_for_the_composer(
                        &account.composer,
                        &account.busy,
                        "the composer waits before the command",
                    );
                    session.person.sends_command(&account.slash.input);
                    let _ = session
                        .person
                        .sees(&account.slash.shows, "the command answers");
                    let after_command =
                        ctx.binding(&session.remote, session.session_id(), instance);
                    assert_eq!(
                        (thread_of(&after_command), after_command.binding_revision),
                        (Some(first_thread.clone()), first.binding_revision),
                        "a command that selects no thread leaves the binding as it was"
                    );
                    if !account.dismiss.is_empty() {
                        session.person.window.type_text(account.dismiss.as_bytes());
                    }

                    // A fork selects another thread, and a new conversation another.
                    session.person.waits_for_the_composer(
                        &account.composer,
                        &account.busy,
                        "the composer waits before the fork",
                    );
                    session.person.sends_command(real.command("fork"));
                    let forked = session.binding_until(
                        instance,
                        "the terminal forks the thread",
                        |binding| {
                            thread_of(binding).is_some_and(|thread| thread != first_thread)
                                && unsuspended(binding)
                        },
                    );
                    let fork_thread = thread_of(&forked).expect("a thread");
                    session.person.waits_for_the_composer(
                        &account.composer,
                        &account.busy,
                        "the composer waits before the new conversation",
                    );
                    session.person.sends_command(real.command("new"));
                    let fresh = session.binding_until(
                        instance,
                        "the terminal starts a new thread",
                        |binding| {
                            thread_of(binding).is_some_and(|thread| thread != fork_thread)
                                && unsuspended(binding)
                        },
                    );
                    assert!(
                        fresh.binding_revision != forked.binding_revision
                            && forked.binding_revision != first.binding_revision,
                        "each selection advanced the binding's revision"
                    );

                    // A launch that resumes the first thread names it.
                    session.person.waits_for_the_composer(
                        &account.composer,
                        &account.busy,
                        "the composer waits before the quit",
                    );
                    session.person.sends_command(real.command("quit"));
                    let _ = ctx.instances_until(
                        &session.remote,
                        session.session_id(),
                        "the first launch has ended",
                        |read| read.agent_instances.instances.is_empty(),
                    );
                    let resumed =
                        session.starts_the_agent(&["resume", &first_thread], Some(instance), &[]);
                    let named =
                        session.binding_until(resumed, "the resumed thread is named", |binding| {
                            thread_of(binding).as_deref() == Some(first_thread.as_str())
                                && unsuspended(binding)
                        });
                    serde_json::json!({
                        "changed_by_a_turn": false,
                        "revision_unchanged_through_a_turn": true,
                        "changed_by_a_command_that_selects_nothing": false,
                        "changed_by_a_fork": true,
                        "changed_by_a_new_conversation": true,
                        "named_by_a_resuming_launch": thread_of(&named) == Some(first_thread),
                    })
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------------------------
// Case 4: a whole session names no method the table does not list.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that its list of stable method names is complete for a 0.155.1
/// session: the binding is not suspended at any step of a turn and a slash command, which the host
/// does only when a frame names a method the table does not list. The binding is read at every
/// step and at every poll between them. The host keeps no cumulative record of the methods a
/// session named, and clears such a suspension at a later valid selection, so a suspension that
/// came and went between two polls is not seen.
#[test]
fn gateway_a_whole_session_names_no_method_the_table_does_not_list() {
    const TEST: &str = "gateway_a_whole_session_names_no_method_the_table_does_not_list";
    run_case(
        "gateway-listed",
        "gateway-4",
        TEST,
        "answer-when-released,keep-reading,stay",
        |ctx, session| {
            let instance = session.starts_the_agent(&[], None, &[Slash::Shown]);
            let binding = match &ctx.route {
                Route::StandIn => {
                    let _ =
                        session.binding_until(instance, "the stream names the turn", |binding| {
                            names(binding, "thread-1", Some("turn-1"))
                        });
                    releases(ctx);
                    session.binding_until(instance, "the turn ends", |binding| {
                        names(binding, "thread-1", None)
                    })
                }
                Route::Real(real) => {
                    let account = &real.account;
                    let _ = session.binding_unsuspended_until(
                        instance,
                        "the agent is up with a thread",
                        |binding| binding.thread_id.0.is_some(),
                    );
                    let marked = mark();
                    let root = ctx.run.root().display().to_string();
                    let (question, sum) = session.person.asks(&[&marked, &root]);
                    real.charge(&ctx.run, "gateway-4", "a turn");
                    let rows_before = session.person.window.screen();
                    session
                        .person
                        .composes(&format!("({marked}) {question}"), &marked);
                    let _ = session
                        .person
                        .sees_the_sum(&sum, &rows_before, "the agent answers");
                    let _ =
                        session.binding_unsuspended_until(instance, "the turn ends", |binding| {
                            binding.thread_id.0.is_some() && binding.turn_id.0.is_none()
                        });
                    session.person.waits_for_the_composer(
                        &account.composer,
                        &account.busy,
                        "the composer waits before the command",
                    );
                    session.person.sends_command(&account.slash.input);
                    let _ = session
                        .person
                        .sees(&account.slash.shows, "the command answers");
                    session.binding_unsuspended_until(instance, "the command is done", |binding| {
                        binding.thread_id.0.is_some() && binding.turn_id.0.is_none()
                    })
                }
            };
            assert!(
                unsuspended(&binding),
                "rich work is not suspended after the whole session: {binding:?}"
            );
            serde_json::json!({ "suspended": binding.rich_mutations_suspended })
        },
    );
}

// ---------------------------------------------------------------------------------------------
// Case 5: a device's prompt over a running turn is refused and reaches nothing.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that `turn/start` over a running turn is not a queue: a device's
/// prompt while a turn runs is refused as a conflict with it, and nothing reaches the agent. The
/// host refuses before any `turn/start` is sent, so the case shows the host's refusal and that the
/// agent's own record holds the terminal's prompt and not the device's.
#[test]
fn gateway_a_device_prompt_over_a_running_turn_is_refused_and_reaches_nothing() {
    const TEST: &str = "gateway_a_device_prompt_over_a_running_turn_is_refused_and_reaches_nothing";
    run_case(
        "gateway-running",
        "gateway-5",
        TEST,
        "answer-when-released,keep-reading,stay",
        |ctx, session| {
            let instance = session.starts_the_agent(&[], None, &[]);
            match &ctx.route {
                Route::StandIn => {
                    let running =
                        session.binding_until(instance, "the stream names the turn", |binding| {
                            names(binding, "thread-1", Some("turn-1"))
                        });
                    let refused = ctx
                        .prompts(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &running,
                            "now",
                        )
                        .expect_err("a prompt over a running turn");
                    assert_eq!(
                        refused.refusal(),
                        Some(ErrorCode::DraftConflict),
                        "{refused}"
                    );
                    assert_eq!(
                        requests_of(ctx, "turn/start"),
                        1,
                        "only the terminal's own turn reached the server"
                    );
                    serde_json::json!({ "refused_as": "DraftConflict", "turn_starts_at_the_server": 1 })
                }
                Route::Real(real) => {
                    // The turn waits on the approval of a write, which keeps it running for as long
                    // as the case needs, and the device declines it at the end.
                    let mark = mark();
                    let log = ctx.run.work().join("a");
                    let command = format!("echo {mark} >> {}", log.display());
                    real.charge(&ctx.run, "gateway-5", "a turn that waits on an approval");
                    session.person.composes(
                        &format!(
                            "({mark}) Use your shell tool to run exactly this command and nothing \
                             else: {command}"
                        ),
                        &mark,
                    );
                    let _ = session.person.sees(
                        &real.account.approval.shows,
                        "the agent asks for approval of the command",
                    );
                    let running = session.binding_until(
                        instance,
                        "the stream names the running turn",
                        |binding| {
                            binding.thread_id.0.is_some()
                                && binding.turn_id.0.is_some()
                                && unsuspended(binding)
                        },
                    );
                    let held = session.interpreted_approval();
                    // Charged before it is sent: where the host did not refuse it, the agent would
                    // take it as a prompt of its own.
                    real.charge(&ctx.run, "gateway-5", "a device prompt over a running turn");
                    let device = format!("{} the device's own prompt", crate::mark());
                    let refused = ctx
                        .prompts(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &running,
                            &device,
                        )
                        .expect_err("a prompt over a running turn");
                    assert_eq!(
                        refused.refusal(),
                        Some(ErrorCode::DraftConflict),
                        "{refused}"
                    );
                    let still = session.interpreted_approval();
                    assert_eq!(
                        (still.resource_id, still.state),
                        (held.resource_id, PendingState::Pending),
                        "the refused prompt leaves the terminal's approval as it was"
                    );
                    let _ = ctx
                        .answers(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &running,
                            held.resource_id,
                            DECLINE,
                        )
                        .expect("the device ends the turn");
                    let _ = session.binding_until(instance, "the turn ends", |binding| {
                        binding.turn_id.0.is_none() && unsuspended(binding)
                    });
                    let recorded = real
                        .conversations(&ctx.run)
                        .unwrap_or_else(|why| panic!("the agent's record is not whole: {why}"));
                    assert!(
                        recorded.contains(&mark) && !recorded.contains(&device),
                        "the agent's record holds the terminal's prompt and not the device's"
                    );
                    assert!(!log.exists(), "the command the device declined did not run");
                    serde_json::json!({ "refused_as": "DraftConflict", "device_prompt_in_the_agents_record": false })
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------------------------
// The shutdown of a host whose state the agent rewrote.
// ---------------------------------------------------------------------------------------------

/// How the host an agent left another host's state in is ended.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// A case that passed: the host is stopped, and the run's closing check is made.
    Stop,
    /// A case that failed: the host is dropped, as a failing case leaves it.
    Drop,
}

/// A stand-in agent that, once it has started, rewrites the environment's identity in the run's
/// state to that of a second daemon and links that daemon's socket at the place the identity gives,
/// which is all `kr` needs to act on the second daemon. The second daemon is the case's own, with a
/// session open, in a run directory of its own; the host is then ended as `ending` says. Nothing is
/// asked of the second daemon: its session is still open, and the host's record shows no `kr`
/// asked for after the agent started. The run's own processes are ended all the same.
fn an_agent_leaves_another_host_and_the_host_ends(ending: Ending) {
    if std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty()) {
        // The stand-in is the agent here; a real agent is never asked to rewrite a host's state.
        return;
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: {why}");
            return;
        }
    };
    // The second daemon's sessions open the managed package's zsh program as their root shell, with
    // no startup entry installed, so that the case runs wherever the package is installed, with or
    // without a system zsh.
    let managed_shell = shell.executable.display().to_string();
    // The second daemon, in a directory of its own, with two sessions open that no terminal is on:
    // the run has one session of its own, number 1, so the second session's number is one the
    // run's own `kr` has no local record of, which it then asks the daemon it reaches to close.
    let other_run = Run::start("gateway-other");
    let other = Host::start(
        &other_run,
        &HostOptions {
            shell_packages: Some(shell.prefix.clone()),
        },
    );
    for _ in 0..2 {
        let _ = other.kr_json(&[
            "new",
            "--invisible",
            "--headless",
            "--shell-mode",
            "native_compat",
            "--shell",
            &managed_shell,
        ]);
    }
    let opened = other.live_sessions();
    assert_eq!(opened.len(), 2, "the second daemon's sessions: {opened:?}");
    // What the stand-in runs when it starts: the identity of the second daemon written over the
    // run's own, and the second daemon's socket linked at the place that identity gives.
    let mut ctx = Context::new(
        shell,
        Route::StandIn,
        Run::start("gateway-leaves"),
        runtime(),
    );
    let socket = other
        .environment()
        .controller_endpoint()
        .expect("the second daemon's endpoint")
        .as_path()
        .to_path_buf();
    let prefix = socket
        .parent()
        .and_then(Path::file_name)
        .expect("the endpoint's directory")
        .to_owned();
    let runtime_directory = ctx.run.root().join("r").join(&prefix);
    let leave = other_run.root().join("leave.sh");
    std::fs::write(
        &leave,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{}' > '{}'\n/bin/mkdir -m 700 '{}'\n/bin/ln -s '{}' '{}'\n",
            other.environment_id(),
            ctx.run.root().join("s/environment-id").display(),
            runtime_directory.display(),
            socket.display(),
            runtime_directory.join("c.sock").display(),
        ),
    )
    .expect("the program the stand-in runs");
    std::fs::set_permissions(&leave, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("executable");
    ctx.place();
    let session = Session::open_with(
        &ctx,
        "answer-when-released,keep-reading,stay,leave-a-host",
        &[("STAND_IN_LEAVE", leave.display().to_string())],
    );
    let _ = session.starts_the_agent(&[], None, &[]);
    assert_eq!(
        std::fs::read_to_string(ctx.run.root().join("s/environment-id"))
            .expect("the identity")
            .trim(),
        other.environment_id().to_string(),
        "the stand-in rewrote the environment's identity"
    );
    assert!(
        std::fs::symlink_metadata(runtime_directory.join("c.sock"))
            .expect("the link the stand-in made")
            .file_type()
            .is_symlink(),
        "the stand-in linked the second daemon's socket at the place the identity gives"
    );
    // The control: what the stand-in left is enough for the run's own `kr`, started here by the
    // case and not by the host, to list the second daemon's sessions and not the run's own.
    let mut listing = std::process::Command::new(ctx.run.binary("kr"));
    listing
        .args(["list", "--json"])
        .env_clear()
        .envs(session.host.variables())
        .current_dir(ctx.run.root());
    let listed = kr_e2e_m1b::run::output_within(listing, LIVENESS).expect("the control's kr list");
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    for session in &opened {
        assert!(
            listed.contains(
                session["session_id"]
                    .as_str()
                    .expect("a session identifier")
            ),
            "kr, run against the state the stand-in left, lists the second daemon's sessions: {listed}"
        );
    }
    let asked = session.host.kr_after_the_agent_started();
    match ending {
        Ending::Stop => {
            ctx.close(&session.host);
            drop(session);
        }
        Ending::Drop => {
            drop(session);
            let closing = ctx
                .run
                .closing_check()
                .unwrap_or_else(|why| panic!("the dropped host left processes: {why}"));
            println!("{closing}");
        }
    }
    assert!(
        asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "a kr was asked for after the agent started"
    );
    assert_eq!(
        other.live_sessions().len(),
        2,
        "the second daemon's sessions are all still open"
    );
    other.stop().expect("the second host stops");
    other_run
        .closing_check()
        .unwrap_or_else(|why| panic!("{why}"));
}

/// The host of a case that passed is stopped without `kr`, and the second daemon is left alone.
#[test]
fn gateway_an_agent_that_rewrote_the_hosts_state_is_not_obeyed_when_the_host_stops() {
    an_agent_leaves_another_host_and_the_host_ends(Ending::Stop);
}

/// The host of a case that failed is dropped without `kr`, and the second daemon is left alone.
#[test]
fn gateway_an_agent_that_rewrote_the_hosts_state_is_not_obeyed_when_the_host_is_dropped() {
    an_agent_leaves_another_host_and_the_host_ends(Ending::Drop);
}

// ---------------------------------------------------------------------------------------------
// The files a typed launch runs.
// ---------------------------------------------------------------------------------------------

/// A stand-in agent that, once it has started, replaces the file the run placed at `replaced` by a
/// link to a program of the case's own that leaves a mark when it runs; the host is then asked to
/// start the agent again, as a line typed again is. Returns the text the second start ended in, and
/// whether the case's program ever ran. The first start is the control: it went through the same
/// check over the files as they were placed.
fn an_agent_replaces_a_placed_file_and_is_started_again(
    replaced: &str,
    forge: bool,
) -> (String, bool) {
    an_agent_leaves_a_change_and_is_started_again(
        forge,
        &|ctx, program, _| {
            let place = ctx.run.root().join(replaced);
            format!(
                "#!/bin/sh\n/bin/rm -f '{}'\n/bin/ln -s '{}' '{}'\n",
                place.display(),
                program.display(),
                place.display()
            )
        },
        &|ctx, _| {
            assert!(
                std::fs::symlink_metadata(ctx.run.root().join(replaced))
                    .expect("the link the stand-in made")
                    .file_type()
                    .is_symlink(),
                "the stand-in replaced {replaced} by a link"
            );
        },
    )
}

/// A stand-in agent that, once it has started, runs the program `script` writes (given the context,
/// the case's own program that leaves a mark, and the case's scratch directory outside the run);
/// with `forge` the run holds the forging launcher where the worker gives the shell its launcher,
/// with the real one beside it; `changed` then asserts that the program did its change; the host is asked to start the agent
/// again, as a line typed again is. Returns the text the second start ended in, and whether the
/// case's program ever ran. The first start is the control: it went through the same checks over
/// the run as it was placed.
fn an_agent_leaves_a_change_and_is_started_again(
    forge: bool,
    script: &dyn Fn(&Context, &Path, &Path) -> String,
    changed: &dyn Fn(&Context, &Path),
) -> (String, bool) {
    if std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty()) {
        // The stand-in is the agent here; a real agent is never asked to replace the run's files.
        return (String::new(), false);
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: {why}");
            return (String::new(), false);
        }
    };
    let scratch = std::fs::canonicalize(std::env::temp_dir())
        .expect("the temporary directory")
        .join(format!("kr-replaced-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&scratch).expect("a directory for the case's programs");
    let mark = scratch.join("mark");
    let program = scratch.join("program.sh");
    std::fs::write(
        &program,
        format!("#!/bin/sh\necho ran >> '{}'\n", mark.display()),
    )
    .expect("the program the link names");
    let mut ctx = Context::new(
        shell,
        Route::StandIn,
        Run::start("gateway-replaces"),
        runtime(),
    );
    ctx.forge = forge;
    ctx.place();
    let leave = scratch.join("leave.sh");
    std::fs::write(&leave, script(&ctx, &program, &scratch))
        .expect("the program the stand-in runs");
    for file in [&program, &leave] {
        std::fs::set_permissions(file, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("executable");
    }
    let mut more = vec![("STAND_IN_LEAVE", leave.display().to_string())];
    if forge {
        // The root every path the forging launcher reads must lie below.
        let root = std::fs::canonicalize(ctx.run.root()).expect("the run's directory");
        more.push(("KALAREACH_E2E_FORGE_ROOT", root.display().to_string()));
    }
    let session = Session::open_with(
        &ctx,
        "answer-when-released,keep-reading,stay,leave-a-host",
        &more,
    );
    let first = session.starts_the_agent(&[], None, &[]);
    changed(&ctx, &scratch);
    let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.starts_the_agent(&[], Some(first), &[])
    }));
    let said = match second {
        Ok(_) => "the second start went through".to_owned(),
        Err(panic) => panic_text(&*panic),
    };
    let ran = mark.exists();
    ctx.close(&session.host);
    drop(session);
    std::fs::remove_dir_all(&scratch).expect("the case's programs go");
    (said, ran)
}

/// A launcher the agent replaced by a link, after its first start, is not run by the next start:
/// the start is refused before the line is typed.
#[test]
fn gateway_a_launcher_the_agent_replaced_is_not_run_by_the_next_start() {
    let (said, ran) = an_agent_replaces_a_placed_file_and_is_started_again("b/kr-hook", false);
    if said.is_empty() {
        return;
    }
    assert!(
        said.contains(ISOLATION_UNPROVEN) && said.contains("symbolic link"),
        "the next start was refused as a replaced file: {said}"
    );
    assert!(!ran, "the program the replaced launcher names ran");
}

/// The real launcher that sits beside the forging one, replaced by a link after the first start, is
/// not run by the next start either: the forging launcher runs it in place, so a replaced file there
/// would run the program the link names. The start is refused before the line is typed.
#[test]
fn gateway_a_real_launcher_the_agent_replaced_beside_the_forging_one_is_not_run_by_the_next_start()
{
    let (said, ran) = an_agent_replaces_a_placed_file_and_is_started_again("b/h/kr-hook", true);
    if said.is_empty() {
        return;
    }
    assert!(
        said.contains(ISOLATION_UNPROVEN) && said.contains("symbolic link"),
        "the next start was refused as a replaced file: {said}"
    );
    assert!(!ran, "the program the replaced real launcher names ran");
}

/// The stand-in the shell finds by name, replaced by a link after the first start, is not run by the
/// next start either.
#[test]
fn gateway_a_stand_in_the_agent_replaced_is_not_run_by_the_next_start() {
    let (said, ran) = an_agent_replaces_a_placed_file_and_is_started_again("t/codex", false);
    if said.is_empty() {
        return;
    }
    assert!(
        said.contains(ISOLATION_UNPROVEN) && said.contains("symbolic link"),
        "the next start was refused as a replaced file: {said}"
    );
    assert!(!ran, "the program the replaced stand-in names ran");
}

/// What the checks made right before a typing say of a run where a launcher was replaced after the
/// checks made before the probes, as a probe may replace it: the control before the replacement
/// and the check after it, as texts. None where the run cannot be made here.
fn launcher_replaced_during_a_probe(
    launcher: &str,
) -> Option<(Result<(), String>, Result<(), String>)> {
    if std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty()) {
        return None;
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: {why}");
            return None;
        }
    };
    let mut ctx = Context::new(
        shell,
        Route::StandIn,
        Run::start("gateway-probe-replaces"),
        runtime(),
    );
    ctx.forge = true;
    ctx.place();
    let checked = |ctx: &Context| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ctx.checks_before_a_typing()
        }))
        .map_err(|panic| panic_text(&*panic))
    };
    let control = checked(&ctx);
    let placed = ctx.run.root().join(launcher);
    let elsewhere = ctx.run.root().join("elsewhere");
    std::fs::write(&elsewhere, b"another program").expect("another file");
    std::fs::remove_file(&placed).expect("the launcher removed");
    std::os::unix::fs::symlink(&elsewhere, &placed).expect("a link in its place");
    let after = checked(&ctx);
    ctx.run.closing_check().expect("nothing runs");
    Some((control, after))
}

/// A launcher a probe replaced, the worker's or the real one beside the forging one, is refused by
/// the checks made right before the typing, which the case makes after every probe.
#[test]
fn gateway_a_launcher_a_probe_replaced_is_refused_by_the_checks_made_right_before_the_typing() {
    for launcher in ["b/kr-hook", "b/h/kr-hook"] {
        let Some((control, after)) = launcher_replaced_during_a_probe(launcher) else {
            return;
        };
        assert!(
            control.is_ok(),
            "the checks pass before the replacement ({launcher}): {control:?}"
        );
        assert!(
            after
                .as_ref()
                .is_err_and(|why| why.contains(ISOLATION_UNPROVEN) && why.contains("symbolic link")),
            "a replaced launcher ({launcher}) is refused before the typing: {after:?}"
        );
    }
}

/// The forging launcher's root reaches the session on a real route too: the variables a session is
/// given hold the case's own on every route, and the stand-in's only on its own.
#[test]
fn the_variables_a_case_asks_for_reach_the_session_on_every_route() {
    let more = [("KALAREACH_E2E_FORGE_ROOT", "/run/root".to_owned())];
    let real = given_variables(None, &more);
    assert_eq!(
        real,
        vec![(
            "KALAREACH_E2E_FORGE_ROOT".to_owned(),
            "/run/root".to_owned()
        )],
        "a real route is given the case's own and no stand-in variable"
    );
    let stand_in = given_variables(
        Some(vec![("STAND_IN".to_owned(), "stay".to_owned())]),
        &more,
    );
    assert_eq!(
        stand_in
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["STAND_IN", "KALAREACH_E2E_FORGE_ROOT"],
        "the stand-in route is given its own first, then the case's"
    );
}

/// A probe that has ended and moved the run's working directory out of the run, leaving an empty
/// directory at its place, leaves the session's shell in the moved directory: the next typing is
/// refused before a byte is typed, though every placed file is as it was placed and the new
/// directory holds nothing that an absence check looks for.
#[test]
fn gateway_a_work_directory_the_agent_moved_out_of_the_run_is_not_started_in_by_the_next_start() {
    let (said, _) = an_agent_leaves_a_change_and_is_started_again(
        false,
        &|ctx, _, scratch| {
            let work = ctx.run.work();
            format!(
                "#!/bin/sh\n/bin/mv '{}' '{}'\n/bin/mkdir '{}'\n",
                work.display(),
                scratch.join("moved").display(),
                work.display()
            )
        },
        &|ctx, scratch| {
            assert!(
                scratch.join("moved").is_dir() && ctx.run.work().is_dir(),
                "the stand-in moved the work directory out and left another in its place"
            );
        },
    );
    if said.is_empty() {
        return;
    }
    assert!(
        said.contains(ISOLATION_UNPROVEN) && said.contains("is another directory"),
        "the next start was refused as another directory at the work directory's place: {said}"
    );
    assert!(
        said.contains("is outside it and is not scanned for keys"),
        "the refusal says what became of the moved directory: {said}"
    );
}

// ---------------------------------------------------------------------------------------------
// The environment of the session's shell, read at its prompt before the first typing.
// ---------------------------------------------------------------------------------------------

/// `list` with `change` made to it.
fn changed(
    list: &[(String, String)],
    change: impl FnOnce(&mut Vec<(String, String)>),
) -> Vec<(String, String)> {
    let mut changed = list.to_vec();
    change(&mut changed);
    changed
}

/// The managed shell of a session holds what the harness gave `kr new`, the stand-in's own variables
/// among it, and its screen shows no value of them; a value that differs, a name the shell lacks, an
/// exported name the build list clears and a name the host would drop are each refused by the
/// variable's name, with no value in the refusal, and the control is the shell as given.
#[test]
fn gateway_the_session_environment_is_read_at_the_prompt_before_the_first_typing() {
    if std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty()) {
        // The shell of a real route is read by every case that starts the agent.
        return;
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: {why}");
            return;
        }
    };
    let mut ctx = Context::new(
        shell,
        Route::StandIn,
        Run::start("gateway-environment"),
        runtime(),
    );
    ctx.place();
    // Enough names that the answer comes in several parts, and the exported names in more than one.
    let padding: Vec<(&str, String)> = [
        "PADDING_A",
        "PADDING_B",
        "PADDING_C",
        "PADDING_D",
        "PADDING_E",
        "PADDING_F",
        "PADDING_G",
        "PADDING_H",
        "PADDING_I",
        "PADDING_J",
        "PADDING_K",
        "PADDING_L",
        "PADDING_M",
        "PADDING_N",
        "PADDING_O",
        "PADDING_P",
        "PADDING_Q",
        "PADDING_R",
        "PADDING_S",
        "PADDING_T",
        "PADDING_U",
    ]
    .into_iter()
    .map(|name| (name, format!("{name}-is-given-to-the-shell")))
    .collect();
    let session = Session::open_with(&ctx, "stay", &padding);
    let list = {
        let mut list = ctx.variables(&session.host);
        list.extend(ctx.stand_in_variables("stay", &padding));
        list
    };
    let release = release_of(&ctx).display().to_string();
    let held = |name: &str| {
        list.iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value.clone())
            .expect("a variable of the list")
    };
    // The control: the shell as given.
    let compared = session
        .person
        .reads_the_environment(&session.person.expected)
        .unwrap_or_else(|why| panic!("the shell holds what it was given: {why}"));
    assert!(
        compared.starts_with(session_environment::PASSED)
            && compared.contains(": ok: ")
            && compared.contains("STAND_IN_RELEASE")
            && !compared.contains('\n'),
        "a pass says what it compared: {compared}"
    );
    assert!(
        list.iter()
            .filter(|(_, value)| value.len() >= session_environment::SHORTEST_VALUE_CHECKED)
            .all(|(_, value)| !compared.contains(value.as_str())),
        "a pass holds no value: {compared}"
    );
    // A function of the session named `printf`, which says so when a word it is given holds the
    // run's marker, as the check's line hands the marker's value to the builtin: the check calls
    // the builtin, so the function is not run with a value, and the answer is read as it was. The
    // word the function prints is made by the shell, so that the typed definition does not show it.
    session.person.types(&format!(
        "printf() {{ [[ \"$*\" == *\"${}\"* ]] && builtin print -r -- KR-$((6*7))-PRINTF; \
         builtin printf \"$@\"; }}",
        ctx.run.mark().0
    ));
    session
        .person
        .reads_the_environment(&session.person.expected)
        .unwrap_or_else(|why| panic!("the check reads past a function named printf: {why}"));
    let screen = session.person.window.screen().join("\n");
    assert!(
        !screen.contains("KR-42-PRINTF"),
        "the function printf was called with a value by a line of the check: {screen}"
    );
    let refused = |expected: &Expected| {
        session
            .person
            .reads_the_environment(expected)
            .expect_err("the shell is not as the harness expects it")
    };
    let expecting = |list: &[(String, String)], cleared: &[&str]| {
        let cleared: Vec<String> = cleared.iter().map(|text| (*text).to_owned()).collect();
        Expected::new(
            list,
            ctx.run.mark(),
            &session
                .host
                .variables()
                .into_iter()
                .map(|(name, _)| name)
                .chain(["TERM".to_owned(), "SHELL".to_owned()])
                .collect::<Vec<_>>(),
            &cleared,
            &[],
        )
        .unwrap_or_else(|why| panic!("{why}"))
    };
    // A value that differs from the one given.
    let why = refused(&expecting(
        &changed(&list, |list| {
            list.iter_mut()
                .find(|(name, _)| name == "STAND_IN_RELEASE")
                .expect("the stand-in's variable")
                .1 = "/not/the/release".to_owned();
        }),
        &[],
    ));
    assert!(
        why.contains("STAND_IN_RELEASE")
            && !why.contains("/not/the/release")
            && !why.contains(&release),
        "a value that differs is refused by its name: {why}"
    );
    // A name given that the shell does not export.
    let why = refused(&expecting(
        &changed(&list, |list| {
            list.push((
                "GIVEN_BUT_NOT_TO_THE_SHELL".to_owned(),
                "not-in-the-shell".to_owned(),
            ))
        }),
        &[],
    ));
    assert!(
        why.contains("GIVEN_BUT_NOT_TO_THE_SHELL") && !why.contains("not-in-the-shell"),
        "a name the shell lacks is refused by its name: {why}"
    );
    // A name the build list clears that the shell exports.
    let why = refused(&expecting(&list, &["STAND_IN_REC*"]));
    assert!(
        why.contains("STAND_IN_RECEIVED") && why.contains("clears"),
        "an exported name the build list clears is refused by its name: {why}"
    );
    assert!(!why.contains(&held("STAND_IN_RECEIVED")), "no value: {why}");
    // A name of the list that the host would drop, by the harness's own expectation.
    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.expects(
            &session.host,
            &changed(&list, |list| {
                list.push(("KR_VARIANTS".to_owned(), "not-for-a-session".to_owned()))
            }),
        )
    }));
    let said = panic_text(&*dropped.expect_err("a name the host drops is refused"));
    assert!(
        said.contains("KR_VARIANTS") && !said.contains("not-for-a-session"),
        "a name the host drops is refused by its name: {said}"
    );
    assert!(
        session.person.expected.value_parts() >= 3,
        "the answer was read in several parts: {:?}",
        session.person.expected
    );
    // The start makes the check: a shell that holds another value than the one given is refused
    // at the first typing, and nothing of the stand-in is typed or run.
    session
        .person
        .types("export STAND_IN_RELEASE=/not/the/release");
    let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.starts_the_agent(&[], None, &[])
    }));
    let said = panic_text(&*started.expect_err("the first start is refused"));
    assert!(
        said.contains("STAND_IN_RELEASE") && !said.contains("/not/the/release"),
        "the first start was refused by the variable's name: {said}"
    );
    assert!(
        !session
            .person
            .window
            .screen()
            .iter()
            .any(|row| row.contains(RAN_AS_TYPED)),
        "the stand-in was typed and ran"
    );
    ctx.close(&session.host);
}

// ---------------------------------------------------------------------------------------------
// A child the agent leaves running outside its process group.
// ---------------------------------------------------------------------------------------------

/// The child the cases below start: this test executable, which runs the test that follows and
/// sleeps. Its own environment is shown by the system on every platform; the system's own
/// protected programs (`sleep`, `sh`) show none on macOS.
#[test]
#[ignore = "started by the cases that leave a child behind"]
fn a_sleeper_the_cases_that_leave_a_child_start() {
    if std::env::var_os("KR_E2E_SLEEPER").is_some() {
        std::thread::sleep(Duration::from_secs(300));
    }
}

/// How long a child that left its process group may take to end after the host has stopped, where
/// the host's own closure ends it.
const ENDED_WITH_THE_HOST: Duration = Duration::from_secs(10);

/// Whether the process `pid` runs, as `kill -0` says.
fn is_running(pid: u32) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A stand-in agent that, once it has started, starts a child that leaves its process group, is
/// adopted by the system's first process, and names nothing of the run on its command line, in the
/// run's working directory, with the environment the agent has or with none. The host is then
/// stopped and the run's closing check made: the child that kept its environment, which carries the
/// run's marker, is found and fails the check, and ended by its number the check then passes; the
/// child that cleared its environment is the limit the check names, and passes.
///
/// On Linux the worker is the child subreaper, so the system hands the child to the worker and not
/// to the first process, and where the host delegates a control group the worker's closure ends
/// every process in it, one that left its process group included, when the host stops. The check
/// then has nothing to find, and passes. That is accepted only for a child that is no longer
/// running within [`ENDED_WITH_THE_HOST`] of the stop, by `kill -0`, with the check Ok; any other
/// result meets the assertion above.
fn an_agent_leaves_a_child_outside_its_group(keeps_environment: bool) {
    if std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty()) {
        // The stand-in is the agent here; a real agent is never asked to leave a child behind.
        return;
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: {why}");
            return;
        }
    };
    let scratch = std::fs::canonicalize(std::env::temp_dir())
        .expect("the temporary directory")
        .join(format!("kr-detached-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&scratch).expect("a directory for the case's files");
    let mut ctx = Context::new(
        shell,
        Route::StandIn,
        Run::start("gateway-detaches"),
        runtime(),
    );
    ctx.place();
    let started = scratch.join("child");
    let leave = scratch.join("leave.sh");
    let environment = if keeps_environment {
        ""
    } else {
        "/usr/bin/env -i PATH=/usr/bin:/bin "
    };
    std::fs::write(
        &leave,
        format!(
            "#!/bin/sh\ncd '{work}' || exit 1\n{environment}KR_E2E_SLEEPER=1 /usr/bin/perl -MPOSIX -e \
             'my $p = fork(); if ($p) {{ print \"$p\\n\"; exit 0 }} POSIX::setsid(); \
             open(STDOUT, \">\", \"/dev/null\"); open(STDERR, \">\", \"/dev/null\"); \
             open(STDIN, \"<\", \"/dev/null\"); \
             exec $ARGV[0], \"--exact\", \"a_sleeper_the_cases_that_leave_a_child_start\", \
             \"--ignored\", \"--nocapture\";' '{exe}' > '{started}'\n",
            work = ctx.run.work().display(),
            exe = std::env::current_exe().expect("this test executable").display(),
            started = started.display(),
        ),
    )
    .expect("the program the stand-in runs");
    std::fs::set_permissions(&leave, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("executable");
    let session = Session::open_with(
        &ctx,
        "answer-when-released,keep-reading,stay,leave-a-host",
        &[("STAND_IN_LEAVE", leave.display().to_string())],
    );
    let _ = session.starts_the_agent(&[], None, &[]);
    let child: u32 = std::fs::read_to_string(&started)
        .expect("the child's number")
        .trim()
        .parse()
        .expect("a number");
    session.host.stop().expect("the host stops");
    let ended_with_the_host = cfg!(target_os = "linux") && {
        let waited = Instant::now();
        while is_running(child) && waited.elapsed() < ENDED_WITH_THE_HOST {
            std::thread::sleep(Duration::from_millis(50));
        }
        !is_running(child)
    };
    let closing = ctx.run.closing_check();
    if keeps_environment {
        if !(ended_with_the_host && closing.is_ok()) {
            let said = closing.expect_err("the child that kept its environment is found");
            assert!(
                said.contains(&format!("process {child} holds the run's marker")),
                "{said}"
            );
        }
    } else {
        let passed = closing.expect("the child that cleared its environment is the named limit");
        assert!(
            passed.contains("whose environment the system shows"),
            "{passed}"
        );
    }
    let _ = std::process::Command::new("/bin/kill")
        .arg(child.to_string())
        .status();
    let waited = Instant::now();
    while is_running(child) && waited.elapsed() < LIVENESS {
        std::thread::sleep(Duration::from_millis(50));
    }
    ctx.run
        .closing_check()
        .unwrap_or_else(|why| panic!("with the child ended the close passes: {why}"));
    drop(session);
    std::fs::remove_dir_all(&scratch).expect("the case's files go");
}

/// A child the agent leaves outside its process group, which keeps its environment, is found by the
/// run's marker at the close, and the close fails on it.
#[test]
fn gateway_a_child_outside_the_agents_group_that_keeps_its_environment_fails_the_close() {
    an_agent_leaves_a_child_outside_its_group(true);
}

/// One that cleared its environment is the limit the closing text names: the close passes, and says
/// only what it checked.
#[test]
fn gateway_a_child_outside_the_agents_group_that_cleared_its_environment_is_the_named_limit() {
    an_agent_leaves_a_child_outside_its_group(false);
}

// ---------------------------------------------------------------------------------------------
// The launch the real route types.
// ---------------------------------------------------------------------------------------------

/// The package's integration serves the launches the real route types, and no launch that types an
/// option: a launch that is not served runs as typed, with no gateway.
/// When the check that everything the run started has ended has failed, the run is not read and the
/// outcome says so with a class; when it passed, it is read.
#[test]
fn the_directory_a_move_probe_leaves_beside_the_run_is_removed_only_where_it_is_empty() {
    let base = std::env::temp_dir().join(format!("kr-moved-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("krm-run");
    let moved = base.join("krm-run-moved");
    std::fs::create_dir_all(&root).expect("a run's root");
    assert_eq!(
        removes_the_moved_work_directory(&root),
        ("none beside the run", false)
    );
    // Empty: removed, and the run's own root is not touched.
    std::fs::create_dir(&moved).expect("a moved directory");
    assert!(
        !removes_the_moved_work_directory(&root).1,
        "an empty directory is no stop"
    );
    assert!(!moved.exists() && root.is_dir());
    // It holds something: left where it is, with what is in it, and said so.
    std::fs::create_dir(&moved).expect("a moved directory");
    std::fs::write(moved.join("theirs"), "kept").expect("a file");
    let (said, stops) = removes_the_moved_work_directory(&root);
    assert!(
        said.contains("holds something") && said.contains("not scanned"),
        "{said}"
    );
    assert!(stops, "a directory that holds something stops the case");
    assert_eq!(
        std::fs::read_to_string(moved.join("theirs")).expect("a file"),
        "kept"
    );
    std::fs::remove_dir_all(&moved).expect("removed");
    // A link at that name is not followed and not removed, and an empty directory it names stays.
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("a directory");
    std::os::unix::fs::symlink(&elsewhere, &moved).expect("a link");
    let (said, stops) = removes_the_moved_work_directory(&root);
    assert!(said.contains("not a directory") && !stops, "{said}");
    assert!(elsewhere.is_dir() && moved.is_symlink());
    // What the end does with it: the outcome says what was found, and a directory that holds
    // something adds the stop; an empty one adds none.
    std::fs::remove_file(&moved).expect("the link removed");
    let (mut evidence, mut stops) = (serde_json::json!({}), Vec::new());
    tells_the_moved_work_directory(&root, &mut evidence, &mut stops);
    assert!(stops.is_empty(), "nothing beside the run: {stops:?}");
    std::fs::create_dir(&moved).expect("a moved directory");
    std::fs::write(moved.join("theirs"), "kept").expect("a file");
    tells_the_moved_work_directory(&root, &mut evidence, &mut stops);
    assert_eq!(
        stops.iter().map(|stop| stop.0).collect::<Vec<_>>(),
        vec!["moved_work_directory_left"]
    );
    assert!(
        evidence["moved_work_directory"]
            .as_str()
            .is_some_and(|said| said.contains("holds something")),
        "{evidence}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_run_whose_processes_are_not_shown_ended_is_not_read() {
    let stop = run_may_be_read(false).expect_err("a run whose processes are not shown ended");
    assert_eq!(stop.0, "run_not_read");
    assert!(stop.1.contains("not read"), "{}", stop.1);
    assert!(run_may_be_read(true).is_ok());
}

#[test]
fn the_launches_the_real_route_types_are_ones_the_command_integration_serves() {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(codex_package().join("plugin.json")).expect("the package's manifest"),
    )
    .expect("a manifest");
    let backend: kr_plugin_sdk::integration::IntegrationBackend =
        serde_json::from_value(manifest["command_integration"]["backend"].clone())
            .expect("the integration's backend");
    let thread = "0199a213-81c0-7800-8aa1-bbab2a035a53";
    for extra in [&[][..], &["resume", thread][..], &["fork", thread][..]] {
        assert_eq!(
            backend.refuses(&launch_words("codex", extra)),
            None,
            "{extra:?}"
        );
    }
    let resume = launch_words("codex", &["resume", thread]);
    assert_eq!(backend.saved_conversation(&resume), Some(thread));
    // The entry's own options are what the integration refuses, which is why they are keys of the
    // run's configuration file instead.
    for options in [
        &["-a", "on-request"][..],
        &["-c", "approval_policy=\"on-request\""][..],
    ] {
        let words = launch_words("codex", options);
        assert!(backend.refuses(&words).is_some(), "{words:?}");
    }
}

/// The agent's list of commands names a command with a description after it, and nothing else on
/// the screen counts: not the composer's own row, not a longer command that begins with the same
/// letters, not the command alone.
#[test]
fn a_command_is_named_only_by_a_row_of_the_agents_own_list_of_commands() {
    assert!(lists_command("  /fork      fork the current chat", "/fork"));
    assert!(lists_command("│ /fork  copy this conversation │", "/fork"));
    assert!(!lists_command("› /fork", "/fork"), "the composer's row");
    assert!(!lists_command("/fork", "/fork"), "no description");
    assert!(!lists_command("  /forked    another command", "/fork"));
    assert!(!lists_command("  /new       start a new chat", "/fork"));
}

/// The list a command is read from is the rows the typing drew, not rows that the screen showed
/// already: a command a history row or a help screen names does not make the list name it.
#[test]
fn a_row_the_screen_showed_before_is_not_the_agents_list_of_commands() {
    let rows = |lines: &[&str]| {
        lines
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
    };
    let history = rows(&["  /fork      fork the current chat", "", "› "]);
    let typed = rows(&["  /fork      fork the current chat", "", "› /fork"]);
    assert!(
        new_rows(&history, &typed)
            .iter()
            .all(|row| !lists_command(row, "/fork")),
        "a row of the history is not the list"
    );
    let listed = rows(&[
        "  /fork      fork the current chat",
        "",
        "› /fork",
        "  /fork      copy this conversation",
    ]);
    assert!(
        new_rows(&history, &listed)
            .iter()
            .any(|row| lists_command(row, "/fork")),
        "a row that was not there before is the list"
    );
    let same_text_again = rows(&["  /fork      fork the current chat", "› /fork"]);
    assert_eq!(
        new_rows(&same_text_again, &same_text_again),
        Vec::<&str>::new(),
        "nothing is new on a screen that did not change"
    );
}

/// The agent's list is the new rows under the composer's own row: a history row that is drawn
/// again with other words above the composer, or a screen with no composer row that holds the
/// typed command, is not a list.
#[test]
fn the_list_of_commands_is_the_new_rows_below_the_composers_row() {
    let rows = |lines: &[&str]| {
        lines
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
    };
    let before = rows(&["history", "  /fork      fork the current chat", "", "› "]);
    // The typing draws the composer's row, and the list under it.
    let drawn = rows(&[
        "history",
        "  /fork      fork the current chat",
        "",
        "› /fork",
        "  /fork      copy this conversation",
        "  /forks     another command",
    ]);
    assert_eq!(
        list_region(&before, &drawn, "/fork"),
        vec![
            "  /fork      copy this conversation",
            "  /forks     another command"
        ]
    );
    // A history row drawn again with other words, above the composer, is not the list.
    let redrawn = rows(&[
        "history",
        "  /fork      fork the chat, as edited",
        "",
        "› /fork",
    ]);
    assert!(
        list_region(&before, &redrawn, "/fork")
            .iter()
            .all(|row| !lists_command(row, "/fork"))
    );
    // A help row that is new but is drawn above the composer's row is not the list either.
    let help_above = rows(&["  /fork      shown by a help screen", "history", "› /fork"]);
    assert!(list_region(&before, &help_above, "/fork").is_empty());
    // No new row holds the typed command with a mark before it: nothing shows that it was typed
    // at the composer, so there is no region.
    let no_composer = rows(&["history", "  /fork      a new description", "", "› "]);
    assert!(list_region(&before, &no_composer, "/fork").is_empty());
}

/// The question's choice and the answer's check use one matcher, and the answer must be drawn after
/// the prompt: a screen that already holds the sum in its comma form, or in a row such as a count of
/// tokens, cannot pass for the answer.
#[test]
fn the_answer_is_checked_with_the_matcher_the_question_was_chosen_by_and_only_in_new_rows() {
    let rows = |lines: &[&str]| {
        lines
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>()
    };
    // What a question's sum must not be on the screen as: the plain digits or the comma form, as a
    // number of its own.
    assert!(on_screen(&rows(&["total 1,557 tokens"]), "1557"));
    assert!(on_screen(&rows(&["x", "= 1557."]), "1557"));
    assert!(!on_screen(&rows(&["thread 019a2b3c-1557-7abc"]), "1557"));
    // The answer is in a row that the screen did not show when the prompt was sent.
    let before = rows(&["tokens used: 1,557", "› "]);
    let typed = rows(&["tokens used: 1,557", "› (kr0123) What is 700 plus 857?"]);
    assert!(
        !answered_since(&before, &typed, "1557"),
        "a count shown before the prompt is not the answer"
    );
    let answered = rows(&[
        "tokens used: 1,557",
        "› (kr0123) What is 700 plus 857?",
        "1557",
    ]);
    assert!(answered_since(&before, &answered, "1557"));
    // A row drawn again, with the sum in it where it was not, is new.
    let redrawn = rows(&["tokens used: 2,100", "› "]);
    assert!(!answered_since(&before, &redrawn, "1557"));
    let again = rows(&["tokens used: 1,557 of 9,000", "› "]);
    assert!(answered_since(&before, &again, "1557"));
}

/// The sum is a number of its own: the plain digits and the form with a thousands separator pass,
/// and the same digits in an identifier, a longer number or a word do not.
#[test]
fn the_sum_is_matched_as_a_whole_word_with_or_without_a_thousands_separator() {
    for shown in [
        "1557",
        "The answer is 1557.",
        "  1,557  ",
        "= 1557, as asked",
        "**1557**",
        "(1557)",
        "1,557.",
    ] {
        assert!(shows_sum(shown, "1557"), "{shown:?}");
    }
    for shown in [
        "thread 019a2b3c-1557-7abc-8d9e-0123456789ab",
        "id a1557",
        "21557",
        "15570",
        "1557.25",
        "1557,123",
        "12,1557",
        "rollout_1557_x",
        "/tmp/1557/x",
        "1,5570",
        "",
    ] {
        assert!(!shows_sum(shown, "1557"), "{shown:?}");
    }
    assert!(shows_sum("2,015", "2015"));
    assert_eq!(with_thousands("1557"), "1,557");
    assert_eq!(with_thousands("1000"), "1,000");
}

/// A failure at the instance wait or at the device's prompt carries the host's list of application
/// instances as the device read it, the last twenty reads in order, and the terminal's screen
/// without its empty rows.
#[test]
fn a_row_the_failure_text_keeps_the_last_twenty_polls_and_the_screen() {
    let polls = Polls::new();
    for number in 0..25 {
        polls.record(&format!("poll {number} listed no instance"));
    }
    let text = diagnosis_text(
        &polls,
        &[
            "TUI: thread/started".to_owned(),
            "   ".to_owned(),
            String::new(),
        ],
    );
    assert_eq!(text.matches(" listed no instance").count(), POLLS_KEPT);
    assert!(
        !text.contains("poll 4 listed"),
        "the oldest reads are dropped"
    );
    assert!(text.contains("poll 5 listed") && text.contains("poll 24 listed"));
    assert!(
        text.find("poll 5 listed") < text.find("poll 24 listed"),
        "the reads are in order"
    );
    assert!(
        text.ends_with("the terminal's screen:\nTUI: thread/started"),
        "{text}"
    );
    assert_eq!(Polls::new().text(), "(no read)");
}

// ---------------------------------------------------------------------------------------------
// The wait that takes a bounded hold for a request in flight.
// ---------------------------------------------------------------------------------------------

/// A binding that names `thread`, with no turn, suspended for `reason` where one is given.
fn a_binding(thread: Option<&str>, reason: Option<&str>) -> AgentBindingState {
    serde_json::from_value(serde_json::json!({
        "binding_revision": 1,
        "thread_id": thread,
        "turn_id": null,
        "profile_id": null,
        "mode": "gateway",
        "rich_mutations_suspended": reason.is_some(),
        "suspension_reason": reason,
    }))
    .expect("a binding")
}

#[test]
fn a_hold_for_a_request_in_flight_is_waited_out_for_a_bounded_time() {
    let watch = InFlightWatch::new(Some("thread-1"));
    let held = a_binding(Some("thread-1"), Some(IN_FLIGHT_REASON));
    let start = Instant::now();
    assert_eq!(watch.judge(&held, start), Verdict::Waiting);
    assert_eq!(
        watch.judge(&held, start + IN_FLIGHT_BOUND / 2),
        Verdict::Waiting
    );
    assert!(matches!(
        watch.judge(&held, start + IN_FLIGHT_BOUND),
        Verdict::Failed(why) if why.contains("waited")
    ));
}

#[test]
fn a_hold_that_ended_starts_its_bound_again() {
    let watch = InFlightWatch::new(None);
    let held = a_binding(Some("thread-1"), Some(IN_FLIGHT_REASON));
    let open = a_binding(Some("thread-1"), None);
    let start = Instant::now();
    assert_eq!(watch.judge(&held, start), Verdict::Waiting);
    assert_eq!(
        watch.judge(&open, start + IN_FLIGHT_BOUND / 2),
        Verdict::Open
    );
    assert_eq!(
        watch.judge(&held, start + IN_FLIGHT_BOUND),
        Verdict::Waiting
    );
}

#[test]
fn a_suspension_for_any_other_reason_fails_at_once() {
    let watch = InFlightWatch::new(Some("thread-1"));
    for reason in [
        "the terminal's conversation is not read from its stream, so which thread it has selected is unknown",
        "what became of the terminal's last request to change its conversation is unknown, so which conversation it is in is unknown",
        "a method the table does not list was sent",
    ] {
        let binding = a_binding(Some("thread-1"), Some(reason));
        assert!(
            matches!(watch.judge(&binding, Instant::now()), Verdict::Failed(_)),
            "{reason}"
        );
    }
}

#[test]
fn a_thread_other_than_the_one_the_wait_is_for_fails_even_where_rich_work_is_available() {
    let watch = InFlightWatch::new(Some("thread-1"));
    assert_eq!(
        watch.judge(&a_binding(Some("thread-1"), None), Instant::now()),
        Verdict::Open
    );
    for other in [Some("thread-2"), None] {
        assert!(matches!(
            watch.judge(&a_binding(other, None), Instant::now()),
            Verdict::Failed(_)
        ));
    }
}

/// A probe the way a build list entry gives it.
fn a_probe(value: serde_json::Value) -> Probe {
    serde_json::from_value(value).expect("a probe")
}

/// The probe-only run is the upgrade case's, on a real build: asked for anywhere else it is refused,
/// and not asked for it is not a probe-only run.
#[test]
fn a_probe_only_run_is_the_upgrade_cases_on_a_real_build_alone() {
    let upgrade = Setup {
        upgrade: true,
        ..Setup::default()
    };
    assert_eq!(probe_only_mode(upgrade, true, true), Ok(true));
    assert_eq!(probe_only_mode(upgrade, false, true), Ok(false));
    assert_eq!(probe_only_mode(Setup::default(), false, false), Ok(false));
    let other = probe_only_mode(Setup::default(), true, true).expect_err("not the upgrade case");
    assert!(other.contains(PROBE_ONLY_VARIABLE), "{other}");
    let stand_in = probe_only_mode(upgrade, true, false).expect_err("no build list entry");
    assert!(stand_in.contains(BUILD_VARIABLE), "{stand_in}");
}

/// What a probe-only run records of a probe says whether the answer holds what the pinned entry
/// expects, which expectation it misses, the answer's digest and the search for keys, keeps the
/// rows the criteria are read from, and refuses adoption where evidence is incomplete.
#[test]
fn a_probe_only_record_names_the_expectation_of_the_pinned_entry_the_answer_misses() {
    let probe = a_probe(serde_json::json!({
        "arguments": ["features", "list"],
        "lines": ["apps stable false", "hooks stable false"],
    }));
    let kept = Kept {
        kept_in: Ok("answer.txt".to_owned()),
        keys_searched: 1,
        key_found: false,
    };
    let record_of = |text: &str, ended: Result<(), String>, kept: &Kept| {
        let answer = Answer {
            text: text.to_owned(),
            stubbed: false,
            ended,
        };
        probe_record(&probe, &answer, kept, &mut RECORDED_TOTAL_CHARS.clone())
    };
    let record = record_of("apps  stable  false\nhooks stable false\n", Ok(()), &kept);
    assert_eq!(record["holds_the_pinned_entrys_expectations"], true);
    assert_eq!(record["misses"], serde_json::Value::Null);
    assert_eq!(record["answer"]["line_count"], 2);
    assert_eq!(
        record["answer"]["sha256"],
        kr_cbor::sha256(b"apps  stable  false\nhooks stable false\n")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(record["answer"]["kept_in"], "answer.txt");
    assert_eq!(record["keys"]["found"], false);
    assert_eq!(record["truncated"], false);
    assert_eq!(record["adoptable"], true);

    let record = record_of("apps stable false\nhooks stable true\n", Ok(()), &kept);
    assert_eq!(record["holds_the_pinned_entrys_expectations"], false);
    assert!(
        record["misses"]
            .as_str()
            .is_some_and(|why| why.contains("hooks stable false")),
        "{record}"
    );
    // The row the answer shows instead is kept: it is a feature row.
    assert_eq!(
        record["relevant_rows"],
        serde_json::json!(["apps stable false", "hooks stable true"])
    );

    // A command that ended badly does not hold, whatever it printed.
    let record = record_of(
        "apps stable false\nhooks stable false\n",
        Err("it ended with exit status: 2".to_owned()),
        &kept,
    );
    assert_eq!(record["holds_the_pinned_entrys_expectations"], false);
    assert_eq!(record["ended"], "it ended with exit status: 2");

    // A feature the entry does not list is kept. A row that is not a feature row is left out of
    // the rows and counted, and the feature list is not adopted with a row left out.
    let record = record_of(
        "apps stable false\nunlisted_feature experimental true\n",
        Ok(()),
        &kept,
    );
    assert_eq!(
        record["relevant_rows"],
        serde_json::json!(["apps stable false", "unlisted_feature experimental true"])
    );
    assert_eq!(record["rows_left_out"], 0);
    assert_eq!(record["adoptable"], true);
    let record = record_of(
        "prose that is no feature\napps stable false\n\napps stable on\n",
        Ok(()),
        &kept,
    );
    assert_eq!(
        record["relevant_rows"],
        serde_json::json!(["apps stable false"])
    );
    assert_eq!(record["answer"]["line_count"], 4);
    assert_eq!(record["rows_left_out"], 2, "{record}");
    assert_eq!(record["adoptable"], false, "{record}");
    // The prompt input's answer is read whole by the reviewers: a row left out is counted and
    // adoption does not turn on it.
    let prompt_input = a_probe(serde_json::json!({
        "arguments": ["debug", "prompt-input"],
        "shows": ["the sandbox is read-only"],
    }));
    let answer = Answer {
        text: "the sandbox is read-only\nsomething else the build says\n".to_owned(),
        stubbed: false,
        ended: Ok(()),
    };
    let record = probe_record(
        &prompt_input,
        &answer,
        &kept,
        &mut RECORDED_TOTAL_CHARS.clone(),
    );
    assert_eq!(record["rows_left_out"], 1, "{record}");
    assert_eq!(record["adoptable"], true, "{record}");

    // A row longer than the bound is cut and said to be: adoption is refused.
    let long = format!("apps stable false {}\n", "x".repeat(RECORDED_ROW_CHARS * 2));
    let record = record_of(&long, Ok(()), &kept);
    assert_eq!(record["truncated"], true);
    assert_eq!(record["adoptable"], false);
    // More relevant rows than the bound: cut and refused.
    let many = "apps stable false\n".repeat(RECORDED_ROWS + 1);
    let record = record_of(&many, Ok(()), &kept);
    assert_eq!(record["truncated"], true);
    assert_eq!(record["adoptable"], false);
    // The bound for all probes together: a second probe finds it used up.
    let mut left = 10;
    let answer = Answer {
        text: "apps stable false\n".to_owned(),
        stubbed: false,
        ended: Ok(()),
    };
    let record = probe_record(&probe, &answer, &kept, &mut left);
    assert_eq!(record["truncated"], true);
    assert_eq!(record["adoptable"], false);
    // An answer that is kept nowhere, or that holds a key, is not adopted.
    let nowhere = Kept {
        kept_in: Err("no directory".to_owned()),
        keys_searched: 1,
        key_found: false,
    };
    assert_eq!(
        record_of("apps stable false\n", Ok(()), &nowhere)["adoptable"],
        false
    );
    let found = Kept {
        kept_in: Err("the answer holds a key".to_owned()),
        keys_searched: 1,
        key_found: true,
    };
    let record = record_of("apps stable false\n", Ok(()), &found);
    assert_eq!(record["keys"]["found"], true);
    assert_eq!(record["adoptable"], false);
}

/// A probe's whole answer is searched for the keys the run holds, by the part's own search, and kept
/// in a new private file of the evidence directory only where it holds none: it is not written over
/// a file that is there, nor kept where no existing absolute directory is named.
#[test]
fn a_probe_answer_is_kept_whole_in_a_private_file_unless_it_holds_a_piece_of_a_key() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = kr_ipc::testing::PrivateTempDir::create();
    let place = std::fs::canonicalize(directory.path()).expect("the directory");
    let keys = ["sk-live-0123456789abcdef", ""];
    let answer = "apps stable false\nhooks stable false\n";

    let kept = searches_and_keeps(&keys, Some(&place), "one.txt", answer);
    assert_eq!(kept.kept_in, Ok("one.txt".to_owned()));
    assert_eq!((kept.keys_searched, kept.key_found), (1, false));
    assert_eq!(
        std::fs::read_to_string(place.join("one.txt")).expect("the kept answer"),
        answer
    );
    let mode = std::fs::metadata(place.join("one.txt"))
        .expect("the file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the file is private");

    // A file that is there is not written over.
    let again = searches_and_keeps(&keys, Some(&place), "one.txt", "other\n");
    assert!(again.kept_in.is_err(), "{:?}", again.kept_in);
    assert_eq!(
        std::fs::read_to_string(place.join("one.txt")).expect("the kept answer"),
        answer
    );

    // A piece of eight characters of a key is found, and the answer is written nowhere.
    let leaked = searches_and_keeps(
        &keys,
        Some(&place),
        "two.txt",
        "a row\nthe key is -live-01 and more\n",
    );
    assert!(leaked.key_found, "a piece of the key is found");
    assert!(leaked.kept_in.is_err());
    assert!(
        !place.join("two.txt").exists(),
        "the answer holding a key is not written"
    );

    // No directory, a relative one and one that is not there keep nothing.
    for directory in [
        None,
        Some(Path::new("relative")),
        Some(Path::new("/nonexistent-evidence-directory")),
    ] {
        let nowhere = searches_and_keeps(&keys, directory, "three.txt", answer);
        assert!(
            nowhere.kept_in.is_err(),
            "{directory:?}: {:?}",
            nowhere.kept_in
        );
    }
}

/// A generation's index that names the Codex package twice is refused, not read at its first entry.
#[test]
fn a_generation_index_that_names_the_codex_package_twice_is_refused() {
    let directory = kr_ipc::testing::PrivateTempDir::create();
    let place = std::fs::canonicalize(directory.path()).expect("the directory");
    std::fs::create_dir_all(place.join("targets")).expect("the targets directory");
    let entry = |version: &str| {
        serde_json::json!({
            "plugin_id": codex().to_string(),
            "version": version,
            "manifest_digest": "00",
            "capabilities": [],
        })
    };
    let write = |entries: serde_json::Value| {
        std::fs::write(
            place.join("targets/index.json"),
            serde_json::json!({ "entries": entries }).to_string(),
        )
        .expect("the index");
    };
    write(serde_json::json!([entry("1.0.0")]));
    assert_eq!(generation_entry(&place).version, "1.0.0");
    write(serde_json::json!([entry("1.0.0"), entry("1.1.0")]));
    let refused = std::panic::catch_unwind(|| generation_entry(&place));
    assert!(
        refused.is_err(),
        "an index that names the Codex package twice is refused"
    );
    let said = refused
        .err()
        .and_then(|why| why.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(said.contains("names the Codex package once"), "{said}");
}

/// A turn the newer build's record holds that its probes did not leave is found by its identity,
/// whatever the totals: a probe's turn that is gone and a new turn do not pass as an equal count.
#[test]
fn a_turn_the_probes_did_not_leave_is_found_by_its_identity_though_the_totals_are_equal() {
    let directory = kr_ipc::testing::PrivateTempDir::create();
    let root = std::fs::canonicalize(directory.path()).expect("the directory");
    let pin = kr_e2e_m1b::run::RootPin::of(&root).expect("a directory to pin");
    let account: Account = serde_json::from_value(serde_json::json!({
        "login": "l", "stored": "s", "home": "run", "budget": "b", "turns": 3,
        "conversations": "sessions/{date}", "prompt_line": "\"role\":\"user\"",
        "ready": "r", "composer": "c", "submit": "\r", "clear": "\u{15}",
        "reply_line": "x", "decision_line": "y", "busy": "b",
        "slash": { "input": "/p", "shows": "p" },
        "interrupt": { "input": "\u{1b}", "shows": "i" },
        "approval": { "shows": "a", "allow": "y", "deny": "n" },
        "resume": ["resume", "{conversation}"], "image": "paste",
        "turn_line": "\"type\":\"task_started\""
    }))
    .expect("an account");
    let line = |number: u8| {
        format!(
            r#"{{"payload":{{"type":"task_started","turn_id":"019a0000-0000-7000-8000-00000000000{number}"}}}}"#
        )
    };
    let count = || turns_recorded(&account, &root, &pin, Path::new("")).expect("a count");
    std::fs::write(root.join("a.jsonl"), format!("{}\n{}\n", line(1), line(2)))
        .expect("a conversation");
    let baseline = count();
    assert_eq!(baseline.turns, 2);
    assert_eq!(
        new_turns(&baseline, &count()),
        0,
        "an equal record has no new turn"
    );
    // One turn the probes left is removed and a new one is written: the total is the same.
    std::fs::write(root.join("a.jsonl"), format!("{}\n{}\n", line(1), line(3)))
        .expect("a rewritten conversation");
    let found = count();
    assert_eq!(found.turns, baseline.turns, "the totals are equal");
    assert_eq!(
        new_turns(&baseline, &found),
        1,
        "the new turn is found by its identity"
    );
    // A turn that names none has an identity of its place and its bytes.
    std::fs::write(root.join("b.jsonl"), "{\"type\":\"task_started\"}\n").expect("no name");
    let unnamed = count();
    assert_eq!(new_turns(&baseline, &unnamed), 2);
    // Its bytes rewritten, the line is another turn though the total is the same.
    std::fs::write(
        root.join("b.jsonl"),
        "{\"type\":\"task_started\",\"again\":true}\n",
    )
    .expect("another line");
    let rewritten = count();
    assert_eq!(rewritten.turns, unnamed.turns, "the totals are equal");
    assert_eq!(
        new_turns(&unnamed, &rewritten),
        1,
        "the rewritten line is found by its identity"
    );
    // A record that only lost a turn has no new one, and no identity is ever printed.
    let kept = count();
    std::fs::write(root.join("a.jsonl"), format!("{}\n", line(1))).expect("a shorter one");
    assert_eq!(new_turns(&kept, &count()), 0);
    assert!(!format!("{kept:?}").contains("019a0000"), "{kept:?}");
}

/// A configuration names a provider by the key of its name, by its table, and by any address of a
/// service, and by nothing else.
#[test]
fn a_configuration_names_a_provider_by_its_name_its_table_or_an_address() {
    assert!(
        provider_keys_in("approval_policy = \"on-request\"\n[features]\nhooks = false\n")
            .is_empty()
    );
    assert_eq!(
        provider_keys_in("model_provider = \"local\"\n"),
        vec!["model_provider".to_owned()]
    );
    assert_eq!(
        provider_keys_in("a = 1\n[model_providers.local]\nname = \"x\"\n"),
        vec!["model_providers".to_owned()]
    );
    assert_eq!(
        provider_keys_in("chatgpt_base_url = \"http://127.0.0.1:1\"\n"),
        vec!["chatgpt_base_url".to_owned()]
    );
    assert!(!provider_keys_in("not = = toml").is_empty());
}
