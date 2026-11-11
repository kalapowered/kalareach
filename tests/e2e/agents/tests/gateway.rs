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
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_e2e_agents::RESULT_VARIABLE;
use kr_e2e_agents::account::{KEY_SCAN_VARIABLE, Ledger};
use kr_e2e_agents::build::{self, Account, Build, InstallSwitch, Probe};
use kr_e2e_agents::held::{
    Absent, Audit, CONFIG_DIRECTORY, HeldKeys, ISOLATION_UNPROVEN, MetaGuard, RunScan, Stop,
    absent_below, absent_paths, audit_turns, conversations_relative, folder_of, grouped_output,
    kept_panic_text, other_agent_processes, other_agents_refusal, panic_text, person_home,
    read_record, turns_recorded, unchanged_before_the_charge,
};
use kr_e2e_agents::outcome::Outcome;
use kr_e2e_agents::session_environment::{self, Expected};
use kr_e2e_agents::stage::{
    Installation, PlacedProgram, closed_port, scan_rules, session_variables,
};
use kr_e2e_agents::stub::RequestStub;
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
    AgentApprovalRespondParams, AgentApprovalRespondResult, AgentBindingState,
    AgentCapabilitiesParams, AgentCapabilitiesResult, AgentMutationResult, AgentMutationTarget,
    AgentPromptParams, AgentSubject, PromptText,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::PendingState;
use kr_protocol::ids::{
    ApplicationInstanceId, PendingResourceId, PluginId, SessionEpoch, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::recovery::{AgentInstancesParams, AgentInstancesResult};
use kr_protocol::scalars::Nullable;
use kr_worker::broker::connectors::fixture;

/// The test support that builds signed catalogue generations.
#[allow(dead_code)]
#[path = "../../../../crates/kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// The variable naming the build list entry of a real agent; without it the agent is the stand-in.
const BUILD_VARIABLE: &str = "KR_AGENTS_GATEWAY_BUILD";

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

/// The directory of the released Codex package's copy.
fn released_codex() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/plugins/released/kalareach/codex/0.3.0")
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

/// A real agent: the entry, its turn ledger, the keys the run's files are searched for, the person's
/// home as the system's account database names it, and the person's own files as they stood before
/// anything started.
struct Real {
    build: Build,
    account: Account,
    ledger: Ledger,
    held: HeldKeys,
    home: PathBuf,
    person: MetaGuard,
    /// The agent's program as the run placed it, recorded once before the agent first starts.
    placed: std::sync::OnceLock<PlacedProgram>,
    /// The agent's configuration files as the harness wrote them, by their place below the run's
    /// directory, each recorded with its stamp and digest when it was written.
    configured: std::sync::Mutex<Vec<PathBuf>>,
}

impl Route {
    /// The route this run was given.
    ///
    /// # Panics
    ///
    /// Panics when the entry names no login, the run's `HOME` is not the person's home as the
    /// system's account database names it, the values of the keys cannot be read, or the person's
    /// files cannot be looked at: nothing has started, and no turn is spent.
    fn from_environment(case: &str) -> Self {
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
        let ledger = Ledger::from_environment(&account.budget, account.turns);
        // The guard over the person's directory compares the whole of it at the end, and cannot
        // tell a write of another agent process of theirs from the run's: none runs at the start.
        let others = other_agent_processes(&executable_name(&build.command), None)
            .unwrap_or_else(|why| panic!("{why}"));
        assert!(
            others.is_empty(),
            "{}",
            other_agents_refusal(&others, "before the run starts")
        );
        let held = HeldKeys::read(&format!("gateway case {case}"), &account);
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
        }))
    }
}

impl Real {
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
    fn variables(&self, host: &Host<'_>, shell: &shells::ManagedShell) -> Vec<(String, String)> {
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
        let files = self
            .account
            .configuration_with_switches("config.toml", &root, &work)
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        for (relative, content) in &files {
            let path = directory.join(relative);
            assert!(
                path.starts_with(&directory) && !relative.contains(".."),
                "a configuration file stays in its directory: {relative}"
            );
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
        variables
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
            self.proves(run, variables, probe).unwrap_or_else(|why| {
                panic!(
                    "{ISOLATION_UNPROVEN} `{} {}` did not answer as it must with the entry's \
                         switches in the run's configuration file alone: {why}",
                    self.build.command,
                    probe.arguments.join(" ")
                )
            });
        }
    }

    /// One probe of [`Real::proves_isolation`].
    fn proves(
        &self,
        run: &Run,
        variables: &[(String, String)],
        probe: &Probe,
    ) -> Result<(), String> {
        let stub = probe
            .arguments
            .iter()
            .any(|argument| argument.contains("{stub}"))
            .then(RequestStub::start)
            .transpose()?;
        // The program is started by the absolute path recorded when it was placed, once the route to
        // it is checked to be as it was: the agent's earlier start may have left another link.
        self.configuration_as_placed(run)?;
        let mut command = self.placed().command(run.root(), run.pin())?;
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
        match stub {
            // The stub refuses the request on purpose, so how the command ended says nothing: what
            // the request offered is the answer.
            Some(stub) => {
                let text = stub.finish()?.join("\n");
                probe.check(&text, &[], None)?;
                let lacking = probe
                    .lacks
                    .iter()
                    .find(|lack| lack.as_str() != "{servers}")
                    .cloned()
                    .unwrap_or_default();
                if !lacking.is_empty()
                    && probe
                        .check(&format!("{text}\nnested control/{lacking}"), &[], None)
                        .is_ok()
                {
                    return Err(format!(
                        "its check did not refuse a tool named for {lacking:?}, added on purpose"
                    ));
                }
                Ok(())
            }
            None => {
                if !output.status.success() {
                    return Err(format!("it ended with {}", output.status));
                }
                let text = String::from_utf8_lossy(&output.stdout).into_owned()
                    + &String::from_utf8_lossy(&output.stderr);
                probe.check(&text, &[], None)
            }
        }
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
        // The launcher the worker gives the shell is run by every typed launch.
        run.note_placed(&binary_place("kr-hook"))
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        let (executable, bin) = match &self.route {
            Route::StandIn => {
                let tools = run.root().join("t");
                kr_ipc::paths::create_private_tree(run.root(), &tools)
                    .expect("a directory for the programs");
                run.place_built("codex-stand-in", &tools.join("codex"), &["--version"]);
                // The shell finds the stand-in by its name on a search path, as it finds the build.
                run.note_placed(Path::new(STAND_IN_PLACE))
                    .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
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
                let installation = Installation::link(run, &real.build.prefix, &real.build.runtime);
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
                (pinned, installation.bin())
            }
        };
        self.executable = executable;
        self.bin = bin;
        self.work = Some(work);
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
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        let mut files = vec![binary_place("kr-hook")];
        if matches!(self.route, Route::StandIn) {
            files.push(PathBuf::from(STAND_IN_PLACE));
        }
        for file in files {
            self.run
                .placed_as_it_was(&file)
                .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
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
                command_integrations: vec![codex().to_string()],
                stable_address: true,
            },
            |environment| {
                let (distribution, version) = self.qualified_as();
                self.runtime.block_on(install_codex(
                    environment,
                    &self.executable,
                    distribution,
                    &version,
                ));
            },
        )
    }

    /// The environment every `kr` the case runs is given.
    fn variables(&self, host: &Host<'_>) -> Vec<(String, String)> {
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
            Route::Real(real) => real.variables(host, &self.shell),
        }
    }

    /// The variables the stand-in is given on the stand-in route, in the list every session is
    /// created with: its variants, the file that releases it, the file its server notes what it
    /// received in, the program its server starts, and `more` (a case's own). A real agent takes
    /// none.
    fn stand_in_variables(&self, variants: &str, more: &[(&str, String)]) -> Vec<(String, String)> {
        if !matches!(self.route, Route::StandIn) {
            return Vec::new();
        }
        let mut variables = vec![
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
        ];
        variables.extend(
            more.iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        );
        variables
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
            .runtime
            .block_on(remote.read(
                Method::AgentInstances,
                &AgentInstancesParams {
                    session_id,
                    agent_resources_from: Nullable::null(),
                },
            ))
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
            let read = self.instances(remote, session_id);
            if holds(&read) {
                return Ok(read);
            }
            if started.elapsed() >= LIVENESS {
                return Err(format!("{why}: the session holds {read:?}"));
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
    fn binding(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
    ) -> AgentBindingState {
        let read: AgentCapabilitiesResult = self
            .runtime
            .block_on(remote.read(
                Method::AgentCapabilities,
                &AgentCapabilitiesParams {
                    subject: subject(session_id, instance),
                },
            ))
            .unwrap_or_else(|why| panic!("agent.capabilities: {why}"));
        read.binding
    }

    /// Reads the binding until `holds` is true of it, within the liveness bound.
    fn binding_until(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> AgentBindingState {
        let started = Instant::now();
        loop {
            let read = self.binding(remote, session_id, instance);
            if holds(&read) {
                return read;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the binding is {read:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
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
    executable: &Path,
    distribution: &str,
    version: &str,
) {
    let digest = PayloadDigest::of(&std::fs::read(executable).expect("the placed agent"));
    let build = QualifiedBuild {
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
        executable_digest: digest,
    };
    let home = environment.state_dir().join("generation-source");
    std::fs::create_dir_all(&home).expect("a directory for the generation");
    let generation = generations::Generation::build(
        &home,
        generations::GenerationSpec {
            package: Some(released_codex()),
            builds: vec![build],
            ..generations::GenerationSpec::default()
        },
    )
    .await;
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
                generations::directory_url(&generation.metadata_dir()),
                generations::directory_url(&generation.targets_dir()),
                generation.root_bytes(),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.3.0").expect("a version");
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
            InstallationGrant::with(vec![
                PluginCapability::CommandIntegrationLaunch,
                PluginCapability::ApprovalDecode,
                PluginCapability::ApprovalRespond,
                PluginCapability::UpstreamAction,
            ]),
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment.environment_id(), &codex(), true)
        .await
        .expect("enabled");
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
    fn enters(ctx: &Context, host: &Host<'_>, given: &[(String, String)]) -> Self {
        let home = ctx.run.home();
        let mut variables = ctx.variables(host);
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
        assert_eq!(sessions.len(), 1, "one live session: {sessions:?}");
        let session_id: SessionId = sessions[0]["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("a session identifier");
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
        let mut said = None;
        loop {
            let rows =
                self.types_the_check(expected, &Expected::exported_line(exported.len(), tag), tag)?;
            let (names, total) = session_environment::read_exported(tag, &exported, said, &rows)?;
            tag += 1;
            said = Some(total);
            exported.extend(names);
            if exported.len() == total {
                break;
            }
        }
        self.clears_the_screen_of(session_environment::ROW);
        expected.judge(&readings, &exported)?;
        Ok(expected.passed_line(exported.len()))
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

/// A named pipe in the run's own directory: a command that writes to it waits there until the case
/// reads, so the case holds a turn open for as long as it needs, and reads what the command wrote.
struct Fifo(PathBuf);

impl Fifo {
    /// Makes the pipe at `path`.
    fn made_at(path: PathBuf) -> Self {
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo starts");
        assert!(made.success(), "mkfifo {} exited {made}", path.display());
        Self(path)
    }

    /// Opens the pipe for reading without waiting for a writer, which lets a command blocked on
    /// opening it for writing go on. The reader stays open, so that a second run of the command,
    /// which would block on opening the pipe, finds it open and writes: what it wrote is read too.
    fn reader(&self) -> FifoReader {
        let flags = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).expect("a flag");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(&self.0)
            .unwrap_or_else(|error| panic!("the case's pipe cannot be opened: {error}"));
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

/// The file that lets the stand-in's terminal go on.
fn release_of(ctx: &Context) -> PathBuf {
    ctx.run.root().join("release")
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

/// A host, a paired device and a person in a managed shell, with the agent not yet started.
struct Session<'a> {
    ctx: &'a Context,
    host: Host<'a>,
    remote: Remote,
    person: Person,
    _device: Device,
    _paired: PairedHost,
    /// Whether the shell's environment was read before the agent's first start.
    environment_read: std::cell::Cell<bool>,
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
        let person = Person::enters(ctx, &host, &ctx.stand_in_variables(variants, more));
        Self {
            ctx,
            host,
            remote,
            person,
            _device: device,
            _paired: paired,
            environment_read: std::cell::Cell::new(false),
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
        self.host.agent_starts();
        match &self.ctx.route {
            Route::StandIn => {
                let _ = self.person.types_until_it_shows(
                    "codex",
                    ASKED,
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
                }
                // The shell finds the agent by its name on a search path that starts in the run, which
                // an earlier start may have changed: the route is checked before each typing.
                let _ = self.person.types_until_it_shows(
                    &real.typed(extra),
                    &real.account.composer,
                    "the agent reaches its composer",
                    &|| {
                        self.ctx.checks_the_placed_files();
                        real.checks_the_route(&self.ctx.run);
                    },
                );
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
        self.gateway_serves(instance);
        if let Route::Real(real) = &self.ctx.route {
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

    /// Reads the binding until `holds` is true of it, and fails at once on any read, the last one
    /// not excepted, that finds rich work suspended.
    fn binding_unsuspended_until(
        &self,
        instance: ApplicationInstanceId,
        why: &str,
        holds: impl Fn(&AgentBindingState) -> bool,
    ) -> AgentBindingState {
        self.binding_until(instance, why, |binding| {
            assert!(
                unsuspended(binding),
                "{why}: rich work is suspended: {:?}",
                binding.suspension_reason.0
            );
            holds(binding)
        })
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
        let charged = real.ledger.charged_here();
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
                    let said = real
                        .ledger
                        .charge_found(
                            case,
                            "a turn in the agent's record that the case did not charge",
                            surplus,
                        )
                        .map_or_else(
                            |why| format!("the ledger could not be written: {why}"),
                            |total| format!("the ledger now says {total} spent"),
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
    match result {
        Ok(shows) if stops.is_empty() => {
            evidence["shows"] = shows;
            record(Outcome::passed(case, test, evidence));
        }
        Ok(shows) => {
            evidence["shows"] = shows;
            record(Outcome::failed(case, test, &stopped.join("; "), evidence));
            panic!(
                "the case showed what it was to, and then: {}",
                stopped.join("; ")
            );
        }
        Err(panic) => {
            let said = kept_panic_text(&panic_text(&*panic));
            let reason = if stopped.is_empty() {
                said
            } else {
                format!("{said}; {}", stopped.join("; "))
            };
            record(Outcome::failed(case, test, &reason, evidence));
            for line in &stopped {
                eprintln!("{line}");
            }
            std::panic::resume_unwind(panic);
        }
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
    let real_asked = std::env::var_os(BUILD_VARIABLE).is_some_and(|value| !value.is_empty());
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() || real_asked => {
            let why = format!("the {leg} leg's managed shell: {why}");
            records_failure(case, test, &why, &[]);
            panic!("{why}");
        }
        Err(why) => {
            eprintln!("skipping the {leg} leg: {why}");
            return;
        }
    };
    let route = match std::panic::catch_unwind(|| Route::from_environment(case)) {
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.place();
        let session = Session::open(&ctx, variants);
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
// Case 1: a device answers an approval, and the terminal closes its prompt.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that the server's word that a request was answered
/// (`serverRequest/resolved`) reaches the terminal through the gateway, which is the only
/// connection both writers use, and that the terminal closes its prompt on it: a paired device
/// answers the approval of a command the terminal holds, the host's resource resolves, the
/// terminal's prompt goes while the turn still runs, and the command runs once.
#[test]
fn gateway_a_device_answers_an_approval_and_the_terminal_closes_its_prompt() {
    const TEST: &str = "gateway_a_device_answers_an_approval_and_the_terminal_closes_its_prompt";
    run_case(
        "gateway-approval",
        "gateway-1",
        TEST,
        "answer-when-released,keep-reading,ping-when-released,stay",
        |ctx, session| {
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
                    let pipe = Fifo::made_at(ctx.run.work().join("f"));
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
                    let mut reader = pipe.reader();
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
                    std::fs::write(release_of(ctx), b"go").expect("the release");
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
                    serde_json::json!({ "turn_started_by_the_host": true })
                }
            }
        },
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
                    std::fs::write(release_of(ctx), b"go").expect("the release");
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
                    std::fs::write(release_of(ctx), b"go").expect("the release");
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
            "/bin/zsh",
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
fn an_agent_replaces_a_placed_file_and_is_started_again(replaced: &str) -> (String, bool) {
    an_agent_leaves_a_change_and_is_started_again(
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
/// `changed` then asserts that the program did its change; the host is asked to start the agent
/// again, as a line typed again is. Returns the text the second start ended in, and whether the
/// case's program ever ran. The first start is the control: it went through the same checks over
/// the run as it was placed.
fn an_agent_leaves_a_change_and_is_started_again(
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
    ctx.place();
    let leave = scratch.join("leave.sh");
    std::fs::write(&leave, script(&ctx, &program, &scratch))
        .expect("the program the stand-in runs");
    for file in [&program, &leave] {
        std::fs::set_permissions(file, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("executable");
    }
    let session = Session::open_with(
        &ctx,
        "answer-when-released,keep-reading,stay,leave-a-host",
        &[("STAND_IN_LEAVE", leave.display().to_string())],
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
    let (said, ran) = an_agent_replaces_a_placed_file_and_is_started_again("b/kr-hook");
    if said.is_empty() {
        return;
    }
    assert!(
        said.contains(ISOLATION_UNPROVEN) && said.contains("symbolic link"),
        "the next start was refused as a replaced file: {said}"
    );
    assert!(!ran, "the program the replaced launcher names ran");
}

/// The stand-in the shell finds by name, replaced by a link after the first start, is not run by the
/// next start either.
#[test]
fn gateway_a_stand_in_the_agent_replaced_is_not_run_by_the_next_start() {
    let (said, ran) = an_agent_replaces_a_placed_file_and_is_started_again("t/codex");
    if said.is_empty() {
        return;
    }
    assert!(
        said.contains(ISOLATION_UNPROVEN) && said.contains("symbolic link"),
        "the next start was refused as a replaced file: {said}"
    );
    assert!(!ran, "the program the replaced stand-in names ran");
}

/// A probe that has ended and moved the run's working directory out of the run, leaving an empty
/// directory at its place, leaves the session's shell in the moved directory: the next typing is
/// refused before a byte is typed, though every placed file is as it was placed and the new
/// directory holds nothing that an absence check looks for.
#[test]
fn gateway_a_work_directory_the_agent_moved_out_of_the_run_is_not_started_in_by_the_next_start() {
    let (said, _) = an_agent_leaves_a_change_and_is_started_again(
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

/// A stand-in agent that, once it has started, starts a child that leaves its process group, is
/// adopted by the system's first process, and names nothing of the run on its command line, in the
/// run's working directory, with the environment the agent has or with none. The host is then
/// stopped and the run's closing check made: the child that kept its environment, which carries the
/// run's marker, is found and fails the check, and ended by its number the check then passes; the
/// child that cleared its environment is the limit the check names, and passes.
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
    let closing = ctx.run.closing_check();
    if keeps_environment {
        let said = closing.expect_err("the child that kept its environment is found");
        assert!(
            said.contains(&format!("process {child} holds the run's marker")),
            "{said}"
        );
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
    while std::process::Command::new("/bin/kill")
        .args(["-0", &child.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
        && waited.elapsed() < LIVENESS
    {
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
fn a_run_whose_processes_are_not_shown_ended_is_not_read() {
    let stop = run_may_be_read(false).expect_err("a run whose processes are not shown ended");
    assert_eq!(stop.0, "run_not_read");
    assert!(stop.1.contains("not read"), "{}", stop.1);
    assert!(run_may_be_read(true).is_ok());
}

#[test]
fn the_launches_the_real_route_types_are_ones_the_command_integration_serves() {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(released_codex().join("plugin.json")).expect("the package's manifest"),
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
