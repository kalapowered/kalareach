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
//!   (`build::Account::configuration_with_switches`). Before a case sends any prompt, the host must
//!   announce the instance as served through a gateway. The model answers, so each prompt a case
//!   sends is charged to the turn ledger (`KR_AGENTS_TURNS`) before it is typed or sent; the
//!   login's value arrives on the descriptor `KR_AGENTS_KEY_FD` names and the values of the other
//!   keys the harness's shell holds on the one `KR_AGENTS_SCAN_FD` names, exactly as for the
//!   qualification cases, and one case runs in each process: the pipes empty when they are read.
//!
//! On a real route every case, whatever became of it, ends the same way (`held`): what the run
//! started is ended, the run's directory is searched for the keys and removed, and the search and
//! the removal are recorded (`KR_AGENTS_KEY_SCAN` names the file); the person's own Codex files are
//! looked at again by their metadata alone and none may have changed; the agent's own record is
//! counted for the turns it ran, and one the ledger was not charged for is charged and stops the
//! case; and no panic message prints a piece of a held key.
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
use kr_e2e_agents::account::Ledger;
use kr_e2e_agents::build::{self, Account, Build, InstallSwitch};
use kr_e2e_agents::held::{
    Absent, CONFIG_DIRECTORY, HeldKeys, ISOLATION_UNPROVEN, MetaGuard, PROXY_VARIABLES, RunScan,
    Stop, absent_paths, conversations_root, kept_panic_text, panic_text, turns_recorded,
};
use kr_e2e_agents::outcome::Outcome;
use kr_e2e_agents::stage::{Installation, closed_port, session_variables};
use kr_e2e_m1b::device::{Device, PairedHost, Remote, RequestError};
use kr_e2e_m1b::host::{Host, HostOptions, Preparation};
use kr_e2e_m1b::run::Run;
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

/// The person's own Codex files whose metadata a real run is held to leave as it found it: the
/// login, the settings, the instructions and hooks the agent would load, and the files it appends
/// to when it is used. Nothing of them is read.
const PERSON_FILES: [&str; 8] = [
    ".codex/auth.json",
    ".codex/config.toml",
    ".codex/AGENTS.md",
    ".codex/hooks.json",
    ".codex/.credentials.json",
    ".codex/history.jsonl",
    ".codex/session_index.jsonl",
    ".codex/log/codex-tui.log",
];

/// The person's own Codex directory, recorded and not held: the person's own programs add and
/// remove entries in it.
const PERSON_DIRECTORIES: [&str; 1] = [".codex"];

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
/// types or its screen shows, and not in the question.
fn fresh_question(avoid: &[&str]) -> (String, String) {
    loop {
        let bytes = *kr_ipc::new_uuid().as_bytes();
        let first = 500 + u64::from(bytes[0]) + u64::from(bytes[1]);
        let second = 500 + u64::from(bytes[2]) + u64::from(bytes[3]);
        let sum = (first + second).to_string();
        let question = format!("What is {first} plus {second}? Reply with only the number.");
        if !question.contains(&sum) && avoid.iter().all(|text| !text.contains(&sum)) {
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

/// The agent a run is given.
enum Route {
    /// The application stand-in, placed as `codex`: offline, no turn.
    StandIn,
    /// The pinned native build of a build list entry, with its login.
    Real(Box<Real>),
}

/// A real agent: the entry, its turn ledger, the keys the run's files are searched for, and the
/// person's own files as they stood before anything started.
struct Real {
    build: Build,
    account: Account,
    ledger: Ledger,
    held: HeldKeys,
    person: MetaGuard,
}

impl Route {
    /// The route this run was given.
    ///
    /// # Panics
    ///
    /// Panics when the entry names no login, its values cannot be read, or the person's files
    /// cannot be looked at.
    fn from_environment(case: &str) -> Self {
        let Some(path) = std::env::var_os(BUILD_VARIABLE)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
        else {
            return Self::StandIn;
        };
        let build = build::read_build(&path);
        let account = build.account.clone().unwrap_or_else(|| {
            panic!("{BUILD_VARIABLE} names an entry with no login, which no case may start")
        });
        let held = HeldKeys::read(&format!("gateway case {case}"), &account);
        let ledger = Ledger::from_environment(&account.budget, account.turns);
        let home = PathBuf::from(std::env::var_os("HOME").expect("the person's home in HOME"));
        let person = MetaGuard::take(&home, &PERSON_FILES, &PERSON_DIRECTORIES);
        Self::Real(Box::new(Real {
            build,
            account,
            ledger,
            held,
            person,
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

    /// The environment a session of the run is created with: the harness's own for a session, with
    /// no proxy variable, since the agent reaches its provider on loopback, the entry's variables,
    /// its configuration directory with the entry's arguments and switches written as the keys of
    /// its `config.toml`, and its login, and none of the variables the entry clears but the ones it
    /// sets itself.
    fn variables(&self, host: &Host<'_>, shell: &shells::ManagedShell) -> Vec<(String, String)> {
        let mut variables = session_variables(host, shell, &self.build.environment, closed_port());
        variables.retain(|(name, _)| !PROXY_VARIABLES.contains(&name.as_str()));
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

    /// Fails the case when a file the entry says would load the person's own settings, hooks or
    /// servers into the agent exists before it starts: every path of the entry's list, with every
    /// template filled in.
    fn checks_absent(&self, run: &Run) {
        let person = PathBuf::from(std::env::var_os("HOME").expect("the person's home in HOME"));
        for path in absent_paths(&self.account, run, &run.home(), &person, Absent::All) {
            assert!(
                !path.exists(),
                "{ISOLATION_UNPROVEN} {} exists, which would load the person's own settings, hooks \
                 or servers into the agent, or which it would remove",
                path.display()
            );
        }
    }

    /// Charges one turn to the entry's budget before a prompt the model answers is sent.
    fn charge(&self, case: &str, what: &str) {
        let _ = self
            .ledger
            .charge(case, what)
            .unwrap_or_else(|why| panic!("{why}"));
    }

    /// The text of every file under the agent's conversation directory.
    ///
    /// # Errors
    ///
    /// Returns the entry of the record that could not be read: a record that is not whole shows
    /// nothing.
    fn conversations(&self, run: &Run) -> Result<String, String> {
        let mut text = String::new();
        let mut pending = vec![conversations_root(&self.account, &Self::config(run))];
        while let Some(path) = pending.pop() {
            let metadata = match std::fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("{}: {error}", path.display())),
            };
            if metadata.is_dir() {
                let entries = std::fs::read_dir(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                for entry in entries {
                    pending.push(
                        entry
                            .map_err(|error| format!("{}: {error}", path.display()))?
                            .path(),
                    );
                }
            } else {
                let bytes =
                    std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        Ok(text)
    }
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
}

impl Context {
    /// Makes the run and places the agent, or says why the case cannot run here.
    fn start(leg: &str, case: &str) -> Option<Self> {
        let shell = match shells::managed_zsh() {
            Ok(shell) => shell,
            Err(why) if shells::required() => panic!("the {leg} leg's managed shell: {why}"),
            Err(why) => {
                eprintln!("skipping the {leg} leg: {why}");
                return None;
            }
        };
        let route = Route::from_environment(case);
        let run = Run::start(leg);
        run.place_built("kr-hook", &run.binary("kr-hook"), &["--version"]);
        let (executable, bin) = match &route {
            Route::StandIn => {
                let tools = run.root().join("t");
                kr_ipc::paths::create_private_tree(run.root(), &tools)
                    .expect("a directory for the programs");
                run.place_built("codex-stand-in", &tools.join("codex"), &["--version"]);
                (tools.join("codex"), tools)
            }
            Route::Real(real) => {
                real.checks_installs_off(&run);
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
                let installation =
                    Installation::link(&run, &real.build.prefix, &real.build.runtime);
                (pinned, installation.bin())
            }
        };
        Some(Self {
            runtime: runtime(),
            run,
            shell,
            route,
            executable,
            bin,
        })
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

    /// Reads what a session holds of its agents.
    fn instances(&self, remote: &Remote, session_id: SessionId) -> AgentInstancesResult {
        self.runtime
            .block_on(remote.read(
                Method::AgentInstances,
                &AgentInstancesParams {
                    session_id,
                    agent_resources_from: Nullable::null(),
                },
            ))
            .unwrap_or_else(|why| panic!("agent.instances: {why}"))
    }

    /// Reads the instances until `holds` is true of them, within the liveness bound.
    fn instances_until(
        &self,
        remote: &Remote,
        session_id: SessionId,
        why: &str,
        holds: impl Fn(&AgentInstancesResult) -> bool,
    ) -> AgentInstancesResult {
        let started = Instant::now();
        loop {
            let read = self.instances(remote, session_id);
            if holds(&read) {
                return read;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "{why}: the session holds {read:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
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
}

impl Person {
    /// Enters a managed shell with `kr new` on a terminal of its own, and waits for its prompt.
    fn enters(ctx: &Context, host: &Host<'_>) -> Self {
        let home = ctx.run.home();
        let variables = ctx.variables(host);
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
        Self { window, session_id }
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

    /// Types `line`, which runs through the integration, and waits until the screen shows
    /// `needle`. A line the shell ran as typed before the worker answered (its bound for the answer
    /// is one second) is typed again on a cleared screen; a launcher that refused the launch fails
    /// the case at once.
    fn types_until_it_shows(&self, line: &str, needle: &str, why: &str) -> Vec<String> {
        let started = Instant::now();
        let mut typed = 0_usize;
        loop {
            self.clears_the_screen();
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

    /// A question whose answer is on the screen now and in none of `avoid`, so that the answer's
    /// appearing is the agent's.
    fn asks(&self, avoid: &[&str]) -> (String, String) {
        loop {
            let (question, sum) = fresh_question(avoid);
            if !self.window.screen().iter().any(|row| row.contains(&sum)) {
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

    /// Exports the stand-in's variables for the next command: its variants, the file that releases
    /// it, and the file the server notes what it received in.
    fn exports(&self, ctx: &Context, variants: &str) {
        self.types(&format!("export KR_STAND_IN={variants}"));
        self.types(&format!(
            "export KR_STAND_IN_RELEASE={}",
            release_of(ctx).display()
        ));
        self.types(&format!(
            "export KR_STAND_IN_RECEIVED={}",
            received_by(ctx).display()
        ));
        self.types(&format!(
            "export KR_STAND_IN_COMMAND='{}'",
            command(&ctx.bin)
        ));
    }
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
    /// opening it for writing go on, and reads until a line arrives or `within` has passed.
    fn line(&self, within: Duration) -> Option<String> {
        let flags = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).expect("a flag");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(&self.0)
            .ok()?;
        let started = Instant::now();
        let mut text = Vec::new();
        loop {
            let mut buffer = [0_u8; 256];
            match file.read(&mut buffer) {
                Ok(count) if count > 0 => {
                    text.extend_from_slice(&buffer[..count]);
                    if text.contains(&b'\n') {
                        return Some(String::from_utf8_lossy(&text).trim().to_owned());
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return None,
            }
            if started.elapsed() >= within {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
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
}

impl<'a> Session<'a> {
    /// Opens the session; `variants` are the stand-in's, and a real agent takes none.
    fn open(ctx: &'a Context, variants: &str) -> Self {
        let host = ctx.host();
        let (device, paired, remote) = ctx.pair(&host);
        let person = Person::enters(ctx, &host);
        if matches!(ctx.route, Route::StandIn) {
            person.exports(ctx, variants);
        }
        Self {
            ctx,
            host,
            remote,
            person,
            _device: device,
            _paired: paired,
        }
    }

    fn session_id(&self) -> SessionId {
        self.person.session_id
    }

    /// Types the agent's command, alone or with `extra` words after it (`resume` and a thread),
    /// waits until the terminal is up, and returns the live instance the host announces for it,
    /// other than `not`, once the host says that a gateway serves it: a launch that ran as typed,
    /// with no gateway, is found here, before any prompt is sent or charged.
    fn starts_the_agent(
        &self,
        extra: &[&str],
        not: Option<ApplicationInstanceId>,
    ) -> ApplicationInstanceId {
        match &self.ctx.route {
            Route::StandIn => {
                let _ = self.person.types_until_it_shows(
                    "codex",
                    ASKED,
                    "the terminal reaches the server through the gateway",
                );
            }
            Route::Real(real) => {
                // The files that would load the person's own settings are known absent before the
                // agent's first start, as they are before any part's.
                if not.is_none() {
                    real.checks_absent(&self.ctx.run);
                }
                let _ = self.person.types_until_it_shows(
                    &real.typed(extra),
                    &real.account.composer,
                    "the agent reaches its composer",
                );
            }
        }
        let instance = self
            .ctx
            .instances_until(&self.remote, self.session_id(), "the instance", |read| {
                read.agent_instances
                    .instances
                    .iter()
                    .any(|instance| Some(instance.application_instance_id) != not)
            })
            .agent_instances
            .instances
            .iter()
            .map(|instance| instance.application_instance_id)
            .find(|id| Some(*id) != not)
            .expect("an instance");
        self.gateway_serves(instance);
        instance
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
/// of a case, a panic included, is followed by.
///
/// What the run started is ended, the person's own files are looked at again by their metadata,
/// the agent's record is counted for turns the ledger was not charged for, the run's directory is
/// searched for the keys and removed, and the outcome is appended. A case that failed is recorded
/// as failed and its failure goes on, as it came.
fn ends(ctx: Context, case: &str, test: &str, result: std::thread::Result<serde_json::Value>) {
    let Context {
        run,
        route,
        runtime,
        ..
    } = ctx;
    drop(runtime);
    let root = run.root().to_path_buf();
    // Nothing the run started may still write when its directory is searched: after a case that
    // stopped part way, everything is ended first and the run's check made.
    let writers_ended = if result.is_ok() {
        true
    } else {
        run.end_everything();
        run.remove_loaded_jobs();
        run.nothing_running().is_ok()
    };
    let mut stops: Vec<Stop> = Vec::new();
    let mut evidence = serde_json::json!({
        "route": if matches!(route, Route::StandIn) { "the application stand-in" } else { "the pinned build" },
    });
    let mut scan = None;
    let mut secrets: Vec<String> = Vec::new();
    evidence["turns"] = serde_json::json!({ "charged": 0 });
    if let Route::Real(real) = &route {
        let (guard_stops, guard_evidence) = real.person.compare();
        stops.extend(guard_stops);
        evidence["person_files"] = guard_evidence;
        let charged = real.ledger.charged_here();
        let recorded = turns_recorded(
            &real.account,
            &conversations_root(&real.account, &run.root().join(CONFIG_DIRECTORY)),
        );
        match &recorded {
            Ok(found) if *found > charged => {
                let surplus = found - charged;
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
                stops.push((
                    "uncharged_turns",
                    format!(
                        "the agent's record holds {found} turn(s) against {charged} charged; \
                         {surplus} charged now ({said})"
                    ),
                ));
            }
            Ok(_) => {}
            Err(why) => stops.push((
                "uncharged_turns",
                format!("the turns in the agent's record could not be counted: {why}"),
            )),
        }
        evidence["turns"] = serde_json::json!({
            "charged": charged,
            "in_the_agents_record": recorded.as_ref().ok(),
        });
        scan = Some(RunScan::of(&root, &real.held));
        secrets = real.held.values();
    }
    // The run is dropped before its directory goes, so its own end does not say it keeps one.
    drop(run);
    if let Some(scan) = scan {
        let (scan_stops, scan_evidence) = scan.finish(&root, case, writers_ended);
        stops.extend(scan_stops);
        evidence["keys"] = scan_evidence;
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

/// Runs one case: a host, a paired device and a person in a managed shell, `body` on them, the
/// host's close, and whatever follows every outcome of a case ([`ends`]).
fn run_case(
    leg: &str,
    case: &str,
    test: &str,
    variants: &str,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    let Some(ctx) = Context::start(leg, case) else {
        return;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = Session::open(&ctx, variants);
        let shows = body(&ctx, &session);
        ctx.close(&session.host);
        shows
    }));
    ends(ctx, case, test, result);
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
            let instance = session.starts_the_agent(&[], None);
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
                    real.charge("gateway-1", "an approval-gated command");
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
                    let written = pipe.line(LIVENESS);
                    assert_eq!(
                        written.as_deref(),
                        Some(mark.as_str()),
                        "the command ran once and wrote its marker"
                    );
                    let _ = session.binding_until(instance, "the turn ends", |binding| {
                        binding.turn_id.0.is_none() && unsuspended(binding)
                    });
                    serde_json::json!({ "command_ran": 1, "turn_open_after_the_prompt_closed": true })
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
            let instance = session.starts_the_agent(&[], None);
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
                        .expect("the device's prompt is carried");
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
                    real.charge("gateway-2", "a prompt from a device");
                    let started = ctx
                        .prompts(
                            &session.remote,
                            session.session_id(),
                            instance,
                            &idle,
                            &format!("({marked}) {question}"),
                        )
                        .expect("the device's prompt is carried");
                    assert!(started.turn_id.0.is_some(), "the host started a turn");
                    let _ = session
                        .person
                        .sees(&sum, "the terminal shows the turn the host started");
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
            let instance = session.starts_the_agent(&[], None);
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
                    real.charge("gateway-3", "a turn in the first thread");
                    session
                        .person
                        .composes(&format!("({marked}) {question}"), &marked);
                    let _ = session.person.sees(&sum, "the agent answers");
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
                    session
                        .person
                        .composes(&account.slash.input, &account.slash.input);
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
                    session.person.composes("/fork", "/fork");
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
                    session.person.composes("/new", "/new");
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
                    session.person.composes("/quit", "/quit");
                    let _ = ctx.instances_until(
                        &session.remote,
                        session.session_id(),
                        "the first launch has ended",
                        |read| read.agent_instances.instances.is_empty(),
                    );
                    let resumed =
                        session.starts_the_agent(&["resume", &first_thread], Some(instance));
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
            let instance = session.starts_the_agent(&[], None);
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
                    real.charge("gateway-4", "a turn");
                    session
                        .person
                        .composes(&format!("({marked}) {question}"), &marked);
                    let _ = session.person.sees(&sum, "the agent answers");
                    let _ =
                        session.binding_unsuspended_until(instance, "the turn ends", |binding| {
                            binding.thread_id.0.is_some() && binding.turn_id.0.is_none()
                        });
                    session.person.waits_for_the_composer(
                        &account.composer,
                        &account.busy,
                        "the composer waits before the command",
                    );
                    session
                        .person
                        .composes(&account.slash.input, &account.slash.input);
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
            let instance = session.starts_the_agent(&[], None);
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
                    real.charge("gateway-5", "a turn that waits on an approval");
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
                    real.charge("gateway-5", "a device prompt over a running turn");
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
// The launch the real route types.
// ---------------------------------------------------------------------------------------------

/// The package's integration serves the launches the real route types, and no launch that types an
/// option: a launch that is not served runs as typed, with no gateway.
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
