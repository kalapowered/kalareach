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
//!   pinned native executable, typed with the entry's switches in a home of the run's own, with the
//!   entry's configuration directory and its login variable. The model answers, so each prompt a
//!   case sends is charged to the turn ledger (`KR_AGENTS_TURNS`) before it is typed or sent; the
//!   login's value arrives on the descriptor `KR_AGENTS_KEY_FD` names and the values of the other
//!   keys the harness's shell holds on the one `KR_AGENTS_SCAN_FD` names, exactly as for the
//!   qualification cases, and the run's directory is searched for all of them when the case ends
//!   (`KR_AGENTS_KEY_SCAN` names the file the search is recorded in). One case runs in each process:
//!   the pipes empty when they are read.
//!
//! Each case shows one assumption of the package's table that a stand-in cannot show of the pinned
//! release, and where the real agent's answer differs from the table's reading a case fails and
//! says what it saw:
//!
//! 1. The server's word that a request was answered reaches the terminal through the gateway, and
//!    the terminal closes its prompt on it, when a device answers an approval the terminal holds.
//! 2. The terminal shows a turn the host started for a device's prompt.
//! 3. The binding's thread changes where the terminal starts, resumes or forks one and nowhere else.
//! 4. A whole session names no method the package's table does not list: the binding is never
//!    suspended.
//! 5. A device's prompt over a running turn is refused, and nothing reaches the server.
//!
//! With a real agent a case spends one turn, and none that is not charged: the whole set is five.
//! Each case appends its outcome to the file `KR_AGENTS_RESULT` names, where one is named.
//!
//! ```text
//! KR_AGENTS_GATEWAY_BUILD=<entry> KR_AGENTS_TURNS=<ledger> KR_AGENTS_RESULT=<file> \
//!     KR_AGENTS_KEY_FD=3 KR_AGENTS_SCAN_FD=4 KR_AGENTS_KEY_SCAN=<file> KR_SHELL_PACKAGES=<prefix> \
//!     cargo test -p kr-e2e-agents --test gateway -- <case> --exact --nocapture
//! ```
//!
//! Not claimed: Windows, where no gateway runs.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_e2e_agents::RESULT_VARIABLE;
use kr_e2e_agents::account::{self, Ledger};
use kr_e2e_agents::build::{self, Account, Build};
use kr_e2e_agents::keys;
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

/// A question whose answer, a number of at least 1000, is not in the question.
fn sum_question() -> (String, String) {
    loop {
        let bytes = *kr_ipc::new_uuid().as_bytes();
        let first = 500 + u64::from(bytes[0]) + u64::from(bytes[1]);
        let second = 500 + u64::from(bytes[2]) + u64::from(bytes[3]);
        let sum = (first + second).to_string();
        let question = format!("What is {first} plus {second}? Reply with only the number.");
        if !question.contains(&sum) {
            return (question, sum);
        }
    }
}

/// The agent a run is given.
enum Route {
    /// The application stand-in, placed as `codex`: offline, no turn.
    StandIn,
    /// The pinned native build of a build list entry, with its login.
    Real(Box<Real>),
}

/// A real agent: the entry, its turn ledger and the keys the run's files are searched for.
struct Real {
    build: Build,
    account: Account,
    ledger: Ledger,
    /// The login's variable and value, where the entry's login is a variable.
    key: Option<(String, String)>,
    /// The values of the other keys the harness's shell holds.
    others: Vec<String>,
}

impl Route {
    /// The route this run was given.
    ///
    /// # Panics
    ///
    /// Panics when the entry names no login, or its values cannot be read.
    fn from_environment() -> Self {
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
        let key = account.variable.as_ref().map(|name| {
            let value = account::key_from_descriptor().unwrap_or_else(|why| {
                panic!("the case carries {name}, and the harness gave no value for it: {why}")
            });
            (name.clone(), value)
        });
        let others: Vec<String> = keys::scan_values_from_descriptor()
            .unwrap_or_else(|why| panic!("the harness gave no values of the keys it holds: {why}"))
            .into_iter()
            .filter(|value| key.as_ref().is_none_or(|(_, own)| own != value))
            .collect();
        let ledger = Ledger::from_environment(&account.budget, account.turns);
        Self::Real(Box::new(Real {
            build,
            account,
            ledger,
            key,
            others,
        }))
    }
}

impl Real {
    /// The run's directory for the agent's configuration and conversations.
    fn config(run: &Run) -> PathBuf {
        run.root().join("agent-config")
    }

    /// The line typed at the shell to start the agent: the command, the entry's arguments and
    /// switches, and `extra` after them.
    fn typed(&self, run: &Run, extra: &[&str]) -> String {
        let work = std::fs::canonicalize(run.work())
            .unwrap_or_else(|error| {
                panic!("the working directory as the system resolves it: {error}")
            })
            .display()
            .to_string();
        let root = run.root().display().to_string();
        let mut words: Vec<String> = self.account.arguments.clone();
        words.extend(
            self.account
                .switches
                .iter()
                .map(|switch| switch.replace("{run}", &root).replace("{work}", &work)),
        );
        words.extend(extra.iter().map(|word| (*word).to_owned()));
        let mut line = self.build.command.clone();
        for word in words {
            line.push(' ');
            line.push_str(&build::quote(&word));
        }
        line
    }

    /// The environment a session of the run is created with: the harness's own for a session, the
    /// entry's variables, its configuration directory and its login, and none of the variables the
    /// entry clears but the ones it sets itself.
    fn variables(&self, host: &Host<'_>, shell: &shells::ManagedShell) -> Vec<(String, String)> {
        let mut variables = session_variables(host, shell, &self.build.environment, closed_port());
        for name in ["USER", "LOGNAME"] {
            if let Ok(value) = std::env::var(name) {
                variables.push((name.to_owned(), value));
            }
        }
        if let Some((name, value)) = &self.key {
            variables.push((name.clone(), value.clone()));
        }
        for (name, value) in &self.account.variables {
            variables.retain(|(existing, _)| existing != name);
            variables.push((name.clone(), value.clone()));
        }
        if let Some(config) = &self.account.config_directory {
            let directory = Self::config(host.run());
            if !directory.is_dir() {
                kr_ipc::paths::create_private_tree(host.run().root(), &directory)
                    .expect("the run's configuration directory");
            }
            for (relative, content) in &config.files {
                let path = directory.join(relative);
                assert!(
                    path.starts_with(&directory) && !relative.contains(".."),
                    "a configuration file stays in its directory: {relative}"
                );
                std::fs::write(&path, content).expect("writes the configuration file");
            }
            variables.retain(|(existing, _)| existing != &config.variable);
            variables.push((config.variable.clone(), directory.display().to_string()));
        }
        let _ = self.build.without_provider_keys(&mut variables);
        variables
    }

    /// Fails the case when a file the entry says would load the person's own settings, hooks or
    /// servers into the agent exists before it starts.
    fn checks_absent(&self, run: &Run) {
        let config = Self::config(run).display().to_string();
        let work = run.work().display().to_string();
        let home = run.home().display().to_string();
        let user = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
            .filter(|name| !name.is_empty())
            .expect("the account name the system has");
        for path in &self.account.absent {
            if path.contains("{ancestors}") || path.contains("{person}") {
                continue;
            }
            let path = PathBuf::from(
                path.replace("{config}", &config)
                    .replace("{work}", &work)
                    .replace("{home}", &home)
                    .replace("{user}", &user),
            );
            assert!(
                !path.exists(),
                "{} exists, which would load the person's own settings, hooks or servers into the \
                 agent, or which it would remove",
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

    /// Searches the run's directory for the login's value and for the other keys' values, and
    /// records where they were found, never what they were.
    ///
    /// # Panics
    ///
    /// Panics when the search was incomplete or found one.
    fn searched(&self, run: &Run, case: &str) {
        let mut values: Vec<&[u8]> = self.others.iter().map(String::as_bytes).collect();
        if let Some((_, value)) = &self.key {
            values.push(value.as_bytes());
        }
        if values.is_empty() {
            return;
        }
        let scan = account::files_holding_any(run.root(), &values);
        let variable = self.key.as_ref().map_or("", |(name, _)| name.as_str());
        account::record_key_scan(case, variable, &scan, 0, false);
        assert!(
            scan.complete() && scan.held_by.is_empty(),
            "the run's directory holds a key's value or could not be searched whole: {} file(s) \
             hold one, {} entries were not read",
            scan.held_by.len(),
            scan.unread.len()
        );
    }

    /// The text of every file under the agent's conversation directory.
    fn conversations(run: &Run) -> String {
        let mut text = String::new();
        let mut pending = vec![Self::config(run).join("sessions")];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&path) {
                    pending.extend(entries.flatten().map(|entry| entry.path()));
                }
            } else if let Ok(bytes) = std::fs::read(&path) {
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        text
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
    fn start(leg: &str) -> Option<Self> {
        let shell = match shells::managed_zsh() {
            Ok(shell) => shell,
            Err(why) if shells::required() => panic!("the {leg} leg's managed shell: {why}"),
            Err(why) => {
                eprintln!("skipping the {leg} leg: {why}");
                return None;
            }
        };
        let route = Route::from_environment();
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
        let mut install = host.command(&["shell", "install", "--json"]);
        install.env_clear().envs(variables.iter().cloned());
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
    /// mark, and submits it after a moment, so that the line end arrives on its own.
    fn composes(&self, text: &str, mark: &str) {
        self.window.type_text(text.as_bytes());
        let _ = self
            .window
            .wait_for_screen(mark, "the typed prompt is on the screen");
        std::thread::sleep(Duration::from_millis(300));
        self.window.type_text(b"\r");
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

    /// Types the agent's command with `extra` words after its switches, waits until the terminal
    /// is up behind the gateway, and returns the live instance the host announces for it, other
    /// than `not`.
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
                real.checks_absent(&self.ctx.run);
                let line = real.typed(&self.ctx.run, extra);
                let _ = self.person.types_until_it_shows(
                    &line,
                    &real.account.composer,
                    "the agent reaches its composer through the gateway",
                );
            }
        }
        self.ctx
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
            .expect("an instance")
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

    /// Ends the case: closes the host, searches the run's directory for the keys of a real agent,
    /// and records the outcome.
    fn ends(self, case: &str, test: &str, evidence: serde_json::Value) {
        let Self { ctx, host, .. } = self;
        ctx.close(&host);
        let turns = match &ctx.route {
            Route::StandIn => 0,
            Route::Real(real) => {
                real.searched(&ctx.run, case);
                real.ledger.charged_here()
            }
        };
        let evidence = serde_json::json!({
            "route": if matches!(ctx.route, Route::StandIn) { "the application stand-in" } else { "the pinned build" },
            "turns": turns,
            "shows": evidence,
        });
        if let Some(path) = std::env::var_os(RESULT_VARIABLE).filter(|value| !value.is_empty()) {
            Outcome::passed(case, test, evidence).append(Path::new(&path));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Case 1: a device answers an approval, and the terminal closes its prompt.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that the server's word that a request was answered
/// (`serverRequest/resolved`) reaches the terminal through the gateway, which is the only
/// connection both writers use, and that the terminal closes its prompt on it: a paired device
/// answers the approval of a command the terminal holds, the host's resource resolves, the
/// terminal's prompt goes, and the command runs once.
#[test]
fn gateway_a_device_answers_an_approval_and_the_terminal_closes_its_prompt() {
    const TEST: &str = "gateway_a_device_answers_an_approval_and_the_terminal_closes_its_prompt";
    let Some(ctx) = Context::start("gateway-approval") else {
        return;
    };
    let session = Session::open(
        &ctx,
        "answer-when-released,keep-reading,ping-when-released,stay",
    );
    let instance = session.starts_the_agent(&[], None);
    let shows = match &ctx.route {
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
            let answers = received_lines(&ctx)
                .iter()
                .filter(|line| line.starts_with("response "))
                .count();
            assert_eq!(answers, 1, "the server received one answer");
            serde_json::json!({ "answers_the_server_received": answers })
        }
        Route::Real(real) => {
            let mark = mark();
            let log = ctx.run.work().join("approved");
            let command = format!("echo {mark} >> {}", log.display());
            real.charge("gateway-1", "an approval-gated command");
            session.person.composes(
                &format!(
                    "({mark}) Use your shell tool to run exactly this command and nothing else: \
                     {command}"
                ),
                &mark,
            );
            let _ = session.person.sees(
                &real.account.approval.shows,
                "the agent asks for approval of the command",
            );
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
            let _ = session.binding_until(instance, "the turn ends", |binding| {
                binding.turn_id.0.is_none() && unsuspended(binding)
            });
            let ran = std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .filter(|line| line.trim() == mark)
                .count();
            assert_eq!(ran, 1, "the command ran once");
            serde_json::json!({ "command_ran": ran })
        }
    };
    session.ends("gateway-1", TEST, shows);
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
    let Some(ctx) = Context::start("gateway-host-turn") else {
        return;
    };
    let session = Session::open(&ctx, "answer-when-released,keep-reading,stay");
    let instance = session.starts_the_agent(&[], None);
    let shows = match &ctx.route {
        Route::StandIn => {
            let _ = session.binding_until(instance, "the stream names the turn", |binding| {
                names(binding, "thread-1", Some("turn-1"))
            });
            std::fs::write(release_of(&ctx), b"go").expect("the release");
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
            let (question, sum) = sum_question();
            real.charge("gateway-2", "a prompt from a device");
            let started = ctx
                .prompts(
                    &session.remote,
                    session.session_id(),
                    instance,
                    &idle,
                    &format!("({}) {question}", mark()),
                )
                .expect("the device's prompt is carried");
            assert!(started.turn_id.0.is_some(), "the host started a turn");
            let _ = session
                .person
                .sees(&sum, "the terminal shows the turn the host started");
            serde_json::json!({ "turn_started_by_the_host": true })
        }
    };
    session.ends("gateway-2", TEST, shows);
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
    let Some(ctx) = Context::start("gateway-thread") else {
        return;
    };
    let session = Session::open(&ctx, "answer-when-released,keep-reading,stay");
    let instance = session.starts_the_agent(&[], None);
    let shows = match &ctx.route {
        Route::StandIn => {
            let started =
                session.binding_until(instance, "the stream names the thread", |binding| {
                    names(binding, "thread-1", Some("turn-1"))
                });
            std::fs::write(release_of(&ctx), b"go").expect("the release");
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
            let (question, sum) = sum_question();
            real.charge("gateway-3", "a turn in the first thread");
            let marked = mark();
            session
                .person
                .composes(&format!("({marked}) {question}"), &marked);
            let _ = session.person.sees(&sum, "the agent answers");
            let first = session.binding_until(instance, "the turn ends", |binding| {
                binding.thread_id.0.is_some() && binding.turn_id.0.is_none() && unsuspended(binding)
            });
            let first_thread = thread_of(&first).expect("a thread");

            // A command that selects nothing changes nothing.
            session.person.window.type_text(b"/pwd\r");
            let _ = session
                .person
                .sees("Current working directory:", "the command answers");
            let after_pwd = ctx.binding(&session.remote, session.session_id(), instance);
            assert_eq!(
                (thread_of(&after_pwd), after_pwd.binding_revision),
                (Some(first_thread.clone()), first.binding_revision),
                "a command that selects no thread leaves the binding as it was"
            );

            // A fork selects another thread, and a new conversation another.
            session.person.window.type_text(b"/fork\r");
            let forked =
                session.binding_until(instance, "the terminal forks the thread", |binding| {
                    thread_of(binding).is_some_and(|thread| thread != first_thread)
                        && unsuspended(binding)
                });
            let fork_thread = thread_of(&forked).expect("a thread");
            session.person.window.type_text(b"/new\r");
            let fresh =
                session.binding_until(instance, "the terminal starts a new thread", |binding| {
                    thread_of(binding).is_some_and(|thread| thread != fork_thread)
                        && unsuspended(binding)
                });
            assert!(
                fresh.binding_revision != forked.binding_revision
                    && forked.binding_revision != first.binding_revision,
                "each selection advanced the binding's revision"
            );

            // A launch that resumes the first thread names it.
            session.person.window.type_text(b"/quit\r");
            let _ = ctx.instances_until(
                &session.remote,
                session.session_id(),
                "the first launch has ended",
                |read| read.agent_instances.instances.is_empty(),
            );
            let resumed = session.starts_the_agent(&["resume", &first_thread], Some(instance));
            let named = session.binding_until(resumed, "the resumed thread is named", |binding| {
                thread_of(binding).as_deref() == Some(first_thread.as_str()) && unsuspended(binding)
            });
            serde_json::json!({
                "changed_by_a_command_that_selects_nothing": false,
                "changed_by_a_fork": true,
                "changed_by_a_new_conversation": true,
                "named_by_a_resuming_launch": thread_of(&named) == Some(first_thread),
            })
        }
    };
    session.ends("gateway-3", TEST, shows);
}

// ---------------------------------------------------------------------------------------------
// Case 4: a whole session names no method the table does not list.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that its list of stable method names is complete for a 0.155.1
/// session: after a turn and a slash command the binding is not suspended, which the host does
/// only when a frame names a method the table does not list.
#[test]
fn gateway_a_whole_session_names_no_method_the_table_does_not_list() {
    const TEST: &str = "gateway_a_whole_session_names_no_method_the_table_does_not_list";
    let Some(ctx) = Context::start("gateway-listed") else {
        return;
    };
    let session = Session::open(&ctx, "answer-when-released,keep-reading,stay");
    let instance = session.starts_the_agent(&[], None);
    let binding = match &ctx.route {
        Route::StandIn => {
            let _ = session.binding_until(instance, "the stream names the turn", |binding| {
                names(binding, "thread-1", Some("turn-1"))
            });
            std::fs::write(release_of(&ctx), b"go").expect("the release");
            session.binding_until(instance, "the turn ends", |binding| {
                names(binding, "thread-1", None)
            })
        }
        Route::Real(real) => {
            let (question, sum) = sum_question();
            real.charge("gateway-4", "a turn");
            let marked = mark();
            session
                .person
                .composes(&format!("({marked}) {question}"), &marked);
            let _ = session.person.sees(&sum, "the agent answers");
            session.person.window.type_text(b"/pwd\r");
            let _ = session
                .person
                .sees("Current working directory:", "the command answers");
            session.binding_until(instance, "the turn ends", |binding| {
                binding.thread_id.0.is_some() && binding.turn_id.0.is_none() && unsuspended(binding)
            })
        }
    };
    assert!(
        unsuspended(&binding),
        "rich work is not suspended after the whole session: {binding:?}"
    );
    session.ends(
        "gateway-4",
        TEST,
        serde_json::json!({ "suspended": binding.rich_mutations_suspended }),
    );
}

// ---------------------------------------------------------------------------------------------
// Case 5: a device's prompt over a running turn is refused and reaches nothing.
// ---------------------------------------------------------------------------------------------

/// The package's table assumes that `turn/start` over a running turn is not a queue: a device's
/// prompt while a turn runs is refused as a conflict with it, and nothing reaches the server.
#[test]
fn gateway_a_device_prompt_over_a_running_turn_is_refused_and_reaches_nothing() {
    const TEST: &str = "gateway_a_device_prompt_over_a_running_turn_is_refused_and_reaches_nothing";
    let Some(ctx) = Context::start("gateway-running") else {
        return;
    };
    let session = Session::open(&ctx, "answer-when-released,keep-reading,stay");
    let instance = session.starts_the_agent(&[], None);
    let shows = match &ctx.route {
        Route::StandIn => {
            let running = session.binding_until(instance, "the stream names the turn", |binding| {
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
                requests_of(&ctx, "turn/start"),
                1,
                "only the terminal's own turn reached the server"
            );
            serde_json::json!({ "refused_as": "DraftConflict", "turn_starts_at_the_server": 1 })
        }
        Route::Real(real) => {
            // The turn waits on an approval, which keeps it running for as long as the case needs.
            let mark = mark();
            real.charge("gateway-5", "a turn that waits on an approval");
            session.person.composes(
                &format!(
                    "({mark}) Use your shell tool to run exactly this command and nothing else: \
                     sleep 30"
                ),
                &mark,
            );
            let _ = session.person.sees(
                &real.account.approval.shows,
                "the agent asks for approval of the command",
            );
            let running =
                session.binding_until(instance, "the stream names the running turn", |binding| {
                    binding.thread_id.0.is_some()
                        && binding.turn_id.0.is_some()
                        && unsuspended(binding)
                });
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
            let held = session.interpreted_approval();
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
            let recorded = Real::conversations(&ctx.run);
            assert!(
                recorded.contains(&mark) && !recorded.contains(&device),
                "the agent's record holds the terminal's prompt and not the device's"
            );
            serde_json::json!({ "refused_as": "DraftConflict", "device_prompt_in_the_agents_record": false })
        }
    };
    session.ends("gateway-5", TEST, shows);
}
