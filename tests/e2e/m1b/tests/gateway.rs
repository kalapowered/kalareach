//! A command typed in a managed root shell, served by a gateway: the whole session.
//!
//! The host is the `kr-controller` daemon, its sessions are `kr-worker` processes, the shell is the
//! managed zsh package this tree built, and the person is `kr` on a real terminal. The command is
//! `codex`: the stand-in for the application (`tests/support/codex-stand-in`) placed under that
//! name, qualified by a signed record whose digest is the placed copy's. The installed package is
//! the worker's own Codex-shaped test package, published in a signed generation, installed with
//! its integration's grant confirmed and turned on in the configuration before the daemon starts.
//! The owner's device is this repository's client library over iroh on loopback.
//!
//! Each case carries, in a comment of its own, the requirement rows its assertions show; what a case
//! shows is in that comment.
//!
//! Not claimed: Windows, where no gateway runs.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_client::cursors::StreamCursors;
use kr_client::reconnect::ClientState;
use kr_e2e_m1b::device::{Device, PairedHost, Remote};
use kr_e2e_m1b::host::{Host, HostOptions, Preparation};
use kr_e2e_m1b::run::{Run, ended_within, groups, running};
use kr_e2e_m1b::view::View;
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
    AgentPromptParams, AgentSteerParams, AgentSubject, PluginActionInvokeParams,
    PluginActionInvokeResult, PromptText,
};
use kr_protocol::broker::{ActionName, InstanceCapabilityState, IntegrationMode};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{PendingKind, PendingState};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    AgentTurnId, ApplicationInstanceId, CapabilityId, PendingResourceId, PluginId, SessionEpoch,
    SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, ReceiptState};
use kr_protocol::recovery::{
    AgentInstancesParams, AgentInstancesResult, EventsSnapshotParams, EventsSnapshotResult,
};
use kr_protocol::root::CommandBypassReason;
use kr_protocol::scalars::{Bytes, Nullable};
use kr_worker::broker::THREAD_NOT_READ;
use kr_worker::broker::connectors::fixture;

/// The test support that builds signed catalogue generations.
#[allow(dead_code)]
#[path = "../../../../crates/kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// What the session's shell prompts with, so a case knows it is reading.
const PROMPT: &str = "kr-session$ ";

/// The person's own startup file for the session's shell. `kr shell install` adds the marked entry
/// that loads the package's integration after it.
const ZSHRC: &str =
    "PROMPT='kr-session$ '\nRPROMPT=''\nHISTFILE=''\nsetopt no_beep\nunsetopt prompt_sp\n";

/// What the stand-in says when it runs as typed, with no gateway's address among its words.
const RAN_AS_TYPED: &str = "codex-stand-in: serves";

/// What the terminal writes when the server asks it for the approval of a command.
const ASKED: &str = "TUI: the server asks for item/commandExecution/requestApproval";

/// What the application's server starts for the turn: a shell with a process of its own, so that
/// there is something below the server to end. The shell's `$0` names the directory the programs
/// are in, which is what lets the run find it by its command line.
fn command(tools: &Path) -> String {
    format!(
        r#"["/bin/sh", "-c", "sleep 120 & wait", "{}"]"#,
        tools.display()
    )
}

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

/// The fixture's table, declaring a tested volatile forwarding mode as the gateway needs of a
/// connector it serves, with every method the stand-in sends or is sent classified, so that no
/// method the table does not list suspends the instance.
fn complete_table() -> String {
    let mut table: serde_json::Value = serde_json::from_str(&fixture::gateway_connector_json_for(
        "kalareach/codex",
        true,
    ))
    .expect("the fixture's table is JSON");
    let added = [
        (
            "thread.start",
            "thread/start",
            "host_to_upstream",
            "mutation",
        ),
        (
            "thread.started",
            "thread/started",
            "upstream_to_host",
            "observation",
        ),
        (
            "turn.started",
            "turn/started",
            "upstream_to_host",
            "observation",
        ),
        (
            "turn.completed",
            "turn/completed",
            "upstream_to_host",
            "observation",
        ),
        (
            "item.agent-message.delta",
            "item/agentMessage/delta",
            "upstream_to_host",
            "observation",
        ),
        (
            "server-request.resolved",
            "serverRequest/resolved",
            "upstream_to_host",
            "observation",
        ),
        (
            "item.command-execution.request-approval",
            "item/commandExecution/requestApproval",
            "upstream_to_host",
            "mutation",
        ),
    ];
    for (method, wire, direction, class) in added {
        table["routes"].as_array_mut().expect("routes").push(
            serde_json::json!({ "method": method, "wire_name": wire, "direction": direction }),
        );
        table["methods"].as_array_mut().expect("methods").push(
            serde_json::json!({ "method": method, "class": class, "evidence": "The stand-in sends it" }),
        );
    }
    serde_json::to_string_pretty(&table).expect("a table encodes")
}

/// Which package a case installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Package {
    /// The worker's Codex-shaped test package, whose table says nothing about the thread, the turn
    /// or how an approval is answered.
    Table,
    /// The Codex package the plugins repository publishes, as the repository holds it.
    Released,
}

/// The directory of the released Codex package's copy.
fn released_codex() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/plugins/released/kalareach/codex/0.3.0")
}

/// Publishes a Codex package in a signed generation of its own, whose index names the digest of
/// `executable` as the one build it qualifies, and installs and enables it in the environment
/// with the grants it asks for, as the owner's confirmation of that exact installation does.
async fn install_codex(
    environment: &EnvironmentPaths,
    run: &Run,
    executable: &Path,
    flavour: Package,
) {
    let written = run.root().join("written");
    let package_dir = match flavour {
        Package::Table => {
            fixture::package_with_connector(
                &written,
                &run.binary("kr-hook"),
                &fixture::Shape::codex_backend(),
                complete_table(),
            )
            .expect("the package is written")
            .package_dir
        }
        Package::Released => released_codex(),
    };
    let digest = PayloadDigest::of(&std::fs::read(executable).expect("the placed stand-in"));
    let build = QualifiedBuild {
        application: Label::new("codex").expect("a label"),
        distribution: Label::new("test stand-in").expect("a label"),
        version: kr_plugin_sdk::version::PackageVersion::parse(fixture::GATEWAY_QUALIFIED_VERSION)
            .expect("a version"),
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
    let home = run.root().join("g");
    std::fs::create_dir_all(&home).expect("a directory for the generation");
    let generation = generations::Generation::build(
        &home,
        generations::GenerationSpec {
            package: Some(package_dir),
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
            InstallationGrant::with(match flavour {
                Package::Table => vec![PluginCapability::CommandIntegrationLaunch],
                Package::Released => vec![
                    PluginCapability::CommandIntegrationLaunch,
                    PluginCapability::ApprovalDecode,
                    PluginCapability::ApprovalRespond,
                    PluginCapability::UpstreamAction,
                ],
            }),
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

/// Everything a case needs besides its host: the run, the managed shell package, the programs and
/// a runtime for the device.
struct Context {
    runtime: tokio::runtime::Runtime,
    run: Run,
    shell: shells::ManagedShell,
    /// The directory the stand-in is placed in as `codex`, and the shell's search path names.
    tools: PathBuf,
    /// The package the case installs.
    package: Package,
}

impl Context {
    /// Makes the run and places the programs, or says why the case cannot run here, for a case that
    /// installs the Codex-shaped test package.
    fn start(leg: &str) -> Option<Self> {
        Self::starting(leg, Package::Table)
    }

    /// The same, for a case that installs the Codex package the plugins repository publishes.
    fn start_released(leg: &str) -> Option<Self> {
        Self::starting(leg, Package::Released)
    }

    fn starting(leg: &str, package: Package) -> Option<Self> {
        let shell = match shells::managed_zsh() {
            Ok(shell) => shell,
            Err(why) if shells::required() => panic!("the {leg} leg's managed shell: {why}"),
            Err(why) => {
                eprintln!("skipping the {leg} leg: {why}");
                return None;
            }
        };
        let run = Run::start(leg);
        run.place_built("kr-hook", &run.binary("kr-hook"), &["--version"]);
        let tools = run.root().join("t");
        kr_ipc::paths::create_private_tree(run.root(), &tools)
            .expect("a directory for the programs");
        run.place_built("codex-stand-in", &tools.join("codex"), &["--version"]);
        Some(Self {
            runtime: runtime(),
            run,
            shell,
            tools,
            package,
        })
    }

    /// The stand-in, as the shell finds it.
    fn codex(&self) -> PathBuf {
        self.tools.join("codex")
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
                self.runtime.block_on(install_codex(
                    environment,
                    &self.run,
                    &self.codex(),
                    self.package,
                ));
            },
        )
    }

    /// The environment every `kr` the case runs is given: the host's, with the stand-in on the
    /// search path and the managed shell and its startup file named.
    fn variables(&self, host: &Host<'_>) -> Vec<(String, String)> {
        let home = self.run.home();
        let mut variables = host.variables();
        variables.retain(|(name, _)| name != "PATH");
        variables.push((
            "PATH".to_owned(),
            format!("{}:/usr/bin:/bin", self.tools.display()),
        ));
        variables.push(("ZDOTDIR".to_owned(), home.display().to_string()));
        variables.push((
            "SHELL".to_owned(),
            self.shell.executable.display().to_string(),
        ));
        variables
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

    /// Reads the capability record the host keeps for an instance.
    fn capability(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        name: &str,
    ) -> (InstanceCapabilityState, Option<String>) {
        let read: AgentCapabilitiesResult = self
            .runtime
            .block_on(remote.read(
                Method::AgentCapabilities,
                &AgentCapabilitiesParams {
                    subject: subject(session_id, instance),
                },
            ))
            .unwrap_or_else(|why| panic!("agent.capabilities: {why}"));
        let record = read
            .capabilities
            .record(&CapabilityId::new(name).expect("a capability"))
            .unwrap_or_else(|| panic!("{name} is not recorded: {:?}", read.capabilities));
        (record.state, record.disabled_reason.0.clone())
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

    /// Answers the pending approval `resource`, and returns what the host answered.
    fn answers(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
        resource: PendingResourceId,
        option: &str,
    ) -> Result<AgentApprovalRespondResult, kr_e2e_m1b::device::RequestError> {
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
        queued: bool,
    ) -> Result<AgentMutationResult, kr_e2e_m1b::device::RequestError> {
        let (target, mutation_target) = Self::target(remote, session_id, instance, binding);
        self.runtime.block_on(remote.mutate(
            if queued {
                Method::AgentPromptQueue
            } else {
                Method::AgentPromptSubmit
            },
            target,
            &AgentPromptParams {
                target: mutation_target,
                draft_id: Nullable::null(),
                text: Nullable::some(PromptText::new(text).expect("a prompt")),
            },
        ))
    }

    /// Steers the turn `turn` of an instance.
    fn steers(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
        turn: &AgentTurnId,
        text: &str,
    ) -> Result<AgentMutationResult, kr_e2e_m1b::device::RequestError> {
        let (target, mutation_target) = Self::target(remote, session_id, instance, binding);
        self.runtime.block_on(remote.mutate(
            Method::AgentTurnSteer,
            target,
            &AgentSteerParams {
                target: mutation_target,
                turn_id: turn.clone(),
                text: PromptText::new(text).expect("a steer"),
            },
        ))
    }

    /// Invokes the package's declared action that cancels the turn that is running.
    fn cancels_by_action(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
    ) -> Result<PluginActionInvokeResult, kr_e2e_m1b::device::RequestError> {
        let (target, mutation_target) = Self::target(remote, session_id, instance, binding);
        self.runtime.block_on(remote.mutate(
            Method::PluginActionInvoke,
            target,
            &PluginActionInvokeParams {
                target: mutation_target,
                plugin_id: codex(),
                action: ActionName::new("turn.cancel").expect("an action"),
                draft_id: Nullable::null(),
                resource_id: Nullable::null(),
                parameters: Bytes::new(b"{}".to_vec()),
            },
        ))
    }

    /// Submits a prompt to an instance at the revision of `binding`, and returns what the host
    /// refused it with.
    fn refused_prompt(
        &self,
        remote: &Remote,
        session_id: SessionId,
        instance: ApplicationInstanceId,
        binding: &AgentBindingState,
    ) -> (ErrorCode, String) {
        let target = ActionTarget {
            environment_id: remote.environment_id(),
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::some(instance),
            agent_binding_revision: Nullable::some(binding.binding_revision),
        };
        let submitted: Result<AgentMutationResult, _> = self.runtime.block_on(remote.mutate(
            Method::AgentPromptSubmit,
            target,
            &AgentPromptParams {
                target: AgentMutationTarget {
                    subject: subject(session_id, instance),
                    binding_revision: binding.binding_revision,
                },
                draft_id: Nullable::null(),
                text: Nullable::some(PromptText::new("hello").expect("a prompt")),
            },
        ));
        match submitted {
            Err(error) => (
                error
                    .refusal()
                    .unwrap_or_else(|| panic!("not a refusal: {error}")),
                error.to_string(),
            ),
            Ok(accepted) => panic!("the prompt was accepted: {accepted:?}"),
        }
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

/// A person at a terminal in a managed session.
struct Person {
    window: Window,
    session_id: SessionId,
    display: String,
}

impl Person {
    /// Enters a managed shell with `kr new` on a terminal of its own, and waits for its prompt.
    fn enters(ctx: &Context, host: &Host<'_>) -> Self {
        let home = ctx.run.home();
        std::fs::write(home.join(".zshrc"), ZSHRC).expect("writes the startup file");
        let variables = ctx.variables(host);
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
        let window = Window::open(
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
        answered(&window, window.answer_capability_queries(0));
        let _ =
            window.wait_for_screen(PROMPT.trim_end(), "the managed shell reads at the terminal");
        let sessions = host.live_sessions();
        assert_eq!(sessions.len(), 1, "one live session: {sessions:?}");
        let session_id: SessionId = sessions[0]["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("a session identifier");
        let display = sessions[0]["display_number"].to_string();
        Self {
            window,
            session_id,
            display,
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

    /// Clears the shell's screen, so that what it shows afterwards is what the next line did.
    ///
    /// A row of the screen is what a person would read, whichever bytes painted it, so a row left
    /// by an earlier line is told from one the next line made only when the earlier ones are gone.
    fn clears_the_screen(&self) {
        self.window.type_text(b"\x0c");
        let started = Instant::now();
        loop {
            let rows = self.window.screen();
            if !rows.iter().any(|row| row.contains(RAN_AS_TYPED)) {
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

    /// Types `line`, which runs through the integration, and waits until the screen shows `needle`.
    ///
    /// The shell asks the worker what a line runs and waits for the answer for one second at most,
    /// the product's bound; on a machine too loaded for the worker to answer in that time the line
    /// runs as it was typed, and the stand-in, which is not told to serve a gateway, says what it
    /// serves and ends. Nothing was started and nothing recorded by it, so the line is typed
    /// again, on a cleared screen so that the row that says it is this line's own, and the wait is
    /// for the screen to show `needle`, whatever the number of lines it took. A launcher that
    /// refused the launch says so, and that is not a late answer: it fails at once.
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
            command(&ctx.tools)
        ));
    }
}

/// The file that lets the stand-in's terminal go on, and the prefix of the files that release its
/// ticks one at a time.
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

/// The parameters of each request of `method` the server received, in order.
fn requests_of(ctx: &Context, method: &str) -> Vec<serde_json::Value> {
    let prefix = format!("params {method} ");
    received_lines(ctx)
        .iter()
        .filter_map(|line| line.strip_prefix(&prefix))
        .map(|rest| serde_json::from_str(rest).expect("the server noted JSON"))
        .collect()
}

/// Waits until the server has received `count` requests of `method`, and returns them.
fn requests_until(ctx: &Context, method: &str, count: usize) -> Vec<serde_json::Value> {
    let started = Instant::now();
    loop {
        let found = requests_of(ctx, method);
        if found.len() >= count {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the server did not receive {count} request(s) of {method}: {:?}",
            received_lines(ctx)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Lets the stand-in's terminal print its tick `number`.
fn tick(ctx: &Context, number: u64) {
    let mut released = release_of(ctx).into_os_string();
    released.push(format!(".tick{number}"));
    std::fs::write(PathBuf::from(released), b"go").expect("the tick's release");
}

/// The lines the stand-in's terminal wrote among `rows`, in order.
fn terminal_lines(rows: &[String]) -> Vec<String> {
    rows.iter()
        .map(|row| row.trim().to_owned())
        .filter(|row| row.starts_with("TUI:"))
        .collect()
}

/// Waits until a process whose command line names this run's directory and holds every one of
/// `marks` is running, and records it.
fn process_running(run: &Run, what: &str, marks: &[&str]) -> ProcessStartIdentity {
    let started = Instant::now();
    loop {
        if let Some(identity) = kr_e2e_m1b::run::processes_under(run.root())
            .unwrap_or_default()
            .into_iter()
            .find_map(|(pid, _)| run.record_named(pid, what, marks))
        {
            return identity;
        }
        assert!(started.elapsed() < LIVENESS, "{what} is not running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether a word of a command line names the program `codex`, by its name or by a path to it.
fn is_codex(word: &str) -> bool {
    Path::new(word)
        .file_name()
        .is_some_and(|name| name == "codex")
}

/// The words of the command line of a process.
fn command_line(identity: &ProcessStartIdentity) -> Vec<String> {
    kr_e2e_m1b::run::describe(identity)
        .unwrap_or_else(|why| panic!("{why}"))
        .expect("the process runs")
        .command
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// Every file named `gw.sock` below `root`.
fn gateway_sockets(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().is_some_and(|name| name == "gw.sock") {
                found.push(path);
            } else if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(path);
            }
        }
    }
    found
}

/// The first instance of the session, once it has one.
fn first_instance(
    ctx: &Context,
    remote: &Remote,
    session_id: SessionId,
) -> kr_protocol::projection::AgentInstanceSummary {
    ctx.instances_until(remote, session_id, "the instance", |read| {
        !read.agent_instances.instances.is_empty()
    })
    .agent_instances
    .instances[0]
        .clone()
}

/// KR-REQ-12.07: a plain `codex resume` typed in a managed root shell runs behind a gateway that
/// exists before the terminal connects, the terminal is started with the vector typed and the
/// integration's flags added and its server with the arguments the package declares, a paired
/// device reads the terminal's approval as an opaque pending request, and the terminal's end ends
/// the server and the instance. The same line with the program named by its absolute path runs as
/// typed, with no flags and no gateway, and a program found running is adopted as a native
/// terminal and is given no server, no socket and no rich prompt: detection never creates a
/// gateway. Scripts, unmanaged shells and a user-disabled integration are keyed in the shell
/// packages' own suites and in `kr-worker`'s fence suite.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_12_07_a_codex_typed_in_a_managed_root_shell_is_served_by_a_gateway_and_an_absolute_path_is_not()
 {
    let Some(ctx) = Context::start("gateway-typed") else {
        return;
    };
    let host = ctx.host();
    let (_device, _paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    let release = release_of(&ctx);
    person.exports(&ctx, "wait-to-connect,leave-unanswered,stay");
    let _ = person.types_until_it_shows(
        "codex resume",
        "TUI: waiting to connect",
        "the terminal waits to connect",
    );

    // The gateway exists before the terminal's session does: the server runs, the socket is
    // bound, the instance is announced and holds no request.
    let instance = first_instance(&ctx, &remote, person.session_id);
    assert_eq!(instance.mode, IntegrationMode::Gateway);
    assert_eq!(instance.plugin_id.0, Some(codex()));
    assert!(instance.bypass.0.is_none() && instance.ended_at.0.is_none());
    assert!(
        ctx.instances(&remote, person.session_id)
            .agent_resources
            .resources
            .is_empty()
    );
    let worker = host.worker_of(&person.session_id.to_string());
    let server = process_running(&ctx.run, "the server", &["app-server"]);
    let terminal = process_running(&ctx.run, "the terminal", &["--remote", "gw.sock"]);
    let sockets = gateway_sockets(host.roots().runtime_root());
    assert_eq!(sockets.len(), 1, "one gateway socket is bound: {sockets:?}");
    let served = command_line(&server);
    assert!(
        served.len() == 4
            && is_codex(&served[0])
            && served[1..] == ["app-server", "--listen", "stdio://"],
        "the server is started with the arguments the package declares: {served:?}"
    );
    let typed = command_line(&terminal);
    assert!(
        typed.len() == 4 && is_codex(&typed[0]) && typed[1..3] == ["resume", "--remote"],
        "the terminal keeps the name and the vector typed and gets the integration's flags: \
         {typed:?}"
    );
    let address = typed[3]
        .strip_prefix("unix://")
        .unwrap_or_else(|| panic!("the address is not a socket's: {typed:?}"));
    assert_eq!(
        std::fs::canonicalize(address).expect("the socket the terminal is given exists"),
        std::fs::canonicalize(&sockets[0]).expect("the bound socket exists"),
        "the terminal is given the address of the socket the gateway bound before it connects"
    );
    let described = kr_e2e_m1b::run::describe(&server)
        .unwrap_or_else(|why| panic!("{why}"))
        .expect("the server runs");
    assert_eq!(
        u64::from(described.parent),
        worker.pid.get(),
        "the server is the worker's child"
    );
    let server_groups = groups(&server)
        .unwrap_or_else(|why| panic!("{why}"))
        .expect("the server runs");
    let worker_groups = groups(&worker)
        .unwrap_or_else(|why| panic!("{why}"))
        .expect("the worker runs");
    assert_ne!(
        server_groups.group, worker_groups.group,
        "the server leads a group of its own"
    );

    // The terminal connects and runs to the approval, which a paired device reads as an opaque
    // pending request.
    std::fs::write(&release, b"go").expect("the release");
    let _ = person.sees(ASKED, "the terminal reaches the server through the gateway");
    let read = ctx.instances_until(&remote, person.session_id, "the request", |read| {
        read.agent_resources.resources.len() == 1
    });
    let pending = &read.agent_resources.resources[0];
    assert_eq!(pending.state, PendingState::Pending);
    assert_eq!(pending.kind, PendingKind::ReverseRpc);
    assert_eq!(
        pending.method.as_str(),
        "item/commandExecution/requestApproval"
    );
    assert!(
        !pending.interpretation_verified,
        "no decoder has read it: the request is opaque"
    );

    // The terminal ends, and the server and the instance end with it.
    person.window.type_text(b"\x03");
    assert!(ended_within(&terminal, LIVENESS), "the terminal ends");
    assert!(ended_within(&server, LIVENESS), "the server ends with it");
    let _ = ctx.instances_until(&remote, person.session_id, "the instance ends", |read| {
        read.agent_instances.instances.is_empty()
    });

    // The same line with the program named by its absolute path runs as typed. Were the route to
    // take paths it would add the gateway's address, and the stand-in would be a terminal waiting
    // to connect; run as typed it is given no address, and says what it serves and ends.
    let absolute = ctx.codex().display().to_string();
    person.clears_the_screen();
    person.types(&format!("{absolute} resume"));
    let _ = person.sees(
        "codex-stand-in: serves",
        "the program ran as typed, with no gateway's address added",
    );

    // A program found running that the integration did not launch is adopted and given no
    // gateway.
    person.types("export KR_STAND_IN=idle");
    person.types(&format!("{absolute} --remote unix:///nonexistent"));
    let adopted = first_instance(&ctx, &remote, person.session_id);
    assert_eq!(adopted.mode, IntegrationMode::NativeTerminal);
    assert_eq!(adopted.bypass.0, Some(CommandBypassReason::AbsolutePath));
    assert!(
        process_absent(&ctx.run, "app-server"),
        "no server is started for it"
    );
    assert!(
        gateway_sockets(host.roots().runtime_root()).is_empty(),
        "and no gateway socket exists"
    );
    let binding = ctx.binding(&remote, person.session_id, adopted.application_instance_id);
    let (code, _) = ctx.refused_prompt(
        &remote,
        person.session_id,
        adopted.application_instance_id,
        &binding,
    );
    assert_eq!(
        code,
        ErrorCode::UnsupportedCapability,
        "a rich prompt has nowhere to go"
    );
    person.window.type_text(b"\x03");
    let _ = ctx.instances_until(&remote, person.session_id, "the adopted one ends", |read| {
        read.agent_instances.instances.is_empty()
    });
    ctx.close(&host);
}

/// Whether no process of the run has `needle` in its command line.
fn process_absent(run: &Run, needle: &str) -> bool {
    kr_e2e_m1b::run::processes_under(run.root())
        .unwrap_or_default()
        .iter()
        .all(|(_, command)| !command.contains(needle))
}

/// KR-REQ-12.06: the binding of a gateway-served terminal says that nothing reads which thread the
/// terminal has selected: it names no thread, its rich mutations are suspended for that reason
/// before and after the terminal connects and completes a turn, and a rich prompt at the revision
/// read is refused for it. The terminal runs its whole turn through
/// the gateway meanwhile. The package's table lists every method the terminal sends, so no method
/// the table does not list is the reason.
///
/// The revision advancing when the selection changes, and a stale submission, need the thread read
/// from the stream and are not claimed here.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_12_06_a_gateway_served_terminals_unread_thread_suspends_rich_mutations_and_leaves_the_terminal_available()
 {
    let Some(ctx) = Context::start("gateway-binding") else {
        return;
    };
    let host = ctx.host();
    let (_device, _paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    person.exports(&ctx, "wait-to-connect,stay");
    let _ = person.types_until_it_shows(
        "codex",
        "TUI: waiting to connect",
        "the terminal waits to connect",
    );
    let instance = first_instance(&ctx, &remote, person.session_id).application_instance_id;
    let before = ctx.binding(&remote, person.session_id, instance);
    assert_eq!(before.mode, IntegrationMode::Gateway);
    assert!(before.thread_id.0.is_none() && before.turn_id.0.is_none());
    assert_eq!(before.binding_revision.get(), 1);
    assert!(
        before.rich_mutations_suspended,
        "nothing reads the thread the terminal will select: {before:?}"
    );
    assert_eq!(before.suspension_reason.0.as_deref(), Some(THREAD_NOT_READ));

    std::fs::write(release_of(&ctx), b"go").expect("the release");
    let _ = person.sees(
        "TUI: turn/completed",
        "the terminal runs its whole turn through the gateway",
    );
    let after = ctx.binding(&remote, person.session_id, instance);
    assert_eq!(
        after, before,
        "the terminal's traffic neither names a thread nor lifts or replaces the reason"
    );
    let (code, said) = ctx.refused_prompt(&remote, person.session_id, instance, &after);
    assert_eq!(code, ErrorCode::DraftConflict);
    assert!(said.contains(THREAD_NOT_READ), "{said}");
    ctx.close(&host);
}

/// KR-REQ-12.10, KR-ACC-006 and the daemon-restart leg of KR-REQ-11.27: the control daemon is
/// killed with nothing said to it while the terminal writes. The worker, the terminal and the
/// server go on, and the terminal's output reaches the local terminal in order while no daemon
/// exists. A daemon started again serves a reconnecting device the same agent instance, the same
/// binding and the same pending request, field for field, once its first admissions round has
/// reached the worker. The device that reconnects had drawn the terminal's output up to the kill,
/// and is drawn the screen as it is then, which is what the local terminal shows, including what
/// was written while no daemon existed. The terminal's answer then reaches the server once, the
/// request resolves once, and the terminal was asked once: a pending request is reconciled and
/// never asked again. The terminal asks the server something after its answer, so the server has
/// read everything the gateway sent it before that question when the case counts what it
/// received. The shell's half
/// (typing into the shell while no daemon exists) is `kr-worker`'s `controller_kill` suite's.
///
/// Not claimed: Windows, where no gateway runs; the Windows leg of KR-ACC-006 is a native
/// Windows run's.
#[test]
fn kr_acc_006_a_daemon_killed_while_the_terminal_writes_leaves_its_agent_and_a_restarted_daemon_serves_the_same_request()
 {
    let Some(ctx) = Context::start("gateway-restart") else {
        return;
    };
    let host = ctx.host();
    let (device, paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    person.exports(&ctx, "answer-when-released,ping-when-released,tick,stay");
    let _ = person.types_until_it_shows(
        "codex",
        ASKED,
        "the terminal reaches the server through the gateway",
    );

    // The device attaches and reads the session as it stands.
    let snapshot: EventsSnapshotResult = ctx
        .runtime
        .block_on(remote.read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id: person.session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
        .unwrap_or_else(|why| panic!("events.snapshot: {why}"));
    let dimensions = snapshot.geometry.dimensions;
    let mut view = ctx
        .runtime
        .block_on(View::attach(
            &remote,
            person.session_id,
            dimensions,
            &StreamCursors::new(),
        ))
        .unwrap_or_else(|why| panic!("the device attaches: {why}"));
    let before = ctx.instances(&remote, person.session_id);
    assert_eq!(before.agent_resources.resources.len(), 1);
    assert_eq!(
        before.agent_resources.resources[0].state,
        PendingState::Pending
    );
    assert_eq!(before.agent_instances.instances.len(), 1);
    let instance = before.agent_instances.instances[0].application_instance_id;
    let binding = ctx.binding(&remote, person.session_id, instance);
    let worker = host.worker_of(&person.session_id.to_string());
    let terminal = process_running(&ctx.run, "the terminal", &["--remote", "gw.sock"]);
    let server = process_running(&ctx.run, "the server", &["app-server"]);

    for number in 1..=3 {
        tick(&ctx, number);
    }
    let _ = person.sees("TUI: tick 3", "the terminal writes");

    // The device has drawn what the terminal wrote before the daemon is killed, and carries what
    // its connection had reached. It reads the screen as a projection, which has no output cursor
    // to carry, so its reconnect is drawn the screen as it is then, not a replay.
    let _ = ctx
        .runtime
        .block_on(view.wait_for(&remote, "TUI: tick 3", LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    let carried = ctx
        .runtime
        .block_on(ClientState::from_session(remote.session(), None));
    drop(view);

    // The daemon is killed, and the terminal goes on writing with no daemon to read it.
    host.kill_daemon();
    for identity in [&worker, &terminal, &server] {
        assert!(running(identity), "{identity:?} goes on without the daemon");
    }
    for number in 4..=6 {
        tick(&ctx, number);
    }
    let _ = person.sees(
        "TUI: tick 6",
        "the terminal's output reaches the local terminal",
    );

    // A daemon is started again. It serves the session once its first round of admissions has
    // reached the worker, which `plugin list` reports as the binding being live.
    host.start_daemon();
    let started = Instant::now();
    loop {
        let listed = host.kr_json(&["plugin", "list"]);
        let live = listed["plugins"]
            .as_array()
            .and_then(|plugins| {
                plugins
                    .iter()
                    .find(|plugin| plugin["plugin_id"] == "kalareach/codex")
            })
            .map(|plugin| plugin["live_bindings"].clone());
        if live.is_some_and(|live| live == "1") {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "the restarted daemon never counted the live binding: {listed}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let remote = ctx
        .runtime
        .block_on(device.reconnect(&paired, carried.cursors.clone()))
        .unwrap_or_else(|why| panic!("the device reconnects: {why}"));
    let mut view = ctx
        .runtime
        .block_on(View::attach(
            &remote,
            person.session_id,
            dimensions,
            &carried.cursors,
        ))
        .unwrap_or_else(|why| panic!("the device attaches again: {why}"));
    let after = ctx.instances(&remote, person.session_id);
    assert_eq!(
        after.agent_resources.resources, before.agent_resources.resources,
        "the same request, still pending"
    );
    assert_eq!(
        after.agent_instances.instances, before.agent_instances.instances,
        "the same instance"
    );
    assert_eq!(
        ctx.binding(&remote, person.session_id, instance),
        binding,
        "the same binding"
    );
    for identity in [&worker, &terminal, &server] {
        assert!(running(identity), "{identity:?} is the one that ran before");
    }

    // What the terminal writes now is drawn to the local terminal and to the device alike.
    for number in 7..=9 {
        tick(&ctx, number);
    }
    let local = person.sees("TUI: tick 9", "the local terminal shows the last tick");
    let drawn = ctx
        .runtime
        .block_on(view.wait_for(&remote, "TUI: tick 9", LIVENESS))
        .unwrap_or_else(|why| panic!("{why}"));
    let ticks: Vec<String> = (1..=9)
        .map(|number| format!("TUI: tick {number}"))
        .collect();
    let lines = terminal_lines(&local);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("TUI: tick"))
            .cloned()
            .collect::<Vec<_>>(),
        ticks,
        "the ticks are on the local terminal in order, those written while no daemon existed among them"
    );
    assert_eq!(
        terminal_lines(&drawn),
        lines,
        "the device is drawn what the local terminal shows"
    );

    // The terminal answers, and the answer reaches the server once. The terminal then asks the
    // server who the account is, which the gateway sends after the answer and the server reads
    // after it: once that is answered, a second copy of the answer sent with the first would have
    // been read, and a server that reads one ends.
    let mark = person.window.mark();
    std::fs::write(release_of(&ctx), b"go").expect("the release");
    let _ = person.sees("TUI: turn/completed", "the turn completes");
    let _ = person.window.wait_for(
        mark,
        b"TUI: the server answered after the turn",
        "the server answers what the terminal asks after its answer",
    );
    let done = ctx.instances_until(&remote, person.session_id, "the request resolves", |read| {
        read.agent_resources.resources.len() == 1
            && read.agent_resources.resources[0].state == PendingState::Resolved
    });
    assert_eq!(
        done.agent_resources.resources[0].resource_id,
        before.agent_resources.resources[0].resource_id
    );
    let asked = terminal_lines(&person.window.screen())
        .iter()
        .filter(|line| line.as_str() == ASKED)
        .count();
    assert_eq!(asked, 1, "the terminal was asked once");
    assert!(
        running(&server),
        "the server goes on: it was sent no second answer"
    );
    let received = std::fs::read_to_string(received_by(&ctx)).expect("what the server received");
    let answers = received
        .lines()
        .filter(|line| line.starts_with("response "))
        .count();
    assert_eq!(
        answers, 1,
        "the server received one answer, and the request was not asked again: {received}"
    );
    ctx.close(&host);
}

/// A session whose server ignores the end of its input and a terminate, with the commands it
/// started: the worker's record of what it owns, read once it names the server and everything
/// below it.
struct Stubborn {
    person: Person,
    worker: ProcessStartIdentity,
    terminal: ProcessStartIdentity,
    server: ProcessStartIdentity,
    /// The shell the server started for its command and the `sleep` below it.
    below: Vec<ProcessStartIdentity>,
}

impl Stubborn {
    fn start(ctx: &Context, host: &Host<'_>) -> Self {
        let person = Person::enters(ctx, host);
        person.exports(ctx, "ignore-eof,ignore-term,leave-unanswered,stay");
        let _ = person.types_until_it_shows(
            "codex",
            ASKED,
            "the terminal reaches the server through the gateway",
        );
        let worker = host.worker_of(&person.session_id.to_string());
        let terminal = process_running(&ctx.run, "the terminal", &["--remote", "gw.sock"]);
        let server = process_running(&ctx.run, "the server", &["app-server"]);
        // The server starts a shell for its command, and the shell starts the `sleep`: each is
        // recorded once it runs.
        let before = ctx.run.owned().len();
        let started = Instant::now();
        while ctx.run.owned().len() < before + 2 {
            ctx.run
                .record_descendants(&server, "under the server")
                .unwrap_or_else(|why| panic!("{why}"));
            assert!(
                started.elapsed() < LIVENESS,
                "the server's shell and its sleep are not both running: {:?}",
                &ctx.run.owned()[before..]
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let below: Vec<ProcessStartIdentity> = ctx.run.owned()[before..]
            .iter()
            .map(|owned| owned.identity.clone())
            .collect();
        assert_eq!(below.len(), 2, "a shell and its sleep: {below:?}");

        // The worker has recorded the server as a root it started and everything below it, which
        // is what a daemon that must close the session reads.
        let journal = kr_worker::journal::Journal::open_read_only(
            host.environment().journal_database(person.session_id),
        )
        .expect("the worker's journal");
        let started = Instant::now();
        loop {
            let record = journal
                .read_owned(person.session_id)
                .expect("the record is readable")
                .expect("the worker recorded the session's processes");
            if record.backends.contains(&server)
                && below
                    .iter()
                    .all(|identity| record.processes.contains(identity))
            {
                break;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "the worker's record does not name the server and what it started: {record:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }

        // The terminal is in the foreground of its tty, and the server leads a group that is
        // neither the terminal's nor the worker's.
        let terminal_groups = groups(&terminal)
            .unwrap_or_else(|why| panic!("{why}"))
            .expect("the terminal runs");
        assert_eq!(
            terminal_groups.group, terminal_groups.foreground,
            "the terminal is the foreground group of its tty"
        );
        let server_groups = groups(&server)
            .unwrap_or_else(|why| panic!("{why}"))
            .expect("the server runs");
        let worker_groups = groups(&worker)
            .unwrap_or_else(|why| panic!("{why}"))
            .expect("the worker runs");
        assert_eq!(
            u64::try_from(server_groups.group).ok(),
            Some(server.pid.get()),
            "the server leads its own group"
        );
        assert_ne!(server_groups.group, terminal_groups.group);
        assert_ne!(server_groups.group, worker_groups.group);
        Self {
            person,
            worker,
            terminal,
            server,
            below,
        }
    }

    /// Checks a closure as `kr status` reports it: the server, the shell it started and the
    /// `sleep` below it, and the terminal, are all named among the processes it ended by the
    /// identities the worker recorded, the server by force since it ignores both a closed input
    /// and a terminate, and no process survives.
    ///
    /// A host whose boundary is the terminal's process group, a Mac, cannot see a descendant that
    /// left it, so its closure never claims the coverage complete, and the closure a daemon writes
    /// for a crashed worker, which has no control group to read there, names that limit among what
    /// survived. That is the only thing a closure may name as surviving. Where the coverage is
    /// complete, nothing is named at all.
    fn closed_as(&self, closure: &serde_json::Value, reason: &str) {
        assert_eq!(closure["reason"], reason, "{closure}");
        let ended = closure["terminated"]
            .as_array()
            .expect("the processes ended");
        let named = |identity: &ProcessStartIdentity| {
            let wanted = serde_json::to_value(identity).expect("an identity");
            ended.iter().find(|process| process["start"] == wanted)
        };
        for identity in std::iter::once(&self.server)
            .chain(&self.below)
            .chain(std::iter::once(&self.terminal))
        {
            assert!(
                named(identity).is_some(),
                "{identity:?} is among what the closure ended: {closure}"
            );
        }
        assert_eq!(
            named(&self.server).map(|process| process["forced"].clone()),
            Some(serde_json::json!(true)),
            "the server needed force: {closure}"
        );
        let surviving = closure["surviving"].as_array().expect("what survived");
        assert!(
            surviving
                .iter()
                .all(|resource| resource["kind"] == "unestablished"),
            "no process survives: {closure}"
        );
        if cfg!(target_os = "macos") {
            assert_eq!(closure["ownership_coverage"], "incomplete", "{closure}");
        } else if closure["ownership_coverage"] == "complete" {
            assert!(surviving.is_empty(), "{closure}");
        }
        for identity in std::iter::once(&self.server)
            .chain(&self.below)
            .chain(std::iter::once(&self.terminal))
        {
            assert!(!running(identity), "{identity:?} is gone");
        }
    }
}

/// Reads the closure `kr status` reports for a session once it has closed.
fn closure_of(host: &Host<'_>, display: &str) -> serde_json::Value {
    host.wait_until_closed(display)["closure"].clone()
}

/// KR-REQ-07.61: `kr close` of a session whose server ignores the end of its input and a terminate
/// ends the server by force, the shell it started and the `sleep` below that, and the terminal, by
/// the identities the worker recorded, and leaves nothing surviving. The server leads a group of
/// its own, neither the terminal's nor the worker's, and the terminal is the foreground group of
/// its tty. On a Mac the closure's coverage is incomplete, since the terminal's group is the
/// boundary there and a descendant could leave it; nothing is claimed of the coverage elsewhere.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_07_61_a_requested_close_ends_the_server_and_what_it_started_by_the_recorded_identities() {
    let Some(ctx) = Context::start("gateway-close") else {
        return;
    };
    let host = ctx.host();
    let session = Stubborn::start(&ctx, &host);
    let _ = host.kr_json(&["close", &session.person.display]);
    let closure = closure_of(&host, &session.person.display);
    session.closed_as(&closure, "close_requested");
    ctx.close(&host);
}

/// KR-REQ-07.61 and KR-REQ-07.66: a worker killed with nothing said to it leaves a server that
/// ignores the end of its input and a terminate, and the daemon, which reads what the worker
/// recorded, ends the server by force, what it started and the terminal, and leaves no process
/// surviving. Where the host has a control group for the worker's service the group is also the
/// daemon's boundary; on a Mac the recorded identities are all it has, and it says so.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_07_61_a_worker_killed_leaves_a_server_the_daemon_ends_with_what_it_started() {
    let Some(ctx) = Context::start("gateway-crash") else {
        return;
    };
    let host = ctx.host();
    let session = Stubborn::start(&ctx, &host);
    kr_e2e_m1b::run::signal(&session.worker, rustix::process::Signal::KILL);
    assert!(ended_within(&session.worker, LIVENESS), "the worker ends");
    let closure = closure_of(&host, &session.person.display);
    session.closed_as(&closure, "worker_crash");
    ctx.close(&host);
}

/// What an approval pending on the stand-in's server is, once a decoder has read it.
fn interpreted_approval(
    ctx: &Context,
    remote: &Remote,
    session_id: SessionId,
) -> kr_protocol::gateway::PendingResource {
    let read = ctx.instances_until(remote, session_id, "the request is interpreted", |read| {
        read.agent_resources.resources.len() == 1
            && read.agent_resources.resources[0].interpretation_verified
    });
    read.agent_resources.resources[0].clone()
}

/// Whether the binding names `thread` and, when `turn` is given, that turn, and rich work is not
/// suspended.
fn names(binding: &AgentBindingState, thread: &str, turn: Option<&str>) -> bool {
    binding
        .thread_id
        .0
        .as_ref()
        .map(ToString::to_string)
        .as_deref()
        == Some(thread)
        && binding
            .turn_id
            .0
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            == turn
        && !binding.rich_mutations_suspended
}

/// KR-REQ-11.22, KR-REQ-11.33 and KR-REQ-12.11: a paired device answers the approval of a real
/// session, behind a gateway, through the Codex package the plugins repository publishes. The
/// terminal holds its own answer and goes on reading. The request is read under the package's
/// trust and answered once, as the response Codex reads, with the decision the device chose; the
/// server's word that it was answered reaches the terminal. When the terminal then sends its own
/// answer, it is not forwarded, the connection goes on, and the server has received one answer,
/// which the terminal's next question after it shows.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_11_33_a_device_answers_an_approval_the_terminal_holds_and_the_late_terminal_answer_is_not_forwarded()
 {
    let Some(ctx) = Context::start_released("gateway-approve-first") else {
        return;
    };
    let host = ctx.host();
    let (_device, _paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    person.exports(
        &ctx,
        "answer-when-released,keep-reading,ping-when-released,stay",
    );
    let _ = person.types_until_it_shows(
        "codex",
        ASKED,
        "the terminal reaches the server through the gateway",
    );
    let instance = first_instance(&ctx, &remote, person.session_id).application_instance_id;
    let binding = ctx.binding_until(
        &remote,
        person.session_id,
        instance,
        "the stream names the thread and the turn",
        |binding| names(binding, "thread-1", Some("turn-1")),
    );
    let pending = interpreted_approval(&ctx, &remote, person.session_id);
    assert_eq!(pending.state, PendingState::Pending);
    let evidence = ctx.capability(&remote, person.session_id, instance, "agent.approval");
    assert_eq!(
        evidence.0,
        InstanceCapabilityState::QualifiedAvailable,
        "{evidence:?}"
    );

    // The device answers. The server is sent the response Codex reads: the request's own
    // identifier and the decision in the member the table names.
    let answered = ctx
        .answers(
            &remote,
            person.session_id,
            instance,
            &binding,
            pending.resource_id,
            "accept-for-session",
        )
        .expect("the device's answer is carried");
    assert_eq!(answered.state, PendingState::Resolved);
    // The server said the request was answered, and the terminal read it while it held its answer.
    // `Resolved` says only that the gateway wrote the answer, so what the server received is read
    // once the server has said it read it.
    let _ = person.sees(
        "TUI: serverRequest/resolved",
        "the terminal reads the server's word that the request was answered",
    );
    let received = received_lines(&ctx);
    assert_eq!(
        received
            .iter()
            .filter(|line| line.starts_with("response "))
            .count(),
        1,
        "{received:?}"
    );

    // The terminal sends its own answer late, and then asks the server a question. The server
    // answers the question, so the connection went on, and it received the one answer.
    let mark = person.window.mark();
    std::fs::write(release_of(&ctx), b"go").expect("the release");
    let _ = person.window.wait_for(
        mark,
        b"TUI: the server answered after the turn",
        "the connection goes on after the terminal's late answer",
    );
    let received = received_lines(&ctx);
    assert_eq!(
        received
            .iter()
            .filter(|line| line.starts_with("response "))
            .count(),
        1,
        "the terminal's late answer was not forwarded: {received:?}"
    );
    let done = ctx.instances_until(
        &remote,
        person.session_id,
        "the request is resolved",
        |read| {
            read.agent_resources.resources.len() == 1
                && read.agent_resources.resources[0].state == PendingState::Resolved
        },
    );
    assert_eq!(
        done.agent_resources.resources[0].resource_id,
        pending.resource_id
    );
    ctx.close(&host);
}

/// KR-REQ-11.33: in the other order the terminal answers first, the request is resolved, and the
/// device's answer to it is refused for that and sends nothing.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_11_33_a_device_answer_to_a_request_the_terminal_answered_is_refused_and_sends_nothing() {
    let Some(ctx) = Context::start_released("gateway-answered-first") else {
        return;
    };
    let host = ctx.host();
    let (_device, _paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    person.exports(&ctx, "answer-when-released,stay");
    let _ = person.types_until_it_shows(
        "codex",
        ASKED,
        "the terminal reaches the server through the gateway",
    );
    let instance = first_instance(&ctx, &remote, person.session_id).application_instance_id;
    let binding = ctx.binding_until(
        &remote,
        person.session_id,
        instance,
        "the stream names the thread and the turn",
        |binding| names(binding, "thread-1", Some("turn-1")),
    );
    let pending = interpreted_approval(&ctx, &remote, person.session_id);

    // The terminal answers, and the server's word that the request was answered completes the turn.
    std::fs::write(release_of(&ctx), b"go").expect("the release");
    let _ = person.sees("TUI: turn/completed", "the turn completes");
    let _ = ctx.instances_until(&remote, person.session_id, "the request resolves", |read| {
        read.agent_resources.resources.len() == 1
            && read.agent_resources.resources[0].state == PendingState::Resolved
    });
    let refused = ctx
        .answers(
            &remote,
            person.session_id,
            instance,
            &binding,
            pending.resource_id,
            "accept",
        )
        .expect_err("the request was answered");
    assert_eq!(
        refused.refusal(),
        Some(ErrorCode::QuestionResolved),
        "{refused}"
    );
    let received = received_lines(&ctx);
    assert_eq!(
        received
            .iter()
            .filter(|line| line.starts_with("response "))
            .count(),
        1,
        "the server received the terminal's answer and nothing else: {received:?}"
    );
    ctx.close(&host);
}

/// KR-REQ-12.06, KR-REQ-12.08 and KR-REQ-12.12: the typed operations of a real session through the
/// Codex package the plugins repository publishes. The binding names the thread and the running
/// turn from the stream, and the capability map says what the package's table lets a device do, a
/// queue excepted. A prompt over the running turn and a queue the table does not declare are
/// refused and send nothing. A steer and the package's declared cancellation reach the server as
/// the requests Codex reads, naming the thread and the turn; the turn's end clears the binding's
/// turn; and a prompt then starts a turn whose identifier the reply names.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn kr_req_12_08_a_device_steers_cancels_and_prompts_through_what_the_released_package_declares() {
    let Some(ctx) = Context::start_released("gateway-operations") else {
        return;
    };
    let host = ctx.host();
    let (_device, _paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    person.exports(&ctx, "answer-when-released,keep-reading,stay");
    let _ = person.types_until_it_shows(
        "codex",
        ASKED,
        "the terminal reaches the server through the gateway",
    );
    let session = person.session_id;
    let instance = first_instance(&ctx, &remote, session).application_instance_id;

    // KR-REQ-12.06: the stream names the thread and the running turn, and rich work is available.
    let running = ctx.binding_until(
        &remote,
        session,
        instance,
        "the stream names the thread and the turn",
        |binding| names(binding, "thread-1", Some("turn-1")),
    );

    // KR-REQ-12.08 and KR-REQ-12.12: what the table lets a device do, and what it does not.
    for name in [
        "agent.prompt",
        "agent.steer",
        "agent.cancel",
        "agent.approval",
    ] {
        let (state, reason) = ctx.capability(&remote, session, instance, name);
        assert_eq!(
            state,
            InstanceCapabilityState::QualifiedAvailable,
            "{name}: {reason:?}"
        );
    }
    let (state, reason) = ctx.capability(&remote, session, instance, "agent.prompt.queue");
    assert_eq!(state, InstanceCapabilityState::Incompatible);
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.contains("queue")),
        "the reason names the table: {reason:?}"
    );

    // Refusals before anything is sent: a prompt over the running turn is not a queue, and the
    // table declares no queue.
    let refused = ctx
        .prompts(&remote, session, instance, &running, "now", false)
        .expect_err("a prompt over a running turn");
    assert_eq!(
        refused.refusal(),
        Some(ErrorCode::DraftConflict),
        "{refused}"
    );
    let refused = ctx
        .prompts(&remote, session, instance, &running, "later", true)
        .expect_err("a queue the table does not declare");
    assert_eq!(
        refused.refusal(),
        Some(ErrorCode::UnsupportedCapability),
        "{refused}"
    );
    assert_eq!(
        requests_of(&ctx, "turn/start").len(),
        1,
        "only the terminal's own turn reached the server"
    );

    // A steer names the thread and the turn it expects, and the reply names the turn.
    let turn = AgentTurnId::new("turn-1").expect("a turn");
    let steered = ctx
        .steers(
            &remote,
            session,
            instance,
            &running,
            &turn,
            "the other file",
        )
        .expect("the steer is carried");
    assert_eq!(
        steered
            .turn_id
            .0
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("turn-1")
    );
    assert_eq!(
        requests_until(&ctx, "turn/steer", 1)[0],
        serde_json::json!({
            "threadId": "thread-1",
            "expectedTurnId": "turn-1",
            "input": [{ "type": "text", "text": "the other file" }]
        })
    );

    // The package's declared cancellation is written from the table's template, with the thread
    // and the turn the host read; the server completes the turn and the binding's turn clears.
    let cancelled = ctx
        .cancels_by_action(&remote, session, instance, &running)
        .expect("the declared cancellation is carried");
    assert!(
        cancelled.mutation.0.is_some(),
        "the action reached the upstream"
    );
    assert_eq!(
        requests_until(&ctx, "turn/interrupt", 1)[0],
        serde_json::json!({ "threadId": "thread-1", "turnId": "turn-1" })
    );
    let idle = ctx.binding_until(
        &remote,
        session,
        instance,
        "the turn's end clears the binding's turn",
        |binding| names(binding, "thread-1", None),
    );

    // With no turn running a prompt starts one, and the reply names it.
    let started = ctx
        .prompts(&remote, session, instance, &idle, "run it again", false)
        .expect("the prompt is carried");
    assert_eq!(
        started
            .turn_id
            .0
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("turn-2")
    );
    assert_eq!(
        requests_until(&ctx, "turn/start", 2)[1],
        serde_json::json!({
            "threadId": "thread-1",
            "input": [{ "type": "text", "text": "run it again" }]
        })
    );

    // A steer with no turn running is refused, and sends nothing.
    let refused = ctx
        .steers(&remote, session, instance, &idle, &turn, "too late")
        .expect_err("the turn is over");
    assert!(refused.refusal().is_some(), "{refused}");
    assert_eq!(requests_of(&ctx, "turn/steer").len(), 1);
    ctx.close(&host);
}

/// KR-GOAL-19: a prompt a device sends while the server dies under it is an outcome nobody can
/// establish, and the caller is told so.
///
/// The prompt reached the upstream before the upstream went: the server noted its request, and then
/// ended. The device is told `OUTCOME_UNKNOWN`, which is neither a refusal it could retry nor a
/// success; the host's receipt for the action says `unknown`; and the person's terminal route
/// carries on, since the shell is back at its prompt and runs what is typed there.
///
/// Not claimed: Windows, where no gateway runs.
#[test]
fn a_prompt_whose_server_dies_under_it_is_an_outcome_nobody_can_establish() {
    let Some(ctx) = Context::start_released("gateway-server-dies") else {
        return;
    };
    let host = ctx.host();
    let (_device, _paired, remote) = ctx.pair(&host);
    let person = Person::enters(&ctx, &host);
    // The server starts no command of its own here: it is killed, and a command it started would
    // be left for the closure to find, which is another case's.
    person.types("export KR_STAND_IN=die-on-second-turn,stay");
    person.types(&format!(
        "export KR_STAND_IN_RECEIVED={}",
        received_by(&ctx).display()
    ));
    let _ = person.types_until_it_shows(
        "codex",
        "TUI: turn/completed",
        "the terminal's turn completes",
    );
    let session = person.session_id;
    let instance = first_instance(&ctx, &remote, session).application_instance_id;
    let idle = ctx.binding_until(
        &remote,
        session,
        instance,
        "the stream names the thread and no turn",
        |binding| names(binding, "thread-1", None),
    );
    let refused = ctx
        .prompts(&remote, session, instance, &idle, "go on", false)
        .expect_err("the server died under the prompt");
    // The host says it cannot establish whether the action happened: the client's own account of
    // an unknown outcome, which carries the action and the host's OUTCOME_UNKNOWN.
    let kr_e2e_m1b::device::RequestError::Client(kr_client::ClientError::OutcomeUnknown {
        action_id,
        error,
    }) = &refused
    else {
        panic!("the outcome is unknown, and the host says so: {refused}");
    };
    assert_eq!(error.code, ErrorCode::OutcomeUnknown, "{refused}");
    // The prompt was dispatched: the upstream received the second turn's request before it ended.
    assert_eq!(
        requests_of(&ctx, "turn/start").len(),
        2,
        "the terminal's turn and the device's prompt each reached the server: {:?}",
        received_lines(&ctx)
    );
    // What the host keeps of the action says what the caller was told: it cannot be established.
    let read: ActionReadResult = ctx
        .runtime
        .block_on(remote.read(
            Method::ActionRead,
            &ActionReadParams {
                action_id: *action_id,
                session_id: Some(session),
            },
        ))
        .unwrap_or_else(|why| panic!("action.read: {why}"));
    assert_eq!(
        read.receipt.state,
        ReceiptState::Unknown,
        "the receipt of a prompt whose server died under it"
    );
    // The terminal route is unharmed: the terminal ended with its server, and the shell it was
    // started from reads and runs what is typed next.
    let _ = ctx.instances_until(&remote, session, "the terminal's end", |read| {
        read.agent_instances
            .instances
            .iter()
            .all(|instance| instance.ended_at.0.is_some())
    });
    person.types("printf 'kala%s-after\\n' reach");
    let _ = person.sees(
        "kalareach-after",
        "the shell runs what is typed after the server died",
    );
    ctx.close(&host);
}
