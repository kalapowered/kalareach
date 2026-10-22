//! The bundled agents' commands, typed in a managed session of a host that has changed nothing.
//!
//! The packages are the shipped repository's own (`bundled-plugins/`), read through the package
//! check as an installation hands them over, and admitted with what the seed gives a package: the
//! repository ceiling's three passive capabilities and nothing else. No command integration is on
//! under that configuration, so the shell is answered that a typed command is not integrated and
//! runs it as typed. The stand-in for an agent is a copy of this test binary placed under the
//! agent's command name and started as the root shell starts a foreground job, with a process group
//! of its own, in the way `adoption` does; the watch then finds it running.
//!
//! The cases here say what the integration decides for each agent's name, and what the worker does
//! with the program once it is running: it is the person's own program, started with the vector
//! they typed, and the worker adopts it as a native terminal instance bound to the bundled package
//! that recognises it.
//!
//! Not claimed: Windows, where the worker's adoption of a foreground program is not built.

#![cfg(unix)]

use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::broker::{BrokerGrant, IntegrationMode};
use kr_protocol::ids::SessionId;
use kr_protocol::projection::AgentInstanceSummary;
use kr_protocol::root::CommandBypassReason;
use kr_protocol::scalars::{Digest256, Uuid};
use kr_shell_integration::host::command::{InvocationContext, Resolution, resolve};
use kr_worker::broker::Broker;
use kr_worker::broker::adoption::{Adoptions, Foreground};
use kr_worker::broker::catalogue::{Admissions, testing};
use kr_worker::broker::connectors::{ConnectorSource, ConnectorSources};
use kr_worker::persistence::JournalHealth;

/// The variable that makes a placed copy of this binary the stand-in program: it sleeps for as
/// many seconds as it names.
const STAND_IN: &str = "KR_BUNDLED_STAND_IN";

/// How long a test waits for something that should happen promptly, before it calls it a failure.
const LIVENESS: Duration = Duration::from_secs(60);

/// The six agents' command names, as the shipped adapters recognise them.
const AGENT_COMMANDS: [&str; 6] = ["claude", "codex", "gemini", "qodercli", "opencode", "kimi"];

/// What a person types after an agent's name.
const AFTER_THE_NAME: [&str; 4] = ["--exact", "the_stand_in_program", "--test-threads", "1"];

/// What the integration decides for `command` typed at a managed root shell's prompt, under the
/// configuration a seeded host starts with: no command integration is installed.
fn decided(command: &str) -> (Vec<String>, Resolution) {
    let line: Vec<String> = std::iter::once(command)
        .chain(AFTER_THE_NAME)
        .map(str::to_owned)
        .collect();
    let resolution = resolve(
        &[],
        InvocationContext {
            managed_root_shell: true,
            interactive: true,
        },
        &line,
    );
    (line, resolution)
}

/// The stand-in program's body. Run by the test harness with nothing set, it does nothing.
#[test]
fn the_stand_in_program() {
    if let Ok(seconds) = std::env::var(STAND_IN) {
        std::thread::sleep(Duration::from_secs(seconds.parse().unwrap_or(60)));
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// The directory the shipped repository keeps its packages in.
fn shipped() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bundled-plugins/targets/packages/kalareach")
}

/// The shipped packages as an installation hands them to the worker under the seed's grant: the
/// release the repository ships of each, with the ceiling's three capabilities granted and no
/// native bridge put in place and no executable qualified.
fn bundled() -> Vec<(String, ConnectorSource)> {
    let mut packages = Vec::new();
    for entry in std::fs::read_dir(shipped()).expect("the shipped repository reads") {
        let name = entry
            .expect("a package directory")
            .file_name()
            .to_string_lossy()
            .into_owned();
        let releases: Vec<_> = std::fs::read_dir(shipped().join(&name))
            .expect("the package's releases read")
            .collect::<Result<_, _>>()
            .expect("the release directories read");
        assert_eq!(
            releases.len(),
            1,
            "the shipped repository holds one release of {name}"
        );
        let release = releases[0].path();
        let manifest = std::fs::read(release.join("plugin.json")).expect("the manifest reads");
        packages.push((
            name,
            ConnectorSource {
                package_digest: Digest256::from_bytes(kr_cbor::sha256(&manifest)),
                package_dir: release,
                bridge: None,
                granted: [
                    PluginCapability::MetadataMatch,
                    PluginCapability::DeclarativePresentation,
                    PluginCapability::BrokerSemanticEvents,
                ]
                .into_iter()
                .collect(),
                qualified: Vec::new(),
            },
        ));
    }
    packages.sort_by(|left, right| left.0.cmp(&right.0));
    packages
}

/// A host tree with the shipped packages admitted, and one session's adoptions on a broker of its
/// own.
struct Setup {
    host: kr_ipc::testing::TempHost,
    broker: Arc<Broker>,
    adoptions: Adoptions,
    packages: Vec<(String, ConnectorSource)>,
}

impl Setup {
    /// Admits every shipped package.
    fn new() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        let packages = bundled();
        let admitted: Vec<_> = packages
            .iter()
            .map(|(_, source)| testing::admitted(source))
            .collect();
        let _ = testing::admit(
            &Admissions::new(),
            &ConnectorSources::new(),
            &broker,
            admitted,
            1,
        );
        let adoptions = Adoptions::new(Arc::clone(&broker), host.environment_id());
        Self {
            host,
            broker,
            adoptions,
            packages,
        }
    }

    /// The digest of the shipped package named `name`.
    fn digest_of(&self, name: &str) -> Digest256 {
        self.packages
            .iter()
            .find(|(package, _)| package == name)
            .unwrap_or_else(|| panic!("the shipped repository has no {name}"))
            .1
            .package_digest
    }

    /// Places the stand-in as `command` and starts it as this process's own child, in a process
    /// group of its own, with the arguments the integration decided it runs with.
    fn typed(&self, command: &str, arguments: &[String]) -> (Typed, PathBuf) {
        let bin = self.host.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        let program = bin.join(command);
        kr_ipc::testing::place_program(
            &std::env::current_exe().expect("this test's own binary"),
            &program,
        );
        let child = Command::new(&program)
            .args(arguments)
            .env(STAND_IN, "60")
            .current_dir(self.host.root())
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the stand-in starts");
        (Typed(child), program)
    }

    /// Looks until the stand-in is adopted: a program at a new path can take a while to start.
    fn adopt(&self, foreground: &Foreground) -> Vec<AgentInstanceSummary> {
        let started = std::time::Instant::now();
        loop {
            let told = self.adoptions.look(foreground);
            if !told.is_empty() || started.elapsed() > LIVENESS {
                return told;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A running stand-in, ended when it goes out of scope.
struct Typed(Child);

impl Drop for Typed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The foreground of a session whose root shell has just started `typed`, answering its line with
/// the bypass the integration decided.
fn foreground(typed: &Typed, program: &Path, bypass: CommandBypassReason) -> Foreground {
    Foreground {
        group: i32::try_from(typed.0.id()).expect("a process identifier"),
        root_shell: kr_ipc::identity::current_process_start_identity().expect("this process"),
        answered: vec![(program.display().to_string(), Some(bypass))],
    }
}

/// KR-REQ-01.06, KR-REQ-12.23: under the configuration a seeded host starts with, each of the six
/// agents' names typed at a managed root shell's prompt is run as it was typed.
///
/// The decision is the integration's own (`resolve`), given the line `<name> --exact
/// the_stand_in_program --test-threads 1` and the entries a seeded host gives a session, which are
/// none: the invocation is bypassed as not integrated, and the command and the argument vector it
/// will run are the ones typed, with nothing added. That is the native terminal route every bundled
/// agent has by default.
#[test]
fn each_agent_name_typed_under_the_default_configuration_is_run_as_typed() {
    for command in AGENT_COMMANDS {
        let (line, resolution) = decided(command);
        assert_eq!(
            resolution,
            Resolution::Bypassed {
                command: command.to_owned(),
                arguments: line,
                reason: CommandBypassReason::NotIntegrated,
            },
            "{command}"
        );
        assert!(!resolution.establishes_backend(), "{command}");
    }
}

/// KR-REQ-12.23, KR-REQ-01.06: under the configuration a seeded host starts with, Claude Code,
/// Codex, Gemini CLI and Qoder CLI, typed by their command names, run as the person's own programs
/// with the vector they typed and are found running as native terminal instances of the bundled
/// package that recognises each.
///
/// What each is found as is the whole of what the worker does with it: the line was answered, by
/// the integration's own decision, that the command is not integrated; the instance is in the native
/// terminal mode; no backend, launch
/// record or registration stands behind it, and its bridges are refused; it is bound to the
/// bundled adapter, which holds the observation the ceiling gives it and no right to act. Nothing
/// of the adapter changes the program, its name or its arguments.
///
/// Not claimed: OpenCode and Kimi Code CLI. The bundled repository ships two adapters that
/// recognise `opencode` exactly and two that recognise `kimi`, and the worker adopts a program
/// that two adapters recognise exactly by neither, so what it makes of those two commands is a
/// fault of the catalogue and is not asserted here.
#[test]
fn the_bundled_agents_with_one_adapter_that_recognises_them_run_as_typed_and_are_found_as_native_terminals()
 {
    let setup = Setup::new();
    for (command, package) in [
        ("claude", "claude-code"),
        ("codex", "codex"),
        ("gemini", "gemini-cli"),
        ("qodercli", "qoder-cli"),
    ] {
        let (line, resolution) = decided(command);
        let Resolution::Bypassed {
            arguments, reason, ..
        } = resolution
        else {
            panic!("{command} is run as typed under the default configuration");
        };
        assert_eq!(arguments, line, "{command}: the vector as typed");
        let (typed, program) = setup.typed(command, &arguments[1..]);
        let told = setup.adopt(&foreground(&typed, &program, reason));
        assert_eq!(told.len(), 1, "{command} is found running: {told:?}");
        let summary = &told[0];
        assert_eq!(
            summary.mode,
            IntegrationMode::NativeTerminal,
            "{command}: the native terminal's mode"
        );
        assert_eq!(
            summary.bypass.as_ref(),
            Some(&CommandBypassReason::NotIntegrated),
            "{command}: its line was answered that it is not integrated"
        );
        assert!(
            summary.refusal.as_ref().is_some(),
            "{command}: none of its bridges is admitted"
        );
        let instance = summary.application_instance_id;
        assert_eq!(
            summary.plugin_id.as_ref().map(ToString::to_string),
            Some(format!("kalareach/{package}")),
            "{command}: the adapter that recognises it"
        );
        let process = kr_ipc::identity::process_start_identity(typed.0.id())
            .expect("the stand-in is identified");
        assert!(
            !setup.broker.holds_process(&process),
            "{command}: no launch stands behind it"
        );
        let profile = setup
            .broker
            .profile_of(instance)
            .expect("the profile it was observed running");
        assert_eq!(
            profile.mode,
            IntegrationMode::NativeTerminal,
            "{command}: recorded as the native terminal"
        );
        assert!(
            profile
                .binary
                .resolved_path
                .ends_with(&format!("/{command}")),
            "{command}: the program the person has, not another: {}",
            profile.binary.resolved_path
        );
        assert_eq!(
            profile.arguments.get(1..),
            Some(
                &[
                    "--exact".to_owned(),
                    "the_stand_in_program".to_owned(),
                    "--test-threads".to_owned(),
                    "1".to_owned()
                ][..]
            ),
            "{command}: the vector as typed, with nothing added"
        );
        let bound = setup
            .broker
            .live_bindings()
            .into_iter()
            .find(|live| live.application_instance_id == instance)
            .unwrap_or_else(|| panic!("{command} is bound to its adapter"));
        assert_eq!(
            bound.release.package_digest,
            setup.digest_of(package),
            "{command}: bound to the shipped {package}"
        );
        let grants = setup
            .broker
            .binding_record(bound.binding_id)
            .expect("the binding is live")
            .grants;
        assert!(
            grants.holds(BrokerGrant::Observation),
            "{command}: the adapter observes what the ceiling lets it"
        );
        for acting in [
            BrokerGrant::UpstreamAction,
            BrokerGrant::ApprovalInterpreter,
        ] {
            assert!(
                !grants.holds(acting),
                "{command}: no control surface the ceiling does not give: {acting:?}"
            );
        }
    }
}
