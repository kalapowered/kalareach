//! What a host seeded from the bundled catalogue does with the six bundled agents until its owner
//! says otherwise.
//!
//! Section 12 ships the native terminal route for every bundled agent: Codex, Claude Code,
//! OpenCode, Gemini CLI, Kimi Code CLI and Qoder CLI each have an adapter installed, and an
//! agent's command integration, the opt-in that puts a worker-owned backend in front of the native
//! program, applies only where the owner turned it on and confirmed what it does. The real daemon
//! binary runs here, started with `--seed` on a tree of its own, and is asked what it reports.

#![cfg(all(unix, debug_assertions))]

mod net_support;

use kr_protocol::broker::IntegrationMode;
use kr_protocol::catalogue::{PluginAdmission, PluginListParams, PluginListResult};
use kr_protocol::hostinfo::{CommandIntegrationState, HostDoctorResult};
use kr_protocol::method::Method;

/// The packages the six bundled agents are shipped as.
const BUNDLED_AGENTS: [&str; 6] = [
    "kalareach/codex",
    "kalareach/claude-code",
    "kalareach/opencode",
    "kalareach/gemini-cli",
    "kalareach/kimi-code-cli",
    "kalareach/qoder-cli",
];

/// The daemon binary this test launches, and the process it becomes.
struct Daemon(Option<std::process::Child>);

impl Daemon {
    /// Starts the daemon binary, copied to the internal disk, on `host`'s own directories, seeded
    /// from the bundle and with nothing else that selects a catalogue or turns an integration on.
    fn start(program: &std::path::Path, host: &kr_ipc::testing::TempHost) -> Self {
        let home = host.root().join("home");
        std::fs::create_dir_all(&home).expect("a home directory");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(host.root().join("daemon.log"))
            .expect("opens the daemon's log");
        let child = std::process::Command::new(program)
            .current_dir(host.root())
            .env("HOME", &home)
            .arg("--runtime-dir")
            .arg(host.root().join("r"))
            .arg("--state-dir")
            .arg(host.root().join("s"))
            .arg("--worker")
            .arg(host.root().join("no-such-worker"))
            .arg("--secret-store")
            .arg("file")
            .arg("--seed")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        Self(Some(child))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A client of the daemon on `host`, once it answers at all: the client endpoint is bound after
/// the seed, so an answer is an answer after it.
async fn connected(host: &kr_ipc::testing::TempHost) -> kr_ipc::client::LocalClient {
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        if let Ok(client) = kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            net_support::build(),
        )
        .await
        {
            return client;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not answer within two minutes; its log says: {}",
            std::fs::read_to_string(host.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// KR-REQ-12.23: a host seeded from the bundled catalogue has an adapter installed and admitted for
/// each of the six bundled agents, and no agent's command integration is on: every integration the
/// admitted releases declare reports that an invocation runs in the native terminal's mode, and the
/// owner has not been asked for, or given, the grant that would change it.
///
/// This is the host's half of the clause, with the real daemon binary: that the adapter is shipped
/// and that nothing about it changes how the person's own command runs. The manifest half is the
/// plugins repository's own check of every bundled adapter, and the typed command's launch under
/// the shell is the worker's (`bundled_agents` in its suite).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seeded_host_ships_every_bundled_agents_adapter_and_leaves_every_command_on_the_native_terminal()
 {
    let host = kr_ipc::testing::TempHost::create();
    let program = host.root().join("kr-controller");
    kr_ipc::testing::place_program(
        std::path::Path::new(env!("CARGO_BIN_EXE_kr-controller")),
        &program,
    );
    let _daemon = Daemon::start(&program, &host);
    let mut client = connected(&host).await;
    let plugins: PluginListResult = client
        .request(
            Method::PluginList,
            &PluginListParams {
                environment_id: host.environment_id(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("plugin.list is served on the local socket")
        .to_typed()
        .expect("a plugin list");
    for agent in BUNDLED_AGENTS {
        let installed = plugins
            .plugins
            .iter()
            .find(|plugin| plugin.plugin_id.as_str() == agent)
            .unwrap_or_else(|| panic!("{agent} is not installed on a seeded host"));
        assert!(installed.enabled, "{agent} is installed and disabled");
        assert_eq!(
            installed.admission.0,
            Some(PluginAdmission::Admitted),
            "{agent}: new bindings may use the adapter"
        );
    }

    let doctor: HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a doctor result");
    assert!(
        !doctor.command_integrations.is_empty(),
        "the bundled releases declare command integrations, and the doctor reports them"
    );
    for report in &doctor.command_integrations {
        assert_ne!(
            report.state,
            CommandIntegrationState::On,
            "{}: nothing turned its integration on",
            report.plugin_id
        );
        assert_eq!(
            report.mode,
            IntegrationMode::NativeTerminal,
            "{}: an invocation of its command runs as the person typed it",
            report.plugin_id
        );
    }
}
