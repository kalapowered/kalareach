//! The daemon binary seeds its catalogue from the generation compiled into it.
//!
//! KR-REQ-04.15, KR-REQ-12.01: a fresh installation has the bundled adapters' packages installed
//! with no repository enrolled and nothing fetched. A build with debug assertions trusts the
//! development lineage's root, which anybody can sign with, so its daemon seeds only when it is
//! started with `--seed` and a test that starts it and expects an empty catalogue is not changed
//! by it. A shipped build seeds always and refuses the bundle until a production root exists; the
//! release-profile case of `kr-plugin-catalogue`'s `seed` suite covers that refusal.
//!
//! The real daemon binary runs here, so the call the binary makes after `Controller::start` and
//! before it binds a client endpoint is what the cases exercise.

#![cfg(all(unix, debug_assertions))]

mod net_support;

use kr_protocol::catalogue::{PluginListParams, PluginListResult};
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::method::Method;

/// The daemon binary this test launches, and the process it becomes.
struct Daemon(Option<std::process::Child>);

impl Daemon {
    /// Starts the daemon binary, copied to the internal disk, on `host`'s own directories. It is
    /// started with `--seed` when `seed` says so, and with nothing else that selects a catalogue.
    fn start(program: &std::path::Path, host: &kr_ipc::testing::TempHost, seed: bool) -> Self {
        let home = host.root().join("home");
        std::fs::create_dir_all(&home).expect("a home directory");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(host.root().join("daemon.log"))
            .expect("opens the daemon's log");
        let mut command = std::process::Command::new(program);
        command
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
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log);
        if seed {
            command.arg("--seed");
        }
        Self(Some(command.spawn().expect("the daemon starts")))
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

/// What the daemon on `host` answers for its diagnostics and its installed plugins, once it
/// answers at all: the client endpoint is bound after the seed, so an answer is an answer after it.
async fn answers(host: &kr_ipc::testing::TempHost) -> (HostDoctorResult, PluginListResult) {
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut client = loop {
        if let Ok(client) = kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            net_support::build(),
        )
        .await
        {
            break client;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not answer within two minutes; its log says: {}",
            std::fs::read_to_string(host.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let doctor: HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a doctor result");
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
    (doctor, plugins)
}

/// KR-REQ-04.15, KR-REQ-12.01: the daemon started with `--seed` has enrolled the official
/// repository from the bundle and installed every bundled package from it, each with nothing
/// granted, and its doctor says where the generation came from; the same daemon started without
/// it has no catalogue at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_seeds_its_catalogue_from_the_bundle_only_when_started_with_seed() {
    let bundle =
        kr_plugin_catalogue::SeedBundle::embedded().expect("the committed bundle is whole");

    let seeded = kr_ipc::testing::TempHost::create();
    let program = seeded.root().join("kr-controller");
    kr_ipc::testing::place_program(
        std::path::Path::new(env!("CARGO_BIN_EXE_kr-controller")),
        &program,
    );
    let _daemon = Daemon::start(&program, &seeded, true);
    let (doctor, plugins) = answers(&seeded).await;

    assert_eq!(plugins.plugins.len(), bundle.packages().len());
    for plugin in &plugins.plugins {
        assert_eq!(plugin.catalogue_id, "official", "{plugin:?}");
        assert!(plugin.enabled, "{plugin:?}");
    }
    let catalogue = doctor
        .checks
        .iter()
        .find(|check| check.id() == "catalogue")
        .expect("the catalogue check");
    // The doctor states a repository's name and message by class and length only, so the message
    // the host composed is checked by its length: the generation the repository activated, and
    // where the bundled one came from.
    let source = &bundle.lock().source;
    let message = format!(
        "generation {generation} activated, seeded from the bundled generation {generation} of {} \
         at commit {}",
        source.repository,
        &source.commit[..12],
        generation = source.generation.get(),
    );
    assert!(
        catalogue
            .detail()
            .contains(&format!("[message withheld, {} bytes]", message.len())),
        "{catalogue:?}"
    );
    assert_ne!(
        catalogue.status,
        DoctorStatus::NotApplicable,
        "{catalogue:?}"
    );

    let bare = kr_ipc::testing::TempHost::create();
    let program = bare.root().join("kr-controller");
    kr_ipc::testing::place_program(
        std::path::Path::new(env!("CARGO_BIN_EXE_kr-controller")),
        &program,
    );
    let _daemon = Daemon::start(&program, &bare, false);
    let (doctor, plugins) = answers(&bare).await;

    assert!(plugins.plugins.is_empty(), "{plugins:?}");
    let catalogue = doctor
        .checks
        .iter()
        .find(|check| check.id() == "catalogue")
        .expect("the catalogue check");
    assert_eq!(
        catalogue.status,
        DoctorStatus::NotApplicable,
        "{catalogue:?}"
    );
}
