//! The command integrations a session is launched with, filled in by the control daemon.
//!
//! A real daemon with a real catalogue: a Gemini CLI connector package, the worker's own test
//! package of that shape, published in a signed generation and installed with its integration's
//! grant confirmed, and the environment's configuration naming it or not. This process plays the
//! worker the daemon asks for, so the launch specification a worker is handed is read as it
//! arrives. The package is published for Linux and macOS, so the suite runs on Unix hosts.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a session is launched with an entry for each integration installed, confirmed and admitted, on where the configuration turns it on and off where it does not; a create request naming one is refused before anything is reserved |
//! | KR-REQ-07.45 | the doctor reports each integration: its package, command, flags and variables, what a new session gets of it and why, the mode an invocation runs in, and the executable the daemon's search path names with the version a signed record gives it |

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, Change, Enrolment, InstallationGrant, Owner, RepositoryId,
    RepositoryKind,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, PluginId, SessionEpoch};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    CommandIntegration, LaunchProfile, Presentation, SessionCreateParams, ShellMode,
};
use kr_protocol::worker::WorkerLaunchSpec;
use kr_worker::broker::connectors::fixture;

/// The catalogue's own builder of signed generations.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// How long the test waits for what the daemon does by itself.
const PATIENCE: Duration = Duration::from_secs(20);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn gemini() -> PluginId {
    PluginId::new("kalareach/gemini-cli").expect("a plugin identifier")
}

/// A supervisor that starts nothing and reports this process as the worker it started, so this
/// process can perform the worker's side of the rendezvous.
#[derive(Debug)]
struct RendezvousSupervisor {
    launched: std::sync::Mutex<std::sync::mpsc::Sender<WorkerLaunch>>,
}

impl WorkerSupervisor for RendezvousSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let _ = self
            .launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(launch.clone());
        LaunchOutcome::Started(
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        )
    }

    fn describe(&self) -> &'static str {
        "a supervisor that hands the rendezvous to this process"
    }
}

/// A daemon whose environment has the Gemini CLI package installed, enabled and granted.
struct Daemon {
    _temp: kr_ipc::testing::TempHost,
    _generation_home: tempfile::TempDir,
    client_endpoint: kr_ipc::paths::Endpoint,
    rendezvous_endpoint: kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    launches: std::sync::mpsc::Receiver<WorkerLaunch>,
    controller: Arc<Controller>,
}

/// Starts a daemon whose environment has the package installed, with its configuration turning on
/// the command integrations of `enabled`, or saying nothing of them where `enabled` is none.
async fn daemon(enabled: Option<&[&str]>) -> Daemon {
    daemon_declaring(enabled, &[]).await
}

/// Starts a daemon as [`daemon`] does, whose package's integration declares `flags`.
async fn daemon_declaring(enabled: Option<&[&str]>, flags: &[&str]) -> Daemon {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    environment.create().expect("the environment's directories");

    // The package, published in a signed generation of its own.
    let written = temp.root().join("written");
    let source = fixture::package(
        &written,
        &temp.root().join("bin").join("kr-hook"),
        &fixture::Shape::gemini_cli(flags),
    )
    .expect("the package is written");
    let generation_home = tempfile::tempdir().expect("a directory on the internal disk");
    let generation = generations::Generation::build(
        generation_home.path(),
        generations::GenerationSpec {
            package: Some(source.package_dir.clone()),
            ..generations::GenerationSpec::default()
        },
    )
    .await;

    // Enrolled, synchronised and installed with every capability it asks for, the integration's
    // among them, on the owner's confirmation of this exact installation.
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
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&gemini(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install_with(
            &id,
            environment_id,
            &gemini(),
            &version,
            digest,
            InstallationGrant::with([
                PluginCapability::UpstreamAction,
                PluginCapability::ApprovalDecode,
                PluginCapability::ApprovalRespond,
                PluginCapability::CommandIntegrationLaunch,
            ]),
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment_id, &gemini(), true)
        .await
        .expect("enabled");
    drop(catalogue);

    if let Some(enabled) = enabled {
        let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
        document.preferences.command_integrations =
            Nullable::some(enabled.iter().map(|plugin| (*plugin).to_owned()).collect());
        let path = kr_protocol::hostinfo::configuration::document_path(
            environment.state_dir(),
            environment.state_root(),
            environment_id,
        );
        std::fs::create_dir_all(path.parent().expect("a directory")).expect("its directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the configuration is written");
    }

    let secrets = environment.secrets_dir();
    let (launched, launches) = std::sync::mpsc::channel();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RendezvousSupervisor {
            launched: std::sync::Mutex::new(launched),
        }),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let client_endpoint = environment.controller_endpoint().expect("an endpoint");
    tokio::spawn(
        Arc::clone(&controller)
            .serve_clients(Listener::bind(&client_endpoint).expect("binds the client endpoint")),
    );
    let rendezvous_endpoint = environment.rendezvous_endpoint().expect("an endpoint");
    tokio::spawn(Arc::clone(&controller).serve_rendezvous(
        Listener::bind(&rendezvous_endpoint).expect("binds the rendezvous endpoint"),
    ));
    Daemon {
        _temp: temp,
        _generation_home: generation_home,
        client_endpoint,
        rendezvous_endpoint,
        environment_id,
        launches,
        controller,
    }
}

/// A create request with `launch_profile`, for an invisible session.
fn create(environment_id: EnvironmentId, launch_profile: LaunchProfile) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile,
        terminal: Nullable::null(),
    }
}

fn target(environment_id: EnvironmentId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// Creates a session through the daemon, performs the worker's side of its rendezvous, and returns
/// the launch specification the daemon hands the worker.
async fn launched(daemon: &Daemon) -> WorkerLaunchSpec {
    launched_from(
        daemon,
        create(daemon.environment_id, LaunchProfile::default()),
    )
    .await
}

/// Creates a session through the daemon from `request`, as [`launched`] does.
async fn launched_from(daemon: &Daemon, request: SessionCreateParams) -> WorkerLaunchSpec {
    let creating = tokio::spawn({
        let endpoint = daemon.client_endpoint.clone();
        let environment_id = daemon.environment_id;
        async move {
            let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            client
                .mutate(
                    Method::SessionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    target(environment_id),
                    &request,
                )
                .await
        }
    });
    let launch = daemon
        .launches
        .recv_timeout(PATIENCE)
        .expect("the daemon asks for a worker");
    let identity = WorkerIdentity::generate(
        launch.session_id,
        SessionEpoch::V1,
        kr_ipc::identity::boot_identity().expect("a boot identity"),
        kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        PROTOCOL_VERSION,
    )
    .expect("a session key");
    let connection = kr_ipc::endpoint::Connection::connect(&daemon.rendezvous_endpoint)
        .await
        .expect("connects to the rendezvous");
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build(),
            client: LocalClientKind::Worker,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
            origin: None,
        }))
        .await
        .expect("writes the hello");
    let acknowledgement: ControlFrame = reader.read_message().await.expect("the daemon answers");
    assert!(
        matches!(acknowledgement, ControlFrame::HelloAck(_)),
        "the daemon acknowledges the worker: {acknowledgement:?}"
    );
    writer
        .write_message(&ControlFrame::Rendezvous(
            identity
                .rendezvous(launch.reservation_id)
                .expect("a startup claim"),
        ))
        .await
        .expect("writes the startup claim");
    let specification: ControlFrame = tokio::time::timeout(PATIENCE, reader.read_message())
        .await
        .expect("the daemon answers in time")
        .expect("the daemon answers");
    let ControlFrame::LaunchSpec(specification) = specification else {
        panic!("the daemon sends a launch specification: {specification:?}");
    };
    // This process is not going on to run a session, so the create is not waited for.
    creating.abort();
    *specification
}

/// The entry the Gemini CLI package's integration gives a session.
fn gemini_entry(enabled: bool) -> CommandIntegration {
    CommandIntegration {
        plugin_id: gemini(),
        command: "gemini".to_owned(),
        flags: Vec::new(),
        enabled,
    }
}

/// KR-REQ-12.07: a session is launched with an entry for the installed package's integration, on,
/// because the environment's configuration turns it on: the package, its command and the flags its
/// verified manifest declares, which for Gemini CLI are none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_07_a_session_gets_the_integration_its_configuration_turns_on() {
    let daemon = daemon(Some(&["kalareach/gemini-cli"])).await;
    let specification = launched(&daemon).await;
    assert_eq!(
        specification.create.launch_profile.command_integrations,
        [gemini_entry(true)]
    );
}

/// KR-REQ-12.07: an installed integration the configuration does not turn on is carried off, so an
/// invocation of its command is answered as a disabled integration and runs as typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_07_an_integration_the_configuration_leaves_off_is_carried_off() {
    for enabled in [None, Some(&["kalareach/claude-code"][..])] {
        let daemon = daemon(enabled).await;
        let specification = launched(&daemon).await;
        assert_eq!(
            specification.create.launch_profile.command_integrations,
            [gemini_entry(false)],
            "{enabled:?}"
        );
    }
}

/// KR-REQ-12.07: a create request that names a command integration is refused before anything is
/// reserved or started: a session's integrations are its environment's to choose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_07_a_create_request_that_names_an_integration_is_refused() {
    let daemon = daemon(Some(&["kalareach/gemini-cli"])).await;
    let mut client = LocalClient::connect(&daemon.client_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target(daemon.environment_id),
            &create(
                daemon.environment_id,
                LaunchProfile {
                    command_integrations: vec![gemini_entry(true)],
                    ..LaunchProfile::default()
                },
            ),
        )
        .await
        .expect("reaches the daemon")
        .expect_err("a request names no command integration");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(
        daemon.launches.try_recv().is_err(),
        "nothing was started for it"
    );
}

/// The daemon's diagnostics, as `kr doctor` reads them.
async fn doctor(daemon: &Daemon) -> kr_protocol::hostinfo::HostDoctorResult {
    let mut client = LocalClient::connect(&daemon.client_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    client
        .request(Method::HostDoctor, &())
        .await
        .expect("reaches the daemon")
        .expect("the diagnostics")
        .to_typed()
        .expect("the diagnostics decode")
}

/// KR-REQ-07.45: the doctor reports the installed integration the configuration turns on: its
/// package and release, its command, its flags and its variables, and why no session created now
/// could launch through it here, which for this daemon is its worker with no launcher beside it;
/// so its command runs as typed, on the native terminal. A package the configuration names that is
/// not installed is reported too, and the check says the configuration asks for what cannot apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_07_45_the_doctor_reports_each_integration_and_what_a_new_session_gets() {
    use kr_protocol::hostinfo::{
        CommandIntegrationState, CommandIntegrationUnavailable, DoctorStatus,
    };

    let daemon = daemon(Some(&["kalareach/gemini-cli", "kalareach/claude-code"])).await;
    let result = doctor(&daemon).await;
    let reported: Vec<(String, CommandIntegrationState)> = result
        .command_integrations
        .iter()
        .map(|report| (report.plugin_id.clone(), report.state))
        .collect();
    assert_eq!(
        reported,
        [
            (
                "kalareach/claude-code".to_owned(),
                CommandIntegrationState::NotInstalled
            ),
            (
                "kalareach/gemini-cli".to_owned(),
                CommandIntegrationState::On
            ),
        ]
    );
    let gemini = &result.command_integrations[1];
    assert_eq!(gemini.version.0.as_deref(), Some("0.3.0"));
    assert_eq!(gemini.command.0.as_deref(), Some("gemini"));
    assert!(gemini.flags.is_empty());
    assert_eq!(
        gemini.variables,
        [kr_protocol::session::EnvironmentVariable {
            name: "GEMINI_CLI_NO_RELAUNCH".to_owned(),
            value: "true".to_owned(),
        }]
    );
    assert_eq!(
        gemini.unavailable.0,
        Some(CommandIntegrationUnavailable::NoLauncher),
        "this daemon's worker has no launcher beside it"
    );
    assert_eq!(
        gemini.mode,
        kr_protocol::broker::IntegrationMode::NativeTerminal
    );
    let check = result
        .checks
        .iter()
        .find(|check| check.id() == "command-integrations")
        .expect("the command integrations are checked");
    assert_eq!(check.status, DoctorStatus::Warning);
}

/// KR-REQ-11.42: the doctor's answer carries the check of the native bridges. A host whose
/// packages have put none in place says that nothing applies, rather than leaving the row out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_42_the_doctor_carries_the_check_of_the_native_bridges() {
    use kr_protocol::hostinfo::DoctorStatus;

    let daemon = daemon(None).await;
    let result = doctor(&daemon).await;
    let check = result
        .checks
        .iter()
        .find(|check| check.id() == "native-bridges")
        .expect("the native bridges are checked");
    assert_eq!(check.status, DoctorStatus::NotApplicable, "{check:?}");
}

/// Sixteen flags of the most bytes a flag may have: the most a package may declare.
fn largest_flags() -> Vec<String> {
    (0..kr_plugin_sdk::integration::MAX_FLAGS)
        .map(|index| {
            format!(
                "--{index}{}",
                "x".repeat(kr_plugin_sdk::integration::MAX_FLAG_BYTES - 4)
            )
        })
        .collect()
}

/// KR-REQ-12.07: a session whose integrations its launch specification cannot carry beside the
/// person's own create request is launched without them rather than not at all, and the doctor's
/// catalogue check names the session and every integration it was launched without.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_07_a_launch_without_room_for_an_integration_is_named_for_the_doctor() {
    let flags = largest_flags();
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let daemon = daemon_declaring(Some(&["kalareach/gemini-cli"]), &flags).await;
    // A create request that one frame carries, with less room beside it than the integration takes.
    let mut request = create(daemon.environment_id, LaunchProfile::default());
    request.environment_snapshot = (0..245)
        .map(|index| kr_protocol::session::EnvironmentVariable {
            name: format!("FILLER_{index}"),
            value: "x".repeat(4_000),
        })
        .collect();
    let specification = launched_from(&daemon, request).await;
    assert!(
        specification
            .create
            .launch_profile
            .command_integrations
            .is_empty(),
        "the integration did not fit"
    );
    let warnings = daemon.controller.catalogue_warnings().await;
    assert!(
        warnings.iter().any(|warning| {
            warning.contains(&specification.session_id.to_string())
                && warning.contains("kalareach/gemini-cli")
        }),
        "{warnings:?}"
    );
}
