//! The control daemon's plugin admissions at the worker's endpoint.
//!
//! A snapshot of admissions arrives in parts on the daemon's authority connection and is applied
//! whole, inside the authority's own boundary. Its packages are read and checked before that
//! boundary is taken, so a read that stalls holds its own snapshot and nothing a replacement of the
//! authority needs; and a snapshot whose connection was replaced while its packages were read
//! publishes nothing. These tests use the real endpoint, the real handshake and the real
//! signatures, because that is where a replacement either lands or does not.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::admission::{
    AdmittedPackage, FrameId, PluginAdmissions, ReleaseOrigin, RevocationPolicy,
};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{BuildId, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::connectors::{ConnectorSource, fixture};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// The time each part of an exchange has in these tests.
const PER_PART: Duration = Duration::from_secs(5);

/// How long a replacement of the authority may take while a snapshot's reads are stalled: far
/// longer than it needs, and far shorter than the stall.
const REPLACEMENT: Duration = Duration::from_secs(5);

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A worker spawned by the daemon generation 1, serving its endpoint in this process.
async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("sleep 30"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        endpoint,
        controller,
        boot,
        environment_id,
    }
}

/// Connects as the daemon of `generation`, on the authority connection, and proves it.
async fn daemon(host: &Host, generation: u64) -> LocalClient {
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    client
}

fn frame(generation: u64, revision: u64, round: u64) -> FrameId {
    FrameId {
        generation: ControllerGeneration::new(generation),
        revision: U64::new(revision),
        round: U64::new(round),
    }
}

/// What an installation hands over for one package the fixture wrote.
fn admitted(source: &ConnectorSource) -> AdmittedPackage {
    AdmittedPackage {
        plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code").expect("an identifier"),
        publisher_id: kr_protocol::ids::PublisherId::new("kalareach").expect("an identifier"),
        version: "1.0.0".to_owned(),
        package_digest: source.package_digest,
        origin: ReleaseOrigin {
            repository_id: "official".to_owned(),
            enrolment_key: "0123456789abcdef0123456789abcdef".to_owned(),
        },
        package_dir: source.package_dir.display().to_string(),
        grants: source
            .granted
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        bridge: Nullable::null(),
        builds: Vec::new(),
        component: Nullable::null(),
    }
}

/// One snapshot at `frame`, in `parts` parts, with every package in the first.
fn snapshot(
    host: &Host,
    frame: FrameId,
    parts: u32,
    packages: Vec<AdmittedPackage>,
) -> Vec<PluginAdmissions> {
    let mut packages = Some(packages);
    (1..=parts)
        .map(|part| PluginAdmissions {
            environment_id: host.environment_id,
            frame,
            part,
            parts,
            policy: RevocationPolicy::WarnOnly,
            packages: packages.take().unwrap_or_default(),
            releases: Vec::new(),
        })
        .collect()
}

/// A package with a connector table, written on the internal disk.
fn package(root: &Path) -> ConnectorSource {
    fixture::claude_code_package(root, Path::new("/opt/kalareach/bin/kr-hook"))
        .expect("the package is written")
}

/// A snapshot whose package read stalls holds nothing a replacement of the authority needs: the
/// replacement completes while the read is stalled, the stalled snapshot then publishes nothing and
/// is refused, and the replacement's own snapshot applies.
///
/// The runtime has one thread, so a read that held it would hold everything the replacement needs
/// too: the listener, its connection and the timers. The bound on the replacement is therefore
/// kept by a thread of its own, which lets the reads go on once it has passed and says whether it
/// had to.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_stalled_package_read_holds_no_replacement_and_its_snapshot_publishes_nothing() {
    let host = host().await;
    let root = tempfile::tempdir().expect("a directory");
    let source = package(root.path());
    let admissions = Arc::clone(host.service.plugin_admissions());
    let (arrived, release) = admissions.pause_reads();

    let mut first = daemon(&host, 1).await;
    let stalled = snapshot(&host, frame(1, 1, 1), 1, vec![admitted(&source)]);
    let exchange = tokio::spawn(async move {
        first
            .exchange_admissions(stalled, Duration::from_secs(60))
            .await
    });
    tokio::task::spawn_blocking(move || arrived.recv())
        .await
        .expect("the wait ends")
        .expect("the snapshot's reads began");

    // A newer daemon takes the authority while the read is stalled, without waiting for it.
    let (replaced, watched) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        let late = watched.recv_timeout(REPLACEMENT).is_err();
        release.send(()).expect("the reads go on");
        late
    });
    let mut replacement = daemon(&host, 2).await;
    let _ = replaced.send(());
    assert!(
        !watchdog.join().expect("the watchdog ends"),
        "a stalled package read holds nothing the replacement needs"
    );
    let refused = exchange.await.expect("the exchange ends");
    assert!(
        refused.is_err(),
        "a snapshot whose connection was replaced is refused: {refused:?}"
    );
    assert_eq!(admissions.frame(), None, "nothing was published");
    assert!(
        host.service
            .connector_sources()
            .for_command(fixture::COMMAND)
            .is_none(),
        "no connector reached the command backends"
    );

    let report = replacement
        .exchange_admissions(
            snapshot(&host, frame(2, 1, 1), 1, vec![admitted(&source)]),
            PER_PART,
        )
        .await
        .expect("the authority's snapshot is applied");
    assert_eq!(report[0].frame, frame(2, 1, 1));
    assert_eq!(admissions.frame(), Some(frame(2, 1, 1)));
    assert!(
        host.service
            .connector_sources()
            .for_command(fixture::COMMAND)
            .is_some()
    );
}

/// A snapshot is applied only once every part has come: one whose connection ends part way applies
/// nothing, and the same snapshot sent whole on the next connection applies and is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_applies_only_whole_and_never_from_a_connection_that_ended_part_way() {
    let host = host().await;
    let root = tempfile::tempdir().expect("a directory");
    let source = package(root.path());
    let admissions = Arc::clone(host.service.plugin_admissions());
    let whole = snapshot(&host, frame(1, 1, 1), 2, vec![admitted(&source)]);

    let partial = daemon(&host, 1).await;
    let (reader, mut writer, _) = partial.into_halves();
    writer
        .write_message(&ControlFrame::PluginAdmissions(Box::new(whole[0].clone())))
        .await
        .expect("the first part is written");
    // Given the part time to arrive, and then the connection ends before the second part.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop((reader, writer));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(admissions.frame(), None, "a part applies nothing");

    let mut next = daemon(&host, 1).await;
    let report = next
        .exchange_admissions(whole, PER_PART)
        .await
        .expect("the whole snapshot is applied");
    assert_eq!(report[0].frame, frame(1, 1, 1));
    assert_eq!(admissions.frame(), Some(frame(1, 1, 1)));
}

/// Only the daemon's authority connection hands this worker admissions: a local client's snapshot
/// is refused by name and applies nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_authority_connection_hands_the_worker_admissions() {
    let host = host().await;
    let mut local = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let refused = local
        .exchange_admissions(snapshot(&host, frame(1, 1, 1), 1, Vec::new()), PER_PART)
        .await
        .expect_err("a local client hands over no admissions");
    assert!(
        refused.to_string().contains("authority connection"),
        "{refused}"
    );
    assert_eq!(host.service.plugin_admissions().frame(), None);
}
