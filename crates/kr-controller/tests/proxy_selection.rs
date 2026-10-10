//! The host's outbound HTTPS goes through the proxy its configuration document selects, and no
//! other.
//!
//! The daemon reads the selection once, when it starts, and every client takes that one reading:
//! the rendezvous it reserves locators at and opens its room at, and delivery, which carries
//! notifications to the gateway and webhook messages to the addresses an owner configured. With
//! none selected they go directly, and never through a proxy the environment names. Mail
//! submission is the one outbound connection outside this: it is SMTP, made directly.

mod net_support;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use connect_proxy::ConnectProxy;
use kr_controller::config::Outbound;
use kr_controller::push::transport::{DeliveryTransports, ManagedTransports};
use kr_controller::service::net::NetworkSetup;
use kr_controller::service::net::rendezvous::Rendezvous;
use kr_controller::service::net::rendezvous_https::HttpsRendezvous;
use kr_crypto::secret::SymmetricKey;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::InvitationId;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;

/// How long an exchange may take before the test gives up on it.
const WATCHDOG: Duration = Duration::from_secs(20);

/// A proxy address no test connects to: the daemon only reads it.
const NAMED_PROXY: &str = "http://proxy.example.com:3128";

/// KR-REQ-26.14: the proxy a daemon goes through is the one its document selected when it started,
/// none when the document names none, and an edit made while it runs applies at the next start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_goes_through_the_proxy_its_document_selected_when_it_started() {
    let unselected = kr_ipc::testing::TempHost::create();
    let controller = start_controller(&unselected.environment(), unselected.environment_id()).await;
    assert_eq!(
        controller.started_outbound().expect("a usable selection"),
        Outbound::Direct,
        "a document that names no proxy selects none, whatever the environment says"
    );
    drop(controller);

    let selected = kr_ipc::testing::TempHost::create();
    let environment = selected.environment();
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.network.proxy_url = Nullable::some(NAMED_PROXY.to_owned());
    write_document(&environment, &document);
    let controller = start_controller(&environment, selected.environment_id()).await;
    let named: ProxyUrl = NAMED_PROXY.parse().expect("a proxy address");
    assert_eq!(
        controller.started_outbound().expect("a usable selection"),
        Outbound::Through(named.clone())
    );

    document.revision = 2;
    document.network.proxy_url = Nullable::null();
    write_document(&environment, &document);
    assert_eq!(
        controller.started_outbound().expect("a usable selection"),
        Outbound::Through(named),
        "an edit made while the daemon runs applies at its next start"
    );
    drop(controller);
}

/// KR-REQ-26.14: a host that selects a proxy reserves its locator through it and opens its room
/// through it, as a `CONNECT` tunnel to the rendezvous; a proxy that refuses the tunnel leaves the
/// rendezvous unavailable rather than reached around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_reaches_its_rendezvous_through_the_proxy_it_selected() {
    let proxy = ConnectProxy::refusing(403).await;
    let rendezvous = HttpsRendezvous::new(Some(proxy.url.parse().expect("a proxy address")))
        .expect("the rendezvous client");
    let (origin, authority, service) = unreached();
    let origin = RendezvousOrigin::new(origin).expect("an origin");
    let locator = Locator::new("abcd").expect("a locator");

    let refused = tokio::time::timeout(
        WATCHDOG,
        rendezvous.reserve(
            &origin,
            &locator,
            InvitationId::new(Uuid::from_bytes([1; 16])),
            TimestampMs::new(1_764_003_600_000),
            Digest256::from_bytes([2; 32]),
        ),
    )
    .await
    .expect("the reservation ends")
    .expect_err("the proxy refuses the tunnel");
    assert_eq!(
        refused.code(),
        ErrorCode::RendezvousUnavailable,
        "{refused}"
    );

    let attached = tokio::time::timeout(
        WATCHDOG,
        rendezvous.attach(&origin, &locator, &SymmetricKey::from_bytes([3; 32])),
    )
    .await
    .expect("the attachment ends");
    let refused = attached.expect_err("the proxy refuses the tunnel");
    assert_eq!(
        refused.code(),
        ErrorCode::RendezvousUnavailable,
        "{refused}"
    );

    let tunnel = format!("CONNECT {authority} HTTP/1.1");
    assert_eq!(proxy.asked(), vec![tunnel.clone(), tunnel]);
    heard_nothing(&service);
}

/// KR-REQ-26.14: the rendezvous client a host's network setup builds from its document goes through
/// the proxy that document selects, as the endpoint does: its reservations, and its room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_network_setup_reaches_its_rendezvous_through_the_proxy_its_document_selects() {
    let proxy = ConnectProxy::refusing(403).await;
    let host = kr_ipc::testing::TempHost::create();
    let mut network = ConfigurationDocument::empty().network;
    network.enabled = Nullable::some(true);
    network.proxy_url = Nullable::some(proxy.url.clone());
    let setup = NetworkSetup::from_configuration(
        &network,
        &host.environment(),
        kr_crypto::store::StoreSelection::File,
    )
    .expect("a usable selection")
    .expect("a host on the network");
    let rendezvous = setup.rendezvous.expect("a rendezvous client");
    let (origin, authority, service) = unreached();
    let origin = RendezvousOrigin::new(origin).expect("an origin");
    let locator = Locator::new("abcd").expect("a locator");

    // A reservation blocks on the rendezvous client's own runtime, so it is made off this one.
    let reserving = std::sync::Arc::clone(&rendezvous);
    let (at, named) = (origin.clone(), locator.clone());
    let reserved = tokio::time::timeout(
        WATCHDOG,
        tokio::task::spawn_blocking(move || {
            reserving.reserve_locator(
                &at,
                &named,
                InvitationId::new(Uuid::from_bytes([1; 16])),
                TimestampMs::new(1_764_003_600_000),
                Digest256::from_bytes([2; 32]),
            )
        }),
    )
    .await
    .expect("the reservation ends")
    .expect("the reservation's thread");
    let refused = reserved.expect_err("the proxy refuses the tunnel");
    assert_eq!(
        refused.code(),
        ErrorCode::RendezvousUnavailable,
        "{refused}"
    );

    let attached = tokio::time::timeout(
        WATCHDOG,
        rendezvous.attach(&origin, &locator, &SymmetricKey::from_bytes([3; 32])),
    )
    .await
    .expect("the attachment ends");
    let refused = attached.expect_err("the proxy refuses the tunnel");
    assert_eq!(
        refused.code(),
        ErrorCode::RendezvousUnavailable,
        "{refused}"
    );

    let tunnel = format!("CONNECT {authority} HTTP/1.1");
    assert_eq!(proxy.asked(), vec![tunnel.clone(), tunnel]);
    heard_nothing(&service);
}

/// KR-REQ-26.14: delivery goes through the proxy the daemon started with. A webhook message to an
/// owner's address reaches the proxy, and the address hears nothing around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_goes_through_the_proxy_the_daemon_started_with() {
    let proxy = ConnectProxy::refusing(502).await;
    let transports = ManagedTransports::new(Outbound::Through(
        proxy.url.parse().expect("a proxy address"),
    ));
    let hook = listening();
    let port = hook.local_addr().expect("an address").port();
    let origin = format!("http://127.0.0.1:{port}");
    let transport = transports
        .to(&GatewayOrigin::new(origin.clone()).expect("a loopback origin"))
        .expect("a transport");
    let address = format!("{origin}/hook");
    let _ = tokio::time::timeout(WATCHDOG, transport.post_json(&address, b"{}", &[]))
        .await
        .expect("the message ends");
    assert_eq!(proxy.asked(), vec![format!("POST {address} HTTP/1.1")]);
    heard_nothing(&hook);
}

/// KR-REQ-26.13, KR-REQ-26.14: a daemon that starts over a configuration document it cannot use
/// leaves no route out. The proxy the document may have named is not known, and nothing goes
/// around it: the delivery the daemon attaches makes no transport, so a webhook address, which a
/// direct route would reach, hears nothing, and neither does the proxy named before. A document put
/// right afterwards changes nothing until the daemon starts again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_started_over_a_document_it_cannot_use_leaves_no_route_out() {
    let documents: Vec<(&str, Vec<u8>, u32)> = vec![
        (
            "a version it does not know",
            br#"{"version": 99}"#.to_vec(),
            0o600,
        ),
        (
            "a member the schema lacks",
            br#"{"version": 2, "not_a_member": 1}"#.to_vec(),
            0o600,
        ),
        ("a document too large", vec![b' '; 70_000], 0o600),
    ];
    for (what, bytes, mode) in documents.into_iter().chain(wider_than_owner_only()) {
        let proxy = ConnectProxy::refusing(502).await;
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let mut accepted = ConfigurationDocument::empty();
        accepted.revision = 1;
        accepted.network.proxy_url = Nullable::some(proxy.url.clone());
        // A daemon accepts the document that names the proxy, and stops.
        write_document(&environment, &accepted);
        let accepting = start_controller(&environment, host.environment_id()).await;
        assert_eq!(
            accepting.started_outbound().expect("a route"),
            Outbound::Through(proxy.url.parse().expect("a proxy address")),
            "{what}: the control: the document names the proxy"
        );
        drop(accepting);
        // The next daemon starts over a document it cannot use.
        write_bytes(&environment, &bytes, mode);
        let controller = start_controller(&environment, host.environment_id()).await;
        let Outbound::Closed(refusal) = controller.started_outbound().expect("a route") else {
            panic!("{what}: a document the daemon cannot use leaves a route");
        };
        assert!(
            refusal.contains("config.json") && refusal.contains("could not use"),
            "{what}: the refusal names the document: {refusal}"
        );
        assert!(
            controller
                .attach_managed_delivery()
                .expect("the shipped daemon attaches its delivery by this route"),
            "{what}: one transport is attached"
        );

        // The transport the catalogue fetches repositories through, asked for an address a direct
        // route would reach: it fetches nothing, and says why.
        let (repository, repository_authority, repository_listener) = unreached();
        let catalogue_transport = controller.catalogue().transport().clone();
        let refused = fetch_error(&catalogue_transport, &format!("{repository}/1.root.json"))
            .await
            .expect_err("the closed route fetches nothing");
        assert!(refused.contains("config.json"), "{what}: {refused}");
        heard_nothing(&repository_listener);

        // The transport the daemon attached, and not one the test builds: asked for an address a
        // direct route would reach, it makes none.
        let hook = listening();
        let origin = format!(
            "http://127.0.0.1:{}",
            hook.local_addr().expect("an address").port()
        );
        let attached = controller
            .delivery_runtime()
            .transports()
            .expect("the daemon attached a transport");
        let Err(refused) =
            attached.to(&GatewayOrigin::new(origin.clone()).expect("a loopback origin"))
        else {
            panic!("{what}: a transport reaches the address");
        };
        assert!(refused.contains("config.json"), "{what}: {refused}");
        heard_nothing(&hook);
        assert!(
            proxy.asked().is_empty(),
            "{what}: and the proxy named before hears nothing"
        );

        // Put right, the document changes nothing until the daemon starts again.
        write_document(&environment, &accepted);
        assert!(
            matches!(controller.started_outbound(), Ok(Outbound::Closed(_))),
            "{what}: a daemon takes its route when it starts"
        );
        drop(controller);
        let restarted = start_controller(&environment, host.environment_id()).await;
        assert_eq!(
            restarted.started_outbound().expect("a route"),
            Outbound::Through(proxy.url.parse().expect("a proxy address")),
            "{what}: and the next start takes the document's proxy"
        );
        // The control, through the transport the restarted daemon attached: the message goes to the
        // proxy and not around it.
        assert!(restarted.attach_managed_delivery().expect("attaches"));
        let transport = restarted
            .delivery_runtime()
            .transports()
            .expect("attached")
            .to(&GatewayOrigin::new(origin.clone()).expect("a loopback origin"))
            .expect("a transport through the proxy");
        let address = format!("{origin}/hook");
        let _ = tokio::time::timeout(WATCHDOG, transport.post_json(&address, b"{}", &[]))
            .await
            .expect("the message ends");
        assert_eq!(proxy.asked(), vec![format!("POST {address} HTTP/1.1")]);
        heard_nothing(&hook);
        // And the catalogue's repositories, through the restarted daemon's own transport: the
        // proxy is asked to open a tunnel to the repository, as often as the transport tries.
        let _ = fetch_error(
            restarted.catalogue().transport(),
            &format!("{repository}/1.root.json"),
        )
        .await;
        let asked = proxy.asked();
        let tunnel = format!("CONNECT {repository_authority} HTTP/1.1");
        assert_eq!(asked.first(), Some(&format!("POST {address} HTTP/1.1")));
        assert!(
            asked.len() >= 2 && asked[1..].iter().all(|line| *line == tunnel),
            "{what}: the repository is asked for only through the proxy: {asked:?}"
        );
        heard_nothing(&repository_listener);
    }
}

/// Fetches `address` through `transport` and reads the whole answer: the stream the transport always
/// returns carries every failure, so a fetch that fails is an error at the end of it.
async fn fetch_error(
    transport: &std::sync::Arc<kr_plugin_catalogue::transport::RepositoryTransport>,
    address: &str,
) -> Result<(), String> {
    use futures_util::TryStreamExt as _;

    let opened = tokio::time::timeout(
        WATCHDOG,
        tough::Transport::fetch(&**transport, address.parse().expect("an address")),
    )
    .await
    .map_err(|_| "the fetch did not end".to_owned())?
    .map_err(|error| error.to_string())?;
    tokio::time::timeout(WATCHDOG, opened.try_collect::<Vec<tough::Bytes>>())
        .await
        .map_err(|_| "the answer did not end".to_owned())?
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// A document that others can read, where there are modes to read it by.
fn wider_than_owner_only() -> Option<(&'static str, Vec<u8>, u32)> {
    cfg!(unix).then(|| {
        (
            "permissions wider than owner-only",
            br#"{"version": 2}"#.to_vec(),
            0o644,
        )
    })
}

/// A loopback address that is listened on and never answered: its origin, its authority, and the
/// listener that says whether anything reached it.
fn unreached() -> (String, String, std::net::TcpListener) {
    let listener = listening();
    let authority = format!(
        "127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    (format!("https://{authority}"), authority, listener)
}

/// A loopback listener that is asked for what has connected to it, and waits for nothing.
fn listening() -> std::net::TcpListener {
    let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("a loopback port");
    listener.set_nonblocking(true).expect("a listener to ask");
    listener
}

/// Asserts that nothing connected to `listener`.
///
/// It is asked once the request has ended. A connection the client opened for it is complete by
/// then and waits to be accepted, so nothing is left to arrive.
fn heard_nothing(listener: &std::net::TcpListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        heard => panic!("a request reached its destination without the proxy: {heard:?}"),
    }
}

/// Writes the configuration document the daemon reads when it starts.
fn write_document(environment: &kr_ipc::paths::EnvironmentPaths, document: &ConfigurationDocument) {
    let path = kr_worker::config::document_path(environment);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the state directory");
    }
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(document).as_bytes(),
    )
    .expect("the document");
}

/// Replaces the configuration document with `bytes` of `mode` where there are modes, whatever they
/// are.
fn write_bytes(environment: &kr_ipc::paths::EnvironmentPaths, bytes: &[u8], mode: u32) {
    let path = kr_worker::config::document_path(environment);
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, bytes).expect("the document");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("its mode");
    }
    #[cfg(not(unix))]
    let _ = mode;
}

/// Starts a daemon in-process on `environment`, launching no worker. A daemon dropped a moment ago
/// holds the environment until its tasks have ended, so a start that meets it is made again until
/// the watchdog ends.
async fn start_controller(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> std::sync::Arc<kr_controller::service::Controller> {
    let began = std::time::Instant::now();
    loop {
        match start_controller_once(environment, environment_id).await {
            Ok(controller) => return controller,
            Err(kr_controller::ControllerError::AlreadyRunning { .. })
                if began.elapsed() < WATCHDOG =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("the daemon starts: {error:?}"),
        }
    }
}

async fn start_controller_once(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> kr_controller::Result<std::sync::Arc<kr_controller::service::Controller>> {
    let secrets = environment.secrets_dir();
    kr_controller::service::Controller::start(kr_controller::service::ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = kr_crypto::store::open_store_in(&secrets)
                .expect("a secret store for the test environment");
            Ok(kr_ipc::verify::ControllerIdentity::open(
                store.store.as_ref(),
                environment_id,
                false,
            )
            .expect("an identity"))
        }),
        secret_store: kr_crypto::store::StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(net_support::RefusingSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: net_support::build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
}
