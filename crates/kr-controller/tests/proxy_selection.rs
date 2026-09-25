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
use tokio::net::TcpListener;

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
        controller.started_proxy().expect("a usable selection"),
        None,
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
        controller.started_proxy().expect("a usable selection"),
        Some(named.clone())
    );

    document.revision = 2;
    document.network.proxy_url = Nullable::null();
    write_document(&environment, &document);
    assert_eq!(
        controller.started_proxy().expect("a usable selection"),
        Some(named),
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
    let (origin, authority, service) = unreached().await;
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
    heard_nothing(&service).await;
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
    let (origin, authority, service) = unreached().await;
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
    heard_nothing(&service).await;
}

/// KR-REQ-26.14: delivery goes through the proxy the daemon started with. A webhook message to an
/// owner's address reaches the proxy, and the address hears nothing around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_goes_through_the_proxy_the_daemon_started_with() {
    let proxy = ConnectProxy::refusing(502).await;
    let transports = ManagedTransports::new(Some(proxy.url.parse().expect("a proxy address")));
    let hook = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
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
    heard_nothing(&hook).await;
}

/// A loopback address that is listened on and never answered: its origin, its authority, and the
/// listener that says whether anything reached it.
async fn unreached() -> (String, String, TcpListener) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let authority = format!(
        "127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    (format!("https://{authority}"), authority, listener)
}

/// Asserts that nothing connected to `listener` within a moment.
async fn heard_nothing(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "a request reached its destination without the proxy"
    );
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

/// Starts a daemon in-process on `environment`, launching no worker.
async fn start_controller(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> std::sync::Arc<kr_controller::service::Controller> {
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
    .expect("the daemon starts")
}
