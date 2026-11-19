//! The network library never holds a proxy's login: its relay and its probes reach the proxy only
//! through the front the endpoint owns, and after the verdict on the login no path writes it again.
//!
//! The endpoint is a real one, the front is the real front, each tunnel is opened by the real
//! `through`, and the proxy and the relay are stand-ins on the loopback. Each case waits for an
//! event it can see (a counter, the verdict, the end of the close), never for a quiet interval.

// A relay server running in this process. This suite uses only its address and its roots.
#[path = "net_support/relay.rs"]
#[allow(dead_code)]
mod local_relay;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use connect_proxy::{ConnectProxy, Login};
use kr_client::tunnel::ProxyTunnels;
use kr_controller::service::net::config::NetworkSettings;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_crypto::secret::SecretVec;
use kr_protocol::hostinfo::configuration::NetworkSelection;
use kr_protocol::scalars::Nullable;
use kr_transport::config::{EndpointConfig, ProxyUrl};
use kr_transport::endpoint::{bind_network, guard_proxy};
use kr_transport::front::FrontOpener;
use kr_transport::proxy::{ProxyCredential, StopKind};
use local_relay::LocalRelay;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// How long a test waits for something before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(30);

fn credential() -> ProxyCredential {
    ProxyCredential::new(
        SecretVec::new(b"user".to_vec()),
        SecretVec::new(b"password".to_vec()),
    )
    .expect("a login")
}

/// A TLS configuration that trusts `roots`.
fn trusting(roots: &[Vec<u8>]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for der in roots {
        store
            .add(rustls::pki_types::CertificateDer::from(der.clone()))
            .expect("a root");
    }
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

/// The relay's `host:port`, as a `CONNECT` names it.
fn authority(relay: &LocalRelay) -> String {
    format!(
        "{}:{}",
        relay.url.host_str().expect("a host"),
        relay.url.port_or_known_default().expect("a port")
    )
}

/// A relay-only endpoint that reaches `relay` through `proxy`, whose login is `login`.
fn config(relay: &LocalRelay, proxy: ProxyUrl, tls: Arc<ClientConfig>) -> EndpointConfig {
    EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        relay_ca_roots: relay.ca_roots.clone(),
        relay_only: true,
        login_front: Some(FrontOpener(Arc::new(ProxyTunnels::new(proxy.clone(), tls)))),
        proxy_url: Some(proxy),
        ..EndpointConfig::default()
    }
}

/// Waits until `condition` holds, polling the counters it reads, or fails the case as stuck.
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(WATCHDOG, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("stuck waiting for {what}"));
}

/// A `CONNECT` to `target` sent to the front with its secret, as the library's relay actor sends
/// it.
async fn dial_front(front: SocketAddr, secret: &str, target: &str) -> TcpStream {
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("kr:{secret}"));
    let mut dial = TcpStream::connect(front).await.expect("the front");
    dial.write_all(
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {basic}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .expect("a request");
    dial
}

/// The first twelve bytes of the front's answer, its version and status.
async fn status_of(dial: &mut TcpStream) -> [u8; 12] {
    let mut status = [0_u8; 12];
    tokio::time::timeout(WATCHDOG, dial.read_exact(&mut status))
        .await
        .expect("the front answered")
        .expect("an answer");
    status
}

/// Whether the proxy has been asked for a `CONNECT` to `target`.
fn asked_to(proxy: &ConnectProxy, target: &str) -> bool {
    proxy
        .asked()
        .iter()
        .any(|line| line.starts_with(&format!("CONNECT {target} ")))
}

/// A relay-only endpoint reaches its relay through the front, the proxy sees nothing but what the
/// one writer sends, and once the verdict on the login is set the library's relay, which redials
/// again and again, writes the login to the proxy no more.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_login_is_written_zero_times_after_the_verdict_by_irohs_relay_and_its_redials() {
    let relay = LocalRelay::spawn().await;
    let proxy = ConnectProxy::authenticating("user", "password", "Basic realm=\"x\"").await;
    let login = credential();
    let proxy_url = proxy
        .url
        .parse::<ProxyUrl>()
        .expect("a proxy address")
        .with_login(login.clone());
    let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
    let (endpoint, closer) = bind_network(&config(&relay, proxy_url, trusting(&[])), &identity)
        .await
        .expect("a network endpoint");
    tokio::time::timeout(WATCHDOG, endpoint.online())
        .await
        .expect("the endpoint reached its relay through the front");
    let probe = closer.front_probe().expect("a front");
    assert!(
        !proxy.logins().is_empty() && proxy.logins().iter().all(|login| *login == Login::Right),
        "every connection the proxy took came from the one writer, with the login: {:?}",
        proxy.logins()
    );

    // The case sets the verdict itself, as the proxy's refusal of the login would, and reads what
    // the proxy has seen at that moment. Then it ends the relay session, so that the library's
    // relay actor dials again, through the front.
    login.refuse(StopKind::Refused);
    let written = proxy.logins().len();
    let before = proxy.accepted() + probe.accepted();
    // A redial that the proxy lets through is ended again as it opens, so that the library keeps
    // dialling and the case sees the same event, three more connections taken, whoever takes them.
    let target = authority(&relay);
    until("three more connections after the verdict", || {
        proxy.close_tunnels_to(&target);
        proxy.accepted() + probe.accepted() >= before + 3
    })
    .await;
    assert_eq!(
        proxy.logins().len(),
        written,
        "the proxy counted no login after the verdict: {:?}",
        proxy.logins()
    );
    closer.close().await;
    assert!(closer.closed() && endpoint.is_closed());
}

/// A tunnel the front admitted before the verdict, and is still connecting, is refused the moment
/// the verdict is set, and the proxy reads no byte from its held connection once it is released.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_front_tunnel_admitted_before_the_verdict_writes_no_login_after_it() {
    let relay = LocalRelay::spawn().await;
    let (certs, server) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
    let roots: Vec<Vec<u8>> = certs.iter().map(|der| der.to_vec()).collect();
    let proxy = ConnectProxy::authenticating_over_tls(
        TlsAcceptor::from(Arc::new(server)),
        "user",
        "password",
        "Basic",
    )
    .await;
    let login = credential();
    let proxy_url = proxy
        .url
        .parse::<ProxyUrl>()
        .expect("a proxy address")
        .with_login(login.clone());
    proxy.hold_tls();
    let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
    let (endpoint, closer) = bind_network(&config(&relay, proxy_url, trusting(&roots)), &identity)
        .await
        .expect("a network endpoint");
    let probe = closer.front_probe().expect("a front");
    let front = closer.front_address().expect("a front");

    // A dial of the case's own: admitted by the front with the secret, and held inside the
    // handshake with the proxy.
    let target = authority(&relay);
    let mut dial = dial_front(front, &probe.secret(), &target).await;
    until("the dial to reach the proxy", || proxy.accepted() >= 1).await;

    // The verdict is set while the handshake is still held: the front answers at once.
    login.refuse(StopKind::Refused);
    let status = status_of(&mut dial).await;
    assert_eq!(
        &status, b"HTTP/1.1 503",
        "the front refused the dial at the verdict while TLS was held"
    );

    // Released, the handshake completes and the writer finds the verdict: no login bytes.
    proxy.release_tls();
    closer.close().await;
    assert!(closer.closed() && endpoint.is_closed());
    assert_eq!(proxy.bytes_read(), 0, "the proxy read no login bytes");
    assert!(proxy.logins().is_empty());
}

/// With two relays in the map, one live and one that hangs up, every probe the library sends
/// reaches the proxy as a `CONNECT` that the one writer made with the login, and the proxy sees no
/// forwarded request: the captive-portal check, a plain `GET`, is not sent. After the verdict the
/// front refuses the library's dials, and the proxy counts no login and no request for them.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn iroh_probes_reach_the_proxy_only_through_the_front_and_the_captive_check_is_off() {
    let relay = LocalRelay::spawn().await;
    let hung_up = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let hung_up_port = hung_up.local_addr().expect("an address").port();
    let hanging_up = tokio::spawn(async move {
        while let Ok((stream, _)) = hung_up.accept().await {
            drop(stream);
        }
    });
    let dead = format!("127.0.0.1:{hung_up_port}");
    let proxy = ConnectProxy::authenticating("user", "password", "Basic realm=\"x\"").await;
    let login = credential();
    let proxy_url = proxy
        .url
        .parse::<ProxyUrl>()
        .expect("a proxy address")
        .with_login(login.clone());
    let mut settings = config(&relay, proxy_url, trusting(&[]));
    settings
        .relay_urls
        .push(format!("https://{dead}").parse().expect("a relay address"));
    let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
    let (endpoint, closer) = bind_network(&settings, &identity)
        .await
        .expect("a network endpoint");
    tokio::time::timeout(WATCHDOG, endpoint.online())
        .await
        .expect("the endpoint reached its relay through the front");
    let probe = closer.front_probe().expect("a front");

    // A new report probes every relay of the map: the case asks for reports until the proxy has
    // been asked for the relay that hangs up.
    tokio::time::timeout(WATCHDOG, async {
        while !asked_to(&proxy, &dead) {
            endpoint.network_change().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the relay that hangs up was probed through the proxy");
    assert!(asked_to(&proxy, &authority(&relay)));
    assert!(
        proxy
            .asked()
            .iter()
            .all(|line| line.starts_with("CONNECT ")),
        "the proxy saw a request that is not a CONNECT: {:?}",
        proxy.asked()
    );
    assert!(
        !proxy.logins().is_empty() && proxy.logins().iter().all(|login| *login == Login::Right),
        "every request the proxy took was written by the one writer with the login: {:?}",
        proxy.logins()
    );

    // After the verdict the library's connections to its relays are ended, so that it dials again,
    // and the front refuses each dial. (The library sends a new report only when the machine's
    // interfaces change, which a case cannot make happen, so the dials stand for the front's
    // refusal of every connection.)
    login.refuse(StopKind::Refused);
    let written = proxy.logins().len();
    let asked = proxy.asked().len();
    let reached = probe.accepted();
    let relay_target = authority(&relay);
    until("three dials the front refused", || {
        proxy.close_tunnels_to(&relay_target);
        proxy.close_tunnels_to(&dead);
        probe.accepted() >= reached + 3
    })
    .await;
    assert_eq!(
        proxy.logins().len(),
        written,
        "the proxy counted no login after the verdict: {:?}",
        proxy.logins()
    );
    assert_eq!(
        proxy.asked().len(),
        asked,
        "the proxy was asked for nothing after the verdict: {:?}",
        proxy.asked()
    );
    closer.close().await;
    assert!(closer.closed() && endpoint.is_closed());
    hanging_up.abort();
}

/// What the front answered to a `CONNECT` it was given, through an `https` proxy whose certificate
/// the start check's trust anchors either hold or do not, and what the proxy read of it. The
/// front is the one a document's selection builds.
async fn front_of_a_document_through(
    relay: &LocalRelay,
    proxy: &ConnectProxy,
    anchors: &[String],
) -> ([u8; 12], Vec<Login>, usize) {
    let login = credential();
    let selection = NetworkSelection {
        enabled: Nullable::some(true),
        relay_urls: Nullable::some(vec![relay.url.to_string()]),
        relay_trust_anchors: Nullable::some(anchors.to_vec()),
        relay_only: Nullable::some(true),
        ..NetworkSelection::default()
    };
    let proxy_url = proxy
        .url
        .parse::<ProxyUrl>()
        .expect("a proxy address")
        .with_login(login);
    let settings = NetworkSettings::from_selection(&selection, Some(proxy_url))
        .expect("the selection is valid")
        .expect("the selection joins");
    let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
    let (_endpoint, closer) = bind_network(&settings.endpoint, &identity)
        .await
        .expect("a network endpoint");
    let probe = closer.front_probe().expect("a front");
    let front = closer.front_address().expect("a front");
    let mut dial = dial_front(front, &probe.secret(), &authority(relay)).await;
    let status = status_of(&mut dial).await;
    closer.close().await;
    (status, proxy.logins(), proxy.bytes_read())
}

/// The front's tunnels are opened over the trust the start check uses for the proxy: a proxy whose
/// root is among the anchors opens the tunnel and gets the login, and a proxy that is not trusted
/// gets no login byte and is answered `502`.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_front_verifies_an_https_proxy_with_the_start_checks_roots() {
    let relay = LocalRelay::spawn().await;
    let (certs, server) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
    let proxy = ConnectProxy::authenticating_over_tls(
        TlsAcceptor::from(Arc::new(server)),
        "user",
        "password",
        "Basic",
    )
    .await;
    let scratch = kr_ipc::testing::PrivateTempDir::create();
    let anchor = scratch.path().join("proxy-root.der");
    std::fs::write(&anchor, certs[0].as_ref()).expect("a root file");
    let anchors = [anchor.to_str().expect("a path").to_owned()];

    let (status, logins, read) = front_of_a_document_through(&relay, &proxy, &[]).await;
    assert_eq!(
        &status, b"HTTP/1.1 502",
        "an untrusted proxy is answered 502"
    );
    assert!(logins.is_empty() && read == 0, "no login byte reached it");

    let (status, logins, _) = front_of_a_document_through(&relay, &proxy, &anchors).await;
    assert_eq!(
        &status, b"HTTP/1.1 200",
        "the tunnel opens when the proxy's root is an anchor"
    );
    assert_eq!(logins, [Login::Right]);
}

/// The front is up before the library binds, so a verdict set before the bind is answered by the
/// front, which refuses every dial, and a guard that starts after the verdict closes the endpoint
/// with no further event.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_front_is_up_before_iroh_binds_and_a_late_guard_closes_at_once() {
    let relay = LocalRelay::spawn().await;
    let proxy = ConnectProxy::authenticating("user", "password", "Basic").await;
    let login = credential();
    let proxy_url = proxy
        .url
        .parse::<ProxyUrl>()
        .expect("a proxy address")
        .with_login(login.clone());
    login.refuse(StopKind::Refused);
    let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
    let (endpoint, closer) = bind_network(&config(&relay, proxy_url, trusting(&[])), &identity)
        .await
        .expect("a network endpoint");
    let probe = closer.front_probe().expect("a front");
    let front = closer.front_address().expect("a front");
    let mut dial = dial_front(front, &probe.secret(), &authority(&relay)).await;
    assert_eq!(
        &status_of(&mut dial).await,
        b"HTTP/1.1 503",
        "the front refuses a dial made after the verdict"
    );
    assert!(!closer.closed() && !endpoint.is_closed());

    // The guard starts after the verdict and closes the endpoint with nothing else to wake it.
    let guard = guard_proxy(&closer, &login);
    until("the guard closed the endpoint", || guard.proxy_closed()).await;
    assert!(endpoint.is_closed());
    assert_eq!(proxy.accepted(), 0, "nothing reached the proxy");
    assert!(proxy.logins().is_empty());
}
