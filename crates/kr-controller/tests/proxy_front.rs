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

use std::sync::Arc;
use std::time::Duration;

use connect_proxy::{ConnectProxy, Login};
use kr_client::tunnel::ProxyTunnels;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_crypto::secret::SecretVec;
use kr_transport::config::{EndpointConfig, ProxyUrl};
use kr_transport::endpoint::bind_network;
use kr_transport::front::FrontOpener;
use kr_transport::proxy::{ProxyCredential, StopKind};
use local_relay::LocalRelay;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
    proxy.close_tunnels_to(&authority(&relay));
    until("three more connections after the verdict", || {
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
    let mut dial = TcpStream::connect(front).await.expect("the front");
    let target = authority(&relay);
    let secret = probe.secret();
    let basic = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!("kr:{secret}"))
    };
    dial.write_all(
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {basic}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .expect("a request");
    until("the dial to reach the proxy", || proxy.accepted() >= 1).await;

    // The verdict is set while the handshake is still held: the front answers at once.
    login.refuse(StopKind::Refused);
    let mut status = [0_u8; 12];
    tokio::time::timeout(WATCHDOG, dial.read_exact(&mut status))
        .await
        .expect("the front answered while TLS was held")
        .expect("an answer");
    assert_eq!(
        &status, b"HTTP/1.1 503",
        "the front refused the dial at the verdict"
    );

    // Released, the handshake completes and the writer finds the verdict: no login bytes.
    proxy.release_tls();
    closer.close().await;
    assert!(closer.closed() && endpoint.is_closed());
    assert_eq!(proxy.bytes_read(), 0, "the proxy read no login bytes");
    assert!(proxy.logins().is_empty());
}
