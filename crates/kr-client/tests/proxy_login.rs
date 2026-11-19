//! A proxy's login in the tunnel: `through` writes it, reads the proxy's refusal, sets the verdict,
//! and reads the verdict again right before it writes.
//!
//! Every proxy is a stand-in on the loopback, and the destination of a tunnel is a listener that
//! accepts and does nothing.

use std::sync::Arc;
use std::time::Duration;

use kr_client::tunnel::{ProxyTunnels, TunnelFailure, through};
use kr_crypto::secret::SecretVec;
use kr_transport::config::ProxyUrl;
use kr_transport::front::{TunnelOpener, TunnelRefusal};
use kr_transport::proxy::{ProxyCredential, ProxyLoginKind, StopKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[path = "support/connect_proxy.rs"]
mod connect_proxy;

use connect_proxy::{ConnectProxy, Login};

/// How long a test waits for something before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(20);

fn credential(user: &str, password: &str) -> ProxyCredential {
    ProxyCredential::new(
        SecretVec::new(user.as_bytes().to_vec()),
        SecretVec::new(password.as_bytes().to_vec()),
    )
    .expect("a login")
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS configuration for a client that trusts nothing.
fn trusting_nothing() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    )
}

/// A server certificate for 127.0.0.1 that is its own authority: the acceptor that serves it, and
/// the client configuration that trusts it.
fn self_signed() -> (TlsAcceptor, Arc<ClientConfig>) {
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("params");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let certificate = params.self_signed(&key).expect("a certificate");
    let der: CertificateDer<'static> = certificate.der().clone();
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("a server configuration");
    let mut roots = RootCertStore::empty();
    roots.add(der).expect("a root");
    let client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    (TlsAcceptor::from(Arc::new(server)), Arc::new(client))
}

/// A destination that accepts connections and holds them.
async fn destination() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let held = tokio::spawn(async move {
        let mut kept = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            kept.push(stream);
        }
    });
    (port, held)
}

fn proxy_of(url: &str, login: Option<&ProxyCredential>) -> ProxyUrl {
    let proxy: ProxyUrl = url.parse().expect("a proxy address");
    match login {
        Some(login) => proxy.with_login(login.clone()),
        None => proxy,
    }
}

/// A tunnel through a proxy that asks for a login carries it in the `CONNECT`, after the TLS to an
/// `https` proxy is up, and a proxy certificate that is not trusted sees no byte of it.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tunnel_through_a_proxy_that_asks_for_a_login_carries_it() {
    let (port, _held) = destination().await;
    let login = credential("us\u{e9}r", "p%41:@/ \u{15b}");
    let plain =
        ConnectProxy::authenticating("us\u{e9}r", "p%41:@/ \u{15b}", "Basic realm=\"x\"").await;
    let plain_url = proxy_of(&plain.url, Some(&login));
    let tunnel = through(&plain_url, "127.0.0.1", port, &trusting_nothing()).await;
    assert!(tunnel.is_ok(), "{:?}", tunnel.err());
    assert_eq!(plain.logins(), vec![Login::Right]);

    let (acceptor, trusted) = self_signed();
    let secure =
        ConnectProxy::authenticating_over_tls(acceptor, "us\u{e9}r", "p%41:@/ \u{15b}", "Basic")
            .await;
    let secure_url = proxy_of(&secure.url, Some(&login));
    let tunnel = through(&secure_url, "127.0.0.1", port, &trusted).await;
    assert!(tunnel.is_ok(), "{:?}", tunnel.err());
    assert_eq!(
        secure.logins(),
        vec![Login::Right],
        "the login went after TLS"
    );

    // A proxy certificate nobody trusts: the handshake fails and no byte of a request is read.
    let stranger = {
        let (acceptor, _) = self_signed();
        ConnectProxy::authenticating_over_tls(acceptor, "us\u{e9}r", "p%41:@/ \u{15b}", "Basic")
            .await
    };
    let untrusted = proxy_of(&stranger.url, Some(&login));
    let refused = through(&untrusted, "127.0.0.1", port, &trusted).await;
    assert!(
        matches!(refused, Err(TunnelFailure::Reason(_))),
        "{:?}",
        refused.err()
    );
    assert_eq!(
        stranger.bytes_read(),
        0,
        "an untrusted proxy read no login bytes"
    );
    assert!(stranger.logins().is_empty());
}

/// After one `407` to a login that was sent the verdict is set, and a second `through` opens no
/// connection; an `HTTP/1.0 407` is read the same way.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_login_is_sent_once_by_every_tunnel_user() {
    let (port, _held) = destination().await;
    for http10 in [false, true] {
        let proxy = if http10 {
            ConnectProxy::authenticating_in_http10("user", "password", "Basic realm=\"x\"").await
        } else {
            ConnectProxy::authenticating("user", "password", "Basic realm=\"x\"").await
        };
        let login = credential("user", "wrong");
        let url = proxy_of(&proxy.url, Some(&login));
        let first = through(&url, "127.0.0.1", port, &trusting_nothing()).await;
        assert!(
            matches!(first, Err(TunnelFailure::Login(ProxyLoginKind::Refused))),
            "{:?}",
            first.err()
        );
        assert_eq!(login.stopped(), Some(StopKind::Refused));
        assert_eq!(proxy.logins(), vec![Login::Wrong]);
        let accepted = proxy.accepted();
        let second = through(&url, "127.0.0.1", port, &trusting_nothing()).await;
        assert!(matches!(
            second,
            Err(TunnelFailure::Login(ProxyLoginKind::Refused))
        ));
        assert_eq!(
            proxy.accepted(),
            accepted,
            "a second call opens no connection"
        );
        assert_eq!(proxy.logins(), vec![Login::Wrong], "and sends no login");
    }
}

/// A proxy that offers only a method this host does not send sets the verdict and its reason, and
/// the second call fails with the same reason, whichever order the two reasons arrive in.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scheme_this_host_does_not_send_is_said_and_stays() {
    let (port, _held) = destination().await;
    let proxy = ConnectProxy::authenticating("user", "password", "Negotiate, NTLM").await;
    let login = credential("user", "wrong");
    let url = proxy_of(&proxy.url, Some(&login));
    let first = through(&url, "127.0.0.1", port, &trusting_nothing()).await;
    assert!(matches!(
        first,
        Err(TunnelFailure::Login(ProxyLoginKind::Unsupported))
    ));
    assert!(login.unsupported());
    login.refuse(StopKind::Refused);
    let second = through(&url, "127.0.0.1", port, &trusting_nothing()).await;
    assert!(
        matches!(
            second,
            Err(TunnelFailure::Login(ProxyLoginKind::Unsupported))
        ),
        "{:?}",
        second.err()
    );
    // With no login held the same answer is `Unsupported` too, and there is no verdict to set.
    let bare = proxy_of(&proxy.url, None);
    let third = through(&bare, "127.0.0.1", port, &trusting_nothing()).await;
    assert!(matches!(
        third,
        Err(TunnelFailure::Login(ProxyLoginKind::Unsupported))
    ));
}

/// A proxy that asks for a Basic login that this host does not hold is `Needed`, and nothing is
/// stopped: there is no login to stop.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_nobody_holds_is_needed_and_stops_nothing() {
    let (port, _held) = destination().await;
    let proxy = ConnectProxy::authenticating("user", "password", "Basic realm=\"x\"").await;
    let bare = proxy_of(&proxy.url, None);
    for _ in 0..2 {
        let needed = through(&bare, "127.0.0.1", port, &trusting_nothing()).await;
        assert!(matches!(
            needed,
            Err(TunnelFailure::Login(ProxyLoginKind::Needed))
        ));
    }
    assert_eq!(
        proxy.logins(),
        vec![Login::Absent, Login::Absent],
        "each call asked again"
    );
}

/// A call that is connecting when the verdict is set reads the verdict again right before it
/// writes, so the proxy reads no byte of a request from it.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn through_reads_the_verdict_again_right_before_it_writes() {
    let (port, _held) = destination().await;
    let (acceptor, trusted) = self_signed();
    let proxy = ConnectProxy::authenticating_over_tls(acceptor, "user", "password", "Basic").await;
    let login = credential("user", "password");
    let url = proxy_of(&proxy.url, Some(&login));
    proxy.hold_tls();
    let connecting = tokio::spawn({
        let url = url.clone();
        async move { through(&url, "127.0.0.1", port, &trusted).await.err() }
    });
    // The call has dialled the proxy and is inside the handshake, which the proxy holds.
    tokio::time::timeout(WATCHDOG, async {
        while proxy.accepted() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the call reached the proxy");
    login.refuse(StopKind::Refused);
    proxy.release_tls();
    let failure = tokio::time::timeout(WATCHDOG, connecting)
        .await
        .expect("the call ended")
        .expect("the task");
    assert!(
        matches!(failure, Some(TunnelFailure::Login(ProxyLoginKind::Refused))),
        "{failure:?}"
    );
    assert_eq!(
        proxy.bytes_read(),
        0,
        "the proxy read no bytes from the held connection"
    );
    assert!(proxy.logins().is_empty());
}

/// The front's opener over `through`: a verdict that stops is `Stopped`, any other failure is
/// `Failed`, and a tunnel that opens is a tunnel.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_front_opens_its_tunnels_through_the_one_writer() {
    let (port, _held) = destination().await;
    let proxy = ConnectProxy::authenticating("user", "password", "Basic").await;
    let login = credential("user", "password");
    let opener = ProxyTunnels::new(proxy_of(&proxy.url, Some(&login)), trusting_nothing());
    assert!(opener.open("127.0.0.1", port).await.is_ok());
    assert_eq!(proxy.logins(), vec![Login::Right]);
    login.refuse(StopKind::Refused);
    assert_eq!(
        opener.open("127.0.0.1", port).await.err(),
        Some(TunnelRefusal::Stopped)
    );
    assert_eq!(
        proxy.logins(),
        vec![Login::Right],
        "no login after the verdict"
    );

    let lost = ProxyTunnels::new(proxy_of("http://127.0.0.1:1", None), trusting_nothing());
    assert_eq!(
        lost.open("127.0.0.1", port).await.err(),
        Some(TunnelRefusal::Failed)
    );
}

/// A request of a service client through a proxy that refuses the login ends with the kind and not
/// as a transport failure, stops the proxy's login for every later request, and writes no login
/// again; a proxy that asks for a login nobody holds is `Needed`, which keeps the retry the request
/// had; a plain `http` address is not sent at all while a login is held.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_request_that_meets_the_proxys_refusal_ends_with_its_kind() {
    use kr_client::error::ClientError;
    use kr_client::retry::{Recovery, RequestClass};
    use kr_client::services::ServiceHttp;
    use kr_client::services::http::{HttpDeadlines, HttpService, ResponseLimits};
    use kr_protocol::service::GatewayOrigin;

    let service = |proxy: &ProxyUrl, origin: &str| {
        HttpService::through(
            GatewayOrigin::new(origin).expect("an origin"),
            HttpDeadlines {
                connect: WATCHDOG,
                read: WATCHDOG,
                total: WATCHDOG,
            },
            ResponseLimits::new(1024),
            Some(proxy),
        )
        .expect("a service client")
    };
    let proxy = ConnectProxy::authenticating("user", "password", "Basic").await;

    let wrong = credential("user", "wrong");
    let url = proxy_of(&proxy.url, Some(&wrong));
    let client = service(&url, "https://service.example");
    let refused = client
        .get_json("https://service.example/x", &[])
        .await
        .expect_err("a refusal");
    assert!(matches!(
        refused,
        ClientError::ProxyLogin(ProxyLoginKind::Refused)
    ));
    assert_eq!(wrong.stopped(), Some(StopKind::Refused));
    assert_eq!(
        refused.decision(RequestClass::IdempotentRead).recovery,
        Recovery::Stop,
        "a refused login is not retried until the host restarts"
    );
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    assert!(
        refused
            .to_string()
            .contains(ProxyLoginKind::Refused.clause())
    );
    let again = client
        .get_json("https://service.example/x", &[])
        .await
        .expect_err("stopped");
    assert!(matches!(
        again,
        ClientError::ProxyLogin(ProxyLoginKind::Refused)
    ));
    assert_eq!(proxy.logins(), vec![Login::Wrong], "no second login");

    let none = proxy_of(&proxy.url, None);
    let needed = service(&none, "https://service.example")
        .get_json("https://service.example/x", &[])
        .await
        .expect_err("a login is needed");
    assert!(matches!(
        needed,
        ClientError::ProxyLogin(ProxyLoginKind::Needed)
    ));
    assert_ne!(
        needed.decision(RequestClass::IdempotentRead).recovery,
        Recovery::Stop,
        "Needed keeps the base's retry"
    );

    let held = credential("user", "password");
    let plain = proxy_of(&proxy.url, Some(&held));
    let before = proxy.logins().len();
    let clear = service(&plain, "http://127.0.0.1:9")
        .get_json("http://127.0.0.1:9/x", &[])
        .await
        .expect_err("plain http");
    assert!(matches!(
        clear,
        ClientError::ProxyLogin(ProxyLoginKind::ClearTextTarget)
    ));
    assert_eq!(proxy.logins().len(), before, "nothing reached the proxy");
}

/// Every reader of a [`ClientError`] that sorts by variant takes a proxy login failure as a send
/// that did not happen: the attempt's reply is `NotSent`, and an answer that was not written is
/// settled.
///
/// Covers KR-REQ-10.02.
#[test]
fn the_readers_of_a_client_error_take_a_proxy_login_failure_as_not_sent() {
    use kr_client::answers::AnswerFailure;
    use kr_client::attempt::Reply;
    use kr_client::error::ClientError;
    use kr_client::session::Settled;

    for kind in [
        ProxyLoginKind::Needed,
        ProxyLoginKind::Refused,
        ProxyLoginKind::Unsupported,
        ProxyLoginKind::ClearTextTarget,
    ] {
        let outcome: Result<Settled, ClientError> = Err(ClientError::ProxyLogin(kind));
        assert_eq!(Reply::of(&outcome), Reply::NotSent, "{kind:?}");
        assert!(AnswerFailure::from(ClientError::ProxyLogin(kind)).settled());
    }
}

/// A join reads the service's description through the proxy with the login it is given: a login the
/// proxy refuses and a proxy that asks for one nobody gave end as the kind, and a refusal the
/// client reads only as a failed tunnel is told by one bounded re-check through the same writer,
/// with no loop.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_carries_the_login_it_is_given_keeps_none_and_tells_a_refusal() {
    use kr_client::services::description::{Unread, connect, fetch, recheck};
    use kr_protocol::service::GatewayOrigin;

    let origin = GatewayOrigin::new("https://service.example").expect("an origin");

    let proxy = ConnectProxy::authenticating("user", "password", "Basic").await;
    let wrong = credential("user", "wrong");
    let url = proxy_of(&proxy.url, Some(&wrong));
    let http = connect(&origin, Some(&url)).expect("a client");
    assert_eq!(
        fetch(&http, &origin).await.expect_err("a refusal"),
        Unread::ProxyLogin(ProxyLoginKind::Refused)
    );
    assert_eq!(proxy.logins(), vec![Login::Wrong]);

    let none = proxy_of(&proxy.url, None);
    let http = connect(&origin, Some(&none)).expect("a client");
    assert_eq!(
        fetch(&http, &origin).await.expect_err("a login is needed"),
        Unread::ProxyLogin(ProxyLoginKind::Needed)
    );
    assert_eq!(proxy.logins(), vec![Login::Wrong, Login::Absent]);

    // `HTTP/1.0 407` reads as a failed tunnel: the request says only that the service is
    // unreachable, and the one re-check tells the refusal.
    let old = ConnectProxy::authenticating_in_http10("user", "password", "Basic").await;
    let wrong = credential("user", "wrong");
    let url = proxy_of(&old.url, Some(&wrong));
    let http = connect(&origin, Some(&url)).expect("a client");
    assert_eq!(
        fetch(&http, &origin)
            .await
            .expect_err("an unreadable refusal"),
        Unread::Unreachable
    );
    assert_eq!(wrong.stopped(), None, "the request alone sets no verdict");
    assert_eq!(
        recheck(Some(&url)).await,
        Some(Unread::ProxyLogin(ProxyLoginKind::Refused))
    );
    assert_eq!(old.logins(), vec![Login::Wrong, Login::Wrong]);
    assert_eq!(recheck(Some(&url)).await, None, "the re-check is made once");
    assert_eq!(old.logins().len(), 2, "no loop");
}
