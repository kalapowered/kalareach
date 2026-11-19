//! A client that goes through a proxy that asks for a login: the connector layer reads the answer
//! to the `CONNECT` that carried the login, sets the verdict, and stops a connect once the verdict
//! is set, with the library's real error chain and a stand-in proxy on the loopback.

// Only the certificates of this suite are used; other suites that share the module use the rest.
#[path = "support/tls.rs"]
#[allow(dead_code)]
mod tls;

#[path = "../../kr-client/src/services/http/connect_proxy.rs"]
mod connect_proxy;

use std::time::Duration;

use connect_proxy::{ConnectProxy, Login};
use kr_crypto::secret::SecretVec;
use kr_transport::config::ProxyUrl;
use kr_transport::proxy::{
    ProxyCredential, ProxyLoginKind, StopKind, Target, note_failure, proxied, proxy_login_kind,
};
use tokio_rustls::TlsAcceptor;

/// How long a test waits for something before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(20);

/// An address nothing listens on: a request to it ends at the proxy.
const ORIGIN: &str = "https://127.0.0.1:9/";

fn credential(password: &str) -> ProxyCredential {
    ProxyCredential::new(
        SecretVec::new(b"user".to_vec()),
        SecretVec::new(password.as_bytes().to_vec()),
    )
    .expect("a login")
}

fn proxy_with(url: &str, login: Option<&ProxyCredential>) -> ProxyUrl {
    let proxy: ProxyUrl = url.parse().expect("a proxy address");
    match login {
        Some(login) => proxy.with_login(login.clone()),
        None => proxy,
    }
}

fn client(proxy: &ProxyUrl, trusted: &[Vec<u8>]) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .timeout(WATCHDOG)
        .tls_backend_preconfigured((*tls::client_config(trusted)).clone());
    proxied(builder, proxy)
        .expect("a proxy the library takes")
        .build()
        .expect("a client")
}

/// A `407` to a `CONNECT` that carried the login is read through the library's real error chain:
/// the kind is `Refused` and the verdict is set with a login, `Needed` and no verdict with none, and
/// a refusal the library does not name (`HTTP/1.0 407`) sets nothing and queues its target.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_layer_reads_the_connect_407_through_the_real_chain() {
    let proxy = ConnectProxy::authenticating("user", "password", "Basic realm=\"x\"").await;

    let login = credential("wrong");
    let with = client(&proxy_with(&proxy.url, Some(&login)), &[]);
    let refused = with.get(ORIGIN).send().await.expect_err("a refusal");
    assert_eq!(proxy_login_kind(&refused), Some(ProxyLoginKind::Refused));
    assert_eq!(login.stopped(), Some(StopKind::Refused));
    assert_eq!(proxy.logins(), vec![Login::Wrong]);
    let again = with
        .get(ORIGIN)
        .send()
        .await
        .expect_err("stopped at the layer");
    assert_eq!(proxy_login_kind(&again), Some(ProxyLoginKind::Refused));
    assert_eq!(
        proxy.logins(),
        vec![Login::Wrong],
        "a second request sends no login"
    );

    let without = client(&proxy_with(&proxy.url, None), &[]);
    let needed = without
        .get(ORIGIN)
        .send()
        .await
        .expect_err("a login is needed");
    assert_eq!(proxy_login_kind(&needed), Some(ProxyLoginKind::Needed));

    let old = ConnectProxy::authenticating_in_http10("user", "password", "Basic").await;
    let login = credential("wrong");
    let url = proxy_with(&old.url, Some(&login));
    let unread = client(&url, &[])
        .get(ORIGIN)
        .send()
        .await
        .expect_err("an HTTP/1.0 refusal");
    assert_eq!(proxy_login_kind(&unread), None, "the layer cannot read it");
    assert_eq!(login.stopped(), None, "and sets no verdict");
    note_failure(&url, &ORIGIN.parse().expect("a URL"), &unread);
    assert_eq!(
        login.suspicion().take(),
        Some(Target {
            host: "127.0.0.1".to_owned(),
            port: 9
        }),
        "the failed target is queued for the one re-check"
    );
}

/// A connect that is admitted before the verdict and still connecting is stopped when the verdict is
/// set: the request fails with the kind while TLS to the proxy is still held, and once the
/// handshake is let go the proxy has read no byte from that connection.
///
/// Covers KR-REQ-10.02.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_admitted_before_the_verdict_writes_no_login_after_it() {
    let authority = tls::Authority::new("proxy authority");
    let proxy = ConnectProxy::authenticating_over_tls(
        TlsAcceptor::from(authority.server_config("127.0.0.1")),
        "user",
        "password",
        "Basic",
    )
    .await;
    let login = credential("password");
    let client = client(
        &proxy_with(&proxy.url, Some(&login)),
        std::slice::from_ref(&authority.der),
    );
    proxy.hold_tls();
    let request = tokio::spawn(async move { client.get(ORIGIN).send().await });
    tokio::time::timeout(WATCHDOG, async {
        while proxy.accepted() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the request reached the proxy");
    login.refuse(StopKind::Refused);
    let ended = tokio::time::timeout(WATCHDOG, request)
        .await
        .expect("the request ended while TLS was held")
        .expect("the task")
        .expect_err("a stopped request");
    assert_eq!(proxy_login_kind(&ended), Some(ProxyLoginKind::Refused));
    proxy.release_tls();
    assert_eq!(proxy.bytes_read(), 0, "the proxy read no login bytes");
    assert!(proxy.logins().is_empty());
}
