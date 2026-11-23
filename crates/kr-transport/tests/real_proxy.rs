//! A client that goes through a real proxy that asks for a login: the squid that
//! `scripts/real-proxy.sh` runs on the loopback, asking every `CONNECT` for a user name and a
//! password by Basic.
//!
//! The stand-in proxies of the other suites say what a client sent. This proxy says what a
//! maintained proxy accepted and answered: its own access log is the record of which tunnels it
//! opened, for whom, and which requests it turned away, and its `407` is the one the library's
//! connector reads. Each case but the last, which checks the login check itself and runs with no
//! proxy, runs only against a proxy the environment names; see `support/real_proxy.rs`.

// The digest proxy is read by the suites that share this module, not by this one.
#[path = "support/real_proxy.rs"]
#[allow(dead_code)]
mod real_proxy;
#[path = "support/tls.rs"]
#[allow(dead_code)]
mod tls;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_transport::config::ProxyUrl;
use kr_transport::proxy::{
    Following, ProxyLoginKind, StopKind, admit, follow, proxied, proxy_login_kind,
};
use real_proxy::{Login, RealProxy, WRONG_PASSWORD, holds_login};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::Url;

/// How long a request waits before the case calls it stuck.
const WATCHDOG: Duration = Duration::from_secs(20);

/// A TLS origin on the loopback that answers every request on a connection with `ok`, and what a
/// client trusts to reach it.
struct Origin {
    address: String,
    root: Vec<u8>,
}

async fn origin() -> Origin {
    let authority = tls::Authority::new("a real proxy case's origin");
    let acceptor = TlsAcceptor::from(authority.server_config("127.0.0.1"));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&chunk[..read]);
                    while let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                        head.drain(..end + 4);
                        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                        if stream.write_all(answer).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    Origin {
        address: format!("127.0.0.1:{port}"),
        root: authority.der,
    }
}

fn client(proxy: &ProxyUrl, origin: &Origin) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .timeout(WATCHDOG)
        .tls_backend_preconfigured(
            (*tls::client_config(std::slice::from_ref(&origin.root))).clone(),
        );
    proxied(builder, proxy)
        .expect("a proxy the library takes")
        .build()
        .expect("a client")
}

/// KR-REQ-10.02: a client that holds the login of a real proxy reaches an origin through it. The
/// proxy opened one tunnel to that origin's address for the user, and the second request travelled
/// in the same tunnel, so the login was written once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only against a proxy this machine runs, named by KR_REAL_PROXY, KR_REAL_PROXY_CREDENTIAL_FILE and KR_REAL_PROXY_ACCESS_LOG"]
async fn a_client_with_the_right_login_reaches_an_origin_through_a_real_proxy() {
    let proxy = RealProxy::basic();
    let origin = origin().await;
    let url = proxy.url(Login::Right);
    let client = client(&url, &origin);

    for _ in 0..2 {
        let answer = client
            .get(format!("https://{}/", origin.address))
            .send()
            .await
            .expect("the origin answers through the proxy");
        assert_eq!(answer.status(), 200);
        assert_eq!(answer.text().await.expect("a body"), "ok");
    }
    let login = url.login().expect("a login");
    assert_eq!(login.stopped(), None, "no verdict was set");

    // The proxy writes a tunnel's line when the tunnel closes.
    drop(client);
    let lines = proxy.exactly(&origin.address, 1).await;
    assert_eq!(
        lines.len(),
        1,
        "one tunnel carried both requests: {lines:?}"
    );
    assert_eq!(lines[0].method, "CONNECT");
    assert_eq!(lines[0].status, 200, "{lines:?}");
    assert_eq!(lines[0].user, proxy.user(), "{lines:?}");
    assert!(
        !proxy.log_holds_own_login(),
        "the proxy's log holds the login"
    );
}

/// KR-REQ-10.02: a real proxy turns a wrong login away with its own `407`, and the client reads it:
/// the request ends with the kind `Refused`, the proxy's log shows the one refused `CONNECT` for the
/// user, and a second request is stopped at the client, so the proxy is asked for the wrong login
/// once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only against a proxy this machine runs, named by KR_REAL_PROXY, KR_REAL_PROXY_CREDENTIAL_FILE and KR_REAL_PROXY_ACCESS_LOG"]
async fn a_wrong_login_is_refused_by_a_real_proxy_once_and_stops_every_request() {
    let proxy = RealProxy::basic();
    let origin = origin().await;
    let url = proxy.url(Login::Wrong);
    let client = client(&url, &origin);

    let refused = client
        .get(format!("https://{}/", origin.address))
        .send()
        .await
        .expect_err("the proxy refuses the login");
    assert_eq!(proxy_login_kind(&refused), Some(ProxyLoginKind::Refused));
    assert_eq!(
        url.login().expect("a login").stopped(),
        Some(StopKind::Refused)
    );
    let lines = proxy.wait_for(&origin.address, 1).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].method, "CONNECT");
    assert_eq!(lines[0].status, 407, "{lines:?}");
    assert_eq!(lines[0].user, proxy.user(), "the login that was sent");

    let again = client
        .get(format!("https://{}/", origin.address))
        .send()
        .await
        .expect_err("stopped at the client");
    assert_eq!(proxy_login_kind(&again), Some(ProxyLoginKind::Refused));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        proxy.lines_to(&origin.address).len(),
        1,
        "a second request sent nothing to the proxy"
    );
    assert!(
        !proxy.log_holds_login(proxy.user(), WRONG_PASSWORD),
        "the proxy's log holds the wrong login"
    );
    assert!(
        !proxy.log_holds_own_login(),
        "the proxy's log holds the login"
    );
}

/// KR-REQ-10.02: a client that holds no login is told by a real proxy that one is needed: the
/// request ends with the kind `Needed`, and the proxy's log shows one refused `CONNECT` that
/// carried no user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only against a proxy this machine runs, named by KR_REAL_PROXY, KR_REAL_PROXY_CREDENTIAL_FILE and KR_REAL_PROXY_ACCESS_LOG"]
async fn a_client_with_no_login_is_told_by_a_real_proxy_that_one_is_needed() {
    let proxy = RealProxy::basic();
    let origin = origin().await;
    let url = proxy.url(Login::None);
    let client = client(&url, &origin);

    let needed = client
        .get(format!("https://{}/", origin.address))
        .send()
        .await
        .expect_err("the proxy asks for a login");
    assert_eq!(proxy_login_kind(&needed), Some(ProxyLoginKind::Needed));
    let lines = proxy.exactly(&origin.address, 1).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0].method, "CONNECT");
    assert_eq!(lines[0].status, 407, "{lines:?}");
    assert_eq!(lines[0].user, "-", "no login was sent: {lines:?}");
    assert!(
        !proxy.log_holds_own_login(),
        "the proxy's log holds the login"
    );
}

/// KR-REQ-10.02: the login travels only in a `CONNECT`. A request to a plain `http` address, sent
/// through `follow` with the gate `admit` to a real proxy that holds the login, is refused as
/// `ClearTextTarget` before anything is sent: no connection reaches that origin and the proxy's
/// log holds no line for it, and no verdict is set. The same client then reaches a TLS origin
/// through the same gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs only against a proxy this machine runs, named by KR_REAL_PROXY, KR_REAL_PROXY_CREDENTIAL_FILE and KR_REAL_PROXY_ACCESS_LOG"]
async fn a_plain_http_target_is_refused_before_a_real_proxy_is_asked() {
    let proxy = RealProxy::basic();
    let tls_origin = origin().await;
    let plain = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let plain_address = plain.local_addr().expect("an address").to_string();
    let reached = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&reached);
    tokio::spawn(async move {
        while let Ok((stream, _)) = plain.accept().await {
            counting.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let url = proxy.url(Login::Right);
    let client = client(&url, &tls_origin);
    let following = || Following {
        limit: 10,
        deadline: Some(WATCHDOG),
    };
    let gate = |target: &Url| admit(Some(&url), target);

    let plain_url: Url = format!("http://{plain_address}/").parse().expect("a URL");
    let request = client.get(plain_url.clone()).build().expect("a request");
    let refused = follow(&client, request, following(), &gate)
        .await
        .expect_err("a plain http target is refused");
    assert_eq!(refused.url, plain_url);
    assert_eq!(
        proxy_login_kind(&refused),
        Some(ProxyLoginKind::ClearTextTarget)
    );
    assert_eq!(
        url.login().expect("a login").stopped(),
        None,
        "refusing a target sets no verdict"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let asked = proxy.lines_naming(&plain_address);
    assert!(asked.is_empty(), "the proxy was asked for it: {asked:?}");
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "nothing reached the origin"
    );

    let request = client
        .get(format!("https://{}/", tls_origin.address))
        .build()
        .expect("a request");
    let answer = follow(&client, request, following(), &gate)
        .await
        .expect("the TLS origin answers through the same gate");
    assert_eq!(answer.status(), 200);
    drop(answer);
    drop(client);
    let lines = proxy.wait_for(&tls_origin.address, 1).await;
    assert_eq!(lines[0].status, 200, "{lines:?}");
    assert_eq!(lines[0].user, proxy.user(), "{lines:?}");
    assert!(
        !proxy.log_holds_own_login(),
        "the proxy's log holds the login"
    );
}

/// The check the cases make of every log finds a login in each form it can take there, and finds
/// nothing in a log that holds neither.
#[test]
fn the_login_check_finds_the_password_and_its_basic_form() {
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode("user:secret-text");
    assert!(holds_login(
        "a line with secret-text in it",
        "user",
        "secret-text"
    ));
    assert!(holds_login(
        &format!("Proxy-Authorization: Basic {basic}"),
        "user",
        "secret-text"
    ));
    assert!(!holds_login("a line with neither", "user", "secret-text"));
    assert!(!holds_login(
        &format!("Proxy-Authorization: Basic {basic}"),
        "user",
        "another-text"
    ));
}
