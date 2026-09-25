//! The proxy the service client goes through is the one its caller names, and no other.
//!
//! A host names the proxy its configuration document selects and a device names none. The gateway
//! here is a loopback address over plain HTTP, which the transport admits for loopback alone, so a
//! request through the proxy arrives as one line the proxy can record: the method and the whole
//! address. Over HTTPS the same selection is a `CONNECT` tunnel, which the room socket's suite
//! exercises.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_client::services::http::{HttpDeadlines, HttpService, ResponseLimits};
use kr_client::services::relay::ServiceHttp;
use kr_protocol::error::ErrorCode;
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[path = "support/connect_proxy.rs"]
mod connect_proxy;

use connect_proxy::ConnectProxy;

/// How long a request may take before the test gives up on it.
const WATCHDOG: Duration = Duration::from_secs(20);

/// A gateway on loopback that is never meant to be reached, and says whether it was.
struct Gateway {
    origin: String,
    listener: TcpListener,
}

impl Gateway {
    async fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        Self {
            origin: format!("http://127.0.0.1:{port}"),
            listener,
        }
    }

    /// Asserts that nothing connected to the gateway itself.
    async fn heard_nothing(&self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), self.listener.accept())
                .await
                .is_err(),
            "the request reached the gateway without the proxy"
        );
    }

    fn client(&self, proxy: &ProxyUrl) -> HttpService {
        HttpService::through(
            GatewayOrigin::new(self.origin.clone()).expect("a loopback origin"),
            HttpDeadlines::default(),
            ResponseLimits::default(),
            Some(proxy),
        )
        .expect("the service client")
    }
}

/// KR-REQ-26.14: a service client whose caller names a proxy sends its request to that proxy, and
/// nothing reaches the gateway around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_client_goes_through_the_proxy_its_caller_names() {
    let gateway = Gateway::start().await;
    let proxy = ConnectProxy::refusing(502).await;
    let service = gateway.client(&proxy.url.parse().expect("a proxy address"));
    let address = format!("{}/api/probe", gateway.origin);
    let _ = tokio::time::timeout(WATCHDOG, service.post_json(&address, b"{}", &[]))
        .await
        .expect("the request ends");
    assert_eq!(proxy.asked(), vec![format!("POST {address} HTTP/1.1")]);
    gateway.heard_nothing().await;
}

/// Where the child finds the server its parent started.
const SERVER: &str = "PROXY_SELECTION_TEST_SERVER";

/// The child half of [`no_proxy_variable_moves_a_client_this_product_builds`].
///
/// It is ignored in an ordinary run because it means nothing without the environment the other
/// test builds around it, and that test runs it by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "no_proxy_variable_moves_a_client_this_product_builds runs this one"]
async fn the_child_of_the_proxy_variable_test() {
    let address = format!(
        "{}/probe",
        std::env::var(SERVER).expect("the parent names its server")
    );

    // A client this product builds names its proxy or none, and here it names none. Building it
    // also installs the TLS provider the ordinary client below needs.
    let built = kr_client::services::http::client_builder(None)
        .expect("the builder")
        .build()
        .expect("a client");

    // The control: a client built the ordinary way reads the proxy variables and asks the address
    // they name. That is what makes what follows about the builder rather than about an
    // environment nothing reads.
    let ordinary = reqwest::Client::builder()
        .build()
        .expect("an ordinary client");
    let _ = tokio::time::timeout(WATCHDOG, ordinary.get(&address).send()).await;

    let answered = tokio::time::timeout(WATCHDOG, built.get(&address).send())
        .await
        .expect("the request ends")
        .expect("the server answers directly");
    assert_eq!(answered.status(), reqwest::StatusCode::NOT_FOUND);
}

/// KR-REQ-26.14: no proxy variable moves a client this product builds. In a process whose
/// `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` name a proxy that records what it is asked, a client
/// from [`kr_client::services::http::client_builder`] with no proxy named reaches its server
/// directly. The proxy is asked once, by the control: a client built the ordinary way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_proxy_variable_moves_a_client_this_product_builds() {
    let server = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let origin = format!(
        "http://127.0.0.1:{}",
        server.local_addr().expect("an address").port()
    );
    let reached = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&reached);
    let serving = tokio::spawn(async move {
        while let Ok((mut stream, _)) = server.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => head.push(byte),
                        Err(_) => return,
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    let proxy = ConnectProxy::refusing(502).await;

    let binary = std::env::current_exe().expect("this test binary");
    let variables = proxy.url.clone();
    let child_origin = origin.clone();
    let ran = tokio::task::spawn_blocking(move || {
        std::process::Command::new(binary)
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "the_child_of_the_proxy_variable_test",
            ])
            .env(SERVER, &child_origin)
            .env("HTTP_PROXY", &variables)
            .env("HTTPS_PROXY", &variables)
            .env("ALL_PROXY", &variables)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            // With it set, as in a CGI program, the plain-HTTP proxy variable is ignored.
            .env_remove("REQUEST_METHOD")
            .current_dir(std::env::temp_dir())
            .output()
            .expect("the child")
    })
    .await
    .expect("the child");
    serving.abort();

    assert!(
        ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("1 passed"),
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert_eq!(
        proxy.asked(),
        vec![format!("GET {origin}/probe HTTP/1.1")],
        "the control went to the proxy the variables name, and the built client did not"
    );
    assert_eq!(
        reached.load(Ordering::SeqCst),
        1,
        "the built client reached its server directly"
    );
}

/// A proxy that cannot be reached ends the request before anything is sent, and the gateway hears
/// nothing: the client does not go around the proxy it was given.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_client_does_not_go_around_a_proxy_that_cannot_be_reached() {
    let gateway = Gateway::start().await;
    let closed = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = closed.local_addr().expect("an address").port();
    drop(closed);
    let service = gateway.client(
        &format!("http://127.0.0.1:{port}")
            .parse()
            .expect("a proxy address"),
    );
    let answered = tokio::time::timeout(
        WATCHDOG,
        service.post_json(&format!("{}/api/probe", gateway.origin), b"{}", &[]),
    )
    .await
    .expect("the request ends");
    let error = answered.expect_err("the proxy cannot be reached");
    assert_eq!(
        error.code(),
        ErrorCode::UpstreamUnavailable,
        "nothing was sent: {error}"
    );
    gateway.heard_nothing().await;
}
