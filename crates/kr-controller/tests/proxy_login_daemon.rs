//! A real daemon behind a proxy that asks for a login: the program starts from a private folder on
//! the internal disk, reads the configuration document and the secret store of that folder, tests
//! the proxy once at its start, and says what it found in the diagnostics it answers on its own
//! socket.
//!
//! The proxy is a stand-in on the loopback. The password is planted: it is in no answer, no
//! diagnostic and no line of the daemon's log.

#![cfg(unix)]

mod net_support;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::time::Duration;

use base64::Engine as _;
use connect_proxy::{ConnectProxy, Login};
use kr_controller::service::net::proxy_login::{item_bytes, item_name};
use kr_crypto::store::open_store_in;
use kr_protocol::delivery::SecretText;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::network_proxy::NetworkProxyLoginSetParams;
use kr_protocol::scalars::Nullable;
use tokio::net::TcpListener;

/// A password that must be found in no answer and no log line.
const PASSWORD: &str = "p4ss-planted-7f3c";

/// The program of one daemon, and the process it becomes.
struct Daemon(Option<std::process::Child>);

impl Daemon {
    /// Starts the daemon program, placed on the internal disk, on the folders of `host`, with an
    /// empty environment but its home and the system's own program directories.
    fn start(host: &kr_ipc::testing::TempHost) -> Self {
        let program = host.root().join("kr-controller");
        if !program.exists() {
            kr_ipc::testing::place_program(
                std::path::Path::new(env!("CARGO_BIN_EXE_kr-controller")),
                &program,
            );
        }
        let home = host.root().join("home");
        std::fs::create_dir_all(&home).expect("a home directory");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(host.root().join("daemon.log"))
            .expect("opens the daemon's log");
        let child = std::process::Command::new(&program)
            .current_dir(host.root())
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .arg("--runtime-dir")
            .arg(host.root().join("r"))
            .arg("--state-dir")
            .arg(host.root().join("s"))
            .arg("--worker")
            .arg(host.root().join("no-such-worker"))
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        Self(Some(child))
    }

    /// Ends the daemon and waits for it.
    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A local client of the daemon on `host`, once it answers.
async fn local_client(host: &kr_ipc::testing::TempHost) -> kr_ipc::client::LocalClient {
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(client) = kr_ipc::client::LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            net_support::build(),
        )
        .await
        {
            return client;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not answer within two minutes; its log says: {}",
            std::fs::read_to_string(host.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The detail of the network check of the diagnostics the daemon answers.
async fn network_detail(host: &kr_ipc::testing::TempHost) -> String {
    let mut client = local_client(host).await;
    let answer = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket");
    let doctor: HostDoctorResult = answer.to_typed().expect("the diagnostics");
    doctor
        .checks
        .iter()
        .find(|check| check.id() == "configuration-network")
        .expect("the network check")
        .detail()
        .to_owned()
}

/// A host whose document joins the network through `proxy`, with a relay that accepts connections
/// and holds them.
async fn host_behind(
    proxy: &ConnectProxy,
) -> (
    kr_ipc::testing::TempHost,
    tokio::task::JoinHandle<()>,
    String,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let held = tokio::spawn(async move {
        let mut kept = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            kept.push(stream);
        }
    });
    let host = kr_ipc::testing::TempHost::create();
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.network.enabled = Nullable::some(true);
    document.network.relay_urls = Nullable::some(vec![format!("https://127.0.0.1:{port}")]);
    document.network.proxy_url = Nullable::some(proxy.url.clone());
    net_support::write_document(&host, &document);
    (host, held, format!("127.0.0.1:{port}"))
}

/// Keeps `user:PASSWORD` as the login this host holds for `proxy`, in the file store the daemon
/// reads.
fn store_login(host: &kr_ipc::testing::TempHost, proxy: &ConnectProxy, user: &str, password: &str) {
    let store = open_store_in(&host.environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in")
        .store;
    let name = item_name(host.environment_id()).expect("the item's name");
    store
        .set(
            &name,
            item_bytes(&proxy.url, format!("{user}:{password}").as_bytes()).expose(),
        )
        .expect("the item is kept");
}

/// KR-REQ-10.02: a daemon behind a proxy that asks for a login, with none stored, starts, says so
/// in the diagnostics, and is not on the network; a login the owner stores is not in force until
/// the next start, which the diagnostics say; and at the next start the daemon is on the network
/// and the proxy has been written the login it takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_behind_a_proxy_that_asks_for_a_login_starts_says_so_and_takes_the_login_at_its_next_start()
 {
    let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (host, _relay, _) = host_behind(&proxy).await;

    let mut daemon = Daemon::start(&host);
    let said = network_detail(&host).await;
    assert!(
        said.contains("the proxy requires a sign-in, and this host holds no login for it"),
        "{said}"
    );
    assert!(
        said.contains("this host is not on the network"),
        "no endpoint is registered: {said}"
    );
    assert_eq!(proxy.logins(), vec![Login::Absent], "the start check, once");

    // The owner stores the login, which is not in force until the host starts again.
    let mut control = local_client(&host).await;
    control
        .mutate(
            Method::NetworkProxyLoginSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id()),
            &NetworkProxyLoginSetParams {
                proxy: proxy.url.clone(),
                login: SecretText::new(format!("user:{PASSWORD}")).expect("a credential text"),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the owner stores the login");
    let said = network_detail(&host).await;
    assert!(
        said.contains(
            "changed since this host started, and the change applies when the host restarts"
        ),
        "{said}"
    );
    assert!(
        said.contains("this host is not on the network"),
        "the login is not in force yet: {said}"
    );

    daemon.stop();
    let mut daemon = Daemon::start(&host);
    let said = network_detail(&host).await;
    assert!(said.contains("this host is on the network"), "{said}");
    assert!(
        !said.contains("requires a sign-in") && !said.contains("refused the login"),
        "{said}"
    );
    assert_eq!(
        proxy.logins().last(),
        Some(&Login::Right),
        "the proxy was written the login it takes: {:?}",
        proxy.logins()
    );
    assert!(
        !proxy.logins().contains(&Login::Wrong),
        "{:?}",
        proxy.logins()
    );
    daemon.stop();
    let log = std::fs::read_to_string(host.root().join("daemon.log")).unwrap_or_default();
    assert!(!log.contains(PASSWORD), "the daemon's log holds the login");
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("user:{PASSWORD}"));
    assert!(!log.contains(&basic), "the daemon's log holds the login");
}

/// KR-REQ-10.02: a daemon whose stored login the proxy refuses is written no login after the
/// check that found the refusal: the proxy counts one wrong login, the diagnostics say that the
/// proxy refused it and that this host starts no new request through the proxy, and the local
/// socket serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_login_is_sent_once_and_the_daemon_stops_every_request_through_the_proxy() {
    let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (host, _relay, _) = host_behind(&proxy).await;
    store_login(&host, &proxy, "user", "not-the-password");

    let mut daemon = Daemon::start(&host);
    let said = network_detail(&host).await;
    assert!(
        said.contains("the proxy refused the login this host holds, so this host starts no new request through the proxy"),
        "{said}"
    );
    assert!(
        said.contains("this host is not on the network"),
        "no endpoint is registered: {said}"
    );
    assert_eq!(
        proxy.logins(),
        vec![Login::Wrong],
        "the check's own request, and no other"
    );
    daemon.stop();
    let log = std::fs::read_to_string(host.root().join("daemon.log")).unwrap_or_default();
    assert!(!log.contains("not-the-password"), "the log holds the login");
}

/// KR-REQ-10.02: a proxy that stops taking the login after a good start ends the daemon's network
/// endpoint, and the daemon keeps serving: the relay's connection through the proxy is ended, the
/// library dials again through the front, the proxy refuses the login, the endpoint is closed, and
/// the diagnostics say so on the local socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_after_a_good_start_closes_the_endpoint_and_the_daemon_keeps_serving() {
    let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (host, _relay, relay) = host_behind(&proxy).await;
    store_login(&host, &proxy, "user", PASSWORD);

    let mut daemon = Daemon::start(&host);
    let said = network_detail(&host).await;
    assert!(said.contains("this host is on the network"), "{said}");

    // The proxy changes its login and ends the relay's tunnel: the library's next dial is refused.
    proxy.change_login("user", "another-password");
    let said = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            proxy.close_tunnels_to(&relay);
            let said = network_detail(&host).await;
            if said.contains("closed its network endpoint") {
                return said;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the endpoint was closed after the proxy's refusal");
    assert!(
        said.contains("the proxy refused the login this host holds, so this host starts no new request through the proxy"),
        "{said}"
    );
    assert!(
        said.contains("the local socket still serves"),
        "the daemon keeps serving: {said}"
    );
    daemon.stop();
    let log = std::fs::read_to_string(host.root().join("daemon.log")).unwrap_or_default();
    assert!(!log.contains(PASSWORD), "the daemon's log holds the login");
}
