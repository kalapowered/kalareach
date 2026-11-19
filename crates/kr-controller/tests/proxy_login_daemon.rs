//! A real daemon behind a proxy that asks for a login: the program starts from a private folder on
//! the internal disk, reads the configuration document and the secret store of that folder, tests
//! the proxy once at its start, and says what it found in the diagnostics it answers on its own
//! socket.
//!
//! The proxy is a stand-in on the loopback. The password is planted: it is in no answer, no
//! diagnostic and no line of the daemon's log.

#![cfg(unix)]

mod net_support;

#[path = "../../kr-client/src/services/http/connect_proxy.rs"]
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
        Self::start_with(host, &[])
    }

    /// As [`Self::start`], with the environment variables `variables` set.
    fn start_with(host: &kr_ipc::testing::TempHost, variables: &[(&str, &str)]) -> Self {
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
            .envs(variables.iter().copied())
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
    check_detail(host, "configuration-network").await
}

/// The detail of the check `id` of the diagnostics the daemon answers.
async fn check_detail(host: &kr_ipc::testing::TempHost, id: &str) -> String {
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
        .find(|check| check.id() == id)
        .unwrap_or_else(|| panic!("the {id} check"))
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
    host_behind_with(proxy, |_| {}).await
}

/// [`host_behind`], with `change` applied to the document before it is written.
async fn host_behind_with(
    proxy: &ConnectProxy,
    change: impl FnOnce(&mut ConfigurationDocument),
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
    change(&mut document);
    net_support::write_document(&host, &document);
    (host, held, format!("127.0.0.1:{port}"))
}

/// An origin that nothing listens on: its `https` address and the `host:port` a `CONNECT` to it
/// names.
async fn unused_origin() -> (String, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    drop(listener);
    (
        format!("https://127.0.0.1:{port}"),
        format!("127.0.0.1:{port}"),
    )
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

/// Keeps `bytes` as the stored login item of `host`, whatever they are.
fn store_item(host: &kr_ipc::testing::TempHost, bytes: &[u8]) {
    let store = open_store_in(&host.environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in")
        .store;
    let name = item_name(host.environment_id()).expect("the item's name");
    store.set(&name, bytes).expect("the item is kept");
}

/// KR-REQ-10.02: an item that cannot be read, an item that does not decode and an item made for
/// another proxy each send no login: the proxy sees the start check's request with none, the
/// diagnostics state which of the two it was, and the daemon starts and serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_item_and_an_item_for_another_proxy_send_no_login() {
    const UNREADABLE: &str = "the proxy login stored on this host could not be read when the host started, so none was sent";
    const ANOTHER: &str = "the stored proxy login was made for another proxy, so this host did not send it when it started";
    let line = format!("user:{PASSWORD}");
    for label in [
        "no line feed",
        "an origin that is no address",
        "a line with no colon",
        "a place that holds a directory",
        "another proxy",
    ] {
        let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
        let (host, _relay, _) = host_behind(&proxy).await;
        let (bytes, says) = match label {
            "no line feed" => (b"a stored value that is no item".to_vec(), UNREADABLE),
            "an origin that is no address" => (
                item_bytes("not an address", line.as_bytes())
                    .expose()
                    .to_vec(),
                UNREADABLE,
            ),
            "a line with no colon" => (
                item_bytes(&proxy.url, b"no-colon-here").expose().to_vec(),
                UNREADABLE,
            ),
            "a place that holds a directory" => {
                // The item is written, then its place is given to a directory: a read of it fails.
                store_login(&host, &proxy, "user", PASSWORD);
                let path = host
                    .environment()
                    .secrets_dir()
                    .join(host.environment_id().to_string())
                    .join("network-proxy-login");
                std::fs::remove_file(&path).expect("the item's file");
                std::fs::create_dir(&path).expect("a directory in its place");
                (Vec::new(), UNREADABLE)
            }
            _ => (
                item_bytes("http://127.0.0.1:9", line.as_bytes())
                    .expose()
                    .to_vec(),
                ANOTHER,
            ),
        };
        if !bytes.is_empty() {
            store_item(&host, &bytes);
        }

        let mut daemon = Daemon::start(&host);
        let said = network_detail(&host).await;
        assert!(said.contains(says), "{label}: {said}");
        assert!(
            said.contains("the proxy requires a sign-in, and this host holds no login for it"),
            "{label}: the route holds no login: {said}"
        );
        assert_eq!(
            proxy.logins(),
            vec![Login::Absent],
            "{label}: the proxy was written no login"
        );
        daemon.stop();
        let log = std::fs::read_to_string(host.root().join("daemon.log")).unwrap_or_default();
        assert!(!log.contains(PASSWORD), "{label}: the log holds the login");
    }
}

/// What the stand-in proxy does for a row of the scheme table.
enum Behaviour {
    /// Opens a tunnel for a request that carries Basic with the right login, and answers every
    /// other with `407` offering these challenges.
    Authenticates(&'static str),
    /// Opens every tunnel.
    Opens,
    /// Refuses every request with this status.
    Refuses(u16),
}

/// One row of the scheme table: its name, what the proxy does, the password of the login stored
/// beforehand (none, or one the proxy does not take), the sentence the diagnostics must hold, the
/// sentence they must not, and the one login the proxy must have been written (none for a row that
/// does not stop at the check).
type Row = (
    &'static str,
    Behaviour,
    Option<&'static str>,
    &'static str,
    &'static str,
    Option<Login>,
);

/// KR-REQ-10.02: the sign-in the proxy asks for decides the state the daemon reports: a proxy that
/// offers no Basic is "unsupported" whether or not a login is held, never "refused"; a Basic
/// challenge with no login held needs one and with a wrong one refuses it; a bare challenge reads
/// as Basic; an open proxy joins the network; any other status says the check could not tell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scheme_the_proxy_asks_for_decides_the_state_the_daemon_reports() {
    const UNSUPPORTED: &str = "the proxy asks for a sign-in method this host does not support; this host can send only a user name and password (Basic)";
    const NEEDED: &str = "the proxy requires a sign-in, and this host holds no login for it";
    const REFUSED: &str = "the proxy refused the login this host holds, so this host starts no new request through the proxy";
    const UNCHECKED: &str = "the start check could not tell whether the proxy asks for a login";
    let rows: [Row; 9] = [
        (
            "NTLM, no login",
            Behaviour::Authenticates("NTLM"),
            None,
            UNSUPPORTED,
            REFUSED,
            Some(Login::Absent),
        ),
        (
            "NTLM, a wrong login",
            Behaviour::Authenticates("Negotiate, NTLM"),
            Some("another"),
            UNSUPPORTED,
            REFUSED,
            Some(Login::Wrong),
        ),
        (
            "Basic, no login",
            Behaviour::Authenticates("Basic realm=\"proxy\""),
            None,
            NEEDED,
            REFUSED,
            Some(Login::Absent),
        ),
        (
            "Basic, a wrong login",
            Behaviour::Authenticates("Basic realm=\"proxy\""),
            Some("another"),
            REFUSED,
            NEEDED,
            Some(Login::Wrong),
        ),
        (
            "a bare challenge, no login",
            Behaviour::Authenticates(""),
            None,
            NEEDED,
            UNSUPPORTED,
            Some(Login::Absent),
        ),
        (
            "a bare challenge, a wrong login",
            Behaviour::Authenticates(""),
            Some("another"),
            REFUSED,
            UNSUPPORTED,
            Some(Login::Wrong),
        ),
        (
            "NTLM and Basic, no login",
            Behaviour::Authenticates("NTLM, Basic realm=\"proxy\""),
            None,
            NEEDED,
            UNSUPPORTED,
            Some(Login::Absent),
        ),
        (
            "a proxy that opens",
            Behaviour::Opens,
            None,
            "this host is on the network",
            REFUSED,
            None,
        ),
        (
            "a status 403",
            Behaviour::Refuses(403),
            None,
            UNCHECKED,
            NEEDED,
            None,
        ),
    ];
    for (label, behaviour, stored, says, never, written) in rows {
        let proxy = match behaviour {
            Behaviour::Authenticates(offered) => {
                ConnectProxy::authenticating("user", PASSWORD, offered).await
            }
            Behaviour::Opens => ConnectProxy::tunnelling().await,
            Behaviour::Refuses(status) => ConnectProxy::refusing(status).await,
        };
        let (host, _relay, _) = host_behind(&proxy).await;
        if let Some(password) = stored {
            store_login(&host, &proxy, "user", password);
        }
        let mut daemon = Daemon::start(&host);
        let said = network_detail(&host).await;
        assert!(said.contains(says), "{label}: {said}");
        assert!(!said.contains(never), "{label}: {said}");
        if let Some(written) = written {
            assert_eq!(
                proxy.logins(),
                vec![written],
                "{label}: the check's own request, and no other"
            );
            assert!(
                said.contains("this host is not on the network"),
                "{label}: no endpoint is registered: {said}"
            );
        } else {
            assert!(
                said.contains("this host is on the network"),
                "{label}: the check does not stop the network: {said}"
            );
        }
        daemon.stop();
    }
}

/// KR-REQ-10.02: a request that goes to an address the start never tested, and that the proxy
/// refuses in words no library reads (`HTTP/1.0 407`), is found by the watch's re-check at that
/// address: the proxy is written the login once more, the verdict is set, and the diagnostics say
/// that the proxy refused the login.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_proxy_refuses_without_a_word_is_found_by_the_recheck_at_its_own_address() {
    let proxy =
        ConnectProxy::authenticating_in_http10("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (origin, target) = unused_origin().await;
    proxy.refuse_target(&target);
    let (host, _relay, tested) = host_behind_with(&proxy, |document| {
        document.relay.origin = Nullable::some(origin.clone());
    })
    .await;
    store_login(&host, &proxy, "user", PASSWORD);

    let mut daemon = Daemon::start_with(
        &host,
        &[(
            kr_controller::testing::ACCOUNT_ORIGIN_VARIABLE,
            origin.as_str(),
        )],
    );
    let said = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let said = network_detail(&host).await;
            if said.contains("the proxy refused the login this host holds") {
                return said;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the diagnostics said that the proxy refused the login");
    assert!(
        said.contains("this host starts no new request through the proxy"),
        "{said}"
    );
    let calls = proxy.calls();
    assert_eq!(
        calls.first().and_then(|call| call.target.as_deref()),
        Some(tested.as_str()),
        "the start check's own request is the first the proxy reads: {calls:?}"
    );
    let to_the_address: Vec<_> = calls
        .iter()
        .filter(|call| call.target.as_deref() == Some(target.as_str()))
        .collect();
    assert!(
        to_the_address.len() >= 2,
        "the carrier's request and the re-check's both reached the proxy: {calls:?}"
    );
    assert!(
        to_the_address.iter().all(|call| call.login == Login::Right),
        "each request to the address carried the login the proxy takes: {calls:?}"
    );
    daemon.stop();
    let log = std::fs::read_to_string(host.root().join("daemon.log")).unwrap_or_default();
    assert!(!log.contains(PASSWORD), "the daemon's log holds the login");
}

/// KR-REQ-10.02: a login the proxy refuses is written once although the release matrix, the
/// authority feed and the mailbox reader are configured and each asks at once: the check's own
/// request is the only one the proxy reads, and the rows of the feed and of the reader say that the
/// proxy's login stopped them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_login_is_sent_once_although_the_matrix_the_feed_and_the_mailbox_each_ask() {
    let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (origin, _) = unused_origin().await;
    let (feed_origin, _) = unused_origin().await;
    let (host, _relay, tested) = host_behind_with(&proxy, |document| {
        document.relay.origin = Nullable::some(origin.clone());
        document.authority.origin = Nullable::some(feed_origin.clone());
    })
    .await;
    store_login(&host, &proxy, "user", "not-the-password");

    let mut daemon = Daemon::start_with(
        &host,
        &[(
            kr_controller::testing::ACCOUNT_ORIGIN_VARIABLE,
            origin.as_str(),
        )],
    );
    let said = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let said = network_detail(&host).await;
            if said.contains("the proxy refused the login this host holds") {
                return said;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the diagnostics said that the proxy refused the login");
    let clause = kr_transport::proxy::ProxyLoginKind::Refused.clause();
    for carrier in ["authority-feed", "mailbox-reader"] {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                if check_detail(&host, carrier).await.contains(clause) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the {carrier} row said the proxy's login stopped it"));
    }
    let calls = proxy.calls();
    assert_eq!(
        calls.len(),
        1,
        "the check's own request, and no other: {calls:?} ({said})"
    );
    assert_eq!(calls[0].target.as_deref(), Some(tested.as_str()));
    assert_eq!(calls[0].login, Login::Wrong);
    daemon.stop();
}

/// KR-REQ-10.02: a trust anchor that cannot be read, in a section that joins the network, ends the
/// start with the anchors' own error, as it does with no proxy, and sends no request through the
/// proxy: the check does not run on a trust it could not build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trust_anchor_that_cannot_be_read_ends_the_start_with_its_own_error_and_sends_nothing() {
    let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (host, _relay, _) = host_behind_with(&proxy, |document| {
        let missing = std::env::temp_dir().join("kr-no-such-anchor.der");
        document.network.relay_trust_anchors =
            Nullable::some(vec![missing.to_string_lossy().into_owned()]);
    })
    .await;
    store_login(&host, &proxy, "user", PASSWORD);

    let mut daemon = Daemon::start(&host);
    let status = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let child = daemon.0.as_mut().expect("a running daemon");
            if let Some(status) = child.try_wait().expect("the daemon's state") {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the daemon's process ended with the anchors' error");
    assert!(!status.success(), "the start ended in failure: {status}");
    let log = std::fs::read_to_string(host.root().join("daemon.log")).unwrap_or_default();
    assert!(
        log.contains("network.relay_trust_anchors entry 1") && log.contains("is not usable"),
        "the start says why it ended: {log}"
    );
    assert!(
        proxy.calls().is_empty(),
        "no request was sent through the proxy: {:?}",
        proxy.calls()
    );
    assert!(!log.contains(PASSWORD), "the daemon's log holds the login");
}

/// KR-REQ-10.02: a section that does not join the network reads no trust anchor, so a file that
/// cannot be read there stops nothing: the daemon starts and answers, and the proxy is sent
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_section_that_does_not_join_reads_no_trust_anchor_and_the_daemon_starts() {
    let proxy = ConnectProxy::authenticating("user", PASSWORD, "Basic realm=\"proxy\"").await;
    let (host, _relay, _) = host_behind_with(&proxy, |document| {
        document.network.enabled = Nullable::some(false);
        document.network.relay_urls = Nullable::null();
        let missing = std::env::temp_dir().join("kr-no-such-anchor.der");
        document.network.relay_trust_anchors =
            Nullable::some(vec![missing.to_string_lossy().into_owned()]);
    })
    .await;
    store_login(&host, &proxy, "user", PASSWORD);

    let mut daemon = Daemon::start(&host);
    let said = network_detail(&host).await;
    assert!(
        !said.contains("relay_trust_anchors"),
        "no anchor is read where the section does not join: {said}"
    );
    assert!(
        proxy.calls().is_empty(),
        "nothing named a target to test the proxy with: {:?}",
        proxy.calls()
    );
    daemon.stop();
}
