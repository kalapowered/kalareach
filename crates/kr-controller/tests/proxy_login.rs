//! The login this host holds for its proxy, as the controller reads and uses it: the stored item,
//! the address the start tests the proxy with, the one check the start makes, and the watch that
//! checks again after a request fails in a way that may be a refusal.
//!
//! The proxy is a stand-in on the loopback that never stores a header value. Each case waits for an
//! event it can see (a count, the verdict, a finished check) and never for a quiet interval.

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::time::Duration;

use connect_proxy::{ConnectProxy, Login};
use kr_controller::config::{ProxyItem, ProxyStart, Started};
use kr_controller::service::net::proxy_login::{
    Timing, Watch, check, item_bytes, item_name, proxy_tls, read_item, start_target,
};
use kr_crypto::secret::SecretVec;
use kr_crypto::store::{MemoryStore, SecretStore};
use kr_protocol::hostinfo::configuration::NetworkSelection;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Nullable;
use kr_transport::config::ProxyUrl;
use kr_transport::proxy::{ProxyCredential, StopKind, Target};
use tokio::net::TcpListener;

/// How long a case waits for something before it fails as stuck.
const WATCHDOG: Duration = Duration::from_secs(30);

fn credential(user: &str, password: &str) -> ProxyCredential {
    ProxyCredential::new(
        SecretVec::new(user.as_bytes().to_vec()),
        SecretVec::new(password.as_bytes().to_vec()),
    )
    .expect("a login")
}

/// A place the proxy can tunnel to.
async fn target() -> (TcpListener, Target) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let port = listener.local_addr().expect("its address").port();
    (
        listener,
        Target {
            host: "127.0.0.1".to_owned(),
            port,
        },
    )
}

fn proxy_at(proxy: &ConnectProxy, login: Option<ProxyCredential>) -> ProxyUrl {
    let url: ProxyUrl = proxy.url.parse().expect("a proxy address");
    match login {
        Some(login) => url.with_login(login),
        None => url,
    }
}

/// Waits until `done` holds, which a case raises by an event it can see.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    tokio::time::timeout(WATCHDOG, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("stuck waiting for {what}"));
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(uuid_one())
}

fn uuid_one() -> kr_protocol::scalars::Uuid {
    kr_protocol::scalars::Uuid::from_bytes([1; 16])
}

/// KR-REQ-10.02: the stored item is used only for the proxy it was made for, and every other
/// outcome reads as a stated item with the route holding no login.
#[test]
fn the_stored_login_is_used_only_for_the_proxy_it_was_made_for() {
    let proxy: ProxyUrl = "http://proxy.example.com:3128".parse().expect("a proxy");
    let store = MemoryStore::new();
    let name = item_name(environment()).expect("a name");

    assert_eq!(
        read_item(&store, environment(), Some(&proxy)).1,
        ProxyItem::Absent
    );
    assert_eq!(read_item(&store, environment(), None).1, ProxyItem::Absent);

    // The origin is compared as a parsed proxy: an explicit default port is the same origin.
    store
        .set(
            &name,
            item_bytes("http://Proxy.example.com:3128/", b"user:pass:word\n").expose(),
        )
        .expect("stored");
    let (login, item) = read_item(&store, environment(), Some(&proxy));
    assert_eq!(item, ProxyItem::Held);
    assert!(login.is_some_and(|login| login == credential("user", "pass:word")));

    store
        .set(
            &name,
            item_bytes("http://other.example.com:3128/", b"user:password").expose(),
        )
        .expect("stored");
    let (login, item) = read_item(&store, environment(), Some(&proxy));
    assert_eq!(item, ProxyItem::ForAnotherProxy);
    assert!(login.is_none());

    for broken in [
        b"no line feed".as_slice(),
        b"http://proxy.example.com:3128/\nno colon".as_slice(),
        b"http://proxy.example.com:3128/\n:empty user".as_slice(),
        b"not a proxy\nuser:password".as_slice(),
        b"http://proxy.example.com:3128/\n\xff\xfe:password".as_slice(),
    ] {
        store.set(&name, broken).expect("stored");
        let (login, item) = read_item(&store, environment(), Some(&proxy));
        assert_eq!(item, ProxyItem::Unreadable, "{broken:?}");
        assert!(login.is_none());
    }
}

/// KR-REQ-10.02: the start tests the proxy with the first selected relay, else the first Pkarr
/// server, else the first origin the route serves, and with nothing when the document names none.
#[test]
fn the_start_tests_the_proxy_with_the_first_address_it_can_serve() {
    let started = |network: NetworkSelection| Started {
        network,
        ..Started::default()
    };
    let of = |started: &Started| start_target(started);
    let target = |host: &str, port: u16| {
        Some(Target {
            host: host.to_owned(),
            port,
        })
    };
    let mut selection = NetworkSelection {
        relay_urls: Nullable::some(vec![
            "https://relay.example.com".to_owned(),
            "http://second.example.com:8080".to_owned(),
        ]),
        pkarr_publisher_url: Nullable::some("https://publish.example.com:8443".to_owned()),
        pkarr_resolver_url: Nullable::some("https://resolve.example.com".to_owned()),
        ..NetworkSelection::default()
    };
    assert_eq!(
        of(&started(selection.clone())),
        target("relay.example.com", 443)
    );
    selection.relay_urls = Nullable::null();
    assert_eq!(
        of(&started(selection.clone())),
        target("publish.example.com", 8443)
    );
    selection.pkarr_publisher_url = Nullable::null();
    assert_eq!(
        of(&started(selection.clone())),
        target("resolve.example.com", 443)
    );
    selection.pkarr_resolver_url = Nullable::null();
    assert_eq!(of(&started(selection)), None);

    // An origin another service names counts, and the managed origin does not count in a test
    // build that has not moved it.
    let mut with_origins = started(NetworkSelection::default());
    with_origins.authority.origin =
        Nullable::some(kr_client::services::account::ACCOUNT_ORIGIN.to_owned());
    with_origins.storage.origin = Nullable::some("https://storage.example.com".to_owned());
    assert_eq!(of(&with_origins), target("storage.example.com", 443));
}

/// KR-REQ-10.02: the check says what the proxy answered, as a state; a refused login sets the
/// verdict and none is written after it; the deadline ends a proxy that never finishes its answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_check_says_what_the_proxy_answered() {
    let (_held, to) = target().await;
    let tls = proxy_tls(&[]).expect("verification");
    let deadline = Duration::from_secs(5);

    let accepting = ConnectProxy::authenticating("user", "password", "Basic").await;
    let proxy = proxy_at(&accepting, Some(credential("user", "password")));
    assert_eq!(check(&proxy, &to, &tls, deadline).await, ProxyStart::Open);
    assert_eq!(accepting.logins(), vec![Login::Right]);

    let refusing = ConnectProxy::authenticating("user", "password", "Basic").await;
    let wrong = credential("user", "wrong");
    let proxy = proxy_at(&refusing, Some(wrong.clone()));
    assert_eq!(
        check(&proxy, &to, &tls, deadline).await,
        ProxyStart::LoginRefused
    );
    assert_eq!(wrong.stopped(), Some(StopKind::Refused));
    assert_eq!(refusing.logins(), vec![Login::Wrong]);
    // The verdict is set, so a second check sends nothing.
    assert_eq!(
        check(&proxy, &to, &tls, deadline).await,
        ProxyStart::LoginRefused
    );
    assert_eq!(refusing.logins(), vec![Login::Wrong]);

    let asking = ConnectProxy::authenticating("user", "password", "Basic").await;
    let proxy = proxy_at(&asking, None);
    assert_eq!(
        check(&proxy, &to, &tls, deadline).await,
        ProxyStart::NeedsLogin
    );

    let other_scheme = ConnectProxy::authenticating("user", "password", "NTLM").await;
    // The login is sent and refused with a scheme the host does not send: that is a limit of this
    // host, not a refusal of the login, and it is the same with no login held.
    let proxy = proxy_at(&other_scheme, Some(credential("user", "wrong")));
    assert_eq!(
        check(&proxy, &to, &tls, deadline).await,
        ProxyStart::SchemeUnsupported
    );
    assert_eq!(
        check(&proxy_at(&other_scheme, None), &to, &tls, deadline).await,
        ProxyStart::SchemeUnsupported
    );

    // Any other answer, and a proxy that never ends its head, leave the proxy unchecked.
    let broken = ConnectProxy::refusing(502).await;
    let proxy = proxy_at(&broken, None);
    assert_eq!(
        check(&proxy, &to, &tls, deadline).await,
        ProxyStart::Unchecked
    );
    let endless = ConnectProxy::answering_without_end().await;
    let proxy = proxy_at(&endless, None);
    assert_eq!(
        check(&proxy, &to, &tls, Duration::from_millis(200)).await,
        ProxyStart::Unchecked
    );
}

/// KR-REQ-10.02: the watch checks the proxy once for each suspected target, takes a target that
/// was queued while it checked another, and ends at the verdict: after a refusal it checks nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_watch_checks_once_for_each_suspicion_and_stops_at_the_verdict() {
    let (_held, first) = target().await;
    let (_held_too, second) = target().await;
    let tls = proxy_tls(&[]).expect("verification");
    let timing = Timing {
        deadline: Duration::from_secs(5),
        interval: Duration::from_millis(10),
    };

    let proxy = ConnectProxy::authenticating("user", "password", "Basic").await;
    let login = credential("user", "password");
    let watch = Watch::start(
        proxy_at(&proxy, Some(login.clone())),
        tls.clone(),
        timing.clone(),
    )
    .expect("a watch");
    // Both are queued before the watch can take one: the second is not left until another
    // failure comes.
    login.suspicion().suspect(first.clone());
    login.suspicion().suspect(second);
    // The same target is queued once.
    login.suspicion().suspect(first);
    until("two checks", || watch.checks_done() == 2).await;
    assert_eq!(proxy.logins(), vec![Login::Right, Login::Right]);
    drop(watch);

    // A login the proxy refuses: the first check sets the verdict, and the watch ends.
    let refusing = ConnectProxy::authenticating("user", "password", "Basic").await;
    let wrong = credential("user", "wrong");
    let (_held, one) = target().await;
    let (_held_too, two) = target().await;
    let watch =
        Watch::start(proxy_at(&refusing, Some(wrong.clone())), tls, timing).expect("a watch");
    wrong.suspicion().suspect(one);
    until("the verdict", || wrong.stopped().is_some()).await;
    until("the first check", || watch.checks_done() == 1).await;
    // The watch ends at the verdict and takes no further suspicion: the proxy saw the one wrong
    // login and no other.
    until("the watch to end", || watch.ended()).await;
    wrong.suspicion().suspect(two);
    assert_eq!(watch.checks_done(), 1);
    assert_eq!(refusing.logins(), vec![Login::Wrong]);
}
