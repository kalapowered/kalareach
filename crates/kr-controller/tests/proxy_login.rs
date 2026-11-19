//! The login this host holds for its proxy, as the controller reads and uses it: the stored item,
//! the address the start tests the proxy with, the one check the start makes, and the watch that
//! checks again after a request fails in a way that may be a refusal.
//!
//! The proxy is a stand-in on the loopback that never stores a header value. Each case waits for an
//! event it can see (a count, the verdict, a finished check) and never for a quiet interval.

mod net_support;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::time::Duration;

use connect_proxy::{ConnectProxy, Login};
use kr_controller::config::{Outbound, ProxyItem, ProxyStart, Started};
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

    // A plain-`http` origin is never a target: the next `https` origin is taken, and a document
    // that names only plain-`http` origins has no target.
    let mut plain = started(NetworkSelection::default());
    plain.authority.origin = Nullable::some("http://127.0.0.1:8080".to_owned());
    plain.mailbox.origin = Nullable::some("http://mailbox.example.com".to_owned());
    assert_eq!(of(&plain), None, "plain-http origins alone give no target");
    plain.storage.origin = Nullable::some("https://storage.example.com".to_owned());
    assert_eq!(
        of(&plain),
        target("storage.example.com", 443),
        "an https origin after plain-http origins is taken"
    );
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

/// KR-REQ-10.02: a host whose document names nothing to test the proxy with still finds a proxy
/// that refuses in `HTTP/1.0`: a request that failed the way such a refusal fails queues the
/// address it went to, the watch checks that address once through the one writer, and the verdict
/// is set by that check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_request_to_an_address_the_start_never_tested_is_rechecked_at_that_address() {
    let (_held, failed) = target().await;
    let proxy = ConnectProxy::authenticating_in_http10("user", "password", "Basic").await;
    let wrong = credential("user", "wrong");
    let through = proxy_at(&proxy, Some(wrong.clone()));
    assert!(
        start_target(&Started::default()).is_none(),
        "the document names no address to test the proxy with"
    );
    let tls = proxy_tls(&[]).expect("verification");
    let watch = Watch::start(
        through.clone(),
        tls.clone(),
        Timing {
            deadline: Duration::from_secs(5),
            interval: Duration::from_millis(10),
        },
    )
    .expect("a watch");

    // A service request through the proxy fails the way an `HTTP/1.0 407` fails: the library has
    // no word for it, and the request that failed names the address the watch checks.
    let client = kr_transport::proxy::proxied(
        reqwest::Client::builder()
            .timeout(WATCHDOG)
            .tls_backend_preconfigured((*tls).clone()),
        &through,
    )
    .expect("a proxy the library takes")
    .build()
    .expect("a client");
    let address: url::Url = format!("https://127.0.0.1:{}/key", failed.port)
        .parse()
        .expect("an address");
    let error = client
        .get(address.clone())
        .send()
        .await
        .expect_err("the proxy refuses the tunnel");
    assert!(
        wrong.stopped().is_none(),
        "the library read no refusal of the login in it"
    );
    kr_transport::proxy::note_failure(&through, &address, &error);
    assert!(
        tokio::time::timeout(Duration::from_secs(10), async {
            while wrong.stopped().is_none() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok(),
        "the watch's check set the verdict"
    );
    assert_eq!(wrong.stopped(), Some(StopKind::Refused));
    assert_eq!(proxy.logins(), vec![Login::Wrong, Login::Wrong]);
    let asked = proxy.asked();
    let named = format!("CONNECT 127.0.0.1:{} ", failed.port);
    assert!(
        asked.len() == 2 && asked.iter().all(|line| line.starts_with(&named)),
        "the request and the one re-check named the failed address: {asked:?}"
    );
    drop(watch);
}

/// KR-REQ-10.02: a proxy whose re-checks meet no refusal is not asked again at once: a suspicion
/// that repeats three times is met by three checks, each at least one interval after the one
/// before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rechecks_that_meet_no_refusal_are_at_least_one_interval_apart() {
    let (_held, checked) = target().await;
    let proxy = ConnectProxy::authenticating("user", "password", "Basic").await;
    let right = credential("user", "password");
    let tls = proxy_tls(&[]).expect("verification");
    let interval = Duration::from_millis(300);
    let watch = Watch::start(
        proxy_at(&proxy, Some(right.clone())),
        tls,
        Timing {
            deadline: Duration::from_secs(5),
            interval,
        },
    )
    .expect("a watch");
    for round in 1..=3_u64 {
        right.suspicion().suspect(checked.clone());
        until("the round's check", || watch.checks_done() >= round).await;
    }
    let calls = proxy.calls();
    assert_eq!(
        calls.len(),
        3,
        "one request for each check, and no other: {calls:?}"
    );
    assert!(right.stopped().is_none(), "no check met a refusal");
    for pair in calls.windows(2) {
        let apart = pair[1].at.duration_since(pair[0].at);
        assert!(
            apart >= interval,
            "two checks were {apart:?} apart, less than the interval {interval:?}"
        );
    }
    drop(watch);
}

/// The daemon of a case: the controller, started over the folders of a temporary host.
async fn start_controller(
    host: &kr_ipc::testing::TempHost,
) -> std::sync::Arc<kr_controller::service::Controller> {
    let environment = host.environment();
    let environment_id = host.environment_id();
    kr_controller::testing::taken_over(|| {
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
    })
    .await
    .unwrap_or_else(|error| panic!("the daemon starts: {error}"))
}

/// KR-REQ-10.02: no value the controller keeps for a start that holds a login prints it, in any
/// spelling: the start's reading, the route, the network's settings and setup, the network that
/// is on the proxy through the front, and the relays of its endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_login_is_in_any_debug_of_the_start_or_the_network() {
    use base64::Engine as _;
    const USER: &str = "usér-planted";
    const SECRET: &str = "p4ss-planted-7f3c";
    let proxy = ConnectProxy::authenticating(USER, SECRET, "Basic realm=\"proxy\"").await;
    let relay = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = relay.local_addr().expect("an address").port();
    let held = tokio::spawn(async move {
        let mut kept = Vec::new();
        while let Ok((stream, _)) = relay.accept().await {
            kept.push(stream);
        }
    });
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{SECRET}"));
    let forms = [USER, SECRET, basic.as_str(), "us%C3%A9r-planted"];

    // The search finds a login that is there, so a clean result means something.
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Printing(String);
    let control = format!("{:?}", Printing(format!("{USER}:{SECRET}")));
    assert!(
        forms[..2].iter().all(|form| control.contains(form)),
        "the search finds a printed login: {control}"
    );

    let login = credential(USER, SECRET);
    let through = proxy_at(&proxy, Some(login.clone()));
    let selection = NetworkSelection {
        enabled: Nullable::some(true),
        bind_address: Nullable::some("127.0.0.1:0".to_owned()),
        relay_urls: Nullable::some(vec![format!("https://127.0.0.1:{port}")]),
        proxy_url: Nullable::some(proxy.url.clone()),
        ..NetworkSelection::default()
    };
    let started = Started {
        network: selection.clone(),
        proxy_login: Some(login.clone()),
        ..Started::default()
    };
    let route = Outbound::Through(through.clone());
    let settings = kr_controller::service::net::config::NetworkSettings::from_selection(
        &selection,
        Some(through),
    )
    .expect("a usable selection")
    .expect("this host joins");
    let setup = kr_controller::service::net::NetworkSetup {
        settings: settings.clone(),
        secrets: std::sync::Arc::new(MemoryStore::new()),
        rendezvous: None,
    };
    let mut printed = vec![
        ("Started", format!("{started:?}")),
        ("Outbound", format!("{route:?}")),
        ("NetworkSettings", format!("{settings:?}")),
        ("NetworkSetup", format!("{setup:?}")),
    ];

    let host = kr_ipc::testing::TempHost::create();
    let controller = start_controller(&host).await;
    let network = kr_controller::service::net::register(&controller, setup)
        .await
        .expect("the daemon joins the network through the front");
    printed.push(("Network", format!("{network:?}")));
    let endpoint = network
        .endpoint_for_tests()
        .expect("the network holds an endpoint");
    let relays =
        kr_controller::relay_leases::endpoint::EndpointRelays::new(endpoint, &settings.endpoint);
    printed.push(("EndpointRelays", format!("{relays:?}")));
    for (what, text) in &printed {
        for form in forms {
            assert!(!text.contains(form), "{what} prints the login: {text}");
        }
    }
    // The panic message of an assertion over a value that prints holds none either.
    let caught = std::panic::catch_unwind(|| {
        let text = format!("{started:?}");
        assert!(text.is_empty(), "the start is {started:?}");
    })
    .expect_err("the assertion fails");
    let message = caught.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(!message.is_empty(), "the panic says what it formed");
    for form in forms {
        assert!(
            !message.contains(form),
            "a panic message prints the login: {message}"
        );
    }
    drop(network);
    drop(controller);
    held.abort();
}
