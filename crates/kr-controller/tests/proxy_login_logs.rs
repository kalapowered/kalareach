//! No log line holds the proxy's login or the front's secret once the directives are applied.
//!
//! The network library prints what it holds at `debug`: its relay client prints the proxy address
//! it was given, the user and the whole request. A host whose endpoint reaches its relay through
//! the front hands the library the front's address and secret, never the login, and its guides
//! name the directives that keep the secret out of a log. This suite is a test binary of its own
//! because it installs one global subscriber: it captures every event in memory, never prints
//! one, and decides what it lets through by two directives of its own. Phase one runs with none
//! and must find the front's secret, which shows that the search can find a login-bearing line.
//! Phase two runs with the directives and must find neither the secret nor any form of the login.
//!
//! It exercises the `tracing` route. With a global subscriber it does not exercise the `log`
//! fallback; the lines that print the secret are `tracing` macros, and a test that scans every
//! source keeps any `log` logger from being installed unreviewed.

// A relay server running in this process. This suite uses only its address and its roots.
#[path = "net_support/relay.rs"]
#[allow(dead_code)]
mod local_relay;

#[path = "../../kr-client/tests/support/connect_proxy.rs"]
mod connect_proxy;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use connect_proxy::{ConnectProxy, Login};
use kr_client::tunnel::ProxyTunnels;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_crypto::secret::SecretVec;
use kr_transport::config::{EndpointConfig, ProxyUrl};
use kr_transport::endpoint::bind_network;
use kr_transport::front::FrontOpener;
use kr_transport::proxy::ProxyCredential;
use local_relay::LocalRelay;
use rustls::{ClientConfig, RootCertStore};

const WATCHDOG: Duration = Duration::from_secs(30);

/// The user name and the password of the planted login.
const USER: &str = "planted-user-7f3c";
const PASSWORD: &str = "planted-pass-9b1d";

/// Every event the subscriber took, as one text each: its target, its level and its fields.
static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Whether the directives of the guides are applied.
static DIRECTIVES: AtomicBool = AtomicBool::new(false);

/// A subscriber that keeps every event it is let to see in memory.
#[derive(Default)]
struct Capture;

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        // The directives change while the suite runs, so no callsite's answer is kept.
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if !DIRECTIVES.load(Ordering::SeqCst) {
            return true;
        }
        let target = metadata.target();
        // `iroh_relay::client::tls=info` and `iroh::address_lookup::pkarr=error`.
        if target.starts_with("iroh_relay::client::tls") {
            return *metadata.level() <= tracing::Level::INFO;
        }
        if target.starts_with("iroh::address_lookup::pkarr") {
            return *metadata.level() <= tracing::Level::ERROR;
        }
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let text = format!(
            "{} {}{}",
            event.metadata().target(),
            event.metadata().level(),
            fields.0
        );
        EVENTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(text);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// The events captured so far.
fn captured() -> Vec<String> {
    EVENTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn forget() {
    EVENTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}

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

/// One dial of a network endpoint through the front and the proxy to the relay, and the front's
/// secret as that dial's endpoint held it.
async fn dial(relay: &LocalRelay, proxy: &ConnectProxy) -> String {
    let login = ProxyCredential::new(
        SecretVec::new(USER.as_bytes().to_vec()),
        SecretVec::new(PASSWORD.as_bytes().to_vec()),
    )
    .expect("a login");
    let proxy_url = proxy
        .url
        .parse::<ProxyUrl>()
        .expect("a proxy address")
        .with_login(login);
    let config = EndpointConfig {
        relay_urls: vec![relay.url.clone()],
        relay_ca_roots: relay.ca_roots.clone(),
        relay_only: true,
        login_front: Some(FrontOpener(Arc::new(ProxyTunnels::new(
            proxy_url.clone(),
            trusting(&[]),
        )))),
        proxy_url: Some(proxy_url),
        ..EndpointConfig::default()
    };
    let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
    let (endpoint, closer) = bind_network(&config, &identity)
        .await
        .expect("a network endpoint");
    tokio::time::timeout(WATCHDOG, endpoint.online())
        .await
        .expect("the endpoint reached its relay through the front");
    let secret = closer.front_probe().expect("a front").secret();
    closer.close().await;
    secret
}

/// The forms the login and the secret can take in a line.
fn needles(secret: &str) -> Vec<(&'static str, String)> {
    let encode = |text: String| base64::engine::general_purpose::STANDARD.encode(text);
    vec![
        ("the password", PASSWORD.to_owned()),
        ("the user", USER.to_owned()),
        (
            "the Basic form of the login",
            encode(format!("{USER}:{PASSWORD}")),
        ),
        ("the front's secret", secret.to_owned()),
        (
            "the Basic form of the front's secret",
            encode(format!("kr:{secret}")),
        ),
    ]
}

/// KR-REQ-10.02: without the directives the library prints the front's secret at `debug`, which
/// shows that the search finds a line that holds one; with the directives of the guides applied,
/// no event of a dial through the front and the proxy holds the secret, the password, the user or
/// either one's Basic form.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_log_holds_the_login_once_the_directives_are_applied() {
    let installed = tracing::subscriber::set_global_default(Capture::default());
    installed.expect("this suite installs the only subscriber of its process");
    let relay = LocalRelay::spawn().await;
    let proxy = ConnectProxy::authenticating(USER, PASSWORD, "Basic realm=\"x\"").await;

    // Phase one: no directives. The negative control.
    let secret = dial(&relay, &proxy).await;
    assert_eq!(
        proxy.logins().first(),
        Some(&Login::Right),
        "the dial went through the proxy with the login"
    );
    let events = captured();
    assert!(!events.is_empty(), "the subscriber captured events");
    assert!(
        events.iter().any(|event| event.contains(&secret)),
        "the library prints the front's secret at debug when no directive holds it back ({} events)",
        events.len()
    );

    // Phase two: the directives are applied, on a new endpoint with a new secret.
    DIRECTIVES.store(true, Ordering::SeqCst);
    forget();
    let secret = dial(&relay, &proxy).await;
    let events = captured();
    assert!(!events.is_empty(), "the subscriber still captured events");
    for (what, needle) in needles(&secret) {
        let holding: Vec<&String> = events
            .iter()
            .filter(|event| event.contains(&needle))
            .collect();
        assert!(
            holding.is_empty(),
            "an event holds {what} with the directives applied: {holding:?}"
        );
    }
}
