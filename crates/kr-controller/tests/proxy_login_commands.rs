//! The owner keeps, replaces and clears the login the host's proxy asks for, at this machine, over
//! the daemon's local socket. The daemon alone writes the secret store, and no answer carries the
//! login back.
//!
//! Everything runs on this machine's loopback interface and in temporary directories on the
//! internal disk.

mod net_support;

use kr_controller::config::ProxyItem;
use kr_controller::service::net::proxy_login::{item_bytes, item_name, read_item};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::secret::SecretVec;
use kr_crypto::store::open_store_in;
use kr_crypto::store::{MemoryStore, SecretName, SecretStore};
use kr_protocol::delivery::SecretText;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::network_proxy::{
    NetworkProxyLoginClearParams, NetworkProxyLoginResult, NetworkProxyLoginSetParams,
};
use kr_transport::config::ProxyUrl;

/// A password that must be found in no answer, no error and no byte of the registry.
const PASSWORD: &str = "p%41ss:wörd-7f3c9a";

/// A word with no colon in it, for the logins that must be refused for having none.
const WORD: &str = "p%41ss-wörd-7f3c9a";

fn params(proxy: &str, login: &str) -> NetworkProxyLoginSetParams {
    NetworkProxyLoginSetParams {
        proxy: proxy.to_owned(),
        login: SecretText::new(login).expect("a credential text"),
    }
}

async fn set(
    control: &mut kr_ipc::client::LocalClient,
    host: &net_support::Host,
    params: &NetworkProxyLoginSetParams,
) -> Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            Method::NetworkProxyLoginSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
}

fn rendered(answer: &Result<ParamsValue, ProtocolError>) -> String {
    match answer {
        Ok(value) => format!("{value:?}"),
        Err(error) => format!("{error:?} {error}"),
    }
}

/// KR-REQ-10.02: the owner stores a login for the proxy; the answer says it applies at the next
/// start and carries no part of the login; the host's store holds the item, which a start reads for
/// that proxy and no other; the owner replaces it and clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_stores_replaces_and_clears_a_proxy_login_that_no_answer_carries_back() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let store = open_store_in(&host.tree().environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in")
        .store;
    let name = item_name(host.environment_id).expect("the item's name");
    let proxy: ProxyUrl = "http://proxy.example.com:3128".parse().expect("a proxy");

    assert!(store.get(&name).expect("the store reads").is_none());
    let answer = set(
        &mut control,
        &host,
        &params("http://proxy.example.com:3128", &format!("user:{PASSWORD}")),
    )
    .await;
    assert!(
        !rendered(&answer).contains(PASSWORD),
        "the answer carries the login: {}",
        rendered(&answer)
    );
    let result: NetworkProxyLoginResult = answer
        .expect("the owner stores a login")
        .to_typed()
        .expect("the result decodes");
    assert!(result.applies_at_next_start);

    let (login, item) = read_item(&*store, host.environment_id, Some(&proxy));
    assert_eq!(item, kr_controller::config::ProxyItem::Held);
    assert!(login.is_some());
    // For the proxy it was made for, and no other.
    let other: ProxyUrl = "http://other.example.com:3128".parse().expect("a proxy");
    assert_eq!(
        read_item(&*store, host.environment_id, Some(&other)).1,
        kr_controller::config::ProxyItem::ForAnotherProxy
    );

    // A second login replaces the first whole.
    set(
        &mut control,
        &host,
        &params("http://proxy.example.com:3128", "second:other"),
    )
    .await
    .expect("the owner replaces the login");
    let held = store
        .get(&name)
        .expect("the store reads")
        .expect("an item is held");
    assert!(
        !String::from_utf8_lossy(held.expose()).contains(PASSWORD),
        "the first login is still held"
    );

    let cleared = control
        .mutate(
            Method::NetworkProxyLoginClear,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &NetworkProxyLoginClearParams::default(),
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the owner clears the login");
    assert!(
        cleared
            .to_typed::<NetworkProxyLoginResult>()
            .expect("the result decodes")
            .applies_at_next_start
    );
    assert!(store.get(&name).expect("the store reads").is_none());
}

/// KR-REQ-10.02: a proxy that names a user or a password, a login with no colon or no user name,
/// and parameters that do not read are each refused with the one fixed sentence, which repeats
/// nothing the request carried, and nothing is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proxy_login_of_the_wrong_shape_is_refused_with_one_sentence_that_repeats_nothing() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let store = open_store_in(&host.tree().environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in")
        .store;
    let name = item_name(host.environment_id).expect("the item's name");

    let mut sentences = Vec::new();
    for bad in [
        params(
            &format!("http://user:{WORD}@proxy.example.com:3128"),
            "user:x",
        ),
        params("http://proxy.example.com:3128/path", "user:x"),
        params("socks5://proxy.example.com:1080", "user:x"),
        params("http://proxy.example.com:3128", &format!("no-colon-{WORD}")),
        params("http://proxy.example.com:3128", &format!(":{WORD}")),
    ] {
        let answer = set(&mut control, &host, &bad).await;
        let said = rendered(&answer);
        assert!(answer.is_err(), "{said}");
        assert!(!said.contains(WORD), "{said}");
        sentences.push(said);
    }
    assert!(
        sentences.iter().all(|said| said
            .contains("network.proxy_login.set takes the proxy as an origin with no user name")),
        "{sentences:?}"
    );
    assert!(store.get(&name).expect("the store reads").is_none());
}

/// KR-REQ-10.02: a request that carries a login is covered by a digest that a guess at the login
/// cannot check: two requests that differ only in the freshness window the host issued give two
/// digests, and neither is the plain digest of the request's parameters, which a guess could be
/// compared with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_digest_of_a_login_request_is_not_one_a_guess_at_the_login_can_check() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let first = control
        .compose(
            Method::NetworkProxyLoginSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &params("http://proxy.example.com:3128", &format!("user:{PASSWORD}")),
        )
        .await
        .expect("the request is composed");
    let mut second = first.clone();
    second.action_window_id = kr_protocol::ids::ActionWindowId::new("kr-window-another-one")
        .expect("a window identifier");
    assert_ne!(first.action_window_id, second.action_window_id);
    let actor = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal");
    let first_digest = kr_protocol::digest::mutation_digest(&first, &actor).expect("a digest");
    let second_digest = kr_protocol::digest::mutation_digest(&second, &actor).expect("a digest");
    assert_ne!(
        first_digest, second_digest,
        "the window is covered, so the digest is not one a guess can be checked against"
    );
    let plain = kr_protocol::scalars::Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
        first.params.as_value(),
    )));
    assert_ne!(
        first_digest, plain,
        "the digest is not the plain digest of the parameters"
    );
    assert_ne!(
        second_digest, plain,
        "the digest is not the plain digest of the parameters"
    );
}

/// A store that fails its first read and answers every later one from the items it holds.
struct FailsOnce {
    items: MemoryStore,
    failed: std::sync::atomic::AtomicBool,
}

impl SecretStore for FailsOnce {
    fn set(&self, name: &SecretName, secret: &[u8]) -> Result<(), kr_crypto::CryptoError> {
        self.items.set(name, secret)
    }

    fn get(&self, name: &SecretName) -> Result<Option<SecretVec>, kr_crypto::CryptoError> {
        if !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(kr_crypto::CryptoError::SecretStore {
                message: "the store failed once".to_owned(),
            });
        }
        self.items.get(name)
    }

    fn delete(&self, name: &SecretName) -> Result<(), kr_crypto::CryptoError> {
        self.items.delete(name)
    }

    fn describe(&self) -> String {
        "a store that fails once".to_owned()
    }
}

/// KR-REQ-10.02: a store read that fails once gives no login and says the item is unreadable, it
/// keeps nothing of the failure, and the next read of the same item is the login.
#[test]
fn a_store_read_that_fails_once_gives_no_login_and_the_next_read_gives_it() {
    let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
    let proxy: ProxyUrl = "http://proxy.example.com:3128".parse().expect("a proxy");
    let store = FailsOnce {
        items: MemoryStore::new(),
        failed: std::sync::atomic::AtomicBool::new(false),
    };
    store
        .items
        .set(
            &item_name(environment_id).expect("the item's name"),
            item_bytes("http://proxy.example.com:3128", b"user:password").expose(),
        )
        .expect("the item is kept");

    let (login, item) = read_item(&store, environment_id, Some(&proxy));
    assert_eq!(item, ProxyItem::Unreadable, "the failed read is unreadable");
    assert!(login.is_none(), "a failed read gives no login");
    let (login, item) = read_item(&store, environment_id, Some(&proxy));
    assert_eq!(item, ProxyItem::Held, "the next read finds the item");
    assert!(login.is_some(), "the next read gives the login");
}

/// KR-REQ-10.02: an item made for an origin that spells out its scheme's default port is held for
/// the same proxy that names no port, and one that names another port is for another proxy.
#[test]
fn an_item_made_for_an_origin_with_its_default_port_spelled_out_is_the_same_proxy() {
    let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
    let read = |made_for: &str, document: &str| {
        let store = MemoryStore::new();
        store
            .set(
                &item_name(environment_id).expect("the item's name"),
                item_bytes(made_for, b"user:password").expose(),
            )
            .expect("the item is kept");
        let proxy: ProxyUrl = document.parse().expect("a proxy");
        read_item(&store, environment_id, Some(&proxy)).1
    };
    assert_eq!(
        read("http://proxy.example.com:80", "http://proxy.example.com"),
        ProxyItem::Held
    );
    assert_eq!(
        read("http://proxy.example.com", "http://proxy.example.com:80"),
        ProxyItem::Held
    );
    assert_eq!(
        read("https://proxy.example.com", "https://proxy.example.com:443"),
        ProxyItem::Held
    );
    assert_eq!(
        read(
            "http://proxy.example.com:80",
            "http://proxy.example.com:8080"
        ),
        ProxyItem::ForAnotherProxy
    );
    assert_eq!(
        read("http://proxy.example.com:443", "https://proxy.example.com"),
        ProxyItem::ForAnotherProxy
    );
}

/// KR-REQ-10.02: the owner repeats `network.proxy_login.set` with the same login and then
/// `network.proxy_login.clear` twice: each repeat is answered as the first was, the store holds the
/// one item the first set made, and a clear of nothing succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_set_and_a_repeated_clear_leave_the_state_the_first_one_made() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let store = open_store_in(&host.tree().environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in")
        .store;
    let name = item_name(host.environment_id).expect("the item's name");
    let login = format!("user:{PASSWORD}");

    let first = set(
        &mut control,
        &host,
        &params("http://proxy.example.com:3128", &login),
    )
    .await;
    let kept = store
        .get(&name)
        .expect("the store reads")
        .expect("the first set kept an item")
        .expose()
        .to_vec();
    let second = set(
        &mut control,
        &host,
        &params("http://proxy.example.com:3128", &login),
    )
    .await;
    assert_eq!(
        rendered(&first),
        rendered(&second),
        "the repeated set is answered as the first was"
    );
    assert_eq!(
        store
            .get(&name)
            .expect("the store reads")
            .expect("the item stands")
            .expose(),
        kept.as_slice(),
        "the repeated set left the item the first one made"
    );

    for round in ["first", "second"] {
        let cleared = control
            .mutate(
                Method::NetworkProxyLoginClear,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &NetworkProxyLoginClearParams::default(),
            )
            .await
            .expect("the call reaches the daemon")
            .unwrap_or_else(|error| panic!("the {round} clear is accepted: {error}"));
        assert!(
            cleared
                .to_typed::<NetworkProxyLoginResult>()
                .expect("the result decodes")
                .applies_at_next_start,
            "the {round} clear is answered as a clear"
        );
        assert!(
            store.get(&name).expect("the store reads").is_none(),
            "no item stands after the {round} clear"
        );
    }
}
