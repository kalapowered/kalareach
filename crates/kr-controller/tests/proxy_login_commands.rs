//! The owner keeps, replaces and clears the login the host's proxy asks for, at this machine, over
//! the daemon's local socket. The daemon alone writes the secret store, and no answer carries the
//! login back.
//!
//! Everything runs on this machine's loopback interface and in temporary directories on the
//! internal disk.

mod net_support;

use kr_controller::service::net::proxy_login::{item_name, read_item};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_protocol::delivery::SecretText;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::ActionId;
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
