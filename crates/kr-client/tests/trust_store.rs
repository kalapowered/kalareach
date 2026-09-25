//! What the product's own TLS clients trust, and what the environment has to do with it.
//!
//! On Linux the verifier the platform provides reads `SSL_CERT_FILE` and `SSL_CERT_DIR`, and while
//! either is set it trusts only what they name. An inherited variable would then decide who may
//! answer for a service. These tests set each variable, and both, to a store that holds a test
//! authority, and hold the service client and the room socket to refusing a server that authority
//! issued. With neither set the same server is refused as well: that is the control, and it is what
//! makes a refusal a statement about trust rather than about a server that never answered.

#[path = "support/trust_store.rs"]
mod trust_store;

use kr_client::pairing::room::{RoomConnector, RoomRole};
use kr_client::services::http::HttpService;
use kr_client::services::relay::ServiceHttp;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::service::GatewayOrigin;
use trust_store::{CountingServer, Store, TestAuthority, server_port, trusted_under};

/// The child half of [`no_certificate_variable_chooses_what_a_client_trusts`].
///
/// It is ignored in an ordinary run because it means nothing without the environment the other
/// test builds around it, and that test runs it by name. Both clients are the ones a shipped host
/// and a shipped device build, with nothing added to what they trust.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "no_certificate_variable_chooses_what_a_client_trusts runs this one"]
async fn the_child_of_the_certificate_variable_test() {
    let origin = format!("https://127.0.0.1:{}", server_port());

    let service = HttpService::new(GatewayOrigin::new(origin.clone()).expect("an origin"))
        .expect("the service client");
    let answered = service
        .post_json(&format!("{origin}/api/probe"), b"{}", &[])
        .await;
    assert!(answered.is_err(), "the server answers nothing");

    let room = RoomConnector::platform().expect("the room connector");
    let opened = room
        .open(
            &RendezvousOrigin::new(origin).expect("an origin"),
            &Locator::new("abcd").expect("a locator"),
            RoomRole::Candidate,
        )
        .await;
    assert!(opened.is_err(), "the server upgrades nothing");
}

/// KR-REQ-26.14: no certificate variable chooses what this product's clients trust.
///
/// A test authority is written into a store, as a file and as a directory, and a loopback server
/// presents a certificate that authority issued. A child process tries the service client and the
/// room socket with `SSL_CERT_FILE` naming the file, with `SSL_CERT_DIR` naming the directory,
/// with both, and with neither. No TLS handshake with the server completes under any of them, and
/// every setting under which one did is reported at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_certificate_variable_chooses_what_a_client_trusts() {
    let authority = TestAuthority::new();
    let store = Store::holding(&authority);
    let server = CountingServer::start(authority.acceptor()).await;
    let trusted = trusted_under(
        "the_child_of_the_certificate_variable_test",
        &store,
        &server,
    )
    .await;
    assert!(
        trusted.is_empty(),
        "a client completed a handshake with a server only the test authority vouches for, \
         under each setting and as many times as listed: {trusted:?}"
    );
}
