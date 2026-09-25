//! What the host's own TLS clients trust, and what the environment has to do with it.
//!
//! Mail submission and the plugin catalogue's repository fetches verify a server with the same
//! trust as the managed-service client: on Linux the distribution's store, whatever
//! `SSL_CERT_FILE` or `SSL_CERT_DIR` names. kr-client's `tests/trust_store.rs` holds the service
//! client and the room socket to it; this suite holds the host's other two.

#[path = "../../kr-client/tests/support/trust_store.rs"]
mod trust_store;

use kr_controller::push::mail::MailSubmission;
use kr_protocol::delivery::{MailAccount, MailSecurity, SecretText};
use kr_protocol::scalars::U64;
use trust_store::{CountingServer, Store, TestAuthority, server_port, trusted_under};

/// The child half of [`no_certificate_variable_chooses_what_mail_and_the_catalogue_trust`].
///
/// It is ignored in an ordinary run because it means nothing without the environment the other
/// test builds around it, and that test runs it by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "no_certificate_variable_chooses_what_mail_and_the_catalogue_trust runs this one"]
async fn the_child_of_the_host_certificate_variable_test() {
    use futures_util::TryStreamExt as _;

    let port = server_port();

    // Mail submission over TLS from the first byte, to the server the parent started.
    let account = MailAccount {
        server: "127.0.0.1".to_owned(),
        port: U64::new(u64::from(port)),
        security: MailSecurity::ImplicitTls,
        username: SecretText::new("person@example.com").expect("a name"),
        password: SecretText::new("a password").expect("a password"),
        from_address: "person@example.com".to_owned(),
    };
    let _ = MailSubmission::verified()
        .submit(
            &account,
            "someone@example.com",
            b"Subject: a test\r\n\r\nA test.\r\n",
        )
        .await;

    // A repository file, fetched the way this host fetches one with no proxy selected.
    let transport = kr_controller::catalogue::repository_transport(None);
    let fetched = match tough::Transport::fetch(
        &transport,
        format!("https://127.0.0.1:{port}/1.root.json")
            .parse()
            .expect("an address"),
    )
    .await
    {
        Ok(stream) => stream.try_collect::<Vec<tough::Bytes>>().await.map(|_| ()),
        Err(error) => Err(error),
    };
    assert!(fetched.is_err(), "the server answers nothing");
}

/// KR-REQ-26.14: no certificate variable chooses what the host's mail submission and repository
/// fetches trust. Under `SSL_CERT_FILE`, `SSL_CERT_DIR`, both and neither naming a store that holds
/// a test authority, no handshake completes with a server only that authority vouches for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_certificate_variable_chooses_what_mail_and_the_catalogue_trust() {
    let authority = TestAuthority::new();
    let store = Store::holding(&authority);
    let server = CountingServer::start(authority.acceptor()).await;
    let trusted = trusted_under(
        "the_child_of_the_host_certificate_variable_test",
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
