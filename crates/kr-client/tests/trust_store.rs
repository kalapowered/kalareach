//! What the product's own TLS clients trust, and what the environment has to do with it.
//!
//! On Linux the verifier the platform provides reads `SSL_CERT_FILE` and `SSL_CERT_DIR`, and while
//! either is set it trusts only what they name. An inherited variable would then decide who may
//! answer for a service. These tests set each variable, and both, to a store that holds a test
//! authority, and hold the service client and the room socket to refusing a server that authority
//! issued. With neither set the same server is refused as well: that is the control, and it is what
//! makes a refusal a statement about trust rather than about a server that never answered.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_client::pairing::room::{RoomConnector, RoomRole};
use kr_client::services::http::HttpService;
use kr_client::services::relay::ServiceHttp;
use kr_protocol::pairing::{Locator, RendezvousOrigin};
use kr_protocol::service::GatewayOrigin;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// Where the child finds the server its parent started.
const ORIGIN: &str = "TRUST_STORE_TEST_ORIGIN";

/// How long one child may take to try both clients.
const PATIENCE: Duration = Duration::from_secs(60);

/// The child half of [`no_certificate_variable_chooses_what_a_client_trusts`].
///
/// It is ignored in an ordinary run because it means nothing without the environment the other
/// test builds around it, and that test runs it by name. Both clients are the ones a shipped host
/// and a shipped device build, with nothing added to what they trust.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "no_certificate_variable_chooses_what_a_client_trusts runs this one"]
async fn the_child_of_the_certificate_variable_test() {
    let origin = std::env::var(ORIGIN).expect("the parent names its server");

    let service = HttpService::new(GatewayOrigin::new(origin.clone()).expect("an origin"))
        .expect("the service client");
    let answered = service
        .post_json(&format!("{origin}/api/probe"), b"{}", &[])
        .await;
    assert!(
        answered.is_err(),
        "the service client was answered by a server only the test authority vouches for"
    );

    let room = RoomConnector::platform().expect("the room connector");
    let opened = room
        .open(
            &RendezvousOrigin::new(origin).expect("an origin"),
            &Locator::new("abcd").expect("a locator"),
            RoomRole::Candidate,
        )
        .await;
    assert!(
        opened.is_err(),
        "a room socket opened to a server only the test authority vouches for"
    );
}

/// KR-REQ-26.14: no certificate variable chooses what this product's clients trust.
///
/// A test authority is written into a store, as a file and as a directory, and a loopback server
/// presents a certificate that authority issued. A child process tries the service client and the
/// room socket with `SSL_CERT_FILE` naming the file, with `SSL_CERT_DIR` naming the directory,
/// with both, and with neither. No TLS handshake with the server completes in any of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_certificate_variable_chooses_what_a_client_trusts() {
    let authority = TestAuthority::new();
    let store = tempfile::tempdir().expect("a directory for the store");
    let file = store.path().join("authority.pem");
    std::fs::write(&file, authority.pem()).expect("the store's file");
    let directory = store.path().join("certs");
    std::fs::create_dir(&directory).expect("the store's directory");
    std::fs::write(directory.join("authority.pem"), authority.pem()).expect("a certificate in it");

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("an address").port();
    let acceptor = authority.acceptor();
    let completed = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&completed);
    let serving = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counted = Arc::clone(&counted);
            tokio::spawn(async move {
                // A handshake that completes is a client that trusted the test authority. What
                // happens after it does not matter: the stream is dropped at once.
                if acceptor.accept(stream).await.is_ok() {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    let origin = format!("https://127.0.0.1:{port}");

    let cases: [(&str, Option<&Path>, Option<&Path>); 4] = [
        ("SSL_CERT_FILE", Some(&file), None),
        ("SSL_CERT_DIR", None, Some(&directory)),
        ("both", Some(&file), Some(&directory)),
        ("neither, the control", None, None),
    ];
    for (case, cert_file, cert_dir) in cases {
        let ran = run_child(&origin, cert_file, cert_dir).await;
        assert!(
            ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("1 passed"),
            "with {case}: {}{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "with {case}, a client completed a handshake with a server only the test authority \
             vouches for"
        );
    }
    serving.abort();
}

/// Runs the child test with the certificate variables set as given, and nothing else of them.
async fn run_child(
    origin: &str,
    cert_file: Option<&Path>,
    cert_dir: Option<&Path>,
) -> std::process::Output {
    let binary = std::env::current_exe().expect("this test binary");
    let mut command = std::process::Command::new(binary);
    command
        .args([
            "--exact",
            "--ignored",
            "--nocapture",
            "the_child_of_the_certificate_variable_test",
        ])
        .env(ORIGIN, origin)
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .current_dir(std::env::temp_dir());
    if let Some(file) = cert_file {
        command.env("SSL_CERT_FILE", file);
    }
    if let Some(directory) = cert_dir {
        command.env("SSL_CERT_DIR", directory);
    }
    let child = tokio::task::spawn_blocking(move || command.output().expect("the child"));
    tokio::time::timeout(PATIENCE, child)
        .await
        .expect("the child finishes")
        .expect("the child's thread")
}

/// A certificate authority no platform trusts, and a certificate it issued for the loopback address.
struct TestAuthority {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
    der: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
}

impl TestAuthority {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::new()).expect("certificate parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "certificate variable test authority");
        let key = KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("a certificate");
        Self {
            pem: certificate.pem(),
            der: certificate.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    fn pem(&self) -> &str {
        &self.pem
    }

    /// TLS presenting a certificate for 127.0.0.1 that this authority issued.
    fn acceptor(&self) -> TlsAcceptor {
        let key = KeyPair::generate().expect("a key pair");
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .expect("certificate parameters")
            .signed_by(&key, &self.issuer)
            .expect("a certificate");
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), self.der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("a server configuration");
        TlsAcceptor::from(Arc::new(config))
    }
}
