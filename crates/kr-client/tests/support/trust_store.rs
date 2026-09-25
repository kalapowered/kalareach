//! What the tests of this product's trust share: a certificate authority no platform trusts, a
//! store that holds it the two ways `SSL_CERT_FILE` and `SSL_CERT_DIR` name one, a loopback TLS
//! server presenting a certificate it issued that counts the handshakes that complete, and the
//! child process each case runs in, because an environment belongs to a process.
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Where a child finds the server its parent started.
pub const SERVER_PORT: &str = "TRUST_STORE_TEST_PORT";

/// How long one child may take.
const PATIENCE: Duration = Duration::from_secs(60);

/// A certificate authority no platform trusts.
pub struct TestAuthority {
    pem: String,
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl TestAuthority {
    /// A new authority.
    pub fn new() -> Self {
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

    /// TLS presenting a certificate for 127.0.0.1 that this authority issued.
    pub fn acceptor(&self) -> TlsAcceptor {
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

/// A store that holds one authority: as a file, and as a file in a directory.
pub struct Store {
    _home: tempfile::TempDir,
    /// The file `SSL_CERT_FILE` names.
    pub file: PathBuf,
    /// The directory `SSL_CERT_DIR` names.
    pub directory: PathBuf,
}

impl Store {
    /// A store holding `authority`.
    pub fn holding(authority: &TestAuthority) -> Self {
        let home = tempfile::tempdir().expect("a directory for the store");
        let file = home.path().join("authority.pem");
        std::fs::write(&file, &authority.pem).expect("the store's file");
        let directory = home.path().join("certs");
        std::fs::create_dir(&directory).expect("the store's directory");
        std::fs::write(directory.join("authority.pem"), &authority.pem)
            .expect("a certificate in it");
        Self {
            _home: home,
            file,
            directory,
        }
    }

    /// The settings a test runs its child under, each named: each variable alone, both, and
    /// neither, which is the control.
    pub fn cases(&self) -> [(&'static str, Option<&Path>, Option<&Path>); 4] {
        [
            ("SSL_CERT_FILE", Some(&self.file), None),
            ("SSL_CERT_DIR", None, Some(&self.directory)),
            ("both", Some(&self.file), Some(&self.directory)),
            ("neither, the control", None, None),
        ]
    }
}

/// A loopback TLS server that counts the handshakes that complete, and drops each connection.
pub struct CountingServer {
    /// The port it listens on.
    pub port: u16,
    completed: Arc<AtomicUsize>,
    serving: JoinHandle<()>,
}

impl CountingServer {
    /// Starts one behind `acceptor`.
    pub async fn start(acceptor: TlsAcceptor) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let completed = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&completed);
        let serving = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    // A handshake that completes is a client that trusted the authority. What
                    // happens after it does not matter: the stream is dropped at once.
                    if acceptor.accept(stream).await.is_ok() {
                        counted.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        Self {
            port,
            completed,
            serving,
        }
    }

    /// How many handshakes have completed so far.
    pub fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }
}

impl Drop for CountingServer {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Runs `test` in this test binary in a child process that knows `port`, with the certificate
/// variables set as given and not otherwise.
pub async fn run_child(
    test: &str,
    port: u16,
    cert_file: Option<&Path>,
    cert_dir: Option<&Path>,
) -> std::process::Output {
    let binary = std::env::current_exe().expect("this test binary");
    let mut command = std::process::Command::new(binary);
    command
        .args(["--exact", "--ignored", "--nocapture", test])
        .env(SERVER_PORT, port.to_string())
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

/// Runs `test` once under each of `store`'s settings against `server`, and returns the settings
/// under which a handshake completed, with how many did. Each child must itself pass.
pub async fn trusted_under(
    test: &str,
    store: &Store,
    server: &CountingServer,
) -> Vec<(&'static str, usize)> {
    let mut trusted = Vec::new();
    for (case, cert_file, cert_dir) in store.cases() {
        let before = server.completed();
        let ran = run_child(test, server.port, cert_file, cert_dir).await;
        assert!(
            ran.status.success() && String::from_utf8_lossy(&ran.stdout).contains("1 passed"),
            "with {case}: {}{}",
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        let handshakes = server.completed() - before;
        if handshakes > 0 {
            trusted.push((case, handshakes));
        }
    }
    trusted
}

/// The port the parent named, read in the child.
pub fn server_port() -> u16 {
    std::env::var(SERVER_PORT)
        .expect("the parent names its server")
        .parse()
        .expect("a port")
}
