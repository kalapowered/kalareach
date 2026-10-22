//! The server an Android release build is pointed at to show that it checks who it is talking to.
//!
//! This is the machine side of a device run, not a test of the product by itself: a script starts it
//! (`scripts/e2e-android-release.sh`) beside the installed, minified release build, so it is ignored
//! in an ordinary run. The server speaks TLS on the loopback interface with a certificate that a
//! private authority issued, and the emulator's system trusts no such authority. A phone whose
//! platform verifier works refuses the certificate: it ends the handshake after the server's hello
//! and before anything else, and no request of any kind reaches the server. Whether the end came as
//! a TLS alert or as a closed connection is recorded apart, and either is a refusal here; neither
//! says why the phone refused. A phone whose verifier was lost to the build's shrinking ends the
//! handshake the same way, so this case does not tell the two apart: the public origin the run also
//! attempts does, since only a working verifier accepts its certificate.
//!
//! What this shows, and what it does not. The emulator's Play image has no root, and a release build
//! trusts no authority a person adds, so a certificate for another host cannot be made to chain to a
//! trusted root there: the refusal shown here is the refusal of an issuer the system does not trust,
//! not of a name that does not match. The name check is the shared Rust code (`verify_server_name`
//! in the platform verifier crate, called on Android as on the desktop), which the client library's
//! own case holds on the desktop.
//!
//! The script talks to this suite through files in `KR_HARNESS_DIR`: the suite writes
//! `tls-listening.json` with the port, and writes `tls-control.json` again after every connection;
//! the script ends the suite by creating `finish`. The record holds the TCP connections accepted,
//! the ClientHellos read (with the name each asked for), the handshakes the client ended (a TLS
//! alert it sent, or a connection it closed), the handshakes that completed, and the bytes of
//! application data that arrived after one: a request.

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt as _;
use tokio_rustls::rustls;

/// What the server saw, as the script reads it.
#[derive(Clone, Default, serde::Serialize)]
struct Seen {
    /// TCP connections accepted.
    accepted: usize,
    /// ClientHellos read, and the name each one asked for (empty for an address).
    client_hellos: usize,
    server_names: Vec<String>,
    /// The TLS alerts the client sent while it ended a handshake, by name, in the order they came.
    alerts: Vec<String>,
    /// How each other handshake the client ended was seen from here (a closed connection, an
    /// I/O error), in the order they came: the client said nothing a TLS alert would carry.
    closed: Vec<String>,
    /// Handshakes that completed.
    handshakes: usize,
    /// Bytes of application data the client sent after a handshake: any is a request.
    request_bytes: usize,
}

/// A leaf certificate for the loopback address from a private authority, as a server configuration.
fn untrusted_server() -> Arc<rustls::ServerConfig> {
    let mut authority_params =
        rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters");
    authority_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    authority_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    authority_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "A private authority".to_owned());
    let authority_key = rcgen::KeyPair::generate().expect("a key pair");
    let authority_certificate = authority_params
        .self_signed(&authority_key)
        .expect("a self-signed authority");
    let authority = rcgen::Issuer::new(authority_params, authority_key);

    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters");
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1".to_owned());
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let leaf = params
        .signed_by(&key, &authority)
        .expect("a signed certificate");
    let chain = vec![leaf.der().clone(), authority_certificate.der().clone()];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key.serialize_der(),
    ));
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("a server configuration"),
    )
}

/// Writes `bytes` to `file` where only this user can read it, whole.
fn write_private(file: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let staging = file.with_extension("partial");
    let mut open = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&staging)
        .expect("a file in the harness directory");
    open.write_all(bytes).expect("the file is written");
    std::fs::rename(&staging, file).expect("the file is put in place");
}

/// Serves one connection, and records what it saw.
async fn serve(
    tcp: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    seen: Arc<Mutex<Seen>>,
    publish: impl Fn(&Seen),
) {
    seen.lock().expect("the record").accepted += 1;
    publish(&seen.lock().expect("the record").clone());

    let hello =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await;
    let Ok(start) = hello else {
        // A connection that ends before it sent a ClientHello has said nothing to record.
        return;
    };
    {
        let mut record = seen.lock().expect("the record");
        record.client_hellos += 1;
        record.server_names.push(
            start
                .client_hello()
                .server_name()
                .unwrap_or_default()
                .to_owned(),
        );
    }
    publish(&seen.lock().expect("the record").clone());

    match start.into_stream(config).await {
        Ok(mut stream) => {
            seen.lock().expect("the record").handshakes += 1;
            let mut buffer = [0u8; 4096];
            while let Ok(read) = stream.read(&mut buffer).await {
                if read == 0 {
                    break;
                }
                seen.lock().expect("the record").request_bytes += read;
                publish(&seen.lock().expect("the record").clone());
            }
        }
        Err(error) => {
            // A client's alert reaches the server as a TLS error wrapped in an I/O error; a client
            // that closes the connection instead reaches it as an end of file.
            let mut record = seen.lock().expect("the record");
            match error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            {
                Some(rustls::Error::AlertReceived(alert)) => {
                    record.alerts.push(format!("{alert:?}"))
                }
                Some(other) => record.closed.push(format!("{other:?}")),
                None => record.closed.push(format!("{error}")),
            }
        }
    }
    publish(&seen.lock().expect("the record").clone());
}

/// Runs the server until the script says the run is finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "started by scripts/e2e-android-release.sh beside an emulator"]
async fn an_issuer_the_system_does_not_trust_is_refused_before_any_request() {
    let directory = PathBuf::from(std::env::var("KR_HARNESS_DIR").expect("KR_HARNESS_DIR"));
    let seconds: u64 = std::env::var("KR_HARNESS_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(900);
    let end = Instant::now() + Duration::from_secs(seconds);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let config = untrusted_server();
    let publish_to = directory.clone();
    let publish = move |record: &Seen| {
        write_private(
            &publish_to.join("tls-control.json"),
            serde_json::to_string(record)
                .expect("the record is text")
                .as_bytes(),
        );
    };
    publish(&Seen::default());
    write_private(
        &directory.join("tls-listening.json"),
        format!("{{\"port\":{port}}}\n").as_bytes(),
    );

    while Instant::now() < end && !directory.join("finish").exists() {
        if let Ok(Ok((tcp, _))) =
            tokio::time::timeout(Duration::from_millis(250), listener.accept()).await
        {
            let (config, seen) = (Arc::clone(&config), Arc::clone(&seen));
            let publish_to = directory.clone();
            tokio::spawn(serve(tcp, config, seen, move |record| {
                write_private(
                    &publish_to.join("tls-control.json"),
                    serde_json::to_string(record)
                        .expect("the record is text")
                        .as_bytes(),
                );
            }));
        }
    }
}
