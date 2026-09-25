//! Certificates from an authority a test makes, for the loopback servers that stand between an
//! endpoint and its relay.
//!
//! An endpoint trusts such an authority only when its configuration names it among the relay's
//! trust anchors, which is how an owner trusts a self-hosted relay's private authority, and how a
//! network that intercepts TLS asks to be trusted.

use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};

/// A certificate authority, and what signs with it.
pub struct Authority {
    /// The authority's own certificate, DER-encoded: what an endpoint names to trust it.
    pub der: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl Authority {
    /// Makes an authority called `name`.
    pub fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name.to_owned());
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("a self-signed certificate");
        Self {
            der: certificate.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A server configuration presenting a certificate for `host`, a name or an address, that
    /// this authority issued.
    pub fn server_config(&self, host: &str) -> Arc<rustls::ServerConfig> {
        let mut params =
            rcgen::CertificateParams::new(vec![host.to_owned()]).expect("certificate parameters");
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let leaf = params
            .signed_by(&key, &self.issuer)
            .expect("a signed certificate");
        let chain = vec![leaf.der().clone(), CertificateDer::from(self.der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Arc::new(
            rustls::ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("protocol versions")
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("a server configuration"),
        )
    }
}

/// A client configuration that trusts `roots` and nothing else.
pub fn client_config(roots: &[Vec<u8>]) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store
            .add(CertificateDer::from(root.clone()))
            .expect("a trust anchor");
    }
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

/// The name a TLS client checks `host`'s certificate against.
pub fn server_name(host: &str) -> ServerName<'static> {
    ServerName::try_from(host.to_owned()).expect("a server name")
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
