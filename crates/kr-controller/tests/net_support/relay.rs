//! A relay server running in this process, for a suite that has to see which relay carries a pair.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use iroh_relay::server::{
    CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
};

/// Whether the relay turns away the endpoints that open a session with it, while it goes on
/// answering the requests an endpoint measures it with.
#[derive(Clone, Debug, Default)]
struct Refusal(Arc<AtomicBool>);

impl iroh_relay::server::AccessControl for Refusal {
    async fn on_connect(
        &self,
        _request: &iroh_relay::server::ClientRequest,
    ) -> iroh_relay::server::Access {
        if self.0.load(Ordering::SeqCst) {
            iroh_relay::server::Access::Deny {
                reason: Some("this relay is not taking sessions".to_owned()),
            }
        } else {
            iroh_relay::server::Access::Allow
        }
    }
}

/// A relay server on the loopback interface, with the trust anchor an endpoint needs for it.
///
/// `iroh::test_utils::run_relay_server` discards the certificate it generated, and an endpoint that
/// cannot verify the relay's HTTPS certificate never reaches it. This spawns the same server and
/// keeps the certificate, which is how a self-hosted deployment with a private authority works: the
/// certificate is pinned as an extra trust anchor.
pub struct LocalRelay {
    pub url: iroh::RelayUrl,
    pub ca_roots: Vec<Vec<u8>>,
    server: Option<Server>,
    /// The certificate and key the relay serves, kept so that it can answer again where it was.
    tls: rustls::ServerConfig,
    port: u16,
    refusal: Refusal,
}

impl LocalRelay {
    pub async fn spawn() -> Self {
        let (certs, tls) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let ca_roots = certs.into_iter().map(|cert| cert.to_vec()).collect();
        let refusal = Refusal::default();
        let (server, port) = Self::serve(&tls, 0, &refusal).await;
        let url: iroh::RelayUrl = format!("https://127.0.0.1:{port}")
            .parse()
            .expect("a relay URL");
        Self {
            url,
            ca_roots,
            server: Some(server),
            tls,
            port,
            refusal,
        }
    }

    async fn serve(tls: &rustls::ServerConfig, port: u16, refusal: &Refusal) -> (Server, u16) {
        let tls = TlsConfig::new(
            (Ipv4Addr::LOCALHOST, port),
            CertConfig::Manual {
                server_config: tls.clone(),
            },
        );
        let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.tls = Some(tls);
        relay.key_cache_capacity = Some(1024);
        relay.access = Arc::new(refusal.clone());

        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));

        let server = Server::spawn(config).await.expect("a relay server");
        let port = server.https_addr().expect("configured").port();
        (server, port)
    }

    /// The bytes the relay has forwarded between endpoints so far, counted over its whole life.
    pub fn forwarded(&self) -> u64 {
        self.server
            .as_ref()
            .map_or(0, |server| server.metrics().server.bytes_sent.get())
    }

    /// Has the relay turn away every endpoint that opens a session with it, or take them again. It
    /// answers an endpoint's measurements of it either way.
    pub fn refuse_sessions(&self, refused: bool) {
        self.refusal.0.store(refused, Ordering::SeqCst);
    }

    /// Stops the relay: nothing answers at its address until [`Self::start_again`].
    pub async fn stop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await.expect("the relay stops");
        }
    }

    /// Starts the relay again at the address it had, with the certificate it had.
    pub async fn start_again(&mut self) {
        assert!(self.server.is_none(), "the relay is running");
        let (server, port) = Self::serve(&self.tls, self.port, &self.refusal).await;
        assert_eq!(port, self.port, "the relay came back at its address");
        self.server = Some(server);
    }
}
