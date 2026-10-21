//! A relay server running in this process, for a suite that has to see which relay carries a pair.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use iroh_relay::server::{
    CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
};

/// What one run of the relay server lets in, and what it has let in so far.
#[derive(Debug, Default)]
struct Admissions {
    /// A test has the relay turn sessions away.
    asked: bool,
    /// The relay is being stopped, and lets no session in.
    stopping: bool,
    /// The sessions the relay let in, and the ones of those that have ended.
    admitted: u64,
    ended: u64,
}

/// Whether the relay turns away the endpoints that open a session with it, while it goes on
/// answering the requests an endpoint measures it with: because a test asked it to, or because it
/// is being stopped. It also counts the sessions it lets in and the ones that end, from the moment
/// of admission to the end of the session, which includes a session that ended before it was
/// registered or whose task was ended with the server's.
///
/// Each run of the relay server has a refusal of its own, so what a stopped server's handlers
/// decide is never changed by a server started after it.
#[derive(Clone, Debug, Default)]
struct Refusal(Arc<Mutex<Admissions>>);

impl Refusal {
    fn state(&self) -> MutexGuard<'_, Admissions> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The refusal of a server started after this one: it turns sessions away as this one does
    /// now, and has let none in.
    fn for_a_server_started_again(&self) -> Self {
        Self(Arc::new(Mutex::new(Admissions {
            asked: self.state().asked,
            ..Admissions::default()
        })))
    }
}

impl iroh_relay::server::AccessControl for Refusal {
    async fn on_connect(
        &self,
        _request: &iroh_relay::server::ClientRequest,
    ) -> iroh_relay::server::Access {
        let mut state = self.state();
        if state.asked || state.stopping {
            iroh_relay::server::Access::Deny {
                reason: Some("this relay is not taking sessions".to_owned()),
            }
        } else {
            state.admitted += 1;
            iroh_relay::server::Access::Allow
        }
    }

    fn on_disconnect(
        &self,
        _endpoint_id: iroh::EndpointId,
        _connection_id: iroh_relay::server::ConnectionId,
    ) {
        self.state().ended += 1;
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
        let (server, port) = Self::serve(&tls, 0, &refusal)
            .await
            .expect("a relay server");
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

    async fn serve(
        tls: &rustls::ServerConfig,
        port: u16,
        refusal: &Refusal,
    ) -> Result<(Server, u16), iroh_relay::server::SpawnError> {
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

        let server = Server::spawn(config).await?;
        let port = server.https_addr().expect("configured").port();
        Ok((server, port))
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
        self.refusal.state().asked = refused;
    }

    /// Stops the relay: nothing answers at its address, and no endpoint is connected to it, until
    /// [`Self::start_again`].
    ///
    /// The server's own shutdown ends the sessions it holds, and an endpoint whose session ended
    /// opens another at once. A session that is past the relay's admission when the server is told
    /// to stop is registered afterwards, and a task of its own serves it that nothing ends, so the
    /// endpoint stays connected to a relay that has stopped. So no session is let in from the moment
    /// the stop begins, the ones the relay holds are ended before the server is told to stop, and
    /// the sweep goes on until every session the relay let in has ended. The relay counts those from
    /// its admission, which the server's own counts do not.
    pub async fn stop(&mut self) {
        let Some(server) = self.server.take() else {
            return;
        };
        self.refusal.state().stopping = true;
        let service = server
            .relay_service()
            .cloned()
            .expect("the relay serves relayed sessions");
        let refusal = self.refusal.clone();
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            service.clients().shutdown().await;
            server.shutdown().await.expect("the relay stops");
            loop {
                {
                    let state = refusal.state();
                    if state.admitted == state.ended {
                        return;
                    }
                }
                service.clients().shutdown().await;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("every session the relay let in has ended");
    }

    /// Starts the relay again at the address it had, with the certificate it had.
    ///
    /// The port a stopped relay had is free for any other program on the machine to take, and on a
    /// machine that runs many tests at once, another relay that binds an address of its own is
    /// given it. The relay takes its port back as soon as whatever has it lets it go, and a test
    /// that went wrong is stopped rather than left to wait.
    pub async fn start_again(&mut self) {
        assert!(self.server.is_none(), "the relay is running");
        self.refusal = self.refusal.for_a_server_started_again();
        let (server, port) = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                match Self::serve(&self.tls, self.port, &self.refusal).await {
                    Ok(served) => return served,
                    Err(error) if is_address_in_use(&error) => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(error) => panic!("a relay server: {error}"),
                }
            }
        })
        .await
        .expect("the port the relay had is free again");
        assert_eq!(port, self.port, "the relay came back at its address");
        self.server = Some(server);
    }
}

/// Whether `error`, or a cause it names, is an address that something else holds.
fn is_address_in_use(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(error) = next {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::AddrInUse)
        {
            return true;
        }
        next = error.source();
    }
    false
}
