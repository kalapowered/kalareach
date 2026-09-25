//! Something on loopback between an endpoint and its relay, that the relay's URL names.
//!
//! A front passes connections to a [`LocalRelay`](super::LocalRelay) and counts them, so a test
//! can tell whether an endpoint reached the relay at all: the relay's own address is not the one
//! the endpoint was given, so nothing reaches the relay except through the front.
//!
//! One kind of front passes every connection unchanged. The other stands for a network that blocks
//! WebSocket upgrades: it terminates TLS with a certificate from its own authority, passes every
//! ordinary request on to the relay over TLS of its own, and answers the relay connection's
//! WebSocket upgrade with a status of the test's choosing.
//!
//! It runs on a runtime of its own, as the proxy does, and dropping it closes its port.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::LocalRelay;
use super::proxy::{authority, read_head};
use super::tls::{Authority, client_config, server_name};

/// The headers that end a refusal: no body, and no further request on the connection.
const CLOSING: &str = "Content-Length: 0\r\nConnection: close\r\n\r\n";

/// A front for one relay.
pub struct RelayFront {
    /// The relay URL an endpoint reaches the relay through this front by.
    pub url: iroh::RelayUrl,
    /// What an endpoint trusts to reach the relay through this front.
    pub ca_roots: Vec<Vec<u8>>,
    accepted: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl RelayFront {
    /// Starts a front that passes every connection to `relay` unchanged, so the relay's own TLS
    /// reaches the endpoint and the relay's own anchor is what the endpoint trusts.
    pub fn passing(relay: &LocalRelay) -> Self {
        let upstream = authority(&relay.url);
        Self::start(relay.ca_roots.clone(), move |client, _refused| {
            let upstream = upstream.clone();
            async move {
                let Ok(mut relay) = TcpStream::connect(&upstream).await else {
                    return;
                };
                let mut client = client;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
            }
        })
    }

    /// Starts a front that answers the relay's WebSocket upgrade with `status` and passes every
    /// other request to `relay`.
    ///
    /// The endpoint trusts the front's own authority, as it would a network's that inspects TLS;
    /// the front trusts the relay's anchor for its own connection to the relay. An ordinary request,
    /// such as the relay latency probe, is passed on and answered by the relay, which is what lets
    /// an endpoint choose the relay as its home and then try to connect to it.
    pub fn refusing_upgrades(relay: &LocalRelay, status: u16) -> Self {
        let host = relay.url.host_str().expect("a relay host").to_owned();
        let upstream = authority(&relay.url);
        let front = Authority::new("relay front");
        let acceptor = TlsAcceptor::from(front.server_config(&host));
        let connector = TlsConnector::from(client_config(&relay.ca_roots));
        Self::start(vec![front.der.clone()], move |client, refused| {
            let (host, upstream) = (host.clone(), upstream.clone());
            let (acceptor, connector) = (acceptor.clone(), connector.clone());
            async move {
                let Ok(client) = acceptor.accept(client).await else {
                    return;
                };
                let mut client = BufReader::new(client);
                let Some(head) = read_head(&mut client).await else {
                    return;
                };
                if is_websocket_upgrade(&head) {
                    refused.fetch_add(1, Ordering::SeqCst);
                    let answer = format!("HTTP/1.1 {status} Upgrade Refused\r\n{CLOSING}");
                    let _ = client.get_mut().write_all(answer.as_bytes()).await;
                    let _ = client.get_mut().shutdown().await;
                    return;
                }
                let Ok(tcp) = TcpStream::connect(&upstream).await else {
                    return;
                };
                let Ok(mut relay) = connector.connect(server_name(&host), tcp).await else {
                    return;
                };
                let early = client.buffer().to_vec();
                if relay.write_all(head.as_bytes()).await.is_err()
                    || relay.write_all(&early).await.is_err()
                {
                    return;
                }
                let mut client = client.into_inner();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
            }
        })
    }

    fn start<F, S>(ca_roots: Vec<Vec<u8>>, serve: S) -> Self
    where
        S: Fn(TcpStream, Arc<AtomicUsize>) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a front listener");
        listener
            .set_nonblocking(true)
            .expect("a listener the runtime can drive");
        let addr: SocketAddr = listener.local_addr().expect("a bound address");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the front's runtime");
        let accepted = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let (counting, refusing) = (Arc::clone(&accepted), Arc::clone(&refused));
        runtime.spawn(async move {
            let listener = TcpListener::from_std(listener).expect("the front listener");
            while let Ok((stream, _)) = listener.accept().await {
                counting.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve(stream, Arc::clone(&refusing)));
            }
        });
        Self {
            url: format!("https://{addr}").parse().expect("a relay URL"),
            ca_roots,
            accepted,
            refused,
            runtime: Some(runtime),
        }
    }

    /// How many connections reached the front.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// How many WebSocket upgrades the front refused.
    pub fn refused_upgrades(&self) -> usize {
        self.refused.load(Ordering::SeqCst)
    }
}

impl Drop for RelayFront {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Whether a request head asks to upgrade its connection to a WebSocket.
fn is_websocket_upgrade(head: &str) -> bool {
    head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("upgrade")
                && value.trim().eq_ignore_ascii_case("websocket")
        })
    })
}
