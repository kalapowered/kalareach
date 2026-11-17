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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::watch;
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
    /// The switch of a stalling front, and what it has read from the device.
    switch: Option<watch::Sender<bool>>,
    from_device: Arc<AtomicU64>,
    runtime: Option<tokio::runtime::Runtime>,
}

/// The receive buffer of a stalling front's listener, which its accepted sockets inherit: a few
/// KiB, so that a stalled front takes almost nothing of what the device sends.
const STALLED_RECEIVE_BUFFER: u32 = 4096;

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
            switch: None,
            from_device: Arc::new(AtomicU64::new(0)),
            runtime: Some(runtime),
        }
    }

    /// Starts a front that passes every byte to `relay` and back until it is told to stall, with
    /// a receive buffer of a few KiB of its own.
    ///
    /// Stalled, it starts no pass of its copy loop on any connection that it holds, so the sockets
    /// stay open and the device's side of each fills. The switch does not stop a pass that is under
    /// way: a read that is ready when the switch is made can still be taken, its chunk is then
    /// written, and that write can end after the switch. It goes on accepting connections that are
    /// made after the switch and leaves each of them alone, so that a client dialling it again
    /// meets a connection that never completes its handshake and not a refusal. On resume it
    /// passes again, bytes and new connections alike; a chunk that was read is written and the
    /// rest was never read, so no byte is lost.
    pub fn stalling(relay: &LocalRelay) -> Self {
        let upstream = authority(&relay.url);
        let (switch, gate) = watch::channel(false);
        let accepted = Arc::new(AtomicUsize::new(0));
        let from_device = Arc::new(AtomicU64::new(0));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the front's runtime");
        let (found, finding) = std::sync::mpsc::channel();
        let (counting, counted) = (Arc::clone(&accepted), Arc::clone(&from_device));
        runtime.spawn(async move {
            let socket = TcpSocket::new_v4().expect("a front socket");
            socket
                .set_recv_buffer_size(STALLED_RECEIVE_BUFFER)
                .expect("a small receive buffer");
            socket
                .bind((Ipv4Addr::LOCALHOST, 0).into())
                .expect("a front address");
            let listener = socket.listen(1024).expect("a front listener");
            found
                .send(listener.local_addr().expect("a bound address"))
                .ok();
            while let Ok((client, _)) = listener.accept().await {
                counting.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(carry(
                    client,
                    upstream.clone(),
                    gate.clone(),
                    Arc::clone(&counted),
                ));
            }
        });
        let addr: SocketAddr = finding.recv().expect("the front's address");
        Self {
            url: format!("https://{addr}").parse().expect("a relay URL"),
            ca_roots: relay.ca_roots.clone(),
            accepted,
            refused: Arc::new(AtomicUsize::new(0)),
            switch: Some(switch),
            from_device,
            runtime: Some(runtime),
        }
    }

    /// Stops a stalling front after the pass that is under way in each direction: a read that is
    /// ready at the switch can still be taken and its chunk written, and that write can end after
    /// the switch.
    pub fn stall(&self) {
        self.switch
            .as_ref()
            .expect("a stalling front")
            .send_replace(true);
    }

    /// Lets a stalling front pass bytes and connections again.
    pub fn resume(&self) {
        self.switch
            .as_ref()
            .expect("a stalling front")
            .send_replace(false);
    }

    /// How many bytes a stalling front has read from the device, which is what the device's relay
    /// actors took.
    pub fn read_from_device(&self) -> u64 {
        self.from_device.load(Ordering::SeqCst)
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

/// Carries one connection of a stalling front to the relay, once the front is not stalled.
async fn carry(
    client: TcpStream,
    upstream: String,
    mut gate: watch::Receiver<bool>,
    from_device: Arc<AtomicU64>,
) {
    // A connection that is made while the front is stalled waits here, accepted and untouched.
    if gate.wait_for(|stalled| !*stalled).await.is_err() {
        return;
    }
    let Ok(relay) = TcpStream::connect(&upstream).await else {
        return;
    };
    let (client_read, client_write) = client.into_split();
    let (relay_read, relay_write) = relay.into_split();
    tokio::join!(
        pump(client_read, relay_write, gate.clone(), Some(from_device)),
        pump(relay_read, client_write, gate.clone(), None),
    );
}

/// Copies `from` to `to` a chunk at a time, and starts no pass while the front is stalled. The
/// `select!` that races a read against the switch is not biased, so a read that is ready when the
/// switch is made can win it and its chunk is then written after the switch; a read that the
/// switch wins has taken nothing, so the stream continues intact on resume.
async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    mut gate: watch::Receiver<bool>,
    count: Option<Arc<AtomicU64>>,
) {
    let mut chunk = vec![0_u8; 16 * 1024];
    loop {
        if gate.wait_for(|stalled| !*stalled).await.is_err() {
            break;
        }
        let read = tokio::select! {
            read = from.read(&mut chunk) => read,
            _ = gate.wait_for(|stalled| *stalled) => continue,
        };
        let Ok(length) = read else { break };
        if length == 0 {
            break;
        }
        if let Some(count) = &count {
            count.fetch_add(length as u64, Ordering::SeqCst);
        }
        if to.write_all(&chunk[..length]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}
