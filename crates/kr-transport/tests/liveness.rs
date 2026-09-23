//! A connection's liveness, observed on real connections rather than read from its constants.
//!
//! Each connection here runs over a UDP path the test owns: a relay of datagrams between the two
//! endpoints that counts what it carries and can be cut. Relaying and discovery are off, so the
//! path is the only way the two endpoints can reach each other.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh::EndpointAddr;
use iroh::endpoint::{Connection, ConnectionError};
use kr_protocol::hello::ALPN;
use support::{Side, paired_pair};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// A cuttable UDP path from a client to a host.
struct Path {
    /// The address the client dials instead of the host's own.
    address: SocketAddr,
    /// While true, datagrams are carried both ways.
    open: Arc<AtomicBool>,
    /// When each datagram carried from the client reached the host.
    towards_host: Arc<Mutex<Vec<Instant>>>,
    /// When each datagram carried from the host reached the client.
    towards_client: Arc<Mutex<Vec<Instant>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Path {
    /// The longest stretch between `from` and `to` in which nothing crossed the path in one
    /// direction.
    async fn longest_silence(
        arrivals: &Mutex<Vec<Instant>>,
        from: Instant,
        to: Instant,
    ) -> Duration {
        let arrivals = arrivals.lock().await;
        let mut previous = from;
        let mut longest = Duration::ZERO;
        for at in arrivals
            .iter()
            .copied()
            .filter(|at| *at >= from && *at <= to)
            .chain(std::iter::once(to))
        {
            longest = longest.max(at - previous);
            previous = at;
        }
        longest
    }
}

impl Drop for Path {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Opens a path to the host's IPv4 loopback socket.
async fn path_to(host: &Side) -> Path {
    let target = host
        .endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .expect("the host is bound on IPv4 loopback");
    let facing_client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a socket for the client side");
    let facing_host = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a socket for the host side");
    facing_host
        .connect(target)
        .await
        .expect("the host side is aimed at the host");
    let address = facing_client.local_addr().expect("an address");
    let open = Arc::new(AtomicBool::new(true));
    let towards_host = Arc::new(Mutex::new(Vec::new()));
    let towards_client = Arc::new(Mutex::new(Vec::new()));
    let task = {
        let open = Arc::clone(&open);
        let towards_host = Arc::clone(&towards_host);
        let towards_client = Arc::clone(&towards_client);
        tokio::spawn(async move {
            let mut client: Option<SocketAddr> = None;
            let mut from_client = vec![0u8; 65_536];
            let mut from_host = vec![0u8; 65_536];
            loop {
                tokio::select! {
                    received = facing_client.recv_from(&mut from_client) => {
                        let Ok((len, sender)) = received else { return };
                        client = Some(sender);
                        if open.load(Ordering::Acquire)
                            && facing_host.send(&from_client[..len]).await.is_ok()
                        {
                            towards_host.lock().await.push(Instant::now());
                        }
                    }
                    received = facing_host.recv(&mut from_host) => {
                        let Ok(len) = received else { return };
                        if let Some(client) = client
                            && open.load(Ordering::Acquire)
                            && facing_client.send_to(&from_host[..len], client).await.is_ok()
                        {
                            towards_client.lock().await.push(Instant::now());
                        }
                    }
                }
            }
        })
    };
    Path {
        address,
        open,
        towards_host,
        towards_client,
        task,
    }
}

/// Connects the client to the host over `path`, and returns the connection with the host's side
/// held open by a task that accepts it.
async fn connect_over(host: &Side, client: &Side, path: &Path) -> Connection {
    let endpoint = host.endpoint.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            if let Ok(connection) = incoming.await {
                held.push(connection);
            }
        }
    });
    let addr = EndpointAddr::new(host.endpoint.id()).with_ip_addr(path.address);
    tokio::time::timeout(Duration::from_secs(20), client.endpoint.connect(addr, ALPN))
        .await
        .expect("the connection opens in time")
        .expect("the connection opens over the path")
}

/// KR-REQ-23.22: a connection with nothing to say is kept alive, never silent for longer than the
/// ten-second keepalive interval, and a connection whose path goes silent is declared unavailable
/// at the thirty-second threshold. Both are observed on live connections: the idle one outlives the
/// threshold with liveness traffic crossing its path both ways at least every ten seconds (with a
/// second allowed for scheduling), and the silenced one ends with a timeout thirty to forty seconds
/// after the last datagram reached it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_connection_is_kept_alive_and_a_silent_one_ends_after_thirty_seconds() {
    let (host, client) = paired_pair().await;
    let (silent_host, silent_client) = paired_pair().await;
    let idle_path = path_to(&host).await;
    let silent_path = path_to(&silent_host).await;
    let idle = connect_over(&host, &client, &idle_path).await;
    let silent = connect_over(&silent_host, &silent_client, &silent_path).await;

    let idle_leg = async {
        let from = Instant::now();
        tokio::time::sleep(Duration::from_secs(35)).await;
        let to = Instant::now();
        assert!(
            idle.close_reason().is_none(),
            "an idle connection outlives the thirty-second threshold"
        );
        for (direction, arrivals) in [
            ("to the host", &idle_path.towards_host),
            ("to the client", &idle_path.towards_client),
        ] {
            let silence = Path::longest_silence(arrivals, from, to).await;
            assert!(
                silence <= Duration::from_secs(11),
                "the idle path went {silence:?} without a datagram {direction}"
            );
        }
    };

    let silent_leg = async {
        // The connection settles first: a path cut in the moment the connection opens is still
        // being validated, and what is measured here is an established connection falling silent.
        tokio::time::sleep(Duration::from_secs(3)).await;
        silent_path.open.store(false, Ordering::Release);
        let error = tokio::time::timeout(Duration::from_secs(90), silent.closed())
            .await
            .expect("a silent connection ends");
        let since_last = silent_path
            .towards_client
            .lock()
            .await
            .last()
            .copied()
            .expect("the connection opened over the path")
            .elapsed();
        assert!(
            matches!(error, ConnectionError::TimedOut),
            "the connection ended by its inactivity threshold: {error:?}"
        );
        assert!(
            since_last >= Duration::from_secs(30) && since_last <= Duration::from_secs(40),
            "it ended {since_last:?} after the last datagram reached it"
        );
    };

    tokio::join!(idle_leg, silent_leg);
}
