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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

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
    /// The stop of a stalling front, and what it has read from the device.
    stop: Option<Arc<Stop>>,
    from_device: Arc<AtomicU64>,
    runtime: Option<tokio::runtime::Runtime>,
}

/// How much one read of a front's pump takes at most. A stalled front starts no read, but a read that was under
/// way when it stopped can end after the switch, so it can still take this much from each connection.
pub const CHUNK: usize = 16 * 1024;

/// The receive buffer that a stalling front's listener can be given, which its accepted sockets
/// inherit: a few KiB, so that a stalled front takes almost nothing of what the device sends and
/// the device's queue for the relay fills.
///
/// A buffer this small can also hold the device's side of a connection back after a resume. After
/// some stops, the window that the front offers once it reads again is smaller than one segment
/// of the device's side. In the traces of this buffer on Linux, every stop that held the device's
/// side back had such a window, and every stop that did not had a window of at least one segment.
/// In those traces the bytes that the stop held back then left the device's side slowly or not at
/// all: in two, one window-sized piece at a time, about ten KB a second or slower, for tens of
/// seconds; in the other two, nothing for more than twenty seconds, until the relay closed the
/// connection. What the device sent to the relay through the front waited that long. A case that
/// needs the hosts of the stopped relay answered again soon after the resume gives the front no
/// buffer of its own (`None`), which leaves the system's default.
pub const STALLED_RECEIVE_BUFFER: u32 = 4096;

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
            stop: None,
            from_device: Arc::new(AtomicU64::new(0)),
            runtime: Some(runtime),
        }
    }

    /// Starts a front that passes every byte to `relay` and back until it is told to stall, with
    /// `receive_buffer` bytes as the receive buffer of its listener (see
    /// [`STALLED_RECEIVE_BUFFER`]) or, for `None`, the system's default.
    ///
    /// Stalled, it starts no pass of its copy loop on any connection that it holds, so the sockets
    /// stay open and the device's side of each fills. The switch does not stop a pass that is under
    /// way: a read that is ready when the switch is made can still be taken, its chunk is then
    /// written, and that write can end after the switch. It goes on accepting connections that are
    /// made after the switch and leaves each of them alone, so that a client dialling it again
    /// meets a connection that never completes its handshake and not a refusal. On resume it
    /// passes again, bytes and new connections alike; a chunk that was read is written and the
    /// rest was never read, so no byte is lost.
    pub fn stalling(relay: &LocalRelay, receive_buffer: Option<u32>) -> Self {
        let upstream = authority(&relay.url);
        let (stop, gate) = Stop::new();
        let accepted = Arc::new(AtomicUsize::new(0));
        let from_device = Arc::new(AtomicU64::new(0));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the front's runtime");
        let (found, finding) = std::sync::mpsc::channel();
        let (counting, counted) = (Arc::clone(&accepted), Arc::clone(&from_device));
        let pumps = Arc::clone(&stop);
        runtime.spawn(async move {
            let socket = TcpSocket::new_v4().expect("a front socket");
            if let Some(bytes) = receive_buffer {
                socket
                    .set_recv_buffer_size(bytes)
                    .expect("a small receive buffer");
            }
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
                    Arc::clone(&pumps),
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
            stop: Some(stop),
            from_device,
            runtime: Some(runtime),
        }
    }

    /// Stops a stalling front after the pass that is under way in each direction: a read that is
    /// ready at the switch can still be taken and its chunk written, and that write can end after
    /// the switch.
    ///
    /// Returns how many bytes the front had read from the device, counted right after the switch.
    /// Only a read that was under way at the switch can add to it before the resume: one chunk of
    /// at most [`CHUNK`] bytes on each connection.
    pub fn stall(&self) -> u64 {
        self.stop.as_ref().expect("a stalling front").set(true);
        self.read_from_device()
    }

    /// Lets a stalling front pass bytes and connections again. Returns the front's instant of the
    /// resume, taken before the switch changes: no pump passes the gate earlier.
    pub fn resume(&self) -> Instant {
        self.stop.as_ref().expect("a stalling front").set(false)
    }

    /// Waits until every pump of the front waits at the gate, for at most `bound`, and returns an
    /// error with its own words when one does not. It blocks on a thread of its own and is bounded
    /// by the clock of the operating system, not by a timer of the caller's runtime. The bound
    /// starts when that thread starts to wait: it does not bound the thread's dispatch or the
    /// caller's next poll, and a pump that misses it is not necessarily stuck, since a loaded host
    /// can delay a pump past it.
    ///
    /// On success it returns the front's instant of the confirmation. The front took it in the
    /// hold of the lock in which the last pump went to the gate, or at the switch if every pump
    /// already waited, so it does not depend on when the blocking thread or the caller runs: a
    /// byte that the device sends after that instant cannot cross the front before the resume.
    /// A front that is not stopped has no stop to confirm: it returns at once with the instant of
    /// the call.
    ///
    /// What it shows: once it returns, no pump takes another read or writes another chunk before
    /// the next resume, so a byte that the device sends after it returns cannot cross the front. A
    /// pump leaves the count only while the front is not stopped, in the same hold of a lock that
    /// reads the stop, so the count cannot show a pump that is about to read. A pump that starts
    /// after the switch (its connection was still being made to the relay) begins at the gate. What
    /// it does not cover: a connection that is accepted during the stop waits at the gate in
    /// `carry`, before it has a pump, so it has nothing to confirm; and bytes that crossed the
    /// front before the pumps stood can still be answered afterwards by the relay, though the
    /// answer cannot come back until the resume.
    pub async fn confirm_stopped(&self, bound: Duration) -> Result<Instant, String> {
        let stop = Arc::clone(self.stop.as_ref().expect("a stalling front"));
        tokio::task::spawn_blocking(move || stop.wait_until_standing(bound))
            .await
            .unwrap_or_else(|_| Err("the wait for the front's pumps ended abnormally".to_owned()))
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
    stop: Arc<Stop>,
    from_device: Arc<AtomicU64>,
) {
    // A connection that is made while the front is stalled waits here, accepted and untouched. It
    // has no pump yet, so it has nothing for [`RelayFront::confirm_stopped`] to wait for.
    if gate.wait_for(|stalled| !*stalled).await.is_err() {
        return;
    }
    let Ok(relay) = TcpStream::connect(&upstream).await else {
        return;
    };
    let (client_read, client_write) = client.into_split();
    let (relay_read, relay_write) = relay.into_split();
    tokio::join!(
        pump(
            client_read,
            relay_write,
            gate.clone(),
            Stand::new(&stop),
            Some(from_device)
        ),
        pump(
            relay_read,
            client_write,
            gate.clone(),
            Stand::new(&stop),
            None
        ),
    );
}

/// Copies `from` to `to` a chunk at a time, and starts no pass while the front is stalled. The
/// `select!` that races a read against the switch is not biased, so a read that is ready when the
/// switch is made can win it and its chunk is then written after the switch; a read that the
/// switch wins has taken nothing, so the stream continues intact on resume. A pump that finds the
/// front stalled waits at the gate and reports that to its [`Stand`].
async fn pump(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    mut gate: watch::Receiver<bool>,
    mut stand: Stand,
    count: Option<Arc<AtomicU64>>,
) {
    let mut chunk = vec![0_u8; CHUNK];
    loop {
        if !stand.at_gate(&mut gate).await {
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

/// The switch of a stalling front, and which of its pumps wait at the gate.
struct Stop {
    switch: watch::Sender<bool>,
    state: Mutex<StopState>,
    changed: Condvar,
}

/// What the pumps of a stalling front have reported.
struct StopState {
    /// Whether the front is stopped. It changes together with the switch, under the lock.
    stopped: bool,
    /// How many pumps run and do not wait at the gate.
    running: usize,
    /// When the stop was confirmed: the instant at which the front was stopped and no pump ran
    /// outside the gate. None while that does not hold.
    confirmed: Option<Instant>,
}

impl StopState {
    /// Takes the confirmed stop's instant, or clears it, after `stopped` or `running` changed. It
    /// is called in the hold of the lock that made the change, by the part where the event
    /// happens: the instant is that of the event, whenever a caller learns of it.
    fn note(&mut self) {
        if self.stopped && self.running == 0 {
            self.confirmed.get_or_insert_with(Instant::now);
        } else {
            self.confirmed = None;
        }
    }
}

impl Stop {
    fn new() -> (Arc<Self>, watch::Receiver<bool>) {
        let (switch, gate) = watch::channel(false);
        let stop = Arc::new(Self {
            switch,
            state: Mutex::new(StopState {
                stopped: false,
                running: 0,
                confirmed: None,
            }),
            changed: Condvar::new(),
        });
        (stop, gate)
    }

    fn lock(&self) -> MutexGuard<'_, StopState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stops or resumes the front: the flag and the switch change under one hold of the lock.
    /// Returns the instant of the change, taken in that hold before the switch changes, so no pump
    /// passes the gate earlier than the instant of a resume.
    fn set(&self, stopped: bool) -> Instant {
        let mut state = self.lock();
        let at = Instant::now();
        state.stopped = stopped;
        state.note();
        self.switch.send_replace(stopped);
        at
    }

    /// Waits while the front is stopped and a pump runs outside the gate, for at most `bound`.
    /// Returns the instant at which the stop was confirmed, which a pump took in the hold of the
    /// lock in which it went to the gate; a front that is not stopped has none, and the instant is
    /// then that of the call.
    fn wait_until_standing(&self, bound: Duration) -> Result<Instant, String> {
        let (state, waited) = self
            .changed
            .wait_timeout_while(self.lock(), bound, |state| {
                state.stopped && state.running != 0
            })
            .unwrap_or_else(PoisonError::into_inner);
        if waited.timed_out() {
            Err(format!(
                "{} pumps of the front did not wait at the gate within {bound:?} of the switch",
                state.running
            ))
        } else {
            Ok(state.confirmed.unwrap_or_else(Instant::now))
        }
    }
}

/// One pump's place in the count of the pumps that run outside the gate.
struct Stand {
    stop: Arc<Stop>,
    /// Whether the pump is counted as waiting at the gate.
    waiting: bool,
}

impl Stand {
    fn new(stop: &Arc<Stop>) -> Self {
        {
            let mut state = stop.lock();
            state.running += 1;
            state.note();
        }
        Self {
            stop: Arc::clone(stop),
            waiting: false,
        }
    }

    /// Waits at the gate while the front is stopped. Returns false when the front is gone.
    async fn at_gate(&mut self, gate: &mut watch::Receiver<bool>) -> bool {
        loop {
            // A pump that runs and sees no stop goes on without the lock: it stays counted.
            if !self.waiting && !*gate.borrow() {
                return true;
            }
            if self.may_go() {
                return true;
            }
            if gate.wait_for(|stalled| !*stalled).await.is_err() {
                return false;
            }
        }
    }

    /// Whether the pump may go on. It may not while the front is stopped, and it is then counted
    /// as waiting. It leaves that count only here, in the hold of the lock that finds the front
    /// not stopped.
    fn may_go(&mut self) -> bool {
        let mut state = self.stop.lock();
        if state.stopped {
            if !self.waiting {
                self.waiting = true;
                state.running -= 1;
                state.note();
                self.stop.changed.notify_all();
            }
            false
        } else {
            if self.waiting {
                self.waiting = false;
                state.running += 1;
                state.note();
            }
            true
        }
    }
}

impl Drop for Stand {
    fn drop(&mut self) {
        if !self.waiting {
            let mut state = self.stop.lock();
            state.running -= 1;
            state.note();
            self.stop.changed.notify_all();
        }
    }
}
