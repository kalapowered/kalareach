//! An endpoint that receives a datagram larger than its receive buffer goes on running.
//!
//! Anyone who can send one UDP datagram to an endpoint's port can send it a datagram above the
//! buffer it receives into, with no handshake and no credential. The socket layer drops such a
//! datagram, and on Apple systems it once did so by calling the receive system call again and again
//! when the socket's queue was empty: the call never returned, the thread that made it ran at full
//! load, and the endpoint handled nothing until some datagram that fitted arrived. A host that is
//! waiting for a peer has no such datagram coming.
//!
//! The case shows that the receive call returned, from outside the endpoint. The listening
//! endpoint runs on a thread and a current-thread runtime of its own, so a receive call that does
//! not return holds the only thread its runtime has, and a task of that runtime that sends a beat
//! at a steady interval stops sending. After each oversized datagram the case waits for a number of
//! beats and fails when one does not come: it decides by the beats that came, and the wait only
//! bounds how long a stopped runtime is given before the case says so. It sends the datagram twice,
//! because a sender can repeat it and because a receive call that read the first one late would
//! hold the thread when the second arrives. Then a second endpoint dials the first and the
//! connection opens, which shows that the endpoint still takes a peer.
//!
//! A datagram that fits would also end a stuck receive call, so neither a small datagram nor a
//! connection attempt can tell a stopped endpoint from a running one; only the beats can. When the
//! beats stop, the case sends one small datagram to let the endpoint go before it fails, so that
//! the thread does not keep running while the rest of the run goes on.
//!
//! The case is built on Unix targets, which is where the endpoint's socket layer can be asked this
//! question with a plain socket: on Apple systems it is the receive path above, and on Linux the
//! datagram is read by a batch call that has no such loop, so there the case guards against the
//! same symptom from another cause. Windows has a socket layer of its own and is not covered here.

#![cfg(unix)]

mod support;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use iroh::EndpointAddr;
use kr_transport::ALPN;
use kr_transport::config::EndpointConfig;
use kr_transport::endpoint::connect;
use support::{direct_addr, side};
use tokio::sync::oneshot;

/// The size of the datagram the endpoint is sent: above the 1,472 bytes it receives into on Apple
/// systems, and within what a loopback delivers whole, so the datagram arrives as one datagram and
/// is cut only by the receive buffer.
const OVERSIZED: usize = 2_000;

/// How many beats must come after a datagram before the endpoint counts as running.
const BEATS: usize = 25;

/// How often the endpoint's runtime sends a beat when nothing holds it.
const BEAT: Duration = Duration::from_millis(2);

/// How long the case waits for one beat before it says the runtime is held. A running runtime
/// sends it within milliseconds; the figure only has to be long enough for a loaded machine.
const STALL: Duration = Duration::from_secs(10);

/// How long the connection of the last step is given to open.
const DEADLINE: Duration = Duration::from_secs(60);

fn loopback_config() -> EndpointConfig {
    EndpointConfig {
        bind_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        ..EndpointConfig::default()
    }
}

/// A listening endpoint on a thread and a current-thread runtime of its own, with a task that sends
/// a beat at a steady interval and another that takes one connection.
struct Host {
    /// The socket the endpoint received on, where the datagrams go.
    socket: SocketAddr,
    /// How a peer dials the endpoint.
    dial: EndpointAddr,
    /// One message for each beat of the runtime.
    beats: mpsc::Receiver<()>,
    /// Set when the endpoint has taken a connection.
    accepted: oneshot::Receiver<()>,
    stop: oneshot::Sender<()>,
    thread: JoinHandle<()>,
}

impl Host {
    fn start() -> Self {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (beat_tx, beats) = mpsc::channel();
        let (accepted_tx, accepted) = oneshot::channel();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the endpoint");
            runtime.block_on(async move {
                let host = side(&loopback_config(), 1, true).await;
                let socket = host
                    .endpoint
                    .bound_sockets()
                    .into_iter()
                    .find(SocketAddr::is_ipv4)
                    .expect("the endpoint's IPv4 socket");
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(BEAT).await;
                        if beat_tx.send(()).is_err() {
                            break;
                        }
                    }
                });
                let endpoint = host.endpoint.clone();
                tokio::spawn(async move {
                    let connection = endpoint
                        .accept()
                        .await
                        .expect("an incoming connection")
                        .await
                        .expect("a connection");
                    let _ = accepted_tx.send(());
                    connection.closed().await;
                });
                ready_tx
                    .send((socket, direct_addr(&host)))
                    .expect("the case is waiting for the address");
                let _ = stopped.await;
            });
        });
        let (socket, dial) = ready_rx
            .recv_timeout(DEADLINE)
            .expect("the endpoint's address");
        Self {
            socket,
            dial,
            beats,
            accepted,
            stop,
            thread,
        }
    }

    /// Whether the endpoint's runtime is running: `BEATS` beats, all of them sent after this call
    /// began, and none of them more than `STALL` after the one before.
    fn runs(&self) -> bool {
        while self.beats.try_recv().is_ok() {}
        for _ in 0..BEATS {
            match self.beats.recv_timeout(STALL) {
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => return false,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("the endpoint's thread ended")
                }
            }
        }
        true
    }
}

#[test]
fn an_endpoint_goes_on_after_a_datagram_above_its_receive_buffer() {
    let host = Host::start();
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a sender");
    let oversized = vec![0x5a_u8; OVERSIZED];

    for round in 1..=2 {
        sender
            .send_to(&oversized, host.socket)
            .expect("the oversized datagram sent");
        if !host.runs() {
            // A datagram that fits ends a receive call that does not return.
            sender
                .send_to(&[0_u8; 16], host.socket)
                .expect("the releasing datagram sent");
            let released = host.runs();
            panic!(
                "after oversized datagram {round} the endpoint's runtime sent no beat for {STALL:?}, \
                 so its receive call held the thread; a datagram that fits {} it",
                if released {
                    "released"
                } else {
                    "did not release"
                }
            );
        }
    }

    let Host {
        dial,
        accepted,
        stop,
        thread,
        ..
    } = host;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the dialling endpoint");
    runtime.block_on(async {
        let client = side(&loopback_config(), 2, false).await;
        let connection = tokio::time::timeout(DEADLINE, connect(&client.endpoint, dial, ALPN))
            .await
            .expect("the connection opens in time")
            .expect("the connection opens");
        tokio::time::timeout(DEADLINE, accepted)
            .await
            .expect("the endpoint takes the connection in time")
            .expect("the endpoint took the connection");
        drop(connection);
    });

    let _ = stop.send(());
    thread.join().expect("the endpoint's thread ends");
}
