//! An endpoint that receives a datagram larger than its receive buffer goes on running.
//!
//! Anyone who can send one UDP datagram to an endpoint's port can send it a datagram above the
//! buffer it receives into, with no handshake and no credential. The socket layer drops such a
//! datagram, and on Apple systems it once did so by calling the receive system call again and again
//! when the socket's queue was empty: the call never returned, the thread that made it ran at full
//! load, and the endpoint handled nothing until some datagram that fitted arrived. A host that is
//! waiting for a peer has no such datagram coming.
//!
//! What the case sees. The listening endpoint runs on a thread and a current-thread runtime of its
//! own, so a receive call that does not return holds the only thread its runtime has, and a task of
//! that runtime that sends a beat at a steady interval stops sending. The beats show that the
//! runtime went on. They do not show that the endpoint read the datagram: a datagram that waits in
//! the socket's queue holds nothing, and the dial that ends the case sends packets that fit, which
//! would end a receive call that does not return. So where the case can read the socket's queue it
//! reads it, and it takes the beats as showing the fault absent only when the queue also shows that
//! the endpoint read the datagram.
//!
//! For each oversized datagram, on Apple systems, the case:
//!
//! 1. holds the endpoint's runtime thread on a channel, so that nothing reads the socket;
//! 2. sends the datagram and waits until the socket's queue holds it, which also shows that the
//!    datagram arrived;
//! 3. releases the thread, and waits for a number of beats that came after that, failing when one
//!    does not come: it decides by the beats that came, and the wait only bounds how long a stopped
//!    runtime is given before the case says so;
//! 4. looks at the queue, and while the datagram is still in it waits for the same number of beats
//!    again and looks again, up to a bound: a queue that held the datagram and is empty is one the
//!    endpoint's driver read, since nothing else reads that socket, and a queue that still holds
//!    it at the bound is one the endpoint did not read;
//! 5. waits for the same number of beats once more, which shows that the runtime goes on after the
//!    read: a receive call that read the datagram and then did not return would stop them.
//!
//! The queue is read through a duplicate of the endpoint's own descriptor, which Apple systems give
//! when a process opens `/dev/fd/<n>`, found by the address it is bound to. Reading it with
//! `peek_from` leaves the queue as it was and changes no flag of the socket. The case looks at the
//! queue while the thread is held, and afterwards once for each run of beats, never in a tight
//! loop: on this system a loop of looks at the queue while the endpoint reads it left the datagram
//! unread in about a third of the runs or more, with the endpoint's runtime running and with no
//! wake-up to come for it, and the same loop of looks over a plain tokio socket did the same. The
//! datagrams are 2,000 and 9,000 bytes, each above the buffer; the second keeps the case able to
//! see the fault if a later release of the library reads into a buffer larger than 2,000 bytes, and
//! a sender can repeat one, so each is sent in turn. After them a second endpoint dials the first
//! and the connection opens, which shows that the endpoint still takes a peer. When the beats stop,
//! the case sends one small datagram to let the endpoint go before it fails, so that the thread
//! does not keep running while the rest of the run goes on.
//!
//! Elsewhere. On Linux and Android the endpoint reads datagrams with a batch call that has no such
//! loop, so the fault does not exist there; and `/dev/fd/<n>` is not a duplicate of a socket there.
//! The case looks for the duplicate on Apple systems only. Elsewhere it reads no queue: it sends
//! the datagrams and waits for the beats, which shows that the runtime went on after each send and
//! says nothing of whether the endpoint read it. The case is built on Unix targets only: Windows has
//! a socket layer of its own, with no such loop, and the file is empty there.

#![cfg(unix)]

mod support;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use iroh::EndpointAddr;
use kr_transport::ALPN;
use kr_transport::config::EndpointConfig;
use kr_transport::endpoint::connect;
use support::{direct_addr, side};
use tokio::sync::oneshot;

/// The sizes of the datagrams the endpoint is sent: above the 1,472 bytes it receives into on
/// Apple systems, and within what a loopback delivers whole (the default limit of an Apple system's
/// UDP datagram is 9,216 bytes), so each arrives as one datagram and is cut only by the receive
/// buffer.
const OVERSIZED: [usize; 2] = [2_000, 9_000];

/// How many beats must come after a step before the endpoint counts as running at that step.
const BEATS: usize = 25;

/// How many times the case looks at the queue for a datagram it has seen there, each look after
/// `BEATS` more beats, before it says that the endpoint did not read the datagram: as long, at
/// the beat's pace, as `STALL`.
const LOOKS: usize = 200;

/// How often the endpoint's runtime sends a beat when nothing holds it.
const BEAT: Duration = Duration::from_millis(2);

/// How long the case waits for one beat, or for the socket's queue to change, before it says what
/// did not happen. A running runtime sends a beat within milliseconds and a loopback delivers at
/// once; the figure only has to be long enough for a loaded machine.
const STALL: Duration = Duration::from_secs(10);

/// How long the connection of the last step is given to open.
const DEADLINE: Duration = Duration::from_secs(60);

/// The descriptors of this process that are looked at when the endpoint's socket is sought: the
/// figure Apple's headers call `OPEN_MAX`. A process that holds a descriptor above it gets no look
/// at that one, and the case then fails saying that no descriptor is the endpoint's socket.
#[cfg(target_vendor = "apple")]
const OPEN_MAX: u32 = 10_240;

fn loopback_config() -> EndpointConfig {
    EndpointConfig {
        bind_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        ..EndpointConfig::default()
    }
}

/// A request that the endpoint's runtime hold itself: it tells `held`, then blocks its thread until
/// `release` is sent to or dropped.
struct Hold {
    held: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

/// A listening endpoint on a thread and a current-thread runtime of its own, with a task that sends a
/// beat at a steady interval, a task that holds the runtime when asked, and another that takes one
/// connection.
struct Host {
    /// The socket the endpoint received on, where the datagrams go.
    socket: SocketAddr,
    /// How a peer dials the endpoint.
    dial: EndpointAddr,
    /// One message for each beat of the runtime.
    beats: mpsc::Receiver<()>,
    /// Asks the runtime to hold itself.
    hold: tokio::sync::mpsc::UnboundedSender<Hold>,
    /// Set when the endpoint has taken a connection.
    accepted: oneshot::Receiver<()>,
    stop: oneshot::Sender<()>,
    thread: JoinHandle<()>,
}

impl Host {
    fn start() -> Self {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (beat_tx, beats) = mpsc::channel();
        let (hold, mut hold_rx) = tokio::sync::mpsc::unbounded_channel::<Hold>();
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
                tokio::spawn(async move {
                    while let Some(Hold { held, release }) = hold_rx.recv().await {
                        // Nothing in this runtime runs between the two calls, or until the case
                        // lets go: the thread is the runtime's only one.
                        let _ = held.send(());
                        let _ = release.recv();
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
            hold,
            accepted,
            stop,
            thread,
        }
    }

    /// Holds the endpoint's runtime thread, once it has taken the request, until the sender this
    /// returns is sent to or dropped.
    fn hold(&self) -> mpsc::Sender<()> {
        let (held_tx, held) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        self.hold
            .send(Hold {
                held: held_tx,
                release,
            })
            .expect("the endpoint's runtime is running");
        held.recv_timeout(STALL)
            .expect("the endpoint's runtime took the hold");
        release_tx
    }

    /// Fails the case, saying what the endpoint's runtime did not do, unless it runs. When it does
    /// not, one small datagram is sent first, to let go a receive call that does not return.
    fn expect_runs(&self, sender: &UdpSocket, round: usize, size: usize) {
        if self.runs() {
            return;
        }
        // A datagram that fits ends a receive call that does not return.
        sender
            .send_to(&[0_u8; 16], self.socket)
            .expect("the releasing datagram sent");
        let released = self.runs();
        panic!(
            "after oversized datagram {round}, {size} bytes, the endpoint's runtime sent no beat \
             for {STALL:?}, so its receive call held the thread; a datagram that fits {} it",
            if released {
                "released"
            } else {
                "did not release"
            }
        );
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

/// A duplicate of this process's descriptor for the socket bound to `address`, to read its queue
/// with. Apple systems open `/dev/fd/<n>` as a duplicate of descriptor `n`, one that shares the
/// socket and its flags, so the socket stays the endpoint's: each descriptor looked at is opened and
/// closed again as its own duplicate, and none of the process's descriptors is closed or changed.
#[cfg(target_vendor = "apple")]
fn duplicate_of_socket_bound_to(address: SocketAddr) -> Option<UdpSocket> {
    (0..OPEN_MAX).find_map(|descriptor| {
        let file = std::fs::File::open(format!("/dev/fd/{descriptor}")).ok()?;
        let socket = UdpSocket::from(std::os::fd::OwnedFd::from(file));
        (socket.local_addr().ok()? == address).then_some(socket)
    })
}

/// Elsewhere the descriptors are not looked at and the queue is not read: on Linux and Android
/// `/dev/fd/<n>` is not a duplicate of a socket, and opening it for a pipe can block.
#[cfg(not(target_vendor = "apple"))]
fn duplicate_of_socket_bound_to(_address: SocketAddr) -> Option<UdpSocket> {
    None
}

/// Whether a datagram waits in the queue of the socket `view` is a duplicate of. It takes nothing
/// out of the queue.
fn queued(view: &UdpSocket) -> bool {
    match view.peek_from(&mut [0_u8; 1]) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("the endpoint's socket could not be looked at: {error}"),
    }
}

/// Looks until `condition` holds, for at most `STALL`, and says whether it did. It waits for the
/// condition itself and sleeps for no figure.
fn becomes(mut condition: impl FnMut() -> bool) -> bool {
    let began = Instant::now();
    while !condition() {
        if began.elapsed() >= STALL {
            return false;
        }
        std::thread::yield_now();
    }
    true
}

#[test]
fn an_endpoint_goes_on_after_a_datagram_above_its_receive_buffer() {
    let host = Host::start();
    let view = duplicate_of_socket_bound_to(host.socket);
    assert!(
        view.is_some() || !cfg!(target_vendor = "apple"),
        "no descriptor of this process is the endpoint's socket {}",
        host.socket
    );
    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a sender");

    for (round, size) in OVERSIZED.into_iter().enumerate() {
        let oversized = vec![0x5a_u8; size];
        let held = view.as_ref().map(|_| host.hold());
        sender
            .send_to(&oversized, host.socket)
            .expect("the oversized datagram sent");
        if let Some(view) = &view {
            assert!(
                becomes(|| queued(view)),
                "oversized datagram {round}, {size} bytes, did not reach the endpoint's socket"
            );
            drop(held);
        }
        host.expect_runs(&sender, round, size);
        if let Some(view) = &view {
            let mut read = false;
            for _ in 0..LOOKS {
                if !queued(view) {
                    read = true;
                    break;
                }
                host.expect_runs(&sender, round, size);
            }
            assert!(
                read,
                "the endpoint's runtime went on after oversized datagram {round}, {size} bytes, \
                 but the datagram is still in the endpoint's socket: the endpoint did not read it"
            );
            // The runtime goes on after the read as well: a receive call that read the datagram
            // and then did not return would stop the beats from here on.
            host.expect_runs(&sender, round, size);
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
