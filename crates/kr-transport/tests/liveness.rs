//! A connection's liveness, observed on real connections rather than read from its constants.
//!
//! Each connection is watched through its own counters of the datagrams it has sent and received,
//! which count every path the connection uses. A loopback pair of endpoints can reach each other
//! over more than one address, so cutting one path would not silence a connection; the silent
//! leg's host therefore runs on a runtime of its own that the test stops dead, and from then on it
//! sends nothing and answers nothing on any path, which is what an unreachable host looks like.

mod support;

use std::time::Duration;

use iroh::endpoint::{Connection, ConnectionError};
use kr_protocol::hello::ALPN;
use kr_transport::config::EndpointConfig;
use support::{direct_addr, paired_pair, side};
use tokio::time::Instant;

/// How often the counters are read.
const SAMPLE: Duration = Duration::from_millis(50);

/// Reads a connection's datagram counters until `until`, and returns the longest stretch in which
/// nothing was sent and the longest in which nothing was received.
async fn longest_silences(connection: &Connection, until: Instant) -> (Duration, Duration) {
    let stats = connection.stats();
    let (mut sent, mut received) = (stats.udp_tx.datagrams, stats.udp_rx.datagrams);
    let (mut sent_at, mut received_at) = (Instant::now(), Instant::now());
    let (mut sent_gap, mut received_gap) = (Duration::ZERO, Duration::ZERO);
    while Instant::now() < until {
        tokio::time::sleep(SAMPLE).await;
        let now = Instant::now();
        let stats = connection.stats();
        if stats.udp_tx.datagrams != sent {
            sent = stats.udp_tx.datagrams;
            sent_at = now;
        }
        if stats.udp_rx.datagrams != received {
            received = stats.udp_rx.datagrams;
            received_at = now;
        }
        sent_gap = sent_gap.max(now - sent_at);
        received_gap = received_gap.max(now - received_at);
    }
    (sent_gap, received_gap)
}

/// Accepts every connection that reaches `endpoint` and holds it open.
fn hold_everything(endpoint: iroh::Endpoint) {
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            if let Ok(connection) = incoming.await {
                held.push(connection);
            }
        }
    });
}

/// KR-REQ-23.22: a connection with nothing to say is kept alive, never silent for longer than the
/// ten-second keepalive interval, and a connection whose peer goes silent is declared unavailable
/// at the thirty-second threshold. Both are observed on live connections through their own
/// datagram counters: the idle one outlives the threshold and never goes more than ten seconds
/// without sending or without receiving (a second allowed for scheduling), and the one whose host
/// stops dead ends with a timeout thirty to forty seconds after the last datagram reached it; the
/// upper bound allows for the one keepalive the client may send after that datagram, which
/// restarts its idle timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_connection_is_kept_alive_and_a_silent_one_ends_after_thirty_seconds() {
    // The idle pair lives on this runtime.
    let (host, client) = paired_pair().await;
    hold_everything(host.endpoint.clone());
    let idle = tokio::time::timeout(
        Duration::from_secs(20),
        client.endpoint.connect(direct_addr(&host), ALPN),
    )
    .await
    .expect("the idle connection opens in time")
    .expect("the idle connection opens");

    // The silent pair's host lives on a thread and a runtime of its own, so the test can stop it.
    let (address_tx, address_rx) = tokio::sync::oneshot::channel();
    let (freeze_tx, freeze_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let silent_host = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime for the silent host");
        runtime.block_on(async move {
            let config = EndpointConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
                ..EndpointConfig::default()
            };
            let host = side(&config, 3, true).await;
            hold_everything(host.endpoint.clone());
            address_tx
                .send(direct_addr(&host))
                .expect("the test is waiting for the address");
            let _ = freeze_rx.await;
            // Stopped dead: this blocks the only thread the host's runtime has, so none of its
            // tasks runs and nothing is sent or answered on any path until the test lets go.
            let _ = release_rx.recv();
            drop(host);
        });
    });
    let silent_client = side(
        &EndpointConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            ..EndpointConfig::default()
        },
        4,
        false,
    )
    .await;
    let silent_addr = address_rx.await.expect("the silent host's address");
    let silent = tokio::time::timeout(
        Duration::from_secs(20),
        silent_client.endpoint.connect(silent_addr, ALPN),
    )
    .await
    .expect("the silent connection opens in time")
    .expect("the silent connection opens");

    let idle_leg = async {
        let (sent_gap, received_gap) =
            longest_silences(&idle, Instant::now() + Duration::from_secs(35)).await;
        assert!(
            idle.close_reason().is_none(),
            "an idle connection outlives the thirty-second threshold"
        );
        assert!(
            sent_gap <= Duration::from_secs(11) && received_gap <= Duration::from_secs(11),
            "the idle connection went {sent_gap:?} without sending and {received_gap:?} without \
             receiving"
        );
    };

    let silent_leg = async {
        // The connection settles first, and then its host stops.
        tokio::time::sleep(Duration::from_secs(3)).await;
        freeze_tx.send(()).expect("the silent host is waiting");
        let mut received = silent.stats().udp_rx.datagrams;
        let mut received_at = Instant::now();
        let error = loop {
            tokio::select! {
                error = silent.closed() => break error,
                () = tokio::time::sleep(SAMPLE) => {
                    let now = silent.stats().udp_rx.datagrams;
                    if now != received {
                        received = now;
                        received_at = Instant::now();
                    }
                    assert!(
                        received_at.elapsed() < Duration::from_secs(90),
                        "a connection whose host went silent is still open"
                    );
                }
            }
        };
        let since_last = received_at.elapsed();
        assert!(
            matches!(error, ConnectionError::TimedOut),
            "the connection ended by its inactivity threshold: {error:?}"
        );
        assert!(
            since_last >= Duration::from_millis(29_900) && since_last <= Duration::from_secs(41),
            "it ended {since_last:?} after the last datagram reached it"
        );
    };

    tokio::join!(idle_leg, silent_leg);
    release_tx.send(()).expect("the silent host is stopped");
    silent_host.join().expect("the silent host's thread");
}
