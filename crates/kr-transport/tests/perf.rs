//! The two transport performance requirements, measured over a real connection.
//!
//! * KR-PERF-005: application scheduling adds less than 25 ms p95 above the measured path round
//!   trip while a bulk transfer is running.
//! * KR-PERF-006: after the transport is available, usable state arrives within two seconds for a
//!   120x40 screen, excluding pairing, discovery outage and operating-system suspension. What this
//!   measures is the transport's share of that budget: reconnecting, completing the handshake,
//!   opening the stream and carrying a screen-sized snapshot. Rendering a real screen from it
//!   belongs to the terminal and the client that own the snapshot format.
//!
//! Both measure loopback, which is the floor rather than a claim about any network. What they
//! prove is that the application's own scheduling and handshake do not add the delay, which is
//! what the requirements are about: the path's own round trip is subtracted in the first, and
//! pairing and discovery are excluded from the second by construction.
//!
//! This is the harness, so run it optimised and record what it ran on:
//!
//! ```text
//! cargo test --release -p kr-transport --test perf -- --nocapture --test-threads=1
//! ```
//!
//! Both are timed, so both print the conditions section 27 states beside their figures: the build,
//! the operating system and architecture, the processors, the memory, the load average and how
//! late the runtime was woken while the measurement ran. KR-PERF-005 is asserted where those
//! conditions hold and recorded with its shortfall where they do not, because its figure is a
//! difference of two percentiles on the same host and noise enters it twice: a host that cannot
//! give the measurement a processor produces a number about contention, and asserting the target
//! against it would fail runs that say nothing about the product. `tests/priority.rs` holds the
//! property behind the figure, with no clock in it, and that one is asserted everywhere.
//!
//! KR-PERF-006 is asserted on every optimised run. Two seconds against a handshake and one
//! screen-sized frame on loopback is three orders of magnitude of room, so no amount of scheduling
//! noise reaches it, and a reconnect that does take two seconds is a defect however busy the host.
//!
//! One thing both assert whatever the host: the transfer was running while KR-PERF-005 measured,
//! and the snapshot arrived whole. A harness that measured an idle connection, or read an empty
//! frame, would otherwise pass by measuring nothing.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use kr_cbor::CanonicalValue;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::hello::ALPN;
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionId, TransferId};
use kr_protocol::scalars::{Nullable, Uuid};
use kr_transport::clock::ManualClock;
use kr_transport::handshake::{self, Admitted, PairedDirectory};
use kr_transport::scheduler::{SendLimits, StreamBudget};
use kr_transport::streams::StreamRegistry;
use std::sync::Arc;
use support::conditions::{Host, SchedulingProbe};
use support::{OneDevice, Side, direct_addr, epochs, ledger, paired_pair, windows};

/// One input round trip, and the payload it carried.
const INPUT_PAYLOAD: &[u8] = b"\x1b[A";

/// Wraps raw bytes as the byte string a frame carries.
///
/// Raw terminal bytes and attachment chunks are CBOR byte strings, not arrays of integers: the
/// profile's collection bound is 4 096 members, so a screen sent as an array would be refused.
fn payload(bytes: &[u8]) -> ParamsValue {
    ParamsValue::new(CanonicalValue::bytes(bytes))
}

/// Returns the bytes a frame carried.
fn bytes_of(value: &ParamsValue) -> &[u8] {
    match value.as_value() {
        CanonicalValue::Bytes(bytes) => bytes,
        other => panic!("a frame carried {other:?} rather than a byte string"),
    }
}

/// How many round trips each measurement takes.
const SAMPLES: usize = 200;

/// Worker threads the harness's own runtime occupies.
///
/// It runs the client, the host and the transfer in one process, so a host with only the reference
/// four processors has none left for the measurement itself. The conditions check says so.
const WORKER_THREADS: usize = 4;

/// The added delay KR-PERF-005 allows.
const ADDED_LIMIT: Duration = Duration::from_millis(25);

/// How often the harness asks the runtime to wake it while it measures.
///
/// Well above the runtime's timer granularity, so what comes back is lateness rather than
/// rounding.
const PROBE_INTERVAL: Duration = Duration::from_millis(5);

/// How late the runtime may be woken and the figure still be about application scheduling.
///
/// A fifth of the target. Above that the host's own scheduling is a material part of any
/// difference the measurement finds, so the difference is no longer evidence about this
/// application.
const MAX_SCHEDULING_DELAY: Duration = Duration::from_millis(5);

/// The time KR-PERF-006 allows before usable state has arrived.
const USABLE_LIMIT: Duration = Duration::from_secs(2);

/// A 120x40 screen, as the bytes a snapshot of one costs.
///
/// Four bytes a cell covers a scalar plus its attributes, which is the shape the terminal crate's
/// canonical grid stores. The number is what matters here: the measurement is of the transport, so
/// the payload only has to be the right size.
const SCREEN_BYTES: usize = 120 * 40 * 4;

fn percentile(samples: &mut [Duration], percentile: f64) -> Duration {
    samples.sort_unstable();
    let index = ((samples.len() as f64) * percentile).ceil() as usize;
    samples[index.saturating_sub(1).min(samples.len() - 1)]
}

fn one_device(client: &Side) -> Arc<dyn PairedDirectory> {
    Arc::new(OneDevice {
        endpoint_id: client.record.endpoint_id,
        record: client.record,
    })
}

fn registry(connection_id: ConnectionId) -> Arc<StreamRegistry> {
    Arc::new(StreamRegistry::new(
        connection_id,
        Arc::new(StreamBudget::new(SendLimits::default())),
        None,
    ))
}

fn input_header(connection_id: ConnectionId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::TerminalInput,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([8; 16]))),
            attachment_id: Nullable::some(AttachmentId::new(Uuid::from_bytes([7; 16]))),
            transfer_id: Nullable::null(),
        },
    }
}

fn attachment_header(connection_id: ConnectionId) -> StreamHeader {
    StreamHeader {
        kind: StreamKind::AttachmentChunks,
        connection_id,
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            session_id: Nullable::null(),
            attachment_id: Nullable::null(),
            transfer_id: Nullable::some(TransferId::new(Uuid::from_bytes([6; 16]))),
        },
    }
}

/// KR-PERF-005.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_input_stays_responsive_under_a_bulk_transfer() {
    let (host, client) = paired_pair().await;
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory = one_device(&client);

    // The host echoes every input frame back on the same stream, and drains anything that arrives
    // on a bulk stream. Echoing is what makes a round trip measurable at all.
    let serving = tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection");
        let clock = ManualClock::new();
        let challenges = ledger();
        let issuer = windows(&clock);
        let admitted = handshake::accept(
            &connection,
            &identity,
            epochs(),
            directory.as_ref(),
            &challenges,
            &issuer,
        )
        .await
        .expect("an admitted connection");
        let Admitted::Authorised(authorised) = admitted else {
            panic!("a paired endpoint is authorised");
        };
        let streams = registry(authorised.connection_id);
        loop {
            let Ok(mut stream) = streams.accept(&connection).await else {
                return;
            };
            tokio::spawn(async move {
                let kind = stream.kind();
                loop {
                    let echoed = match stream.read_payload().await {
                        Ok(Some(frame)) => frame,
                        _ => return,
                    };
                    if kind == StreamKind::TerminalInput
                        && stream.write_payload(&echoed).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let streams = registry(authorised.connection_id);

    let mut input = streams
        .open(&connection, input_header(authorised.connection_id))
        .await
        .expect("an input stream");

    let mut baseline = round_trips(&mut input, SAMPLES).await;
    let baseline_p95 = percentile(&mut baseline, 0.95);

    // A bulk transfer now fills the connection. The scheduler's job is to keep the keystroke ahead
    // of it.
    let bulk_connection = connection.clone();
    let bulk_streams = Arc::clone(&streams);
    let bulk_connection_id = authorised.connection_id;
    let chunks = Arc::new(AtomicUsize::new(0));
    let bulk_chunks = Arc::clone(&chunks);
    let bulk = tokio::spawn(async move {
        let mut stream = bulk_streams
            .open(&bulk_connection, attachment_header(bulk_connection_id))
            .await
            .expect("a bulk stream");
        let chunk = payload(&vec![0u8; 512 * 1024]);
        loop {
            // The bulk write goes through the data stream, so every chunk is charged against the
            // connection's queued-bytes ceiling before it is handed to the connection.
            if stream.write_message(&chunk).await.is_err() {
                return;
            }
            bulk_chunks.fetch_add(1, Ordering::Relaxed);
        }
    });
    // Let the transfer reach steady state before the keystrokes are measured against it.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let before = chunks.load(Ordering::Relaxed);
    let probe = SchedulingProbe::start(PROBE_INTERVAL);
    let mut loaded = round_trips(&mut input, SAMPLES).await;
    let mut lateness = probe.stop();
    let during = chunks.load(Ordering::Relaxed) - before;
    let loaded_p95 = percentile(&mut loaded, 0.95);
    let scheduling_p95 = percentile(&mut lateness, 0.95);
    bulk.abort();

    let added = loaded_p95.saturating_sub(baseline_p95);
    let host = Host::read();
    println!("KR-PERF-005 remote input under a bulk transfer");
    for line in host.lines() {
        println!("{line}");
    }
    println!(
        "  runtime woken     {:.3} ms late at p95, over {} asks",
        scheduling_p95.as_secs_f64() * 1000.0,
        lateness.len()
    );
    println!("  samples           {SAMPLES} round trips");
    println!("  transfer          {during} chunks of 512 KiB while they ran");
    println!(
        "  path round trip   {:.3} ms p95",
        baseline_p95.as_secs_f64() * 1000.0
    );
    println!(
        "  under transfer    {:.3} ms p95",
        loaded_p95.as_secs_f64() * 1000.0
    );
    println!(
        "  added             {:.3} ms p95 against a {:.3} ms target",
        added.as_secs_f64() * 1000.0,
        ADDED_LIMIT.as_secs_f64() * 1000.0
    );

    // Whatever the host, the measurement has to have measured something: a transfer that never
    // started leaves the loaded phase idle, and the figure would be a second idle measurement.
    assert!(
        during > 0,
        "the transfer moved nothing while the round trips ran, so they were not measured under one"
    );
    assert!(
        !lateness.is_empty(),
        "the harness recorded no runtime lateness, so its conditions are unknown"
    );

    let shortfalls = host.shortfalls(WORKER_THREADS, scheduling_p95, MAX_SCHEDULING_DELAY);
    if shortfalls.is_empty() {
        println!("  conditions        section 27's are met, so the target is asserted here");
        assert!(
            added < ADDED_LIMIT,
            "application scheduling added {added:?} above the measured path round trip"
        );
    } else {
        for shortfall in &shortfalls {
            println!("  condition missing {shortfall}");
        }
        println!(
            "  conditions        not met, so the figure above is recorded and the target is not \
             asserted here"
        );
    }

    connection.close(0u32.into(), b"done");
    serving.abort();
}

async fn round_trips(
    stream: &mut kr_transport::streams::DataStream,
    samples: usize,
) -> Vec<Duration> {
    let mut measurements = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        stream
            .write_message(&payload(INPUT_PAYLOAD))
            .await
            .expect("the keystroke was sent");
        let echoed = stream
            .read_message::<ParamsValue>()
            .await
            .expect("an echo")
            .expect("the stream did not end");
        measurements.push(started.elapsed());
        assert_eq!(bytes_of(&echoed), INPUT_PAYLOAD);
    }
    measurements
}

/// KR-PERF-006.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_reaches_usable_state_within_two_seconds() {
    let (host, client) = paired_pair().await;
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory = one_device(&client);

    // The host answers the first frame on a semantic-updates stream with a screen-sized snapshot,
    // which stands for the state a client installs before it is usable.
    let serving = tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let Ok(connection) = incoming.await else {
                continue;
            };
            let identity = Arc::clone(&identity);
            let directory = Arc::clone(&directory);
            tokio::spawn(async move {
                let clock = ManualClock::new();
                let challenges = ledger();
                let issuer = windows(&clock);
                let Ok(Admitted::Authorised(authorised)) = handshake::accept(
                    &connection,
                    &identity,
                    epochs(),
                    directory.as_ref(),
                    &challenges,
                    &issuer,
                )
                .await
                else {
                    return;
                };
                let streams = registry(authorised.connection_id);
                let Ok(mut stream) = streams.accept(&connection).await else {
                    return;
                };
                let _ = stream.read_payload().await;
                let snapshot = payload(&vec![0u8; SCREEN_BYTES]);
                stream
                    .write_message(&snapshot)
                    .await
                    .expect("the snapshot was sent");
                // The connection has to outlive the write, or the snapshot never leaves.
                let _ = connection.closed().await;
            });
        }
    });

    // One connection first, so the measurement is of a reconnect rather than of a cold start.
    let first = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let _ = handshake::connect(&first, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    first.close(0u32.into(), b"reconnecting");

    let started = Instant::now();
    let connection = client
        .endpoint
        .connect(direct_addr(&host), ALPN)
        .await
        .expect("a connection");
    let authorised = handshake::connect(&connection, &client.identity, &host.record)
        .await
        .expect("an authorised connection");
    let streams = registry(authorised.connection_id);
    let mut stream = streams
        .open(
            &connection,
            StreamHeader {
                kind: StreamKind::SemanticUpdates,
                connection_id: authorised.connection_id,
                stream_id: Nullable::null(),
                resource: StreamResource {
                    environment_id: EnvironmentId::new(Uuid::from_bytes([9; 16])),
                    session_id: Nullable::some(SessionId::new(Uuid::from_bytes([8; 16]))),
                    attachment_id: Nullable::null(),
                    transfer_id: Nullable::null(),
                },
            },
        )
        .await
        .expect("a semantic stream");
    stream
        .write_message(&payload(b"subscribe"))
        .await
        .expect("the subscription was sent");
    let snapshot = stream
        .read_message::<ParamsValue>()
        .await
        .expect("a snapshot")
        .expect("the stream did not end");
    let elapsed = started.elapsed();

    assert_eq!(bytes_of(&snapshot).len(), SCREEN_BYTES);
    let host = Host::read();
    println!("KR-PERF-006 the transport's share of a reconnect");
    for line in host.lines() {
        println!("{line}");
    }
    println!("  screen            120x40, {SCREEN_BYTES} bytes");
    println!(
        "  usable state      {:.3} ms against a 2000.000 ms target",
        elapsed.as_secs_f64() * 1000.0
    );
    assert!(
        elapsed < USABLE_LIMIT,
        "usable state took {elapsed:?}, against a {USABLE_LIMIT:?} target"
    );

    connection.close(0u32.into(), b"done");
    serving.abort();
}
