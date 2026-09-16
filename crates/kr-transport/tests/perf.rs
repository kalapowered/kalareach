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
//! Both are timed, so both print what section 27 asks to be recorded beside a figure: the build,
//! the operating system and architecture, the processor, the processors, the memory and the load
//! average. KR-PERF-005 prints two readings besides, because it is the one whose target the
//! conditions decide: the share of each phase the hypervisor took from this guest, and how late a
//! thread of its own was woken while it measured. `tests/support/conditions.rs` says which of
//! those is a condition and which is evidence, and why.
//!
//! KR-PERF-005 is asserted where the host meets every condition it can be shown against, and
//! recorded with the shortfall named where it does not. Its figure is a difference of two
//! percentiles on the same host, so noise enters it twice and does not cancel: on a host the
//! hypervisor kept taking the processor from, the figure alone cannot separate what the application
//! added from what the host took. What it is not is proof of the reverse: a run with no measured
//! shortfall is a run with no measured shortfall, not a certified reference-host measurement, and
//! positive stolen time does not establish that contention caused the whole difference either. Lateness alone
//! never suppresses anything, because the application under test can cause lateness and a
//! regression must not be able to switch off the check that would catch it. `tests/priority.rs`
//! holds the property behind the figure, with nothing timed in it, and that one is asserted
//! everywhere.
//!
//! KR-PERF-006 is asserted on every run, unoptimised builds included. It has held on every host
//! this has run on by three orders of magnitude, which is why it is asserted unconditionally: that
//! is a choice about where the line sits rather than a claim that no host could miss it. What it
//! measures is the transport's share alone: a screen-sized frame arriving, not a screen rendered
//! from it.
//!
//! One thing both assert whatever the host: the transfer was still running at the end of the phase
//! KR-PERF-005 measured, and the snapshot arrived whole. A harness that measured an idle
//! connection, or read an empty frame, would otherwise pass by measuring nothing.

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
use support::conditions::{
    Host, MAX_STOLEN_SHARE, SchedulingProbe, StolenSample, StolenTime, report,
};
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

/// The added delay KR-PERF-005 allows.
const ADDED_LIMIT: Duration = Duration::from_millis(25);

/// How often the harness's own thread asks to be woken while it measures.
///
/// Well above a platform's sleep granularity, so what comes back is lateness rather than
/// rounding. What it records is evidence beside the figure and no part of the conditions check;
/// `tests/support/conditions.rs` says why.
const PROBE_INTERVAL: Duration = Duration::from_millis(5);

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

    // The guest's stolen time is read once a phase, because a phase that lost a tenth of its
    // processor and a phase that lost nothing average to a figure that describes neither, and both
    // percentiles go into the difference the target is about.
    let mut stolen = StolenTime::start();
    let probe = SchedulingProbe::start(PROBE_INTERVAL);

    let mut baseline = round_trips(&mut input, SAMPLES).await;
    let baseline_p95 = percentile(&mut baseline, 0.95);
    let stolen_idle = stolen.take();

    // A bulk transfer now fills the connection. The scheduler's job is to keep the keystroke ahead
    // of it.
    let bulk_connection = connection.clone();
    let bulk_streams = Arc::clone(&streams);
    let bulk_connection_id = authorised.connection_id;
    let chunks = Arc::new(AtomicUsize::new(0));
    let bulk_chunks = Arc::clone(&chunks);
    let bulk: tokio::task::JoinHandle<Result<(), kr_transport::error::TransportError>> =
        tokio::spawn(async move {
            let mut stream = bulk_streams
                .open(&bulk_connection, attachment_header(bulk_connection_id))
                .await
                .expect("a bulk stream");
            let chunk = payload(&vec![0u8; 512 * 1024]);
            loop {
                // The bulk write goes through the data stream, so every chunk is charged against
                // the connection's queued-bytes ceiling before it is handed to the connection. The
                // error that ends it is what this task returns, so a measurement taken after the
                // transfer stopped says which write stopped it rather than saying a task ended.
                stream.write_message(&chunk).await?;
                bulk_chunks.fetch_add(1, Ordering::Relaxed);
            }
        });
    // Let the transfer reach steady state before the keystrokes are measured against it.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // The transfer's own warm-up is behind us, so this span is the loaded phase alone.
    let _ = stolen.take();
    let before = chunks.load(Ordering::Relaxed);
    let mut loaded = round_trips(&mut input, SAMPLES).await;
    let during = chunks.load(Ordering::Relaxed) - before;
    // Before the abort, because a transfer that stopped part way through leaves the rest of the
    // loaded phase measured against an idle connection, and `during` alone cannot see that.
    let transfer_ran_throughout = !bulk.is_finished();
    let stolen_loaded = stolen.take();
    // The worse of the two phases: a figure is inside the cutoff only if both phases were.
    let stolen_share = match (stolen_idle, stolen_loaded) {
        (Some(idle), Some(loaded)) => Some(idle.max(loaded)),
        (single, None) | (None, single) => single,
    };
    let mut lateness = probe.stop();
    // Before the percentile, which has no answer for an empty set.
    assert!(
        !lateness.is_empty(),
        "the harness recorded no scheduling evidence beside its figure"
    );
    let loaded_p95 = percentile(&mut loaded, 0.95);
    let scheduling_p95 = percentile(&mut lateness, 0.95);

    let added = loaded_p95.saturating_sub(baseline_p95);
    let host = Host::read();
    let shortfalls = host.shortfalls(stolen_share);
    let phase_share = |share: Option<f64>| {
        share.map_or_else(
            || "unverified".to_owned(),
            |share| format!("{:.2}%", share * 100.0),
        )
    };
    let mut lines = host.lines();
    lines.push(format!(
        "  woken late        {:.3} ms at p95, over {} asks, as evidence beside the figure",
        scheduling_p95.as_secs_f64() * 1000.0,
        lateness.len()
    ));
    lines.push(if stolen_idle.is_none() && stolen_loaded.is_none() {
        "  taken by the host not accounted for here, so unverified in both phases".to_owned()
    } else {
        format!(
            "  taken by the host {} of the idle phase and {} of the loaded one, against a {:.2}% \
             cutoff",
            phase_share(stolen_idle),
            phase_share(stolen_loaded),
            MAX_STOLEN_SHARE * 100.0
        )
    });
    lines.push(format!("  samples           {SAMPLES} round trips"));
    lines.push(format!(
        "  transfer          {during} chunks of 512 KiB while they ran"
    ));
    lines.push(format!(
        "  path round trip   {:.3} ms p95",
        baseline_p95.as_secs_f64() * 1000.0
    ));
    lines.push(format!(
        "  under transfer    {:.3} ms p95",
        loaded_p95.as_secs_f64() * 1000.0
    ));
    lines.push(format!(
        "  added             {:.3} ms p95 against a {:.3} ms target",
        added.as_secs_f64() * 1000.0,
        ADDED_LIMIT.as_secs_f64() * 1000.0
    ));
    // What the measurement was of, before what it came to. A transfer that never started or that
    // stopped part way leaves some of the loaded phase idle, and a figure taken against an idle
    // connection is not a figure about a transfer whatever it says.
    let invalid = if during == 0 {
        Some("the transfer moved nothing while the round trips ran")
    } else if transfer_ran_throughout {
        None
    } else {
        Some("the transfer stopped part way through the loaded phase")
    };
    if let Some(reason) = invalid {
        lines.push(format!(
            "  verdict           this measurement is not valid: {reason}, so the figure above is \
             not a figure about a transfer and the target is neither met nor missed here"
        ));
    } else if shortfalls.is_empty() {
        lines.push(format!(
            "  verdict           {}",
            if added < ADDED_LIMIT {
                "no measured shortfall, and the target is met on this host"
            } else {
                "no measured shortfall, and the target is not met on this host"
            }
        ));
        lines.push(
            "  conditions        no measured shortfall, so the target is asserted here; what the \
             lines above call unverified stays unverified"
                .to_owned(),
        );
    } else {
        lines.push(format!(
            "  verdict           {} the target, with a condition missing, so it is recorded and \
             not asserted here",
            if added < ADDED_LIMIT {
                "inside"
            } else {
                "outside"
            }
        ));
        for shortfall in &shortfalls {
            lines.push(format!("  condition missing {shortfall}"));
        }
        lines.push(
            "  conditions        not met, so the figure above is recorded and the target is not \
             asserted here; the target's evidence is the reference-host run in the release \
             acceptance record"
                .to_owned(),
        );
    }
    if invalid.is_some() {
        for shortfall in &shortfalls {
            lines.push(format!("  condition missing {shortfall}"));
        }
    }
    // Before the assertions, so a run the target failed on retains the figure and the verdict.
    report("KR-PERF-005 remote input under a bulk transfer", &lines);

    // Whatever the host, the measurement has to have measured something: a transfer that never
    // started, or one that stopped part way, leaves some or all of the loaded phase idle and the
    // figure would be a second idle measurement. The transfer that ended is reported first,
    // because it is the one that says why.
    if !transfer_ran_throughout {
        // It only ends by failing: nothing else leaves that loop. Awaiting it names the write.
        match bulk.await {
            Ok(Err(error)) => {
                panic!("the transfer stopped part way through the loaded phase: {error}")
            }
            Err(join) => panic!("the transfer's task ended during the loaded phase: {join}"),
            Ok(Ok(())) => unreachable!("the transfer's loop has no successful exit"),
        }
    }
    assert!(
        during > 0,
        "the transfer moved nothing while the round trips ran, so they were not measured under one"
    );

    if shortfalls.is_empty() {
        assert!(
            added < ADDED_LIMIT,
            "application scheduling added {added:?} above the measured path round trip"
        );
    }

    bulk.abort();
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

/// The boundary rules of the stolen-share reading, over readings that are supplied rather than
/// read, including one that failed.
///
/// A reading that fails has to become the boundary of the next span. Otherwise the span after it
/// is measured from the boundary before it, and time from one phase is reported as another's,
/// which is how a share confined to the transfer's warm-up could suppress the loaded phase's
/// target. Both spans touching the failed reading answer nothing, and the span after them
/// recovers. No host can be made to fail a `/proc/stat` read on demand, so the rules are driven
/// through [`StolenTime::advance`].
#[test]
fn a_reading_that_failed_leaves_its_spans_unverified_and_the_next_recovers() {
    let mut stolen = StolenTime::start();
    // `start` reads the host, so the boundary is cleared first and the sequence below is the
    // whole of what this checks. Without that, the readings here would be compared with the
    // machine's own counters and the first assertion would be about this host rather than about
    // these rules.
    assert_eq!(stolen.advance(None), None);
    // A first reading establishes a boundary and answers nothing: there is no span yet.
    assert_eq!(stolen.advance(Some(StolenSample::new(0, 1_000))), None);
    // One span, a tenth of it taken.
    assert_eq!(
        stolen.advance(Some(StolenSample::new(100, 2_000))),
        Some(0.1)
    );
    // A reading that failed. The span it ended answers nothing.
    assert_eq!(stolen.advance(None), None);
    // And so does the span after it, because that span has no boundary to start from.
    assert_eq!(stolen.advance(Some(StolenSample::new(900, 5_000))), None);
    // The next span recovers, and it is measured from the reading that succeeded rather than from
    // the one before the failure: 100 of 1,000 rather than 900 of 4,000.
    assert_eq!(
        stolen.advance(Some(StolenSample::new(1_000, 6_000))),
        Some(0.1)
    );
    // A counter that went backwards is a discontinuity, not a negative share.
    assert_eq!(stolen.advance(Some(StolenSample::new(0, 0))), None);
    // And the boundary moved to it, so the span after the discontinuity is measured from there.
    assert_eq!(stolen.advance(Some(StolenSample::new(10, 100))), Some(0.1));
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
    let mut lines = host.lines();
    lines.push(format!("  screen            120x40, {SCREEN_BYTES} bytes"));
    lines.push(format!(
        "  usable state      {:.3} ms against a 2000.000 ms target",
        elapsed.as_secs_f64() * 1000.0
    ));
    lines.push(format!(
        "  verdict           {}",
        if elapsed < USABLE_LIMIT {
            "the target is met on this host"
        } else {
            "the target is not met on this host"
        }
    ));
    // Before the assertion, so a run the target failed on retains the figure and the verdict.
    report("KR-PERF-006 the transport's share of a reconnect", &lines);
    assert!(
        elapsed < USABLE_LIMIT,
        "usable state took {elapsed:?}, against a {USABLE_LIMIT:?} target"
    );

    connection.close(0u32.into(), b"done");
    serving.abort();
}
