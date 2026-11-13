//! The two transport performance requirements, measured over a real connection.
//!
//! * Application scheduling adds less than 25 ms p95 above the measured path round trip while a
//!   bulk transfer is running.
//! * After the transport is available, usable state arrives within two seconds for a 120x40
//!   screen, excluding pairing, discovery outage and operating-system suspension. What this
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
//! average. The first prints two readings besides, because it is the one whose target the
//! conditions decide: the share of each phase the hypervisor took from this guest, and how late a
//! thread of its own was woken while it measured. `tests/support/conditions.rs` says which of
//! those is a condition and which is evidence, and why.
//!
//! The first is asserted where the host meets every condition it can be shown against, and
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
//! What the first asserts is the median of seven rounds, each the 95th percentile of 200 round
//! trips on a connection of its own, because one run's 95th percentile rests on about ten samples
//! and is too unsteady on a shared host to hold a target to. What the median cannot see is a
//! regression that hits at most three rounds of seven, which a ceiling of three times the target
//! on every round bounds. An unoptimised build takes one round, because it asserts nothing.
//!
//! The second is asserted on every run, unoptimised builds included. It has held on every host
//! this has run on by three orders of magnitude, which is why it is asserted unconditionally: that
//! is a choice about where the line sits rather than a claim that no host could miss it. What it
//! measures is the transport's share alone: a screen-sized frame arriving, not a screen rendered
//! from it.
//!
//! One thing both assert whatever the host: the transfer was still running at the end of the phase
//! the first measured, and the snapshot arrived whole. A harness that measured an idle
//! connection, or read an empty frame, would otherwise pass by measuring nothing.

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use support::{OneDevice, Side, allow_streams, direct_addr, epochs, ledger, paired_pair, windows};

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

/// How many rounds the figure is taken over, and the median of them is what the target is held to.
///
/// An unoptimised build asserts nothing, so it takes the one round that records its figure.
const ROUNDS: usize = if cfg!(debug_assertions) { 1 } else { 7 };

/// The most any one round may add: three times the target.
const ROUND_CEILING: Duration = Duration::from_millis(75);

/// What the rounds of one run come to.
struct Judgement {
    rounds: usize,
    median: Duration,
    worst: Duration,
    over_target: usize,
}

fn judge(added: &[Duration]) -> Judgement {
    Judgement {
        rounds: added.len(),
        median: median(added),
        worst: added.iter().copied().max().expect("at least one round"),
        over_target: added.iter().filter(|added| **added >= ADDED_LIMIT).count(),
    }
}

impl Judgement {
    /// Whether the median alone is under the target, whatever the ceiling says.
    fn median_inside_target(&self) -> bool {
        self.median < ADDED_LIMIT
    }

    /// The sentences of the assertions this run fails, one for each that failed.
    fn failures(&self) -> Vec<String> {
        let mut failures = Vec::new();
        if !self.median_inside_target() {
            failures.push(format!(
                "the median of {} added {:?} above the measured path round trip, against a \
                 {ADDED_LIMIT:?} target",
                rounds_phrase(self.rounds),
                self.median
            ));
        }
        if self.worst > ROUND_CEILING {
            failures.push(format!(
                "one round added {:?} above the measured path round trip, over the \
                 {ROUND_CEILING:?} ceiling on any one round",
                self.worst
            ));
        }
        failures
    }
}

/// The largest share of the processor that any phase of any round lost, where one was read.
fn worst_share(shares: impl IntoIterator<Item = Option<f64>>) -> Option<f64> {
    shares.into_iter().flatten().reduce(f64::max)
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

/// A round that was not a measurement of a transfer.
struct Invalid {
    /// What the record says.
    reason: &'static str,
    /// What the run fails with: the write that stopped the transfer, where one did.
    failure: String,
}

/// One round: an idle phase and a phase under a transfer, on a connection of its own.
struct Round {
    baseline_p95: Duration,
    loaded_p95: Duration,
    added: Duration,
    /// The chunks the transfer moved while the loaded phase ran.
    chunks: usize,
    /// How late the harness's own thread was woken while this round measured.
    lateness: Vec<Duration>,
    stolen_idle: Option<f64>,
    stolen_loaded: Option<f64>,
    invalid: Option<Invalid>,
}

/// The middle one of the values, the upper of the two where there is an even number of them.
fn median<T: Ord + Copy>(values: &[T]) -> T {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn milliseconds_of(duration: Duration) -> String {
    format!("{:.3}", duration.as_secs_f64() * 1000.0)
}

fn rounds_phrase(rounds: usize) -> String {
    format!("{rounds} round{}", if rounds == 1 { "" } else { "s" })
}

/// Measures one round: what a keystroke's round trip costs on an idle connection, then what it
/// costs while a bulk transfer fills the same connection.
///
/// `injected` is held onto every echo once the transfer has started, which is how the assertions
/// are shown a regression; it is zero in every run that measures the transport.
async fn measure_round(injected: Duration) -> Round {
    let (host, client) = paired_pair().await;
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory = one_device(&client);
    // Set by the bulk stream's first frame, so that an injected delay reaches the loaded phase
    // alone and the idle phase it is subtracted from stays clean.
    let transfer_started = Arc::new(AtomicBool::new(false));
    let serving_started = Arc::clone(&transfer_started);

    // The host echoes every input frame back on the same stream, and drains anything that arrives
    // on a bulk stream. Echoing is what makes a round trip measurable at all.
    let serving = tokio::spawn(async move {
        let connection = endpoint
            .accept()
            .await
            .expect("an incoming connection")
            .await
            .expect("a connection");
        allow_streams(&connection);
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
            let Ok(mut stream) = support::accept_any(&streams, &connection).await else {
                return;
            };
            let transfer_started = Arc::clone(&serving_started);
            tokio::spawn(async move {
                let kind = stream.kind();
                loop {
                    let echoed = match stream.read_payload().await {
                        Ok(Some(frame)) => frame,
                        _ => return,
                    };
                    if kind != StreamKind::TerminalInput {
                        transfer_started.store(true, Ordering::Relaxed);
                        continue;
                    }
                    if !injected.is_zero() && transfer_started.load(Ordering::Relaxed) {
                        tokio::time::sleep(injected).await;
                    }
                    if stream.write_payload(&echoed).await.is_err() {
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
    let lateness = probe.stop();
    let loaded_p95 = percentile(&mut loaded, 0.95);

    // What the measurement was of, before what it came to. A transfer that never started or that
    // stopped part way leaves some of the loaded phase idle, and a figure taken against an idle
    // connection is not a figure about a transfer whatever it says.
    let reason = if during == 0 {
        "the transfer moved nothing while the round trips ran"
    } else {
        "the transfer stopped part way through the loaded phase"
    };
    let invalid = if !transfer_ran_throughout {
        // It only ends by failing: nothing else leaves that loop. Awaiting it names the write.
        let failure = match bulk.await {
            Ok(Err(error)) => {
                format!("the transfer stopped part way through the loaded phase: {error}")
            }
            Err(join) => format!("the transfer's task ended during the loaded phase: {join}"),
            Ok(Ok(())) => unreachable!("the transfer's loop has no successful exit"),
        };
        Some(Invalid { reason, failure })
    } else if during == 0 {
        bulk.abort();
        Some(Invalid {
            reason,
            failure: "the transfer moved nothing while the round trips ran, so they were not \
                      measured under one"
                .to_owned(),
        })
    } else {
        bulk.abort();
        None
    };
    connection.close(0u32.into(), b"done");
    serving.abort();

    Round {
        baseline_p95,
        loaded_p95,
        added: loaded_p95.saturating_sub(baseline_p95),
        chunks: during,
        lateness,
        stolen_idle,
        stolen_loaded,
        invalid,
    }
}

/// What a run measured and what it concludes from it, before anything is asserted.
struct Measurement {
    /// The lines of the record.
    lines: Vec<String>,
    /// The assertions the figures fail, one sentence for each.
    failures: Vec<String>,
    /// The conditions the host can be shown not to meet, which leave the target unasserted.
    shortfalls: Vec<String>,
    /// What the run fails with where a round was not a measurement of a transfer.
    invalid: Option<String>,
}

impl Measurement {
    /// Fails the run as its measurement says it must.
    fn assert_target(&self) {
        // Whatever the host, the measurement has to have measured something: a transfer that never
        // started, or one that stopped part way, leaves some or all of the loaded phase idle and
        // the figure would be a second idle measurement. The transfer that ended is reported
        // first, because it is the one that says why.
        if let Some(invalid) = &self.invalid {
            panic!("{invalid}");
        }
        // Two assertions, each with a sentence of its own, so that a red run says which one failed.
        if self.shortfalls.is_empty() {
            assert!(self.failures.is_empty(), "{}", self.failures.join("; "));
        }
    }
}

/// Takes the rounds and works out what they come to. `injected` is zero wherever the transport is
/// what is being measured.
async fn measure(rounds_wanted: usize, injected: Duration) -> Measurement {
    let mut rounds: Vec<Round> = Vec::with_capacity(rounds_wanted);
    for _ in 0..rounds_wanted {
        let round = measure_round(injected).await;
        let measured_nothing = round.invalid.is_some();
        rounds.push(round);
        // A round that was not a measurement of a transfer is the run's answer, and more rounds
        // would only repeat it.
        if measured_nothing {
            break;
        }
    }

    let mut lateness: Vec<Duration> = rounds
        .iter()
        .flat_map(|round| round.lateness.iter().copied())
        .collect();
    // Before the percentile, which has no answer for an empty set.
    assert!(
        !lateness.is_empty(),
        "the harness recorded no scheduling evidence beside its figure"
    );
    let scheduling_p95 = percentile(&mut lateness, 0.95);
    // The worst of the phases of every round: a figure is inside the cutoff only if all of them
    // were.
    let stolen_idle = worst_share(rounds.iter().map(|round| round.stolen_idle));
    let stolen_loaded = worst_share(rounds.iter().map(|round| round.stolen_loaded));
    let stolen_share = worst_share([stolen_idle, stolen_loaded]);
    // A phase the platform gave no reading for does not count against the host, and the record
    // says how many of them the worst figure above leaves out.
    let unverified = rounds
        .iter()
        .flat_map(|round| [round.stolen_idle, round.stolen_loaded])
        .filter(Option::is_none)
        .count();

    let added: Vec<Duration> = rounds.iter().map(|round| round.added).collect();
    let judgement = judge(&added);
    let failures = judgement.failures();
    let rounds_taken = rounds_phrase(rounds.len());
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
            "  taken by the host {} of the idle phase and {} of the loaded one, at the worst of \
             the rounds, against a {:.2}% cutoff; {unverified} of {} phases unverified",
            phase_share(stolen_idle),
            phase_share(stolen_loaded),
            MAX_STOLEN_SHARE * 100.0,
            rounds.len() * 2
        )
    });
    if !injected.is_zero() {
        lines.push(format!(
            "  injected          every echo was held {} ms once the transfer started, so these \
             figures are not a measurement of the transport",
            injected.as_millis()
        ));
    }
    lines.push(format!(
        "  samples           {SAMPLES} round trips in each of {rounds_taken}"
    ));
    for (index, round) in rounds.iter().enumerate() {
        lines.push(format!(
            "  {:<18}added {} ms p95 (path round trip {} ms, under transfer {} ms, {} chunks)",
            format!("round {}", index + 1),
            milliseconds_of(round.added),
            milliseconds_of(round.baseline_p95),
            milliseconds_of(round.loaded_p95),
            round.chunks
        ));
    }
    lines.push(format!(
        "  transfer          {} chunks of 512 KiB while they ran, the median of {rounds_taken}",
        median(&rounds.iter().map(|round| round.chunks).collect::<Vec<_>>())
    ));
    lines.push(format!(
        "  path round trip   {} ms p95, the median of {rounds_taken}",
        milliseconds_of(median(
            &rounds
                .iter()
                .map(|round| round.baseline_p95)
                .collect::<Vec<_>>()
        ))
    ));
    lines.push(format!(
        "  under transfer    {} ms p95, the median of {rounds_taken}",
        milliseconds_of(median(
            &rounds
                .iter()
                .map(|round| round.loaded_p95)
                .collect::<Vec<_>>()
        ))
    ));
    lines.push(format!(
        "  added             {} ms p95, the median of {rounds_taken}, against a {} ms target",
        milliseconds_of(judgement.median),
        milliseconds_of(ADDED_LIMIT)
    ));
    lines.push(format!(
        "  worst round       {} ms p95 added, against a {} ms ceiling on any one round",
        milliseconds_of(judgement.worst),
        milliseconds_of(ROUND_CEILING)
    ));
    lines.push(format!(
        "  rounds over       {} of {rounds_taken} added {} ms or more",
        judgement.over_target,
        milliseconds_of(ADDED_LIMIT)
    ));
    let invalid = rounds.iter().find_map(|round| round.invalid.as_ref());
    if let Some(invalid) = invalid {
        lines.push(format!(
            "  verdict           this measurement is not valid: {}, so the figures above are \
             not figures about a transfer and the target is neither met nor missed here",
            invalid.reason
        ));
    } else if shortfalls.is_empty() {
        lines.push(if failures.is_empty() {
            format!(
                "  verdict           no measured shortfall, and the target is met on this host: \
                 the median of {rounds_taken} is inside it, {} of them were over it, and no round \
                 went over the ceiling",
                judgement.over_target
            )
        } else {
            format!(
                "  verdict           no measured shortfall, and the target is not met on this \
                 host, judged by the median of {rounds_taken} and the ceiling on each: {}",
                failures.join("; ")
            )
        });
        lines.push(
            "  conditions        no measured shortfall, so the target is asserted here, by the \
             median of the rounds and by the ceiling on each; what the lines above call \
             unverified stays unverified"
                .to_owned(),
        );
    } else {
        lines.push(format!(
            "  verdict           {} the target by the median of {rounds_taken}{}, with a condition \
             missing, so it is recorded and not asserted here",
            if judgement.median_inside_target() {
                "inside"
            } else {
                "outside"
            },
            if judgement.worst > ROUND_CEILING {
                ", and a round went over the ceiling"
            } else {
                ""
            }
        ));
        for shortfall in &shortfalls {
            lines.push(format!("  condition missing {shortfall}"));
        }
        lines.push(
            "  conditions        not met, so the figures above are recorded and the target is not \
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
    Measurement {
        lines,
        failures,
        shortfalls,
        invalid: invalid.map(|invalid| invalid.failure.clone()),
    }
}

/// One run of the case: the rounds, the record, and the assertions the record's verdict rests on.
///
/// Returns the conditions the host fell short of, which are why nothing was asserted when there
/// are any. `record` keeps the figures in the run's evidence; a run that is not the case's own
/// only prints them.
async fn run_case(rounds_wanted: usize, injected: Duration, record: bool) -> Vec<String> {
    let measurement = measure(rounds_wanted, injected).await;
    // Before the assertions, so a run the target failed on retains the figures and the verdict.
    if record {
        report(
            "KR-PERF-005 remote input under a bulk transfer",
            &measurement.lines,
        );
    } else {
        for line in &measurement.lines {
            println!("{line}");
        }
    }
    measurement.assert_target();
    measurement.shortfalls
}

/// KR-PERF-005.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_input_stays_responsive_under_a_bulk_transfer() {
    run_case(ROUNDS, Duration::ZERO, true).await;
}

/// KR-PERF-005: the case can fail. A regression of the target's size, held onto every echo once the
/// transfer runs, fails the case on a host that asserts the target.
///
/// A harness whose assertions could not fail would pass by measuring nothing. This is a run of its
/// own, so its figures stay out of the evidence the case keeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_regression_of_the_targets_size_fails_the_case() {
    // Nothing is asserted on a host that already falls short, so there is nothing to show there.
    if !Host::read().shortfalls(None).is_empty() {
        return;
    }
    match tokio::spawn(run_case(1, ADDED_LIMIT, false)).await {
        Ok(shortfalls) => assert!(
            !shortfalls.is_empty(),
            "a regression of the target's size passed the case on a host that asserts the target"
        ),
        Err(failure) => {
            let message = failure
                .into_panic()
                .downcast::<String>()
                .map_or_else(|_| String::new(), |message| *message);
            assert!(
                message.starts_with("the median of 1 round added"),
                "the case failed, but not on the median: {message:?}"
            );
        }
    }
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

fn milliseconds(figures: &[u64]) -> Vec<Duration> {
    figures.iter().copied().map(Duration::from_millis).collect()
}

/// KR-PERF-005: the target is held by the median of the rounds, so a round or two that a shared
/// host stalled does not fail it and a regression that moves most rounds does.
///
/// The rounds are supplied rather than measured, so the rule is driven through every count of
/// rounds over the target that it has an edge at.
#[test]
fn the_median_of_the_rounds_decides_the_target() {
    // A shared host's stalled round, the shape of a run that failed by noise.
    let stalled = judge(&milliseconds(&[16, 17, 15, 30, 18, 16, 17]));
    assert!(stalled.failures().is_empty(), "{:?}", stalled.failures());
    assert_eq!(stalled.over_target, 1);
    // Three of seven rounds over the target leave the median inside it. That is what a median
    // cannot see; the ceiling below is what bounds it.
    let three = judge(&milliseconds(&[16, 40, 17, 40, 18, 40, 17]));
    assert!(three.failures().is_empty(), "{:?}", three.failures());
    assert_eq!(three.over_target, 3);
    // Four of seven put the median over it.
    let four = judge(&milliseconds(&[16, 40, 17, 40, 40, 40, 17]));
    assert_eq!(four.failures().len(), 1);
    assert!(
        four.failures()[0].contains("median"),
        "{:?}",
        four.failures()
    );
    assert_eq!(four.median, Duration::from_millis(40));
    // A median exactly at the target is not under it.
    let at = judge(&milliseconds(&[25, 25, 25]));
    assert_eq!(at.failures().len(), 1);
}

/// KR-PERF-005: no one round may add more than three times the target, however the rest went.
#[test]
fn one_round_far_over_the_target_fails_beside_a_median_inside_it() {
    let at_the_ceiling = judge(&milliseconds(&[16, 17, 15, 75, 18, 16, 17]));
    assert!(
        at_the_ceiling.failures().is_empty(),
        "{:?}",
        at_the_ceiling.failures()
    );
    let past_it = judge(&milliseconds(&[16, 17, 15, 76, 18, 16, 17]));
    let failures = past_it.failures();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(failures[0].contains("ceiling"), "{failures:?}");
    assert_eq!(past_it.worst, Duration::from_millis(76));
    // The record's word for the median comes from the median alone, so it does not call the median
    // outside the target because a round went over the ceiling.
    assert!(past_it.median_inside_target());
    assert!(!judge(&milliseconds(&[90, 90, 90, 90, 17, 15, 16])).median_inside_target());
    // Both can fail at once, and the run then says both.
    let both = judge(&milliseconds(&[90, 90, 90, 16, 17, 15, 80]));
    assert_eq!(both.failures().len(), 2, "{:?}", both.failures());
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
                allow_streams(&connection);
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
                let Ok(mut stream) = support::accept_any(&streams, &connection).await else {
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
