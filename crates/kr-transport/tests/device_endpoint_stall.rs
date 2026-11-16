//! A relay that stops taking data, and a host on another relay beside it.
//!
//! The device's one endpoint has one relay actor for all of its relay clients, and that actor takes
//! a datagram for one relay only while no send of its own is pending. This case tries to make that
//! happen: several hosts, each with the product's budget of connections, sit on one relay that
//! stops reading and writing, and a host on a healthy relay is asked a small question every 100
//! milliseconds before, during and after. It prints what it measured and asserts conditions alone:
//! the healthy host's connection stays open and every question is answered. It asserts no time.
//!
//! It is outside the default suite: it runs for minutes and is a figure to be read, so it is
//! asked for by name with `--ignored --nocapture`.

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, VarInt};
use iroh::{Endpoint, RelayUrl};
use kr_crypto::keys::DeviceKeys;
use kr_transport::ALPN;
use kr_transport::config::EndpointConfig;
use kr_transport::dialler::{DeviceEndpoint, HostServices};
use support::front::RelayFront;
use support::{LocalRelay, Side};
use tokio::task::JoinHandle;

/// How long an answer may take before the case counts the question as unanswered.
const PATIENCE: Duration = Duration::from_secs(60);

/// The healthy host is asked one question this often. This is the case's first timed window.
const INTERVAL: Duration = Duration::from_millis(100);

/// The limit that a question's round trip is held to, in milliseconds.
const LIMIT_MS: u64 = 2000;

/// How often the case looks at a count that no future announces.
const LOOK: Duration = Duration::from_millis(50);

/// Connections to each host on the stopped relay: the product's budget for one host.
const CONNECTIONS_PER_HOST: usize = 32;

/// How much each sender writes on one stream.
const BULK: usize = 256 * 1024;

/// The questions of each phase: before the stop, during it and after the front resumes.
const BEFORE: usize = 200;
const DURING: usize = 400;
const AFTER: usize = 200;

// The library's own log lines of its relay transport, kept with their time. ----------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Line {
    /// "Lost connection to relay server: ..."
    Lost,
    /// A dial that ran out, or a flush that dropped the datagrams the queue held.
    Dialling,
    /// A relay client of the endpoint connected, to this URL.
    Connected(String),
}

#[derive(Default)]
struct Seen(Mutex<Vec<(Instant, Line)>>);

#[derive(Default)]
struct Words {
    message: String,
    url: String,
}

impl tracing::field::Visit for Words {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "url" => self.url = format!("{value:?}").trim_matches('"').to_owned(),
            _ => {}
        }
    }
}

struct Capture(Arc<Seen>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        (metadata
            .target()
            .starts_with("iroh::socket::transports::relay")
            && *metadata.level() <= tracing::Level::DEBUG)
            || metadata.target() == "iroh::_events::relay::connected"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut words = Words::default();
        event.record(&mut words);
        let line = if event.metadata().target() == "iroh::_events::relay::connected" {
            Line::Connected(words.url)
        } else if words.message.contains("Lost connection to relay server") {
            Line::Lost
        } else if words.message.contains("trying to establish a connection")
            || words.message.contains("Dropping datagrams to send")
        {
            Line::Dialling
        } else {
            return;
        };
        let mut lines = self.0.0.lock().unwrap_or_else(PoisonError::into_inner);
        if lines.len() < 100_000 {
            lines.push((Instant::now(), line));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Installs the capture once for the whole test program.
fn capture() -> &'static Arc<Seen> {
    static SEEN: OnceLock<Arc<Seen>> = OnceLock::new();
    SEEN.get_or_init(|| {
        let seen = Arc::new(Seen::default());
        let _ = tracing::subscriber::set_global_default(Capture(Arc::clone(&seen)));
        seen
    })
}

/// What the stopped relay's actor was doing at `at`, by what the library logged since the switch.
fn actor_state(seen: &Seen, front: &RelayUrl, switched: Instant, at: Instant) -> &'static str {
    let mut dialling = false;
    for (when, line) in seen.0.lock().unwrap_or_else(PoisonError::into_inner).iter() {
        if *when > at {
            break;
        }
        match line {
            Line::Lost if *when >= switched => dialling = true,
            Line::Connected(url)
                if dialling && url.parse::<RelayUrl>().ok().as_ref() == Some(front) =>
            {
                dialling = false;
            }
            _ => {}
        }
    }
    if dialling {
        "DIALLING AGAIN"
    } else {
        "CONNECTED"
    }
}

// The hosts and the questions. -------------------------------------------------------------------

/// A host on a relay that takes every stream, reads it to its end and answers a label.
struct Responder {
    side: Side,
    serving: JoinHandle<()>,
}

impl Responder {
    async fn on(relay: &LocalRelay, byte: u8) -> Self {
        let config = EndpointConfig {
            relay_urls: vec![relay.url.clone()],
            relay_ca_roots: relay.ca_roots.clone(),
            relay_only: true,
            ..EndpointConfig::default()
        };
        let side = support::side(&config, byte, true).await;
        tokio::time::timeout(PATIENCE, side.endpoint.online())
            .await
            .expect("the host reaches its relay");
        let serving = serve(side.endpoint.clone());
        Self { side, serving }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

fn serve(endpoint: Endpoint) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                connection.set_max_concurrent_bi_streams(VarInt::from_u32(1024));
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let mut chunk = vec![0_u8; 64 * 1024];
                        while let Ok(Some(_)) = recv.read(&mut chunk).await {}
                        let _ = send.write_all(b"ok").await;
                        let _ = send.finish();
                    });
                }
            });
        }
    })
}

async fn ask(connection: &Connection) -> Result<(), String> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(b"?").await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    recv.read_to_end(64)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn connect(device: &DeviceEndpoint, view: &EndpointConfig, host: &Responder) -> Connection {
    let address = view
        .peer_addr(host.side.keys.transport.public())
        .expect("a host's address");
    tokio::time::timeout(
        PATIENCE,
        kr_transport::endpoint::connect(device.endpoint(), address, ALPN),
    )
    .await
    .expect("the attempt ends by itself")
    .expect("a connection to the host")
}

/// One connection's sender: bulk streams of [`BULK`] bytes, one after another, until it is ended.
async fn send_loop(connection: Connection, sent: Arc<AtomicUsize>) {
    let bulk = vec![0_u8; BULK];
    let mut first = true;
    loop {
        let Ok((mut send, mut recv)) = connection.open_bi().await else {
            return;
        };
        if send.write_all(&bulk).await.is_err() || send.finish().is_err() {
            return;
        }
        if recv.read_to_end(64).await.is_err() {
            return;
        }
        if first {
            sent.fetch_add(1, Ordering::SeqCst);
            first = false;
        }
    }
}

/// One question to the healthy host: when it started, and how long the answer took, or why none came.
type Outcome = Option<(Instant, Result<Duration, String>)>;

fn spawn_question(connection: Connection, slots: &Arc<Mutex<Vec<Outcome>>>) -> JoinHandle<()> {
    let index = {
        let mut slots = slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.push(None);
        slots.len() - 1
    };
    let slots = Arc::clone(slots);
    tokio::spawn(async move {
        let started = Instant::now();
        let outcome = match tokio::time::timeout(PATIENCE, ask(&connection)).await {
            Ok(Ok(())) => Ok(started.elapsed()),
            Ok(Err(reason)) => Err(reason),
            Err(_) => Err(format!("no answer in {PATIENCE:?}")),
        };
        slots.lock().unwrap_or_else(PoisonError::into_inner)[index] = Some((started, outcome));
    })
}

fn started(slots: &Mutex<Vec<Outcome>>) -> usize {
    slots.lock().unwrap_or_else(PoisonError::into_inner).len()
}

async fn until(what: &str, mut reached: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(600), async {
        while !reached() {
            tokio::time::sleep(LOOK).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} never came"));
}

fn figure(phase: &str, rows: &[(usize, Duration)], total: usize) -> String {
    let mut times: Vec<u128> = rows.iter().map(|(_, rtt)| rtt.as_millis()).collect();
    times.sort_unstable();
    let at =
        |share: usize| times.get((times.len() * share / 100).min(times.len().saturating_sub(1)));
    format!(
        "FIGURE {phase}: questions {total}, answered {}, median {} ms, p99 {} ms, max {} ms",
        times.len(),
        at(50).copied().unwrap_or(0),
        at(99).copied().unwrap_or(0),
        times.last().copied().unwrap_or(0),
    )
}

/// One arrangement: `hosts` hosts with [`CONNECTIONS_PER_HOST`] connections each on the relay that
/// stops. Returns the lines it printed, and the three outcomes.
async fn arrangement(hosts: usize) -> (Vec<String>, bool, usize, Option<String>) {
    let seen = capture();
    let connections = hosts * CONNECTIONS_PER_HOST;
    let (healthy, stopping) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
    let front = RelayFront::stalling(&stopping);
    let a = Responder::on(&healthy, 1).await;
    let mut stalled = Vec::new();
    for index in 0..hosts {
        stalled.push(Responder::on(&stopping, 10 + u8::try_from(index).expect("few hosts")).await);
    }

    let keys = DeviceKeys::generate().expect("device keys");
    let device = DeviceEndpoint::bind(
        &EndpointConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
            relay_ca_roots: [&healthy, &stopping]
                .iter()
                .flat_map(|relay| relay.ca_roots.iter().cloned())
                .collect(),
            ..EndpointConfig::default()
        },
        &keys.transport,
    )
    .await
    .expect("the device's endpoint");
    let view = |relay: &RelayUrl| EndpointConfig {
        relay_urls: vec![relay.clone()],
        ..EndpointConfig::default()
    };
    let view_a = view(&healthy.url);
    let view_b = view(&front.url);
    device
        .introduce(HostServices::paired(&view_a, a.side.keys.transport.public()).expect("host A"))
        .await
        .expect("host A");
    for host in &stalled {
        device
            .introduce(
                HostServices::paired(&view_b, host.side.keys.transport.public()).expect("a host"),
            )
            .await
            .expect("a host");
    }

    let to_a = connect(&device, &view_a, &a).await;
    let sent = Arc::new(AtomicUsize::new(0));
    let mut senders = Vec::new();
    for host in &stalled {
        let dials = (0..CONNECTIONS_PER_HOST).map(|_| connect(&device, &view_b, host));
        for connection in futures::future::join_all(dials).await {
            senders.push(tokio::spawn(send_loop(connection, Arc::clone(&sent))));
        }
    }
    until("every sender's first stream", || {
        sent.load(Ordering::SeqCst) == connections
    })
    .await;

    // The questions, one every INTERVAL, each on a task of its own.
    let slots: Arc<Mutex<Vec<Outcome>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let asking = {
        let (slots, stop, to_a) = (Arc::clone(&slots), Arc::clone(&stop), to_a.clone());
        tokio::spawn(async move {
            let mut tasks = Vec::new();
            let mut tick = tokio::time::interval(INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while !stop.load(Ordering::SeqCst) {
                tick.tick().await;
                tasks.push(spawn_question(to_a.clone(), &slots));
            }
            for task in tasks {
                let _ = task.await;
            }
        })
    };

    let metrics = &device.endpoint().metrics().socket;
    let first = started(&slots);
    until("the questions before the stop", || {
        started(&slots) >= first + BEFORE
    })
    .await;
    let (relay_before, front_before) = (metrics.send_relay.get(), front.read_from_device());
    front.stall();
    let switched = Instant::now();
    let switch_index = started(&slots);
    until("the questions during the stop", || {
        started(&slots) >= switch_index + DURING
    })
    .await;
    let (relay_after, front_after) = (metrics.send_relay.get(), front.read_from_device());
    front.resume();
    let resume_index = started(&slots);
    until("the questions after the resume", || {
        started(&slots) >= resume_index + AFTER
    })
    .await;
    stop.store(true, Ordering::SeqCst);
    let _ = asking.await;
    for sender in &senders {
        sender.abort();
    }

    let outcomes: Vec<(Instant, Result<Duration, String>)> = slots
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|slot| slot.clone().expect("every question ended"))
        .collect();
    let phase = |from: usize, count: usize| -> Vec<(usize, Result<Duration, String>)> {
        (from..(from + count).min(outcomes.len()))
            .map(|index| (index, outcomes[index].1.clone()))
            .collect()
    };
    let phases = [
        ("BEFORE", phase(first, BEFORE)),
        ("DURING", phase(switch_index, DURING)),
        ("AFTER", phase(resume_index, AFTER)),
    ];
    let mut lines = vec![format!("ARRANGEMENT K={hosts} N={connections}")];
    let mut worst: Option<(usize, Duration, &'static str)> = None;
    let mut unanswered = 0;
    for (name, rows) in &phases {
        let answered: Vec<(usize, Duration)> = rows
            .iter()
            .filter_map(|(index, outcome)| outcome.as_ref().ok().map(|rtt| (*index, *rtt)))
            .collect();
        unanswered += rows.len() - answered.len();
        lines.push(figure(name, &answered, rows.len()));
        for (index, outcome) in rows {
            let started_at = outcomes[*index].0;
            let state = actor_state(seen, &front.url, switched, started_at);
            match outcome {
                Ok(rtt) if rtt.as_millis() > u128::from(LIMIT_MS) => {
                    lines.push(format!(
                        "OVER {LIMIT_MS} ms: request {index} in {name} took {} ms, relay actor {state}",
                        rtt.as_millis()
                    ));
                    if worst.is_none_or(|(_, longest, _)| *rtt > longest) {
                        worst = Some((*index, *rtt, state));
                    }
                }
                Ok(_) => {}
                Err(reason) => lines.push(format!(
                    "UNANSWERED: request {index} in {name}, relay actor {state}: {reason}"
                )),
            }
        }
    }
    let closed = to_a.close_reason().map(|reason| reason.to_string());
    lines.push(format!(
        "COUNTERS relay_conns_closed {}, send_relay {} B (stop {} B), front accepted {}, read from device {} B (stop {} B)",
        metrics.relay_conns_closed.get(),
        metrics.send_relay.get(),
        relay_after - relay_before,
        front.accepted(),
        front.read_from_device(),
        front_after - front_before,
    ));
    match worst {
        None => {
            lines.push(format!("LIMIT {LIMIT_MS} ms: HELD"));
            lines.push(format!(
                "QUEUE: the queue stayed unfull: no question passed the limit; the device made {} B for the relay after the stop and the front read {} B",
                relay_after - relay_before,
                front_after - front_before
            ));
        }
        Some((index, rtt, state)) => lines.push(format!(
            "LIMIT {LIMIT_MS} ms: PASSED BY {} ms AT REQUEST {index} WHILE {state} (K={hosts}, N={connections})",
            rtt.as_millis() - u128::from(LIMIT_MS)
        )),
    }
    lines.push(format!("UNANSWERED: {unanswered}"));
    lines.push(format!("A CLOSED: {}", closed.as_deref().unwrap_or("none")));
    device.close().await;
    (lines, closed.is_none(), unanswered, closed)
}

/// The case that tries to fill the queue of a relay that has stopped: K = 3 hosts and then K = 6,
/// each with 32 connections on the relay, which stops reading and writing, also stalls the
/// connections that are made after the stop, and resumes. A host on a healthy relay is asked a
/// small question every 100 ms throughout. The figures and the outcome lines are printed first;
/// then the conditions are asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a figure to be read, run by name: --ignored --nocapture"]
async fn a_relay_that_stops_taking_data_does_not_hold_a_host_on_another_relay() {
    let host = support::conditions::Host::read();
    let mut conditions = host.lines();
    let mut every_line = Vec::new();
    let mut failures = Vec::new();
    for hosts in [3, 6] {
        let (lines, open, unanswered, closed) = arrangement(hosts).await;
        every_line.extend(lines);
        if !open {
            failures.push(format!(
                "K={hosts}: the healthy host's connection closed: {closed:?}"
            ));
        }
        if unanswered != 0 {
            failures.push(format!(
                "K={hosts}: {unanswered} questions were not answered"
            ));
        }
    }
    conditions.extend(every_line);
    support::conditions::report("the healthy host beside a relay that stops", &conditions);
    assert!(failures.is_empty(), "{failures:?}");
}
