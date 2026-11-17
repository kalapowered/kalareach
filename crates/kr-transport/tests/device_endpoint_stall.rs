//! A relay that stops taking data, and a host on another relay beside it.
//!
//! The device's one endpoint has one relay actor for all of its relay clients, and that actor takes
//! a datagram for one relay only while no send of its own is pending. This case tries to make that
//! happen: several hosts, each with 32 connections that each carry a sender, sit on one relay that
//! stops reading, and a host on a healthy relay is asked a small question every 100 milliseconds
//! before, during and after. That is a stress load, above what the product shows a host using. It
//! prints what it measured and asserts conditions alone: the healthy host's connection stays open
//! and every question is answered. It asserts no time.
//!
//! It is outside the default suite: it runs for minutes and is a figure to be read, so it is
//! asked for by name with `--ignored --nocapture`.

mod support;

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

/// Connections to each host on the stopped relay, each with a sender: a stress load, above what the
/// product shows one host using.
const CONNECTIONS_PER_HOST: usize = 32;

/// How much each sender writes on one stream.
const BULK: usize = 256 * 1024;

/// The questions of each phase: before the stop, during it and after the front resumes.
const BEFORE: usize = 200;
const DURING: usize = 400;
const AFTER: usize = 200;

// The library's own log lines of its relay transport, kept with their time and with the endpoint
// and the relay client whose spans each came in. --------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    /// "Lost connection to relay server: ..."
    Lost,
    /// A dial that ran out, or a flush that dropped the datagrams the queue held.
    Dialling,
    /// A relay client of the endpoint connected.
    Connected,
}

/// One kept line: when it came, the span of the endpoint and the URL of the relay client that it
/// came from, and what it said. A line that came outside the spans of an endpoint has span 0, and a
/// line outside those of a relay client has an empty relay: neither matches a filter.
#[derive(Clone, Debug)]
struct Logged {
    when: Instant,
    endpoint: u64,
    relay: String,
    line: Line,
}

#[derive(Default)]
struct Seen {
    lines: Mutex<Vec<Logged>>,
    /// Set just before the device's endpoint is bound: the next `endpoint` span is the device's.
    expecting: AtomicBool,
    device: AtomicU64,
}

impl Seen {
    /// Marks the next endpoint that is bound as the device's, so that its lines can be told from
    /// the lines of the hosts' endpoints, which log in the same program.
    fn expect_the_device(&self) {
        self.device.store(0, Ordering::SeqCst);
        self.expecting.store(true, Ordering::SeqCst);
    }

    /// The span of the device's endpoint, once it was bound.
    fn the_device(&self) -> u64 {
        let span = self.device.load(Ordering::SeqCst);
        assert_ne!(span, 0, "the capture saw the span of the device's endpoint");
        span
    }

    /// The kept lines of the endpoint with this span about the relay `relay`, in the order they
    /// came.
    fn of(&self, endpoint: u64, relay: &RelayUrl) -> Vec<Logged> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|logged| {
                logged.endpoint == endpoint
                    && logged.relay.parse::<RelayUrl>().ok().as_ref() == Some(relay)
            })
            .cloned()
            .collect()
    }
}

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

/// A span of the library on the way from an endpoint to a relay client: `endpoint`, `relay-actor`
/// and `active-relay`, which has the relay client's URL in `url`.
struct Scope {
    name: &'static str,
    url: String,
    parent: Option<u64>,
}

thread_local! {
    /// The spans entered on this thread, the innermost last.
    static ENTERED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

struct Capture {
    seen: Arc<Seen>,
    scopes: Mutex<HashMap<u64, Scope>>,
    next: AtomicU64,
}

impl Capture {
    fn scopes(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Scope>> {
        self.scopes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if metadata.is_span() {
            return matches!(metadata.name(), "endpoint" | "relay-actor" | "active-relay");
        }
        (metadata
            .target()
            .starts_with("iroh::socket::transports::relay")
            && *metadata.level() <= tracing::Level::DEBUG)
            || metadata.target() == "iroh::_events::relay::connected"
    }
    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut words = Words::default();
        attributes.record(&mut words);
        let parent = attributes
            .parent()
            .map(tracing::span::Id::into_u64)
            .or_else(|| {
                attributes
                    .is_contextual()
                    .then(|| ENTERED.with(|entered| entered.borrow().last().copied()))
                    .flatten()
            });
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let name = attributes.metadata().name();
        if name == "endpoint" && self.seen.expecting.swap(false, Ordering::SeqCst) {
            self.seen.device.store(id, Ordering::SeqCst);
        }
        self.scopes().insert(
            id,
            Scope {
                name,
                url: words.url,
                parent,
            },
        );
        tracing::span::Id::from_u64(id)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut words = Words::default();
        event.record(&mut words);
        let line = if event.metadata().target() == "iroh::_events::relay::connected" {
            Line::Connected
        } else if words.message.contains("Lost connection to relay server") {
            Line::Lost
        } else if words.message.contains("trying to establish a connection")
            || words.message.contains("Dropping datagrams to send")
        {
            Line::Dialling
        } else {
            return;
        };
        let (mut endpoint, mut relay) = (0, words.url);
        let mut at = event.parent().map(tracing::span::Id::into_u64).or_else(|| {
            event
                .is_contextual()
                .then(|| ENTERED.with(|entered| entered.borrow().last().copied()))
                .flatten()
        });
        {
            let scopes = self.scopes();
            while let Some((id, scope)) = at.and_then(|id| scopes.get(&id).map(|scope| (id, scope)))
            {
                match scope.name {
                    "endpoint" if endpoint == 0 => endpoint = id,
                    "active-relay" if relay.is_empty() => relay.clone_from(&scope.url),
                    _ => {}
                }
                at = scope.parent;
            }
        }
        let mut lines = self
            .seen
            .lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if lines.len() < 100_000 {
            lines.push(Logged {
                when: Instant::now(),
                endpoint,
                relay,
                line,
            });
        }
    }
    fn enter(&self, span: &tracing::span::Id) {
        ENTERED.with(|entered| entered.borrow_mut().push(span.into_u64()));
    }
    fn exit(&self, span: &tracing::span::Id) {
        ENTERED.with(|entered| {
            let mut entered = entered.borrow_mut();
            if let Some(index) = entered.iter().rposition(|id| *id == span.into_u64()) {
                entered.remove(index);
            }
        });
    }
}

/// Installs the capture once for the whole test program.
fn capture() -> &'static Arc<Seen> {
    static SEEN: OnceLock<Arc<Seen>> = OnceLock::new();
    SEEN.get_or_init(|| {
        let seen = Arc::new(Seen::default());
        let _ = tracing::subscriber::set_global_default(Capture {
            seen: Arc::clone(&seen),
            scopes: Mutex::default(),
            next: AtomicU64::new(1),
        });
        seen
    })
}

/// What the stopped relay's actor was doing at `at`, by what the library logged since the switch
/// for the device's endpoint and the front's URL alone.
fn actor_state(
    seen: &Seen,
    endpoint: u64,
    front: &RelayUrl,
    switched: Instant,
    at: Instant,
) -> &'static str {
    let mut dialling = false;
    for logged in seen.of(endpoint, front) {
        if logged.when > at {
            break;
        }
        match logged.line {
            Line::Lost if logged.when >= switched => dialling = true,
            Line::Connected if dialling => dialling = false,
            _ => {}
        }
    }
    if dialling {
        "DIALLING AGAIN"
    } else {
        "CONNECTED"
    }
}

/// The count of each kind of kept line of the device's endpoint about the relay `relay`, for the
/// printout, with the endpoint's short identity and its span.
fn events_line(seen: &Seen, endpoint: u64, identity: &str, relay: &RelayUrl) -> String {
    let kept = seen.of(endpoint, relay);
    let count = |wanted: Line| kept.iter().filter(|logged| logged.line == wanted).count();
    format!(
        "EVENTS endpoint {identity} (span {endpoint}) relay {relay}: lost {}, dialling {}, connected {}",
        count(Line::Lost),
        count(Line::Dialling),
        count(Line::Connected),
    )
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
    seen.expect_the_device();
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
    let me = device.endpoint().id().fmt_short().to_string();
    let device_span = seen.the_device();
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
            let state = actor_state(seen, device_span, &front.url, switched, started_at);
            match outcome {
                Ok(rtt) if rtt.as_millis() > u128::from(LIMIT_MS) => {
                    lines.push(format!(
                        "OVER {LIMIT_MS} ms: request {index} in {name} took {} ms, relay actor {state} (endpoint {me}, relay {})",
                        rtt.as_millis(),
                        front.url
                    ));
                    if worst.is_none_or(|(_, longest, _)| *rtt > longest) {
                        worst = Some((*index, *rtt, state));
                    }
                }
                Ok(_) => {}
                Err(reason) => lines.push(format!(
                    "UNANSWERED: request {index} in {name}, relay actor {state} (endpoint {me}, relay {}): {reason}",
                    front.url
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
    lines.push(events_line(seen, device_span, &me, &front.url));
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
/// each with 32 connections on the relay, which stops reading and also stalls the connections that
/// are made after the stop, and resumes. A host on a healthy relay is asked a small question every
/// 100 ms throughout. The figures and the outcome lines are printed first; then the conditions are
/// asserted.
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
