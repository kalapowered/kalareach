//! A relay that stops taking data, and a host on another relay beside it.
//!
//! The device's one endpoint has one relay actor for all of its relay clients. In the transport
//! library's 1.4.1 release that actor takes a datagram for one relay only while no send of its own
//! is pending, so a relay that stops reading can hold the sends to every relay. This file holds two
//! cases of that. Both put several hosts on one relay that stops reading, each with 32 connections,
//! and ask a host on a healthy relay a small question every 100 milliseconds. In the first, each
//! connection carries a sender that writes without a pause: a stress load, above what the product
//! shows a host using, which keeps the relay's queue full. In the second, each connection is asked
//! a small question, a load that does not keep that queue full.
//!
//! The first stops the relay once and asks the healthy host before the stop, during it and after
//! the relay resumes. It fails unless every question the healthy host is asked, from the first to
//! the last and also between two phases, is answered, the healthy host's connection stays open, no
//! answer takes [`LIMIT_MS`] or longer, the run filled the stopped relay's queue, which the
//! library's own line about a datagram dropped for a full queue shows, and the stopped front read
//! next to nothing from the device while it was stopped, so that the queue was filled by a relay
//! that stopped and not by the load alone. The limit is a bound of this test: it has room above
//! what the library's changed relay transport gives and is far below what the release's hold
//! gives.
//!
//! The second stops the relay three times for five seconds. It asks each connection to the hosts on
//! the stopped relay a small question every half second. The first stop follows about ten seconds
//! after the connections are made, once the healthy host has been asked its first hundred
//! questions. Each later stop follows once every one of those connections has answered a question
//! that was asked after the last resume, or, if one has not answered by twice [`RECOVERY`] after
//! that resume, at that time. After each switch the case waits until every pump of the front waits
//! at the gate, and it judges the stop by the questions that were asked from then until the resume.
//! It fails unless every connection stays open, each is answered again within [`RECOVERY`] after
//! each resume, every question to them is answered, every pump waits at the gate within [`STAND`]
//! of each switch, at least one question is asked in each stop's window, none of the questions
//! asked in a window is answered before the relay resumes, and the healthy host stays under the
//! limit through every stop. The windows are judged once every question has ended. It prints how
//! many datagrams the relay actor dropped for the stopped relay's queue in each stop and outside
//! the stops, and asserts no count of them: a short stop can end before the queue is full.
//!
//! Both are outside the default suite: each runs for minutes, so they are asked for by name with
//! `--ignored --nocapture`, which prints what they measured. They run with one test thread
//! (`--test-threads=1`): the capture marks the device's endpoint for the whole process, so two
//! cases that run at once would mix their lines.

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

/// The limit that a question's round trip to the healthy host is held to, in milliseconds. It is a
/// bound of these cases and not a figure of the product. An answer that takes this long or longer is
/// over it.
const LIMIT_MS: u64 = 2000;
const LIMIT: Duration = Duration::from_millis(LIMIT_MS);

/// How often the recovery case asks each connection to a host on the relay that stops: a load that
/// does not keep that relay's queue full. A host that hears nothing from the device for its idle
/// time-out of 30 seconds closes the connection. Each probe interval can exceed the one before by a
/// capped step, so that takes every probe in about thirty seconds to be lost; a load that keeps the
/// relay's queue full can drop them, and this case's load does not keep it full.
const HOST_INTERVAL: Duration = Duration::from_millis(500);

/// How many times the recovery case stops the relay, and for how long each time: less than a
/// connection's idle time-out of 30 seconds and less than the library's send time-out of 15 seconds.
const STOPS: usize = 3;
const STOP_FOR: Duration = Duration::from_secs(5);

/// The longest that the recovery case waits after a switch for every pump of the front to wait at
/// the gate. A pump has at most one read and one write to finish, which takes milliseconds; a pump
/// that still runs after this is stuck, and the case fails with a line of its own. It is shorter
/// than a stop, so each stop keeps a window.
const STAND: Duration = Duration::from_secs(3);

/// The longest that a connection to a host on the relay that resumed may take to answer a question
/// that was asked after the resume: the recovery case fails when one takes longer, and when one has
/// not answered after twice this.
const RECOVERY: Duration = Duration::from_secs(5);

/// The healthy host's questions before the first stop and after the last resume of the recovery
/// case.
const FRAME: usize = 100;

/// How often the case looks at a count that no future announces.
const LOOK: Duration = Duration::from_millis(50);

/// Connections to each host on the relay that stops. The stall case gives each a sender, a stress
/// load above what the product shows one host using.
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
    /// The relay actor dropped a datagram because the queue of the relay client that it was for
    /// was full.
    Dropped,
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
            "url" => {
                // A span writes the URL as text; a line writes it as `RelayUrl("...")`.
                let text = format!("{value:?}");
                let url = text
                    .strip_prefix("RelayUrl(")
                    .and_then(|rest| rest.strip_suffix(')'))
                    .unwrap_or(&text);
                self.url = url.trim_matches('"').to_owned();
            }
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
        let relay_transport = metadata
            .target()
            .starts_with("iroh::socket::transports::relay");
        // A line at the trace level is kept only when it names the relay client by its `url`, which
        // is how the library words a dropped datagram.
        (relay_transport
            && (*metadata.level() <= tracing::Level::DEBUG
                || metadata.fields().field("url").is_some()))
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
        } else if words.message.contains("queue full") {
            Line::Dropped
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
        if lines.len() < 1_000_000 {
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

/// What the stopped relay's actor was doing at `at`, by what the library logged since the switch,
/// in `kept`: the lines of the device's endpoint about the front's URL, in the order they came.
fn actor_state(kept: &[Logged], switched: Instant, at: Instant) -> &'static str {
    let mut dialling = false;
    for logged in kept {
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
        "EVENTS endpoint {identity} (span {endpoint}) relay {relay}: lost {}, dialling {}, connected {}, dropped for a full queue {}",
        count(Line::Lost),
        count(Line::Dialling),
        count(Line::Connected),
        count(Line::Dropped),
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

/// Asks one question on a task of its own. The task takes the question's start right before it
/// asks and the answer's arrival right after the answer comes, so both are recorded by the task
/// that sends and receives. `began` is set once the start is taken.
fn spawn_question(
    connection: Connection,
    slots: &Arc<Mutex<Vec<Outcome>>>,
    began: Option<Arc<AtomicBool>>,
) -> JoinHandle<()> {
    let index = {
        let mut slots = slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.push(None);
        slots.len() - 1
    };
    let slots = Arc::clone(slots);
    tokio::spawn(async move {
        let started = Instant::now();
        if let Some(began) = began {
            began.store(true, Ordering::SeqCst);
        }
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

/// The bytes that the device's connections to the hosts on the relay that stops have handed to the
/// endpoint so far: what the device offered that relay's path.
fn offered(held: &[Connection]) -> u64 {
    held.iter()
        .map(|connection| connection.stats().udp_tx.bytes)
        .sum()
}

/// How many datagrams the relay actor of the device's endpoint dropped for the full queue of the
/// relay client of `relay` between `from` and `to`.
fn dropped(seen: &Seen, endpoint: u64, relay: &RelayUrl, from: Instant, to: Instant) -> usize {
    seen.of(endpoint, relay)
        .iter()
        .filter(|logged| logged.line == Line::Dropped && logged.when >= from && logged.when <= to)
        .count()
}

/// The answers of one host's questions that took the limit or longer, the questions that got none,
/// and the longest answer.
fn tally(outcomes: &[(Instant, Result<Duration, String>)]) -> (usize, usize, Duration) {
    let (mut over, mut none, mut longest) = (0, 0, Duration::ZERO);
    for (_, outcome) in outcomes {
        match outcome {
            Ok(rtt) => {
                over += usize::from(*rtt >= LIMIT);
                longest = longest.max(*rtt);
            }
            Err(_) => none += 1,
        }
    }
    (over, none, longest)
}

/// One question every `interval` to one connection, each on a task of its own, until
/// [`Asker::finish`].
struct Asker {
    connection: Connection,
    slots: Arc<Mutex<Vec<Outcome>>>,
    stop: Arc<AtomicBool>,
    task: JoinHandle<()>,
    /// The questions that the case asked itself, outside the ticks, by [`Asker::ask_now`].
    extra: Mutex<Vec<JoinHandle<()>>>,
}

impl Asker {
    fn start(connection: &Connection, interval: Duration) -> Self {
        let slots: Arc<Mutex<Vec<Outcome>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let task = {
            let (slots, stop, connection) =
                (Arc::clone(&slots), Arc::clone(&stop), connection.clone());
            tokio::spawn(async move {
                let mut tasks = Vec::new();
                let mut tick = tokio::time::interval(interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                while !stop.load(Ordering::SeqCst) {
                    tick.tick().await;
                    tasks.push(spawn_question(connection.clone(), &slots, None));
                }
                for task in tasks {
                    let _ = task.await;
                }
            })
        };
        Self {
            connection: connection.clone(),
            slots,
            stop,
            task,
            extra: Mutex::default(),
        }
    }

    /// Asks one more question now, outside the ticks, and returns once the question's task has
    /// taken its start. The start is recorded by that task, so it is later than anything that
    /// happened before this call and earlier than anything that happens after it returns.
    async fn ask_now(&self) {
        let began = Arc::new(AtomicBool::new(false));
        let task = spawn_question(
            self.connection.clone(),
            &self.slots,
            Some(Arc::clone(&began)),
        );
        self.extra
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(task);
        until("the case's own question to start", || {
            began.load(Ordering::SeqCst)
        })
        .await;
    }

    fn started(&self) -> usize {
        started(&self.slots)
    }

    /// When the first question that was asked at or after `at` was answered, if one was.
    fn answered_after(&self, at: Instant) -> Option<Instant> {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .flatten()
            .filter_map(|(started, outcome)| match outcome {
                Ok(rtt) if *started >= at => Some(*started + *rtt),
                _ => None,
            })
            .min()
    }

    /// Stops asking, waits for every question to end, and returns when each was asked and how it
    /// ended, in the order they were asked.
    async fn finish(self) -> Vec<(Instant, Result<Duration, String>)> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.task.await;
        let extra = std::mem::take(&mut *self.extra.lock().unwrap_or_else(PoisonError::into_inner));
        for task in extra {
            let _ = task.await;
        }
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|slot| slot.clone().expect("every question ended"))
            .collect()
    }
}

/// What each connection to a host on the relay that stops carries.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Load {
    /// A sender that writes bulk streams one after another: a stress load that keeps the relay's
    /// queue full.
    Bulk,
    /// Nothing of its own: the case asks the connection a small question, and the relay's queue is
    /// not kept full.
    Questions,
}

impl Load {
    /// The receive buffer of the front before the relay that stops. The case that keeps the relay's
    /// queue full gives the front a few KiB, so that a stopped front takes almost nothing; the case
    /// that asks questions leaves the system's default, so that the bytes a stop holds back drain
    /// at once after the resume.
    const fn front_buffer(self) -> Option<u32> {
        match self {
            Self::Bulk => Some(support::front::STALLED_RECEIVE_BUFFER),
            Self::Questions => None,
        }
    }
}

/// What one arrangement holds alive: the two relays, the front before the one that stops, the
/// hosts, the device's endpoint and the connections that the device keeps to them.
struct World {
    front: RelayFront,
    _a: Responder,
    _stalled: Vec<Responder>,
    device: DeviceEndpoint,
    device_span: u64,
    /// The device's short identity, for the printout.
    me: String,
    to_a: Connection,
    /// Every connection to a host on the relay that stops.
    held: Vec<Connection>,
    /// When each of `held` closed and why, by its index in `held`, in the order they closed.
    closes: Arc<Mutex<Vec<(usize, Instant, String)>>>,
    senders: Vec<JoinHandle<()>>,
    watchers: Vec<JoinHandle<()>>,
    _relays: (LocalRelay, LocalRelay),
}

impl World {
    /// Starts one host on a healthy relay and `hosts` hosts on the relay that stops, connects the
    /// device to each, makes [`CONNECTIONS_PER_HOST`] connections to every host on the relay that
    /// stops, and gives each its `load`. It returns once each sender, if the load has one, has
    /// finished its first stream.
    async fn start(hosts: usize, load: Load) -> Self {
        let seen = capture();
        let connections = hosts * CONNECTIONS_PER_HOST;
        let (healthy, stopping) = (LocalRelay::spawn().await, LocalRelay::spawn().await);
        let front = RelayFront::stalling(&stopping, load.front_buffer());
        let a = Responder::on(&healthy, 1).await;
        let mut stalled = Vec::new();
        for index in 0..hosts {
            stalled
                .push(Responder::on(&stopping, 10 + u8::try_from(index).expect("few hosts")).await);
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
            .introduce(
                HostServices::paired(&view_a, a.side.keys.transport.public()).expect("host A"),
            )
            .await
            .expect("host A");
        for host in &stalled {
            device
                .introduce(
                    HostServices::paired(&view_b, host.side.keys.transport.public())
                        .expect("a host"),
                )
                .await
                .expect("a host");
        }

        let to_a = connect(&device, &view_a, &a).await;
        let sent = Arc::new(AtomicUsize::new(0));
        let (mut held, mut senders) = (Vec::new(), Vec::new());
        for host in &stalled {
            let dials = (0..CONNECTIONS_PER_HOST).map(|_| connect(&device, &view_b, host));
            for connection in futures::future::join_all(dials).await {
                held.push(connection.clone());
                if load == Load::Bulk {
                    senders.push(tokio::spawn(send_loop(connection, Arc::clone(&sent))));
                }
            }
        }
        if load == Load::Bulk {
            until("every sender's first stream", || {
                sent.load(Ordering::SeqCst) == connections
            })
            .await;
        }
        let closes: Arc<Mutex<Vec<(usize, Instant, String)>>> = Arc::default();
        let watchers = held
            .iter()
            .enumerate()
            .map(|(index, connection)| {
                let (connection, closes) = (connection.clone(), Arc::clone(&closes));
                tokio::spawn(async move {
                    let reason = connection.closed().await.to_string();
                    closes.lock().unwrap_or_else(PoisonError::into_inner).push((
                        index,
                        Instant::now(),
                        reason,
                    ));
                })
            })
            .collect();
        Self {
            front,
            _a: a,
            _stalled: stalled,
            device,
            device_span,
            me,
            to_a,
            held,
            closes,
            senders,
            watchers,
            _relays: (healthy, stopping),
        }
    }

    /// Ends every sender and watcher and closes the device's endpoint.
    async fn close(self) {
        for task in self.senders.iter().chain(&self.watchers) {
            task.abort();
        }
        self.device.close().await;
    }
}

/// One arrangement: `hosts` hosts with [`CONNECTIONS_PER_HOST`] connections each on the relay that
/// stops. Returns the lines it printed, and the conditions it failed.
async fn arrangement(hosts: usize) -> (Vec<String>, Vec<String>) {
    let seen = capture();
    let connections = hosts * CONNECTIONS_PER_HOST;
    let world = World::start(hosts, Load::Bulk).await;
    let (front, me) = (&world.front, world.me.as_str());

    // The questions, one every INTERVAL, each on a task of its own.
    let asking = Asker::start(&world.to_a, INTERVAL);
    let metrics = &world.device.endpoint().metrics().socket;
    let first = asking.started();
    until("the questions before the stop", || {
        asking.started() >= first + BEFORE
    })
    .await;
    let relay_before = metrics.send_relay.get();
    let offered_before = offered(&world.held);
    let front_before = front.stall();
    let switched = Instant::now();
    let switch_index = asking.started();
    until("the questions during the stop", || {
        asking.started() >= switch_index + DURING
    })
    .await;
    let (relay_after, front_after) = (metrics.send_relay.get(), front.read_from_device());
    let connections_at_end = front.accepted();
    let offered_after = offered(&world.held);
    let resumed = Instant::now();
    front.resume();
    let resume_index = asking.started();
    until("the questions after the resume", || {
        asking.started() >= resume_index + AFTER
    })
    .await;
    let outcomes = asking.finish().await;
    for sender in &world.senders {
        sender.abort();
    }

    // The three phases together hold every question that was asked: those before the switch, those
    // from the switch to the resume, and every one after the resume, also the ones that the asking
    // added while the case read its counts.
    let phase = |from: usize, to: usize| -> Vec<(usize, Result<Duration, String>)> {
        (from..to)
            .map(|index| (index, outcomes[index].1.clone()))
            .collect()
    };
    let phases = [
        ("BEFORE", phase(0, switch_index)),
        ("DURING", phase(switch_index, resume_index)),
        ("AFTER", phase(resume_index, outcomes.len())),
    ];
    let kept = seen.of(world.device_span, &front.url);
    let mut lines = vec![format!("ARRANGEMENT K={hosts} N={connections}")];
    let mut worst: Option<(usize, Duration, &'static str)> = None;
    let (mut over, mut unanswered) = (0, 0);
    for (name, rows) in &phases {
        let answered: Vec<(usize, Duration)> = rows
            .iter()
            .filter_map(|(index, outcome)| outcome.as_ref().ok().map(|rtt| (*index, *rtt)))
            .collect();
        unanswered += rows.len() - answered.len();
        lines.push(figure(name, &answered, rows.len()));
        for (index, outcome) in rows {
            // Read only for a question that went wrong: every kept line is read for it.
            let state = || actor_state(&kept, switched, outcomes[*index].0);
            match outcome {
                Ok(rtt) if *rtt >= LIMIT => {
                    let state = state();
                    over += 1;
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
                    "UNANSWERED: request {index} in {name}, relay actor {} (endpoint {me}, relay {}): {reason}",
                    state(),
                    front.url
                )),
            }
        }
    }
    let closed = world.to_a.close_reason().map(|reason| reason.to_string());
    let filled = dropped(seen, world.device_span, &front.url, switched, resumed);
    lines.push(format!(
        "COUNTERS relay_conns_closed {}, send_relay {} B (stop {} B), front accepted {}, read from device {} B (stop {} B), handed to the endpoint by the connections to the stopped relay's hosts (stop {} B)",
        metrics.relay_conns_closed.get(),
        metrics.send_relay.get(),
        relay_after - relay_before,
        front.accepted(),
        front.read_from_device(),
        front_after - front_before,
        offered_after - offered_before,
    ));
    lines.push(events_line(seen, world.device_span, me, &front.url));
    match worst {
        Some((index, rtt, state)) => lines.push(format!(
            "LIMIT {LIMIT_MS} ms: PASSED BY {:?} AT REQUEST {index} WHILE {state} (K={hosts}, N={connections}); {over} answers took the limit or longer, {unanswered} questions had none",
            rtt - LIMIT
        )),
        None if unanswered > 0 => lines.push(format!(
            "LIMIT {LIMIT_MS} ms: NOT SHOWN, {unanswered} questions had no answer (K={hosts}, N={connections})"
        )),
        None => lines.push(format!("LIMIT {LIMIT_MS} ms: HELD")),
    }
    lines.push(if filled > 0 {
        format!(
            "QUEUE: filled: the device's relay actor dropped {filled} datagrams for the stopped relay's full queue during the stop; the connections to its hosts handed the endpoint {} B and the front read {} B",
            offered_after - offered_before,
            front_after - front_before
        )
    } else {
        format!(
            "QUEUE: not shown filled: the device's relay actor logged no datagram dropped for the stopped relay's queue during the stop; the connections to its hosts handed the endpoint {} B and the front read {} B",
            offered_after - offered_before,
            front_after - front_before
        )
    });
    lines.push(format!("UNANSWERED: {unanswered}"));
    lines.push(format!("A CLOSED: {}", closed.as_deref().unwrap_or("none")));

    let mut failures = Vec::new();
    if let Some(reason) = &closed {
        failures.push(format!(
            "K={hosts}: the healthy host's connection closed: {reason}"
        ));
    }
    if unanswered != 0 {
        failures.push(format!(
            "K={hosts}: {unanswered} questions of the healthy host were not answered"
        ));
    }
    if over + unanswered != 0 {
        failures.push(format!(
            "K={hosts}: the healthy host was not answered within the limit of {LIMIT_MS} ms: {over} answers took the limit or longer and {unanswered} questions had none"
        ));
    }
    if filled == 0 {
        failures.push(format!(
            "K={hosts}: the run did not fill the stopped relay's queue: no datagram was dropped for it during the stop"
        ));
    }
    // The stop's own effect. The count of what the front read is taken as the stop is made, so only a read that was
    // under way at the switch can enter the window: one of at most CHUNK bytes on each connection that reached the
    // front. The allowance is twice that. A run in which the relay never stopped reads megabytes, and the queue then
    // fills by the load alone.
    let read_while_stopped = front_after - front_before;
    let at_most = 2 * connections_at_end as u64 * support::front::CHUNK as u64;
    if read_while_stopped > at_most {
        failures.push(format!(
            "K={hosts}: the front read {read_while_stopped} B from the device while it was stopped, more than the {at_most} B that a stopped front can still take ({connections_at_end} connections): the relay was not stopped"
        ));
    }
    world.close().await;
    (lines, failures)
}

/// The recovery arrangement: `hosts` hosts with [`CONNECTIONS_PER_HOST`] connections each on the
/// relay that stops `stops` times for `stop_for`, a small question every [`HOST_INTERVAL`] on each of
/// those connections, and the next stop only once every one of them has answered a question that
/// was asked after the resume, or at the deadline of that wait. Each stop is checked once every
/// question has ended: no question that was asked after every pump of the front waited at the gate,
/// and before the resume, may have been answered before the resume. Returns the lines it printed,
/// and the conditions it failed.
async fn recovery(hosts: usize, stops: usize, stop_for: Duration) -> (Vec<String>, Vec<String>) {
    let seen = capture();
    let world = World::start(hosts, Load::Questions).await;
    let (front, me) = (&world.front, world.me.as_str());
    let healthy = Asker::start(&world.to_a, INTERVAL);
    let began = Instant::now();
    let asking: Vec<Asker> = world
        .held
        .iter()
        .map(|connection| Asker::start(connection, HOST_INTERVAL))
        .collect();
    let first = healthy.started();
    until(
        "an answer on every connection before the first stop",
        || {
            asking
                .iter()
                .all(|asker| asker.answered_after(began).is_some())
        },
    )
    .await;
    until("the questions before the first stop", || {
        healthy.started() >= first + FRAME
    })
    .await;

    let connections = world.held.len();
    let mut lines = vec![format!(
        "ARRANGEMENT RECOVERY K={hosts} N={connections}: {stops} stops of {stop_for:?}, a question to each connection every {HOST_INTERVAL:?}, the next stop only after every connection answered a question asked after the resume (within {RECOVERY:?})"
    )];
    let mut failures = Vec::new();
    let mut windows: Vec<(Instant, Instant)> = Vec::new();
    // When every pump of the front waited at the gate in each stop, or none if one did not. The
    // front takes this instant, and the instant of each resume, at the event under its own lock.
    let mut stood: Vec<Option<Instant>> = Vec::new();
    for stop in 1..=stops {
        front.stall();
        let switched = Instant::now();
        // The stop is judged from the moment that every pump waits at the gate: no pause decides it.
        match front.confirm_stopped(STAND).await {
            Ok(at) => {
                stood.push(Some(at));
                // One question of the case's own in each window, so that no delay of the others'
                // tasks can leave the window empty: its start is taken after the front's instant
                // and before the resume.
                asking[0].ask_now().await;
            }
            Err(reason) => {
                failures.push(format!("stop {stop}: {reason}"));
                stood.push(None);
            }
        }
        tokio::time::sleep(stop_for.saturating_sub(switched.elapsed())).await;
        let resumed = front.resume();
        windows.push((switched, resumed));
        let deadline = resumed + RECOVERY * 2;
        while Instant::now() < deadline
            && !asking
                .iter()
                .all(|asker| asker.answered_after(resumed).is_some())
        {
            tokio::time::sleep(LOOK).await;
        }
        let filled = dropped(seen, world.device_span, &front.url, switched, resumed);
        lines.push(format!(
            "STOP {stop}: the relay stood still {} ms; the device's relay actor dropped {filled} datagrams for its queue",
            (resumed - switched).as_millis()
        ));
        let answers: Vec<Option<Duration>> = asking
            .iter()
            .map(|asker| asker.answered_after(resumed).map(|at| at - resumed))
            .collect();
        let none = answers.iter().filter(|answer| answer.is_none()).count();
        let late = answers
            .iter()
            .flatten()
            .filter(|rtt| **rtt > RECOVERY)
            .count();
        let slowest = answers.iter().flatten().max().copied().unwrap_or_default();
        lines.push(format!(
            "RECOVERY stop {stop}: {} of {connections} connections answered a question asked after the resume, the slowest {} ms after it; {late} later than {RECOVERY:?}, {none} not within {:?}",
            connections - none,
            slowest.as_millis(),
            RECOVERY * 2
        ));
        if none != 0 {
            failures.push(format!(
                "stop {stop}: {none} of {connections} connections were not answered again within {:?} of the resume",
                RECOVERY * 2
            ));
        }
        if late != 0 {
            failures.push(format!(
                "stop {stop}: {late} of {connections} connections were answered again later than {RECOVERY:?} after the resume"
            ));
        }
    }
    let before_last = healthy.started();
    until("the questions after the last resume", || {
        healthy.started() >= before_last + FRAME
    })
    .await;
    let ended = Instant::now();

    let a_outcomes = healthy.finish().await;
    let (over, none, longest) = tally(&a_outcomes);
    lines.push(format!(
        "FIGURE healthy host through every stop: questions {}, longest {} ms, over {LIMIT_MS} ms {over}, unanswered {none}",
        a_outcomes.len(),
        longest.as_millis()
    ));
    let closed = world.to_a.close_reason().map(|reason| reason.to_string());
    if let Some(reason) = &closed {
        failures.push(format!("the healthy host's connection closed: {reason}"));
    }
    if none != 0 {
        failures.push(format!(
            "{none} questions of the healthy host were not answered"
        ));
    }
    if over + none != 0 {
        failures.push(format!(
            "the healthy host was not answered within the limit of {LIMIT_MS} ms: {over} answers took the limit or longer and {none} questions had none"
        ));
    }
    let (mut asked, mut unanswered, mut slowest) = (0, 0, Duration::ZERO);
    let mut by_connection: Vec<Vec<(Instant, Result<Duration, String>)>> = Vec::new();
    for asker in asking {
        let outcomes = asker.finish().await;
        let (_, none, longest) = tally(&outcomes);
        asked += outcomes.len();
        unanswered += none;
        slowest = slowest.max(longest);
        by_connection.push(outcomes);
    }
    lines.push(format!(
        "FIGURE connections to the hosts on the stopped relay: connections {connections}, questions {asked}, unanswered {unanswered}, longest {} ms",
        slowest.as_millis()
    ));
    if unanswered != 0 {
        failures.push(format!(
            "{unanswered} questions to the hosts on the stopped relay were not answered"
        ));
    }
    // The stops' own effect, judged now that every question has ended. A stopped front passes no byte
    // either way, so a question that was asked once every pump waited at the gate gets no answer
    // before the resume. Every instant compared here is taken where its event happens, at the event,
    // and no instant of the case's own task is used: the stop's confirmation and the resume by the
    // front under its lock, a question's start and its answer's arrival by the question's own task.
    // A delay of any task can only move the question's recorded start or arrival later.
    for (number, ((_, resumed), stood)) in windows.iter().zip(&stood).enumerate() {
        let Some(stood) = stood else { continue };
        let (mut in_window, mut answered_early) = (0, 0);
        for (began, outcome) in by_connection.iter().flatten() {
            if began >= stood && began < resumed {
                in_window += 1;
                answered_early +=
                    usize::from(matches!(outcome, Ok(rtt) if *began + *rtt < *resumed));
            }
        }
        let stop = number + 1;
        lines.push(format!(
            "STOPPED stop {stop}: {answered_early} of {in_window} questions asked after every pump of the front waited at the gate and before the resume were answered before the resume"
        ));
        if in_window == 0 {
            failures.push(format!(
                "stop {stop}: no question was asked after every pump of the front waited at the gate and before the resume, so the stop was not checked"
            ));
        }
        if answered_early != 0 {
            failures.push(format!(
                "stop {stop}: {answered_early} of {in_window} questions asked after every pump of the front waited at the gate and before the resume were answered before the resume: the relay was not stopped"
            ));
        }
    }
    let in_stops: usize = windows
        .iter()
        .map(|(switched, resumed)| {
            dropped(seen, world.device_span, &front.url, *switched, *resumed)
        })
        .sum();
    let in_run = dropped(seen, world.device_span, &front.url, began, ended);
    lines.push(format!(
        "QUEUE: the device's relay actor dropped {in_stops} datagrams for the stopped relay's queue during the stops and {} outside them",
        in_run.saturating_sub(in_stops)
    ));
    let closed_held: Vec<String> = world
        .held
        .iter()
        .filter_map(|connection| connection.close_reason().map(|reason| reason.to_string()))
        .collect();
    let per_host = connections / hosts;
    let first_stop = windows[0].0;
    let mut closes = world
        .closes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    closes.sort_by_key(|(_, when, _)| *when);
    for (index, when, reason) in &closes {
        // The last stop that began before the close, and where the close fell against it.
        let place = windows
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (switched, _))| switched <= when)
            .map_or_else(
                || "before stop 1".to_owned(),
                |(number, (switched, resumed))| {
                    if when <= resumed {
                        format!(
                            "during stop {}, {} ms after it began",
                            number + 1,
                            when.duration_since(*switched).as_millis()
                        )
                    } else {
                        format!(
                            "{} ms after resume {}, {} ms after stop {} began",
                            when.duration_since(*resumed).as_millis(),
                            number + 1,
                            when.duration_since(*switched).as_millis(),
                            number + 1
                        )
                    }
                },
            );
        lines.push(format!(
            "CLOSED connection {index} (host {}) {} ms after stop 1 began: {place}: {reason}",
            index / per_host + 1,
            when.duration_since(first_stop).as_millis()
        ));
    }
    lines.push(format!(
        "CONNECTIONS to the hosts on the stopped relay: {connections} held, {} closed{}",
        closed_held.len(),
        closed_held
            .first()
            .map_or(String::new(), |reason| format!(", the first: {reason}"))
    ));
    if !closed_held.is_empty() {
        failures.push(format!(
            "{} of {connections} connections to the hosts on the stopped relay closed, the first: {}",
            closed_held.len(),
            closed_held[0]
        ));
    }
    lines.push(events_line(seen, world.device_span, me, &front.url));
    lines.push(format!("A CLOSED: {}", closed.as_deref().unwrap_or("none")));
    world.close().await;
    (lines, failures)
}

/// The case that tries to fill the queue of a relay that has stopped: K = 3 hosts and then K = 6,
/// each with 32 connections on the relay, which stops reading and also stalls the connections that
/// are made after the stop, and resumes. A host on a healthy relay is asked a small question every
/// 100 ms throughout. The figures and the outcome lines are printed first; then the conditions are
/// asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs for minutes: asked for by name with --ignored --nocapture"]
async fn a_relay_that_stops_taking_data_does_not_hold_a_host_on_another_relay() {
    let host = support::conditions::Host::read();
    let mut conditions = host.lines();
    let mut every_line = Vec::new();
    let mut failures = Vec::new();
    for hosts in [3, 6] {
        let (lines, broken) = arrangement(hosts).await;
        every_line.extend(lines);
        failures.extend(broken);
    }
    conditions.extend(every_line);
    support::conditions::report("the healthy host beside a relay that stops", &conditions);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The case that follows a relay through repeated stops: K = 3 hosts with 32 connections each on the
/// relay, which stops [`STOPS`] times for [`STOP_FOR`], each time less than a connection's idle
/// time-out. Each connection is asked a small question throughout, and the next stop waits until
/// every one has answered a question asked after the resume. The hosts on it keep every connection
/// and are answered again after each resume; the host on the healthy relay stays under the limit
/// throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs for minutes: asked for by name with --ignored --nocapture"]
async fn the_hosts_of_a_relay_that_stops_and_resumes_keep_their_connections_and_are_answered_again()
{
    let host = support::conditions::Host::read();
    let mut conditions = host.lines();
    let (lines, failures) = recovery(3, STOPS, STOP_FOR).await;
    conditions.extend(lines);
    support::conditions::report("the hosts of a relay that stops and resumes", &conditions);
    assert!(failures.is_empty(), "{failures:#?}");
}
