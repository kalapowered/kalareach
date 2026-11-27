//! What the connect of a paired device says when it fails for good.
//!
//! The client reduces a transport failure to one line that is safe to show, so a case that fails
//! to connect keeps nothing else of it. This keeps what is needed to tell which layer failed:
//! the variant and the text of the transport's error, each attempt with the time it ended, the
//! addresses the dial offered and the ones the endpoint it dialled from knew for the host when the
//! attempt failed, and the lines the process logged. It prints error texts only: no key, no seed
//! and no pairing secret is an input of any of them.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use iroh::Endpoint;
use kr_client::ClientError;
use kr_client::transport::NetworkTransport;
use kr_transport::TransportError;
use kr_transport::scheduler::SendLimits;

use super::{PairedDial, pairing};

/// How many lines the capture keeps, and how many characters of each.
const KEPT_LINES: usize = 64;
const LINE_LENGTH: usize = 240;

/// The lines the process logged, the oldest first, kept in memory under a fixed bound.
static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// When the capture was set up, which the times of the lines and of the report count from.
static STARTED: OnceLock<Instant> = OnceLock::new();

/// Whether this capture is the process's subscriber.
static CAPTURING: AtomicBool = AtomicBool::new(false);

fn milliseconds_since_start(at: Instant) -> u128 {
    STARTED.get().map_or(0, |started| {
        at.saturating_duration_since(*started).as_millis()
    })
}

/// What the capture keeps: what this workspace's transport and controller log from `debug`, and
/// anything else from `warn`.
fn wanted(metadata: &tracing::Metadata<'_>) -> bool {
    let target = metadata.target();
    let own = target.starts_with("kr_transport") || target.starts_with("kr_controller");
    *metadata.level()
        <= if own {
            tracing::Level::DEBUG
        } else {
            tracing::Level::WARN
        }
}

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = if field.name() == "message" {
            write!(self.0, " {value:?}")
        } else {
            write!(self.0, " {}={value:?}", field.name())
        };
    }
}

/// A subscriber that keeps the last lines in memory and prints nothing.
struct Capture;

impl tracing::Subscriber for Capture {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if wanted(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        wanted(metadata)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let metadata = event.metadata();
        let mut line = format!(
            "+{} ms {} {}{}",
            milliseconds_since_start(Instant::now()),
            metadata.level(),
            metadata.target(),
            fields.0
        );
        if line.chars().count() > LINE_LENGTH {
            line = line.chars().take(LINE_LENGTH).collect();
            line.push_str("...");
        }
        let mut lines = LINES.lock().unwrap_or_else(PoisonError::into_inner);
        if lines.len() == KEPT_LINES {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Sets the capture up as the process's subscriber, once, unless the process has one already: a
/// case never fails for that, and the report says no lines were kept.
pub fn install_capture() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = STARTED.set(Instant::now());
        CAPTURING.store(
            tracing::subscriber::set_global_default(Capture).is_ok(),
            Ordering::SeqCst,
        );
    });
}

/// The layer a failure of the client is, as far as the client's reduction lets it be told.
#[must_use]
pub fn layer_of(error: &ClientError) -> &'static str {
    match error {
        ClientError::Transport(error) => match error {
            TransportError::Connect(_) => "the dial: the connection was not established",
            TransportError::RelayRefused(_) => "the dial: a relay refused this endpoint",
            TransportError::Stream(_) => {
                "the handshake's control stream: it was opened, written or read"
            }
            TransportError::Closed(_) => "the host closed the connection",
            TransportError::Refused(_) => "the host refused the device",
            TransportError::Handshake(_)
            | TransportError::Crypto(_)
            | TransportError::Selection(_)
            | TransportError::Frame(_)
            | TransportError::Cbor(_) => {
                "the handshake: the device's own check of what the host sent"
            }
            TransportError::Inactive
            | TransportError::Deadline(_)
            | TransportError::ControlLost
            | TransportError::LimitExceeded { .. } => "the connection after it was made",
            _ => "another failure of the transport",
        },
        _ => "the client, which is not a failure of the transport",
    }
}

/// The text of a failure and of each source under it. A transport error keeps the text of the
/// connection library's error as one string, so that text is the lowest level there is.
#[must_use]
pub fn chain_of(error: &ClientError) -> String {
    match error {
        ClientError::Transport(error) => {
            let mut text = error.to_string();
            let mut source = std::error::Error::source(error);
            while let Some(cause) = source {
                let _ = write!(text, "; caused by: {cause}");
                source = cause.source();
            }
            text
        }
        other => other.to_string(),
    }
}

/// One attempt that failed, as it stood when it failed.
struct Note {
    at: Duration,
    layer: &'static str,
    chain: String,
    offered: String,
    known: String,
}

/// What the dial gave the transport to reach the host with.
fn offered(dial: &PairedDial) -> String {
    let mut text = format!(
        "the dial offered: {:?}",
        dial.addr.ip_addrs().collect::<Vec<_>>()
    );
    let relays = dial.addr.relay_urls().collect::<Vec<_>>();
    if !relays.is_empty() {
        let _ = write!(text, ", relays {relays:?}");
    }
    text
}

/// What the endpoint the dial goes out from holds for the host now: the addresses it learned from
/// earlier connections, which a host that came back on another port does not answer on.
async fn known(endpoint: &Endpoint, peer: iroh::EndpointId) -> String {
    if endpoint.is_closed() {
        return "the dialling endpoint is closed".to_owned();
    }
    match endpoint.remote_info(peer).await {
        None => "the dialling endpoint knows for the host: nothing".to_owned(),
        Some(info) => {
            let mut addresses = info
                .addrs()
                .map(|address| format!("{:?} {:?}", address.addr(), address.usage()))
                .collect::<Vec<_>>();
            addresses.sort();
            format!(
                "the dialling endpoint knows for the host: [{}]",
                addresses.join(", ")
            )
        }
    }
}

/// A connect that failed for good, with what it knows of itself.
pub struct DialFailed {
    /// The client's error, as the last attempt returned it.
    pub error: ClientError,
    first: Instant,
    host_started: Instant,
    notes: Vec<Note>,
}

impl DialFailed {
    /// Ends the case with the helper's own message and the report after it.
    pub fn into_panic(self) -> ! {
        panic!("the paired device connects: {}", self.report())
    }

    fn report(&self) -> String {
        let now = Instant::now();
        let mut text = format!(
            "{}\n  layer: {}\n  error: {}\n  since the host started: {} ms; since the first dial: \
             {} ms (on the capture's clock the host started at +{} ms, the first dial was at +{} \
             ms and this is +{} ms)\n  attempts: {}\n",
            self.error,
            layer_of(&self.error),
            chain_of(&self.error),
            now.saturating_duration_since(self.host_started).as_millis(),
            now.saturating_duration_since(self.first).as_millis(),
            milliseconds_since_start(self.host_started),
            milliseconds_since_start(self.first),
            milliseconds_since_start(now),
            self.notes.len(),
        );
        for (index, note) in self.notes.iter().enumerate() {
            let _ = write!(
                text,
                "  attempt {} at +{} ms: {}: {}\n    {}\n    {}\n",
                index + 1,
                note.at.as_millis(),
                note.layer,
                note.chain,
                note.offered,
                note.known,
            );
        }
        if CAPTURING.load(Ordering::SeqCst) {
            let lines = LINES.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = writeln!(
                text,
                "  the lines below are the process's, from every host and device in it, the last \
                 {KEPT_LINES} at most, oldest first (kr_transport and kr_controller from debug, \
                 anything else from warn):"
            );
            if lines.is_empty() {
                text.push_str("    none\n");
            }
            for line in lines.iter() {
                let _ = writeln!(text, "    {line}");
            }
        } else {
            text.push_str(
                "  no lines were kept: this process had a subscriber of its own before the capture\n",
            );
        }
        text
    }
}

/// One connect of the device's to the host, authorised as the device, made again for as long as the
/// transport gives up on an attempt unanswered ([`pairing::until_answered`]); on any other failure
/// it returns the failure with what was seen of every attempt.
pub(super) async fn dial(dial: &PairedDial) -> Result<NetworkTransport, DialFailed> {
    let first = Instant::now();
    let notes = Mutex::new(Vec::new());
    let kept = &notes;
    let endpoint = &dial.from.endpoint().await;
    let outcome = pairing::until_answered(
        move || async move {
            let outcome = NetworkTransport::connect(
                endpoint,
                dial.addr.clone(),
                &dial.identity,
                &dial.host_record,
                SendLimits::default(),
            )
            .await;
            if let Err(error) = &outcome {
                let note = Note {
                    at: first.elapsed(),
                    layer: layer_of(error),
                    chain: chain_of(error),
                    offered: offered(dial),
                    known: known(endpoint, dial.addr.id).await,
                };
                kept.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(note);
            }
            outcome
        },
        pairing::transport_gave_up_unanswered,
    )
    .await;
    outcome.map_err(|error| DialFailed {
        error,
        first,
        host_started: dial.host_started,
        notes: notes.into_inner().unwrap_or_else(PoisonError::into_inner),
    })
}
