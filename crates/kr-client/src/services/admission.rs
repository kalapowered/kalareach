//! Pairing admission: reaching a host through a managed relay before pairing with it.
//!
//! A managed relay carries a payload only under a lease, and a lease needs a payer and a pair that
//! has already paired. A device that has never paired with a host therefore cannot reach it through
//! such a relay, whether or not the host holds a lease with another device, unless the managed
//! service has told that relay to forward the pairing exchange between the two. That statement is
//! an admission: bounded in bytes and time, drawn from the service's free-service abuse budget, with
//! no payer and no session access. Asking for one is [`PairingAdmissionService::admit`].
//!
//! What a pairing needs from the rest of this module is [`PairingAdmissions`]: it decides which of a
//! host's relays are the managed service's, asks for an admission as the device starts to dial,
//! keeps the answer so that the re-dials of one attempt share it, and never lets any of it stop a
//! dial. A relay that is not the managed service's is never named to it.
//!
//! # What the cache keeps, and for how long
//!
//! One entry per relay and host. An admission is kept until half a minute before it ends. An
//! answer that the service is unable (the free budget is spent, a network asked too often) is kept
//! for the longer of the delay the service named and a minute, so that a dial that fails afterwards
//! can say why; whether to ask again is a separate time, the delay the service named, or twenty
//! seconds when it named none. A pair that holds a lease needs nothing, and a relay that is not the
//! service's is not asked about again, for a minute and for ten minutes. A dial marks its entry
//! doubtful when it starts and clears the mark only when it connects, so a dial that was cut short
//! leaves it doubtful without anything running when it is cut, and a later dial asks again after
//! twenty seconds. No entry is asked about more than three times between connections, and the
//! count starts again ten minutes after the last request, which is when what that request got has
//! ended. Until then a refusal from the service goes on explaining a failed dial, though the minute
//! it is kept for has passed, because nothing asks again to renew it.
//!
//! What a kept answer explains is one of two things, told apart by what the service named. An answer
//! that names the paths that still work is exhausted capacity, and the list and the delay are kept
//! with it. An answer that names none, and a refusal in the service's own envelope with a status of
//! the 5xx class, is a fault of the service: no list, and the delay when one was named. Both are
//! kept for as long as each other and asked again at the moments a refusal always was; a transport
//! failure and an answer that is not the service's envelope explain nothing.
//!
//! A service that answers that it does not serve the request (it has no such route) or that this
//! device is not allowed to ask stops every request for ten minutes. Nothing here ever turns that
//! into a reason a person is told, and nothing here waits for the service past a short bound.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_cbor::signing_value;
use kr_protocol::error::ErrorCode;
use kr_protocol::pairing::NetworkConfig;
use kr_protocol::scalars::{EndpointKey, U64};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::alternatives::Alternatives;
use super::matrix::ReleaseGate;
use super::relay::{ManagedRelayLeaseService, ServiceHttp, ServiceSigner};
use super::{ServiceFuture, relay};
use crate::error::ClientError;

/// The path an admission request is addressed to.
pub const RELAY_ADMISSION_PATH: &str = "/api/relay/admission";

/// The method name an admission request's credential covers.
pub const RELAY_ADMISSION_ISSUE_METHOD: &str = "relay.admission.issue";

/// The domain an admission request's body digest covers.
pub const RELAY_ADMISSION_REQUEST_DOMAIN: &str = "kr-relay-admission-request/1";

/// How many of a host's relays one dial asks the service about.
pub const MOST_RELAYS_ASKED: usize = 3;

/// How long a dial waits for the service to answer, all its requests together, before it connects
/// without the answer.
pub const ANSWER_WAIT: Duration = Duration::from_secs(2);

/// How long before an admission ends the device stops relying on it.
const ENDS_SOON: Duration = Duration::from_secs(30);

/// How long after asking an entry that no dial connected on is asked about again.
const DOUBT_AFTER: Duration = Duration::from_secs(20);

/// The longest an entry is asked about between connections.
const MOST_ASKS: u32 = 3;

/// How long after its last request an entry may be asked about again, though it has been asked
/// [`MOST_ASKS`] times with no connection between: what the last request got has ended by then.
const ASK_WINDOW: Duration = Duration::from_secs(10 * 60);

/// The longest the cache believes a time the service names, so that a figure that is not meant to
/// be believed cannot overflow a clock reading.
const LONGEST_NAMED: Duration = Duration::from_secs(24 * 60 * 60);

/// How long an answer that the service is unable is kept, at least.
const KEEP_UNAVAILABLE: Duration = Duration::from_secs(60);

/// How long a pair that holds a lease is believed to.
const KEEP_NOT_NEEDED: Duration = Duration::from_secs(60);

/// How long a relay that is not the service's is believed not to be.
const KEEP_NOT_MANAGED: Duration = Duration::from_secs(10 * 60);

/// How long every request stops for when the service says it does not serve them.
const SUSPEND: Duration = Duration::from_secs(10 * 60);

/// What a device asks the service for.
#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    /// The endpoint being paired with.
    pub host: EndpointKey,
    /// The endpoint that is pairing: this device's own.
    pub candidate: EndpointKey,
    /// The relay about to be dialled, as the invitation names it.
    pub relay_url: String,
}

/// The body of an admission request, in the one shape both representations come from.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAdmissionIssueBody {
    /// The endpoint being paired with.
    pub host_endpoint_key: EndpointKey,
    /// The endpoint that is pairing.
    pub candidate_endpoint_key: EndpointKey,
    /// The relay about to be dialled.
    pub relay_url: String,
}

impl RelayAdmissionIssueBody {
    /// Builds the body of one request.
    #[must_use]
    pub fn of(request: &AdmissionRequest) -> Self {
        Self {
            host_endpoint_key: request.host,
            candidate_endpoint_key: request.candidate,
            relay_url: request.relay_url.clone(),
        }
    }

    /// The bytes this body's digest is taken over.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the body cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> std::result::Result<Vec<u8>, kr_cbor::CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_ADMISSION_REQUEST_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// An admission the service issued and installed.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admitted {
    relay_url: String,
    relay_instance_id: String,
    expires_in_seconds: u64,
    byte_ceiling: U64,
}

/// Why no admission was issued, and what to do instead.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Unavailable {
    message: String,
    alternatives: Vec<String>,
    #[serde(default)]
    retry_after_seconds: Option<u64>,
}

/// The answer to an admission request, as the service tags it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum TaggedAnswer {
    Admitted(Admitted),
    NotNeeded,
    NotManaged,
    Unavailable(Unavailable),
}

/// What an admission request was answered with.
///
/// Five answers, and none is a failure of the request: an admission was issued; the pair needs none
/// because it holds a lease; the relay is not one the service carries traffic through; the service
/// cannot admit now, which section 17 reports as unavailable managed capacity with the paths that
/// still work and never as a failure of the host; or the service failed on its side and said so in
/// its own envelope.
#[derive(Clone, PartialEq, Eq)]
pub enum AdmissionAnswer {
    /// An admission is installed at the relay.
    Admitted {
        /// Seconds it lasts, at most, from the answer.
        expires_in_seconds: u64,
        /// The bytes it allows.
        byte_ceiling: u64,
    },
    /// The pair holds a lease, which decides it alone.
    NotNeeded,
    /// The relay is not the managed service's.
    NotManaged,
    /// The service cannot admit now.
    Unavailable {
        /// What happened, in English. Safe to display.
        message: String,
        /// Paths that still work: a direct connection, or a self-hosted relay. None when the cause
        /// is the service's own fault.
        alternatives: Vec<String>,
        /// Seconds after which the same request could succeed, when that is known.
        retry_after_seconds: Option<u64>,
    },
    /// The service refused in its own envelope with a status of the 5xx class: it failed on its
    /// side. An answer that is not its envelope, and an exchange that ended with no answer, are not
    /// this, because nothing in them says the service was reached.
    Faulted {
        /// The code the refusal maps to, which decides whether requests stop for a while.
        code: ErrorCode,
        /// Seconds after which the same request could succeed, when the refusal named them.
        retry_after_seconds: Option<u64>,
    },
}

impl std::fmt::Debug for AdmissionAnswer {
    /// Which answer, and nothing the service wrote.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admitted { .. } => formatter.write_str("AdmissionAnswer::Admitted"),
            Self::NotNeeded => formatter.write_str("AdmissionAnswer::NotNeeded"),
            Self::NotManaged => formatter.write_str("AdmissionAnswer::NotManaged"),
            Self::Unavailable { .. } => formatter.write_str("AdmissionAnswer::Unavailable"),
            Self::Faulted { .. } => formatter.write_str("AdmissionAnswer::Faulted"),
        }
    }
}

impl From<TaggedAnswer> for AdmissionAnswer {
    fn from(answer: TaggedAnswer) -> Self {
        match answer {
            TaggedAnswer::Admitted(admitted) => Self::Admitted {
                expires_in_seconds: admitted.expires_in_seconds,
                byte_ceiling: admitted.byte_ceiling.get(),
            },
            TaggedAnswer::NotNeeded => Self::NotNeeded,
            TaggedAnswer::NotManaged => Self::NotManaged,
            TaggedAnswer::Unavailable(unavailable) => Self::Unavailable {
                message: unavailable.message,
                alternatives: unavailable.alternatives,
                retry_after_seconds: unavailable.retry_after_seconds,
            },
        }
    }
}

/// Where pairing admissions are obtained.
pub trait PairingAdmissionService: Send + Sync + std::fmt::Debug {
    /// Asks for an admission for a pair of endpoints at one relay.
    fn admit<'a>(&'a self, request: &'a AdmissionRequest) -> ServiceFuture<'a, AdmissionAnswer>;
}

/// The managed pairing-admission client.
///
/// It speaks over the transport and the signer the lease client does, because it is the same kind
/// of caller with the same credential, and it never reads a body the service did not write.
#[derive(Clone, Debug)]
pub struct ManagedPairingAdmission {
    service: ManagedRelayLeaseService,
}

impl ManagedPairingAdmission {
    /// Builds a client against one gateway.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            service: ManagedRelayLeaseService::new(origin, http, signer),
        }
    }

    /// The same client, asking `gate` before it sends an admission request.
    #[must_use]
    pub fn gated_by(self, gate: Arc<ReleaseGate>) -> Self {
        Self {
            service: self.service.gated_by(gate),
        }
    }

    /// The origin this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        self.service.origin()
    }
}

impl PairingAdmissionService for ManagedPairingAdmission {
    fn admit<'a>(&'a self, request: &'a AdmissionRequest) -> ServiceFuture<'a, AdmissionAnswer> {
        Box::pin(async move {
            self.service.when_the_gate_is_open()?;
            let body = RelayAdmissionIssueBody::of(request);
            let signing_input = body.signing_input()?;
            let answer = self
                .service
                .post_signed(
                    RELAY_ADMISSION_PATH,
                    RELAY_ADMISSION_ISSUE_METHOD,
                    body,
                    signing_input,
                    None,
                )
                .await?;
            let data = match relay::data_of(&answer, RELAY_ADMISSION_ISSUE_METHOD) {
                Ok(data) => data,
                // A refusal in the service's envelope under a status of the 5xx class is the
                // service failing on its side. Only here is the status still known.
                Err(ClientError::Refused {
                    error,
                    retry_after_seconds,
                    ..
                }) if (500..600).contains(&answer.status) => {
                    return Ok(AdmissionAnswer::Faulted {
                        code: error.code,
                        retry_after_seconds,
                    });
                }
                Err(error) => return Err(error),
            };
            serde_json::from_value::<TaggedAnswer>(data)
                .map(AdmissionAnswer::from)
                .map_err(|_| {
                    // The service answered, so an admission may have been issued. A caller does not
                    // ask again blindly, and nothing about the answer is quoted.
                    relay::unreadable(200, "this client cannot read its admission answer")
                })
        })
    }
}

/// The clock the cache reads: the system's, moved forward by whatever a test adds.
///
/// Nothing in the product moves it. It exists so a test decides when a time in the cache passes
/// without waiting for it.
#[derive(Clone, Debug, Default)]
pub struct AdmissionClock {
    forward_ms: Arc<AtomicU64>,
}

impl AdmissionClock {
    /// The present moment.
    #[must_use]
    pub fn now(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.forward_ms.load(Ordering::SeqCst))
    }

    /// Moves this clock, and every clone of it, forward.
    pub fn advance(&self, by: Duration) {
        let milliseconds = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.forward_ms.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

/// One relay at which one host is reached.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    relay: String,
    host: EndpointKey,
}

/// What the cache holds of one answer.
#[derive(Clone, Debug)]
enum Held {
    /// Nothing has answered yet.
    Nothing,
    /// An admission is installed until then.
    Admitted { until: Instant },
    /// The service is unable, or failed on its side. `kept_until` is how long the answer explains
    /// a failed dial, and `retry_at` is when a dial asks again. `alternatives` is what the service
    /// named, with no entry for a fault; `retry_after_seconds` is the delay it named, as it named it.
    Unavailable {
        kept_until: Instant,
        retry_at: Instant,
        alternatives: Alternatives,
        retry_after_seconds: Option<u64>,
    },
    /// The pair holds a lease, or the relay is not the service's, until then.
    Needs { until: Instant },
    /// A request failed, and a dial asks again then.
    Failed { retry_at: Instant },
}

/// One entry of the cache.
#[derive(Clone, Debug)]
struct Entry {
    held: Held,
    /// Whether a request for this entry is on its way.
    pending: bool,
    /// When it was last asked, if it has been.
    asked_at: Option<Instant>,
    /// How many times it has been asked since a dial last connected.
    asks: u32,
    /// Whether a dial started since one last connected.
    in_doubt: bool,
}

impl Entry {
    const fn new() -> Self {
        Self {
            held: Held::Nothing,
            pending: false,
            asked_at: None,
            asks: 0,
            in_doubt: false,
        }
    }

    /// Whether the entry was last asked about [`ASK_WINDOW`] ago or longer.
    fn window_passed(&self, now: Instant) -> bool {
        self.asked_at
            .is_some_and(|asked| now.saturating_duration_since(asked) >= ASK_WINDOW)
    }

    /// Whether a dial that starts `now` asks for this entry again.
    fn asks_again(&self, now: Instant) -> bool {
        if self.pending || (self.asks >= MOST_ASKS && !self.window_passed(now)) {
            return false;
        }
        match self.held {
            Held::Nothing => true,
            Held::Admitted { until } => {
                now + ENDS_SOON >= until
                    || (self.in_doubt
                        && self.asked_at.is_some_and(|asked| {
                            now.saturating_duration_since(asked) >= DOUBT_AFTER
                        }))
            }
            Held::Unavailable { retry_at, .. } | Held::Failed { retry_at } => now >= retry_at,
            Held::Needs { until } => now >= until,
        }
    }
}

/// The cache's state.
#[derive(Default)]
struct State {
    entries: HashMap<Key, Entry>,
    /// Until when no request is made, because the service said it does not serve them.
    suspended_until: Option<Instant>,
}

/// The managed service's admissions for the relays a device dials, asked for as it dials.
///
/// See this module's note on what is kept and for how long.
#[derive(Clone)]
pub struct PairingAdmissions {
    service: Arc<dyn PairingAdmissionService>,
    origin: url::Url,
    clock: AdmissionClock,
    wait: Duration,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for PairingAdmissions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingAdmissions")
            .finish_non_exhaustive()
    }
}

impl PairingAdmissions {
    /// Admissions asked of `service`, for the relays that belong to the service at `origin`.
    ///
    /// # Errors
    ///
    /// Returns an error when `origin` is not a URL.
    pub fn new(
        service: Arc<dyn PairingAdmissionService>,
        origin: &GatewayOrigin,
    ) -> std::result::Result<Self, ClientError> {
        let origin = url::Url::parse(origin.as_str()).map_err(|_| {
            ClientError::refusal(
                ErrorCode::InvalidArgument,
                "the managed service's origin is not a URL".into(),
            )
        })?;
        Ok(Self {
            service,
            origin,
            clock: AdmissionClock::default(),
            wait: ANSWER_WAIT,
            state: Arc::new(Mutex::new(State::default())),
        })
    }

    /// The same, waiting `wait` for answers before a dial goes on without them. A test sets it.
    #[must_use]
    pub const fn waiting(mut self, wait: Duration) -> Self {
        self.wait = wait;
        self
    }

    /// The same, reading `clock`, so that a test can make time pass.
    #[must_use]
    pub fn on_clock(mut self, clock: AdmissionClock) -> Self {
        self.clock = clock;
        self
    }

    /// Whether `relay` is one of the managed service's, and may be named to it.
    ///
    /// Its host is the service's host, an address included, or a name under the service's own name
    /// by whole labels. Nothing else is ever sent to the service: a device pairing through a
    /// self-hosted relay tells the managed service nothing about it.
    #[must_use]
    pub fn belongs_to_the_service(&self, relay: &str) -> bool {
        let Ok(relay) = url::Url::parse(relay) else {
            return false;
        };
        match (relay.host(), self.origin.host()) {
            (Some(url::Host::Domain(relay)), Some(url::Host::Domain(origin))) => {
                let (relay, origin) = (relay.to_ascii_lowercase(), origin.to_ascii_lowercase());
                relay == origin || relay.ends_with(&format!(".{origin}"))
            }
            (Some(url::Host::Ipv4(relay)), Some(url::Host::Ipv4(origin))) => relay == origin,
            (Some(url::Host::Ipv6(relay)), Some(url::Host::Ipv6(origin))) => relay == origin,
            _ => false,
        }
    }

    /// The relays of `network` that are the service's, at most [`MOST_RELAYS_ASKED`], in order.
    fn relays_of(&self, network: &NetworkConfig) -> Vec<String> {
        network
            .relay_urls
            .iter()
            .map(|hint| hint.as_str().to_owned())
            .filter(|relay| self.belongs_to_the_service(relay))
            .take(MOST_RELAYS_ASKED)
            .collect()
    }

    /// The cache's key for the relay a dial addresses, which is the first of the host's relays.
    fn dialled_key(&self, network: &NetworkConfig, host: &EndpointKey) -> Option<Key> {
        let first = network.relay_urls.first()?.as_str();
        self.belongs_to_the_service(first).then(|| Key {
            relay: normalised(first),
            host: *host,
        })
    }

    /// Asks the service for an admission for each of the host's relays that is its own, and waits
    /// for the answers for a short bound, as a device starts to dial `host`.
    ///
    /// Nothing here can fail a dial: a service that is down, slow or refusing is the dial's own
    /// business to find out, and a request that has not answered by the bound goes on by itself and
    /// is kept for the next dial.
    pub async fn before_dial(
        &self,
        network: &NetworkConfig,
        host: &EndpointKey,
        candidate: EndpointKey,
    ) {
        let now = self.clock.now();
        let dialled = self.dialled_key(network, host);
        let mut started = Vec::new();

        for relay in self.relays_of(network) {
            let key = Key {
                relay: normalised(&relay),
                host: *host,
            };
            let asks = {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                let suspended = state.suspended_until.is_some_and(|until| now < until);
                let entry = state.entries.entry(key.clone()).or_insert_with(Entry::new);
                let ask = !suspended && entry.asks_again(now);
                if ask {
                    if entry.window_passed(now) {
                        entry.asks = 0;
                    }
                    entry.pending = true;
                    entry.asks += 1;
                    entry.asked_at = Some(now);
                }
                // A dial that starts is in doubt until one connects, whichever relay it addresses
                // and whether or not it asks now.
                if dialled.as_ref() == Some(&key) {
                    entry.in_doubt = true;
                }
                ask
            };
            if asks {
                let this = self.clone();
                let request = AdmissionRequest {
                    host: *host,
                    candidate,
                    relay_url: relay,
                };
                // A task of its own, so that a deadline that ends this dial does not end the
                // request: its answer is kept for the next one.
                started.push(tokio::spawn(async move { this.ask(key, request).await }));
            }
        }

        if !started.is_empty() {
            let _ = tokio::time::timeout(self.wait, futures_util::future::join_all(started)).await;
        }
    }

    /// Asks the service, and keeps what it answers.
    async fn ask(&self, key: Key, request: AdmissionRequest) {
        let answer = self.service.admit(&request).await;
        let now = self.clock.now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let refused = match &answer {
            Err(error) => Some(error.code()),
            Ok(AdmissionAnswer::Faulted { code, .. }) => Some(*code),
            Ok(_) => None,
        };
        if refused.is_some_and(|code| {
            matches!(
                code,
                ErrorCode::InvalidArgument
                    | ErrorCode::HostNotConfigured
                    | ErrorCode::PermissionDenied
            )
        }) {
            state.suspended_until = Some(now + SUSPEND);
        }
        let Some(entry) = state.entries.get_mut(&key) else {
            return;
        };
        entry.pending = false;
        entry.held = match answer {
            Ok(AdmissionAnswer::Admitted {
                expires_in_seconds, ..
            }) => Held::Admitted {
                until: now + named_time(expires_in_seconds),
            },
            Ok(AdmissionAnswer::NotNeeded) => Held::Needs {
                until: now + KEEP_NOT_NEEDED,
            },
            Ok(AdmissionAnswer::NotManaged) => Held::Needs {
                until: now + KEEP_NOT_MANAGED,
            },
            Ok(AdmissionAnswer::Unavailable {
                alternatives,
                retry_after_seconds,
                ..
            }) => Held::Unavailable {
                kept_until: now + kept_for(retry_after_seconds),
                retry_at: now + retry_after_seconds.map_or(DOUBT_AFTER, named_time),
                alternatives: Alternatives::named(alternatives),
                retry_after_seconds,
            },
            // Asked again as any other refusal is, and explained for as long as an unavailable
            // answer is.
            Ok(AdmissionAnswer::Faulted {
                retry_after_seconds,
                ..
            }) => Held::Unavailable {
                kept_until: now + kept_for(retry_after_seconds),
                retry_at: now + after_a_refusal(retry_after_seconds),
                alternatives: Alternatives::none(),
                retry_after_seconds,
            },
            Err(error) => Held::Failed {
                retry_at: now + retry_delay(&error),
            },
        };
    }

    /// Records that a dial to `host` connected: what the entry was doubtful about is settled.
    pub fn dial_succeeded(&self, network: &NetworkConfig, host: &EndpointKey) {
        let Some(key) = self.dialled_key(network, host) else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&key) {
            entry.in_doubt = false;
            entry.asks = 0;
        }
    }

    /// What the service's answer says a dial to `host` that failed was held back by, when it says
    /// anything and that answer still stands: no free capacity to admit this device through the
    /// relay the dial addresses, with the paths that still work and the delay it named, or a fault
    /// of the service itself.
    ///
    /// It decides what a dial that failed is reported as: a managed relay that cannot admit a
    /// device is not a host that cannot be reached.
    #[must_use]
    pub fn refusal(&self, network: &NetworkConfig, host: &EndpointKey) -> Option<RelayRefusal> {
        let key = self.dialled_key(network, host)?;
        let now = self.clock.now();
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = state.entries.get(&key)?;
        // An answer that the service is unable stands for as long as it explains a failed dial, and
        // for as long as the cache will not ask again (three requests with no connection, until the
        // ten minutes after the last), because nothing renews it while no request is made.
        match &entry.held {
            Held::Unavailable {
                kept_until,
                alternatives,
                retry_after_seconds,
                ..
            } if now < *kept_until || (entry.asks >= MOST_ASKS && !entry.window_passed(now)) => {
                Some(if alternatives.is_empty() {
                    RelayRefusal::Fault {
                        retry_after_seconds: *retry_after_seconds,
                    }
                } else {
                    RelayRefusal::Capacity {
                        alternatives: alternatives.clone(),
                        retry_after_seconds: *retry_after_seconds,
                    }
                })
            }
            _ => None,
        }
    }
}

/// What a standing answer of the managed service says a failed dial was held back by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayRefusal {
    /// The service has no managed capacity to admit this device through the relay now, and named
    /// the paths that still work.
    Capacity {
        /// The paths it named, each as it wrote it. Never empty.
        alternatives: Alternatives,
        /// Seconds after which the same request could succeed, as the service named them.
        retry_after_seconds: Option<u64>,
    },
    /// The service failed on its side, and no capacity was refused. An answer that names no path,
    /// and a refusal in its envelope under a status of the 5xx class, are this.
    Fault {
        /// Seconds after which the same request could succeed, when the answer named them.
        retry_after_seconds: Option<u64>,
    },
}

/// A relay's URL as the cache compares it: no trailing slash, scheme and host in lower case.
fn normalised(relay: &str) -> String {
    relay.trim_end_matches('/').to_ascii_lowercase()
}

/// A time the service names, in seconds, as the cache holds it.
fn named_time(seconds: u64) -> Duration {
    Duration::from_secs(seconds).min(LONGEST_NAMED)
}

/// How long after a failed request a dial asks again.
fn retry_delay(error: &ClientError) -> Duration {
    match error {
        ClientError::Refused {
            retry_after_seconds,
            ..
        } => after_a_refusal(*retry_after_seconds),
        _ => DOUBT_AFTER,
    }
}

/// How long after a refusal in the service's envelope a dial asks again: the wait it named, and not
/// less than [`DOUBT_AFTER`].
fn after_a_refusal(named: Option<u64>) -> Duration {
    named.map_or(DOUBT_AFTER, |seconds| named_time(seconds).max(DOUBT_AFTER))
}

/// How long an answer that the service is unable is kept: the delay it named, and at least
/// [`KEEP_UNAVAILABLE`].
fn kept_for(named: Option<u64>) -> Duration {
    named
        .map(named_time)
        .unwrap_or_default()
        .max(KEEP_UNAVAILABLE)
}
