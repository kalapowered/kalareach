//! The relay a lease is installed on, and the endpoint that has to be at it.
//!
//! The service chooses the relay instance that carries a pair, installs the lease there, and names
//! it in the grant. A relay forwards for a pair only while it holds the pair's lease, so the pair's
//! traffic has to reach this host there: the host's home relay is the one a peer sends to, and iroh
//! chooses it by latency among the relays in the endpoint's map, keeping the one it has unless
//! another is much faster. A relay added to the map is therefore only a candidate. The keeper tells
//! the endpoint which relay its leases are installed on, and the endpoint is held to that relay
//! alone for as long as it is named, so that it is the home relay.
//!
//! The lease is the paid path the service chose, but it is never worth the host having no relay.
//! So the endpoint is moved in steps:
//!
//! * The leased relay is added beside the configured ones, and the configured ones are set aside
//!   only once the endpoint's own measurement has seen the leased relay answer.
//! * A relay that answers a measurement may still refuse the host a session. If the held relay
//!   fails to carry the endpoint for [`REACH_BOUND`], the configured relays come back, the lease
//!   stays held, and the leased relay is taken out of the endpoint's map, so that it cannot be
//!   chosen as the home relay, until a delay has passed. The delay doubles with each failure up to
//!   [`REACH_RETRY_LIMIT`] and starts again after a hold that connected.
//! * After the delay the relay is added beside the configured ones again, and the steps repeat.
//!
//! When no lease is held the endpoint is at the relays the configuration document listed.
//!
//! The configuration document stays the owner's choice of whether this host uses relays at all: an
//! endpoint that selected none is left as it is.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use iroh::{RelayConfig, RelayUrl, Watcher};
use kr_transport::config::EndpointConfig;

/// How long the leased relay may fail to carry the endpoint before the configured relays come back.
pub const REACH_BOUND: Duration = Duration::from_secs(30);

/// How long a relay that failed to carry the endpoint is left out of its map the first time.
pub const REACH_RETRY: Duration = Duration::from_secs(60);

/// The longest a relay that keeps failing is left out of the endpoint's map.
pub const REACH_RETRY_LIMIT: Duration = Duration::from_secs(15 * 60);

/// How soon the endpoint looks again at a relay it is waiting on.
const LOOK_AGAIN: Duration = Duration::from_secs(10);

/// What a look at the endpoint's relays found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Homing {
    /// When to look again, when the endpoint is waiting for a relay to answer or to stay down.
    pub look_again: Option<Duration>,
    /// Whether the relay the leases are installed on has not answered for [`REACH_BOUND`], so that
    /// the endpoint is at the configured relays while the leases are held.
    pub unreachable: bool,
}

/// The relays this host's endpoint connects to.
pub trait HomeRelays: Send + Sync {
    /// Has the endpoint's home relay be the relay at `leased`, the one this host's leases are
    /// installed on, or one of the relays its configuration lists when `leased` is none. `now` is
    /// the time the bound is counted on.
    fn home_on<'a>(
        &'a self,
        leased: Option<&'a str>,
        now: Instant,
    ) -> Pin<Box<dyn Future<Output = Homing> + Send + 'a>>;
}

/// Where the endpoint stands with the relay the leases are installed on.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    /// At the configured relays, with no leased relay named.
    Configured,
    /// The leased relay is in the map beside the configured ones, and not yet seen to answer.
    Waiting {
        relay: RelayUrl,
        /// Since when the endpoint has waited.
        since: Instant,
        /// When the endpoint was last asked to measure its relays again.
        nudged: Instant,
        /// How long the relay is left out of the map if the hold that follows fails.
        retry: Duration,
        /// Whether the relay failed to carry the endpoint before.
        failed: bool,
    },
    /// The map holds the leased relay alone.
    Held {
        relay: RelayUrl,
        /// Since when the relay has not carried the endpoint, when it has not.
        down_since: Option<Instant>,
        /// How long the relay is left out of the map if this hold fails.
        retry: Duration,
        /// Whether the relay failed to carry the endpoint before and has not carried it since.
        trouble: bool,
    },
    /// The relay failed to carry the endpoint: it is out of the map, which holds the configured
    /// relays, until `until`.
    Away {
        relay: RelayUrl,
        until: Instant,
        /// How long it is left out the next time it fails.
        retry: Duration,
    },
}

/// The relays of this host's own endpoint.
#[derive(Debug)]
pub struct EndpointRelays {
    endpoint: iroh::Endpoint,
    /// The relays the configuration document lists.
    configured: Vec<RelayUrl>,
    /// Lets one change of the endpoint's relays finish before the next begins.
    changing: tokio::sync::Mutex<()>,
    mode: Mutex<Mode>,
}

impl EndpointRelays {
    /// The relays of `endpoint`, which was built from `config`.
    #[must_use]
    pub fn new(endpoint: iroh::Endpoint, config: &EndpointConfig) -> Self {
        Self {
            endpoint,
            configured: config.relay_urls.clone(),
            changing: tokio::sync::Mutex::new(()),
            mode: Mutex::new(Mode::Configured),
        }
    }

    /// The relays the endpoint is at now: the one it is held to, or the ones the configuration
    /// lists. A peer is told these, because they are where this host is reached.
    #[must_use]
    pub fn selected(&self) -> Vec<RelayUrl> {
        match &*self.mode.lock().unwrap_or_else(PoisonError::into_inner) {
            Mode::Held { relay, .. } => vec![relay.clone()],
            Mode::Configured | Mode::Waiting { .. } | Mode::Away { .. } => self.configured.clone(),
        }
    }

    fn mode(&self) -> Mode {
        self.mode
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap_or_else(PoisonError::into_inner) = mode;
    }

    /// Puts `relay` in the endpoint's map, which also has the endpoint measure its relays again.
    async fn add(&self, relay: &RelayUrl) {
        self.endpoint
            .insert_relay(relay.clone(), Arc::new(RelayConfig::from(relay.clone())))
            .await;
    }

    async fn add_configured(&self) {
        for configured in &self.configured {
            self.add(configured).await;
        }
    }

    async fn remove_configured_but(&self, kept: &RelayUrl) {
        for configured in self.configured.iter().filter(|url| *url != kept) {
            self.endpoint.remove_relay(configured).await;
        }
    }

    async fn remove_unless_configured(&self, relay: &RelayUrl) {
        if !self.configured.contains(relay) {
            self.endpoint.remove_relay(relay).await;
        }
    }

    /// Takes a relay that failed to carry the endpoint out of its map, so that it cannot be chosen
    /// as the home relay, also when the configuration lists it, as long as another relay remains.
    async fn leave_out(&self, relay: &RelayUrl) {
        if self.configured.iter().any(|url| url != relay) || !self.configured.contains(relay) {
            self.endpoint.remove_relay(relay).await;
        }
    }

    /// Whether the endpoint's latest measurement of its relays saw `relay` answer.
    fn answered(&self, relay: &RelayUrl) -> bool {
        self.endpoint.net_report().get().is_some_and(|report| {
            report
                .relay_latency
                .iter()
                .any(|(_, measured, _)| measured == relay)
        })
    }

    /// Whether the endpoint is connected to `relay` as its home relay.
    fn connected(&self, relay: &RelayUrl) -> bool {
        self.endpoint
            .home_relay_status()
            .get()
            .iter()
            .any(|home| home.url() == relay && home.is_connected())
    }

    /// The endpoint waits beside the configured relays for `relay` to answer.
    async fn wait_for(&self, relay: RelayUrl, now: Instant, retry: Duration, failed: bool) {
        self.add_configured().await;
        self.add(&relay).await;
        self.set(Mode::Waiting {
            relay,
            since: now,
            nudged: now,
            retry,
            failed,
        });
    }

    async fn look(&self, target: Option<RelayUrl>, now: Instant) -> Homing {
        let looking = |unreachable| Homing {
            look_again: Some(LOOK_AGAIN),
            unreachable,
        };
        let Some(wanted) = target else {
            match self.mode() {
                Mode::Configured => {}
                Mode::Waiting { relay, .. }
                | Mode::Held { relay, .. }
                | Mode::Away { relay, .. } => {
                    self.add_configured().await;
                    self.remove_unless_configured(&relay).await;
                    self.set(Mode::Configured);
                }
            }
            return Homing::default();
        };
        match self.mode() {
            Mode::Configured => {
                self.wait_for(wanted, now, REACH_RETRY, false).await;
                looking(false)
            }
            Mode::Waiting { relay, .. } | Mode::Held { relay, .. } | Mode::Away { relay, .. }
                if relay != wanted =>
            {
                // The leases moved to another relay: the endpoint waits, beside the configured
                // relays, for the new one.
                self.wait_for(wanted, now, REACH_RETRY, false).await;
                self.remove_unless_configured(&relay).await;
                looking(false)
            }
            Mode::Waiting {
                relay,
                since,
                nudged,
                retry,
                failed,
            } => {
                if self.answered(&relay) {
                    self.remove_configured_but(&relay).await;
                    self.set(Mode::Held {
                        relay,
                        down_since: Some(now),
                        retry,
                        trouble: failed,
                    });
                    return looking(failed);
                }
                // The relay is in the map, so each full measurement of the endpoint's relays names
                // it when it answers. A relay that did not is measured again now and then.
                let nudged = if now.saturating_duration_since(nudged) >= REACH_BOUND {
                    self.add(&relay).await;
                    now
                } else {
                    nudged
                };
                let unreachable = failed || now.saturating_duration_since(since) >= REACH_BOUND;
                self.set(Mode::Waiting {
                    relay,
                    since,
                    nudged,
                    retry,
                    failed,
                });
                looking(unreachable)
            }
            Mode::Held {
                relay,
                down_since,
                retry,
                trouble,
            } => {
                if self.connected(&relay) {
                    // A relay that carried the endpoint starts the delays again.
                    self.set(Mode::Held {
                        relay,
                        down_since: None,
                        retry: REACH_RETRY,
                        trouble: false,
                    });
                    return looking(false);
                }
                let down = down_since.unwrap_or(now);
                if now.saturating_duration_since(down) >= REACH_BOUND {
                    // The leased relay does not carry the endpoint: the configured relays come
                    // back, and the leased relay is out of the map for a delay that grows.
                    self.add_configured().await;
                    self.leave_out(&relay).await;
                    self.set(Mode::Away {
                        relay,
                        until: now + retry,
                        retry: (retry * 2).min(REACH_RETRY_LIMIT),
                    });
                    return looking(true);
                }
                self.set(Mode::Held {
                    relay,
                    down_since: Some(down),
                    retry,
                    trouble,
                });
                looking(trouble)
            }
            Mode::Away {
                relay,
                until,
                retry,
            } => {
                if now >= until {
                    self.wait_for(relay, now, retry, true).await;
                    return looking(true);
                }
                self.set(Mode::Away {
                    relay,
                    until,
                    retry,
                });
                Homing {
                    look_again: Some(
                        until
                            .saturating_duration_since(now)
                            .clamp(Duration::from_secs(1), LOOK_AGAIN),
                    ),
                    unreachable: true,
                }
            }
        }
    }
}

impl HomeRelays for EndpointRelays {
    fn home_on<'a>(
        &'a self,
        leased: Option<&'a str>,
        now: Instant,
    ) -> Pin<Box<dyn Future<Output = Homing> + Send + 'a>> {
        Box::pin(async move {
            // No relay selected is a choice not to use one: nothing is connected to for a lease.
            if self.configured.is_empty() {
                return Homing::default();
            }
            let target = match leased.map(str::parse::<RelayUrl>) {
                None => None,
                Some(Ok(relay)) => Some(relay),
                Some(Err(_)) => {
                    eprintln!(
                        "kr-controller: the relay a lease names is not an address this host reads"
                    );
                    return Homing::default();
                }
            };
            let _changing = self.changing.lock().await;
            self.look(target, now).await
        })
    }
}
