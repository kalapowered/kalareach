//! The device's one endpoint, and the hosts it dials through it.
//!
//! A device that dials several hosts keeps one endpoint for all of them. No rule of this endpoint
//! refuses, closes or restarts the connection of one host on account of a request for another.
//! Separate endpoints of one identity that share a relay cannot promise that, because the relay
//! deactivates the older connection of an identity that connects again.
//!
//! The transport library limits that, at the release that core takes: its one relay actor serves
//! every relay of an endpoint and reads a datagram to send only while no send of its own is
//! pending, so a relay that stops reading can hold the sends to every relay until the library's own
//! time-outs end the hold.
//!
//! The endpoint is built with no relay and no discovery service. It takes them one host at a time,
//! when the device first dials that host:
//!
//! * a host's address lookups, its Pkarr resolver and its DNS origin, are registered under the
//!   host's endpoint identity in one dispatcher, and a lookup is asked about that identity and no
//!   other. An identity that no host owns gets no answer and no outside request.
//! * a paired host's relays enter the endpoint's relay map. An invited host's relays do not: they
//!   stay out of the map until the pairing completes, and a dial reaches the relay its address
//!   names without it.
//!
//! The endpoint publishes nothing. A [`HostServices`] has no publisher, so a host's configuration
//! cannot turn a publication on, and the dispatcher takes none.
//!
//! The table of hosts changes at the call, in the order of the calls. The relay map follows it: a
//! change that alters a host's relays starts one task that sets the map equal to the table, and the
//! caller waits for that task. A caller that stops waiting leaves the task to finish, and a task
//! that runs late sets the map to the table as it then stands, so an earlier introduction never
//! puts back what a later `forget` took out.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use futures::StreamExt as _;
use iroh::address_lookup::{
    AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, DnsAddressLookup,
    Error as LookupError, Item,
};
use iroh::{Endpoint, EndpointId, PublicKey, RelayConfig, RelayMap, RelayUrl};
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::scalars::EndpointKey;

use crate::config::{EndpointConfig, ProxyUrl, Url};
use crate::error::{Result, TransportError};

/// What the device knows of one host's network services, and nothing else.
///
/// There is no publisher among them: the device publishes its own record to no server, whatever
/// the host's configuration names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostServices {
    identity: EndpointId,
    relays: BTreeSet<RelayUrl>,
    pkarr_resolver: Option<Url>,
    dns_origin: Option<String>,
}

impl HostServices {
    /// The services of a paired host: its relays go into the endpoint's relay map when it is
    /// introduced, and its resolver and DNS origin are asked about its identity.
    ///
    /// The configuration's Pkarr publisher, local discovery, DHT, bind address, proxy and trust
    /// roots are ignored: they are this device's own choices, and the endpoint holds them.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] when `identity` is not a public key.
    pub fn paired(config: &EndpointConfig, identity: &EndpointKey) -> Result<Self> {
        Self::from_config(config, identity, true)
    }

    /// The services of a host that a pairing invitation named and that is not paired yet: its
    /// resolver and DNS origin are asked about its identity, and its relays stay out of the map
    /// until the pairing completes and the host is introduced again as paired.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] when `identity` is not a public key.
    pub fn invited(config: &EndpointConfig, identity: &EndpointKey) -> Result<Self> {
        Self::from_config(config, identity, false)
    }

    fn from_config(
        config: &EndpointConfig,
        identity: &EndpointKey,
        relays_enter_the_map: bool,
    ) -> Result<Self> {
        Ok(Self {
            identity: endpoint_id(identity)?,
            relays: if relays_enter_the_map {
                config.relay_urls.iter().cloned().collect()
            } else {
                BTreeSet::new()
            },
            pkarr_resolver: config.discovery.pkarr_resolver_url.clone(),
            dns_origin: config.discovery.dns_origin.clone(),
        })
    }

    /// The host's endpoint identity.
    #[must_use]
    pub fn identity(&self) -> EndpointId {
        self.identity
    }

    /// The relays this host puts into the endpoint's relay map.
    #[must_use]
    pub fn relays(&self) -> &BTreeSet<RelayUrl> {
        &self.relays
    }
}

/// One host in the table: its services and the address lookups built from them.
#[derive(Debug)]
struct Host {
    services: HostServices,
    lookups: Vec<Arc<dyn AddressLookup>>,
}

/// Every host the device has introduced and not forgotten, by endpoint identity.
#[derive(Debug, Default)]
struct Table {
    hosts: BTreeMap<EndpointId, Host>,
}

impl Table {
    /// The relays that the hosts of the table put into the map: each of them, once.
    fn wanted_relays(&self) -> BTreeSet<RelayUrl> {
        self.hosts
            .values()
            .flat_map(|host| host.services.relays.iter().cloned())
            .collect()
    }
}

/// What the endpoint, the dispatcher and the tasks that set the relay map share.
#[derive(Debug, Default)]
struct Shared {
    /// The hosts. Held only for a change of the table or a read of it, never across a wait, so the
    /// table is in the order of the calls whatever the callers do afterwards.
    table: Mutex<Table>,
    /// Held by the task that sets the relay map equal to the table, from the moment it reads the
    /// table to the moment it has changed the map, so two such tasks never interleave.
    turn: tokio::sync::Mutex<()>,
    #[cfg(feature = "testing")]
    gate: gate::Gate,
}

impl Shared {
    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The endpoint's one address lookup. It answers for an identity that a host owns, with that host's
/// own lookups, and for no other.
///
/// It implements no `publish`, so the publications that the endpoint hands to every registered
/// lookup reach nothing.
#[derive(Debug)]
struct Dispatcher {
    shared: Arc<Shared>,
}

impl AddressLookup for Dispatcher {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<futures::stream::BoxStream<'static, std::result::Result<Item, LookupError>>> {
        let lookups = self
            .shared
            .table()
            .hosts
            .get(&endpoint_id)
            .map(|host| host.lookups.clone())?;
        let streams: Vec<_> = lookups
            .iter()
            .filter_map(|lookup| lookup.resolve(endpoint_id))
            .collect();
        if streams.is_empty() {
            return None;
        }
        Some(futures::stream::select_all(streams).boxed())
    }
}

/// The device's endpoint, with the hosts that it has been introduced to.
pub struct DeviceEndpoint {
    endpoint: Endpoint,
    /// The relay map that the endpoint was given. It is the endpoint's own: the endpoint's relay
    /// transport and its `insert_relay` and `remove_relay` use this one shared map, and the
    /// library has no accessor that returns the map of a bound endpoint.
    relay_map: RelayMap,
    /// The proxy of the bind's configuration, which each host's record resolver goes through.
    proxy: Option<ProxyUrl>,
    shared: Arc<Shared>,
}

impl DeviceEndpoint {
    /// Binds the device's endpoint: a dialler with an empty relay map and no address lookup but
    /// the dispatcher, which holds nothing until a host is introduced.
    ///
    /// The configuration may name an IP transport choice, a bind address, extra trust roots and a
    /// proxy. It may not name a relay or a discovery service: those come only from hosts.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] when the configuration names a relay or a
    /// discovery service, or as [`crate::endpoint::bind_dialer`] does, and
    /// [`TransportError::Bind`] when the socket cannot be bound.
    pub async fn bind(
        config: &EndpointConfig,
        identity: &TransportIdentityKeyPair,
    ) -> Result<Self> {
        Self::bind_with(config, identity, None).await
    }

    /// Binds the device's endpoint, as [`Self::bind`] does, looking every name up through the one
    /// name server `name_server` and through no other.
    ///
    /// For this crate's own tests, as [`crate::endpoint::bind_dialer_asking`] is.
    ///
    /// # Errors
    ///
    /// As [`Self::bind`].
    #[cfg(feature = "testing")]
    pub async fn bind_asking(
        config: &EndpointConfig,
        identity: &TransportIdentityKeyPair,
        name_server: std::net::SocketAddr,
    ) -> Result<Self> {
        Self::bind_with(config, identity, Some(name_server)).await
    }

    async fn bind_with(
        config: &EndpointConfig,
        identity: &TransportIdentityKeyPair,
        name_server: Option<std::net::SocketAddr>,
    ) -> Result<Self> {
        if !config.relay_urls.is_empty() || !config.discovery.is_empty() {
            return Err(TransportError::Configuration {
                what: "the device endpoint's configuration".to_owned(),
                kind: "device endpoint",
                reason: "it names a relay or a discovery service, which a host brings when the \
                         device first dials it"
                    .to_owned(),
            });
        }
        let config = EndpointConfig {
            relays_added_on_dial: true,
            ..config.clone()
        };
        let (endpoint, relay_map) =
            crate::endpoint::bind_sharing_map(&config, identity, false, name_server).await?;
        let shared = Arc::new(Shared::default());
        endpoint
            .address_lookup()
            .map_err(|_| closed())?
            .add(Dispatcher {
                shared: Arc::clone(&shared),
            });
        Ok(Self {
            endpoint,
            relay_map,
            proxy: config.proxy_url,
            shared,
        })
    }

    /// The endpoint to dial from.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The relays in the endpoint's relay map now.
    #[must_use]
    pub fn relay_urls(&self) -> BTreeSet<RelayUrl> {
        self.relay_map.urls()
    }

    /// Introduces a host: its lookups are registered under its identity and its relays go into the
    /// relay map, replacing what an earlier introduction of the same identity put there.
    ///
    /// Introducing equal services again changes nothing. A call that alters the host's relays
    /// returns when the map holds them. A caller that stops waiting leaves the change to finish.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Bind`] when the endpoint is closed, and
    /// [`TransportError::Configuration`] when a lookup cannot be built from the services. The table
    /// and the map are then as they were.
    pub async fn introduce(&self, services: HostServices) -> Result<()> {
        if self.endpoint.is_closed() {
            return Err(closed());
        }
        let relays_changed = {
            let mut table = self.shared.table();
            let before = match table.hosts.get(&services.identity) {
                Some(host) if host.services == services => return Ok(()),
                Some(host) => host.services.relays.clone(),
                None => BTreeSet::new(),
            };
            let lookups = self.lookups_of(&services)?;
            let relays_changed = before != services.relays;
            table
                .hosts
                .insert(services.identity, Host { services, lookups });
            relays_changed
        };
        if relays_changed {
            self.set_the_map().await
        } else {
            Ok(())
        }
    }

    /// Forgets a host: its lookups leave the dispatcher, and each relay of its entry that no other
    /// host names leaves the map. Nothing else changes: a connection to the host stays open until
    /// whoever holds it closes it.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Configuration`] when `identity` is not a public key.
    pub async fn forget(&self, identity: &EndpointKey) -> Result<()> {
        let identity = endpoint_id(identity)?;
        let had_relays = self
            .shared
            .table()
            .hosts
            .remove(&identity)
            .is_some_and(|host| !host.services.relays.is_empty());
        if had_relays {
            self.set_the_map().await
        } else {
            Ok(())
        }
    }

    /// Closes the endpoint.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    /// Builds a host's address lookups from the endpoint's own resolver and trust, and the bind's
    /// proxy for the record resolver.
    fn lookups_of(&self, services: &HostServices) -> Result<Vec<Arc<dyn AddressLookup>>> {
        let mut lookups: Vec<Arc<dyn AddressLookup>> = Vec::new();
        if let Some(server) = &services.pkarr_resolver {
            let lookup = crate::pkarr::Resolver {
                server: server.clone(),
                proxy: self.proxy.clone(),
            }
            .into_address_lookup(&self.endpoint)
            .map_err(lookup_error)?;
            lookups.push(Arc::new(lookup));
        }
        if let Some(origin) = &services.dns_origin {
            let lookup = DnsAddressLookup::builder(origin.clone())
                .into_address_lookup(&self.endpoint)
                .map_err(lookup_error)?;
            lookups.push(Arc::new(lookup));
        }
        Ok(lookups)
    }

    /// Starts the task that sets the relay map equal to the table, and waits for it.
    ///
    /// The map is changed by a task that no caller's drop reaches: the library changes its map at
    /// once and then awaits a send to its relay actor, so a caller that stopped after its first
    /// poll would leave the map changed and the actor not told.
    async fn set_the_map(&self) -> Result<()> {
        tokio::spawn(set_map_to_table(
            Arc::clone(&self.shared),
            self.endpoint.clone(),
            self.relay_map.clone(),
        ))
        .await
        .map_err(|error| {
            TransportError::Bind(format!(
                "the device endpoint's relay map was not set: {error}"
            ))
        })
    }
}

/// Sets the endpoint's relay map equal to the table as the table stands once this task has its
/// turn, inserting what the map lacks and removing what no host names.
async fn set_map_to_table(shared: Arc<Shared>, endpoint: Endpoint, relay_map: RelayMap) {
    #[cfg(feature = "testing")]
    let held = shared.gate.pass().await;
    let _turn = shared.turn.lock().await;
    let wanted = shared.table().wanted_relays();
    let present: BTreeSet<RelayUrl> = relay_map.urls();
    for url in present.difference(&wanted) {
        endpoint.remove_relay(url).await;
    }
    for url in wanted.difference(&present) {
        endpoint
            .insert_relay(url.clone(), Arc::new(RelayConfig::from(url.clone())))
            .await;
    }
    #[cfg(feature = "testing")]
    if let Some(held) = held {
        held.ended();
    }
}

/// The key of a host as the library's endpoint identity.
fn endpoint_id(identity: &EndpointKey) -> Result<EndpointId> {
    PublicKey::from_bytes(identity.as_bytes()).map_err(|error| TransportError::Configuration {
        what: kr_protocol::scalars::to_base64url(identity.as_bytes()),
        kind: "endpoint identity",
        reason: error.to_string(),
    })
}

/// The error of a request on an endpoint that is closed.
fn closed() -> TransportError {
    TransportError::Bind("the device endpoint is closed".to_owned())
}

fn lookup_error(error: AddressLookupBuilderError) -> TransportError {
    match error {
        AddressLookupBuilderError::EndpointClosed { .. } => closed(),
        other => TransportError::Configuration {
            what: "a host's address lookup".to_owned(),
            kind: "address lookup",
            reason: other.to_string(),
        },
    }
}

/// A hold that a test puts on the task that sets the relay map, so that the order of the map's
/// changes and the end of a caller that stopped waiting can be tested at a moment of the test's
/// choosing.
#[cfg(feature = "testing")]
mod gate {
    use std::sync::{Mutex, PoisonError};

    use tokio::sync::oneshot;

    /// The one hold that is armed, if any: the next task to reach the gate takes it.
    #[derive(Debug, Default)]
    pub(super) struct Gate(Mutex<Option<Armed>>);

    #[derive(Debug)]
    struct Armed {
        reached: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
        ended: oneshot::Sender<()>,
    }

    /// A task that the gate holds.
    pub(super) struct Held(oneshot::Sender<()>);

    impl Held {
        /// Says that the held task has done its work.
        pub(super) fn ended(self) {
            let _ = self.0.send(());
        }
    }

    impl Gate {
        /// Holds the calling task if a hold is armed, and returns what ends the hold's wait for it.
        pub(super) async fn pass(&self) -> Option<Held> {
            let armed = self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()?;
            let _ = armed.reached.send(());
            let _ = armed.release.await;
            Some(Held(armed.ended))
        }

        pub(super) fn arm(&self) -> super::ReconcileHold {
            let (reached, reaching) = oneshot::channel();
            let (release, releasing) = oneshot::channel();
            let (ended, ending) = oneshot::channel();
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(Armed {
                reached,
                release: releasing,
                ended,
            });
            super::ReconcileHold {
                reached: reaching,
                release,
                ended: ending,
            }
        }
    }
}

/// The hold on the next task that sets the relay map, which [`DeviceEndpoint::hold_next_map_task`]
/// arms.
#[cfg(feature = "testing")]
pub struct ReconcileHold {
    reached: tokio::sync::oneshot::Receiver<()>,
    release: tokio::sync::oneshot::Sender<()>,
    ended: tokio::sync::oneshot::Receiver<()>,
}

/// How long a wait on a hold may take before it is a failure. The held task has the shared lock and
/// one change of the map to make, on this machine, so this is a bound on a fault and not a time
/// that anything is expected to take.
#[cfg(feature = "testing")]
const HOLD_PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(feature = "testing")]
impl ReconcileHold {
    /// Waits until a task is held at the gate, before it has taken its turn or read the table.
    ///
    /// # Panics
    ///
    /// Panics when no task reaches the gate within the bound, and when the gate dropped this hold,
    /// which a second hold armed over it does.
    pub async fn reached(&mut self) {
        match tokio::time::timeout(HOLD_PATIENCE, &mut self.reached).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => panic!("the gate dropped the hold before a task reached it"),
            Err(_) => panic!("no task reached the hold within {HOLD_PATIENCE:?}"),
        }
    }

    /// Lets the held task go on, and waits until it has changed the map and ended.
    ///
    /// # Panics
    ///
    /// Panics when the gate dropped this hold, when the held task ends without saying so, and when
    /// the task does not end within the bound.
    pub async fn release(self) {
        assert!(
            self.release.send(()).is_ok(),
            "the gate dropped the hold before it was released"
        );
        match tokio::time::timeout(HOLD_PATIENCE, self.ended).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => panic!("the held task ended without finishing its change of the map"),
            Err(_) => panic!("the held task did not end within {HOLD_PATIENCE:?}"),
        }
    }
}

#[cfg(feature = "testing")]
impl DeviceEndpoint {
    /// Arms a hold on the next task that sets the relay map: that task stops before it takes its
    /// turn, so it blocks no other task, and goes on when the hold is released.
    ///
    /// For this crate's own tests, as the pool's close gate is for the pool's.
    #[must_use]
    pub fn hold_next_map_task(&self) -> ReconcileHold {
        self.shared.gate.arm()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::EndpointKey;

    fn key() -> EndpointKey {
        *TransportIdentityKeyPair::generate()
            .expect("a transport identity")
            .public()
    }

    fn full_config() -> EndpointConfig {
        EndpointConfig {
            relay_urls: vec!["https://relay.kala.to".parse().expect("a relay URL")],
            discovery: crate::config::DiscoveryConfig {
                pkarr_publisher_url: Some(Url::parse("https://publish.kala.to").expect("a URL")),
                pkarr_resolver_url: Some(Url::parse("https://resolve.kala.to").expect("a URL")),
                dns_origin: Some("dns.kala.to".to_owned()),
                local_discovery: true,
                mainline_dht: true,
                ..crate::config::DiscoveryConfig::default()
            },
            bind_addr: Some("127.0.0.1:0".parse().expect("an address")),
            relay_ca_roots: vec![vec![1, 2, 3]],
            proxy_url: Some("http://127.0.0.1:3128".parse().expect("a proxy")),
            ..EndpointConfig::default()
        }
    }

    /// KR-REQ-10.02: what a host's services hold is its relays, its resolver and its DNS origin.
    /// The publisher, local discovery, the DHT and the device's own bind address, trust and proxy
    /// that its configuration carried change nothing.
    #[test]
    fn a_hosts_services_ignore_everything_but_its_relays_and_resolvers() {
        let key = key();
        let mut plain = full_config();
        plain.discovery.pkarr_publisher_url = None;
        plain.discovery.local_discovery = false;
        plain.discovery.mainline_dht = false;
        plain.bind_addr = None;
        plain.relay_ca_roots = Vec::new();
        plain.proxy_url = None;
        assert_eq!(
            HostServices::paired(&full_config(), &key).expect("a paired host"),
            HostServices::paired(&plain, &key).expect("a paired host"),
        );
    }

    /// KR-REQ-10.02: an invited host's relays stay out of the map until it is paired, and its
    /// lookups are the same as a paired host's.
    #[test]
    fn an_invited_host_puts_no_relay_into_the_map() {
        let key = key();
        let paired = HostServices::paired(&full_config(), &key).expect("a paired host");
        let invited = HostServices::invited(&full_config(), &key).expect("an invited host");
        assert_eq!(paired.relays().len(), 1);
        assert!(invited.relays().is_empty());
        assert_eq!(paired.pkarr_resolver, invited.pkarr_resolver);
        assert_eq!(paired.dns_origin, invited.dns_origin);
        assert_eq!(paired.identity(), invited.identity());
    }

    /// KR-REQ-10.02: the device's endpoint takes its relays and lookups from hosts alone, so a
    /// configuration that names one is refused before anything is bound.
    #[tokio::test]
    async fn a_device_endpoint_refuses_a_configuration_that_names_a_service() {
        let identity = TransportIdentityKeyPair::generate().expect("a transport identity");
        let named_relay = EndpointConfig {
            relay_urls: vec!["https://relay.kala.to".parse().expect("a relay URL")],
            ..EndpointConfig::default()
        };
        let named_lookup = EndpointConfig {
            discovery: crate::config::DiscoveryConfig {
                dns_origin: Some("dns.kala.to".to_owned()),
                ..crate::config::DiscoveryConfig::default()
            },
            ..EndpointConfig::default()
        };
        for config in [named_relay, named_lookup] {
            assert!(matches!(
                DeviceEndpoint::bind(&config, &identity).await,
                Err(TransportError::Configuration {
                    kind: "device endpoint",
                    ..
                })
            ));
        }
    }
}
