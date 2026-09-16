//! Two paired endpoints, in one process.
//!
//! Every integration test in this crate needs the same thing: a host and a client that have
//! already paired, so the connection handshake has real records to check against. This builds that
//! pair, with the relay either disabled or pointed at a relay server running in the same process.

#![allow(dead_code)]

pub mod conditions;

use std::sync::Arc;

use iroh::{Endpoint, EndpointAddr};
use kr_crypto::connect::{ChallengeLedger, PairedPeer};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::ids::{BootEpoch, BuildId, ClockEpoch, DeviceId, DeviceKeyRevision};
use kr_protocol::scalars::{EndpointKey, Uuid};
use kr_transport::clock::{ContinuousClock, ManualClock};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};

/// One side of a paired pair.
pub struct Side {
    pub keys: DeviceKeys,
    pub identity: Arc<LocalIdentity>,
    pub endpoint: Endpoint,
    pub record: PairedPeer,
}

impl Side {
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }
}

/// A directory that knows exactly one paired endpoint.
#[derive(Debug)]
pub struct OneDevice {
    pub endpoint_id: EndpointKey,
    pub record: PairedPeer,
}

impl PairedDirectory for OneDevice {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.endpoint_id).then_some(self.record)
    }
}

/// A directory that knows nobody, so every endpoint is an unpaired candidate.
#[derive(Debug)]
pub struct NoDevices;

impl PairedDirectory for NoDevices {
    fn paired_peer(&self, _endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        None
    }
}

/// The host's boot and clock epochs for a test.
pub fn epochs() -> HostEpochs {
    HostEpochs {
        boot_epoch: BootEpoch::new(1),
        clock_epoch: ClockEpoch::new(1),
    }
}

/// A fresh challenge ledger.
pub fn ledger() -> Arc<std::sync::Mutex<ChallengeLedger>> {
    Arc::new(std::sync::Mutex::new(ChallengeLedger::with_limit(64)))
}

/// A fresh action-window issuer on a clock the test drives.
pub fn windows(clock: &ManualClock) -> Arc<ActionWindowIssuer> {
    let clock: Arc<dyn ContinuousClock> = Arc::new(clock.clone());
    Arc::new(ActionWindowIssuer::new(clock, MAX_WINDOW_VALIDITY))
}

/// Builds one side: fresh device keys, an endpoint and the record the other side will hold.
pub async fn side(config: &EndpointConfig, device_byte: u8, listening: bool) -> Side {
    let keys = DeviceKeys::generate().expect("device keys");
    let endpoint = if listening {
        kr_transport::endpoint::bind_listener(config, &keys.transport)
            .await
            .expect("a listening endpoint")
    } else {
        kr_transport::endpoint::bind_dialer(config, &keys.transport)
            .await
            .expect("a dialling endpoint")
    };
    let device_id = DeviceId::new(Uuid::from_bytes([device_byte; 16]));
    let device_key_revision = DeviceKeyRevision::new(1);
    let endpoint_id = *keys.transport.public();
    let record = PairedPeer {
        device_id,
        device_key_revision,
        authorisation: *keys.authorisation.public(),
        endpoint_id,
    };
    let identity = Arc::new(LocalIdentity::new(
        device_id,
        device_key_revision,
        endpoint_id,
        keys.authorisation.clone(),
        BuildId::new("kr/0.1.0+test").expect("a build identity"),
    ));
    Side {
        keys,
        identity,
        endpoint,
        record,
    }
}

/// A paired host and client with relaying disabled: the two endpoints talk over loopback.
pub async fn paired_pair() -> (Side, Side) {
    let config = EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    };
    let host = side(&config, 1, true).await;
    let client = side(&config, 2, false).await;
    (host, client)
}

/// The address of a host reachable over loopback, with no relay and no discovery.
pub fn direct_addr(side: &Side) -> EndpointAddr {
    let mut addr = EndpointAddr::new(side.endpoint.id());
    for socket in side.endpoint.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/// A relay server running in this process, with the trust anchor a client needs for it.
///
/// `iroh::test_utils::run_relay_server` discards the certificate it generated, and a client that
/// cannot verify the relay's HTTPS certificate never reaches it. This spawns the same server and
/// keeps the certificate, which is also how a self-hosted deployment with a private authority
/// works: the certificate is pinned as an extra trust anchor.
pub struct LocalRelay {
    pub url: iroh::RelayUrl,
    pub ca_roots: Vec<Vec<u8>>,
    _server: iroh_relay::server::Server,
}

impl LocalRelay {
    pub async fn spawn() -> Self {
        use std::net::Ipv4Addr;

        use iroh_relay::server::{
            CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server, ServerConfig,
            TlsConfig,
        };

        let (certs, server_config) =
            iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let tls = TlsConfig::new(
            (Ipv4Addr::LOCALHOST, 0),
            CertConfig::Manual { server_config },
        );
        let mut relay = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.tls = Some(tls);
        relay.key_cache_capacity = Some(1024);

        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));

        let server = Server::spawn(config).await.expect("a relay server");
        let url: iroh::RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
            .parse()
            .expect("a relay URL");
        Self {
            url,
            ca_roots: certs.into_iter().map(|cert| cert.to_vec()).collect(),
            _server: server,
        }
    }
}
