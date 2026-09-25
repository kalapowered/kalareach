//! What the companion's suites share: this computer as a device on parts a test gives, and as the
//! owner device of kr-controller's in-process host.
//!
//! The parts are a secret store in memory rather than this computer's own, the host's room or a
//! test's, and endpoints on loopback. Each suite that uses this includes kr-controller's network
//! support as `net_support`.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use companion_tauri::device::{Device, Parts};
use companion_tauri::owner::{Owner, RequestView};
use kr_client::pairing::candidate::{AttemptState, CandidateRoom};
use kr_client::pairing::clock::DeviceClock;
use kr_client::pairing::paired::PairedHost;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, SecretStore, store_device_keys};
use kr_protocol::ids::DeviceKeyRevision;

use crate::net_support::Host;

/// How long a test waits for a step before it fails as stuck.
pub const WATCHDOG: Duration = Duration::from_secs(60);

pub fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("loopback")
}

/// Everything the page could have been sent, as the text it would have received.
#[derive(Default)]
pub struct Capture(Mutex<Vec<String>>);

impl Capture {
    pub fn keep(&self, value: &impl serde::Serialize) {
        self.0
            .lock()
            .expect("the capture")
            .push(serde_json::to_string(value).expect("serialises"));
    }

    pub fn texts(&self) -> Vec<String> {
        self.0.lock().expect("the capture").clone()
    }
}

/// A device on this test's parts, whose every change the capture keeps.
pub fn device(
    data: &std::path::Path,
    secrets: Arc<dyn SecretStore>,
    room: Arc<dyn CandidateRoom>,
    capture: &Arc<Capture>,
) -> Arc<Device> {
    device_in_boot(
        data,
        secrets,
        room,
        capture,
        DeviceClock::current().expect("a clock"),
    )
}

/// A device on this test's parts, running in the boot `clock` belongs to.
pub fn device_in_boot(
    data: &std::path::Path,
    secrets: Arc<dyn SecretStore>,
    room: Arc<dyn CandidateRoom>,
    capture: &Arc<Capture>,
    clock: DeviceClock,
) -> Arc<Device> {
    let held: Arc<OnceLock<Arc<Device>>> = Arc::new(OnceLock::new());
    let (seen, kept) = (Arc::clone(capture), Arc::clone(&held));
    let device = Device::with(
        data,
        Parts {
            secrets,
            room,
            bind: Some(loopback()),
            clock: Arc::new(clock),
        },
        move || {
            if let Some(device) = kept.get() {
                seen.keep(&device.view());
            }
        },
    )
    .expect("the device opens");
    let _ = held.set(Arc::clone(&device));
    device.start();
    device
}

/// Waits until the device's attempt reaches a state `until` accepts, or ends.
pub async fn reached(device: &Device, until: impl Fn(&AttemptState) -> bool) -> AttemptState {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = device.view().state;
            if until(&state) || matches!(state, AttemptState::Ended { .. }) {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the attempt gets there")
}

/// This computer as the host's owner device: the owner's keys in its store and its record of
/// the host.
pub fn owner_device(host: &Host, owner_keys: &DeviceKeys, data: &std::path::Path) -> Arc<Device> {
    owner_device_with(host, owner_keys, data, &Arc::new(Capture::default()))
}

/// The host's owner device, whose every change the capture keeps.
pub fn owner_device_with(
    host: &Host,
    owner_keys: &DeviceKeys,
    data: &std::path::Path,
    capture: &Arc<Capture>,
) -> Arc<Device> {
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    store_device_keys(&*secrets, "device", owner_keys).expect("the owner's keys are kept");
    let device = device(data, secrets, Arc::new(host.room.clone()), capture);
    record_owned(&device, host, "the test host");
    device
}

/// Records `host`, which was started with this computer's keys as its owner, as a host this
/// computer owns, named `name`.
pub fn record_owned(device: &Device, host: &Host, name: &str) {
    let record = host.owner.clone().expect("the owner device");
    let identity = host.network().pairing().identity();
    device
        .pairing()
        .hosts
        .record(PairedHost {
            host_device_id: identity.device_id,
            host_key_revision: DeviceKeyRevision::new(1),
            host_keys: identity.keys,
            host_endpoint_id: host.network().endpoint_id(),
            network_config: host.network().network_config().expect("the configuration"),
            device_id: record.device_id,
            grant_id: record.grant.grant_id,
            proposed_grant: kr_pairing::grants::personal_owner_grant(),
            name: Some(name.to_owned()),
            paired_at_ms: record.paired_at_ms.get(),
        })
        .expect("the host is recorded");
}

/// Whether this computer is in contact with the host named `name`, as the pairing screen shows it.
pub fn in_contact_with(device: &Device, name: &str) -> Option<bool> {
    device
        .view()
        .hosts
        .iter()
        .find(|host| host.name == name)
        .and_then(|host| host.in_contact)
}

/// A host this computer owns that takes its connection, completes the authorised handshake, and
/// then answers nothing, holding every connection open.
pub struct SilentHost {
    /// This computer's record of it.
    pub record: PairedHost,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    endpoint: iroh::Endpoint,
    serving: tokio::task::JoinHandle<()>,
}

/// The one device a silent host knows.
#[derive(Debug)]
struct OnlyDevice(kr_crypto::connect::PairedPeer);

impl kr_transport::handshake::PairedDirectory for OnlyDevice {
    fn paired_peer(
        &self,
        endpoint_id: &kr_protocol::scalars::EndpointKey,
    ) -> Option<kr_crypto::connect::PairedPeer> {
        (*endpoint_id == self.0.endpoint_id).then_some(self.0)
    }
}

impl SilentHost {
    /// Starts a silent host on the loopback network whose owner device holds `device_keys`.
    pub async fn start(device_keys: &DeviceKeys, name: &str) -> Self {
        use kr_protocol::ids::{BootEpoch, ClockEpoch, DeviceId, GrantId};
        use kr_transport::handshake::{Admitted, HostEpochs, LocalIdentity};

        let host_keys = DeviceKeys::generate().expect("keys");
        let config = kr_transport::config::EndpointConfig {
            bind_addr: Some(loopback()),
            ..kr_transport::config::EndpointConfig::default()
        };
        let endpoint = kr_transport::endpoint::bind_listener(&config, &host_keys.transport)
            .await
            .expect("a listening endpoint");
        let host_device_id = DeviceId::new(kr_ipc::new_uuid());
        let device_id = DeviceId::new(kr_ipc::new_uuid());
        let identity = Arc::new(LocalIdentity::new(
            host_device_id,
            DeviceKeyRevision::new(1),
            *host_keys.transport.public(),
            host_keys.authorisation.clone(),
            kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
        ));
        let directory = Arc::new(OnlyDevice(kr_crypto::connect::PairedPeer {
            device_id,
            device_key_revision: DeviceKeyRevision::new(1),
            authorisation: *device_keys.authorisation.public(),
            endpoint_id: *device_keys.transport.public(),
        }));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let serving = tokio::spawn({
            let (endpoint, accepted) = (endpoint.clone(), Arc::clone(&accepted));
            async move {
                let mut held = Vec::new();
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    let clock: Arc<dyn kr_transport::clock::ContinuousClock> =
                        Arc::new(kr_transport::clock::ManualClock::new());
                    let windows = kr_transport::window::ActionWindowIssuer::new(
                        clock,
                        kr_transport::window::MAX_WINDOW_VALIDITY,
                    );
                    let challenges = Arc::new(std::sync::Mutex::new(
                        kr_crypto::connect::ChallengeLedger::with_limit(16),
                    ));
                    let admitted = kr_transport::handshake::accept(
                        &connection,
                        &identity,
                        HostEpochs {
                            boot_epoch: BootEpoch::new(1),
                            clock_epoch: ClockEpoch::new(1),
                        },
                        directory.as_ref(),
                        &challenges,
                        &windows,
                    )
                    .await;
                    if let Ok(Admitted::Authorised(authorised)) = admitted {
                        accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // Kept, and never read: every question on it goes unanswered.
                        held.push((connection, authorised));
                    }
                }
            }
        });
        let mut network_config = config.to_network_config().expect("a configuration");
        network_config.direct_addresses = endpoint
            .bound_sockets()
            .into_iter()
            .map(|socket| {
                kr_protocol::pairing::NetworkHint::new(socket.to_string()).expect("a hint")
            })
            .collect();
        let record = PairedHost {
            host_device_id,
            host_key_revision: DeviceKeyRevision::new(1),
            host_keys: host_keys.public_keys(),
            host_endpoint_id: *host_keys.transport.public(),
            network_config,
            device_id,
            grant_id: GrantId::new(kr_ipc::new_uuid()),
            proposed_grant: kr_pairing::grants::personal_owner_grant(),
            name: Some(name.to_owned()),
            paired_at_ms: kr_ipc::now_ms().get(),
        };
        Self {
            record,
            accepted,
            endpoint,
            serving,
        }
    }

    /// Waits until this computer has completed `count` handshakes with the host.
    pub async fn accepted(&self, count: usize) {
        tokio::time::timeout(WATCHDOG, async {
            while self.accepted.load(std::sync::atomic::Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("this computer reached the silent host");
    }

    /// Stops the host.
    pub async fn stop(self) {
        self.serving.abort();
        self.endpoint.close().await;
    }
}

/// Whether this computer is in contact with the host it owns, as the pairing screen shows it.
pub fn owned_host_in_contact(device: &Device) -> Option<bool> {
    device
        .view()
        .hosts
        .iter()
        .find(|host| host.owner)
        .and_then(|host| host.in_contact)
}

/// Waits until the pairing screen shows the owned host `in_contact` or not.
pub async fn owned_host_shown(device: &Device, in_contact: bool) {
    tokio::time::timeout(WATCHDOG, async {
        while owned_host_in_contact(device) != Some(in_contact) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the owned host is shown so");
}

/// Waits until `owner` lists a request `matching` accepts, and returns it.
pub async fn listed(owner: &Owner, matching: impl Fn(&RequestView) -> bool) -> RequestView {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            if let Some(request) = owner.view().requests.into_iter().find(&matching) {
                return request;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the owner device lists the request")
}
