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
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    store_device_keys(&*secrets, "device", owner_keys).expect("the owner's keys are kept");
    let device = device(
        data,
        secrets,
        Arc::new(host.room.clone()),
        &Arc::new(Capture::default()),
    );
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
            name: Some("the test host".to_owned()),
            paired_at_ms: record.paired_at_ms.get(),
        })
        .expect("the host is recorded");
    device
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
