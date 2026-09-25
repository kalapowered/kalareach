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
        self.keep_text(serde_json::to_string(value).expect("serialises"));
    }

    /// Keeps text exactly as the page would receive it.
    pub fn keep_text(&self, text: impl Into<String>) {
        self.0.lock().expect("the capture").push(text.into());
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

/// A pasteboard and an alert a test controls: the text the pasteboard holds, and the answer the
/// person gives when an invitation names another service. It counts what it was asked.
#[derive(Debug, Default)]
pub struct StubPaste {
    text: Mutex<Option<String>>,
    accepts: std::sync::atomic::AtomicBool,
    /// The services the person was asked about, each with the one this computer is set to use.
    pub asked: Mutex<Vec<(String, String)>>,
}

impl StubPaste {
    /// A pasteboard holding `text`, whose person answers `accepts` when asked.
    pub fn holding(text: &str, accepts: bool) -> Arc<Self> {
        let stub = Self::default();
        *stub.text.lock().expect("the pasteboard") = Some(text.to_owned());
        stub.accepts
            .store(accepts, std::sync::atomic::Ordering::SeqCst);
        Arc::new(stub)
    }

    /// What the pasteboard holds now.
    pub fn held(&self) -> Option<String> {
        self.text.lock().expect("the pasteboard").clone()
    }

    /// Copies `text` to the pasteboard, and answers `accepts` from now on.
    pub fn copy(&self, text: &str, accepts: bool) {
        *self.text.lock().expect("the pasteboard") = Some(text.to_owned());
        self.accepts
            .store(accepts, std::sync::atomic::Ordering::SeqCst);
    }
}

impl companion_tauri::pairing::PastePlatform for StubPaste {
    fn text(&self) -> Option<String> {
        self.held()
    }

    fn clear(&self) -> bool {
        *self.text.lock().expect("the pasteboard") = None;
        true
    }

    fn use_another_service<'a>(
        &'a self,
        named: &'a kr_protocol::pairing::RendezvousOrigin,
        configured: &'a str,
    ) -> kr_client::pairing::BoxFuture<'a, bool> {
        self.asked
            .lock()
            .expect("the record")
            .push((named.as_str().to_owned(), configured.to_owned()));
        let accepts = self.accepts.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move { accepts })
    }
}

/// Where the bundle's pages are served from, which is where the page's calls come from.
#[cfg(windows)]
const BUNDLE: &str = "http://tauri.localhost";
#[cfg(not(windows))]
const BUNDLE: &str = "tauri://localhost";

/// This computer's companion backend on the mock runtime, made of a test's parts: the pairing
/// commands the application registers, called as the page calls them, and everything the page is
/// sent, as the page receives it: each command's answer or refusal, and each of the two events.
pub struct Companion {
    pub app: tauri::App<tauri::test::MockRuntime>,
    window: tauri::WebviewWindow<tauri::test::MockRuntime>,
    /// Each event the page was sent, as its payload.
    pub heard: Arc<Capture>,
    /// Each command's answer or refusal, as the page received it.
    pub answered: Arc<Capture>,
}

impl Companion {
    /// Starts the backend on `parts`, with its records under `data`, answering confirmations
    /// through `ceremony` and pasting through `paste`.
    pub fn start(
        data: &std::path::Path,
        parts: Parts,
        ceremony: Arc<dyn kr_client::pairing::owner::Ceremony>,
        paste: Arc<dyn companion_tauri::pairing::PastePlatform>,
    ) -> Self {
        use tauri::Listener as _;

        let app = tauri::test::mock_builder()
            .manage(companion_tauri::AppState::new())
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::pairing_set_origin,
                companion_tauri::commands::pairing_view,
                companion_tauri::commands::pairing_start_code,
                companion_tauri::commands::pairing_paste,
                companion_tauri::commands::pairing_start_read,
                companion_tauri::commands::pairing_stop,
                companion_tauri::commands::owner_confirmations,
                companion_tauri::commands::owner_confirmation_review,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("an application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        let heard = Arc::new(Capture::default());
        for event in [
            companion_tauri::pairing::PAIRING_EVENT,
            companion_tauri::pairing::CONFIRMATIONS_EVENT,
        ] {
            let heard = Arc::clone(&heard);
            app.listen_any(event, move |published| heard.keep_text(published.payload()));
        }
        companion_tauri::start_pairing(app.handle(), data, parts, ceremony, paste)
            .expect("this computer opens as a device that pairs");
        Self {
            app,
            window,
            heard,
            answered: Arc::new(Capture::default()),
        }
    }

    /// Everything the page was sent: every event and every answer.
    pub fn sent(&self) -> Vec<String> {
        let mut sent = self.heard.texts();
        sent.extend(self.answered.texts());
        sent
    }

    /// This computer as a device, for what a test does around the page.
    pub fn device(&self) -> Arc<Device> {
        use tauri::Manager as _;
        self.app
            .state::<companion_tauri::AppState>()
            .device()
            .expect("opened")
    }

    /// Calls `command` with `body` as the page does, through the invoke path, and returns what the
    /// page receives: the command's answer, or its refusal. Both are kept with what the page was
    /// sent.
    pub fn call(
        &self,
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, serde_json::Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let answered = tokio::task::block_in_place(|| {
            tauri::test::get_ipc_response(
                &self.window,
                tauri::webview::InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            )
        });
        match answered {
            Ok(answer) => {
                let answer: serde_json::Value =
                    answer.deserialize().expect("an answer the page can read");
                self.answered.keep(&answer);
                Ok(answer)
            }
            Err(refusal) => {
                self.answered.keep(&refusal);
                Err(refusal)
            }
        }
    }

    /// Asks for the pairing screen's state until `until` accepts it, as the page would read it.
    pub async fn reached(&self, until: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let view = self
                    .call("pairing_view", serde_json::json!({}))
                    .expect("the pairing screen's state");
                if until(&view["state"]) {
                    return view;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the attempt gets there")
    }

    /// Asks for the owner confirmations until one `matching` accepts is listed, and returns it.
    pub async fn listed(&self, matching: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let view = self
                    .call("owner_confirmations", serde_json::json!({}))
                    .expect("the confirmations");
                if let Some(request) = view["requests"]
                    .as_array()
                    .and_then(|requests| requests.iter().find(|request| matching(request)))
                {
                    return request.clone();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the owner device lists the request")
    }
}

/// The parts a test's device is made of: secrets in `secrets`, rooms through `room`, endpoints on
/// loopback, and this boot's clock.
pub fn parts(secrets: Arc<dyn SecretStore>, room: Arc<dyn CandidateRoom>) -> Parts {
    Parts {
        secrets,
        room,
        bind: Some(loopback()),
        clock: Arc::new(DeviceClock::current().expect("a clock")),
    }
}
