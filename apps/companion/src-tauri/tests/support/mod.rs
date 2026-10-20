//! What the companion's suites share: this computer as a device on parts a test gives, and as the
//! owner device of kr-controller's in-process host.
//!
//! The parts are a secret store in memory rather than this computer's own, the host's room or a
//! test's, and endpoints on loopback. Each suite that uses this includes kr-controller's network
//! support as `net_support`.

#![allow(dead_code)]

pub mod call;

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

use crate::net_support::pairing::{self as calls, Signer};
use crate::net_support::{Host, proposal};
use kr_client::pairing::BoxFuture;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
use kr_protocol::rights::ActionRight;
use serde_json::json;

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
            link: None,
            managed: None,
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
    /// Each change of an opened session's standing, as its event reached the page.
    pub standing: Arc<Capture>,
    /// Every state each channel a command was given was sent.
    pub channels: Arc<Mutex<std::collections::BTreeMap<u32, Vec<serde_json::Value>>>>,
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
        Self::start_with_voice(
            data,
            parts,
            ceremony,
            paste,
            companion_tauri::voice::Calls::absent(),
            companion_tauri::account::AccountSlot::new(Box::new(|| {
                Box::pin(async { Err("no account runs in this suite".to_owned()) })
            })),
        )
    }

    /// Starts the backend as [`Self::start`] does, holding the voice calls `calls` and the account
    /// `account`.
    pub fn start_with_voice(
        data: &std::path::Path,
        parts: Parts,
        ceremony: Arc<dyn kr_client::pairing::owner::Ceremony>,
        paste: Arc<dyn companion_tauri::pairing::PastePlatform>,
        calls: companion_tauri::voice::Calls,
        account: companion_tauri::account::AccountSlot,
    ) -> Self {
        use tauri::Listener as _;

        let state = companion_tauri::AppState::new();
        state.keep_under(data);
        let channels: Arc<Mutex<std::collections::BTreeMap<u32, Vec<serde_json::Value>>>> =
            Arc::default();
        let heard_on_channels = Arc::clone(&channels);
        let builder = tauri::test::mock_builder()
            .manage(state)
            .manage(calls)
            .manage(account)
            .manage(companion_tauri::agent::WorkerLinks::local())
            .channel_interceptor(move |_webview, callback, _index, body| {
                if let tauri::ipc::InvokeResponseBody::Json(json) = body {
                    let state: serde_json::Value =
                        serde_json::from_str(json).expect("a state the page reads");
                    heard_on_channels
                        .lock()
                        .expect("the record")
                        .entry(callback.0)
                        .or_default()
                        .push(state);
                }
                true
            })
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::question_read,
                companion_tauri::commands::question_answer,
                companion_tauri::commands::question_kept,
                companion_tauri::commands::pairing_set_origin,
                companion_tauri::commands::pairing_view,
                companion_tauri::commands::pairing_start_code,
                companion_tauri::commands::pairing_paste,
                companion_tauri::commands::pairing_start_read,
                companion_tauri::commands::pairing_stop,
                companion_tauri::commands::owner_confirmations,
                companion_tauri::commands::owner_confirmation_review,
                companion_tauri::commands::revocation_view,
                companion_tauri::commands::revocation_revoke,
                companion_tauri::commands::hosts_use,
                companion_tauri::commands::hosts_forget,
                companion_tauri::commands::connection_state,
                companion_tauri::commands::session_list,
                companion_tauri::commands::session_read,
                companion_tauri::commands::session_describe,
                companion_tauri::commands::session_close,
                companion_tauri::commands::session_open,
                companion_tauri::commands::session_leave,
                companion_tauri::commands::terminal_view_open,
                companion_tauri::commands::terminal_view_resize,
                companion_tauri::commands::terminal_view_move,
                companion_tauri::commands::terminal_view_input,
                companion_tauri::commands::terminal_view_close,
                companion_tauri::commands::session_agents,
                companion_tauri::commands::agent_capabilities,
                companion_tauri::commands::agent_snapshot,
                companion_tauri::commands::agent_commands,
                companion_tauri::commands::agent_approval_inspect,
                companion_tauri::commands::agent_prompt_submit,
                companion_tauri::commands::agent_prompt_queue,
                companion_tauri::commands::agent_turn_steer,
                companion_tauri::commands::agent_turn_cancel,
                companion_tauri::commands::agent_approval_respond,
                companion_tauri::commands::action_read,
                companion_tauri::commands::action_cancel,
                companion_tauri::commands::history_page,
                companion_tauri::commands::question_settle,
                companion_tauri::commands::question_send_kept,
                companion_tauri::commands::shell_launch,
                companion_tauri::commands::draft_create,
                companion_tauri::commands::draft_add_attachment,
                companion_tauri::commands::attachment_upload,
                companion_tauri::commands::attachment_upload_bytes,
                companion_tauri::commands::host_info,
                companion_tauri::commands::attention_read,
                companion_tauri::commands::review_read,
                companion_tauri::commands::changeset_read,
                companion_tauri::commands::device_list,
                companion_tauri::commands::grant_held,
                companion_tauri::commands::voice_prepare,
                companion_tauri::commands::voice_allow,
                companion_tauri::commands::voice_scope,
                companion_tauri::commands::voice_start,
                companion_tauri::commands::voice_stop,
                companion_tauri::commands::voice_set_muted,
                companion_tauri::commands::voice_call_state,
                companion_tauri::commands::settings_view,
                companion_tauri::commands::settings_devices_refresh,
                companion_tauri::commands::settings_device_share,
            ]);
        let app = companion_tauri::terminal::install(
            builder,
            companion_tauri::terminal::TerminalViews::local(),
        )
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
        let standing = Arc::new(Capture::default());
        {
            let standing = Arc::clone(&standing);
            app.listen_any(
                companion_tauri::standing::STANDING_EVENT,
                move |published| {
                    standing.keep_text(published.payload());
                },
            );
        }
        companion_tauri::start_pairing(app.handle(), data, parts, ceremony, paste)
            .expect("this computer opens as a device that pairs");
        Self {
            app,
            window,
            heard,
            answered: Arc::new(Capture::default()),
            standing,
            channels,
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

    /// Starts `command` as `call` makes it, and returns at once with what will answer: the call
    /// goes on while the test does something else, as a page's call does.
    pub fn start_call(
        &self,
        command: &str,
        body: serde_json::Value,
    ) -> tokio::task::JoinHandle<Result<serde_json::Value, serde_json::Value>> {
        let window = self.window.clone();
        let command = command.to_owned();
        tokio::task::spawn_blocking(move || {
            let answered = tauri::test::get_ipc_response(
                &window,
                tauri::webview::InvokeRequest {
                    cmd: command,
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: tauri::test::INVOKE_KEY.to_owned(),
                },
            );
            match answered {
                Ok(answer) => Ok(answer.deserialize().expect("an answer the page can read")),
                Err(refusal) => Err(refusal),
            }
        })
    }

    /// Every state `channel` has been sent so far.
    pub fn states(&self, channel: u32) -> Vec<serde_json::Value> {
        self.channels
            .lock()
            .expect("the record")
            .get(&channel)
            .cloned()
            .unwrap_or_default()
    }

    /// Waits until a state `channel` was sent satisfies `until`, and returns it.
    pub async fn state_where(
        &self,
        channel: u32,
        until: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                if let Some(state) = self.states(channel).iter().find(|state| until(state)) {
                    return state.clone();
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no state on channel {channel} within the watchdog; it was sent {:?}",
                self.states(channel)
            )
        })
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
        link: None,
        managed: None,
    }
}

/// A ceremony nobody is asked: these devices own nothing.
pub struct NoOwner;

impl Ceremony for NoOwner {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, _reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        Box::pin(async { CeremonyOutcome::NotConfirmed })
    }
}

/// This computer as a phone: its backend, the pasteboard the person copies an invitation to, the
/// secret store its keys live in and the directory its records live in.
pub struct Phone {
    pub companion: Companion,
    pub paste: Arc<StubPaste>,
    pub secrets: Arc<dyn SecretStore>,
    pub room: Arc<dyn CandidateRoom>,
    pub data: tempfile::TempDir,
}

/// A phone that has paired with nothing.
pub fn unpaired_phone(host: &Host) -> Phone {
    let data = tempfile::tempdir().expect("a directory");
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let room: Arc<dyn CandidateRoom> = Arc::new(host.room.clone());
    let paste = StubPaste::holding("", false);
    let companion = Companion::start(
        data.path(),
        parts(Arc::clone(&secrets), Arc::clone(&room)),
        Arc::new(NoOwner),
        Arc::clone(&paste) as Arc<dyn companion_tauri::pairing::PastePlatform>,
    );
    Phone {
        companion,
        paste,
        secrets,
        room,
        data,
    }
}

/// `phone` paired with `host` as a device holding `rights`, by a direct invitation the person
/// pastes and the host's owner approves.
pub async fn pair(phone: &Phone, host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) {
    pair_under(phone, host, owner, proposal(rights)).await;
}

/// `phone` paired with `host` under the grant `proposed`, by a direct invitation the person pastes
/// and the host's owner approves.
pub async fn pair_under(
    phone: &Phone,
    host: &Host,
    owner: &DeviceKeys,
    proposed: kr_protocol::pairing::ProposedGrant,
) {
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(owner);
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposed,
        &signer,
    )
    .await
    .expect("a direct invitation");
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation");
    };
    phone.paste.copy(qr_text.as_str(), false);
    let companion = &phone.companion;
    companion
        .call("pairing_paste", json!({}))
        .expect("the invitation is read");
    companion
        .call("pairing_start_read", json!({}))
        .expect("pairing starts");
    companion
        .reached(|state| state["state"] == "awaiting_approval")
        .await;
    calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner approves");
    companion.reached(|state| state["state"] == "paired").await;
}

/// A phone paired with `host` as a device holding `rights`.
pub async fn phone_paired_with(host: &Host, owner: &DeviceKeys, rights: &[ActionRight]) -> Phone {
    let phone = unpaired_phone(host);
    pair(&phone, host, owner, rights).await;
    phone
}

/// What a test does to the connections a phone makes to its host: holds them until it says, makes
/// them fail as a host that cannot be reached does, or makes the host refuse them at admission.
#[derive(Default)]
pub struct LinkControl {
    /// How many connections to a paired host were asked for.
    asked: std::sync::atomic::AtomicUsize,
    state: Mutex<LinkState>,
}

#[derive(Default)]
struct LinkState {
    holding: bool,
    unreachable: bool,
    /// Whether a connection that is let through is ended as it is made, as a network that drops it
    /// at once does.
    ending: bool,
    refusing: Option<kr_protocol::error::ErrorCode>,
    waiting: Vec<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl LinkControl {
    /// A control that lets every connection through.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Holds each connection asked for from now on until the test releases it.
    pub fn hold(&self) {
        self.state.lock().expect("the record").holding = true;
    }

    /// Lets connections through again. Those held stay held until released.
    pub fn stop_holding(&self) {
        self.state.lock().expect("the record").holding = false;
    }

    /// How many connections have been asked for, held ones included.
    pub fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many connections are held now.
    pub fn held(&self) -> usize {
        self.state
            .lock()
            .expect("the record")
            .waiting
            .iter()
            .filter(|each| each.is_some())
            .count()
    }

    /// Releases the held connection that was asked for `index`th among the held ones (counting
    /// from 0).
    pub fn release(&self, index: usize) {
        let sender = self
            .state
            .lock()
            .expect("the record")
            .waiting
            .get_mut(index)
            .and_then(Option::take);
        if let Some(sender) = sender {
            let _ = sender.send(());
        }
    }

    /// Releases every held connection.
    pub fn release_all(&self) {
        let waiting: Vec<_> = self
            .state
            .lock()
            .expect("the record")
            .waiting
            .iter_mut()
            .filter_map(Option::take)
            .collect();
        for sender in waiting {
            let _ = sender.send(());
        }
    }

    /// Makes every connection fail as one to a host that cannot be reached does, or stops that.
    pub fn unreachable(&self, down: bool) {
        self.state.lock().expect("the record").unreachable = down;
    }

    /// Makes every connection that is let through end as it is made, or stops that. The caller finds
    /// a connection that is closed: its first send or read fails.
    pub fn end_connections(&self, ending: bool) {
        self.state.lock().expect("the record").ending = ending;
    }

    /// Makes the host refuse every connection at admission with `code`, or stops that.
    pub fn refuse(&self, code: Option<kr_protocol::error::ErrorCode>) {
        self.state.lock().expect("the record").refusing = code;
    }
}

/// The phone's way to its host, with a test's control over the connections to a paired host.
struct ControlledLink {
    own: Arc<dyn kr_client::pairing::link::HostLink>,
    control: Arc<LinkControl>,
}

impl kr_client::pairing::link::HostLink for ControlledLink {
    fn dial<'a>(
        &'a self,
        network: &'a kr_protocol::pairing::NetworkConfig,
        endpoint: &'a kr_protocol::scalars::EndpointKey,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<iroh::endpoint::Connection, kr_client::pairing::link::LinkError>,
    > {
        self.own.dial(network, endpoint)
    }

    fn relay_capacity_refused(
        &self,
        network: &kr_protocol::pairing::NetworkConfig,
        endpoint: &kr_protocol::scalars::EndpointKey,
    ) -> bool {
        self.own.relay_capacity_refused(network, endpoint)
    }

    fn open_unpaired<'a>(
        &'a self,
        connection: &'a iroh::endpoint::Connection,
        identity: &'a kr_transport::handshake::LocalIdentity,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<Box<dyn kr_client::pairing::link::Preauth>, kr_client::pairing::link::LinkError>,
    > {
        self.own.open_unpaired(connection, identity)
    }

    fn connect_paired_transport<'a>(
        &'a self,
        host: &'a kr_client::pairing::paired::PairedHost,
        identity: &'a kr_transport::handshake::LocalIdentity,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<
            Arc<dyn kr_client::transport::ControlTransport>,
            kr_client::pairing::link::LinkError,
        >,
    > {
        Box::pin(async move {
            self.control
                .asked
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let held = {
                let mut state = self.control.state.lock().expect("the record");
                if state.holding {
                    let (sender, receiver) = tokio::sync::oneshot::channel();
                    state.waiting.push(Some(sender));
                    Some(receiver)
                } else {
                    None
                }
            };
            if let Some(receiver) = held {
                let _ = receiver.await;
            }
            // What the host does is decided when the connection is let through, so a test can
            // change it while the connection is held.
            let (refusing, unreachable, ending) = {
                let state = self.control.state.lock().expect("the record");
                (state.refusing, state.unreachable, state.ending)
            };
            if let Some(code) = refusing {
                return Err(kr_client::pairing::link::LinkError::Refused(
                    kr_protocol::error::ProtocolError::new(code, "the host refused the device"),
                ));
            }
            if unreachable {
                return Err(kr_client::pairing::link::LinkError::Lost(
                    "the host could not be reached".to_owned(),
                ));
            }
            let transport = self.own.connect_paired_transport(host, identity).await?;
            if ending {
                transport.close();
            }
            Ok(transport)
        })
    }

    fn hold<'a>(
        &'a self,
        network: &'a kr_protocol::pairing::NetworkConfig,
    ) -> kr_client::pairing::BoxFuture<
        'a,
        Result<kr_client::pairing::link::EndpointHold, kr_client::pairing::link::LinkError>,
    > {
        self.own.hold(network)
    }
}

/// A phone that has paired with nothing, whose connections to a paired host `control` governs.
pub fn unpaired_phone_controlled(host: &Host, control: &Arc<LinkControl>) -> Phone {
    let data = tempfile::tempdir().expect("a directory");
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let room: Arc<dyn CandidateRoom> = Arc::new(host.room.clone());
    let paste = StubPaste::holding("", false);
    let mut governed = parts(Arc::clone(&secrets), Arc::clone(&room));
    let control = Arc::clone(control);
    governed.link = Some(Box::new(move |own| {
        Arc::new(ControlledLink { own, control }) as Arc<dyn kr_client::pairing::link::HostLink>
    }));
    let companion = Companion::start(
        data.path(),
        governed,
        Arc::new(NoOwner),
        Arc::clone(&paste) as Arc<dyn companion_tauri::pairing::PastePlatform>,
    );
    Phone {
        companion,
        paste,
        secrets,
        room,
        data,
    }
}
