//! The person's settings, through the commands the page calls, against the sync service as a local
//! Worker answered it.
//!
//! Drafts travel in the same collection when the person turns that on: they are held to the privacy
//! mode of the host they were written for, one host's store at a time, and a draft from another
//! device arrives as a kept copy. What this computer can read of a host's privacy mode is scripted
//! here ([`ScriptedHosts`]): the connection to a real host that answers `privacy.status` is the
//! companion's own and is not under test.
//!
//! KR-REQ-24.28: a host in privacy mode stops what leaves for the sync service at its recorded
//! generation: `a_draft_of_a_host_in_privacy_mode_stays_here_until_the_host_lets_it_go`,
//! `an_edit_made_while_the_host_is_private_is_not_sent` and
//! `the_drafts_of_a_host_this_computer_cannot_read_stay_here_and_the_view_says_why` (a host that
//! cannot be read is treated as private); the colour mode, which holds no session content, keeps
//! going. KR-REQ-20.13: a draft is a draft, never an execution request:
//! `a_draft_another_device_wrote_arrives_as_a_kept_copy_and_nothing_is_sent_for_it`.
//!
//! KR-REQ-20.13: settings sync uses per-object revisions and compare-and-swap writes, keeps the
//! content a refused write lost for the person to choose from instead of choosing by the clock, and
//! never overwrites a host's grants. KR-REQ-18.05: encrypted settings sync. KR-REQ-17.14: the sync
//! service is a client the application fills with the service it is set to use.
//!
//! The companion runs on the mock runtime, its commands are called the way the page calls them,
//! and its transport is the real one, talking over loopback to the stand-in `kr_service_stand_in`
//! provides, which `crates/kr-client/tests/settings_answers.rs` holds to a recording of a local
//! Worker. A second device is a second sync store of the same collection, opened with the keys the
//! first one holds and writing as a client of the same library writes: the collection admits
//! members, and how a device joins is not under test here.
#![cfg(desktop)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_tauri::AppState;
use companion_tauri::device::DeviceIdentity;
use companion_tauri::drafts::DraftHost;
use companion_tauri::settings::{Holds, HostLists, HostPrivacy, Hosts, SETTINGS_EVENT};
use kr_client::drafts::{Draft, DraftSealer, DraftStore, DraftSync, DraftTarget, SyncCheckpoint};
use kr_client::pairing::BoxFuture;
use kr_client::pairing::owner::{Ceremony, CeremonyKind, CeremonyOutcome};
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceSigner, SyncBackupService,
    managed_response_limits,
};
use kr_client::sync::{
    CollectionKeys, Published, Restored, SettingValue, SharedCollectionService,
    StoredCollectionKeys, SyncBody, SyncClient, SyncObject, SyncStore, fresh_revision,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::MemoryStore;
use kr_protocol::ids::{
    DeviceId, DraftId, EnvironmentId, SessionId, SyncCollectionId, SyncObjectId,
};
use kr_protocol::pairing::DevicePublicKeys;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner, installation_id};
use kr_protocol::sync::SyncObjectKind;
use kr_service_stand_in::{Moment, Served, serve};
use serde_json::{Value, json};
use tauri::test::{INVOKE_KEY, MockRuntime, mock_builder, mock_context, noop_assets};
use tauri::webview::InvokeRequest;
use tauri::{Listener as _, Manager as _};

const SYNC_PATH: &str = "/api/sync/exchange";

/// Where the bundle's pages are served from, which is where the page's calls come from.
#[cfg(windows)]
const BUNDLE: &str = "http://tauri.localhost";
#[cfg(not(windows))]
const BUNDLE: &str = "tauri://localhost";

/// A device's key, signing as an installation.
#[derive(Debug)]
struct Installation(AuthorisationKeyPair);

impl ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.0.public()
    }

    fn sign(&self, message: &[u8]) -> kr_client::Result<Signature64> {
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            message.to_vec(),
        )
        .expect("a transcript");
        Ok(sign(&self.0, &transcript).expect("a signature"))
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
}

/* -------------------------------------------------------------------------- */
/* This computer, and the application started on it                            */
/* -------------------------------------------------------------------------- */

/// What survives the application being closed: the service, the data directory and the secure
/// store, which holds the device's keys and, once sync is on, the collection's.
struct Computer {
    served: Arc<Served>,
    data: tempfile::TempDir,
    secrets: Arc<MemoryStore>,
    /// What this computer can read of each host's privacy mode.
    hosts: Arc<ScriptedHosts>,
    /// What the person does when this computer asks them to confirm.
    ceremony: Arc<ScriptedCeremony>,
}

/// The platform's ceremony, answered as a test says.
struct ScriptedCeremony {
    answer: Mutex<CeremonyOutcome>,
    asked: Mutex<Vec<String>>,
    /// What happens while the person is being asked, as the world does not wait for them.
    meanwhile: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl ScriptedCeremony {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(CeremonyOutcome::Confirmed),
            asked: Mutex::new(Vec::new()),
            meanwhile: Mutex::new(None),
        })
    }

    /// `then` happens while the person is being asked, once.
    fn while_asking(&self, then: impl Fn() + Send + 'static) {
        *self.meanwhile.lock().expect("the record") = Some(Box::new(then));
    }

    fn will_answer(&self, answer: CeremonyOutcome) {
        *self.answer.lock().expect("the answer") = answer;
    }

    /// What the dialog said each time it was shown.
    fn reasons(&self) -> Vec<String> {
        self.asked.lock().expect("the record").clone()
    }
}

impl Ceremony for ScriptedCeremony {
    fn kind(&self) -> CeremonyKind {
        CeremonyKind::TouchId
    }

    fn verify<'a>(&'a self, reason: &'a str, _within: Duration) -> BoxFuture<'a, CeremonyOutcome> {
        self.asked
            .lock()
            .expect("the record")
            .push(reason.to_owned());
        if let Some(then) = self.meanwhile.lock().expect("the record").take() {
            then();
        }
        let answer = *self.answer.lock().expect("the answer");
        Box::pin(async move { answer })
    }
}

/// A device a host lists: what it is called, its keys, and what the host says of it.
#[derive(Clone)]
struct Listed {
    name: String,
    /// What the host reports of its four keys: none until the device declares them.
    keys: Option<DevicePublicKeys>,
    manages_host: bool,
    revoked: bool,
    /// Whether its grant has run out, which a host reports beside the actions the grant lists.
    expired: bool,
    /// The platform the host says it runs.
    platform: kr_protocol::pairing::DevicePlatform,
}

/// A call a host is asked, held until the test lets it go.
struct Held {
    arrived: tokio::sync::Notify,
    released: tokio::sync::Notify,
}

impl Held {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            arrived: tokio::sync::Notify::new(),
            released: tokio::sync::Notify::new(),
        })
    }

    /// The call is waiting at the host.
    async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(60), self.arrived.notified())
            .await
            .expect("the call reached the host");
    }

    /// The host answers the call.
    fn release(&self) {
        self.released.notify_one();
    }
}

/// What this computer can learn of each host, as a test says it.
///
/// A session belongs to one host ([`ScriptedHosts::belongs`]), and the hosts this computer is
/// connected to are the ones the test connects ([`ScriptedHosts::connect`]): a connected host holds
/// the sessions that belong to it and no others. A host's privacy mode is what the test said of it,
/// and a host nobody said anything of is one this computer cannot read.
struct ScriptedHosts {
    said: Mutex<BTreeMap<EnvironmentId, HostPrivacy>>,
    /// What a host says from the read after the number of reads named, as a host that went private
    /// while a pass was out at the service does.
    turning: Mutex<BTreeMap<EnvironmentId, (u32, HostPrivacy)>>,
    reads: Mutex<BTreeMap<EnvironmentId, u32>>,
    /// The host each session belongs to.
    owners: Mutex<BTreeMap<SessionId, DraftHost>>,
    /// The hosts this computer is connected to.
    connected: Mutex<BTreeSet<EnvironmentId>>,
    /// The hosts that refuse to say whether they hold a session, as one does for a session outside
    /// the right it gave this device.
    refusing: Mutex<BTreeSet<EnvironmentId>>,
    /// The devices the host this computer can ask lists.
    devices: Mutex<Vec<Listed>>,
    /// The devices a second host lists, when there is one.
    second: Mutex<Option<Vec<Listed>>>,
    /// Whether a host this computer owns does not answer.
    silent: Mutex<bool>,
    /// Whether every host this computer owns refuses to list its devices to it.
    refusing_lists: Mutex<bool>,
    /// Whether the host this computer can ask refuses, and a second host, if there is one, lists.
    first_refusing: Mutex<bool>,
    /// How many times a host was asked whether it holds a session.
    asked: Mutex<u32>,
    /// The next question to the hosts for their devices, held while a step waits on it.
    holding_lists: Mutex<Option<Arc<Held>>>,
}

impl ScriptedHosts {
    fn new() -> Self {
        Self {
            said: Mutex::default(),
            turning: Mutex::default(),
            reads: Mutex::default(),
            owners: Mutex::default(),
            connected: Mutex::default(),
            refusing: Mutex::default(),
            devices: Mutex::default(),
            second: Mutex::default(),
            silent: Mutex::default(),
            refusing_lists: Mutex::default(),
            first_refusing: Mutex::default(),
            asked: Mutex::default(),
            holding_lists: Mutex::default(),
        }
    }

    /// The next time the hosts are asked for their devices, the answer waits for the test.
    fn hold_the_next_list(&self) -> Arc<Held> {
        let held = Held::new();
        *self.holding_lists.lock().expect("the record") = Some(Arc::clone(&held));
        held
    }

    fn say(&self, host: EnvironmentId, state: HostPrivacy) {
        self.said.lock().expect("the record").insert(host, state);
    }

    /// The host says `state` once it has been asked `after` times from now on.
    fn turn_after(&self, host: EnvironmentId, after: u32, state: HostPrivacy) {
        self.reads.lock().expect("the record").insert(host, 0);
        self.turning
            .lock()
            .expect("the record")
            .insert(host, (after, state));
    }

    /// `session` belongs to `host`.
    fn belongs(&self, session: SessionId, host: &DraftHost) {
        self.owners
            .lock()
            .expect("the record")
            .insert(session, host.clone());
    }

    /// This computer is connected to `host` as well.
    fn connect(&self, host: &DraftHost) {
        self.connected
            .lock()
            .expect("the record")
            .insert(host.environment);
    }

    /// `host` refuses to say whether it holds a session.
    fn refuse_to_say(&self, host: &DraftHost) {
        self.refusing
            .lock()
            .expect("the record")
            .insert(host.environment);
    }

    /// The host this computer can ask lists exactly `devices`.
    fn list(&self, devices: Vec<Listed>) {
        *self.devices.lock().expect("the record") = devices;
    }

    /// A second host lists exactly `devices`.
    fn list_at_a_second_host(&self, devices: Vec<Listed>) {
        *self.second.lock().expect("the record") = Some(devices);
    }

    /// A host this computer owns does not answer, or answers again.
    fn go_silent(&self, silent: bool) {
        *self.silent.lock().expect("the record") = silent;
    }

    /// A host this computer owns refuses to list its devices to it, or lists them again.
    fn refuse_to_list(&self, refusing: bool) {
        *self.refusing_lists.lock().expect("the record") = refusing;
    }

    /// The host this computer can ask refuses to list its devices to it, or lists them again.
    fn refuse_at_the_first_host(&self, refusing: bool) {
        *self.first_refusing.lock().expect("the record") = refusing;
    }

    fn times_asked_who_holds(&self) -> u32 {
        *self.asked.lock().expect("the record")
    }

    /// How many times the privacy mode of `host` was read.
    fn reads_of(&self, host: EnvironmentId) -> u32 {
        self.reads
            .lock()
            .expect("the record")
            .get(&host)
            .copied()
            .unwrap_or(0)
    }
}

impl Hosts for ScriptedHosts {
    fn device_lists(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostLists> + Send + '_>> {
        let list_of = |devices: &[Listed]| kr_protocol::sharing::DeviceListResult {
            devices: devices
                .iter()
                .enumerate()
                .map(|(number, device)| listed_device(number, device))
                .collect(),
            authority_revision: kr_protocol::ids::AuthorityRevision::new(1),
            feed_synchronised_at_ms: Nullable::null(),
            feed_stale: false,
            feed_removed: false,
        };
        let devices = self.devices.lock().expect("the record").clone();
        let mut lists = Vec::new();
        let first_refuses = *self.first_refusing.lock().expect("the record");
        if !devices.is_empty() && !first_refuses {
            lists.push(list_of(&devices));
        }
        if let Some(second) = &*self.second.lock().expect("the record") {
            lists.push(list_of(second));
        }
        let silent = *self.silent.lock().expect("the record");
        let all_refuse = *self.refusing_lists.lock().expect("the record");
        if all_refuse {
            lists.clear();
        }
        let refused = all_refuse || first_refuses;
        let held = self.holding_lists.lock().expect("the record").take();
        Box::pin(async move {
            if let Some(held) = held {
                held.arrived.notify_one();
                held.released.notified().await;
            }
            HostLists {
                lists,
                silent,
                refused,
            }
        })
    }

    fn holds(
        &self,
        session: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Holds> + Send + '_>> {
        *self.asked.lock().expect("the record") += 1;
        let connected = self.connected.lock().expect("the record").clone();
        let answer = if connected.is_empty() {
            Holds::Unknown
        } else {
            match self.owners.lock().expect("the record").get(&session) {
                Some(host)
                    if self
                        .refusing
                        .lock()
                        .expect("the record")
                        .contains(&host.environment) =>
                {
                    Holds::Refused
                }
                Some(host) if connected.contains(&host.environment) => Holds::Here(host.clone()),
                _ => Holds::NotHere,
            }
        };
        Box::pin(std::future::ready(answer))
    }

    fn privacy(
        &self,
        environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>> {
        let asked = {
            let mut reads = self.reads.lock().expect("the record");
            let asked = reads.entry(environment).or_default();
            *asked += 1;
            *asked
        };
        let turned = self
            .turning
            .lock()
            .expect("the record")
            .get(&environment)
            .filter(|(after, _)| asked > *after)
            .map(|(_, state)| state.clone());
        let state = turned.unwrap_or_else(|| {
            self.said
                .lock()
                .expect("the record")
                .get(&environment)
                .cloned()
                .unwrap_or_else(|| HostPrivacy::Unreadable {
                    reason: "this computer is not connected to that host".to_owned(),
                })
        });
        Box::pin(std::future::ready(state))
    }
}

/// One entry of a host's device list.
fn listed_device(number: usize, device: &Listed) -> kr_protocol::sharing::DeviceSummary {
    kr_protocol::sharing::DeviceSummary {
        device_id: DeviceId::new(Uuid::from_bytes([u8::try_from(number).expect("a few"); 16])),
        display_name: device.name.clone(),
        grant_id: kr_protocol::ids::GrantId::new(Uuid::from_bytes([0x90; 16])),
        paired_at_ms: TimestampMs::new(1),
        revoked: device.revoked,
        keys: device.keys.map_or_else(Nullable::null, Nullable::some),
        manages_host: device.manages_host,
        platform: device.platform,
        grant_expires_at_ms: Nullable::null(),
        grant_expired: device.expired,
        all_sessions: true,
    }
}

impl Computer {
    async fn new() -> Self {
        Self {
            served: Arc::new(serve().await),
            data: tempfile::tempdir().expect("a directory"),
            secrets: Arc::new(MemoryStore::new()),
            hosts: Arc::new(ScriptedHosts::new()),
            ceremony: ScriptedCeremony::new(),
        }
    }

    /// Another computer of the same person, reaching the same sync service.
    async fn beside(other: &Self) -> Self {
        Self {
            served: Arc::clone(&other.served),
            data: tempfile::tempdir().expect("a directory"),
            secrets: Arc::new(MemoryStore::new()),
            hosts: Arc::new(ScriptedHosts::new()),
            ceremony: ScriptedCeremony::new(),
        }
    }

    /// This computer as a host lists it.
    fn listed(&self, name: &str) -> Listed {
        let keys = self.identity().keys;
        Listed {
            name: name.to_owned(),
            keys: Some(DevicePublicKeys {
                transport: *keys.transport.public(),
                authorisation: *keys.authorisation.public(),
                stored_envelope: *keys.stored_envelope.public(),
                notification_preview: *keys.notification_preview.public(),
            }),
            manages_host: true,
            revoked: false,
            expired: false,
            platform: kr_protocol::pairing::DevicePlatform::Macos,
        }
    }

    fn identity(&self) -> DeviceIdentity {
        DeviceIdentity::in_store(Arc::clone(&self.secrets) as _).expect("the device's keys")
    }

    fn origin(&self) -> GatewayOrigin {
        GatewayOrigin::new(self.served.origin()).expect("an origin")
    }

    /// The application, started over this computer's records, with the sync service chosen to be
    /// the one this computer can reach.
    fn start(&self) -> Page {
        let app = mock_builder()
            .manage(AppState::new())
            .invoke_handler(tauri::generate_handler![
                companion_tauri::commands::sync_service_set,
                companion_tauri::commands::settings_view,
                companion_tauri::commands::settings_colour_mode_set,
                companion_tauri::commands::settings_sync_turn_on,
                companion_tauri::commands::settings_sync_now,
                companion_tauri::commands::settings_conflicts,
                companion_tauri::commands::settings_conflict_resolve,
                companion_tauri::commands::settings_drafts_set,
                companion_tauri::commands::settings_devices_refresh,
                companion_tauri::commands::settings_device_share,
                companion_tauri::commands::settings_device_remove,
                companion_tauri::commands::settings_devices_dismiss,
                companion_tauri::commands::settings_join,
                companion_tauri::commands::device_drafts,
                companion_tauri::commands::device_draft_discard,
            ])
            .build(mock_context(noop_assets()))
            .expect("an application on the mock runtime");
        // What the application's start does, over this computer's records.
        app.state::<AppState>().keep_under(self.data.path());
        companion_tauri::start_sync_service(app.handle(), self.data.path());
        companion_tauri::start_settings_sync(
            app.handle(),
            self.data.path(),
            &self.identity(),
            Arc::clone(&self.hosts) as Arc<dyn Hosts>,
            Arc::clone(&self.ceremony) as Arc<dyn Ceremony>,
        )
        .expect("settings sync opens");
        companion_tauri::watch_settings(app.handle());
        let heard = Arc::new(Mutex::new(Vec::<Value>::new()));
        let listening = Arc::clone(&heard);
        app.listen(SETTINGS_EVENT, move |event| {
            listening
                .lock()
                .expect("the record")
                .push(serde_json::from_str(event.payload()).expect("a view"));
        });
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("a window");
        let page = Page {
            app,
            window,
            heard,
            hosts: Arc::clone(&self.hosts),
        };
        page.call(
            "sync_service_set",
            json!({ "origin": self.served.origin() }),
        )
        .expect("the service is chosen");
        page
    }

    /// Another device of the person's: a second store of the collection this computer started,
    /// opened with the key this computer holds.
    fn elsewhere(&self) -> Elsewhere {
        self.elsewhere_at(0)
    }

    /// Another device's store of the collection, reading and writing under the key of `epoch`:
    /// the collection starts at epoch 0, and each device added or taken out moves it on by one.
    fn elsewhere_at(&self, epoch: u64) -> Elsewhere {
        let record: Value = serde_json::from_slice(
            &std::fs::read(self.data.path().join("settings-sync").join("sync.json"))
                .expect("the record sync keeps"),
        )
        .expect("a record");
        let collection_id: SyncCollectionId =
            serde_json::from_value(record["collection_id"].clone()).expect("a collection");
        let object_id = SyncObjectId::new(collection_id.get());
        let keys = self.identity().keys;
        let origin = self.origin();
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport");
        let service = Arc::new(ManagedSyncService::new(
            origin,
            Arc::new(http),
            Arc::new(Installation(keys.authorisation.clone())),
        ));
        let held_service = Arc::clone(&service);
        let collection = kr_client::sync::membership::CollectionRef {
            home: installation_id(keys.authorisation.public()),
            collection_id,
        };
        let directory = tempfile::tempdir().expect("a directory");
        let shared = Arc::new(SharedCollectionService::new(service, collection, epoch));
        let sealer = Arc::new(shared.sealer(Arc::new(StoredCollectionKeys::in_store(
            Arc::clone(&self.secrets) as _,
            companion_tauri::settings::sync::SCOPE,
        )) as Arc<dyn CollectionKeys>));
        let client = SyncClient::new(
            Arc::clone(&shared) as _,
            Arc::clone(&sealer) as _,
            SyncStore::open(directory.path()).expect("a store"),
        );
        Elsewhere {
            client,
            shared,
            sealer,
            service: held_service,
            collection,
            object_id,
            device: DeviceId::new(Uuid::from_bytes([0xee; 16])),
            _directory: directory,
        }
    }
}

/// A client over the settings store a computer keeps, with the keys it holds.
struct OwnStore {
    client: SyncClient,
    object_id: SyncObjectId,
}

impl Computer {
    /// A client at `epoch` over the store this computer's settings sync keeps, as the application
    /// itself reads and writes it: for a case that arranges the store as a step that stopped left it.
    fn client_on_its_own_store(&self, epoch: u64) -> OwnStore {
        let record = sync_record(self);
        let collection_id: SyncCollectionId =
            serde_json::from_value(record["collection_id"].clone()).expect("a collection");
        let keys = self.identity().keys;
        let origin = self.origin();
        let http = HttpService::with(
            origin.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport");
        let service = Arc::new(ManagedSyncService::new(
            origin,
            Arc::new(http),
            Arc::new(Installation(keys.authorisation.clone())),
        ));
        let collection = kr_client::sync::membership::CollectionRef {
            home: installation_id(keys.authorisation.public()),
            collection_id,
        };
        let shared =
            Arc::new(SharedCollectionService::new(service, collection, epoch).believing_from(0));
        let sealer = Arc::new(shared.sealer(Arc::new(StoredCollectionKeys::in_store(
            Arc::clone(&self.secrets) as _,
            companion_tauri::settings::sync::SCOPE,
        )) as Arc<dyn CollectionKeys>));
        let store = SyncStore::open(self.data.path().join("settings-sync").join("store"))
            .expect("the store sync keeps");
        OwnStore {
            client: SyncClient::new(shared as _, sealer as _, store),
            object_id: SyncObjectId::new(collection_id.get()),
        }
    }
}

/// The application's backend, called as the page calls it.
struct Page {
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
    /// Every view the page was told of by the backend itself.
    heard: Arc<Mutex<Vec<Value>>>,
    /// What this computer learns of its hosts.
    hosts: Arc<ScriptedHosts>,
}

impl Page {
    /// Calls `command` with `body` through the invoke path, and returns the answer the page gets,
    /// or its refusal.
    fn call(&self, command: &str, body: Value) -> Result<Value, Value> {
        assert!(
            companion_tauri::commands::NAMED_COMMANDS
                .iter()
                .any(|(name, _)| *name == command),
            "{command} is a command the application registers"
        );
        let answered = tokio::task::block_in_place(|| {
            tauri::test::get_ipc_response(
                &self.window,
                InvokeRequest {
                    cmd: command.into(),
                    callback: tauri::ipc::CallbackFn(0),
                    error: tauri::ipc::CallbackFn(1),
                    url: BUNDLE.parse().expect("the bundle's address"),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: INVOKE_KEY.to_owned(),
                },
            )
        });
        match answered {
            Ok(answer) => Ok(answer.deserialize().expect("an answer the page can read")),
            Err(refusal) => Err(refusal),
        }
    }

    fn view(&self) -> Value {
        self.call("settings_view", json!({})).expect("the view")
    }

    fn choose(&self, mode: &str) -> Value {
        self.call("settings_colour_mode_set", json!({ "mode": mode }))
            .expect("the choice is kept")
    }

    fn turn_on(&self) -> Value {
        self.call("settings_sync_turn_on", json!({}))
            .expect("sync is turned on")
    }

    fn sync_now(&self) -> Value {
        self.call("settings_sync_now", json!({}))
            .expect("sync runs")
    }

    /// The devices the page is shown, as the last step found them.
    fn devices(&self) -> Value {
        self.view()["sync"]["devices"].clone()
    }

    /// The page asks every host who it lists.
    fn devices_refresh(&self) -> Value {
        self.call("settings_devices_refresh", json!({}))
            .expect("the hosts are asked")["sync"]["devices"]
            .clone()
    }

    /// The page names a device it was shown and the person confirms (or not) on this computer.
    fn share(&self, reference: &str) -> Result<Value, Value> {
        self.call("settings_device_share", json!({ "reference": reference }))
    }

    fn unshare(&self, reference: &str) -> Result<Value, Value> {
        self.call("settings_device_remove", json!({ "reference": reference }))
    }

    fn join(&self, reference: &str) -> Result<Value, Value> {
        self.call("settings_join", json!({ "reference": reference }))
    }

    fn drafts_on(&self, enabled: bool) -> Result<Value, Value> {
        self.call("settings_drafts_set", json!({ "enabled": enabled }))
    }

    /// A draft the person wrote for a session of `host` while this computer was connected to it,
    /// saved as the page saves one, and what the store says it is: its identity and its version. A
    /// draft for no host is for a session no host holds, written while this computer is connected
    /// to none.
    fn write_draft(&self, host: Option<&DraftHost>, text: &str) -> (DraftId, String) {
        self.write_draft_while(host, host, text)
    }

    /// A draft for a session of `of`, written while this computer is connected to `connected`.
    fn write_draft_while(
        &self,
        of: Option<&DraftHost>,
        connected: Option<&DraftHost>,
        text: &str,
    ) -> (DraftId, String) {
        let session = self.session_of(of);
        self.connect(connected);
        let saved = self
            .app
            .state::<AppState>()
            .drafts()
            .save(
                serde_json::from_value(draft_params(None, None, text, session))
                    .expect("parameters"),
                TimestampMs::new(now_ms()),
            )
            .expect("the draft is saved");
        let saved = serde_json::to_value(saved).expect("a value");
        (
            serde_json::from_value(saved["draft"]["id"].clone()).expect("an identity"),
            saved["draft"]["revision"]
                .as_str()
                .expect("a version")
                .to_owned(),
        )
    }

    /// The draft written again, as the page writes a later version, while this computer is
    /// connected to `connected`.
    fn rewrite_draft(
        &self,
        of: Option<&DraftHost>,
        connected: Option<&DraftHost>,
        id: DraftId,
        version: &str,
        text: &str,
    ) -> String {
        let session = self.session_of(of);
        self.connect(connected);
        let saved = self
            .app
            .state::<AppState>()
            .drafts()
            .save(
                serde_json::from_value(draft_params(Some((id, version)), None, text, session))
                    .expect("parameters"),
                TimestampMs::new(now_ms()),
            )
            .expect("the draft is saved");
        serde_json::to_value(saved).expect("a value")["draft"]["revision"]
            .as_str()
            .expect("a version")
            .to_owned()
    }

    /// The session a draft for `host` is for, which belongs to it.
    fn session_of(&self, host: Option<&DraftHost>) -> SessionId {
        let Some(host) = host else {
            return SessionId::new(Uuid::from_bytes([0x7f; 16]));
        };
        let number = u8::from_str_radix(&host.environment.to_string()[..2], 16).expect("a number");
        let session = SessionId::new(Uuid::from_bytes([number | 0x80; 16]));
        self.hosts.belongs(session, host);
        session
    }

    /// This computer is connected to `host`, when there is one, as well.
    fn connect(&self, host: Option<&DraftHost>) {
        if let Some(host) = host {
            self.hosts.connect(host);
        }
    }

    /// The draft pointed at a session of `to`, which this computer is connected to, as the person
    /// does by choosing where it goes.
    fn retarget_draft(&self, id: DraftId, version: &str, to: &DraftHost) -> String {
        let session = self.session_of(Some(to));
        self.connect(Some(to));
        let retargeted = self
            .app
            .state::<AppState>()
            .drafts()
            .retarget(
                serde_json::from_value(json!({
                    "id": id,
                    "expectedRevision": version,
                    "sessionId": session,
                    "applicationInstanceId": null,
                    "agentBindingRevision": null
                }))
                .expect("parameters"),
                TimestampMs::new(now_ms()),
            )
            .expect("the draft is retargeted");
        serde_json::to_value(retargeted).expect("a value")["revision"]
            .as_str()
            .expect("a version")
            .to_owned()
    }

    /// Throws a draft away, as the page does once it sent it or the person discarded it.
    fn discard_draft(&self, id: DraftId, version: &str) -> Value {
        self.call(
            "device_draft_discard",
            json!({ "params": { "id": id, "expectedRevision": version } }),
        )
        .expect("the draft is discarded")
    }

    /// The drafts this computer keeps, as the page reads them.
    fn kept_drafts(&self) -> Vec<Value> {
        self.call("device_drafts", json!({}))
            .expect("the drafts are read")["drafts"]
            .as_array()
            .expect("a list")
            .clone()
    }
}

/// The parameters of a save of a draft for a session.
fn draft_params(
    replacing: Option<(DraftId, &str)>,
    instance: Option<&str>,
    text: &str,
    session: SessionId,
) -> Value {
    json!({
        "id": replacing.map(|(id, _)| id),
        "expectedRevision": replacing.map(|(_, version)| version),
        "sessionId": session,
        "applicationInstanceId": instance,
        "agentBindingRevision": instance.map(|_| "1"),
        "state": "open",
        "text": text,
        "attachments": []
    })
}

/// A host, with a name.
fn host(number: u8, name: &str) -> (EnvironmentId, DraftHost) {
    let environment = EnvironmentId::new(Uuid::from_bytes([number; 16]));
    (
        environment,
        DraftHost {
            environment,
            name: Some(name.to_owned()),
        },
    )
}

/// Another device's drafts.
struct OtherDrafts {
    store: DraftStore,
    sync: DraftSync,
    _directory: tempfile::TempDir,
}

impl OtherDrafts {
    /// A draft written for a session, and published.
    async fn publish(&self, text: &str) -> Draft {
        let draft = self
            .store
            .create(
                DraftTarget::session(SessionId::new(Uuid::from_bytes([5; 16]))),
                text.to_owned(),
                TimestampMs::new(now_ms()),
            )
            .expect("a draft");
        self.sync
            .publish(
                &self.store,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(now_ms()),
            )
            .await
            .expect("a publication");
        draft
    }

    /// The draft with `text`, written again, and published against where it stood.
    async fn edit(&self, draft: &Draft, text: &str) {
        let mut edited = self.store.load(draft.draft_id).expect("the draft");
        edited.text = text.to_owned();
        let stored = self
            .store
            .update(&edited, TimestampMs::new(now_ms()))
            .expect("an update");
        self.sync
            .publish(
                &self.store,
                stored.draft_id,
                stored.revision,
                TimestampMs::new(now_ms()),
            )
            .await
            .expect("a publication");
    }
}

/// Another device's store of the collection.
struct Elsewhere {
    client: SyncClient,
    shared: Arc<SharedCollectionService>,
    sealer: Arc<kr_client::sync::CollectionSealer>,
    service: Arc<ManagedSyncService>,
    collection: kr_client::sync::membership::CollectionRef,
    object_id: SyncObjectId,
    device: DeviceId,
    _directory: tempfile::TempDir,
}

impl Elsewhere {
    /// This device writes `draft` at the service first, as another device's draft under the
    /// identity of the same draft, so that the publication of this computer's own is refused.
    async fn claim_draft(&self, draft: &Draft) {
        let mut theirs = draft.clone();
        theirs.device_id = self.device;
        let sealed = self
            .sealer
            .seal(&DraftStore::encode_payload(&theirs).expect("a payload"))
            .expect("sealed");
        self.shared
            .compare_exchange(
                &kr_client::drafts::draft_collection(draft.draft_id),
                kr_client::sync::fresh_object_id()
                    .expect("an identity")
                    .get(),
                now_ms(),
                None,
                &sealed,
            )
            .await
            .expect("the claim is answered");
    }

    /// How many objects the service holds, settings and drafts together.
    async fn objects(&self) -> u64 {
        self.service
            .compare_shared(&self.collection, &[], false, None)
            .await
            .expect("a comparison")
            .expect("a member")
            .stored
            .objects
            .get()
    }

    /// Where the service holds a draft, as the number of writes of it, or none when it holds none.
    async fn draft_at(&self, draft: DraftId) -> Option<u64> {
        self.service
            .compare_shared(&self.collection, &[], false, None)
            .await
            .expect("a comparison")
            .expect("a member")
            .objects
            .iter()
            .find(|held| held.object_id.get() == draft.get())
            .map(|held| held.position.write_sequence)
    }

    /// The epoch of the key the service says `object` is sealed under, or none when it holds none.
    async fn epoch_of(&self, object: Uuid) -> Option<u64> {
        self.service
            .compare_shared(&self.collection, &[], false, None)
            .await
            .expect("a comparison")
            .expect("a member")
            .objects
            .iter()
            .find(|held| held.object_id.get() == object)
            .and_then(|held| held.epoch)
    }

    /// What the service holds of a draft, as the bytes it stores.
    async fn draft_stored(&self, draft: DraftId) -> Option<Vec<u8>> {
        match self
            .shared
            .fetch(&kr_client::drafts::draft_collection(draft))
            .await
            .expect("a read")
        {
            kr_client::services::SyncFetched::Held { ciphertext, .. } => Some(ciphertext),
            kr_client::services::SyncFetched::Absent { .. } => None,
        }
    }

    /// Another device's drafts: its own draft store, and the half that publishes them.
    fn drafts(&self) -> OtherDrafts {
        let directory = tempfile::tempdir().expect("a directory");
        let store = DraftStore::open(
            directory.path().join("drafts"),
            DeviceId::new(Uuid::from_bytes([0xdd; 16])),
        )
        .expect("a draft store");
        let sync = DraftSync::new(
            Arc::clone(&self.shared) as _,
            Arc::clone(&self.sealer) as Arc<dyn DraftSealer>,
            SyncStore::open(directory.path().join("sync")).expect("a sync store"),
        );
        OtherDrafts {
            store,
            sync,
            _directory: directory,
        }
    }

    /// How many copies of refused writes the service is keeping for the person to choose between.
    async fn copies_kept(&self) -> usize {
        self.service
            .compare_shared(&self.collection, &[], true, None)
            .await
            .expect("a comparison")
            .expect("a member")
            .copies
            .len()
    }

    /// The colour mode the service holds, as this device reads it.
    async fn colour(&self) -> String {
        let Restored::Settings { object, .. } = self
            .client
            .fetch(
                SyncObjectKind::Settings,
                self.object_id,
                TimestampMs::new(now_ms()),
            )
            .await
            .expect("a fetch")
        else {
            panic!("settings");
        };
        colour_of(&object)
    }

    /// Writes `mode` as this device: it reads where the object stands, changes it, and publishes.
    async fn write(&self, mode: &str) -> Published {
        match self
            .client
            .fetch(
                SyncObjectKind::Settings,
                self.object_id,
                TimestampMs::new(now_ms()),
            )
            .await
        {
            Ok(_) => {}
            // The collection holds no settings yet, and this device writes the first.
            Err(kr_client::sync::SyncError::Client(error))
                if error.code() == kr_protocol::error::ErrorCode::UnknownSession => {}
            Err(error) => panic!("a fetch: {error:?}"),
        }
        let mut settings = kr_client::sync::SyncSettings::default();
        settings.values.insert(
            "colour_mode".to_owned(),
            SettingValue::Text(mode.to_owned()),
        );
        self.client
            .store()
            .put_object(&SyncObject {
                object_id: self.object_id,
                revision: fresh_revision().expect("a revision"),
                device_id: self.device,
                updated_at_ms: TimestampMs::new(now_ms()),
                body: SyncBody::Settings(settings),
                went_over: Vec::new(),
            })
            .expect("the object is kept");
        self.client
            .publish(self.object_id, TimestampMs::new(now_ms()))
            .await
            .expect("a publication")
    }
}

fn colour_of(object: &SyncObject) -> String {
    match &object.body {
        SyncBody::Settings(settings) => match settings.values.get("colour_mode") {
            Some(SettingValue::Text(word)) => word.clone(),
            other => panic!("no colour mode: {other:?}"),
        },
        other => panic!("not settings: {other:?}"),
    }
}

/// How many requests reached the sync route.
fn sync_requests(computer: &Computer) -> usize {
    computer.served.web().requests_to(SYNC_PATH)
}

/* -------------------------------------------------------------------------- */
/* The colour mode, on this computer                                           */
/* -------------------------------------------------------------------------- */

/// The mode a person chose is on this computer's disk before the page is told, is the mode the
/// window is opened in after a restart, and goes nowhere: settings sync is off until it is turned
/// on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_colour_mode_is_kept_here_and_the_window_is_opened_in_it_and_nothing_is_sent() {
    let computer = Computer::new().await;
    let page = computer.start();

    let view = page.view();
    assert_eq!(view["colour_mode"], "system");
    assert_eq!(view["sync"]["state"], "off");

    assert_eq!(page.choose("dark")["colour_mode"], "dark");
    // A word outside the three is not a mode, and the choice stands.
    page.call("settings_colour_mode_set", json!({ "mode": "sepia" }))
        .expect_err("that is not a colour mode");
    assert_eq!(page.view()["colour_mode"], "dark");
    assert_eq!(
        sync_requests(&computer),
        0,
        "nothing is sent while settings sync is off"
    );

    // The file is the one source: a restart opens the window in the mode, as data in its document.
    drop(page);
    let again = computer.start();
    assert_eq!(again.view()["colour_mode"], "dark");
    let script = again
        .app
        .state::<AppState>()
        .settings()
        .expect("settings")
        .local()
        .initial_script();
    assert!(script.contains(r#"{"colour_mode":"dark"}"#), "{script}");
}

/* -------------------------------------------------------------------------- */
/* Turning it on                                                               */
/* -------------------------------------------------------------------------- */

/// Turning sync on starts a collection of this computer's own, claims it with its first key record,
/// and puts the settings in it sealed: another device with the collection's key reads the mode, and
/// no request carries an account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_sync_on_starts_a_collection_and_puts_the_settings_in_it_sealed() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");

    let view = page.turn_on();
    assert_eq!(view["sync"]["state"], "on");
    assert_eq!(view["sync"]["outstanding"], 0);
    assert_eq!(view["sync"]["conflicts"], 0);
    assert!(view["sync"]["problem"].is_null(), "{view}");

    assert_eq!(computer.elsewhere().colour().await, "dark");

    // Every request is proven by this device's signature alone: no account, no token.
    let arrived = computer.served.web().arrived();
    assert!(!arrived.is_empty());
    for request in &arrived {
        assert_eq!(request.path, SYNC_PATH);
        assert!(request.token.is_none(), "an account token was sent");
        assert!(matches!(
            request.signed_by,
            Some((ServiceRequestSigner::Installation, _))
        ));
    }
}

/// A start the service could not take is not lost: the record names the collection, and turning
/// sync on again goes on with it instead of starting a second one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_that_did_not_finish_goes_on_with_the_collection_it_began() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");

    computer.served.web().fail(SYNC_PATH, 1, Moment::Before);
    let started = page.turn_on();
    assert_eq!(
        started["sync"]["state"], "starting",
        "the claim has not been answered, so the collection is not started"
    );
    let record = std::fs::read(computer.data.path().join("settings-sync").join("sync.json"))
        .expect("the record");

    let view = page.turn_on();
    assert_eq!(view["sync"]["state"], "on");
    assert_eq!(
        std::fs::read(computer.data.path().join("settings-sync").join("sync.json"))
            .map(|after| {
                serde_json::from_slice::<Value>(&after).expect("a record")["collection_id"].clone()
            })
            .expect("the record"),
        serde_json::from_slice::<Value>(&record).expect("a record")["collection_id"],
        "the collection is the one the first start named"
    );
    assert_eq!(computer.elsewhere().colour().await, "dark");
}

/* -------------------------------------------------------------------------- */
/* Keeping in step                                                             */
/* -------------------------------------------------------------------------- */

/// A change made here reaches the service, and a change another device made, while this computer
/// had changed nothing since it last agreed, is followed: the settings file takes it and the page
/// is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_here_is_sent_and_a_change_elsewhere_is_followed() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");
    page.turn_on();
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.colour().await, "dark");

    page.choose("light");
    assert_eq!(elsewhere.colour().await, "light", "a change here is sent");

    assert!(matches!(
        elsewhere.write("dark").await,
        Published::Accepted { .. }
    ));
    let before = page.heard.lock().expect("the record").len();
    let view = page.sync_now();
    assert_eq!(
        view["colour_mode"], "dark",
        "a change elsewhere is followed"
    );
    assert_eq!(view["sync"]["conflicts"], 0);
    assert!(
        page.heard.lock().expect("the record").len() > before,
        "the page is told the settings changed"
    );

    // The file holds it: a restart opens in it.
    drop(page);
    assert_eq!(computer.start().view()["colour_mode"], "dark");
}

/// Checking with nothing changed on either side writes nothing, so a change another device makes
/// after any number of checks is a change this computer follows, and not one it answers with a
/// write of its own against the old place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_that_finds_nothing_new_writes_nothing_and_a_later_change_is_still_followed() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");
    page.turn_on();
    let elsewhere = computer.elsewhere();

    let writes = || {
        computer
            .served
            .web()
            .arrived()
            .iter()
            .filter(|arrived| arrived.path == SYNC_PATH && arrived.body.get("exchange").is_some())
            .count()
    };
    let before = writes();
    for _ in 0..3 {
        let view = page.sync_now();
        assert_eq!(view["colour_mode"], "dark");
        assert_eq!(view["sync"]["conflicts"], 0);
    }
    assert_eq!(
        writes(),
        before,
        "a check that finds nothing new writes nothing"
    );
    assert_eq!(elsewhere.copies_kept().await, 0);

    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));
    let view = page.sync_now();
    assert_eq!(
        view["colour_mode"], "light",
        "the other device's change is followed"
    );
    assert_eq!(view["sync"]["conflicts"], 0, "and asks the person nothing");
    assert_eq!(elsewhere.copies_kept().await, 0);
}

/// Two companions on one computer share the settings file, and neither answers from what it read
/// when it started: the one that did not make a change finds it, and does not write what it held
/// before over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_companion_on_this_computer_does_not_write_over_the_first_ones_choice() {
    let computer = Computer::new().await;
    let first = computer.start();
    first.choose("dark");
    first.turn_on();
    let second = computer.start();
    assert_eq!(second.view()["colour_mode"], "dark");
    let elsewhere = computer.elsewhere();

    first.choose("light");
    assert_eq!(elsewhere.colour().await, "light");
    assert_eq!(
        second.view()["colour_mode"],
        "light",
        "the second one reads the file"
    );
    let view = second.sync_now();
    assert_eq!(view["colour_mode"], "light");
    assert_eq!(view["sync"]["conflicts"], 0);
    assert_eq!(
        elsewhere.colour().await,
        "light",
        "nothing was written over it"
    );
    assert_eq!(elsewhere.copies_kept().await, 0);
}

/// A choice made while the first read of the service is out is not replaced by what that read
/// brings: this computer held nothing when the read left, so there is no version kept beside, and
/// the next publication is refused and keeps what the other device wrote for the person to choose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_choice_made_while_the_first_read_is_out_does_not_replace_what_the_other_device_wrote() {
    use companion_tauri::settings::ColourMode;
    let computer = Computer::new().await;
    let page = computer.start();
    // Nothing is chosen on this computer, and sync is on.
    page.turn_on();
    let elsewhere = computer.elsewhere();
    let before = sync_requests(&computer);
    page.sync_now();
    let per_step = sync_requests(&computer) - before;
    assert!(per_step >= 1, "a step asks the service something");
    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));

    // The step's last request is the read; it is made, and the answer is given when it is let go.
    let web = computer.served.web();
    let asked = sync_requests(&computer);
    web.fail(
        SYNC_PATH,
        u32::try_from(per_step).expect("a small count"),
        Moment::Slow,
    );
    let settings = page.app.state::<AppState>().settings().expect("settings");
    let step = tokio::spawn({
        let settings = Arc::clone(&settings);
        async move { settings.sync_now().await }
    });
    web.requests_reach(SYNC_PATH, asked + per_step).await;
    settings
        .local()
        .set_colour_mode(ColourMode::Dark)
        .expect("the person's choice");
    web.release_held();
    step.await.expect("the step ran").expect("the step ended");

    let view = page.sync_now();
    assert_eq!(view["colour_mode"], "dark", "the person's choice stands");
    assert_eq!(
        view["sync"]["conflicts"], 1,
        "what the other device wrote waits"
    );
    assert_eq!(
        elsewhere.colour().await,
        "light",
        "and is still at the service"
    );
}

/// A step that stops after it read what another device wrote, and before it took it, leaves a note
/// of where that write stands and nothing that holds it. The person's choice made after that is
/// not published against the note: the other device's write is kept beside it for them to choose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_step_that_stopped_before_taking_what_was_read_does_not_let_the_next_choice_replace_it() {
    use companion_tauri::settings::ColourMode;
    let computer = Computer::new().await;
    let page = computer.start();
    // Nothing is chosen on this computer, and sync is on.
    page.turn_on();
    let elsewhere = computer.elsewhere();
    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));

    // The step reads the other device's write and cannot take it: a directory stands where the
    // lock on the settings file is made, so the settings file cannot be written.
    let lock = computer.data.path().join("settings.lock");
    std::fs::create_dir(&lock).expect("a directory where the lock goes");
    let refusal = page
        .call("settings_sync_now", json!({}))
        .expect_err("the step could not take what it read");
    // It stopped where the settings file is taken, which comes after the read: the read left its
    // note, and nothing else is the reason the next choice is kept beside what was read.
    assert!(
        refusal.to_string().contains("could not be locked"),
        "the step stopped at the lock on the settings file: {refusal}"
    );
    std::fs::remove_dir(&lock).expect("the directory goes");

    // The person chooses; the next steps do not publish it over what the other device wrote.
    let settings = page.app.state::<AppState>().settings().expect("settings");
    settings
        .local()
        .set_colour_mode(ColourMode::Dark)
        .expect("the person's choice");
    let view = page.sync_now();
    assert_eq!(view["colour_mode"], "dark", "the person's choice stands");
    assert_eq!(
        view["sync"]["conflicts"], 1,
        "what the other device wrote waits"
    );
    assert_eq!(
        elsewhere.colour().await,
        "light",
        "and is still at the service"
    );
}

/// A file this build cannot read is no choice to compare with, and a mode read from elsewhere does
/// not replace it.
#[test]
fn a_file_this_build_cannot_read_is_not_replaced_by_a_mode_read_elsewhere() {
    use companion_tauri::settings::{ColourMode, LocalSettings};
    let directory = tempfile::tempdir().expect("a directory");
    let file = directory.path().join("settings.json");
    let newer = br#"{"version":99,"colour_mode":"sepia"}"#;
    std::fs::write(&file, newer).expect("a newer build's file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .expect("owner only");
    }
    let settings = LocalSettings::open(directory.path());
    assert!(
        !settings
            .replace_colour_mode(None, ColourMode::Light)
            .expect("a refusal that is no failure")
    );
    assert_eq!(
        std::fs::read(&file).expect("the file"),
        newer,
        "it was not touched"
    );
    // The person's own choice still replaces it.
    settings
        .set_colour_mode(ColourMode::Dark)
        .expect("a choice");
    assert_eq!(settings.chosen_colour_mode(), Some(ColourMode::Dark));
}

/// A replacement that names the choice it expects does not replace a choice made since: the
/// answer says it did not, and the file holds the newer choice.
#[test]
fn a_replacement_that_expected_an_earlier_choice_leaves_the_later_one() {
    use companion_tauri::settings::{ColourMode, LocalSettings};
    let directory = tempfile::tempdir().expect("a directory");
    let settings = LocalSettings::open(directory.path());
    settings
        .set_colour_mode(ColourMode::Dark)
        .expect("a choice");

    assert!(
        settings
            .replace_colour_mode(Some(ColourMode::Dark), ColourMode::Light)
            .expect("a replacement"),
        "the choice that was expected is replaced"
    );
    settings
        .set_colour_mode(ColourMode::System)
        .expect("a later choice");
    assert!(
        !settings
            .replace_colour_mode(Some(ColourMode::Light), ColourMode::Dark)
            .expect("a refusal that is no failure"),
        "a choice made since is not replaced"
    );
    assert_eq!(settings.chosen_colour_mode(), Some(ColourMode::System));
    assert!(
        !settings
            .replace_colour_mode(None, ColourMode::Dark)
            .expect("a refusal that is no failure"),
        "nothing chosen was expected, and something has been"
    );
    // The file says so too: a second reader opened later finds the same.
    assert_eq!(
        LocalSettings::open(directory.path()).chosen_colour_mode(),
        Some(ColourMode::System)
    );
}

/// A change made here while another device changed the same setting is kept for the person: the
/// mode this computer is in stays what the person chose, what the other device wrote is kept
/// beside it, and neither this step nor any later one picks between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_on_both_sides_is_kept_for_the_person_and_nothing_picks_between_them() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");
    page.turn_on();
    let elsewhere = computer.elsewhere();

    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));
    // This computer has not heard of it: its own change is a write against the old place.
    let view = page.choose("system");
    assert_eq!(
        view["colour_mode"], "system",
        "the person's own choice stands"
    );
    assert_eq!(view["sync"]["conflicts"], 1);

    // Later steps leave both where they are.
    for _ in 0..2 {
        let view = page.sync_now();
        assert_eq!(view["colour_mode"], "system");
        assert_eq!(view["sync"]["conflicts"], 1);
    }
    assert_eq!(
        elsewhere.colour().await,
        "light",
        "the service still holds what the other device wrote"
    );
}

/// A service that cannot be reached does not undo the person's choice: it is kept, the page is told
/// what the step could not do, and the next step that reaches the service sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_that_cannot_be_reached_does_not_undo_the_choice() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");
    page.turn_on();
    let elsewhere = computer.elsewhere();

    computer.served.web().fail(SYNC_PATH, 1, Moment::Before);
    let view = page.choose("light");
    assert_eq!(view["colour_mode"], "light");
    assert!(view["sync"]["problem"].is_string(), "{view}");
    assert_eq!(elsewhere.colour().await, "dark");

    let view = page.sync_now();
    assert_eq!(view["colour_mode"], "light");
    assert!(view["sync"]["problem"].is_null(), "{view}");
    assert_eq!(elsewhere.colour().await, "light");
}

/* -------------------------------------------------------------------------- */
/* Choosing between two versions                                               */
/* -------------------------------------------------------------------------- */

/// A computer that chose `system` while another device wrote `light`, with sync on and the
/// collection's copies waiting for a choice.
async fn waiting_for_a_choice(computer: &Computer) -> (Page, Elsewhere) {
    let page = computer.start();
    page.choose("dark");
    page.turn_on();
    let elsewhere = computer.elsewhere();
    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));
    let view = page.choose("system");
    assert_eq!(view["sync"]["conflicts"], 1);
    (page, elsewhere)
}

/// The versions are shown as they are, this computer's own and each the other devices wrote, and
/// the times that are shown decide nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_versions_are_listed_and_none_is_picked_for_the_person() {
    let computer = Computer::new().await;
    let (page, _elsewhere) = waiting_for_a_choice(&computer).await;

    let listed = page
        .call("settings_conflicts", json!({}))
        .expect("the versions");
    assert_eq!(listed["mine"]["colour_mode"], "system");
    let others = listed["others"].as_array().expect("the other versions");
    assert_eq!(others.len(), 1);
    assert_eq!(others[0]["colour_mode"], "light");
    assert!(others[0]["conflict_id"].is_string());

    // Nothing was chosen by being listed or by being synced.
    assert_eq!(page.sync_now()["colour_mode"], "system");
    assert_eq!(page.sync_now()["sync"]["conflicts"], 1);
}

/// Keeping this computer's settings lets every copy go, on this computer and at the service, and
/// sends them as the settings every device now holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeping_this_computers_settings_lets_the_other_content_go_and_sends_them() {
    let computer = Computer::new().await;
    let (page, elsewhere) = waiting_for_a_choice(&computer).await;
    assert_eq!(elsewhere.copies_kept().await, 1);

    let view = page
        .call(
            "settings_conflict_resolve",
            json!({ "keep": { "choice": "mine" } }),
        )
        .expect("the choice is recorded");
    assert_eq!(view["colour_mode"], "system");
    assert_eq!(view["sync"]["conflicts"], 0);
    assert_eq!(elsewhere.colour().await, "system");
    assert_eq!(
        elsewhere.copies_kept().await,
        0,
        "the service kept nothing of the choice"
    );
    assert!(
        page.call("settings_conflicts", json!({}))
            .expect("a read")
            .is_null(),
        "nothing waits"
    );
}

/// Keeping what another device wrote takes it as this computer's own: the settings file holds it,
/// the service holds it as this computer's write, and the page is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeping_what_another_device_wrote_takes_it_as_this_computers_own() {
    let computer = Computer::new().await;
    let (page, elsewhere) = waiting_for_a_choice(&computer).await;
    let listed = page
        .call("settings_conflicts", json!({}))
        .expect("the versions");
    let copy = listed["others"][0]["conflict_id"].clone();

    let view = page
        .call(
            "settings_conflict_resolve",
            json!({ "keep": { "choice": "copy", "conflict_id": copy } }),
        )
        .expect("the choice is recorded");
    assert_eq!(view["colour_mode"], "light");
    assert_eq!(view["sync"]["conflicts"], 0);
    assert_eq!(elsewhere.copies_kept().await, 0);
    drop(page);
    assert_eq!(
        computer.start().view()["colour_mode"],
        "light",
        "the file holds it"
    );
}

/// A choice whose telling the service failed is made all the same: it is on this computer's disk
/// and the copy is gone from it, and the next step that reaches the service tells it, so the
/// service's copy goes too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_choice_the_service_was_not_told_of_is_told_later() {
    let computer = Computer::new().await;
    let (page, elsewhere) = waiting_for_a_choice(&computer).await;

    // The service cannot be reached for as long as the choice is being recorded and sent.
    for nth in 1..=8 {
        computer.served.web().fail(SYNC_PATH, nth, Moment::Before);
    }
    let view = page
        .call(
            "settings_conflict_resolve",
            json!({ "keep": { "choice": "mine" } }),
        )
        .expect("the choice is recorded");
    assert_eq!(view["colour_mode"], "system");
    assert_eq!(
        view["sync"]["conflicts"], 0,
        "the copy is gone from this computer"
    );
    assert!(view["sync"]["problem"].is_string(), "{view}");
    computer.served.web().mend();
    assert_eq!(
        elsewhere.copies_kept().await,
        1,
        "the service has not been told it can let its copy go"
    );

    let view = page.sync_now();
    assert!(view["sync"]["problem"].is_null(), "{view}");
    assert_eq!(elsewhere.copies_kept().await, 0);
    assert_eq!(elsewhere.colour().await, "system");
}

/// Content that says what this computer's settings say asks nothing of the person: it is let go,
/// and nothing is shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_that_says_what_this_computer_says_asks_nothing() {
    let computer = Computer::new().await;
    let page = computer.start();
    page.choose("dark");
    page.turn_on();
    let elsewhere = computer.elsewhere();
    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));
    // This computer chooses the same mode the other device wrote, without having heard of it.
    let view = page.choose("light");
    assert_eq!(view["sync"]["conflicts"], 1);

    let view = page.sync_now();
    assert_eq!(view["sync"]["conflicts"], 0);
    assert_eq!(view["colour_mode"], "light");
    assert_eq!(elsewhere.copies_kept().await, 0);
}

/// A choice that names nothing waiting is refused, and nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_choice_that_names_nothing_waiting_is_refused() {
    let computer = Computer::new().await;
    let (page, _elsewhere) = waiting_for_a_choice(&computer).await;
    let stranger = json!("00000000-0000-4000-8000-0000000000aa");
    page.call(
        "settings_conflict_resolve",
        json!({ "keep": { "choice": "copy", "conflict_id": stranger } }),
    )
    .expect_err("that content is not waiting");
    assert_eq!(page.view()["sync"]["conflicts"], 1);

    let quiet = Computer::new().await;
    let page = quiet.start();
    page.call(
        "settings_conflict_resolve",
        json!({ "keep": { "choice": "mine" } }),
    )
    .expect_err("settings sync is not on");
}

/* -------------------------------------------------------------------------- */
/* Drafts                                                                      */
/* -------------------------------------------------------------------------- */

/// A computer with settings sync on, which drafts sync needs.
async fn with_sync_on(computer: &Computer) -> Page {
    let page = computer.start();
    page.choose("dark");
    assert_eq!(page.turn_on()["sync"]["state"], "on");
    page
}

/// What the page is shown of the drafts kept here and not sent: the reasons, host by host.
fn kept_here(view: &Value) -> Vec<(String, String, u64)> {
    view["sync"]["drafts"]["kept_here"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|kept| {
            (
                kept["host"].as_str().unwrap_or("").to_owned(),
                kept["why"].as_str().expect("a reason").to_owned(),
                kept["drafts"].as_u64().expect("a count"),
            )
        })
        .collect()
}

/// Drafts travel in the settings collection only when the person turns that on, and only once
/// settings sync is on: until then a draft is written and read on this computer and nothing of it
/// is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drafts_stay_on_this_computer_until_the_person_turns_drafts_sync_on() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });

    // Settings sync is off: the switch is refused, and a draft goes nowhere.
    let page = computer.start();
    let refused = page.drafts_on(true).expect_err("settings sync is not on");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|said| said.contains("settings sync")),
        "{refused}"
    );

    page.choose("dark");
    assert_eq!(page.turn_on()["sync"]["state"], "on");
    let (draft, _) = page.write_draft(Some(&studio), "a prompt nobody has sent");
    let view = page.sync_now();
    assert_eq!(view["sync"]["drafts"]["enabled"], false);
    assert_eq!(
        computer.elsewhere().objects().await,
        1,
        "the collection holds the settings and no draft"
    );
    assert_eq!(computer.elsewhere().draft_at(draft).await, None);
}

/// A draft of a host that allows it is sealed on this device and published once, again when the
/// person edits it, and not again while it is unchanged. Another device with the collection's key
/// reads it as a draft; the service holds nothing it could read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_is_published_sealed_once_drafts_sync_is_on_and_again_only_when_it_changes() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version) = page.write_draft(Some(&studio), "a prompt to send later");

    let view = page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(view["sync"]["drafts"]["enabled"], true);
    assert!(kept_here(&view).is_empty(), "{view}");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.objects().await, 2, "the settings and the draft");
    assert_eq!(elsewhere.draft_at(draft).await, Some(1));
    let stored = elsewhere.draft_stored(draft).await.expect("a sealed draft");
    assert!(
        !stored.windows(6).any(|window| window == b"a prom"),
        "what the service holds does not contain the prompt"
    );

    // Unchanged, it is not sent again.
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, Some(1));

    // Edited, it is: the same object at its next write.
    page.rewrite_draft(
        Some(&studio),
        Some(&studio),
        draft,
        &version,
        "a prompt to send tomorrow",
    );
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, Some(2));

    // Another device with the key reads the draft; nothing about it is a request to run anything.
    let other = elsewhere.drafts();
    let fetched = other
        .sync
        .fetch_beside(&other.store, draft, TimestampMs::new(now_ms()))
        .await
        .expect("a fetch");
    assert_eq!(fetched.remote.text, "a prompt to send tomorrow");
}

/// Privacy mode at a host keeps that host's drafts on this device, and the view says so. A host with
/// it off lets them go; the colour mode, which carries no session content, goes either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_of_a_host_in_privacy_mode_stays_here_until_the_host_lets_it_go() {
    let computer = Computer::new().await;
    let (private, studio) = host(1, "studio");
    let (open, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(private, HostPrivacy::On { generation: 3 });
    computer.hosts.say(open, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (held, _) = page.write_draft(Some(&studio), "written for the studio");
    let (sent, _) = page.write_draft(Some(&laptop), "written for the laptop");

    let view = page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(
        elsewhere.draft_at(sent).await,
        Some(1),
        "the open host's draft left"
    );
    assert_eq!(
        elsewhere.draft_at(held).await,
        None,
        "the private host's draft stayed"
    );
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 1)],
        "the view says which drafts are kept and why: {view}"
    );

    // The colour mode is not session content: it still goes.
    page.choose("light");
    assert_eq!(elsewhere.colour().await, "light");

    // Privacy mode goes off at the host, at a generation of its own, and the draft goes.
    computer
        .hosts
        .say(private, HostPrivacy::Off { generation: 4 });
    let view = page.sync_now();
    assert_eq!(elsewhere.draft_at(held).await, Some(1));
    assert!(kept_here(&view).is_empty(), "{view}");
}

/// A host in privacy mode stops what was already published too: a draft edited while the host is
/// private is not sent, and goes once the host lets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_made_while_the_host_is_private_is_not_sent() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version) = page.write_draft(Some(&studio), "first");
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(draft).await, Some(1));

    computer
        .hosts
        .say(environment, HostPrivacy::On { generation: 2 });
    page.rewrite_draft(
        Some(&studio),
        Some(&studio),
        draft,
        &version,
        "second, while private",
    );
    let view = page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, Some(1), "nothing left");
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 1)]
    );

    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 3 });
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, Some(2));
}

/// A host this computer cannot read is treated as private: its drafts stay here, and the view says
/// that this computer could not read it and why. So are the drafts of a host no connection was up
/// to name when they were written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_drafts_of_a_host_this_computer_cannot_read_stay_here_and_the_view_says_why() {
    let computer = Computer::new().await;
    let (_unread, studio) = host(1, "studio");
    // Nothing is said of the studio: this computer is not connected to it.
    let page = with_sync_on(&computer).await;
    let (unreadable, _) = page.write_draft(Some(&studio), "written for a host nobody can read");
    let (unknown, _) = page.write_draft(None, "written while no host was connected");

    let view = page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(unreadable).await, None);
    assert_eq!(elsewhere.draft_at(unknown).await, None);
    assert_eq!(elsewhere.objects().await, 1, "only the settings");
    let mut kept = kept_here(&view);
    kept.sort();
    assert_eq!(
        kept,
        vec![
            (String::new(), "unknown_host".to_owned(), 1),
            ("studio".to_owned(), "unreadable".to_owned(), 1),
        ],
        "{view}"
    );
    let detail = view["sync"]["drafts"]["kept_here"]
        .as_array()
        .expect("a list")
        .iter()
        .find_map(|kept| kept["detail"].as_str())
        .expect("what this computer could not read, in words");
    assert!(detail.contains("not connected"), "{detail}");
}

/// A draft another device wrote arrives as a copy kept beside this computer's own: it is never one of
/// this computer's drafts, a version of it that was brought down is not brought down again, and a
/// later version is another copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_another_device_wrote_arrives_as_a_kept_copy_and_nothing_is_sent_for_it() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    page.write_draft(Some(&studio), "this computer's own draft");
    page.drafts_on(true).expect("drafts sync is on");

    let elsewhere = computer.elsewhere();
    let other = elsewhere.drafts();
    let theirs = other.publish("what the other device wrote").await;
    page.sync_now();

    let listed = page.kept_drafts();
    assert_eq!(
        listed.len(),
        2,
        "this computer's own and one copy: {listed:?}"
    );
    let copy = listed
        .iter()
        .find(|draft| !draft["copyOf"].is_null())
        .expect("a copy");
    assert_eq!(copy["copyOf"], json!(theirs.draft_id));
    assert_eq!(copy["text"], "what the other device wrote");
    let own = listed
        .iter()
        .find(|draft| draft["copyOf"].is_null())
        .expect("an own draft");
    assert_eq!(own["text"], "this computer's own draft");

    // Brought down once: the same version is not asked for again.
    let before = computer.served.web().requests_to(SYNC_PATH);
    page.sync_now();
    assert_eq!(page.kept_drafts().len(), 2);
    let after = computer.served.web().requests_to(SYNC_PATH);
    assert!(after > before, "a step still looks at the collection");
    assert_eq!(
        elsewhere.draft_at(theirs.draft_id).await,
        Some(1),
        "this computer wrote nothing of it"
    );

    // A later version is another copy.
    other
        .edit(&theirs, "what the other device wrote next")
        .await;
    page.sync_now();
    let texts: Vec<String> = page
        .kept_drafts()
        .iter()
        .filter(|draft| !draft["copyOf"].is_null())
        .map(|draft| draft["text"].as_str().expect("text").to_owned())
        .collect();
    assert_eq!(texts.len(), 2, "{texts:?}");
    assert!(texts.contains(&"what the other device wrote next".to_owned()));
}

/// A draft thrown away or sent is removed at the service, so its place is free and its sealed copy
/// does not stay there. A draft that never left asks nothing of the service, and a removal owed to a
/// host in privacy mode waits for the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_thrown_away_is_removed_at_the_service_when_its_host_allows_it() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (kept, kept_version) = page.write_draft(Some(&studio), "sent, then thrown away");
    let (never, never_version) = page.write_draft(Some(&studio), "never left this computer");
    // The second draft is thrown away before drafts sync was ever on.
    page.discard_draft(never, &never_version);
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(kept).await, Some(1));
    assert_eq!(elsewhere.draft_at(never).await, None);
    assert_eq!(elsewhere.objects().await, 2);

    // The host goes private, and the person sends the first draft. It goes from here at once, and
    // the service's copy waits for the host.
    computer
        .hosts
        .say(environment, HostPrivacy::On { generation: 2 });
    assert_eq!(page.discard_draft(kept, &kept_version)["removed"], true);
    page.sync_now();
    assert_eq!(
        elsewhere.draft_at(kept).await,
        Some(1),
        "waiting for the host"
    );
    assert!(page.kept_drafts().is_empty(), "it is gone here");

    // The host lets it go: the service's copy is removed and its place is free. It does not come
    // back as a copy of somebody else's draft.
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 3 });
    page.sync_now();
    assert_eq!(elsewhere.draft_at(kept).await, None);
    assert_eq!(elsewhere.objects().await, 1, "only the settings");
    page.sync_now();
    assert!(
        page.kept_drafts().is_empty(),
        "nothing came back: {:?}",
        page.kept_drafts()
    );
}

/// Turning drafts sync off stops what a step does and keeps what it knew, so turning it on again
/// takes up where it stopped, and the choice survives a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_drafts_sync_off_sends_nothing_and_the_choice_is_kept_across_a_restart() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    page.drafts_on(true).expect("on");
    let (draft, _) = page.write_draft(Some(&studio), "written while it is on");
    page.drafts_on(false).expect("off");
    page.sync_now();
    assert_eq!(computer.elsewhere().draft_at(draft).await, None);

    drop(page);
    let page = computer.start();
    assert_eq!(page.view()["sync"]["drafts"]["enabled"], false);
    page.drafts_on(true).expect("on again");
    assert_eq!(computer.elsewhere().draft_at(draft).await, Some(1));
    drop(page);
    let page = computer.start();
    assert_eq!(page.view()["sync"]["drafts"]["enabled"], true);
}

/// Typing in a draft that is kept on this computer reaches no service: a draft saved while drafts
/// sync is off wakes nothing, and one saved while it is on asks for a pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_saved_while_drafts_sync_is_off_wakes_nothing() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let settings = page
        .app
        .state::<AppState>()
        .settings()
        .expect("the settings");
    let woken = |settings: Arc<companion_tauri::settings::Settings>| async move {
        tokio::time::timeout(std::time::Duration::ZERO, settings.drafts_changed())
            .await
            .is_ok()
    };

    page.write_draft(Some(&studio), "typed while it is off");
    assert!(
        !woken(Arc::clone(&settings)).await,
        "nothing asked for a pass"
    );

    // Turning it on asks for one. Taking that, a save asks for another.
    page.drafts_on(true).expect("drafts sync is on");
    assert!(woken(Arc::clone(&settings)).await);
    page.write_draft(Some(&studio), "typed while it is on");
    assert!(woken(Arc::clone(&settings)).await, "a save asks for a pass");
}

/// A draft is for the host that holds its session, and a host is not given a draft by being the one
/// connected when the draft is saved: the draft of a private host that was written while no host
/// was connected, or a draft saved again for a mark while another host is connected, stays here
/// until the host that holds its session says so, and then it is held to that host's mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_is_given_to_no_host_by_being_saved_while_that_host_is_connected() {
    let computer = Computer::new().await;
    let (private, studio) = host(1, "studio");
    let (open, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(private, HostPrivacy::On { generation: 3 });
    computer.hosts.say(open, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    // Written for a session of the studio while this computer was connected to no host, and saved
    // again, as the page does to mark it, while it is connected to the laptop.
    let (draft, version) = page.write_draft_while(Some(&studio), None, "written for the studio");
    page.rewrite_draft(
        Some(&studio),
        Some(&laptop),
        draft,
        &version,
        "written for the studio, again",
    );

    let view = page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(
        computer.elsewhere().draft_at(draft).await,
        None,
        "the laptop is not the host of a session it does not hold"
    );
    assert_eq!(
        kept_here(&view),
        vec![(String::new(), "unknown_host".to_owned(), 1)]
    );

    // The studio is connected, says it holds the session, and is private.
    computer.hosts.connect(&studio);
    let view = page.sync_now();
    assert_eq!(computer.elsewhere().draft_at(draft).await, None);
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 1)]
    );

    // And when the studio lets its drafts go, this one goes.
    computer
        .hosts
        .say(private, HostPrivacy::Off { generation: 4 });
    page.sync_now();
    assert_eq!(computer.elsewhere().draft_at(draft).await, Some(1));
}

/// A host is asked about a draft's session until one says it holds it, and not again once it has:
/// and a host that cannot be asked is asked once for the whole pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_cannot_be_asked_is_asked_once_for_all_the_drafts_of_a_pass() {
    let computer = Computer::new().await;
    let (_unread, studio) = host(1, "studio");
    let page = with_sync_on(&computer).await;
    for turn in 0..3 {
        page.write_draft_while(
            Some(&studio),
            None,
            &format!("written for the studio {turn}"),
        );
    }
    page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(
        computer.hosts.times_asked_who_holds(),
        1,
        "the first question had no answer, and the pass asked no more"
    );
}

/// Sending a draft to a session of another host makes it that host's draft: what the first host
/// said of the old session says nothing of the new one, so the draft waits for the second host and
/// is held to its mode, though the first host would let it go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_sent_to_a_session_of_another_host_is_held_to_that_hosts_mode() {
    let computer = Computer::new().await;
    let (open, studio) = host(1, "studio");
    let (private, laptop) = host(2, "laptop");
    computer.hosts.say(open, HostPrivacy::Off { generation: 1 });
    computer
        .hosts
        .say(private, HostPrivacy::On { generation: 5 });
    let page = with_sync_on(&computer).await;
    let (draft, version) = page.write_draft(Some(&studio), "written for the studio");
    page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(computer.elsewhere().draft_at(draft).await, Some(1));

    page.retarget_draft(draft, &version, &laptop);
    let view = page.sync_now();
    assert_eq!(
        computer.elsewhere().draft_at(draft).await,
        Some(1),
        "nothing more of it left"
    );
    assert_eq!(
        kept_here(&view),
        vec![("laptop".to_owned(), "private".to_owned(), 1)]
    );
}

/// A host that reads as private is private for the rest of the pass: it is not asked again for
/// every draft of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_host_is_read_once_for_all_its_drafts_in_a_pass() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::On { generation: 2 });
    let page = with_sync_on(&computer).await;
    for turn in 0..3 {
        page.write_draft(Some(&studio), &format!("written for the studio {turn}"));
    }
    let view = page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 3)]
    );
    assert_eq!(computer.hosts.reads_of(environment), 1);
}

/// The first publication of a draft is held at the service: it acts on it and gives its answer when
/// it is let go. The host says `says` meanwhile, without the pass having read it since. What is
/// noted of the draft is returned, and what the pass reports.
async fn host_says_while_a_publication_is_out(
    computer: &Computer,
    says: HostPrivacy,
) -> (Option<SyncCheckpoint>, Value) {
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(computer).await;
    page.drafts_on(true).expect("drafts sync is on");
    let (draft, _) = page.write_draft(Some(&studio), "a prompt on its way out");

    // The pass asks the collection once for the settings and then publishes the draft, so the
    // publication is the second request.
    let web = computer.served.web();
    let asked = sync_requests(computer);
    web.fail(SYNC_PATH, 2, Moment::Slow);
    let settings = page.app.state::<AppState>().settings().expect("settings");
    let step = tokio::spawn({
        let settings = Arc::clone(&settings);
        async move { settings.sync_now().await }
    });
    web.requests_reach(SYNC_PATH, asked + 2).await;
    computer.hosts.say(environment, says);
    web.release_held();
    let view = step.await.expect("the step ran").expect("the step ended");

    let noted = page
        .app
        .state::<AppState>()
        .drafts()
        .store()
        .expect("drafts")
        .checkpoint(draft)
        .expect("the note");
    (noted, serde_json::to_value(view).expect("a view"))
}

/// A host that goes private while a publication is out at the service is read again when the answer
/// arrives, before the answer is settled: the answer is discarded and nothing is noted of the
/// draft, whatever the pass had read of the host before, and the view says the draft is kept for
/// the host's privacy mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_goes_private_while_a_publication_is_out_has_the_answer_discarded() {
    let computer = Computer::new().await;
    let (noted, view) =
        host_says_while_a_publication_is_out(&computer, HostPrivacy::On { generation: 2 }).await;
    assert_eq!(
        noted, None,
        "the answer to a publication admitted under the old generation is not noted"
    );
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 1)],
        "{view}"
    );
}

/// A publication of a draft another device wrote first is refused, and the service answers with the
/// other device's draft. When the host cannot be read as the answer arrives, nothing of it is kept
/// beside this computer's own: the draft is fenced, as the host's privacy mode asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_that_arrives_while_the_host_cannot_be_read_brings_nothing_down() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, _) = page.write_draft(Some(&studio), "written for the studio");
    let held = page
        .app
        .state::<AppState>()
        .drafts()
        .store()
        .expect("drafts");
    computer
        .elsewhere()
        .claim_draft(&held.load(draft).expect("the draft"))
        .await;
    // The pass reads the host when it opens the store and before the draft leaves, and the host
    // cannot be read from the third question, which is the one as the answer arrives.
    computer.hosts.turn_after(
        environment,
        2,
        HostPrivacy::Unreadable {
            reason: "the connection dropped".to_owned(),
        },
    );

    page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(
        page.kept_drafts().len(),
        1,
        "nothing the service answered with was kept: {:?}",
        page.kept_drafts()
    );
    assert_eq!(
        kept_here(&page.view()),
        vec![("studio".to_owned(), "unreadable".to_owned(), 1)],
        "and the card says why the draft waits"
    );
}

/// A host whose state was reset reports a generation below the one this computer holds for it. Its
/// word that privacy mode is off is believed, and a store cannot follow it down when it turns on
/// again: it is fenced at the generation it holds, so what an answer brings down is withheld. A
/// write the service applied before then is noted all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_goes_private_below_the_generation_held_has_what_the_answer_brings_withheld() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 10 });
    let page = with_sync_on(&computer).await;
    page.write_draft(Some(&studio), "published at generation ten");
    page.drafts_on(true).expect("drafts sync is on");

    let (draft, _) = page.write_draft(Some(&studio), "written after the host was reset");
    let held = page
        .app
        .state::<AppState>()
        .drafts()
        .store()
        .expect("drafts");
    computer
        .elsewhere()
        .claim_draft(&held.load(draft).expect("the draft"))
        .await;
    // The host is reset, says off at generation 1, and says private at generation 2 as the answer
    // arrives.
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    computer
        .hosts
        .turn_after(environment, 2, HostPrivacy::On { generation: 2 });
    let view = page.sync_now();
    assert_eq!(
        page.kept_drafts().len(),
        2,
        "nothing the service answered with was kept: {:?}",
        page.kept_drafts()
    );
    let kept = &view["sync"]["drafts"]["kept_here"];
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "unreadable".to_owned(), 1)],
        "and the card says why the draft waits: {kept}"
    );
    assert!(
        kept[0]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("ahead")),
        "and that the store is ahead of the host: {kept}"
    );
}

/// A host that cannot be read when the answer arrives is treated as private from then on: the store
/// is fenced at the generation it holds, so what an answer brings down is withheld. The account of
/// a write the service applied is kept all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_cannot_be_read_when_the_answer_arrives_is_treated_as_private() {
    let computer = Computer::new().await;
    let (noted, view) = host_says_while_a_publication_is_out(
        &computer,
        HostPrivacy::Unreadable {
            reason: "the connection dropped".to_owned(),
        },
    )
    .await;
    assert!(noted.is_some(), "the write the service applied is noted");
    assert!(
        kept_here(&view).is_empty(),
        "it left, and nothing waits: {view}"
    );
}

/// A host that goes private while a pass is out at the service is read again just before each draft
/// of it leaves: the first draft goes under the mode the host was in, and the second does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_goes_private_during_a_pass_keeps_the_drafts_that_had_not_left_yet() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (first, _) = page.write_draft(Some(&studio), "the first");
    let (second, _) = page.write_draft(Some(&studio), "the second");
    // The pass asks once when it begins, once before each draft and once when each answer arrives:
    // the host answers private from the fourth question, which is the one before the second draft.
    computer
        .hosts
        .turn_after(environment, 3, HostPrivacy::On { generation: 2 });

    let view = page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    let left = [
        elsewhere.draft_at(first).await,
        elsewhere.draft_at(second).await,
    ];
    assert_eq!(
        left.iter().flatten().count(),
        1,
        "exactly one draft left before the host went private: {left:?}"
    );
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 1)]
    );
}

/// A draft thrown away while its first publication is out, and whose answer is lost, still leaves
/// nothing at the service: the answer is found by asking, it settles a note after the draft is gone,
/// and the removal is made against that position. It is not brought back as another device's draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_thrown_away_while_its_first_publication_is_out_leaves_nothing_at_the_service() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version) = page.write_draft(Some(&studio), "sent before the answer came back");
    // The service takes the draft's first publication and the answer is lost. The pass asks the
    // collection once for the settings and then publishes the draft, so it is the second request.
    computer.served.web().fail(SYNC_PATH, 2, Moment::After);
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(draft).await, Some(1), "it landed");
    let sent = computer
        .served
        .web()
        .arrived()
        .iter()
        .filter(|arrived| arrived.path == SYNC_PATH && arrived.body["exchange"]["kind"] == "draft")
        .count();
    assert_eq!(
        sent, 1,
        "the publication went once, and its answer was lost"
    );
    assert!(
        page.view()["sync"]["drafts"]["problem"].is_string(),
        "the pass says it could not settle the publication: {}",
        page.view()
    );

    // The person sends it, and it goes from here while the publication is still unsettled.
    assert_eq!(page.discard_draft(draft, &version)["removed"], true);
    page.sync_now();
    page.sync_now();
    assert_eq!(
        elsewhere.draft_at(draft).await,
        None,
        "it left nothing behind"
    );
    assert_eq!(elsewhere.objects().await, 1, "only the settings");
    assert!(
        page.kept_drafts().is_empty(),
        "and it did not come back as a copy: {:?}",
        page.kept_drafts()
    );
}

/// The first publication of a draft is applied and its answer is lost.
async fn with_a_publication_whose_answer_was_lost(
    computer: &Computer,
    page: &Page,
    studio: &DraftHost,
) -> (DraftId, String, Elsewhere) {
    let (draft, version) = page.write_draft(Some(studio), "sent before the answer came back");
    // The pass asks the collection once for the settings and then publishes the draft, so it is the
    // second request.
    computer.served.web().fail(SYNC_PATH, 2, Moment::After);
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(draft).await, Some(1), "it landed");
    (draft, version, elsewhere)
}

/// A host that goes private after a publication's answer was lost, and before the pass that asks
/// what became of it, has that publication settled under a generation it has moved past, which
/// notes nothing of where the draft landed. A draft sent meanwhile is still owed a removal: it is
/// made against the place the publication left it, when the host lets it, and the draft does not
/// come back as another device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_privacy_change_that_settles_a_lost_answer_leaves_the_removal_owed() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version, elsewhere) =
        with_a_publication_whose_answer_was_lost(&computer, &page, &studio).await;

    assert_eq!(page.discard_draft(draft, &version)["removed"], true);
    computer
        .hosts
        .say(environment, HostPrivacy::On { generation: 2 });
    page.sync_now();
    assert_eq!(
        elsewhere.draft_at(draft).await,
        Some(1),
        "the host is private, so the removal waits"
    );
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 3 });
    page.sync_now();
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, None, "it was removed");
    assert!(
        page.kept_drafts().is_empty(),
        "and it did not come back as a copy: {:?}",
        page.kept_drafts()
    );
}

/// A publication that left through a host the draft is no longer for is asked about all the same:
/// the draft is sent to a session of a host that is private, a pass proves that host, the person
/// sends the prompt, and when the host lets go the removal is made, since the first host's store
/// was reconciled and says where the draft landed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_publication_that_left_through_another_host_is_asked_about_though_the_draft_moved_on() {
    let computer = Computer::new().await;
    let (first, studio) = host(1, "studio");
    let (second, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(first, HostPrivacy::Off { generation: 1 });
    computer
        .hosts
        .say(second, HostPrivacy::On { generation: 2 });
    let page = with_sync_on(&computer).await;
    let (draft, version, elsewhere) =
        with_a_publication_whose_answer_was_lost(&computer, &page, &studio).await;

    let moved = page.retarget_draft(draft, &version, &laptop);
    let view = page.sync_now();
    assert_eq!(
        kept_here(&view),
        vec![("laptop".to_owned(), "private".to_owned(), 1)]
    );
    assert_eq!(page.discard_draft(draft, &moved)["removed"], true);
    computer
        .hosts
        .say(second, HostPrivacy::Off { generation: 3 });
    page.sync_now();
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, None, "it was removed");
    assert!(
        page.kept_drafts().is_empty(),
        "and it did not come back as a copy: {:?}",
        page.kept_drafts()
    );
}

/// An entry left for a draft that is still stored belongs to a removal that did not happen: it is
/// dropped, and the draft keeps the note of where the service holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_left_for_a_draft_that_is_still_stored_is_dropped_and_the_draft_keeps_its_note() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, _) = page.write_draft(Some(&studio), "a prompt");
    page.drafts_on(true).expect("drafts sync is on");
    let held = page
        .app
        .state::<AppState>()
        .drafts()
        .store()
        .expect("drafts");
    assert!(held.checkpoint(draft).expect("the note").is_some());

    let ledger = computer
        .data
        .path()
        .join("settings-sync/drafts/removals.json");
    kr_ipc::paths::write_owner_only_file(
        &ledger,
        &serde_json::to_vec(&json!([{
            "id": "6c1e9a52-0000-4000-8000-000000000001",
            "draft": draft,
            "host": null,
            "note": null
        }]))
        .expect("a ledger"),
    )
    .expect("the stale entry");
    page.sync_now();
    assert!(
        held.checkpoint(draft).expect("the note").is_some(),
        "the draft kept its note"
    );
    let left: Vec<Value> =
        serde_json::from_slice(&std::fs::read(&ledger).expect("the ledger")).expect("a list");
    assert!(left.is_empty(), "and the entry is gone: {left:?}");
    // A draft that forgot its note would be published against nothing, refused, and kept beside
    // the service's copy of itself.
    assert_eq!(computer.elsewhere().draft_at(draft).await, Some(1));
    assert_eq!(
        page.kept_drafts().len(),
        1,
        "and no copy of its own text was kept beside it: {:?}",
        page.kept_drafts()
    );
}

/// A stale entry for a draft that is still stored is dropped by the pass that reads it, and a discard
/// that adopts it while that pass is out at the service keeps it: the draft is removed afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discard_that_adopts_a_stale_entry_while_a_pass_is_out_keeps_the_removal_owed() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (first, first_version) = page.write_draft(Some(&studio), "a prompt sent first");
    let (second, second_version) = page.write_draft(Some(&studio), "a prompt kept");
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(first).await, Some(1));
    assert_eq!(elsewhere.draft_at(second).await, Some(1));

    // The first draft is thrown away, and an entry is left behind for the second, which is still
    // stored: the ledger reads the first's removal, then the second's stale entry.
    assert_eq!(page.discard_draft(first, &first_version)["removed"], true);
    let ledger = computer
        .data
        .path()
        .join("settings-sync/drafts/removals.json");
    let mut entries: Vec<Value> =
        serde_json::from_slice(&std::fs::read(&ledger).expect("the ledger")).expect("a list");
    entries.push(json!({
        "id": "6c1e9a52-0000-4000-8000-000000000001",
        "draft": second,
        "host": null,
        "note": null
    }));
    kr_ipc::paths::write_owner_only_file(&ledger, &serde_json::to_vec(&entries).expect("a ledger"))
        .expect("the stale entry");

    // The pass asks the collection once for the settings and then removes the first draft, which
    // is the second request; the service gives its answer when it is let go.
    let web = computer.served.web();
    let asked = sync_requests(&computer);
    web.fail(SYNC_PATH, 2, Moment::Slow);
    let settings = page.app.state::<AppState>().settings().expect("settings");
    let step = tokio::spawn({
        let settings = Arc::clone(&settings);
        async move { settings.sync_now().await }
    });
    web.requests_reach(SYNC_PATH, asked + 2).await;
    assert_eq!(page.discard_draft(second, &second_version)["removed"], true);
    web.release_held();
    step.await.expect("the step ran").expect("the step ended");

    page.sync_now();
    page.sync_now();
    assert_eq!(elsewhere.draft_at(first).await, None);
    assert_eq!(
        elsewhere.draft_at(second).await,
        None,
        "the draft thrown away while the pass was out at the service was removed"
    );
    assert!(page.kept_drafts().is_empty(), "{:?}", page.kept_drafts());
}

/// A host that refuses to say whether it holds one session does not keep this computer from asking
/// about the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_about_one_session_does_not_stop_the_questions_about_the_others() {
    let computer = Computer::new().await;
    let (restricted, studio) = host(1, "studio");
    let (answering, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(restricted, HostPrivacy::Off { generation: 1 });
    computer
        .hosts
        .say(answering, HostPrivacy::Off { generation: 1 });
    computer.hosts.refuse_to_say(&studio);
    let page = with_sync_on(&computer).await;
    let (refused, _) = page.write_draft(Some(&studio), "written for the studio");
    let (answered, _) = page.write_draft(Some(&laptop), "written for the laptop");

    let view = page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(refused).await, None);
    assert_eq!(elsewhere.draft_at(answered).await, Some(1));
    assert_eq!(
        kept_here(&view),
        vec![(String::new(), "unknown_host".to_owned(), 1)]
    );
}

/// A second window throwing away a draft the first already threw away leaves what the first owed:
/// the removal is still made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_discard_of_a_removed_draft_keeps_what_the_first_owed() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version, elsewhere) =
        with_a_publication_whose_answer_was_lost(&computer, &page, &studio).await;

    assert_eq!(page.discard_draft(draft, &version)["removed"], true);
    assert_eq!(page.discard_draft(draft, &version)["removed"], false);
    page.sync_now();
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, None, "it was removed");
}

/// Turning drafts sync off does not turn off what the service is owed: a draft sent while it is off
/// whose first publication never got an answer is removed when it is on again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_sent_while_drafts_sync_is_off_is_still_removed_at_the_service() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version, elsewhere) =
        with_a_publication_whose_answer_was_lost(&computer, &page, &studio).await;

    page.drafts_on(false).expect("off");
    assert_eq!(page.discard_draft(draft, &version)["removed"], true);
    page.drafts_on(true).expect("on");
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, None, "it was removed");
    assert!(
        page.kept_drafts().is_empty(),
        "and it did not come back as a copy: {:?}",
        page.kept_drafts()
    );
}

/// A draft sent to a session of another host after its first publication lost its answer is still
/// owed a removal where the publication went: the removal is found through the store of the host
/// the publication left through, and not only the host the draft is for now.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_sent_to_another_host_after_a_lost_answer_is_still_removed_where_it_was_published()
{
    let computer = Computer::new().await;
    let (first, studio) = host(1, "studio");
    let (second, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(first, HostPrivacy::Off { generation: 1 });
    computer
        .hosts
        .say(second, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version, elsewhere) =
        with_a_publication_whose_answer_was_lost(&computer, &page, &studio).await;

    let moved = page.retarget_draft(draft, &version, &laptop);
    assert_eq!(page.discard_draft(draft, &moved)["removed"], true);
    page.sync_now();
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, None, "it was removed");
    assert!(
        page.kept_drafts().is_empty(),
        "and it did not come back as a copy: {:?}",
        page.kept_drafts()
    );
}

/// A host whose store cannot be opened is one this computer cannot send for, and says why; the
/// drafts of the other hosts go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_whose_store_cannot_be_opened_does_not_stop_the_drafts_of_the_others() {
    let computer = Computer::new().await;
    let (broken, studio) = host(1, "studio");
    let (steady, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(broken, HostPrivacy::Off { generation: 1 });
    computer
        .hosts
        .say(steady, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (held, _) = page.write_draft(Some(&studio), "written for the studio");
    let (sent, _) = page.write_draft(Some(&laptop), "written for the laptop");
    // Where the studio's store is to be, there is a file.
    let place = computer
        .data
        .path()
        .join("settings-sync/drafts")
        .join(broken.to_string());
    std::fs::create_dir_all(&place).expect("a directory");
    std::fs::write(place.join("store"), b"not a store").expect("a file");

    let view = page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    assert_eq!(elsewhere.draft_at(held).await, None);
    assert_eq!(elsewhere.draft_at(sent).await, Some(1), "the laptop's went");
    let kept = kept_here(&view);
    assert_eq!(kept.len(), 1, "{view}");
    assert_eq!(
        (kept[0].0.as_str(), kept[0].1.as_str()),
        ("studio", "unreadable")
    );
    assert!(
        view["sync"]["drafts"]["kept_here"][0]["detail"].is_string(),
        "and the view says why: {view}"
    );
}

/// A record of what the service is owed that this version cannot read is not written over: the
/// removal is refused and the draft stays, since one the service is owed for and no record of it is
/// a draft that comes back as another device's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ledger_this_version_cannot_read_is_not_written_over_and_the_draft_stays() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version) = page.write_draft(Some(&studio), "a prompt");
    page.drafts_on(true).expect("drafts sync is on");
    let ledger = computer
        .data
        .path()
        .join("settings-sync/drafts/removals.json");
    kr_ipc::paths::write_owner_only_file(&ledger, b"this is not a list")
        .expect("the ledger is spoiled");

    let refused = page.call(
        "device_draft_discard",
        json!({ "params": { "id": draft, "expectedRevision": version } }),
    );
    assert!(refused.is_err(), "the removal is refused: {refused:?}");
    assert_eq!(page.kept_drafts().len(), 1, "the draft stays");
    assert_eq!(
        std::fs::read(&ledger).expect("the ledger"),
        b"this is not a list",
        "and the record is as it was"
    );
}

/// A draft of another device that its device removes is gone at the service, and what this computer
/// kept to ask about it goes too, so the list of what it asks about does not grow with every draft
/// that ever came down. The copy that was kept stays: it is the person's to keep or throw away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_the_other_device_removed_is_forgotten_here_and_the_kept_copy_stays() {
    let computer = Computer::new().await;
    let (environment, studio) = host(1, "studio");
    computer
        .hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    page.write_draft(Some(&studio), "this computer's own");
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = computer.elsewhere();
    let other = elsewhere.drafts();
    let theirs = other.publish("written on the laptop").await;
    page.sync_now();
    let pulled = || -> Vec<String> {
        std::fs::read(
            computer
                .data
                .path()
                .join("settings-sync/drafts/pulled.json"),
        )
        .map(|bytes| serde_json::from_slice(&bytes).expect("a list"))
        .unwrap_or_default()
    };
    assert_eq!(pulled(), vec![theirs.draft_id.to_string()]);
    assert_eq!(
        from_other_devices(&page.kept_drafts()),
        1,
        "the copy is another device's"
    );

    // The other device throws its draft away, and the service no longer holds it.
    let note = other
        .store
        .checkpoint(theirs.draft_id)
        .expect("a note")
        .expect("it was published");
    other
        .sync
        .remove(theirs.draft_id, note.position, TimestampMs::new(now_ms()))
        .await
        .expect("a removal");
    page.sync_now();
    assert!(pulled().is_empty(), "nothing is asked about it any more");
    assert_eq!(
        page.kept_drafts().len(),
        2,
        "the copy stays beside the own draft"
    );
    assert_eq!(
        from_other_devices(&page.kept_drafts()),
        1,
        "and it is still said to be another device's, not another window's"
    );
}

/// How many of the drafts kept here were written on another device.
fn from_other_devices(drafts: &[Value]) -> usize {
    drafts
        .iter()
        .filter(|draft| draft["fromAnotherDevice"] == true)
        .count()
}

/// A host that reports an older privacy generation than this computer holds for it (its state was
/// reset) is not believed: the store keeps the generation it has, so a host that says privacy mode is
/// on would otherwise leave the store open. Nothing of that host is sent, and the others go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_reports_an_older_generation_than_this_computer_holds_is_not_believed() {
    let computer = Computer::new().await;
    let (reset, studio) = host(1, "studio");
    let (steady, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(reset, HostPrivacy::Off { generation: 7 });
    computer
        .hosts
        .say(steady, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    page.write_draft(Some(&studio), "written for the studio");
    page.write_draft(Some(&laptop), "written for the laptop");
    page.drafts_on(true).expect("drafts sync is on");

    // The studio's state is reset: it is private again, at generation 1 of a new history.
    computer.hosts.say(reset, HostPrivacy::On { generation: 1 });
    let (written_after, _) =
        page.write_draft(Some(&studio), "written for the studio, after the reset");
    let (kept, _) = page.write_draft(Some(&laptop), "written for the laptop, after the reset");
    let view = page.sync_now();
    let elsewhere = computer.elsewhere();
    assert_eq!(
        elsewhere.draft_at(written_after).await,
        None,
        "the store holds generation 7, unfenced: the host is not believed, and nothing is sent"
    );
    assert_eq!(
        elsewhere.draft_at(kept).await,
        Some(1),
        "the other host's draft went on"
    );
    assert!(
        kept_here(&view)
            .iter()
            .any(|(host, _, drafts)| host == "studio" && *drafts == 1),
        "the view says the studio's draft stays: {view}"
    );
}

/* -------------------------------------------------------------------------- */
/* Another device joins                                                        */
/* -------------------------------------------------------------------------- */

/// A reference of the first entry of `list`, which a page names a device or an offer by.
fn first_reference(list: &Value) -> String {
    list[0]["reference"]
        .as_str()
        .expect("a reference")
        .to_owned()
}

/// The person's two computers, both listed as owner devices by the hosts each can ask.
async fn two_computers() -> (Computer, Computer) {
    let this = Computer::new().await;
    let other = Computer::beside(&this).await;
    let devices = vec![this.listed("this-mac"), other.listed("the-phone")];
    this.hosts.list(devices.clone());
    other.hosts.list(devices);
    (this, other)
}

/// A second device the hosts list is offered the settings, the person confirms on the first, the
/// second finds the offer and joins when the person confirms there, and the settings the first
/// wrote follow it: the key moved on when the device was added, and the first sealed the settings
/// under the new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_device_is_given_the_key_joins_and_reads_what_the_first_wrote() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();

    // Nothing shares anything yet, and the phone is a device the first computer's hosts list.
    let offers = phone.devices_refresh();
    assert_eq!(offers["offers"], json!([]), "{offers}");
    let shown = page.devices_refresh();
    assert_eq!(shown["candidates"][0]["name"], "the-phone", "{shown}");
    assert_eq!(shown["members"].as_array().expect("members").len(), 1);

    // The person confirms on the first computer, with what is asked of them in the dialog.
    page.share(&first_reference(&shown["candidates"]))
        .expect("the device is shared with");
    assert_eq!(
        this.ceremony.reasons(),
        vec!["Share your settings with the-phone".to_owned()]
    );
    let shown = page.devices();
    assert_eq!(
        shown["members"].as_array().expect("members").len(),
        2,
        "{shown}"
    );
    assert_eq!(shown["candidates"], json!([]), "{shown}");

    // The phone is offered the collection and joins it when the person confirms there.
    let offers = phone.devices_refresh();
    assert_eq!(
        offers["offers"].as_array().expect("offers").len(),
        1,
        "{offers}"
    );
    phone
        .join(&first_reference(&offers["offers"]))
        .expect("the collection is joined");
    assert_eq!(
        other.ceremony.reasons(),
        vec!["Join the settings started on this-mac".to_owned()]
    );

    // Settings the first wrote reach the phone once the first has sealed them under the new key.
    page.sync_now();
    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "dark", "{view}");
    assert_eq!(
        view["sync"]["devices"]["members"]
            .as_array()
            .expect("members")
            .len(),
        2
    );

    // And a change on the phone reaches the first.
    phone.choose("light");
    assert_eq!(page.sync_now()["colour_mode"], "light");
}

/// A person who does not confirm on the computer that holds the settings gives nobody the key, and
/// a computer that cannot ask them adds and joins nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_is_not_given_the_key_unless_the_person_confirms() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    let shown = page.devices_refresh();
    let reference = first_reference(&shown["candidates"]);

    this.ceremony.will_answer(CeremonyOutcome::NotConfirmed);
    assert!(page.share(&reference).is_err(), "it was not confirmed");
    this.ceremony.will_answer(CeremonyOutcome::Unavailable);
    assert!(page.share(&reference).is_err(), "there was no way to ask");

    let shown = page.devices();
    assert_eq!(
        shown["members"].as_array().expect("members").len(),
        1,
        "{shown}"
    );
    assert_eq!(
        shown["candidates"].as_array().expect("candidates").len(),
        1,
        "{shown}"
    );
    let offers = phone.devices_refresh();
    assert_eq!(offers["offers"], json!([]), "{offers}");
}

/// A device taken out is given no key for what is written afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_taken_out_does_not_read_what_is_written_afterwards() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");
    let offers = phone.devices_refresh();
    phone
        .join(&first_reference(&offers["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    let members = page.devices()["members"].clone();
    let phone_ref = members
        .as_array()
        .expect("members")
        .iter()
        .find(|member| member["this_computer"] == false)
        .map(|member| {
            member["reference"]
                .as_str()
                .expect("a reference")
                .to_owned()
        })
        .expect("the phone is a member");
    page.unshare(&phone_ref).expect("the device is taken out");
    page.choose("light");
    page.sync_now();

    let view = phone.sync_now();
    assert_eq!(
        view["colour_mode"], "dark",
        "what was written after the key moved on did not reach it: {view}"
    );
    assert_eq!(view["sync"]["devices"]["out"], true, "{view}");
}

/// A device a host reports revoked is taken out of the shared settings at the next step, without
/// asking the person: the key moves on, and the device reads nothing written after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_a_host_reports_revoked_is_taken_out_at_the_next_step() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");
    let offers = phone.devices_refresh();
    phone
        .join(&first_reference(&offers["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    // The host revokes the phone. Both computers' hosts say so.
    let mut revoked = other.listed("the-phone");
    revoked.revoked = true;
    let devices = vec![this.listed("this-mac"), revoked];
    this.hosts.list(devices.clone());
    other.hosts.list(devices);
    page.choose("light");
    let view = page.sync_now();
    let members = view["sync"]["devices"]["members"]
        .as_array()
        .expect("members");
    assert_eq!(members.len(), 1, "{view}");

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "dark", "{view}");
    assert_eq!(view["sync"]["devices"]["out"], true, "{view}");
}

/// A revocation this computer sent that a host's feed holds takes the device out of the shared
/// settings at the next step, before any host says it is revoked: the hosts still list the device
/// as it was, and the key moves on all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_in_a_hosts_feed_takes_a_member_out_before_any_host_says_so() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");
    let offers = phone.devices_refresh();
    phone
        .join(&first_reference(&offers["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    let recorded = page
        .app
        .state::<AppState>()
        .settings()
        .expect("settings are open")
        .revocations_sent(&[*other.identity().keys.authorisation.public()])
        .await
        .expect("the revocation is recorded");
    assert!(recorded, "the membership recorded it");
    // Both computers' hosts still list the phone as it was.
    page.choose("light");
    let view = page.sync_now();
    let members = view["sync"]["devices"]["members"]
        .as_array()
        .expect("members");
    assert_eq!(members.len(), 1, "the phone was taken out: {view}");

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "dark", "{view}");
    assert_eq!(view["sync"]["devices"]["out"], true, "{view}");
}

/// The person's two computers share settings: the second has joined and both are in step.
async fn two_computers_sharing(this: &Computer, other: &Computer) -> (Page, Page) {
    let page = with_sync_on(this).await;
    let phone = other.start();
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");
    let offers = phone.devices_refresh();
    phone
        .join(&first_reference(&offers["offers"]))
        .expect("joined");
    page.sync_now();
    phone.sync_now();
    (page, phone)
}

/// The future `revoking` is polled once, as the first thing the runtime does with a task.
async fn polled_once<F: std::future::Future>(
    revoking: &mut std::pin::Pin<&mut F>,
) -> std::task::Poll<F::Output> {
    std::future::poll_fn(|context| std::task::Poll::Ready(revoking.as_mut().poll(context))).await
}

/// A revocation that arrives while a step waits on the hosts, holding the membership, is not lost
/// and does not wait for that step to publish: the step in hand publishes nothing once the
/// revocation has arrived, and the device is taken out as soon as the step ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_that_arrives_while_a_step_waits_on_the_hosts_stops_that_step_publishing() {
    let (this, other) = two_computers().await;
    let (page, phone) = two_computers_sharing(&this, &other).await;
    let phone_key = *other.identity().keys.authorisation.public();
    // Adding the phone moved the key on once.
    let elsewhere = this.elsewhere_at(1);
    assert_eq!(elsewhere.colour().await, "dark");

    // The person changes a setting, and the step that would publish it waits on the hosts.
    let settings = page.app.state::<AppState>().settings().expect("settings");
    settings
        .local()
        .set_colour_mode(companion_tauri::settings::ColourMode::Light)
        .expect("the person's choice");
    let held = this.hosts.hold_the_next_list();
    let step = tokio::spawn({
        let settings = Arc::clone(&settings);
        async move { settings.sync_now().await }
    });
    held.reached().await;

    // The revocation arrives now. It waits for the step in hand, and publication stops at once.
    let revoked = [phone_key];
    let mut revoking = std::pin::pin!(settings.revocations_sent(&revoked));
    assert!(
        polled_once(&mut revoking).await.is_pending(),
        "the revocation waits for the step in hand"
    );
    held.release();
    let view = step.await.expect("the step ran").expect("the step ended");
    let view = serde_json::to_value(view).expect("a view");
    assert_eq!(view["sync"]["problem"], Value::Null, "{view}");
    assert_eq!(view["sync"]["outstanding"], 0, "{view}");
    assert_eq!(
        elsewhere.colour().await,
        "dark",
        "the step in hand published nothing after the revocation arrived"
    );
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    // The device is taken out, and the change goes out under the key that follows its removal.
    assert!(revoking.await.expect("the revocation is recorded"));
    page.sync_now();
    assert_eq!(
        page.devices()["members"].as_array().expect("members").len(),
        1
    );
    // Taking the phone out moved the key on again, and the change went out under that one.
    assert_eq!(this.elsewhere_at(2).colour().await, "light");
    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "dark", "{view}");
    assert_eq!(view["sync"]["devices"]["out"], true, "{view}");
}

/// A draft saved after a revocation arrived, while the step in hand waits on the service, is not
/// sent under the key the removed device holds: it goes out once, under the key that follows the
/// device's removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_saved_after_a_revocation_is_not_sent_under_the_key_the_removed_device_holds() {
    let (this, other) = two_computers().await;
    let (environment, studio) = host(1, "studio");
    this.hosts
        .say(environment, HostPrivacy::Off { generation: 1 });
    let (page, _phone) = two_computers_sharing(&this, &other).await;
    page.drafts_on(true).expect("drafts sync is on");
    let phone_key = *other.identity().keys.authorisation.public();
    let elsewhere = this.elsewhere();
    let before = elsewhere
        .epoch_of(elsewhere.object_id.get())
        .await
        .expect("the settings are sealed under an epoch");

    // The step in hand has read the settings, and the drafts are the next it does.
    let web = this.served.web();
    let asked = sync_requests(&this);
    web.fail(SYNC_PATH, 1, Moment::Slow);
    let settings = page.app.state::<AppState>().settings().expect("settings");
    let step = tokio::spawn({
        let settings = Arc::clone(&settings);
        async move { settings.sync_now().await }
    });
    web.requests_reach(SYNC_PATH, asked + 1).await;
    let revoked = [phone_key];
    let mut revoking = std::pin::pin!(settings.revocations_sent(&revoked));
    assert!(
        polled_once(&mut revoking).await.is_pending(),
        "the revocation waits for the step in hand"
    );
    let (draft, _) = page.write_draft(Some(&studio), "written after the revocation");
    web.release_held();
    step.await.expect("the step ran").expect("the step ended");
    assert_eq!(
        elsewhere.draft_at(draft).await,
        None,
        "the step in hand sent nothing written after the revocation"
    );

    assert!(revoking.await.expect("the revocation is recorded"));
    page.sync_now();
    assert_eq!(elsewhere.draft_at(draft).await, Some(1));
    assert!(
        elsewhere
            .epoch_of(draft.get())
            .await
            .is_some_and(|epoch| epoch > before),
        "the draft is sealed under the key that follows the removal"
    );
}

/// A computer the person does not confirm on joins nothing: the offer stays, and the settings the
/// first computer holds are not read there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_computer_the_person_does_not_confirm_on_does_not_join() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");
    let offers = phone.devices_refresh();
    let reference = first_reference(&offers["offers"]);

    other.ceremony.will_answer(CeremonyOutcome::NotConfirmed);
    assert!(phone.join(&reference).is_err(), "it was not confirmed");
    other.ceremony.will_answer(CeremonyOutcome::Unavailable);
    assert!(phone.join(&reference).is_err(), "there was no way to ask");

    page.sync_now();
    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "system", "nothing was read: {view}");
    assert_eq!(
        phone.devices_refresh()["offers"]
            .as_array()
            .expect("offers")
            .len(),
        1,
        "the offer stands"
    );
}

/// A device is offered the settings only when a host lists all four of its keys and says it holds the
/// right to manage the host: the pairing the owner approved is what binds a key to a device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_a_host_lists_without_its_keys_or_the_right_to_manage_is_not_offered_the_key() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;

    let mut without_keys = other.listed("the-phone");
    without_keys.keys = None;
    this.hosts
        .list(vec![this.listed("this-mac"), without_keys.clone()]);
    assert_eq!(page.devices_refresh()["candidates"], json!([]));

    let mut without_the_right = other.listed("the-phone");
    without_the_right.manages_host = false;
    this.hosts
        .list(vec![this.listed("this-mac"), without_the_right]);
    assert_eq!(page.devices_refresh()["candidates"], json!([]));

    let mut expired = other.listed("the-phone");
    expired.expired = true;
    this.hosts.list(vec![this.listed("this-mac"), expired]);
    assert_eq!(
        page.devices_refresh()["candidates"],
        json!([]),
        "a grant that has run out manages nothing, whatever it listed"
    );

    this.hosts
        .list(vec![this.listed("this-mac"), other.listed("the-phone")]);
    assert_eq!(
        page.devices_refresh()["candidates"]
            .as_array()
            .expect("candidates")
            .len(),
        1
    );
}

/// A reference the page was never shown names no device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reference_the_page_was_not_shown_names_no_device() {
    let (this, _other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.devices_refresh();

    assert!(page.share("00000000000000000000000000000000").is_err());
    assert!(page.unshare("00000000000000000000000000000000").is_err());
    assert!(page.join("00000000-0000-0000-0000-000000000000").is_err());
    assert!(this.ceremony.reasons().is_empty(), "nobody was asked");
}

/// Where the service held the settings this computer's own store last agreed with, as the record
/// keeps a place.
fn position_of(own: &OwnStore) -> Value {
    let note = own
        .client
        .store()
        .checkpoint(own.object_id)
        .expect("a store")
        .expect("a note of where the settings stand");
    serde_json::to_value(note.position).expect("a position")
}

/// The record a computer's settings sync keeps, as the file holds it.
fn sync_record(computer: &Computer) -> Value {
    serde_json::from_slice(
        &std::fs::read(computer.data.path().join("settings-sync").join("sync.json"))
            .expect("the record sync keeps"),
    )
    .expect("a record")
}

/// The reference the page was shown for the device called `name`, among `list`'s entries.
fn reference_of(list: &Value, name: &str) -> String {
    list.as_array()
        .expect("a list")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("{name} is in {list}"))["reference"]
        .as_str()
        .expect("a reference")
        .to_owned()
}

/// A host that does not answer says nothing of any device: the devices only it lists stay in the
/// shared settings. A host that answers and reports one revoked takes it out, and so does one that
/// answers and lists no such device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_does_not_answer_takes_no_device_out_but_one_that_does_can() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    let members = |view: &Value| {
        view["sync"]["devices"]["members"]
            .as_array()
            .expect("m")
            .len()
    };

    // The host that answers lists this computer alone, and another host this computer owns is
    // asleep: the phone may be listed there.
    this.hosts.list(vec![this.listed("this-mac")]);
    this.hosts.go_silent(true);
    assert_eq!(members(&page.sync_now()), 2, "silence takes nobody out");

    // The host that answers reports it revoked, whoever else is silent.
    let mut revoked = other.listed("the-phone");
    revoked.revoked = true;
    this.hosts.list(vec![this.listed("this-mac"), revoked]);
    assert_eq!(members(&page.sync_now()), 1, "a revocation is an answer");

    // And the phone, given the key again, goes out when the host that answers lists no such device.
    this.hosts
        .list(vec![this.listed("this-mac"), other.listed("the-phone")]);
    this.hosts.go_silent(false);
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared again");
    assert_eq!(page.devices()["members"].as_array().expect("m").len(), 2);
    this.hosts.list(vec![this.listed("this-mac")]);
    assert_eq!(
        members(&page.sync_now()),
        1,
        "absence from an answering host is not silence"
    );
}

/// A computer does not join the settings while a host of its own does not answer: the offer stays,
/// and the join is made when the host answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_computer_does_not_join_the_settings_while_a_host_of_its_own_does_not_answer() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    let offer = first_reference(&phone.devices_refresh()["offers"]);

    other.hosts.go_silent(true);
    phone.join(&offer).expect_err("a host did not answer");
    assert_eq!(
        phone.devices_refresh()["offers"]
            .as_array()
            .expect("offers")
            .len(),
        1,
        "the offer stands"
    );

    other.hosts.go_silent(false);
    phone.join(&offer).expect("joined");
    assert_eq!(phone.sync_now()["sync"]["devices"]["out"], false);
}

/// Hosts that all answer that they will not list their devices to this computer have answered:
/// this computer can vouch for nobody to them, so it checks nobody and publishes nothing, and says
/// so. It takes nobody out for that: whether they stay is for the person, and a computer that has
/// lost its right on its hosts is the last one to decide it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosts_that_all_refuse_to_list_their_devices_stop_this_computer_and_take_nobody_out() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    this.hosts.refuse_to_list(true);
    let stopped = page
        .call("settings_sync_now", json!({}))
        .expect_err("this computer says it cannot check who may share");
    assert!(
        stopped.to_string().contains("will not list their devices"),
        "{stopped}"
    );
    assert_eq!(
        page.devices()["members"].as_array().expect("members").len(),
        2,
        "nobody was taken out"
    );
    page.choose("light");
    assert_eq!(
        phone.sync_now()["colour_mode"],
        "dark",
        "nothing was published under the key"
    );

    // The right comes back, and the change goes out.
    this.hosts.refuse_to_list(false);
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "light");
}

/// A host that refuses beside a host that does not answer, with none that lists, leaves this
/// computer as unable to check as hosts that all refuse: it stops, and takes nobody out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_beside_a_silent_host_stops_this_computer_too() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();

    this.hosts.refuse_to_list(true);
    this.hosts.go_silent(true);
    let stopped = page
        .call("settings_sync_now", json!({}))
        .expect_err("this computer says it cannot check who may share");
    assert!(
        stopped.to_string().contains("will not list their devices"),
        "{stopped}"
    );
    assert_eq!(
        page.devices()["members"].as_array().expect("members").len(),
        2,
        "nobody was taken out"
    );
    page.choose("light");
    assert_eq!(
        phone.sync_now()["colour_mode"],
        "dark",
        "nothing was published on the answers from before"
    );
}

/// A host that refuses to list its devices to this computer says nothing of the devices only it
/// lists, as a host that does not answer says nothing: they stay, while the host that lists is
/// believed about the devices it mentions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_refuses_beside_one_that_lists_leaves_the_devices_only_it_lists_in() {
    let (this, other) = two_computers().await;
    this.hosts
        .list_at_a_second_host(vec![this.listed("this-mac")]);
    let page = with_sync_on(&this).await;
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();

    this.hosts.refuse_at_the_first_host(true);
    let view = page.sync_now();
    assert_eq!(
        view["sync"]["devices"]["members"]
            .as_array()
            .expect("members")
            .len(),
        2,
        "the phone, which only the host that refuses lists, is kept: {view}"
    );
}

/// Two hosts that list one device under different stored-envelope keys leave it nothing to be
/// given: a key sealed to the wrong one of the two is a key given to whoever holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosts_that_disagree_on_a_devices_keys_give_it_no_key() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let shown = page.devices_refresh();
    let reference = first_reference(&shown["candidates"]);

    let mut disputed = other.listed("the-phone");
    disputed.keys = disputed.keys.map(|mut keys| {
        keys.stored_envelope = *kr_crypto::keys::DeviceKeys::generate()
            .expect("keys")
            .stored_envelope
            .public();
        keys
    });
    this.hosts
        .list_at_a_second_host(vec![this.listed("this-mac"), disputed]);
    assert_eq!(page.devices_refresh()["candidates"], json!([]));
    assert!(page.share(&reference).is_err(), "nothing is shared");
    assert!(this.ceremony.reasons().is_empty(), "nobody was asked");
}

/// A key is given on what the hosts say when the person confirms, and not on what they said before:
/// when none answers, or the device has been revoked meanwhile, nothing is shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_share_is_given_on_what_the_hosts_say_at_the_time_of_the_confirmation() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    let reference = first_reference(&page.devices_refresh()["candidates"]);
    let members = || page.devices()["members"].as_array().expect("m").len();

    // No host answers: what they said last time is not what a key is given on.
    this.hosts.list(vec![]);
    assert!(page.share(&reference).is_err());
    assert!(this.ceremony.reasons().is_empty(), "nobody was asked");

    // The hosts answer, then none does while the person is being asked.
    let devices = vec![this.listed("this-mac"), other.listed("the-phone")];
    this.hosts.list(devices.clone());
    let hosts = Arc::clone(&this.hosts);
    this.ceremony.while_asking(move || hosts.list(vec![]));
    assert!(page.share(&reference).is_err());
    assert_eq!(this.ceremony.reasons().len(), 1, "the person was asked");
    assert_eq!(members(), 1);

    // The hosts answer, and one reports the device revoked while the person is being asked.
    this.hosts.list(devices);
    let hosts = Arc::clone(&this.hosts);
    let mut revoked = other.listed("the-phone");
    revoked.revoked = true;
    let this_mac = this.listed("this-mac");
    this.ceremony
        .while_asking(move || hosts.list(vec![this_mac.clone(), revoked.clone()]));
    assert!(page.share(&reference).is_err());
    assert_eq!(members(), 1);
    assert_eq!(
        phone.devices_refresh()["offers"],
        json!([]),
        "no key was given"
    );
}

/// A device that was not the last to write the settings still seals them again for a device added
/// later, so that device is not left waiting for the writer: it may be gone, or taken out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_that_did_not_write_the_settings_seals_them_again_for_a_device_added_later() {
    let this = Computer::new().await;
    let second = Computer::beside(&this).await;
    let third = Computer::beside(&this).await;
    let devices = vec![
        this.listed("the-mac"),
        second.listed("the-phone"),
        third.listed("the-tablet"),
    ];
    for computer in [&this, &second, &third] {
        computer.hosts.list(devices.clone());
    }
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = second.start();
    let tablet = third.start();

    // The first computer writes the settings and shares them with the phone, which follows them.
    let shown = page.devices_refresh();
    page.share(&reference_of(&shown["candidates"], "the-phone"))
        .expect("shared with the phone");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("the phone joins");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    // The phone takes the first computer out, and the key moves on: what the first computer wrote
    // is not believed by the phone until it has been sealed again.
    let mac = reference_of(&phone.devices()["members"], "the-mac");
    phone
        .unshare(&mac)
        .expect("the first computer is taken out");
    assert_eq!(
        sync_record(&second)["floor"],
        2,
        "the epoch of the removal is the oldest the phone believes"
    );

    // The phone shares with the tablet. The settings were written by the first computer, and the
    // phone seals them again for the tablet all the same.
    let shown = phone.devices_refresh();
    phone
        .share(&reference_of(&shown["candidates"], "the-tablet"))
        .expect("shared with the tablet");
    tablet
        .join(&first_reference(&tablet.devices_refresh()["offers"]))
        .expect("the tablet joins");
    phone.sync_now();
    let view = tablet.sync_now();
    assert_eq!(view["colour_mode"], "dark", "{view}");
    assert_eq!(view["sync"]["devices"]["waiting"], false);
}

/// A computer that chose a colour before it joined, and cannot read what the service holds, waits
/// with its choice kept: it asks, and sends nothing over what it cannot compare with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_computer_that_cannot_read_what_the_service_holds_waits_and_sends_nothing_over_it() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    phone.choose("light");

    // Another device wrote the settings, this computer chose something else before it followed, and
    // the choice waits for the person. A computer with a choice waiting seals nothing again, so the
    // settings stay sealed under the first key when the phone is given the second.
    let elsewhere = this.elsewhere();
    assert!(matches!(
        elsewhere.write("light").await,
        Published::Accepted { .. }
    ));
    assert_eq!(page.choose("system")["sync"]["conflicts"], 1);
    let shown = page.devices_refresh();
    page.share(&first_reference(&shown["candidates"]))
        .expect("shared");

    let writes = || {
        this.served
            .web()
            .arrived()
            .iter()
            .filter(|arrived| arrived.path == SYNC_PATH && arrived.body.get("exchange").is_some())
            .count()
    };
    let (written, copies) = (writes(), elsewhere.copies_kept().await);
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    let view = phone.sync_now();
    assert_eq!(view["sync"]["devices"]["waiting"], true, "{view}");
    assert!(view["sync"]["problem"].is_null(), "{view}");
    assert_eq!(view["colour_mode"], "light", "its choice is kept");
    assert_eq!(
        writes(),
        written,
        "nothing was written over what it cannot read"
    );
    assert_eq!(
        elsewhere.copies_kept().await,
        copies,
        "no refused write was left"
    );

    // An answer that does not come says nothing of what the service holds, and the first object is
    // not made on it: the step that finds the service unreachable at that question stops, and the
    // next asks again.
    let before = this.served.web().arrived().len();
    phone.sync_now();
    let step: Vec<_> = this.served.web().arrived().split_off(before);
    let asking = step
        .iter()
        .position(|arrived| arrived.body.get("compare").is_some())
        .expect("the step asks what the service holds");
    this.served.web().fail(
        SYNC_PATH,
        u32::try_from(asking).expect("a few") + 1,
        Moment::Before,
    );
    let stopped = phone.call("settings_sync_now", json!({}));
    this.served.web().mend();
    assert!(stopped.is_err(), "the step says it stopped");
    assert_eq!(
        writes(),
        written,
        "no object was made on a question that was not answered"
    );
    let view = phone.sync_now();
    assert_eq!(view["sync"]["devices"]["waiting"], true, "{view}");
    assert_eq!(writes(), written);
    assert_eq!(elsewhere.copies_kept().await, copies);
}

/// A step that stopped between putting the settings sealed again in the store and hearing how they
/// were published finishes the sealing as it began it: another device's settings refused them, and
/// they are followed, with nothing asked of the person.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealing_a_step_stopped_in_is_finished_as_it_was_begun() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    // The step put the settings sealed again in the store and stopped; the other device wrote.
    let own = this.client_on_its_own_store(1);
    let (client, object_id) = (&own.client, own.object_id);
    let held = client
        .store()
        .object(object_id)
        .expect("a store")
        .expect("settings");
    let again = SyncObject {
        revision: fresh_revision().expect("a revision"),
        ..held.clone()
    };
    client
        .store()
        .put_object(&again)
        .expect("the sealing began");
    let path = this.data.path().join("settings-sync").join("sync.json");
    let mut record = sync_record(&this);
    record["resealing"] = json!({
        "from": serde_json::to_value(held.revision).expect("a revision"),
        "to": serde_json::to_value(again.revision).expect("a revision"),
        "at": position_of(&own),
    });
    std::fs::write(&path, serde_json::to_vec(&record).expect("a record")).expect("written");
    phone.choose("light");

    let view = page.sync_now();
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert!(
        sync_record(&this).get("resealing").is_none(),
        "the marker is spent"
    );
}

/// Runs `step` while the settings file cannot be written, as it cannot when the disk fails, and
/// lets it be written again after.
#[cfg(unix)]
fn while_the_settings_cannot_be_written<T>(computer: &Computer, step: impl FnOnce() -> T) -> T {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = computer.data.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is read only");
    let done = step();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is writable again");
    done
}

/// The mark that settings are being sealed again outlasts the following of another device's
/// settings, so a step that stops in between does not leave the person to be asked about settings
/// they never changed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_following_that_stops_leaves_the_sealing_marked_and_asks_nothing_after() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();

    // The other device's settings are kept beside the settings this computer was sealing again.
    phone.choose("light");
    let own = this.client_on_its_own_store(1);
    let (client, object_id) = (&own.client, own.object_id);
    let store = client.store();
    let held = store.object(object_id).expect("a store").expect("settings");
    client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(now_ms()),
        )
        .await
        .expect("the other device's settings are kept beside this computer's");
    let path = this.data.path().join("settings-sync").join("sync.json");
    let mut record = sync_record(&this);
    let revision = serde_json::to_value(held.revision).expect("a revision");
    record["resealing"] = json!({ "from": revision, "to": revision, "at": position_of(&own) });
    std::fs::write(&path, serde_json::to_vec(&record).expect("a record")).expect("written");

    // The step stops where it takes the other device's settings.
    let stopped =
        while_the_settings_cannot_be_written(&this, || page.call("settings_sync_now", json!({})));
    assert!(stopped.is_err(), "the step says it stopped");
    let view = page.sync_now();
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    assert_eq!(view["colour_mode"], "light", "{view}");
}

/// The same when the sealing was refused by the other device's write in the step itself.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_following_that_stops_after_a_refused_sealing_asks_nothing_after() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    let own = this.client_on_its_own_store(1);
    let (client, object_id) = (&own.client, own.object_id);
    let held = client
        .store()
        .object(object_id)
        .expect("a store")
        .expect("settings");
    let again = SyncObject {
        revision: fresh_revision().expect("a revision"),
        ..held.clone()
    };
    client
        .store()
        .put_object(&again)
        .expect("the sealing began");
    let path = this.data.path().join("settings-sync").join("sync.json");
    let mut record = sync_record(&this);
    record["resealing"] = json!({
        "from": serde_json::to_value(held.revision).expect("a revision"),
        "to": serde_json::to_value(again.revision).expect("a revision"),
        "at": position_of(&own),
    });
    std::fs::write(&path, serde_json::to_vec(&record).expect("a record")).expect("written");
    phone.choose("light");

    let stopped =
        while_the_settings_cannot_be_written(&this, || page.call("settings_sync_now", json!({})));
    assert!(stopped.is_err(), "the step says it stopped");
    let view = page.sync_now();
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    assert_eq!(view["colour_mode"], "light", "{view}");
}

/// A record that names another collection than the membership says this computer is in, as one does
/// when a step stopped between joining and writing it down, is put right by the membership's word.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_naming_another_collection_than_the_membership_is_put_right() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    let joined = sync_record(&other)["collection_id"].clone();
    drop(phone);

    // The step stopped before the record was written: it still names a collection of its own.
    let path = other.data.path().join("settings-sync").join("sync.json");
    let mut record = sync_record(&other);
    record["collection_id"] = json!("00000000-0000-4000-8000-000000000001");
    std::fs::write(&path, serde_json::to_vec(&record).expect("a record")).expect("written");

    let phone = other.start();
    let view = phone.sync_now();
    assert_eq!(sync_record(&other)["collection_id"], joined);
    assert_eq!(view["colour_mode"], "dark", "{view}");
}

/// A draft another device sealed before this computer joined is one this computer cannot read yet.
/// That is not a fault to report at every pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_sealed_before_this_computer_joined_is_not_a_problem_for_it() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.drafts_on(true).expect("drafts sync is on");
    let elsewhere = this.elsewhere();
    elsewhere
        .drafts()
        .publish("written before the phone joined")
        .await;
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");

    let phone = other.start();
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    let asked = |phone: &Page| {
        let before = this.served.web().requests_to(SYNC_PATH);
        let view = phone.sync_now();
        (view, this.served.web().requests_to(SYNC_PATH) - before)
    };
    asked(&phone);
    let (_, without_drafts) = asked(&phone);
    phone.drafts_on(true).expect("drafts sync is on");
    for _ in 0..2 {
        let (view, requests) = asked(&phone);
        assert!(view["sync"]["drafts"]["problem"].is_null(), "{view}");
        assert_eq!(
            requests,
            without_drafts + 1,
            "one look at the collection and no request for a draft it does not believe"
        );
    }
    assert!(phone.kept_drafts().is_empty(), "it cannot read the draft");
}

/// A host that did not answer does not override what a host that did says of a member: one an
/// answering host lists without the right to manage the host, or whose grant has run out, goes
/// out whoever else is silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_host_does_not_override_what_an_answering_host_says_of_a_member() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();

    let mut expired = other.listed("the-phone");
    expired.expired = true;
    this.hosts.list(vec![this.listed("this-mac"), expired]);
    this.hosts.go_silent(true);
    let view = page.sync_now();
    assert_eq!(
        view["sync"]["devices"]["members"]
            .as_array()
            .expect("members")
            .len(),
        1,
        "{view}"
    );
}

/// Two hosts that start to disagree about a device's keys while the person is being asked leave the
/// device no key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dispute_that_starts_while_the_person_is_asked_gives_the_device_no_key() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let phone = other.start();
    let reference = first_reference(&page.devices_refresh()["candidates"]);

    let hosts = Arc::clone(&this.hosts);
    let this_mac = this.listed("this-mac");
    let mut disputed = other.listed("the-phone");
    disputed.keys = disputed.keys.map(|mut keys| {
        keys.stored_envelope = *kr_crypto::keys::DeviceKeys::generate()
            .expect("keys")
            .stored_envelope
            .public();
        keys
    });
    this.ceremony.while_asking(move || {
        hosts.list_at_a_second_host(vec![this_mac.clone(), disputed.clone()])
    });
    assert!(page.share(&reference).is_err());
    assert_eq!(this.ceremony.reasons().len(), 1, "the person was asked");
    assert_eq!(page.devices()["members"].as_array().expect("m").len(), 1);
    assert_eq!(phone.devices_refresh()["offers"], json!([]));
}

/// A member whose last write no remaining device has read leaves the settings waiting rather than
/// repeating a write the service refuses at every check: a write that leaves a copy each time, and
/// ends when the service has no room. The person's next change goes over what cannot be read, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_a_taken_out_device_wrote_last_are_waited_for_and_then_written_over_by_a_change() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    assert_eq!(phone.sync_now()["colour_mode"], "dark");

    // The phone writes, and the first computer takes it out before it has read what was written.
    phone.choose("light");
    let phone_ref = reference_of(&page.devices()["members"], "the-phone");
    page.unshare(&phone_ref).expect("the phone is taken out");

    let writes = || {
        this.served
            .web()
            .arrived()
            .iter()
            .filter(|arrived| arrived.path == SYNC_PATH && arrived.body.get("exchange").is_some())
            .count()
    };
    let elsewhere = this.elsewhere();
    let (written, copies) = (writes(), elsewhere.copies_kept().await);
    for _ in 0..3 {
        let view = page.sync_now();
        assert_eq!(view["sync"]["devices"]["waiting"], true, "{view}");
        assert!(view["sync"]["problem"].is_null(), "{view}");
    }
    assert_eq!(writes(), written, "waiting writes nothing");
    assert_eq!(elsewhere.copies_kept().await, copies);

    // A change the person makes goes over what cannot be believed: one refused write, then the
    // change itself.
    page.choose("system");
    let view = page.sync_now();
    assert_eq!(view["sync"]["outstanding"], 0, "{view}");
    assert_eq!(view["sync"]["devices"]["waiting"], false, "{view}");
    assert!(view["sync"]["problem"].is_null(), "{view}");
    assert_eq!(elsewhere.copies_kept().await, copies + 1);
    let settled = writes();
    page.sync_now();
    assert_eq!(writes(), settled, "nothing more is written once it agrees");
}

/// The person's computers, sharing the settings, each joined and agreed on `dark`: the first, which
/// started them, then one for each name after it.
async fn computers_sharing(names: &[&str]) -> (Vec<Computer>, Vec<Page>) {
    let first = Computer::new().await;
    let mut computers = vec![first];
    for _ in names {
        let beside = Computer::beside(&computers[0]).await;
        computers.push(beside);
    }
    let mut devices = vec![computers[0].listed("this-mac")];
    for (computer, name) in computers.iter().skip(1).zip(names) {
        devices.push(computer.listed(name));
    }
    for computer in &computers {
        computer.hosts.list(devices.clone());
    }
    let first_page = with_sync_on(&computers[0]).await;
    let mut pages = vec![first_page];
    for computer in computers.iter().skip(1) {
        pages.push(computer.start());
    }
    for (name, joiner) in names.iter().zip(pages.iter().skip(1)) {
        let shown = pages[0].devices_refresh();
        pages[0]
            .share(&reference_of(&shown["candidates"], name))
            .expect("shared");
        joiner
            .join(&first_reference(&joiner.devices_refresh()["offers"]))
            .expect("joined");
    }
    for member in &pages {
        assert_eq!(member.sync_now()["colour_mode"], "dark");
    }
    (computers, pages)
}

/// The first computer, a phone and a tablet, sharing the settings.
async fn three_computers_sharing() -> (Computer, Computer, Computer, Page, Page, Page) {
    let (mut computers, mut pages) = computers_sharing(&["the-phone", "the-tablet"]).await;
    let (tablet, phone, page) = (pages.remove(2), pages.remove(1), pages.remove(0));
    let (tablet_computer, phone_computer, this) = (
        computers.remove(2),
        computers.remove(1),
        computers.remove(0),
    );
    (this, phone_computer, tablet_computer, page, phone, tablet)
}

/// The change the first computer makes goes over what the tablet last wrote once the tablet is taken
/// out, as the write of a device nobody believes. The phone never held that write, so it follows the
/// change and is asked nothing, and nobody is offered what the tablet wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_over_the_last_write_of_a_device_taken_out_asks_nobody_and_offers_it_to_nobody() {
    let (_this, _phone_computer, _tablet_computer, page, phone, tablet) =
        three_computers_sharing().await;
    tablet.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-tablet"))
        .expect("the tablet is taken out");
    assert_eq!(page.sync_now()["sync"]["devices"]["waiting"], true);

    let view = page.choose("system");
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "system", "{view}");
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    assert!(
        phone
            .call("settings_conflicts", json!({}))
            .expect("a read")
            .is_null(),
        "the write of the device taken out is offered to nobody"
    );
    assert_eq!(page.sync_now()["sync"]["conflicts"], 0);
}

/// The change the first computer makes goes over a write of the phone's that it could not believe
/// because a device was taken out since. The phone holds that write, so it keeps the change beside
/// it and its person chooses; and what they choose is what the other computers come to hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_over_the_write_of_a_member_asks_the_member_before_it_replaces_it() {
    let (_this, _phone_computer, _tablet_computer, page, phone, _tablet) =
        three_computers_sharing().await;
    phone.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-tablet"))
        .expect("the tablet is taken out");
    assert_eq!(page.sync_now()["sync"]["devices"]["waiting"], true);

    let view = page.choose("system");
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    let view = phone.sync_now();
    assert_eq!(
        view["colour_mode"], "light",
        "its person has not chosen: {view}"
    );
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
    let versions = phone
        .call("settings_conflicts", json!({}))
        .expect("the versions");
    assert_eq!(versions["mine"]["colour_mode"], "light");
    assert_eq!(versions["others"][0]["colour_mode"], "system");
    // Later steps leave the choice where it is.
    assert_eq!(phone.sync_now()["sync"]["conflicts"], 1);

    // Keeping the phone's own settings is what the first computer then holds.
    let view = phone
        .call(
            "settings_conflict_resolve",
            json!({ "keep": { "choice": "mine" } }),
        )
        .expect("the choice is recorded");
    assert_eq!(view["colour_mode"], "light");
    assert_eq!(view["sync"]["conflicts"], 0);
    let view = page.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
}

/// A third computer that has a change of its own when the change that went over a write arrives
/// keeps it beside its own, and what its person chooses carries on what was gone over: the device
/// that held the write is asked when it meets the choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_choice_made_beside_a_change_that_went_over_a_write_still_asks_the_device_that_held_it() {
    let (_computers, pages) = computers_sharing(&["the-phone", "the-tablet", "the-laptop"]).await;
    let [page, phone, tablet, _laptop] = &pages[..] else {
        panic!("four computers");
    };
    phone.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-laptop"))
        .expect("the laptop is taken out");
    page.sync_now();
    page.choose("system");

    // The tablet has not read it, and changes its mind: the change that went over is kept beside.
    let view = tablet.choose("light");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
    let versions = tablet
        .call("settings_conflicts", json!({}))
        .expect("the versions");
    let copy = versions["others"][0]["conflict_id"].clone();
    let view = tablet
        .call(
            "settings_conflict_resolve",
            json!({ "keep": { "choice": "copy", "conflict_id": copy } }),
        )
        .expect("the choice is recorded");
    assert_eq!(view["colour_mode"], "system");

    // The phone held what was gone over, and it is asked.
    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
}

/// A third computer that chooses what the change that went over says, so that the copy is let go
/// and nothing is asked of its person, still carries what that change went over: the device that
/// held the write is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_choice_that_says_what_the_change_over_a_write_says_still_asks_the_device_that_held_it() {
    let (_computers, pages) = computers_sharing(&["the-phone", "the-tablet", "the-laptop"]).await;
    let [page, phone, tablet, _laptop] = &pages[..] else {
        panic!("four computers");
    };
    phone.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-laptop"))
        .expect("the laptop is taken out");
    page.sync_now();
    page.choose("system");

    tablet.choose("system");
    let view = tablet.sync_now();
    assert_eq!(
        view["sync"]["conflicts"], 0,
        "nothing is asked of the tablet: {view}"
    );

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
}

/// A third computer that keeps its own settings beside the change that went over a write carries
/// what that change went over: the device that held the write is asked when it meets them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeping_its_own_settings_beside_a_change_that_went_over_a_write_still_asks_the_device_that_held_it()
 {
    let (_computers, pages) = computers_sharing(&["the-phone", "the-tablet", "the-laptop"]).await;
    let [page, phone, tablet, _laptop] = &pages[..] else {
        panic!("four computers");
    };
    phone.choose("light");
    tablet.sync_now();
    page.unshare(&reference_of(&page.devices()["members"], "the-laptop"))
        .expect("the laptop is taken out");
    page.sync_now();
    page.choose("system");

    // The tablet followed the phone, then changed its mind before reading what went over it.
    let view = tablet.choose("dark");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
    let view = tablet
        .call(
            "settings_conflict_resolve",
            json!({ "keep": { "choice": "mine" } }),
        )
        .expect("the choice is recorded");
    assert_eq!(view["colour_mode"], "dark");

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
}

/// Two changes in a row over writes their writers could not read: the second goes over what the
/// first replaced, which its writer cannot see inside the object it replaces, and the device that
/// held the first write is still asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_change_over_unreadable_settings_still_asks_the_device_that_held_the_first_write()
{
    let (_computers, pages) =
        computers_sharing(&["the-phone", "the-tablet", "the-t1", "the-t2"]).await;
    let [page, phone, tablet, _first, _second] = &pages[..] else {
        panic!("five computers");
    };
    phone.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-t1"))
        .expect("the first computer is taken out");
    page.sync_now();
    page.choose("system");

    // The tablet takes the other one out before it reads anything, and so cannot read what the
    // first computer wrote either: its change goes over that.
    tablet
        .unshare(&reference_of(&tablet.devices()["members"], "the-t2"))
        .expect("the second computer is taken out");
    assert_eq!(tablet.sync_now()["sync"]["devices"]["waiting"], true);
    tablet.choose("system");

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
}

/// A change made from the settings that went over a write is still one that went over it: the device
/// that held the write is asked when it meets either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_change_made_from_settings_that_went_over_a_write_still_asks_the_device_that_held_it()
 {
    let (_this, _phone_computer, _tablet_computer, page, phone, _tablet) =
        three_computers_sharing().await;
    phone.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-tablet"))
        .expect("the tablet is taken out");
    page.sync_now();
    page.choose("system");
    // The first computer changes its mind before the phone has looked.
    page.choose("dark");

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
}

/// A computer that holds no settings of its own, and meets what the service holds sealed before a
/// device was taken out, asks what the service holds again at each step instead of making its first
/// settings and publishing them: each of those would leave one more refused write at the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_computer_holding_no_settings_asks_again_what_it_cannot_read_instead_of_writing() {
    let this = Computer::new().await;
    let phone_computer = Computer::beside(&this).await;
    let tablet_computer = Computer::beside(&this).await;
    let devices = vec![
        this.listed("this-mac"),
        phone_computer.listed("the-phone"),
        tablet_computer.listed("the-tablet"),
    ];
    for computer in [&this, &phone_computer, &tablet_computer] {
        computer.hosts.list(devices.clone());
    }
    let page = with_sync_on(&this).await;
    let phone = phone_computer.start();
    let tablet = tablet_computer.start();

    // The phone joins and reads the settings, and cannot take them: a directory stands where the
    // lock on its settings file is made. It holds nothing, and a note of where they stand.
    let lock = phone_computer.data.path().join("settings.lock");
    std::fs::create_dir(&lock).expect("a directory where the lock goes");
    page.share(&reference_of(
        &page.devices_refresh()["candidates"],
        "the-phone",
    ))
    .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect_err("the settings could not be taken");
    std::fs::remove_dir(&lock).expect("the directory goes");

    // The tablet joins, writes, and is taken out before anyone has read what it wrote.
    page.share(&reference_of(
        &page.devices_refresh()["candidates"],
        "the-tablet",
    ))
    .expect("shared");
    tablet
        .join(&first_reference(&tablet.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();
    tablet.sync_now();
    tablet.choose("light");
    page.unshare(&reference_of(&page.devices()["members"], "the-tablet"))
        .expect("the tablet is taken out");

    let writes = || {
        this.served
            .web()
            .arrived()
            .iter()
            .filter(|arrived| arrived.path == SYNC_PATH && arrived.body.get("exchange").is_some())
            .count()
    };
    let elsewhere = this.elsewhere();
    let (written, copies) = (writes(), elsewhere.copies_kept().await);
    phone.choose("system");
    for _ in 0..3 {
        let view = phone.sync_now();
        assert_eq!(view["sync"]["devices"]["waiting"], true, "{view}");
        assert!(view["sync"]["problem"].is_null(), "{view}");
        assert_eq!(view["colour_mode"], "system", "its choice is kept: {view}");
    }
    assert_eq!(
        writes(),
        written,
        "nothing was written over what it cannot read"
    );
    assert_eq!(
        elsewhere.copies_kept().await,
        copies,
        "no refused write was left at the service"
    );
}

/// Settings written over the ones this computer was sealing again are not those settings
/// continued: the person is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_written_over_the_ones_being_sealed_again_are_left_for_the_person() {
    let (_this, phone_computer, _tablet_computer, page, phone, _tablet) =
        three_computers_sharing().await;
    phone.choose("light");
    let own = phone_computer.client_on_its_own_store(1);
    let held = own
        .client
        .store()
        .object(own.object_id)
        .expect("a store")
        .expect("settings");
    let at = position_of(&own);
    page.unshare(&reference_of(&page.devices()["members"], "the-tablet"))
        .expect("the tablet is taken out");
    page.sync_now();
    page.choose("system");
    assert_eq!(phone.sync_now()["sync"]["conflicts"], 1);

    // What a lost answer to the phone's sealing again of its settings leaves behind: the marker
    // that says the settings were being sealed again when the change that went over them arrived.
    let path = phone_computer
        .data
        .path()
        .join("settings-sync")
        .join("sync.json");
    let mut record = sync_record(&phone_computer);
    let revision = serde_json::to_value(held.revision).expect("a revision");
    record["resealing"] = json!({ "from": revision, "to": revision, "at": at });
    std::fs::write(&path, serde_json::to_vec(&record).expect("a record")).expect("written");

    let view = phone.sync_now();
    assert_eq!(view["colour_mode"], "light", "{view}");
    assert_eq!(view["sync"]["conflicts"], 1, "{view}");
}

/// Another device's settings that were refused to settings this computer was only sealing again are
/// that device's to continue: the person is asked nothing, for they changed nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_refused_to_settings_only_sealed_again_is_followed_and_asks_nothing() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    page.choose("dark");
    let phone = other.start();
    page.share(&first_reference(&page.devices_refresh()["candidates"]))
        .expect("shared");
    phone
        .join(&first_reference(&phone.devices_refresh()["offers"]))
        .expect("joined");
    page.sync_now();

    // What a lost answer to a reseal leaves behind: the settings this computer held, the other
    // device's settings kept beside them, and the marker that says the settings were being sealed
    // again when the other device's were refused.
    phone.choose("light");
    let own = this.client_on_its_own_store(1);
    let (client, object_id) = (&own.client, own.object_id);
    let store = client.store();
    let held = store.object(object_id).expect("a store").expect("settings");
    client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(now_ms()),
        )
        .await
        .expect("the other device's settings are kept beside this computer's");
    assert_eq!(store.conflicts(object_id).expect("copies").items.len(), 1);
    let path = this.data.path().join("settings-sync").join("sync.json");
    let mut record = sync_record(&this);
    let revision = serde_json::to_value(held.revision).expect("a revision");
    record["resealing"] = json!({ "from": revision, "to": revision, "at": position_of(&own) });
    std::fs::write(&path, serde_json::to_vec(&record).expect("a record")).expect("written");

    let view = page.sync_now();
    assert_eq!(view["sync"]["conflicts"], 0, "{view}");
    assert_eq!(view["colour_mode"], "light", "{view}");
}

/// A device on a platform with no ceremony to join with is not offered the settings: it could never
/// join them. The computers that can are offered them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_on_a_platform_with_no_ceremony_is_not_offered_the_settings() {
    let (this, other) = two_computers().await;
    let page = with_sync_on(&this).await;
    let reference = first_reference(&page.devices_refresh()["candidates"]);

    for platform in [
        kr_protocol::pairing::DevicePlatform::Ios,
        kr_protocol::pairing::DevicePlatform::Android,
        kr_protocol::pairing::DevicePlatform::Linux,
    ] {
        let mut without = other.listed("the-phone");
        without.platform = platform;
        this.hosts.list(vec![this.listed("this-mac"), without]);
        assert_eq!(
            page.devices_refresh()["candidates"],
            json!([]),
            "{platform:?}"
        );
        assert!(page.share(&reference).is_err(), "{platform:?}");
    }
    assert!(this.ceremony.reasons().is_empty(), "nobody was asked");

    let mut windows = other.listed("the-pc");
    windows.platform = kr_protocol::pairing::DevicePlatform::Windows;
    this.hosts.list(vec![this.listed("this-mac"), windows]);
    assert_eq!(
        page.devices_refresh()["candidates"]
            .as_array()
            .expect("candidates")
            .len(),
        1
    );
}
