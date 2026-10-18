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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use companion_tauri::AppState;
use companion_tauri::device::DeviceIdentity;
use companion_tauri::drafts::DraftHost;
use companion_tauri::settings::{DraftHosts, HostPrivacy, SETTINGS_EVENT};
use kr_client::drafts::{Draft, DraftSealer, DraftStore, DraftSync, DraftTarget};
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
use kr_protocol::scalars::{AuthorisationKey, Signature64, TimestampMs, Uuid};
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
    served: Served,
    data: tempfile::TempDir,
    secrets: Arc<MemoryStore>,
    /// What this computer can read of each host's privacy mode.
    hosts: Arc<ScriptedHosts>,
}

/// What this computer can read of each host's privacy mode, as a test says it: a host nobody said
/// anything of is one this computer is not connected to.
#[derive(Default)]
struct ScriptedHosts {
    said: Mutex<BTreeMap<EnvironmentId, HostPrivacy>>,
    /// What a host says from the read after the number of reads named, as a host that went private
    /// while a pass was out at the service does.
    turning: Mutex<BTreeMap<EnvironmentId, (u32, HostPrivacy)>>,
    reads: Mutex<BTreeMap<EnvironmentId, u32>>,
}

impl ScriptedHosts {
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
}

impl DraftHosts for ScriptedHosts {
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

impl Computer {
    async fn new() -> Self {
        Self {
            served: serve().await,
            data: tempfile::tempdir().expect("a directory"),
            secrets: Arc::new(MemoryStore::new()),
            hosts: Arc::new(ScriptedHosts::default()),
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
            Arc::clone(&self.hosts) as Arc<dyn DraftHosts>,
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
        let page = Page { app, window, heard };
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
        let record: Value = serde_json::from_slice(
            &std::fs::read(self.data.path().join("settings-sync").join("sync.json"))
                .expect("the record sync keeps"),
        )
        .expect("a record");
        let collection_id: SyncCollectionId =
            serde_json::from_value(record["collection_id"].clone()).expect("a collection");
        let object_id: SyncObjectId =
            serde_json::from_value(record["object_id"].clone()).expect("an object");
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
        let shared = Arc::new(SharedCollectionService::new(service, collection, 0));
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

/// The application's backend, called as the page calls it.
struct Page {
    app: tauri::App<MockRuntime>,
    window: tauri::WebviewWindow<MockRuntime>,
    /// Every view the page was told of by the backend itself.
    heard: Arc<Mutex<Vec<Value>>>,
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

    fn drafts_on(&self, enabled: bool) -> Result<Value, Value> {
        self.call("settings_drafts_set", json!({ "enabled": enabled }))
    }

    /// A draft the person wrote for a session of `host`, saved as the page saves one, and what the
    /// store says it is: its identity and its version.
    fn write_draft(&self, host: Option<&DraftHost>, text: &str) -> (DraftId, String) {
        let saved = self
            .app
            .state::<AppState>()
            .drafts()
            .save(
                serde_json::from_value(draft_params(None, None, text)).expect("parameters"),
                host.cloned(),
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

    /// The draft written again, as the page writes a later version.
    fn rewrite_draft(
        &self,
        host: Option<&DraftHost>,
        id: DraftId,
        version: &str,
        text: &str,
    ) -> String {
        let saved = self
            .app
            .state::<AppState>()
            .drafts()
            .save(
                serde_json::from_value(draft_params(Some((id, version)), None, text))
                    .expect("parameters"),
                host.cloned(),
                TimestampMs::new(now_ms()),
            )
            .expect("the draft is saved");
        serde_json::to_value(saved).expect("a value")["draft"]["revision"]
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
fn draft_params(replacing: Option<(DraftId, &str)>, instance: Option<&str>, text: &str) -> Value {
    json!({
        "id": replacing.map(|(id, _)| id),
        "expectedRevision": replacing.map(|(_, version)| version),
        "sessionId": "8a7b6c50-22bb-4c3d-8e4f-000000000101",
        "applicationInstanceId": instance,
        "agentBindingRevision": instance.map(|_| "1"),
        "state": "open",
        "text": text,
        "attachments": []
    })
}

/// A host a draft is written for, with a name.
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
    page.rewrite_draft(Some(&studio), draft, &version, "a prompt to send tomorrow");
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
    page.rewrite_draft(Some(&studio), draft, &version, "second, while private");
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

/// The host a draft was written for is the one that was connected when it was first written. A later
/// save from a window that was left open, or while another host is connected, does not move it, so
/// a draft written for a host in privacy mode is not published because another host allows it. A
/// retarget, which is the person choosing a session on the connected host, does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_keeps_the_host_it_was_written_for_when_another_host_is_connected_at_a_later_save()
{
    let computer = Computer::new().await;
    let (private, studio) = host(1, "studio");
    let (open, laptop) = host(2, "laptop");
    computer
        .hosts
        .say(private, HostPrivacy::On { generation: 3 });
    computer.hosts.say(open, HostPrivacy::Off { generation: 1 });
    let page = with_sync_on(&computer).await;
    let (draft, version) = page.write_draft(Some(&studio), "written for the studio");
    // The laptop is connected when the application saves the draft again, for a mark.
    page.rewrite_draft(
        Some(&laptop),
        draft,
        &version,
        "written for the studio, again",
    );

    let view = page.drafts_on(true).expect("drafts sync is on");
    assert_eq!(
        computer.elsewhere().draft_at(draft).await,
        None,
        "the studio is private, whichever host is connected now"
    );
    assert_eq!(
        kept_here(&view),
        vec![("studio".to_owned(), "private".to_owned(), 1)]
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
    // The pass asks once when it begins and once before each draft: the host answers private from
    // the third question, which is the one before the second draft.
    computer
        .hosts
        .turn_after(environment, 2, HostPrivacy::On { generation: 2 });

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
    let (kept, _) = page.write_draft(Some(&laptop), "written for the laptop");
    page.drafts_on(true).expect("drafts sync is on");

    // The studio's state is reset: it is private again, at generation 1 of a new history.
    computer.hosts.say(reset, HostPrivacy::On { generation: 1 });
    let (written_after, _) =
        page.write_draft(Some(&studio), "written for the studio, after the reset");
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
