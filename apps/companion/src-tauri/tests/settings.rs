//! The person's settings, through the commands the page calls, against the sync service as a local
//! Worker answered it.
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

use std::sync::{Arc, Mutex};

use companion_tauri::AppState;
use companion_tauri::device::DeviceIdentity;
use companion_tauri::settings::SETTINGS_EVENT;
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedSyncService, ServiceSigner, managed_response_limits,
};
use kr_client::sync::{
    CollectionKeys, Published, Restored, SettingValue, SharedCollectionService,
    StoredCollectionKeys, SyncBody, SyncClient, SyncObject, SyncStore, fresh_revision,
};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_crypto::store::MemoryStore;
use kr_protocol::ids::{DeviceId, SyncCollectionId, SyncObjectId};
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
}

impl Computer {
    async fn new() -> Self {
        Self {
            served: serve().await,
            data: tempfile::tempdir().expect("a directory"),
            secrets: Arc::new(MemoryStore::new()),
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
            ])
            .build(mock_context(noop_assets()))
            .expect("an application on the mock runtime");
        // What the application's start does, over this computer's records.
        app.state::<AppState>().keep_under(self.data.path());
        companion_tauri::start_sync_service(app.handle(), self.data.path());
        companion_tauri::start_settings_sync(app.handle(), self.data.path(), &self.identity())
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
        let shared = SharedCollectionService::new(service, collection, 0);
        let sealer = shared.sealer(Arc::new(StoredCollectionKeys::in_store(
            Arc::clone(&self.secrets) as _,
            companion_tauri::settings::sync::SCOPE,
        )) as Arc<dyn CollectionKeys>);
        let client = SyncClient::new(
            Arc::new(shared),
            Arc::new(sealer),
            SyncStore::open(directory.path()).expect("a store"),
        );
        Elsewhere {
            client,
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
}

/// Another device's store of the collection.
struct Elsewhere {
    client: SyncClient,
    service: Arc<ManagedSyncService>,
    collection: kr_client::sync::membership::CollectionRef,
    object_id: SyncObjectId,
    device: DeviceId,
    _directory: tempfile::TempDir,
}

impl Elsewhere {
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
